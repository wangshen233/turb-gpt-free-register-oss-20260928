# -*- coding: utf-8 -*-
"""
curl_cffi Session 封装
统一管理 Cookie、请求头和 TLS 指纹
"""
import logging
import hashlib
import random
import threading
import time
import uuid
from urllib.parse import urlparse
from curl_cffi.requests import Session

from config import (
    USER_AGENT, SEC_CH_UA, SEC_CH_UA_PLATFORM, SEC_CH_UA_MOBILE,
    SEC_CH_UA_FULL_VERSION_LIST, SEC_CH_UA_FULL_VERSION, SEC_CH_UA_PLATFORM_VERSION,
    SEC_CH_UA_ARCH, SEC_CH_UA_BITNESS, SEC_CH_UA_MODEL,
    should_send_high_entropy_client_hints,
    ACCEPT_LANGUAGE, IMPERSONATE, OAI_CLIENT_BUILD_NUMBER, OAI_CLIENT_VERSION,
    REQUEST_TIMEOUT, pick_proxy, pick_browser_profile, validate_browser_profile,
    BROWSER_PROFILE_POOL, build_browser_environment,
)


logger = logging.getLogger(__name__)
_GEO_CACHE: dict[str, tuple[float, dict]] = {}
_GEO_CACHE_LOCK = threading.Lock()
# 出口地理缓存 TTL（秒）。原来按代理 URL 永久缓存，换国家后（同一个本地桥端口
# 换挂别的国家的上游）旧画像会一直生效：日本出口配巴西 pt-BR/America/Sao_Paulo，
# 地区画像和出口 IP 不一致，账号容易被风控。加 TTL 后会自动重新探测。
_GEO_CACHE_TTL = 600.0
_CF_COOKIE_NAMES = ("cf_clearance", "__cf_bm", "__cfseq", "cf_chl_rc_i", "cf_chl_rc_ni", "cf_chl_rc_m")


# 本地 SOCKS 桥（tools/socks_bridge_10808.py）默认按连接轮询上游，一次注册里
# chatgpt.com / auth.openai.com / sentinel.openai.com 会各走一个出口 IP，风控可以
# 直接判定不是同一个人。这里给桥补一个会话级 SOCKS5 用户名，桥据此把整次会话
# （含 Node sentinel runner）粘到同一条住宅上游。
_BRIDGE_HOSTS = ("127.0.0.1", "localhost", "::1")
_BRIDGE_SESSION_PREFIX = "oai-"
_CF_CHALLENGE_MARKERS = ("just a moment", "cf-chl", "attention required", "checking your browser")


def is_cf_challenge_response(resp) -> bool:
    """响应是不是 Cloudflare 人机挑战（出口 IP 问题，换 IP 可解）。"""
    if resp is None:
        return False
    try:
        headers = getattr(resp, "headers", {}) or {}
        if str(headers.get("cf-mitigated") or "").strip().lower() == "challenge":
            return True
        if int(getattr(resp, "status_code", 0) or 0) not in (403, 429, 503):
            return False
        body = (getattr(resp, "text", "") or "")[:600].lower()
    except Exception:
        return False
    return any(marker in body for marker in _CF_CHALLENGE_MARKERS)


def bridge_session_key(key: str, slot: int = 0) -> str:
    """由 device_id 派生稳定的 SOCKS5 用户名；slot 变化＝换一条上游。"""
    digest = hashlib.sha1(f"{key}|{int(slot or 0)}".encode("utf-8")).hexdigest()
    return _BRIDGE_SESSION_PREFIX + digest[:20]


def _with_bridge_session_key(proxy: str, key: str, slot: int = 0) -> str:
    """本地 SOCKS 桥代理补会话用户名；非本地桥/已带用户名时原样返回。"""
    text = str(proxy or "").strip()
    if not text or not key:
        return proxy
    try:
        parsed = urlparse(text)
    except Exception:
        return proxy
    if parsed.scheme not in ("socks5", "socks5h", "socks4", "socks4a"):
        return proxy
    if (parsed.hostname or "") not in _BRIDGE_HOSTS:
        return proxy
    if parsed.username:
        return proxy
    netloc = f"{bridge_session_key(key, slot)}:x@{parsed.hostname}"
    if parsed.port:
        netloc += f":{parsed.port}"
    return f"{parsed.scheme}://{netloc}"


def _seed_uuid(seed: str, salt: str) -> str:
    text = f"{salt}:{seed}".strip()
    return str(uuid.uuid5(uuid.NAMESPACE_URL, text))


_TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def _seed_token(seed: str, salt: str, length: int) -> str:
    """从 fingerprint_seed 派生固定长度的 base62 串，用于前端可观测性 ID。"""
    digest = hashlib.sha256(f"{salt}:{seed}".encode("utf-8")).digest()
    return "".join(_TOKEN_ALPHABET[b % len(_TOKEN_ALPHABET)] for b in digest[:max(1, int(length))])


def _seed_int(seed: str, salt: str, *, bits: int = 63) -> int:
    digest = hashlib.sha256(f"{salt}:{seed}".encode("utf-8")).digest()
    nbytes = max(1, (bits + 7) // 8)
    value = int.from_bytes(digest[:nbytes], "big")
    mask = (1 << bits) - 1
    return value & mask


def _seeded_browser_profile(seed: str, geo: dict | None = None) -> dict:
    if not seed:
        return pick_browser_profile(geo)
    pool = list(BROWSER_PROFILE_POOL or [])
    if not pool:
        return pick_browser_profile(geo)
    idx = _seed_int(seed, "browser_profile_index", bits=32) % len(pool)
    return build_browser_environment(geo, base_profile=pool[idx])


class BrowserSession:
    """
    模拟 Chrome 浏览器的 HTTP 会话管理器。
    使用 curl_cffi 的 impersonate 功能绕过 Cloudflare TLS 指纹检测。
    """

    def __init__(
        self,
        proxy: str = None,
        *,
        detect_exit_geo: bool = True,
        device_id: str | None = None,
        auth_session_logging_id: str | None = None,
        oai_session_id: str | None = None,
        sentinel_sid: str | None = None,
        browser_profile: dict | None = None,
        fingerprint_seed: str | None = None,
    ):
        """
        初始化会话。

        Args:
            proxy: 代理地址，如 "socks5h://user:pass@host:port"。
                   不传则从 config.PROXY_POOL 随机抽一个。
                   显式传 "" 表示禁用代理。
            detect_exit_geo: 是否探测出口 IP 并自动选择语言/时区画像。
                             套餐查询等短请求可关闭，避免额外网络等待。
        """
        # proxy=None  → 从池里随机抽（默认行为）
        # proxy=""    → 禁用代理（直连）
        # proxy="..." → 使用指定代理
        if proxy is None:
            self.proxy = pick_proxy()
        else:
            self.proxy = proxy

        self.fingerprint_seed = str(fingerprint_seed or "").strip()

        # 生成/复用设备ID（oai-did），整个任务周期复用。
        if device_id:
            self.device_id = str(device_id)
        elif self.fingerprint_seed:
            self.device_id = _seed_uuid(self.fingerprint_seed, "device_id")
        else:
            self.device_id = str(uuid.uuid4())

        # 本地 SOCKS 桥把同一个 device_id 的所有请求绑到同一条上游出口。
        self._bridge_slot = 0
        self._bridge_pool_key = str(self.device_id)
        self.proxy = _with_bridge_session_key(self.proxy, self._bridge_pool_key, self._bridge_slot)

        # 页面"打开"时刻（毫秒）：sentinel 指纹里 performance.timeOrigin 固定用它，
        # performance.now() 由墙钟推导，保证整场会话里 timeOrigin 不变、now() 单调增长，
        # 和真实浏览器一致（之前两次调用各自随机，等于自曝伪造）。
        self.page_time_origin_ms = time.time() * 1000 - random.uniform(20000, 32000)

        # 生成 auth_session_logging_id
        if auth_session_logging_id:
            self.auth_session_logging_id = str(auth_session_logging_id)
        elif self.fingerprint_seed:
            self.auth_session_logging_id = _seed_uuid(self.fingerprint_seed, "auth_session_logging_id")
        else:
            self.auth_session_logging_id = str(uuid.uuid4())

        # ChatGPT 前端会话 ID：CES / Statsig / API 链路内保持稳定。
        if oai_session_id:
            self.oai_session_id = str(oai_session_id)
        elif self.fingerprint_seed:
            self.oai_session_id = _seed_uuid(self.fingerprint_seed, "oai_session_id")
        else:
            self.oai_session_id = str(uuid.uuid4())

        # Datadog/RUM 关联 ID：每个 BrowserSession 独立生成，禁止跨账号复用。
        # 同一账号的运行时环境尽量保持固定，避免同账号多次操作指纹漂移。
        if self.fingerprint_seed:
            self.datadog_trace_id = str(_seed_int(self.fingerprint_seed, "datadog_trace_id"))
            self.datadog_parent_id = str(_seed_int(self.fingerprint_seed, "datadog_parent_id"))
        else:
            self.datadog_trace_id = str(random.getrandbits(63))
            self.datadog_parent_id = str(random.getrandbits(63))
        self.datadog_origin = "rum"

        # Sentinel SDK 内部 sid：真实 SDK 会单独生成一个 UUID，和 oai-did 不是同一个值。
        # Python 初始 p 与 Node Runner 最终 token 都复用这个 sid，保持同一 SDK 实例语义。
        if sentinel_sid:
            self.sentinel_sid = str(sentinel_sid)
        elif self.fingerprint_seed:
            self.sentinel_sid = _seed_uuid(self.fingerprint_seed, "sentinel_sid")
        else:
            self.sentinel_sid = str(uuid.uuid4())
        if self.fingerprint_seed:
            self.react_listening_key = "_reactListening" + _seed_uuid(self.fingerprint_seed, "react_listening_key").replace("-", "")[:12]
            self.react_container_key = "__reactContainer$" + _seed_uuid(self.fingerprint_seed, "react_container_key").replace("-", "")[:11]
        else:
            self.react_listening_key = "_reactListening" + uuid.uuid4().hex[:12]
            self.react_container_key = "__reactContainer$" + uuid.uuid4().hex[:11]
        self.react_resources_key = "__reactResources$" + self.react_container_key.split("$", 1)[1]
        if self.fingerprint_seed:
            self.document_navigation_id = _seed_uuid(self.fingerprint_seed, "document_navigation_id")
        else:
            self.document_navigation_id = str(uuid.uuid4())

        # x-oai-is-client-observation：抓包形态 "v1.r.p.rLCTeWHX17N363CT"
        # （v1.r.p. + 16 位 base62）。同一 session 稳定，跨 session 分散。
        if self.fingerprint_seed:
            self.client_observation_id = "v1.r.p." + _seed_token(self.fingerprint_seed, "client_observation_id", 16)
        else:
            self.client_observation_id = "v1.r.p." + "".join(random.choices(_TOKEN_ALPHABET, k=16))

        # 创建 curl_cffi 会话
        self.session = Session(impersonate=IMPERSONATE)

        # 设置代理
        if self.proxy:
            self.session.proxies = {
                "http": self.proxy,
                "https": self.proxy,
            }

        # 设置超时
        self.session.timeout = REQUEST_TIMEOUT

        # 会话级熔断：收到 403/429 后停止继续打后续接口，避免异常状态下扩大误伤。
        self.blocked_until = 0.0
        self.blocked_reason = ""
        self._traffic = {
            "request_count": 0,
            "completed_request_count": 0,
            "failed_request_count": 0,
            "upload_bytes": 0,
            "download_bytes": 0,
        }

        # 先用当前代理检测出口 IP 地理信息，再为本会话挑一份稳定浏览器画像。
        # 这样 Accept-Language / navigator.language / timezone 可自动跟随出口地区。
        self.exit_geo = self._detect_exit_geo() if detect_exit_geo else {}
        self._enforce_proxy_quality()
        if browser_profile:
            self.browser_profile = dict(browser_profile)
        else:
            self.browser_profile = dict(_seeded_browser_profile(self.fingerprint_seed, self.exit_geo))
        self.browser_profile["react_listening_key"] = self.react_listening_key
        self.browser_profile["react_container_key"] = self.react_container_key
        self.browser_profile["react_resources_key"] = self.react_resources_key
        self.browser_profile["page_time_origin_ms"] = self.page_time_origin_ms
        issues = validate_browser_profile(self.browser_profile)
        if issues:
            logger.warning("[指纹] 浏览器画像存在不一致: %s", "; ".join(issues))

        # 让 HTTP Cookie、OAuth 参数 ext-oai-did、Sentinel 里的 id 三者一致。
        # 浏览器里 oai-did 通常会作为一方 Cookie 存在；协议层主动补齐可减少同一会话内
        # “头部/参数/JS 指纹有设备 ID，但 Cookie Jar 为空”的不一致。
        for domain in ("chatgpt.com", "auth.openai.com", "sentinel.openai.com"):
            self.session.cookies.set("oai-did", self.device_id, domain=domain, path="/")

        # Cloudflare 状态只能来自真实响应 Set-Cookie；这里仅记录变化，不主动伪造/覆盖。
        self._cf_cookie_seen = self.cf_cookie_snapshot()

    def rotate_bridge_upstream(self) -> str:
        """把本地桥粘性的上游换一条（当前出口被 Cloudflare 挑战时用）。

        桥按 SOCKS5 用户名哈希选上游，所以换个用户名就等于换 IP；
        匿名/远程代理没法这样换，返回空串表示不支持。
        """
        parsed = None
        try:
            parsed = urlparse(str(self.proxy or ""))
        except Exception:
            parsed = None
        if not parsed or (parsed.hostname or "") not in _BRIDGE_HOSTS:
            return ""
        if not str(parsed.username or "").startswith(_BRIDGE_SESSION_PREFIX):
            return ""
        self._bridge_slot = int(getattr(self, "_bridge_slot", 0)) + 1
        self.proxy = _with_bridge_session_key(
            f"{parsed.scheme}://{parsed.hostname}" + (f":{parsed.port}" if parsed.port else ""),
            getattr(self, "_bridge_pool_key", self.device_id),
            self._bridge_slot,
        )
        self.session.proxies = {"http": self.proxy, "https": self.proxy}
        # 换了出口就重开熔断：旧 IP 的挑战不该挡住新 IP 的重试。
        self.reset_circuit_breaker()
        return self.proxy

    def cf_cookie_snapshot(self) -> dict:
        """返回当前 CookieJar 中的 Cloudflare 关键 Cookie 摘要，便于确认同 IP/同会话连续性。"""
        out = {}
        try:
            for cookie in self.session.cookies.jar:
                name = getattr(cookie, "name", "")
                if name in _CF_COOKIE_NAMES:
                    out[f"{getattr(cookie, 'domain', '')}:{name}"] = len(str(getattr(cookie, "value", "") or ""))
        except Exception:
            pass
        return out

    @staticmethod
    def _short_value(value: object, limit: int = 80) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        return text if len(text) <= limit else text[: max(0, limit - 3)] + "..."

    def fingerprint_summary(self) -> dict:
        """返回适合日志/落库的浏览器指纹摘要，不展开过长数组字段。"""
        profile = getattr(self, "browser_profile", {}) or {}
        geo = profile.get("geo") or self.exit_geo or {}
        summary = {
            "device_id": self.device_id,
            "proxy": self.proxy or "",
            "proxy_mode": "direct" if not self.proxy else "proxy",
            "browser_family": profile.get("browser_family") or "chrome",
            "browser_os": profile.get("browser_os") or "Windows",
            "user_agent": profile.get("user_agent") or USER_AGENT,
            "accept_language": profile.get("accept_language") or ACCEPT_LANGUAGE,
            "navigator_language": profile.get("navigator_language") or "zh-CN",
            "navigator_languages": list(profile.get("navigator_languages") or []),
            "timezone_iana": profile.get("timezone_iana") or "",
            "timezone_offset_minutes": int(profile.get("timezone_offset_minutes", 0) or 0),
            "timezone_name": profile.get("timezone_name") or "",
            "screen_width": int(profile.get("screen_width", 0) or 0),
            "screen_height": int(profile.get("screen_height", 0) or 0),
            "device_pixel_ratio": profile.get("device_pixel_ratio") or 0,
            "hardware_concurrency": profile.get("hardware_concurrency") or 0,
            "device_memory": profile.get("device_memory") or 0,
            "js_heap_size_limit": profile.get("js_heap_size_limit") or 0,
            "sec_ch_ua": profile.get("sec_ch_ua") or "",
            "sec_ch_ua_platform": profile.get("sec_ch_ua_platform") or "",
            "sec_ch_ua_platform_version": profile.get("sec_ch_ua_platform_version") or "",
            "sec_ch_ua_mobile": profile.get("sec_ch_ua_mobile") or "",
            "sec_ch_ua_arch": profile.get("sec_ch_ua_arch") or "",
            "sec_ch_ua_bitness": profile.get("sec_ch_ua_bitness") or "",
            "sec_ch_ua_model": profile.get("sec_ch_ua_model") or "",
            "sec_ch_ua_full_version_list": profile.get("sec_ch_ua_full_version_list") or "",
            "react_listening_key": profile.get("react_listening_key") or "",
            "react_container_key": profile.get("react_container_key") or "",
            "react_resources_key": profile.get("react_resources_key") or "",
            "sentinel_sid": self.sentinel_sid,
            "oai_session_id": self.oai_session_id,
            "auth_session_logging_id": self.auth_session_logging_id,
            "document_navigation_id": self.document_navigation_id,
            "datadog_trace_id": self.datadog_trace_id,
            "datadog_parent_id": self.datadog_parent_id,
            "geo_country": geo.get("country") or "",
            "geo_city": geo.get("city") or "",
            "geo_timezone": geo.get("timezone") or "",
            "geo_org": geo.get("org") or "",
        }
        return summary

    def fingerprint_summary_text(self) -> str:
        """把摘要压成单行，方便日志输出。"""
        p = self.fingerprint_summary()
        parts = [
            f"device_id={self._short_value(p.get('device_id'), 12)}",
            f"proxy={self._short_value(p.get('proxy') or 'direct', 36)}",
            f"ua={self._short_value(p.get('user_agent'), 72)}",
            f"lang={p.get('accept_language')}",
            f"tz={p.get('timezone_iana')}({p.get('timezone_offset_minutes')})",
            f"screen={p.get('screen_width')}x{p.get('screen_height')}@{p.get('device_pixel_ratio')}",
            f"cpu={p.get('hardware_concurrency')}",
            f"mem={p.get('device_memory')}",
            f"geo={p.get('geo_country') or '?'}:{p.get('geo_city') or '?'}",
        ]
        return " ".join(parts)

    def _observe_cf_cookie_changes(self, url: str) -> None:
        current = self.cf_cookie_snapshot()
        if current != getattr(self, "_cf_cookie_seen", {}):
            logger.info("[CF] Cookie 状态更新 url=%s keys=%s", url, sorted(current.keys()))
            self._cf_cookie_seen = current

    def _enforce_proxy_quality(self) -> None:
        """根据 GeoIP org/ASN 粗判代理质量，默认拒绝云厂商/DC 出口。"""
        try:
            from config import browser as _browser_cfg
            reject = bool(getattr(_browser_cfg, "REJECT_CLOUD_PROXY", True))
            keywords = list(getattr(_browser_cfg, "CLOUD_PROXY_ORG_KEYWORDS", []) or [])
        except Exception:
            return
        if not reject or not self.exit_geo:
            return
        org = str(self.exit_geo.get("org") or "").lower()
        if not org:
            return
        hit = next((kw for kw in keywords if kw and str(kw).lower() in org), "")
        if hit:
            raise RuntimeError(
                f"代理出口疑似云厂商/DC，已拒绝继续注册："
                f"ip={self.exit_geo.get('ip') or '?'} country={self.exit_geo.get('country') or '?'} "
                f"org={self.exit_geo.get('org') or '?'} hit={hit}. "
                f"如确认是住宅代理，可设置 REJECT_CLOUD_PROXY=False。"
            )

    def _cookie_header_for_domain(self, domain: str) -> str:
        """导出当前会话给指定域名可见的 Cookie，供 Node VM document.cookie 使用。"""
        pairs = []
        wanted = domain.lower().lstrip(".")
        try:
            for cookie in self.session.cookies.jar:
                name = getattr(cookie, "name", "")
                value = getattr(cookie, "value", "")
                cdom = str(getattr(cookie, "domain", "") or "").lower().lstrip(".")
                if not name:
                    continue
                if cdom and not (wanted == cdom or wanted.endswith("." + cdom) or cdom.endswith("." + wanted)):
                    continue
                pairs.append(f"{name}={value}")
        except Exception:
            pass
        return "; ".join(pairs)

    def auth_cookie_header(self) -> str:
        return self._cookie_header_for_domain("auth.openai.com") or f"oai-did={self.device_id}"

    def chatgpt_cookie_header(self) -> str:
        return self._cookie_header_for_domain("chatgpt.com") or f"oai-did={self.device_id}"

    def _detect_exit_geo(self) -> dict:
        """通过当前代理检测出口 IP 地理信息；失败返回空 dict 并回退到默认地区画像。"""
        try:
            from config import browser as _browser_cfg
            if not getattr(_browser_cfg, "AUTO_BROWSER_LOCALE_FROM_IP", True):
                return {}
            endpoints = list(getattr(_browser_cfg, "IP_GEO_ENDPOINTS", []) or [])
            timeout = float(getattr(_browser_cfg, "IP_GEO_TIMEOUT", 6) or 6)
        except Exception:
            return {}

        cache_key = self.proxy or "__direct__"
        now = time.time()
        with _GEO_CACHE_LOCK:
            cached = _GEO_CACHE.get(cache_key)
            if cached is not None and now - cached[0] < _GEO_CACHE_TTL:
                return dict(cached[1])

        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        # 探测失败不能直接把 {} 用下去：出口是巴西住宅 IP 却报 en-US +
        # America/Los_Angeles，就是最典型的"地区画像和 IP 打架"死号指纹。
        # 探测本身是瞬时的（超时/偶发 5xx），所以整轮重试几次再说。
        attempts = 3
        for attempt in range(1, attempts + 1):
            for url in endpoints:
                try:
                    resp = self.session.get(url, headers=headers, timeout=timeout)
                    if resp.status_code != 200:
                        continue
                    data = resp.json()
                    geo = self._normalize_geo_response(data)
                    if geo.get("country") or geo.get("timezone"):
                        with _GEO_CACHE_LOCK:
                            _GEO_CACHE[cache_key] = (now, dict(geo))
                        logger.info(
                            "[指纹] 出口IP地理信息: ip=%s country=%s city=%s timezone=%s",
                            geo.get("ip") or "?", geo.get("country") or "?",
                            geo.get("city") or "?", geo.get("timezone") or "?",
                        )
                        return geo
                except Exception as exc:
                    logger.debug(f"[指纹] 出口 IP 地理检测失败 endpoint={url}: {type(exc).__name__}: {exc}")
                    continue
            if attempt < attempts:
                logger.debug("[指纹] 出口地理探测第 %s 轮未拿到结果，重试", attempt)
                time.sleep(0.5 * attempt)
        # 失败结果**不写缓存**：下一个会话立刻重试，而不是继续沿用默认画像。
        logger.warning("[指纹] 出口地理探测连续 %s 轮失败，本会话只能退回默认地区画像", attempts)
        return {}

    @staticmethod
    def _normalize_geo_response(data: dict) -> dict:
        """兼容 ipinfo / ipapi / ipwho.is 等常见 JSON 字段。"""
        if not isinstance(data, dict):
            return {}
        timezone = data.get("timezone")
        if isinstance(timezone, dict):
            timezone = timezone.get("id") or timezone.get("name")
        raw_cc = str(data.get("country_code") or data.get("countryCode") or "").strip()
        raw_country = str(data.get("country") or "").strip()
        if len(raw_cc) == 2 and raw_cc.isalpha():
            country = raw_cc.upper()
        elif len(raw_country) == 2 and raw_country.isalpha():
            country = raw_country.upper()
        else:
            country = {
                "VIET NAM": "VN", "VIETNAM": "VN",
                "INDIA": "IN", "THAILAND": "TH", "INDONESIA": "ID",
                "PHILIPPINES": "PH", "MALAYSIA": "MY", "SINGAPORE": "SG",
            }.get(raw_country.upper(), raw_country.upper())
        return {
            "ip": data.get("ip") or data.get("query"),
            "country": country,
            "region": data.get("region") or data.get("regionName"),
            "city": data.get("city"),
            "timezone": timezone or "",
            "org": data.get("org") or data.get("isp") or data.get("connection", {}).get("org"),
        }

    def _get_common_headers(self, host: str = "") -> dict:
        """获取通用请求头，优先使用本 BrowserSession 的稳定画像。

        host 决定是否附带高熵 Client Hints：2026-09-11 抓包中 chatgpt.com 87/97 条
        带全套高熵（full-version-list / full-version / arch / bitness / model /
        platform-version），auth.openai.com 100/100 条全都不带（低熵 3 个照发）。
        """
        profile = getattr(self, "browser_profile", {}) or {}
        headers = {
            "User-Agent": str(profile.get("user_agent") or USER_AGENT),
            "accept-language": str(profile.get("accept_language") or ACCEPT_LANGUAGE),
        }

        # Safari 不发送 Chromium Client Hints；Chrome/Chromium 画像才补 sec-ch-*。
        send_client_hints = bool(profile.get("send_client_hints", bool(SEC_CH_UA)))
        if send_client_hints:
            if profile.get("sec_ch_ua") or SEC_CH_UA:
                headers["sec-ch-ua"] = str(profile.get("sec_ch_ua") or SEC_CH_UA)
            if profile.get("sec_ch_ua_mobile") or SEC_CH_UA_MOBILE:
                headers["sec-ch-ua-mobile"] = str(profile.get("sec_ch_ua_mobile") or SEC_CH_UA_MOBILE)
            if profile.get("sec_ch_ua_platform") or SEC_CH_UA_PLATFORM:
                headers["sec-ch-ua-platform"] = str(profile.get("sec_ch_ua_platform") or SEC_CH_UA_PLATFORM)
            if should_send_high_entropy_client_hints(host):
                headers.update({
                    "sec-ch-ua-full-version-list": str(profile.get("sec_ch_ua_full_version_list") or SEC_CH_UA_FULL_VERSION_LIST),
                    "sec-ch-ua-full-version": str(profile.get("sec_ch_ua_full_version") or SEC_CH_UA_FULL_VERSION),
                    "sec-ch-ua-platform-version": str(profile.get("sec_ch_ua_platform_version") or SEC_CH_UA_PLATFORM_VERSION),
                    "sec-ch-ua-arch": str(profile.get("sec_ch_ua_arch") or SEC_CH_UA_ARCH),
                    "sec-ch-ua-bitness": str(profile.get("sec_ch_ua_bitness") or SEC_CH_UA_BITNESS),
                    "sec-ch-ua-model": str(profile.get("sec_ch_ua_model") or SEC_CH_UA_MODEL),
                })
        return headers

    def navigator_language(self) -> str:
        """当前会话画像里的 navigator.language。"""
        return str((getattr(self, "browser_profile", {}) or {}).get("navigator_language") or "zh-CN")

    @staticmethod
    def _sec_fetch_site_for(target_origin: str, referer: str) -> str:
        """按 Referer 粗略模拟浏览器的 Sec-Fetch-Site。"""
        ref = (referer or "").lower()
        target = target_origin.lower().rstrip("/")
        if ref.startswith(target):
            return "same-origin"
        if ref.startswith("https://chatgpt.com") or ref.startswith("https://auth.openai.com") or ref.startswith("https://sentinel.openai.com"):
            return "cross-site"
        return "none"

    def get_datadog_headers(self) -> dict:
        """获取当前会话稳定的 Datadog/RUM 关联头。"""
        return {
            "x-datadog-origin": self.datadog_origin,
            "x-datadog-sampling-priority": "1",
            "x-datadog-trace-id": self.datadog_trace_id,
            "x-datadog-parent-id": self.datadog_parent_id,
        }

    def get_trace_context_headers(self) -> dict:
        """补齐 Auth Web 抓包里的 W3C traceparent / Datadog tracestate。"""
        trace_hex = format(int(self.datadog_trace_id), "032x")[-32:]
        parent_hex = format(int(self.datadog_parent_id), "016x")[-16:]
        return {
            "traceparent": f"00-{trace_hex}-{parent_hex}-01",
            "tracestate": f"dd=s:1;o:{self.datadog_origin}",
        }

    def _attach_auth_rum_headers(self, headers: dict) -> dict:
        """Auth Web JSON 接口头：HAR 中只出现 RUM/trace/access-flow，不带 oai-client-*。"""
        headers.update(self.get_trace_context_headers())
        headers["x-access-flow-invocation-id"] = str(uuid.uuid4())
        headers["x-openai-document-navigation-id"] = self.document_navigation_id
        headers.update(self.get_datadog_headers())
        return headers

    def js_timezone_offset_min(self) -> int:
        """返回 JS Date.getTimezoneOffset() 语义：UTC-local，东八区为 -480。"""
        profile = getattr(self, "browser_profile", {}) or {}
        return -int(profile.get("timezone_offset_minutes", 0) or 0)

    def _attach_datadog_headers(self, headers: dict) -> dict:
        """按需补齐 Datadog 头。

        抓包事实：x-datadog-* 只出现在 auth.openai.com 的 JSON 接口（email-otp/validate
        与 create_account 两条），chatgpt.com 前端 / sentinel / 导航请求全都**不带**。
        因此默认不再全域挂载，只有 auth JSON 链路（_attach_auth_rum_headers）使用。
        """
        headers.update(self.get_datadog_headers())
        return headers

    def _attach_oai_context_headers(self, headers: dict) -> dict:
        """补齐同一设备上下文头，和 oai-did Cookie / OAuth ext-oai-did 保持一致。"""
        headers["oai-client-build-number"] = OAI_CLIENT_BUILD_NUMBER
        headers["oai-client-version"] = OAI_CLIENT_VERSION
        headers["oai-device-id"] = self.device_id
        headers["oai-language"] = self.navigator_language()
        headers["oai-session-id"] = self.oai_session_id
        # 抓包里 76 条带 authorization 的 chatgpt.com 请求全部带这个头，本地原先缺失。
        headers["x-oai-is-client-observation"] = self.client_observation_id
        return headers

    def _attach_frontend_api_headers(self, headers: dict) -> dict:
        """chatgpt.com / sentinel 前端 API 统一头：oai 上下文（含可观测性头）。

        抓包里 chatgpt.com 前端与 sentinel 请求都不带 x-datadog-*，所以这里不再挂
        Datadog；只有 auth.openai.com 的 JSON 接口才带（见 _attach_auth_rum_headers）。
        """
        self._attach_oai_context_headers(headers)
        return headers

    def get_nextauth_headers(self, referer: str = "https://chatgpt.com/") -> dict:
        """NextAuth `/api/auth/*` 头；HAR 中不携带 oai-client-*。

        抓包里只有 /api/auth/providers 与 /api/auth/csrf 两个 GET 带 content-type，
        其余 GET 不带；本函数只服务这两个 NextAuth GET 与 signin 表单 POST，故保留。
        """
        headers = self._get_common_headers("chatgpt.com")
        headers.update({
            "accept": "*/*",
            "content-type": "application/json",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": referer,
        })
        return headers

    def get_chatgpt_headers(self, referer: str = "https://chatgpt.com/login", *, include_content_type: bool = False) -> dict:
        """
        获取 chatgpt.com 域名的请求头。
        用于步骤1-3。

        抓包里 45 条 GET /backend-api/* **全都**没有 content-type，只有两个 NextAuth
        GET（见 get_nextauth_headers）带。所以默认不加 content-type；需要发 JSON body
        的调用点显式传 include_content_type=True。
        """
        headers = self._get_common_headers("chatgpt.com")
        headers.update({
            "accept": "*/*",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": referer,
        })
        if include_content_type:
            headers["content-type"] = "application/json"
        return self._attach_frontend_api_headers(headers)

    def get_chatgpt_mweb_headers(self, referer: str = "https://chatgpt.com/") -> dict:
        """chatgpt.com 未登录 mweb 接口头（2026-09-12 注册抓包）。

        `/unauth-mweb/*` 的请求**不带**任何 oai-* 上下文头：抓包 20 个头里没有
        oai-client-build-number / oai-client-version / oai-device-id / oai-language /
        oai-session-id / x-oai-is-client-observation，只有 UA + 全套 Client Hints +
        Sec-Fetch 四件套。用 get_chatgpt_headers() 会多挂那一串，所以单独走这个最小集合。
        """
        headers = self._get_common_headers("chatgpt.com")
        headers.update({
            "accept": "*/*",
            "content-type": "application/json",
            "origin": "https://chatgpt.com",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": referer,
        })
        return headers

    def get_auth_headers(self, referer: str = "https://auth.openai.com/create-account/password") -> dict:
        """
        获取 auth.openai.com 域名的请求头。
        用于步骤7、10、12。

        auth 域只发低熵 Client Hints（抓包 100/100 条都没有高熵提示）。
        """
        headers = self._get_common_headers("auth.openai.com")
        headers.update({
            "accept": "application/json",
            "content-type": "application/json",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": referer,
            "origin": "https://auth.openai.com",
        })
        return self._attach_auth_rum_headers(headers)

    def get_auth_navigate_headers(self, referer: str = "https://chatgpt.com/", user_initiated: bool = True, target_origin: str = "https://auth.openai.com") -> dict:
        """
        获取 auth.openai.com 导航请求头（用于GET页面请求）。
        用于步骤4、5、8。
        """
        headers = self._get_common_headers("auth.openai.com")
        headers.update({
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "sec-fetch-site": self._sec_fetch_site_for(target_origin, referer),
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "document",
            "referer": referer,
            "upgrade-insecure-requests": "1",
        })
        if user_initiated:
            headers["sec-fetch-user"] = "?1"
        return headers

    def get_chatgpt_navigate_headers(self, referer: str = "https://chatgpt.com/", user_initiated: bool = True) -> dict:
        """获取 chatgpt.com 页面导航请求头，用于预热登录页 / 回到应用页。"""
        headers = self._get_common_headers("chatgpt.com")
        headers.update({
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "sec-fetch-site": self._sec_fetch_site_for("https://chatgpt.com", referer),
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "document",
            "referer": referer,
            "upgrade-insecure-requests": "1",
        })
        if user_initiated:
            headers["sec-fetch-user"] = "?1"
        return headers

    def get_sentinel_headers(self) -> dict:
        """
        获取 sentinel.openai.com 的请求头。
        用于步骤6、9、11。
        """
        from config import SENTINEL_SV
        headers = self._get_common_headers("sentinel.openai.com")
        headers.update({
            "accept": "*/*",
            "content-type": "text/plain;charset=UTF-8",
            "origin": "https://sentinel.openai.com",
            "referer": f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={SENTINEL_SV}",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
        })
        return self._attach_frontend_api_headers(headers)


    @staticmethod
    def _chatgpt_target_route(path: str) -> str:
        """把真实 URL path 归一成 HAR 里的 x-openai-target-route 形态。"""
        if path.startswith("/backend-api/accounts/check/"):
            return "/backend-api/accounts/check/{version}"
        if path.startswith("/backend-api/checkout_pricing_config/configs/"):
            return "/backend-api/checkout_pricing_config/configs/{country_code}"
        if path.startswith("/backend-anon/accounts/check/"):
            return "/backend-anon/accounts/check/{version}"
        if path.startswith("/backend-api/conversation/") and path != "/backend-api/conversation/init":
            return "/backend-api/conversation/{conversation_id}"
        if path.startswith("/backend-anon/conversation/") and path != "/backend-anon/conversation/init":
            return "/backend-anon/conversation/{conversation_id}"
        return path

    def _attach_openai_target_headers_for_url(self, url: str, headers: dict | None) -> dict | None:
        """
        自动补齐 HAR 中 chatgpt.com 前端 API 的 target 诊断头。

        NextAuth `/api/auth/*` 和 auth.openai.com JSON 接口在抓包中不带这些头，
        这里仅对 chatgpt.com 的 backend/ces 前端接口补齐，避免各调用点手动维护。
        """
        if headers is None:
            return headers
        try:
            parsed = urlparse(str(url))
        except Exception:
            return headers
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        if host != "chatgpt.com":
            return headers
        if not (path.startswith("/backend-api/") or path.startswith("/backend-anon/") or path.startswith("/ces/")):
            return headers
        # 不覆盖调用方显式指定的值，便于后续特殊接口单独调整。
        headers.setdefault("x-openai-target-path", path)
        headers.setdefault("x-openai-target-route", self._chatgpt_target_route(path))
        return headers

    def _raise_if_circuit_open(self) -> None:
        if self.blocked_until and time.time() < self.blocked_until:
            remain = max(0, int(self.blocked_until - time.time()))
            raise RuntimeError(f"当前 BrowserSession 已熔断冷却（剩余 {remain}s）：{self.blocked_reason}")

    def reset_circuit_breaker(self) -> None:
        """清理一次可选预热产生的本地熔断状态。

        某些 best-effort bootstrap 接口返回 403 时，不代表后续正式认证接口
        不可用；调用方完成错误隔离后可显式恢复本会话继续执行。
        """
        self.blocked_until = 0.0
        self.blocked_reason = ""

    @staticmethod
    def _parse_retry_after(value: str | None) -> int:
        if not value:
            return 0
        text = str(value).strip()
        if text.isdigit():
            return max(0, int(text))
        return 0

    def _observe_response_for_circuit_breaker(self, resp, url: str):
        status = int(getattr(resp, "status_code", 0) or 0)
        self._observe_cf_cookie_changes(url)
        if status not in (403, 429):
            return resp
        if is_cf_challenge_response(resp):
            # Cloudflare 挑战是出口 IP 的问题：换上游就能过。这里不熔断，
            # 否则刚换的 IP 也会被 900s 冷却一起挡掉（注册直接白烧邮箱）。
            logger.warning("[熔断] 跳过：%s 是 Cloudflare 挑战，交由换 IP 逻辑处理", url)
            return resp
        retry_after = self._parse_retry_after(getattr(resp, "headers", {}).get("retry-after") if getattr(resp, "headers", None) else None)
        cool_down = retry_after if retry_after > 0 else (300 if status == 429 else 900)
        self.blocked_until = max(self.blocked_until, time.time() + min(cool_down, 3600))
        self.blocked_reason = f"HTTP {status} from {url}"
        logger.warning("[熔断] 当前会话收到 HTTP %s，进入冷却 %ss，停止后续请求：%s", status, min(cool_down, 3600), url)
        return resp

    @staticmethod
    def _body_len(value) -> int:
        if value is None:
            return 0
        if isinstance(value, (bytes, bytearray, memoryview)):
            return len(value)
        if isinstance(value, str):
            return len(value.encode("utf-8", errors="replace"))
        try:
            return len(value)
        except Exception:
            return 0

    def _record_http_traffic(self, resp, *, upload_hint: int = 0, failed: bool = False) -> None:
        stats = getattr(self, "_traffic", None)
        if not isinstance(stats, dict):
            return
        stats["request_count"] = int(stats.get("request_count") or 0) + 1
        upload = max(0, int(upload_hint or 0))
        download = 0
        if resp is not None:
            # 只算「实际过线的字节」。原来用 len(resp.content)，那是 br/gzip 解压后的大小：
            # 实测登录页解压后 1.07 MB、真实下行只有 185 KiB（虚高 6 倍），整单虚高约 2.5 倍
            # （DB 记 2785 KiB，独立计量代理实测 793 KiB）。
            # curl_cffi 直接暴露 curl 的传输计数：response_size / request_size（真实过线字节，
            # 已含压缩与头部），优先用它们；取不到再退回 content-length，最后才退回 len(content)。
            try:
                download = 0
                try:
                    rs = getattr(resp, "response_size", None)
                    if isinstance(rs, int) and rs > 0:
                        download = rs
                except Exception:
                    download = 0
                if not download:
                    cl = None
                    try:
                        cl = (getattr(resp, "headers", {}) or {}).get("content-length")
                    except Exception:
                        cl = None
                    if cl is not None and str(cl).strip().isdigit():
                        download = int(str(cl).strip())
                if not download:
                    content = getattr(resp, "content", b"") or b""
                    download = len(content) if isinstance(content, (bytes, bytearray, memoryview)) else self._body_len(content)
            except Exception:
                download = 0
            header_len = 0
            # 走 response_size 时它已经包含响应头，不能再加一次 header_len。
            if not (isinstance(getattr(resp, "response_size", None), int) and getattr(resp, "response_size") > 0):
                try:
                    for key, value in (getattr(resp, "headers", {}) or {}).items():
                        header_len += len(str(key)) + len(str(value)) + 4
                except Exception:
                    header_len = 0
                download += header_len
            # 上传侧同理：用 curl 的真实 request_size（含请求头），否则退回 body 长度。
            try:
                rq = getattr(resp, "request_size", None)
                if isinstance(rq, int) and rq > 0:
                    upload = rq
            except Exception:
                pass
            status = int(getattr(resp, "status_code", 0) or 0)
            if 200 <= status < 400:
                stats["completed_request_count"] = int(stats.get("completed_request_count") or 0) + 1
            else:
                stats["failed_request_count"] = int(stats.get("failed_request_count") or 0) + 1
        elif failed:
            stats["failed_request_count"] = int(stats.get("failed_request_count") or 0) + 1
        stats["upload_bytes"] = int(stats.get("upload_bytes") or 0) + upload
        stats["download_bytes"] = int(stats.get("download_bytes") or 0) + download

    def network_traffic_snapshot(self) -> dict:
        stats = dict(getattr(self, "_traffic", {}) or {})
        upload = int(stats.get("upload_bytes") or 0)
        download = int(stats.get("download_bytes") or 0)
        return {
            "available": True,
            "source": "protocol",
            "upload_bytes": upload,
            "download_bytes": download,
            "total_bytes": upload + download,
            "http_upload_bytes": upload,
            "http_download_bytes": download,
            "websocket_upload_bytes": 0,
            "websocket_download_bytes": 0,
            "request_count": int(stats.get("request_count") or 0),
            "completed_request_count": int(stats.get("completed_request_count") or 0),
            "failed_request_count": int(stats.get("failed_request_count") or 0),
            "unfinished_request_count": 0,
            "unknown_size_request_count": 0,
        }

    def get(self, url: str, headers: dict = None, **kwargs):
        """发送 GET 请求"""
        self._raise_if_circuit_open()
        headers = self._attach_openai_target_headers_for_url(url, headers)
        upload_hint = self._body_len(kwargs.get("data") or kwargs.get("json") or kwargs.get("content"))
        try:
            resp = self.session.get(url, headers=headers, **kwargs)
        except Exception:
            self._record_http_traffic(None, upload_hint=upload_hint, failed=True)
            raise
        self._record_http_traffic(resp, upload_hint=upload_hint)
        return self._observe_response_for_circuit_breaker(resp, url)

    def post(self, url: str, headers: dict = None, **kwargs):
        """发送 POST 请求"""
        self._raise_if_circuit_open()
        headers = self._attach_openai_target_headers_for_url(url, headers)
        upload_hint = self._body_len(kwargs.get("data") or kwargs.get("json") or kwargs.get("content"))
        try:
            resp = self.session.post(url, headers=headers, **kwargs)
        except Exception:
            self._record_http_traffic(None, upload_hint=upload_hint, failed=True)
            raise
        self._record_http_traffic(resp, upload_hint=upload_hint)
        return self._observe_response_for_circuit_breaker(resp, url)
