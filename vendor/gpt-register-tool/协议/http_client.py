"""
HTTP 客户端 - 使用 curl_cffi 实现 TLS 指纹模拟
支持 Cloudflare 绕过，降级到 requests
"""
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# 尝试使用 curl_cffi（推荐，自带 TLS 指纹模拟）
try:
    from curl_cffi.requests import Session as CffiSession

    _HAS_CFFI = True
    logger.debug("curl_cffi 可用，使用 TLS 指纹模拟")
except ImportError:
    _HAS_CFFI = False
    logger.debug("curl_cffi 不可用，降级到 requests")

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 通用 UA（fallback，优先使用 fingerprint.generate_fingerprint() 生成的值）
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
)

# TLS 握手瞬断的识别标记（与 AuthFlow._is_tls_error 保持同一套口径）
_TLS_ERROR_MARKERS = ("curl: (35)", "tls connect error", "openssl_internal", "sslerror")


# ---------------------------------------------------------------------------
# 流量计量（按 URL 明细）
#
# 之前协议机完全没有流量统计，只能靠外部（代理中继）看到总量，没法定位是哪个
# 请求在烧流量。这里在 session 层记录每次请求/响应的字节数（响应正文 + 头 +
# 请求正文 + 头），按「host + path 模板」归并。
#
# 用途：优化流量时先看这份明细，找出真正的大头（例如误下载 SPA bundle）。
# 开关：环境变量 TRAFFIC_LOG=1 时，进程退出前由调用方 dump_traffic() 打印。
# ---------------------------------------------------------------------------
TRAFFIC: dict = {"total": 0, "requests": 0, "by_key": {}}


def _traffic_key(method: str, url: str) -> str:
    """把 URL 归并成 host + 去掉可变段的 path。"""
    try:
        from urllib.parse import urlsplit
        u = urlsplit(str(url))
        path = u.path
        # 把明显的 id 段折叠，避免每个账号开一行
        import re as _re
        path = _re.sub(r"/[0-9a-fA-F-]{16,}", "/<id>", path)
        return "%s %s%s" % (method.upper(), u.netloc, path)
    except Exception:
        return "%s %s" % (method.upper(), str(url)[:80])


def _account_traffic(method: str, url: str, resp=None, req_body=None) -> None:
    """记一笔流量。字节数 = 响应正文 + 响应头 + 请求正文 + 请求头。"""
    try:
        n = 0
        body_in = body_out = hdr_out = 0
        if resp is not None:
            try:
                body_in = len(resp.content or b"")
            except Exception:
                body_in = len((getattr(resp, "text", "") or "").encode("utf-8", "replace"))
            try:
                hdrs = getattr(resp, "headers", None)
                if hdrs is not None:
                    hdr_out = sum(len(str(k)) + len(str(v)) + 4 for k, v in hdrs.items())
                    # ⛔ 2026-09-24 调试：某些请求的响应头高达 9~13 KiB（占了那条
                    #    请求的 90%+），明显不正常 —— 大概率是一串重复的 Set-Cookie。
                    #    头超过 8 KiB 就把明细写到 %TEMP%\turb_big_headers.txt。
                    if hdr_out > 8192 and os.environ.get("TURB_DUMP_HEADERS", "1") != "0":
                        try:
                            import os as _os, time as _t
                            _p = _os.path.join(_os.environ.get("TEMP") or "/tmp", "turb_big_headers.txt")
                            with open(_p, "a", encoding="utf-8") as _f:
                                _f.write("\n===== %s %s  hdr=%d bytes  %s =====\n"
                                         % (method.upper(), str(url)[:110], hdr_out, _t.strftime("%H:%M:%S")))
                                for _k, _v in hdrs.items():
                                    _f.write("  %s: %s\n" % (_k, str(_v)[:400]))
                        except Exception:
                            pass
            except Exception:
                pass
            n += body_in + hdr_out
        if req_body:
            body_out = len(req_body if isinstance(req_body, (bytes, bytearray))
                           else str(req_body).encode("utf-8", "replace"))
            n += body_out
        k = _traffic_key(method, url)
        TRAFFIC["total"] += n
        TRAFFIC["requests"] += 1
        slot = TRAFFIC["by_key"].setdefault(k, {"bytes": 0, "n": 0})
        slot["bytes"] += n
        slot["n"] += 1
        # ── 请求侧 / 响应侧拆开记 ──
        # 2026-09-24：单号 377 KiB 里 sentinel 占了 166 KiB（2.7 次，每次 ~61 KiB），
        # 这个量级不正常 —— 必须知道 61 KiB 是**响应正文**（challenge 里夹带 sdk.js）
        # 还是**请求正文**（PoW 太长）。只看总数没法优化，所以拆成四段。
        slot["body_in"] = slot.get("body_in", 0) + body_in     # 响应正文
        slot["hdr_out"] = slot.get("hdr_out", 0) + hdr_out     # 响应头
        slot["body_out"] = slot.get("body_out", 0) + body_out  # 请求正文
    except Exception:
        pass


def dump_traffic(top: int = 30) -> str:
    """返回可打印的流量明细（按字节降序）。"""
    rows = sorted(TRAFFIC["by_key"].items(), key=lambda kv: -kv[1]["bytes"])[:top]
    out = ["总流量 %.1f KiB / %d 次请求" % (TRAFFIC["total"] / 1024.0, TRAFFIC["requests"])]
    for k, v in rows:
        out.append("  %8.1f KiB  x%-3d  %s" % (v["bytes"] / 1024.0, v["n"], k))
    return "\n".join(out)


def _is_tls_handshake_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(m in msg for m in _TLS_ERROR_MARKERS)


class _TlsRetrySession:
    """给 session 的 get/post 套一层 TLS 瞬断重试，其余属性原样透传。

    ── 为什么要有这东西 ──
    代理链路会偶发 `curl: (35) TLS connect error ... OPENSSL_internal`，
    连 HTTP 请求都没发出去就炸。2026-08-10 实测（148 轮扫描）：

        发生率            5.4%（8/148）
        与指纹的关系      无 —— chrome146/142/136、safari18_0/15_3、firefox133 都中过
        与域名的关系      无 —— chatgpt.com 3/25、auth.openai.com 1/25，
                          且见过同一轮两个域一起炸（那一路出口链路整个坏了）

    换句话说这是**链路级瞬断**，不是风控、不是指纹问题，摘掉任何一个指纹都没用。

    ── 为什么必须原 session 重试，不能重建 ──
    warmup 那处的重试是重建 session（换出口 IP），因为那时还没 cookie。
    但链路中后段（auth_oauth_init / sentinel / authorize_continue …）session 里
    已经装着 warmup 种的 oai-did 和 csrf，**一重建就全丢，直接变 409 invalid_state**
    —— 那正是上一轮刚修好的病。所以这里只重试，绝不碰 session。

    实测原 session 重试的效果（8 次 TLS35 事件全部捕获后立即重试）：

        恢复 8/8，全部**第 1 次重试就成功**，恢复后 oai-did 仍在 8/8

    ── 为什么包在 session 层，而不是逐个调用点加 try ──
    这个错能打在链上**任意一步**。主人 2026-08-10 那批 10 个号的两次失败就分别
    炸在 `[3/10] auth_oauth_init` 和 `[4/10] sentinel`（后者还被 sentinel_quickjs
    的 catch-all 吞成 "QuickJS 失败/主 token 缺失"，真因全被掩盖）。auth_flow 里
    有 35 处 session.get/post，且 sentinel.py 是直接拿 session 对象自己发请求的，
    逐点打补丁既治不完也漏得到 —— 包在出口这一层才是一次覆盖全部。

    ── 透传安全性（已实测）──
    全项目在 session 上访问的非 get/post 属性只有 cookies(20处) / trust_env(3) /
    proxies(3) / mount(2) / headers(1)，实测包装后全部行为一致：
    cookies.get_dict() / cookies.get() / cookies.jar / 迭代 / __setattr__ 透传均 OK。
    （注：迭代 session.cookies 产出的是 str 而非 Cookie 对象、拿不到 .name，
    这是 curl_cffi **原生行为**，包装前后一致，与本类无关。）
    """

    def __init__(self, inner, retries: int = 2, backoff: float = 1.5):
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "_retries", max(0, int(retries)))
        object.__setattr__(self, "_backoff", float(backoff))

    # 除 get/post 外的一切读写都直达真 session
    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_inner"), name)

    def __setattr__(self, name, value):
        setattr(object.__getattribute__(self, "_inner"), name, value)

    def __iter__(self):
        return iter(object.__getattribute__(self, "_inner"))

    def _call_with_retry(self, method: str, *args, **kwargs):
        import time

        inner = object.__getattribute__(self, "_inner")
        retries = object.__getattribute__(self, "_retries")
        backoff = object.__getattribute__(self, "_backoff")
        fn = getattr(inner, method)

        for attempt in range(retries + 1):
            try:
                resp = fn(*args, **kwargs)
                try:
                    # ⚠️ stream=True 的响应不能碰 .content —— 一碰就触发下载，
                    # 反而把我们要省的流量又拉回来了。这类响应只计头。
                    _streamed = bool(kwargs.get("stream"))
                    _account_traffic(method, args[0] if args else kwargs.get("url", "?"),
                                     resp=None if _streamed else resp,
                                     req_body=kwargs.get("data") or kwargs.get("json"))
                    if _streamed:
                        try:
                            _hdrs = getattr(resp, "headers", None)
                            if _hdrs is not None:
                                TRAFFIC["total"] += sum(
                                    len(str(k)) + len(str(v)) + 4 for k, v in _hdrs.items())
                        except Exception:
                            pass
                except Exception:
                    pass
                return resp
            except Exception as e:
                # 只兜 TLS 瞬断：HTTP 错误码、超时、业务异常一律原样抛，
                # 免得把"服务端明确拒绝"也变成重试，反而更像异常流量。
                if not _is_tls_handshake_error(e) or attempt >= retries:
                    raise
                wait = backoff * (attempt + 1)
                url = args[0] if args else kwargs.get("url", "?")
                logger.warning(
                    "TLS 瞬断，%.1fs 后原 session 重试 (%d/%d): %s",
                    wait, attempt + 1, retries, str(url)[:80],
                )
                time.sleep(wait)

    def get(self, *args, **kwargs):
        return self._call_with_retry("get", *args, **kwargs)

    def post(self, *args, **kwargs):
        return self._call_with_retry("post", *args, **kwargs)

    def put(self, *args, **kwargs):
        return self._call_with_retry("put", *args, **kwargs)


def create_http_session(
    proxy: Optional[str] = None,
    impersonate: str = "safari18_0",
    user_agent: Optional[str] = None,
    tls_fp: Optional[dict] = None,
    akamai_fp: Optional[str] = None,
):
    """
    创建 HTTP 会话。优先使用 curl_cffi 模拟浏览器 TLS 指纹，
    不可用时降级到 requests。

    tls_fp: 来自 tls_fingerprint.unique_tls_fingerprint() 的 extra_fp 参数。
        传了就给本次会话换一套独有的 JA3/HTTP2；不传则沿用 curl_cffi
        内置 profile 的固定指纹（全球协议机共用，极易被整体拉黑）。
    """
    if _HAS_CFFI:
        _extra = None
        if tls_fp:
            try:
                from tls_fingerprint import merge_extra_fp
                _extra = merge_extra_fp(tls_fp)
            except Exception:
                _extra = {k: v for k, v in tls_fp.items() if not k.startswith("_")} or None
        _kw = {}
        if _extra:
            _kw["extra_fp"] = _extra
        if akamai_fp:
            # HTTP/2 指纹（Akamai）。不传则用 curl_cffi 内置 profile 的固定值，
            # 那是全球协议机共用的 52d84b11737d980aef85，已被整体拉黑。
            _kw["akamai"] = akamai_fp
        session = CffiSession(impersonate=impersonate, **_kw) if _kw \
            else CffiSession(impersonate=impersonate)
        # 使用显式配置，避免被系统 HTTP(S)_PROXY 隐式污染。
        session.trust_env = False
        if proxy:
            # curl_cffi 在 SOCKS 代理下建议使用 socks5h，让 DNS 走代理端解析。
            # 这能减少本地 DNS/链路导致的 TLS 握手异常。
            normalized_proxy = proxy
            if proxy.startswith("socks5://"):
                normalized_proxy = "socks5h://" + proxy[len("socks5://"):]
                logger.info("代理协议已标准化: socks5:// -> socks5h://")
            session.proxies = {"https": normalized_proxy, "http": normalized_proxy}
        else:
            # 显式设置空代理，覆盖系统环境变量 (trust_env=False 对 libcurl 不够)
            session.proxies = {"https": "", "http": ""}
        # 代理链路 5.4% 偶发 TLS 瞬断，原 session 重试实测 8/8 一次即恢复。
        # 包在这里才能同时覆盖 auth_flow 的 35 处调用和 sentinel（它直接拿 session 自己发请求）。
        return _TlsRetrySession(session)
    else:
        session = requests.Session()
        session.trust_env = False
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        if proxy:
            session.proxies = {"https": proxy, "http": proxy}
        session.headers["User-Agent"] = user_agent or USER_AGENT
        return session
