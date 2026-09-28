# -*- coding: utf-8 -*-
"""wreq 后端 —— 用 Rust 的浏览器模拟层替换 curl_cffi（TLS / HTTP2 指纹）

── 为什么非换不可 ──
Cloudflare 判的是「TLS 指纹」和「请求里声称的 Chrome 版本」是否一致。实测
（同一个 200 端口池，随机取 IP，每组 8 次打 create-account/password）：

    TLS 142 + 声称 142    过闸 8/8      <- curl_cffi 时代唯一能过的组合
    TLS 146 + 声称 146    过闸 1/8
    TLS 136 + 声称 136    过闸 0/8
    TLS 142 + 声称 152    过闸 0/6
    TLS 142 + 声称 146    过闸 1/6

curl_cffi 0.16 内置档位**最高只到 chrome146**，也就是说「一致」最多只能停在 146。
可 146 拿不到 Plus 试用（试用率明显掉）。于是成了死结：

    声称 142  ->  过得了闸，但没有试用
    声称 152  ->  有试用，但过不了闸

wreq（0x676e67，Rust 重写，跟上游更紧）把档位提到了 Chrome153。实测过闸：

    Chrome153  5/5        Chrome152  4/5
    Chrome146  1/5        Chrome142  1/5

死结解开：TLS 和声称版本可以**同时**落在 15x。

── 与 curl_cffi 的行为差异（全部实测过，逐条在这里抹平）──
 1. 默认**不跟随跳转** -> 构造时给 redirect=Policy.limited(30)
 2. 逐请求 allow_redirects=False -> redirect=Policy.none()
 3. params= 被**静默忽略**（不报错、直接丢）-> 自己 urlencode 拼进 URL
 4. timeout= 只收 datetime.timedelta，给 int 会 TypeError -> 自动转换
 5. 响应是 r.status / r.text() / r.bytes()，不是 .status_code / .text
 6. r.headers 是 HeaderMap：.get() 返回 **bytes**、没有 .items()、要 list(H) 取对
 7. r.cookies 是 list[Cookie]，不是 RequestsCookieJar
 8. 异常是 wreq.exceptions.*，消息里没有 curl 的 curl: (35) 标记
 9. cookie_jar 只在 cookie_store=True 时存在；Jar.add/get 都要带 url
10. stream=True **确实生效**（正文延迟下载，实测 1.64s -> 0.73s），但必须原样
    透传；读 .text()/.bytes() 只会拿到已缓冲的一小段 —— 与 curl_cffi 的「stream=True
    时 .text 恒为空」是同一个用法约定，调用方本来就只在不要正文时用它
11. Client 构造期的 proxy= / proxies= **静默无效**（照样直连），代理只能逐请求传
    —— 这条最阴：不报错、请求还成功，只是出口 IP 是本机
12. data= / content= 也是**静默丢弃**的 —— body 直接空着发出去。只有 form=（urlencoded）
    和 body=（原始字节）真的会发。适配层把 data=dict 翻成 form=、data=str/bytes 翻成 body=
13. json= 的紧凑格式与 curl_cffi **逐字节一致**，不用翻译

── 有意不做的两件事 ──
* 不接 tls_fp / akamai_fp（协议机那套「每个会话随机 JA3」）：wreq 的 emulation
  档位内部是自洽的，往里掺随机 JA3 恰恰是把 CF 逼出来的原因 —— curl_cffi 时代
  的 142/142 之所以稳，就是因为那一档没人乱改。
* 不改调用方一行代码：接口对齐 curl_cffi，靠 install() 打补丁。
"""
from __future__ import annotations

import datetime
import logging
import os
import re
import sys
import time
from typing import Any, Optional
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

try:
    import wreq  # type: ignore

    _HAS_WREQ = True
except ImportError:  # pragma: no cover
    wreq = None  # type: ignore
    _HAS_WREQ = False

# 从 http_client 复用流量计量（按 URL 明细），两边共用同一个 TRAFFIC 字典
try:
    from http_client import _account_traffic, TRAFFIC  # noqa: E402
except Exception:  # pragma: no cover
    TRAFFIC = {"total": 0, "requests": 0, "by_key": {}}

    def _account_traffic(*_a, **_kw):  # type: ignore
        return None


# ── 配置（全部可用环境变量覆盖）──────────────────────────────────────────
_DEFAULT_EMULATION = (os.environ.get("TURB_WREQ_EMULATION", "") or "Chrome152").strip()
_REDIRECT_LIMIT = int(os.environ.get("TURB_WREQ_MAX_REDIRECTS", "30") or 30)
_RETRIES = int(os.environ.get("TURB_WREQ_RETRIES", "2") or 2)
_BACKOFF = float(os.environ.get("TURB_WREQ_BACKOFF", "1.5") or 1.5)
_DEFAULT_TIMEOUT = float(os.environ.get("TURB_WREQ_TIMEOUT", "30") or 30)

# 链路级瞬断才重试 —— 与 curl_cffi 那层 _TlsRetrySession 同一口径：
# 服务端明确拒绝（403/409）绝不能重试，否则反而更像异常流量。
_RETRY_EXC = {"ConnectionError", "TimeoutError", "ConnectionResetError",
              "TlsError", "ProxyConnectionError"}
_NO_RETRY_EXC = {"StatusError", "DecodingError", "RedirectError", "BodyError",
                 "BuilderError"}
_RETRY_MARKERS = ("is_connect", "timed out", "timeout", "tls", "handshake",
                  "connection reset", "unexpected eof", "broken pipe",
                  "certificate", "proxy")


def _is_retryable(exc: Exception) -> bool:
    name = type(exc).__name__
    if name in _NO_RETRY_EXC:
        return False
    if name in _RETRY_EXC:
        return True
    msg = str(exc).lower()
    return any(m in msg for m in _RETRY_MARKERS)


def _td(seconds: Any) -> datetime.timedelta:
    """wreq 的 timeout 只收 timedelta，给 int 直接 TypeError。"""
    if isinstance(seconds, datetime.timedelta):
        return seconds
    try:
        s = float(seconds)
    except Exception:
        s = _DEFAULT_TIMEOUT
    return datetime.timedelta(seconds=max(1.0, s))


def _normalize_proxy(proxy: Optional[str]) -> Optional[str]:
    """curl_cffi 在 SOCKS 下建议 socks5h（DNS 走代理端解析），wreq 同样。"""
    p = (proxy or "").strip()
    if not p:
        return None
    if p.startswith("socks5://"):
        return "socks5h://" + p[len("socks5://"):]
    if p.startswith("socks4://"):
        return "socks4a://" + p[len("socks4://"):]
    return p


def _with_params(url: str, params: Any) -> str:
    """wreq 把 params= 静默丢掉，所以自己拼（OAuth 全靠 query 传参）。"""
    if not params:
        return url
    try:
        items = params.items() if hasattr(params, "items") else params
        pairs = []
        for k, v in items:
            if isinstance(v, (list, tuple)):
                for x in v:
                    pairs.append((str(k), "" if x is None else str(x)))
            else:
                pairs.append((str(k), "" if v is None else str(v)))
        if not pairs:
            return url
        qs = urlencode(pairs)
    except Exception:
        return url
    return url + ("&" if "?" in url else "?") + qs


# curl_cffi 风格名 -> wreq Emulation
_ALIAS = {"chrome": "Chrome", "chromium": "Chrome", "safari": "Safari",
          "ios_safari": "SafariIos", "firefox": "Firefox", "edge": "Edge",
          "opera": "Opera", "okhttp": "OkHttp"}


def _emulation(name: Optional[str]):
    """把 impersonate 名映射到 wreq.Emulation。

    优先认 wreq 原生名（Chrome153），其次认 curl_cffi 名（chrome142 / safari18_0），
    都不认就用 TURB_WREQ_EMULATION。
    """
    if not _HAS_WREQ:
        return None
    n = (name or "").strip()
    if n and hasattr(wreq.Emulation, n):
        return getattr(wreq.Emulation, n)
    if n:
        m = re.match(r"^([a-z_]+?)[-_]?(\d+)(?:[._](\d+))?$", n.lower())
        if m:
            fam, major, minor = m.group(1), m.group(2), m.group(3)
            for cand in ("%s%s_%s" % (_ALIAS.get(fam, fam.title()), major, minor),
                         "%s%s" % (_ALIAS.get(fam, fam.title()), major)):
                if cand and hasattr(wreq.Emulation, cand):
                    return getattr(wreq.Emulation, cand)
    return getattr(wreq.Emulation, _DEFAULT_EMULATION, None)


# ── Cookie 兼容层 ────────────────────────────────────────────────────────
class _CookieView:
    """对齐 curl_cffi 的 Cookie 对象（.name/.value/.domain/.path）。"""

    __slots__ = ("name", "value", "domain", "path", "secure", "http_only", "expires")

    def __init__(self, raw=None, **kw):
        def g(k, d=None):
            if raw is not None:
                return getattr(raw, k, d)
            return kw.get(k, d)
        self.name = str(g("name", "") or "")
        self.value = str(g("value", "") or "")
        self.domain = str(g("domain", "") or "")
        self.path = str(g("path", "/") or "/")
        self.secure = bool(g("secure", False))
        self.http_only = bool(g("http_only", False))
        self.expires = g("expires", None)

    def __repr__(self):
        return "<Cookie %s=%s domain=%s>" % (self.name, self.value[:24], self.domain or "-")

    def __str__(self):
        return self.name

    def __eq__(self, other):
        return isinstance(other, _CookieView) and (self.name, self.value) == (other.name, other.value)

    def __hash__(self):
        return hash((self.name, self.value))


class WreqCookies:
    """session.cookies 的兼容层。

    协议机在 session.cookies 上只用这几样（全量核对过 32 处调用）：
        get(name, default) / get_dict() / set(name, value, domain=) /
        迭代（要么 Cookie 对象要么裸名字，代码两种都兜）/ .jar（可迭代，取 .name/.value）

    真值仍在 wreq 自己的 RFC cookie jar 里（domain/path/secure/__Host- 前缀都由它管），
    这里只是每次请求后**镜像**一份扁平 name->Cookie，读的时候按名字拿。
    扁平命名空间跟 curl_cffi 的 .get() 行为一致 —— 协议机本来就为「按 domain 隔离
    拿不到」写了兜底，所以这样只会更宽松，不会更严。
    """

    def __init__(self, session):
        object.__setattr__(self, "_session", session)
        object.__setattr__(self, "_d", {})

    # -- 同步 ---------------------------------------------------------------
    def _sync(self) -> None:
        jar = self._session._jar()
        if jar is None:
            return
        try:
            allc = jar.get_all()
        except Exception:
            return
        d = object.__getattribute__(self, "_d")
        for c in allc or []:
            v = _CookieView(c)
            if v.name:
                d[v.name] = v

    # -- 读 -----------------------------------------------------------------
    def get(self, name, default=None):
        c = object.__getattribute__(self, "_d").get(str(name))
        return c.value if c is not None else default

    def get_dict(self):
        return {k: v.value for k, v in object.__getattribute__(self, "_d").items()}

    @property
    def jar(self):
        return list(object.__getattribute__(self, "_d").values())

    def keys(self):
        return list(object.__getattribute__(self, "_d").keys())

    def values(self):
        return list(object.__getattribute__(self, "_d").values())

    def items(self):
        return list(object.__getattribute__(self, "_d").items())

    def copy(self):
        return dict(object.__getattribute__(self, "_d"))

    # -- 写 -----------------------------------------------------------------
    def set(self, name, value, domain=None, path="/", **kw):
        name = str(name)
        view = _CookieView(name=name, value="" if value is None else str(value),
                           domain=str(domain or ""), path=str(path or "/"))
        object.__getattribute__(self, "_d")[name] = view
        jar = self._session._jar()
        if jar is None:
            return
        host = (view.domain or "chatgpt.com").lstrip(".")
        try:
            jar.add(wreq.Cookie(name=view.name, value=view.value,
                                domain=view.domain or None, path=view.path or "/"),
                    "https://%s/" % host)
        except Exception as exc:
            logger.debug("cookie 注入 wreq jar 失败（已留在镜像里）: %s", exc)

    def update(self, other):
        if hasattr(other, "items"):
            for k, v in other.items():
                self.set(k, v)
        elif hasattr(other, "get_dict"):
            for k, v in other.get_dict().items():
                self.set(k, v)

    def clear(self):
        object.__getattribute__(self, "_d").clear()
        jar = self._session._jar()
        if jar is not None:
            try:
                jar.clear()
            except Exception:
                pass

    # -- 容器协议 -----------------------------------------------------------
    def __iter__(self):
        return iter(list(object.__getattribute__(self, "_d").values()))

    def __len__(self):
        return len(object.__getattribute__(self, "_d"))

    def __contains__(self, name):
        return str(name) in object.__getattribute__(self, "_d")

    def __getitem__(self, name):
        return object.__getattribute__(self, "_d")[str(name)].value

    def __setitem__(self, name, value):
        self.set(name, value)

    def __delitem__(self, name):
        object.__getattribute__(self, "_d").pop(str(name), None)

    def __repr__(self):
        return "<WreqCookies %s>" % self.get_dict()


# ── 响应兼容层 ───────────────────────────────────────────────────────────
class _Headers:
    """HeaderMap -> 大小写不敏感的 str 视图（对齐 requests / curl_cffi）。

    wreq 的 HeaderMap：.get() 返回 bytes、没有 .items()、但 list(H) 能给 (k, v) 对、
    .get_all(k) 能给同名多值（Set-Cookie 就靠它）。
    """

    __slots__ = ("_raw", "_cache")

    def __init__(self, raw):
        self._raw = raw
        self._cache = None

    @staticmethod
    def _s(v):
        if v is None:
            return ""
        if isinstance(v, (bytes, bytearray)):
            return bytes(v).decode("utf-8", "replace")
        return str(v)

    def _pairs(self):
        if self._cache is not None:
            return self._cache
        out = []
        raw = self._raw
        if raw is not None:
            try:
                for item in list(raw):
                    try:
                        k, v = item
                    except Exception:
                        continue
                    out.append((self._s(k), self._s(v)))
            except Exception:
                out = []
        self._cache = out
        return out

    def get(self, key, default=None):
        try:
            v = self._raw.get(str(key))
        except Exception:
            v = None
        if v is None:
            lk = str(key).lower()
            for k, val in self._pairs():
                if k.lower() == lk:
                    return val
            return default
        return self._s(v)

    def get_list(self, key, default=None):
        try:
            vals = self._raw.get_all(str(key))
        except Exception:
            vals = None
        if not vals:
            one = self.get(key, None)
            return [one] if one else (default if default is not None else [])
        return [self._s(v) for v in vals]

    # requests 的老名字
    getlist = get_list

    def items(self):
        return list(self._pairs())

    def keys(self):
        return [k for k, _ in self._pairs()]

    def values(self):
        return [v for _, v in self._pairs()]

    def to_dict(self):
        return {k: v for k, v in self._pairs()}

    def __getitem__(self, key):
        v = self.get(key, None)
        if v is None:
            raise KeyError(key)
        return v

    def __contains__(self, key):
        return self.get(key, None) is not None

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        return len(self._pairs())

    def __repr__(self):
        return "<Headers %s>" % self.to_dict()


class WreqResponse:
    """对齐 curl_cffi / requests 的响应对象。"""

    __slots__ = ("_raw", "_session", "_headers")

    def __init__(self, raw, session=None):
        self._raw = raw
        self._session = session
        self._headers = None

    @property
    def status_code(self) -> int:
        st = getattr(self._raw, "status", None)
        if st is None:
            return 0
        try:
            return int(st.as_int())
        except Exception:
            try:
                return int(str(st).split()[0])
            except Exception:
                return 0

    @property
    def text(self) -> str:
        try:
            return self._raw.text() or ""
        except Exception:
            try:
                return self._raw.bytes().decode("utf-8", "replace")
            except Exception:
                return ""

    @property
    def content(self) -> bytes:
        try:
            return self._raw.bytes()
        except Exception:
            return self.text.encode("utf-8", "replace")

    def json(self, **kw):
        import json as _json
        return _json.loads(self.text, **kw)

    @property
    def headers(self):
        if self._headers is None:
            self._headers = _Headers(getattr(self._raw, "headers", None))
        return self._headers

    @property
    def cookies(self):
        out = []
        try:
            for c in getattr(self._raw, "cookies", None) or []:
                out.append(_CookieView(c))
        except Exception:
            pass
        return out

    @property
    def url(self) -> str:
        try:
            return str(self._raw.url)
        except Exception:
            return ""

    @property
    def ok(self) -> bool:
        return self.status_code < 400

    @property
    def history(self):
        try:
            return list(getattr(self._raw, "history", None) or [])
        except Exception:
            return []

    @property
    def encoding(self) -> str:
        return "utf-8"

    @property
    def reason(self) -> str:
        try:
            s = str(self._raw.status)
            return s.split(" ", 1)[1] if " " in s else ""
        except Exception:
            return ""

    def raise_for_status(self):
        try:
            self._raw.raise_for_status()
        except Exception as exc:
            if type(exc).__name__ == "StatusError":
                raise RuntimeError("HTTP %d: %s" % (self.status_code, self.url)) from exc
            raise

    def close(self):
        try:
            self._raw.close()
        except Exception:
            pass

    def __repr__(self):
        return "<WreqResponse %d %s>" % (self.status_code, self.url[:80])


# ── 会话 ─────────────────────────────────────────────────────────────────
class WreqSession:
    """curl_cffi Session 的替代品（只实现协议机真正用到的那部分）。

    用到的方法/属性（全量核对过）：get / post / put / cookies / headers /
    trust_env / proxies / mount —— 就这些。
    """

    def __init__(self, proxy: Optional[str] = None, impersonate: Optional[str] = None,
                 user_agent: Optional[str] = None, timeout: Any = None,
                 retries: Optional[int] = None):
        if not _HAS_WREQ:
            raise RuntimeError("wreq 未安装：pip install wreq")
        self._proxy_url = _normalize_proxy(proxy)
        self._impersonate = impersonate or _DEFAULT_EMULATION
        self._emulation = _emulation(self._impersonate)
        self._timeout = float(timeout) if timeout else _DEFAULT_TIMEOUT
        self._retries = _RETRIES if retries is None else max(0, int(retries))
        self._headers: dict = {}
        if user_agent:
            self._headers["user-agent"] = str(user_agent)
        self.trust_env = False
        self._client = None
        self._proxy_obj = None
        self.cookies = WreqCookies(self)
        self._build()

    # -- 构建 / 重建 --------------------------------------------------------
    def _build(self) -> None:
        kw = {
            "emulation": self._emulation,
            "timeout": _td(self._timeout),
            "cookie_store": True,
            "redirect": wreq.redirect.Policy.limited(_REDIRECT_LIMIT),
        }
        if self._headers:
            kw["headers"] = dict(self._headers)
        # ⛔ 千万别在这里给 proxy=：wreq 的 Client 构造期**静默忽略** proxy/proxies，
        #    实测 Client(proxy=Proxy.all(...)) 打 httpbin.org/ip 回的还是本机出口 IP
        #    （223.104.151.162 = 直连），只有逐请求传才真的走代理
        #    （同一端口逐请求传 -> 14.162.164.179 = 代理出口）。所以代理只在 _call 里给。
        self._client = wreq.blocking.Client(**kw)
        self._proxy_obj = wreq.Proxy.all(self._proxy_url) if self._proxy_url else None
        logger.debug("wreq 会话已建：emulation=%s proxy=%s",
                     self._impersonate, self._proxy_url or "-")

    def _jar(self):
        try:
            return self._client.cookie_jar if self._client is not None else None
        except Exception:
            return None

    @property
    def proxies(self):
        return {"http": self._proxy_url or "", "https": self._proxy_url or ""}

    @proxies.setter
    def proxies(self, value):
        new = None
        if isinstance(value, dict):
            new = value.get("https") or value.get("http") or None
        elif isinstance(value, str):
            new = value or None
        new = _normalize_proxy(new)
        if new != self._proxy_url:
            self._proxy_url = new
            try:
                self._client.close()
            except Exception:
                pass
            self._build()

    @property
    def headers(self):
        return self._headers

    @headers.setter
    def headers(self, value):
        self._headers = dict(value or {})
        try:
            self._client.close()
        except Exception:
            pass
        self._build()

    def mount(self, *_a, **_kw):
        return None

    def close(self):
        try:
            self._client.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False

    # -- 请求 ---------------------------------------------------------------
    def _prepare(self, url, kw):
        kw = dict(kw)
        params = kw.pop("params", None)
        if params:
            url = _with_params(url, params)
        allow = kw.pop("allow_redirects", True)
        # ⚠️ stream=True **必须原样透传给 wreq**，绝不能丢。
        #    实测（httpbin 1 MiB 端点）：plain GET 1.64s vs stream=True 0.73s，
        #    且 r.bytes()/r.text() 只拿到已缓冲的一小段（102400 / 97010 字节）——
        #    说明正文**根本没下载**，要 .stream() 迭代或读完才会拉。
        #    协议机有 4 处靠它省正文：auth_oauth_init 那一跳要吞掉 auth.openai.com
        #    整页（实测 ~453 KiB），另外三处是 chatgpt.com 首页（~442 KiB）。
        #    丢掉这个参数 = 单号白多下 ~1 MiB。
        kw.pop("verify", None)
        kw.pop("cert", None)
        kw.pop("files", None)       # 协议机不用 multipart

        # ⛔ wreq 的 data= / content= 是**静默丢弃**的 —— 不报错、请求照发、body 是空的。
        #    实测（httpbin 回显）：
        #        data=dict   -> form={} data=''
        #        data=str    -> form={} data=''
        #        data=bytes  -> form={} data=''
        #        content=b   -> form={} data=''
        #        form=dict   -> form={'callbackUrl': '/', ...}   ✅
        #        body=str    -> data='callbackUrl=%2F&...'       ✅
        #    curl_cffi 里 data=dict 走 x-www-form-urlencoded，所以这里翻成 form=。
        #    这就是 10 并发那轮 0/10 的真因：signin 的 csrfToken 没发出去 -> 空响应
        #    -> resp.json() 抛 Expecting value: line 1 column 1 (char 0)。
        req_body = None
        if "data" in kw:
            _d = kw.pop("data")
            req_body = _d
            if _d is None:
                pass
            elif hasattr(_d, "items"):
                kw["form"] = [(str(k), "" if v is None else str(v)) for k, v in _d.items()]
            else:
                kw["body"] = _d
        if "content" in kw:
            _c = kw.pop("content")
            req_body = _c
            if _c is not None:
                kw["body"] = _c
        if kw.get("json") is not None:
            req_body = kw["json"]
            # json= 不用翻译：实测 wreq 的紧凑格式与 curl_cffi **逐字节一致**
            #   curl_cffi {"username":{"value":"...","kind":"email"},"screen_hint":"signup"}
            #   wreq      {"username":{"value":"...","kind":"email"},"screen_hint":"signup"}

        to = kw.pop("timeout", None)
        kw["timeout"] = _td(to if to is not None else self._timeout)
        kw["redirect"] = (wreq.redirect.Policy.limited(_REDIRECT_LIMIT) if allow
                          else wreq.redirect.Policy.none())
        hdrs = dict(self._headers)
        extra = kw.pop("headers", None)
        if extra:
            hdrs.update({str(k): str(v) for k, v in dict(extra).items()})
        if hdrs:
            kw["headers"] = hdrs
        return url, kw, req_body

    def _call(self, method: str, url: str, **kw):
        url, kw, req_body = self._prepare(url, kw)
        if self._proxy_obj is not None:
            kw["proxy"] = self._proxy_obj
        fn = getattr(self._client, method)
        last = None
        for attempt in range(self._retries + 1):
            try:
                raw = fn(url, **kw)
                self.cookies._sync()
                resp = WreqResponse(raw, self)
                try:
                    # ⚠️ stream=True 的响应不能碰 .content —— 一碰就把刚省下的
                    #    正文又拉回来了。这类响应只计头（与 curl_cffi 那层同一口径）。
                    if kw.get("stream"):
                        _account_traffic(method, url, resp=None, req_body=req_body)
                        try:
                            TRAFFIC["total"] += sum(
                                len(k) + len(v) + 4 for k, v in resp.headers.items())
                        except Exception:
                            pass
                    else:
                        _account_traffic(method, url, resp=resp, req_body=req_body)
                except Exception:
                    pass
                return resp
            except Exception as exc:
                last = exc
                if not _is_retryable(exc) or attempt >= self._retries:
                    raise
                wait = _BACKOFF * (attempt + 1)
                logger.warning("链路瞬断，%.1fs 后原会话重试 (%d/%d): %s | %s",
                               wait, attempt + 1, self._retries,
                               str(url)[:80], str(exc)[:120])
                time.sleep(wait)
        raise last  # pragma: no cover

    def get(self, url, **kw):
        return self._call("get", url, **kw)

    def post(self, url, **kw):
        return self._call("post", url, **kw)

    def put(self, url, **kw):
        return self._call("put", url, **kw)

    def head(self, url, **kw):
        return self._call("head", url, **kw)

    def delete(self, url, **kw):
        return self._call("delete", url, **kw)

    def patch(self, url, **kw):
        return self._call("patch", url, **kw)

    def request(self, method, url, **kw):
        return self._call(str(method).lower(), url, **kw)

    def __repr__(self):
        return "<WreqSession %s proxy=%s>" % (self._impersonate, self._proxy_url or "-")


# ── 工厂 + 打补丁 ────────────────────────────────────────────────────────
def create_http_session(proxy: Optional[str] = None, impersonate: str = "chrome152",
                        user_agent: Optional[str] = None, tls_fp: Optional[dict] = None,
                        akamai_fp: Optional[str] = None, **_kw):
    """与 http_client.create_http_session 同签名。

    tls_fp / akamai_fp 有意忽略 —— 见文件头「有意不做的两件事」。
    """
    return WreqSession(proxy=proxy, impersonate=impersonate, user_agent=user_agent)


def install(force: bool = False) -> bool:
    """把 http_client.create_http_session 换成 wreq 后端。

    ⚠️ 必须**同时**改所有已经 from http_client import create_http_session 过的模块，
    否则那些模块手里还是旧函数对象的引用（auth_flow 就是这么导入的）。

    开关：TURB_HTTP_ENGINE=wreq（默认）/ curl_cffi（回退老路）。
    """
    if not _HAS_WREQ:
        sys.stderr.write("[wreq] 未安装，继续用 curl_cffi\n")
        return False
    engine = (os.environ.get("TURB_HTTP_ENGINE", "") or "wreq").strip().lower()
    if engine not in ("wreq", "wreq-blocking") and not force:
        sys.stderr.write("[wreq] TURB_HTTP_ENGINE=%s，保持 curl_cffi\n" % engine)
        return False
    try:
        import http_client
    except Exception as exc:
        sys.stderr.write("[wreq] 加载 http_client 失败: %s\n" % exc)
        return False

    old = getattr(http_client, "create_http_session", None)
    http_client.create_http_session = create_http_session
    patched = ["http_client"]
    for name, mod in list(sys.modules.items()):
        if mod is None or mod is http_client:
            continue
        try:
            if old is not None and getattr(mod, "create_http_session", None) is old:
                setattr(mod, "create_http_session", create_http_session)
                patched.append(name)
        except Exception:
            continue
    sys.stderr.write("[wreq] HTTP 层已切到 wreq（emulation=%s），补丁模块: %s\n"
                     % (_DEFAULT_EMULATION, ", ".join(patched)))
    return True
