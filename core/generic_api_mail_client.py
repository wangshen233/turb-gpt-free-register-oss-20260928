# -*- coding: utf-8 -*-
"""
通用 API 取码邮箱客户端。

邮箱池导入格式：
    email----code_url

注册时领取 email；取码时直接 GET code_url，并从响应中提取 6 位验证码。
响应可以是纯文本、HTML 或 JSON，只要其中包含 6 位验证码即可。
"""
import json
import logging
import re
import time
import base64
import html as html_lib
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, unquote, urlparse, urlunparse, parse_qsl, urlencode

import requests

from config import email as _email_cfg
from config import proxy as _proxy_cfg
from core.otp_utils import extract_otp

logger = logging.getLogger(__name__)

_CODE_REGEX = re.compile(r"\b(\d{6})\b")
_CONTEXT_WORDS = ("code", "verify", "verification", "验证码", "代码", "确认码", "認証", "コード")
_CONTEXT_CACHE: dict[str, "GenericApiEmailAccount"] = {}
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ACCOUNTS_FILE = _PROJECT_ROOT / "用于注册的API邮箱.txt"
_YANGYANG_MESSAGES_RE = re.compile(r"/messages/([^/]+)/([^/?#]+)", re.IGNORECASE)
_PUBLIC_INBOX_LINK_RE = re.compile(r"^/i/([^/?#]+)/*$", re.IGNORECASE)
_PUBLIC_INBOX_API_RE = re.compile(
    r"^/api/public/inboxes/([^/?#]+)/latest-code/*$", re.IGNORECASE,
)
_YANGYANG_OPENAI_SUBJECT_HINTS = (
    "temporary chatgpt",
    "chatgpt verification code",
    "chatgpt login code",
    "临时 chatgpt",
    "chatgpt 登录代码",
    "chatgpt 验证码",
    "一時的な認証コード",
    "一時ログインコード",
)


class GenericApiMailError(RuntimeError):
    """通用 API 取码邮箱错误。"""


def _redact_proxy_url(proxy_url: str) -> str:
    """日志中保留代理地址和协议，但隐藏认证信息。"""
    raw = str(proxy_url or "").strip()
    if not raw:
        return "direct"
    try:
        parsed = urlparse(raw)
        if not parsed.hostname:
            return "configured-proxy"
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port else ""
        auth = "***@" if parsed.username or parsed.password else ""
        return f"{parsed.scheme}://{auth}{host}{port}"
    except Exception:
        return "configured-proxy"


def _new_http_session(proxy_url: str = "") -> requests.Session:
    """创建不继承系统代理的取码会话；传入代理时 HTTP/HTTPS 均走该代理。"""
    session = requests.Session()
    session.trust_env = False
    # 取码地址必须拿到"当前"验证码，不能吃中间缓存。部分取码源不接受任何
    # 额外 query 参数（见 _cache_busted_url），所以这里用请求头兜底。
    session.headers.update({"Cache-Control": "no-cache", "Pragma": "no-cache"})
    proxy_url = str(proxy_url or "").strip()
    if proxy_url:
        session.proxies.update({"http": proxy_url, "https": proxy_url})
    return session


# query 里出现这些键，说明凭据放在 query 上；再追加参数会被网关判成无效 key。
_AUTH_QUERY_KEYS = {"token", "key", "apikey", "api_key", "access_token", "auth", "secret"}


def _cache_busted_url(url: str, attempt: int) -> str:
    """给取码接口加缓存破坏参数，避免 CDN/反向代理一直返回上一封验证码。

    例外：有些网关（实测 icloud.tongsheep.cyou）把整个 query 当成 API Key 校验，
    追加任何参数都会回 401 INVALID_API_KEY —— 连 &x=1 都会。这类地址的 query 里
    通常带 token= 之类的凭据，此时原样返回，防缓存交给 no-cache 请求头。
    """
    try:
        parsed = urlparse(str(url))
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if {k.lower() for k, _ in query} & _AUTH_QUERY_KEYS:
            return url
        query.append(("_otp_poll", f"{int(time.time() * 1000)}-{attempt}"))
        return urlunparse(parsed._replace(query=urlencode(query)))
    except Exception:
        return url


@dataclass
class GenericApiEmailAccount:
    email: str
    code_url: str


def _public_inbox_latest_code_url(code_url: str) -> str | None:
    """把公开收件链接 /i/{token} 转成 /api/public/inboxes/{token}/latest-code。"""
    try:
        parsed = urlparse(str(code_url or "").strip())
    except Exception:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    match = _PUBLIC_INBOX_LINK_RE.match(parsed.path or "")
    if not match:
        # 也接受用户直接导入 latest-code API 地址。
        match = _PUBLIC_INBOX_API_RE.match(parsed.path or "")
    if not match:
        return None
    token = unquote(match.group(1)).strip()
    if not token or "/" in token:
        return None
    origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", "")).rstrip("/")
    return f"{origin}/api/public/inboxes/{quote(token, safe='')}/latest-code"


def _public_inbox_page_api_url(code_url: str) -> str | None:
    """返回公开收件页面实际使用的收件箱列表 API。"""
    latest_url = _public_inbox_latest_code_url(code_url)
    if not latest_url:
        return None
    return latest_url.rsplit("/latest-code", 1)[0]


def _fetch_public_inbox_page_otp(
    session: requests.Session,
    api_url: str,
    email: str,
    headers: dict,
    after_ts: float | None = None,
) -> tuple[str, dict] | None:
    """按 /i/{token} 页面使用的 inbox API，从最新邮件预览/正文提取验证码。"""
    resp = session.get(
        api_url,
        headers={**headers, "Accept": "application/json"},
        timeout=20,
        verify=False,
    )
    if resp.status_code != 200:
        logger.debug("[GenericAPI] public inbox 页面 API HTTP %s: %s", resp.status_code, (resp.text or "")[:160])
        return None
    try:
        data = resp.json()
    except Exception:
        try:
            data = json.loads(resp.text or "")
        except Exception:
            return None
    if not isinstance(data, dict):
        return None
    mailbox = data.get("mailbox") or {}
    actual_email = str(mailbox.get("address") if isinstance(mailbox, dict) else mailbox or "").strip()
    if actual_email and actual_email.lower() != email.lower():
        raise GenericApiMailError(
            f"公开收件链接邮箱不匹配: expected={email}, actual={actual_email}"
        )
    items = [x for x in (data.get("messages") or []) if isinstance(x, dict)]
    items.sort(
        key=lambda x: _parse_generic_api_ts(x.get("receivedAt") or x.get("received_at")) or 0,
        reverse=True,
    )
    origin = api_url.split("/api/public/inboxes/", 1)[0]
    token_path = api_url.split("/api/public/inboxes/", 1)[1].split("?", 1)[0].strip("/")
    for item in items:
        received_at = item.get("receivedAt") or item.get("received_at")
        msg_ts = _parse_generic_api_ts(received_at)
        if after_ts and msg_ts and msg_ts + 2 < after_ts:
            continue
        raw_codes = item.get("verificationCodes") or item.get("verification_codes") or []
        code = next(
            (m.group(1) for value in raw_codes if (m := _CODE_REGEX.search(str(value)))),
            None,
        )
        subject = str(item.get("subject") or "")
        preview = str(item.get("preview") or "")
        if not code:
            code = _extract_yangyang_openai_code(subject, preview)
        msg_id = str(item.get("id") or "").strip()
        # 页面列表预览仍未抽到时，读取页面点击邮件时使用的详情 API。
        if not code and msg_id:
            detail_url = (
                f"{origin}/api/public/inboxes/{quote(unquote(token_path), safe='')}"
                f"/messages/{quote(msg_id, safe='')}"
            )
            try:
                detail_resp = session.get(
                    detail_url,
                    headers={**headers, "Accept": "application/json"},
                    timeout=20,
                    verify=False,
                )
                if detail_resp.status_code == 200:
                    detail = detail_resp.json()
                    detail_text = "\n".join([
                        str(detail.get("subject") or subject),
                        str(detail.get("preview") or preview),
                        str(detail.get("textBody") or ""),
                        str(detail.get("htmlBody") or ""),
                    ])
                    code = _extract_yangyang_openai_code(subject, detail_text)
            except Exception as exc:
                logger.debug("[GenericAPI] public inbox 邮件详情读取失败: %s: %s", type(exc).__name__, exc)
        if code:
            return code, {
                "source": "public_inbox_page",
                "mail_id": msg_id,
                "received_at": received_at,
                "msg_ts": msg_ts,
                "subject": subject,
                "from": item.get("fromAddress") or item.get("sender"),
            }
    return None


def _flatten_json(obj) -> str:
    parts: list[str] = []
    def walk(x):
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        elif x is not None:
            parts.append(str(x))
    walk(obj)
    return "\n".join(parts)


_NESTED_CODE_LIST_KEYS = ("codes", "code_list", "otp_list", "verification_codes")
_NESTED_TEXT_KEYS = ("text", "body", "content", "html", "subject", "snippet", "preview")


def _iter_nested_dicts(node, depth: int = 0):
    """深度优先遍历嵌套 JSON，产出所有 dict 节点（限深，避免畸形响应打爆）。"""
    if depth > 8:
        return
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _iter_nested_dicts(value, depth + 1)
    elif isinstance(node, list):
        for item in node[:20]:
            yield from _iter_nested_dicts(item, depth + 1)


def _nested_message_code(data) -> tuple[str, dict] | None:
    """从嵌套的消息结构里取验证码。

    实测 mokeyun.icu 的返回体：

        {"data": {"alias": "a@icloud.com",
                  "expiresAt": 1789535466.297436,
                  "message": {"uid": 845,
                              "subject": "Mã xác minh tạm thời của bạn cho ChatGPT",
                              "date": 1789484508,
                              "text": "... để tiếp tục: 553159 ...",
                              "codes": ["553159"]}},
         "ok": true}

    顶层没有 code/otp 字段，而 **expiresAt 的小数部分 297436 恰好是 6 位数字**，
    会被 _extract_code(_flatten_json(...)) 当成验证码抓走。实测就是它导致一批
    40 个号里 38 个失败：提交错误验证码 → 服务端连续拒绝 → 页面退回邮箱输入页
    （表现为「找不到 OTP 输入框」）。

    所以这里显式优先读 codes 列表，其次读正文文本。
    """
    for node in _iter_nested_dicts(data):
        for key in _NESTED_CODE_LIST_KEYS:
            raw = node.get(key)
            if isinstance(raw, list):
                for item in raw:
                    m = _CODE_REGEX.search(str(item))
                    if m:
                        return m.group(1), node
            elif isinstance(raw, str):
                m = _CODE_REGEX.search(raw)
                if m:
                    return m.group(1), node
        for key in _NESTED_TEXT_KEYS:
            value = node.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            found = _extract_code(value)
            if found:
                return found, node
    return None


def _decode_data_uri(text: str) -> str:
    """把 data:text/html;base64,... 正文解码成可抽取 OTP 的 HTML/文本。"""
    if not isinstance(text, str):
        return ""
    if not text.startswith("data:"):
        return text
    try:
        _meta, payload = text.split(",", 1)
    except ValueError:
        return text
    if ";base64" in _meta.lower():
        try:
            return base64.b64decode(payload).decode("utf-8", errors="replace")
        except Exception:
            return text
    try:
        from urllib.parse import unquote_to_bytes
        return unquote_to_bytes(payload).decode("utf-8", errors="replace")
    except Exception:
        return text


# HTML 的 <style> 块和内联 style 属性会写十六进制颜色（#172033、#667085 ……），
# 这些都是 6 位数字，会被 _CODE_REGEX 当成验证码抓走。实测 api.wdmail.top 的
# **空收件箱**页面因此返回假码 667085 —— 提交必然 401。扫验证码前先清掉。
_STYLE_SCRIPT_RE = re.compile(r"<(style|script)\b[^>]*>.*?</\1>", re.DOTALL | re.IGNORECASE)
_HEX_COLOR_RE = re.compile(r"#[0-9a-fA-F]{6}\b")


def _strip_html_noise(text: str) -> str:
    """去掉 <style>/<script> 块和 #RRGGBB 颜色值，避免把 CSS 颜色当成验证码。"""
    if not text:
        return text
    out = _STYLE_SCRIPT_RE.sub(" ", text)
    return _HEX_COLOR_RE.sub(" ", out)


def _extract_code(text: str) -> str | None:
    """从纯文本/HTML/JSON 文本中提取 6 位 OTP。"""
    if not text:
        return None

    # 兼容 JSON：优先把所有 value 拉平再抽取。
    candidates_text = [_decode_data_uri(_strip_html_noise(text)), _strip_html_noise(text)]
    try:
        parsed = json.loads(text)
        candidates_text.insert(0, _decode_data_uri(_flatten_json(parsed)))
    except Exception:
        pass

    for body in candidates_text:
        # 复用邮件 OTP 抽取逻辑。
        code = extract_otp({"text": body, "content": body, "subject": body[:200]})
        if code:
            return code

        codes = _CODE_REGEX.findall(body)
        if not codes:
            continue
        lower = body.lower()
        for code in codes:
            idx = lower.find(code)
            window = lower[max(0, idx - 80): idx + 86]
            if any(w.lower() in window for w in _CONTEXT_WORDS):
                return code
        return codes[-1]
    return None


def _extract_yangyang_openai_code(subject: str, body: str) -> str | None:
    """
    yangyang 邮件详情里 OpenAI 模板常混入多个 6 位数字：
    - 202123 / 353740 这类 CSS/模板数字
    - 真正 OTP 在 “Your code is / code:” 附近，通常是正文最后一个业务 6 位数
    所以不能直接复用通用 _extract_code 的“第一个上下文命中”。
    """
    body = _decode_data_uri(body or "")
    subject_l = (subject or "").lower()
    text = "\n".join([subject or "", body])

    # 去掉 style/script，减少 CSS 颜色、宽高等 6 位数字干扰。
    clean = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r"<script[^>]*>.*?</script>", " ", clean, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r"#[0-9a-fA-F]{6}\b", " ", clean)
    clean = re.sub(r"(?:color|background|border|width|height|font-size|line-height)\s*:\s*[^;\"']+", " ", clean, flags=re.IGNORECASE)
    clean = re.sub(r"<[^>]+>", " ", clean)
    clean = re.sub(r"\s+", " ", clean).strip()

    codes = _CODE_REGEX.findall(clean)
    if not codes:
        return None

    # 过滤已知模板噪声；保留其它 6 位候选。
    noise = {"000000", "202123", "353740"}
    candidates = [c for c in codes if c not in noise]
    if not candidates:
        candidates = codes

    lower = clean.lower()
    patterns = (
        r"(?:code is|code:|verification code is|login code is|your code is)\D{0,80}(\d{6})",
        r"(?:验证码|驗證碼|登录代码|登入代碼|確認コード|認証コード|ログインコード)\D{0,80}(\d{6})",
        r"(\d{6})\D{0,80}(?:code|验证码|驗證碼|確認コード|認証コード)",
    )
    for pat in patterns:
        matches = re.findall(pat, clean, flags=re.IGNORECASE)
        matches = [m for m in matches if m not in noise]
        if matches:
            return matches[-1]

    # OpenAI 临时代码邮件：清理噪声后最后一个业务 6 位数最稳定。
    if any(h in subject_l for h in _YANGYANG_OPENAI_SUBJECT_HINTS) or "openai" in lower or "chatgpt" in lower:
        return candidates[-1]

    return _extract_code(clean)


def _parse_yangyang_code_url(code_url: str) -> tuple[str, str, str] | None:
    """
    解析 yangyang.website 这类邮箱页面：
        /messages/{token}/{email}
    返回 (origin, token, email)。
    """
    try:
        parsed = urlparse(code_url)
    except Exception:
        return None
    m = _YANGYANG_MESSAGES_RE.search(parsed.path or "")
    if not m:
        return None
    origin = urlunparse((parsed.scheme or "http", parsed.netloc, "", "", "", ""))
    token = unquote(m.group(1))
    email = unquote(m.group(2))
    if not origin or not token or not email:
        return None
    return origin.rstrip("/"), token, email


def _parse_yangyang_ts(value: str | None) -> float | None:
    if not value:
        return None
    raw = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(raw[:19], fmt).timestamp()
        except Exception:
            pass
    return None


def _parse_generic_api_ts(value) -> float | None:
    """解析通用 API 返回的时间字段，兼容 ISO8601/Z 和常见本地时间格式。"""
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    # 数字时间戳：秒 / 毫秒
    if re.fullmatch(r"\d+(?:\.\d+)?", raw):
        try:
            ts = float(raw)
            return ts / 1000.0 if ts > 10_000_000_000 else ts
        except Exception:
            return None
    # ISO8601: 2026-08-05T01:10:17.000Z
    try:
        iso = raw
        if iso.endswith("Z"):
            iso = iso[:-1] + "+00:00"
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            return dt.timestamp()
        return dt.timestamp()
    except Exception:
        pass
    # 常见字符串格式
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(raw[:19], fmt).timestamp()
        except Exception:
            pass
    return None


def _ts_precision_grace(ts_raw) -> float:
    """按时间戳的**精度**给过滤宽限。

    取码接口给的时间戳精度不一：ISO8601 精确到秒（+2 秒宽限就够），但也有只到分钟的
    （实测 ic-mail.tibosb.cloud 返回 "received_at": "2026-09-18 18:35"）。
    只到分钟时，解析出来是那一分钟的 00 秒，最多比真实到达时间早 59 秒 —— 宽限还是 2 秒的话，
    **同一分钟内到达的新验证码会被当成"上一轮的旧码"直接丢掉**，一直轮询到超时。
    2026-09-18 实测：2FA 重认证的码 18 秒就到了，却因为 after_ts 是 18:35:12、戳是 18:35:00
    而被判旧码 → 8 个号的 2FA 全部失败。只到分钟的戳给 60 秒宽限。
    """
    text = str(ts_raw or "")
    m = re.search(r"\d{1,2}:\d{2}(:\d{2})?", text)
    if m and not m.group(1):
        return 60.0
    return 2.0


_HTML_ARTICLE_RE = re.compile(r"<article\b[^>]*>(.*?)</article>", re.DOTALL | re.IGNORECASE)
_META_TIME_RES = (
    re.compile(r"(?:时间|時間|time|date|received)[：:]\s*(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?)", re.IGNORECASE),
    re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})"),
)


def _html_inbox_code(text: str, after_ts: float | None = None) -> tuple[str, dict] | None:
    """从「收件箱 HTML 页」取最新一封邮件的验证码，并按 after_ts 过滤旧邮件。

    实测 api.wdmail.top / icloud-api.top 这类网关返回的是 HTML 收件箱页：

        <article><h2>ChatGPT 用の一時ログインコード</h2>
          <div class='meta'>发件人：... 时间：2026-09-16 02:12:11</div>
          <pre>... 123456 ...</pre></article>

    纯文本路径（_extract_code）**不认 after_ts** —— 所以 2FA 重认证时会拿**注册那封的旧码**
    去提交，必然 401 wrong_email_otp_code。实测 1050-1107 那批有 10~19 个号就是这么挂的。
    这里把 meta 里的时间解析出来做过滤：只有「不早于 after_ts」的邮件才认。
    """
    if not text or "<" not in text:
        return None
    blocks = _HTML_ARTICLE_RE.findall(text) or [text]
    best: tuple[float, str] | None = None
    for blk in blocks:
        code = _extract_code(blk)
        if not code:
            continue
        ts = 0.0
        for pat in _META_TIME_RES:
            m = pat.search(blk)
            if m:
                parsed = _parse_generic_api_ts(m.group(1))
                if parsed:
                    ts = parsed
                    break
        if best is None or ts >= best[0]:
            best = (ts, code)
    if best is None:
        return None
    ts, code = best
    if after_ts and ts and ts + 2 < after_ts:
        logger.debug(
            "[GenericAPI] HTML 收件箱跳过旧邮件: code=%s ts=%s after=%s",
            code, ts, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(after_ts)),
        )
        return None
    return code, {
        "source": "html_inbox",
        "received_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else None,
        "msg_ts": ts or None,
    }


def _extract_structured_api_code(text: str, after_ts: float | None = None) -> tuple[str, dict] | None:
    """
    兼容 newzoe 这类直接返回 JSON 的取码接口：
      {"code":"784207","from":"...","subject":"Your temporary ChatGPT login code","time":"2026-08-05T01:10:17.000Z"}

    如果响应里有 time/date/received_at，会按 after_ts 过滤旧码，避免拿到上一次缓存验证码。
    """
    if not text:
        return None
    try:
        data = json.loads(text)
    except Exception:
        # 不是 JSON → 可能是「收件箱 HTML 页」网关（wdmail / icloud-api.top）。
        # 走 HTML 分支才能拿到邮件时间、按 after_ts 过滤掉注册期的旧验证码。
        return _html_inbox_code(text, after_ts)
    if isinstance(data, list):
        # 取码接口常见返回数组，元素形如
        #   {"otp": "788395", "time": "2026-09-15T18:20:56+08:00"}
        # 且新旧顺序不保证（有的新在前，有的新在后）。取时间最新的那条；
        # 全都没有时间字段时退回最后一条。
        items = [x for x in data if isinstance(x, dict)]
        if not items:
            return None

        def _item_ts(x: dict) -> float:
            return _parse_generic_api_ts(
                x.get("time") or x.get("date") or x.get("received_at")
                or x.get("receivedAt") or x.get("created_at") or x.get("createdAt")
                or x.get("timestamp")
            ) or 0.0

        newest = max(items, key=_item_ts)
        if not _item_ts(newest):
            newest = items[-1]
        data = newest
    if not isinstance(data, dict):
        return None

    # 常见字段优先级：code / otp / verification_code；没有再回退从拉平文本提取。
    raw_code = (
        data.get("code")
        or data.get("otp")
        or data.get("verification_code")
        or data.get("verificationCode")
        or data.get("email_code")
        or data.get("emailCode")
    )
    code = None
    if raw_code is not None:
        m = _CODE_REGEX.search(str(raw_code))
        if m:
            code = m.group(1)
    # 顶层没有 code/otp 字段时，先看嵌套的 message.codes / message.text ——
    # 直接走 _flatten_json 兜底会被 expiresAt 的小数部分骗走（见 _nested_message_code）。
    nested_node: dict = {}
    if not code:
        nested = _nested_message_code(data)
        if nested:
            code, nested_node = nested
    if not code:
        code = _extract_code(_flatten_json(data))
    if not code:
        return None

    ts_raw = (
        data.get("time")
        or data.get("date")
        or data.get("received_at")
        or data.get("receivedAt")
        or data.get("created_at")
        or data.get("createdAt")
        or data.get("timestamp")
    )
    if not ts_raw and nested_node:
        ts_raw = (
            nested_node.get("date")
            or nested_node.get("time")
            or nested_node.get("received_at")
            or nested_node.get("receivedAt")
            or nested_node.get("created_at")
        )
    msg_ts = _parse_generic_api_ts(ts_raw)
    if after_ts and msg_ts and msg_ts + _ts_precision_grace(ts_raw) < after_ts:
        logger.debug(
            "[GenericAPI] structured API 跳过旧验证码: code=%s ts=%s after=%s subject=%r",
            code,
            ts_raw,
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(after_ts)),
            str(data.get("subject") or "")[:80],
        )
        return None

    return code, {
        "source": "structured_api",
        "received_at": ts_raw,
        "msg_ts": msg_ts,
        "subject": data.get("subject"),
        "from": data.get("from") or data.get("fromAddress") or data.get("sender"),
    }


def _fetch_yangyang_otp(
    session: requests.Session,
    code_url: str,
    headers: dict,
    after_ts: float | None = None,
) -> tuple[str, dict] | None:
    """从 yangyang 邮箱页面的列表 API + 详情 API 中抽取最新 6 位验证码。"""
    parsed = _parse_yangyang_code_url(code_url)
    if not parsed:
        return None
    origin, token, email = parsed
    token_q = quote(token, safe="")
    email_q = quote(email, safe="@._+-")
    api_url = f"{origin}/api/messages/{token_q}/{email_q}"

    items: list[dict] = []
    cursor: str | None = None
    # 一般第一页足够；保守支持最多翻 5 页。
    for _ in range(5):
        url = api_url if not cursor else f"{api_url}?cursor={quote(str(cursor), safe='')}"
        resp = session.get(url, headers={**headers, "Accept": "application/json"}, timeout=20, verify=False)
        if resp.status_code != 200:
            if resp.status_code == 404:
                # 兼容 mail.ai1998.xyz 这类同样是 /messages/{token}/{email}，
                # 但没有 /api/messages，邮件直接内嵌在 HTML 页面中的实现。
                return _fetch_inline_messages_page_otp(
                    session=session,
                    code_url=code_url,
                    headers=headers,
                    after_ts=after_ts,
                )
            logger.debug(f"[GenericAPI] yangyang 邮件列表 HTTP {resp.status_code}: {resp.text[:160]}")
            return None
        data = resp.json()
        page_items = data.get("items") or []
        if isinstance(page_items, list):
            items.extend([x for x in page_items if isinstance(x, dict)])
        if not data.get("has_more") or not data.get("next_cursor"):
            break
        cursor = str(data.get("next_cursor"))

    # API 默认新邮件在前；再次按时间倒序，尽量取最新验证码。
    items.sort(key=lambda x: _parse_yangyang_ts(x.get("received_at") or x.get("receivedAt")) or 0, reverse=True)
    for item in items:
        msg_ts_raw = item.get("received_at") or item.get("receivedAt")
        msg_ts = _parse_yangyang_ts(msg_ts_raw)
        if after_ts and msg_ts and msg_ts + 2 < after_ts:
            logger.debug(
                "[GenericAPI] yangyang 跳过旧邮件: id=%s ts=%s after=%s subject=%r",
                item.get("id"), msg_ts_raw, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(after_ts)),
                item.get("subject") or "",
            )
            continue
        msg_id = item.get("id")
        if not msg_id:
            continue
        detail_url = f"{origin}/message/{quote(str(msg_id), safe='')}/{token_q}/{email_q}"
        try:
            detail_resp = session.get(detail_url, headers={**headers, "Accept": "application/json"}, timeout=20, verify=False)
            if detail_resp.status_code != 200:
                continue
            detail = detail_resp.json()
        except Exception as exc:
            logger.debug(f"[GenericAPI] yangyang 邮件详情读取失败: {type(exc).__name__}: {exc}")
            continue

        raw_body = str(detail.get("body") or "")
        body = _decode_data_uri(raw_body)
        subject = str(detail.get("subject") or item.get("subject") or "")
        text = "\n".join([
            subject,
            str(detail.get("fromAddress") or item.get("from_address") or ""),
            str(detail.get("receivedAt") or item.get("received_at") or ""),
            body,
        ])
        code = _extract_yangyang_openai_code(subject, body)
        if code:
            logger.info(
                f"[GenericAPI] yangyang 页面提取到 OTP={code}, "
                f"mail_id={msg_id}, ts={detail.get('receivedAt') or item.get('received_at')}, subject={subject[:80]!r}"
            )
            return code, {
                "mail_id": msg_id,
                "received_at": detail.get("receivedAt") or item.get("received_at"),
                "subject": subject,
                "msg_ts": msg_ts,
            }
    return None


def _strip_html_fragment(value: str) -> str:
    value = str(value or "")
    value = re.sub(r"<br\s*/?>", "\n", value, flags=re.IGNORECASE)
    value = re.sub(r"<[^>]+>", " ", value)
    value = html_lib.unescape(value)
    value = re.sub(r"[ \t\r\f\v]+", " ", value)
    value = re.sub(r"\n\s+", "\n", value)
    return value.strip()


def _fetch_inline_messages_page_otp(
    *,
    session: requests.Session,
    code_url: str,
    headers: dict,
    after_ts: float | None = None,
) -> tuple[str, dict] | None:
    """解析无 JSON API、直接把邮件卡片渲染在 HTML 里的 /messages 页面。"""
    try:
        resp = session.get(
            code_url,
            headers={**headers, "Accept": "text/html,application/xhtml+xml,text/plain,*/*"},
            timeout=20,
            verify=False,
        )
        if resp.status_code != 200:
            logger.debug("[GenericAPI] inline messages 页面 HTTP %s: %s", resp.status_code, (resp.text or "")[:160])
            return None
        html = resp.text or ""
    except Exception as exc:
        logger.debug("[GenericAPI] inline messages 页面读取失败: %s: %s", type(exc).__name__, exc)
        return None

    cards = re.findall(r"<article\b[^>]*class=[\"'][^\"']*mail-card[^\"']*[\"'][^>]*>(.*?)</article>", html, flags=re.DOTALL | re.IGNORECASE)
    # 没有 article 时退一步按 details 分块，避免 class 名细微变化。
    if not cards:
        cards = re.findall(r"<details\b[^>]*>(.*?)</details>", html, flags=re.DOTALL | re.IGNORECASE)

    items: list[dict] = []
    for idx, card in enumerate(cards):
        subject_m = re.search(r"<span\b[^>]*class=[\"'][^\"']*subject[^\"']*[\"'][^>]*>(.*?)</span>", card, flags=re.DOTALL | re.IGNORECASE)
        date_m = re.search(r"<span\b[^>]*class=[\"'][^\"']*date[^\"']*[\"'][^>]*>(.*?)</span>", card, flags=re.DOTALL | re.IGNORECASE)
        from_m = re.search(r"<div\b[^>]*class=[\"'][^\"']*meta[^\"']*[\"'][^>]*>(.*?)</div>", card, flags=re.DOTALL | re.IGNORECASE)
        body_m = re.search(r"<pre\b[^>]*class=[\"'][^\"']*body[^\"']*[\"'][^>]*>(.*?)</pre>", card, flags=re.DOTALL | re.IGNORECASE)
        if not body_m:
            body_m = re.search(r"<div\b[^>]*class=[\"'][^\"']*body[^\"']*[\"'][^>]*>(.*?)</div>", card, flags=re.DOTALL | re.IGNORECASE)

        subject = _strip_html_fragment(subject_m.group(1) if subject_m else "")
        received_at = _strip_html_fragment(date_m.group(1) if date_m else "")
        from_addr = _strip_html_fragment(from_m.group(1) if from_m else "")
        body = _strip_html_fragment(body_m.group(1) if body_m else card)
        msg_ts = _parse_yangyang_ts(received_at)
        items.append({
            "mail_id": f"inline-{idx}",
            "subject": subject,
            "received_at": received_at,
            "from": from_addr,
            "body": body,
            "msg_ts": msg_ts or 0.0,
        })

    items.sort(key=lambda x: float(x.get("msg_ts") or 0.0), reverse=True)
    for item in items:
        msg_ts = float(item.get("msg_ts") or 0.0)
        if after_ts and msg_ts and msg_ts + 2 < after_ts:
            logger.debug(
                "[GenericAPI] inline messages 跳过旧邮件: id=%s ts=%s after=%s subject=%r",
                item.get("mail_id"), item.get("received_at"),
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(after_ts)),
                item.get("subject") or "",
            )
            continue
        code = _extract_yangyang_openai_code(str(item.get("subject") or ""), str(item.get("body") or ""))
        if code:
            logger.info(
                "[GenericAPI] inline messages 页面提取到 OTP=%s, mail_id=%s, ts=%s, subject=%r",
                code, item.get("mail_id"), item.get("received_at"), str(item.get("subject") or "")[:80],
            )
            return code, {
                "mail_id": item.get("mail_id"),
                "received_at": item.get("received_at"),
                "subject": item.get("subject"),
                "msg_ts": msg_ts,
            }
    return None


def pick_account() -> GenericApiEmailAccount:
    """直接从 SQLite 邮箱库领取一个可用通用 API 邮箱。"""
    from core.db import claim_next_generic_api_email, generic_api_email_pool_summary

    row = claim_next_generic_api_email()
    if row is None:
        summary = generic_api_email_pool_summary()
        raise GenericApiMailError(
            f"通用 API 邮箱池没有可用账号: {summary}. 请在 WebUI 邮箱池导入：邮箱----取码地址"
        )
    account = GenericApiEmailAccount(email=row["email"], code_url=row["code_url"])
    _CONTEXT_CACHE[account.email] = account
    logger.info(f"[GenericAPI] 选中邮箱: {account.email}（DB id={row.get('id')}）")
    return account


def import_from_file(path: str | Path | None = None) -> tuple[int, int]:
    """从文本文件导入通用 API 邮箱，每行：email----code_url 或 email====code_url。"""
    from core.db import import_generic_api_emails
    p = Path(path) if path else _ACCOUNTS_FILE
    if not p.is_absolute():
        p = _PROJECT_ROOT / p
    if not p.exists():
        return 0, 0
    records = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("----") if "----" in line else line.split("====")
        parts = [x.strip() for x in parts]
        if len(parts) < 2:
            continue
        records.append({"email": parts[0], "code_url": parts[1]})
    return import_generic_api_emails(records)


def get_account_context(email: str) -> GenericApiEmailAccount | None:
    if email in _CONTEXT_CACHE:
        return _CONTEXT_CACHE[email]
    from core.db import get_generic_api_email_by_email
    row = get_generic_api_email_by_email(email)
    if row is None:
        return None
    account = GenericApiEmailAccount(email=row["email"], code_url=row["code_url"])
    _CONTEXT_CACHE[email] = account
    return account


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    from core.db import release_generic_api_email
    release_generic_api_email(email, status=status, note=note)
    _CONTEXT_CACHE.pop(email, None)


def _fetch_poll_payload(
    *,
    proxy_url: str,
    poll_url: str,
    email: str,
    headers: dict,
    after_ts: float | None,
    is_yangyang: bool,
    public_inbox_api_url: str | None,
):
    """执行单次取码请求，网络路由由调用方指定。"""
    session = _new_http_session(proxy_url)
    yy_result = (
        _fetch_yangyang_otp(session, poll_url, headers, after_ts=after_ts)
        if is_yangyang else None
    )
    public_result = (
        _fetch_public_inbox_page_otp(
            session, poll_url, email, headers, after_ts=after_ts,
        )
        if public_inbox_api_url else None
    )
    page_result = yy_result or public_result
    if page_result or is_yangyang or public_inbox_api_url:
        return page_result, yy_result, None, ""
    resp = session.get(poll_url, headers=headers, timeout=20, verify=False)
    return None, None, resp, resp.text or ""


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
) -> str:
    """
    轮询该邮箱配置的 code_url，直到提取到 6 位验证码或超时。

    settle 机制：首次拿到验证码后不立刻返回，而是继续等 OTP_SETTLE_SECONDS 秒。
    如果期间取码地址返回了不同验证码，则替换候选并重置 settle 倒计时；
    连续 settle 秒没有变化后才返回，避免取到接口缓存中的旧码。
    """
    account = get_account_context(email)
    if account is None:
        raise GenericApiMailError(f"通用 API 邮箱不存在或未导入: {email}")

    deadline = time.time() + (max_wait or _email_cfg.OTP_MAX_WAIT)
    interval = poll_interval or _email_cfg.OTP_POLL_INTERVAL
    settle = settle_seconds if settle_seconds is not None else _email_cfg.OTP_SETTLE_SECONDS
    headers = {
        "Accept": "application/json,text/plain,*/*",
        "User-Agent": "Mozilla/5.0 (compatible; gpt-register/1.0)",
        "Cache-Control": "no-cache, no-store, max-age=0",
        "Pragma": "no-cache",
    }
    last_error = ""
    best_otp: str | None = None
    best_seen_at: float = 0.0
    settle_until: float | None = None
    logger.info(
        f"[GenericAPI] 开始轮询取码地址: {email}，"
        f"最长 {max_wait or _email_cfg.OTP_MAX_WAIT}s, settle={settle}s"
    )
    is_yangyang = _parse_yangyang_code_url(account.code_url) is not None
    public_inbox_api_url = _public_inbox_page_api_url(account.code_url)
    if public_inbox_api_url:
        logger.info(
            "[GenericAPI] 已识别公开收件页面，使用页面 inbox API: host=%s email=%s",
            urlparse(public_inbox_api_url).netloc,
            email,
        )

    selected_proxy = str(_proxy_cfg.pick_proxy() or "").strip()
    routes: list[tuple[str, str]] = []
    if selected_proxy:
        routes.append(("proxy", selected_proxy))
    routes.append(("direct", ""))
    logger.info(
        "[GenericAPI] HTTP 路由：首选=%s，网络异常时%s",
        _redact_proxy_url(selected_proxy),
        "回退直连" if selected_proxy else "使用直连",
    )

    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            # 不修改 yangyang 的路径型 URL；其列表接口本身按邮件 ID 返回数据。
            base_poll_url = public_inbox_api_url or account.code_url
            poll_url = base_poll_url if is_yangyang else _cache_busted_url(base_poll_url, attempt)
            route_error: Exception | None = None
            page_result = yy_result = resp = None
            text = ""
            for route_index, (_route_name, route_proxy) in enumerate(routes):
                try:
                    page_result, yy_result, resp, text = _fetch_poll_payload(
                        proxy_url=route_proxy,
                        poll_url=poll_url,
                        email=email,
                        headers=headers,
                        after_ts=after_ts,
                        is_yangyang=is_yangyang,
                        public_inbox_api_url=public_inbox_api_url,
                    )
                    route_error = None
                    break
                except requests.RequestException as exc:
                    route_error = exc
                    last_error = f"{type(exc).__name__}: {exc}"
                    has_fallback = route_index + 1 < len(routes)
                    logger.warning(
                        "[GenericAPI] 页面/API 请求失败：route=%s %s: %s%s",
                        _redact_proxy_url(route_proxy),
                        type(exc).__name__,
                        exc,
                        "，切换直连重试" if has_fallback else "",
                    )
            if route_error is not None:
                raise route_error

            if page_result:
                code, yy_meta = page_result
                result_source = str(yy_meta.get("source") or ("yangyang" if yy_result else "public_inbox_page"))
                now_seen = time.time()
                if not best_otp:
                    best_otp = code
                    best_seen_at = now_seen
                    settle_until = now_seen + settle
                    logger.info(
                        f"[GenericAPI] 首次锁定 OTP={code}, source={result_source} mail_id={yy_meta.get('mail_id')} ts={yy_meta.get('received_at')}, "
                        f"等 {settle}s 看取码接口是否出现更新验证码..."
                    )
                elif code != best_otp:
                    logger.info(
                        f"[GenericAPI] 发现更新 OTP={code}, source={result_source} mail_id={yy_meta.get('mail_id')} ts={yy_meta.get('received_at')}，"
                        f"替换之前的 {best_otp}, 重置 settle 计时"
                    )
                    best_otp = code
                    best_seen_at = now_seen
                    settle_until = now_seen + settle
                else:
                    logger.debug(f"[GenericAPI] 取码接口仍返回候选 OTP={best_otp}")
                resp = None
                text = ""
            else:
                if is_yangyang or public_inbox_api_url:
                    last_error = (
                        "yangyang 列表中尚未出现 after_ts 之后的新验证码邮件"
                        if is_yangyang else
                        "公开收件页面中尚未出现 after_ts 之后的新验证码邮件"
                    )
                    resp = None
                    text = ""
            if resp is None:
                pass
            elif resp.status_code == 200:
                public_payload = None
                if public_inbox_api_url:
                    try:
                        public_payload = json.loads(text)
                    except Exception:
                        public_payload = None
                mailbox = str((public_payload or {}).get("mailbox") or "").strip()
                mailbox_mismatch = bool(mailbox and mailbox.lower() != email.lower())
                if mailbox_mismatch:
                    structured = None
                    last_error = f"latest-code 返回邮箱不匹配: expected={email}, actual={mailbox}"
                else:
                    # 此类公开 latest-code 服务的 receivedAt 可能使用独立服务器时间，
                    # 与运行机器相差数小时甚至跨日。它只返回“最新一封”，因此这里
                    # 把时间字段作为诊断信息，不作为硬过滤条件；候选更新仍由
                    # code/messageId 变化及 settle 机制负责。
                    structured = _extract_structured_api_code(
                        text,
                        after_ts=None if public_inbox_api_url else after_ts,
                    )
                structured_meta = structured[1] if structured else {}
                if structured:
                    code = structured[0]
                else:
                    # 响应是 JSON 时**不能**走 _extract_code 兜底：结构化提取会按
                    # after_ts 滤掉旧验证码并返回 None，而 _extract_code 只看文本里
                    # 有没有 6 位数、不做时间过滤，会把刚被滤掉的注册期旧码捞回来，
                    # 提交后必然 401 wrong_email_otp_code（803 就是这么挂的）。
                    _json_body = False
                    try:
                        json.loads(text)
                        _json_body = True
                    except Exception:
                        _json_body = False
                    code = None if _json_body else _extract_code(text)
                if mailbox_mismatch:
                    code = None
                if code:
                    if (
                        public_inbox_api_url
                        and after_ts
                        and structured_meta.get("msg_ts")
                        and float(structured_meta["msg_ts"]) + 2 < after_ts
                    ):
                        logger.warning(
                            "[GenericAPI] latest-code 的 receivedAt 早于取码基准，"
                            "按服务端最新邮件继续作为候选：receivedAt=%s after=%s messageId=%s",
                            structured_meta.get("received_at"),
                            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(after_ts)),
                            (public_payload or {}).get("messageId"),
                        )
                    now_seen = time.time()
                    if not best_otp:
                        best_otp = code
                        best_seen_at = now_seen
                        settle_until = now_seen + settle
                        if structured_meta:
                            logger.info(
                                f"[GenericAPI] 首次锁定 OTP={code}, source=structured_api "
                                f"ts={structured_meta.get('received_at')} subject={str(structured_meta.get('subject') or '')[:80]!r}, "
                                f"等 {settle}s 看取码接口是否出现更新验证码..."
                            )
                        else:
                            logger.info(
                                f"[GenericAPI] 首次锁定 OTP={code}, "
                                f"等 {settle}s 看取码接口是否出现更新验证码..."
                            )
                    elif code != best_otp:
                        if structured_meta:
                            logger.info(
                                f"[GenericAPI] 发现更新 OTP={code}, source=structured_api "
                                f"ts={structured_meta.get('received_at')} subject={str(structured_meta.get('subject') or '')[:80]!r}，"
                                f"替换之前的 {best_otp}, 重置 settle 计时"
                            )
                        else:
                            logger.info(
                                f"[GenericAPI] 发现更新 OTP={code}，"
                                f"替换之前的 {best_otp}, 重置 settle 计时"
                            )
                        best_otp = code
                        best_seen_at = now_seen
                        settle_until = now_seen + settle
                    else:
                        logger.debug(f"[GenericAPI] 取码接口仍返回候选 OTP={best_otp}")
                else:
                    if not mailbox_mismatch:
                        if public_inbox_api_url and isinstance(public_payload, dict) and public_payload.get("code") is None:
                            last_error = "latest-code 返回 code=null，邮箱暂未收到验证码"
                        else:
                            last_error = f"HTTP 200 但未提取到 6 位验证码，响应预览: {text[:160]}"
            else:
                last_error = f"HTTP {resp.status_code}: {text[:160]}"
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

        now = time.time()
        if best_otp and settle_until is not None and now >= settle_until:
            logger.info(
                f"[GenericAPI] settle 完成，返回 OTP={best_otp}, "
                f"候选锁定时间={time.strftime('%H:%M:%S', time.localtime(best_seen_at))}"
            )
            return best_otp

        remaining = int(deadline - now)
        if best_otp and settle_until is not None:
            logger.info(
                f"[GenericAPI] 已锁定候选 OTP={best_otp}，等 settle 中"
                f"（剩余 settle ~{max(0, int(settle_until - now))}s, 总剩余 {remaining}s）..."
            )
        else:
            logger.info(
                f"[GenericAPI] 暂未从取码接口拿到验证码，"
                f"{interval}s 后重试（剩余 {remaining}s）..."
            )
        time.sleep(interval)

    if best_otp:
        logger.warning(f"[GenericAPI] 总超时但已有候选，返回 OTP={best_otp}")
        return best_otp

    raise GenericApiMailError(f"等待通用 API 验证码超时: {email}; {last_error}")
