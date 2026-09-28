# -*- coding: utf-8 -*-
"""
QQ 邮箱 IMAP 客户端（Cloudflare 域名邮箱模式）

工作流：
    1. pick_domain_email()    生成 random@domain 域名邮箱并落库
    2. fetch_latest_otp()     通过 QQ 邮箱 IMAP 轮询取 OTP

依赖：Python 标准库（imaplib, email, ssl），无新增第三方包。
"""
import imaplib
import email as email_lib
import logging
import random
import string
import time
from datetime import datetime, timezone
from email.header import decode_header
from pathlib import Path

from config import email as _email_cfg
from core.otp_utils import looks_like_openai_email, extract_otp

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class QQMailClientError(RuntimeError):
    """QQ 邮箱服务相关异常。"""


# ============================================================
# 邮件解析工具
# ============================================================

def _decode_email_header(header_value: str | None) -> str:
    """解码邮件头（处理 =?UTF-8?B?...?= 等编码）。"""
    if not header_value:
        return ""
    decoded_parts = decode_header(header_value)
    result = []
    for part, charset in decoded_parts:
        if isinstance(part, bytes):
            try:
                result.append(part.decode(charset or "utf-8", errors="replace"))
            except (LookupError, UnicodeDecodeError):
                result.append(part.decode("utf-8", errors="replace"))
        else:
            result.append(str(part))
    return " ".join(result)


def _parse_email_date(msg) -> float | None:
    """从 email.message 解析日期为 UTC 时间戳。"""
    date_str = msg.get("Date") or msg.get("date")
    if not date_str:
        return None
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        pass
    try:
        parsed = email_lib.utils.parsedate(date_str)
        if parsed:
            import calendar
            return calendar.timegm(parsed)
    except Exception:
        pass
    return None


def _decode_part_payload(part) -> str:
    try:
        payload = part.get_payload(decode=True)
        if payload:
            charset = part.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
    except Exception:
        pass
    return ""


def _get_msg_parts(msg) -> tuple[str, str]:
    """提取纯文本和 HTML 正文。"""
    text_parts: list[str] = []
    html_parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            cdisp = str(part.get("Content-Disposition", ""))
            if "attachment" in cdisp:
                continue
            ctype = part.get_content_type()
            body = _decode_part_payload(part)
            if not body:
                continue
            if ctype == "text/plain":
                text_parts.append(body)
            elif ctype == "text/html":
                html_parts.append(body)
    else:
        body = _decode_part_payload(msg)
        ctype = msg.get_content_type()
        if ctype == "text/html":
            html_parts.append(body)
        else:
            text_parts.append(body)
    return "\n".join(text_parts), "\n".join(html_parts)


def _get_msg_text(msg) -> str:
    """递归提取邮件正文（纯文本优先）。"""
    text, html = _get_msg_parts(msg)
    return text or html


def _header_blob(msg) -> str:
    parts = []
    for key, value in msg.items():
        parts.append(f"{key}: {_decode_email_header(value)}")
    return "\n".join(parts)


def _msg_to_dict(msg) -> dict:
    """将 email.message 转为统一 dict（与 outlook_client 兼容）。"""
    subject = _decode_email_header(msg.get("Subject") or msg.get("subject") or "")
    from_ = _decode_email_header(msg.get("From") or msg.get("from") or "")
    to_ = _decode_email_header(msg.get("To") or msg.get("to") or "")
    delivered_to = _decode_email_header(msg.get("Delivered-To") or "")
    original_to = _decode_email_header(
        msg.get("X-Original-To") or msg.get("Original-To") or msg.get("X-Forwarded-To") or ""
    )
    resent_to = _decode_email_header(msg.get("Resent-To") or "")
    cc_ = _decode_email_header(msg.get("Cc") or "")
    body_text, body_html = _get_msg_parts(msg)
    combined = "\n".join(p for p in (body_text, body_html) if p)
    ts = _parse_email_date(msg)
    ts_str = (
        datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if ts else ""
    )
    return {
        "subject": subject,
        "from": from_,
        "to": to_,
        "cc": cc_,
        "deliveredTo": delivered_to,
        "xOriginalTo": original_to,
        "resentTo": resent_to,
        "headers": _header_blob(msg),
        "sendEmail": from_,
        "text": body_text or combined,
        "html": body_html,
        "bodyPreview": combined,
        "bodyText": combined,
        "date": ts_str,
        "receivedDateTime": ts_str,
    }


def _recipient_haystack(item: dict) -> str:
    return " ".join([
        str(item.get("to") or ""),
        str(item.get("cc") or ""),
        str(item.get("deliveredTo") or ""),
        str(item.get("xOriginalTo") or ""),
        str(item.get("resentTo") or ""),
        str(item.get("headers") or "")[:12000],
        str(item.get("text") or "")[:8000],
        str(item.get("html") or "")[:8000],
        str(item.get("bodyPreview") or "")[:8000],
        str(item.get("bodyText") or "")[:8000],
    ]).lower()


def message_matches_target(item: dict, email: str) -> bool:
    """Duck 转发到 QQ 后 To 经常变成 QQ 地址，按原地址 / local-part / QQ 收件人匹配。"""
    target = str(email or "").strip().lower()
    if not target:
        return False
    hay = _recipient_haystack(item)
    if target in hay:
        return True
    local, _, domain = target.partition("@")
    if local and local in hay:
        return True
    qq = str(getattr(_email_cfg, "QQ_EMAIL", "") or "").strip().lower()
    if domain in {"duck.com", "duckduckgo.com"} and qq:
        to_fields = " ".join([
            str(item.get("to") or ""),
            str(item.get("cc") or ""),
            str(item.get("deliveredTo") or ""),
        ]).lower()
        if qq in to_fields:
            return True
    return False


# ============================================================
# IMAP 连接与搜索
# ============================================================

def _connect_imap() -> imaplib.IMAP4_SSL:
    """连接 QQ 邮箱 IMAP 服务器并返回连接对象。"""
    server = _email_cfg.QQ_IMAP_SERVER
    port = _email_cfg.QQ_IMAP_PORT
    qq_email = _email_cfg.QQ_EMAIL
    password = _email_cfg.QQ_IMAP_PASSWORD

    if not qq_email or not password:
        raise QQMailClientError(
            "QQ 邮箱 IMAP 未配置，请在 config/email.py 中设置 QQ_EMAIL 和 QQ_IMAP_PASSWORD"
        )

    try:
        mail = imaplib.IMAP4_SSL(server, port)
        # QQ IMAP 要求客户端先发 ID，否则常报 Account is abnormal。
        try:
            mail._simple_command(
                "ID",
                '("name" "Mozilla Thunderbird" "version" "128.0" "vendor" "Mozilla")',
            )
        except Exception:
            pass
        mail.login(qq_email, password)
        mail.select("INBOX")
        return mail
    except imaplib.IMAP4.error as exc:
        raise QQMailClientError(f"QQ 邮箱 IMAP 登录失败: {exc}")
    except Exception as exc:
        raise QQMailClientError(f"QQ 邮箱 IMAP 连接失败: {exc}")


_IMAP_FOLDERS = ("INBOX", "Junk")


def _search_folder(mail: imaplib.IMAP4_SSL, folder: str, after_dt: datetime | None = None) -> list[dict]:
    try:
        status, data = mail.select(folder)
    except Exception as exc:
        logger.debug("[QQMail] 无法打开目录 %s: %s", folder, exc)
        return []
    if status != "OK":
        logger.debug("[QQMail] 跳过目录 %s: %s", folder, data)
        return []

    search_criteria = "ALL"
    if after_dt is not None:
        date_str = after_dt.strftime("%d-%b-%Y")
        search_criteria = f'(SINCE {date_str})'

    status, msg_ids = mail.search(None, search_criteria)
    if status != "OK":
        logger.warning("[QQMail] IMAP search 失败 folder=%s: %s", folder, status)
        return []

    ids = msg_ids[0].split() if msg_ids[0] else []
    if not ids:
        return []

    recent_ids = ids[-30:]
    messages = []
    for mid in recent_ids:
        status, data = mail.fetch(mid, "(RFC822)")
        if status != "OK":
            continue
        raw_email = data[0][1]
        try:
            msg = email_lib.message_from_bytes(raw_email)
            item = _msg_to_dict(msg)
            item["_folder"] = folder
            messages.append(item)
        except Exception as exc:
            logger.debug("[QQMail] 解析邮件 %s/%s 失败: %s", folder, mid, exc)
            continue
    return messages


def _search_messages(mail: imaplib.IMAP4_SSL, after_dt: datetime | None = None) -> list[dict]:
    """搜索 INBOX + Junk 中 after_dt 之后的邮件。"""
    messages: list[dict] = []
    for folder in _IMAP_FOLDERS:
        messages.extend(_search_folder(mail, folder, after_dt=after_dt))
    return messages


# ============================================================
# 公共接口
# ============================================================

def _mint_duck_address() -> str:
    """用 Duck Email Protection API 生成一个新的 xxx@duck.com。"""
    import json as _json

    token = str(getattr(_email_cfg, "DUCK_EMAIL_TOKEN", "") or "").strip()
    if not token:
        raise QQMailClientError("DUCK_EMAIL_TOKEN 未配置")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Origin": "https://duckduckgo.com",
        "Referer": "https://duckduckgo.com/",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
        ),
    }
    url = "https://quack.duckduckgo.com/api/email/addresses"
    last_exc: Exception | None = None
    # 大陆直连 quack 经常超时；优先走本机 10808，失败再直连。
    for proxy in ("socks5h://127.0.0.1:10808", "socks5h://127.0.0.1:11080", ""):
        try:
            from curl_cffi import requests as cr
            kwargs = {
                "headers": headers,
                "timeout": 20,
                "allow_redirects": True,
            }
            if proxy:
                kwargs["proxies"] = {"http": proxy, "https": proxy}
            resp = cr.post(url, **kwargs)
            payload = resp.json() if resp.content else {}
            if int(getattr(resp, "status_code", 0) or 0) >= 400:
                raise QQMailClientError(f"Duck API HTTP {resp.status_code}: {str(payload)[:180]}")
            local = str((payload or {}).get("address") or "").strip().lower()
            if not local:
                raise QQMailClientError(f"Duck API 未返回 address: {payload}")
            return f"{local}@duck.com"
        except QQMailClientError:
            raise
        except Exception as exc:
            last_exc = exc
            logger.warning("[QQMail] Duck API 失败 proxy=%s: %s: %s", proxy or "direct", type(exc).__name__, str(exc)[:160])
            continue
    raise QQMailClientError(f"Duck API 领取失败: {last_exc}")


def _duck_address_is_consumed(email: str) -> bool:
    """已注册 / 已成功任务 / 域名池 used 的 Duck 别名不能再拿去注册。"""
    target = str(email or "").strip().lower()
    if not target:
        return True
    try:
        from core.db import get_account_by_email, _load_domain_pool, _find_domain_email, _load_jobs
        if get_account_by_email(target):
            return True
        row = _find_domain_email(_load_domain_pool(), target)
        if row and str(row.get("status") or "").lower() in {"used", "failed", "disabled", "registered"}:
            return True
        for job in _load_jobs():
            if str(job.get("email") or "").strip().lower() != target:
                continue
            if str(job.get("status") or "").lower() in {"success", "succeeded", "ok"}:
                return True
            if str(job.get("job_type") or "") == "registration" and job.get("account_id"):
                return True
    except Exception as exc:
        logger.debug("[QQMail] 检查 Duck 地址占用失败: %s", exc)
    return False


def pick_domain_email() -> str:
    """生成注册邮箱并落库。

    Duck 隐私邮箱必须走官方 API（不能自己拼随机串）；其它域名仍生成 random@EMAIL_DOMAIN。
    """
    from core.db import claim_next_domain_email

    token = str(getattr(_email_cfg, "DUCK_EMAIL_TOKEN", "") or "").strip()
    domain = str(getattr(_email_cfg, "EMAIL_DOMAIN", "") or "").strip().lstrip("@").lower()
    if token or domain in {"duck.com", "duckduckgo.com"}:
        seen: set[str] = set()
        last_email = ""
        for attempt in range(1, 8):
            email = _mint_duck_address()
            last_email = email
            if email in seen or _duck_address_is_consumed(email):
                logger.warning("[QQMail] Duck 地址不可用，丢弃 %s，重试 %s/8", email, attempt)
                try:
                    from core.db import release_domain_email as _release_used
                    _release_used(email, status="used", note="duck alias already consumed")
                except Exception:
                    pass
                time.sleep(0.5 * attempt)
                continue
            seen.add(email)
            claim_next_domain_email(email)
            logger.info("[QQMail] 生成 Duck 隐私邮箱: %s", email)
            return email
        raise QQMailClientError(
            f"Duck API 连续返回已用地址（最后一次 {last_email}）。请在 Duck 后台再生成一个新别名。"
        )

    if not domain:
        raise QQMailClientError(
            "EMAIL_DOMAIN 未配置。Duck 隐私邮箱请填 duck.com 并配置 DUCK_EMAIL_TOKEN"
        )

    prefix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    email = f"{prefix}@{domain}"
    claim_next_domain_email(email)
    logger.info("[QQMail] 生成域名邮箱: %s", email)
    return email


def release_domain_email(email: str, status: str = "available", note: str | None = None) -> None:
    """更新域名邮箱状态。"""
    from core.db import release_domain_email as _release
    _release(email, status=status, note=note)


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
) -> str:
    """
    通过 QQ 邮箱 IMAP 轮询取 OTP。

    每个轮询周期：
        1. 连接 QQ 邮箱 IMAP，搜索 after_ts 时间点之后的邮件
        2. 筛选 TO 收件地址匹配 email 的邮件
        3. 用 otp_utils 识别 OpenAI 验证码邮件并提取 6 位 OTP
        4. settle 机制：抓到首封后再等 OTP_SETTLE_SECONDS 秒，
           确认没有更晚的邮件才返回，避免取到途中旧 OTP

    Args:
        email: 注册用的域名邮箱地址（同时用于 IMAP TO 收件地址过滤）
        after_ts: UTC 时间戳，只看比这个时间新的邮件
        max_wait / poll_interval: 默认走 config 里的值
    """
    if not after_ts:
        after_ts = time.time()
    deadline = time.time() + (max_wait or _email_cfg.OTP_MAX_WAIT)
    interval = poll_interval or _email_cfg.OTP_POLL_INTERVAL
    settle = settle_seconds if settle_seconds is not None else _email_cfg.OTP_SETTLE_SECONDS
    # 30s 时钟偏差容忍
    after_dt = datetime.fromtimestamp(after_ts - 30, tz=timezone.utc)

    logger.info(
        f"[QQMail] 开始轮询 QQ 邮箱收件箱（域名: {email}），"
        f"最长 {max_wait or _email_cfg.OTP_MAX_WAIT}s, settle={settle}s..."
    )

    target_lower = email.lower()

    best_otp: str | None = None
    best_ts: float = 0.0
    best_subject: str = ""
    settle_until: float | None = None

    while time.time() < deadline:
        mail = None
        try:
            mail = _connect_imap()
            messages = _search_messages(mail, after_dt=after_dt)
        except QQMailClientError as exc:
            logger.warning(f"[QQMail] IMAP 连接失败: {exc}")
            messages = []
        finally:
            if mail:
                try:
                    mail.logout()
                except Exception:
                    pass

        # 按时间降序排列
        messages.sort(key=lambda m: m.get("date") or "", reverse=True)

        openai_seen = 0
        matched = 0
        # 查找最新 OpenAI 邮件
        for item in messages:
            if not looks_like_openai_email(item):
                continue
            openai_seen += 1

            # Duck 转发后 To 经常变成 QQ 地址，且原地址不一定出现在正文。
            if not message_matches_target(item, target_lower):
                continue
            matched += 1

            subject = item.get("subject") or ""
            otp = extract_otp(item)
            if not otp:
                continue

            # 解析时间戳
            ts = 0.0
            raw_ts = item.get("date") or item.get("receivedDateTime") or ""
            if raw_ts:
                try:
                    ts = (
                        datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                        .timestamp()
                    )
                except Exception:
                    ts = 0.0

            if after_ts and ts < after_ts - 30:
                continue

            if ts > best_ts:
                if best_otp:
                    logger.info(
                        f"[QQMail] 发现更晚的 OTP={otp} (ts={raw_ts}), "
                        f"替换之前的 {best_otp}, 重置 settle 计时"
                    )
                else:
                    logger.info(
                        f"[QQMail] 首次锁定 OTP={otp}, ts={raw_ts}, "
                        f"subject={subject!r}, 等 {settle}s 看是否有更晚邮件..."
                    )
                best_otp = otp
                best_ts = ts
                best_subject = subject
                settle_until = time.time() + settle
            break  # 只关心最新那一封

        # settle 判断
        now = time.time()
        if best_otp and settle_until is not None and now >= settle_until:
            logger.info(
                f"[QQMail] settle 完成，返回 OTP={best_otp}, subject={best_subject!r}"
            )
            return best_otp

        remaining = int(deadline - now)
        if best_otp:
            logger.info(
                f"[QQMail] 已锁定候选 OTP={best_otp}，等 settle 中"
                f"（剩余 settle ~{int(settle_until - now)}s, 总剩余 {remaining}s）..."
            )
        elif openai_seen:
            logger.info(
                f"[QQMail] 看到 {openai_seen} 封 OpenAI 邮件但未匹配 {email}"
                f"（matched={matched}, folders=INBOX/Junk），{interval}s 后重试（剩余 {remaining}s）..."
            )
        else:
            logger.info(
                f"[QQMail] 暂未收到 OpenAI 邮件（INBOX+Junk），{interval}s 后重试（剩余 {remaining}s）..."
            )
        time.sleep(interval)

    # 超时但有候选
    if best_otp:
        logger.warning(
            f"[QQMail] 总超时但已有候选，返回 OTP={best_otp} (subject={best_subject!r})"
        )
        return best_otp

    raise QQMailClientError(
        f"等待 {email} 的 OTP 超时（>{max_wait or _email_cfg.OTP_MAX_WAIT}s）。"
        f"可能：QQ IMAP 未扫到 / Duck 转发未到 2557224193@qq.com / OpenAI 邮件未发出。"
    )
