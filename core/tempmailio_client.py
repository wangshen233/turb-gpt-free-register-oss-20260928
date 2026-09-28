# -*- coding: utf-8 -*-
"""temp-mail.io 免费临时邮箱客户端。

公开 API（https://api.internal.temp-mail.io/api/v3），无需 API Key：
    POST /email/new                       创建地址 → {email, token}
    GET  /email/{email}/messages?token=   列出邮件
    GET  /email/{email}/messages/{id}?token=  取单封正文

与 mail.tm 的区别：域名不固定，每次创建时由服务端轮换（ooynib.com / ozsaip.com 等），
供应商域名轮换比 mail.tm 固定域名更难被一次性封禁。

凭证（email/token）落盘 tools/tempmailio_accounts.json，查活时复用。
"""
from __future__ import annotations

import json
import logging
import secrets
import string
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import requests

from config import email as _email_cfg
from core.otp_utils import extract_otp, looks_like_openai_email

logger = logging.getLogger(__name__)

DEFAULT_API_BASE = "https://api.internal.temp-mail.io/api/v3"
REQUEST_TIMEOUT = 20
_ACCOUNTS_FILE = Path(__file__).resolve().parent.parent / "tools" / "tempmailio_accounts.json"
_LOCK = threading.Lock()


class TempMailIoError(RuntimeError):
    """temp-mail.io 请求或取码失败。"""


@dataclass
class TempMailIoAccount:
    email: str
    token: str = ""
    status: str = "used"
    note: str = ""
    created_at: str = ""
    extra: dict = field(default_factory=dict)


_CONTEXT_CACHE: dict[str, TempMailIoAccount] = {}


def _cfg(name: str, default: str = "") -> str:
    return str(getattr(_email_cfg, name, default) or default).strip()


def _api_base() -> str:
    return (_cfg("TEMPMAILIO_API_BASE", DEFAULT_API_BASE) or DEFAULT_API_BASE).rstrip("/")


def _key(email: str) -> str:
    return str(email or "").strip().lower()


def _session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    proxy = _cfg("TEMPMAILIO_PROXY")
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    session.headers.update({
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
        ),
    })
    return session


def _load_rows() -> list[dict]:
    if not _ACCOUNTS_FILE.exists():
        return []
    try:
        raw = json.loads(_ACCOUNTS_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("[TempMailIo] 凭证文件解析失败：%s", exc)
        return []
    return raw if isinstance(raw, list) else []


def _save_rows(rows: list[dict]) -> None:
    try:
        _ACCOUNTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        _ACCOUNTS_FILE.write_text(
            json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except Exception as exc:
        logger.warning("[TempMailIo] 凭证保存失败：%s", exc)


def _row_to_account(row: dict) -> TempMailIoAccount | None:
    email = str(row.get("email") or "").strip()
    if not email:
        return None
    return TempMailIoAccount(
        email=email,
        token=str(row.get("token") or ""),
        status=str(row.get("status") or "used"),
        note=str(row.get("note") or ""),
        created_at=str(row.get("created_at") or ""),
        extra=dict(row.get("extra") or {}),
    )


def _account_to_row(account: TempMailIoAccount) -> dict:
    return {
        "email": account.email,
        "token": account.token,
        "status": account.status,
        "note": account.note,
        "created_at": account.created_at,
        "extra": account.extra,
    }


def _persist(account: TempMailIoAccount) -> None:
    with _LOCK:
        rows = _load_rows()
        target = _key(account.email)
        for index, row in enumerate(rows):
            if _key(str(row.get("email") or "")) == target:
                rows[index] = _account_to_row(account)
                break
        else:
            rows.append(_account_to_row(account))
        _save_rows(rows)


def pick_account() -> TempMailIoAccount:
    """创建一个 temp-mail.io 地址并落盘凭证。"""
    length = 10
    try:
        length = int(_cfg("TEMPMAILIO_NAME_LENGTH", "10") or 10)
    except ValueError:
        length = 10

    session = _session()
    last_exc: Exception | None = None
    for attempt in range(1, 4):
        try:
            resp = session.post(
                f"{_api_base()}/email/new",
                json={
                    "min_name_length": length,
                    "max_name_length": length,
                    "domain": _cfg("TEMPMAILIO_DOMAIN") or None,
                },
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code >= 400:
                raise TempMailIoError(
                    f"创建地址 HTTP {resp.status_code}: {(resp.text or '')[:160]}"
                )
            payload = resp.json() or {}
            address = str(payload.get("email") or "").strip()
            token = str(payload.get("token") or "").strip()
            if not address:
                raise TempMailIoError(f"创建地址未返回 email：{str(payload)[:160]}")
            account = TempMailIoAccount(
                email=address,
                token=token,
                status="used",
                created_at=datetime.now(timezone.utc).isoformat(),
                extra={"domain": address.split("@")[-1]},
            )
            _CONTEXT_CACHE[_key(address)] = account
            _persist(account)
            logger.info("[TempMailIo] 已创建邮箱: %s", address)
            return account
        except Exception as exc:
            last_exc = exc
            logger.warning("[TempMailIo] 创建失败（第 %s/3 次）：%s", attempt, str(exc)[:160])
            time.sleep(1.5 * attempt)
    raise TempMailIoError(f"temp-mail.io 创建邮箱失败: {last_exc}")


def get_account_context(email: str) -> TempMailIoAccount | None:
    target = _key(email)
    if not target:
        return None
    cached = _CONTEXT_CACHE.get(target)
    if cached:
        return cached
    for row in _load_rows():
        if _key(str(row.get("email") or "")) == target:
            account = _row_to_account(row)
            if account:
                _CONTEXT_CACHE[target] = account
            return account
    return None


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    account = get_account_context(email)
    if not account:
        return
    account.status = str(status or "available")
    if note is not None:
        account.note = str(note)
    _persist(account)


def _message_to_item(message: dict) -> dict:
    text = str(message.get("body_text") or message.get("body") or "")
    html = str(message.get("body_html") or "")
    sender = message.get("from") or ""
    if isinstance(sender, dict):
        sender = sender.get("address") or sender.get("email") or ""
    created = message.get("created_at") or message.get("createdAt") or ""
    subject = str(message.get("subject") or "")
    return {
        "subject": subject,
        "from": str(sender),
        "sendEmail": str(sender),
        "text": text,
        "bodyPreview": text or html,
        "bodyText": text,
        "html": html,
        "content": html,
        "date": str(created),
        "receivedDateTime": str(created),
    }


def _created_ts(item: dict) -> float:
    raw = str(item.get("date") or "")
    if not raw:
        return 0.0
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


def _fetch_raw(session: requests.Session, account: TempMailIoAccount) -> list[dict]:
    resp = session.get(
        f"{_api_base()}/email/{account.email}/messages",
        params={"token": account.token},
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code >= 400:
        return []
    payload = resp.json() or []
    return payload if isinstance(payload, list) else []


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
) -> str:
    """轮询 temp-mail.io 收件箱并返回最新的 6 位 OTP。"""
    account = get_account_context(email)
    if not account:
        raise TempMailIoError(
            f"没有 {email} 的 temp-mail.io 凭证（tools/tempmailio_accounts.json 缺失）"
        )

    wait_seconds = int(max_wait if max_wait is not None else getattr(_email_cfg, "OTP_MAX_WAIT", 180) or 180)
    interval = int(poll_interval if poll_interval is not None else getattr(_email_cfg, "OTP_POLL_INTERVAL", 3) or 3)
    settle = int(settle_seconds if settle_seconds is not None else getattr(_email_cfg, "OTP_SETTLE_SECONDS", 5) or 5)
    if after_ts is None:
        after_ts = time.time()

    session = _session()
    deadline = time.time() + wait_seconds
    best: tuple[float, str] | None = None
    settle_until: float | None = None
    logger.info("[TempMailIo] 开始轮询 %s，最长 %ss, settle=%ss", email, wait_seconds, settle)

    while time.time() < deadline:
        try:
            messages = _fetch_raw(session, account)
        except requests.RequestException as exc:
            logger.warning("[TempMailIo] 拉取收件箱失败：%s", str(exc)[:140])
            time.sleep(interval)
            continue

        for raw in messages:
            if not isinstance(raw, dict):
                continue
            item = _message_to_item(raw)
            ts = _created_ts(item)
            if ts and ts < after_ts - 60:
                continue
            if not looks_like_openai_email(item):
                continue
            code = extract_otp(item)
            if not code:
                continue
            if best is None or ts > best[0]:
                if best is not None:
                    logger.info("[TempMailIo] 出现更新的 OTP，重置 settle：%s → %s", best[1], code)
                best = (ts, code)
                settle_until = time.time() + settle

        now = time.time()
        if best is not None and settle_until is not None and now >= settle_until:
            logger.info("[TempMailIo] settle 完成，返回 OTP=%s", best[1])
            return best[1]

        remaining = int(deadline - now)
        if best is not None:
            logger.info("[TempMailIo] 已锁定 OTP=%s，等 settle（剩余 %ss）", best[1], remaining)
            time.sleep(max(0.5, min(1.5, remaining)))
        else:
            logger.info("[TempMailIo] 暂未收到 OpenAI 邮件，%ss 后重试（剩余 %ss）", interval, remaining)
            time.sleep(interval)

    if best is not None:
        return best[1]
    raise TempMailIoError(f"等待 {email} 的 OTP 超时（>{wait_seconds}s）")
