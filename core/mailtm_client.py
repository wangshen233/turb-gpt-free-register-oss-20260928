# -*- coding: utf-8 -*-
"""mail.tm 免费临时邮箱客户端。

mail.tm 是公开免费 API（https://api.mail.tm），可自助注册临时邮箱并收信：
    POST /domains           列出可用域名
    POST /accounts          创建邮箱（address + password）
    POST /token             换取 JWT
    GET  /messages          Bearer JWT 列出邮件
    GET  /messages/{id}     取单封邮件正文

实测 2026-09：域名 uberip.com 被 ChatGPT 注册流程接受，OTP 正常送达，
因此可以作为纯协议注册的免费邮箱来源（source 名 "mailtm"）。

凭证（address/password）会落盘到 tools/mailtm_accounts.json，
因为"查活"要用同一个邮箱重新走一遍 OTP，进程重启后必须能恢复。
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

DEFAULT_API_BASE = "https://api.mail.tm"
REQUEST_TIMEOUT = 20
_ACCOUNTS_FILE = Path(__file__).resolve().parent.parent / "tools" / "mailtm_accounts.json"
_LOCK = threading.Lock()


class MailTmError(RuntimeError):
    """mail.tm 请求或取码失败。"""


@dataclass
class MailTmAccount:
    email: str
    password: str
    token: str = ""
    status: str = "used"
    note: str = ""
    created_at: str = ""
    extra: dict = field(default_factory=dict)


_CONTEXT_CACHE: dict[str, MailTmAccount] = {}


def _cfg(name: str, default: str = "") -> str:
    return str(getattr(_email_cfg, name, default) or default).strip()


def _api_base() -> str:
    return (_cfg("MAILTM_API_BASE", DEFAULT_API_BASE) or DEFAULT_API_BASE).rstrip("/")


def _key(email: str) -> str:
    return str(email or "").strip().lower()


def _session() -> requests.Session:
    """不继承系统代理；需要时走 MAILTM_PROXY。"""
    session = requests.Session()
    session.trust_env = False
    proxy = _cfg("MAILTM_PROXY")
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    return session


# ---------------- 凭证落盘 ----------------

def _load_rows() -> list[dict]:
    if not _ACCOUNTS_FILE.exists():
        return []
    try:
        raw = json.loads(_ACCOUNTS_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("[MailTm] 凭证文件解析失败：%s", exc)
        return []
    return raw if isinstance(raw, list) else []


def _save_rows(rows: list[dict]) -> None:
    try:
        _ACCOUNTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        _ACCOUNTS_FILE.write_text(
            json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except Exception as exc:
        logger.warning("[MailTm] 凭证保存失败：%s", exc)


def _row_to_account(row: dict) -> MailTmAccount | None:
    email = str(row.get("email") or "").strip()
    password = str(row.get("password") or "").strip()
    if not email or not password:
        return None
    return MailTmAccount(
        email=email,
        password=password,
        token=str(row.get("token") or ""),
        status=str(row.get("status") or "used"),
        note=str(row.get("note") or ""),
        created_at=str(row.get("created_at") or ""),
        extra=dict(row.get("extra") or {}),
    )


def _account_to_row(account: MailTmAccount) -> dict:
    return {
        "email": account.email,
        "password": account.password,
        "token": account.token,
        "status": account.status,
        "note": account.note,
        "created_at": account.created_at,
        "extra": account.extra,
    }


def _persist(account: MailTmAccount) -> None:
    with _LOCK:
        rows = _load_rows()
        target = _key(account.email)
        replaced = False
        for index, row in enumerate(rows):
            if _key(str(row.get("email") or "")) == target:
                rows[index] = _account_to_row(account)
                replaced = True
                break
        if not replaced:
            rows.append(_account_to_row(account))
        _save_rows(rows)


def _restore(email: str) -> MailTmAccount | None:
    target = _key(email)
    if not target:
        return None
    for row in _load_rows():
        if _key(str(row.get("email") or "")) == target:
            return _row_to_account(row)
    return None


# ---------------- 邮箱创建 / 登录 ----------------

def _extract_domain(payload) -> str:
    items = payload.get("hydra:member") if isinstance(payload, dict) else payload
    if not isinstance(items, list) or not items:
        raise MailTmError(f"mail.tm 未返回可用域名：{str(payload)[:160]}")
    active = [d for d in items if isinstance(d, dict) and d.get("isActive", True)]
    chosen = (active or items)[0]
    domain = str(chosen.get("domain") or "").strip()
    if not domain:
        raise MailTmError(f"mail.tm 域名条目缺少 domain：{str(chosen)[:160]}")
    return domain


def _random_local(length: int = 12) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(max(6, int(length))))


def _login(session: requests.Session, email: str, password: str) -> str:
    resp = session.post(
        f"{_api_base()}/token", json={"address": email, "password": password}, timeout=REQUEST_TIMEOUT
    )
    if resp.status_code != 200:
        raise MailTmError(f"mail.tm 登录失败 HTTP {resp.status_code}: {(resp.text or '')[:160]}")
    token = str((resp.json() or {}).get("token") or "").strip()
    if not token:
        raise MailTmError("mail.tm 登录未返回 token")
    return token


def pick_account() -> MailTmAccount:
    """新建一个 mail.tm 临时邮箱并落盘凭证。"""
    preferred = _cfg("MAILTM_DOMAIN")
    length = 12
    try:
        length = int(_cfg("MAILTM_NAME_LENGTH", "12") or 12)
    except ValueError:
        length = 12

    session = _session()
    last_exc: Exception | None = None
    for attempt in range(1, 4):
        try:
            if preferred:
                domain = preferred
            else:
                resp = session.get(f"{_api_base()}/domains", timeout=REQUEST_TIMEOUT)
                if resp.status_code != 200:
                    raise MailTmError(f"mail.tm 域名列表 HTTP {resp.status_code}")
                domain = _extract_domain(resp.json())

            address = f"{_random_local(length)}@{domain}"
            password = secrets.token_urlsafe(12)
            created = session.post(
                f"{_api_base()}/accounts",
                json={"address": address, "password": password},
                timeout=REQUEST_TIMEOUT,
            )
            if created.status_code not in (200, 201):
                raise MailTmError(
                    f"mail.tm 创建邮箱失败 HTTP {created.status_code}: {(created.text or '')[:160]}"
                )
            token = _login(session, address, password)
            account = MailTmAccount(
                email=address,
                password=password,
                token=token,
                status="used",
                created_at=datetime.now(timezone.utc).isoformat(),
                extra={"domain": domain},
            )
            _CONTEXT_CACHE[_key(address)] = account
            _persist(account)
            logger.info("[MailTm] 已创建邮箱: %s", address)
            return account
        except Exception as exc:
            last_exc = exc
            logger.warning("[MailTm] 创建邮箱失败（第 %s/3 次）：%s", attempt, str(exc)[:160])
            time.sleep(1.5 * attempt)
    raise MailTmError(f"mail.tm 创建邮箱失败: {last_exc}")


def get_account_context(email: str) -> MailTmAccount | None:
    """内存 → 落盘凭证恢复；查活/重启后仍能取码。"""
    target = _key(email)
    if not target:
        return None
    cached = _CONTEXT_CACHE.get(target)
    if cached:
        return cached
    restored = _restore(email)
    if restored:
        _CONTEXT_CACHE[target] = restored
    return restored


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    account = get_account_context(email)
    if not account:
        return
    account.status = str(status or "available")
    if note is not None:
        account.note = str(note)
    _persist(account)


# ---------------- 取码 ----------------

def _message_to_item(session: requests.Session, token: str, summary: dict) -> dict:
    detail = {}
    msg_id = str(summary.get("id") or "").strip()
    if msg_id:
        try:
            resp = session.get(
                f"{_api_base()}/messages/{msg_id}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 200:
                detail = resp.json() or {}
        except Exception as exc:
            logger.debug("[MailTm] 取正文失败 %s: %s", msg_id, exc)
    merged = dict(summary)
    merged.update({k: v for k, v in detail.items() if v})
    sender = merged.get("from") or {}
    if isinstance(sender, list) and sender:
        sender = sender[0]
    address = sender.get("address") if isinstance(sender, dict) else str(sender or "")
    text = str(merged.get("text") or "")
    html = str(merged.get("html") or "")
    return {
        "subject": str(merged.get("subject") or ""),
        "from": str(address or ""),
        "sendEmail": str(address or ""),
        "text": text,
        "bodyPreview": text or html,
        "bodyText": text,
        "html": html,
        "content": html,
        "date": str(merged.get("createdAt") or ""),
        "receivedDateTime": str(merged.get("createdAt") or ""),
    }


def _created_ts(item: dict) -> float:
    raw = str(item.get("date") or "")
    if not raw:
        return 0.0
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
) -> str:
    """轮询 mail.tm 收件箱并返回最新的 6 位 OTP。"""
    account = get_account_context(email)
    if not account:
        raise MailTmError(
            f"没有 {email} 的 mail.tm 凭证（tools/mailtm_accounts.json 缺失或邮箱不是本进程创建）"
        )

    wait_seconds = int(max_wait if max_wait is not None else getattr(_email_cfg, "OTP_MAX_WAIT", 180) or 180)
    interval = int(poll_interval if poll_interval is not None else getattr(_email_cfg, "OTP_POLL_INTERVAL", 3) or 3)
    settle = int(settle_seconds if settle_seconds is not None else getattr(_email_cfg, "OTP_SETTLE_SECONDS", 5) or 5)
    if after_ts is None:
        after_ts = time.time()

    session = _session()
    token = account.token or _login(session, account.email, account.password)
    account.token = token

    deadline = time.time() + wait_seconds
    best: tuple[float, str] | None = None
    settle_until: float | None = None
    logger.info("[MailTm] 开始轮询 %s，最长 %ss, settle=%ss", email, wait_seconds, settle)

    while time.time() < deadline:
        try:
            resp = session.get(
                f"{_api_base()}/messages",
                headers={"Authorization": f"Bearer {token}"},
                params={"page": 1},
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as exc:
            logger.warning("[MailTm] 拉取收件箱失败：%s", str(exc)[:140])
            time.sleep(interval)
            continue
        if resp.status_code == 401:
            token = _login(session, account.email, account.password)
            account.token = token
            continue
        if resp.status_code != 200:
            logger.warning("[MailTm] 收件箱 HTTP %s: %s", resp.status_code, (resp.text or "")[:140])
            time.sleep(interval)
            continue

        payload = resp.json() or {}
        rows = payload.get("hydra:member") if isinstance(payload, dict) else payload
        for summary in rows or []:
            if not isinstance(summary, dict):
                continue
            item = _message_to_item(session, token, summary)
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
                    logger.info("[MailTm] 出现更新的 OTP，重置 settle：%s → %s", best[1], code)
                best = (ts, code)
                settle_until = time.time() + settle

        now = time.time()
        if best is not None and settle_until is not None and now >= settle_until:
            logger.info("[MailTm] settle 完成，返回 OTP=%s", best[1])
            return best[1]

        remaining = int(deadline - now)
        if best is not None:
            logger.info("[MailTm] 已锁定 OTP=%s，等 settle（剩余 %ss）", best[1], remaining)
            time.sleep(max(0.5, min(1.5, remaining)))
        else:
            logger.info("[MailTm] 暂未收到 OpenAI 邮件，%ss 后重试（剩余 %ss）", interval, remaining)
            time.sleep(interval)

    if best is not None:
        return best[1]
    raise MailTmError(f"等待 {email} 的 OTP 超时（>{wait_seconds}s）")
