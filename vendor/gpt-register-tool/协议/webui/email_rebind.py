"""Manual iCloud -> custom-domain email rebinding.

The workflow is deliberately separate from registration. It logs into the
selected existing account, performs the official ChatGPT email-change request
sequence, waits for the replacement mailbox OTP, and only then updates the
local registered-account key.
"""
from __future__ import annotations

import logging
import threading
import time
from contextlib import contextmanager
from typing import Any, Mapping, Optional
from uuid import uuid4

from auth_flow import AuthFlow
from config import Config
from mail_providers import MailProviderError, create_mail_provider, validate_email

from . import db
from .probes import record_operation_probe, redact_probe_error

logger = logging.getLogger("webui.email_rebind")

CHATGPT_ORIGIN = "https://chatgpt.com"
CHANGE_PATHS = {
    "eligibility": "/backend-api/accounts/change_email/eligibility",
    "mfa_info": "/backend-api/accounts/mfa_info",
    "begin": "/backend-api/accounts/change_email/begin",
    "verify": "/backend-api/accounts/change_email/verify",
}
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)


class EmailRebindError(RuntimeError):
    """A user-facing, credential-free rebinding error."""


_BULK_REBIND_LOCK = threading.RLock()
_BULK_REBIND_JOBS: dict[str, dict[str, Any]] = {}
_BULK_REBIND_ACTIVE: set[str] = set()


def _notify_phase(callback: Any, stage: str, status: str, **details: Any) -> None:
    """Send a redacted stage event to a batch snapshot when one is active."""
    if not callable(callback):
        return
    try:
        callback(stage, status, **details)
    except Exception:  # noqa: BLE001
        logger.debug("批量换绑阶段回调失败 stage=%s", stage, exc_info=True)


@contextmanager
def _phase(callback: Any, stage: str, **details: Any):
    started = time.perf_counter()
    record_operation_probe(f"email_rebind.{stage}", "started", **details)
    _notify_phase(callback, stage, "started", **details)
    try:
        yield
    except Exception as exc:
        elapsed = int((time.perf_counter() - started) * 1000)
        record_operation_probe(
            f"email_rebind.{stage}", "failed", duration_ms=elapsed, error=exc, **details
        )
        _notify_phase(callback, stage, "failed", duration_ms=elapsed, error=str(exc)[:240], **details)
        raise
    else:
        elapsed = int((time.perf_counter() - started) * 1000)
        record_operation_probe(f"email_rebind.{stage}", "ok", duration_ms=elapsed, **details)
        _notify_phase(callback, stage, "ok", duration_ms=elapsed, **details)


def _clean_email(value: str, label: str) -> str:
    value = (value or "").strip().lower()
    if not value:
        raise EmailRebindError(f"{label}不能为空")
    try:
        validate_email(value)
    except ValueError as exc:
        raise EmailRebindError(f"{label}格式无效") from exc
    return value


def _response_payload(response: Any) -> dict:
    try:
        payload = response.json()
    except Exception:  # noqa: BLE001
        return {}
    return payload if isinstance(payload, dict) else {}


def _response_summary(response: Any) -> dict:
    payload = _response_payload(response)
    summary = {"status": getattr(response, "status_code", None)}
    for key in ("success", "eligible", "status", "code", "error"):
        value = payload.get(key)
        if isinstance(value, (bool, int, float, str)):
            summary[key] = str(value)[:80] if isinstance(value, str) else value
    return summary


def _close_provider(provider: Any) -> None:
    close = getattr(provider, "close", None)
    if callable(close):
        try:
            close()
            return
        except Exception:  # noqa: BLE001
            pass
    session = getattr(provider, "_session", None)
    close_session = getattr(session, "close", None)
    if callable(close_session):
        try:
            close_session()
        except Exception:  # noqa: BLE001
            pass


def _session_id(flow: AuthFlow, access_token: str) -> str:
    sid = str(getattr(flow, "_client_auth_session_id", "") or "").strip()
    if sid:
        return sid
    payload = {}
    try:
        from webui.exporter import _decode_jwt_payload

        payload = _decode_jwt_payload(access_token)
    except Exception:  # noqa: BLE001
        payload = {}
    sid = str(payload.get("session_id") or payload.get("sid") or "").strip()
    if sid:
        return sid
    dump = getattr(flow, "_client_auth_session_dump", {})
    if isinstance(dump, Mapping):
        client_dump = dump.get("client_auth_session")
        if isinstance(client_dump, Mapping):
            sid = str(client_dump.get("session_id") or "").strip()
            if sid:
                return sid
    return ""


def _account_id(access_token: str) -> str:
    try:
        from webui.exporter import _decode_jwt_payload, _get_auth

        auth = _get_auth(_decode_jwt_payload(access_token))
    except Exception:  # noqa: BLE001
        auth = {}
    return str(auth.get("chatgpt_account_id") or auth.get("account_id") or "").strip()


def _request(flow: AuthFlow, method: str, path: str, headers: dict, body: Optional[dict] = None):
    url = f"{CHATGPT_ORIGIN}{path}"
    try:
        if method == "GET":
            return flow.session.get(url, headers=headers, timeout=30)
        return flow.session.post(url, headers=headers, json=body or {}, timeout=30)
    except Exception as exc:  # noqa: BLE001
        raise EmailRebindError(f"换绑请求失败（{type(exc).__name__}）") from exc


def _build_headers(flow: AuthFlow, result: Any, path: str) -> dict[str, str]:
    access_token = str(getattr(result, "access_token", "") or "").strip()
    account_id = _account_id(access_token)
    session_id = _session_id(flow, access_token)
    device_id = str(getattr(result, "device_id", "") or "").strip()
    if not account_id:
        raise EmailRebindError("登录会话缺少账号标识，无法发起换绑")
    if not session_id:
        raise EmailRebindError("登录会话缺少 session 标识，请重新登录后重试")
    if not device_id:
        raise EmailRebindError("登录会话缺少设备标识，请重新登录后重试")

    headers = {
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
        "OAI-Device-Id": device_id,
        "OAI-Session-Id": session_id,
        "ChatGPT-Account-Id": account_id,
        "Origin": CHATGPT_ORIGIN,
        "Referer": f"{CHATGPT_ORIGIN}/",
        "X-OpenAI-Target-Path": path,
        "X-OpenAI-Target-Route": path,
        "User-Agent": str(getattr(flow, "_ua", "") or DEFAULT_USER_AGENT),
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    cookie_header = str(getattr(result, "cookie_header", "") or "").strip()
    if cookie_header:
        headers["Cookie"] = cookie_header
    return headers


def _require_ok(response: Any, label: str) -> dict:
    summary = _response_summary(response)
    if not getattr(response, "ok", False):
        raise EmailRebindError(
            f"{label}失败（HTTP {summary.get('status') or 'unknown'}）"
        )
    return _response_payload(response)


def _change_email(
    flow: AuthFlow,
    target_email: str,
    target_mail: Any,
    otp_timeout: int,
    phase_callback: Any = None,
) -> None:
    path = CHANGE_PATHS["eligibility"]
    with _phase(phase_callback, "eligibility"):
        eligibility_response = _request(flow, "GET", path, _build_headers(flow, flow.result, path))
        eligibility = _require_ok(eligibility_response, "换绑资格检查")
        if eligibility.get("eligible") is not True:
            raise EmailRebindError("当前账号不满足邮箱换绑条件")

    path = CHANGE_PATHS["mfa_info"]
    with _phase(phase_callback, "mfa"):
        mfa_response = _request(flow, "GET", path, _build_headers(flow, flow.result, path))
        _require_ok(mfa_response, "MFA 状态检查")

    begin_started_at = time.time()
    path = CHANGE_PATHS["begin"]
    with _phase(phase_callback, "begin", target_email=target_email):
        begin_response = _request(
            flow, "POST", path, _build_headers(flow, flow.result, path), {"email": target_email}
        )
        begin = _require_ok(begin_response, "发起邮箱换绑")
        if begin.get("success") is not True:
            raise EmailRebindError("服务端拒绝发起邮箱换绑")

    with _phase(phase_callback, "otp.read", target_email=target_email):
        try:
            code = target_mail.wait_for_otp(
                target_email,
                timeout=otp_timeout,
                issued_after=begin_started_at,
            )
        except Exception as exc:  # noqa: BLE001
            raise EmailRebindError("目标域名邮箱验证码读取超时或失败") from exc
        if not code or len(str(code).strip()) != 6 or not str(code).strip().isdigit():
            raise EmailRebindError("目标邮箱验证码格式无效")

    path = CHANGE_PATHS["verify"]
    with _phase(phase_callback, "verify", target_email=target_email):
        verify_response = _request(
            flow,
            "POST",
            path,
            _build_headers(flow, flow.result, path),
            {"email": target_email, "code": str(code).strip()},
        )
        verify = _require_ok(verify_response, "确认邮箱换绑")
        if verify.get("success") is not True:
            raise EmailRebindError("服务端未确认邮箱换绑成功")


def rebind_registered_email(
    source_email: str,
    target_email: str = "",
    *,
    proxy: str = "",
    otp_timeout: int = 180,
    phase_callback: Any = None,
) -> dict:
    """Run one explicit iCloud-to-domain rebinding task."""
    source_email = _clean_email(source_email, "源邮箱")
    target_email = (target_email or "").strip().lower()
    proxy = (proxy or "").strip()
    otp_timeout = max(60, min(int(otp_timeout or 180), 600))

    with _phase(phase_callback, "validate", source_email=source_email):
        cred = db.get_registered(source_email)
        if not cred:
            raise EmailRebindError("未找到源账号的注册凭证")
        account = db.get_account(source_email)
        if not account or account.get("kind") != "icloud_relay":
            raise EmailRebindError("该账号不是已导入的 iCloud 中转邮箱")
        if not (cred.get("password") or "").strip():
            raise EmailRebindError("源账号缺少密码，无法执行手动换绑")

        settings = db.get_mail_settings()
        domain = (settings.get("cf_domain") or "").strip().lstrip("@").lower()
        if not domain:
            raise EmailRebindError("请先在邮箱配置中设置目标域名")

    target_mail = None
    source_mail = None
    flow = None
    if target_email:
        target_email = _clean_email(target_email, "目标邮箱")
        if target_email.rsplit("@", 1)[1] != domain:
            raise EmailRebindError(f"目标邮箱必须使用已配置域名 @{domain}")
    if target_email and target_email == source_email:
        raise EmailRebindError("源邮箱和目标邮箱不能相同")
    if target_email and db.email_in_use(target_email, exclude=source_email):
        raise EmailRebindError("目标邮箱已存在于本地账号或邮箱池")

    try:
        with _phase(phase_callback, "mailbox.prepare", target_email=target_email, domain=domain):
            target_mail = create_mail_provider("cf_temp", settings)
            if not target_email:
                target_email = _clean_email(target_mail.create_mailbox(), "自动生成的目标邮箱")
            if target_email.rsplit("@", 1)[1] != domain:
                raise EmailRebindError(f"目标邮箱必须使用已配置域名 @{domain}")
            if target_email == source_email:
                raise EmailRebindError("源邮箱和目标邮箱不能相同")
            if db.email_in_use(target_email, exclude=source_email):
                raise EmailRebindError("自动生成的目标邮箱已存在，请重试")

        source_mail = create_mail_provider("icloud_relay", settings, account)
        family = (db.get_setting("fingerprint_browser_family", "auto") or "auto").strip().lower()
        country = (db.get_setting("fingerprint_country", "") or "").strip().upper()
        if family not in {"auto", "chrome", "firefox", "safari"}:
            family = "auto"
        flow = AuthFlow(
            Config(proxy=proxy or None),
            env_overrides={
                "WEBUI_ALLOW_LOGIN": "1",
                "OTP_TIMEOUT": str(otp_timeout),
                "OAUTH_CODEX_RT_BEFORE_CALLBACK": "0",
                "OAUTH_CODEX_RT_EXCHANGE": "0",
                "OAUTH_SECONDARY_AUTHORIZE_EXCHANGE": "0",
            },
            account_callback=lambda _email: {
                "password": cred.get("password") or "",
                "totp_secret": cred.get("totp_secret") or "",
            },
            fingerprint_country=country,
            fingerprint_browser_family=family,
        )
        logger.info("[email_rebind] 开始手动换绑 source=%s target=%s", source_email, target_email)
        with _phase(phase_callback, "protocol.login", source_email=source_email):
            flow.run_protocol_login(
                source_mail,
                source_email,
                password=(cred.get("password") or "").strip(),
            )
        _change_email(flow, target_email, target_mail, otp_timeout, phase_callback)

        # The remote account changes first. Refresh session fields when
        # possible, then atomically re-key the local record.
        try:
            flow.get_auth_session()
        except Exception as exc:  # noqa: BLE001
            logger.info("[email_rebind] 换绑后刷新 session 跳过: %s", type(exc).__name__)
        with _phase(phase_callback, "database.update", source_email=source_email, target_email=target_email):
            db.complete_email_rebind(
                source_email,
                target_email,
                credential_updates=flow.result.to_dict(),
                metadata={
                    "source_email": source_email,
                    "target_email": target_email,
                    "source_kind": "icloud_relay",
                    "target_kind": "cf_temp",
                    "completed_at": time.time(),
                },
            )
        logger.info("[email_rebind] 换绑完成 source=%s target=%s", source_email, target_email)
        return {"source_email": source_email, "target_email": target_email, "status": "changed"}
    except EmailRebindError:
        raise
    except MailProviderError as exc:
        raise EmailRebindError(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("[email_rebind] 未预期失败 source=%s", source_email)
        raise EmailRebindError(f"换绑失败（{type(exc).__name__}）") from exc
    finally:
        if flow is not None:
            try:
                flow.session.close()
            except Exception:  # noqa: BLE001
                pass
        if target_mail is not None:
            _close_provider(target_mail)
        if source_mail is not None:
            _close_provider(source_mail)


def _bulk_job_snapshot(job: Mapping[str, Any]) -> dict[str, Any]:
    """Return a JSON-safe copy without exposing credentials or provider state."""
    return {
        "job_id": job["job_id"],
        "status": job["status"],
        "total": job["total"],
        "completed": job["completed"],
        "succeeded": job["succeeded"],
        "failed": job["failed"],
        "current": job.get("current", ""),
        "current_phase": job.get("current_phase", ""),
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
        "results": [
            {**dict(item), "phases": [dict(phase) for phase in item.get("phases", [])]}
            for item in job.get("results", [])
        ],
    }


def _bulk_update(job_id: str, **changes: Any) -> None:
    with _BULK_REBIND_LOCK:
        job = _BULK_REBIND_JOBS.get(job_id)
        if job is not None:
            job.update(changes)


def _run_bulk_rebind(job_id: str, source_emails: list[str], proxy: str, otp_timeout: int) -> None:
    logger.info("[email_rebind] 批量换绑开始 job=%s total=%s", job_id, len(source_emails))
    try:
        _bulk_update(job_id, status="running")
        for index, source_email in enumerate(source_emails):
            _bulk_update(job_id, current=source_email, current_phase="item")
            started = time.monotonic()
            def phase_callback(stage: str, status: str, **details: Any) -> None:
                event = {"stage": stage, "status": status, "timestamp": time.time()}
                for key in ("duration_ms", "error", "target_email", "domain", "source_email"):
                    if key in details and details[key] not in (None, ""):
                        event[key] = redact_probe_error(details[key]) if key == "error" else details[key]
                with _BULK_REBIND_LOCK:
                    job = _BULK_REBIND_JOBS.get(job_id)
                    if job is not None:
                        phases = job["results"][index].setdefault("phases", [])
                        phases.append(event)
                        job["current_phase"] = stage if status == "started" else ""

            phase_callback("item", "started", source_email=source_email)
            try:
                result = rebind_registered_email(
                    source_email,
                    proxy=proxy,
                    otp_timeout=otp_timeout,
                    phase_callback=phase_callback,
                )
                phase_callback("item", "ok", duration_ms=int((time.monotonic() - started) * 1000))
                item = {
                    "source_email": source_email,
                    "target_email": result.get("target_email", ""),
                    "status": "changed",
                    "error": "",
                    "duration_ms": int((time.monotonic() - started) * 1000),
                }
                succeeded_delta = 1
                failed_delta = 0
                logger.info(
                    "[email_rebind] 批量换绑成功 job=%s index=%s source=%s target=%s",
                    job_id,
                    index + 1,
                    source_email,
                    item["target_email"],
                )
            except EmailRebindError as exc:
                error_text = redact_probe_error(exc)
                phase_callback("item", "failed", duration_ms=int((time.monotonic() - started) * 1000), error=error_text)
                item = {
                    "source_email": source_email,
                    "target_email": "",
                    "status": "failed",
                    "error": error_text,
                    "duration_ms": int((time.monotonic() - started) * 1000),
                }
                succeeded_delta = 0
                failed_delta = 1
                logger.warning(
                    "[email_rebind] 批量换绑失败 job=%s index=%s source=%s error=%s",
                    job_id,
                    index + 1,
                    source_email,
                    item["error"],
                )
            except Exception as exc:  # noqa: BLE001
                error_text = redact_probe_error(exc)
                phase_callback("item", "failed", duration_ms=int((time.monotonic() - started) * 1000), error=error_text)
                item = {
                    "source_email": source_email,
                    "target_email": "",
                    "status": "failed",
                    "error": f"换绑失败（{type(exc).__name__}）",
                    "duration_ms": int((time.monotonic() - started) * 1000),
                }
                succeeded_delta = 0
                failed_delta = 1
                logger.exception(
                    "[email_rebind] 批量换绑未预期异常 job=%s source=%s",
                    job_id,
                    source_email,
                )

            with _BULK_REBIND_LOCK:
                job = _BULK_REBIND_JOBS.get(job_id)
                if job is None:
                    return
                item["phases"] = list(job["results"][index].get("phases", []))
                job["results"][index] = item
                job["completed"] += 1
                job["succeeded"] += succeeded_delta
                job["failed"] += failed_delta
                job["current"] = ""
                job["current_phase"] = ""

        _bulk_update(
            job_id,
            status="done",
            current="",
            current_phase="",
            finished_at=time.time(),
        )
        logger.info("[email_rebind] 批量换绑完成 job=%s succeeded=%s failed=%s", job_id, job["succeeded"], job["failed"])
    except Exception:  # noqa: BLE001
        logger.exception("[email_rebind] 批量任务异常 job=%s", job_id)
        _bulk_update(job_id, status="failed", current="", current_phase="", finished_at=time.time())
    finally:
        with _BULK_REBIND_LOCK:
            for source_email in source_emails:
                _BULK_REBIND_ACTIVE.discard(source_email)


def start_bulk_rebind(
    source_emails: list[str],
    *,
    proxy: str = "",
    otp_timeout: int = 180,
) -> dict[str, Any]:
    """Start a sequential protocol rebinding batch and return its job snapshot."""
    cleaned: list[str] = []
    for raw_email in source_emails or []:
        email = _clean_email(raw_email, "源邮箱")
        if email not in cleaned:
            cleaned.append(email)
    if not cleaned:
        raise EmailRebindError("至少选择一个源邮箱")

    proxy = (proxy or "").strip()
    otp_timeout = max(60, min(int(otp_timeout or 180), 600))
    with _BULK_REBIND_LOCK:
        active = [email for email in cleaned if email in _BULK_REBIND_ACTIVE]
        if active:
            raise EmailRebindError(f"这些邮箱已有批量换绑任务运行中: {', '.join(active[:3])}")
        job_id = uuid4().hex[:12]
        job = {
            "job_id": job_id,
            "status": "queued",
            "total": len(cleaned),
            "completed": 0,
            "succeeded": 0,
            "failed": 0,
            "current": "",
            "current_phase": "",
            "started_at": time.time(),
            "finished_at": None,
            "results": [
                {
                    "source_email": email,
                    "target_email": "",
                    "status": "queued",
                    "error": "",
                    "duration_ms": 0,
                    "phases": [],
                }
                for email in cleaned
            ],
        }
        _BULK_REBIND_JOBS[job_id] = job
        _BULK_REBIND_ACTIVE.update(cleaned)

    thread = threading.Thread(
        target=_run_bulk_rebind,
        args=(job_id, cleaned, proxy, otp_timeout),
        daemon=True,
        name=f"email-rebind-{job_id}",
    )
    try:
        thread.start()
    except Exception as exc:
        with _BULK_REBIND_LOCK:
            _BULK_REBIND_ACTIVE.difference_update(cleaned)
            _BULK_REBIND_JOBS.pop(job_id, None)
        raise EmailRebindError("批量换绑线程启动失败，请重试") from exc
    with _BULK_REBIND_LOCK:
        return _bulk_job_snapshot(_BULK_REBIND_JOBS[job_id])


def get_bulk_rebind(job_id: str) -> Optional[dict[str, Any]]:
    """Return a current batch snapshot, or None for an unknown/expired id."""
    with _BULK_REBIND_LOCK:
        job = _BULK_REBIND_JOBS.get((job_id or "").strip())
        return _bulk_job_snapshot(job) if job else None


__all__ = [
    "EmailRebindError",
    "get_bulk_rebind",
    "rebind_registered_email",
    "start_bulk_rebind",
]
