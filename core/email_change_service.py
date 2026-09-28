# -*- coding: utf-8 -*-
"""ChatGPT 账号邮箱换绑后台队列。"""
from __future__ import annotations

import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from core import db
from core.email_provider import (
    acquire_email_from_source, email_material_line,
    release_email_if_unconsumed, wait_for_otp,
)
from core.session import BrowserSession

logger = logging.getLogger(__name__)
_EXECUTOR = ThreadPoolExecutor(max_workers=3, thread_name_prefix="email-change")
_SLOTS = threading.BoundedSemaphore(100)
_RUNNING: set[int] = set()
_LOCK = threading.Lock()
_LOG_DIR = Path(__file__).resolve().parent.parent / "注册日志"


def log_path(account_id: int) -> Path:
    return _LOG_DIR / f"email-change-{int(account_id)}.log"


def _append_log(account_id: int, message: str, *, clear: bool = False) -> None:
    path = log_path(account_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "w" if clear else "a"
    with path.open(mode, encoding="utf-8") as fh:
        fh.write(f"{datetime.now().strftime('%H:%M:%S')} [INFO] {message}\n")


def _proxy(value: str | None) -> str:
    text = str(value or "").strip()
    return text if text.lower().startswith(("http://", "https://", "socks4://", "socks5://", "socks5h://")) else ""


def _proxy_label(value: str | None) -> str:
    """日志用代理摘要，保留路由信息但隐藏认证密码。"""
    text = str(value or "").strip()
    if not text:
        return "direct"
    try:
        parsed = urlparse(text)
        auth = "***:***@" if parsed.username or parsed.password else ""
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{auth}{parsed.hostname or '?'}{port}"
    except Exception:
        return "proxy://***"


def _cost(started: float) -> str:
    return f"{time.monotonic() - started:.2f}s"


def _new_session(account_id: int, proxy, *, email: str = "") -> BrowserSession:
    # 与 2FA/查活统一使用账号级种子。同一账号做敏感操作时保持 device_id、
    # Sentinel sid、浏览器画像稳定，而不是为“换绑”另造一套新设备指纹。
    seed = f"account:{email.lower()}" if email else f"email-change:{account_id}"
    return BrowserSession(proxy=proxy, fingerprint_seed=seed)


def _response_error(resp) -> str:
    try:
        data = resp.json()
        err = data.get("error") if isinstance(data, dict) else None
        if isinstance(err, dict):
            return str(err.get("message") or err.get("code") or data)
        return str(err or data)
    except Exception:
        return str(getattr(resp, "text", "") or f"HTTP {resp.status_code}")[:500]


def _is_reauth_required(exc: BaseException) -> bool:
    text = str(exc or "").lower()
    return "reauth_required" in text or "recent login required" in text


def _post(session: BrowserSession, path: str, token: str, payload: dict) -> dict:
    headers = session.get_chatgpt_headers(referer="https://chatgpt.com/", include_content_type=True)
    headers.update({
        "authorization": f"Bearer {token}", "oai-device-id": session.device_id,
        "oai-language": session.navigator_language(), "origin": "https://chatgpt.com",
    })
    resp = session.post(f"https://chatgpt.com{path}", headers=headers, data=json.dumps(payload, separators=(",", ":")))
    if resp.status_code != 200:
        raise RuntimeError(f"{path} 返回 {resp.status_code}: {_response_error(resp)}")
    data = resp.json()
    if not isinstance(data, dict) or not data.get("success"):
        raise RuntimeError(f"{path} 返回失败: {data}")
    return data


def _post_with_network_retry(
    session: BrowserSession, *, account_id: int, path: str, token: str, payload: dict,
    fingerprint_email: str = "",
) -> tuple[dict, BrowserSession]:
    """TLS reset/超时等传输故障时换会话重试，最后一次明确直连兜底。"""
    last_exc: Exception | None = None
    current = session
    for attempt in range(1, 4):
        attempt_started = time.monotonic()
        _append_log(
            account_id,
            f"HTTP 请求开始：path={path} attempt={attempt}/3 "
            f"route={_proxy_label(getattr(current, 'proxy', None))} "
            f"device_id={str(getattr(current, 'device_id', '') or '')[:12]}...",
        )
        try:
            result = _post(current, path, token, payload)
            _append_log(
                account_id,
                f"HTTP 请求成功：path={path} status=200 attempt={attempt}/3 cost={_cost(attempt_started)}",
            )
            return result, current
        except Exception as exc:
            last_exc = exc
            text = str(exc)
            _append_log(
                account_id,
                f"HTTP 请求失败：path={path} attempt={attempt}/3 cost={_cost(attempt_started)} "
                f"error={type(exc).__name__}: {text[:300]}",
            )
            # 明确的业务 4xx 不重复提交；网络错误、429 和 5xx 才重试。
            if isinstance(exc, RuntimeError) and "返回 4" in text and "返回 429" not in text:
                raise
            if attempt >= 3:
                break
            delay = attempt * 2
            next_route = "代理池新会话" if attempt == 1 else "直连兜底"
            _append_log(
                account_id,
                f"请求异常（第 {attempt}/3 次）：{type(exc).__name__}: {text[:300]}；"
                f"{delay}s 后切换到{next_route}重试",
            )
            logger.warning("[邮箱换绑] %s attempt=%s failed: %s", path, attempt, text[:300])
            time.sleep(delay)
            # 第二次从代理池重新选择出口；第三次明确直连，避免坏代理持续 reset。
            current = _new_session(
                account_id, None if attempt == 1 else "", email=fingerprint_email,
            )
    assert last_exc is not None
    raise last_exc


def _enqueue_live_check_after_change(account_id: int, email: str) -> dict:
    """换绑成功后立即排队查活，用新邮箱重新登录并刷新失效的 AT。"""
    from core import live_check_service

    result = live_check_service.enqueue_account_live_check(
        account_id=int(account_id), email=str(email),
        trigger="email_change_auto", proxy=None,
    )
    if result.get("accepted"):
        logger.info("[邮箱换绑] 已自动加入查活队列 account_id=%s email=%s", account_id, email)
        _append_log(account_id, f"自动查活已入队：email={email}")
    else:
        logger.warning(
            "[邮箱换绑] 换绑成功，但自动查活入队失败 account_id=%s email=%s error=%s",
            account_id, email, result.get("error") or "未知错误",
        )
        _append_log(account_id, f"自动查活入队失败：{result.get('error') or '未知错误'}")
    return result


def _login_via_password_then_totp(
    session: BrowserSession,
    email: str,
    password: str,
    otp_after_ts: float,
    email_source: str | None = None,
) -> dict:
    """密码 → TOTP 的完整重认证链，完全不碰邮箱取码。

    account_liveness._login_via_password_or_otp() 是直接 POST /api/accounts/password/verify，
    但该端点要求 session 已处于 log-in/password 状态，否则服务端直接回 409（实测无 body）。
    所以必须先走 get_csrf_token → signin_openai → follow_authorize 落到 /log-in/password。
    与 tools/password_verify_login.py 里已跑通的链完全一致。
    """
    from core.account_liveness import (
        _complete_mfa_if_challenged,
        _extract_continue_url,
        _follow_continue_and_fetch,
        _password_verify,
    )
    from core.chatgpt_auth import get_csrf_token, signin_openai
    from core.openai_auth import follow_authorize

    csrf = get_csrf_token(session)
    auth_url = signin_openai(session, csrf, email)
    landing = str(follow_authorize(session, auth_url) or "")
    if "/log-in/password" not in landing:
        raise RuntimeError("密码重认证没落到密码页，落点=" + landing[:120])

    result = _password_verify(session, password)
    continue_url = _extract_continue_url(result)
    page = (result or {}).get("page") if isinstance(result, dict) else {}
    page = page if isinstance(page, dict) else {}
    page_type = str(page.get("type") or "")
    if not continue_url:
        raise RuntimeError("密码校验没有 continue_url: " + str(result)[:200])
    if "email-verification" in str(continue_url):
        raise RuntimeError("密码被拒，服务端转去邮箱验证")
    continue_url, used_mfa = _complete_mfa_if_challenged(session, email, continue_url, page_type)
    logger.info("[换绑] 密码+TOTP 重认证完成，used_mfa=%s", used_mfa)
    return _follow_continue_and_fetch(
        session,
        continue_url,
        referer="https://auth.openai.com/mfa-challenge/" if used_mfa else "https://auth.openai.com/log-in/password",
    )


def _refresh_recent_login(
    session: BrowserSession,
    *,
    account_id: int,
    email: str,
    email_source: str,
    access_token: str,
) -> str:
    """复用已验证的 2FA 流程，预热登录态并完成一次重认证。

    重认证有两条链：

    * _login_via_password_or_otp —— 密码 → /mfa-challenge → TOTP。
      **有密码 + 有 totp_secret 时优先走这条**：老邮箱（iCloud / remail 之类）
      早就死了也能换绑，完全不碰邮箱取码。
    * _login_via_reauth —— reauth signin → authorize → 原邮箱 OTP（→ 可能再过 TOTP）。
      只在没有密码时兜底。
    """
    # 延迟导入，避免 account_liveness 初始化时形成模块循环。
    from core.account_liveness import (
        _login_via_password_or_otp,
        _login_via_reauth,
        _warm_authenticated_session,
    )
    from core.codex_oauth import _account_registration_password

    _append_log(account_id, "开始账号级指纹预热（复用现有 accessToken）")
    warm_started = time.monotonic()
    _warm_authenticated_session(session, access_token)
    _append_log(account_id, f"登录态预热完成：cost={_cost(warm_started)}")

    otp_after_ts = time.time()
    reauth_started = time.monotonic()

    password = ""
    try:
        password = _account_registration_password(email) or ""
    except Exception as exc:
        _append_log(account_id, f"读取注册密码失败（改用邮箱 OTP）：{exc}")

    if password:
        _append_log(
            account_id,
            "Recent Login 开始（密码 + TOTP 链）：signin_openai → authorize → /log-in/password → password/verify → /mfa-challenge → TOTP",
        )
        try:
            info = _login_via_password_then_totp(
                session, email, password, otp_after_ts, email_source=email_source or None,
            )
        except Exception as exc:
            _append_log(account_id, f"密码+TOTP 重认证失败，回落邮箱 OTP：{type(exc).__name__}: {exc}")
            info = _login_via_reauth(
                session, email, otp_after_ts, email_source=email_source or None,
            )
    else:
        _append_log(
            account_id,
            "Recent Login 开始（邮箱 OTP 链）：CSRF → reauth signin → authorize → 原邮箱 OTP → OAuth callback → session/AT",
        )
        info = _login_via_reauth(
            session, email, otp_after_ts, email_source=email_source or None,
        )
    fresh_token = str((info or {}).get("accessToken") or "").strip()
    if not fresh_token:
        raise RuntimeError("Recent Login 重认证完成，但未获取到新 access_token")
    _append_log(
        account_id,
        f"Recent Login 完成：原邮箱 OTP 已验证，已获取新鲜 AT，cost={_cost(reauth_started)}",
    )
    return fresh_token


def _begin_change_with_optional_reauth(
    session: BrowserSession,
    *,
    account_id: int,
    current_email: str,
    current_source: str,
    new_email: str,
    access_token: str,
) -> tuple[BrowserSession, str, float, bool]:
    """优先直接 begin；仅在服务端明确要求 Recent Login 时验证原邮箱。"""
    otp_after_ts = time.time()
    try:
        _, session = _post_with_network_retry(
            session,
            account_id=account_id,
            path="/backend-api/accounts/change_email/begin",
            token=access_token,
            payload={"email": new_email},
            fingerprint_email=current_email,
        )
        _append_log(account_id, "现有 AT 满足 Recent Login 要求，已跳过原邮箱 OTP 重认证")
        return session, access_token, otp_after_ts, False
    except Exception as exc:
        if not _is_reauth_required(exc):
            raise

    _append_log(account_id, "服务端返回 reauth_required，开始执行原邮箱 OTP 重认证")
    fresh_token = _refresh_recent_login(
        session,
        account_id=account_id,
        email=current_email,
        email_source=current_source,
        access_token=access_token,
    )
    # 新邮箱 OTP 的时间基准必须放在第二次 begin 之前，不能沿用重认证前时间。
    otp_after_ts = time.time()
    _, session = _post_with_network_retry(
        session,
        account_id=account_id,
        path="/backend-api/accounts/change_email/begin",
        token=fresh_token,
        payload={"email": new_email},
        fingerprint_email=current_email,
    )
    _append_log(account_id, "原邮箱重认证完成，使用新鲜 AT 重试 begin 成功")
    return session, fresh_token, otp_after_ts, True


def _check_live_in_current_session(
    session: BrowserSession,
    *,
    account_id: int,
    email: str,
    email_source: str,
) -> dict:
    """换绑后复用当前已通过 CF/reauth 的会话重新登录并刷新 AT。"""
    from core.account_liveness import (
        _login_via_password_or_otp,
        _safe_fingerprint_for_account,
        _safe_fingerprint_text_for_account,
    )
    from core.chatgpt_auth import get_csrf_token, signin_openai
    from core.openai_auth import follow_authorize

    live_started = time.monotonic()
    _append_log(account_id, "原会话查活开始：复用 Cookie、CF 状态、出口和当前指纹")
    step_started = time.monotonic()
    csrf = get_csrf_token(session)
    _append_log(account_id, f"原会话查活：CSRF 获取成功，cost={_cost(step_started)}")
    step_started = time.monotonic()
    authorize_url = signin_openai(session, csrf, email)
    _append_log(account_id, f"原会话查活：signin 成功并取得 authorize URL，cost={_cost(step_started)}")
    otp_after_ts = time.time()
    step_started = time.monotonic()
    follow_authorize(session, authorize_url)
    _append_log(account_id, f"原会话查活：authorize 跟随完成，进入密码/OTP/MFA 阶段，cost={_cost(step_started)}")
    step_started = time.monotonic()
    session_info = _login_via_password_or_otp(
        session,
        email,
        otp_after_ts,
        email_source=email_source or None,
    )
    access_token = str((session_info or {}).get("accessToken") or "").strip()
    if not access_token:
        raise RuntimeError("换绑后原会话查活未获取到 access_token")
    _append_log(account_id, f"原会话查活：登录验证及 session 获取成功，cost={_cost(step_started)}")
    result = {
        "ok": True,
        "status": "live",
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "access_token": access_token,
        "session": session_info,
        "proxy_used": session.proxy or None,
        "fingerprint": _safe_fingerprint_for_account(session),
        "fingerprint_text": _safe_fingerprint_text_for_account(session),
    }
    db.update_account_liveness(account_id, result)
    _append_log(account_id, f"原会话查活成功：最新 AT 已写回，total={_cost(live_started)}")
    return result


def _run(account_id: int, source: str, forced_email: str | None = None) -> dict:
    new_email = ""
    task_started = time.monotonic()
    stage = "初始化"
    with _LOCK:
        _RUNNING.add(account_id)
    try:
        _append_log(account_id, f"任务执行开始：account_id={account_id} source={source}")
        stage = "读取账号"
        account = db.get_account(account_id)
        if not account:
            raise RuntimeError("账号不存在")
        token = str(account.get("access_token") or "").strip()
        if not token:
            raise RuntimeError("账号缺少 access_token，请先查活刷新 AT")
        stage = "领取新邮箱"
        acquire_started = time.monotonic()
        if forced_email:
            # 指定新邮箱：不按 id 升序领，避免领到池里那些已经删掉的死地址。
            new_email = str(forced_email).strip()
            _append_log(account_id, f"使用指定新邮箱：{new_email}")
            try:
                from core.imap_mail_client import release_account as _release_imap
                if db.get_imap_email_by_email(new_email):
                    _release_imap(new_email, status="used", note="换绑占用")
                    _append_log(account_id, "已在 IMAP 池标记该地址为已占用")
            except Exception as exc:
                _append_log(account_id, f"标记 IMAP 池占用失败（忽略）：{exc}")
        else:
            new_email = acquire_email_from_source(source)
            _append_log(account_id, f"新邮箱领取成功：source={source} email={new_email} cost={_cost(acquire_started)}")
        if new_email.lower() == str(account.get("email") or "").lower():
            raise RuntimeError("领取到的邮箱与当前邮箱相同")
        if not db.mark_account_email_change_running(account_id, new_email):
            raise RuntimeError("换绑任务状态已失效")

        stage = "创建网络会话"
        saved_proxy = _proxy(account.get("proxy_used"))
        # 账号没有可复用的真实代理 URL 时，先按全局代理池选路，而不是直接裸连。
        current_email = str(account.get("email") or "").strip()
        current_source = str(account.get("email_source") or "").strip().lower()
        session = _new_session(account_id, saved_proxy or None, email=current_email)
        _append_log(
            account_id,
            f"网络会话已创建：route={'账号代理' if saved_proxy else '全局代理池/默认网络'} "
            f"proxy={_proxy_label(getattr(session, 'proxy', None))}",
        )
        _append_log(account_id, f"指纹摘要：{session.fingerprint_summary_text()}")

        logger.info("[邮箱换绑] begin account_id=%s old=%s new=%s source=%s", account_id, account.get("email"), new_email, source)
        _append_log(account_id, f"开始换绑：原邮箱={account.get('email') or '-'}，新邮箱={new_email}，来源={source}")
        stage = "发送新邮箱验证码/按需重认证"
        session, token, after_ts, reauthenticated = _begin_change_with_optional_reauth(
            session,
            account_id=account_id,
            current_email=current_email,
            current_source=current_source,
            new_email=new_email,
            access_token=token,
        )
        _append_log(
            account_id,
            f"新邮箱验证码发送成功，开始等待 OTP；reauth={'yes' if reauthenticated else 'no'}",
        )
        stage = "等待新邮箱 OTP"
        otp_started = time.monotonic()
        otp = wait_for_otp(new_email, after_ts=after_ts, email_source=source, force_service=True)
        _append_log(account_id, f"新邮箱 OTP 获取成功：source={source} cost={_cost(otp_started)}（验证码不写入日志）")
        stage = "验证新邮箱 OTP"
        _, session = _post_with_network_retry(
            session, account_id=account_id,
            path="/backend-api/accounts/change_email/verify", token=token,
            payload={"email": new_email, "code": otp},
            fingerprint_email=current_email,
        )
        _append_log(account_id, "新邮箱 OTP 服务端验证成功，开始更新本地账号记录")

        stage = "更新本地账号"
        db_started = time.monotonic()
        db.finish_account_email_change(
            account_id, ok=True, new_email=new_email, source=source,
            material_line=email_material_line(new_email, source),
        )
        _append_log(account_id, f"本地账号更新成功：current_email={new_email}，旧 AT 已清空，cost={_cost(db_started)}")
        # 抓包显示 verify 后旧 AT 会立刻 401，但当前会话中的 __cf_bm、OAuth
        # Cookie 和出口连续性仍然有效。优先在该会话内重新登录，避免另建会话后
        # `/api/auth/csrf` 被 CF 403；原会话失败时再退回后台查活队列。
        stage = "换绑后自动查活"
        try:
            live_result = _check_live_in_current_session(
                session,
                account_id=account_id,
                email=new_email,
                email_source=source,
            )
            live_mode = "same_session"
        except Exception as live_exc:
            _append_log(
                account_id,
                f"原会话查活失败：{type(live_exc).__name__}: {str(live_exc)[:300]}；改用后台查活队列",
            )
            logger.warning("[邮箱换绑] 原会话查活失败 account_id=%s: %s", account_id, str(live_exc)[:300])
            live_result = _enqueue_live_check_after_change(account_id, new_email)
            live_mode = "queued"
        logger.info("[邮箱换绑] 成功 account_id=%s new=%s；已执行换绑后查活", account_id, new_email)
        _append_log(account_id, f"换绑任务完成：live_check_mode={live_mode} total={_cost(task_started)}")
        return {
            "ok": True, "id": account_id, "email": new_email,
            "live_check_started": bool(live_result.get("ok") or live_result.get("accepted")),
            "live_check_mode": live_mode,
            "live_check_error": None if (live_result.get("ok") or live_result.get("accepted")) else live_result.get("error"),
        }
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        db.finish_account_email_change(account_id, ok=False, new_email=new_email or None, source=source, error=error)
        _append_log(account_id, f"换绑失败：stage={stage} total={_cost(task_started)} error={error}")
        if new_email:
            try:
                release_email_if_unconsumed(new_email, note=f"账号 #{account_id} 换绑失败: {error[:300]}")
                _append_log(account_id, f"失败邮箱处理完成：已请求回收 email={new_email}")
            except Exception:
                _append_log(account_id, f"失败邮箱回收异常：email={new_email}")
                logger.exception("[邮箱换绑] 回收新邮箱失败: %s", new_email)
        logger.exception("[邮箱换绑] 失败 account_id=%s", account_id)
        return {"ok": False, "id": account_id, "error": error}
    finally:
        with _LOCK:
            _RUNNING.discard(account_id)
        _SLOTS.release()


def enqueue(account_id: int, source: str, trigger: str = "manual",
            forced_email: str | None = None) -> dict:
    account_id = int(account_id)
    source = str(source or "").strip().lower()
    if not _SLOTS.acquire(blocking=False):
        return {"accepted": False, "error": "邮箱换绑队列已满"}
    if not db.claim_account_email_change(account_id, source, trigger):
        _SLOTS.release()
        return {"accepted": False, "busy": True, "error": "账号正在换绑或不存在"}
    _append_log(account_id, f"换绑任务已入队：source={source} trigger={trigger}", clear=True)
    try:
        future = _EXECUTOR.submit(_run, account_id, source, forced_email)
        return {"accepted": True, "future": future}
    except Exception as exc:
        _SLOTS.release()
        db.finish_account_email_change(account_id, ok=False, error=str(exc))
        _append_log(account_id, f"换绑任务提交失败：{type(exc).__name__}: {exc}")
        return {"accepted": False, "error": str(exc)}


def is_running(account_id: int) -> bool:
    with _LOCK:
        return int(account_id) in _RUNNING
