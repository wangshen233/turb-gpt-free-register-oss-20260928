# -*- coding: utf-8 -*-
"""账号 2FA/TOTP 后台设置队列。"""
from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from config import email as _email_cfg
from core import db
from core.account_export import setup_2fa
from core.session import BrowserSession

logger = logging.getLogger(__name__)

# 并发度可调：默认 2（原行为）。2FA 的瓶颈几乎全在「等邮箱码」上（实测 ic-mail
# 网关发码最慢能到 t+145s），2 并发跑 40 个号要几个小时。放大不会让**同一个号**被
# 并发处理 —— 每个 account_id 只入队一次，_QUEUE_SLOTS 仍然限总量。
_EXECUTOR_WORKERS = max(1, int(os.environ.get("TWOFA_MAX_WORKERS") or 2))
_EXECUTOR = ThreadPoolExecutor(max_workers=_EXECUTOR_WORKERS, thread_name_prefix="twofa")
_QUEUE_SLOTS = threading.BoundedSemaphore(max(50, _EXECUTOR_WORKERS * 8))
_RUNNING: set[int] = set()
_LOCK = threading.Lock()
_LOG_DIR = Path(__file__).resolve().parent.parent / "注册日志"


def log_path(email: str) -> Path:
    safe = str(email or "").replace("/", "_").replace("\\", "_").replace(":", "_")
    return _LOG_DIR / f"twofa-{safe}.log"


def _normalize_proxy(proxy: str | None) -> str | None:
    """
    2FA 入口只接受真实代理地址。

    注册流程里有些 `proxy_used` 字段保存的是环境标签，例如 `skyvern:jp`、
    `browser_use:jp`，这类不是 curl_cffi 可用代理，会导致 Unsupported proxy syntax。
    """
    text = str(proxy or "").strip()
    if not text:
        return None
    low = text.lower()
    if low.startswith(("http://", "https://", "socks5://", "socks5h://", "socks4://", "socks4a://")):
        return text
    return None


def is_running(acc_id: int) -> bool:
    with _LOCK:
        return int(acc_id) in _RUNNING


def _append_log(email: str, line: str, *, clear: bool = False) -> None:
    p = log_path(email)
    p.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%H:%M:%S")
    mode = "w" if clear else "a"
    with p.open(mode, encoding="utf-8") as f:
        f.write(f"{stamp} [INFO] {line}\n")


def _run_twofa(
    *, account_id: int, email: str, access_token: str, proxy: str | None,
    trigger: str,
) -> dict:
    fh: logging.FileHandler | None = None
    root_logger = logging.getLogger()
    thread_name = threading.current_thread().name
    try:
        with _LOCK:
            _RUNNING.add(int(account_id))
        if not db.mark_account_totp_setup_running(account_id):
            return {"ok": False, "status": "failed", "error": "账号已删除或 2FA 状态已被重置"}
        log_file = log_path(email)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.write_text("", encoding="utf-8")
        fh = logging.FileHandler(str(log_path(email)), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
        fh.addFilter(lambda record: record.threadName == thread_name)
        root_logger.addHandler(fh)
        logger.info("[2FA] 开始后台设置：email=%s trigger=%s", email, trigger)
        real_proxy = _normalize_proxy(proxy)
        identity = email.strip().lower()
        session = BrowserSession(proxy=real_proxy, fingerprint_seed=f"account:{identity}")
        _append_log(email, f"[2FA] 会话创建完成：proxy={session.proxy or 'direct'} device_id={session.device_id}")
        _append_log(email, f"[2FA] 指纹摘要：{session.fingerprint_summary_text()}")
        secret = setup_2fa(session, email, access_token=access_token)
        # setup_2fa 重认证后会换发新 token，挂在 session 上；这里连同 secret 一起写回，
        # 避免数据库里长期保留注册时的旧 token（服务端吊销后账号会变成登不进去）。
        refreshed = str(getattr(session, "refreshed_access_token", "") or "").strip()
        if refreshed and refreshed != str(access_token or "").strip():
            _append_log(email, "[2FA] 已换发新 accessToken，写回数据库")
            logger.info("[2FA] 已换发新 accessToken: %s...%s", refreshed[:12], refreshed[-8:])
        db.update_account_totp_secret(
            account_id,
            {
                "ok": True,
                "status": "success",
                "totp_secret": secret,
                "access_token": refreshed or None,
                "message": "2FA 设置完成",
            },
        )
        _append_log(email, f"[2FA] 完成：secret={secret[:4]}...{secret[-4:]}")
        logger.info("[2FA] 完成：email=%s secret=%s...%s", email, secret[:4], secret[-4:])
        return {"ok": True, "status": "success", "totp_secret": secret, "message": "2FA 设置完成"}
    except Exception as exc:
        result = {"ok": False, "status": "failed", "error": f"{type(exc).__name__}: {str(exc)[:500]}"}
        try:
            db.update_account_totp_secret(account_id, result)
        except Exception:
            logger.exception("[2FA] 写回失败状态失败: account_id=%s", account_id)
        try:
            _append_log(email, f"[2FA] 失败：{result['error']}")
        except Exception:
            pass
        logger.exception("[2FA] 后台异常: %s", email)
        return result
    finally:
        if fh is not None:
            try:
                root_logger.removeHandler(fh)
                fh.close()
            except Exception:
                pass
        with _LOCK:
            _RUNNING.discard(int(account_id))
        release_account_lock(account_id)
        _QUEUE_SLOTS.release()


_LOCK_DIR = Path(__file__).resolve().parent.parent / "注册日志" / ".twofa_locks"


def acquire_account_lock(account_id: int) -> bool:
    """跨进程独占锁：同一个账号同时只能有一个 2FA 流程在跑。

    为什么需要：claim_account_totp_setup 的状态写在库里，但 twofa_drain.py 的
    --force-recover 会把看起来像孤儿的 queued/running 复位成 stopped —— 如果此时
    **另一个进程其实还在跑这个账号**，就会有两个流程并发操作同一个账号。
    实测后果很严重：一个流程完成了 enroll（服务端已经开了 TOTP），另一个流程随后
    失败并覆盖状态，**secret 就永久丢了**（special.blaster-0b 就是这么变成
    「服务端有 2FA、我们手里没有密钥」的）。

    用文件锁做进程间互斥；进程崩溃留下的陈旧锁按 mtime 超过 30 分钟视为失效。
    """
    try:
        _LOCK_DIR.mkdir(parents=True, exist_ok=True)
        p = _LOCK_DIR / ("acc_%d.lock" % int(account_id))
        if p.exists():
            try:
                if time.time() - p.stat().st_mtime < 1800:
                    return False
                # 陈旧锁（持有进程已经死了，没人来 release）：**必须先删掉**。
                # 不删的话下面的 O_CREAT|O_EXCL 一定 FileExistsError → 永远返回
                # False → 这个账号的 2FA 就永久卡死，drain 每次看它都是 busy。
                p.unlink(missing_ok=True)
            except OSError:
                pass
        fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode("ascii"))
        os.close(fd)
        return True
    except FileExistsError:
        return False
    except Exception:
        return True   # 锁机制本身出问题时不阻断主流程


def release_account_lock(account_id: int) -> None:
    try:
        p = _LOCK_DIR / ("acc_%d.lock" % int(account_id))
        p.unlink(missing_ok=True)
    except Exception:
        pass


def enqueue_account_totp_setup(
    *,
    account_id: int,
    email: str,
    access_token: str,
    trigger: str = "manual",
    proxy: str | None = None,
) -> dict:
    account_id = int(account_id)
    email = str(email or "").strip()
    access_token = str(access_token or "").strip()
    if not email:
        return {"accepted": False, "busy": False, "error": "email 为空"}
    if not access_token:
        return {"accepted": False, "busy": False, "error": "缺少 access_token"}
    if not bool(getattr(_email_cfg, "USE_EMAIL_SERVICE", False)):
        return {"accepted": False, "busy": False, "error": "启用 2FA 需要先开启 USE_EMAIL_SERVICE 自动收取邮箱验证码"}
    if not acquire_account_lock(account_id):
        return {"accepted": False, "busy": True,
                "error": "该账号已有另一个 2FA 流程在跑（跨进程锁），拒绝并发"}
    if not _QUEUE_SLOTS.acquire(blocking=False):
        release_account_lock(account_id)
        return {"accepted": False, "busy": False, "queue_full": True, "error": "2FA 队列已满，请稍后重试"}
    if not db.claim_account_totp_setup(acc_id=account_id, trigger=trigger):
        _QUEUE_SLOTS.release()
        release_account_lock(account_id)
        return {"accepted": False, "busy": True, "error": "该账号正在设置 2FA"}

    _append_log(email, f"[2FA] 已入队 account_id={account_id} trigger={trigger}", clear=True)
    try:
        future = _EXECUTOR.submit(
            _run_twofa,
            account_id=account_id,
            email=email,
            access_token=access_token,
            proxy=proxy,
            trigger=str(trigger or "manual"),
        )
        return {"accepted": True, "busy": False, "future": future, "log_path": str(log_path(email))}
    except Exception as exc:
        _QUEUE_SLOTS.release()
        db.update_account_totp_secret(account_id, {"ok": False, "status": "failed", "error": f"{type(exc).__name__}: {exc}"})
        return {"accepted": False, "busy": False, "error": f"{type(exc).__name__}: {exc}"}
