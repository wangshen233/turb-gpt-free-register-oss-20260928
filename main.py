# -*- coding: utf-8 -*-
"""
ChatGPT 协议注册全流程入口
串联 12 个步骤，自动完成 ChatGPT 账号注册
"""
import os
import sys
import argparse
import logging
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Callable

from config import REGISTER_EMAIL, REGISTER_NAME  # 这两个一般不在 WebUI 改
# 可热改的，按模块属性方式读
from config import email as _email_cfg
from config import roxybrowser as _roxy_cfg
from config import openai_protocol as _protocol_cfg
import threading
from core.account_export import (
    create_batch_archive_dir,
    save_account_data,
)
from core.name_samples import random_display_name
from core.profile_utils import generate_random_birthday

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)



def configure_logging(verbose: bool = False) -> None:
    """配置 CLI 日志：默认简洁，--verbose 时显示完整步骤细节。"""
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    for handler in root.handlers:
        handler.setLevel(logging.DEBUG if verbose else logging.INFO)

    if verbose:
        logging.getLogger("core").setLevel(logging.DEBUG)
        return

    logging.getLogger("core").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def _is_success(result: dict) -> bool:
    """判断单次注册结果是否成功，集中收敛批量统计规则。"""
    return isinstance(result, dict) and bool(result.get("success"))


def generate_display_name() -> str:
    """生成只包含英文字母和空格的显示名，符合注册接口限制。"""
    return random_display_name()


def prepare_registration_inputs() -> tuple[str | None, str, str]:
    """按 CLI 规则准备一次注册所需的邮箱、显示名和生日。"""
    email = REGISTER_EMAIL
    name = REGISTER_NAME
    birthday = generate_random_birthday()

    # 邮箱：自动模式下先留空；浏览器驱动会在页面找到邮箱输入框后领取，
    # protocol 驱动会在 run_registration 开始认证前领取。
    if not email:
        if not _email_cfg.USE_EMAIL_SERVICE:
            email = input("请输入注册邮箱: ").strip()

    # 显示名称：未填则随机生成
    # OpenAI 限制：name_invalid_chars —— 只允许字母和空格，不能含数字/标点
    if not name:
        if _email_cfg.USE_EMAIL_SERVICE:
            name = generate_display_name()
            logger.debug(f"自动生成显示名称: {name}")
        else:
            name = input("请输入显示名称: ").strip()

    if not name:
        raise RuntimeError("显示名称不能为空")
    if not email and not _email_cfg.USE_EMAIL_SERVICE:
        raise RuntimeError("邮箱不能为空")

    return email, name, birthday


_BOOTSTRAP_EXECUTOR: ThreadPoolExecutor | None = None
_BOOTSTRAP_EXECUTOR_LOCK = threading.Lock()


def _schedule_authenticated_bootstrap(session, access_token: str | None) -> bool:
    """登录态预热：默认扔到后台线程，返回 True 表示已异步调度。

    实测这一步串行打十来个 /backend-api 请求要 ~18s，占单号墙钟时间约 19%，
    而它发生在账号已建好、accessToken 已拿到之后 —— 卡住只会占着 worker 槽位。
    设 CHATGPT_BOOTSTRAP_ASYNC=False 可退回原来的同步行为；
    CHATGPT_BOOTSTRAP_STRICT=True 时预热失败会中断主流程，必须同步执行。
    """
    if not getattr(_protocol_cfg, "CHATGPT_AUTH_BOOTSTRAP_ENABLED", True):
        return False
    strict = bool(getattr(_protocol_cfg, "CHATGPT_BOOTSTRAP_STRICT", False))
    if strict or not bool(getattr(_protocol_cfg, "CHATGPT_BOOTSTRAP_ASYNC", True)):
        from core.chatgpt_bootstrap import authenticated_bootstrap

        authenticated_bootstrap(session, access_token, strict=strict)
        return False

    global _BOOTSTRAP_EXECUTOR
    with _BOOTSTRAP_EXECUTOR_LOCK:
        if _BOOTSTRAP_EXECUTOR is None:
            workers = max(1, int(getattr(_protocol_cfg, "CHATGPT_BOOTSTRAP_ASYNC_WORKERS", 4) or 4))
            _BOOTSTRAP_EXECUTOR = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="bootstrap")

        def _run() -> None:
            try:
                from core.chatgpt_bootstrap import authenticated_bootstrap

                authenticated_bootstrap(session, access_token, strict=False)
            except Exception as exc:  # best-effort：失败不影响已保存的账号
                logger.warning(
                    "[Bootstrap] 后台预热失败（不影响账号）：%s: %s",
                    type(exc).__name__,
                    str(exc)[:180],
                )

        _BOOTSTRAP_EXECUTOR.submit(_run)
    logger.info("[Bootstrap] 登录态预热已转入后台线程，worker 立即释放")
    return True


def _run_registration_via_protocol(
    email: str | None,
    name: str,
    birthday: str | None,
    proxy: str | None,
    batch_dir,
    on_email_acquired,
) -> dict:
    """协议引擎注册 —— 直接驱动 vendored 的协议注册机。

    老流程整块删掉后，这里只负责「领邮箱 -> 交给协议机 -> 落库 -> 回收邮箱」四件事，
    真正的注册状态机在 vendor/gpt-register-tool/协议/auth_flow.py 里。

    返回值契约与老流程保持一致，批量统计（_is_success）不用改。
    """
    from core.email_provider import (
        acquire_email,
        email_material_line,
        release_email,
        resolve_email_source,
    )
    from core.register_protocol_engine import register as proto_register

    # 协议机没有“邮箱输入框”可等待，所以在起链路之前先领。
    if not str(email or "").strip():
        if not _email_cfg.USE_EMAIL_SERVICE:
            raise RuntimeError(
                "手动模式未配置邮箱。请在注册页填写邮箱，或到配置页设置 REGISTER_EMAIL，"
                "或开启 USE_EMAIL_SERVICE 并从邮箱池领取。"
            )
        email = acquire_email()
        if on_email_acquired:
            on_email_acquired(email)

    source = resolve_email_source(email)
    material = str(email_material_line(email, source) or "")
    # 协议机的 icloud_relay provider 吃的是 "email----中转链接" 两段格式，
    # 正好就是号池里存的那一行 copy_line。
    segments = material.split("----")
    relay_url = segments[1].strip() if len(segments) >= 2 else ""
    if not relay_url:
        err = (
            f"协议引擎需要 iCloud 中转取件链接（email----relay_url），"
            f"但邮箱素材里没有：source={source} line={material[:80]!r}"
        )
        logger.error("[协议引擎] %s", err)
        try:
            release_email(email, status="available", note=err[:150])
        except Exception:
            pass
        return {"success": False, "email": email, "error": err, "network_traffic": None}

    # ⚠️ 代理必须是真的。
    # 协议机拿到空 proxy 时，allocate_environment 会把 None 原样传下去，
    # curl 收到字面量字符串 "None" → "Could not resolve proxy: None"，
    # 整轮白跑（实测 2026-09-22：warmup 20 次全挂在同一个错上，烧掉 9 分钟）。
    # 所以这里先把 proxy 解析出来，解析不到就直接失败，绝不把 None 往下传。
    resolved_proxy = str(proxy or "").strip()
    if not resolved_proxy:
        try:
            from config import proxy as _proxy_cfg
            pool = list(getattr(_proxy_cfg, "PROXY_POOL", []) or [])
        except Exception:
            pool = []
        if pool:
            import random as _random
            resolved_proxy = str(_random.choice(pool)).strip()
        else:
            resolved_proxy = str(os.environ.get("PROTOCOL_PROXY", "") or "").strip()
    if not resolved_proxy:
        err = (
            "协议引擎需要出口代理，但 config.PROXY_POOL 是空的、也没设 PROTOCOL_PROXY。"
            "（老流程会用 BrowserSession 兜底，协议机没有兜底，传空会让 curl 去解析主机名 'None'）"
        )
        logger.error("[协议引擎] %s", err)
        try:
            release_email(email, status="available", note=err[:150])
        except Exception:
            pass
        return {"success": False, "email": email, "error": err, "network_traffic": None}

    logger.info("[协议引擎] 注册 %s（来源=%s，代理=%s）", email, source, resolved_proxy)

    try:
        data = proto_register(email, relay_url, proxy=resolved_proxy)
    except Exception as exc:
        err = f"{type(exc).__name__}: {exc}"
        logger.error("[协议引擎] %s 异常：%s", email, err)
        try:
            release_email(email, status="available", note=f"协议引擎异常: {err[:140]}")
        except Exception:
            pass
        return {"success": False, "email": email, "error": err, "network_traffic": None}

    if not data.get("ok"):
        err = str(data.get("error") or "未知错误")
        logger.error("[协议引擎] %s 失败：%s", email, err[:300])
        try:
            release_email(email, status="available", note=f"协议引擎失败: {err[:140]}")
        except Exception:
            pass
        return {"success": False, "email": email, "error": err, "network_traffic": None}

    d = data.get("result") or {}
    access_token = str(d.get("access_token") or "")
    totp_secret = str(d.get("totp_secret") or "")
    partial = bool(data.get("partial"))

    account_id = save_account_data(
        email=email,
        access_token=access_token,
        totp_secret=totp_secret,
        email_source=source,
        proxy_used=resolved_proxy,
        batch_dir=batch_dir,
        extra={
            "engine": "protocol",
            # ⚠️ 键名必须是 registration_password —— WebUI 读的就是它
            #    （webui/app.py:111 与 core/account_export.py:67 都只认这个键）。
            #    塞成 "password" 的话库里其实有密码，但页面上显示「未设置」。
            "registration_password": d.get("password"),
            "device_id": d.get("device_id"),
            "session_token": d.get("session_token"),
            "refresh_token": d.get("refresh_token"),
            "id_token": d.get("id_token"),
            "csrf_token": d.get("csrf_token"),
            "cookie_header": d.get("cookie_header"),
            "partial": partial,
            # 流量：WebUI 读 extra_json["network_traffic"]（webui/app.py:118）。
            # 协议引擎的流量由桥从子进程的 http_client.TRAFFIC 搬出来。
            "network_traffic": data.get("network_traffic") or None,
            # ⚠️ plan_type 必须给，否则页面上优惠信息一个字都不显示。
            #    WebUI 的 _planCell 只在 plan == 'free' 时才渲染优惠块
            #    （index.html:3563），不是 free 直接走另一分支把 promo_summary 丢掉。
            #    新注册的号必然是 free 档。
            "account": {"planType": "free"},
        },
    )
    logger.info(
        "[完成] %s，账号ID=%s，Token=%s… (partial=%s)",
        email, account_id, access_token[:16], partial,
    )

    # ⚠️ 成功注册后必须把邮箱标成 used。
    #    不标的话它会一直留在 available，下一轮又被领一遍 → 409 invalid_state 白烧一个号。
    #    2026-09-22 实测：1409 / 1410 注册完状态还是 available。
    #    注意这是**成功路径**的标记，跟上面失败分支的 release(available) 是两回事。
    try:
        release_email(email, status="used", note=f"已注册，账号ID={account_id}")
    except Exception as exc:
        logger.warning("[协议引擎] %s 邮箱标记 used 失败：%s", email, exc)

    return {
        "success": bool(access_token),
        "email": email,
        "account_id": account_id,
        "access_token": access_token,
        "totp_secret": totp_secret,
        "flow": {"status": "skipped", "ok": False, "message": "协议引擎"},
        "codex": {"status": "skipped", "ok": False, "message": "协议引擎"},
        "network_traffic": None,
        "error": None,
    }


def run_registration(
    email: str | None,
    name: str,
    birthday: str | None = None,
    proxy: str = None,
    otp_code: str = None,
    batch_dir=None,
    on_email_acquired: Callable[[str], None] | None = None,
):
    """
    执行完整的 ChatGPT 注册流程（OTP-only，无密码）。

    OpenAI 当前默认流程：signin 时携带 login_hint+screen_hint=signup（2026-09-12 起）
    → follow_authorize 重定向链自动落到 /email-verification 并触发 OTP 发送
    → 用户输入验证码 → validate_email_otp → about-you 提交昵称生日 → 完成。

    Args:
        email: 注册邮箱
        name: 用户显示名称
        birthday: 生日，格式 YYYY-MM-DD
        proxy: 代理地址（不传则从 PROXY_POOL 随机抽）
        otp_code: 邮箱验证码（如果为None，会等待手动输入）
    """
    # 可选注册驱动：
    #   protocol     = 原有纯协议（curl_cffi）
    #   roxy         = RoxyBrowser 指纹浏览器 + Selenium
    #   cloak        = CloakBrowser + Playwright/Selenium 适配层
    #   browser_use  = Browser Use Cloud stealth Chromium + Playwright
    #   skyvern      = Skyvern Browser Sessions + Playwright
    driver_mode = str(getattr(_roxy_cfg, "REGISTRATION_DRIVER", "protocol") or "protocol").strip().lower()
    if driver_mode in ("roxy", "roxybrowser", "fingerprint", "browser"):
        from core.roxy_registration import run_roxy_registration
        return run_roxy_registration(
            email=email,
            name=name,
            birthday=birthday or generate_random_birthday(),
            proxy=proxy,
            otp_code=otp_code,
            batch_dir=batch_dir,
            on_email_acquired=on_email_acquired,
        )
    if driver_mode in ("cloak", "cloakbrowser"):
        from core.cloakbrowser_registration import run_cloak_registration
        return run_cloak_registration(
            email=email,
            name=name,
            birthday=birthday or generate_random_birthday(),
            proxy=proxy,
            otp_code=otp_code,
            batch_dir=batch_dir,
            on_email_acquired=on_email_acquired,
        )
    if driver_mode in ("browser_use", "browseruse", "browser-use", "bu"):
        from core.browser_use_registration import run_browser_use_registration
        return run_browser_use_registration(
            email=email,
            name=name,
            birthday=birthday or generate_random_birthday(),
            proxy=proxy,
            otp_code=otp_code,
            batch_dir=batch_dir,
            on_email_acquired=on_email_acquired,
        )
    if driver_mode in ("skyvern", "sv"):
        from core.skyvern_registration import run_skyvern_registration
        return run_skyvern_registration(
            email=email,
            name=name,
            birthday=birthday or generate_random_birthday(),
            proxy=proxy,
            otp_code=otp_code,
            batch_dir=batch_dir,
            on_email_acquired=on_email_acquired,
        )
    if driver_mode not in ("protocol", "api", "http"):
        raise RuntimeError(
            f"不支持的 REGISTRATION_DRIVER={driver_mode!r}，可选 protocol / roxy / cloak / browser_use / skyvern"
        )

    # ==================== 协议引擎（默认）====================
    # turb 原来那套协议注册（network_preflight / follow_authorize / sentinel /
    # create_account / _finalize_registration_session …）**已整块删除**，
    # 活交给 vendored 的协议注册机（vendor/gpt-register-tool/协议/）。
    # 想回退到老流程：git 里翻这次替换之前的 main.py（见 commit 说明）。
    return _run_registration_via_protocol(
        email=email,
        name=name,
        birthday=birthday,
        proxy=proxy,
        batch_dir=batch_dir,
        on_email_acquired=on_email_acquired,
    )



def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="ChatGPT 协议注册 CLI")
    parser.add_argument("-n", "--count", type=int, default=1, help="连续注册数量，默认 1")
    parser.add_argument("--workers", type=int, default=1, help="并发注册线程数，默认 1（串行）")
    parser.add_argument("--delay", type=float, default=0, help="每次注册结束后的间隔秒数")
    parser.add_argument("--continue-on-fail", action="store_true", help="单个账号失败后继续注册下一个")
    parser.add_argument("--verbose", action="store_true", help="显示详细步骤日志和错误堆栈")
    args = parser.parse_args()
    configure_logging(args.verbose)

    if args.count < 1:
        logger.error("注册数量必须大于 0")
        sys.exit(1)

    if args.workers < 1:
        logger.error("并发线程数必须大于 0")
        sys.exit(1)

    if args.count > 1 and REGISTER_EMAIL:
        logger.error("config.REGISTER_EMAIL 已固定邮箱，不适合批量注册；请留空后再使用 --count")
        sys.exit(1)

    if args.workers > 1 and not _email_cfg.USE_EMAIL_SERVICE:
        logger.error("多线程注册需要启用 Outlook 自动取件；请开启 USE_EMAIL_SERVICE 或改用 --workers 1")
        sys.exit(1)

    if args.workers > args.count:
        logger.info(f"[批量] 并发线程数 {args.workers} 大于目标数量，已按 {args.count} 个任务执行")
        args.workers = args.count

    if args.workers > 1:
        batch_dir = create_batch_archive_dir(args.count, args.workers)
        logger.info("[批量] 账号数据将直接写入 SQLite")
        results = run_parallel_batch(args.count, args.workers, args.delay, args.continue_on_fail, batch_dir)
    else:
        batch_dir = create_batch_archive_dir(args.count, args.workers)
        logger.info("[批量] 账号数据将直接写入 SQLite")
        results = run_serial_batch(args.count, args.delay, args.continue_on_fail, batch_dir)

    success_count = sum(1 for r in results if _is_success(r))
    flow_success_count = sum(
        1 for r in results
        if _is_success(r) and isinstance(r.get("flow"), dict) and r["flow"].get("ok")
    )
    flow_failed_count = sum(
        1 for r in results
        if _is_success(r)
        and isinstance(r.get("flow"), dict)
        and r["flow"].get("status") == "failed"
    )
    flow_skipped_count = sum(
        1 for r in results
        if _is_success(r)
        and isinstance(r.get("flow"), dict)
        and r["flow"].get("status") == "skipped"
    )
    codex_success_count = sum(
        1 for r in results
        if _is_success(r) and isinstance(r.get("codex"), dict) and r["codex"].get("ok")
    )
    codex_failed_count = sum(
        1 for r in results
        if _is_success(r)
        and isinstance(r.get("codex"), dict)
        and r["codex"].get("status") == "failed"
    )
    codex_skipped_count = sum(
        1 for r in results
        if _is_success(r)
        and isinstance(r.get("codex"), dict)
        and r["codex"].get("status") == "skipped"
    )
    logger.info(f"[批量] 完成：成功 {success_count} / 尝试 {len(results)} / 目标 {args.count}")
    if success_count:
        logger.info(
            f"[批量] Flow：成功 {flow_success_count} / 失败 {flow_failed_count} / 跳过 {flow_skipped_count}"
        )
        logger.info(
            f"[批量] Codex：成功 {codex_success_count} / 失败 {codex_failed_count} / 跳过 {codex_skipped_count}"
        )
    # 批跑完兜底清僵尸：Roxy 窗口没关干净会锁 disk-cache 槽，下一批每号多烧 6~10 MB。
    try:
        from tools.reap_roxy_zombies import reap_roxy_zombies
        reap_roxy_zombies(quiet=True)
    except Exception:
        pass
    sys.exit(0 if success_count == args.count else 1)


def run_one_batch_item(index: int, total: int, batch_dir=None) -> dict:
    """执行批量注册中的一个任务，返回结构化结果。"""
    logger.info(f"[批量] 开始第 {index + 1}/{total} 个注册")
    try:
        email, name, birthday = prepare_registration_inputs()
        return run_registration(
            email=email,
            name=name,
            birthday=birthday,
            batch_dir=batch_dir,
            # proxy 不传 → BrowserSession 会从 PROXY_POOL 随机抽
        )
    except Exception as exc:
        logger.error(f"[批量] 第 {index + 1} 个注册准备阶段失败: {type(exc).__name__}: {exc}")
        logger.debug("准备阶段错误详情:", exc_info=True)
        return {"success": False, "error": str(exc)}


def run_serial_batch(count: int, delay: float, continue_on_fail: bool, batch_dir=None) -> list[dict]:
    """按原有串行方式执行批量注册。"""
    results = []
    for index in range(count):
        result = run_one_batch_item(index, count, batch_dir)
        results.append(result)
        if not _is_success(result) and not continue_on_fail:
            logger.error("[批量] 当前账号失败，已停止。需要继续跑可加 --continue-on-fail")
            break

        if delay > 0 and index < count - 1:
            logger.info(f"[批量] 等待 {delay} 秒后继续")
            time.sleep(delay)
    return results


def run_parallel_batch(
    count: int,
    workers: int,
    delay: float,
    continue_on_fail: bool,
    batch_dir=None,
) -> list[dict]:
    """使用线程池并发执行批量注册。"""
    logger.info(f"[批量] 启用多线程注册：目标 {count}，并发 {workers}")
    if delay > 0:
        logger.info(f"[批量] 并发模式下 --delay={delay} 表示提交任务之间的错峰间隔")

    results: list[dict] = []
    future_to_index = {}
    next_index = 0
    stop_submitting = False

    def submit_next(executor: ThreadPoolExecutor) -> bool:
        nonlocal next_index
        if stop_submitting or next_index >= count:
            return False
        future = executor.submit(run_one_batch_item, next_index, count, batch_dir)
        future_to_index[future] = next_index
        next_index += 1
        if delay > 0 and next_index < count:
            time.sleep(delay)
        return True

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="reg-cli") as executor:
        while len(future_to_index) < workers and submit_next(executor):
            pass

        while future_to_index:
            done, _ = wait(future_to_index, return_when=FIRST_COMPLETED)
            for future in done:
                index = future_to_index.pop(future)
                try:
                    result = future.result()
                except Exception as exc:
                    logger.error(f"[批量] 第 {index + 1}/{count} 个注册线程异常: {type(exc).__name__}: {exc}")
                    logger.debug("线程错误详情:", exc_info=True)
                    result = {"success": False, "error": str(exc)}
                results.append(result)

                if not _is_success(result) and not continue_on_fail:
                    stop_submitting = True
                    logger.error("[批量] 当前账号失败，已停止提交新任务。已开始的任务会继续跑完。")

            while len(future_to_index) < workers and submit_next(executor):
                pass

    return results


if __name__ == "__main__":
    main()
