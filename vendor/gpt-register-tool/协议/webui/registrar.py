"""注册 worker：调 auth_flow.run_register，并把日志/状态实时推到队列。

每个注册任务跑在独立线程；通过 `RunLogger` 把 `logging` 记录 + tail 状态推
到队列，前端用 SSE 实时收日志。
"""
from __future__ import annotations

import logging
import os
import queue
import sys
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]  # gpt-outlook-register/
sys.path.insert(0, str(ROOT))

from config import Config  # noqa: E402
from auth_flow import AuthFlow  # noqa: E402
from browser_launcher import FingerprintRuntimeMismatch  # noqa: E402
from mail_providers import (  # noqa: E402
    MailProviderError,
    create_mail_provider,
    get_provider_class,
)
from sms_provider import PhoneCallbackController  # noqa: E402

from . import db  # noqa: E402
from .environment import EnvironmentAllocationError, allocate_environment  # noqa: E402
from .probes import ProbeSession, instrument_method, redact_log_message, redact_probe_error  # noqa: E402

# run_id -> queue of log strings; sentinel = None 表示流结束
_run_queues: dict[str, queue.Queue] = {}
_lock = threading.Lock()

# 当前线程正在跑哪个 run。
# ⚠️ 为什么需要这个：QueueLogHandler 是挂在 **root logger** 上的，而 root logger
#    是进程全局的。auto_loop 并发时 N 个 run 各挂一个 handler，每条日志会被
#    广播进**所有** run 的文件和 SSE 流 —— 实测 2026-08-04 三 worker 并发，
#    一个号的记录同时出现在 3 个 .log 里，WebUI 上三个号的日志搅在一起，
#    而 "[4/10] 获取 Sentinel Token..." 这类行不带邮箱，根本分不清是谁的。
#
#    注册链路（auth_flow / mail_providers / sentinel）内部不开任何线程，
#    一个 run 的日志全在自己那条线程上产生，所以线程绑定就能干净切开。
_current_run = threading.local()

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


def _instrument_flow_for_probe(flow: Any, probe: ProbeSession, engine: str) -> Any:
    """Attach run-scoped probes to the important protocol/browser boundaries."""
    if engine == "browser":
        stages = {
            "_warmup": "browser.warmup",
            "_detect_country": "browser.network.observe",
            "_click_signup": "browser.signup.open",
            "_enter_email": "browser.signup.email",
            "_run_auth_steps": "browser.auth.steps",
            "_wait_for_chat_page": "browser.chat.ready",
            "_extract_tokens": "browser.tokens.extract",
            "_fetch_access_token": "browser.tokens.access",
        }
    else:
        stages = {
            "check_proxy": "network.preflight",
            "warmup": "auth.warmup",
            "get_csrf_token": "auth.csrf",
            "get_auth_url": "auth.url",
            "auth_oauth_init": "auth.oauth_init",
            "get_sentinel_token": "auth.sentinel",
            "signup": "auth.signup",
            "register_password": "auth.password",
            "send_otp": "mail.otp.send",
            "verify_otp": "mail.otp.verify",
            "create_account": "auth.account.create",
            "get_auth_session": "auth.session",
            "oauth_codex_rt_exchange": "oauth.codex.exchange",
            "oauth_token_exchange": "oauth.token.exchange",
            "oauth_secondary_authorize_exchange": "oauth.secondary.exchange",
        }
    for method_name, stage in stages.items():
        instrument_method(
            flow, method_name, probe, stage,
            false_is_failure=method_name in {"check_proxy", "warmup", "register_password"},
        )
    return flow


def record_environment_observation(
    run_id: str, probe: ProbeSession, observation: dict,
) -> None:
    """Persist the latest runtime observation and append its probe event."""
    if not isinstance(observation, dict):
        return
    try:
        db.record_run_observation(run_id, observation)
    except Exception as observer_error:
        logging.getLogger("registrar").debug(
            "[environment] 记录运行时观测失败: %s", observer_error
        )
    all_passed = observation.get("all_passed")
    runtime_status = (
        "ok" if all_passed is True
        else "failed" if all_passed is False
        else "skipped"
    )
    probe.mark(
        "environment.runtime",
        runtime_status,
        kind=observation.get("kind", ""),
        all_passed=all_passed,
        checks=observation.get("checks", {}),
        network=observation.get("network", {}),
    )


class QueueLogHandler(logging.Handler):
    """把 logging 记录扔进 run queue + 写 log 文件。

    只收**本 run 线程**产生的日志，见 emit 里的过滤。
    """

    def __init__(self, run_id: str, log_file: Path):
        super().__init__()
        self.run_id = run_id
        self._fh = open(log_file, "a", encoding="utf-8")
        self.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        ))

    def emit(self, record: logging.LogRecord):
        try:
            # emit 是在**打日志的那条线程**里同步跑的，所以这里读到的就是
            # 日志产生者的 run_id。别人 run 的日志直接丢掉。
            rid = getattr(_current_run, "run_id", None)
            if rid != self.run_id:
                return
            msg = redact_log_message(self.format(record))
            self._fh.write(msg + "\n")
            self._fh.flush()
            q = _run_queues.get(self.run_id)
            if q is not None:
                q.put(msg)
        except Exception:
            pass

    def close(self):
        try:
            self._fh.close()
        except Exception:
            pass
        super().close()


def _redact_status_payload(value: Any) -> Any:
    """Redact free-form diagnostic text before it enters the SSE queue."""
    if isinstance(value, dict):
        return {str(key): _redact_status_payload(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_status_payload(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_status_payload(item) for item in value]
    if isinstance(value, str):
        return redact_log_message(value)
    return value


def _emit_status(run_id: str, kind: str, payload: dict | str = ""):
    """前端约定：以 `__EVENT__:` 开头的行被解析成 JSON 状态事件。"""
    import json as _json
    q = _run_queues.get(run_id)
    if q is None:
        return
    body = payload if isinstance(payload, dict) else {"message": str(payload)}
    if kind in {"phase", "error"}:
        body = _redact_status_payload(body)
    body["kind"] = kind
    q.put("__EVENT__:" + _json.dumps(body, ensure_ascii=False))


# 网络/环境层错误特征：命中任一就把号放回 available（号本身没问题，是环境炸了）
_NETWORK_ERROR_PATTERNS = [
    "tls", "ssl", "sslerror", "connection", "connect error", "timeout", "timed out",
    "proxy", "socks", "dns", "name resolution", "name or service",
    "cloudflare", "just a moment", "403 forbidden",
    "csrf token 获取失败", "csrf token 失败",
    "/sentinel/req", "sentinel /req", "sentinel quickjs",
    "check_proxy 失败", "网络预检查",
    "curl: (35)", "curl: (28)", "curl: (6)", "curl: (7)",
    "remote disconnected", "connection reset", "connection aborted",
    "max retries exceeded",
    "invalid_state",
    "任务出口 ip", "浏览器出口环境校验失败",
]


def classify_error(err: str | BaseException, mail_source: str = "") -> str:
    """分类错误：'network'（环境/代理问题，号无辜）/ 'account'（号本身有问题）/ 'unknown'。

    mail_source 用来问 provider 要不要豁免某些模式 —— 比如 iCloud 中转号
    本来就是买的老号，"已有账号"是正常流程不是失败（见
    MailProvider.accepts_existing_account）。留空则按最严格的规则判。
    """
    if isinstance(err, FingerprintRuntimeMismatch):
        return "network"
    s = str(err or "").lower()

    account_patterns = [
        "wrong_email_otp_code", "invalid_grant", "imap xoauth2",
        "outlook imap account unusable", "user is authenticated but not connected",
        "outlook refresh failed", "authentication failed", "authenticate failed",
        "outlook otp timeout", "registration_disallowed",
        "已有账号", "账号被", "refresh_token 失效",
    ]
    if mail_source:
        try:
            exempt = get_provider_class(mail_source).accepts_existing_account
        except MailProviderError:
            exempt = False  # 未知来源 —— 按默认最严格规则走
        # ⚠️ 用 if-in 而不是裸 remove()：上面的模式表将来被人改动/重排后，
        #    remove 抛的 ValueError 会跟 get_provider_class 的错混在同一个
        #    except 里被一起吞掉，豁免静默失效且没人看得出来。
        if exempt and "已有账号" in account_patterns:
            account_patterns.remove("已有账号")

    # 先匹配 account 特征（更具体），避免子串误命中（如 "outlook OTP timeout" 含 "timeout"）
    if any(p in s for p in account_patterns):
        return "account"
    if any(p in s for p in _NETWORK_ERROR_PATTERNS):
        return "network"
    return "unknown"


def _do_register(
    run_id: str,
    account: dict,
    options: dict,
    log_file: Path,
):
    """实际注册任务。

    options:
        want_access_token: bool
        want_session_token: bool
        want_refresh_token: bool
        proxy: Optional[str]
        otp_timeout: int
        allow_existing_login: bool
    """
    # 先认领本线程，再挂 handler —— 顺序不能反：中间要是有日志产生，
    # 没打标记的话会被广播到其他并发 run 的日志里去。
    _current_run.run_id = run_id

    handler = QueueLogHandler(run_id, log_file)
    handler.setLevel(logging.INFO)
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    # 第一次需要的话提到 INFO 级别
    if root_logger.level > logging.INFO or root_logger.level == 0:
        root_logger.setLevel(logging.INFO)

    email = account["email"]
    probe = ProbeSession(run_id)
    environment = options.get("environment") or {}
    if not isinstance(environment, dict):
        environment = dict(environment)

    def _record_environment_observation(observation: dict) -> None:
        record_environment_observation(run_id, probe, observation)

    # 提前读取，避免在 try 块前异常时 except 引用未定义
    mail_source = db.get_setting("mail_source", "outlook")
    # 要不要操作号池（mark_done / mark_failed / release）由 provider 声明的
    # pooled 决定。未知 kind 时保守当池化处理 —— 号池里真有这行的话
    # 至少不会漏掉状态回写，把号永远卡在 in_use。
    try:
        is_pooled = get_provider_class(mail_source).pooled
    except MailProviderError:
        is_pooled = True

    try:
        probe.mark(
            "task.started",
            "ok",
            email=email,
            engine=options.get("engine", "protocol"),
            fingerprint_id=environment.get("fingerprint_id", ""),
            country_code=environment.get("country_code", ""),
            browser_family=environment.get("browser_family", ""),
            screen=(environment.get("fingerprint") or {}).get("screen", ""),
            viewport=(environment.get("fingerprint") or {}).get("viewport", {}),
        )
        # 本次注册专属的配置覆盖。
        # ⚠️ 以前是写 os.environ + finally 还原，但 auto_loop 并发跑多个 worker，
        #    os.environ 是**进程全局**的：A 设的 OTP_TIMEOUT/WEBUI_ALLOW_LOGIN 会被
        #    B 读到，B 跑完还原成 A 之前的值，A 后半程就用上别人的配置了。
        #    现在整个 dict 直接传给 AuthFlow，只挂在实例上，谁都污染不到谁。
        env_overrides = {}
        # outlook 接码邮箱常被 OpenAI 走 passwordless_signup 流程（新号收码而非设密码），
        # auth_flow 会误判为"已有账号"分支 → 不设 WEBUI_ALLOW_LOGIN 会 fast-fail。
        # 单号 WebUI 场景下 fast-fail 没意义（批量跑才需要"跳过被识别的号"），故强制 ON。
        env_overrides["WEBUI_ALLOW_LOGIN"] = "1"
        env_overrides["OTP_TIMEOUT"] = str(int(options.get("otp_timeout") or 180))
        # 用户不要 refresh_token → 直接跳过 Codex OAuth（每次都失败浪费 ~10s + 一堆告警）
        if not options.get("want_refresh_token", True):
            env_overrides["SKIP_OAUTH_TOKEN_EXCHANGE"] = "1"
            env_overrides["OAUTH_CODEX_RT_EXCHANGE"] = "0"
            env_overrides["OAUTH_CODEX_RT_BEFORE_CALLBACK"] = "0"
        # PROXY 走 cfg.proxy，无需 env

        cfg = Config()
        cfg.proxy = (
            environment.get("proxy") if environment else options.get("proxy")
        ) or None
        cfg.proxy = str(cfg.proxy).strip() or None

        # ─ 邮箱来源路由 ─
        # 原来是 if cf_temp / else outlook 的写死分支，加一种邮箱就得回来改。
        # 现在交给注册表工厂：provider 自己从 settings + account 里取需要的字段。
        with probe.step("mail.provider.create", source=mail_source):
            mail = create_mail_provider(mail_source, db.get_mail_settings(), account)
        instrument_method(
            mail,
            "wait_for_otp",
            probe,
            "mail.otp.read",
            capture_first_arg=True,
        )
        logging.getLogger("registrar").info(
            f"[register] 邮箱来源: {mail_source} ({mail.display_name})"
        )

        # ─ 2FA 绑定钩子：插在「拿到 session」和「Codex 授权」之间 ─
        #   主人指定的顺序：注册完 → 绑 2FA → Codex 授权 → 接码。
        #   2FA 必须有 access_token 才能打 mfa/enroll，而 at 只能从 get_auth_session 拿，
        #   所以这是唯一「已有 at 且 Codex 还没跑」的位置（见 auth_flow.py 那处注释）。
        #   钩子里绑成了就把结果存进 _tfa_box，run_register 返回后直接取，不再重绑。
        _tfa_box: dict = {}

        def _bind_2fa_hook(_flow, at: str) -> None:
            # ⚠️ 这里**不查密码**。快路径 bind_totp_2fa_inline 只拿 access_token 打
            #    mfa_info / enroll / activate，全程不碰密码（two_factor.py:153）。
            #    以前拿 flow.result.password 当门禁，把**重跑的老号全挡在门外**：
            #    老号被 OpenAI 认成已有账号 → 本轮不走 register_password →
            #    内存里密码是空的（真密码在库里，靠下面那段回读补），于是 at 明明齐活
            #    也绑不上（实测一个重跑的老号：at 长度 1762 齐活，却被跳过）。
            from .two_factor import bind_totp_2fa_inline
            info = bind_totp_2fa_inline(_flow, at)
            if info and info.get("secret"):
                _tfa_box.update(info)
                # ★ 一拿到 secret 立刻落盘，别等后面 Codex 授权 + 接码那几分钟。
                #   接码太久用户一关进程，_tfa_box 内存里的 secret 就永久没了，
                #   而 secret 一次性下发、服务端取不回（跟 _save_password_early 同理）。
                #   ⚠️ 必须用【真正的注册邮箱】flow.result.email，绝不能用外层 email：
                #      非池化 provider（CF 等）外层 email 是占位符
                #      xxx_placeholder_N@placeholder.local，用它落盘会跟后面 save_registered
                #      的真实邮箱对不上 —— 库里凭空多出一条占位垃圾行（两行）。
                #      run_register 一开头就设了 result.email（auth_flow.py:3102），
                #      走到这个钩子时它必然已是真实邮箱；取不到再退回外层 email 兜底。
                #   这里绝不能拖垮注册，包一层 try：落盘失败也还有 _tfa_box 兜着。
                try:
                    real_email = getattr(getattr(_flow, "result", None), "email", "") or email
                    db.save_totp_early(real_email, info["secret"], info.get("factor_id", ""))
                    logging.getLogger("registrar").info(
                        f"[register] 2FA secret 已早落盘 email={real_email}"
                    )
                except Exception as e:
                    logging.getLogger("registrar").warning(
                        f"[register] 2FA secret 早落盘失败（内存仍保留）: {e}"
                    )

        def _account_callback_for_flow(email: str) -> dict:
            """从数据库加载账号凭证（密码和 totp_secret）供 AuthFlow 登录时使用。

            用于既有账号登录场景：当服务端返回 mfa-challenge 时，AuthFlow 需要
            totp_secret 来计算 6 位动态码完成 2FA 验证。
            """
            try:
                data = db.get_registered(email)
                if data:
                    return {
                        "password": data.get("password", ""),
                        "totp_secret": data.get("totp_secret", ""),
                    }
            except Exception as e:
                logging.getLogger("registrar").warning(f"[register] account_callback 异常: {e}")
            return {}

        engine = options.get("engine", "protocol")
        probe.mark("flow.init", "started", engine=engine)
        if engine == "browser":
            from browser_flow import BrowserAuthFlow
            flow = BrowserAuthFlow(
                cfg,
                sms_callback=_build_sms_callback(run_id, probe),
                env_overrides={**env_overrides, "want_2fa": bool(options.get("want_2fa"))},
                on_password=_save_password_early,
                # ⚠ 不传 on_session_ready：浏览器引擎在 _bind_2fa_via_api 内部完成 2FA，
                # _bind_2fa_hook 调的 bind_totp_2fa_inline 需要协议引擎的 _common_headers，
                # 对 BrowserAuthFlow 会直接崩。
                on_session_ready=None,
                account_callback=_account_callback_for_flow,
                headless=options.get("browser_headless", True),
                engine_type=options.get("browser_engine") or "auto",
                fingerprint=environment.get("fingerprint"),
                fingerprint_country=(
                    environment.get("country_code")
                    or options.get("fingerprint_country", "")
                ),
                browser_family=(
                    environment.get("browser_family")
                    or options.get("fingerprint_browser_family")
                    or "auto"
                ),
                environment=environment,
                environment_observer=_record_environment_observation,
            )
        else:
            flow = AuthFlow(
                cfg,
                sms_callback=_build_sms_callback(run_id, probe),
                env_overrides=env_overrides,
                on_password=_save_password_early,
                on_session_ready=_bind_2fa_hook if options.get("want_2fa") else None,
                account_callback=_account_callback_for_flow,
                fingerprint=environment.get("fingerprint"),
                fingerprint_country=(
                    environment.get("country_code")
                    or options.get("fingerprint_country", "")
                ),
                fingerprint_browser_family=(
                    environment.get("browser_family")
                    or options.get("fingerprint_browser_family")
                    or "auto"
                ),
                environment=environment,
                environment_observer=_record_environment_observation,
            )
        _instrument_flow_for_probe(flow, probe, engine)
        probe.mark("flow.init", "ok", engine=engine)
        _emit_status(run_id, "phase", {"phase": "starting", "email": email})
        logging.getLogger("registrar").info(f"[register] 开始: {email}")

        partial = False
        d: dict
        probe.mark("registration.run", "started", engine=engine)
        try:
            result = flow.run_register(mail)
            d = result.to_dict()
            probe.mark(
                "registration.run",
                "ok",
                engine=engine,
                access_token_present=bool(d.get("access_token")),
                session_token_present=bool(d.get("session_token")),
                refresh_token_present=bool(d.get("refresh_token")),
            )
        except RuntimeError as e:
            # 部分凭证也算成功（OTP 验证通过 + create_account 成功 → flow.result 有 token）
            d = flow.result.to_dict()
            need_access = options.get("want_access_token", True)
            need_session = options.get("want_session_token", True)
            need_refresh = options.get("want_refresh_token", True)
            # 用户勾选的凭证全拿到 → 算正常完成（不视为 partial）
            wanted_ok = (
                (not need_access or d.get("access_token"))
                and (not need_session or d.get("session_token"))
                and (not need_refresh or d.get("refresh_token"))
            )
            has_any = bool(
                d.get("access_token") or d.get("refresh_token") or d.get("session_token")
            )
            if wanted_ok and has_any:
                probe.mark("registration.run", "partial", error=e, partial=False)
                logging.getLogger("registrar").warning(
                    f"[register] 流程末段异常但用户勾选的凭证已齐: {e}"
                )
            elif has_any:
                partial = True
                probe.mark("registration.run", "partial", error=e, partial=True)
                logging.getLogger("registrar").warning(
                    f"[register] 部分凭证 (缺用户勾选的某项): {e}"
                )
            else:
                raise

        # ─ 用户选项过滤：未勾选的字段从结果里抹掉，DB 只存用户想要的
        full = d
        d = {
            "email": full.get("email", ""),
            "password": full.get("password", ""),
        }
        if options.get("want_access_token", True):
            d["access_token"] = full.get("access_token", "")
        if options.get("want_session_token", True):
            d["session_token"] = full.get("session_token", "")
            d["cookie_header"] = full.get("cookie_header", "")  # 同样是浏览器注入用
        if options.get("want_refresh_token", True):
            d["refresh_token"] = full.get("refresh_token", "")
            d["id_token"] = full.get("id_token", "")

        # ─ 密码回读：必须在 2FA 之前 ─
        # ⚠️ d 是**本轮内存里**的结果，它不一定知道这个号有密码：
        #    重跑一个之前设过密码的邮箱时，OpenAI 会认成已有账号 → passwordless_login
        #    → register_password 根本不执行 → d["password"] 是空的，
        #    但上一轮 save_password_early 存的密码还在库里。
        #    两个下游都要它：① 2FA 慢路径要用密码重走 login 链；
        #    ② 前端 done 事件 `v-if="lastRunResult.password"` 判空会把密码行
        #       连同两个复制按钮一起藏掉，主人会以为密码丢了。
        #    以前这段在 2FA **之后**，于是老号在 2FA 眼里永远"无密码"→ 被跳过。
        #    只在 d 里密码为空时查一次，正常路径零额外开销。
        if not (d.get("password") or "").strip():
            try:
                _saved = db.get_registered(d.get("email") or "")
                _pw = ((_saved or {}).get("password") or "").strip()
                if _pw:
                    d["password"] = _pw
                    logging.getLogger("registrar").info(
                        "[register] 本轮未设密码，沿用库中已存密码（上一轮 register_password 留下的）"
                    )
            except Exception as e:
                logging.getLogger("registrar").warning(f"[register] 回读已存密码失败: {e}")

        # ─ 可选：绑定 TOTP 2FA（仅用户勾选 want_2fa 时才跑） ─
        #   正常情况上面的 on_session_ready 钩子已经在【Codex 授权之前】绑完了，
        #   这里只是兜底：钩子没跑到（run_register 中途抛异常走 partial 分支、
        #   或那时 access_token 还是空）时再补一次。
        #   兜底本身也是先快后慢两条路（见 two_factor.py 模块头）：
        #     快 bind_totp_2fa_inline —— 直接复用刚跑完注册的 flow + access_token，
        #        6.2s 搞定，零 PoW 零邮件（实测 2026-08-08 <测试号>@<自建域>
        #        四个请求全 200，mfa_enabled=true）。
        #     慢 bind_totp_2fa —— 新起 AuthFlow 重走 login 正式链，约 40s + 一次 PoW
        #        + 一封验证码邮件。只在快路径没成时兜底。
        #   失败仅告警、绝不废掉已注册成功的号；secret 一次性下发，成功即随 d 落库+推前端。
        #   ⚠️ 入口条件**不查密码**：快路径只要 access_token。密码只是慢路径
        #      （重走 login 链）的前提，所以判断挪到回落那一步再做。
        if options.get("want_2fa"):
            probe.mark("two_factor.bind", "started")
            _emit_status(run_id, "phase", {"phase": "binding_2fa", "email": d.get("email")})
            try:
                from .two_factor import bind_totp_2fa, bind_totp_2fa_inline
                # 钩子（Codex 授权之前那次）已经绑好就直接用，别再打一遍 enroll
                tinfo = dict(_tfa_box) if _tfa_box.get("secret") else None
                # 浏览器引擎在 _bind_2fa_via_api 内部已经绑好了，结果存在 result.totp_secret
                if not tinfo and getattr(flow.result, "totp_secret", ""):
                    tinfo = {"secret": flow.result.totp_secret}
                if not tinfo:
                    tinfo = bind_totp_2fa_inline(flow, full.get("access_token", ""))
                if not (tinfo and tinfo.get("secret")):
                    # 慢路径要拿密码重登一次，没密码就只能到此为止
                    if (d.get("password") or "").strip():
                        logging.getLogger("registrar").info(
                            "[register] 2FA 快路径未成，回落重走登录链..."
                        )
                        tinfo = bind_totp_2fa(
                            cfg, d.get("email", ""), d.get("password", ""),
                            mail_provider=mail, env_overrides=env_overrides,
                        )
                    else:
                        logging.getLogger("registrar").warning(
                            "[register] 2FA 快路径未成，且该号无密码（库里也没有），"
                            "慢路径走不了，跳过绑定"
                        )
                if tinfo and tinfo.get("secret"):
                    d["totp_secret"] = tinfo["secret"]
                    d["totp_factor_id"] = tinfo.get("factor_id", "")
                    logging.getLogger("registrar").info(
                        f"[register] 2FA 绑定成功 email={d.get('email')}"
                    )
                    _emit_status(run_id, "phase", {"phase": "2fa_bound", "email": d.get("email")})
                    probe.mark("two_factor.bind", "ok", secret_present=True)
                else:
                    probe.mark("two_factor.bind", "skipped", reason="provider returned no secret")
                    logging.getLogger("registrar").warning(
                        "[register] 2FA 绑定未成功（账号仍有效，仅未绑 2FA）"
                    )
            except Exception as e:
                probe.mark("two_factor.bind", "failed", error=e)
                logging.getLogger("registrar").warning(
                    f"[register] 2FA 绑定异常（账号仍有效）: {e}"
                )
        # 落库（密码已在 2FA 之前回读补齐，这里 d 里该有的都有了）
        with probe.step("database.registered.save", email=d.get("email", "")):
            db.save_registered(d)

        # 2026-09-24 定案：**默认不再自动查**。
        #
        #   分工（主人明确）：**协议机只管注册，查优惠是 turb 的事**。
        #   这里再查一遍 = 同一份请求打两遍：
        #       协议机：check_coupon(2.2 KiB) + accounts/check(10.4 KiB)
        #       turb  ：accounts/check(~13 KiB) + 建结账会话
        #   accounts/check 是**完全重复**的一次调用。
        #
        #   更糟的是它用的是**注册那一刻的出口**。实测池子里稳定有 10/100 条
        #   出口对所有账号都返回 not_eligible（同一个有资格的号换 8 条出口：
        #   7 条 eligible、1 条 not_eligible —— 结论完全由出口决定）。
        #   拿一条脏出口的结论给号打上 free 标签纯属误导，还会让人以为
        #   「这个号没资格」，其实只是那条出口脏。
        #
        #   要恢复自动查：PROTOCOL_PLUS_CHECK=1
        #   （WebUI 上那个手动的「查试用」按钮不受影响，那是点了才跑。）
        plus_check = None
        _plus_env = str(os.environ.get("PROTOCOL_PLUS_CHECK", "0")).strip().lower()
        _want_plus_check = _plus_env in ("1", "true", "yes")
        if _want_plus_check and full.get("access_token"):
            probe.mark("plus_trial.check", "started")
            _emit_status(
                run_id,
                "phase",
                {"phase": "checking_plus_trial", "email": d.get("email")},
            )
            try:
                from plus_trial_checker import check_plus_trial

                plus_check = check_plus_trial(
                    full.get("access_token", ""),
                    proxy=(environment.get("proxy") or cfg.proxy or ""),
                    fingerprint=environment.get("fingerprint"),
                    device_id=full.get("device_id", ""),
                )
                d["plus_check"] = plus_check
                if plus_check.get("status") not in ("error", "no_at"):
                    db.update_plus_check(d.get("email", ""), plus_check)
                logging.getLogger("registrar").info(
                    "[register] 0元试用资格: email=%s status=%s label=%s",
                    d.get("email"),
                    plus_check.get("status"),
                    plus_check.get("label"),
                )
                _emit_status(
                    run_id,
                    "phase",
                    {
                        "phase": "plus_trial_checked",
                        "email": d.get("email"),
                        "status": plus_check.get("status"),
                        "label": plus_check.get("label"),
                        "trial_eligible": bool(plus_check.get("trial_eligible")),
                    },
                )
                probe.mark(
                    "plus_trial.check",
                    "failed" if plus_check.get("status") == "error" else "ok",
                    error=plus_check.get("error") if plus_check.get("status") == "error" else None,
                    result_status=plus_check.get("status"),
                    trial_eligible=bool(plus_check.get("trial_eligible")),
                )
            except Exception as exc:  # noqa: BLE001
                probe.mark("plus_trial.check", "failed", error=exc)
                logging.getLogger("registrar").warning(
                    "[register] 0元试用资格检测失败（账号仍有效）: %s",
                    str(exc)[:240],
                )
        elif not _want_plus_check:
            probe.mark("plus_trial.check", "skipped", reason="disabled: PROTOCOL_PLUS_CHECK=0")
            logging.getLogger("registrar").info(
                "[register] 跳过 0元试用资格检测（协议机只管注册；"
                "查优惠交给 turb，避免 accounts/check 重复打两遍）"
            )
        else:
            probe.mark("plus_trial.check", "skipped", reason="access token not requested")
            logging.getLogger("registrar").info(
                "[register] 未请求 access_token，跳过 0元试用资格检测"
            )
        # 非池化 provider 的 email 是虚拟占位（xxx_placeholder_N@placeholder.local），
        # 号池里根本没这行，不能去 mark。判据用 provider 的 pooled，不写死 kind。
        if is_pooled:
            db.mark_done(email)

        # ─ 可选：导出到 CPA / SUB2API 面板（仅勾选启用时才执行） ─
        _try_export_to_panels(run_id, d, probe=probe)

        result_summary = {
            "email": d.get("email"),
            # 密码走明文推给前端：token 只给长度是因为太长且必须点按钮复制，
            # 但密码是随机 16 位、用户注册完第一件事就是拿去登录，
            # 藏在「查看凭证」弹窗里等于每次都要多点两下。
            # 这是本机自用工具，SSE 只发给本地浏览器，不外传。
            "password": d.get("password") or "",
            "access_token_len": len(d.get("access_token") or ""),
            "session_token_len": len(d.get("session_token") or ""),
            "refresh_token_len": len(d.get("refresh_token") or ""),
            # 2FA secret 一次性下发、服务端取不回，明文推前端让用户当场导入验证器
            # （理由同密码；本机自用工具，SSE 只发本地浏览器）。未绑则为空串。
            "totp_secret": d.get("totp_secret") or "",
            "plus_trial_status": (plus_check or {}).get("status", ""),
            "plus_trial_label": (plus_check or {}).get("label", ""),
            "plus_trial_eligible": bool((plus_check or {}).get("trial_eligible")),
            "partial": partial,
        }
        _emit_status(run_id, "done", result_summary)
        logging.getLogger("registrar").info(
            f"[register] 完成 email={d.get('email')} "
            f"password_present={bool(d.get('password'))} "
            f"at={result_summary['access_token_len']} "
            f"st={result_summary['session_token_len']} "
            f"rt={result_summary['refresh_token_len']}"
        )
        db.finish_run(run_id, "done")
        probe.mark("task.finished", "ok", partial=partial)

    except Exception as e:
        err = redact_probe_error(e)
        category = classify_error(e, mail_source)
        logging.getLogger("registrar").error(f"[register] 失败 (category={category}): {err}")
        # ⚠️ 密码是在 register_password 里现生成的，只活在内存里。
        #    走到这里说明 save_registered 没执行过 —— 但 POST user/register 可能**已经成功**，
        #    OpenAI 那边账号连同这个密码已经建好了，只是后续步骤（发码/验证/建账户）挂了。
        #    不打出来的话这个号就成了谁也登不进去的孤儿。这里只写日志不落库，
        #    避免把没有任何 token 的半成品塞进「注册结果」表里。
        try:
            _pw = (flow.result.password or "").strip()
            if _pw:
                logging.getLogger("registrar").error(
                    f"[register] 该号已生成密码，请查看已保存凭证: {flow.result.email or email}"
                )
        except Exception:
            pass  # flow 还没建出来（异常发生在 AuthFlow 之前），没密码可救
        if category != "account":
            logging.getLogger("registrar").error(traceback.format_exc())
        # 非池化 provider 没有号池记录，不操作
        if is_pooled:
            if category == "network":
                db.release_unused(email)
                logging.getLogger("registrar").warning(
                    f"[register] {email} 判定为网络/环境错误，号已 release 回 available"
                )
            else:
                db.mark_failed(email, f"[{category}] {err}")
        db.finish_run(run_id, "failed", err, category=category)
        _emit_status(run_id, "error", {"message": err, "category": category})
        probe.fail_open(e)
        probe.mark("task.finished", "failed", error=e, error_category=category)

    finally:
        probe.fail_open("task ended before stage completion")
        # env 覆盖现在只挂在 AuthFlow 实例上，随实例一起回收，无需还原。
        # 关闭 handler
        try:
            root_logger.removeHandler(handler)
            handler.close()
        except Exception:
            pass
        q = _run_queues.get(run_id)
        if q is not None:
            q.put(None)  # sentinel: 流结束
        # 线程标记清掉。理论上线程跑完就回收了，但 threading.local 是绑在
        # 线程对象上的，万一以后换成线程池复用线程，残留的 run_id 会让下一个
        # 任务的日志全被投递到上一个 run 的（已关闭的）文件里去。
        _current_run.run_id = None


def _try_export_to_panels(run_id: str, cred: dict, *, probe: Optional[ProbeSession] = None) -> None:
    """注册完成后可选地把凭证导出到 CPA / SUB2API 面板。

    - 任一目标的"启用"开关关闭时,该目标跳过(不发请求);两者都未启用时整段 no-op。
    - 任何异常都不抛,只 emit 日志/状态(不影响注册主流程)。
    """
    try:
        cfg = db.get_export_internal_config()
    except Exception as e:
        logging.getLogger("registrar").warning(f"[export] 读取配置失败: {e}")
        return

    cpa_enabled = bool(cfg.get("cpa", {}).get("enabled"))
    sub2api_enabled = bool(cfg.get("sub2api", {}).get("enabled"))
    if not (cpa_enabled or sub2api_enabled):
        if probe:
            probe.mark("export.panels", "skipped", reason="no export target enabled")
        return  # 用户没勾选任何目标 → 完全不执行

    from . import exporter  # 懒 import,避免未启用时强依赖

    explog = logging.getLogger("registrar")

    def _log(msg: str, level: str = "info") -> None:
        if level == "error":
            explog.error(f"[export] {msg}")
        elif level == "warn":
            explog.warning(f"[export] {msg}")
        else:
            explog.info(f"[export] {msg}")
        try:
            _emit_status(run_id, "phase", {"phase": "export", "message": msg, "level": level})
        except Exception:
            pass

    try:
        if probe:
            probe.mark("export.panels", "started", cpa=cpa_enabled, sub2api=sub2api_enabled)
        results = exporter.run_exports(
            cred,
            cpa_cfg=cfg.get("cpa") if cpa_enabled else None,
            sub2api_cfg=cfg.get("sub2api") if sub2api_enabled else None,
            log_fn=_log,
        )
    except Exception as e:
        if probe:
            probe.mark("export.panels", "failed", error=e)
        _log(f"导出整体异常: {e}", "error")
        return

    # 汇总成一个事件给前端
    summary = {}
    if results.get("cpa") is not None:
        summary["cpa"] = {"ok": bool(results["cpa"].get("ok")),
                          "message": results["cpa"].get("message") or results["cpa"].get("error") or ""}
    if results.get("sub2api") is not None:
        summary["sub2api"] = {"ok": bool(results["sub2api"].get("ok")),
                              "message": results["sub2api"].get("message") or results["sub2api"].get("error") or ""}
    try:
        _emit_status(run_id, "phase", {"phase": "export_done", "summary": summary})
        if probe:
            probe.mark("export.panels", "ok", summary=summary)
    except Exception:
        pass


def _save_password_early(email: str, password: str) -> None:
    """AuthFlow 的 on_password 回调：密码在 OpenAI 侧一生效就落盘。

    以前密码只在流程**全部**跑通后才随 save_registered 一起入库，
    中间任何一步失败（实测最常见的是 OTP 超时）密码就只剩一行 ERROR 日志兜底 ——
    换台机器、日志轮转、或者干脆没人去翻，号就废了。

    这里存的是"有密码、无凭证"的半成品行，跑通后 save_registered 会用
    同一个 email 主键覆盖补全，不会多出一行对不上的记录。
    """
    log = logging.getLogger("registrar")
    try:
        db.save_password_early(email, password)
        log.info(f"[register] 密码已落盘: {email}（凭证待补）")
    except Exception as e:
        # 落盘失败不能影响注册；下面 except 里那行 ERROR 日志仍然是兜底
        log.warning(f"[register] 密码落盘失败，仅剩日志兜底: {e}")


def _build_sms_callback(
    run_id: str,
    probe: Optional[ProbeSession] = None,
) -> Optional[PhoneCallbackController]:
    """根据 webui 配置创建 SMS 接码 controller。

    未启用接码或未配置 API key 时返回 None，flow 会回退到环境变量路径。
    log_fn 把租号/等码的状态推到 SSE 流，前端可见。
    """
    cfg = db.get_sms_internal_config()
    if not cfg.get("sms_enabled"):
        return None
    api_key = (cfg.get("sms_api_key") or "").strip()
    if not api_key:
        logging.getLogger("registrar").warning("[sms] 已启用接码但未配置 sms_api_key，跳过")
        return None

    smslog = logging.getLogger("registrar")

    def _log(msg: str) -> None:
        # 既写日志、又通过 _emit_status 推 phase 事件给前端
        smslog.info(f"[sms] {msg}")
        try:
            _emit_status(run_id, "phase", {"phase": "sms", "message": msg})
        except Exception:
            pass

    try:
        controller = PhoneCallbackController(
            provider_key=cfg["sms_provider"],
            config=cfg,
            service=cfg.get("sms_service") or "openai",
            country=cfg.get("sms_country") or "52",
            log_fn=_log,
            auto_select_country=bool(cfg.get("sms_auto_country")),
        )
        if probe:
            instrument_method(controller, "get_phone", probe, "sms.rent")
            instrument_method(controller, "get_code", probe, "sms.otp.read")
            instrument_method(controller, "report_success", probe, "sms.report_success")
            instrument_method(controller, "cleanup", probe, "sms.cleanup")
        return controller
    except Exception as e:
        smslog.warning(f"[sms] 创建接码 controller 失败: {e}")
        return None


def start_registration(account: dict, options: dict) -> str:
    """启动一次注册任务，返回 run_id。"""
    run_id = uuid.uuid4().hex[:12]
    log_file = LOG_DIR / f"{run_id}.log"
    db.create_run(run_id, account["email"], str(log_file))
    probe = ProbeSession(run_id)
    probe.mark("task.requested", "ok", email=account.get("email", ""))

    # Freeze the complete task environment before the worker thread starts.
    # This makes the protocol and browser flows consume the same proxy/profile,
    # and lets SQLite reject historical IP/profile reuse atomically.
    try:
        probe.mark("environment.allocate", "started")
        environment = allocate_environment(run_id, options or {})
        db.update_run_environment(run_id, environment)
        probe.mark(
            "environment.allocate",
            "ok",
            exit_ip=environment.get("exit_ip", ""),
            exit_country=environment.get("exit_country", ""),
            country_code=environment.get("country_code", ""),
            fingerprint_id=environment.get("fingerprint_id", ""),
            browser_family=environment.get("browser_family", ""),
            browser_engine=environment.get("browser_engine", ""),
        )
    except Exception as exc:
        probe.mark("environment.allocate", "failed", error=exc)
        db.finish_run(run_id, "failed", str(exc), category="network")
        # A claimed pooled account must not remain in_use when allocation fails.
        db.release_unused(account.get("email", ""))
        if isinstance(exc, EnvironmentAllocationError):
            raise
        raise EnvironmentAllocationError(f"任务环境初始化失败: {exc}") from exc

    frozen_options = dict(options or {})
    frozen_options["environment"] = environment
    # The selected proxy/profile are authoritative for this task. Keep the
    # original pool in options only for diagnostics; it is never re-selected.
    frozen_options["proxy"] = environment.get("proxy", "")
    frozen_options["fingerprint"] = environment["fingerprint"]
    frozen_options["fingerprint_country"] = environment.get("country_code", "")
    frozen_options["fingerprint_browser_family"] = environment.get(
        "browser_family", "auto"
    )

    q: queue.Queue = queue.Queue()
    with _lock:
        _run_queues[run_id] = q

    th = threading.Thread(
        target=_do_register,
        args=(run_id, account, frozen_options, log_file),
        daemon=True,
        name=f"register-{run_id}",
    )
    th.start()
    return run_id


def get_run_queue(run_id: str) -> Optional[queue.Queue]:
    return _run_queues.get(run_id)


def remove_run_queue(run_id: str) -> None:
    with _lock:
        _run_queues.pop(run_id, None)
