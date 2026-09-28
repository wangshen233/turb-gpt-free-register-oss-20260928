"""浏览器注册引擎 —— 使用 Playwright 无头浏览器完成 ChatGPT 账号注册。

与 auth_flow.AuthFlow 同接口：
  - 构造参数相同（config, sms_callback, env_overrides, on_password, ...）
  - 入口方法 run_register(mail_provider) -> AuthResult
  - 返回同一个 AuthResult 对象

共享模块：mail_providers（邮箱/OTP）、sms_provider（SMS 验证）、webui（db/registrar/SSE）。
不依赖：http_client（TLS 模拟）、sentinel（PoW 计算）。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import random
import re
import struct
import time
from pathlib import Path
from typing import Optional, Any

from config import Config
from auth_flow import AuthResult
from browser_launcher import (
    FingerprintRuntimeMismatch,
    close_browser,
    launch_browser,
    validate_page_fingerprint,
)
from fingerprint import generate_fingerprint, validate_fingerprint
from webui.environment import compare_exit_observation

logger = logging.getLogger(__name__)

# ── 截图保存目录 ──────────────────────────────────────────────
SCREENSHOT_DIR = Path(__file__).resolve().parent / "data" / "screenshots"
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

# ── 姓名池（和 auth_flow.py 保持一致）──────────────────────────
_FIRST_NAMES = [
    "James", "John", "Robert", "Michael", "William", "David", "Richard",
    "Joseph", "Thomas", "Charles", "Mary", "Patricia", "Jennifer", "Linda",
    "Elizabeth", "Barbara", "Susan", "Jessica", "Sarah", "Karen",
]
_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
    "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
]


# ── TOTP 工具（复用 auth_flow 的逻辑）────────────────────────
def _hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def _totp_now(secret_b32: str) -> str:
    return _hotp(secret_b32, int(time.time()) // 30)


def _random_password(length: int = 16) -> str:
    """生成随机密码，与 auth_flow._random_password 逻辑一致。"""
    import string
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*"
    must = [
        random.choice(upper),
        random.choice(lower),
        random.choice(digits),
        random.choice(special),
    ]
    all_chars = upper + lower + digits + special
    rest = random.choices(all_chars, k=length - len(must))
    pwd_list = must + rest
    random.shuffle(pwd_list)
    return "".join(pwd_list)


class BrowserAuthFlow:
    """使用无头浏览器的注册引擎，与 AuthFlow 同接口。"""

    def __init__(
        self,
        config: Config,
        sms_callback: Optional[Any] = None,
        env_overrides: Optional[dict] = None,
        on_password: Optional[Any] = None,
        on_session_ready: Optional[Any] = None,
        account_callback: Optional[Any] = None,
        headless: bool = True,
        engine_type: str = "auto",
        fingerprint: Optional[dict] = None,
        fingerprint_country: str = "",
        browser_family: str = "auto",
        environment: Optional[dict] = None,
        environment_observer: Optional[Any] = None,
    ):
        self.config = config
        self.result = AuthResult()
        self._sms_callback = sms_callback
        self._env_overrides = dict(env_overrides or {})
        self._on_password = on_password
        self._on_session_ready = on_session_ready
        self._account_callback = account_callback
        self._headless = headless
        self._engine_type = engine_type
        self._browser_family = (browser_family or "auto").strip().lower()
        self._environment = dict(environment or {})
        self._environment_observer = environment_observer
        self._runtime_diagnostic: dict = {}
        self._country_code = (
            fingerprint_country
            or self._env("FINGERPRINT_COUNTRY", "")
        ).strip().upper()
        self._detected_country = ""
        if fingerprint is not None:
            validate_fingerprint(fingerprint)
            if self._country_code and self._country_code != str(fingerprint.get("country_code", "")).upper():
                raise ValueError("fingerprint country does not match fingerprint_country")
            self._fingerprint = fingerprint
            self._country_code = str(fingerprint.get("country_code", self._country_code)).upper()
        else:
            if not self._country_code:
                self._country_code = self._probe_country_before_launch()
            self._fingerprint = generate_fingerprint(
                country_code=self._country_code,
                browser_family=self._browser_family,
                prefer_firefox=(
                    (self._engine_type or "auto").strip().lower() in ("auto", "camoufox")
                    and self._browser_family in ("", "auto", "random")
                ),
            )
        logger.info(
            "[browser] 任务画像: id=%s family=%s type=%s country=%s screen=%s "
            "viewport=%sx%s locale=%s timezone=%s",
            self._fingerprint["fingerprint_id"],
            self._fingerprint["browser_family"],
            self._fingerprint["browser_type"],
            self._fingerprint.get("country_code", "") or "N/A",
            self._fingerprint["screen"],
            self._fingerprint["viewport"]["width"],
            self._fingerprint["viewport"]["height"],
            self._fingerprint["locale"],
            self._fingerprint["timezone"],
        )

    def _probe_country_before_launch(self) -> str:
        """Best-effort proxy country probe before the browser profile is created."""
        proxy = (getattr(self.config, "proxy", None) or "").strip()
        if not proxy:
            return ""
        try:
            import requests

            resp = requests.get(
                "https://cloudflare.com/cdn-cgi/trace",
                proxies={"http": proxy, "https": proxy},
                timeout=10,
            )
            if resp.ok:
                for line in resp.text.splitlines():
                    if line.startswith("loc="):
                        code = line.split("=", 1)[1].strip().upper()
                        logger.info("[browser] 启动前代理国家探测: %s", code)
                        return code
        except Exception as exc:
            logger.debug("[browser] 启动前代理国家探测失败: %s", exc)
        return ""

    def _env(self, key: str, default: str = "") -> str:
        """读配置覆盖（优先 env_overrides，再 os.environ）。"""
        return self._env_overrides.get(key, os.getenv(key, default))

    # ══════════════════════════════════════════════════════════
    #  主入口
    # ══════════════════════════════════════════════════════════

    def run_register(self, mail_provider) -> AuthResult:
        """完整的浏览器注册流程。与 AuthFlow.run_register() 同签名。"""
        pw_inst, browser, ctx, page = None, None, None, None

        try:
            # ─ 创建邮箱 ─
            email = mail_provider.create_mailbox()
            self.result.email = email
            logger.info(f"[browser] 邮箱: {email}")

            # ─ 启动浏览器 ─
            logger.info("[browser] [1/10] 启动浏览器...")
            pw_inst, browser, ctx = launch_browser(
                engine_type=self._engine_type,
                proxy=self.config.proxy,
                headless=self._headless,
                country_code=self._country_code,
                fingerprint=self._fingerprint,
            )
            page = ctx.new_page()
            try:
                self._runtime_diagnostic = validate_page_fingerprint(page, self._fingerprint)
            except FingerprintRuntimeMismatch as exc:
                self._runtime_diagnostic = exc.report
                if self._environment_observer:
                    try:
                        self._environment_observer(exc.report)
                    except Exception as observer_error:
                        logger.debug("[browser] 记录运行时环境观测失败: %s", observer_error)
                logger.error("[browser] 运行时画像校验失败: %s", exc)
                raise
            if self._environment_observer:
                try:
                    self._environment_observer(self._runtime_diagnostic)
                except Exception as observer_error:
                    logger.debug("[browser] 记录运行时环境观测失败: %s", observer_error)
            logger.info("[browser] 运行时画像校验通过: %s", self._fingerprint["fingerprint_id"])

            # ─ 注册流程 ─
            # 邮箱提交后 OpenAI 会按 A/B 测试 + 地域走不同分支（旧的 auth.openai.com
            # 多页跳转 / 新的 chatgpt.com 内嵌 SPA），落地 URL 完全不同但 DOM 组件一致。
            # 所以这里不按固定顺序硬走，而是循环识别当前页面属于哪一步再分发。
            self._warmup(page)
            self._detect_country(page)
            self._click_signup(page)
            self._enter_email(page, email)
            self._run_auth_steps(page, mail_provider, email)
            self._wait_for_chat_page(page)

            # ─ 提取凭证 ─
            logger.info("[browser] [9/10] 提取凭证...")
            self._extract_tokens(page, ctx)
            self._fetch_access_token(page)

            # ─ 浏览器的职责到此为止 ─
            # 2FA 绑定、Codex OAuth、手机接码等后续操作全部交给 registrar
            # 通过协议引擎完成（复用 access_token + cookie，不需要浏览器）。

            logger.info(
                f"[browser] [10/10] 注册完成 email={self.result.email} "
                f"at={len(self.result.access_token)} "
                f"st={len(self.result.session_token)} "
                f"rt={len(self.result.refresh_token)}"
            )
            return self.result

        except Exception as e:
            if page:
                self._screenshot_on_error(page, str(e))
            raise

        finally:
            if browser:
                close_browser(pw_inst, browser)
                logger.info("[browser] 浏览器已关闭")

    # ══════════════════════════════════════════════════════════
    #  各步骤实现
    # ══════════════════════════════════════════════════════════

    def _warmup(self, page):
        """[2/10] 打开 chatgpt.com，等待页面完全加载。"""
        logger.info("[browser] [2/10] 打开 chatgpt.com ...")
        page.goto("https://chatgpt.com/", wait_until="domcontentloaded")
        # chatgpt.com 有 SSE/WebSocket 长连接，networkidle 永远到不了，用 load 即可
        page.wait_for_load_state("load", timeout=60_000)
        # 如果遇到 CF 验证页，等待自动通过
        self._wait_for_cf_challenge(page)
        logger.info("[browser] 页面加载完成")

    def _detect_country(self, page):
        """Validate the browser context's exit and merge it into diagnostics."""
        try:
            resp = page.request.get("https://cloudflare.com/cdn-cgi/trace", timeout=10_000)
            values = {}
            for line in (resp.text() if resp.ok else "").splitlines():
                key, separator, value = line.partition("=")
                if separator:
                    values[key.strip().lower()] = value.strip()
            self._detected_country = values.get("loc", "").upper()
            exit_report = compare_exit_observation(
                self._environment,
                exit_ip=values.get("ip", ""),
                exit_country=self._detected_country,
                status_code=resp.status,
            )
            self._runtime_diagnostic["network"] = exit_report
            merged_checks = dict(self._runtime_diagnostic.get("checks") or {})
            merged_checks.update(exit_report["checks"])
            self._runtime_diagnostic["checks"] = merged_checks
            self._runtime_diagnostic["all_passed"] = all(merged_checks.values())
            if self._environment_observer:
                self._environment_observer(self._runtime_diagnostic)
            logger.info(
                "[browser] 检测出口: ip=%s country=%s profile=%s result=%s",
                values.get("ip", "") or "N/A",
                self._detected_country or "N/A",
                self._fingerprint.get("country_code", "") or "N/A",
                exit_report["all_passed"],
            )
            if not exit_report["all_passed"]:
                raise RuntimeError(
                    "浏览器运行时出口与冻结环境不一致: "
                    f"expected={exit_report['expected']} observed={exit_report['observed']}"
                )
        except Exception as e:
            logger.error(f"[browser] 出口环境校验失败: {e}")
            raise RuntimeError(f"浏览器出口环境校验失败: {e}") from e

    def _click_signup(self, page):
        """[3/10] 跳转到注册页。

        不在首页找按钮（文本会随语言变化），直接用 URL 参数 screen_hint=signup
        让服务端路由到注册流程。
        """
        logger.info("[browser] [3/10] 导航到注册页...")
        page.goto(
            "https://chatgpt.com/auth/login?screen_hint=signup",
            wait_until="load",
            timeout=60_000,
        )
        # auth.openai.com 也可能有 CF 验证
        self._wait_for_cf_challenge(page)

    def _enter_email(self, page, email: str):
        """[4/10] 输入邮箱并提交。

        真实 DOM（chatgpt.com/auth/login?screen_hint=signup）：
          <input type="email" id="email" name="email" aria-label="Email address">
          <button type="submit" class="...btn-primary...">  （单个 submit，安全）
        """
        logger.info(f"[browser] [4/10] 输入邮箱: {email}")
        # 等待邮箱输入框出现 — 优先使用已验证的选择器
        email_selectors = [
            'input[name="email"]',          # 真实 DOM: name="email"
            'input[type="email"]',          # 备选
            'input[id="email"]',            # 真实 DOM: id="email"
        ]
        email_input = None
        for sel in email_selectors:
            try:
                el = page.locator(sel).first
                el.wait_for(state="visible", timeout=10_000)
                email_input = el
                break
            except Exception:
                continue

        if not email_input:
            raise RuntimeError("未找到邮箱输入框")

        email_input.fill(email)
        time.sleep(random.uniform(0.3, 0.8))  # 模拟人类输入间隔

        # ⚠ 邮箱提交后落到哪个 URL 完全不确定（旧路径 auth.openai.com/email-verification、
        # 新路径 chatgpt.com/auth/login?email=xxx、甚至 URL 原地不动的纯 SPA 切换）。
        # 唯一可靠的判据是 DOM：只要不再是邮箱页，就说明这一步过了。
        # React 在跳转前会短暂清空 email input，因此不能一看到空框就重填。
        #
        # 提交本身也可能静默落空（按钮当时还 disabled、React 尚未绑定 handler），
        # 实测表现是 URL 已带上 ?email= 但页面纹丝不动。与其傻等一个长超时，
        # 不如短超时多轮：每轮都重新填一次再提交，总时长反而更短。
        for attempt in range(1, 4):
            self._click_continue(page)
            self._email_submitted_at = time.time()

            targets = {"otp", "password", "login_password", "profile", "done"}
            step = self._wait_for_step(page, targets, timeout=15)

            # 提交已生效、只是 React 还没切走 → 接着等，千万别重填
            # （重填会再发一封验证码，旧码作废，OTP 步骤反而更容易失败）
            if step == "email_submitted":
                logger.info("[browser] 邮箱已提交，等待页面切换...")
                step = self._wait_for_step(page, targets, timeout=30)

            if step == "login_password":
                raise RuntimeError(f"邮箱已被注册（落到登录密码页）: {email}")

            if step in ("otp", "password", "profile", "done"):
                logger.info(f"[browser] 邮箱已提交，当前步骤: {step}")
                return

            if attempt < 3:
                logger.warning(
                    f"[browser] 邮箱提交后未进入下一步（第 {attempt} 次），"
                    f"重填重试 step={step} url={page.url}"
                )
                try:
                    el = page.locator(
                        'input[name="email"], input[type="email"]').first
                    if el.is_visible(timeout=5_000):
                        el.fill(email)
                        time.sleep(0.5)
                except Exception as e:
                    logger.debug(f"[browser] 邮箱重填失败: {e}")

        raise RuntimeError(
            f"邮箱提交 3 次后仍停在邮箱页 url={page.url} "
            f"errors={self._page_state(page).get('errors')}"
        )

    # ══════════════════════════════════════════════════════════
    #  注册状态机 —— 按当前页面实际处于哪一步分发，而不是按固定顺序硬走
    # ══════════════════════════════════════════════════════════

    def _run_auth_steps(self, page, mail_provider, email: str):
        """循环识别当前步骤并处理，直到账号建成（done）。

        邮箱提交后可能的分支：
          A) otp → 点“使用密码继续”→ password → 填密码 → 回到 otp → 填验证码 → profile → done
          B) otp → 直接填验证码（passwordless）→ profile → done
          C) password → 填密码 → otp → 填验证码 → profile → done
        每一步做完都重新识别页面，不假设下一步是什么。
        """
        otp_done = False       # 验证码是否已提交成功
        password_done = False  # 密码是否已设置
        stall = 0              # 连续识别为 unknown 的次数

        for _round in range(20):
            step = self._detect_step(page)

            if step == "done":
                logger.info("[browser] 账号已创建")
                return

            if step == "login_password":
                raise RuntimeError(f"邮箱已被注册（落到登录密码页）: {email}")

            if step == "otp":
                # 还没设过密码 → 先去密码页（有密码的账号更稳，也便于后续登录）
                if not password_done and not otp_done:
                    if self._goto_password_page(page):
                        continue  # 已进入密码页，下一轮处理
                self._handle_otp(page, mail_provider, email)
                otp_done = True
                stall = 0
                continue

            if step == "password":
                if password_done:
                    # 密码已提交成功，页面还在过渡（SPA 切换慢），等一轮
                    time.sleep(2)
                    continue
                self._set_password(page)
                password_done = True
                stall = 0
                continue

            if step == "profile":
                self._complete_profile(page)
                stall = 0
                continue

            if step == "phone":
                self._handle_phone_if_needed(page)
                stall = 0
                continue

            if step == "email":
                # 回到邮箱页 = 上一步被打回了
                raise RuntimeError(f"注册流程被打回邮箱页 url={page.url}")

            if step == "email_submitted":
                # 邮箱已提交、React 还没切走的过渡态，等下一轮即可
                stall = 0
                time.sleep(2)
                continue

            # unknown：可能是 CF 挑战 / 正在跳转 / 中间过渡页
            stall += 1
            if stall == 1:
                self._wait_for_cf_challenge(page)
            if stall >= 8:
                state = self._page_state(page)
                raise RuntimeError(
                    f"注册流程卡在未知页面 url={page.url} "
                    f"inputs={state.get('inputs')} errors={state.get('errors')}"
                )
            time.sleep(2)

        raise RuntimeError(f"注册流程轮次超限，当前 url={page.url}")


    def _goto_password_page(self, page) -> bool:
        """在 OTP 页点“使用密码继续”入口，进入密码设置页。成功返回 True。

        真实 DOM（旧路径 auth.openai.com/email-verification）：
          <a href="https://auth.openai.com/create-account/password"
             class="_root_1h9ak_58 _outline_1h9ak_115"> ... </a>
        必须点击导航（不能 page.goto），否则丢失 auth session 状态，
        报 error_code: create_account_password_missing_username。

        ⚠ 只按 href 属性匹配，不看按钮文案 —— 页面语言随代理出口国变化。
        """
        logger.info("[browser] 尝试进入密码设置页...")
        # 找带 create-account/password 的链接（唯一可靠特征）
        try:
            link = page.locator('a[href*="create-account/password"]').first
            if not link.is_visible(timeout=5_000):
                raise RuntimeError("not visible")
        except Exception:
            logger.info("[browser] 无密码入口链接，走 passwordless（仅验证码）注册")
            return False

        try:
            link.click()
        except Exception as e:
            logger.info(f"[browser] 密码入口点击失败: {e}")
            return False

        # 等页面真的变成密码页（SPA 下 URL 可能不变，只能看 DOM）
        step = self._wait_for_step(page, {"password"}, timeout=15)
        if step == "password":
            logger.info("[browser] 已进入密码设置页")
            return True
        logger.info(f"[browser] 点击密码入口后未进入密码页（当前={step}），走 passwordless")
        return False

    def _set_password(self, page) -> str:
        """[5/10] 设置密码。

        真实 DOM（auth.openai.com/create-account/password）：
          <input type="password" name="new-password" placeholder="密码">
          <input type="hidden" name="username">
          <input type="hidden" name="usernameKind">
          <button type="submit" class="..._primary_...">   ← 主按钮
          <button type="submit" name="intent" class="..._outline_...">  ← 返回 OTP

        正常流程：导航到密码页 → 填密码 → 点主 submit → 回到 OTP 页。
        如果未导航到密码页（_goto_password_page 失败），8s 超时后跳过。
        """
        logger.info("[browser] [5/10] 设置密码...")
        password = _random_password()

        # 等待密码输入框 — 优先使用已验证的真实 DOM 选择器
        pw_selectors = [
            'input[name="new-password"]',   # 真实 DOM: name="new-password"
            'input[type="password"]',       # 备选
        ]
        pw_input = None
        for sel in pw_selectors:
            try:
                el = page.locator(sel).first
                el.wait_for(state="visible", timeout=8_000)
                pw_input = el
                break
            except Exception:
                continue

        if not pw_input:
            # 密码页没出现 — 可能已跳到个人资料页，不报错
            logger.info("[browser] 未出现密码输入框，跳过密码设置（passwordless 注册）")
            return ""

        self.result.password = password
        pw_input.fill(password)
        time.sleep(random.uniform(0.3, 0.6))

        # 回调：密码一生效就存盘
        if self._on_password:
            try:
                self._on_password(self.result.email, password)
            except Exception as e:
                logger.warning(f"[browser] on_password 回调异常: {e}")

        self._click_continue(page)

        # 提交密码后应离开密码页（回到 OTP 页或直接进资料页）
        step = self._wait_for_step(
            page, {"otp", "profile", "phone", "done"}, timeout=25
        )
        logger.info(f"[browser] 密码已设置，当前步骤: {step}")
        return password

    def _find_otp_input(self, page):
        """定位验证码输入框。只按技术属性匹配，绝不用 input[type=text] 泛匹配
        （泛匹配会命中 Google 登录页的邮箱框，之前就踩过这个坑）。"""
        for sel in (
            'input[autocomplete="one-time-code"]',
            'input[name="code"]',
            'input[name="otp"]',
            'input[inputmode="numeric"]',
            'input[type="tel"][maxlength="6"]',
            'input[type="text"][maxlength="6"]',
            'input[data-testid*="otp"]',
            'input[data-testid*="code"]',
        ):
            try:
                el = page.locator(sel).first
                if el.is_visible(timeout=1_500):
                    logger.info(f"[browser] OTP 输入框匹配: {sel}")
                    return el
            except Exception:
                continue
        return None

    def _click_resend_otp(self, page) -> bool:
        """点击重发验证码。真实 DOM 是 <button name="intent" value="resend"
        class="..._transparent_...">，按属性匹配，不看文案。"""
        for sel in (
            'button[name="intent"][value*="resend" i]',
            'button[type="submit"][class*="_transparent_"]',
            'button[data-testid*="resend"]',
        ):
            try:
                btn = page.locator(sel).first
                if btn.is_visible(timeout=2_000) and btn.is_enabled():
                    btn.click()
                    logger.info(f"[browser] 已点击重发验证码: {sel}")
                    time.sleep(2)
                    return True
            except Exception:
                continue
        return False

    def _handle_otp(self, page, mail_provider, email: str):
        """输入邮箱验证码。

        真实 DOM（新旧路径组件一致）：
          <input type="text" name="code" maxlength="6" autocomplete="one-time-code">
          <button type="submit" name="intent" class="..._primary_...">      ← 提交
          <button type="submit" name="intent" class="..._transparent_...">  ← 重发
        """
        logger.info("[browser] 等待 OTP 验证码...")
        otp_timeout = int(self._env("OTP_TIMEOUT", "60"))
        # ⚠ issued_after 必须用邮箱提交时间（而非当前时间），否则会漏掉已到的邮件
        issued_after = getattr(self, "_email_submitted_at", time.time()) - 10

        for attempt in range(1, 3):
            otp_input = self._find_otp_input(page)
            split_boxes = None
            if not otp_input:
                boxes = page.locator('input[maxlength="1"]')
                if boxes.count() >= 6:
                    split_boxes = boxes
                    logger.info("[browser] 检测到 6 个单字符 OTP 输入框")
                else:
                    state = self._page_state(page)
                    raise RuntimeError(f"未找到 OTP 输入框 inputs={state.get('inputs')}")

            code = mail_provider.wait_for_otp(email, otp_timeout, issued_after)
            logger.info(f"[browser] 收到 OTP: {code}")

            if split_boxes is not None:
                for i, digit in enumerate(code):
                    split_boxes.nth(i).fill(digit)
                    time.sleep(random.uniform(0.05, 0.15))
            else:
                otp_input.fill(code)
            time.sleep(random.uniform(0.3, 0.6))

            self._click_continue(page)

            # 等待离开验证码页。⚠ 超时本身不算失败：
            # 只有页面明确标了 aria-invalid / FieldError 才是验证码错了，
            # 否则就是服务端建号慢，按成功放行（参考项目踩过同样的坑）。
            deadline = time.time() + 40
            while time.time() < deadline:
                state = self._page_state(page)
                if self._classify(state) != "otp":
                    logger.info(f"[browser] OTP 已验证，当前 url={page.url}")
                    return
                if state.get("errors") or any(i.get("invalid") for i in state.get("inputs") or []):
                    logger.warning(
                        f"[browser] 验证码被拒（第 {attempt} 次）: {state.get('errors')}"
                    )
                    break
                time.sleep(1)
            else:
                logger.info("[browser] OTP 提交后仍在验证码页但无错误标记，按跳转缓慢处理")
                return

            # 验证码确实错了 → 重发一封再试
            if attempt == 1 and self._click_resend_otp(page):
                issued_after = time.time() - 5
                continue
            raise RuntimeError(f"验证码验证失败: {self._page_state(page).get('errors')}")

    def _complete_profile(self, page):
        """填写个人资料（姓名 + 年龄）。

        真实 DOM（auth.openai.com/about-you 与 chatgpt.com 内嵌路径组件相同）：
          <input type="text" name="name">
          <input type="number" name="age">
          <input type="hidden" name="birthday">
          <button type="submit" class="..._primary_...">

        调用方（状态机）已确认当前就是资料页，这里不再等待。
        """
        logger.info("[browser] 填写个人资料...")
        first_name = random.choice(_FIRST_NAMES)
        last_name = random.choice(_LAST_NAMES)
        age = str(random.randint(22, 35))

        # 姓名：优先单字段 name，其次 first/last 拆分
        name_filled = False
        for sel in ('input[name="name"]', 'input[name="fullName"]',
                    'input[name="full_name"]', 'input[autocomplete="name"]'):
            try:
                el = page.locator(sel).first
                if el.is_visible(timeout=3_000):
                    el.fill(f"{first_name} {last_name}")
                    name_filled = True
                    break
            except Exception:
                continue

        if not name_filled:
            try:
                fn = page.locator('input[name="firstName"], input[name="first_name"]').first
                ln = page.locator('input[name="lastName"], input[name="last_name"]').first
                if fn.is_visible(timeout=3_000):
                    fn.fill(first_name)
                    ln.fill(last_name)
                    name_filled = True
            except Exception:
                pass

        if not name_filled:
            logger.warning("[browser] 未找到姓名输入框")

        # 年龄 / 生日
        age_filled = False
        for sel in ('input[name="age"]', 'input[type="number"]'):
            try:
                el = page.locator(sel).first
                if el.is_visible(timeout=3_000):
                    el.fill(age)
                    age_filled = True
                    break
            except Exception:
                continue
        if not age_filled:
            try:
                bd = page.locator('input[name="birthday"], input[type="date"]').first
                if bd.is_visible(timeout=2_000):
                    year = time.localtime().tm_year - int(age)
                    bd.fill(f"{year}-06-15")
            except Exception:
                pass

        time.sleep(random.uniform(0.3, 0.6))
        self._click_continue(page)
        logger.info(f"[browser] 个人资料已填写: {first_name} {last_name}, age={age}")

        # 提交后服务端要建账号 + 多次重定向，给足 60s；只看 DOM 不看 URL
        step = self._wait_for_step(page, {"done", "phone"}, timeout=60, exclude="profile")
        logger.info(f"[browser] 资料页提交完成，当前步骤: {step}")

    def _handle_phone_if_needed(self, page):
        """[7.5/10] 处理手机验证（如果出现的话）。"""
        # 检查是否出现了手机验证页面
        phone_selectors = [
            'input[name="phone"]',
            'input[type="tel"]',
            'input[aria-label*="phone" i]',
        ]
        phone_input = None
        for sel in phone_selectors:
            try:
                el = page.locator(sel).first
                if el.is_visible(timeout=5_000):
                    phone_input = el
                    break
            except Exception:
                continue

        if not phone_input:
            logger.info("[browser] 未出现手机验证，跳过")
            return

        logger.info("[browser] 检测到手机验证页面")
        if not self._sms_callback:
            logger.warning("[browser] 需要手机验证但未配置 SMS，尝试跳过...")
            # 尝试点击跳过按钮（用 DOM 属性）
            try:
                skip = page.locator(
                    'button[data-testid*="skip"], a[data-testid*="skip"], '
                    'button[class*="skip"], a[class*="skip"]'
                ).first
                if skip.is_visible(timeout=3_000):
                    skip.click()
                    return
            except Exception:
                pass
            raise RuntimeError("需要手机验证但未配置 SMS 提供商")

        # 获取手机号
        phone_info = self._sms_callback.get_phone()
        if not phone_info:
            raise RuntimeError("SMS 提供商无法获取手机号")

        phone_number = phone_info.get("phone_number", "")
        logger.info(f"[browser] 使用手机号: {phone_number}")

        # 输入手机号
        phone_input.fill(phone_number)
        time.sleep(random.uniform(0.3, 0.6))
        self._click_continue(page)

        # 等待 SMS 验证码
        logger.info("[browser] 等待 SMS 验证码...")
        try:
            sms_code = self._sms_callback.get_code(timeout=120)
        except Exception as e:
            raise RuntimeError(f"SMS 验证码获取失败: {e}")

        logger.info(f"[browser] 收到 SMS 验证码: {sms_code}")

        # 输入 SMS 验证码
        code_input = page.locator('input[name="code"], input[type="text"]').first
        code_input.wait_for(state="visible", timeout=10_000)
        code_input.fill(sms_code)
        time.sleep(random.uniform(0.3, 0.5))
        self._click_continue(page)

        if self._sms_callback:
            try:
                self._sms_callback.report_success()
            except Exception:
                pass

        logger.info("[browser] 手机验证完成")

    def _wait_for_chat_page(self, page):
        """[8/10] 确认账号已建成并落到 ChatGPT 主页。

        判据是 /api/auth/session 返回 accessToken —— 比任何 URL 匹配都可靠。
        状态机跑完后通常已经是 done 了，这里只做兜底确认 + 必要时手动导航。
        """
        logger.info("[browser] [8/10] 确认登录态...")
        deadline = time.time() + 60
        while time.time() < deadline:
            if self._has_access_token(page):
                logger.info("[browser] 登录态已确认")
                break
            # 仍在 auth 页 = 服务端还在处理，安静等待，绝不乱点按钮
            # （之前这里会去点 button[type=submit]，把正在提交的表单打乱）
            time.sleep(2)
        else:
            raise RuntimeError(f"未能确认登录态，当前 URL: {page.url}")

        # 确保停在主页（cookie 提取需要 chatgpt.com 上下文）
        if "chatgpt.com" not in page.url or "/auth/" in page.url:
            try:
                page.goto("https://chatgpt.com/", wait_until="load", timeout=30_000)
            except Exception as e:
                logger.debug(f"[browser] 回主页导航异常（不致命）: {e}")

        # 关闭可能出现的欢迎引导弹窗（按 DOM 属性，不看文案）
        for sel in ('button[data-testid*="continue"]', 'button[data-testid*="next"]',
                    'button[data-testid*="okay"]', '[role="dialog"] button[class*="primary"]'):
            try:
                btn = page.locator(sel).first
                if btn.is_visible(timeout=1_500):
                    btn.click()
                    time.sleep(1)
            except Exception:
                continue
        logger.info("[browser] 已到达 ChatGPT 主页")

    def _extract_tokens(self, page, ctx):
        """从浏览器 cookies 中提取凭证。"""
        cookies = ctx.cookies()
        cookie_map = {}
        chatgpt_cookies = []

        for c in cookies:
            domain = c.get("domain", "")
            if "chatgpt.com" in domain or "openai.com" in domain:
                cookie_map[c["name"]] = c["value"]
                chatgpt_cookies.append(c)

        self.result.session_token = cookie_map.get("__Secure-next-auth.session-token", "")
        self.result.device_id = cookie_map.get("oai-did", "")
        self.result.csrf_token = cookie_map.get("__Host-next-auth.csrf-token", "")
        self.result.cookie_header = "; ".join(
            f"{c['name']}={c['value']}" for c in chatgpt_cookies
        )

        logger.info(
            f"[browser] Cookie 提取: "
            f"session_token={len(self.result.session_token)} "
            f"device_id={len(self.result.device_id)} "
            f"csrf_token={len(self.result.csrf_token)}"
        )

    def _fetch_access_token(self, page):
        """通过 API 获取 access_token。

        代理链路抖动会让这个请求偶发 TLS 断开（实测出现过一次），而没有
        access_token 的号对下游基本没用 —— 注册都跑完了不该栽在这一下，
        所以重试几次。
        """
        logger.info("[browser] 获取 access_token...")
        for attempt in range(1, 4):
            try:
                resp = page.request.get(
                    "https://chatgpt.com/api/auth/session",
                    timeout=15_000,
                )
                if resp.ok:
                    data = resp.json()
                    self.result.access_token = data.get("accessToken", "")
                    if self.result.access_token:
                        logger.info(
                            f"[browser] access_token 长度: "
                            f"{len(self.result.access_token)}"
                        )
                        return
                    reason = "响应里没有 accessToken"
                else:
                    reason = f"HTTP {resp.status}"
            except Exception as e:
                # ⚠ Playwright 的异常带完整 call log，里面是整串 Cookie（含
                # session-token）。原样打进日志既刷屏又等于把凭证写到磁盘上。
                reason = str(e).split("\n", 1)[0][:200]

            if attempt < 3:
                logger.warning(
                    f"[browser] 获取 access_token 失败（第 {attempt} 次）: {reason}，重试"
                )
                time.sleep(3)
            else:
                logger.warning(f"[browser] 获取 access_token 最终失败: {reason}")

    def _try_codex_exchange(self, page):
        """尝试通过 Codex OAuth 获取 refresh_token。

        用 page.request 做 PKCE 授权码流程，复用浏览器的 cookie。

        ⚠ 必须用 Codex CLI 的 client_id + localhost 回调，不能用 ChatGPT
        自己那套 web client_id —— web session 拿不到 offline_access，
        authorize 会直接回 200 页面而不是带 code 的 302（实测五次全空）。
        参数与 auth_flow.py 的协议引擎保持一致。
        """
        logger.info("[browser] 尝试 Codex OAuth 获取 refresh_token...")
        try:
            import secrets
            import hashlib
            from urllib.parse import urlparse, parse_qs, urlencode, urljoin

            client_id = self._env("OAUTH_CODEX_CLIENT_ID", "").strip() \
                or "app_EMoamEEZ73f0CkXaXp7hrann"
            redirect_uri = self._env("OAUTH_CODEX_REDIRECT_URI", "").strip() \
                or "http://localhost:1455/auth/callback"
            scope = self._env("OAUTH_CODEX_SCOPE", "").strip() \
                or "openid email profile offline_access"

            code_verifier = secrets.token_urlsafe(43)
            code_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).decode().rstrip("=")

            authorize_url = "https://auth.openai.com/oauth/authorize?" + urlencode({
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": redirect_uri,
                "scope": scope,
                "state": base64.urlsafe_b64encode(
                    secrets.token_bytes(24)).decode().rstrip("="),
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "id_token_add_organizations": "true",
                "codex_cli_simplified_flow": "true",
                "prompt": self._env("OAUTH_CODEX_PROMPT", "login").strip() or "login",
            })

            # 回调指向 localhost:1455，真去请求必然连不上，所以只能逐跳跟随、
            # 在 Location 里把 code 截下来，绝不让它把 callback 消费掉。
            cb_base = redirect_uri.split("?", 1)[0].rstrip("/")
            auth_code, current = "", authorize_url
            for _hop in range(12):
                resp = page.request.get(
                    current, max_redirects=0, timeout=30_000,
                    headers={"Referer": "https://chatgpt.com/"},
                )
                if resp.status not in (301, 302, 303, 307, 308):
                    # 号没绑手机时 OAuth 会停在验证页而不是 302 到 callback，
                    # 这是没接码的号的正常结果，不是故障。
                    logger.info(
                        f"[browser] Codex authorize 未放行（多半是没绑手机号）"
                        f" status={resp.status}"
                    )
                    break
                loc = (resp.headers.get("location") or "").strip()
                if not loc:
                    break
                if loc.startswith("/"):
                    loc = urljoin(current, loc)
                if loc.split("?", 1)[0].rstrip("/") == cb_base:
                    auth_code = parse_qs(urlparse(loc).query).get("code", [""])[0]
                    break
                current = loc

            if not auth_code:
                logger.info("[browser] 无 refresh_token（未接码的号拿不到，属正常）")
                return

            token_resp = page.request.post(
                "https://auth.openai.com/oauth/token",
                form={
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "code": auth_code,
                    "redirect_uri": redirect_uri,
                    "code_verifier": code_verifier,
                },
                timeout=15_000,
            )
            if token_resp.ok:
                td = token_resp.json()
                self.result.refresh_token = td.get("refresh_token", "")
                self.result.id_token = td.get("id_token", "")
                logger.info(
                    f"[browser] Codex OAuth 成功: "
                    f"rt={len(self.result.refresh_token)} "
                    f"id_token={len(self.result.id_token)}"
                )
            else:
                logger.warning(
                    f"[browser] Codex token 交换失败: "
                    f"{token_resp.status} {token_resp.text()[:200]}"
                )

        except Exception as e:
            # 同 _fetch_access_token：Playwright 异常的 call log 里有整串 Cookie
            brief = str(e).split("\n", 1)[0][:200]
            logger.warning(f"[browser] Codex OAuth 异常（不影响注册）: {brief}")

    def _bind_2fa_via_api(self, page):
        """通过浏览器的 API context 绑定 TOTP 2FA。

        直接调用 backend-api，复用浏览器 cookie（包含 session），
        不需要重新登录。逻辑与 two_factor._enroll_and_activate 相同。
        """
        logger.info("[browser] 绑定 2FA...")
        at = self.result.access_token
        if not at:
            logger.warning("[browser] 没有 access_token，跳过 2FA 绑定")
            return

        api_base = "https://chatgpt.com/backend-api/accounts"
        headers = {"Authorization": f"Bearer {at}"}

        try:
            # 1. 检查是否已绑定
            r1 = page.request.get(
                f"{api_base}/mfa_info",
                headers=headers, timeout=15_000,
            )
            if r1.ok:
                info = r1.json()
                if info.get("mfa_enabled") and (info.get("factors", {}) or {}).get("totp"):
                    logger.info("[browser] 该号已绑 2FA，跳过")
                    return

            # 2. Enroll
            logger.info("[browser] enroll TOTP（★secret 只在本次响应出现）...")
            r2 = page.request.post(
                f"{api_base}/mfa/enroll",
                headers={**headers, "Content-Type": "application/json"},
                data=json.dumps({"factor_type": "totp"}),
                timeout=15_000,
            )
            if not r2.ok:
                logger.warning(f"[browser] 2FA enroll 失败: {r2.status} {r2.text()[:200]}")
                return
            en = r2.json()
            secret = en.get("secret", "")
            session_id = en.get("session_id", "")
            factor_id = (en.get("factor", {}) or {}).get("id", "")
            if not secret or not session_id:
                logger.warning(f"[browser] 2FA enroll 响应缺 secret/session_id: {json.dumps(en)[:200]}")
                return

            # 立刻存 secret（一次性下发，取不回）
            self.result.totp_secret = secret
            logger.info(f"[browser] 2FA secret 已获取 (factor_id={factor_id})")

            # 3. Activate
            logger.info("[browser] 计算 TOTP 码并激活...")
            code = _totp_now(secret)
            r3 = page.request.post(
                f"{api_base}/mfa/user/activate_enrollment",
                headers={**headers, "Content-Type": "application/json"},
                data=json.dumps({
                    "code": code,
                    "factor_type": "totp",
                    "session_id": session_id,
                }),
                timeout=15_000,
            )
            if not r3.ok:
                logger.warning(f"[browser] 2FA activate 失败: {r3.status} {r3.text()[:200]}")
                return

            # 4. 验证
            time.sleep(2)
            r4 = page.request.get(
                f"{api_base}/mfa_info",
                headers=headers, timeout=15_000,
            )
            if r4.ok and r4.json().get("mfa_enabled"):
                logger.info("[browser] ✅ 2FA 绑定成功 mfa_enabled=true")
            else:
                logger.warning(
                    f"[browser] 2FA enroll/activate 已 200，但 mfa_info 复核异常: "
                    f"{r4.status} {r4.text()[:120]}"
                )

        except Exception as e:
            logger.warning(f"[browser] 2FA 绑定异常（账号仍有效）: {e}")

    # ══════════════════════════════════════════════════════════
    #  页面状态识别（不依赖 URL、不依赖页面文字）
    # ══════════════════════════════════════════════════════════

    # 一次性把当前页面所有可见 input / button / a / 错误提示抓下来。
    # 只读 DOM 技术属性（name/type/id/autocomplete/inputmode/href/aria-invalid），
    # 绝不读按钮文案 —— 页面语言跟着代理出口国走，文字匹配必然失效。
    _STATE_JS = r"""() => {
        const vis = el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
            && getComputedStyle(el).visibility !== 'hidden'
            && getComputedStyle(el).display !== 'none';
        const inputs = [...document.querySelectorAll('input')].filter(vis).map(el => ({
            type: el.getAttribute('type') || '',
            name: el.getAttribute('name') || '',
            id: el.id || '',
            autocomplete: el.getAttribute('autocomplete') || '',
            inputmode: el.getAttribute('inputmode') || '',
            maxlength: el.maxLength > 0 && el.maxLength < 999999 ? el.maxLength : 0,
            invalid: String(el.getAttribute('aria-invalid') || '').toLowerCase() === 'true',
            disabled: !!el.disabled || !!el.readOnly,
            value: el.type === 'password' ? '' : (el.value || ''),
        }));
        const links = [...document.querySelectorAll('a[href]')].filter(vis)
            .map(el => (el.getAttribute('href') || '').toLowerCase());
        const buttons = [...document.querySelectorAll('button,input[type=submit],[role=button]')].filter(vis)
            .map(el => ({
                type: el.getAttribute('type') || '',
                name: (el.getAttribute('name') || '').toLowerCase(),
                value: (el.getAttribute('value') || '').toLowerCase(),
                cls: String(el.className || '').toLowerCase(),
                disabled: !!el.disabled || String(el.getAttribute('aria-disabled') || '').toLowerCase() === 'true',
            }));
        const errors = [...document.querySelectorAll(
            '.react-aria-FieldError,[slot="errorMessage"],[id$="-error"],[role="alert"]')]
            .filter(vis).map(el => (el.innerText || '').trim()).filter(Boolean).slice(0, 5);
        return {url: location.href, inputs, links, buttons, errors};
    }"""

    def _page_state(self, page) -> dict:
        """抓取当前页面的 DOM 结构快照。失败时返回只含 url 的空状态。"""
        try:
            return page.evaluate(self._STATE_JS) or {}
        except Exception as e:
            logger.debug(f"[browser] 页面状态抓取失败: {e}")
            try:
                return {"url": page.url, "inputs": [], "links": [], "buttons": [], "errors": []}
            except Exception:
                return {"url": "", "inputs": [], "links": [], "buttons": [], "errors": []}

    def _has_access_token(self, page) -> bool:
        """真正的“已登录”判据：调 /api/auth/session 看有没有 accessToken。

        比任何 URL 匹配都可靠 —— 新旧注册路径的落地 URL 完全不同，
        但只要账号建成了，这个接口就一定返回 accessToken。
        用的是相对路径，所以只在 chatgpt.com 上下文里才有意义。
        """
        try:
            if "chatgpt.com" not in page.url:
                return False
            return bool(page.evaluate(
                """() => fetch('/api/auth/session', {credentials:'include'})
                        .then(r => r.json()).then(j => !!(j && j.accessToken))
                        .catch(() => false)"""
            ))
        except Exception:
            return False

    @staticmethod
    def _classify(state: dict) -> str:
        """根据 DOM 快照判断当前处于注册流程的哪一步。

        返回：email / otp / password / login_password / profile / phone / done / unknown
        判据全部基于输入框的技术属性，URL 只做辅助（新旧路径 URL 不同但 DOM 相同）。
        """
        url = str(state.get("url") or "").lower()
        inputs = state.get("inputs") or []
        links = state.get("links") or []

        def attrs(i):
            return " ".join(str(i.get(k) or "") for k in
                            ("type", "name", "id", "autocomplete", "inputmode")).lower()

        all_attrs = " ".join(attrs(i) for i in inputs)

        # ① 登录密码页（邮箱已被注册）—— 必须最先判，避免被当成注册密码页
        if "/log-in/password" in url:
            return "login_password"

        # ② OTP 验证码页：autocomplete=one-time-code / name=code / 6 位数字框
        for i in inputs:
            a = attrs(i)
            if "one-time-code" in a or "otp" in a:
                return "otp"
            if i.get("name") == "code":
                return "otp"
            if i.get("maxlength") == 6 and i.get("inputmode") in ("numeric", "tel"):
                return "otp"
        if sum(1 for i in inputs if i.get("maxlength") == 1) >= 6:
            return "otp"
        if "email-verification" in url:
            return "otp"

        # ③ 注册密码页：type=password 或 autocomplete=new-password
        for i in inputs:
            a = attrs(i)
            if i.get("type") == "password" or "new-password" in a:
                return "password"
        if "create-account/password" in url:
            return "password"

        # ④ 手机号页
        for i in inputs:
            a = attrs(i)
            if i.get("type") == "tel" or "phone" in a or "tel-national" in a:
                return "phone"

        # ⑤ 资料页：name + age/birthday
        has_name = any(i.get("name") in ("name", "fullName", "full_name", "firstName", "first_name")
                       or "autocomplete name" in attrs(i) for i in inputs)
        has_age = any(i.get("name") in ("age", "birthday", "birthdate")
                      or i.get("type") == "number" for i in inputs)
        if has_name and (has_age or "about-you" in url or "profile" in url):
            return "profile"
        if "about-you" in url and inputs:
            return "profile"

        # ⑥ 邮箱输入页
        for i in inputs:
            a = attrs(i)
            if i.get("type") == "email" or i.get("name") in ("email", "username") or "email" in a:
                # 新内嵌路径提交成功后 URL 变成 /auth/login?email=<已填地址>，
                # 但 React 会先把邮箱页重渲染一遍才切到验证码页 —— 这个过渡态
                # 里输入框还在，看起来像「没提交」。此时重填重提交只会白等一轮
                # 并多发一封验证码，所以单独标记出来让调用方继续等。
                if re.search(r"[?&]email=[^&]+", url):
                    return "email_submitted"
                return "email"

        # ⑦ 只剩「使用密码继续」链接（OTP 页密码入口）→ 仍算 OTP 页
        if any("create-account/password" in h for h in links):
            return "otp"

        # ⑧ 以上都不是，且已在 chatgpt.com 非 auth 路径 → 账号已建成
        # ⚠ 这个判断必须放最后：资料页有时也挂在不带 /auth/ 的 chatgpt.com URL 上，
        # 先判会把资料页误当成功。
        if "chatgpt.com" in url and "/auth/" not in url and "/log-in" not in url:
            if not any(x in all_attrs for x in ("password", "one-time-code", "otp")):
                return "done"

        return "unknown"

    def _detect_step(self, page) -> str:
        """识别当前步骤。已登录优先用 accessToken 判定。"""
        step = self._classify(self._page_state(page))
        if step in ("done", "unknown") and self._has_access_token(page):
            return "done"
        return step

    def _wait_for_step(self, page, targets, timeout: int = 30, exclude: str = "") -> str:
        """轮询等待页面进入 targets 之一。

        SPA 客户端跳转不会触发 load 事件，wait_for_load_state 立刻返回、毫无意义，
        只能按秒轮询 DOM。exclude 用于排除“还停在原地”的当前步骤。
        """
        targets = set(targets)
        deadline = time.time() + timeout
        last = ""
        while time.time() < deadline:
            step = self._detect_step(page)
            last = step
            if step in targets and step != exclude:
                return step
            time.sleep(1)
        logger.warning(f"[browser] 等待 {targets} 超时({timeout}s)，当前步骤={last} url={page.url}")
        return last

    # ══════════════════════════════════════════════════════════
    #  工具方法
    # ══════════════════════════════════════════════════════════

    _IDP_RE = re.compile(
        r"google|apple|microsoft|github|facebook|saml|sso|oauth|oidc|"
        r"social|idp|provider|authorize|consent"
    )

    def _is_third_party_idp(self, btn) -> bool:
        """判断按钮是否是第三方登录入口（Google / Apple / Microsoft ...）。

        页面语言跟着代理 IP 走，按钮文案不可依赖，所以只看 DOM 属性 +
        祖先节点的 href/formaction。误点一次就会整条流程跑进 Google 登录页
        （任务 da5d4add427f 就是这么废掉的），宁可漏点也不能点错。
        """
        try:
            blob = btn.evaluate(
                """el => {
                    const parts = [el.className, el.id, el.name, el.value,
                                   el.getAttribute('formaction') || '',
                                   el.getAttribute('data-provider') || '',
                                   el.getAttribute('data-testid') || ''];
                    const a = el.closest('a[href]');
                    if (a) parts.push(a.getAttribute('href') || '');
                    const f = el.closest('form');
                    if (f) parts.push(f.getAttribute('action') || '');
                    return parts.join(' ').toLowerCase();
                }"""
            )
        except Exception:
            return False
        return bool(self._IDP_RE.search(blob or ""))

    def _click_continue(self, page):
        """点击当前页面的主操作按钮（continue / submit）。

        ⚠ 关键：auth.openai.com 的 OTP 页和密码页有 **两个** button[type="submit"]：
          - 主操作: class 含 "_primary_"（提交验证码 / 提交密码）
          - 次要:   class 含 "_transparent_"（重发验证码）或 "_outline_"（返回）
        直接 locator('button[type="submit"]').first 会选到错误的按钮！
        必须优先匹配 _primary_ 类名。

        chatgpt.com 的邮箱输入页只有一个 submit 按钮（class 含 btn-primary），
        不存在这个问题，但为了统一也用 class 匹配。
        """
        btn_selectors = [
            # ① auth.openai.com 双 submit 页面：主按钮 class 含 _primary_
            'button[type="submit"][class*="_primary_"]',
            # ② chatgpt.com 登录/注册页面（单按钮）
            'button[type="submit"][class*="btn-primary"]',
            # ③ 通用 submit（排除已知的次要按钮样式）
            'button[type="submit"]:not([class*="_outline_"]):not([class*="_transparent_"])',
            # ④ data-testid 定位
            'button[data-testid*="continue"]',
            'button[data-testid*="submit"]',
            'input[type="submit"]',
            # ⑤ 表单兜底（排除次要按钮）
            'form button:not([class*="_outline_"]):not([class*="_transparent_"])',
        ]
        for sel in btn_selectors:
            try:
                btn = page.locator(sel).first
                if not btn.is_visible(timeout=3_000):
                    continue
                if self._is_third_party_idp(btn):
                    continue
                # ⚠ 可见 ≠ 可点。React 表单校验没跑完时按钮是 disabled 的，
                # 而 Playwright 的 click() 会一直等它 enable 再超时抛错，
                # 异常被 except 吞掉后整轮白白卡掉几十秒（实测邮箱页卡 40s）。
                # disabled 基本都是暂时的，所以这里主动短轮询等它 enable，
                # 等不到才换下一个选择器 —— 不等的话第一次提交必定落空。
                enabled_at = time.time() + 6
                while btn.is_disabled() and time.time() < enabled_at:
                    time.sleep(0.3)
                if btn.is_disabled():
                    continue
                btn.click(timeout=5_000)
                # ⚠ SPA 表单提交是客户端跳转，load 事件早就触发过了，
                # wait_for_load_state 会立刻返回，等于没等。真正的等待
                # 交给调用方的 _wait_for_step（轮询 DOM）。这里只是给
                # 传统整页跳转留个机会，超时不算错。
                try:
                    page.wait_for_load_state("load", timeout=5_000)
                except Exception:
                    pass
                return
            except Exception:
                continue

        # 兜底①：直接让当前聚焦控件所在的 form 自己提交。
        # 按钮可能因为样式类名改版全部匹配不到，但 form 一定还在。
        try:
            submitted = page.evaluate(
                """() => {
                    const el = document.activeElement;
                    const form = (el && el.closest && el.closest('form'))
                        || document.querySelector('form');
                    if (!form) return false;
                    if (form.requestSubmit) form.requestSubmit();
                    else form.submit();
                    return true;
                }"""
            )
            if submitted:
                logger.debug("[browser] 未匹配到提交按钮，改用 form.requestSubmit()")
                time.sleep(2)
                return
        except Exception:
            pass

        # 兜底②：按回车提交
        logger.debug("[browser] 未找到提交按钮，按 Enter")
        page.keyboard.press("Enter")
        time.sleep(2)

    @staticmethod
    def _on_auth_page(url: str) -> bool:
        """判断当前 URL 是否在 auth 流程页面上（兼容新旧两种路径）。

        旧路径：auth.openai.com/email-verification, /create-account/password, /about-you
        新路径：chatgpt.com/auth/login?email=xxx（内嵌式，所有步骤在 chatgpt.com 上）
        """
        if "auth.openai.com" in url:
            return True
        # 新路径：chatgpt.com/auth/login?email= 表示已经进入验证流程
        if "chatgpt.com/auth/login" in url and "email=" in url:
            return True
        return False

    @staticmethod
    def _email_step_done(current_url: str, initial_url: str) -> bool:
        """判断邮箱提交后是否已进入下一步（OTP / 密码选择页面）。

        成功标志：
          - URL 跳转到 auth.openai.com（旧路径）
          - URL 变为 chatgpt.com/auth/login?email=xxx（新路径，内嵌式）
          - 任何 URL 中出现 email= 参数（通用）
        """
        if "auth.openai.com" in current_url:
            return True
        if "email=" in current_url and current_url != initial_url:
            return True
        return False

    def _wait_for_cf_challenge(self, page, timeout: int = 30):
        """等待 Cloudflare 验证页自动通过。

        Camoufox 能通过大多数 CF Turnstile 验证（3-5 秒自动解决）。
        如果用 Playwright 原版则大概率超时。
        """
        # 检测 CF 验证页特征
        cf_selectors = [
            '#challenge-running',
            '#challenge-stage',
            'iframe[src*="challenges.cloudflare.com"]',
            '[id*="turnstile"]',
        ]
        is_cf = False
        for sel in cf_selectors:
            try:
                if page.locator(sel).count() > 0:
                    is_cf = True
                    break
            except Exception:
                continue

        if not is_cf:
            return  # 不是 CF 验证页

        logger.info("[browser] 检测到 Cloudflare 验证，等待自动通过...")
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(2)
            still_cf = False
            for sel in cf_selectors:
                try:
                    if page.locator(sel).count() > 0:
                        still_cf = True
                        break
                except Exception:
                    continue
            if not still_cf:
                logger.info("[browser] ✅ Cloudflare 验证已通过")
                page.wait_for_load_state("load", timeout=15_000)
                return

        raise RuntimeError(
            f"Cloudflare 验证超时（{timeout}s）。"
            "浏览器指纹可能被检测，建议使用 Camoufox 引擎。"
        )

    def _screenshot_on_error(self, page, error_msg: str = ""):
        """出错时保存截图用于调试。"""
        try:
            ts = int(time.time())
            email_safe = (self.result.email or "unknown").replace("@", "_at_")
            path = SCREENSHOT_DIR / f"error_{email_safe}_{ts}.png"
            page.screenshot(path=str(path), full_page=True)
            logger.error(f"[browser] 错误截图已保存: {path}")
            if error_msg:
                # 同时保存页面 HTML 方便分析
                html_path = path.with_suffix(".html")
                html_path.write_text(page.content(), encoding="utf-8")
        except Exception as e:
            logger.warning(f"[browser] 保存截图失败: {e}")
