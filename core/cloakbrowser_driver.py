# -*- coding: utf-8 -*-
"""CloakBrowser 的 Selenium 风格轻量适配层。"""
from __future__ import annotations

import logging
import os
import random
import re
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any

from config import cloakbrowser as _cfg

logger = logging.getLogger(__name__)


@dataclass
class CloakOpenResult:
    profile_id: str = "cloakbrowser"
    raw: dict | None = None


class CloakElement:
    def __init__(self, page, locator=None, handle=None):
        self.page = page
        self.locator = locator
        self.handle = handle

    def _handle(self):
        if self.handle is not None:
            return self.handle
        return self.locator.element_handle(timeout=5000)

    def _eval(self, expression: str, arg: Any = None) -> Any:
        if self.locator is not None:
            try:
                return self.locator.evaluate(expression, arg, timeout=3000)
            except TypeError:
                return self.locator.evaluate(expression, arg)
        return self.handle.evaluate(expression, arg)

    def _eval_handle(self, expression: str, arg: Any = None) -> Any:
        h = self._handle()
        return h.evaluate_handle(expression, arg)

    def is_displayed(self) -> bool:
        try:
            if self.locator is not None:
                return bool(self.locator.is_visible(timeout=800))
            return bool(self.handle.evaluate("el => !!el && !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) && getComputedStyle(el).visibility !== 'hidden' && getComputedStyle(el).display !== 'none'"))
        except Exception:
            return False

    def is_enabled(self) -> bool:
        try:
            if self.locator is not None:
                return bool(self.locator.is_enabled(timeout=800))
            return bool(self.handle.evaluate("el => !el.disabled && el.getAttribute('aria-disabled') !== 'true'"))
        except Exception:
            return False

    def click(self) -> None:
        if self.locator is not None:
            self.locator.click(timeout=10000)
        else:
            self.handle.click(timeout=10000)

    def clear(self) -> None:
        try:
            if self.locator is not None:
                self.locator.fill("", timeout=10000)
            else:
                self.handle.fill("", timeout=10000)
        except Exception:
            # 部分非 input 元素不支持 fill，回退键盘清空。
            self.click()
            self.page.keyboard.press("Meta+A")
            self.page.keyboard.press("Backspace")

    @property
    def tag_name(self) -> str:
        try:
            return str(self._eval("el => el.tagName.toLowerCase()") or "")
        except Exception:
            return ""

    # Selenium Keys 私有区字符 → Playwright 键名。
    _SPECIAL_KEYS = {
        "\ue003": "Backspace",
        "\ue004": "Tab",
        "\ue006": "Return",
        "\ue007": "Enter",
        "\ue00c": "Escape",
        "\ue00d": "Space",
        "\ue011": "PageUp",
        "\ue012": "ArrowLeft",
        "\ue013": "ArrowUp",
        "\ue014": "ArrowRight",
        "\ue015": "ArrowDown",
        "\ue016": "Insert",
        "\ue017": "Delete",
        "\ue031": "Home",
        "\ue035": "End",
    }

    def _focus_for_typing(self) -> None:
        """Selenium 的 send_keys 会把焦点交给元素；这里优先 focus()，失败再 click()。"""
        try:
            if self.locator is not None:
                self.locator.focus(timeout=3000)
                return
        except Exception:
            pass
        try:
            if self.handle is not None:
                self.handle.focus()
                return
        except Exception:
            pass
        try:
            self.click()
        except Exception:
            pass

    def _type_literal(self, text: str) -> None:
        if not text:
            return
        try:
            self.page.keyboard.type(text, delay=random.randint(18, 45))
        except Exception:
            # 键盘输入不可用时退回直接写值（语义上是覆盖，仅作兜底）。
            if self.locator is not None:
                self.locator.press_sequentially(text, timeout=10000)
            elif self.handle is not None:
                self.handle.fill(text)

    def send_keys(self, *values: str) -> None:
        """按 Selenium 语义输入：在光标处追加，支持 Keys.* 特殊键。

        之前用 locator.fill() 实现，逐字符输入时每敲一个字符都会覆盖整个输入框，
        最终只留下最后一个字符（例如 邮箱只剩结尾的 "m"，验证码只留最后一位）。
        """
        text = "".join(str(v or "") for v in values)
        lower = text.lower()
        self._focus_for_typing()
        if not text:
            return
        if "\ue03d" in text or "\ue009" in text or "command" in lower or "control" in lower:
            # Selenium Keys.CONTROL/COMMAND：本项目里只用于“全选”。
            modifier = "Meta" if sys.platform == "darwin" else "Control"
            try:
                self.page.keyboard.press(f"{modifier}+A")
            except Exception:
                self.page.keyboard.press("Control+A")
            return

        buffer: list[str] = []
        for ch in text:
            key = self._SPECIAL_KEYS.get(ch)
            if key is None:
                buffer.append(ch)
                continue
            if buffer:
                self._type_literal("".join(buffer))
                buffer = []
            self.page.keyboard.press(key)
        if buffer:
            self._type_literal("".join(buffer))

    def get_attribute(self, name: str) -> str | None:
        try:
            if self.locator is not None:
                return self.locator.get_attribute(name, timeout=1000)
            return self.handle.get_attribute(name)
        except Exception:
            return None


class _SwitchTo:
    def __init__(self, driver: "CloakSeleniumDriver"):
        self._driver = driver

    def window(self, handle: str) -> None:
        self._driver._switch_window(handle)


class CloakBrowserStalled(RuntimeError):
    """Playwright 调用在页面上卡死（无响应）并被看门狗强制中断。"""


class CloakSeleniumDriver:
    """只实现本项目 Roxy Selenium 流程实际用到的 WebDriver 子集。"""

    # 页面在导航瞬间执行 JS 时，Playwright 偶尔既不返回也不报错（调用挂死）。
    # 看门狗在 STALL_SECONDS 内没有任何成功调用时杀掉浏览器进程树，让挂死的调用
    # 立刻抛错退出，而不是让整批注册永久停住。
    STALL_SECONDS = float(os.getenv("CLOAK_STALL_SECONDS") or 75)

    def __init__(self, browser: Any, context: Any | None, page: Any):
        self.browser = browser
        self.context = context
        self.page = page
        self._page_load_timeout_ms = int(getattr(_cfg, "CLOAK_SELENIUM_TIMEOUT", 90) or 90) * 1000
        self.switch_to = _SwitchTo(self)
        self.stalled = False
        self._last_ok = time.time()
        self._watchdog_stop = threading.Event()
        self._watchdog = threading.Thread(
            target=self._stall_watchdog, name="cloak-stall-watchdog", daemon=True
        )
        self._watchdog.start()

    def note_activity(self) -> None:
        self._last_ok = time.time()

    def _iter_child_processes(self) -> list[Any]:
        try:
            import psutil
        except ImportError:
            return []
        try:
            parent = psutil.Process(os.getpid())
            return parent.children(recursive=True)
        except Exception:
            return []

    def _kill_browser_processes(self) -> int:
        killed = 0
        for proc in self._iter_child_processes():
            try:
                name = (proc.name() or "").lower()
            except Exception:
                continue
            if not any(token in name for token in ("chrome", "chromium", "headless", "cloak")):
                continue
            try:
                proc.kill()
                killed += 1
            except Exception:
                pass
        return killed

    def _stall_watchdog(self) -> None:
        interval = max(5.0, min(15.0, self.STALL_SECONDS / 4))
        while not self._watchdog_stop.wait(interval):
            if self.stalled:
                return
            silent = time.time() - self._last_ok
            if silent < self.STALL_SECONDS:
                continue
            self.stalled = True
            killed = self._kill_browser_processes()
            logger.warning(
                "[Cloak] 页面 %.0fs 无响应，看门狗已中断浏览器（killed=%s），让挂死的调用抛错退出",
                silent, killed,
            )
            return

    def close(self) -> None:
        self._watchdog_stop.set()

    @property
    def current_url(self) -> str:
        return str(getattr(self.page, "url", "") or "")

    @property
    def window_handles(self) -> list[str]:
        pages = self._pages()
        return [str(i) for i in range(len(pages))]

    def _pages(self) -> list[Any]:
        try:
            if self.context is not None:
                return list(self.context.pages)
        except Exception:
            pass
        try:
            contexts = list(getattr(self.browser, "contexts", []) or [])
            pages = []
            for ctx in contexts:
                pages.extend(list(getattr(ctx, "pages", []) or []))
            return pages or [self.page]
        except Exception:
            return [self.page]

    def _switch_window(self, handle: str) -> None:
        pages = self._pages()
        idx = int(handle)
        self.page = pages[idx]
        try:
            self.page.bring_to_front()
        except Exception:
            pass

    def set_page_load_timeout(self, seconds: int) -> None:
        self._page_load_timeout_ms = int(seconds) * 1000
        try:
            self.page.set_default_navigation_timeout(self._page_load_timeout_ms)
            self.page.set_default_timeout(self._page_load_timeout_ms)
        except Exception:
            pass

    def get(self, url: str) -> None:
        self.page.goto(url, wait_until="domcontentloaded", timeout=self._page_load_timeout_ms)
        self.note_activity()

    def back(self) -> None:
        self.page.go_back(wait_until="domcontentloaded", timeout=self._page_load_timeout_ms)
        self.note_activity()

    def refresh(self) -> None:
        self.page.reload(wait_until="domcontentloaded", timeout=self._page_load_timeout_ms)
        self.note_activity()

    def quit(self) -> None:
        self._watchdog_stop.set()
        try:
            if self.context is not None:
                self.context.close()
        except Exception:
            pass
        try:
            self.browser.close()
        except Exception:
            pass

    def find_elements(self, by: Any, selector: str) -> list[CloakElement]:
        loc = self._locator(by, selector)
        try:
            count = min(int(loc.count()), 200)
        except Exception:
            count = 0
        return [CloakElement(self.page, loc.nth(i)) for i in range(count)]

    def find_element(self, by: Any, selector: str) -> CloakElement:
        els = self.find_elements(by, selector)
        if not els:
            raise RuntimeError(f"找不到页面元素: {selector}")
        return els[0]

    def _locator(self, by: Any, selector: str):
        by_s = str(by or "").lower()
        if "xpath" in by_s or str(selector).startswith("//"):
            return self.page.locator(f"xpath={selector}")
        return self.page.locator(selector)

    def execute_script(self, script: str, *args: Any) -> Any:
        return self._evaluate(script, args=args, async_mode=False)

    def execute_async_script(self, script: str, *args: Any) -> Any:
        return self._evaluate(script, args=args, async_mode=True)

    def execute_cdp_cmd(self, cmd: str, params: dict | None = None) -> Any:
        params = params or {}
        try:
            client = self.context.new_cdp_session(self.page) if self.context is not None else self.page.context.new_cdp_session(self.page)
            return client.send(cmd, params)
        except Exception as exc:
            logger.debug("[Cloak] CDP 命令失败 %s: %s", cmd, exc)
            return None

    def _serialize_args(self, args: tuple[Any, ...]) -> tuple[CloakElement | None, list[Any]]:
        """拆分 Selenium 脚本参数。

        Playwright 的 JSHandle/ElementHandle 不能可靠地嵌在 dict/list payload 中跨
        page.evaluate 传递；Selenium 脚本最常见模式是 `arguments[0]` 为元素，
        因此这里把第一个 CloakElement 作为真实 DOM `el` 传入，其它参数保持
        JSON 可序列化。
        """
        first_el = args[0] if args and isinstance(args[0], CloakElement) else None
        rest = list(args[1:] if first_el else args)
        cleaned = []
        for item in rest:
            if isinstance(item, CloakElement):
                # 极少数脚本会传多个元素；用真实 handle 直接会在嵌套 payload 中失效，
                # 这里退化为 None，比把错误对象传进 JS 更安全。
                cleaned.append(None)
            else:
                cleaned.append(item)
        return first_el, cleaned

    @staticmethod
    def _unwrap_js_result(page, handle: Any) -> Any:
        try:
            element = handle.as_element()
        except Exception:
            element = None
        if element is not None:
            return CloakElement(page, handle=element)
        try:
            return handle.json_value()
        except Exception as exc:
            msg = str(exc)
            if "Execution context was destroyed" in msg or "navigation" in msg.lower():
                logger.info("[Cloak] JS 执行后页面发生跳转，忽略返回值读取失败：%s", msg[:160])
                return {"ok": True, "reason": "navigation_after_script"}
            raise
        finally:
            try:
                handle.dispose()
            except Exception:
                pass

    # 页面在评估 JS 的瞬间发生跳转（Cloudflare 挑战、auth 重定向、SPA 路由）时，
    # Playwright 会抛 "Execution context was destroyed"；这不是流程错误，等页面
    # 稳定后重试即可。之前直接抛出去会让整个注册在"找邮箱输入框"阶段失败。
    NAV_RETRY = 4
    NAV_RETRY_DELAY = 0.6
    _NAV_TRANSIENT_MARKERS = (
        "Execution context was destroyed",
        "because of a navigation",
        "Execution context is not available",
        "Frame was detached",
        "Target page, context or browser has been closed",
    )

    def _is_transient_navigation_error(self, exc: Exception) -> bool:
        message = str(exc)
        return any(marker.lower() in message.lower() for marker in self._NAV_TRANSIENT_MARKERS)

    def _with_navigation_retry(self, action, *, what: str):
        last_exc: Exception | None = None
        for attempt in range(1, self.NAV_RETRY + 1):
            if self.stalled:
                raise CloakBrowserStalled(f"{what} 跳过：浏览器已被看门狗中断")
            began = time.time()
            try:
                result = action()
                self.note_activity()
                if attempt > 1:
                    logger.info("[Cloak] %s 第 %s 次尝试成功（%.2fs）", what, attempt, time.time() - began)
                return result
            except Exception as exc:
                if not self._is_transient_navigation_error(exc) or attempt >= self.NAV_RETRY:
                    raise
                last_exc = exc
                logger.info(
                    "[Cloak] %s 遇到页面跳转（第 %s/%s 次，%.2fs），等待页面稳定后重试：%s",
                    what, attempt, self.NAV_RETRY, time.time() - began, str(exc)[:120],
                )
                try:
                    self.page.wait_for_load_state("domcontentloaded", timeout=5000)
                    logger.debug("[Cloak] %s 第 %s 次等待页面稳定完成", what, attempt)
                except Exception as settle_exc:
                    logger.debug("[Cloak] %s 等待页面稳定失败：%s", what, str(settle_exc)[:120])
                time.sleep(min(3.0, self.NAV_RETRY_DELAY * attempt))
                logger.info("[Cloak] %s 第 %s 次重试开始：action=%s", what, attempt + 1, getattr(action, "__name__", "call"))
        if last_exc is not None:
            raise last_exc

    def _evaluate(self, script: str, args: tuple[Any, ...], async_mode: bool) -> Any:
        first_el, serial_args = self._serialize_args(args)
        if async_mode:
            wrapper = """async ({script, args}) => {
              return await new Promise((resolve) => {
                const fn = new Function(...args.map((_, i) => 'a' + i), '__cloak_done', script);
                const timer = setTimeout(() => resolve({__cloak_timeout:true}), 120000);
                const __cloak_done = (v) => { clearTimeout(timer); resolve(v); };
                try { fn(...args, __cloak_done); } catch (e) { clearTimeout(timer); resolve({ok:false, error:String(e)}); }
              });
            }"""
            element_wrapper = """async (el, payload) => {
              const args = [el, ...payload.args];
              return await new Promise((resolve) => {
                const fn = new Function(...args.map((_, i) => 'a' + i), '__cloak_done', payload.script);
                const timer = setTimeout(() => resolve({__cloak_timeout:true}), 120000);
                const __cloak_done = (v) => { clearTimeout(timer); resolve(v); };
                try { fn(...args, __cloak_done); } catch (e) { clearTimeout(timer); resolve({ok:false, error:String(e)}); }
              });
            }"""
            if first_el is not None:
                result = self._with_navigation_retry(
                    lambda: first_el._eval(element_wrapper, {"script": script, "args": serial_args}),
                    what="execute_async_script",
                )
            else:
                result = self._with_navigation_retry(
                    lambda: self.page.evaluate(wrapper, {"script": script, "args": serial_args}),
                    what="execute_async_script",
                )
            if isinstance(result, dict) and result.get("__cloak_timeout"):
                raise TimeoutError("execute_async_script timeout")
            return result

        # Selenium 脚本经常以 `return ...` 为主体；用 Function 保持语义。
        wrapper = """({script, args}) => {
          const fn = new Function(...args.map((_, i) => 'a' + i), script);
          return fn(...args);
        }"""
        element_wrapper = """(el, payload) => {
          const args = [el, ...payload.args];
          const fn = new Function(...args.map((_, i) => 'a' + i), payload.script);
          return fn(...args);
        }"""
        if first_el is not None:
            handle = self._with_navigation_retry(
                lambda: first_el._eval_handle(element_wrapper, {"script": script, "args": serial_args}),
                what="execute_script",
            )
        else:
            handle = self._with_navigation_retry(
                lambda: self.page.evaluate_handle(wrapper, {"script": script, "args": serial_args}),
                what="execute_script",
            )
        return self._unwrap_js_result(self.page, handle)


def _normalize_proxy(proxy: str | None) -> str | None:
    proxy = str(proxy or "").strip()
    if not proxy:
        return None
    return proxy.replace("socks5h://", "socks5://")


def _detect_cloak_exit_geo(proxy_url: str | None = None) -> dict:
    """按当前/代理出口检测地理信息，供 Cloak 显式 locale/timezone 使用。"""
    try:
        import requests
        from config import browser as _browser_cfg
        endpoints = list(getattr(_browser_cfg, "IP_GEO_ENDPOINTS", []) or [])
        timeout = float(getattr(_browser_cfg, "IP_GEO_TIMEOUT", 6) or 6)
    except Exception:
        return {}
    proxies = None
    if proxy_url:
        proxies = {"http": proxy_url, "https": proxy_url}
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
    for url in endpoints:
        try:
            resp = requests.get(url, headers=headers, proxies=proxies, timeout=timeout)
            if resp.status_code != 200:
                continue
            data = resp.json()
            timezone = data.get("timezone")
            if isinstance(timezone, dict):
                timezone = timezone.get("id") or timezone.get("name")
            geo = {
                "ip": data.get("ip") or data.get("query"),
                "country": (data.get("country") or data.get("country_code") or data.get("countryCode") or "").upper(),
                "region": data.get("region") or data.get("regionName"),
                "city": data.get("city"),
                "timezone": timezone or "",
                "org": data.get("org") or data.get("isp") or (data.get("connection") or {}).get("org"),
            }
            if geo.get("country") or geo.get("timezone"):
                logger.info(
                    "[Cloak] 出口IP地理信息：ip=%s country=%s city=%s timezone=%s",
                    geo.get("ip") or "?", geo.get("country") or "?", geo.get("city") or "?", geo.get("timezone") or "?",
                )
                return geo
        except Exception as exc:
            logger.debug("[Cloak] 出口 IP 地理检测失败 endpoint=%s: %s: %s", url, type(exc).__name__, exc)
    return {}


def _build_cloak_locale_options(proxy_url: str | None = None) -> dict:
    """生成 Cloak/Playwright 双层语言时区配置。"""
    explicit_locale = str(getattr(_cfg, "CLOAK_LOCALE", "") or "").strip()
    explicit_timezone = str(getattr(_cfg, "CLOAK_TIMEZONE", "") or "").strip()
    out = {}
    if explicit_locale:
        out["locale"] = explicit_locale
        # Accept-Language 用 config.browser 自动推断更完整；显式时给一个保守值。
        out["accept_language"] = f"{explicit_locale},{explicit_locale.split('-')[0]};q=0.9,en-US;q=0.8,en;q=0.7"
    if explicit_timezone:
        out["timezone"] = explicit_timezone
    if explicit_locale and explicit_timezone:
        return out
    if not bool(getattr(_cfg, "CLOAK_GEOIP", True)):
        return out
    try:
        from config.browser import build_browser_environment
        geo = _detect_cloak_exit_geo(proxy_url)
        profile = build_browser_environment(geo)
        out.setdefault("locale", str(profile.get("navigator_language") or ""))
        out.setdefault("timezone", str(profile.get("timezone_iana") or ""))
        out.setdefault("accept_language", str(profile.get("accept_language") or ""))
        out["geo"] = geo
    except Exception as exc:
        logger.debug("[Cloak] 构建自动语言/时区失败：%s: %s", type(exc).__name__, exc)
    return {k: v for k, v in out.items() if v}


def build_cloak_driver(proxy: str | None = None) -> tuple[CloakSeleniumDriver, CloakOpenResult]:
    """启动 CloakBrowser 并返回 Selenium 风格 driver。

    proxy=None  时按 config.proxy.PROXY_POOL 随机抽取；
    proxy=""    时显式禁用代理；
    proxy="..." 时使用指定代理。
    """
    if proxy is None and bool(getattr(_cfg, "CLOAK_USE_PROXY", True)):
        try:
            from config.proxy import pick_proxy
            proxy = pick_proxy()
        except Exception:
            proxy = None
    try:
        from cloakbrowser import launch, launch_persistent_context
    except ImportError as exc:
        raise RuntimeError("未安装 cloakbrowser，请执行：pip install cloakbrowser") from exc

    launch_args = list(getattr(_cfg, "CLOAK_EXTRA_ARGS", []) or [])
    seed = str(getattr(_cfg, "CLOAK_FINGERPRINT_SEED", "") or "").strip()
    if seed:
        launch_args.append(f"--fingerprint={seed}")

    proxy_url = _normalize_proxy(proxy) if bool(getattr(_cfg, "CLOAK_USE_PROXY", True)) else None
    locale_opts = _build_cloak_locale_options(proxy_url)
    # geoip=True 交给 CloakBrowser 根据当前出口 IP 自动匹配 timezone/locale/WebRTC。
    # 之前只有显式 proxy_url 时才开启；如果用户走系统代理/VPN/透明代理，代码层面
    # 看不到 proxy_url，会误关 geoip，导致语言/时区不跟随出口。这里改为完全尊重配置。
    opts = {
        "headless": bool(getattr(_cfg, "CLOAK_HEADLESS", False)),
        "humanize": bool(getattr(_cfg, "CLOAK_HUMANIZE", True)),
        "geoip": bool(getattr(_cfg, "CLOAK_GEOIP", True)),
    }
    if locale_opts.get("locale"):
        opts["locale"] = locale_opts["locale"]
    if locale_opts.get("timezone"):
        opts["timezone"] = locale_opts["timezone"]
    if proxy_url:
        opts["proxy"] = proxy_url
    if launch_args:
        opts["args"] = launch_args
    license_key = str(getattr(_cfg, "CLOAK_LICENSE_KEY", "") or "").strip()
    if license_key:
        opts["license_key"] = license_key

    user_data_dir = str(getattr(_cfg, "CLOAK_USER_DATA_DIR", "") or "").strip()
    logger.info(
        "[Cloak] 启动 CloakBrowser：headless=%s humanize=%s geoip=%s proxy=%s locale=%s timezone=%s accept_language=%s persistent=%s",
        opts.get("headless"), opts.get("humanize"), opts.get("geoip"),
        proxy_url or "无", opts.get("locale") or "自动/默认", opts.get("timezone") or "自动/默认",
        locale_opts.get("accept_language") or "自动/默认", bool(user_data_dir),
    )
    context_kwargs = {}
    if locale_opts.get("locale"):
        context_kwargs["locale"] = locale_opts["locale"]
    if locale_opts.get("timezone"):
        context_kwargs["timezone_id"] = locale_opts["timezone"]
    if locale_opts.get("accept_language"):
        context_kwargs["extra_http_headers"] = {"Accept-Language": locale_opts["accept_language"]}

    if user_data_dir:
        context = launch_persistent_context(user_data_dir, **opts)
        page = context.new_page()
        browser = getattr(context, "browser", None) or context
        # persistent context 的 locale/timezone 已通过 launch_persistent_context 参数传入。
    else:
        browser = launch(**opts)
        context = browser.new_context(**context_kwargs)
        page = context.new_page()

    driver = CloakSeleniumDriver(browser=browser, context=context, page=page)
    # Roxy/Cloak 共用部分页面操作函数；给共享函数一个显式日志前缀，
    # 避免 Cloak 注册流程里出现 `[Roxy注册]`。
    driver._registration_log_prefix = "[Cloak注册]"
    driver.set_page_load_timeout(int(getattr(_cfg, "CLOAK_SELENIUM_TIMEOUT", 90) or 90))
    return driver, CloakOpenResult(raw={"driver": "cloakbrowser", "proxy": proxy_url, "locale": locale_opts, "options": {k: v for k, v in opts.items() if k != "license_key"}})
