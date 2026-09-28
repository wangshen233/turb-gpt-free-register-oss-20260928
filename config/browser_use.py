# -*- coding: utf-8 -*-
"""
Browser Use Cloud 配置。

文档：
- https://docs.browser-use.com/cloud/browser/stealth
- https://docs.browser-use.com/cloud/browser/playwright-puppeteer-selenium

用法：
  1. 在 config/roxybrowser.py 设置 REGISTRATION_DRIVER = "browser_use"
  2. 在 .env 填入 BROWSER_USE_API_KEY（也可用 WebUI 密钥字段写入 .env）
  3. 推荐先关 Codex：ENABLE_CODEX_AUTO = False
"""
from config.env_loader import env_str, apply_env_overrides

# Browser Use API Key（Cloud Dashboard 创建；优先读 .env / 环境变量）
BROWSER_USE_API_KEY: str = env_str("BROWSER_USE_API_KEY", "")

# 连接方式：
#   "cdp_url" = 直接用官方 CDP websocket（推荐，最简单）
#   "sdk"     = 先调 REST 创建 session（预留；默认仍走 cdp_url）
BROWSER_USE_CONNECT_MODE: str = "cdp_url"

# CDP 连接地址模板。{api_key}/{proxy_country_code}/{profile_id} 会按需替换或追加 query。
BROWSER_USE_CDP_BASE: str = "wss://connect.browser-use.com"

# 可选 REST API 根地址（以后若改走显式 create/stop session 用）
BROWSER_USE_API_BASE: str = "https://api.browser-use.com/api/v2"

# 代理国家代码，两位小写，例如 jp / us / sg / de；留空则用 Browser Use 默认出口
BROWSER_USE_PROXY_COUNTRY_CODE: str = "jp"

# 是否使用 Browser Use 内置代理。False 时尽量不强制 cloud proxy（仍取决于服务端默认）
BROWSER_USE_USE_PROXY: bool = True

# 可选：固定 Browser Use profileId，用于复用 cookies/localStorage。
# 个人批量注册建议留空，让每次新会话更干净。
BROWSER_USE_PROFILE_ID: str = ""

# Playwright / 页面超时
BROWSER_USE_TIMEOUT: int = 90
BROWSER_USE_NAVIGATION_TIMEOUT: int = 90

# Browser Use 云端浏览器 keepAlive / 会话存活时间（分钟）。
# 这会作为 connect URL 的 timeout 参数传给 Browser Use，用于让远端浏览器在等待 OTP、短信、callback 时保持活跃。
# Browser Use 当前 timeout 单位是分钟，官方上限通常为 240；代码里会 clamp 到 1~240。
BROWSER_USE_SESSION_TIMEOUT: int = 240

# 快速模式：减少 Browser Use 流程里额外 human_delay 和长等待；默认开启。
BROWSER_USE_FAST_MODE: bool = True

# 阶段耗时日志：打印 connect/goto/email/otp/phone/callback 等步骤耗时，方便定位慢点。
BROWSER_USE_LOG_TIMING: bool = True

# 资料页最大处理时间；超时后不再卡住，直接尝试读取 /api/auth/session 的 accessToken。
BROWSER_USE_PROFILE_TIMEOUT: int = 28
SKYVERN_PROFILE_TIMEOUT: int = 45

# 资料页结束/超时后读取 accessToken 的最大等待时间；取不到则任务失败。
BROWSER_USE_SESSION_ACCESS_TOKEN_TIMEOUT: int = 18
SKYVERN_SESSION_ACCESS_TOKEN_TIMEOUT: int = 35

# 任务结束后是否主动断开 CDP
BROWSER_USE_KEEP_BROWSER_OPEN: bool = False

# 额外 CDP query 参数，会合并到 connect URL；同名字段会覆盖上面的 BROWSER_USE_SESSION_TIMEOUT。
# 例：{"timeout": "120"}  # 单位分钟
BROWSER_USE_EXTRA_QUERY: dict = {}

# 打开的起始注册页
BROWSER_USE_START_URL: str = "https://chatgpt.com/auth/login"

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'BROWSER_USE_API_KEY': 'str', 'BROWSER_USE_PROXY_COUNTRY_CODE': 'str', 'BROWSER_USE_USE_PROXY': 'bool', 'BROWSER_USE_PROFILE_ID': 'str', 'BROWSER_USE_CDP_BASE': 'str', 'BROWSER_USE_TIMEOUT': 'int', 'BROWSER_USE_SESSION_TIMEOUT': 'int', 'BROWSER_USE_FAST_MODE': 'bool', 'BROWSER_USE_LOG_TIMING': 'bool', 'BROWSER_USE_PROFILE_TIMEOUT': 'int', 'SKYVERN_PROFILE_TIMEOUT': 'int', 'BROWSER_USE_SESSION_ACCESS_TOKEN_TIMEOUT': 'int', 'SKYVERN_SESSION_ACCESS_TOKEN_TIMEOUT': 'int', 'BROWSER_USE_KEEP_BROWSER_OPEN': 'bool', 'BROWSER_USE_START_URL': 'str'})
