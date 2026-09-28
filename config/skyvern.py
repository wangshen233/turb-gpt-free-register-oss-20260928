# -*- coding: utf-8 -*-
"""Skyvern 云端浏览器配置。"""
from config.env_loader import env_str, apply_env_overrides

# Skyvern API Key（Skyvern Cloud Dashboard 创建；优先读 .env / 环境变量）
SKYVERN_API_KEY: str = env_str("SKYVERN_API_KEY", "")

# Skyvern API 根地址。Cloud 默认：https://api.skyvern.com
SKYVERN_API_BASE: str = "https://api.skyvern.com"

# Browser Session 创建参数
SKYVERN_BROWSER_SESSION_TIMEOUT: int = 60  # 分钟
SKYVERN_BROWSER_PROFILE_ID: str = ""
SKYVERN_PROXY_LOCATION: str = ""  # 可选：jp 会自动转成 RESIDENTIAL_JP；留空不传
SKYVERN_GENERATE_BROWSER_PROFILE: bool = False
SKYVERN_AD_BLOCKER: bool = True
SKYVERN_BROWSER_TYPE: str = "stealth-chromium"

# Playwright / 页面超时；留空时实际流程仍会使用 Browser Use 配置中的默认超时
SKYVERN_KEEP_BROWSER_OPEN: bool = False

# Skyvern 手动注册不容易封时，自动化默认尽量贴近“手动操作”：
# - 不走 Browser Use 的 fast mode；
# - 不额外覆盖 UA/语言/时区/Client Hints；
# - 保留较慢逐字输入、点击前停顿、提交后停留。
SKYVERN_HUMAN_MODE: bool = True

# 打开的起始注册页
SKYVERN_START_URL: str = "https://chatgpt.com/auth/login"

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {
    'SKYVERN_API_KEY': 'str',
    'SKYVERN_API_BASE': 'str',
    'SKYVERN_BROWSER_SESSION_TIMEOUT': 'int',
    'SKYVERN_BROWSER_PROFILE_ID': 'str',
    'SKYVERN_PROXY_LOCATION': 'str',
    'SKYVERN_GENERATE_BROWSER_PROFILE': 'bool',
    'SKYVERN_AD_BLOCKER': 'bool',
    'SKYVERN_BROWSER_TYPE': 'str',
    'SKYVERN_KEEP_BROWSER_OPEN': 'bool',
    'SKYVERN_HUMAN_MODE': 'bool',
    'SKYVERN_START_URL': 'str',
})
