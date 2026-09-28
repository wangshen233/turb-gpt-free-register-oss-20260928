# -*- coding: utf-8 -*-
"""
RoxyBrowser 指纹浏览器自动化注册配置。

官方文档：
- API 默认 host: http://127.0.0.1:50000
- 所有接口请求头必须带 token
- 可配合 Selenium / Puppeteer / Playwright 自动化
"""
from config.env_loader import env_int, env_str, apply_env_overrides


# 注册驱动：
#   "protocol"     = 原有 curl_cffi 纯协议注册（容易封号，不建议）
#   "roxy"         = 调用 RoxyBrowser 指纹浏览器 + Selenium 自动化注册
#   "cloak"        = 调用 CloakBrowser + Playwright/Selenium 适配层注册
#   "browser_use"  = Browser Use Cloud stealth Chromium + Playwright
#   "skyvern"      = Skyvern Browser Sessions + Playwright
REGISTRATION_DRIVER: str = "roxy"

# RoxyBrowser 本地 API
ROXY_API_BASE: str = "http://127.0.0.1:50100"
ROXY_API_TOKEN: str = env_str("ROXY_API_TOKEN", "")

# ---- 本地无限窗口 API（_reverse/roxy-api.mjs，默认 50001）----
# 该服务绕过 Roxy 服务端，全部档案从 browser-cache 本地解析，不受账号
# maxWindowCount 限制。代价是请求体与官方不同：create 收 "proxy" 字符串而不是
# proxyInfo，delete 收 "dirId" 单数而不是 "dirIds" 数组。开启后客户端自动切换。
# 留空时按 ROXY_API_BASE 是否指向 :50001 自动判定。
ROXY_UNLIMITED_API: bool = env_str("ROXY_UNLIMITED_API", "").strip().lower() in ("1", "true", "yes", "on")

# 无限窗口 API 下新建档案写入的代理，必须是 Roxy 内核能直连的地址。
# 本机 CN 出口无法直连部分住宅网关（例如 gate*.example.com），
# 必须指向本地 socks5 桥，由桥再接 xray/上游网关。
ROXY_UNLIMITED_PROXY: str = env_str("ROXY_UNLIMITED_PROXY", "socks5://127.0.0.1:11080")
# 代理模板占位符 {SEQ} 的起始序号。并发注册时 ROXY_UNLIMITED_PROXY 写成
#   socks5://icloud{SEQ}:x@127.0.0.1:11099
# 每个新建环境自动拿下一个序号，保证 5 个并发窗口落在 5 个不同的住宅账号上。
ROXY_UNLIMITED_PROXY_SEQ_BASE: int = env_int("ROXY_UNLIMITED_PROXY_SEQ_BASE", 0)

# 无限窗口 API 的 /browser/create 支持 locale / timeZone / screen / os：
#   locale 一次设定「语言 + Accept-Language + 时区」，并让窗口尺寸跟随档案 screen 配置。
# 留空 = 按窗口出口 IP 自动推断（复用 Cloak 那套 _detect_cloak_exit_geo + _build_locale_from_geo），
# BR 出口 → pt-BR / America/Sao_Paulo，VN → vi-VN / Asia/Ho_Chi_Minh，JP → ja-JP / Asia/Tokyo。
ROXY_UNLIMITED_LOCALE: str = env_str("ROXY_UNLIMITED_LOCALE", "")
ROXY_UNLIMITED_TIMEZONE: str = env_str("ROXY_UNLIMITED_TIMEZONE", "")
# 显式分辨率，如 "1920x1080"；留空由 API 从内置档位随机。
ROXY_UNLIMITED_SCREEN: str = env_str("ROXY_UNLIMITED_SCREEN", "")
# 显式系统，取值仅 "Windows 11" / "Windows 10"；留空随机。
ROXY_UNLIMITED_OS: str = env_str("ROXY_UNLIMITED_OS", "")
# 额外内核启动参数（逗号或换行分隔）。一般不用填：
# locale/screen 已由档案层接管，窗口尺寸会跟指纹保持一致。
ROXY_UNLIMITED_EXTRA_ARGS: str = env_str("ROXY_UNLIMITED_EXTRA_ARGS", "")

# 共享磁盘缓存根目录（留空 = 不用缓存）。客户端会按 worker 分槽成 <root>/w1、/w2 …
# 复用 chatgpt.com 的 CDN bundle（内容 hash 不可变，跨档案安全）：
# 不开的话每个账号都新建档案、缓存为空，同一份 ~6 MiB 的 JS 每号重下一次。
# 注意必须分槽：多个 Chromium 并发写同一个 cache dir 会互相淘汰，反而更费流量。
ROXY_UNLIMITED_CACHE_DIR: str = env_str("ROXY_UNLIMITED_CACHE_DIR", "")
ROXY_UNLIMITED_CACHE_SIZE_MB: int = 512

# Roxy 环境/Profile ID；留空时使用 ROXY_PROFILE_CREATE_* 先创建临时环境（如果接口支持）
ROXY_PROFILE_ID: str = ""

# Roxy 工作区 ID。Roxy 创建 Profile 时接口要求 workspaceId，必须填写。
# 可在 Roxy 工作区/团队页面或 API 返回中查看。
ROXY_WORKSPACE_ID: str = "90143"

# Roxy 项目 ID。/browser/workspace 返回 project_details.projectId；创建 Profile 时一并提交。
ROXY_PROJECT_ID: str = "97471"

# 获取团队/工作区列表接口路径。不同版本若不同，可在 WebUI 修改；客户端也会自动尝试多个常见路径。
ROXY_WORKSPACE_LIST_PATH: str = "/browser/workspace"
ROXY_WORKSPACE_LIST_METHOD: str = "GET"

# 接口路径模板。不同版本如有差异，只改这里即可。
# {profile_id} 会替换为 ROXY_PROFILE_ID。
ROXY_OPEN_PATH: str = "/browser/open"
ROXY_CLOSE_PATH: str = "/browser/close"
ROXY_CREATE_PATH: str = "/browser/create"

# 接口方法：常见 open/close 为 GET；若你的版本要求 POST，可在 WebUI/配置里改。
ROXY_OPEN_METHOD: str = "POST"
ROXY_CLOSE_METHOD: str = "POST"
ROXY_CREATE_METHOD: str = "POST"

# 打开浏览器时是否无头启动：
#   False = 显示 Roxy 浏览器窗口（便于观察/调试）
#   True  = 无头启动，不显示窗口（如果当前 Roxy 版本支持 headless）
ROXY_OPEN_HEADLESS: bool = False

# 打开浏览器时附加参数；会合并到 /browser/open 请求体，优先级高于默认值。
ROXY_OPEN_EXTRA_PARAMS: dict = {}

# Selenium 行为
ROXY_SELENIUM_TIMEOUT: int = 90
ROXY_KEEP_BROWSER_OPEN: bool = False

# Roxy API transient 错误重试。create 接口默认不重试，避免超时后重复创建孤儿环境；open/close/delete 会重试。
ROXY_API_RETRIES: int = 3
ROXY_API_RETRY_DELAY: int = 2

# 环境生命周期：
#   True  = 一号一环境：每个账号强制创建新 Profile，用完关闭并删除，不允许复用 ROXY_PROFILE_ID
#   False = 可复用 ROXY_PROFILE_ID 或只关闭不删除
ROXY_ONE_PROFILE_PER_ACCOUNT: bool = True

# 一号一环境结束后是否删除 Profile。建议保持 True。
ROXY_DELETE_PROFILE_AFTER_RUN: bool = True

# 删除环境接口路径/方法；如你的 Roxy 版本不同，只改这里。
ROXY_DELETE_PATH: str = "/browser/delete"
ROXY_DELETE_METHOD: str = "POST"

# 创建 Roxy 环境时随机系统指纹；开启后每次 /browser/create 在 Windows / macOS 里随机选一个，
# 避免固定 macOS 指纹。
ROXY_RANDOM_OS_ON_CREATE: bool = True
ROXY_RANDOM_OS_CHOICES: str = "Windows,macOS"

# 创建 Roxy 环境时随机名称；开启后会覆盖 ROXY_PROFILE_CREATE_PAYLOAD 里的固定 name。
ROXY_RANDOM_PROFILE_NAME_ON_CREATE: bool = True
ROXY_PROFILE_NAME_PREFIX: str = "rb"

# 创建 Roxy 环境时默认系统指纹。仅在 ROXY_RANDOM_OS_ON_CREATE=False 时使用。
# Roxy 官方 os 枚举：Windows / macOS / Linux / IOS / Android。
ROXY_DEFAULT_OS: str = "macOS"
# 留空则使用 Roxy 对应系统的默认/最大版本；如需固定可填 15.3.2、14.7 等。
ROXY_DEFAULT_OS_VERSION: str = ""

# 创建 Roxy 环境时是否使用 config/proxy.py 的 PROXY_POOL：
#   False = 不主动给 Roxy 环境设置代理
#   True  = 每次创建环境时从 PROXY_POOL 随机取一个代理写入 proxyInfo
ROXY_CREATE_USE_PROXY_POOL: bool = False

# Roxy 代理检测通道；留空则不传 checkChannel。
ROXY_PROXY_CHECK_CHANNEL: str = "IPRust.io"

# 没有 ROXY_PROFILE_ID 时创建环境的最小 payload；按你的 Roxy 版本字段调整。
# 默认开启 ROXY_RANDOM_PROFILE_NAME_ON_CREATE，因此这里的 name 只是兜底值。
ROXY_PROFILE_CREATE_PAYLOAD: dict = {
    "name": "gpt-free-register",
    "os": "macOS",
}


# Roxy Codex 授权等待 callback 的最长秒数
ROXY_CODEX_CALLBACK_TIMEOUT: int = 180

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'REGISTRATION_DRIVER': 'str', 'ROXY_API_BASE': 'str', 'ROXY_API_TOKEN': 'str', 'ROXY_UNLIMITED_API': 'bool', 'ROXY_UNLIMITED_PROXY': 'str', 'ROXY_UNLIMITED_PROXY_SEQ_BASE': 'int', 'ROXY_UNLIMITED_EXTRA_ARGS': 'str', 'ROXY_UNLIMITED_CACHE_DIR': 'str', 'ROXY_UNLIMITED_CACHE_SIZE_MB': 'int', 'ROXY_UNLIMITED_LOCALE': 'str', 'ROXY_UNLIMITED_TIMEZONE': 'str', 'ROXY_UNLIMITED_SCREEN': 'str', 'ROXY_UNLIMITED_OS': 'str', 'ROXY_PROFILE_ID': 'str', 'ROXY_WORKSPACE_ID': 'str', 'ROXY_PROJECT_ID': 'str', 'ROXY_WORKSPACE_LIST_PATH': 'str', 'ROXY_OPEN_PATH': 'str', 'ROXY_OPEN_HEADLESS': 'bool', 'ROXY_CLOSE_PATH': 'str', 'ROXY_KEEP_BROWSER_OPEN': 'bool', 'ROXY_ONE_PROFILE_PER_ACCOUNT': 'bool', 'ROXY_DELETE_PROFILE_AFTER_RUN': 'bool', 'ROXY_RANDOM_OS_ON_CREATE': 'bool', 'ROXY_RANDOM_OS_CHOICES': 'str', 'ROXY_RANDOM_PROFILE_NAME_ON_CREATE': 'bool', 'ROXY_PROFILE_NAME_PREFIX': 'str', 'ROXY_CREATE_USE_PROXY_POOL': 'bool', 'ROXY_PROXY_CHECK_CHANNEL': 'str', 'ROXY_DELETE_PATH': 'str', 'ROXY_CODEX_CALLBACK_TIMEOUT': 'int'})
