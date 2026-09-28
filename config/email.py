# -*- coding: utf-8 -*-
"""
邮箱服务配置。

Outlook 注册邮箱与 OTP 的默认池行为：
    1. 首次启动会把旧的 `用于注册的邮箱.txt` 迁移到 SQLite
    2. 运行期间通过 WebUI「邮箱库」导入和管理邮箱
    3. 注册时直接从 SQLite 邮箱库领取可用邮箱
"""
from config.env_loader import env_str, apply_env_overrides


# True: REGISTER_EMAIL 留空时从 Outlook 账号池自动获取邮箱，OTP 自动收取
# False: 走人工输入邮箱 + 人工填 OTP 的流程
USE_EMAIL_SERVICE = False

# 可选值（也可以用英文逗号配置多个，按顺序兜底，例如 "outlook,generic_api,mailnest,remail"）：
#   "outlook"           — 外购 Outlook 账号池 + mail.chatai.codes 远端取信
#   "cloudflare_domain" — Cloudflare 域名邮箱（转发到 QQ 邮箱），通过 IMAP 取信
#   "cloudflare" — Cloudflare Worker 临时邮箱（cloudflare_temp_email），API 创建并取码
#   "generic_api"       — 通用 API 取码邮箱池（邮箱----取码地址）
#   "imap"              — 通用 IMAP 邮箱池（每条素材包含服务器和登录凭证）
#   "gptmail"           — GPTMail 临时邮箱 API（运行时随机生成邮箱并自动收码）
#   "mailnest"          — MailNest/迈巢临时邮箱 API（运行时购买邮箱并自动收码）
#   "cloudmail"         — CloudMail/Cloud Mail API（自动从平台获取域名并随机生成邮箱）
#   "remail"            — Remail 开放 API（按项目下单并自动收取验证码）
EMAIL_SOURCE = "outlook,generic_api,mailnest"


# ============================================================
# Outlook 模式（外购账号池 + 取信服务）
# ============================================================

OUTLOOK_ACCOUNTS_FILE = "用于注册的邮箱.txt"

# Outlook 取件模式：
#   "auto"   = 先用远端 mail.chatai.codes；远端 402/DEPLOYMENT_DISABLED 时自动切 Microsoft Graph 直连
#   "remote" = 只用远端 mail.chatai.codes
#   "direct" = 只用 Microsoft Graph 直连（使用 clientId + refreshToken 换 access_token）
OUTLOOK_FETCH_MODE = "auto"

# 取邮件 API 的根 URL（远端模式使用）
OUTLOOK_API_BASE = "https://mail.chatai.codes"


# ============================================================
# OTP 轮询参数
# ============================================================

OTP_POLL_INTERVAL = 3
OTP_MAX_WAIT = 90

# Outlook 双协议取件：抓到一封 OTP 后再多等多少秒看是否有更晚到达的邮件。
OTP_SETTLE_SECONDS = 5

# 通用 IMAP 邮箱默认收件箱目录；服务器、端口和凭证随邮箱素材导入。
IMAP_MAILBOX = "INBOX"


# ============================================================
# Cloudflare 域名邮箱模式（转发到 QQ 邮箱，通过 IMAP 取信）
# ============================================================

# 转发域名。Duck 隐私邮箱填 duck.com；Cloudflare Email Routing 填自有域名。
# 有 DUCK_EMAIL_TOKEN 时会调 Duck API 生成地址，不能自己拼随机串。
EMAIL_DOMAIN = "duck.com"

# DuckDuckGo Email Protection：POST https://quack.duckduckgo.com/api/email/addresses
# Authorization: Bearer <token>，返回 {"address":"xxx"} → xxx@duck.com，再转发到 QQ IMAP。
DUCK_EMAIL_TOKEN = env_str("DUCK_EMAIL_TOKEN", "")

# QQ 邮箱 IMAP 服务器地址（固定为 imap.qq.com）
QQ_IMAP_SERVER = "imap.qq.com"

# QQ 邮箱 IMAP 端口（SSL）
QQ_IMAP_PORT = 993

# QQ 邮箱地址（接收 Cloudflare 转发的邮件），如 "123456@qq.com"
QQ_EMAIL = ""

# QQ 邮箱 IMAP 授权码（在 QQ 邮箱网页版 → 设置 → 账户 → POP3/IMAP/SMTP 服务 中生成）
# 注意：这是 16 位授权码，不是 QQ 密码
QQ_IMAP_PASSWORD = env_str("QQ_IMAP_PASSWORD", "")


# ============================================================
# GPTMail 临时邮箱 API（固定地址：https://mail.chatgpt.org.uk）
# ============================================================

# 选择 EMAIL_SOURCE="gptmail" 时必填；请在 WebUI「配置 → 邮箱 / OTP」填写。
GPTMAIL_API_KEY = env_str("GPTMAIL_API_KEY", "")


# ============================================================
# Cloudflare Worker 临时邮箱（cloudflare_temp_email 兼容）
# EMAIL_SOURCE 含 "cloudflare" 时启用；与 cloudflare_domain（QQ IMAP）不同。
# ============================================================

# Worker API 根地址，例如 https://mail.example.com
CLOUDFLARE_API_BASE = env_str("CLOUDFLARE_API_BASE", "")

# 匿名模式可留空；admin 模式填 ADMIN_PASSWORD
CLOUDFLARE_API_KEY = env_str("CLOUDFLARE_API_KEY", "")

# none / bearer / x-api-key / x-admin-auth / query-key
CLOUDFLARE_AUTH_MODE = "none"

# Worker 全局密码（PASSWORDS），注入请求头 x-custom-auth
CLOUDFLARE_CUSTOM_AUTH = env_str("CLOUDFLARE_CUSTOM_AUTH", "")

CLOUDFLARE_PATH_DOMAINS = "/api/domains"
CLOUDFLARE_PATH_ACCOUNTS = "/api/new_address"
CLOUDFLARE_PATH_TOKEN = "/api/token"
CLOUDFLARE_PATH_MESSAGES = "/api/mails"

# 默认收信域名，多个可用换行或逗号分隔；留空则由 Worker 决定
CLOUDFLARE_DEFAULT_DOMAINS = []

CLOUDFLARE_REQUEST_TIMEOUT = 20
CLOUDFLARE_NAME_LENGTH = 10


# ============================================================
# MailNest-迈巢 Outlook 临时邮箱：https://mailnest.top/
# ============================================================

# 选择 EMAIL_SOURCE="mailnest" 时必填；请在 WebUI「配置 → 邮箱 / OTP」填写。
MAIL_NEST_API_KEY = env_str("MAIL_NEST_API_KEY", "")

# MailNest 项目代码；OpenAI/ChatGPT 默认 chatgpt001。
MAIL_NEST_PROJECT_CODE = "chatgpt001"

# ============================================================
# CloudMail API 文档：https://doc.skymail.ink/api/api-doc
# ============================================================

# Cloud Mail Worker/API 地址，例如：https://mail.example.com
CLOUDMAIL_API_BASE = ""

# CloudMail 管理员邮箱/密码；用于手动生成 Token，也用于域名被隐藏时自动登录获取域名。
CLOUDMAIL_ADMIN_EMAIL = env_str("CLOUDMAIL_ADMIN_EMAIL", "")
CLOUDMAIL_PASSWORD = env_str("CLOUDMAIL_PASSWORD", "")

# CloudMail 生成 Token 接口路径；默认按 Cloud Mail 公共 API 风格。
CLOUDMAIL_TOKEN_PATH = "/api/public/genToken"

# CloudMail/Cloud Mail API Authorization Token；可手动填写，也可由账号密码自动获取。
CLOUDMAIL_AUTH_TOKEN = env_str("CLOUDMAIL_AUTH_TOKEN", "")

# 邮箱域名列表，每行一个或用英文逗号分隔；可留空，运行时会从 CloudMail 平台自动获取。
CLOUDMAIL_DOMAINS = []

# 生成邮箱后是否调用 /api/public/addUser 创建邮箱用户。
CLOUDMAIL_AUTO_ADD_USER = True

# 随机邮箱 local-part 长度。
CLOUDMAIL_RANDOM_LOCAL_LENGTH = 12


# ============================================================
# Remail 开放 API：https://remail.aishop6.com/docs
# ============================================================

# API 根地址；也兼容填写 https://remail.aishop6.com/docs，客户端会自动规范化。
REMAIL_API_BASE = "https://remail.aishop6.com"

# Remail 控制台生成的 rk- 开头 API Key。
REMAIL_API_KEY = env_str("REMAIL_API_KEY", "")

# 在 Remail 项目列表中选择用于 ChatGPT/OpenAI 验证码的项目 ID，默认使用项目 2。
REMAIL_PROJECT_ID = 2

# 项目下单的邮箱后缀；outlook.com 为微软邮箱商品的常用选择。
REMAIL_EMAIL_SUFFIX = "outlook.com"

# 自建域名池，逗号分隔。单个自建域名一轮只放 16 个可用地址，用满后订单
# 还能建但邮箱收不到验证码，因此批量注册要按域名轮换。留空则只用
# REMAIL_EMAIL_SUFFIX 一个后缀。
REMAIL_EMAIL_SUFFIXES = ""

# 每个后缀用满多少个订单后自动换下一个（自建域名实测为 16）。
REMAIL_SUFFIX_QUOTA = 16

# code 为短效接码；purchase 为可重复收件的长效购买，默认使用 purchase。
REMAIL_SERVICE_MODE = "purchase"

# private_first 优先使用自己的库存；public_only 只使用公开库存，默认使用 public_only。
REMAIL_SUPPLY_POLICY = "public_only"

# 下单响应未立即返回 service token 时，等待订单详情补齐凭证的最长秒数。
REMAIL_ORDER_WAIT_SECONDS = 30

# Remail HTTP 请求超时。
REMAIL_REQUEST_TIMEOUT = 20


# ============================================================
# mail.tm 免费临时邮箱：https://mail.tm （EMAil_SOURCE="mailtm"）
# ============================================================
# 公开免费 API，不需要 API Key。实测 uberip.com 被 ChatGPT 注册流程接受。
# 凭证（address/password）会落盘到 tools/mailtm_accounts.json，查活时复用。

# API 根地址，一般不用改。
MAILTM_API_BASE = "https://api.mail.tm"

# 指定收信域名；留空则每次从 /domains 自动取当前可用域名。
MAILTM_DOMAIN = env_str("MAILTM_DOMAIN", "")

# 可选：mail.tm 请求走的代理；留空直连。
MAILTM_PROXY = env_str("MAILTM_PROXY", "")

# 随机邮箱 local-part 长度。
MAILTM_NAME_LENGTH = 12


# ============================================================
# temp-mail.io 免费临时邮箱（EMAIL_SOURCE="tempmailio"）
# ============================================================
# 公开 API，不需要 API Key；域名由服务端轮换（比 mail.tm 固定域名更难被封）。
# 凭证会落盘到 tools/tempmailio_accounts.json。

TEMPMAILIO_API_BASE = "https://api.internal.temp-mail.io/api/v3"
TEMPMAILIO_DOMAIN = env_str("TEMPMAILIO_DOMAIN", "")
TEMPMAILIO_PROXY = env_str("TEMPMAILIO_PROXY", "")
TEMPMAILIO_NAME_LENGTH = 10

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'USE_EMAIL_SERVICE': 'bool', 'OTP_MAX_WAIT': 'int', 'OTP_POLL_INTERVAL': 'int', 'EMAIL_SOURCE': 'str', 'IMAP_MAILBOX': 'str', 'EMAIL_DOMAIN': 'str', 'DUCK_EMAIL_TOKEN': 'str', 'QQ_EMAIL': 'str', 'QQ_IMAP_PASSWORD': 'str', 'GPTMAIL_API_KEY': 'str', 'OUTLOOK_FETCH_MODE': 'str', 'MAIL_NEST_API_KEY': 'str', 'MAIL_NEST_PROJECT_CODE': 'str', 'CLOUDFLARE_API_BASE': 'str', 'CLOUDFLARE_API_KEY': 'str', 'CLOUDFLARE_AUTH_MODE': 'str', 'CLOUDFLARE_CUSTOM_AUTH': 'str', 'CLOUDFLARE_PATH_DOMAINS': 'str', 'CLOUDFLARE_PATH_ACCOUNTS': 'str', 'CLOUDFLARE_PATH_TOKEN': 'str', 'CLOUDFLARE_PATH_MESSAGES': 'str', 'CLOUDFLARE_DEFAULT_DOMAINS': 'list_str_multiline', 'CLOUDFLARE_REQUEST_TIMEOUT': 'int', 'CLOUDFLARE_NAME_LENGTH': 'int', 'CLOUDMAIL_API_BASE': 'str', 'CLOUDMAIL_ADMIN_EMAIL': 'str', 'CLOUDMAIL_PASSWORD': 'str', 'CLOUDMAIL_TOKEN_PATH': 'str', 'CLOUDMAIL_AUTH_TOKEN': 'str', 'CLOUDMAIL_DOMAINS': 'list_str_multiline', 'CLOUDMAIL_AUTO_ADD_USER': 'bool', 'CLOUDMAIL_RANDOM_LOCAL_LENGTH': 'int', 'REMAIL_API_BASE': 'str', 'REMAIL_API_KEY': 'str', 'REMAIL_PROJECT_ID': 'int', 'REMAIL_EMAIL_SUFFIX': 'str', 'REMAIL_EMAIL_SUFFIXES': 'str', 'REMAIL_SUFFIX_QUOTA': 'int', 'REMAIL_SERVICE_MODE': 'str', 'REMAIL_SUPPLY_POLICY': 'str', 'REMAIL_ORDER_WAIT_SECONDS': 'int', 'REMAIL_REQUEST_TIMEOUT': 'int', 'MAILTM_API_BASE': 'str', 'MAILTM_DOMAIN': 'str', 'MAILTM_PROXY': 'str', 'MAILTM_NAME_LENGTH': 'int', 'TEMPMAILIO_API_BASE': 'str', 'TEMPMAILIO_DOMAIN': 'str', 'TEMPMAILIO_PROXY': 'str', 'TEMPMAILIO_NAME_LENGTH': 'int'})
