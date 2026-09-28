# -*- coding: utf-8 -*-
"""
OpenAI / ChatGPT OAuth 协议固定参数

来自抓包，OpenAI 自己的 client_id 是固定值。
SENTINEL_SV 是 sdk.js 的版本号，会随 OpenAI 更新而变化，
更新时去 https://sentinel.openai.com/sentinel/<version>/sdk.js 找当前版本。
"""

# OAuth 客户端 ID（固定）
OPENAI_CLIENT_ID = "app_X8zY6vW2pQ9tR3dE7nK1jL5gH"

# OAuth scopes
OPENAI_SCOPE = (
    "openid email profile offline_access "
    "model.request model.read "
    "organization.read organization.write"
)

# OAuth audience
OPENAI_AUDIENCE = "https://api.openai.com/v1"

# OAuth 回调（chatgpt.com 端）
OPENAI_REDIRECT_URI = "https://chatgpt.com/api/auth/callback/openai"

# Sentinel SDK 版本号（影响 sentinel iframe URL 与 referer header）
SENTINEL_SV = "20260810913b"

# ChatGPT 页面 build 标识（用于 Sentinel p[6] / documentElement data-build 模拟）
OPENAI_BUILD_ID = "prod-8bfe9e3526fbf9900f9332d46fef7bc0065c4478"

# ChatGPT 前端 CES / API 上报头，来自 2026-09-11 抓包。
OAI_CLIENT_BUILD_NUMBER = "10577136"
OAI_CLIENT_VERSION = OPENAI_BUILD_ID

# Statsig / Analytics SDK 版本，纯协议补齐前端同形态链路时使用。
STATSIG_CLIENT_KEY = "client-nb0qtYlZuy2tCMN5s5ncnuIBCJncjRViT0IzFm7GqST"
STATSIG_SDK_VERSION = "3.33.1"
STATSIG_SDK_TYPE = "javascript-client"
AB_CLIENT_KEY = "client-tN5GMyzpIPKXd3KNv7ANIfiqjRSvNNTTWbZdbdabF58"
AB_SDK_VERSION = "3.32.7"

# 2026-09-09 HAR 中 email-otp/validate 携带 openai-sentinel-token / so-token，flow=email_otp_validate。
SEND_SENTINEL_ON_EMAIL_OTP_VALIDATE = True

# 是否补齐 HAR 中 ChatGPT Web 首屏 bootstrap 预热链路。
# 2026-09-11 抓包：那约 8 个 /backend-anon/* 请求全库 ABSENT（浏览器直接进
# chatgpt.com/auth/login?next=%2F），因此默认关闭，避免邮箱尚未建立 auth session
# 前先打一堆匿名接口（其中还含一次匿名 sentinel prepare）。需要复现旧链路时置 True。
# 2026-09-13 真机复抓（Roxy，同一入口 chatgpt.com/auth/login）：
#   POST /unauth-mweb/auth/handoff **没有**发生；真机这条链路只有
#   GET /auth/login?next=%2F → GET /api/auth/csrf → GET /api/auth/providers → POST /api/auth/signin/openai。
# 所以这枪默认关掉（原先按 09-12 抓包打开，属于对单次抓包的过拟合）。
PROTOCOL_AUTH_HANDOFF_ENABLED = False

# 2026-09-13 真机复抓：/backend-anon/{me, accounts/check, checkout_pricing_config} 真机在发，
# 之前按 09-11 抓包关掉是过时的（那次真机走的是另一个入口）。改回开启。
CHATGPT_ANON_BOOTSTRAP_ENABLED = True
# 匿名态额外预热（models / system_hints / conversation/init / sentinel chat-requirements）。
# 2026-09-13 真机复抓证实真机**不发**这些，属于不相关部分：既多机器特征又白吃流量
# （chat-requirements/prepare 单条解压后 89.6 KiB）。默认关。
CHATGPT_ANON_EXTRA_WARMUP = False

# 预检里那条整页 GET https://chatgpt.com/auth/login?next=%2F。
# 说明：真机前端入口确实是这个页面（保留它更"像真机"），但它是整页 HTML，
# 实测单条真实下行 179.9 KiB —— 占协议注册总下行（760 KiB）的四分之一。
# 关掉后预检剩 csrf / sentinel 两条轻量检查；auth.openai.com 出口被 Cloudflare
# 挑战时仍由 follow_authorize 的换上游逻辑兜底（功能不减，只是没提前一枪）。
PROTOCOL_PREFLIGHT_PAGE_ENABLED = False
CHATGPT_AUTH_BOOTSTRAP_ENABLED = True
# True 时预热失败会中断主流程；默认 False，仅记录日志并继续。
CHATGPT_BOOTSTRAP_STRICT = False

# 登录态预热放后台线程。这一步是 best-effort，但要串行打十来个 /backend-api 请求，
# 实测占单号 ~18s（约 19% 的墙钟时间），而且它在账号已经建好、accessToken 已经拿到
# 之后才跑 —— 卡在这里只是占着 worker 槽位。放后台后 worker 立刻去领下一个号，
# 预热请求照发不误。前置条件：CHATGPT_BOOTSTRAP_STRICT=False（strict 会中断主流程，
# 必须同步执行，代码里会自动回退成同步）。
# 注意：Python 的 ThreadPoolExecutor 线程是非 daemon 的，进程退出前会等它们跑完，
# 所以不会丢预热；批处理只是在收尾时多等一会儿。
CHATGPT_BOOTSTRAP_ASYNC = True
# 后台预热线程池大小。8 个注册 worker 时 4 个预热线程够用（每个 ~18s）。
CHATGPT_BOOTSTRAP_ASYNC_WORKERS = 4

# 首屏静态资源补拉：纯协议链路只 GET 文档、从不下载 /cdn/assets 下的 JS/CSS，
# 在服务端请求日志里就是"一个连脚本都不取的浏览器"。开启后按 modulepreload
# 顺序补拉入口 JS 与主 CSS，让会话形态贴近真实首屏（约 0.3~1 MB）。
PROTOCOL_WARM_PAGE_ASSETS = False
PROTOCOL_WARM_PAGE_ASSET_LIMIT = 8
