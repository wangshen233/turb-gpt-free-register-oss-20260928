# -*- coding: utf-8 -*-
"""sub2api 对接配置。"""
from config.env_loader import apply_env_overrides

# 生成 Codex Agent Token 成功后，是否自动同步到 sub2api。
SUB2API_AUTO_EXPORT: bool = True

# 同步模式：
# api  = 直接调用 sub2api 接口上传
# file = 只追加/更新本地 sub2api.json
# both = 接口上传成功/失败不影响本地文件同步
SUB2API_SYNC_MODE: str = "api"

# sub2api API 基址；Agent Token 上传和 Codex OAuth 都复用这个地址。
SUB2API_API_BASE: str = ""

# 兼容旧配置：Agent Token 直接上传完整 URL。
SUB2API_API_URL: str = ""

# sub2api 管理接口 API Key；为空则不带鉴权头。
SUB2API_API_KEY: str = ""

# 兼容旧配置名：SUB2API_API_TOKEN。
SUB2API_API_TOKEN: str = ""

# sub2api 管理接口鉴权头：x-api-key: <your-admin-api-key>。
SUB2API_API_AUTH_HEADER: str = "x-api-key"

# x-api-key 不需要 Bearer 前缀。
SUB2API_API_AUTH_PREFIX: str = ""

# 上传超时秒数。
SUB2API_API_TIMEOUT: int = 20

# 本地 sub2api 配置文件输出路径；相对路径按项目根目录解析。
SUB2API_OUTPUT_PATH: str = "sub2api.json"

# 可选代理键；写入 account.proxy_key，并在 sub2api.json proxies 为空时初始化 proxies[0].proxy_key。
SUB2API_PROXY_KEY: str = ""


# ============================================================
# Codex OAuth 授权对接 sub2
# 当 config.codex.CODEX_AUTH_URL_SOURCE="sub2" 时使用：
#   1) 从 sub2 获取 Codex 授权链接
#   2) 浏览器/协议流程拿到 localhost callback 后回传给 sub2
# ============================================================

# 兼容旧配置：sub2 Codex 管理 API 基址；为空时使用 SUB2API_API_BASE。
SUB2_CODEX_API_BASE: str = ""

# 获取 Codex 授权链接接口路径。
# sub2api 当前接口：POST /api/v1/admin/openai/generate-auth-url
SUB2_CODEX_AUTH_URL_PATH: str = "/api/v1/admin/openai/generate-auth-url"

# 上传/提交 OAuth callback 并创建账号接口路径。
# sub2api 当前创建账号接口：POST /api/v1/admin/openai/create-from-oauth
SUB2_CODEX_CALLBACK_PATH: str = "/api/v1/admin/openai/create-from-oauth"

# 兼容旧配置：sub2 Codex API 鉴权 Token；为空时复用 SUB2API_API_KEY / SUB2API_API_TOKEN。
SUB2_CODEX_API_TOKEN: str = ""

# 鉴权头名称/前缀；为空时复用 SUB2API_API_AUTH_HEADER / SUB2API_API_AUTH_PREFIX。
SUB2_CODEX_AUTH_HEADER: str = ""
SUB2_CODEX_AUTH_PREFIX: str = ""

# callback 上传 payload：
# create_from_oauth => sub2api 原生创建账号：{"session_id","code","state","redirect_uri","name","concurrency","priority"}
# exchange_code     => 只换 token，不创建账号（兼容旧逻辑）
SUB2_CODEX_CALLBACK_PAYLOAD_MODE: str = "create_from_oauth"

apply_env_overrides(globals(), {
    'SUB2API_AUTO_EXPORT': 'bool',
    'SUB2API_SYNC_MODE': 'str',
    'SUB2API_API_BASE': 'str',
    'SUB2API_API_URL': 'str',
    'SUB2API_API_KEY': 'str',
    'SUB2API_API_TOKEN': 'str',
    'SUB2API_API_AUTH_HEADER': 'str',
    'SUB2API_API_AUTH_PREFIX': 'str',
    'SUB2API_API_TIMEOUT': 'int',
    'SUB2API_OUTPUT_PATH': 'str',
    'SUB2API_PROXY_KEY': 'str',
    'SUB2_CODEX_API_BASE': 'str',
    'SUB2_CODEX_AUTH_URL_PATH': 'str',
    'SUB2_CODEX_CALLBACK_PATH': 'str',
    'SUB2_CODEX_API_TOKEN': 'str',
    'SUB2_CODEX_AUTH_HEADER': 'str',
    'SUB2_CODEX_AUTH_PREFIX': 'str',
    'SUB2_CODEX_CALLBACK_PAYLOAD_MODE': 'str',
})
