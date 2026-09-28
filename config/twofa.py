# -*- coding: utf-8 -*-
"""
2FA（TOTP）配置

是否在注册成功后自动设置 2FA：
    True:  注册完成 → 拉新 OTP 邮件 → enroll TOTP → activate → 把 secret 写入 DB
    False: 跳过整个 2FA 流程，只保存 邮箱 + accessToken

关掉 2FA 不会影响账号可用性，仅意味着账号没有动态口令保护，且少收一封 OTP 邮件。
"""
from config.env_loader import apply_env_overrides

ENABLE_2FA = False

# 自动 2FA 用的出口。留空 = 沿用注册时那个代理（proxy_used，也就是计费住宅代理）。
#
# 实测 2FA 全程只需要一个能连 chatgpt.com 的出口：重认证 → 邮箱 OTP → 换发 token →
# enroll TOTP → activate，没有任何一步要求出口必须是注册地区。所以默认走本地
# 10808 隧道（东京出口）即可 —— **不花住宅代理流量**，也不会因为住宅 IP 抖动失败。
#
# 注意前缀是 socks5h://（Python 侧要远端解析 DNS，见 config/proxy.py）。
TWOFA_PROXY = "socks5h://127.0.0.1:10808"

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'ENABLE_2FA': 'bool', 'TWOFA_PROXY': 'str'})
