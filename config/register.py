# -*- coding: utf-8 -*-
"""
注册基础信息（默认值）

CLI 走 main.py 时会优先读这里；Web 控制台批量注册时也会用同样的默认值。
留空字段会触发交互式输入或自动生成（仅 USE_EMAIL_SERVICE=True 时邮箱会从 Outlook 池领取）。
"""
from config.env_loader import apply_env_overrides

# 注册邮箱（留空 + USE_EMAIL_SERVICE=True 时从 Outlook 池领取）
REGISTER_EMAIL = ""

# 注册密码（留空则自动生成 14 位随机密码）
# 仅在 SET_PASSWORD_ON_REGISTER=True 时用得上。
REGISTER_PASSWORD = ""

# 注册时是否**给账号设置密码**。
#
# False（默认，历史行为）：落到 /create-account/password 时点击「使用一次性验证码
#   注册」入口，走 passwordless + OTP。账号在 OpenAI 侧**没有密码**，只能靠邮箱
#   验证码或已开启的 2FA 登录。
#
# True：不点一次性验证码入口，直接在密码页填密码并提交，然后才进邮箱 OTP。
#   密码会写进账号的 extra.registration_password，导出的 copy_line 第三段就是它。
#   卖方要求「注册时把密码跟 2FA 一起弄上」（账号被封时还能登录）时打开这个。
#
# 注意：密码页提交偶发不跳转，代码里已经加了兜底 —— 20 秒还在密码页就自动回退到
# 一次性验证码入口，不会把邮箱白烧。
SET_PASSWORD_ON_REGISTER = False

# 用户名（注册完成后设置的显示名称，留空会自动生成 "Foo Bar" 形式）
# OpenAI 限制：name_invalid_chars —— 只允许字母和空格
REGISTER_NAME = ""

# 注册成功落库后是否自动查询套餐/Plus 资格。
# 关闭后不会在注册完成后立刻访问 backend-api/accounts/check，后续可在账号列表手动查询。
AUTO_PLAN_CHECK_AFTER_REGISTER = True

# 注册成功并拿到 accessToken 后，在浏览器里随机停留一段时间再关闭连接。
# 格式：最小秒,最大秒。设为 "0,0" 表示不额外停留。
POST_REGISTER_DWELL_SECONDS_RANGE = "18,45"

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {
    'REGISTER_EMAIL': 'str',
    'REGISTER_PASSWORD': 'str',
    'SET_PASSWORD_ON_REGISTER': 'bool',
    'REGISTER_NAME': 'str',
    'AUTO_PLAN_CHECK_AFTER_REGISTER': 'bool',
    'POST_REGISTER_DWELL_SECONDS_RANGE': 'str',
})
