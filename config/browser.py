# -*- coding: utf-8 -*-
"""
浏览器指纹与 HTTP 客户端配置。

这里集中维护同一个“浏览器环境画像”，供三层同时使用：
1. curl_cffi TLS / HTTP 头；
2. Python 端生成 Sentinel 初始 p；
3. Node VM 端运行 sdk.js。

原则：同一 BrowserSession 内稳定，不同 BrowserSession 可自然分散；协议头、JS
navigator/screen/timezone/client hints 不能互相打架。
"""
from __future__ import annotations

from config.env_loader import apply_env_overrides

import random
import re
import threading
from datetime import datetime
from zoneinfo import ZoneInfo


def _latest_chrome_major(default: str = "145") -> str:
    """兼容旧模块导入；必须与 curl_cffi 实际 TLS impersonate 版本一致。"""
    return default


CHROME_MAJOR = "145"
CHROME_FULL_VERSION = "145.0.0.0"

SAFARI_VERSION = ""
SAFARI_WEBKIT_VERSION = "537.36"
# UA 里的平台段。Chrome 做了 UA 缩减，Windows 11 也只暴露 "Windows NT 10.0; Win64; x64"，
# 真实系统版本只体现在 sec-ch-ua-platform-version。
WINDOWS_UA_PLATFORM = "Windows NT 10.0; Win64; x64"

# ---------- curl_cffi 模拟浏览器 ----------
# 2026-09-11 实测（同一固定出口 IP，各 4 次打 https://chatgpt.com/login）：
#   chrome146 4/4 403/CF、chrome145 4/4 403/CF、chrome136 4/4 403/CF、chrome133a 3/4 403/CF
#   chrome142 4/4 200、chrome131 4/4 200、chrome124 4/4 200、safari 4/4 200
# 所以 TLS 档位固定在 curl_cffi 能过的最高档 chrome142（curl_cffi 官方最高 chrome146，
# 没有 chrome152，不要写 chrome152）。UA / Client Hints / JS navigator 必须同步为
# Windows 11 + Chrome 142，否则就是 TLS=142 而 HTTP/JS 版本或平台不同的拼接指纹。
IMPERSONATE = "chrome145"

# ---------- 桌面 Chrome 画像（Windows 11 + Chrome 142）----------
# 抓包真机是 Windows 11 + Chrome 152，但我们只能用到 chrome142 的 TLS，
# 因此把 TLS / UA / Client Hints / JS navigator 四处统一成同一套自洽画像。
BROWSER_FAMILY = "chrome"
BROWSER_OS = "Windows"
# OS 相关字段必须和 UA / Client Hints / JS navigator 三方一致。
NAVIGATOR_PLATFORM = "Win32"
NAVIGATOR_VENDOR = "Google Inc."
USER_AGENT_DATA_PLATFORM = "Windows"
USER_AGENT = (
    f"Mozilla/5.0 ({WINDOWS_UA_PLATFORM}) "
    f"AppleWebKit/{SAFARI_WEBKIT_VERSION} (KHTML, like Gecko) "
    f"Chrome/{CHROME_FULL_VERSION} Safari/{SAFARI_WEBKIT_VERSION}"
)

SEC_CH_UA = '"Chromium";v="145", "Not?A_Brand";v="24", "Google Chrome";v="145"'
SEC_CH_UA_FULL_VERSION_LIST = '"Chromium";v="145.0.0.0", "Not?A_Brand";v="24.0.0.0", "Google Chrome";v="145.0.0.0"'
# 高熵提示里的完整版本（抓包里 UA 是缩减版、高熵提示才是真实小版本）。
# 本地没有 chrome142 的真实 build，暂用 142.0.0.0 与 UA / full-version-list 自洽。
SEC_CH_UA_FULL_VERSION = '"145.0.0.0"'
SEC_CH_UA_PLATFORM = '"Windows"'
SEC_CH_UA_PLATFORM_VERSION = '"19.0.0"'
SEC_CH_UA_MOBILE = "?0"
SEC_CH_UA_ARCH = '"x86"'
SEC_CH_UA_BITNESS = '"64"'
SEC_CH_UA_MODEL = '""'
SEND_CLIENT_HINTS = True
# 高熵 Client Hints 改为按域白名单发送（full-version-list / full-version / arch /
# bitness / model / platform-version）。True = 开启按域发送（不是全域发送）。
#
# 2026-09-11 抓包：chatgpt.com 87/97 条带全套，auth.openai.com 100/100 条全都不带。
# 2026-09-12 注册抓包（hrr-export）：这条规律**已经反转**——
#     chatgpt.com     127 条 / 115 条带满 6 项
#     auth.openai.com   2 条 /   2 条带满 6 项（email-otp/validate、create_account）
# auth 域继续只发低熵就是在注册最后两步露馅，所以把 auth.openai.com 加进白名单。
SEND_HIGH_ENTROPY_CLIENT_HINTS = True
HIGH_ENTROPY_CLIENT_HINTS_DOMAINS = ("chatgpt.com", "auth.openai.com")


def should_send_high_entropy_client_hints(host: str) -> bool:
    """按域判断是否附带高熵 Client Hints（只在白名单域发送，与抓包一致）。"""
    if not SEND_HIGH_ENTROPY_CLIENT_HINTS:
        return False
    name = str(host or "").strip().lower().split(":", 1)[0].lstrip(".")
    if not name:
        return False
    return any(name == domain or name.endswith("." + domain) for domain in HIGH_ENTROPY_CLIENT_HINTS_DOMAINS)

# ---------- 语言 / 时区 ----------
# 出口探测失败时的兜底画像。不要用 jp：ja-JP + Asia/Tokyo 套在印度/越南住宅
# IP 上是死号指纹。未知国家走英文。
BROWSER_LOCALE_PROFILE = "us"
AUTO_BROWSER_LOCALE_FROM_IP = True
IP_GEO_TIMEOUT = 6.0
IP_GEO_ENDPOINTS = [
    "https://ipinfo.io/json",
    "https://ipapi.co/json",
    "https://ipwho.is/",
]

# 代理出口质量诊断：默认不拦截，只在手动开启时拒绝云厂商/DC ASN。
# 用户可能明确使用固定云出口复现实验抓包，因此默认 False。
REJECT_CLOUD_PROXY = False
CLOUD_PROXY_ORG_KEYWORDS = [
    "amazon", "aws", "google cloud", "google llc", "microsoft", "azure",
    "digitalocean", "linode", "akamai", "ovh", "hetzner", "oracle",
    "tencent", "alibaba", "aliyun", "huawei cloud", "vultr", "contabo",
    "data center", "datacenter", "hosting", "host", "server", "cloud",
]

# ---------- Roxy/Cloak 浏览器省流量模式 ----------
# 默认关闭。开启后只拦截可选的图片/媒体，以及下面明确列出的统计/第三方 URL；
# 不拦截登录所需的 document、核心 script、stylesheet、xhr/fetch、websocket；
# Playwright 会放行带验证码/challenge 关键词的 URL。
# 该模式仅应用于 Roxy/Cloak，本地浏览器才需要节省带宽；Browser Use/Skyvern 云端
# 浏览器不会安装省流量拦截器。Selenium/CDP 只能按 URL 后缀拦截，若验证码异常可关闭。
BROWSER_DATA_SAVER_MODE: bool = True
# 每行一个 Playwright resource_type。可选 image/media/font/manifest/texttrack 等；
# 默认只拦截 image、media；也可配置 stylesheet/font 等资源；Roxy 还会通过 Chromium 启动参数关闭图片加载，
# 遇到页面布局或验证码异常时可关闭模式。
BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES: list[str] = [
    "image", "media", "font", "manifest", "texttrack", "eventsource",
]
# URL glob 级别的额外拦截。以下是资源明细中确认不参与邮箱密码注册主流程的
# RUM/广告统计资源；Google GSI 仅用于 Google 登录，不使用 Google 登录时默认拦截。
# 不要把 ChatGPT/auth.openai 的 CDN chunk 当作候选：即使某个 chunk 只有少量函数
# 被调用，也可能负责路由、表单切换或懒加载；需经过单变量 A/B 验证后才能加入规则。
# 不要把 chatgpt/openai 的核心 API 或 sentinel URL 加到这里。
# `**` 用于匹配 URL 中的任意路径；Roxy/Cloak 的 Playwright/Selenium 会读取这组规则。
BROWSER_DATA_SAVER_BLOCKED_URL_PATTERNS: list[str] = [
    "**://auth.openai.com/awe/api/v2/rum**",
    "**://chatgpt.com/ces/statsc/flush**",
    "**://connect.facebook.net/**",
    "**://*.google-analytics.com/**",
    "**://*.googletagmanager.com/**",
    "**://*.doubleclick.net/**",
    "**://*.hotjar.com/**",
    "**://*.clarity.ms/**",
    "**://*.sentry.io/**",
    "**://*.segment.io/**",
    "**://*.mixpanel.com/**",
    "**://*.amplitude.com/**",
    "**://analytics.tiktok.com/**",
    "**://snap.licdn.com/**",
    "**://bat.bing.com/**",
    "**://accounts.google.com/gsi/client**",
]

# ---------- Roxy/Cloak 浏览器流量明细日志 ----------
# 默认关闭；开启后在每次注册结束时按单请求总字节降序输出资源 URL、类型、状态和大小。
# URL 查询参数值会脱敏，不保存请求/响应 body 或完整 Header 内容。
BROWSER_TRAFFIC_DETAIL_LOG: bool = False
BROWSER_TRAFFIC_DETAIL_MAX_ENTRIES: int = 2000

# ---------- Roxy/Cloak 浏览器 JS 精确覆盖率 ----------
# 开启后通过 Chrome DevTools Protocol Profiler 记录本次会话实际执行过的
# JavaScript 函数/代码范围。只保存函数名、调用计数和 offset，不读取参数、返回值
# 或源码；Browser Use/Skyvern 云端浏览器不启用该监听；默认关闭，避免给正常注册增加额外开销。
BROWSER_JS_COVERAGE_LOG: bool = False
BROWSER_JS_COVERAGE_MAX_ENTRIES: int = 1000
COUNTRY_LOCALE_PROFILE_MAP = {
    "JP": "jp", "CN": "cn", "HK": "hk", "TW": "tw", "US": "us", "CA": "us",
    "SG": "sg", "GB": "gb", "AU": "gb", "DE": "de", "FR": "fr", "NL": "nl",
    "IN": "in", "VN": "vn", "PH": "ph", "ID": "id", "MY": "my", "TH": "th",
    "KR": "kr", "AE": "ae", "BD": "bd", "PK": "pk", "LK": "lk",
    "BR": "br",
}

BROWSER_LOCALE_PROFILES = {
    "jp": {"navigator_language": "ja-JP", "navigator_languages": ["ja-JP"], "accept_language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Asia/Tokyo", "timezone_offset_minutes": 9 * 60, "timezone_name": "Japan Standard Time"},
    "cn": {"navigator_language": "zh-CN", "navigator_languages": ["zh-CN", "zh"], "accept_language": "zh-CN,zh;q=0.9", "timezone_iana": "Asia/Shanghai", "timezone_offset_minutes": 8 * 60, "timezone_name": "China Standard Time"},
    "us": {"navigator_language": "en-US", "navigator_languages": ["en-US"], "accept_language": "en-US,en;q=0.9", "timezone_iana": "America/Los_Angeles", "timezone_offset_minutes": -7 * 60, "timezone_name": "Pacific Daylight Time"},
    "sg": {"navigator_language": "en-SG", "navigator_languages": ["en-SG"], "accept_language": "en-SG,en-US;q=0.9,en;q=0.8", "timezone_iana": "Asia/Singapore", "timezone_offset_minutes": 8 * 60, "timezone_name": "Singapore Standard Time"},
    "hk": {"navigator_language": "zh-HK", "navigator_languages": ["zh-HK"], "accept_language": "zh-HK,zh-TW;q=0.9,zh;q=0.8,en-US;q=0.7,en;q=0.6", "timezone_iana": "Asia/Hong_Kong", "timezone_offset_minutes": 8 * 60, "timezone_name": "Hong Kong Standard Time"},
    "tw": {"navigator_language": "zh-TW", "navigator_languages": ["zh-TW"], "accept_language": "zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Asia/Taipei", "timezone_offset_minutes": 8 * 60, "timezone_name": "Taipei Standard Time"},
    "gb": {"navigator_language": "en-GB", "navigator_languages": ["en-GB"], "accept_language": "en-GB,en-US;q=0.9,en;q=0.8", "timezone_iana": "Europe/London", "timezone_offset_minutes": 1 * 60, "timezone_name": "British Summer Time"},
    "de": {"navigator_language": "de-DE", "navigator_languages": ["de-DE"], "accept_language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Europe/Berlin", "timezone_offset_minutes": 2 * 60, "timezone_name": "Central European Summer Time"},
    "fr": {"navigator_language": "fr-FR", "navigator_languages": ["fr-FR"], "accept_language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Europe/Paris", "timezone_offset_minutes": 2 * 60, "timezone_name": "Central European Summer Time"},
    "nl": {"navigator_language": "nl-NL", "navigator_languages": ["nl-NL"], "accept_language": "nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7", "timezone_iana": "Europe/Amsterdam", "timezone_offset_minutes": 2 * 60, "timezone_name": "Central European Summer Time"},
    "in": {"navigator_language": "en-IN", "navigator_languages": ["en-IN", "en", "hi"], "accept_language": "en-IN,en;q=0.9,hi;q=0.8", "timezone_iana": "Asia/Kolkata", "timezone_offset_minutes": 330, "timezone_name": "India Standard Time"},
    "vn": {"navigator_language": "vi-VN", "navigator_languages": ["vi-VN", "vi", "en"], "accept_language": "vi-VN,vi;q=0.9,en;q=0.8", "timezone_iana": "Asia/Ho_Chi_Minh", "timezone_offset_minutes": 7 * 60, "timezone_name": "Indochina Time"},
    "ph": {"navigator_language": "en-PH", "navigator_languages": ["en-PH", "en"], "accept_language": "en-PH,en;q=0.9", "timezone_iana": "Asia/Manila", "timezone_offset_minutes": 8 * 60, "timezone_name": "Philippine Standard Time"},
    "id": {"navigator_language": "id-ID", "navigator_languages": ["id-ID", "id", "en"], "accept_language": "id-ID,id;q=0.9,en;q=0.8", "timezone_iana": "Asia/Jakarta", "timezone_offset_minutes": 7 * 60, "timezone_name": "Western Indonesia Time"},
    "my": {"navigator_language": "en-MY", "navigator_languages": ["en-MY", "en", "ms"], "accept_language": "en-MY,en;q=0.9,ms;q=0.8", "timezone_iana": "Asia/Kuala_Lumpur", "timezone_offset_minutes": 8 * 60, "timezone_name": "Malaysia Time"},
    "th": {"navigator_language": "th-TH", "navigator_languages": ["th-TH", "th", "en"], "accept_language": "th-TH,th;q=0.9,en;q=0.8", "timezone_iana": "Asia/Bangkok", "timezone_offset_minutes": 7 * 60, "timezone_name": "Indochina Time"},
    "kr": {"navigator_language": "ko-KR", "navigator_languages": ["ko-KR", "ko"], "accept_language": "ko-KR,ko;q=0.9,en;q=0.8", "timezone_iana": "Asia/Seoul", "timezone_offset_minutes": 9 * 60, "timezone_name": "Korean Standard Time"},
    "ae": {"navigator_language": "en-AE", "navigator_languages": ["en-AE", "en", "ar"], "accept_language": "en-AE,en;q=0.9,ar;q=0.8", "timezone_iana": "Asia/Dubai", "timezone_offset_minutes": 4 * 60, "timezone_name": "Gulf Standard Time"},
    "bd": {"navigator_language": "en-BD", "navigator_languages": ["en-BD", "en", "bn"], "accept_language": "en-BD,en;q=0.9,bn;q=0.8", "timezone_iana": "Asia/Dhaka", "timezone_offset_minutes": 6 * 60, "timezone_name": "Bangladesh Standard Time"},
    "pk": {"navigator_language": "en-PK", "navigator_languages": ["en-PK", "en", "ur"], "accept_language": "en-PK,en;q=0.9,ur;q=0.8", "timezone_iana": "Asia/Karachi", "timezone_offset_minutes": 5 * 60, "timezone_name": "Pakistan Standard Time"},
    "lk": {"navigator_language": "en-LK", "navigator_languages": ["en-LK", "en", "si"], "accept_language": "en-LK,en;q=0.9,si;q=0.8", "timezone_iana": "Asia/Colombo", "timezone_offset_minutes": 330, "timezone_name": "India Standard Time"},
    "br": {"navigator_language": "pt-BR", "navigator_languages": ["pt-BR", "pt", "en"], "accept_language": "pt-BR,pt;q=0.9,en;q=0.8", "timezone_iana": "America/Sao_Paulo", "timezone_offset_minutes": -180, "timezone_name": "Brasilia Standard Time"},
}

TIMEZONE_NAME_BY_IANA = {
    "America/Sao_Paulo": "Brasilia Standard Time",
    "America/Argentina/Buenos_Aires": "Argentina Standard Time",
    "America/Santiago": "Chile Standard Time",
    "Asia/Tokyo": "Japan Standard Time",
    "Asia/Shanghai": "China Standard Time",
    "Asia/Singapore": "Singapore Standard Time",
    "Asia/Hong_Kong": "Hong Kong Standard Time",
    "Asia/Taipei": "Taipei Standard Time",
    "Asia/Kolkata": "India Standard Time",
    "Asia/Calcutta": "India Standard Time",
    "Asia/Colombo": "India Standard Time",
    "Asia/Dhaka": "Bangladesh Standard Time",
    "Asia/Karachi": "Pakistan Standard Time",
    "Asia/Kathmandu": "Nepal Time",
    "Asia/Ho_Chi_Minh": "Indochina Time",
    "Asia/Saigon": "Indochina Time",
    "Asia/Bangkok": "Indochina Time",
    "Asia/Jakarta": "Western Indonesia Time",
    "Asia/Manila": "Philippine Standard Time",
    "Asia/Kuala_Lumpur": "Malaysia Time",
    "Asia/Seoul": "Korean Standard Time",
    "Asia/Dubai": "Gulf Standard Time",
    "America/Los_Angeles": "Pacific Daylight Time",
    "America/New_York": "Eastern Daylight Time",
    "America/Chicago": "Central Daylight Time",
    "America/Denver": "Mountain Daylight Time",
    "Europe/London": "British Summer Time",
    "Europe/Berlin": "Central European Summer Time",
    "Europe/Paris": "Central European Summer Time",
    "Europe/Amsterdam": "Central European Summer Time",
}

# Windows 默认没有 IANA tzdata，ZoneInfo 会失败并退回画像默认偏移。
# 这些无夏令时的常用出口必须写死，避免出现 Asia/Kolkata + GMT+0900。
TIMEZONE_OFFSET_FALLBACK = {
    "Asia/Tokyo": 9 * 60,
    "Asia/Seoul": 9 * 60,
    "Asia/Shanghai": 8 * 60,
    "Asia/Singapore": 8 * 60,
    "Asia/Hong_Kong": 8 * 60,
    "Asia/Taipei": 8 * 60,
    "Asia/Manila": 8 * 60,
    "Asia/Kuala_Lumpur": 8 * 60,
    "Asia/Kolkata": 330,
    "Asia/Calcutta": 330,
    "Asia/Colombo": 330,
    "Asia/Kathmandu": 345,
    "Asia/Dhaka": 6 * 60,
    "Asia/Karachi": 5 * 60,
    "Asia/Dubai": 4 * 60,
    "Asia/Ho_Chi_Minh": 7 * 60,
    "Asia/Saigon": 7 * 60,
    "Asia/Bangkok": 7 * 60,
    "Asia/Jakarta": 7 * 60,
}


def _offset_minutes_for_timezone(tz_name: str, default: int) -> int:
    try:
        offset = datetime.now(ZoneInfo(tz_name)).utcoffset()
        if offset is not None:
            return int(offset.total_seconds() // 60)
    except Exception:
        pass
    if tz_name in TIMEZONE_OFFSET_FALLBACK:
        return int(TIMEZONE_OFFSET_FALLBACK[tz_name])
    return int(default)


def _timezone_name_for_iana(tz_name: str, default: str = "") -> str:
    mapped = TIMEZONE_NAME_BY_IANA.get(tz_name)
    if mapped:
        return mapped
    text = str(tz_name or "").strip()
    if text:
        city = text.split("/")[-1].replace("_", " ")
        return city + " Time"
    return str(default or "")


def _locale_profile_key_from_geo(geo: dict | None) -> str:
    if not geo or not AUTO_BROWSER_LOCALE_FROM_IP:
        return BROWSER_LOCALE_PROFILE
    country = str(geo.get("country") or geo.get("country_code") or "").upper()
    if not country:
        return BROWSER_LOCALE_PROFILE
    # 已知国家未录入时用英文，不要把印度出口伪装成日语东京。
    return COUNTRY_LOCALE_PROFILE_MAP.get(country, "us")


def _build_locale_from_geo(geo: dict | None) -> dict:
    key = _locale_profile_key_from_geo(geo)
    locale = dict(BROWSER_LOCALE_PROFILES.get(key, BROWSER_LOCALE_PROFILES[BROWSER_LOCALE_PROFILE]))
    country = str((geo or {}).get("country") or (geo or {}).get("country_code") or "").upper()
    mapped = COUNTRY_LOCALE_PROFILE_MAP.get(country)
    # 已知国家锁定画像自带时区。ipinfo 经常把越南标成 Asia/Bangkok，
    # 造成 vi-VN + Bangkok 这种自相矛盾的指纹，注册后会被直接打废。
    if geo and AUTO_BROWSER_LOCALE_FROM_IP and not mapped:
        tz = str(geo.get("timezone") or "").strip()
        if tz:
            locale["timezone_iana"] = tz
            locale["timezone_offset_minutes"] = _offset_minutes_for_timezone(tz, int(locale["timezone_offset_minutes"]))
            locale["timezone_name"] = _timezone_name_for_iana(tz, locale.get("timezone_name", ""))
    locale["locale_profile"] = key
    return locale


_LOCALE = BROWSER_LOCALE_PROFILES.get(BROWSER_LOCALE_PROFILE, BROWSER_LOCALE_PROFILES["us"])
NAVIGATOR_LANGUAGE = _LOCALE["navigator_language"]
NAVIGATOR_LANGUAGES = list(_LOCALE["navigator_languages"])
ACCEPT_LANGUAGE = _LOCALE["accept_language"]
TIMEZONE_IANA = _LOCALE["timezone_iana"]
TIMEZONE_OFFSET_MINUTES = int(_LOCALE["timezone_offset_minutes"])
TIMEZONE_NAME = _LOCALE["timezone_name"]

# ---------- Sentinel / JS VM 环境 ----------
SCREEN_WIDTH = 1680
SCREEN_HEIGHT = 1050
HARDWARE_CONCURRENCY = 6
JS_HEAP_SIZE_LIMIT = 4395630592
DEVICE_MEMORY = 8

# 这些列表必须与 sentinel/sentinel-runner.js 的 createBrowserContext 保持一致。
NAVIGATOR_PROTO_SAMPLES = [
    "createAuctionNonce−function createAuctionNonce() { [native code] }",
    "clearOriginJoinedAdInterestGroups−function clearOriginJoinedAdInterestGroups() { [native code] }",
    "updateAdInterestGroups−function updateAdInterestGroups() { [native code] }",
    "canLoadAdAuctionFencedFrame−function canLoadAdAuctionFencedFrame() { [native code] }",
    "gpu−[object GPU]",
    "getBattery−function getBattery() { [native code] }",
    "getGamepads−function getGamepads() { [native code] }",
    "javaEnabled−function javaEnabled() { [native code] }",
    "sendBeacon−function sendBeacon() { [native code] }",
    "vibrate−function vibrate() { [native code] }",
    "login−[object NavigatorLogin]",
    "registerProtocolHandler−function registerProtocolHandler() { [native code] }",
    "deprecatedReplaceInURN−function deprecatedReplaceInURN() { [native code] }",
    "presentation−[object Presentation]",
    "doNotTrack",
    "credentials−[object CredentialsContainer]",  # U+2212, SDK P() 拼接形态
]
DOCUMENT_KEY_SAMPLES = [
    "location", "currentScript", "scripts", "cookie", "URL", "documentURI", "referrer",
    "title", "characterSet", "charset", "compatMode", "contentType", "readyState",
    "visibilityState", "hidden", "hasFocus", "documentElement", "body",
    "addEventListener", "removeEventListener", "querySelector", "querySelectorAll",
    "getElementById", "getElementsByTagName", "createElement",
]
WINDOW_KEY_SAMPLES = [
    "window", "self", "top", "parent", "frames", "navigator", "screen", "location",
    "localStorage", "sessionStorage", "history", "innerWidth", "innerHeight",
    "outerWidth", "outerHeight", "devicePixelRatio", "chrome", "performance", "crypto",
    "TextEncoder", "URL", "URLSearchParams", "AbortController",
    "locationbar", "scrollX", "scrollY", "ondevicemotion",
    "onlostpointercapture", "onratechange", "oncanplay",
    "requestAnimationFrame", "queueMicrotask", "onfocus", "onblur", "onpageshow",
    "releaseEvents", "captureEvents", "__oai_so_cs2", "__oai_so_cs",
]

SCRIPT_SRC_SAMPLES = [
    "https://accounts.google.com/gsi/client",
    "https://chatgpt.com/cdn-cgi/challenge-platform/scripts/jsd/api.js?onload=jsdOnload",
    "https://sentinel.openai.com/sentinel/20260810913b/sdk.js",
]

WINDOW_FEATURE_FLAGS = {
    "ai": 0,
    "InstallTrigger": 0,
    "cache": 0,
    "data": 0,
    "solana": 0,
    "dump": 0,
    # HAR 样本 p[24] 为 0；默认不暴露，必要时由画像开关启用。
    "requestIdleCallback": 0,
}

# ---------- HTTP 超时 ----------
REQUEST_TIMEOUT = 30

# HAR 参考画像：Default-all-domains-1784468371563.json 解码 p[0]/p[2]/p[16] 得出。
HAR_CAPTURE_BASE_PROFILE = {"screen_width": 1680, "screen_height": 1050, "hardware_concurrency": 6, "device_memory": 8, "js_heap_size_limit": 4395630592, "device_pixel_ratio": 2}

# Chrome 在 macOS 上固定上报 10_15_7（UA 缩减），不要写真实系统版本。
MACOS_UA_PLATFORM = "Macintosh; Intel Mac OS X 10_15_7"


def user_agent_for_device(device_os: str) -> str:
    """按设备系统生成 UA，保证与 Client Hints / navigator.platform 同源。"""
    platform = MACOS_UA_PLATFORM if str(device_os).lower() in ("macos", "mac", "darwin") else WINDOWS_UA_PLATFORM
    return (
        f"Mozilla/5.0 ({platform}) "
        f"AppleWebKit/{SAFARI_WEBKIT_VERSION} (KHTML, like Gecko) "
        f"Chrome/{CHROME_FULL_VERSION} Safari/{SAFARI_WEBKIT_VERSION}"
    )


# 设备画像池：每个条目是一台"真实机器"（屏幕 / DPR / 核心数 / 内存 / JS 堆上限），
# UA、navigator.platform、Client Hints、高熵提示全部由 build_browser_environment
# 按条目派生。
#
# 之前池里只有 1 条（抓包那台 1707x1067 / 2 核），结果是**所有账号共用同一套
# 屏幕+核心数**：173 个账号里 163 个完全相同，跨账号一眼就能被串起来。现在按
# 真实机型档位铺开，同一 session 内仍然固定，不同 session 自然分散。
#
# 约束（validate_browser_profile 会检查）：
#   * js_heap_size_limit ≤ 4.6e9（Chrome 64 位上限），且与 device_memory 同档；
#   * Windows 用 x86/19.0.0，macOS 用 arm/15.3.0；
#   * DPR 与分辨率要能对上（高分屏 1.25~2，1080p 多为 1.0）。
BROWSER_PROFILE_POOL = [
    # —— 2026-09-11 抓包实机（Windows 11 + 2 核，保留为候选之一，不再全局钉死）——
    {"os": "windows", "screen_width": 1707, "screen_height": 1067, "device_pixel_ratio": 1.25,
     "hardware_concurrency": 2, "device_memory": 8, "js_heap_size_limit": 4395630592,
     "sec_ch_ua_platform_version": '"19.0.0"', "sec_ch_ua_arch": '"x86"'},
    # —— Windows 11 常见办公/家用机 ——
    {"os": "windows", "screen_width": 1920, "screen_height": 1080, "device_pixel_ratio": 1.0,
     "hardware_concurrency": 8, "device_memory": 16, "js_heap_size_limit": 4294705152,
     "sec_ch_ua_platform_version": '"19.0.0"', "sec_ch_ua_arch": '"x86"'},
    {"os": "windows", "screen_width": 1536, "screen_height": 864, "device_pixel_ratio": 1.25,
     "hardware_concurrency": 4, "device_memory": 8, "js_heap_size_limit": 2147483648,
     "sec_ch_ua_platform_version": '"19.0.0"', "sec_ch_ua_arch": '"x86"'},
    {"os": "windows", "screen_width": 1366, "screen_height": 768, "device_pixel_ratio": 1.0,
     "hardware_concurrency": 4, "device_memory": 8, "js_heap_size_limit": 2147483648,
     "sec_ch_ua_platform_version": '"10.0.0"', "sec_ch_ua_arch": '"x86"'},
    {"os": "windows", "screen_width": 2560, "screen_height": 1440, "device_pixel_ratio": 1.0,
     "hardware_concurrency": 12, "device_memory": 32, "js_heap_size_limit": 4395630592,
     "sec_ch_ua_platform_version": '"19.0.0"', "sec_ch_ua_arch": '"x86"'},
    {"os": "windows", "screen_width": 2048, "screen_height": 1152, "device_pixel_ratio": 1.25,
     "hardware_concurrency": 6, "device_memory": 16, "js_heap_size_limit": 4294705152,
     "sec_ch_ua_platform_version": '"19.0.0"', "sec_ch_ua_arch": '"x86"'},
    {"os": "windows", "screen_width": 1600, "screen_height": 900, "device_pixel_ratio": 1.0,
     "hardware_concurrency": 4, "device_memory": 16, "js_heap_size_limit": 4294705152,
     "sec_ch_ua_platform_version": '"10.0.0"', "sec_ch_ua_arch": '"x86"'},
    {"os": "windows", "screen_width": 1920, "screen_height": 1200, "device_pixel_ratio": 1.5,
     "hardware_concurrency": 8, "device_memory": 16, "js_heap_size_limit": 4294705152,
     "sec_ch_ua_platform_version": '"19.0.0"', "sec_ch_ua_arch": '"x86"'},
    {"os": "windows", "screen_width": 1440, "screen_height": 900, "device_pixel_ratio": 1.0,
     "hardware_concurrency": 8, "device_memory": 8, "js_heap_size_limit": 2147483648,
     "sec_ch_ua_platform_version": '"10.0.0"', "sec_ch_ua_arch": '"x86"'},
    {"os": "windows", "screen_width": 2880, "screen_height": 1620, "device_pixel_ratio": 1.5,
     "hardware_concurrency": 6, "device_memory": 16, "js_heap_size_limit": 4294705152,
     "sec_ch_ua_platform_version": '"19.0.0"', "sec_ch_ua_arch": '"x86"'},
    # —— macOS（Chrome on Mac，retina 2x）——
    {"os": "macos", "screen_width": 1440, "screen_height": 900, "device_pixel_ratio": 2,
     "hardware_concurrency": 8, "device_memory": 16, "js_heap_size_limit": 4294705152,
     "sec_ch_ua_platform_version": '"15.3.0"', "sec_ch_ua_arch": '"arm"'},
    {"os": "macos", "screen_width": 1512, "screen_height": 982, "device_pixel_ratio": 2,
     "hardware_concurrency": 10, "device_memory": 16, "js_heap_size_limit": 4294705152,
     "sec_ch_ua_platform_version": '"15.3.0"', "sec_ch_ua_arch": '"arm"'},
    {"os": "macos", "screen_width": 1728, "screen_height": 1117, "device_pixel_ratio": 2,
     "hardware_concurrency": 8, "device_memory": 16, "js_heap_size_limit": 4294705152,
     "sec_ch_ua_platform_version": '"14.5.0"', "sec_ch_ua_arch": '"arm"'},
    {"os": "macos", "screen_width": 1680, "screen_height": 1050, "device_pixel_ratio": 2,
     "hardware_concurrency": 8, "device_memory": 32, "js_heap_size_limit": 4395630592,
     "sec_ch_ua_platform_version": '"15.3.0"', "sec_ch_ua_arch": '"x86"'},
    {"os": "macos", "screen_width": 2560, "screen_height": 1440, "device_pixel_ratio": 2,
     "hardware_concurrency": 12, "device_memory": 32, "js_heap_size_limit": 4395630592,
     "sec_ch_ua_platform_version": '"15.3.0"', "sec_ch_ua_arch": '"arm"'},
]

# ---- 机型矩阵：把设备池铺开，避免所有账号共用同一台机器 ----
# 每个条目就是一台"真实机器"：屏幕/DPR/核心数/内存/JS 堆上限，外加系统版本与架构。
# UA、navigator.platform、userAgentData.platform、Client Hints 全部由 build_browser_environment
# 派生，所以这里只描述硬件，不写任何可变字符串。
_HEAP_TIERS = {
    4: (1073741824, 2147483648),
    8: (2147483648, 4294705152),
    16: (4294705152, 4395630592),
    24: (4294705152, 4395630592),
    32: (4395630592, 4395630592),
    36: (4395630592, 4395630592),
}


def _heap_for(memory: int, alt: bool = False) -> int:
    """按内存档位取 Chrome 64 位实际会报的 jsHeapSizeLimit。"""
    tier = _HEAP_TIERS.get(int(memory), (2147483648, 4294705152))
    return int(tier[1] if alt else tier[0])


def _device(os_name, width, height, dpr, cores, memory, platform_version, arch='"x86"', alt_heap=False):
    return {
        "os": os_name,
        "screen_width": int(width),
        "screen_height": int(height),
        "device_pixel_ratio": float(dpr),
        "hardware_concurrency": int(cores),
        "device_memory": int(memory),
        "js_heap_size_limit": _heap_for(memory, alt=alt_heap),
        "sec_ch_ua_platform_version": platform_version,
        "sec_ch_ua_arch": arch,
    }


_WIN11 = '"19.0.0"'
_WIN10 = '"10.0.0"'
_MAC_SEQUOIA = '"15.3.0"'
_MAC_SONOMA = '"14.5.0"'

BROWSER_PROFILE_POOL += [
    # —— Windows 11 办公/家用/游戏本 ——
    _device("windows", 1366, 768, 1.0, 4, 8, _WIN11),
    _device("windows", 1600, 900, 1.25, 4, 8, _WIN11),
    _device("windows", 1600, 900, 1.0, 4, 8, _WIN11),
    _device("windows", 1920, 1080, 1.0, 4, 8, _WIN11),
    _device("windows", 1920, 1080, 1.0, 10, 16, _WIN11),
    _device("windows", 1920, 1080, 1.25, 6, 16, _WIN11, alt_heap=True),
    _device("windows", 1920, 1080, 1.5, 8, 16, _WIN11),
    _device("windows", 1920, 1200, 1.0, 6, 8, _WIN11),
    _device("windows", 1920, 1200, 1.25, 8, 16, _WIN11),
    _device("windows", 1920, 1200, 1.75, 8, 16, _WIN11),
    _device("windows", 2048, 1152, 1.5, 6, 16, _WIN11),
    _device("windows", 2160, 1440, 1.5, 8, 16, _WIN11),
    _device("windows", 2560, 1080, 1.0, 8, 16, _WIN11),
    _device("windows", 2560, 1440, 1.0, 8, 16, _WIN11, alt_heap=True),
    _device("windows", 2560, 1440, 1.25, 12, 32, _WIN11),
    _device("windows", 2560, 1600, 1.5, 8, 16, _WIN11),
    _device("windows", 2880, 1620, 1.5, 8, 16, _WIN11),
    _device("windows", 3200, 1800, 2.0, 12, 32, _WIN11),
    _device("windows", 3440, 1440, 1.0, 12, 32, _WIN11),
    _device("windows", 3840, 2160, 1.5, 16, 32, _WIN11),
    # —— Windows 10 存量机 ——
    _device("windows", 1366, 768, 1.0, 2, 4, _WIN10),
    _device("windows", 1440, 900, 1.0, 4, 8, _WIN10),
    _device("windows", 1536, 864, 1.25, 4, 8, _WIN10),
    _device("windows", 1600, 900, 1.0, 4, 8, _WIN10),
    _device("windows", 1920, 1080, 1.0, 6, 8, _WIN10),
    _device("windows", 1920, 1080, 1.25, 8, 16, _WIN10),
    # —— macOS（Chrome 上报逻辑分辨率 + retina 2x）——
    _device("macos", 1280, 800, 2, 8, 8, _MAC_SEQUOIA, '"arm"'),
    _device("macos", 1470, 956, 2, 8, 16, _MAC_SONOMA, '"arm"'),
    _device("macos", 1512, 982, 2, 11, 36, _MAC_SEQUOIA, '"arm"'),
    _device("macos", 1680, 1050, 2, 8, 16, _MAC_SONOMA, '"x86"'),
    _device("macos", 1728, 1117, 2, 10, 24, _MAC_SEQUOIA, '"arm"'),
    _device("macos", 1920, 1200, 2, 10, 32, _MAC_SEQUOIA, '"arm"'),
    _device("macos", 2056, 1329, 2, 12, 32, _MAC_SEQUOIA, '"arm"'),
    _device("macos", 2880, 1800, 2, 12, 36, _MAC_SEQUOIA, '"arm"'),
    _device("macos", 3008, 1692, 2, 10, 16, _MAC_SEQUOIA, '"arm"'),
    _device("macos", 3456, 2234, 2, 12, 36, _MAC_SEQUOIA, '"arm"'),
]

# —— 第二批机型：把常见分辨率/缩放/内存组合继续铺满 ——
BROWSER_PROFILE_POOL += [
    _device("windows", 1280, 720, 1.0, 4, 8, _WIN11),
    _device("windows", 1280, 800, 1.25, 4, 8, _WIN10),
    _device("windows", 1440, 810, 1.25, 6, 16, _WIN11),
    _device("windows", 1440, 900, 1.25, 4, 8, _WIN11),
    _device("windows", 1600, 900, 1.25, 8, 16, _WIN11),
    _device("windows", 1600, 1200, 1.0, 4, 8, _WIN10),
    _device("windows", 1680, 1050, 1.0, 6, 16, _WIN11),
    _device("windows", 1680, 1050, 1.25, 8, 16, _WIN10, alt_heap=True),
    _device("windows", 1920, 1080, 1.75, 8, 16, _WIN11),
    _device("windows", 1920, 1080, 1.0, 16, 32, _WIN11, alt_heap=True),
    _device("windows", 1920, 1080, 1.25, 12, 32, _WIN11),
    _device("windows", 2256, 1504, 1.5, 8, 16, _WIN11),
    _device("windows", 2736, 1824, 2.0, 8, 16, _WIN11),
    _device("windows", 3000, 2000, 2.0, 16, 32, _WIN11),
    _device("windows", 2560, 1440, 1.5, 8, 32, _WIN11),
    _device("windows", 2560, 1440, 2.0, 12, 32, _WIN11, alt_heap=True),
    _device("windows", 2560, 1600, 1.25, 10, 16, _WIN11),
    _device("windows", 2880, 1800, 2.0, 12, 32, _WIN11),
    _device("windows", 3200, 2000, 2.0, 8, 16, _WIN11),
    _device("windows", 3840, 2160, 2.0, 16, 32, _WIN11, alt_heap=True),
    _device("windows", 3840, 2400, 2.0, 12, 32, _WIN11),
    _device("windows", 1920, 1080, 1.0, 2, 4, _WIN10),
    _device("windows", 1440, 900, 1.25, 2, 4, _WIN10),
    _device("macos", 1152, 720, 2, 8, 8, _MAC_SONOMA, '"arm"'),
    _device("macos", 1350, 878, 2, 8, 16, _MAC_SONOMA, '"arm"'),
    _device("macos", 1600, 1000, 2, 8, 16, _MAC_SEQUOIA, '"arm"'),
    _device("macos", 1792, 1120, 2, 10, 24, _MAC_SEQUOIA, '"arm"'),
    _device("macos", 2224, 1390, 2, 12, 36, _MAC_SEQUOIA, '"arm"'),
    _device("macos", 3840, 2160, 2, 12, 36, _MAC_SEQUOIA, '"arm"'),
]

# JS 堆上限与内存档位的对应关系（Chrome 64 位实际取值区间）。
# 取值区间来自实测：2026-09-11 抓包真机 jsHeapSizeLimit=4395630592，
# 只按 deviceMemory 硬套档位会把它判成矛盾，所以同档允许到实测上限。
HEAP_LIMIT_BY_MEMORY = {
    4: (1073741824, 2147483648),
    8: (2147483648, 4395630592),
    16: (4294705152, 4395630592),
    32: (4395630592, 4395630592),
}


# 全局轮转队列：批量注册时保证"连续几个账号不撞同一台机器"。
# 纯 random.choice 在 80 个画像下仍会撞（生日悖论），而设备指纹撞车正是
# 我们要消除的相关性，所以改为打乱整池轮转，用完再洗一轮。
_POOL_LOCK = threading.Lock()
_POOL_QUEUE: list[dict] = []


def next_pool_entry() -> dict:
    """取下一台设备（洗牌轮转，同池不重复直到一轮走完）。"""
    global _POOL_QUEUE
    with _POOL_LOCK:
        if not _POOL_QUEUE:
            _POOL_QUEUE = list(BROWSER_PROFILE_POOL)
            random.shuffle(_POOL_QUEUE)
        return dict(_POOL_QUEUE.pop())


def build_browser_environment(geo: dict | None = None, base_profile: dict | None = None) -> dict:
    """构建完整浏览器环境画像，作为所有指纹字段的单一数据源。

    设备（屏幕/DPR/核心数/内存）来自画像池条目，UA / navigator.platform /
    Client Hints / userAgentData.platform 全部由该条目的系统派生，
    保证不会出现"Windows UA 配 MacBook 分辨率"这类拼接指纹。
    """
    locale = _build_locale_from_geo(geo)
    profile = dict(base_profile or next_pool_entry())
    device_os = str(profile.get("os") or "windows").lower()
    is_mac = device_os in ("macos", "mac", "darwin", "ios")
    platform_name = "macOS" if is_mac else "Windows"
    # navigator.deviceMemory 的取值被 Chrome 上限卡死在 8（0.25/0.5/1/2/4/8），
    # 报 16/32 反而是"物理上不可能"的指纹；真实内存档只用于内部推理与记录。
    profile["navigator_device_memory"] = min(8, int(profile.get("device_memory") or 8) or 8)
    profile.update({
        "locale_profile": locale.get("locale_profile", BROWSER_LOCALE_PROFILE),
        "geo": dict(geo or {}),
        "timezone_iana": locale["timezone_iana"],
        "timezone_offset_minutes": int(locale["timezone_offset_minutes"]),
        "timezone_name": locale["timezone_name"],
        "navigator_language": locale["navigator_language"],
        "navigator_languages": list(locale["navigator_languages"]),
        "accept_language": locale["accept_language"],
        "browser_family": BROWSER_FAMILY,
        "device_os": device_os,
        "browser_os": platform_name,
        "navigator_platform": "MacIntel" if is_mac else "Win32",
        "navigator_vendor": NAVIGATOR_VENDOR,
        "user_agent_data_platform": platform_name,
        "safari_version": SAFARI_VERSION,
        "safari_webkit_version": SAFARI_WEBKIT_VERSION,
        "chrome_major": CHROME_MAJOR,
        "chrome_full_version": CHROME_FULL_VERSION,
        "impersonate": IMPERSONATE,
        "user_agent": user_agent_for_device(device_os),
        "send_client_hints": SEND_CLIENT_HINTS,
        "sec_ch_ua": SEC_CH_UA,
        "sec_ch_ua_platform": f'"{platform_name}"',
        "sec_ch_ua_platform_version": str(
            profile.get("sec_ch_ua_platform_version") or ('"15.3.0"' if is_mac else SEC_CH_UA_PLATFORM_VERSION)
        ),
        "sec_ch_ua_arch": str(profile.get("sec_ch_ua_arch") or ('"arm"' if is_mac else SEC_CH_UA_ARCH)),
        "sec_ch_ua_bitness": SEC_CH_UA_BITNESS,
        "sec_ch_ua_model": SEC_CH_UA_MODEL,
        "sec_ch_ua_full_version_list": SEC_CH_UA_FULL_VERSION_LIST,
        "sec_ch_ua_full_version": SEC_CH_UA_FULL_VERSION,
        "sec_ch_ua_mobile": SEC_CH_UA_MOBILE,
        "navigator_proto_samples": list(NAVIGATOR_PROTO_SAMPLES),
        "document_key_samples": list(DOCUMENT_KEY_SAMPLES),
        "window_key_samples": list(WINDOW_KEY_SAMPLES),
        "script_src_samples": list(SCRIPT_SRC_SAMPLES),
        "window_feature_flags": dict(WINDOW_FEATURE_FLAGS),
        "build_id": __import__("config.openai_protocol", fromlist=["OPENAI_BUILD_ID"]).OPENAI_BUILD_ID,
    })
    return profile


def pick_browser_profile(geo: dict | None = None) -> dict:
    """为一个 BrowserSession 随机挑选稳定桌面画像；HAR 尺寸只是候选之一。"""
    return build_browser_environment(geo)


def validate_browser_profile(profile: dict) -> list[str]:
    """返回画像内部矛盾点，主要用于日志/自测。"""
    issues: list[str] = []
    ua = str(profile.get("user_agent") or "")
    family = str(profile.get("browser_family") or BROWSER_FAMILY)
    if family == "safari":
        if "Version/" not in ua or "Safari/" not in ua or "Chrome/" in ua or "Chromium/" in ua:
            issues.append("Safari UA 不一致")
        if profile.get("send_client_hints"):
            issues.append("Safari 不应发送 Chromium Client Hints")
    elif f"Chrome/{profile.get('chrome_full_version')}" not in ua:
        issues.append("UA 与 chrome_full_version 不一致")
    if profile.get("browser_os") == "macOS":
        if "Macintosh; Intel Mac OS X" not in ua:
            issues.append("macOS 画像但 UA 不是 Macintosh")
        if str(profile.get("navigator_platform") or "") != "MacIntel":
            issues.append("macOS 画像但 navigator.platform 不是 MacIntel")
        if "macOS" not in str(profile.get("sec_ch_ua_platform") or ""):
            issues.append("macOS 画像但 sec-ch-ua-platform 不是 macOS")
    if profile.get("browser_os") == "Windows":
        if "Windows NT 10.0; Win64; x64" not in ua:
            issues.append("Windows 画像但 UA 不是 Windows NT 10.0; Win64; x64")
        if str(profile.get("navigator_platform") or "") != "Win32":
            issues.append("Windows 画像但 navigator.platform 不是 Win32")
        if "Windows" not in str(profile.get("sec_ch_ua_platform") or ""):
            issues.append("Windows 画像但 sec-ch-ua-platform 不是 Windows")
        if str(profile.get("user_agent_data_platform") or "") != "Windows":
            issues.append("Windows 画像但 userAgentData.platform 不是 Windows")
    # TLS 档位（curl_cffi impersonate）必须与画像 Chrome 主版本同代。
    impersonate = str(profile.get("impersonate") or IMPERSONATE)
    if impersonate.startswith("chrome") and not impersonate.endswith(str(profile.get("chrome_major") or "")):
        issues.append(f"TLS impersonate={impersonate} 与 chrome_major={profile.get('chrome_major')} 不同代")
    if not profile.get("navigator_language"):
        issues.append("navigator_language 为空")
    languages = profile.get("navigator_languages") or []
    if profile.get("navigator_language") and profile.get("navigator_language") not in languages:
        issues.append("navigator.language 不在 navigator.languages 中")

    # ---- 设备维度自洽性 ----
    os_name = str(profile.get("browser_os") or BROWSER_OS)
    if os_name == "macOS":
        if str(profile.get("user_agent_data_platform") or "") != "macOS":
            issues.append("macOS 画像但 userAgentData.platform 不是 macOS")
        if str(profile.get("sec_ch_ua_arch") or "") not in ('"arm"', '"x86"'):
            issues.append("macOS 画像但 sec-ch-ua-arch 不是 arm/x86")
        if "macOS" not in str(profile.get("user_agent_data_platform") or ""):
            issues.append("macOS 画像但 userAgentData.platform 不匹配")
    width = int(profile.get("screen_width") or 0)
    height = int(profile.get("screen_height") or 0)
    dpr = float(profile.get("device_pixel_ratio") or 0)
    if not (1024 <= width <= 5120 and 600 <= height <= 2880):
        issues.append(f"屏幕尺寸超出常见范围: {width}x{height}")
    if dpr and not (1.0 <= dpr <= 3.0):
        issues.append(f"devicePixelRatio 异常: {dpr}")
    if os_name == "Windows" and dpr and dpr < 1.0:
        issues.append("Windows 画像 DPR 小于 1")
    heap = int(profile.get("js_heap_size_limit") or 0)
    memory = int(profile.get("device_memory") or 0)
    if heap and heap > 4_600_000_000:
        issues.append(f"jsHeapSizeLimit 超出 Chrome 上限: {heap}")
    if heap and memory:
        low, high = HEAP_LIMIT_BY_MEMORY.get(memory, (1073741824, 4395630592))
        if not (low <= heap <= high):
            issues.append(f"deviceMemory={memory}GB 与 jsHeapSizeLimit={heap} 不同档")
    cores = int(profile.get("hardware_concurrency") or 0)
    if cores and not (2 <= cores <= 32):
        issues.append(f"hardwareConcurrency 异常: {cores}")
    # navigator.deviceMemory 上限是 8，报更大就是物理不可能值。
    nav_memory = profile.get("navigator_device_memory")
    if nav_memory is not None and not (0.25 <= float(nav_memory) <= 8):
        issues.append(f"navigator.deviceMemory 超出 Chrome 上限: {nav_memory}")
    if nav_memory is not None and memory and float(nav_memory) > memory:
        issues.append(f"navigator.deviceMemory={nav_memory} 大于真实内存档 {memory}")
    # requestIdleCallback 是否暴露由画像决定。
    return issues

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'BROWSER_LOCALE_PROFILE': 'str', 'AUTO_BROWSER_LOCALE_FROM_IP': 'bool', 'IP_GEO_TIMEOUT': 'float', 'REJECT_CLOUD_PROXY': 'bool', 'BROWSER_DATA_SAVER_MODE': 'bool', 'BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES': 'list_str_multiline', 'BROWSER_DATA_SAVER_BLOCKED_URL_PATTERNS': 'list_str_multiline', 'BROWSER_TRAFFIC_DETAIL_LOG': 'bool', 'BROWSER_TRAFFIC_DETAIL_MAX_ENTRIES': 'int', 'BROWSER_JS_COVERAGE_LOG': 'bool', 'BROWSER_JS_COVERAGE_MAX_ENTRIES': 'int'})
