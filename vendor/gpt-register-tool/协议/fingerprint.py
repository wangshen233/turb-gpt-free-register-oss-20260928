"""浏览器指纹随机化（多浏览器家族）。

每次注册调用 generate_fingerprint() 生成一套一致的指纹组合：
  - TLS impersonate（curl_cffi 用）
  - User-Agent
  - sec-ch-ua / sec-ch-ua-platform / sec-ch-ua-mobile（仅 Chrome，低熵，浏览器自动发）
  - 屏幕分辨率
  - Accept-Language
  - browser_type 标识（mac_safari / ios_safari / chrome / firefox）
  - fallback_impersonates 同家族回退列表

Client Hints 分两档，生成侧必须区别对待（2026-09-20 真机抓包事实）：

  低熵（默认发，任何站点都发）
      sec-ch-ua / sec-ch-ua-mobile / sec-ch-ua-platform
      → 抓包 68/68 requestHeaders 全带，直接写进指纹 dict，调用方无条件下发。

  高熵（**默认不发**，只有站点用 Accept-CH 响应头索取后才发）
      sec-ch-ua-full-version-list / -arch / -bitness / -model / -platform-version
      → 真机 418 个抓包文件里这 5 个头出现 **0 次**；1027 个请求里仅 1 次
        （某个响应回过 Accept-CH 的端点）。
      生成侧因此**默认把这 5 个字段留成空串**，调用方原有的
      if fp.get("sec_ch_ua_...") 守卫会自动跳过，一个字都不多发。
      真值始终保留在 ua_full_version_list / ua_arch / ua_bitness /
      ua_model / ua_platform_version 名下，站点真的索取时用
      set_high_entropy_hints() 就地打开即可（不必重新生成指纹）。
"""
from __future__ import annotations

import logging
import os
import random
import secrets
from collections.abc import Mapping

from tls_fingerprint import unique_akamai_fingerprint, unique_tls_fingerprint

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# macOS Safari（保留原有）
# ---------------------------------------------------------------------------
_SAFARI_VERSIONS = [
    {
        "impersonate": "safari15_3",
        "safari_ver": "15.3",
        "webkit_ver": "605.1.15",
        "macos_versions": ["10_15_7", "12_0", "12_1"],
    },
    {
        "impersonate": "safari15_5",
        "safari_ver": "15.5",
        "webkit_ver": "605.1.15",
        "macos_versions": ["10_15_7", "12_4", "12_5"],
    },
    {
        "impersonate": "safari17_0",
        "safari_ver": "17.0",
        "webkit_ver": "605.1.15",
        "macos_versions": ["13_6", "14_0", "14_1"],
    },
    {
        "impersonate": "safari18_0",
        "safari_ver": "18.0",
        "webkit_ver": "605.1.15",
        "macos_versions": ["14_4", "14_5", "15_0", "15_1"],
    },
]

_MAC_SCREENS = [
    "1440x900",
    "1512x982",
    "1728x1117",
    "2560x1440",
    "1920x1080",
]

# ---------------------------------------------------------------------------
# iOS Safari
# ---------------------------------------------------------------------------
_IOS_SAFARI_VERSIONS = [
    {
        "impersonate": "safari17_2_ios",
        "safari_ver": "17.2",
        "webkit_ver": "605.1.15",
        "ios_versions": ["17_1_2", "17_2"],
    },
    {
        "impersonate": "safari18_0_ios",
        "safari_ver": "18.0",
        "webkit_ver": "605.1.15",
        "ios_versions": ["18_0", "18_1", "18_1_1"],
    },
]

_IPHONE_SCREENS = [
    "390x844",   # iPhone 13 / 14
    "393x852",   # iPhone 14 Pro / 15
    "428x926",   # iPhone 13 Pro Max / 14 Plus
    "430x932",   # iPhone 14 Pro Max / 15 Plus
]

# ---------------------------------------------------------------------------
# Chrome (Windows)
# ---------------------------------------------------------------------------
# 真机版本池（2026-09-20 抓包事实，captures/revive-20260920-reg）：
#   User-Agent:               Chrome/152.0.0.0        ← 缩减形式：major.0.0.0
#   sec-ch-ua:                "Chromium";v="152", ... ← 只有 major
#   sec-ch-ua-full-version-list（Accept-CH 索取时才发）:
#                             "Chromium";v="152.0.7977.83", ... ← 真实完整构建号
# 这三个值的语义**互不相同**，必须分开存，不能像旧版那样拿一个 full_ver
# 同时拼 UA 和 full-version-list —— 旧版 full_ver 其实是 "136.0.0.0"，拼出来
# 就是自然界不存在的 "Google Chrome";v="136.0.0.0"。
#
# 实测到的真实构建号：152.0.7977.65 / 152.0.7977.83。
#
# impersonate 是 curl_cffi 的 TLS/HTTP2 画像名。当前锁定的 curl_cffi 0.16.0
# 最高只到 chrome146，**没有 chrome152**；而 TLS 画像本身不带版本号，服务端
# 读不出 "146"，所以用最接近的 chrome146/chrome145 顶替是安全的。
# curl_cffi 一旦放出 chrome152，把下面的 impersonate 换成 chrome152 即可，
# 其余字段（UA / sec-ch-ua / full-version-list）不受影响。
_CHROME_TLS_FALLBACK_NOTE = "curl_cffi 0.16.0 最高 chrome146（无 chrome152）"

# ⚠️ 声称的 Chrome 版本 = **真机版本 152**，不要降到 curl_cffi 的 TLS 版本去"对齐"。
#
# 2026-09-22 实测教训：曾经把这里改成 146（想消掉「UA 说 152、TLS 是 chrome146」
# 的矛盾），结果**注册出来的号全部拿不到 Plus 试用**（check_coupon 返回
# not_eligible），而 Roxy 真机（Chrome 152）注册的号返回 eligible。
# 同一个出口 IP、同一个请求路径，唯一差别就是注册时声称的版本。
#   Roxy 真机    Chrome/152.0.0.0   -> check_coupon eligible   VN:0元
#   协议机 152   Chrome/152.0.0.0   -> 曾拿到 VN:0元（见 exports/revive/README.md）
#   协议机 146   Chrome/146.0.0.0   -> not_eligible            VN:no
# 结论：落后 6 个大版本的 Chrome 本身就是可疑信号，比 TLS/UA 版本不齐更致命。
# Roxy 的 coreVersion 是 152，所以 152 才是"看起来像真机"的值。
_CHROME_VERSIONS = [
    {
        "impersonate": "chrome146",
        "ver": "152",                  # sec-ch-ua 用：只有 major
        "ua_ver": "152.0.0.0",         # UA 用：major.0.0.0 缩减形式
        "full_ver": "152.0.7977.83",   # full-version-list 用：真实构建号
        "platform_version": "15.0.0",  # Win11（对齐 Roxy WINDOWS_PROFILES 真值）
    },
    {
        "impersonate": "chrome145",
        "ver": "152",
        "ua_ver": "152.0.0.0",
        "full_ver": "152.0.7977.65",
        "platform_version": "15.0.0",
    },
]

# greasy brand 的真值。真机实测（68/68 requestHeaders 同值）：
#   "Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"
# 名字带问号（Not?A_Brand，不是 Not.A/Brand / Not/A)Brand），版本是 24 不是 99，
# 且固定排在**第二位**（Chromium → greasy → Google Chrome）。
_GREASY_BRAND_NAME = "Not?A_Brand"
_GREASY_BRAND_VERSION = "24"

# 高熵 client hints 真值（只有 Accept-CH 索取时才下发）
_CHROME_UA_ARCH = "x86"
_CHROME_UA_BITNESS = "64"
# 桌面 Chrome 的 model 就是**空串的引号形式**：被 Accept-CH 索取时真机发的是
#   sec-ch-ua-model: ""
# 即 header 值本身是两个引号字符（不是"不发这个头"）。所以这里是 '""' 而不是 ''——
# 调用方的 if fp.get("sec_ch_ua_model") 守卫靠真值判断，"不发" 用 '' 表示。
_CHROME_UA_MODEL = '""'


def _format_brand_list(chrome: Mapping[str, object], *, full: bool) -> str:
    """按真机排列拼 Chromium 的 brand 列表。

    顺序固定为 Chromium / <greasy> / Google Chrome（greasy 在第二位）；
    高熵形态（full=True）用真实构建号 + greasy 的 24.0.0.0 形态。

    真值样例：
        full=False → "Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"
        full=True  → "Chromium";v="152.0.7977.83", "Not?A_Brand";v="24.0.0.0",
                     "Google Chrome";v="152.0.7977.83"
    """
    if full:
        ver = str(chrome["full_ver"])
        greasy_ver = _GREASY_BRAND_VERSION + ".0.0.0"
    else:
        ver = str(chrome["ver"])
        greasy_ver = _GREASY_BRAND_VERSION
    return (
        f'"Chromium";v="{ver}", '
        f'"{_GREASY_BRAND_NAME}";v="{greasy_ver}", '
        f'"Google Chrome";v="{ver}"'
    )


def set_high_entropy_hints(fp: dict, enabled: bool = True) -> dict:
    """就地开关高熵 client hints，返回同一个 dict（便于链式调用）。

    真实 Chrome 只对**用 Accept-CH 索取过**的站点发这 5 个头；对没索取的站点
    一个都不发。所以生成侧默认全空，调用方在收到带 Accept-CH 的响应后调
    set_high_entropy_hints(fp, True)，之后调用方原有的
    if fp.get("sec_ch_ua_full_version_list") 守卫会自动把它们带出去。

    关掉（enabled=False）只是把值清回空串，真值仍留在 ua_* 名下。
    非 Chrome 家族永远保持关闭。
    """
    on = bool(enabled) and str(fp.get("browser_type", "")) == "chrome"
    fp["client_hints_high_entropy"] = on
    if on:
        fp["sec_ch_ua_full_version_list"] = str(fp.get("ua_full_version_list") or "")
        fp["sec_ch_ua_arch"] = str(fp.get("ua_arch") or "")
        fp["sec_ch_ua_bitness"] = str(fp.get("ua_bitness") or "")
        # model 的真值是 '""'（两个引号字符）：真机被索取时发的是
        # sec-ch-ua-model: ""，是「值为空串的头」，不是「不发这个头」。
        # 关闭时置成 '' 才能让调用方的 if fp.get(...) 守卫跳过它。
        fp["sec_ch_ua_model"] = str(fp.get("ua_model") or '""')
        fp["sec_ch_ua_platform_version"] = str(fp.get("ua_platform_version") or "")
    else:
        fp["sec_ch_ua_full_version_list"] = ""
        fp["sec_ch_ua_arch"] = ""
        fp["sec_ch_ua_bitness"] = ""
        fp["sec_ch_ua_model"] = ""
        fp["sec_ch_ua_platform_version"] = ""
    return fp


# Windows 真实分辨率分布（5 → 10，补熵；见 exports/revive/F3-fingerprint-fix.md 策略建议）
# 对齐 Roxy fingerprint.mjs 的 SCREENS（8 档，1920x1080 三倍权重）：
# 砍掉 3840x2160 / 2560x1600 / 1680x1050 / 1280x1024 —— 那些在真实
# Windows 桌面里占比极低，凑熵反而把自己推成离群样本。
_WIN_SCREENS = [
    "1920x1080",   # 绝对主流（3 倍权重）
    "1920x1080",
    "1920x1080",
    "1536x864",
    "1600x900",
    "2560x1440",
    "1366x768",
    "1440x900",
]

# ---------------------------------------------------------------------------
# Firefox (Windows)
# ---------------------------------------------------------------------------
_FIREFOX_VERSIONS = [
    {"impersonate": "firefox133", "ver": "133.0"},
    {"impersonate": "firefox144", "ver": "144.0"},
]

# ---------------------------------------------------------------------------
# 国家 → 时区/语言画像（IP 地理联动优化）
# ---------------------------------------------------------------------------
_COUNTRY_PROFILES = {
    # 亚洲
    "JP": {
        "timezones": [("Asia/Tokyo", 1.0)],
        "languages": ["ja-JP", "ja", "en-US", "en", "zh-CN"],
    },
    "CN": {
        "timezones": [("Asia/Shanghai", 1.0)],
        "languages": ["zh-CN", "zh", "en-US", "en"],
    },
    "HK": {
        "timezones": [("Asia/Hong_Kong", 1.0)],
        "languages": ["zh-HK", "zh-CN", "zh", "en-US", "en"],
    },
    "TW": {
        "timezones": [("Asia/Taipei", 1.0)],
        "languages": ["zh-TW", "zh", "en-US", "en", "ja"],
    },
    "KR": {
        "timezones": [("Asia/Seoul", 1.0)],
        "languages": ["ko-KR", "ko", "en-US", "en", "ja"],
    },
    "SG": {
        "timezones": [("Asia/Singapore", 1.0)],
        "languages": ["zh-CN", "zh", "en-US", "en", "ms-MY", "ms"],
    },
    "MY": {
        "timezones": [("Asia/Kuala_Lumpur", 1.0)],
        "languages": ["ms-MY", "ms", "zh-CN", "zh", "en-US", "en"],
    },
    "TH": {
        "timezones": [("Asia/Bangkok", 1.0)],
        "languages": ["th-TH", "th", "en-US", "en"],
    },
    "VN": {
        "timezones": [("Asia/Ho_Chi_Minh", 1.0)],
        # 4 → 7：主语言仍固定 vi-VN，副语言从「3 选 2~3」变「6 选 2~4」，
        # Accept-Language 组合 9 → 510（原池只有 9 种，批量必碰撞）
        "languages": ["vi-VN", "vi", "en-US", "en", "en-GB", "ja-JP", "ko-KR"],
    },
    "IN": {
        "timezones": [("Asia/Kolkata", 1.0)],
        "languages": ["en-IN", "en-US", "en", "hi-IN", "hi"],
    },
    "ID": {
        "timezones": [("Asia/Jakarta", 1.0)],
        "languages": ["id-ID", "id", "en-US", "en"],
    },
    "PH": {
        "timezones": [("Asia/Manila", 1.0)],
        "languages": ["en-US", "en", "tl-PH", "tl"],
    },
    "PK": {
        "timezones": [("Asia/Karachi", 1.0)],
        "languages": ["en-US", "en", "ur-PK", "ur"],
    },
    "BD": {
        "timezones": [("Asia/Dhaka", 1.0)],
        "languages": ["bn-BD", "bn", "en-US", "en"],
    },
    "IL": {
        "timezones": [("Asia/Jerusalem", 1.0)],
        "languages": ["he-IL", "he", "en-US", "en", "ar"],
    },
    "TR": {
        "timezones": [("Europe/Istanbul", 1.0)],
        "languages": ["tr-TR", "tr", "en-US", "en"],
    },
    "SA": {
        "timezones": [("Asia/Riyadh", 1.0)],
        "languages": ["ar-SA", "ar", "en-US", "en"],
    },
    "AE": {
        "timezones": [("Asia/Dubai", 1.0)],
        "languages": ["ar-AE", "ar", "en-US", "en"],
    },
    # 北美
    "US": {
        "timezones": [
            ("America/New_York", 0.4),      # 东部（数据中心多）
            ("America/Los_Angeles", 0.3),   # 西部
            ("America/Chicago", 0.2),       # 中部
            ("America/Denver", 0.1),        # 山地
        ],
        "languages": ["en-US", "en", "es-US", "es", "zh-CN"],
    },
    "CA": {
        "timezones": [
            ("America/Toronto", 0.6),       # 东部（安大略）
            ("America/Vancouver", 0.3),     # 西部（BC）
            ("America/Edmonton", 0.1),      # 山地（阿尔伯塔）
        ],
        "languages": ["en-CA", "en-US", "en", "fr-CA", "fr"],
    },
    "MX": {
        "timezones": [("America/Mexico_City", 1.0)],
        "languages": ["es-MX", "es", "en-US", "en"],
    },
    # 南美
    "BR": {
        "timezones": [
            ("America/Sao_Paulo", 0.7),
            ("America/Manaus", 0.2),
            ("America/Fortaleza", 0.1),
        ],
        "languages": ["pt-BR", "pt", "en-US", "en", "es"],
    },
    "AR": {
        "timezones": [("America/Argentina/Buenos_Aires", 1.0)],
        "languages": ["es-AR", "es", "en-US", "en"],
    },
    "CL": {
        "timezones": [("America/Santiago", 1.0)],
        "languages": ["es-CL", "es", "en-US", "en"],
    },
    "CO": {
        "timezones": [("America/Bogota", 1.0)],
        "languages": ["es-CO", "es", "en-US", "en"],
    },
    # 欧洲
    "GB": {
        "timezones": [("Europe/London", 1.0)],
        "languages": ["en-GB", "en-US", "en", "fr", "de"],
    },
    "DE": {
        "timezones": [("Europe/Berlin", 1.0)],
        "languages": ["de-DE", "de", "en-US", "en", "fr"],
    },
    "FR": {
        "timezones": [("Europe/Paris", 1.0)],
        "languages": ["fr-FR", "fr", "en-US", "en", "de"],
    },
    "IT": {
        "timezones": [("Europe/Rome", 1.0)],
        "languages": ["it-IT", "it", "en-US", "en", "fr"],
    },
    "ES": {
        "timezones": [("Europe/Madrid", 1.0)],
        "languages": ["es-ES", "es", "en-US", "en", "fr"],
    },
    "NL": {
        "timezones": [("Europe/Amsterdam", 1.0)],
        "languages": ["nl-NL", "nl", "en-US", "en", "de"],
    },
    "BE": {
        "timezones": [("Europe/Brussels", 1.0)],
        "languages": ["nl-BE", "fr-BE", "nl", "fr", "en-US", "en"],
    },
    "CH": {
        "timezones": [("Europe/Zurich", 1.0)],
        "languages": ["de-CH", "fr-CH", "de", "fr", "it", "en-US", "en"],
    },
    "SE": {
        "timezones": [("Europe/Stockholm", 1.0)],
        "languages": ["sv-SE", "sv", "en-US", "en"],
    },
    "NO": {
        "timezones": [("Europe/Oslo", 1.0)],
        "languages": ["nb-NO", "nb", "en-US", "en"],
    },
    "DK": {
        "timezones": [("Europe/Copenhagen", 1.0)],
        "languages": ["da-DK", "da", "en-US", "en"],
    },
    "FI": {
        "timezones": [("Europe/Helsinki", 1.0)],
        "languages": ["fi-FI", "fi", "sv", "en-US", "en"],
    },
    "PL": {
        "timezones": [("Europe/Warsaw", 1.0)],
        "languages": ["pl-PL", "pl", "en-US", "en"],
    },
    "RU": {
        "timezones": [
            ("Europe/Moscow", 0.7),         # 莫斯科（MSK，主要数据中心）
            ("Asia/Yekaterinburg", 0.15),   # 叶卡捷琳堡（+5）
            ("Asia/Novosibirsk", 0.15),     # 新西伯利亚（+7）
        ],
        "languages": ["ru-RU", "ru", "en-US", "en"],
    },
    "UA": {
        "timezones": [("Europe/Kiev", 1.0)],
        "languages": ["uk-UA", "uk", "ru", "en-US", "en"],
    },
    "CZ": {
        "timezones": [("Europe/Prague", 1.0)],
        "languages": ["cs-CZ", "cs", "en-US", "en", "de"],
    },
    "AT": {
        "timezones": [("Europe/Vienna", 1.0)],
        "languages": ["de-AT", "de", "en-US", "en"],
    },
    "GR": {
        "timezones": [("Europe/Athens", 1.0)],
        "languages": ["el-GR", "el", "en-US", "en"],
    },
    "PT": {
        "timezones": [("Europe/Lisbon", 1.0)],
        "languages": ["pt-PT", "pt", "en-US", "en", "es"],
    },
    # 大洋洲
    "AU": {
        "timezones": [
            ("Australia/Sydney", 0.5),      # 悉尼（NSW，数据中心多）
            ("Australia/Melbourne", 0.3),   # 墨尔本（VIC）
            ("Australia/Brisbane", 0.2),    # 布里斯班（QLD）
        ],
        "languages": ["en-AU", "en-US", "en", "zh-CN", "zh"],
    },
    "NZ": {
        "timezones": [("Pacific/Auckland", 1.0)],
        "languages": ["en-NZ", "en-US", "en"],
    },
    # 非洲
    "ZA": {
        "timezones": [("Africa/Johannesburg", 1.0)],
        "languages": ["en-ZA", "en-US", "en", "af"],
    },
    "EG": {
        "timezones": [("Africa/Cairo", 1.0)],
        "languages": ["ar-EG", "ar", "en-US", "en"],
    },
    "NG": {
        "timezones": [("Africa/Lagos", 1.0)],
        "languages": ["en-NG", "en-US", "en"],
    },
    "KE": {
        "timezones": [("Africa/Nairobi", 1.0)],
        "languages": ["sw-KE", "sw", "en-US", "en"],
    },
}

# 兜底策略（未知国家）
_DEFAULT_COUNTRY_PROFILE = {
    "timezones": [("UTC", 1.0)],
    "languages": ["en-US", "en"],
}


def country_context(country_code: str = "") -> tuple[str, str]:
    """Return deterministic fallback (timezone, locale) for a country code.

    Per-task fingerprints still choose weighted values from the same profile. This
    helper is for callers that need a stable preview without creating a profile.
    """
    code = (country_code or "").strip().upper()
    profile = _COUNTRY_PROFILES.get(code, _DEFAULT_COUNTRY_PROFILE)
    return profile["timezones"][0][0], profile["languages"][0]


def supported_country_codes() -> tuple[str, ...]:
    """Return country codes available for explicit task-profile selection."""
    return tuple(sorted(_COUNTRY_PROFILES))


def screen_dimensions(screen: str) -> tuple[int, int]:
    """Parse a ``WIDTHxHEIGHT`` screen value and reject invalid dimensions."""
    value = str(screen or "").strip().lower()
    try:
        width_text, height_text = value.split("x", 1)
        width, height = int(width_text), int(height_text)
    except (TypeError, ValueError):
        raise ValueError(f"invalid screen dimensions: {screen!r}") from None
    if width <= 0 or height <= 0:
        raise ValueError(f"screen dimensions must be positive: {screen!r}")
    return width, height


def validate_fingerprint(fp: Mapping[str, object]) -> None:
    """Validate the cross-layer invariants required by browser startup.

    A generated profile is intentionally strict here. Silently repairing one field
    at the launcher boundary would make the HTTP/session profile diverge from the
    browser profile again.
    """
    required = (
        "fingerprint_id",
        "browser_type",
        "browser_family",
        "country_code",
        "user_agent",
        "screen",
        "viewport",
        "screen_width",
        "screen_height",
        "locale",
        "lang",
        "lang_full",
        "timezone",
        "navigator_platform",
        "navigator_vendor",
        "hardware_concurrency",
        "max_touch_points",
        "device_pixel_ratio",
        "is_mobile",
        "has_touch",
    )
    missing = [key for key in required if key not in fp]
    if missing:
        raise ValueError(f"fingerprint is missing fields: {', '.join(missing)}")

    browser_type = str(fp["browser_type"])
    family_by_type = {
        "mac_safari": "safari",
        "ios_safari": "safari",
        "chrome": "chrome",
        "firefox": "firefox",
    }
    expected_family = family_by_type.get(browser_type)
    if expected_family is None:
        raise ValueError(f"unsupported browser_type: {browser_type!r}")
    if fp["browser_family"] != expected_family:
        raise ValueError(
            f"browser family mismatch: {browser_type!r} -> {fp['browser_family']!r}"
        )

    screen_width, screen_height = screen_dimensions(str(fp["screen"]))
    viewport = fp["viewport"]
    if not isinstance(viewport, Mapping):
        raise ValueError("fingerprint viewport must be a mapping")
    try:
        viewport_width = int(viewport["width"])
        viewport_height = int(viewport["height"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("fingerprint viewport must contain integer width/height") from None
    if (screen_width, screen_height) != (viewport_width, viewport_height):
        raise ValueError(
            "screen and viewport must match exactly: "
            f"screen={screen_width}x{screen_height}, "
            f"viewport={viewport_width}x{viewport_height}"
        )
    try:
        if int(fp["screen_width"]) != screen_width or int(fp["screen_height"]) != screen_height:
            raise ValueError("fingerprint screen_width/screen_height do not match screen")
    except (TypeError, ValueError):
        raise ValueError("fingerprint screen_width/screen_height must match screen") from None
    if str(fp["locale"]).strip() != str(fp["lang"]).strip():
        raise ValueError("fingerprint locale and lang must match")
    if not str(fp["lang"]).strip() or not str(fp["lang_full"]).strip():
        raise ValueError("fingerprint language fields must not be empty")
    if not str(fp["lang_full"]).strip().startswith(str(fp["lang"]).strip()):
        raise ValueError("fingerprint Accept-Language must start with lang")
    if not str(fp["timezone"]).strip():
        raise ValueError("fingerprint timezone must not be empty")
    if bool(fp["has_touch"]) != (int(fp["max_touch_points"]) > 0):
        raise ValueError("fingerprint has_touch and max_touch_points disagree")
    if bool(fp["is_mobile"]) != (browser_type == "ios_safari"):
        raise ValueError("fingerprint is_mobile does not match browser_type")
    if browser_type == "chrome":
        if "Chrome/" not in str(fp["user_agent"]) or fp["navigator_platform"] != "Win32":
            raise ValueError("Chrome fingerprint has an incompatible UA or platform")
        # sec-ch-ua 的三段顺序/名字/版本应与真机逐字一致：
        #   "Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"
        # 真值见 captures/revive-20260920-reg（68/68 requestHeaders 同值）。
        #
        # ⚠️ 这里**只警告不抛异常**。原因：环境指纹会被冻结进 DB 并在「恢复运行」
        # 时回灌（webui/auto_loop.py:390 get_run_environment → registrar.py:907
        # frozen_options["fingerprint"] → register_outlook.py:112 →
        # auth_flow.py:118 validate_fingerprint）。旧版本按**旧规则**生成的指纹
        # 当时是"合法"的，replay 它顶多多发几个高熵头，不是灾难；但硬抛
        # ValueError 会让"恢复运行"这条路径直接崩，那是回归。
        # 新生成的指纹由 generate_fingerprint 内部保证正确，不依赖这条检查兜底。
        sec_ch_ua = str(fp.get("sec_ch_ua") or "")
        if sec_ch_ua:
            ua = str(fp["user_agent"])
            ua_major = ua.split("Chrome/", 1)[1].split(".", 1)[0] if "Chrome/" in ua else ""
            if not ua_major:
                logger.warning(
                    "Chrome 指纹的 UA 里找不到 Chrome/<version>，跳过 sec-ch-ua 一致性检查: %r",
                    ua,
                )
            else:
                expected = _format_brand_list({"ver": ua_major}, full=False)
                if sec_ch_ua != expected:
                    logger.warning(
                        "Chrome sec-ch-ua 与真机形态不一致（应为 "
                        "'Chromium' / 'Not?A_Brand' / 'Google Chrome' 顺序 + UA major 版本）: "
                        "got %r, expected %r —— 历史环境指纹按旧规则生成时属正常，"
                        "新生成的指纹不应出现",
                        sec_ch_ua,
                        expected,
                    )
        # 高熵开关与 full-version-list 应同生同灭（同样只警告）
        if fp.get("client_hints_high_entropy") and not str(
            fp.get("sec_ch_ua_full_version_list") or ""
        ):
            logger.warning(
                "client_hints_high_entropy 已打开但 sec_ch_ua_full_version_list 为空"
            )
    elif browser_type == "firefox":
        if "Firefox/" not in str(fp["user_agent"]) or fp["navigator_platform"] != "Win32":
            raise ValueError("Firefox fingerprint has an incompatible UA or platform")
    elif browser_type == "mac_safari":
        if "Safari/" not in str(fp["user_agent"]) or fp["navigator_platform"] != "MacIntel":
            raise ValueError("macOS Safari fingerprint has an incompatible UA or platform")
    elif browser_type == "ios_safari":
        if "iPhone" not in str(fp["user_agent"]) or fp["navigator_platform"] != "iPhone":
            raise ValueError("iOS Safari fingerprint has an incompatible UA or platform")

    try:
        if float(fp["device_pixel_ratio"]) <= 0:
            raise ValueError("fingerprint device_pixel_ratio must be positive")
    except (TypeError, ValueError):
        raise ValueError("fingerprint device_pixel_ratio must be positive") from None

    languages = fp.get("languages")
    if languages is not None:
        if not isinstance(languages, (list, tuple)) or not languages:
            raise ValueError("fingerprint languages must be a non-empty list")
        if str(languages[0]).strip() != str(fp["lang"]).strip():
            raise ValueError("fingerprint languages must start with lang")


def browser_family_for_type(browser_type: str) -> str:
    """Map a generated browser type to the actual Playwright engine family."""
    try:
        return {
            "mac_safari": "safari",
            "ios_safari": "safari",
            "chrome": "chrome",
            "firefox": "firefox",
        }[browser_type]
    except KeyError:
        raise ValueError(f"unsupported browser_type: {browser_type!r}") from None


def browser_types_for_family(browser_family: str) -> tuple[str, ...]:
    """Return concrete profile types for a UI-level browser family policy."""
    family = (browser_family or "auto").strip().lower()
    if family in ("auto", "random"):
        return tuple(_BROWSER_TYPES)
    if family == "safari":
        return ("mac_safari", "ios_safari")
    if family in ("chrome", "firefox"):
        return (family,)
    if family in _GENERATORS:
        return (family,)
    raise ValueError(f"unsupported browser_family: {browser_family!r}")


def _browser_type_for_policy(
    browser_family: str,
    r: random.Random,
    *,
    prefer_firefox: bool = False,
) -> str:
    family = (browser_family or "auto").strip().lower()
    if prefer_firefox and family in ("", "auto", "random"):
        return "firefox"
    if family in ("", "auto", "random"):
        # ⚠️ auto 必须走**加权**抽取。旧实现这里是无条件 r.choice（等概率），
        # _BROWSER_WEIGHTS / _WEIGHTS 算出来但从没被用过 —— 改权重等于没改。
        return r.choices(_BROWSER_TYPES, weights=_WEIGHTS, k=1)[0]
    choices = browser_types_for_family(family)
    return r.choice(list(choices))

# ---------------------------------------------------------------------------
# 共享（旧的固定语言列表，保留兼容性）
# ---------------------------------------------------------------------------
_LANGUAGES = [
    ("en-US", "en-US,en;q=0.9"),
    ("en-US", "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7"),
    ("en-GB", "en-GB,en;q=0.9,en-US;q=0.8"),
    ("en-US", "en-US,en;q=0.9,ja;q=0.8"),
]

# 方案 A（保守）。依据：2026-09-20 真机抓包 68/68 全是 Chrome，但样本来自
# **同一个浏览器实例**，100% 是采样偏差而不是车队真实分布；100/0 会让整批
# 账号家族完全一致，反而是更硬的群体特征。Chrome 又是唯一验证过能注册成功的
# 家族，所以权重压倒性倾斜。详见 exports/revive/F3-fingerprint-fix.md 策略建议。
_BROWSER_WEIGHTS = [
    ("chrome",     90),
    ("firefox",     5),
    ("mac_safari",  4),
    ("ios_safari",  1),
]

_BROWSER_TYPES = [t for t, _ in _BROWSER_WEIGHTS]
_WEIGHTS = [w for _, w in _BROWSER_WEIGHTS]


# ---------------------------------------------------------------------------
# 硬件 / navigator 一致性画像（按浏览器家族绑定）
#
# 关键点：navigator.platform / vendor / deviceMemory 在不同引擎行为不同——
#   - vendor:       Safari/iOS="Apple Computer, Inc."，Chrome="Google Inc."，
#                   Firefox=""（空串，不是 undefined）
#   - deviceMemory: 仅 Chromium 暴露且 spec 封顶 8；Safari/Firefox 为 None(undefined)
#   - platform:     mac_safari=MacIntel, ios_safari=iPhone, chrome/firefox=Win32
#   - maxTouchPoints: 只有 iOS 触摸屏=5，其余=0
#   - devicePixelRatio: Retina=2.0/3.0，Windows 常见 1.0/1.25/1.5
# 这些值在一次注册内必须**固定**（真实浏览器同会话不会变），故在
# generate_fingerprint() 里用同一个 RNG 一次性定死，写进指纹 dict。
# ---------------------------------------------------------------------------
_HARDWARE_PROFILES = {
    "mac_safari": {
        "navigator_platform": "MacIntel",
        "navigator_vendor": "Apple Computer, Inc.",
        "hardware_concurrency": [8, 10, 12, 16],
        "device_memory": [None],          # Safari 不暴露 deviceMemory
        "max_touch_points": [0],
        "device_pixel_ratio": [2.0],      # Retina 必定 2.0
    },
    "ios_safari": {
        "navigator_platform": "iPhone",
        "navigator_vendor": "Apple Computer, Inc.",
        "hardware_concurrency": [4, 6],   # A15/A16/A17
        "device_memory": [None],          # iOS Safari 不暴露
        "max_touch_points": [5],          # 触摸屏
        "device_pixel_ratio": [2.0, 3.0],
    },
    "chrome": {
        "navigator_platform": "Win32",
        "navigator_vendor": "Google Inc.",
        # 对齐 Roxy fingerprint.mjs 的 navigator：
        #   hardwareConcurrency: pick([4,6,8,8,12,12,16,16,24])
        # 去掉 20 / 32 —— Roxy 注释原话：「真实浏览器永远不会报 16/32，
        # 那是能被指纹库直接抓到的异常值」。24 是上限。
        "hardware_concurrency": [4, 6, 8, 8, 12, 12, 16, 16, 24],
        # deviceMemory: pick([4,4,8,8,8,8,8]) —— spec 封顶 8
        "device_memory": [4, 4, 8, 8, 8, 8, 8],
        "max_touch_points": [0],
        "device_pixel_ratio": [1.0, 1.25, 1.5, 2.0],
    },
    "firefox": {
        "navigator_platform": "Win32",
        "navigator_vendor": "",           # Firefox navigator.vendor 为空串
        "hardware_concurrency": [4, 6, 8, 12, 16],
        "device_memory": [None],          # Firefox 不暴露 deviceMemory
        "max_touch_points": [0],
        "device_pixel_ratio": [1.0, 1.5],
    },
}


def _apply_hardware(fp: dict, r: random.Random) -> None:
    """按 browser_type 从画像池抽一套一致的硬件参数写进指纹 dict。"""
    prof = _HARDWARE_PROFILES.get(fp["browser_type"], _HARDWARE_PROFILES["chrome"])
    fp["navigator_platform"] = prof["navigator_platform"]
    fp["navigator_vendor"] = prof["navigator_vendor"]
    fp["hardware_concurrency"] = r.choice(prof["hardware_concurrency"])
    fp["device_memory"] = r.choice(prof["device_memory"])
    fp["max_touch_points"] = r.choice(prof["max_touch_points"])
    fp["device_pixel_ratio"] = r.choice(prof["device_pixel_ratio"])


# ---------------------------------------------------------------------------
# 指纹生成
# ---------------------------------------------------------------------------

def _gen_mac_safari(r: random.Random) -> dict:
    safari = r.choice(_SAFARI_VERSIONS)
    macos_ver = r.choice(safari["macos_versions"])
    others = [s["impersonate"] for s in _SAFARI_VERSIONS if s["impersonate"] != safari["impersonate"]]
    return {
        "browser_type": "mac_safari",
        "impersonate": safari["impersonate"],
        "fallback_impersonates": [safari["impersonate"]] + r.sample(others, min(2, len(others))),
        "user_agent": (
            f"Mozilla/5.0 (Macintosh; Intel Mac OS X {macos_ver}) "
            f"AppleWebKit/{safari['webkit_ver']} (KHTML, like Gecko) "
            f"Version/{safari['safari_ver']} Safari/{safari['webkit_ver']}"
        ),
        "sec_ch_ua": "",
        "sec_ch_ua_platform": "",
        "sec_ch_ua_mobile": "",
        "screen": r.choice(_MAC_SCREENS),
    }


def _gen_ios_safari(r: random.Random) -> dict:
    safari = r.choice(_IOS_SAFARI_VERSIONS)
    ios_ver = r.choice(safari["ios_versions"])
    others = [s["impersonate"] for s in _IOS_SAFARI_VERSIONS if s["impersonate"] != safari["impersonate"]]
    fallbacks = [safari["impersonate"]] + others
    return {
        "browser_type": "ios_safari",
        "impersonate": safari["impersonate"],
        "fallback_impersonates": fallbacks,
        "user_agent": (
            f"Mozilla/5.0 (iPhone; CPU iPhone OS {ios_ver} like Mac OS X) "
            f"AppleWebKit/{safari['webkit_ver']} (KHTML, like Gecko) "
            f"Version/{safari['safari_ver']} Mobile/15E148 Safari/604.1"
        ),
        "sec_ch_ua": "",
        "sec_ch_ua_platform": "",
        "sec_ch_ua_mobile": "",
        "screen": r.choice(_IPHONE_SCREENS),
    }


def _gen_chrome(r: random.Random) -> dict:
    chrome = r.choice(_CHROME_VERSIONS)
    others = [c["impersonate"] for c in _CHROME_VERSIONS if c["impersonate"] != chrome["impersonate"]]
    # 低熵：Chromium / Not?A_Brand / Google Chrome（greasy 在第二位）
    sec_ch_ua = _format_brand_list(chrome, full=False)
    # 高熵：同一顺序，但用真实构建号（"152.0.7977.83"）和 greasy 的 24.0.0.0
    ua_full_version_list = _format_brand_list(chrome, full=True)

    return {
        "browser_type": "chrome",
        "impersonate": chrome["impersonate"],
        "fallback_impersonates": [chrome["impersonate"]] + r.sample(others, min(2, len(others))),
        "user_agent": (
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{chrome['ua_ver']} Safari/537.36"
        ),
        # ── 低熵 client hints：真机对任何站点都发 ──
        "sec_ch_ua": sec_ch_ua,
        "sec_ch_ua_platform": '"Windows"',
        "sec_ch_ua_mobile": "?0",
        # ── 高熵 client hints：默认**不发**（见模块顶部说明）──
        # 这 5 个键默认空串，调用方原有的 if fp.get(...) 守卫会自动跳过。
        # 站点回过 Accept-CH 时用 set_high_entropy_hints(fp, True) 打开。
        "sec_ch_ua_full_version_list": "",
        "sec_ch_ua_arch": "",
        "sec_ch_ua_bitness": "",
        "sec_ch_ua_model": "",
        "sec_ch_ua_platform_version": "",
        "client_hints_high_entropy": False,
        # ── 高熵真值：始终保留，供 Accept-CH 索取 / Sentinel JS 取用 ──
        "ua_full_version_list": ua_full_version_list,
        "ua_arch": _CHROME_UA_ARCH,
        "ua_bitness": _CHROME_UA_BITNESS,
        "ua_model": _CHROME_UA_MODEL,
        "ua_platform_version": str(chrome["platform_version"]),
        "screen": r.choice(_WIN_SCREENS),
    }


def _gen_firefox(r: random.Random) -> dict:
    ff = r.choice(_FIREFOX_VERSIONS)
    others = [f["impersonate"] for f in _FIREFOX_VERSIONS if f["impersonate"] != ff["impersonate"]]
    fallbacks = [ff["impersonate"]] + others
    return {
        "browser_type": "firefox",
        "impersonate": ff["impersonate"],
        "fallback_impersonates": fallbacks,
        "user_agent": (
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{ff['ver']}) "
            f"Gecko/20100101 Firefox/{ff['ver']}"
        ),
        "sec_ch_ua": "",
        "sec_ch_ua_platform": "",
        "sec_ch_ua_mobile": "",
        "screen": r.choice(_WIN_SCREENS),
    }


_GENERATORS = {
    "mac_safari": _gen_mac_safari,
    "ios_safari": _gen_ios_safari,
    "chrome": _gen_chrome,
    "firefox": _gen_firefox,
}


def generate_fingerprint(
    rng: random.Random | None = None,
    country_code: str = "",
    browser_type: str | None = None,
    browser_family: str = "auto",
    *,
    prefer_firefox: bool = False,
    include_high_entropy_hints: bool = False,
) -> dict:
    """生成一套一致的浏览器指纹。

    参数:
        rng: 随机数生成器（传入可保证会话内一致性）
        country_code: IP 地理国家码（如 JP/US/DE），用于时区/语言联动优化
        browser_type: 具体画像类型；传入后不会再次随机浏览器家族
        browser_family: auto/random/chrome/firefox/safari 策略
        prefer_firefox: auto 策略下优先使用 Firefox（Camoufox 需要）
        include_high_entropy_hints: **默认 False**。True 时把 5 个高熵 client
            hints（full-version-list / arch / bitness / model / platform-version）
            填进 sec_ch_ua_* 字段。默认 False 是照抄真机行为：这 5 个头只在站点
            用 Accept-CH 索取后才发（真机 418 个抓包里出现 0 次）。需要动态
            协商时不必重生成指纹，直接调 set_high_entropy_hints(fp, True)。

    返回 dict:
        browser_type: str     — 浏览器家族
        impersonate: str      — curl_cffi TLS 指纹名
        fallback_impersonates: list[str] — 同家族回退 impersonate 列表
        user_agent: str       — 完整 UA 字符串
        sec_ch_ua: str        — 低熵 Client Hints（仅 Chrome 非空）
        sec_ch_ua_platform: str
        sec_ch_ua_mobile: str
        client_hints_high_entropy: bool  — 高熵 hints 是否已打开（默认 False）
        sec_ch_ua_full_version_list: str — 高熵；默认 ""（未打开时）
        sec_ch_ua_arch: str              — 高熵；默认 ""
        sec_ch_ua_bitness: str           — 高熵；默认 ""
        sec_ch_ua_model: str             — 高熵；默认 ""（真值本就是空串）
        sec_ch_ua_platform_version: str  — 高熵；默认 ""
        ua_full_version_list: str        — 高熵真值，始终有值（仅 Chrome）
        ua_arch: str                     — 高熵真值，始终有值（仅 Chrome）
        ua_bitness: str                  — 高熵真值，始终有值（仅 Chrome）
        ua_model: str                    — 高熵真值，始终有值（仅 Chrome，空串）
        ua_platform_version: str         — 高熵真值，始终有值（仅 Chrome）
        screen: str           — 屏幕分辨率 (WxH)
        lang: str             — 主语言
        lang_full: str        — 完整 Accept-Language
        timezone: str         — IANA 时区名（如 Asia/Tokyo）
        navigator_platform: str  — navigator.platform（MacIntel/iPhone/Win32）
        navigator_vendor: str    — navigator.vendor（按引擎；Firefox 为空串）
        hardware_concurrency: int — CPU 逻辑核心数
        device_memory: int|None   — navigator.deviceMemory（仅 Chromium 有值）
        max_touch_points: int     — navigator.maxTouchPoints（iOS=5）
        device_pixel_ratio: float — window.devicePixelRatio
        viewport: dict — 与 screen 完全相同的浏览器 viewport
        fingerprint_id: str — 本次任务唯一画像 ID
    """
    if rng is None:
        # Do not use the process-global RNG: concurrent tasks must not influence
        # each other's profile sequence.
        r = random.Random(secrets.randbits(128))
    else:
        r = rng

    if browser_type is None:
        browser_type = _browser_type_for_policy(
            browser_family,
            r,
            prefer_firefox=prefer_firefox,
        )
    browser_type = str(browser_type).strip().lower()
    if browser_type not in _GENERATORS:
        raise ValueError(f"unsupported browser_type: {browser_type!r}")
    expected_family = browser_family_for_type(browser_type)
    requested_family = (browser_family or "auto").strip().lower()
    if requested_family not in ("", "auto", "random", expected_family, browser_type):
        raise ValueError(
            f"browser_type {browser_type!r} does not match browser_family {browser_family!r}"
        )

    fp = _GENERATORS[browser_type](r)

    # IP 地理联动：按国家码选择时区/语言
    country_code = (country_code or "").strip().upper()
    profile = _COUNTRY_PROFILES.get(country_code, _DEFAULT_COUNTRY_PROFILE)

    # 加权随机选择时区
    tz_choices = profile["timezones"]
    tz_list = [tz for tz, _ in tz_choices]
    tz_weights = [w for _, w in tz_choices]
    timezone = r.choices(tz_list, weights=tz_weights, k=1)[0]

    # 多语言优化：从池中随机选 3~5 个，保证第一语言是主语言
    lang_pool = profile["languages"].copy()
    # 目标 3~5 个语言；语言池不足 3 个时按池长度取（避免 randint 下界>上界）
    lo = min(3, len(lang_pool))
    hi = min(5, len(lang_pool))
    num_langs = r.randint(lo, hi)
    primary_lang = lang_pool[0]  # 主语言固定第一位
    other_langs = lang_pool[1:]
    r.shuffle(other_langs)  # 其他语言随机打乱
    selected = [primary_lang] + other_langs[:num_langs - 1]

    # 构建 Accept-Language header（带 q 值权重递减）
    # 真实浏览器格式：主语言无 q，第一个副语言 q=0.9，之后 0.8/0.7…
    lang_parts = []
    for i, lang in enumerate(selected):
        if i == 0:
            lang_parts.append(lang)
        else:
            q = round(1.0 - i * 0.1, 1)  # i=1→0.9, i=2→0.8, ...
            lang_parts.append(f"{lang};q={q}")
    lang_full = ",".join(lang_parts)

    fp["lang"] = primary_lang
    fp["lang_full"] = lang_full
    fp["languages"] = selected
    fp["locale"] = primary_lang
    fp["country_code"] = country_code
    fp["timezone"] = timezone
    _apply_hardware(fp, r)

    width, height = screen_dimensions(fp["screen"])
    fp["screen_width"] = width
    fp["screen_height"] = height
    fp["viewport"] = {"width": width, "height": height}
    fp["browser_family"] = expected_family
    fp["is_mobile"] = browser_type == "ios_safari"
    fp["has_touch"] = fp["max_touch_points"] > 0
    fp["fingerprint_id"] = f"fp_{secrets.token_urlsafe(12)}"

    # ── TLS / HTTP2 指纹唯一化（2026-09-21）──
    # 不这么做的话，全世界所有 curl_cffi 协议机共用同一个 JA3
    #   chrome146 -> a912eb0417c28969ea568912bb1dd121
    #   akamai   -> 52d84b11737d980aef85
    # WAF 拉黑这一个就等于拉黑全部协议机。实测越南段 60 次只过 11 次（18%），
    # 同一 IP 反复 403/200 横跳，就是这个原因。
    # 这里给每个任务一套独有的 JA3 + Akamai，全程固定（浏览器的握手参数
    # 在一次会话内不会变，所以是"每任务一次"而不是"每请求一次"）。
    _tf_seed = r.randrange(1 << 62)
    # TLS_UNIQUE=0 关闭唯一化，退回 curl_cffi 内置的 chrome14x 原生指纹。
    # ⚠️ 排查用：唯一化（尤其 permute_extensions）虽然能大幅提高过 CF 的比例，
    # 但会打乱 TLS 扩展顺序 —— 那是**真机 Chrome 永远不会出现的形态**，
    # 可能导致注册出来的账号被服务端标记（拿不到 Plus 试用）。
    fp["tls_fp"] = (
        unique_tls_fingerprint(seed=_tf_seed)
        if str(os.getenv("TLS_UNIQUE", "1")).strip().lower() not in ("0", "false", "off", "no")
        else None
    )

    # ⚠️ Akamai（HTTP/2）唯一化：**默认关闭**。实测（2026-09-21，同出口 11900，
    # 每档 10 次）：
    #     裸 chrome146           0/10   403 x10
    #     +唯一 JA3              2/10   200 x2, 403 x5, 超时 x3
    #     +唯一 JA3 +自造 Akamai  0/10   403 x10   ← 反而更差
    #     只有自造 Akamai         0/10   403 x10
    # 原因：自造的串为了让哈希唯一，去掉了 ENABLE_PUSH(2:0)、还打乱 SETTINGS
    # 顺序 —— 造出真 Chrome 不会有的 HTTP/2 指纹，比"共用指纹"更可疑。
    # 结论：HTTP/2 层保持 curl_cffi 内置的 Chrome 真值，只唯一化 TLS 层。
    # 需要实验时置 AKAMAI_VARY=1 打开。
    fp["akamai_fp"] = (
        unique_akamai_fingerprint(seed=_tf_seed ^ 0x5DEECE66D)
        if str(os.getenv("AKAMAI_VARY", "")).strip() in ("1", "true", "yes", "on")
        else None
    )

    # 非 Chrome 家族补齐空值键（保证调用方统一取值不报 KeyError）
    if browser_type != "chrome":
        fp.setdefault("sec_ch_ua_full_version_list", "")
        fp.setdefault("sec_ch_ua_arch", "")
        fp.setdefault("sec_ch_ua_bitness", "")
        fp.setdefault("sec_ch_ua_model", "")
        fp.setdefault("sec_ch_ua_platform_version", "")
        fp.setdefault("ua_full_version_list", "")
        fp.setdefault("ua_arch", "")
        fp.setdefault("ua_bitness", "")
        fp.setdefault("ua_model", "")
        fp.setdefault("ua_platform_version", "")
        fp.setdefault("client_hints_high_entropy", False)

    # 高熵 client hints 只在显式 opt-in 时填值（默认照抄真机：不发）
    set_high_entropy_hints(fp, include_high_entropy_hints)

    validate_fingerprint(fp)
    return fp


def diagnose_fingerprint(
    fp: Mapping[str, object],
    *,
    engine_type: str = "auto",
    detected_country: str = "",
) -> dict:
    """Return a serialisable consistency report for the WebUI and tests."""
    errors: list[str] = []
    try:
        validate_fingerprint(fp)
    except ValueError as exc:
        errors.append(str(exc))

    browser_type = str(fp.get("browser_type", ""))
    family = str(fp.get("browser_family", ""))
    ua = str(fp.get("user_agent", ""))
    platform = str(fp.get("navigator_platform", ""))
    lang = str(fp.get("lang", ""))
    locale = str(fp.get("locale", ""))
    viewport = fp.get("viewport") if isinstance(fp.get("viewport"), Mapping) else {}
    screen = str(fp.get("screen", ""))

    try:
        screen_size = screen_dimensions(screen)
        viewport_size = (int(viewport.get("width", 0)), int(viewport.get("height", 0)))
    except (TypeError, ValueError):
        screen_size = (0, 0)
        viewport_size = (0, 0)

    ua_matches = {
        "chrome": "Chrome/" in ua and "Windows NT" in ua,
        "firefox": "Firefox/" in ua and "Windows NT" in ua,
        "safari": "Safari/" in ua and "AppleWebKit" in ua,
    }.get(family, False)
    platform_matches = {
        "chrome": platform == "Win32",
        "firefox": platform == "Win32",
        "safari": platform in ("MacIntel", "iPhone"),
    }.get(family, False)
    country = str(fp.get("country_code", "")).upper()
    observed = (detected_country or "").strip().upper()
    checks = {
        "screen_matches_viewport": screen_size == viewport_size and screen_size != (0, 0),
        "ua_matches_browser_family": ua_matches,
        "platform_matches_browser_family": platform_matches,
        "language_matches_locale": bool(lang and locale and lang == locale),
        "timezone_is_explicit": bool(str(fp.get("timezone", "")).strip()),
        "geoip_override_disabled": True,
        "country_matches_detected": not observed or not country or country == observed,
    }
    checks["all_passed"] = not errors and all(checks.values())
    return {
        "fingerprint_id": fp.get("fingerprint_id", ""),
        "browser_type": browser_type,
        "browser_family": family,
        "engine_type": engine_type,
        "country_code": country,
        "detected_country": observed,
        "user_agent": ua,
        "navigator_platform": platform,
        "screen": screen,
        "viewport": dict(viewport),
        "locale": locale,
        "lang": lang,
        "languages": list(fp.get("languages") or []),
        "accept_language": fp.get("lang_full", ""),
        "timezone": fp.get("timezone", ""),
        "device_pixel_ratio": fp.get("device_pixel_ratio"),
        "checks": checks,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# impersonate → UA 映射（TLS 旋转用）
# ---------------------------------------------------------------------------

_ALL_IMPERSONATES: dict[str, dict] = {}

for s in _SAFARI_VERSIONS:
    _ALL_IMPERSONATES[s["impersonate"]] = {"type": "mac_safari", "data": s}
for s in _IOS_SAFARI_VERSIONS:
    _ALL_IMPERSONATES[s["impersonate"]] = {"type": "ios_safari", "data": s}
for c in _CHROME_VERSIONS:
    _ALL_IMPERSONATES[c["impersonate"]] = {"type": "chrome", "data": c}
for f in _FIREFOX_VERSIONS:
    _ALL_IMPERSONATES[f["impersonate"]] = {"type": "firefox", "data": f}


def fingerprint_for_impersonate(impersonate: str, current_fp: dict) -> dict:
    """把指纹里**随 impersonate 版本变化**的字段同步到新版本，其余原样保留。

    TLS 旋转（_rotate_impersonate_session）换 impersonate 时，光换 UA 是不够的：
    _common_headers / _navigation_headers 的 sec-ch-ua* 全从指纹取，不同步就会出现
    「UA 说 Chrome/152.0.0.0、sec-ch-ua 说 v=145」，连 greasy brand 都对不上，
    是 CF 一抓一个准的自相矛盾特征。

    只动版本相关字段（sec_ch_ua / ua_full_version_list / user_agent），
    屏幕、语言、时区、硬件等会话级属性保持不变 —— 那些跟浏览器版本无关，
    换了反而破坏"同一台机器"的一致性。

    高熵 hints 的**开关状态**原样保留：轮换 TLS 画像不该顺手把原本默认关掉的
    5 个高熵头打开，也不该把站点已经索取过的那 5 个头关掉。

    未知 impersonate 或非 Chrome 家族：Safari/Firefox 本就不发 client hints
    （sec_ch_ua 为空串），无需同步，原样返回副本。
    """
    entry = _ALL_IMPERSONATES.get(impersonate)
    fp = dict(current_fp or {})
    if not entry:
        return fp

    t, d = entry["type"], entry["data"]
    fp["impersonate"] = impersonate
    fp["browser_type"] = t
    fp["browser_family"] = browser_family_for_type(t)
    fp["is_mobile"] = t == "ios_safari"
    fp["user_agent"] = ua_for_impersonate(impersonate, fp.get("user_agent", ""))

    if t == "chrome":
        fp["sec_ch_ua"] = _format_brand_list(d, full=False)
        # 高熵真值随版本刷新；是否**下发**由开关决定（默认关）
        fp["ua_full_version_list"] = _format_brand_list(d, full=True)
        fp["ua_arch"] = _CHROME_UA_ARCH
        fp["ua_bitness"] = _CHROME_UA_BITNESS
        fp["ua_model"] = _CHROME_UA_MODEL
        fp["ua_platform_version"] = str(d.get("platform_version") or "")
        # platform/mobile 只跟设备走，不随 Chrome 版本变，沿用原指纹即可
        # （缺失时给桌面 Windows 默认值）
        fp.setdefault("sec_ch_ua_platform", '"Windows"')
        fp.setdefault("sec_ch_ua_mobile", "?0")
        # 用原开关状态重算 5 个高熵字段：既不误开，也不误关
        set_high_entropy_hints(fp, bool(fp.get("client_hints_high_entropy")))
    else:
        # 非 Chromium：一个 client hint 都不发（真实浏览器行为）
        fp["sec_ch_ua"] = ""
        fp["sec_ch_ua_platform"] = ""
        fp["sec_ch_ua_mobile"] = ""
        fp["sec_ch_ua_full_version_list"] = ""
        fp["sec_ch_ua_arch"] = ""
        fp["sec_ch_ua_bitness"] = ""
        fp["sec_ch_ua_model"] = ""
        fp["sec_ch_ua_platform_version"] = ""
        fp["client_hints_high_entropy"] = False
    fp["has_touch"] = int(fp.get("max_touch_points", 0)) > 0
    validate_fingerprint(fp)
    return fp


def ua_for_impersonate(impersonate: str, current_ua: str) -> str:
    """根据 impersonate 名生成匹配的 UA。"""
    entry = _ALL_IMPERSONATES.get(impersonate)
    if not entry:
        return current_ua

    t, d = entry["type"], entry["data"]

    if t == "mac_safari":
        macos_ver = random.choice(d["macos_versions"])
        return (
            f"Mozilla/5.0 (Macintosh; Intel Mac OS X {macos_ver}) "
            f"AppleWebKit/{d['webkit_ver']} (KHTML, like Gecko) "
            f"Version/{d['safari_ver']} Safari/{d['webkit_ver']}"
        )
    elif t == "ios_safari":
        ios_ver = random.choice(d["ios_versions"])
        return (
            f"Mozilla/5.0 (iPhone; CPU iPhone OS {ios_ver} like Mac OS X) "
            f"AppleWebKit/{d['webkit_ver']} (KHTML, like Gecko) "
            f"Version/{d['safari_ver']} Mobile/15E148 Safari/604.1"
        )
    elif t == "chrome":
        # UA 用缩减形式 major.0.0.0（真机实测 Chrome/152.0.0.0），
        # 真实构建号 152.0.7977.83 只出现在 sec-ch-ua-full-version-list 里
        return (
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{d['ua_ver']} Safari/537.36"
        )
    elif t == "firefox":
        return (
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{d['ver']}) "
            f"Gecko/20100101 Firefox/{d['ver']}"
        )
    return current_ua
