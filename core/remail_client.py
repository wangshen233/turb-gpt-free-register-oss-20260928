# -*- coding: utf-8 -*-
"""Remail 开放 API 邮箱客户端。

Remail 的开放 API 与本项目已有的“生成随机邮箱”类服务不同：

1. 先用 API Key 按项目下一个 ``code`` 或 ``purchase`` 订单；
2. 订单返回交付邮箱和只属于该订单的 service token；
3. 取码时使用 ``/v1/pickup``，不再携带 API Key，只携带邮箱和 service token。

因此 service token 必须和邮箱一起保存在当前进程上下文中，不能只根据邮箱地址
重新拼接取件请求。
"""
from __future__ import annotations

import json
import logging
import random
import re
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

import requests

from config import email as _email_cfg
from core.otp_utils import extract_otp

logger = logging.getLogger(__name__)

DEFAULT_API_BASE = "https://remail.aishop6.com"
REQUEST_TIMEOUT = 20
_CODE_RE = re.compile(r"\b(\d{6})\b")
_FINAL_ORDER_STATUSES = {"failed", "refunded", "closed"}

# 并发下单重试：remail 的 POST /v1/open/orders 在高并发下会间歇性 ReadTimeout。
# 实测 8 worker 同时下单时会出现连续 20-60 秒的 ReadTimeout/ConnectionError 风暴，
# 只重试 9 秒会整单丢号，因此放到 6 次、退避 5/10/15/20/25 秒（共约 75 秒）。
# 重试沿用同一个 Idempotency-Key，服务端不会因此多扣一个邮箱。
_ORDER_CREATE_ATTEMPTS = 6
_ORDER_CREATE_BACKOFF = 5.0  # 秒；第 n 次重试等待 n * backoff

# 库存不足是暂时性的（同一个后缀在 11:55 报 422，11:56 又能下单），
# 批量注册时不能按普通网络错误只重试 9 秒就放弃。这里给库存不足单独一个
# 更长的重试窗口：最多 10 次、退避 8/16/24/30/30…，总计约 4 分钟。
_INVENTORY_RETRY_ATTEMPTS = 10
_INVENTORY_RETRY_BACKOFF = 8.0  # 秒；第 n 次重试等待 n * backoff
_INVENTORY_RETRY_MAX_SLEEP = 30.0  # 秒；单次等待上限
_INVENTORY_RETRY_JITTER = 2.0  # 秒；随机抖动，避免多 worker 同时重试
_SAME_SUFFIX_INVENTORY_TRIES = 3  # 同一后缀连续几次报库存不足就换下一个后缀

# 自建域名池轮换状态：单个自建域名一轮只放十几个可用地址，用满后订单
# 仍能建但邮箱收不到验证码，所以按后缀计数轮换（见 claim_email_suffix）。
_SUFFIX_QUOTA_DEFAULT = 16
_SUFFIX_LOCK = threading.RLock()
_SUFFIX_CURSOR = 0
_SUFFIX_USED: dict[str, int] = {}


class RemailError(RuntimeError):
    """Remail API 请求、下单或取码失败。"""


def _is_inventory_shortage(exc: Exception) -> bool:
    """判断异常是否为暂时性库存不足（HTTP 422 Insufficient inventory）。

    这类失败与服务端地址池的瞬时供给有关，换一个后缀或等一会儿就能成功，
    因此使用比普通网络错误更长的重试窗口。
    """
    text = str(exc or "").casefold()
    return "insufficient inventory" in text or "insufficient_inventory" in text


def _is_suffix_rejected(exc: Exception) -> bool:
    """判断异常是否为后缀本身不可用（HTTP 422 Invalid order request）。

    域名没在 Remail 侧开通时会返回这个错误，重试没有意义，直接换下一个后缀。
    """
    text = str(exc or "").casefold()
    return "invalid order request" in text


# 兼容调用方可能使用的命名。
RemailClientError = RemailError


@dataclass
class RemailAccount:
    """一次 Remail 订单的取件上下文。"""

    email: str
    service_token: str
    order_no: str
    project_id: int
    email_suffix: str


_CONTEXT_CACHE: dict[str, RemailAccount] = {}
_CONTEXT_LOCK = threading.RLock()


def _cache_key(email: str) -> str:
    return str(email or "").strip().lower()


def _base_url(value: str | None = None) -> str:
    """返回 API 根地址，也兼容用户误填文档地址 ``.../docs``。"""
    raw = str(
        value if value is not None else getattr(_email_cfg, "REMAIL_API_BASE", DEFAULT_API_BASE) or DEFAULT_API_BASE
    ).strip()
    if not raw:
        raw = DEFAULT_API_BASE
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw

    parsed = urlsplit(raw.rstrip("/"))
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        raise RemailError("Remail API 地址无效，请填写 https://remail.aishop6.com（不要填写接口路径）")

    path = parsed.path.rstrip("/")
    # 文档链接可直接粘贴到配置页；API 实际位于同一域名根路径。
    if path.lower() == "/docs":
        path = ""
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", "")).rstrip("/")


def _request_timeout() -> int:
    try:
        value = int(getattr(_email_cfg, "REMAIL_REQUEST_TIMEOUT", REQUEST_TIMEOUT) or REQUEST_TIMEOUT)
    except (TypeError, ValueError):
        value = REQUEST_TIMEOUT
    return max(1, min(120, value))


def _api_key() -> str:
    value = str(getattr(_email_cfg, "REMAIL_API_KEY", "") or "").strip()
    if not value:
        raise RemailError("Remail API Key 未配置，请在配置 → 邮箱 / OTP 填写 REMAIL_API_KEY")
    return value


def _auth_headers() -> dict[str, str]:
    return {"Accept": "application/json", "Authorization": f"Bearer {_api_key()}"}


def _error_message(payload, response) -> str:
    if isinstance(payload, dict):
        message = payload.get("message") or payload.get("error") or payload.get("detail")
        request_id = payload.get("requestId") or payload.get("request_id")
        if message:
            return f"{message} (requestId={request_id})" if request_id else str(message)
    text = str(getattr(response, "text", "") or "").strip()
    return text[:240] if text else "服务端未返回错误信息"


def _request(
    method: str,
    path: str,
    *,
    params: dict | None = None,
    json_body: dict | None = None,
    headers: dict[str, str] | None = None,
    authenticated: bool = True,
    timeout: int | None = None,
):
    """调用 Remail API 并返回 JSON payload。

    ``authenticated=False`` 仅用于 pickup 接口。服务 token 不写入日志和异常文本。
    """
    request_headers = {"Accept": "application/json"}
    if authenticated:
        request_headers.update(_auth_headers())
    if headers:
        request_headers.update(headers)

    url = _base_url() + (path if str(path).startswith("/") else f"/{path}")
    try:
        response = requests.request(
            method.upper(),
            url,
            params=params,
            json=json_body,
            headers=request_headers,
            timeout=_request_timeout() if timeout is None else max(1, int(timeout)),
        )
    except requests.RequestException as exc:
        raise RemailError(f"Remail 请求失败 ({method.upper()} {path}): {type(exc).__name__}: {exc}") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        if response.status_code >= 400:
            raise RemailError(
                f"Remail 请求失败 ({method.upper()} {path}): HTTP {response.status_code}; "
                f"{_error_message(None, response)}"
            ) from exc
        raise RemailError(f"Remail 响应不是 JSON ({method.upper()} {path})") from exc

    if response.status_code >= 400:
        if response.status_code == 401 and authenticated:
            raise RemailError(f"Remail API Key 无效或已失效 ({path})")
        raise RemailError(
            f"Remail 请求失败 ({method.upper()} {path}): HTTP {response.status_code}; "
            f"{_error_message(payload, response)}"
        )
    return payload


def _first_value(data: dict, *keys: str):
    for key in keys:
        value = data.get(key)
        if value is not None and value != "":
            return value
    return None


def _unwrap_order(payload) -> dict:
    """读取 OpenAPI 定义的 Order，并兼容少数网关包裹 data/order 的响应。"""
    if not isinstance(payload, dict):
        raise RemailError("Remail 下单响应不是对象")
    if any(
        k in payload
        for k in ("orderNo", "order_no", "deliveryEmail", "delivery_email", "serviceToken", "service_token")
    ):
        return payload
    for key in ("data", "order"):
        value = payload.get(key)
        if isinstance(value, dict):
            return value
    raise RemailError("Remail 下单响应缺少订单数据")


def _project_id() -> int:
    raw = getattr(_email_cfg, "REMAIL_PROJECT_ID", 2)
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        value = 0
    if value <= 0:
        raise RemailError(
            "Remail 项目 ID 未配置，请先通过 Remail API 查询项目后填写 REMAIL_PROJECT_ID"
        )
    return value


def _suffix_quota() -> int:
    """每个后缀用满多少个订单后换下一个（自建域名实测 16 个）。"""
    try:
        value = int(getattr(_email_cfg, "REMAIL_SUFFIX_QUOTA", _SUFFIX_QUOTA_DEFAULT) or _SUFFIX_QUOTA_DEFAULT)
    except (TypeError, ValueError):
        value = _SUFFIX_QUOTA_DEFAULT
    return max(1, value)


def _email_suffixes() -> list[str]:
    """返回可用于下单的后缀池，按配置顺序排列。

    优先读取 REMAIL_EMAIL_SUFFIXES（逗号/分号/空白分隔的域名池）；
    未配置时退化为单后缀 REMAIL_EMAIL_SUFFIX，保持旧行为。
    """
    raw = str(getattr(_email_cfg, "REMAIL_EMAIL_SUFFIXES", "") or "").strip()
    if not raw:
        raw = str(getattr(_email_cfg, "REMAIL_EMAIL_SUFFIX", "outlook.com") or "")
    items: list[str] = []
    for part in re.split(r"[,;\s]+", raw):
        suffix = part.strip().lstrip("@").lstrip(".")
        if not suffix or "@" in suffix:
            continue
        if suffix not in items:
            items.append(suffix)
    if not items:
        raise RemailError("Remail 邮箱后缀无效，请填写 outlook.com 等域名（不要填写完整邮箱）")
    return items


def _email_suffix() -> str:
    """兼容旧调用：返回主后缀（池中第一个）。"""
    return _email_suffixes()[0]


def mark_suffix_exhausted(suffix: str) -> None:
    """把某个后缀标记为已用满，后续下单直接跳过它。"""
    target = str(suffix or "").strip()
    if not target:
        return
    with _SUFFIX_LOCK:
        _SUFFIX_USED[target] = _suffix_quota()
    logger.info("[Remail] 后缀已用满，切换下一个: %s", target)


def claim_email_suffix(*, exclude: set[str] | None = None) -> str:
    """按轮换顺序领取一个还有配额的后缀，并计入一次使用。

    单域名配额用尽时自动跳到下一个；全部用尽则重置计数回绕，
    避免批量注册直接卡死（此时服务端通常会返回 Insufficient inventory）。
    """
    suffixes = _email_suffixes()
    quota = _suffix_quota()
    blocked = {str(x).strip() for x in (exclude or set()) if str(x).strip()}
    with _SUFFIX_LOCK:
        global _SUFFIX_CURSOR
        total = len(suffixes)
        for step in range(total):
            index = (_SUFFIX_CURSOR + step) % total
            candidate = suffixes[index]
            if candidate in blocked:
                continue
            if _SUFFIX_USED.get(candidate, 0) < quota:
                used = _SUFFIX_USED.get(candidate, 0) + 1
                _SUFFIX_USED[candidate] = used
                _SUFFIX_CURSOR = index
                if used == 1:
                    logger.info("[Remail] 本轮使用后缀: %s（配额 %s）", candidate, quota)
                return candidate
        logger.warning("[Remail] 所有后缀配额已用尽，重置轮换计数重新开始")
        _SUFFIX_USED.clear()
        candidate = suffixes[_SUFFIX_CURSOR % total]
        _SUFFIX_USED[candidate] = 1
        return candidate


def _supply_policy() -> str:
    value = str(getattr(_email_cfg, "REMAIL_SUPPLY_POLICY", "public_only") or "public_only").strip().lower()
    if value not in {"private_first", "public_only"}:
        raise RemailError("Remail 库存策略无效，只支持 private_first 或 public_only")
    return value


def _service_mode() -> str:
    value = str(getattr(_email_cfg, "REMAIL_SERVICE_MODE", "purchase") or "purchase").strip().lower()
    if value not in {"code", "purchase"}:
        raise RemailError("Remail 服务模式无效，只支持 code 或 purchase")
    return value


def _order_wait_seconds() -> int:
    try:
        value = int(getattr(_email_cfg, "REMAIL_ORDER_WAIT_SECONDS", 30) or 30)
    except (TypeError, ValueError):
        value = 30
    return max(0, min(180, value))


def _order_credentials(order: dict) -> tuple[str, str, str] | None:
    email = str(_first_value(order, "deliveryEmail", "delivery_email") or "").strip()
    token = str(_first_value(order, "serviceToken", "service_token") or "").strip()
    order_no = str(_first_value(order, "orderNo", "order_no") or "").strip()
    if email and "@" in email and token:
        return email, token, order_no
    return None


def _cache_context(account: RemailAccount) -> RemailAccount:
    """缓存订单取件上下文并返回对象。"""
    with _CONTEXT_LOCK:
        _CONTEXT_CACHE[_cache_key(account.email)] = account
    return account


def _context_from_order(order: dict, target_email: str) -> RemailAccount | None:
    """从订单对象创建上下文，并要求交付邮箱完全匹配。"""
    credentials = _order_credentials(order)
    if not credentials:
        return None
    email, service_token, order_no = credentials
    if email.casefold() != str(target_email or "").strip().casefold():
        return None

    raw_project_id = _first_value(order, "projectId", "project_id")
    try:
        project_id = int(str(raw_project_id).strip()) if raw_project_id is not None else _project_id()
    except (TypeError, ValueError, RemailError):
        # 订单详情理论上一定有 projectId；历史接口缺失时不影响取件，保留
        # 当前配置值作为展示/兼容字段。
        try:
            project_id = _project_id()
        except RemailError:
            project_id = 0

    suffix = str(
        _first_value(order, "emailSuffix", "email_suffix")
        or email.rsplit("@", 1)[-1]
        or _email_suffix()
    ).strip().lstrip("@")
    return RemailAccount(
        email=email,
        service_token=service_token,
        order_no=order_no,
        project_id=project_id,
        email_suffix=suffix,
    )


def _order_list_items(payload) -> list[dict]:
    """读取订单列表响应，兼容 data/items 的网关包裹。"""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    items = payload.get("items")
    if isinstance(items, list):
        return [item for item in items if isinstance(item, dict)]
    data = payload.get("data")
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    return []


def _saved_context_metadata(email: str) -> dict:
    """读取账号保存的 Remail 订单凭证，不把解析失败传播到查活主流程。"""
    try:
        from core import db

        row = db.get_account_by_email(email)
    except Exception as exc:
        logger.debug("[Remail] 读取已注册账号订单信息失败: %s: %s", type(exc).__name__, exc)
        return {}
    if not row:
        return {}

    raw = row.get("extra_json")
    if isinstance(raw, str) and raw.strip():
        try:
            extra = json.loads(raw)
        except (TypeError, ValueError):
            extra = {}
    elif isinstance(raw, dict):
        extra = raw
    else:
        extra = {}
    if not isinstance(extra, dict):
        return {}

    # 新字段使用 email_service；同时兼容早期开发版本可能使用 remail。
    for key in ("email_service", "remail"):
        value = extra.get(key)
        if isinstance(value, dict):
            source = str(value.get("source") or "remail").strip().lower()
            if source == "remail":
                return dict(value)
    return {}


def get_account_context_metadata(email: str) -> dict | None:
    """返回可持久化的 Remail 订单上下文，用于注册账号落库。

    service token 是取件凭证，不写日志；这里仅由账号持久化层调用，普通列表
    API 不会直接返回 ``extra_json``。
    """
    account = get_account_context(email)
    if account is None:
        return None
    return {
        "source": "remail",
        "email": account.email,
        "service_token": account.service_token,
        "order_no": account.order_no,
        "project_id": account.project_id,
        "email_suffix": account.email_suffix,
    }


def restore_account_context(email: str) -> RemailAccount | None:
    """恢复已注册账号的 Remail 取件上下文。

    进程重启后 ``_CONTEXT_CACHE`` 会丢失。优先使用账号保存的 service token，
    其次按保存的订单号查详情，最后用 API Key 按邮箱搜索订单。所有候选订单
    都必须与目标邮箱大小写不敏感地完全匹配，避免拿错其他邮箱的验证码。
    """
    target = str(email or "").strip()
    if not target:
        return None
    cached = get_account_context(target)
    if cached is not None:
        return cached

    metadata = _saved_context_metadata(target)
    saved_email = str(metadata.get("email") or "").strip()
    if saved_email and saved_email.casefold() != target.casefold():
        metadata = {}

    saved_token = str(metadata.get("service_token") or metadata.get("serviceToken") or "").strip()
    if saved_token:
        order = {
            "deliveryEmail": saved_email or target,
            "serviceToken": saved_token,
            "orderNo": str(metadata.get("order_no") or metadata.get("orderNo") or "").strip(),
            "projectId": metadata.get("project_id") or metadata.get("projectId"),
            "emailSuffix": metadata.get("email_suffix") or metadata.get("emailSuffix"),
        }
        account = _context_from_order(order, target)
        if account is not None:
            logger.info(
                "[Remail] 已从账号保存信息恢复取件上下文: %s order=%s",
                target,
                account.order_no or "-",
            )
            return _cache_context(account)

    saved_order_no = str(metadata.get("order_no") or metadata.get("orderNo") or "").strip()
    if saved_order_no:
        try:
            detail = _unwrap_order(
                _request("GET", f"/v1/open/orders/{quote(saved_order_no, safe='')}")
            )
        except RemailError as exc:
            logger.debug("[Remail] 按已保存订单号恢复失败: order=%s error=%s", saved_order_no, exc)
        else:
            account = _context_from_order(detail, target)
            if account is not None:
                logger.info(
                    "[Remail] 已按订单号恢复取件上下文: %s order=%s",
                    target,
                    account.order_no or saved_order_no,
                )
                return _cache_context(account)

    # 没有可用的持久化凭证时，通过 API Key 查询用户自己的订单。列表接口的
    # search 是服务端过滤；仍需在客户端做完整邮箱匹配，不能接受模糊命中。
    try:
        payload = _request(
            "GET",
            "/v1/open/orders",
            params={"search": target},
        )
    except RemailError as exc:
        logger.debug("[Remail] 按邮箱搜索订单失败: email=%s error=%s", target, exc)
        return None

    candidates = [
        item
        for item in _order_list_items(payload)
        if str(_first_value(item, "deliveryEmail", "delivery_email") or "").strip().casefold()
        == target.casefold()
    ]
    candidates.sort(
        key=lambda item: _parse_timestamp(
            _first_value(item, "updatedAt", "updated_at", "createdAt", "created_at")
        )
        or float("-inf"),
        reverse=True,
    )

    # 列表响应通常直接带 serviceToken；若网关出于安全策略隐藏 token，
    # 再逐个请求订单详情（优先最新订单）。
    for order in candidates:
        account = _context_from_order(order, target)
        if account is not None:
            logger.info(
                "[Remail] 已按邮箱搜索恢复取件上下文: %s order=%s",
                target,
                account.order_no or "-",
            )
            return _cache_context(account)

    for order in candidates[:5]:
        order_no = str(_first_value(order, "orderNo", "order_no") or "").strip()
        if not order_no:
            continue
        try:
            detail = _unwrap_order(
                _request("GET", f"/v1/open/orders/{quote(order_no, safe='')}")
            )
        except RemailError:
            continue
        account = _context_from_order(detail, target)
        if account is not None:
            logger.info(
                "[Remail] 已按订单详情恢复取件上下文: %s order=%s",
                target,
                account.order_no or order_no,
            )
            return _cache_context(account)
    return None


def _order_status_error(order: dict) -> str | None:
    status = str(order.get("status") or "").strip().lower()
    if status in _FINAL_ORDER_STATUSES:
        failure = str(order.get("failureCode") or order.get("failure_code") or "").strip()
        return f"Remail 订单未就绪: status={status}" + (f", failure={failure}" if failure else "")
    return None


def _wait_for_order_credentials(order: dict) -> tuple[str, str, str]:
    credentials = _order_credentials(order)
    if credentials:
        return credentials

    order_no = str(_first_value(order, "orderNo", "order_no") or "").strip()
    if not order_no:
        raise RemailError("Remail 下单成功但响应缺少 service token 或订单号")

    error = _order_status_error(order)
    if error:
        raise RemailError(error)

    deadline = time.monotonic() + _order_wait_seconds()
    latest = order
    while time.monotonic() <= deadline:
        try:
            latest = _unwrap_order(_request("GET", f"/v1/open/orders/{order_no}"))
        except RemailError:
            # 订单已创建，短暂的详情接口错误不应重新下单，继续等待到截止时间。
            if time.monotonic() >= deadline:
                raise
        else:
            credentials = _order_credentials(latest)
            if credentials:
                return credentials
            error = _order_status_error(latest)
            if error:
                raise RemailError(error)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(1, remaining))

    status = str(latest.get("status") or "unknown")
    raise RemailError(f"Remail 订单等待 service token 超时: order={order_no}, status={status}")


_PRESEEDED_FILE = Path(__file__).resolve().parent.parent / "tools" / "remail_preseeded.json"
_PRESEEDED_LOCK = threading.RLock()


def _pop_preseeded_account() -> RemailAccount | None:
    """取一条外部手工塞进来的取件上下文（形如 /pickup?email=..&token=.. 里那两个值）。

    用途：已经下过单、但因为浏览器抖动等原因没注册成功的邮箱，不想再花钱重新下单，
    直接把 email + service token 塞进 tools/remail_preseeded.json，注册机就会优先用它们。

    文件格式：[{"email": "...@icloud.com", "token": "st_..."}, ...]
    取出即从文件里删除，保证同一个邮箱不会被两条注册流水线同时抢。
    """
    with _PRESEEDED_LOCK:
        if not _PRESEEDED_FILE.exists():
            return None
        try:
            items = json.loads(_PRESEEDED_FILE.read_text(encoding="utf-8") or "[]")
        except Exception as exc:
            logger.warning("[Remail] 预置取件文件解析失败: %s", exc)
            return None
        if not isinstance(items, list) or not items:
            return None
        head = items.pop(0)
        try:
            _PRESEEDED_FILE.write_text(
                json.dumps(items, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
            )
        except Exception as exc:
            logger.warning("[Remail] 预置取件文件回写失败: %s", exc)
    email = str((head or {}).get("email") or "").strip()
    token = str((head or {}).get("token") or head.get("service_token") or "").strip()
    if not email or "@" not in email or not token:
        logger.warning("[Remail] 预置取件条目缺少 email/token，已跳过")
        return None
    account = RemailAccount(
        email=email,
        service_token=token,
        order_no=str(head.get("order_no") or ""),
        project_id=int(head.get("project_id") or 0) or _project_id(),
        email_suffix=str(head.get("email_suffix") or email.split("@", 1)[1]),
    )
    logger.info("[Remail] 使用预置取件上下文: %s", email)
    return _cache_context(account)


def pick_account() -> RemailAccount:
    """按配置创建一个 Remail 接码/长效购买订单并返回交付邮箱。

    单个自建域名一轮只放十几个可用地址：配额用满后订单仍能建成功，但交付的
    邮箱收不到验证码。因此这里按后缀池轮换 —— 某个后缀用满配额、或服务端连续
    报 Insufficient inventory 时，自动换下一个后缀重试。
    """
    preseeded = _pop_preseeded_account()
    if preseeded is not None:
        return preseeded

    project_id = _project_id()
    service_mode = _service_mode()
    supply = _supply_policy()
    suffix_pool = _email_suffixes()
    tried_suffixes: list[str] = []

    def _new_idempotency_key(suffix: str) -> str:
        return f"turb-gpt-free-register-{suffix}-{uuid.uuid4()}"

    email_suffix = claim_email_suffix()
    idempotency_key = _new_idempotency_key(email_suffix)

    # 并发注册时 remail 下单接口会间歇性 ReadTimeout（实测 8 worker 下 16 单丢 6 单）。
    # 这里沿用同一个 Idempotency-Key 重试：服务端若已把单建出来，会返回同一张订单，
    # 不会因为重试多烧一个邮箱；若确实没建出来则重试即成功。
    order = None
    last_exc: Exception | None = None
    attempt = 0
    inventory_attempt = 0
    same_suffix_tries = 0
    while True:
        attempt += 1
        try:
            payload = _request(
                "POST",
                "/v1/open/orders",
                params={"serviceMode": service_mode, "supply": supply},
                json_body={"projectId": project_id, "emailSuffix": email_suffix},
                headers={"Idempotency-Key": idempotency_key},
            )
            order = _unwrap_order(payload)
            break
        except RemailError as exc:
            last_exc = exc
            if _is_inventory_shortage(exc) or _is_suffix_rejected(exc):
                inventory_attempt += 1
                same_suffix_tries += 1
                if _is_suffix_rejected(exc):
                    # 后缀本身不可用，直接换下一个，不必先确认抖动。
                    same_suffix_tries = _SAME_SUFFIX_INVENTORY_TRIES
                if inventory_attempt >= _INVENTORY_RETRY_ATTEMPTS:
                    raise
                if len(suffix_pool) > 1 and same_suffix_tries >= _SAME_SUFFIX_INVENTORY_TRIES:
                    # 确认不是瞬时抖动：该后缀没货了，换池子里的下一个。
                    exhausted = email_suffix
                    mark_suffix_exhausted(exhausted)
                    if exhausted not in tried_suffixes:
                        tried_suffixes.append(exhausted)
                    if len(tried_suffixes) >= len(suffix_pool):
                        raise
                    email_suffix = claim_email_suffix(exclude=set(tried_suffixes))
                    idempotency_key = _new_idempotency_key(email_suffix)
                    same_suffix_tries = 0
                    backoff = 1.0 + random.uniform(0, 1.0)
                    logger.warning(
                        "[Remail] 后缀 %s 已无库存，切换后缀（已试 %s/%s）: %s",
                        exhausted, len(tried_suffixes), len(suffix_pool), str(exc)[:120],
                    )
                else:
                    backoff = min(
                        _INVENTORY_RETRY_MAX_SLEEP,
                        _INVENTORY_RETRY_BACKOFF * inventory_attempt,
                    ) + random.uniform(0, _INVENTORY_RETRY_JITTER)
                    logger.warning(
                        "[Remail] 库存暂时不足（%s/%s），%.1fs 后重试: %s",
                        inventory_attempt, _INVENTORY_RETRY_ATTEMPTS, backoff, str(exc)[:160],
                    )
            else:
                if attempt >= _ORDER_CREATE_ATTEMPTS:
                    raise
                backoff = _ORDER_CREATE_BACKOFF * attempt
                logger.warning(
                    "[Remail] 下单失败（%s/%s），%ss 后重试: %s",
                    attempt, _ORDER_CREATE_ATTEMPTS, backoff, str(exc)[:160],
                )
            time.sleep(backoff)
    if order is None:
        raise last_exc or RemailError("Remail 下单失败")
    email, service_token, order_no = _wait_for_order_credentials(order)
    account = RemailAccount(
        email=email,
        service_token=service_token,
        order_no=order_no,
        project_id=project_id,
        email_suffix=email_suffix,
    )
    _cache_context(account)
    logger.info("[Remail] 已创建邮箱订单: %s order=%s project=%s", email, order_no or "-", project_id)
    return account


def get_email() -> str:
    """兼容其他临时邮箱客户端的旧入口。"""
    return pick_account().email


def get_account_context(email: str) -> RemailAccount | None:
    with _CONTEXT_LOCK:
        return _CONTEXT_CACHE.get(_cache_key(email))


def release_account(email: str, status: str = "available", note: str | None = None) -> None:
    """释放本地取件上下文；订单生命周期由 Remail 服务端管理。"""
    with _CONTEXT_LOCK:
        account = _CONTEXT_CACHE.pop(_cache_key(email), None)
    if account:
        logger.info(
            "[Remail] 已释放取件上下文: %s order=%s status=%s note=%s",
            email,
            account.order_no or "-",
            status,
            note or "",
        )


def _parse_timestamp(raw) -> float | None:
    if raw is None or raw == "":
        return None
    if isinstance(raw, (int, float)):
        value = float(raw)
        return value / 1000.0 if value > 10_000_000_000 else value

    text = str(raw).strip()
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        value = float(text)
        return value / 1000.0 if value > 10_000_000_000 else value
    try:
        iso = text[:-1] + "+00:00" if text.endswith("Z") else text
        parsed = datetime.fromisoformat(iso)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def _pickup_items(payload) -> list[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if isinstance(data, dict):
        payload = data
    elif isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    items = payload.get("items")
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def _message_code(message: dict) -> str | None:
    direct = _first_value(message, "verificationCode", "verification_code", "code", "otp")
    if direct is not None:
        match = _CODE_RE.search(str(direct))
        if match:
            return match.group(1)

    preview = str(_first_value(message, "bodyPreview", "body_preview", "body", "text", "content") or "")
    return extract_otp(
        {
            "from": str(_first_value(message, "sender", "from", "fromEmail") or ""),
            "subject": str(message.get("subject") or ""),
            "text": preview,
            "content": preview,
        }
    )


def fetch_latest_otp(
    email: str,
    after_ts: float | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
    settle_seconds: int | None = None,
) -> str:
    """轮询 Remail pickup，返回领取时间之后最新的六位验证码。"""
    target = str(email or "").strip()
    if not target:
        raise RemailError("Remail 取码缺少邮箱地址")
    account = get_account_context(target) or restore_account_context(target)
    if account is None:
        raise RemailError(
            "Remail 找不到该邮箱的 service token，且无法从已保存订单恢复；"
            "请确认账号注册来源为 Remail、订单仍可取件，并已配置 Remail API Key"
        )

    try:
        wait_seconds = int(max_wait if max_wait is not None else getattr(_email_cfg, "OTP_MAX_WAIT", 90))
    except (TypeError, ValueError):
        wait_seconds = 90
    try:
        interval = int(poll_interval if poll_interval is not None else getattr(_email_cfg, "OTP_POLL_INTERVAL", 3))
    except (TypeError, ValueError):
        interval = 3
    try:
        settle = int(settle_seconds if settle_seconds is not None else getattr(_email_cfg, "OTP_SETTLE_SECONDS", 5))
    except (TypeError, ValueError):
        settle = 5
    interval = max(1, interval)
    settle = max(0, settle)
    deadline = time.monotonic() + max(0, wait_seconds)
    best_otp: str | None = None
    best_timestamp = float("-inf")
    settle_until: float | None = None
    last_error = "收件箱为空或尚未出现新的验证码"

    logger.info("[Remail] 开始轮询邮箱 %s，最长 %ss", target, wait_seconds)
    while time.monotonic() <= deadline:
        try:
            # 单次 pickup 的 timeout 不能吃掉整个轮询预算。
            # 旧代码固定用 REMAIL_REQUEST_TIMEOUT（.env 里是 60s），而总预算
            # OTP_MAX_WAIT 只有 180s —— 一次 hang 就废掉 1/3，两次直接判死。
            # 实测该接口正常只要 0.4s，60s 的读超时是异常长尾。
            # 改成「剩余预算内取小值」，超时就快速重试，把预算用在重试上。
            budget_left = deadline - time.monotonic()
            payload = _request(
                "GET",
                "/v1/pickup",
                params={"email": target, "token": account.service_token},
                authenticated=False,
                timeout=min(_request_timeout(), max(5, int(budget_left))),
            )
            items = _pickup_items(payload)
            messages = []
            for message in items:
                received_at = _first_value(
                    message, "receivedAt", "received_at", "timestamp", "createdAt", "created_at"
                )
                timestamp = _parse_timestamp(received_at)
                if after_ts is not None and timestamp is not None and timestamp < after_ts - 30:
                    continue
                code = _message_code(message)
                if code:
                    messages.append((timestamp, code))

            messages.sort(
                key=lambda value: value[0] if value[0] is not None else float("-inf"),
                reverse=True,
            )
            for timestamp, code in messages:
                candidate_time = float("-inf") if timestamp is None else timestamp
                if (
                    best_otp is None
                    or candidate_time > best_timestamp
                    or (candidate_time == best_timestamp and code != best_otp)
                ):
                    best_otp = code
                    best_timestamp = candidate_time
                    settle_until = time.monotonic() + settle
                    logger.info("[Remail] 锁定 OTP 候选，等待 %ss 确认", settle)

            if best_otp and settle_until is not None and time.monotonic() >= settle_until:
                return best_otp
        except RemailError as exc:
            last_error = str(exc)
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(interval, remaining))

    if best_otp:
        return best_otp
    raise RemailError(f"等待 Remail 验证码超时: {target}; {last_error}")


def list_projects(*, search: str | None = None, product_type: str | None = "microsoft") -> list[dict]:
    """查询当前 API Key 可见项目，供配置/诊断使用。"""
    params = {"offset": 0, "limit": 100}
    if search:
        params["search"] = str(search).strip()
    if product_type:
        params["productType"] = str(product_type).strip()
    payload = _request("GET", "/v1/open/projects", params=params)
    if isinstance(payload, dict):
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        items = data.get("items") if isinstance(data, dict) else None
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    return []
