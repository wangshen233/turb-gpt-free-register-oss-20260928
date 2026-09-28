"""Per-task network and browser environment allocation.

The allocator freezes the network observation and the generated fingerprint before
the registration thread starts. SQLite owns the historical uniqueness guarantees so
concurrent workers cannot reserve the same exit IP or semantic profile.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import random
from collections.abc import Mapping
from typing import Any

from fingerprint import generate_fingerprint, validate_fingerprint

from . import db

logger = logging.getLogger("environment")

TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"


class EnvironmentAllocationError(RuntimeError):
    """Raised when a task cannot receive a fresh, verifiable environment."""


def proxy_fingerprint(proxy: str | None) -> str:
    value = (proxy or "").strip()
    if not value:
        return "direct"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def parse_proxy_pool(text: str | list[str] | tuple[str, ...] | None) -> list[str]:
    """Normalize a proxy pool while preserving input order and removing duplicates."""
    if isinstance(text, (list, tuple)):
        values = text
    else:
        values = str(text or "").splitlines()
    out: list[str] = []
    seen: set[str] = set()
    for item in values:
        proxy = str(item or "").strip()
        if not proxy or proxy.startswith("#") or proxy in seen:
            continue
        seen.add(proxy)
        out.append(proxy)
    return out


def fingerprint_signature(fingerprint: Mapping[str, Any]) -> str:
    """Hash the semantic profile, excluding only the per-task opaque ID."""
    validate_fingerprint(fingerprint)
    payload = {key: value for key, value in fingerprint.items() if key != "fingerprint_id"}
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_trace(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in (text or "").splitlines():
        key, separator, value = raw_line.partition("=")
        if separator:
            values[key.strip().lower()] = value.strip()
    exit_ip = values.get("ip", "")
    if not exit_ip:
        raise EnvironmentAllocationError("出口探测响应缺少 ip")
    try:
        normalized_ip = str(ipaddress.ip_address(exit_ip))
    except ValueError:
        raise EnvironmentAllocationError(f"出口探测返回了无效 IP: {exit_ip!r}") from None
    return {"exit_ip": normalized_ip, "exit_country": values.get("loc", "").upper()}


def compare_exit_observation(
    environment: Mapping[str, Any],
    *,
    exit_ip: str = "",
    exit_country: str = "",
    status_code: int | None = None,
) -> dict[str, Any]:
    """Compare a live task exit with the frozen allocation.

    A manually selected country is an intentional profile override: it is shown
    in the report and remains unchanged even when the proxy country differs.
    The exit IP itself is always strict because it identifies the network path.
    """
    expected_ip = str(environment.get("exit_ip") or "").strip()
    expected_country = str(
        environment.get("country_code") or environment.get("exit_country") or ""
    ).strip().upper()
    country_source = str(environment.get("country_source") or "default").strip().lower()
    observed_ip = str(exit_ip or "").strip()
    if observed_ip:
        try:
            observed_ip = str(ipaddress.ip_address(observed_ip))
        except ValueError:
            pass
    observed_country = str(exit_country or "").strip().upper()
    ip_matches = not expected_ip or observed_ip == expected_ip
    country_matches = (
        not expected_country
        or not observed_country
        or observed_country == expected_country
        or country_source == "manual"
    )
    status_ok = status_code is None or int(status_code) == 200
    checks = {
        "trace_reachable": status_ok,
        "exit_ip_matches": ip_matches,
        "country_matches_profile": country_matches,
        "country_policy_respected": country_source == "manual" or country_matches,
    }
    return {
        "expected": {
            "exit_ip": expected_ip,
            "country_code": expected_country,
            "country_source": country_source,
        },
        "observed": {
            "exit_ip": observed_ip,
            "exit_country": observed_country,
            "status_code": status_code,
        },
        "checks": checks,
        "all_passed": all(checks.values()),
    }


def probe_exit(proxy: str | None, timeout: float = 15.0) -> dict[str, str]:
    """Read the real egress IP and country through the task's proxy."""
    try:
        import requests
    except ImportError as exc:
        raise EnvironmentAllocationError(
            "出口探测依赖 requests 未安装，请先安装 requirements.txt"
        ) from exc
    proxy_value = (proxy or "").strip()
    proxies = {"http": proxy_value, "https": proxy_value}
    try:
        response = requests.get(TRACE_URL, proxies=proxies, timeout=timeout)
    except Exception as exc:
        raise EnvironmentAllocationError(
            f"出口探测失败 ({proxy_fingerprint(proxy_value)}): {exc}"
        ) from exc
    if response.status_code != 200:
        raise EnvironmentAllocationError(
            f"出口探测返回 HTTP {response.status_code} ({proxy_fingerprint(proxy_value)})"
        )
    return _parse_trace(response.text)


def _requested_country(options: Mapping[str, Any], observed_country: str) -> tuple[str, str]:
    manual = str(options.get("fingerprint_country") or "").strip().upper()
    if manual:
        return manual, "manual"
    if observed_country:
        return observed_country, "proxy"
    return "", "default"


def _fingerprint_policy(options: Mapping[str, Any]) -> tuple[str, str, bool]:
    family = str(options.get("fingerprint_browser_family") or "auto").strip().lower()
    engine = str(options.get("browser_engine") or "auto").strip().lower()
    prefer_firefox = engine in ("auto", "camoufox") and family in ("", "auto", "random")
    return family or "auto", engine or "auto", prefer_firefox


def _candidate_proxies(options: Mapping[str, Any]) -> list[str]:
    pool = parse_proxy_pool(options.get("proxy_pool"))
    if pool:
        # Start each task at a different pool position. Reservation remains the
        # authority when workers happen to probe the same entry concurrently.
        random.SystemRandom().shuffle(pool)
        return pool
    return [str(options.get("proxy") or "").strip()]


def allocate_environment(run_id: str, options: Mapping[str, Any]) -> dict[str, Any]:
    """Probe, generate, and atomically reserve one complete task environment."""
    family, engine, prefer_firefox = _fingerprint_policy(options)
    try:
        timeout = float(options.get("environment_probe_timeout") or 15.0)
    except (TypeError, ValueError):
        timeout = 15.0
    timeout = max(3.0, min(timeout, 60.0))

    failures: list[str] = []
    for proxy in _candidate_proxies(options):
        try:
            observed = probe_exit(proxy, timeout=timeout)
        except EnvironmentAllocationError as exc:
            failures.append(str(exc))
            logger.warning("任务 %s 环境探测失败: %s", run_id, exc)
            continue

        profile_country, country_source = _requested_country(options, observed["exit_country"])
        if (
            country_source == "manual"
            and observed["exit_country"]
            and observed["exit_country"] != profile_country
        ):
            logger.info(
                "任务 %s 使用手动地区 %s，出口探测为 %s；保留手动画像地区",
                run_id,
                profile_country,
                observed["exit_country"],
            )

        if db.environment_seen(exit_ip=observed["exit_ip"]):
            failures.append(f"出口 IP 已在历史账本中: {observed['exit_ip']}")
            continue

        for _ in range(32):
            fingerprint = generate_fingerprint(
                country_code=profile_country,
                browser_family=family,
                prefer_firefox=prefer_firefox,
            )
            signature = fingerprint_signature(fingerprint)
            if db.environment_seen(fingerprint_signature=signature):
                continue

            environment = {
                "allocation_id": f"{run_id}:{fingerprint['fingerprint_id']}",
                "run_id": run_id,
                "proxy": proxy,
                "proxy_fingerprint": proxy_fingerprint(proxy),
                "exit_ip": observed["exit_ip"],
                "exit_country": observed["exit_country"],
                "country_code": profile_country,
                "country_source": country_source,
                "browser_family": fingerprint["browser_family"],
                "browser_engine": engine,
                "fingerprint_id": fingerprint["fingerprint_id"],
                "fingerprint_signature": signature,
                "fingerprint": fingerprint,
            }
            if db.reserve_environment(run_id, environment):
                logger.info(
                    "任务 %s 环境已冻结: ip=%s exit_country=%s profile_country=%s "
                    "fingerprint=%s proxy=%s",
                    run_id,
                    observed["exit_ip"],
                    observed["exit_country"] or "N/A",
                    profile_country or "default",
                    fingerprint["fingerprint_id"],
                    environment["proxy_fingerprint"],
                )
                return environment

            # A concurrent task won the reservation between the existence check
            # and INSERT. Generate another profile and let the unique constraints
            # arbitrate the race again.
            if db.environment_seen(exit_ip=observed["exit_ip"]):
                failures.append(f"出口 IP 已被并发任务预留: {observed['exit_ip']}")
                break

    detail = "; ".join(failures[-6:]) or "没有可用代理或直连出口"
    raise EnvironmentAllocationError(
        f"没有可分配的全新任务环境（代理池/出口 IP/画像去重失败）: {detail}"
    )
