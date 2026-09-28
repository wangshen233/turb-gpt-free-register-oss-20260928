"""Run real local browser contexts; intercept every request before the network."""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if (ROOT / ".vendor").exists():
    sys.path.insert(0, str(ROOT / ".vendor"))

from browser_launcher import (  # noqa: E402
    FingerprintRuntimeMismatch, close_browser, launch_browser, validate_page_fingerprint,
)
from fingerprint import generate_fingerprint  # noqa: E402


def host_memory_snapshot():
    """Capture Windows memory pressure alongside native launch failures."""
    if sys.platform != "win32":
        return {"status": "not_measured"}
    import ctypes
    from ctypes import wintypes

    class MemoryStatus(ctypes.Structure):
        _fields_ = [("length", wintypes.DWORD), ("load", wintypes.DWORD)] + [
            (name, ctypes.c_ulonglong) for name in (
                "total_physical", "available_physical", "commit_limit", "available_commit",
                "total_virtual", "available_virtual", "available_extended_virtual",
            )
        ]

    status = MemoryStatus()
    status.length = ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return {"status": "read_failed"}
    return {
        "status": "measured", "physical_load_percent": status.load,
        **{name + "_mib": round(getattr(status, name) / (1024 * 1024), 1) for name in (
            "total_physical", "available_physical", "commit_limit", "available_commit",
        )},
    }


def inspect_capabilities(page):
    return page.evaluate("""async () => {
      let nativePermissionStatus = null;
      let permissionError = null;
      if (navigator.permissions && typeof PermissionStatus !== 'undefined') {
        try {
          nativePermissionStatus = (await navigator.permissions.query({name: 'notifications'}))
            instanceof PermissionStatus;
        } catch (error) {
          permissionError = error.name;
        }
      }
      return {
        user_agent: navigator.userAgent,
        user_agent_data: navigator.userAgentData
          ? await navigator.userAgentData.getHighEntropyValues([
              'fullVersionList', 'platformVersion', 'architecture', 'bitness']) : null,
        features: {
          temporal: typeof Temporal !== 'undefined',
          webassembly: typeof WebAssembly !== 'undefined',
          bigint: typeof BigInt !== 'undefined',
        },
        permission_status_is_native: nativePermissionStatus,
        permission_error: permissionError,
      };
    }""")


def check_native_runtime(engine):
    """Test the installed engine without profile overrides or init scripts."""
    from playwright.sync_api import sync_playwright

    result = {"engine": engine, "stage": "start", "host_memory": host_memory_snapshot()}
    try:
        with sync_playwright() as runtime:
            result["stage"] = "launch"
            browser = getattr(runtime, engine).launch(headless=True)
            try:
                result["native_version"] = browser.version
                result["stage"] = "new_context"
                context = browser.new_context(service_workers="block")
                context.route("**/*", lambda route: route.fulfill(
                    status=200, content_type="text/html", body="<!doctype html><title>Native baseline</title>"))
                result["stage"] = "new_page"
                page = context.new_page()
                result["stage"] = "navigate"
                page.goto("http://127.0.0.1/native-baseline", timeout=15_000)
                result["stage"] = "inspect"
                result["capabilities"] = inspect_capabilities(page)
                result["stage"] = "complete"
                result["status"] = "passed"
            finally:
                browser.close()
    except Exception as exc:
        result["status"] = "failed"
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def assess_runtime(result, profile):
    """Do not equate injected field equality with native engine consistency."""
    checks = {"browser_context": "error" not in result}
    if "error" not in result:
        headers = result.get("request_headers", {})
        capabilities = result.get("client_hints_and_features", {})
        checks.update({
            "page_fields": result.get("page_environment", {}).get("all_passed"),
            "request_user_agent": headers.get("user-agent") == profile["user_agent"],
            "request_accept_language": headers.get("accept-language") == profile["lang_full"],
            "ua_matches_native_major": result.get("ua_matches_native_major"),
            "native_permission_status": capabilities.get("permission_status_is_native"),
        })
        if profile["browser_type"] == "chrome":
            data = capabilities.get("user_agent_data") or {}
            brands = {item["brand"]: item["version"] for item in data.get("brands", [])}
            full_versions = {item["brand"]: item["version"] for item in data.get("fullVersionList", [])}
            advertised = re.search(r"Chrome/(\d+)", profile["user_agent"])
            header_major = re.search(r'"Chromium";v="(\d+)"', headers.get("sec-ch-ua", ""))
            checks["client_hints_match_ua_major"] = bool(
                advertised and header_major
                and advertised.group(1) == header_major.group(1) == brands.get("Chromium")
            )
            checks["client_hints_match_native_version"] = (
                full_versions.get("Chromium") == result.get("native_version")
            )
        baseline = result.get("native_baseline", {})
        checks["native_baseline"] = baseline.get("status") == "passed" if baseline else None
        checks["features_match_native_baseline"] = (
            capabilities.get("features") == baseline.get("capabilities", {}).get("features")
            if baseline.get("status") == "passed" else None
        )

    failures = [name for name, passed in checks.items() if passed is False]
    unmeasured = [name for name, passed in checks.items() if passed is None]
    # An intercepted HTTP request reveals neither a TLS handshake nor HTTP/2 settings.
    unmeasured.extend(["tls_handshake", "http2_settings", "remote_workflows"])
    return {
        "status": "failed" if failures else "incomplete",
        "checks": checks,
        "failures": failures,
        "unmeasured": unmeasured,
    }


def check_runtime(browser_type, baseline=None):
    profile = generate_fingerprint(country_code="JP", browser_type=browser_type)
    result = {
        "browser_type": browser_type, "fingerprint_id": profile["fingerprint_id"],
        "native_baseline": baseline or {}, "stage": "launch",
        "tls_http2": "not_measured_local_request_intercepted",
        "scope": "local_browser_context_only",
        "host_memory": host_memory_snapshot(),
    }
    runtime = browser = None
    try:
        runtime, browser, context = launch_browser(engine_type="playwright", fingerprint=profile)
        result["native_version"] = browser.version
        captured = {}

        def respond(route):
            captured.update({k: v for k, v in route.request.all_headers().items()
                             if k in {"user-agent", "accept-language"} or k.startswith("sec-ch-ua")})
            route.fulfill(status=200, content_type="text/html", body="<!doctype html><title>Local runtime probe</title>")

        context.route("**/*", respond)
        result["stage"] = "new_page"
        page = context.new_page()
        result["stage"] = "navigate"
        page.goto("http://127.0.0.1/runtime-probe", timeout=15_000)
        result["stage"] = "inspect"
        try:
            result["page_environment"] = validate_page_fingerprint(page, profile)
        except FingerprintRuntimeMismatch as exc:
            result["page_environment"] = exc.report
        result["request_headers"] = captured
        result["client_hints_and_features"] = inspect_capabilities(page)
        # WebKit is an engine; its version is not an installed Safari version.
        advertised = re.search(r"(?:Chrome|Firefox)/(\d+)", profile["user_agent"])
        result["ua_matches_native_major"] = (
            advertised.group(1) == browser.version.split(".")[0] if advertised else None
        )
        result["stage"] = "complete"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if browser is not None:
            close_browser(runtime, browser)
    result["assessment"] = assess_runtime(result, profile)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "output" / "browser-runtime.json")
    args = parser.parse_args()
    baselines = {}
    results = []
    for browser_type in ("chrome", "firefox", "mac_safari", "ios_safari"):
        engine = {"chrome": "chromium", "firefox": "firefox"}.get(browser_type, "webkit")
        if engine not in baselines:
            baselines[engine] = check_native_runtime(engine)
        result = check_runtime(browser_type, baselines[engine])
        results.append(result)
        print(json.dumps({
            "browser_type": browser_type, "native_version": result.get("native_version"),
            "page_fields_passed": result.get("page_environment", {}).get("all_passed"),
            "ua_matches_native_major": result.get("ua_matches_native_major"),
            "status": result["assessment"]["status"],
            "failures": result["assessment"]["failures"],
            "native_baseline": result["native_baseline"]["status"],
            "error": result["error"].splitlines()[0] if result.get("error") else None,
        }, ensure_ascii=True), flush=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    # Even without observed mismatches, transport checks remain unmeasured.
    return 1 if any(result["assessment"]["status"] == "failed" for result in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
