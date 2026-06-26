#!/usr/bin/env python3
"""
Crawl a local web app and report links, forms, and input fields.
Uses Playwright to render JavaScript (SPAs like OWASP Juice Shop).
For authorized security testing only.
"""

from __future__ import annotations

import argparse
import sys
from collections import deque
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

try:
    from playwright.sync_api import Browser, Page, sync_playwright
except ImportError:
    sync_playwright = None  # type: ignore[assignment,misc]


DEFAULT_START_URL = "http://localhost:3000"
DEFAULT_MAX_PAGES = 100

EXTRACT_JS = """
() => {
  const links = [];
  const seen = new Set();

  function addLink(href, text, source) {
    if (!href) return;
    const key = href + "\\0" + text;
    if (seen.has(key)) return;
    seen.add(key);
    links.push({ href, text: (text || "").trim().slice(0, 200), source });
  }

  for (const a of document.querySelectorAll("a[href]")) {
    addLink(a.getAttribute("href"), a.innerText, "a[href]");
  }
  for (const el of document.querySelectorAll("[routerlink], [routerLink]")) {
    addLink(el.getAttribute("routerlink") || el.getAttribute("routerLink"), el.innerText, "routerLink");
  }
  for (const el of document.querySelectorAll("[href]")) {
    if (el.tagName !== "A" && el.tagName !== "LINK") {
      addLink(el.getAttribute("href"), el.innerText, el.tagName.toLowerCase() + "[href]");
    }
  }

  function fieldInfo(el) {
    const tag = el.tagName.toLowerCase();
    const info = {
      tag,
      type: el.getAttribute("type") || (tag === "textarea" ? "textarea" : tag === "select" ? "select" : "text"),
      name: el.getAttribute("name") || "",
      id: el.id || el.getAttribute("id") || "",
      value: el.value ?? el.getAttribute("value") ?? "",
      placeholder: el.getAttribute("placeholder") || "",
      required: el.required || el.hasAttribute("required"),
      ariaLabel: el.getAttribute("aria-label") || "",
    };
    const label = el.id && document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
    if (label) info.label = label.innerText.trim();
    return info;
  }

  const forms = [];
  for (const form of document.querySelectorAll("form")) {
    const inputs = [];
    for (const el of form.querySelectorAll("input, textarea, select, button")) {
      inputs.push(fieldInfo(el));
    }
    forms.push({
      action: form.getAttribute("action") || "",
      method: (form.getAttribute("method") || "GET").toUpperCase(),
      enctype: form.getAttribute("enctype") || "application/x-www-form-urlencoded",
      id: form.id || "",
      name: form.getAttribute("name") || "",
      inputs,
    });
  }

  const orphanInputs = [];
  for (const el of document.querySelectorAll("input, textarea, select, button")) {
    if (!el.closest("form")) {
      orphanInputs.push(fieldInfo(el));
    }
  }

  return { links, forms, orphanInputs };
}
"""


def normalize_url(base: str, href: str) -> str | None:
    """Resolve and normalize a URL; return None if not crawlable."""
    if not href or href.startswith(("javascript:", "mailto:", "tel:", "data:")):
        return None

    absolute = urljoin(base, href)
    parsed = urlparse(absolute)
    if parsed.scheme not in ("http", "https"):
        return None

    normalized = urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, "")
    )
    return normalized


def same_origin(url: str, origin: str) -> bool:
    p_url, p_origin = urlparse(url), urlparse(origin)
    return p_url.scheme == p_origin.scheme and p_url.netloc == p_origin.netloc


def dismiss_overlays(page: Page) -> None:
    """Dismiss common cookie/consent banners that block interaction."""
    for selector in (
        "button:has-text('Me want it!')",
        "button:has-text('Accept')",
        "button:has-text('Got it')",
        "button:has-text('OK')",
        ".cc-dismiss",
        "[aria-label='dismiss cookie message']",
    ):
        try:
            btn = page.locator(selector).first
            if btn.is_visible(timeout=500):
                btn.click(timeout=2000)
                page.wait_for_timeout(300)
                return
        except Exception:
            continue


def wait_for_app(page: Page, timeout_ms: float) -> None:
    """Wait until a JS app has rendered meaningful content."""
    page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
    try:
        page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 8000))
    except Exception:
        pass
    try:
        page.wait_for_function(
            """() => {
              const root = document.querySelector("app-root, #root, #app, [data-testid='root']");
              if (root && root.children.length > 0) return true;
              return document.querySelectorAll("a[href], form, input, button, [routerlink]").length > 0;
            }""",
            timeout=min(timeout_ms, 10000),
        )
    except Exception:
        page.wait_for_timeout(1500)


def extract_page(page: Page) -> dict:
    return page.evaluate(EXTRACT_JS)


def print_report(
    url: str,
    links: list[dict],
    forms: list[dict],
    orphan_inputs: list[dict],
    error: str | None,
) -> None:
    print(f"\n{'=' * 72}")
    print(f"URL: {url}")
    print("=" * 72)

    if error:
        print(f"  [!] {error}")
        return

    print(f"\nLinks ({len(links)}):")
    if not links:
        print("  (none)")
    for link in links:
        line = f"  href={link['href']!r}"
        if link.get("text"):
            line += f"  text={link['text']!r}"
        if link.get("source"):
            line += f"  source={link['source']!r}"
        print(line)

    print(f"\nForms ({len(forms)}):")
    if not forms:
        print("  (none)")
    for i, form in enumerate(forms, 1):
        action = form["action"] or "(current page)"
        print(f"\n  Form #{i}:")
        print(f"    action:  {action}")
        print(f"    method:  {form['method']}")
        print(f"    enctype: {form['enctype']}")
        if form.get("id"):
            print(f"    id:      {form['id']}")
        if form.get("name"):
            print(f"    name:    {form['name']}")
        _print_inputs(form.get("inputs", []), indent="    ")

    print(f"\nInputs outside forms ({len(orphan_inputs)}):")
    if not orphan_inputs:
        print("  (none)")
    else:
        _print_inputs(orphan_inputs, indent="  ")


def _print_inputs(inputs: list[dict], indent: str) -> None:
    print(f"{indent}inputs ({len(inputs)}):")
    if not inputs:
        print(f"{indent}  (none)")
        return
    for inp in inputs:
        parts = [f"type={inp.get('type', '?')!r}"]
        if inp.get("name"):
            parts.append(f"name={inp['name']!r}")
        if inp.get("id"):
            parts.append(f"id={inp['id']!r}")
        if inp.get("value"):
            parts.append(f"value={inp['value']!r}")
        if inp.get("placeholder"):
            parts.append(f"placeholder={inp['placeholder']!r}")
        if inp.get("ariaLabel"):
            parts.append(f"aria-label={inp['ariaLabel']!r}")
        if inp.get("label"):
            parts.append(f"label={inp['label']!r}")
        if inp.get("required"):
            parts.append("required")
        print(f"{indent}  [{inp['tag']}] " + ", ".join(parts))


def crawl_playwright(
    start_url: str,
    max_pages: int,
    timeout: float,
    headed: bool,
    wait_ms: int,
) -> None:
    if sync_playwright is None:
        print(
            f"Playwright is not installed for this Python:\n"
            f"  {sys.executable}\n\n"
            "Install with the SAME python you use to run this script:\n"
            f"  {sys.executable} -m pip install playwright\n"
            f"  {sys.executable} -m playwright install chromium",
            file=sys.stderr,
        )
        raise SystemExit(1)

    origin = start_url
    visited: set[str] = set()
    queue: deque[str] = deque([start_url])
    pages_crawled = 0
    timeout_ms = timeout * 1000

    print(
        f"Crawling {start_url} with Playwright "
        f"(max {max_pages} pages, same-origin, JS rendering enabled)"
    )

    with sync_playwright() as p:
        browser: Browser = p.chromium.launch(headless=not headed)
        context = browser.new_context(
            user_agent="SecurityTestCrawler/2.0 (Playwright)",
            ignore_https_errors=True,
        )
        page = context.new_page()

        while queue and pages_crawled < max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)

            try:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                wait_for_app(page, timeout_ms)
                dismiss_overlays(page)
                if wait_ms:
                    page.wait_for_timeout(wait_ms)
                data = extract_page(page)
                print_report(url, data["links"], data["forms"], data["orphanInputs"], None)

                for link in data["links"]:
                    normalized = normalize_url(url, link["href"])
                    if normalized and same_origin(normalized, origin) and normalized not in visited:
                        queue.append(normalized)

            except Exception as e:
                print_report(url, [], [], [], str(e))

            pages_crawled += 1

        browser.close()

    print(f"\n{'=' * 72}")
    print(f"Done. Crawled {pages_crawled} page(s), discovered {len(visited)} unique URL(s).")
    if queue:
        print(f"Stopped early: {len(queue)} URL(s) remaining (increase --max-pages to crawl more).")


# --- Static HTML fallback (no JavaScript) -----------------------------------

class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[dict] = []
        self.forms: list[dict] = []
        self._current_form: dict | None = None
        self._current_label: str | None = None
        self._label_for: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k: (v or "") for k, v in attrs}
        tag = tag.lower()

        if tag == "a":
            self.links.append({"href": attr.get("href", ""), "text": "", "source": "a[href]"})

        elif tag == "form":
            self._current_form = {
                "action": attr.get("action", ""),
                "method": attr.get("method", "GET").upper(),
                "enctype": attr.get("enctype", "application/x-www-form-urlencoded"),
                "id": attr.get("id", ""),
                "name": attr.get("name", ""),
                "inputs": [],
            }
            self.forms.append(self._current_form)

        elif tag == "label" and self._current_form is not None:
            self._current_label = ""
            self._label_for = attr.get("for")

        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append(
                {
                    "tag": "input",
                    "type": attr.get("type", "text"),
                    "name": attr.get("name", ""),
                    "id": attr.get("id", ""),
                    "value": attr.get("value", ""),
                    "placeholder": attr.get("placeholder", ""),
                    "required": "required" in attr,
                }
            )

        elif tag in ("textarea", "select", "button") and self._current_form is not None:
            self._current_form["inputs"].append(
                {
                    "tag": tag,
                    "type": attr.get("type", tag),
                    "name": attr.get("name", ""),
                    "id": attr.get("id", ""),
                    "value": attr.get("value", ""),
                }
            )

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "form":
            self._current_form = None
        elif tag == "label":
            if self._label_for and self._current_form is not None:
                for inp in self._current_form["inputs"]:
                    if inp.get("id") == self._label_for and self._current_label:
                        inp["label"] = self._current_label.strip()
            self._current_label = None
            self._label_for = None

    def handle_data(self, data: str) -> None:
        if self._current_label is not None:
            self._current_label += data
        if self.links and not self.links[-1]["text"]:
            text = data.strip()
            if text:
                self.links[-1]["text"] = text


def fetch_page_static(url: str, timeout: float) -> tuple[str | None, str | None]:
    req = Request(url, headers={"User-Agent": "SecurityTestCrawler/1.0"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                return None, f"skipped (Content-Type: {content_type})"
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.read().decode(charset, errors="replace"), None
    except HTTPError as e:
        return None, f"HTTP {e.code}"
    except URLError as e:
        return None, str(e.reason)
    except TimeoutError:
        return None, "timeout"


def crawl_static(start_url: str, max_pages: int, timeout: float) -> None:
    origin = start_url
    visited: set[str] = set()
    queue: deque[str] = deque([start_url])
    pages_crawled = 0

    print(f"Crawling {start_url} (static HTML only, max {max_pages} pages, same-origin)")

    while queue and pages_crawled < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        html, error = fetch_page_static(url, timeout)
        pages_crawled += 1

        if html is None:
            print_report(url, [], [], [], error)
            continue

        parser = PageParser()
        parser.feed(html)
        print_report(url, parser.links, parser.forms, [], None)

        for link in parser.links:
            normalized = normalize_url(url, link["href"])
            if normalized and same_origin(normalized, origin) and normalized not in visited:
                queue.append(normalized)

    print(f"\n{'=' * 72}")
    print(f"Done. Crawled {pages_crawled} page(s), discovered {len(visited)} unique URL(s).")
    if queue:
        print(f"Stopped early: {len(queue)} URL(s) remaining (increase --max-pages to crawl more).")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Crawl a local web app and list links, forms, and inputs."
    )
    parser.add_argument(
        "url",
        nargs="?",
        default=DEFAULT_START_URL,
        help=f"Start URL (default: {DEFAULT_START_URL})",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=DEFAULT_MAX_PAGES,
        help=f"Maximum pages to crawl (default: {DEFAULT_MAX_PAGES})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Page load timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--wait-ms",
        type=int,
        default=1000,
        help="Extra wait after render in milliseconds (default: 1000)",
    )
    parser.add_argument(
        "--headed",
        action="store_true",
        help="Show the browser window while crawling",
    )
    parser.add_argument(
        "--static",
        action="store_true",
        help="Use static HTML parser only (no JavaScript rendering)",
    )
    args = parser.parse_args()

    try:
        if args.static:
            crawl_static(args.url, args.max_pages, args.timeout)
        else:
            crawl_playwright(
                args.url,
                args.max_pages,
                args.timeout,
                args.headed,
                args.wait_ms,
            )
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
