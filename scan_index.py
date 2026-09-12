#!/usr/bin/env python3
"""
Simple HTML safety scanner for a single URL (raw GitHub file).
Usage:
  1) pip install requests
  2) python3 scan_index.py
"""
import re, hashlib, sys
from urllib.parse import urlparse
import requests

RAW_URL = "https://raw.githubusercontent.com/patelprakash3615-byte/Balaji-ride-/main/index.html"

SUSPICIOUS_PATTERNS = {
    "eval_call": re.compile(r"\beval\s*\("),
    "new_Function": re.compile(r"\bnew\s+Function\s*\("),
    "atob_btoa": re.compile(r"\b(atob|btoa)\s*\("),
    "document_write": re.compile(r"\bdocument\.write\s*\("),
    "innerHTML_assign": re.compile(r"\binnerHTML\s*="),
    "fromCharCode": re.compile(r"fromCharCode\s*\("),
    "hex_escapes": re.compile(r"\\x[0-9A-Fa-f]{2}"),
}

RE_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
RE_LINKS = re.compile(r'href=["\']([^"\']+)["\']', re.I)
RE_BASE64_LIKE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")  # long base64-like sequences


def fetch(url):
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    return r.text


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def find_external_hosts(s):
    hosts = set()
    for m in RE_SCRIPT_SRC.findall(s):
        parsed = urlparse(m)
        if parsed.netloc:
            hosts.add(parsed.netloc)
    for m in RE_LINKS.findall(s):
        parsed = urlparse(m)
        if parsed.netloc:
            hosts.add(parsed.netloc)
    return sorted(hosts)


def scan_text(s):
    findings = {}
    for name, pat in SUSPICIOUS_PATTERNS.items():
        matches = pat.findall(s)
        findings[name] = len(matches)
    findings["long_base64_strings"] = len(RE_BASE64_LIKE.findall(s))
    findings["script_src_count"] = len(RE_SCRIPT_SRC.findall(s))
    findings["links_count"] = len(RE_LINKS.findall(s))
    findings["external_hosts"] = find_external_hosts(s)
    return findings


def print_report(url, text, digest, findings):
    print("SCAN REPORT")
    print("URL:", url)
    print("SHA256:", digest)
    print()
    print("Summary:")
    for k in ("eval_call","new_Function","atob_btoa","document_write","innerHTML_assign","fromCharCode","hex_escapes"):
        if findings.get(k,0):
            print(f"  - {k}: {findings[k]} occurrence(s)  <-- suspicious")
    if findings["long_base64_strings"]:
        print(f"  - long_base64_strings: {findings['long_base64_strings']} (possible obfuscated content)")
    print(f"  - script tags with src: {findings['script_src_count']}")
    print(f"  - href occurrences: {findings['links_count']}")
    if findings["external_hosts"]:
        print("  - external hosts referenced:", ", ".join(findings["external_hosts"]))
    else:
        print("  - no external script hosts detected")
    print()
    print("Recommendation:")
    print(" - If no suspicious findings, file looks safe for basic usage.")
    print(" - If suspicious patterns found, inspect the matched lines manually or run on VirusTotal / sandbox.")
    print()


def main():
    try:
        print("Fetching:", RAW_URL)
        txt = fetch(RAW_URL)
    except Exception as e:
        print("Error fetching URL:", e, file=sys.stderr)
        sys.exit(2)

    digest = sha256(txt)
    findings = scan_text(txt)
    print_report(RAW_URL, txt, digest, findings)

    # optional: print first few suspicious lines for quick inspection
    suspicious_lines = []
    for i, line in enumerate(txt.splitlines(), start=1):
        for pat in SUSPICIOUS_PATTERNS.values():
            if pat.search(line):
                suspicious_lines.append((i, line.strip()))
                break
        if len(suspicious_lines) >= 10:
            break

    if suspicious_lines:
        print("Suspicious lines (up to 10):")
        for ln, content in suspicious_lines:
            print(f" L{ln}: {content}")
    else:
        print("No suspicious lines found by quick line-scan.")


if __name__ == "__main__":
    main()
