#!/usr/bin/env python3
"""
Runs the web-tier Sigma logic from detection/sigma/ against a PHP built-in server
log (lab/logs/access.log) or any file with one request per line, and prints every
hit with the rule that matched and the ATT&CK technique.

This is a direct, deliberately readable implementation of the four web rules, so the
detection can be exercised without a SIEM. The YAML files are the portable version.
"""
import re
import sys
from pathlib import Path

RULES = [
    (
        "web_lfi_path_traversal",
        "T1190",
        re.compile(r"\.\./|\.\.%2f|\.\.\.\.//|php://", re.IGNORECASE),
    ),
    (
        "web_php_session_file_include",
        "T1190, T1505.003",
        re.compile(r"sess_"),
    ),
    (
        "web_include_of_upload_dir",
        "T1505.003",
        re.compile(r"(page|file|template|include)=[^&]*uploads/"),
    ),
    (
        "web_webshell_command_parameter",
        "T1059, T1505.003",
        re.compile(
            r"(^|[?&])(c|cmd|exec|command)=(id|whoami|uname|hostname|cat|ls|pwd|wget|curl|nc|ncat|bash|sh|python|perl)(%20|\+|&|$)"
        ),
    ),
]

# PHP built-in server: "[date] 127.0.0.1:port [status]: METHOD /path?query"
REQUEST_LINE = re.compile(r"^\[(?P<ts>[^\]]+)\]\s+(?P<ip>[\d.]+):\d+\s+\[(?P<status>\d+)\]:\s+(?P<method>[A-Z]+)\s+(?P<uri>\S+)")


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "lab/logs/access.log")
    if not path.exists():
        sys.exit(f"log not found: {path}")

    total = hits = 0
    for line in path.read_text(errors="replace").splitlines():
        m = REQUEST_LINE.match(line)
        if not m:
            continue
        total += 1
        uri = m.group("uri")
        query = uri.split("?", 1)[1] if "?" in uri else ""
        for name, technique, rx in RULES:
            if rx.search(query):
                hits += 1
                print(f"[{name}] {technique}")
                print(f"    {m.group('ts')}  {m.group('ip')}  {m.group('method')} {uri}  -> {m.group('status')}")
    print(f"\n{total} request lines scanned, {hits} rule hits")


if __name__ == "__main__":
    main()
