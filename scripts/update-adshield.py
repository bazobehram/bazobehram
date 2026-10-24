#!/usr/bin/env python3
"""Build AdShield's one-domain-per-line feed from maintained blocklists."""
from __future__ import annotations
import ipaddress
import os
from pathlib import Path
import re
import sys
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "adshield-rules.txt"
MANUAL = ROOT / "adshield" / "manual-rules.txt"
ALLOW = ROOT / "adshield" / "allowlist.txt"
SOURCES = {
    "HaGeZi Multi LIGHT": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/light-onlydomains.txt",
    "StevenBlack unified hosts": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
}
HOST = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)

def normalize(line: str) -> str | None:
    line = line.strip().lower()
    if not line or line.startswith(("#", "!", "[", "/")):
        return None
    line = line.split("#", 1)[0].strip()
    parts = line.split()
    if len(parts) > 1:
        try:
            ipaddress.ip_address(parts[0])
        except ValueError:
            return None
        if not parts[0] in ("0.0.0.0", "127.0.0.1", "::", "::1"):
            return None
        line = parts[1]
    if line.startswith("*."):
        line = line[2:]
    if line.startswith("."):
        line = line[1:]
    if line in ("localhost", "localhost.localdomain", "local"):
        return None
    return line if len(line) <= 253 and HOST.fullmatch(line) else None

def parse(blob: str) -> set[str]:
    return {domain for line in blob.splitlines() if (domain := normalize(line))}

def protected(domain: str, allowed: set[str]) -> bool:
    return any(domain == item or domain.endswith("." + item) for item in allowed)

def main() -> None:
    allowed = parse(ALLOW.read_text(encoding="utf-8"))
    manual = parse(MANUAL.read_text(encoding="utf-8"))
    if len(manual) < 90:
        raise RuntimeError("Manual rule count unexpectedly low; refusing to publish")
    merged = set(manual)
    for name, url in SOURCES.items():
        request = urllib.request.Request(url, headers={"User-Agent": "AdShield-feed-builder/1.0"})
        with urllib.request.urlopen(request, timeout=90) as response:
            data = response.read(16_000_001)
        if len(data) > 16_000_000:
            raise RuntimeError(f"{name} exceeds 16 MB")
        domains = parse(data.decode("utf-8-sig"))
        if len(domains) < 20_000:
            raise RuntimeError(f"{name} returned suspiciously few domains: {len(domains)}")
        merged.update(domains)
        print(f"{name}: {len(domains)} domains")
    merged = {x for x in merged if not protected(x, allowed)}
    if not 30_000 <= len(merged) <= 300_000:
        raise RuntimeError(f"Suspicious output count {len(merged)}; refusing to publish")
    header = "# AdShield Aggregated DNS Blocklist\n# Generated automatically from HaGeZi LIGHT, StevenBlack and personal rules\n# Domain-only format, one entry per line\n"
    output = header + "\n".join(sorted(merged)) + "\n"
    tmp = OUTPUT.with_suffix(".tmp")
    tmp.write_text(output, encoding="utf-8")
    os.replace(tmp, OUTPUT)
    print(f"Published {len(merged)} unique domains")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Build failed; existing feed preserved: {exc}", file=sys.stderr)
        sys.exit(1)
