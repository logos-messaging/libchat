#!/usr/bin/env python3
import re
import sys
from datetime import datetime

TIMESTAMP_RE = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)')

def parse_ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ")

def fmt_offset(ms):
    if ms < 1000:
        return f"+{ms:7.0f}ms"
    else:
        return f"+{ms/1000:7.3f}s "

lines = sys.stdin.readlines()
base = None

for line in lines:
    m = TIMESTAMP_RE.match(line)
    if not m:
        print(line, end="")
        continue

    ts = parse_ts(m.group(1))
    if base is None:
        base = ts

    delta_us = (ts - base).total_seconds() * 1_000_000
    rounded_ms = round(delta_us / 5000) * 5

    rest = line[m.end():]
    print(f"{fmt_offset(rounded_ms)}  {rest}", end="")
