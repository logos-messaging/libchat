#!/usr/bin/env python3
"""
Usage: python3 align_logs.py <reference_file> <target_file>

Translates identifiers in target_file to match reference_file,
based on order of first appearance. Output is the translated target_file.
Mapping is printed to stderr.
"""
import re
import sys

PATTERNS = [
    ('app',         re.compile(r'(?<=app=")([^"]+)(?=")')),
    ('proposal_id', re.compile(r'(?<=proposal_id=)(\d+)')),
    ('conversation',re.compile(r'(?<=conversation=")([^"]+)(?=")')),
    ('convo',       re.compile(r'(?<=convo=")([^"]+)(?=")')),
]

def extract_ordered(lines, pattern):
    seen, seen_set = [], set()
    for line in lines:
        for m in pattern.finditer(line):
            v = m.group(1)
            if v not in seen_set:
                seen.append(v)
                seen_set.add(v)
    return seen

def build_mapping(ref_lines, tgt_lines):
    mapping = {}
    for name, pat in PATTERNS:
        ref_vals = extract_ordered(ref_lines, pat)
        tgt_vals = extract_ordered(tgt_lines, pat)
        for tgt, ref in zip(tgt_vals, ref_vals):
            if tgt != ref:
                mapping[tgt] = ref
                print(f"  [{name}] {tgt} -> {ref}", file=sys.stderr)
    return mapping

def apply_mapping(lines, mapping):
    if not mapping:
        return lines
    keys = sorted(mapping, key=len, reverse=True)
    pat = re.compile('|'.join(re.escape(k) for k in keys))
    return [pat.sub(lambda m: mapping[m.group(0)], line) for line in lines]

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <reference_file> <target_file>", file=sys.stderr)
    sys.exit(1)

with open(sys.argv[1]) as f:
    ref_lines = f.readlines()
with open(sys.argv[2]) as f:
    tgt_lines = f.readlines()

mapping = build_mapping(ref_lines, tgt_lines)
for line in apply_mapping(tgt_lines, mapping):
    print(line, end="")
