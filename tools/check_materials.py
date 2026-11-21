#!/usr/bin/env python3
"""Verify the current maintenance materials without executing firmware code."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
MATERIALS = ROOT / 'materials'
errors = []
expected = {}
for number, line in enumerate((MATERIALS / 'SHA256SUMS').read_text().splitlines(), 1):
    match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
    if not match:
        errors.append(f'invalid manifest line {number}')
        continue
    digest, relative = match.groups()
    parsed = PurePosixPath(relative)
    if parsed.is_absolute() or '..' in parsed.parts or relative in expected:
        errors.append(f'unsafe or duplicate manifest path: {relative}')
        continue
    expected[relative] = digest
for relative, digest in expected.items():
    path = MATERIALS / relative
    if path.is_symlink() or not path.is_file():
        errors.append(f'missing/non-regular material: {relative}')
    elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        errors.append(f'hash mismatch: {relative}')
actual = {str(p.relative_to(MATERIALS)) for p in MATERIALS.rglob('*')
          if (p.is_file() or p.is_symlink()) and p != MATERIALS / 'SHA256SUMS'
          and '__pycache__' not in p.parts and p.name != '.DS_Store'}
for extra in sorted(actual - expected.keys()):
    errors.append(f'unlisted material: {extra}')
for relative, executable in json.loads((MATERIALS / 'runtime-modes.json').read_text()).items():
    path = MATERIALS / 'firmware/port-3726/files' / relative
    if path.is_file() and bool(path.stat().st_mode & 0o111) != executable:
        errors.append(f'executable mode mismatch: {relative}')
if errors:
    print('\n'.join(errors), file=sys.stderr)
    sys.exit(1)
print(f'PASS: {len(expected)} material hashes and runtime executable modes verified; no firmware executed.')
