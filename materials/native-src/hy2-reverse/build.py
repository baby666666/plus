#!/usr/bin/env python3
"""Build the dependency-free Linux/amd64 reverse worker with pinned Go."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--go', required=True, help='Go 1.26.4 executable')
parser.add_argument('--output', type=Path)
args = parser.parse_args()
source = Path(__file__).resolve().parent
repo = source.parents[2]
output = args.output or repo / 'materials/firmware/port-3726/files/usr/sbin/nr-hy2-reverse'
go = str(Path(args.go).resolve())
version = subprocess.check_output([go, 'version'], text=True).strip()
if not version.startswith('go version go1.26.4 '):
    raise SystemExit('Go 1.26.4 is required for the recorded binary')
environment = dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH='amd64',
                   GOTOOLCHAIN='local', GOMAXPROCS='2')
output.parent.mkdir(parents=True, exist_ok=True)
subprocess.run([go, 'build', '-trimpath', '-buildvcs=false', '-ldflags=-s -w -buildid=',
                '-o', str(output.resolve()), '.'], cwd=source, env=environment, check=True)
output.chmod(0o755)
data = output.read_bytes()
print(f'{hashlib.sha256(data).hexdigest()}  {output}')
print(f'{len(data)} bytes; {version}; CGO_ENABLED=0 GOOS=linux GOARCH=amd64')
