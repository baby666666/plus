#!/usr/bin/env python3
"""Real health-cycle inventory with public-only command fixtures, no networking."""
from pathlib import Path
import hashlib
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'firmware/port-3726/files/usr/ikuai/script/native_exit_health.sh'
checks = 0


def check(ok, message):
    global checks
    assert ok, message
    checks += 1


STUBS = r'''
set -e
source "$SOURCE"
NR="$STATE"
nr_health_now(){ cat "$NR/now"; }
ip(){
 printf 'ip %s\n' "$*" >> "$NR/commands"
 case "$*" in
  '-o link show') [ ! -f "$NR/fail.links" ] && cat "$NR/input-links";;
  '-o -4 addr show') [ ! -f "$NR/fail.addresses" ] && cat "$NR/input-addresses";;
  *) echo 'Unexpected non-global ip read' >&2;return 90;;
 esac
}
wg(){
 printf 'wg %s\n' "$*" >> "$NR/commands"
 [ "$1" = show ] && [ "$2" = all ] || return 91
 case "$3" in peers|allowed-ips|endpoints) ;; *) echo 'Non-public WG read refused' >&2;return 92;;esac
 [ ! -f "$NR/fail.$3" ] && cat "$NR/input-$3"
}
nr_health_guarded(){ [ ! -f "$NR/unguarded.$1" ]; }
nr_health_probe(){
 printf '%s\n' "$1" >> "$NR/probes"
 [ ! -f "$NR/probe-fail.$1" ] && echo 1 > "$4" || echo 0 > "$4"
}
nr_health_native(){ return 0; }
ik_cntl(){ printf '%s\n' "$*" >> "$NR/published"; }
'''


class Fixture:
    def __init__(self, root, count=32):
        self.root = root
        root.mkdir()
        self.count = count
        self.interfaces = [f'wg{i}' for i in range(1, count + 1)]
        self.links = {name: f'{100+i}: {name}: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n'
                      for i, name in enumerate(self.interfaces, 1)}
        self.addresses = {name: f'{100+i}: {name}    inet 198.19.{i}.1/24 scope global {name}\\       valid_lft forever preferred_lft forever\n'
                          for i, name in enumerate(self.interfaces, 1)}
        self.peer_fields = {field: {} for field in ['peers', 'allowed-ips', 'endpoints']}
        for i, name in enumerate(self.interfaces, 1):
            # Multiple peers and exact whitespace must retain the old signature.
            self.peer_fields['peers'][name] = f'public-{i}-a\npublic-{i}-b\n'
            self.peer_fields['allowed-ips'][name] = f'public-{i}-a\t0.0.0.0/0\npublic-{i}-b\t198.18.{i}.0/24 198.20.{i}.0/24\n'
            self.peer_fields['endpoints'][name] = f'public-{i}-a\t192.0.2.{i}:51820\npublic-{i}-b\t(none)\n'
        (root / 'now').write_text('100')
        (root / 'exits').write_text(''.join(f'{i} {name} {name} 1\n' for i, name in enumerate(self.interfaces, 1)))
        (root / 'policies').write_text('1 ' + ','.join(map(str, range(1, count + 1))) + ' 6 0\n')
        (root / 'policy-workers').write_text('1 1 1.1.1.1\n')
        self.write_inventory()
        self.env = dict(os.environ, SOURCE=str(SOURCE), STATE=str(root))

    def write_inventory(self):
        (self.root / 'input-links').write_text('1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n' + ''.join(self.links.values()))
        (self.root / 'input-addresses').write_text('1: lo    inet 127.0.0.1/8 scope host lo\n' + ''.join(self.addresses.values()))
        for field, values in self.peer_fields.items():
            (self.root / f'input-{field}').write_text(''.join(name + '\t' + line + '\n' for name, body in values.items() for line in body.splitlines()))

    def run(self, command='nr_exit_health_sync', success=True):
        result = subprocess.run(['bash', '-c', STUBS + '\n' + command], env=self.env, capture_output=True, text=True, timeout=15)
        check((result.returncode == 0) == success, f'expected execution result: {result.stderr}')
        check(not result.stderr, f'no unexpected command/error: {result.stderr}')
        return result.stdout

    def cache(self):
        return {int(line.split()[0]): line.split()[1:] for line in (self.root / 'exit-health-cache').read_text().splitlines()}

    def health(self):
        return {int(line.split()[0]): tuple(map(int, line.split()[1:])) for line in (self.root / 'exit-health').read_text().splitlines()}

    def lines(self, name):
        p = self.root / name
        return p.read_text().splitlines() if p.exists() else []

    def clear_commands(self):
        (self.root / 'commands').write_text('')

    def expected_signature(self, i):
        name = f'wg{i}'
        source = f'{i} {name} {name} 1 1.1.1.1\n'
        if name in self.links:
            source += f'{100+i}\n'
        source += self.addresses.get(name, '')
        source += ''.join(self.peer_fields[field].get(name, '') for field in ['peers', 'allowed-ips', 'endpoints'])
        return hashlib.sha256(source.encode()).hexdigest()


with tempfile.TemporaryDirectory(prefix='nr-health-cycle-') as td:
    root = Path(td)
    f = Fixture(root / 'many')
    f.run()
    check(all(f.cache()[i][0] == f.expected_signature(i) for i in range(1, 33)), 'all 32 signatures equal the prior per-device byte sequence')
    expected_calls = ['ip -o link show', 'ip -o -4 addr show', 'wg show all peers', 'wg show all allowed-ips', 'wg show all endpoints']
    check(f.lines('commands') == expected_calls, '32 exits use exactly two global ip and three public WG captures')
    check(len(f.lines('probes')) == 4, 'first cycle retains the four-exit probe bound')
    for tick in range(1, 8):
        (f.root / 'now').write_text(str(100 + tick * 3))
        f.run()
    check(len(f.lines('probes')) == 32 and len(set(f.lines('probes'))) == 32, 'eight cycles still sample 32 exits without starvation')
    check(all(v == (1, 1) for v in f.health().values()), 'every successfully sampled exit is healthy')
    check(f.lines('commands') == expected_calls * 8, 'inventory is fresh exactly once on every invocation')

    # Keep the clock fixed so only public identity changes invalidate the cache.
    old = f.cache()
    f.peer_fields['endpoints']['wg9'] = 'public-9-a\t203.0.113.9:60123\npublic-9-b\t(none)\n'
    f.write_inventory(); f.clear_commands(); before = len(f.lines('probes'))
    f.run()
    check(f.cache()[9][0] != old[9][0] and f.cache()[9][0] == f.expected_signature(9), 'a peer IP and port change is visible on the next cycle')
    check('9' in f.lines('probes')[before:], 'changed endpoint is re-probed without waiting for old TTL')
    check(f.cache()[1][0] == old[1][0] and f.cache()[32][0] == old[32][0], 'unrelated interface signature bytes stay identical')
    check(f.lines('commands') == expected_calls, 'endpoint refresh does not add per-interface kernel reads')

    # The configured exit can disappear while the global command still succeeds.
    f.links.pop('wg2'); f.addresses.pop('wg2')
    for field in f.peer_fields.values(): field.pop('wg2')
    f.write_inventory(); before = len(f.lines('probes')); f.run()
    check(f.health()[2] == (0, 1), 'missing interface is known down, not cached healthy')
    check('2' not in f.lines('probes')[before:], 'missing interface never launches a network probe')
    check(f.cache()[2][0] == f.expected_signature(2), 'disappeared interface has the same empty public fields as prior reads')

    # A partial producer error cannot commit a mixed or false-positive snapshot.
    for kind in ['links', 'addresses', 'peers', 'allowed-ips', 'endpoints']:
        fail = f.root / ('fail.' + kind); fail.touch()
        before = {name: (f.root / name).read_bytes() for name in ['exit-health-cache', 'exit-health', 'published', 'probes']}
        f.run(success=False)
        check(all((f.root / name).read_bytes() == content for name, content in before.items()), kind + ' read failure preserves all previously published state and starts no probes')
        check(not list(f.root.glob('.health.*')), kind + ' read failure removes partial private snapshot')
        fail.unlink()
    f.run()
    check(not list(f.root.glob('.health.*')), 'successful cycle also removes its private inventory')

    f = Fixture(root / 'wan', 1)
    (f.root / 'exits').write_text('1 wan1 wan1_ad 1\n')
    (f.root / 'input-links').write_text('12: wan1_ad: <POINTOPOINT,UP,LOWER_UP> mtu 1492\n')
    (f.root / 'input-addresses').write_text('12: wan1_ad    inet 192.0.2.4 peer 192.0.2.1/32 scope global wan1_ad\n')
    f.run()
    check(f.health()[1] == (1, 1), 'PPPoE address on the real _ad device remains sufficient')
    check(f.lines('commands') == expected_calls[:2], 'WAN-only cycle does not invoke WG')
    check(not f.lines('probes'), 'WAN-only cycle keeps native health without new probes')

print(f'health-cycle-inventory: {checks} checks passed')
