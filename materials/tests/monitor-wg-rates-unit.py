#!/usr/bin/env python3
"""Real monitor shell/awk rate sampling, including concurrent shell processes.

All input counters, interfaces and clocks are synthetic. A tiny flock adapter
uses the host kernel fcntl.flock on the inherited descriptor (not a lock mock),
allowing the real bounded-retry shell path to run on macOS as well as Linux.
No device, service, network, production configuration or firmware is changed.
"""
from pathlib import Path
import concurrent.futures
import fcntl
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / 'materials/firmware/port-3726/files/usr/ikuai/script/monitor_lanip.sh').read_text()


def function(name):
    return re.search(r'^' + name + r'\(\)\s*\{.*?^\}', SOURCE, re.M | re.S).group()


checks = 0


def check(value, message):
    global checks
    assert value, message
    checks += 1


with tempfile.TemporaryDirectory(prefix='monitor-wg-rates-') as directory:
    temp = Path(directory)
    runtime, network, binpath = temp / 'runtime', temp / 'net', temp / 'bin'
    for path in (runtime, network, binpath):
        path.mkdir()
    peers, stats, transfer, handshakes, endpoints, uptime, calls = [temp / name for name in
        ('peers', 'stats', 'transfer', 'handshakes', 'endpoints', 'uptime', 'calls')]
    for iface, index in [('wg8', 48), ('wg9', 49)]:
        (network / iface).mkdir()
        (network / iface / 'ifindex').write_text(str(index) + '\n')
    flock = binpath / 'flock'
    flock.write_text('#!' + sys.executable + '\nimport fcntl,sys\ntry: fcntl.flock(int(sys.argv[-1]),fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError: sys.exit(1)\n')
    flock.chmod(0o755)
    wg = binpath / 'wg-fixture'
    wg.write_text('''#!/bin/sh
printf '%s\\n' "$3" >> "$FIXTURE/calls"
case "$3" in
 transfer) [ "${TRANSFER_FAIL:-0}" = 1 ] && exit 1
   [ -n "$TRANSFER_DELAY" ] && sleep "$TRANSFER_DELAY"
   cat "$FIXTURE/transfer";;
 latest-handshakes) cat "$FIXTURE/handshakes";;
 endpoints) cat "$FIXTURE/endpoints";;
esac
''')
    wg.chmod(0o755)
    env = dict(os.environ, PATH=str(binpath) + os.pathsep + os.environ['PATH'], FIXTURE=str(temp))
    definitions = '\n'.join(function(name) for name in ('__wg_monitor_sample', '__wg_monitor_data'))
    definitions = definitions.replace('/tmp/iktmp', str(runtime)).replace('/proc/ikuai/stats/host_stats', str(stats))
    definitions = definitions.replace('/proc/uptime', str(uptime)).replace('/sys/class/net/', str(network) + '/')
    dependencies = '''
sqlite3(){ cat "$FIXTURE/peers"; }
__wg_bin(){ echo "$FIXTURE/bin/wg-fixture"; }
conntrack(){ :; }
'''
    cache = runtime / 'wireguard/monitor/rates.tsv'
    lock = runtime / 'wireguard/monitor/lock'
    peers.write_text('1|wg9|pub9|198.18.1.2/32|phone\n')
    stats.write_text('')
    handshakes.write_text('wg9\tpub9\t1000\n')
    endpoints.write_text('wg9\tpub9\t192.0.2.9:51820\n')

    def inputs(clock, rx, tx):
        uptime.write_text(str(clock) + ' 0\n')
        transfer.write_text(f'wg9\tpub9\t{rx}\t{tx}\n')

    def run(extra_env=None, prefix=''):
        result = subprocess.run(['bash', '-c', dependencies + definitions + '\n' + prefix + '\n__wg_monitor_data\n'],
                                text=True, capture_output=True, env={**env, **(extra_env or {})}, timeout=8)
        assert result.returncode == 0, result.stderr
        assert 'awk:' not in result.stderr and 'syntax error' not in result.stderr, result.stderr
        return json.loads(result.stdout)

    def row(extra_env=None, prefix=''):
        return run(extra_env, prefix)[0]

    def rate(value):
        return value['upload'], value['download']

    def cached():
        return {tuple(fields[:2]): fields for fields in (line.split('\t') for line in cache.read_text().splitlines())}

    inputs(100, 1000, 5000)
    check(rate(row()) == (0, 0), 'first observation establishes a zero-rate baseline')
    inputs(102, 13000, 65000)
    check(rate(row()) == (6000, 30000), 'missing native row uses monotonic WG counter deltas')
    check(cached()[('wg9', 'pub9')][4:7] == ['102.00', '13000', '65000'], 'sampling baseline is persisted without integer truncation')
    inputs(102.20, 19000, 95000)
    check(rate(row()) == (6000, 30000), 'subsecond request reuses the last completed rate')
    check(cached()[('wg9', 'pub9')][4:7] == ['102.00', '13000', '65000'], 'subsecond request does not consume the counter/time baseline')
    inputs(104, 25000, 125000)
    check(rate(row()) == (6000, 30000), 'next full interval includes traffic since the original baseline')

    # Multiple independent shells reach the real kernel flock concurrently.
    # None may replace a useful rate with zero or expose partial cache contents.
    inputs(106, 37000, 185000)
    reader_stop = threading.Event()
    reader_failures = []

    def read_cache():
        while not reader_stop.is_set():
            try:
                lines = cache.read_text().splitlines()
                if len(lines) != 1 or len(lines[0].split('\t')) != 9:
                    reader_failures.append('partial cache')
            except Exception as error:
                reader_failures.append(type(error).__name__)
            time.sleep(.001)

    reader = threading.Thread(target=read_cache)
    reader.start()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            concurrent_rows = list(pool.map(lambda _: row({'TRANSFER_DELAY': '.03'}), range(4)))
    finally:
        reader_stop.set()
        reader.join()
    check(all(rate(value) == (6000, 30000) for value in concurrent_rows), 'four concurrent shell pollers preserve one consistent nonzero rate')
    check(not reader_failures, 'concurrent readers see only complete atomically replaced caches')

    stats.write_text('198.18.1.2 0 5 0 0\n')
    inputs(108, 49000, 245000)
    check(rate(row()) == (0, 0), 'present native zero rates remain authoritative')
    stats.write_text('198.18.1.2 0 5 77 88\n')
    inputs(110, 61000, 305000)
    check(rate(row()) == (77, 88), 'present native rates override calculated peer rates')
    stats.write_text('')
    inputs(112, 73000, 365000)
    check(rate(row()) == (6000, 30000), 'fallback has a current baseline when native statistics disappear')
    inputs(114, 73000, 365000)
    check(rate(row()) == (0, 0), 'idle traffic becomes zero after the next complete sampling interval')
    inputs(145, 83000, 465000)
    check(rate(row()) == (0, 0), 'a sampling gap above thirty seconds discards stale averages')
    inputs(147, 95000, 525000)
    check(rate(row()) == (6000, 30000), 'fresh rate recovers after the long-gap baseline')
    inputs(149, 100, 200)
    check(rate(row()) == (0, 0), 'counter rollback establishes a new baseline without negative rates')
    inputs(151, 300, 600)
    check(rate(row()) == (100, 200), 'counter reset recovery uses only new counter increments')
    inputs(10, 10000, 20000)
    check(rate(row()) == (0, 0), 'monotonic time rollback resets even when counters increased')
    inputs(12, 10200, 20400)
    check(rate(row()) == (100, 200), 'time reset recovery produces correct subsequent rates')

    (network / 'wg9/ifindex').write_text('149\n')
    inputs(14, 1000000, 2000000)
    check(rate(row()) == (0, 0), 'recreated interface resets even if its new counters exceed the old counters')
    inputs(16, 1000200, 2000400)
    check(rate(row()) == (100, 200), 'recreated interface obtains an independent baseline')
    peers.write_text('17|wg9|pub9|198.18.1.2/32|replacement\n')
    inputs(18, 2000000, 3000000)
    check(rate(row()) == (0, 0), 'replacement configuration peer identity does not inherit a previous rate')
    inputs(20, 2000200, 3000400)
    check(rate(row()) == (100, 200), 'replacement peer rate recovers normally')
    inputs(22, 2000300, 3000600)
    before_failure = cache.read_bytes()
    failed_sample = subprocess.run(['bash', '-c', dependencies + definitions + '\n__wg_monitor_data\n'],
                                  text=True, capture_output=True, env={**env, 'TRANSFER_FAIL': '1'}, timeout=8)
    check(failed_sample.returncode != 0 and not failed_sample.stdout and cache.read_bytes() == before_failure,
          'transfer failure fails the snapshot, publishes no stale rate and preserves the last good cache')

    # Hold the same lock in a different real process. Timeout is bounded and
    # killing the holder releases the kernel lock despite the lock file staying.
    ready = temp / 'holder-ready'
    holder_code = 'import fcntl,os,time; f=open(' + repr(str(lock)) + ',"w"); fcntl.flock(f,fcntl.LOCK_EX); open(' + repr(str(ready)) + ',"w").close(); time.sleep(10)'
    holder = subprocess.Popen([sys.executable, '-c', holder_code])
    try:
        deadline = time.monotonic() + 3
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        assert ready.exists()
        began = time.monotonic()
        value = row()
        waited = time.monotonic() - began
        check(rate(value) == (0, 0) and cache.read_bytes() == before_failure and waited < 4,
              'occupied lock times out without stale output or cache mutation')
    finally:
        holder.kill()
        holder.wait()
    check(rate(row()) == (50, 100), 'terminated lock owner cannot leave a stale held lock')
    before_unavailable = cache.read_bytes()
    inputs(24, 2000500, 3001000)
    unavailable = 'command(){ if [ "$1" = -v ] && [ "$2" = flock ]; then return 1; else builtin command "$@"; fi; }'
    check(rate(row(prefix=unavailable)) == (0, 0) and cache.read_bytes() == before_unavailable,
          'missing flock degrades only optional rates without blocking or corrupting cache')
    stats.write_text('198.18.1.2 0 2 11 22\n')
    check(rate(row(prefix=unavailable)) == (11, 22), 'native rates survive unavailable optional locking')
    stats.write_text('')
    cache.write_text('malformed cache\n')
    check(rate(row()) == (0, 0), 'malformed cache establishes a clean baseline')

    peers.write_text('1|wg8|shared|198.18.1.2/32|first\n2|wg9|shared|198.18.2.2/32|second\n')
    handshakes.write_text('wg8\tshared\t1000\nwg9\tshared\t2000\n')
    endpoints.write_text('wg8\tshared\t192.0.2.8:51820\nwg9\tshared\t192.0.2.9:51821\n')
    uptime.write_text('30 0\n')
    transfer.write_text('wg8\tshared\t111\t222\nwg9\tshared\t333\t444\n')
    values = run()
    check([[v['total_up'], v['total_down']] for v in values] == [[111, 222], [333, 444]], 'same public key across interfaces has independent totals')
    check([v['latest_handshake'] for v in values] == [1000, 2000] and [v['endpoint'] for v in values] == ['192.0.2.8:51820', '192.0.2.9:51821'],
          'same public key across interfaces has independent handshakes and endpoints')
    uptime.write_text('32 0\n')
    transfer.write_text('wg8\tshared\t131\t262\nwg9\tshared\t393\t544\n')
    values = run()
    check([rate(v) for v in values] == [(10, 20), (30, 50)], 'same public key across interfaces has independent rate baselines')
    check(len(cached()) == 2, 'removed peers are pruned when a new snapshot is committed')

    peers.write_text('1|wg9|pub9|198.18.1.2/32|wide\n')
    inputs(40, 8589934593, 17179869186)
    row()
    inputs(42, 17179869193, 34359738586)
    value = row()
    check(rate(value) == (4294967300, 8589934700) and value['total_up'] == 17179869193 and value['total_down'] == 34359738586,
          'counter and derived rate output retains values above signed and unsigned 32-bit boundaries')
    check(value['ip_addr_int'] == 3323068674, 'high IPv4 numeric sort key remains unchanged')

    handshakes.write_text('pub9\t1000\n')
    endpoints.write_text('pub9\t192.0.2.9:51820\n')
    uptime.write_text('44 0\n')
    transfer.write_text('pub9\t17179869393\t34359738986\n')
    value = row()
    check(rate(value) == (100, 200) and value['latest_handshake'] == 1000 and value['endpoint'] == '192.0.2.9:51820',
          'legacy output without interface is supported only for uniquely attributable public keys')
    peers.write_text('1|wg8|pub9|198.18.1.2/32|first\n2|wg9|pub9|198.18.2.2/32|second\n')
    check(all(v['total_up'] == 0 and v['latest_handshake'] == 0 and v['endpoint'] == '' for v in run()),
          'ambiguous legacy output is not attributed to either interface')
    leftovers = [p.name for p in (runtime / 'wireguard').glob('monitor_*')]
    check(not leftovers, 'per-request snapshot files are removed: ' + repr(leftovers))
    check({p.name for p in cache.parent.iterdir()} == {'lock', 'rates.tsv'}, 'atomic cache staging files are removed')
    check(cache.stat().st_mode & 0o777 == 0o600 and cache.parent.stat().st_mode & 0o777 == 0o700, 'rate cache uses private file and directory permissions')

print('PASS:', checks, 'WG monitor rate checks; actual shell/awk and concurrent processes with kernel flock')
