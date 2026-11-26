#!/usr/bin/env python3
"""Bounded recovery scheduling using the shipped function, without a router."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'firmware/port-3726/files/usr/ikuai/script/native_rules.sh').read_text()
start = source.index('nr_failed_ingress_reconcile(){')
end = start + re.search(r'^\}', source[start:], re.M).end()
program = source[start:end].replace('/proc/uptime', '"$TEST_ROOT/uptime"')
program = program.replace('/sys/class/net/', '$TEST_ROOT/net/')
program = program.replace('/usr/ikuai/script/native_ingress.sh up', 'repair')
count = 0

def check(ok, label):
    global count
    assert ok, label
    count += 1

with tempfile.TemporaryDirectory(prefix='nr-ingress-recovery-') as td:
    p = Path(td)
    (p / 'net').mkdir()
    for name in ['wg1', 'wg2', 'wg3', 'wg4']:
        (p / 'net' / name).mkdir()
        (p / 'net' / name / 'ifindex').write_text(name[2:] + '\n')
    (p / 'exits').write_text('1 wg1 wg1 1\n2 wg2 wg2 1\n3 wg3 wg3 1\n4 wg4 wg4 0\n5 wan1 wan1 1\n6 wg6 wg6 1\n')
    (p / 'exit-health').write_text('1 1 1\n2 0 1\n3 0 0\n4 0 1\n5 0 1\n6 0 1\n')
    (p / 'calls').write_text('')
    stubs = '''repair(){
 printf '%s\n' "$1" >> "$TEST_ROOT/calls"
 [ ! -f "$TEST_ROOT/fail" ] && [ ! -f "$TEST_ROOT/fail-$1" ]
}
'''
    def run(now):
        (p / 'uptime').write_text(str(now) + '.00 0.00\n')
        return subprocess.run(['bash', '-c', stubs + program + '\nnr_failed_ingress_reconcile'],
                              env=dict(os.environ, TEST_ROOT=str(p), NR=str(p)),
                              capture_output=True, text=True, timeout=5)
    def calls():
        return (p / 'calls').read_text().splitlines()
    check(run(100).returncode == 0 and calls() == ['wg2'], 'only existing, available, known-failed WG exit is audited')
    check(run(103).returncode == 0 and calls() == ['wg2'], 'normal three-second poll does not repeat tc work')
    check(run(129).returncode == 0 and len(calls()) == 1, 'throttle remains active through 29 seconds')
    check(run(130).returncode == 0 and calls() == ['wg2', 'wg2'], 'persistent failure gets a bounded later audit')
    check(run(20).returncode == 0 and len(calls()) == 3, 'uptime rollback does not retain stale suppression')
    (p / 'ingress-recovery/wg2').write_text('invalid\n')
    check(run(21).returncode == 0 and len(calls()) == 4, 'invalid audit marker cannot suppress recovery')
    (p / 'exit-health').write_text('1 1 1\n2 1 1\n3 0 0\n4 0 1\n5 0 1\n')
    check(run(1000).returncode == 0 and len(calls()) == 4, 'healthy exits never enter the tc audit path')
    (p / 'exit-health').write_text('2 0 1\n')
    (p / 'fail').touch()
    check(run(1001).returncode != 0, 'repair error is propagated to the caller')
    check((p / 'ingress-recovery/wg2').read_text().strip() == '1001 2 0', 'failed attempt is recorded without claiming success')
    (p / 'fail').unlink()
    check(run(1002).returncode == 0 and len(calls()) == 6, 'next poll retries a failed repair')
    (p / 'exit-health').unlink()
    check(run(2000).returncode == 0 and len(calls()) == 6, 'missing health evidence does not guess failed exits')

    (p / 'exit-health').write_text('2 0 1\n')
    (p / 'calls').write_text('')
    (p / 'ingress-recovery/wg2').write_text('3000 2 1\n')
    check(run(3001).returncode == 0 and not calls(), 'unchanged interface identity retains successful throttle')
    (p / 'net/wg2/ifindex').write_text('202\n')
    check(run(3002).returncode == 0 and calls() == ['wg2'], 'same-name interface rebuild bypasses recent successful throttle')
    check((p / 'ingress-recovery/wg2').read_text().strip() == '3002 202 1', 'successful marker uses the new ifindex')
    check(run(3003).returncode == 0 and len(calls()) == 1, 'new identity is throttled after its successful repair')
    (p / 'exits').write_text('2 wg2 wg2 1\n7 wg2 wg2 1\n')
    (p / 'exit-health').write_text('2 0 1\n7 0 1\n')
    check(run(3032).returncode == 0 and len(calls()) == 2, 'duplicate exit references audit their shared interface once')
    for marker in ['08 202 1\n', '9999999999999999999999 202 1\n', '3032 202 1 extra\n', '3032\n']:
        (p / 'ingress-recovery/wg2').write_text(marker)
        before = len(calls())
        check(run(3033).returncode == 0 and len(calls()) == before + 1, 'corrupt/legacy marker cannot suppress recovery: ' + marker.strip())

    # A realistic maximum set of failed exits is audited in bounded, fair batches.
    for i in range(1, 33):
        d = p / f'net/wg{i}'
        d.mkdir(exist_ok=True)
        (d / 'ifindex').write_text(str(i) + '\n')
    (p / 'exits').write_text(''.join(f'{i} wg{i} wg{i} 1\n' for i in range(1, 33)))
    (p / 'exit-health').write_text(''.join(f'{i} 0 1\n' for i in range(1, 33)))
    for f in (p / 'ingress-recovery').iterdir():
        f.unlink()
    (p / 'calls').write_text('')
    for batch in range(8):
        before = len(calls())
        check(run(4000 + batch * 3).returncode == 0 and len(calls()) - before == 4,
              f'32 failed exits: batch {batch + 1} performs exactly four audits')
    check(len(calls()) == len(set(calls())) == 32, 'all 32 failed exits receive a first audit without repeats or starvation')
    check(run(4024).returncode == 0 and len(calls()) == 32, 'all successful audits remain suppressed before their own 30-second deadline')
    check(run(4030).returncode == 0 and calls()[32:] == calls()[:4], 'oldest successful batch becomes eligible first')
    before = len(calls())
    check(run(1).returncode == 0 and len(calls()) - before == 4, 'uptime rollback re-enables audits but preserves the four-interface budget')

    # A permanently failing helper remains retryable and does not monopolize
    # the oldest-attempt queue while other exits have never been inspected.
    for f in (p / 'ingress-recovery').iterdir():
        f.unlink()
    (p / 'calls').write_text('')
    (p / 'fail-wg1').touch()
    for batch in range(9):
        before = len(calls())
        result = run(5000 + batch * 3)
        check(0 < len(calls()) - before <= 4, 'persistent failure still respects the per-pass attempt budget')
        check(result.returncode != 0, 'later successful batches cannot release the guard while an earlier failed repair remains unresolved')
    check(set(calls()) == {f'wg{i}' for i in range(1, 33)}, 'a persistently failing first interface does not starve the other 31 exits')
    check(calls().count('wg1') == 2 and result.returncode != 0, 'failed interface is retried after older pending interfaces and still reports failure')
    (p / 'fail-wg1').unlink()
    check(run(5027).returncode == 0 and calls()[-1] == 'wg1', 'failure is eligible again next poll despite a fresh attempt marker')

    (p / 'calls').write_text('')
    (p / 'exit-health').write_text(''.join(f'{i} 1 1\n' for i in range(1, 33)))
    check(run(6000).returncode == 0 and not calls(), '32 healthy interfaces perform no ingress helper work')

print(f'failed-ingress-reconcile: {count} checks passed')
