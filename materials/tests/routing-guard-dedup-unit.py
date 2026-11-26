#!/usr/bin/env python3
"""Run the real guard emitters; compare first-install rules and repeated paths.

Only command inputs/outputs are isolated. No firewall, VM or configuration is
changed. Final-artifact traffic/failover checks are required separately.
"""
from pathlib import Path
import json
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'materials/firmware/port-3726/files/usr/ikuai/script/native_runtime.sh'
checks = 0


def check(value, reason):
    global checks
    assert value, reason
    checks += 1


def exit_reference(mark, dev, windows):
    """Original complete bundle: every OR window, then one terminal DROP."""
    rows = []
    for table, chain in [('filter', 'NR_FWD'), ('mangle', 'NR_EGRESS')]:
        prefix = ['-t', table, '-A', chain, '-m', 'connmark', '--mark', str(mark)]
        for window in windows.split('\n'):
            rows.append(prefix + shlex.split(window) + ['-m', 'conntrack', '--ctdir', 'REPLY', '-j', 'RETURN'])
            rows.append(prefix + shlex.split(window) + ['-o', dev, '-j', 'RETURN'])
        rows.append(prefix + ['-j', 'DROP'])
    return rows


def fallback_reference(pid, base, windows):
    rows = []
    for table, chain in [('filter', 'NR_FWD'), ('mangle', 'NR_EGRESS')]:
        prefix = ['-t', table, '-A', chain, '-m', 'connmark', '--mark', str(base)]
        for window in windows.split('\n'):
            rows.append(prefix + shlex.split(window) + ['-g', 'NR_B' + str(pid)])
        rows.append(prefix + ['-j', 'DROP'])
    nat = ['-t', 'nat', '-A', 'NR_NAT', '-m', 'connmark', '--mark', str(base) + '/0xffffff00']
    return rows + [nat + ['-p', 'tcp', '-j', 'MASQUERADE', '--random-fully'], nat + ['-j', 'MASQUERADE']]


def classification(rows):
    return [r for r in rows if '-A' in r and r[r.index('-A')+1] in ['NR_CLASS', 'NR_LOWER', 'NR_FALLBACK']]


def guards(rows):
    return [r for r in rows if '-A' in r and r[r.index('-A')+1] in ['NR_FWD', 'NR_EGRESS', 'NR_NAT']]


with tempfile.TemporaryDirectory(prefix='routing-guard-dedup-') as folder:
    temp = Path(folder)
    script = temp / 'runtime.sh'
    script.write_text(SOURCE.read_text().replace('source /usr/ikuai/script/native_exit_health.sh', ':'))
    state = temp / 'state'
    (state / 'active').mkdir(parents=True)
    (state / 'active/dns-bindings').write_text('')
    prelude = f'''
set -e -o pipefail
source {shlex.quote(str(script))}
NR={shlex.quote(str(state))}
calls=0
nr_ipt(){{
 calls=$((calls+1)); printf 'IPT'; printf '\t%s' "$@"; printf '\n'
 [ "${{FAIL_AFTER:-0}}" != "$calls" ]
}}
ipset(){{ [ "$*" = 'create nr_hy_direct hash:net,net family inet maxelem 65536 -exist' ]; }}
nr_owner_routes_begin(){{ :; }}
nr_reset_evidence(){{ :; }}
'''

    def run(body):
        (state / 'exits').write_text('1 wan1 wan1_ad 1\n2 wg2 wg2 1\n')
        (state / 'policies').write_text('7 1,2 6 0\n8 1,2 6 1\n9 2 0 1\n10 2 0 1\n11 0 0 1\n')
        result = subprocess.run(['bash'], input=prelude + body, text=True, capture_output=True)
        check(result.returncode == 0, result.stderr + result.stdout)
        return [line.split('\t')[1:] for line in result.stdout.splitlines() if line.startswith('IPT\t')], result.stdout

    bound = 0x55000000 + 9 * 256 + 2
    one, _ = run("nr_policy_rule '-s 198.18.1.2/32 -p tcp' 9 ''\n")
    check(guards(one) == exit_reference(bound, 'wg2', ''), 'nonduplicated single-bound rules match the original argv and order')
    many, _ = run("""
nr_policy_rule '-s 198.18.1.2/32 -p tcp' 9 ''
nr_policy_rule '-s 198.18.1.2/32 -p udp' 9 ''
""")
    check(guards(many) == guards(one), 'TCP+UDP alternatives install one complete bound guard bundle')
    expected = []
    for proto in ['tcp', 'udp']:
        prefix = ['-t', 'mangle', '-A', 'NR_CLASS', '-s', '198.18.1.2/32', '-p', proto]
        expected += [prefix + ['-j', 'MARK', '--set-mark', str(bound)], prefix + ['-j', 'CONNMARK', '--save-mark'], prefix + ['-j', 'ACCEPT']]
    check(classification(many) == expected, 'all classifier alternatives remain in their original order')
    check(len(guards(one))*2 == 12 and len(guards(many)) == 6, 'two alternative bound guards shrink from 12 rules to 6')

    windows = '-m time --weekdays 1 --timestart 08:00:00 --timestop 09:00:59\n-m time --weekdays 1 --timestart 18:00:00 --timestop 19:00:59'
    freebase = 0x58000000 + 7 * 256
    call = "nr_policy_rule '-s 198.18.1.2/32 -m set --match-set nr_d_1 dst,src' 7 " + shlex.quote(windows) + '\n'
    reference = exit_reference(freebase+1, 'wan1_ad', windows) + exit_reference(freebase+2, 'wg2', windows) + fallback_reference(7, freebase, windows)
    single, _ = run(call)
    check(guards(single) == reference, 'nonduplicated multi-exit guards, fallback gates and NAT retain original argv order')
    repeated, _ = run(call + call.replace('nr_d_1', 'nr_h_1') + call.replace('nr_d_1', 'nr_extra_1'))
    check(guards(repeated) == reference, 'three classification paths share only their identical candidate/fallback bundles')
    check(len(classification(repeated)) == 3 and all(r[-2:] == ['-j', 'NR_P7'] for r in classification(repeated)), 'every multi-exit classifier still reaches its policy selector')
    check(len(reference)*3 == 84 and len(guards(repeated)) == 28, 'two exits/two windows/three alternatives reduce 84 guard+NAT rows to 28')
    for chain in ['NR_FWD', 'NR_EGRESS']:
        for mark in [freebase+1, freebase+2, freebase]:
            rows = [r for r in guards(repeated) if r[3] == chain and r[7] == str(mark)]
            check(rows[-1][-2:] == ['-j', 'DROP'], 'each distinct candidate/fallback identity retains its terminal guard')
    check(all(r[-2] == '-g' for r in guards(repeated) if 'NR_B7' in r), 'fallback uses goto, not global ACCEPT')

    independent, _ = run("nr_policy_rule '-s 198.18.1.2' 9 ''\nnr_policy_rule '-s 198.18.1.3' 10 ''\n")
    check(guards(independent) == exit_reference(bound, 'wg2', '') + exit_reference(0x55000000+10*256+2, 'wg2', ''), 'different rule policy IDs on the same exit remain independent')
    isolated, _ = run("nr_policy_rule '-s 198.18.1.2' 7 ''\nnr_policy_rule '-s 198.18.1.3' 8 ''\n")
    wanted = exit_reference(freebase+1, 'wan1_ad', '') + exit_reference(freebase+2, 'wg2', '') + fallback_reference(7, freebase, '')
    boundbase = 0x55000000 + 8 * 256
    wanted += exit_reference(boundbase+1, 'wan1_ad', '') + exit_reference(boundbase+2, 'wg2', '')
    check(guards(isolated) == wanted, 'bound and unbound strategies sharing exits are never merged')
    check(not any('NR_B8' in r for r in guards(isolated)), 'bound policy does not gain a main fallback gate')

    first, second = windows.split('\n')
    for first_dev, second_dev, a, b, reason in [
            ('wg2', 'wan1_ad', '', '', 'real device'),
            ('wg2', 'wg2', first, second, 'time window'),
            ('wg2', 'wg2', windows, second+'\n'+first, 'OR window order'),
            ('wg2', 'wg2', '', first, 'unrestricted versus restricted window')]:
        rows, _ = run('nr_exit_guard ' + ' '.join(map(shlex.quote, [str(bound), first_dev, a])) + '\n' +
                      'nr_exit_guard ' + ' '.join(map(shlex.quote, [str(bound), second_dev, b])) + '\n')
        check(guards(rows) == exit_reference(bound, first_dev, a) + exit_reference(bound, second_dev, b), reason + ' differences are preserved without time union')
    blackhole, _ = run("nr_policy_rule '-s 198.18.1.2/32' 11 ''\n")
    check(blackhole == [['-t', 'mangle', '-A', 'NR_CLASS', '-s', '198.18.1.2/32', '-j', 'DROP']], 'blackhole behavior does not acquire an exit allowance')

    failed, text = run(f'''
FAIL_AFTER=2
if nr_exit_guard {bound} wg2 '';then echo BAD_SUCCESS;else echo EXPECTED_ERROR;fi
printf 'FAILED_KEYS:%s\n' "${{#NR_GUARD_KEYS[@]}}"
FAIL_AFTER=0
nr_exit_guard {bound} wg2 ''
printf 'RECOVERED_KEYS:%s\n' "${{#NR_GUARD_KEYS[@]}}"
''')
    check('EXPECTED_ERROR' in text and 'BAD_SUCCESS' not in text and 'FAILED_KEYS:0' in text, 'failed partial installation is never recorded as a completed guard')
    check(failed[2:] == exit_reference(bound, 'wg2', '') and 'RECOVERED_KEYS:1' in text, 'retry after failure reinstalls the whole original bundle')
    for command, failure, expected, reason in [
            (f"nr_exit_guard {bound} wg2 ''", 4, exit_reference(bound, 'wg2', ''), 'after filter has completed'),
            (f"nr_exit_guard {bound} wg2 ''", 6, exit_reference(bound, 'wg2', ''), 'at final mangle DROP'),
            (f"nr_fallback_guard 7 {freebase} ''", 6, fallback_reference(7, freebase, ''), 'at second NAT append')]:
        emitted, text = run(f'''
FAIL_AFTER={failure}
if {command};then echo BAD_SUCCESS;else echo EXPECTED_ERROR;fi
printf 'FAILED_KEYS:%s\n' "${{#NR_GUARD_KEYS[@]}}"
FAIL_AFTER=0
{command}
''')
        check('EXPECTED_ERROR' in text and 'BAD_SUCCESS' not in text and 'FAILED_KEYS:0' in text, reason + ' failure is not recorded as success')
        check(emitted[failure:] == expected, reason + ' retry reinstalls the complete original bundle')
    reapply, text = run(f'''
nr_exit_guard {bound} wg2 ''
nr_begin >/dev/null
printf 'RESET_KEYS:%s\n' "${{#NR_GUARD_KEYS[@]}}"
nr_exit_guard {bound} wg2 ''
printf 'REAPPLY_KEYS:%s\n' "${{#NR_GUARD_KEYS[@]}}"
''')
    check('RESET_KEYS:0' in text and 'REAPPLY_KEYS:1' in text, 'full apply clears deduplication state and installs guards again')
    check(reapply == exit_reference(bound, 'wg2', '') * 2, 'full apply emits the original guard again rather than only restoring its bookkeeping')

print(json.dumps({'suite': 'routing guard deduplication', 'checks': checks, 'status': 'passed',
                  'bound_two_alternatives': {'before': 12, 'after': 6},
                  'multi_three_alternatives': {'before': 84, 'after': 28},
                  'scope': 'real shell emitters; final kernel traffic/failover validation required'}))
