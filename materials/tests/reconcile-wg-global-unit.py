#!/usr/bin/env python3
"""Actual reconcile WG branch with isolated kernel/process fixtures."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'firmware/port-3726/files/usr/ikuai/script/native_rules.sh'
source = SOURCE.read_text()
start = re.search(r'^reconcile\(\)\{', source, re.M).start()
end = start + re.search(r'^\}', source[start:], re.M).end()
program = source[start:end].replace('/proc/', '$PROC_FIXTURE/').replace('/sys/class/net/', '$NET_FIXTURE/')
program = program.replace('/usr/ikuai/script/native_dns_bind.sh check', 'stub_bind')
checks = 0


def check(ok, message):
    global checks
    assert ok, message
    checks += 1


STUBS = r'''
log(){ printf '%s\n' "$*" >> "$STATE/events"; }
ensure_conf(){ :; }
lock_action(){ :; }
stub_bind(){ return 0; }
apply_config(){ log unexpected-apply; return 90; }
guard(){ log guard; }
unguard(){ log unguard; }
nr_wg_transport_sync(){ log transport;[ ! -f "$STATE/transport-fail" ]; }
nr_failed_ingress_reconcile(){ log ingress;[ ! -f "$STATE/ingress-fail" ]; }
nr_probe_owner_routes_sync(){ log owner-routes;[ "$1" = '0: from all lookup local' ] && [ ! -f "$STATE/owner-fail" ]; }
nr_policy_reconcile(){ log policy; }
restart_changed_workers(){ log restart-workers;[ ! -f "$STATE/worker-fail" ]; }
stop_dns(){ log unexpected-stop-dns;return 91; }
start_dns(){ log unexpected-start-dns;return 91; }
ip(){
 log "ip $*"
 case "$*" in '-o link show '*)
  [ ! -f "$NET_FIXTURE/$4/down" ] || return 0
  printf '1: %s: <UP,LOWER_UP>\n' "$4";;
  'route replace default dev '*) return 0;;
  'rule show') [ ! -f "$STATE/read-fail" ] || return 1;echo '0: from all lookup local';;
  *) return 92;;
 esac
}
wg(){
 log "wg $*"
 case "$1:$3" in
  show:fwmark) cat "$NET_FIXTURE/$2/mark";;
  set:fwmark) printf '%s\n' "$4" > "$NET_FIXTURE/$2/mark";;
  *) return 93;;
 esac
}
nr_ipt(){
 log "iptables $*"
 local operation chain
 [ "$1" != -t ] || shift 2
 operation="$1";chain="$2"
 if [ "$operation" = -C ];then [ -f "$STATE/$chain" ];return;fi
 [ "$operation" = -I ] || return 94
 [ ! -f "$STATE/insert-fail" ] || return 1
 [ ! -f "$STATE/insert-fail-$chain" ] || return 1
 touch "$STATE/$chain"
}
'''


with tempfile.TemporaryDirectory(prefix='nr-reconcile-global-') as td:
    root = Path(td)
    failures = {'insert-fails': 'insert-fail', 'insert-filter-fails': 'insert-fail-NR_OUTPUT',
                'read-fails': 'read-fail', 'ingress-fails': 'ingress-fail',
                'owner-fails': 'owner-fail', 'transport-fails': 'transport-fail', 'worker-fails': 'worker-fail'}
    for scenario in ['existing', 'missing', 'none', *failures]:
        state = root / scenario
        for p in ['nr/active', 'proc/100', 'proc/101', 'net', 'region', 'domain']:
            (state / p).mkdir(parents=True)
        (state / 'nr/active/front.pid').write_text('100')
        (state / 'nr/active/dns-base.pid').write_text('101')
        (state / 'nr/active/dns-ids').write_text('')
        (state / 'proc/100/cmdline').write_text('native-rule-dns')
        (state / 'proc/101/cmdline').write_text('strict-dnsmasq')
        (state / 'events').write_text('')
        (state / 'nr/exits').write_text(''.join(f'{i} wg{i} wg{i} 1\n' for i in range(1, 33)))
        if scenario != 'none':
            for i in range(1, 33):
                d = state / f'net/wg{i}'; d.mkdir()
                (d / 'mark').write_text('off' if i % 2 else '0x12340000')
            (state / 'net/wg32/down').touch()
        if scenario == 'existing':
            (state / 'NR_OUT').touch(); (state / 'NR_OUTPUT').touch()
        if scenario in failures: (state / failures[scenario]).touch()
        env = dict(os.environ, STATE=str(state), NR=str(state / 'nr'), NET_FIXTURE=str(state / 'net'),
                   PROC_FIXTURE=str(state / 'proc'), RG_HOME=str(state / 'region'), DM_HOME=str(state / 'domain'))
        result = subprocess.run(['bash', '-c', STUBS + '\n' + program + '\nreconcile'], env=env,
                                capture_output=True, text=True, timeout=10)
        events = (state / 'events').read_text().splitlines()
        check(not result.stderr and not any('unexpected-' in e for e in events), scenario + ' makes no unexpected calls')
        check((result.returncode == 0) == (scenario not in failures), scenario + ' result is explicit')
        firewall = [e for e in events if e.startswith('iptables ')]
        if scenario == 'none':
            check(not firewall and not any(e.startswith('wg ') for e in events), 'no extant WG interfaces means no global checks or mark reads')
        elif scenario in ['insert-fails', 'insert-filter-fails']:
            check(len(firewall) == (2 if scenario == 'insert-fails' else 4) and 'policy' not in events, 'failed global repair stops before policy publication')
            check('guard' in events and (state / 'nr/policy-reconcile.failed').exists(), 'both shared-chain insertion failures install and remember the guard')
        elif scenario in ['read-fails', 'ingress-fails', 'owner-fails']:
            check('guard' in events and 'policy' not in events and 'transport' not in events, 'read/repair failure stays closed before health publication')
            check((state / 'nr/policy-reconcile.failed').exists(), 'failed repair is remembered for safe retry')
        elif scenario == 'transport-fails':
            check('guard' in events and 'policy' not in events and (state / 'nr/policy-reconcile.failed').exists(), 'transport repair failure stays guarded before health publication')
        elif scenario == 'worker-fails':
            check('guard' in events and 'unguard' not in events and (state / 'nr/policy-reconcile.failed').exists(), 'worker failure retains the guard even after routing repair')
        else:
            check(sum(' -C ' in e for e in firewall) == 2, '32 WG interfaces check each shared chain only once')
            check(sum(' -I ' in e for e in firewall) == (2 if scenario == 'missing' else 0), scenario + ' adds each missing shared rule once')
            check(sum(e.startswith('wg set ') for e in events) == 16, 'every off mark is still repaired')
            check(all((state / f'net/wg{i}/mark').read_text().strip() == ('0x56000000' if i % 2 else '0x12340000') for i in range(1, 33)), 'existing custom marks are preserved')
            check(sum(e.startswith('ip route replace ') for e in events) == 31, 'only UP interfaces get default-route reconciliation')
            check(events[-5:] == ['ingress', 'owner-routes', 'transport', 'policy', 'restart-workers'], 'live state repair precedes transport and health selection')
            check(events.count('ip rule show') == 1, 'one route snapshot is shared by both recovery helpers')
        if scenario in failures:
            (state / 'events').write_text('')
            retry = subprocess.run(['bash', '-c', STUBS + '\n' + program + '\nreconcile'], env=env,
                                   capture_output=True, text=True, timeout=10)
            pending_events = (state / 'events').read_text().splitlines()
            check(retry.returncode != 0 and 'guard' in pending_events and 'unguard' not in pending_events
                  and (state / 'nr/policy-reconcile.failed').exists(), scenario + ' stays guarded while the error persists')
            (state / failures[scenario]).unlink()
            (state / 'events').write_text('')
            retry = subprocess.run(['bash', '-c', STUBS + '\n' + program + '\nreconcile'], env=env,
                                   capture_output=True, text=True, timeout=10)
            recovered_events = (state / 'events').read_text().splitlines()
            check(retry.returncode == 0 and not retry.stderr and not (state / 'nr/policy-reconcile.failed').exists(), scenario + ' is recoverable on the next successful poll')
            check(recovered_events[-2:] == ['restart-workers', 'unguard'] and recovered_events.count('unguard') == 1,
                  scenario + ' removes the guard only after routing and workers agree')

print(f'reconcile-wg-global: {checks} checks passed')
