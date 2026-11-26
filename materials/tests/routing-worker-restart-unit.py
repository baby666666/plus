#!/usr/bin/env python3
"""Exercise the real DNS worker restart/reconcile control flow locally.

No host process is signalled or started. /proc is redirected to temporary
fixtures, kill/sleep are shell functions, and only the daemon command (not its
identity string) is replaced. Firewall, routing, locks and DNS start/stop calls
in reconcile are controlled stubs. No router or network access is required.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'materials/firmware/port-3726/files/usr/ikuai/script/native_rules.sh'
checked = 0


def check(value, description):
    global checked
    assert value, description
    checked += 1


def function(source, name):
    start = re.search(r'^' + name + r'\(\)\s*\{', source, re.M).start()
    end = start + re.search(r'^\}', source[start:], re.M).end()
    return source[start:end]


source = SOURCE.read_text()
program = '\n'.join(function(source, name) for name in ['restart_changed_workers', 'reconcile'])
program = program.replace('/proc/', '$PROC_FIXTURE/')
program = re.sub(r'(?m)^(\s*)/usr/sbin/strict-dnsmasq(?= )', r'\1stub_dnsmasq', program)
program = program.replace('/usr/ikuai/script/native_dns_bind.sh check', 'stub_dns_bind check')
assert not re.search(r'(?m)^\s*/usr/sbin/strict-dnsmasq ', program)
assert '/proc/' not in program

STUBS = r'''
log(){ printf '%s\n' "$*" >> "$EVENTS"; }
kill(){
 log "kill $*"
 [[ "$1" =~ ^[0-9]+$ ]] && [ -d "$PROC_FIXTURE/$1" ] || return 97
 [ ! -f "$CONTROL/kill-fail-$1" ] || return 1
 [ ! -f "$CONTROL/kill-stuck-$1" ] || return 0
 rm -rf "$PROC_FIXTURE/$1"
}
sleep(){ log "sleep $*"; }
stub_dnsmasq(){
 local test=0 config wid pid executable=/usr/sbin/strict-dnsmasq
 [ "$1" != --test ] || { test=1; shift; }
 [ "$1" = -C ] && [ -f "$2" ] || return 98
 config="$2"; wid=${config##*/dns-};wid=${wid%.conf}
 [[ "$wid" =~ ^[0-9]+$ ]] || return 99
 if [ "$test" = 1 ];then log "test $wid"; [ ! -f "$CONTROL/test-fail-$wid" ];return;fi
 log "start $wid"
 [ ! -f "$CONTROL/start-fail-$wid" ] || return 1
 [ ! -f "$CONTROL/start-no-pid-$wid" ] || return 0
 pid=$((9000+wid));mkdir -p "$PROC_FIXTURE/$pid"
 [ ! -f "$CONTROL/start-wrong-identity-$wid" ] || executable=/fixture/unrelated
 printf '%s\0-C\0%s\0' "$executable" "$config" > "$PROC_FIXTURE/$pid/cmdline"
 printf '%s\n' "$pid" > "$NR/active/dns-$wid.pid"
}
ensure_conf(){ log ensure; }
lock_action(){ log lock; }
stub_dns_bind(){ log bind; [ ! -f "$CONTROL/bind-fail" ]; }
apply_config(){ log apply; return 1; }
nr_wg_transport_sync(){ log transport; }
nr_failed_ingress_reconcile(){ log ingress; }
nr_probe_owner_routes_sync(){ log owner-routes; [ "$1" = '0: from all lookup local' ]; }
nr_policy_reconcile(){ log policy; [ ! -f "$CONTROL/policy-fail" ]; }
guard(){ log guard; touch "$CONTROL/guard-active"; }
unguard(){ log unguard; rm -f "$CONTROL/guard-active"; }
stop_dns(){ log stop-dns; [ ! -f "$CONTROL/stop-dns-fail" ]; }
start_dns(){ log start-dns; [ ! -f "$CONTROL/start-dns-fail" ]; }
# Any unexpected routing branch fails safely; no native host command can run.
nr_ipt(){ log "unexpected-iptables $*"; return 96; }
ip(){
 if [ "$*" = 'rule show' ];then
  log route-inventory;printf '%s\n' '0: from all lookup local';return 0
 fi
 log "unexpected-ip $*"; return 96
}
wg(){ log "unexpected-wg $*"; return 96; }
'''


class Fixture:
    def __init__(self, directory):
        self.root = Path(directory)
        self.nr = self.root / 'nr'
        self.proc = self.root / 'proc'
        self.control = self.root / 'control'
        for path in [self.nr / 'active', self.proc, self.control,
                     self.root / 'region', self.root / 'domain']:
            path.mkdir(parents=True)
        self.events_file = self.root / 'events'
        self.events_file.write_text('')
        (self.nr / 'policy-workers').write_text('1 4 1.1.1.1\n2 5 8.8.8.8\n3 6 9.9.9.9\n')
        (self.nr / 'exits').write_text('')
        (self.nr / 'active/dns-ids').write_text('1\n2\n3\n')
        for wid in [1, 2, 3]:
            (self.nr / f'active/dns-{wid}.conf').write_text(f'port={6200+wid}\n')
            self.process(2000 + wid, f'dns-{wid}', '/usr/sbin/strict-dnsmasq',
                         str(self.nr / f'active/dns-{wid}.conf'))
        self.process(3000, 'front', '/usr/sbin/native-rule-dns', 'front.rules')
        self.process(3001, 'dns-base', '/usr/sbin/strict-dnsmasq', 'dns-base.conf')
        self.env = dict(os.environ, NR=str(self.nr), PROC_FIXTURE=str(self.proc),
                        CONTROL=str(self.control), EVENTS=str(self.events_file),
                        RG_HOME=str(self.root / 'region'), DM_HOME=str(self.root / 'domain'),
                        CONF=str(self.root / 'config.json'))

    def process(self, pid, name, executable, config):
        path = self.proc / str(pid)
        path.mkdir(exist_ok=True)
        (path / 'cmdline').write_bytes((executable + '\0-C\0' + config + '\0').encode())
        (self.nr / f'active/{name}.pid').write_text(str(pid) + '\n')

    def pending(self, contents):
        (self.nr / 'worker-restart.ids').write_text(contents)

    def pending_value(self):
        path = self.nr / 'worker-restart.ids'
        return path.read_text() if path.exists() else None

    def events(self):
        return self.events_file.read_text().splitlines()

    def run(self, function_name='restart_changed_workers'):
        result = subprocess.run(['bash', '-c', STUBS + '\n' + program + '\n' + function_name],
                                env=self.env, capture_output=True, text=True, timeout=15)
        check(not result.stderr, function_name + ' has no shell errors: ' + result.stderr)
        check(not any(line.startswith('unexpected-') for line in self.events()),
              'fixture never executes host routing/firewall operations')
        return result.returncode


with tempfile.TemporaryDirectory(prefix='routing-worker-restart-') as directory:
    root = Path(directory)
    f = Fixture(root / 'none')
    check(f.run() == 0 and f.events() == [], 'no pending request is a no-op')

    f = Fixture(root / 'one')
    f.pending('2\n2\n2\n')
    check(f.run() == 0, 'one requested worker can restart')
    check(f.events() == ['test 2', 'kill 2002', 'start 2'], 'duplicate IDs restart only the named worker once')
    check(f.pending_value() is None, 'completed pending file is removed')
    check((f.nr / 'active/dns-2.pid').read_text().strip() == '9002', 'new worker identity accepted')
    check(all((f.nr / f'active/dns-{wid}.pid').read_text().strip() == str(2000 + wid)
              and (f.proc / str(2000 + wid) / 'cmdline').exists() for wid in [1, 3]),
          'unrequested workers keep the same live PID')

    for mismatch in ['executable', 'config', 'malformed-pid']:
        f = Fixture(root / mismatch)
        f.pending('2\n')
        if mismatch == 'executable':
            f.process(2002, 'dns-2', '/fixture/unrelated', str(f.nr / 'active/dns-2.conf'))
        elif mismatch == 'config':
            f.process(2002, 'dns-2', '/usr/sbin/strict-dnsmasq', str(f.nr / 'active/dns-1.conf'))
        else:
            (f.nr / 'active/dns-2.pid').write_text('2002;bad\n')
        check(f.run() != 0, mismatch + ' refuses to authorize restart')
        check(f.events() == ['test 2'], mismatch + ' never signals or starts a process')
        check((f.proc / '2002/cmdline').exists() and f.pending_value() == '2\n',
              mismatch + ' preserves the process and retry request')

    for invalid in ['0', '33', '9', '../2', '2 extra']:
        f = Fixture(root / ('invalid-' + invalid.replace('/', '_').replace(' ', '_')))
        f.pending(invalid + '\n')
        check(f.run() != 0 and not f.events(), 'invalid/unconfigured worker ID rejected: ' + invalid)

    for fault in ['test-fail-2', 'kill-fail-2002', 'kill-stuck-2002',
                  'start-no-pid-2', 'start-wrong-identity-2']:
        f = Fixture(root / fault)
        f.pending('2\n')
        (f.control / fault).touch()
        check(f.run() != 0 and f.pending_value() == '2\n', fault + ' keeps retry pending')
        if fault.startswith(('test-', 'kill-')):
            check('start 2' not in f.events(), fault + ' prevents replacement launch')
        if fault.startswith('kill-'):
            check((f.proc / '2002/cmdline').exists(), fault + ' leaves original process visible')

    f = Fixture(root / 'partial-retry')
    f.pending('2\n1\n2\n')
    (f.control / 'start-fail-2').touch()
    check(f.run() != 0, 'later daemon failure is returned')
    check(f.pending_value() == '2\n', 'completed first worker is removed before later failure')
    check((f.nr / 'active/dns-1.pid').read_text().strip() == '9001'
          and not (f.nr / 'active/dns-2.pid').exists(), 'partial completion is durable')
    (f.control / 'start-fail-2').unlink()
    check(f.run() == 0 and f.pending_value() is None, 'retry completes remaining worker')
    check(f.events().count('start 1') == 1 and f.events().count('kill 2001') == 1
          and 'kill 9001' not in f.events(), 'retry does not restart an already completed worker')
    check((f.nr / 'active/dns-3.pid').read_text().strip() == '2003', 'partial retry leaves unrelated worker intact')

    f = Fixture(root / 'policy-recovery')
    (f.control / 'policy-fail').touch()
    check(f.run('reconcile') != 0, 'policy failure fails reconcile')
    check((f.control / 'guard-active').exists() and (f.nr / 'policy-reconcile.failed').exists(),
          'policy failure installs guard and owns its recovery marker')
    check(f.events().count('route-inventory') == 1 and
          f.events().index('ingress') < f.events().index('owner-routes') <
          f.events().index('transport') < f.events().index('policy'),
          'isolated recovery hooks share one route inventory before policy and workers')
    (f.control / 'policy-fail').unlink()
    check(f.run('reconcile') == 0, 'later policy retry succeeds')
    check(not (f.control / 'guard-active').exists() and not (f.nr / 'policy-reconcile.failed').exists(),
          'successful policy retry clears its own guard and recovery marker')

    f = Fixture(root / 'worker-recovery')
    f.pending('1\n2\n')
    (f.control / 'start-fail-2').touch()
    check(f.run('reconcile') != 0 and f.pending_value() == '2\n',
          'worker failure retains only unfinished work through real reconcile')
    check((f.control / 'guard-active').exists() and (f.nr / 'policy-reconcile.failed').exists(),
          'worker restart failure stays guarded')
    (f.control / 'start-fail-2').unlink()
    check(f.run('reconcile') == 0, 'worker retry recovers through real reconcile')
    check(f.pending_value() is None and not (f.control / 'guard-active').exists()
          and not (f.nr / 'policy-reconcile.failed').exists(), 'recovered worker releases owned guard')
    check(f.events().count('start 1') == 1 and f.events().count('unguard') == 1,
          'reconcile retries neither completed workers nor guard release twice')

    for blocker in ['commit.pending', 'native-dirty', 'native-stage.pending']:
        f = Fixture(root / blocker)
        (f.nr / blocker).touch()
        (f.nr / 'policy-reconcile.failed').touch()
        check(f.run('reconcile') != 0, blocker + ' refuses DNS-only recovery')
        check('policy' not in f.events() and 'unguard' not in f.events()
              and (f.nr / 'policy-reconcile.failed').exists(), blocker + ' cannot be cleared by worker retry')

    f = Fixture(root / 'foreign-guard')
    (f.control / 'guard-active').touch()
    check(f.run('reconcile') == 0, 'healthy reconcile without owned failure succeeds')
    check((f.control / 'guard-active').exists() and 'unguard' not in f.events(),
          'healthy reconcile does not clear an unrelated guard')

print(f'routing-worker-restart: {checked} checks passed')
