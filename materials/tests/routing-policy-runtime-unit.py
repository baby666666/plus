#!/usr/bin/env python3
"""Exercise real policy shell emitters without a network, firewall or router.

The mocked health snapshot is intentional: actual probe and native target ABI
have separate isolated-VM tests. This suite verifies boundaries at their caller.
"""
from pathlib import Path
import json
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'materials/firmware/port-3726/files/usr/ikuai/script/native_runtime.sh'
checks = 0


def check(value, why):
    global checks
    assert value, why
    checks += 1


with tempfile.TemporaryDirectory(prefix='routing-policy-runtime-') as directory:
    d = Path(directory)
    script = d / 'runtime.sh'
    script.write_text(SCRIPT.read_text().replace('source /usr/ikuai/script/native_exit_health.sh', ':'))
    state = d / 'state'
    state.mkdir()
    for sub in ('policy-state', 'worker-state'):
        (state / sub).mkdir()
    (state / 'exits').write_text('1 wan1 wan1 1\n2 wg2 wg2 1\n')
    (state / 'owner-routes').write_text('')
    prelude = f'''
set -e -o pipefail
source {shlex.quote(str(script))}
NR={shlex.quote(str(state))}
nr_ipt(){{ printf 'IPT';printf '\t%s' "$@";printf '\n'; }}
iptables(){{ return 99; }}
ipset(){{ [ "$*" = 'create nr_hy_direct hash:net,net family inet maxelem 65536 -exist' ] || return 99; }}
ip(){{ printf 'IP';printf '\t%s' "$@";printf '\n';[ "$1 $2" != 'rule del' ]; }}
iptables-restore(){{ printf 'RESTORE_BEGIN\n';cat;printf 'RESTORE_END\n'; }}
conntrack(){{ printf 'CT';printf '\t%s' "$@" >> "$NR/ct.calls";printf '\n' >> "$NR/ct.calls"; }}
nr_exit_health_sync(){{ cp "$NR/fixture-health" "$NR/exit-health"; }}
'''

    def run(body):
        return subprocess.check_output(['bash'], input=prelude + body, text=True)

    def lines(output, prefix):
        return [line.split('\t')[1:] for line in output.splitlines() if line.startswith(prefix + '\t')]

    # Two distinct strategies share the same physical exits and stay isolated.
    # The single bound path remains usable even when its health is unknown.
    init = run('''
nr_policy 7 1,2 3 0
nr_policy 8 1,2 6 1
nr_policy 9 2 0 1
nr_policy_rule '-s 198.18.1.2/32 -p tcp --dport 443' 7 $'-m time --weekdays 1 --timestart 08:00:00 --timestop 09:00:00\n-m time --weekdays 1 --timestart 18:00:00 --timestop 19:00:00'
nr_policy_rule '-s 198.18.1.3/32' 8 ''
nr_policy_rule '-s 198.18.1.4/32' 9 ''
''')
    argv = lines(init, 'IPT')
    freebase, boundbase = 0x58000000 + 7 * 256, 0x55000000 + 8 * 256
    for eid, dev in ((1, 'wan1'), (2, 'wg2')):
        mark = str(freebase + eid)
        for table, chain in (('filter', 'NR_FWD'), ('mangle', 'NR_EGRESS')):
            rows = [a for a in argv if '-A' in a and a[a.index('-A')+1] == chain and '--mark' in a and a[a.index('--mark')+1] == mark and a[a.index('-t')+1] == table]
            check(len(rows) == 5, 'each candidate has both OR windows then one terminal guard')
            check(rows[-1][-1] == 'DROP', 'candidate cannot fall through to another exit')
            check([a[a.index('-o')+1] for a in rows if '-o' in a] == [dev, dev], 'unbound candidates still confine egress to their exact interface')
    fallback = [a for a in argv if '--mark' in a and a[a.index('--mark')+1] == str(freebase) and '-g' in a]
    check(len(fallback) == 4 and all(a[a.index('-g')+1] == 'NR_B7' for a in fallback), 'each fallback time window uses goto, preserving native firewall')
    check(not any('--mark' in a and a[a.index('--mark')+1] == str(boundbase) for a in argv), 'bound policy has no eid=0 fallback')
    check(any('--set-mark' in a and a[a.index('--set-mark')+1] == str(0x55000000+9*256+2) for a in argv), 'single bound path retains direct fixed mark')

    (state / 'policy-workers').write_text('1 7 192.0.2.53\n2 8 192.0.2.53\n')
    (state / 'fixture-health').write_text('1 0 1\n2 0 0\n')
    unknown = run('nr_policy_reconcile apply')
    check('-A NR_P7 -j DROP' in unknown and '-A NR_B7 -j RETURN' not in unknown, 'unknown candidate is not proof of all-down and cannot release main fallback')
    check((state / 'worker-state/1').read_text().startswith(f'  {freebase} '), 'unknown unbound DNS also remains prohibited until sampling completes')
    check('-A NR_E1 -j DROP' in unknown and '-A NR_E1 -j RETURN' not in unknown, 'unknown DNS worker cannot escape through POSTROUTING')
    (state / 'fixture-health').write_text('1 1 1\n2 0 0\n')
    partial = run('nr_policy_reconcile')
    check(f'--set-mark {freebase+1} --set-ifname wan1 ' in partial and '-A NR_B7 -j RETURN' not in partial, 'a known healthy candidate may serve while another remains unknown')
    check((state / 'worker-state/1').read_text().startswith(f'wan1 wan1 {freebase+1} '), 'DNS can use the known healthy candidate without waiting for unrelated unknown exit')
    (state / 'worker-restart.ids').unlink(missing_ok=True)
    # Reset initial fixture state to test first successful initialization.
    for filename in (state / 'worker-state').iterdir(): filename.unlink()
    for filename in (state / 'policy-state').iterdir(): filename.unlink()
    (state / 'fixture-health').write_text('1 1 1\n2 1 1\n')
    both = run('nr_policy_reconcile')
    check(f'--set-mark {freebase+1},{freebase+2} --set-ifname wan1,wg2 --set-band-flag 0 --set-mode 3' in both, 'ordered configured candidates and native mode are passed through')
    check(f'--set-mark {boundbase+1},{boundbase+2} --set-ifname wan1,wg2 --set-band-flag 0 --set-mode 6' in both, 'bound retains its independent marks/mode while NTH legacy band callback stays disabled')
    check('--set-band-flag 1' not in both, 'native legacy band cannot override explicit policy route/guard binding')
    check('-A NR_P7 -j CONNMARK --restore-mark\n' in both and '-A NR_P7 -j DROP\n' in both, 'target result is explicitly restored and a no-result cannot reach a later rule')
    check('-A NR_B7 -j RETURN' not in both, 'main fallback gate stays closed with healthy candidates')
    check((state / 'worker-state/1').read_text().startswith(f'wan1 wan1 {freebase+1} '), 'unbound DNS picks a configured healthy candidate')
    check((state / 'worker-state/2').read_text().startswith(f'wan1 wan1 {boundbase+1} '), 'bound DNS uses its independent strategy mark')
    for wid, base in ((1, freebase), (2, boundbase)):
        check(f'-A NR_E{wid} -m connmark ! --mark {base+1} -j DROP\n-A NR_E{wid} ! -d 192.0.2.53 -j DROP\n-A NR_E{wid} ! -o wan1 -j DROP\n-A NR_E{wid} -j RETURN' in both,
              'DNS POSTROUTING permits only the selected full identity, configured resolver and device')
    check(not (state / 'worker-restart.ids').exists(), 'initial worker setup does not enqueue a restart')
    check(not run('nr_policy_reconcile').strip(), 'unchanged health does not rebuild rules or delete flows')
    forced = run('nr_policy_reconcile apply')
    check('-F NR_W1' in forced and '-F NR_D1' in forced, 'hot full apply recreates worker guards even if routing is unchanged')
    check('-F NR_E1' in forced and '-A NR_E1 ! -o wan1 -j DROP' in forced, 'hot full apply reinstalls independent DNS egress guard')
    check(not (state / 'worker-restart.ids').exists(), 'force rebuilding identical worker route preserves socket and PID')

    (state / 'fixture-health').write_text('1 0 1\n2 1 1\n')
    one = run('nr_policy_reconcile apply')
    check(f'--set-mark {freebase+2} --set-ifname wg2 ' in one, 'new connections prefer remaining configured exit')
    ct = (state / 'ct.calls').read_text()
    check(f'{freebase+1}/0xffffffff' in ct and str(boundbase+1) not in ct, 'failure removes only the precise unbound candidate connections')
    check((state / 'worker-restart.ids').read_text().splitlines() == ['1', '2'], 'hot full apply queues only workers whose route changed for socket restart')
    check('-A NR_D1 ! -o wg2 -j DROP' in one and '-A NR_D2 ! -o wg2 -j DROP' in one, 'both DNS workers follow healthy candidate with exact output guards')
    check('-A NR_E1 ! -o wg2 -j DROP' in one and '-A NR_E2 ! -o wg2 -j DROP' in one, 'both DNS egress guards move to selected healthy candidate')

    (state / 'fixture-health').write_text('1 0 1\n2 0 1\n')
    down = run('nr_policy_reconcile')
    check(f'-A NR_P7 -j MARK --set-mark {freebase}' in down, 'all-down unbound sets explicit policy fallback identity')
    check('-A NR_B7 -j RETURN' in down and '-A NR_B7 -j ACCEPT' not in down, 'fallback gate returns to native firewall rather than accepting FORWARD')
    check('-A NR_P8 -j DROP' in down and f'--set-mark {boundbase}\n' not in down, 'all-down bound has no default escape')
    check((state / 'worker-state/1').read_text().startswith(f'main  {freebase} '), 'only unbound DNS can select main on all-down')
    check((state / 'worker-state/2').read_text().startswith(f'  {boundbase} '), 'bound DNS has no owner lookup before terminal prohibit')
    check('-A NR_D2 -j DROP' in down and '-A NR_W2 -j DROP' in down, 'bound DNS is blocked in both mangle and filter')
    check('-A NR_D1 ! -d 192.0.2.53 -j DROP' in down, 'unbound default DNS remains restricted to its configured resolver')
    check(f'-A NR_E1 -m connmark ! --mark {freebase} -j DROP\n-A NR_E1 ! -d 192.0.2.53 -j DROP\n-A NR_E1 -j RETURN' in down,
          'known all-down unbound DNS permits only its exact fallback identity and resolver')
    check('-A NR_E1 ! -o' not in down and '-A NR_E2 -j DROP' in down and '-A NR_E2 -j RETURN' not in down,
          'only unbound main fallback loses the selected device restriction; bound egress remains closed')

    (state / 'fixture-health').write_text('1 0 1\n2 1 1\n')
    recovery = run('nr_policy_reconcile')
    check(f'{freebase}/0xffffffff' in (state / 'ct.calls').read_text(), 'healthy recovery deletes only this strategy default-fallback connections')
    check('-A NR_B7 -j RETURN' not in recovery, 'recovery closes default gate before candidates resume')
    check(recovery.index('-A NR_B7 -j DROP') < recovery.index('-A NR_P7 -j NTH_CONNMARK'), 'fallback is closed before selector transition')
    # Worker registration is tested with a local passwd substitution, never /etc.
    fake = d / 'passwd'
    fake.write_text('nrdns1:x:48201:0:x:/x:/bin/false\n')
    script.write_text(script.read_text().replace('/etc/passwd', str(fake)))
    registered = run('nr_worker 1 7 192.0.2.53')
    check(any(a[-2:] == ['-g', 'NR_D1'] for a in lines(registered, 'IPT')), 'worker goto reaches native OUTPUT after its RETURN and avoids final UID DROP')
    check(not any(a[-2:] == ['-j', 'ACCEPT'] for a in lines(registered, 'IPT') if '-t' not in a), 'worker registration never bypasses native filter')
    egress = [a for a in lines(registered, 'IPT') if '-A' in a and a[a.index('-A')+1] == 'NR_EGRESS']
    check(egress == [['-t', 'mangle', '-A', 'NR_EGRESS', '-m', 'owner', '--uid-owner', '48201', '-m', 'connmark', '--mark', f'{freebase}/0xffffff00', '-g', 'NR_E1']],
          'DNS-only egress entry requires private worker UID and its policy connmark, excluding forwarded data and WG outer transport')
    check(any(a == ['-t', 'mangle', '-A', 'NR_E1', '-j', 'DROP'] for a in lines(registered, 'IPT')),
          'new independent worker egress chain starts closed before health initialization')

    (state / 'active').mkdir()
    (state / 'active/dns-bindings').write_text('169.254.252.1 ppphy1\n')
    old_worker = (state / 'worker-state/1').read_text()
    old_pending = (state / 'worker-restart.ids').read_text()
    begun = run('NR_KEEP_POLICY_WORKERS=1; nr_reset_evidence(){ :; }; nr_begin')
    emitted=lines(begun,'IPT')
    for table,chain,target,verdict in [('mangle','NR_SCOPE','NR_CLASS','ACCEPT'),('nat','NR_DNS_I','NR_DNS','RETURN')]:
        direct=['-t',table,'-A',chain,'-i','ppphy+','-m','set','--match-set','nr_hy_direct','src,dst','-j',verdict]
        public=['-t',table,'-A',chain,'-i','ppp+','-j',target]
        check(emitted.index(direct)<emitted.index(public),'Authenticated direct LAN precedes generic '+chain+' classification')
    for table,chain,target in [('mangle','NR_SCOPE','NR_CLASS'),('nat','NR_DNS_I','NR_DNS')]:
        check(['-t',table,'-A',chain,'-i','ppp+','-j',target] in emitted,'HY2 enters existing '+chain)
    check(['-t','mangle','-A','NR_CLASS','-i','ppphy+','-j','DPROTO'] in emitted,'HY2 invokes native protocol classification')
    for proto in ['udp','tcp']:
        check(['-t','nat','-A','NR_DNS53','-i','ppphy1','-p',proto,'--dport','53','-j','DNAT','--to-destination','169.254.252.1:53'] in emitted,'HY2 '+proto+' uses dedicated DNS binding')
        check(['-A','NR_INPUT','-i','ppphy1','-d','169.254.252.1','-p',proto,'--dport','53','-j','ACCEPT'] in emitted,'DNS input admission is exact '+proto+' scope')
    check(['-A','NR_INPUT','-d','169.254.252.1','-j','DROP'] in emitted,'other ingress cannot reach the HY2-specific DNS identity')
    check(not any(a[-2:]==['-j','ACCEPT'] and '-A' in a and a[a.index('-A')+1]=='NR_FWD' for a in emitted),'HY2 never installs a broad forward accept')
    check(['-t', 'mangle', '-F', 'NR_E1'] in lines(begun, 'IPT') and ['-t', 'mangle', '-X', 'NR_E1'] in lines(begun, 'IPT'), 'full apply removes previous worker egress chains after detaching their caller')
    check((state / 'worker-state/1').read_text() == old_worker, 'hot apply begin preserves existing worker route identity')
    check((state / 'worker-restart.ids').read_text() == old_pending, 'hot apply preserves failed pending worker restart instead of losing retry')
    check(not list((state / 'policy-state').iterdir()), 'full apply still rebuilds policy selectors')
    run('NR_KEEP_POLICY_WORKERS=0; nr_reset_evidence(){ :; }; nr_begin')
    check(not list((state / 'worker-state').iterdir()) and not (state / 'worker-restart.ids').exists(), 'cold worker restart discards only obsolete worker state and retry queue')
    script.write_text(script.read_text().replace('/usr/ikuai/script/wg_site.sh hooks',':'))
    finished=lines(run('nr_wg_transport_sync(){ :; };nr_hook(){ :; };nr_policy_reconcile(){ :; };nr_finish'),'IPT')
    for proto in ['udp','tcp']:
        check(['-t','nat','-A','NR_DNS','-i','ppphy+','-m','addrtype','--dst-type','LOCAL','-p',proto,'--dport','53','-j','NR_DNS53'] in finished,'default HY2 '+proto+' DNS only captures router-owned destination')
    for mark in ['0x55000000/0xff000000','0x58000000/0xff000000']:
        check(['-A','NR_FWD','-m','connmark','--mark',mark,'-j','DROP'] in finished,'HY2 keeps terminal forwarding guard '+mark)

    source = SCRIPT.read_text()
    check('0x58000000/0xff000000 -j CONNMARK --restore-mark' in source, 'existing unbound flow restores selection before NTH')
    check('0x58000000/0xff000000 -j DROP' in source, 'unknown unbound strategy marks retain terminal egress guard')
    check('"$((0x55000000))"|"$((0x58000000))"' in source, 'unbound data marks cannot masquerade as WireGuard transport')
    subprocess.run(['bash', '-n', str(SCRIPT)], check=True)

print(json.dumps({'suite': 'routing policy runtime', 'checks': checks, 'status': 'passed'}))
