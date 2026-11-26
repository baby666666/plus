#!/usr/bin/env python3
"""Independent kernel-state model for local WG INVALID DNS reset protection."""
from pathlib import Path
import importlib.util
import json
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / 'materials/firmware/port-3726/files/usr/ikuai/script/native_runtime.sh'
spec = importlib.util.spec_from_file_location('recovery_fixture', Path(__file__).with_name('routing-recovery-state-unit.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
mock = fixture.MOCK.replace("elif a==['-o','-4','addr','show']:\n  out='1: lo inet 127.0.0.1/8\\n'", """elif a[:4]==['-o','-4','addr','show']:
  out=s.get('addresses','')
  if len(a)==6:out='\\n'.join(r for r in out.splitlines() if r.split()[1]==a[5])+'\\n'
  if s.get('fail_addr_read'):rc=1""")
assert "out=s.get('addresses','')" in mock
mock = mock.replace("if s.get('fail_ipt_add'):rc=1", "if s.get('fail_ipt_add') or (s.get('fail_reset_add') and 'nr-wg-probe-reset' in row):rc=1")
mock = mock.replace("elif s.get('fail_ipt_del'):rc=1", "elif s.get('fail_ipt_del') or (s.get('fail_reset_del') and 'nr-wg-probe-reset' in row):rc=1")
checks = 0


def check(value, why):
    global checks
    assert value, why
    checks += 1


def guard(ip='198.19.3.1', dev='wg3'):
    return shlex.split(f'NR_OUTPUT -s {ip}/32 ! -o {dev} -p tcp --dport 53 --tcp-flags RST RST -m conntrack --ctstate INVALID -m comment --comment nr-wg-probe-reset -j DROP')


def is_reset(row):
    return 'nr-wg-probe-reset' in row


with tempfile.TemporaryDirectory(prefix='wg-probe-reset-') as directory:
    d = Path(directory)
    (d/'mock.py').write_text(mock)
    (d/'runtime.sh').write_text(RUNTIME.read_text().replace('source /usr/ikuai/script/native_exit_health.sh', ':'))
    (d/'exits').write_text('3 wg3 wg3 1\n')
    path = d/'kernel.json'
    lo = shlex.split('NR_OUTPUT -o lo -j RETURN')
    owner = shlex.split('NR_OUTPUT -m owner --uid-owner 48103 ! -o wg3 -j DROP')
    owner_return = shlex.split('NR_OUTPUT -m owner --uid-owner 48103 -j RETURN')
    addresses = '1: lo inet 127.0.0.1/8\n7: wg3 inet 198.19.3.1/24\n'
    base = {'rules': ['10000: from all fwmark 0x2711 lookup wan1'],
            'iptables': [lo, owner, owner_return], 'addresses': addresses, 'calls': []}
    path.write_text(json.dumps(base))
    prelude = ('set -e -o pipefail\nsource '+shlex.quote(str(d/'runtime.sh'))+'\nNR='+shlex.quote(str(d))+'\n'
               +'mock(){ python3 '+shlex.quote(str(d/'mock.py'))+' '+shlex.quote(str(path))+' "$@"; }\n'
               +'ip(){ mock ip "$@"; }\nwg(){ mock wg "$@"; }\nnr_ipt(){ mock ipt "$@"; }\n')

    def read():
        return json.loads(path.read_text())

    def mutate(**kw):
        state = read();state.update(calls=[], **kw);path.write_text(json.dumps(state))

    def run(body='nr_wg_transport_sync'):
        return subprocess.run(['bash'], input=prelude+body+'\n', text=True, capture_output=True, timeout=30)

    def writes():
        return [c for c in read()['calls'] if c[0]=='ipt' and c[1] in ('-I','-A','-D')]

    r=run();check(r.returncode==0,r.stderr)
    check(guard() in read()['iptables'],'initial sync installs the exact local IPv4 reset guard')
    check(read()['iptables'].index(guard()) < read()['iptables'].index(owner_return),'initial reset guard precedes owner bypass')
    check(sum(c==['ip','-o','-4','addr','show'] for c in read()['calls'])==1 and
          sum(c==['ipt','-S','NR_OUTPUT'] for c in read()['calls'])==1,'transport and reset guard share one chain and one address inventory')
    saved=read()['iptables'];cache=(d/'wg-transport').read_text()
    mutate();check(run().returncode==0 and not writes(),'stable synchronization performs zero firewall writes')

    mutate(iptables=[r for r in saved if not is_reset(r)])
    check(run().returncode==0,'missing reset guard is repaired even when the transport cache matches')
    check(len(writes())==1 and writes()[0][1:4]==['-I','NR_OUTPUT','2'],'missing guard adds only the narrow rule at slot 2')
    check((d/'wg-transport').read_text()==cache,'reset repair does not alter desired transport cache')

    mutate(iptables=[r for r in saved if not is_reset(r)]+[guard()])
    check(run().returncode==0,'late reset guard is repaired')
    check(read()['iptables'].index(guard()) < read()['iptables'].index(owner_return),'late guard gets an effective early copy')
    check(len(writes())==1 and all(c[1]!='-D' for c in writes()),'ordering repair adds before retaining harmless late copy, with no protection gap')
    mutate();check(run().returncode==0 and not writes(),'retained late duplicate does not cause repeated writes')

    mutate(addresses=addresses.replace('198.19.3.1','198.19.3.2'))
    check(run().returncode==0,'changed WG IPv4 address is observed on next invocation')
    check(guard('198.19.3.2') in read()['iptables'] and guard() in read()['iptables'],'new address is protected while old-address late packets remain protected')
    mutate(addresses=addresses.replace('198.19.3.1','198.19.3.2')+'8: wg4 inet 198.19.3.1/24\n')
    check(run().returncode==0,'old address reused by another current WG is transferred safely')
    check(guard() not in read()['iptables'] and guard('198.19.3.1','wg4') in read()['iptables'],'no old wrong-device guard remains to conflict with the new owning WG')
    check(writes()[0][1]=='-I' and all(c[1]=='-D' for c in writes()[1:]),'new-owner guard is installed before conflicting old-owner guards are removed')

    # Return to a single current interface and exercise read/add/delete failure.
    mutate(iptables=saved,addresses=addresses,fail_addr_read=True)
    check(run().returncode!=0 and not writes(),'failed address read with partial stdout performs no firewall mutation')
    mutate(fail_addr_read=False,addresses='')
    check(run().returncode!=0 and not writes(),'empty global address output fails rather than claiming synchronization')
    mutate(addresses='7: wg3 inet broken/24\n')
    check(run().returncode!=0,'malformed managed WG address fails synchronization')
    mutate(addresses=addresses+'8: wg4 inet 198.19.3.1/24\n')
    check(run().returncode!=0,'ambiguous address ownership fails synchronization')
    mutate(addresses=addresses,iptables=[r for r in saved if not is_reset(r)],fail_reset_add=True)
    check(run().returncode!=0,'failed missing reset installation propagates for caller protection')
    check((d/'wg-transport').read_text()==cache and guard() not in read()['iptables'],'failed installation cannot publish a protected result')
    mutate(fail_reset_add=False);check(run().returncode==0,'next invocation retries a failed guard installation')
    mutate(addresses='1: lo inet 127.0.0.1/8\n8: wg4 inet 198.19.3.1/24\n',fail_reset_del=True)
    check(run().returncode!=0,'failed conflicting old guard deletion propagates')
    check(guard() in read()['iptables'] and guard('198.19.3.1','wg4') in read()['iptables'],'delete failure retains protection for both devices until the next guarded retry')
    mutate(fail_reset_del=False);check(run().returncode==0 and guard() not in read()['iptables'],'next invocation removes only conflicting old ownership')

    mutate(iptables=saved,addresses=addresses,rule_prefix='[fastid: 0] ')
    check(run().returncode==0 and not writes(),'native fastid prefixes preserve stable zero-write behavior')
    mutate(rule_prefix='[fastid: broken] ')
    check(run().returncode!=0 and not writes(),'malformed vendor prefix remains a failed chain read')
    mutate(rule_prefix='',iptables=[shlex.split('NR_OUTPUT -j RETURN')]+saved[1:])
    check(run().returncode!=0 and not writes(),'first-row bypass cannot be falsely repaired by inserting an unreachable slot-2 guard')
    mutate(iptables=saved,addresses='1: lo inet 127.0.0.1/8\n',down=['wg3'])
    check(run().returncode==0 and guard() in read()['iptables'],'disappeared interface keeps old-address protection without fabricating a new address')

    # Full apply uses the same exact restriction, independent of reconciliation.
    mutate(iptables=[lo],addresses=addresses,down=[])
    r=run('nr_wg_probe_reset_install wg3');check(r.returncode==0,r.stderr)
    check(read()['iptables']==[lo,guard()],'full-apply installer emits only exact /32, wrong WG, TCP53, RST and INVALID DROP')
    mutate(iptables=[lo],fail_addr_read=True)
    check(run('nr_wg_probe_reset_install wg3').returncode!=0 and not writes(),'full-apply address read failure propagates')
    mutate(fail_addr_read=False,fail_reset_add=True)
    check(run('nr_wg_probe_reset_install wg3').returncode!=0,'full-apply guard insertion failure propagates')

    many=''.join(f'{i} wg{i} wg{i} 1\n' for i in range(1,33))
    (d/'exits').write_text(many)
    many_addr='1: lo inet 127.0.0.1/8\n'+''.join(f'{i+1}: wg{i} inet 198.19.{i}.1/24\n' for i in range(1,33))
    mutate(iptables=[lo],addresses=many_addr,fail_reset_add=False)
    r=run();check(r.returncode==0,r.stderr)
    check(sum(is_reset(r) for r in read()['iptables'])==32,'all 32 exits receive their exact local-address protection')
    mutate();check(run().returncode==0 and not writes(),'32-exit steady state makes zero firewall writes')
    check(sum(c==['ip','-o','-4','addr','show'] for c in read()['calls'])==1 and
          sum(c==['ipt','-S','NR_OUTPUT'] for c in read()['calls'])==1 and
          sum(c==['ip','rule','show'] for c in read()['calls'])==1,'32 exits still use one global address, chain and route inventory')
    print(json.dumps({'passed':True,'checks':checks,'scope':'independent mocked kernel; no router or host kernel accessed'}))
