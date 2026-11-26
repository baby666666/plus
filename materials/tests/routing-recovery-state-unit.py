#!/usr/bin/env python3
"""Kernel-state regression for native WG transport and probe owner routes.

The command shim models kernel state independently from native-rules cache
files. No network, router, firewall or privileged host command is used.
"""
from pathlib import Path
import argparse
import json
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / 'materials/firmware/port-3726/files/usr/ikuai/script/native_runtime.sh'
checks = 0


def check(value, why):
    global checks
    assert value, why
    checks += 1


MOCK = r'''
import json,sys
from pathlib import Path
p=Path(sys.argv[1]);op=sys.argv[2];a=sys.argv[3:];s=json.loads(p.read_text())
s['calls'].append([op]+a)
rc=0;out=''
def val(key,default=None):return a[a.index(key)+1] if key in a else default
if op=='ip':
 if a==['rule','show']:
  if s.get('fail_rule_read'):rc=1
  else:out='\n'.join(s['rules'])+'\n'
 elif a==['-o','-4','addr','show']:
  out='1: lo inet 127.0.0.1/8\n'
 elif a[:3]==['-o','link','show']:
  dev=a[3]
  if dev in s.get('down',[]):rc=1
  else:out='7: '+dev+': <UP,LOWER_UP>\n'
 elif a[:2]==['rule','add']:
  if s.get('fail_rule_add'):rc=1
  else:
   pref=val('pref');uid=val('uidrange')
   target='prohibit' if 'prohibit' in a else 'lookup '+val('table')
   line=pref+': from all uidrange '+uid+' '+target
   s['rules'].append(line)
 elif a[:2]==['rule','del']:
  pref=val('pref');uid=val('uidrange')
  found=next((i for i,r in enumerate(s['rules']) if r.startswith(pref+':') and ('uidrange '+uid+' ') in r),None)
  if s.get('fail_rule_del') or found is None:rc=1
  else:s['rules'].pop(found)
 else:rc=98
elif op=='wg':
 if a[:1]==['show'] and a[-1]=='listen-port':out=str(s.get('ports',{}).get(a[1],s.get('port',51820)))+'\n'
 else:rc=98
elif op=='ipt':
 table='filter'
 if a[:2]==['-t','filter']:a=a[2:]
 elif a[:2]==['-t','mangle']:table='mangle';a=a[2:]
 if a[:1]==['-S']:
  if s.get('fail_ipt_read'):rc=1
  elif s.get('malformed_ipt_read'):out='broken output\n'
  else:
   out='-N '+a[1]+'\n'
   out+=''.join(s.get('rule_prefix','')+'-A '+r[0]+' '+' '.join(r[1:])+'\n' for r in s['iptables'] if r[0]==a[1])
 elif a[:1] in (['-C'],['-I'],['-A'],['-D']):
  action=a[0];row=a[1:];position=0
  if action=='-I' and len(row)>1 and row[1].isdigit():position=int(row[1])-1;row=row[:1]+row[2:]
  if action=='-C':rc=0 if row in s['iptables'] else 1
  elif action in ('-A','-I'):
   if s.get('fail_ipt_add'):rc=1
   elif action=='-I':s['iptables'].insert(position,row)
   else:s['iptables'].append(row)
  elif s.get('fail_ipt_del'):rc=1
  elif row in s['iptables']:s['iptables'].remove(row)
  else:rc=1
 else:rc=98
else:rc=98
p.write_text(json.dumps(s));sys.stdout.write(out);sys.exit(rc)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, default=RUNTIME,
                        help='Current runtime source to verify')
    args = parser.parse_args()
    source = args.runtime.read_text()
    with tempfile.TemporaryDirectory(prefix='native-recovery-state-') as directory:
        d = Path(directory)
        (d/'mock.py').write_text(MOCK)
        (d/'tables').write_text('254 main\n29993 wg3\n10001 wan1\n')
        local = source.replace('source /usr/ikuai/script/native_exit_health.sh', ':')
        local = local.replace('/etc/iproute2/rt_tables', str(d/'tables'))
        (d/'runtime.sh').write_text(local)
        (d/'exits').write_text('3 wg3 wg3 1\n')
        (d/'owner-routes').write_text('143 48103\n')
        base = {'rules':['0: from all lookup local',
                         '143: from all uidrange 48103-48103 lookup wg3',
                         '180: from all uidrange 48101-48232 prohibit',
                         '10000: from all fwmark 0x10001 lookup wan1'],
                'iptables':[], 'calls':[]}
        path=d/'kernel.json'
        path.write_text(json.dumps(base))
        prelude = ('set -e -o pipefail\nsource '+shlex.quote(str(d/'runtime.sh'))+'\nNR='+shlex.quote(str(d))+'\n'
                   +'mock(){ python3 '+shlex.quote(str(d/'mock.py'))+' '+shlex.quote(str(path))+' "$@"; }\n'
                   +'ip(){ mock ip "$@"; }\nwg(){ mock wg "$@"; }\n'
                   +'nr_ipt(){ mock ipt "$@"; }\niptables(){ mock ipt "$@"; }\n')

        def run(body):
            return subprocess.run(['bash'],input=prelude+body+'\n',text=True,capture_output=True)

        def read():
            return json.loads(path.read_text())

        def mutate(fn):
            state=read();state['calls']=[];fn(state);path.write_text(json.dumps(state))

        r=run('nr_wg_transport_sync')
        check(r.returncode==0,r.stderr)
        check(len(read()['iptables'])==1,'initial transport permission installed')
        cache=(d/'wg-transport').read_text()
        mutate(lambda s:s['iptables'].clear())
        r=run('nr_wg_transport_sync')
        check(r.returncode==0,r.stderr)
        recovered=len(read()['iptables'])==1
        check(recovered,'unchanged text cache cannot suppress repair of a missing kernel transport permission')
        check((d/'wg-transport').read_text()==cache,'repair preserves desired transport state')

        mutate(lambda s:s['rules'].remove('143: from all uidrange 48103-48103 lookup wg3'))
        r=run('nr_probe_owner_routes_sync')
        check(r.returncode==0,r.stderr)
        owner_recovered='143: from all uidrange 48103-48103 lookup wg3' in read()['rules']
        check(owner_recovered,'missing positive probe owner route is restored to the exact configured table')
        check('180: from all uidrange 48101-48232 prohibit' in read()['rules'],'terminal owner prohibition remains installed')

        def reset_rules(rows, **flags):
            state=read()
            for key in list(state):
                if key.startswith('fail_') or key.startswith('malformed_'):
                    del state[key]
            state.update(rules=rows,calls=[],**flags)
            path.write_text(json.dumps(state))

        terminal='180: from all uidrange 48101-48232 prohibit'
        owner='143: from all uidrange 48103-48103 lookup wg3'
        basic=['0: from all lookup local',terminal,'10000: from all fwmark 0x10001 lookup wan1']
        reset_rules(basic+[owner])
        r=run('nr_probe_owner_routes_sync')
        check(r.returncode==0,r.stderr)
        check(read()['calls']==[['ip','rule','show']],'correct positive routes require one inventory and no mutation')
        reset_rules(basic+['143: from all uidrange 48103-48103 lookup 29993'])
        check(run('nr_probe_owner_routes_sync').returncode==0,'numeric table alias accepted')
        check(read()['calls']==[['ip','rule','show']],'numeric table alias is not rewritten unnecessarily')

        unrelated=['143: from all uidrange 48104-48104 lookup wan1',
                   '144: from all uidrange 48103-48103 lookup wan1',
                   '101: from all uidrange 48201-48201 lookup wg3']
        reset_rules(basic+unrelated+[owner,owner.replace('wg3','wan1'),owner])
        r=run('nr_probe_owner_routes_sync')
        check(r.returncode==0,r.stderr)
        check(read()['rules'].count(owner)==1 and not any(row==owner.replace('wg3','wan1') for row in read()['rules']),
              'wrong and duplicated positive routes are replaced by one exact configured table')
        check(all(row in read()['rules'] for row in unrelated),'another UID, priority and DNS worker remain unchanged')
        changes=[c for c in read()['calls'] if c[:3]==['ip','rule','del']]
        check(len(changes)==3 and all(c==['ip','rule','del','pref','143','uidrange','48103-48103'] for c in changes),
              'deletion is bounded by captured count and exact owned priority plus UID')

        reset_rules(['0: from all lookup local',owner.replace('wg3','wan1')])
        r=run('nr_probe_owner_routes_sync')
        check(r.returncode==0,r.stderr)
        mutations=[c for c in read()['calls'] if c[:2]==['ip','rule'] and c[2]!='show']
        check(mutations[0]==['ip','rule','add','pref','180','uidrange','48101-48232','prohibit'],
              'terminal prohibition is restored before replacing any positive route')
        check(owner in read()['rules'] and terminal in read()['rules'],'missing prohibition plus wrong route repaired')

        reset_rules(basic+[owner],fail_rule_read=True)
        r=run('nr_probe_owner_routes_sync')
        check(r.returncode!=0,'failed route inventory fails reconciliation')
        check(read()['rules']==basic+[owner] and len(read()['calls'])==1,'read failure never mutates kernel state')
        reset_rules(basic+[owner.replace('wg3','wan1')],fail_rule_del=True)
        check(run('nr_probe_owner_routes_sync').returncode!=0,'failed positive-route removal is propagated')
        check(owner not in read()['rules'],'failed removal cannot be followed by a duplicate successful-looking route')
        reset_rules(basic,fail_rule_add=True)
        check(run('nr_probe_owner_routes_sync').returncode!=0,'failed positive-route installation is propagated')
        check(terminal in read()['rules'],'failed repair retains terminal prohibit')
        reset_rules(basic+['180: from all uidrange 48101-48232 lookup main'])
        check(run('nr_probe_owner_routes_sync').returncode!=0,'conflicting terminal range fails closed for caller guard')
        check(len(read()['calls'])==1,'ambiguous terminal policy is not silently rewritten')

        reset_rules(basic+[owner])
        (d/'exits').write_text('3 wg3 wg3 0\n')
        check(run('nr_probe_owner_routes_sync').returncode==0,'unavailable exit reconciliation succeeds')
        check(owner not in read()['rules'] and terminal in read()['rules'],'unavailable exit has no positive lookup but retains terminal prohibit')
        for invalid in ['40 wg3 wg3 1\n','101 wg3 wg3 1\n','3 missing missing 1\n','3 wg3 wg3 1\n3 wg3 wg3 1\n']:
            reset_rules(basic)
            (d/'exits').write_text(invalid)
            check(run('nr_probe_owner_routes_sync').returncode!=0,'invalid or overlapping probe identity is refused')
            check(len(read()['calls'])==1,'invalid plan makes no routing mutation')
        (d/'exits').write_text('3 wg3 wg3 1\n')
        reset_rules(basic+[owner])
        mutate(lambda s:s['iptables'].clear())
        mutate(lambda s:s.update(fail_ipt_read=True))
        check(run('nr_wg_transport_sync').returncode!=0,'failed kernel transport inventory is propagated')
        check(not read()['iptables'] and (d/'wg-transport').read_text()==cache,'failed read preserves desired cache and does not publish permission')
        mutate(lambda s:s.update(fail_ipt_read=False,malformed_ipt_read=True))
        check(run('nr_wg_transport_sync').returncode!=0,'malformed kernel inventory is not treated as an empty healthy chain')
        mutate(lambda s:s.update(malformed_ipt_read=False,fail_ipt_add=True))
        check(run('nr_wg_transport_sync').returncode!=0,'transport repair failure is propagated')
        check(not read()['iptables'] and (d/'wg-transport').read_text()==cache,'failed repair does not claim synchronized kernel state')
        mutate(lambda s:s.update(fail_ipt_add=False))
        check(run('nr_wg_transport_sync').returncode==0,'next invocation retries missing transport permission')
        check(len(read()['iptables'])==1,'retry repairs only the missing exact permission')
        mutate(lambda s:None)
        check(run('nr_wg_transport_sync').returncode==0,'stable kernel transport state remains healthy')
        check(sum(c==['ipt','-S','NR_OUTPUT'] for c in read()['calls'])==1 and
              not any(c[0]=='ipt' and c[1] in ['-I','-D','-A','-C'] for c in read()['calls']),
              'stable state reads one chain and performs no per-pair checks or mutation')

        permission=read()['iptables'][0]
        # Native 3.7.26 -S prefixes rule rows, but not chain declarations.
        mutate(lambda s:s.update(rule_prefix='[fastid: 0] '))
        check(run('nr_wg_transport_sync').returncode==0,'native fastid rule prefix is accepted')
        check(not any(c[0]=='ipt' and c[1] in ['-I','-D','-A','-C'] for c in read()['calls']),
              'native prefixed stable inventory still performs zero kernel writes')
        mutate(lambda s:s.update(rule_prefix='[fastid: broken] '))
        check(run('nr_wg_transport_sync').returncode!=0,'malformed fastid prefix remains a hard read failure')
        mutate(lambda s:s.update(rule_prefix='garbage '))
        check(run('nr_wg_transport_sync').returncode!=0,'unrecognized leading garbage is not stripped')
        mutate(lambda s:s.update(rule_prefix='[fastid: 0] '))
        loopback=['NR_OUTPUT','-o','lo','-j','RETURN']
        probe_guard=['NR_OUTPUT','-m','owner','--uid-owner','48103','!','-o','wg3','-j','DROP']
        worker_gate=['NR_OUTPUT','-m','owner','--uid-owner','48201','-g','NR_D1']
        mutate(lambda s:s.update(iptables=[loopback,probe_guard,worker_gate,permission]))
        r=run('nr_wg_transport_sync')
        check(r.returncode==0,r.stderr)
        check(read()['iptables']==[loopback,permission,probe_guard,worker_gate],
              'existing exact transport permission after owner control is moved to original slot 2')
        check(sum(c[:3]==['ipt','-D','NR_OUTPUT'] for c in read()['calls'])==1 and
              sum(c[:4]==['ipt','-I','NR_OUTPUT','2'] for c in read()['calls'])==1,
              'late permission repair removes and adds only its identical owned row')
        mutate(lambda s:None)
        check(run('nr_wg_transport_sync').returncode==0,'correct permission ordering remains healthy')
        check(not any(c[0]=='ipt' and c[1] in ['-I','-D','-A','-C'] for c in read()['calls']),
              'correct ordering performs no firewall mutation')
        mutate(lambda s:s.update(iptables=[loopback,permission,probe_guard,permission,worker_gate]))
        check(run('nr_wg_transport_sync').returncode==0,'duplicate identical transport permissions are repaired')
        check(read()['iptables']==[loopback,permission,probe_guard,worker_gate],
              'duplicates collapse to one correctly placed exact permission')
        mutate(lambda s:s.update(iptables=[probe_guard,permission,worker_gate]))
        check(run('nr_wg_transport_sync').returncode!=0,'first-row owner control fails instead of placing a still-unreachable permission')
        check(read()['iptables']==[probe_guard,permission,worker_gate] and
              not any(c[0]=='ipt' and c[1] in ['-I','-D','-A'] for c in read()['calls']),
              'ambiguous first-row owner control is preserved for caller fail-closed guard')
        mutate(lambda s:s.update(iptables=[loopback,probe_guard,permission],fail_ipt_del=True))
        check(run('nr_wg_transport_sync').returncode!=0,'late-permission removal failure propagates')
        check(read()['iptables']==[loopback,probe_guard,permission],
              'failed removal does not claim reordered permission or append a duplicate')
        mutate(lambda s:s.update(fail_ipt_del=False,fail_ipt_add=True))
        check(run('nr_wg_transport_sync').returncode!=0,'late-permission reinsertion failure propagates')
        check(read()['iptables']==[loopback,probe_guard],
              'failed reinsertion leaves owner guard closed, without broader exemption')
        mutate(lambda s:s.update(fail_ipt_add=False))
        check(run('nr_wg_transport_sync').returncode==0,'later cycle retries ordering repair after command recovery')
        check(read()['iptables']==[loopback,permission,probe_guard],
              'retry restores only exact port, mark and dedicated UID permission')

        mutate(lambda s:s.update(port=51821,fail_ipt_del=True))
        check(run('nr_wg_transport_sync').returncode!=0,'retired exact permission deletion failure is propagated')
        check((d/'wg-transport').read_text()==cache and permission in read()['iptables'],
              'retired deletion failure preserves old cache for the next guarded retry')
        mutate(lambda s:s.update(fail_ipt_del=False))
        check(run('nr_wg_transport_sync').returncode==0,'retired permission is removed on successful retry')
        check(permission not in read()['iptables'] and (d/'wg-transport').read_text()=='51821 0x10001\n',
              'successful retry publishes only the current listen port')
        mutate(lambda s:s.update(port=51820,iptables=[loopback,probe_guard]))
        check(run('nr_wg_transport_sync').returncode==0,'already absent retired permission needs no deletion')
        check(not any(c[:3]==['ipt','-D','NR_OUTPUT'] for c in read()['calls']),
              'missing retired row is distinguished from a failed kernel deletion')


        # One shared route inventory covers all probes and all transports.
        (d/'tables').write_text('254 main\n10001 wan1\n'+''.join('%s wg%s\n'%(29900+i,i) for i in range(1,33)))
        (d/'exits').write_text(''.join('%s wg%s wg%s 1\n'%(i,i,i) for i in range(1,33)))
        rows=basic+['%s: from all uidrange %s-%s lookup wg%s'%(140+i,48100+i,48100+i,i) for i in range(1,33)]
        reset_rules(rows)
        mutate(lambda s:s.update(iptables=[],ports={'wg'+str(i):51800+i for i in range(1,33)}))
        r=run('snapshot=$(ip rule show); nr_probe_owner_routes_sync "$snapshot"; nr_wg_transport_sync "$snapshot"')
        check(r.returncode==0,r.stderr)
        calls=read()['calls']
        check(sum(c==['ip','rule','show'] for c in calls)==1,'32 exits share one fresh route inventory')
        check(sum(c==['ipt','-S','NR_OUTPUT'] for c in calls)==1,'32 distinct transports share one kernel chain inventory')
        check(len(read()['iptables'])==32,'all 32 exact transport permissions are present')
        mutate(lambda s:None)
        r=run('snapshot=$(ip rule show); nr_probe_owner_routes_sync "$snapshot"; nr_wg_transport_sync "$snapshot"')
        check(r.returncode==0,r.stderr)
        check(not any(c[:3] in [['ip','rule','add'],['ip','rule','del']] or c[0]=='ipt' and c[1] in ['-I','-D','-A','-C'] for c in read()['calls']),
              'second 32-exit cycle makes zero kernel changes and zero per-pair permission checks')

        print(json.dumps({'passed':True,'checks':checks,'mode':'regression',
                          'scope':'independent mocked kernel state; no production or host kernel accessed'}))


if __name__=='__main__':
    main()

