#!/usr/bin/env python3
"""Run the actual ingress helper against isolated link/tc command fixtures."""
from pathlib import Path
import json
import os
import subprocess
import tempfile

source = Path(__file__).resolve().parents[1] / 'firmware/port-3726/files/usr/ikuai/script/native_ingress.sh'
checks = 0


def check(ok, name):
    global checks
    assert ok, name
    checks += 1
    print('PASS', name, flush=True)


driver = r'''#!/usr/bin/env python3
from pathlib import Path
import json,os,sys
p=Path(os.environ['FIXTURE']);f=p/'state.json';s=json.loads(f.read_text());a=sys.argv[1:];tool=Path(sys.argv[0]).name
def save():f.write_text(json.dumps(s))
def mutate():
 with (p/'mutations').open('a') as out:out.write(tool+' '+' '.join(a)+'\n')
def val(k):return a[a.index(k)+1]
def device():return val('dev')
def iface(name):return p/'net'/name
def make(name,index,mtu,flags):
 q=iface(name);q.mkdir(exist_ok=True)
 for k,v in [('ifindex',index),('mtu',mtu),('flags',flags)]:(q/k).write_text(str(v)+'\n')
if s.get('fail')==tool+' '+' '.join(a):sys.exit(1)
if tool=='ip':
 if a[:5]==['-o','-4','addr','show','dev']:
  name=a[5]
  for address in s.get('addresses',{}).get(name,[]):print('1: '+name+' inet '+address+' scope global '+name)
 elif a[:3]==['tunnel','show','pppwg3']:
  t=s.get('tunnel')
  if t:print('pppwg3: '+s.get('tunnel_kind','any/ip')+' remote '+t['remote']+' local '+t['local']+' dev '+t['dev']+' ttl inherit')
 elif a[:3]==['link','add','pppwg3']:
  mutate();make('pppwg3',20,1480,'0x80');s['tunnel']={'local':val('local'),'remote':val('remote'),'dev':val('dev')};save()
 elif a[:3]==['tunnel','change','pppwg3']:
  mutate();s['tunnel']={'local':val('local'),'remote':val('remote'),'dev':val('dev')};save()
 elif a[:4]==['-4','addr','flush','dev']:
  mutate();s['addresses'][device()]=[];save()
 elif a[:2]==['addr','add']:
  mutate();s['addresses'].setdefault(device(),[]).append(a[2]);save()
 elif a[:3]==['link','set','pppwg3']:
  mutate();(iface('pppwg3')/'mtu').write_text(val('mtu')+'\n');(iface('pppwg3')/'flags').write_text('0x81\n')
 elif a[:3]==['link','del','pppwg3']:
  mutate()
  for item in iface('pppwg3').iterdir():item.unlink()
  iface('pppwg3').rmdir();s['addresses'].pop('pppwg3',None);s['tunnel']=None;save()
 else:raise RuntimeError('unhandled fixture ip command')
elif tool=='tc':
 if a[:2]==['qdisc','show']:
  print('qdisc fq_codel 0: root refcnt 2 limit 10240p')
  if s.get('qdisc'):print('qdisc '+s['qdisc']+' '+s.get('handle','ffff:')+' parent ffff:fff1')
 elif a[:2]==['qdisc','add']:
  mutate();assert not s.get('qdisc');s['qdisc']='ingress';s['handle']=val('handle');save()
 elif a[:2]==['filter','show']:
  pref=val('pref');row=s['filters'].get(pref)
  expected=s.get('handle','ffff:')+('fff2' if s.get('qdisc')=='clsact' else '')
  if val('parent')==expected and row:
   print('filter protocol ip pref '+pref+' u32 chain 0')
   print('filter protocol ip pref '+pref+' u32 chain 0 fh 800: ht divisor 1')
   print('filter protocol ip pref '+pref+' u32 chain 0 fh 800::800 order 2048 key ht 800 bkt 0 terminal flowid ???')
   for match in row.get('matches',[]):print('  match '+match)
   for action in row.get('actions',[]):print('  action order 1: '+action)
 elif a[0]=='filter' and a[1] in ('add','replace','del'):
  mutate();pref=val('pref');expected=s.get('handle','ffff:')+('fff2' if s.get('qdisc')=='clsact' else '')
  assert val('parent')==expected,'wrong ingress parent'
  if a[1]=='del':s['filters'].pop(pref,None)
  elif 'dst' in a:
   address=val('dst').split('/')[0];h=''.join('%02x'%int(v) for v in address.split('.'))
   s['filters'][pref]={'matches':[h+'/ffffffff at 16'],'actions':['gact action pass']}
  else:s['filters'][pref]={'matches':['00000000/00000000 at 12'],'actions':['mirred (Ingress Redirect to device '+val('dev')+') stolen']}
  # val(dev) is the first dev; the redirect target is the final argument.
  if a[1]!='del' and 'mirred' in a:s['filters'][pref]['actions']=['mirred (Ingress Redirect to device '+a[-1]+') stolen']
  save()
 else:raise RuntimeError('unhandled fixture tc command')
else:raise RuntimeError('unknown fixture tool')
'''


with tempfile.TemporaryDirectory(prefix='native-ingress-state-') as td:
    p = Path(td)
    net = p / 'net'
    state_dir = p / 'owned'
    bindir = p / 'bin'
    for directory in (net, state_dir, bindir):
        directory.mkdir()
    for tool in ('ip', 'tc'):
        f = bindir / tool
        f.write_text(driver)
        f.chmod(0o700)
    helper = p / 'native_ingress.sh'
    helper.write_text(source.read_text().replace('/tmp/iktmp/native-wg-ingress', str(state_dir)).replace('/sys/class/net', str(net)))

    def setup():
        for path in net.glob('*/*'):
            path.unlink()
        for path in net.iterdir():
            path.rmdir()
        for path in state_dir.iterdir():
            path.unlink()
        for name, index in [('wg3', 13), ('pppwg3', 20)]:
            q = net / name
            q.mkdir()
            for field, value in [('ifindex', index), ('mtu', 1420), ('flags', '0x81')]:
                (q / field).write_text(str(value) + '\n')
        s = {'qdisc': 'ingress', 'handle': 'ffff:', 'addresses': {'wg3': ['10.100.2.1/24'], 'pppwg3': ['10.100.2.1/32']},
             'tunnel': {'local': '127.252.0.13', 'remote': '127.253.0.13', 'dev': 'lo'},
             'filters': {'49200': {'matches': ['0a640201/ffffffff at 16'], 'actions': ['gact action pass']},
                         '49201': {'matches': ['00000000/00000000 at 12'], 'actions': ['mirred (Ingress Redirect to device pppwg3) stolen']}}}
        (state_dir / 'wg3').write_text('13\n')
        (state_dir / 'wg3.local-address').write_text('10.100.2.1\n')
        put(s)
        (p / 'mutations').write_text('')
        return s

    def put(s):
        (p / 'state.json').write_text(json.dumps(s))

    def get():
        return json.loads((p / 'state.json').read_text())

    def run(action='up', name='wg3'):
        return subprocess.run(['bash', str(helper), action, name], capture_output=True, text=True, timeout=10,
                              env={**os.environ, 'FIXTURE': str(p), 'PATH': str(bindir) + os.pathsep + os.environ['PATH']})

    def mutations():
        return (p / 'mutations').read_text().splitlines()

    # Minimal old-code reproduction: the cache and gact action remain present,
    # but the actual dst /32 was replaced by another address. It must be fixed.
    s = setup()
    s['filters']['49200']['matches'] = ['0a6402ff/ffffffff at 16']
    put(s)
    r = run()
    check(r.returncode == 0 and get()['filters']['49200']['matches'] == ['0a640201/ffffffff at 16'],
          'same cached address with wrong live tc destination is repaired')

    s = setup()
    r = run('check')
    check(r.returncode == 0 and not mutations(), 'coherent single-interface check is read-only')
    check(run().returncode == 0 and not mutations(), 'coherent up performs no duplicate link or tc writes')
    s['tunnel_kind'] = 'ip/ip'
    put(s)
    check(run('check').returncode == 0 and not mutations(), 'both native any/ip and ip/ip tunnel display formats are accepted')
    for pref, row, label in [
        ('49200', None, 'missing local reply exception'),
        ('49200', {'matches': ['0a640201/ffffff00 at 16'], 'actions': ['gact action pass']}, 'wide destination mask'),
        ('49200', {'matches': ['0a640201/ffffffff at 12'], 'actions': ['gact action pass']}, 'wrong match offset'),
        ('49200', {'matches': ['0a640201/ffffffff at 16'], 'actions': ['gact action drop']}, 'wrong local action'),
        ('49200', {'matches': ['0a640201/ffffffff at 16', '00000000/00000000 at 12'], 'actions': ['gact action pass']}, 'extra local selector'),
        ('49201', None, 'missing forwarding redirect'),
        ('49201', {'matches': ['0a000000/ff000000 at 12'], 'actions': ['mirred (Ingress Redirect to device pppwg3) stolen']}, 'restricted forwarding selector'),
        ('49201', {'matches': ['00000000/00000000 at 12'], 'actions': ['mirred (Ingress Redirect to device pppwg9) stolen']}, 'wrong redirect device'),
    ]:
        s = setup()
        if row is None:
            s['filters'].pop(pref)
        else:
            s['filters'][pref] = row
        put(s)
        r = run('check')
        check(r.returncode != 0 and not mutations(), label + ' detected without mutation')
        r = run()
        check(r.returncode == 0 and run('check').returncode == 0, label + ' repaired')

    s = setup()
    s['qdisc'] = 'clsact'
    put(s)
    check(run('check').returncode == 0 and not mutations(), 'external clsact ingress parent is inspected without replacement')
    s['filters'].pop('49200')
    put(s)
    check(run().returncode == 0 and get()['qdisc'] == 'clsact' and not any('qdisc add' in x for x in mutations()), 'repair preserves existing clsact and root qdisc')
    s = setup()
    s['handle'] = '1234:'
    put(s)
    check(run('check').returncode == 0 and not mutations(), 'existing ingress handle is respected')

    s = setup()
    s['addresses']['pppwg3'] = ['10.100.9.1/32']
    put(s)
    check(run('check').returncode != 0 and not mutations(), 'wrong helper address is detected')
    check(run().returncode == 0 and get()['addresses']['pppwg3'] == ['10.100.2.1/32'] and get()['addresses']['wg3'] == ['10.100.2.1/24'], 'helper DNS address restored without changing WG address')
    s = setup()
    (net / 'wg3/ifindex').write_text('27\n')
    check(run('check').returncode != 0 and run().returncode == 0 and get()['tunnel']['local'] == '127.252.0.27' and run('check').returncode == 0, 'same-address recreated WG interface repairs helper tunnel identity')
    s = setup()
    (net / 'pppwg3/mtu').write_text('1200\n')
    (net / 'pppwg3/flags').write_text('0x80\n')
    check(run('check').returncode != 0 and run().returncode == 0 and run('check').returncode == 0, 'helper MTU and UP state recover')
    s = setup()
    s['addresses']['wg3'] = ['10.100.9.1/24']
    put(s)
    check(run('check').returncode != 0 and run().returncode == 0 and run('check').returncode == 0 and
          get()['filters']['49200']['matches'] == ['0a640901/ffffffff at 16'], 'changed WG address updates helper DNS and actual destination selector')
    s = setup()
    s['tunnel']['local'] = '127.252.0.99'
    put(s)
    check(run('check').returncode != 0 and run().returncode == 0 and run('check').returncode == 0, 'wrong actual helper tunnel identity is repaired despite matching cache')
    s = setup()
    for item in (net / 'pppwg3').iterdir():
        item.unlink()
    (net / 'pppwg3').rmdir()
    for item in state_dir.iterdir():
        item.unlink()
    s['qdisc'] = None
    s['filters'] = {}
    s['tunnel'] = None
    s['addresses'].pop('pppwg3')
    put(s)
    check(run().returncode == 0 and run('check').returncode == 0 and get()['qdisc'] == 'ingress', 'new interface creates only its helper and ingress rules')
    s = setup()
    s['addresses']['pppwg3'].append('10.100.9.1/32')
    put(s)
    check(run('check').returncode != 0 and run().returncode == 0 and get()['addresses']['pppwg3'] == ['10.100.2.1/32'], 'extra stale address is removed only from owned helper')
    s = setup()
    (state_dir / 'wg3').unlink()
    check(run().returncode != 0 and not mutations(), 'foreign reserved helper is not modified')
    s = setup()
    (state_dir / 'wg3').unlink()
    for item in (net / 'pppwg3').iterdir():
        item.unlink()
    (net / 'pppwg3').rmdir()
    check(run().returncode != 0 and not mutations(), 'unowned reserved filters are not overwritten when helper is absent')
    s = setup()
    s['fail'] = 'tc qdisc show dev wg3'
    put(s)
    check(run('check').returncode != 0 and run().returncode != 0 and not any(x.startswith('tc ') for x in mutations()), 'qdisc read failure does not replace external qdisc')
    s = setup()
    s['fail'] = 'tc filter show dev wg3 parent ffff: protocol ip pref 49200'
    put(s)
    check(run('check').returncode != 0 and run().returncode != 0 and not any(x.startswith('tc ') for x in mutations()), 'filter read failure does not blindly replace rules')
    s = setup()
    s['filters'].pop('49200')
    s['fail'] = 'tc filter add dev wg3 parent ffff: protocol ip pref 49200 u32 match ip dst 10.100.2.1/32 action gact pass'
    put(s)
    check(run().returncode != 0 and run('check').returncode != 0, 'failed rule installation is never reported as repaired')
    s = setup()
    s['qdisc'] = 'clsact'
    s['filters']['40000'] = {'matches': [], 'actions': ['external']}
    put(s)
    check(run('down').returncode == 0 and get()['qdisc'] == 'clsact' and '40000' in get()['filters'] and
          not (net / 'pppwg3').exists() and not (state_dir / 'wg3').exists(), 'owned teardown preserves external qdisc and unrelated filters')
    s = setup()
    for item in state_dir.iterdir():
        item.unlink()
    state_dir.rmdir()
    check(run('check').returncode != 0 and not state_dir.exists() and not mutations(), 'read-only check does not create missing ownership state')
    state_dir.mkdir()
    s = setup()
    check(run('check', 'wg3;bad').returncode != 0 and not mutations(), 'invalid interface cannot select a command or path')

print('NATIVE_INGRESS_STATE_PASS', checks)
