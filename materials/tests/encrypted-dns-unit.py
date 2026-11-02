#!/usr/bin/env python3
"""Validate real Lua configuration and emitted firewall scope, without a router."""
from pathlib import Path
import copy,json,subprocess,tempfile
from lupa.lua51 import LuaRuntime
root=Path(__file__).resolve().parents[2]
scripts=root/'materials/firmware/port-3726/files/usr/ikuai/script'
lua=LuaRuntime(unpack_returned_tuples=True)
module=lua.eval('dofile')(str(scripts/'encrypted_dns.lua'))
def table(v):
 if isinstance(v,dict):return lua.table_from({k:table(x)for k,x in v.items()})
 if isinstance(v,list):return lua.table_from([table(x)for x in v])
 return v
checks=0
def check(v,msg):
 global checks
 assert v,msg
 checks+=1
base={'enabled':True,'sources':['198.18.1.2/32'],'ingress':'wg1','exceptions':[],
      'allowed':[],'custom':[],'dot':True,'doh':True,'builtin':True}
check(module.command(None)=='nr_encrypted_dns_off','legacy configs default off')
valid=[{}, {'sources':[]}, {'ingress':''}, {'enabled':False,'sources':[],'ingress':''},
       {'sources':['198.18.1.9/24','0.0.0.0/0']}, {'dot':False}, {'doh':False,'builtin':False},
       {'builtin':False,'custom':['192.0.2.53/32']}, {'exceptions':['198.18.1.3'],'allowed':['1.1.1.1']}]
for patch in valid:
 c=module.normalize(table({**base,**patch}));check(c is not None,'valid scope')
invalid=[{'enabled':1},{'sources':[],'ingress':''},{'dot':False,'doh':False},
 {'builtin':False},{'sources':['10.0.0.1/33']},{'sources':['256.0.0.1']},
 {'sources':['10.0.0.1\n-j ACCEPT']},{'sources':['10.0.0.1/24','10.0.0.9/24']},
 {'sources':['x']},{'sources':'10.0.0.1'},{'sources':{'x':'10.0.0.1'}},
 {'sources':['10.0.0.1']*65},{'ingress':'wan1'},{'ingress':'wg+'},
 {'ingress':'wg1;echo x'},{'ingress':'pppwg1'}, {'custom':['192.0.2.0/24']},
 {'allowed':['0.0.0.0']},{'custom':['224.0.0.1']},{'unused':True}]
for patch in invalid:
 try:module.normalize(table({**base,**patch}))
 except Exception:check(True,'invalid rejected')
 else:raise AssertionError(('accepted invalid',patch))
normalized=module.normalize(table({**base,'sources':['198.18.1.199/24']}))
check(normalized.sources[1]=='198.18.1.0/24','canonical network')
runtime=(scripts/'native_runtime.sh').read_text().replace('source /usr/ikuai/script/native_exit_health.sh','')
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'runtime.sh').write_text(runtime)
 def emitted(config):
  command=module.command(table(config))
  sh='''set -e -o pipefail
source "$1"
nr_ipt(){ [ "$1" != -D ] || return 1;printf 'IPT %s\\n' "$*"; }
ipset(){ printf 'SET %s\\n' "$*"; }
'''+command+'\n'
  (p/'run.sh').write_text(sh)
  return subprocess.check_output(['bash',str(p/'run.sh'),str(p/'runtime.sh')],text=True).splitlines()
 rows=emitted({**base,'sources':['0.0.0.0/0'],'exceptions':['198.18.1.3/32'],'allowed':['1.1.1.1']})
 text='\n'.join(rows)
 check('SET add nr_edns_src 0.0.0.0/1' in text and 'SET add nr_edns_src 128.0.0.0/1' in text,'explicit /0 ipset representation')
 check('-i wg1 -j NR_EDNS_DROP' in text and '-i pppwg1 -j NR_EDNS_DROP' in text,'native and WG reinjection ingress')
 check('--ctdir REPLY -j RETURN' in text,'no reply-direction block')
 check('--match-set nr_edns_except src -j RETURN' in text and '--match-set nr_edns_allow dst -j RETURN' in text,'exceptions continue existing firewall')
 drops=[r for r in rows if r.endswith('-j DROP')]
 check(len(drops)==4 and all('--dport 853' in r or ('--dport 443' in r and '--match-set nr_edns_dest dst' in r)for r in drops),'no blanket 443 block')
 check(all('OUTPUT' not in r and 'INPUT' not in r for r in rows),'router upstream and management unaffected')
 check(len([r for r in emitted({**base,'dot':False})if r.endswith('-j DROP')])==2,'DoT toggle')
 check(len([r for r in emitted({**base,'doh':False})if r.endswith('-j DROP')])==2,'DoH toggle')
 rows=emitted({**base,'enabled':False});check(not any('-A 'in r for r in rows),'disabled installs no forwarding match')
check("nr_hook filter FORWARD NR_EDNS" in runtime,'restriction before forward acceptance')
print(json.dumps({'passed':True,'checks':checks,'scope':'real validation and emitter; native traffic tests required separately'}))
