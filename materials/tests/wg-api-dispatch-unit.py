#!/usr/bin/env python3
"""Exercise actual native dispatcher with isolated, delayed mock modules.

Only the fixed module-directory path is redirected. No router or API server is
contacted. Background mock operations terminate before temporary files vanish.
"""
from pathlib import Path
import json,subprocess,sys,tempfile,time
source=Path(sys.argv[1]).read_text()
assert source.count('IK_DIR_FUNCAPI=/usr/ikuai/function')==1
count=0
with tempfile.TemporaryDirectory(prefix='wg-api-dispatch-') as tmp:
 d=Path(tmp);modules=d/'modules';modules.mkdir()
 dispatcher=d/'func_api.sh'
 dispatcher.write_text(source.replace('IK_DIR_FUNCAPI=/usr/ikuai/function','IK_DIR_FUNCAPI="'+str(modules)+'"'))
 module=r'''#!/bin/bash
up(){ :; }
down(){ :; }
del(){ :; }
show(){ :; }
name=${0##*/}
state="${0%/*}/$name.state"
printf 'START\n' > "$state"
sleep .2
printf 'DONE\n' > "$state"
if [ -f "${0%/*}/$name.fail" ];then
 printf '%s\n' 'Controlled WG apply failure'
 exit 7
fi
exit 0
'''
 for name in ['wireguard','other_native','ike_client']:
  p=modules/name;p.write_text(module);p.chmod(0o755)
 def run(name,action,failure=False):
  state=modules/(name+'.state');state.unlink(missing_ok=True)
  flag=modules/(name+'.fail');flag.unlink(missing_ok=True)
  if failure:flag.touch()
  r=subprocess.run(['bash',str(dispatcher),name,action,'id=4'],capture_output=True,text=True,timeout=5)
  assert r.returncode==0,(name,action,'dispatcher exit',r.stderr)
  obj=json.loads(r.stdout)
  completed=state.exists() and state.read_text()=='DONE\n'
  return obj,completed
 for action in ['up','down','del']:
  for failure in [False,True]:
   count+=1;obj,completed=run('wireguard',action,failure)
   assert completed,(action,'returned before WG mutation finished')
   assert obj['Result']==(30002 if failure else 30000),(action,obj)
   assert obj['ErrMsg']==('Controlled WG apply failure' if failure else 'Success'),(action,obj)
 count+=1;obj,completed=run('wireguard','clean')
 assert obj['Result']==30002 and obj['ErrMsg']=='invalid action' and not completed,'no new WG clean action introduced'
 count+=1;obj,completed=run('other_native','down',True)
 assert obj['Result']==30000 and not completed,'unrelated native asynchronous behavior changed'
 # Wait for the intentionally background fixture; do not remove its directory early.
 deadline=time.monotonic()+3
 while time.monotonic()<deadline:
  state=modules/'other_native.state'
  if state.exists() and state.read_text()=='DONE\n':break
  time.sleep(.02)
 else:raise AssertionError('background fixture did not finish')
 count+=1;obj,completed=run('ike_client','up',True)
 assert obj['Result']==30002 and completed,'existing native synchronous exception changed'
print(f'PASS {count} WG API dispatch completion, error and compatibility cases')
