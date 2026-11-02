#!/usr/bin/env python3
"""Exercise the shipped synchronizer with isolated kernel command responses."""
from pathlib import Path
import json, shlex, subprocess, tempfile

root=Path(__file__).resolve().parents[2]
source=(root/'materials/firmware/port-3726/files/usr/ikuai/script/native_runtime.sh').read_text()
function=source[source.index('nr_wg_probe_reset_sync(){'):source.index('\n# Runs inside')]
checks=0
def check(value, message):
 global checks
 assert value,message
 checks+=1
with tempfile.TemporaryDirectory() as directory:
 p=Path(directory)
 harness=p/'harness.sh'
 harness.write_text('''set -e -o pipefail
NR=$1
ip(){
 if [ "$1 $2" = 'rule show' ];then
  echo scan >> "$NR/scans"
  [ ! -f "$NR/fail" ] || return 1
  cat "$NR/rules"
 elif [ "$*" = '-o -4 addr show' ];then
  echo '1: lo inet 127.0.0.1/8'
 elif [ "$1 $2 $3" = '-o link show' ];then
  [ "$4" != wg9 ] || return 1
  printf '1: %s: <UP,LOWER_UP>\\n' "$4"
 else return 1;fi
}
wg(){ [ "$2" != wg8 ] || { echo 0;return; };case "$2" in wg7)echo invalid;; *)echo "${PORT:-51820}";;esac; }
nr_ipt(){
 printf '%s\\n' "$*" >> "$NR/iptables"
 case "$1" in
  -S) printf '%s\\n' '-N NR_OUTPUT';cat "$NR/kernel-iptables";;
  -I) printf '%s\\n' "-A $2 ${*:4}" >> "$NR/kernel-iptables";;
  -D) awk -v row="-A $2 ${*:3}" '$0!=row' "$NR/kernel-iptables" > "$NR/kernel-next";mv "$NR/kernel-next" "$NR/kernel-iptables";;
  *) return 1;;
 esac
}
'''+function+'\nnr_wg_transport_sync\n')
 (p/'kernel-iptables').write_text('')
 (p/'rules').write_text('1: from all fwmark 0x10001 lookup wan1\n2: from all fwmark 0x10001 lookup wan1\n3: from all fwmark 0x10002 lookup wan2\n4: fwmark 0x55000101 lookup wg1\n5: fwmark 0x58000101 lookup wg2\n6: fwmark 0x0 lookup wan1\n7: fwmark 0x20001/0xff lookup wan2\n8: fwmark 0x20002 prohibit\n')
 def run(exits, fail=False, port=None):
  (p/'exits').write_text(exits)
  for name in ('scans','iptables'):(p/name).write_text('')
  if fail:(p/'fail').touch()
  else:(p/'fail').unlink(missing_ok=True)
  env=__import__('os').environ.copy()
  if port:env['PORT']=str(port)
  result=subprocess.run(['bash',str(harness),str(p)],capture_output=True,text=True,env=env)
  return result,(p/'scans').read_text().splitlines(),(p/'iptables').read_text().splitlines()
 for exits in ('','1 wan1 wan1 1\n','1 wg9 wg9 1\n2 wg8 wg8 1\n3 wg7 wg7 1\n'):
  r,scans,calls=run(exits);check(r.returncode==0,r.stderr);check(not scans,'no inventory without eligible WG')
 for count in (1,2,32):
  exits=''.join(f'{i+1} wg{i+20} wg{i+20} 1\n' for i in range(count))
  r,scans,calls=run(exits);check(r.returncode==0,r.stderr);check(len(scans)==1,'one fresh inventory per invocation')
  check((p/'wg-transport').read_text()=='51820 0x10001\n51820 0x10002\n','same allowed mark/port pairs; excluded marks absent')
  if count>1:check(calls==['-S NR_OUTPUT'],'unchanged state reads the chain once without mutating firewall')
 old=(p/'wg-transport').read_text()
 r,scans,calls=run(exits,fail=True)
 check(r.returncode!=0,'kernel read failure reported');check((p/'wg-transport').read_text()==old and not calls,'read failure preserves installed state');check(not (p/'wg-transport.next').exists(),'no partial snapshot retained')
 (p/'rules').write_text('1: fwmark 0x10003 lookup wan3\n')
 r,scans,calls=run(exits,port=51999)
 check(r.returncode==0,r.stderr);check((p/'wg-transport').read_text()=='51999 0x10003\n','next call observes port and route changes')
 check(sum(x.startswith('-D ')for x in calls)==2,'obsolete exemptions removed')
 check(all('--uid-owner 48101-48232' in x and '--sport ' in x for x in calls if not x.startswith('-S ')),'owner and source port retained')
 (p/'rules').write_text('1: from all lookup main\n')
 r,scans,calls=run(exits);check(r.returncode==0,r.stderr);check((p/'wg-transport').read_text()=='','valid empty inventory removes last exception')
 check(any(x.startswith('-D ')for x in calls),'empty inventory cleanup')
print(json.dumps({'passed':True,'checks':checks,'scope':'isolated synchronizer, no kernel or router modified'}))
