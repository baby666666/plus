#!/usr/bin/env python3
"""Exercise real health sampler functions with isolated command/device fixtures."""
import os, pathlib, subprocess, tempfile, time
ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE=ROOT/'firmware/port-3726/files/usr/ikuai/script/native_exit_health.sh'
passed=0
with tempfile.TemporaryDirectory(prefix='nr-health-') as td:
 d=pathlib.Path(td);state=d/'state';state.mkdir();(state/'now').write_text('100')
 common='''set -e
source "$SOURCE"
NR="$STATE"
nr_health_now(){ cat "$NR/now"; }
# This suite controls device/signature results below. The separate inventory
# suite exercises the real global public snapshot and its failure handling.
nr_health_inventory(){ ip -o -4 addr show > "$1/addresses"; }
nr_health_signature(){ printf '%s %s' "$*" "$(cat "$NR/identity" 2>/dev/null || true)" | sha256sum | awk '{print $1}'; }
nr_health_device(){ [ ! -f "$NR/down.$1" ]; }
nr_health_native(){ [ ! -f "$NR/native.$1" ] || return 0;[ ! -f "$NR/native-fail.$1" ] || return 1;return 2; }
nr_health_guarded(){ [ ! -f "$NR/unguarded.$1" ]; }
nr_health_probe(){ echo "$1" >> "$NR/calls"; sleep .03; if [ -f "$NR/fail.$1" ];then echo 0;else echo 1;fi > "$4"; }
ip(){ printf '1: lo inet 127.0.0.1/8\n2: wg9 inet 198.18.1.1/24\n'; }
ik_cntl(){ echo "$*" >> "$NR/published"; }
'''
 def sh(s,body=common,timeout=8):
  return subprocess.run(['/bin/bash','-c',body+s],env={**os.environ,'SOURCE':str(SOURCE),'STATE':str(state)},text=True,capture_output=True,timeout=timeout,check=True).stdout.strip()
 def check(v,label):
  global passed
  assert v,label
  passed+=1;print('PASS',label)
 def setup(n=1):
  for f in state.iterdir():
   if f.is_file():f.unlink()
  (state/'now').write_text('100');(state/'exits').write_text(''.join(f'{i} wg{i} wg{i} 1\n'for i in range(1,n+1)))
  (state/'policies').write_text('1 '+','.join(map(str,range(1,n+1)))+' 6 0\n')
  (state/'policy-workers').write_text('1 1 10.0.2.2\n')
 def health():return {int(r.split()[0]):tuple(map(int,r.split()[1:])) for r in(state/'exit-health').read_text().splitlines()}
 def calls():return (state/'calls').read_text().splitlines() if(state/'calls').exists() else []
 setup();sh('nr_exit_health_sync apply');check(health()=={1:(1,1)},'apply performs first bounded sample')
 check(calls()==['1'],'single initial probe');check('iface_band set wg1 1' in(state/'published').read_text(),'WG native health published')
 (state/'now').write_text('105');sh('nr_exit_health_sync');check(calls()==['1'],'fresh cache avoids repeat network')
 (state/'now').write_text('110');(state/'fail.1').touch();sh('nr_exit_health_sync');check(health()[1]==(0,1),'failed probe is known down')
 (state/'fail.1').unlink();(state/'now').write_text('120');sh('nr_exit_health_sync');check(health()[1]==(1,1),'probe recovery healthy')
 (state/'identity').write_text('new-peer');(state/'unguarded.1').touch();sh('nr_exit_health_sync');check(health()[1]==(0,0),'identity invalidation and missing guard remain unknown')
 (state/'unguarded.1').unlink();sh('nr_exit_health_sync');check(health()[1]==(1,1),'matching guard allows new identity sample')
 (state/'now').write_text('181');(state/'unguarded.1').touch();sh('nr_exit_health_sync');check(health()[1]==(0,0),'expired positive cache not reused')
 (state/'unguarded.1').unlink();sh('nr_exit_health_sync');(state/'now').write_text('50');(state/'unguarded.1').touch();sh('nr_exit_health_sync');check(health()[1]==(0,0),'uptime rollback invalidates positive cache')
 setup();(state/'down.wg1').touch();sh('nr_exit_health_sync');check(health()[1]==(0,1) and not calls(),'administrative down known without probe')
 setup();(state/'policy-workers').write_text('1 1 127.0.0.1\n2 1 198.18.1.1\n');sh('nr_exit_health_sync');check(health()[1]==(0,0) and not calls(),'loopback and router local targets excluded')
 setup();(state/'policy-workers').write_text('1 1 10.0.2.2\n2 1 10.0.2.3\n3 1 10.0.2.4\n');(state/'locals').write_text('10.0.2.2\n');check(sh('nr_health_targets 1 "$NR/locals"')=='10.0.2.3\n10.0.2.4','target cap and local exclusion')
 for target,wanted in [('1.1.1.1',0),('198.18.2.1',0),('0.0.0.0',1),('127.2.3.4',1),('224.0.0.1',1),('1.2.3.256',1),('1.2.3',1),('1.2.3.4;echo',1)]:
  out=sh('set +e;nr_health_ipv4 '+repr(target)+';echo $?');check(int(out)==wanted,'IPv4 target validation '+target)
 setup(32)
 sh('nr_exit_health_sync apply');check(len(calls())==4,'32 exits first apply bounded to four');check(sum(v[1] for v in health().values())==4,'unsampled exits explicitly unknown')
 for n in range(1,8):
  (state/'now').write_text(str(100+3*n));sh('nr_exit_health_sync')
 check(len(calls())==32 and len(set(calls()))==32,'oldest first visits 32 exits without starvation');check(all(v==(1,1)for v in health().values()),'all 32 sampled within TTL')
 setup(5)
 for i in range(1,5):(state/f'unguarded.{i}').touch()
 sh('nr_exit_health_sync');check(calls()==['5'] and health()[5]==(1,1),'missing guards do not consume probe slots or starve later exit')
 check(all(health()[i]==(0,0)for i in range(1,5)),'missing guard candidates remain unknown')
 setup();(state/'exits').write_text('1 wan1 wan1_ad 1\n');(state/'native.wan1').touch();sh('nr_exit_health_sync');check(health()[1]==(1,1) and not calls(),'WAN uses native health without new probe')
 (state/'native.wan1').unlink();(state/'native-fail.wan1').touch();sh('nr_exit_health_sync');check(health()[1]==(0,1),'native WAN failure overrides previous healthy cache')
 (state/'native-fail.wan1').unlink();sh('nr_exit_health_sync');check(health()[1]==(0,0),'missing WAN monitor stays unknown instead of permitting fallback')
 mon=d/'monitor';mon.mkdir();native=d/'native-source.sh';native.write_text(SOURCE.read_text().replace('/tmp/iktmp/monitor-link',str(mon)))
 for status,expected in [(None,2),('',2),('--',2),('fail',1),('success',0)]:
  if status is not None:(mon/'wan1_ad').write_text('wan1_ad wan1 ip gw mode time auto '+status+'\n')
  out=sh(f'set +e;source "{native}";nr_health_native wan1 wan1_ad;echo $?',body='')
  check(int(out)==expected,'real native monitor status '+repr(status))
 device='''set -e;source "$SOURCE"
ip(){ case "$*" in '-o link show wan1_ad') echo '1: wan1_ad: <UP,LOWER_UP>';; '-o -4 addr show dev wan1_ad') echo '1: wan1_ad inet 192.0.2.1/24';; *) return 1;;esac; }
'''
 check(sh('nr_health_device wan1 wan1_ad;echo OK',device)=='OK','PPPoE real device IPv4 sufficient without logical address')
 # The real supervisor/child functions run separate shell processes. Replace
 # only the absolute external executable with a fixture, retaining all traps.
 fake=d/'strict-probe';fake.write_text('#!/bin/bash\necho $$ >> "$PROBE_PIDS"\nif [ "$PROBE_KIND" = success ];then exit 0;fi\ntrap "" TERM\nwhile :;do sleep 1;done\n');fake.chmod(0o755)
 source=d/'probe-source.sh';source.write_text(SOURCE.read_text().replace('/usr/sbin/strict-probe',str(fake)))
 env={**os.environ,'PROBE_PIDS':str(d/'pids'),'PROBE_KIND':'success'}
 def run_probe(kind):
  env['PROBE_KIND']=kind
  return subprocess.run(['/bin/bash','-c',f'source "{source}";nr_health_probe 1 wg1 10.0.2.2,10.0.2.3 "{d}/result"'],env=env,capture_output=True,text=True,timeout=5,check=True)
 run_probe('success');check((d/'result').read_text().strip()=='1','real concurrent shell probe accepts success')
 (d/'result.ok').unlink();start=time.monotonic();run_probe('hang');elapsed=time.monotonic()-start
 check((d/'result').read_text().strip()=='0' and elapsed<4,'real child processes bounded despite ignored TERM')
 live=[]
 for pid in(d/'pids').read_text().splitlines():
  try:os.kill(int(pid),0);live.append(pid)
  except ProcessLookupError:pass
 check(not live,'probe child processes cleaned after bound')
 check(not list(state.glob('.health.*')),'private temporary snapshots cleaned')
print(f'{passed} native exit health assertions passed')
