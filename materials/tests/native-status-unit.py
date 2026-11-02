#!/usr/bin/env python3
"""Bounded read-only routing status checks; no router or real credentials needed."""
from pathlib import Path
import argparse
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--lua', default='lua')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
scripts = root / 'firmware/port-3726/files/usr/ikuai/script'
passed = 0


def check(ok, label):
    global passed
    assert ok, label
    passed += 1
    print('PASS', label, flush=True)


with tempfile.TemporaryDirectory(prefix='native-status-test-') as tmp:
    d = Path(tmp)
    (d / 'read-max').write_bytes(b'x' * 32768)
    (d / 'read-large').write_bytes(b'x' * 32769)
    lua = r'''
package.preload.cjson=function()return {}end
NATIVE_STATUS_TEST=true
local api=dofile(SOURCE)
local count=0
local function check(ok,label)
 assert(ok,label);count=count+1;print('PASS '..label)
end
local prefix='/tmp/iktmp/native-rules/'
local guard={
 {'iptables -t mangle -S NR_GUARD 2>/dev/null','NR_GUARD'},
 {'iptables -S NR_FORWARD_GUARD 2>/dev/null','NR_FORWARD_GUARD'},
 {'iptables -S NR_OUT_GUARD 2>/dev/null','NR_OUT_GUARD'}
}
local files,commands,calls,reads,existing
local function reset()
 files={['/proc/uptime']='1000.00 50.00'}
 commands={['ipset list nr_quarantine -terse 2>/dev/null']='Name: nr_quarantine\nNumber of entries: 0\n'}
 for _,g in ipairs(guard)do commands[g[1]]='-N '..g[2]..'\n'end
 calls={};reads={};existing={}
end
local function file(name,value)files[prefix..name]=value end
local function run(busy)
 return api.collect({
  read=function(path)reads[#reads+1]=path;return files[path]end,
  exists=function(path)return existing[path]or false end,
  time=function()return 10000 end,
  command=function(cmd)calls[#calls+1]=cmd;return commands[cmd]end
 },busy)
end
local function has(t,value)for _,v in ipairs(t)do if v==value then return true end end;return false end
local function text(value)
 if type(value)~='table'then return tostring(value)end
 local items={};for k,v in pairs(value)do items[#items+1]=tostring(k)..'='..text(v)end
 return '{'..table.concat(items,',')..'}'
end
reset();local result=run()
check(result.phase=='inactive'and result.guard=='clear'and not result.busy,'complete empty guards report inactive')
existing[prefix..'active/snapshot.json']=true;result=run()
check(result.phase=='running'and result.guard=='clear','complete applied snapshot reports running')
for i,g in ipairs(guard)do
 reset();existing[prefix..'active/snapshot.json']=true;commands[g[1]]=nil;result=run()
 check(result.phase=='unknown'and result.guard=='unknown'and has(result.reasons,'guard_status_unavailable'),'missing guard command '..i..' remains unknown')
end
for _,bad in ipairs{'','unexpected diagnostic\n','-N WRONG_CHAIN\n','-N NR_GUARD\nmalformed\n',string.rep('x',65537)}do
 reset();existing[prefix..'active/snapshot.json']=true;commands[guard[1][1]]=bad;result=run()
 check(result.phase=='unknown'and result.guard=='unknown','malformed or oversized guard sample cannot report clear')
end
reset();commands[guard[1][1]]='-N NR_GUARD\n-A NR_GUARD -i wg1 -j DROP\n';result=run()
check(result.phase=='protected'and result.guard=='active'and has(result.reasons,'forwarding_guard'),'observed drop guard is protected')
commands[guard[2][1]]=nil;result=run()
check(result.phase=='protected'and result.guard=='active'and has(result.reasons,'guard_status_unavailable'),'observed protection survives incomplete other guard samples')
reset();commands[guard[1][1]]='-N NR_GUARD\n-A NR_GUARD -j DROPPED\n';result=run()
check(result.guard=='clear','only exact DROP target is recognized')
for _,item in ipairs{{'boot.pending','starting'},{'commit.pending','applying'},{'native-stage.pending','protected'},{'native-dirty','protected'},{'policy-reconcile.failed','protected'}}do
 reset();existing[prefix..item[1]]=true;commands[guard[1][1]]=nil;result=run()
 check(result.phase==item[2]and has(result.reasons,item[1]),'pending phase survives unavailable commands: '..item[1])
end
reset();existing[prefix..'commit.pending']=true;existing[prefix..'boot.pending']=true;result=run()
check(result.phase=='starting','startup takes precedence over commit flag')
reset();file('exits','1 wg1 wg1 1\n');file('policy-workers','1 7 1.1.1.1\n');result=run(true)
check(result.phase=='busy'and result.busy and result.guard=='unknown'and #calls==0 and #result.exits==0 and #result.workers==0 and result.dns_front==nil,'busy read executes no diagnostic commands or detail reads')
check(#reads==1 and reads[1]=='/proc/uptime','busy read does not inspect worker, exit or process data')
reset();file('active/front.pid','123\n');files['/proc/123/cmdline']='/usr/sbin/native-rule-dns\0PRIVATE_ARGUMENT\0';result=run()
check(result.dns_front=='running'and not text(result):find('PRIVATE_ARGUMENT',1,true),'expected executable is recognized without leaking arguments')
files['/proc/123/cmdline']='/usr/bin/other\0native-rule-dns\0';result=run()
check(result.dns_front=='stopped','process arguments cannot impersonate DNS executable')
files['/proc/123/cmdline']=nil;result=run()
check(result.dns_front=='unknown','unreadable existing PID sample is unknown')
file('active/front.pid','123;cat /etc/shadow');result=run()
check(result.dns_front=='stopped'and not has(reads,'/proc/123;cat /etc/shadow/cmdline'),'invalid PID cannot select a path or command')
reset();file('exits','1 wg1 wg1 1\n2 wan2 eth1 0\n3 wg3 wg3 1\n4 wg4 wg4 1\n5 wg5 wg5 1\n')
file('exit-health-cache','1 aa 950 1\n2 bb 999 0\n3 cc 939 1\n4 dd 1001 1\n5 ee 0 1\n')
commands['wg show wg1 latest-handshakes 2>/dev/null']='SECRET_PUBLIC_KEY\t9988\nOTHER_KEY\t9990\n'
commands['wg show wg3 latest-handshakes 2>/dev/null']='KEY\t10001\n'
result=run()
check(result.exits[1].health=='reachable'and result.exits[1].probe_age_seconds==50 and result.exits[1].handshake_age_seconds==10,'fresh health cache and latest handshake have bounded ages')
check(result.exits[2].health=='failed'and not result.exits[2].available,'known failed exit remains failed')
check(result.exits[3].health=='unknown'and result.exits[4].health=='unknown'and result.exits[5].health=='unknown','expired, future and zero timestamps remain unknown')
check(result.exits[3].handshake_age_seconds==nil and result.exits[4].handshake_age_seconds==nil,'future or unavailable handshakes do not gain an age')
check(not text(result):find('SECRET_PUBLIC_KEY',1,true)and not text(result):find('OTHER_KEY',1,true),'public keys and full command output are never returned')
reset();file('exits','1 wg1;touch wg1 1\n2 ../secret dev 1\n133 wg9 wg9 1\n0 wg0 wg0 1\n3 wg2 wg2 1\n')
result=run()
check(#result.exits==1 and result.exits[1].interface=='wg2','invalid exit identifiers and shell/path text are rejected')
check(#calls==5 and calls[4]=='wg show wg2 latest-handshakes 2>/dev/null','only fixed guard, public handshake and terse count commands run')
reset();local many={};for i=1,200 do many[#many+1]='1 wg1 wg1 1'end;file('exits',table.concat(many,'\n'));result=run()
check(#result.exits==132 and #text(result)<65536,'exit rows and serialized diagnostic size are bounded')
file('exits',string.rep('1 wg1 wg1 1\n',3000));result=run()
check(#result.exits==0,'oversized exit file is rejected, not accepted as a prefix')
reset();file('policy-workers','1 7 1.1.1.1\n2 8 8.8.8.8\n3 9 9.9.9.9\n33 9 9.9.9.9\n')
file('worker-state/1','wan1 wan1 1000 123');file('worker-state/2','  1000 123');file('worker-state/3','garbage')
file('active/dns-1.pid','88');files['/proc/88/cmdline']='/usr/sbin/strict-dnsmasq\0-C\0SECRET_CONFIG\0';result=run()
check(#result.workers==3 and result.workers[1].state=='selected'and result.workers[1].interface=='wan1'and result.workers[1].process=='running','worker selection and executable are reported')
check(result.workers[2].state=='blocked'and result.workers[3].state=='unknown'and not text(result):find('SECRET_CONFIG',1,true),'blocked and malformed workers stay distinct without private data')
many={};for i=1,100 do many[#many+1]='1 7 1.1.1.1'end;file('policy-workers',table.concat(many,'\n'));result=run()
check(#result.workers==32,'worker row count is bounded')
reset();commands['ipset list nr_quarantine -terse 2>/dev/null']='Name: nr_quarantine\nNumber of entries: 12\n';file('quarantine-window','1061');result=run()
check(result.quarantine.available and result.quarantine.entries==12 and result.quarantine.remaining_seconds==61,'quarantine upper window is reported from uptime')
file('quarantine-window','1062');result=run();check(result.quarantine.remaining_seconds==61,'rounded deadline remains capped at actual 61 second window')
for _,stamp in ipairs{'999','1063','bad'}do
 file('quarantine-window',stamp);result=run();check(result.quarantine.remaining_seconds==nil,'invalid quarantine countdown stays unknown')
end
commands['ipset list nr_quarantine -terse 2>/dev/null']=nil;result=run()
check(not result.quarantine.available and result.quarantine.entries==nil,'failed quarantine command is unavailable')
commands['ipset list nr_quarantine -terse 2>/dev/null']='Number of entries: 262145';result=run()
check(not result.quarantine.available,'quarantine count above configured bound is rejected')
check(api.read(TEMP..'/read-max')==string.rep('x',32768)and api.read(TEMP..'/read-large')==nil and api.read(TEMP..'/missing')==nil,'real file reader enforces complete 32KiB samples')
-- Lua 5.1 close may return true even when its child failed. Test the actual
-- wrapper with that behavior, short reads, and an extra byte beyond the cap.
local original=io.popen
local output,closed,popened,close_result
io.popen=function(cmd)
 popened=cmd;local position=1;closed=false
 return {read=function(self,n)local s=output:sub(position,position+n-1);position=position+n;return s~=''and s or nil end,
 close=function()closed=true;return close_result end}
end
close_result=true;output='valid\n__NR_STATUS_RC:0\n'
check(api.command('FIXED')=='valid'and closed and popened=='FIXED; printf \'\\n__NR_STATUS_RC:%s\\n\' "$?"','command wrapper appends fixed exit-status trailer')
for _,bad in ipairs{'valid\n__NR_STATUS_RC:1\n','valid\n__NR_STATUS_RC:127\n','valid','valid\n__NR_STATUS_RC:0\n__NR_STATUS_RC:7\n'}do
 output=bad;check(api.command('FIXED')==nil and closed,'nonzero or missing exit trailer rejects otherwise plausible output')
end
output=string.rep('x',65536)..'\n__NR_STATUS_RC:0\n'
check(api.command('FIXED')==string.rep('x',65536),'command sample exactly at 64KiB is retained')
output=string.rep('x',65537)..'\n__NR_STATUS_RC:0\n'
check(api.command('FIXED')==nil,'command sample one byte over 64KiB is rejected')
output=string.rep('x',70000)..'\n__NR_STATUS_RC:0\n'
check(api.command('FIXED')==nil and closed,'oversized command pipe is closed after bounded reads')
output='valid\n__NR_STATUS_RC:0\n';close_result=nil
check(api.command('FIXED')==nil,'pipe close failure is unavailable')
io.popen=function()return nil end;check(api.command('FIXED')==nil,'unavailable popen stays unknown')
io.popen=function()error('popen not supported')end;check(api.command('FIXED')==nil,'unsupported popen stays unknown')
io.popen=original
print('LUA_CHECKS '..count)
'''
    harness = d / 'test.lua'
    harness.write_text('local SOURCE=' + json.dumps(str(scripts / 'native_status.lua')) + '\nlocal TEMP=' + json.dumps(str(d)) + '\n' + lua)
    result = subprocess.run([args.lua, str(harness)], capture_output=True, text=True, timeout=15)
    print(result.stdout, end='', flush=True)
    assert result.returncode == 0, result.stderr
    passed += int(result.stdout.rsplit('LUA_CHECKS ', 1)[1].strip())

    # Exercise the actual shell lock/trap flow with only fixed paths redirected
    # into temporary fixtures and the Lua process replaced by a recorder.
    state = d / 'state'
    fake = d / 'lua'
    fake.write_text('''#!/usr/bin/env python3
import json,os,sys,time
from pathlib import Path
s=Path(os.environ['STATUS_STATE']);lock=s/'lock'
busy=sys.argv[-1]=='busy'
owner=(lock/'pid').read_text().strip() if (lock/'pid').is_file() else ''
print(json.dumps({'busy':busy,'owned':owner==str(os.getppid())}),flush=True)
mode=os.environ.get('STATUS_MODE','')
if mode=='replace':
 (lock/'pid').write_text('99999\\n');(lock/'foreign').write_text('preserve')
if mode=='signal':
 Path(os.environ['STATUS_READY']).touch();time.sleep(.35)
if mode=='fail':sys.exit(7)
''')
    fake.chmod(0o700)
    source = (scripts / 'native_status.sh').read_text().replace('STATE=/tmp/iktmp/strict-routing', 'STATE=' + str(state)).replace('/usr/bin/lua', str(fake))
    shell = d / 'status.sh'
    shell.write_text(source)
    env = {**os.environ, 'STATUS_STATE': str(state), 'STATUS_READY': str(d / 'ready')}

    def run_shell(mode='', source_path=shell, extra_env=None):
        return subprocess.run(['bash', str(source_path)], capture_output=True, text=True, timeout=5,
                              env={**env, 'STATUS_MODE': mode, **(extra_env or {})})

    r = run_shell()
    check(r.returncode == 0 and json.loads(r.stdout)['busy'] and not state.exists(), 'missing lock parent reports busy without creating runtime state')
    state.mkdir()
    lock = state / 'lock'
    lock.mkdir()
    (lock / 'pid').write_text('9999999\n')
    (lock / 'foreign').write_text('preserve')
    before = {p.name: p.read_bytes() for p in lock.iterdir()}
    r = run_shell()
    check(r.returncode == 0 and json.loads(r.stdout)['busy'] and before == {p.name: p.read_bytes() for p in lock.iterdir()}, 'existing or stale writer lock is never recovered or changed')
    shutil.rmtree(lock)
    r = run_shell()
    check(r.returncode == 0 and json.loads(r.stdout) == {'busy': False, 'owned': True} and not lock.exists(), 'successful snapshot owns and cleans its lock')
    r = run_shell('fail')
    check(r.returncode == 7 and not lock.exists(), 'failed Lua snapshot preserves error and cleans lock')
    r = run_shell('replace')
    check(r.returncode == 0 and (lock / 'pid').read_text() == '99999\n' and (lock / 'foreign').read_text() == 'preserve', 'cleanup preserves a lock replaced by another owner')
    shutil.rmtree(lock)
    failed_write = d / 'pid-write-fail.sh'
    failed_write.write_text(source.replace('STATE=' + str(state), 'printf(){ return 1; }\nSTATE=' + str(state), 1))
    r = run_shell(source_path=failed_write)
    check(r.returncode == 0 and json.loads(r.stdout)['busy'] and not lock.exists(), 'PID publication failure cleans own empty lock and reports busy')
    bindir = d / 'bin'
    bindir.mkdir()
    (bindir / 'mkdir').write_text('#!/bin/sh\nexit 1\n')
    (bindir / 'mkdir').chmod(0o700)
    r = run_shell(extra_env={'PATH': str(bindir) + os.pathsep + os.environ['PATH']})
    check(r.returncode == 0 and json.loads(r.stdout)['busy'] and not lock.exists(), 'lock acquisition failure never starts an unlocked full snapshot')
    proc = subprocess.Popen(['bash', str(shell)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env={**env, 'STATUS_MODE': 'signal'})
    deadline = time.monotonic() + 3
    while not (d / 'ready').exists() and time.monotonic() < deadline:
        time.sleep(.01)
    assert (d / 'ready').exists(), 'signal fixture did not start'
    proc.send_signal(signal.SIGTERM)
    stdout, stderr = proc.communicate(timeout=3)
    check(proc.returncode == 143 and not lock.exists(), 'termination releases the reader lock after child completion')

print('NATIVE_STATUS_PASS', passed)
