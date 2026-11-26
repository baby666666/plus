#!/usr/bin/env python3
"""Run actual DNS readiness/startup against isolated process/socket/link fixtures."""
from pathlib import Path
import os, subprocess, tempfile

ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'materials/firmware/port-3726/files/usr/ikuai/script/native_dns_bind.sh'
checks=0
def check(value,name):
    global checks
    assert value,name
    checks+=1

with tempfile.TemporaryDirectory(prefix='nr-dns-ingress-ready-') as directory:
    root=Path(directory);state=root/'state';proc=root/'proc';active=state/'active'
    active.mkdir(parents=True);(proc/'101/fd').mkdir(parents=True);(proc/'net').mkdir()
    calls=root/'calls';calls.write_text('')
    controller=root/'controller'
    leaks=root/'leaks';leaks.write_text('')
    controller.write_text('#!/bin/bash\nprintf "%s\\n" "$1" >> "'+str(calls)+'"\nfor fd in 8 9;do [ ! -e /dev/fd/$fd ] || echo "$fd" >> "'+str(leaks)+'";done\nexit "${APPLY_FAIL:-0}"\n')
    controller.chmod(0o700)
    text=SOURCE.read_text().replace('/tmp/iktmp/native-rules',str(state)).replace('/proc/',str(proc)+'/').replace('/usr/ikuai/script/native_rules.sh',str(controller))
    script=root/'run.sh'
    script.write_text('''#!/bin/bash
kill(){ [ "$*" = '-0 101' ] && [ "${DEAD:-0}" != 1 ]; }
ip(){
 case "$*" in
  '-o link show'|'-o link show dev ppphy1') printf '10: ppphy1: <BROADCAST,UP,LOWER_UP> mtu 1500 state UP\\n';;
  '-o -4 addr show dev ppphy1') printf '10: ppphy1 inet 10.100.1.1/32 scope global ppphy1\\n';;
  *) return 2;;
 esac
}
'''+text)
    def setup():
        (state/'dns-bindings').write_text('169.254.252.1 ppphy1\n')
        (active/'dns-bindings').write_text('169.254.252.1 ppphy1\n')
        (active/'front.ready').write_text('ready\n');(active/'front.pid').write_text('101\n')
        (active/'snapshot.json').write_text('{}')
        (proc/'101/cmdline').write_bytes(b'/usr/sbin/native-rule-dns\0test\0')
        for name,kind,inode in [('udp','07',2001),('tcp','0A',2002)]:
            (proc/'net'/name).write_text(' 0: 01FCFEA9:0035 00000000:0000 '+kind+' 0:0 00:0 0 0 0 '+str(inode)+'\n')
            link=proc/'101/fd'/name
            link.unlink(missing_ok=True);link.symlink_to('socket:['+str(inode)+']')
        for name in ['commit.pending','native-dirty','native-stage.pending','boot.pending','policy-reconcile.failed']:(state/name).unlink(missing_ok=True)
        calls.write_text('')
    def run(action='ready',name='ppphy1',**env):
        return subprocess.run(['bash',str(script),action,name],env={**os.environ,**env},capture_output=True,text=True).returncode
    setup();check(run()==0,'live owned UDP and TCP bindings ready')
    check(calls.read_text()=='','read-only check never invokes native transaction')
    for mutate,name in [
      (lambda:(active/'front.ready').unlink(),'ready file missing'),
      (lambda:(active/'front.pid').write_text('invalid\n'),'invalid PID'),
      (lambda:(proc/'101/cmdline').write_bytes(b'/usr/bin/other\0'),'foreign process'),
      (lambda:(proc/'net/udp').write_text(''),'missing UDP socket'),
      (lambda:(proc/'net/tcp').write_text(''),'missing TCP socket'),
      (lambda:(proc/'101/fd/tcp').unlink(),'foreign TCP socket inode'),
      (lambda:(active/'dns-bindings').write_text('169.254.252.2 ppphy1\n'),'uncommitted binding generation'),
      (lambda:(state/'commit.pending').touch(),'incomplete commit'),
      (lambda:(state/'native-dirty').touch(),'dirty engine'),
      (lambda:(state/'native-stage.pending').touch(),'staged engine'),
      (lambda:(state/'boot.pending').touch(),'boot guard'),
      (lambda:(state/'policy-reconcile.failed').touch(),'failed policy reconcile guard')]:
        setup();mutate();check(run()!=0,name+' fails closed')
    setup();check(run(DEAD='1')!=0,'dead dispatcher cannot use stale ready file')
    for name in ['ppphy2','ppphy1x','wg1','ppphy1;true']:
        setup();check(run(name=name)!=0,'reject unbound or invalid ingress '+name)
        check(run('ensure',name)!=0 and calls.read_text()=='','invalid ingress never applies rules '+name)
    setup();check(run('ensure')==0 and calls.read_text()=='reconcile\n','existing plan reconciles before core start')
    setup();(active/'snapshot.json').unlink()
    check(run('ensure')==0 and calls.read_text()=='apply\n','first startup applies before core start')
    setup();check(run('ensure',APPLY_FAIL='1')!=0,'transaction failure cannot publish readiness')
    for name in ['boot.pending','policy-reconcile.failed']:
        setup();(state/name).touch()
        check(run('ensure')!=0,name+' keeps a new HY2 core unavailable')
        (state/name).unlink()
        check(run('ensure')==0,name+' removal by native recovery permits automatic retry')
    # Test the actual inherited descriptors, rather than only checking source
    # text: the parent must retain both while the native child sees neither.
    for bootstrap in [False,True]:
        setup();leaks.write_text('')
        if bootstrap:(active/'snapshot.json').unlink()
        parent='exec 8>"$2/engine.lock" 9>"$2/controller.lock"; bash "$1" ensure ppphy1; result=$?; [ -e /dev/fd/8 ] && [ -e /dev/fd/9 ] || exit 90; exit "$result"'
        code=subprocess.run(['bash','-c',parent,'parent',str(script),str(root)],capture_output=True,text=True).returncode
        check(code==0 and leaks.read_text()=='',('apply' if bootstrap else 'reconcile')+' closes inherited engine/controller descriptors only in child')
print('PASS',checks,'isolated HY2 DNS ingress readiness cases')
