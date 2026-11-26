"""Exercise same-number listener handoff and the rules protecting the inner WG socket."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[2] / 'materials/firmware/port-3726/files/usr/ikuai/script/wg_hyr_ports.sh'


class PortHandoffTest(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)
        self.state = self.root/'state'
        self.state.write_text(json.dumps({'enabled':True,'members':{'1':{
            'interface':'wg1','transport':'pure_hy2','port_mode':'wg','port':51820,'inner_port':21000,'server_key':'server'}}}))
        self.db = self.root/'config.db'
        with sqlite3.connect(self.db) as db:
            db.execute('CREATE TABLE wireguard(name,local_listenport,enabled)')
            db.execute("INSERT INTO wireguard VALUES('wg1',51820,'yes')")
        self.plan = self.root/'assign'
        self.plan.write_text('wg1 51820 21000 server\n')
        self.port = self.root/'socket'
        self.port.write_text('51820\n')
        self.log = self.root/'ops'
        self.log.touch()
        self.rulefile = self.root/'rules'
        self.rulefile.touch()
        self.flags=self.root/'sys/wg1/flags';self.flags.parent.mkdir(parents=True)
        self.flags.write_text('0x91\n')
        self.udp6=self.root/'udp6';self.udp6.touch()
        self.tool('ip','''
            if [ "$1 $2 $3" = "-6 route show" ];then
                printf "local fd72:6e72:6879:2::1 dev wg1 proto kernel metric 0 pref medium\n"
            fi''')
        self.tool('flock','exit 0')
        self.tool('wg','''
            case "$1:$3" in
                show:public-key) echo server;;
                show:listen-port) cat "$SOCKET";;
                show:peers) echo phone;;
                set:listen-port)
                    [ "$4" != "${FAIL_PORT:-}" ] || exit 1
                    echo "listen $4" >> "$OPS";echo "$4" > "$SOCKET";;
                *) exit 1;;
            esac''')
        iptables = '''
            exe=${0##*/}
            test "$1 $2 $3 $4" = '-w 3 -t mangle' || exit 1
            shift 4; op=$1; chain=$2; shift 2
            if [ "$op" = -I ];then test "$1" = 1 || exit 1;shift; fi
            rule="$exe $chain $*"
            case "$op" in
                -C) grep -Fqx "$rule" "$RULES";;
                -I) echo "$rule" >> "$RULES"; echo "add $rule" >> "$OPS";;
                -D) grep -Fvx "$rule" "$RULES" > "$RULES.tmp" || true;mv "$RULES.tmp" "$RULES";echo "del $rule" >> "$OPS";;
                *) exit 1;;
            esac'''
        self.tool('iptables',iptables); self.tool('ip6tables',iptables)
        source=SOURCE.read_text().replace('/etc/mnt/ikuai/wg-hyr/state.json',str(self.state))
        source=source.replace('/tmp/iktmp/wg-hyr-ports',str(self.root/'maps')).replace('wg=/usr/bin/wg','wg='+str(self.root/'wg'))
        source=source.replace('/sys/class/net/',str(self.root/'sys')+'/').replace('/proc/net/udp6',str(self.udp6))
        source=source.replace('export PATH=/usr/sbin:/usr/bin:/sbin:/bin','export PATH="'+str(self.root)+':$PATH"')
        if os.uname().sysname=='Darwin':source=source.replace("stat -c '%u:%a'", "stat -f '%u:%Lp'")
        source=source.replace('= 0:700','= '+str(os.getuid())+':700')
        self.script=self.root/'ports.sh';self.script.write_text(source)

    def tool(self,name,source):
        p=self.root/name;p.write_text('#!/bin/bash\n'+source+'\n');p.chmod(0o700)

    def run_port(self,*args,fail=None,check=True):
        return subprocess.run(['bash',str(self.script),*map(str,args)],text=True,capture_output=True,check=check,
            env={**os.environ,'SOCKET':str(self.port),'OPS':str(self.log),'RULES':str(self.rulefile),'FAIL_PORT':fail or ''})

    def test_keep_private_during_key_replacement_and_restore_after_stop(self):
        self.assertEqual(self.run_port('resolve','wg1',51820,'replacement-key').stdout.strip(),'21000')
        self.assertEqual(self.run_port('resolve','wg9',51839,'unmanaged').stdout.strip(),'51839')
        self.run_port('apply',self.plan,self.db)
        self.assertEqual(self.port.read_text().strip(),'21000')
        rules=self.rulefile.read_text().splitlines()
        self.assertEqual(len(rules),4)
        self.assertTrue(any('iptables INPUT ! -i lo' in r and '--dport 21000' in r for r in rules))
        self.assertTrue(any('iptables OUTPUT ! -o lo' in r and '--sport 21000' in r for r in rules))
        self.assertTrue(all(r.endswith('-j DROP') for r in rules))
        ops=self.log.read_text().splitlines()
        self.assertEqual(ops[-1],'listen 21000')
        self.run_port('apply',self.plan,self.db)
        self.assertEqual(self.log.read_text().splitlines(),ops)
        with sqlite3.connect(self.db) as db:db.execute("UPDATE wireguard SET local_listenport=51999 WHERE name='wg1'")
        self.assertNotEqual(self.run_port('apply','/dev/null',self.db,fail='51999',check=False).returncode,0)
        self.assertEqual(self.rulefile.read_text().splitlines(),rules)
        self.run_port('apply','/dev/null',self.db)
        self.assertEqual(self.port.read_text().strip(),'51999')
        self.assertFalse(self.rulefile.read_text())
        self.assertLess(self.log.read_text().index('listen 51999'),self.log.read_text().index('del iptables'))

    def test_wrong_device_key_withdraws_its_target_and_applies_other_placements(self):
        self.run_port('apply',self.plan,self.db)
        maps=self.root/'maps'
        (maps/'wg2.target').write_text('fd72:6e72:6879:2::2\n')
        self.tool('ip',"""
            if [ "$1 $2 $3 $4 $5" = "-6 addr show dev wg2" ];then echo '    inet6 fd72:6e72:6879:2::2/128 scope global';fi
            if [ "$1 $2 $3" = '-6 addr del' ];then echo "withdraw $4 $6" >>"$OPS";fi
        """)
        self.plan.write_text('wg2 51821 21001 different-saved-key\nwg1 51820 21000 server\n')
        self.port.write_text('51820\n')
        self.log.write_text('')
        self.run_port('apply',self.plan,self.db)
        operations=self.log.read_text().splitlines()
        self.assertIn('withdraw fd72:6e72:6879:2::2/128 wg2',operations)
        self.assertIn('listen 21000',operations)
        self.assertNotIn('listen 21001',operations)
        self.assertFalse((maps/'wg2.target').exists())

    def test_retired_target_cannot_be_armed(self):
        config=json.loads(self.state.read_text())
        del config['members']['1']['transport']
        self.state.write_text(json.dumps(config))
        self.assertEqual(self.run_port('resolve','wg1',51820,'server').stdout.strip(),'51820')
        for action in ('arm','ready'):
            self.assertEqual(self.run_port(action,'wg1',21000,'server','phone','fd72:6e72:6879:2::1',check=False).returncode,2)
        self.assertFalse(self.rulefile.read_text())

    def test_kernel_bind_failure_retains_protection_and_retries(self):
        self.run_port('apply',self.plan,self.db,fail='21000')  # later per-device arm check remains closed
        self.assertEqual(self.port.read_text().strip(),'51820')
        self.assertEqual(len(self.rulefile.read_text().splitlines()),4)
        self.run_port('apply',self.plan,self.db)
        self.assertEqual(self.port.read_text().strip(),'21000')
        self.run_port('apply','/dev/null',self.db)
        self.assertEqual(self.port.read_text().strip(),'51820')


if __name__=='__main__':
    unittest.main()
