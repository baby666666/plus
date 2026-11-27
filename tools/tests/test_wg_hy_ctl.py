"""Exercise HY2 controller ordering on storage and listener failures."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[2] / 'materials/firmware/port-3726/files/usr/ikuai/script'


def wireguard_source():
    source = (SCRIPTS / 'wireguard.sh').read_text()
    return source.replace('/usr/ikuai/script/wg_pure_routing.sh', str(SCRIPTS / 'wg_pure_routing.sh'))


class TunnelControllerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.log = self.root / 'operations'
        self.tool('direction', 'exit 0')
        self.tool('ports', '''case "$1" in arm|ready) test "$5" = "$PHONE_KEY";; *) exit 0;; esac''')
        self.tool('flock', 'exit 0')
        self.tool('fsync', 'exit 0')
        pure_source=(SCRIPTS/'wg_pure_service.sh').read_text()
        (self.root/'pure-service').write_text(pure_source)
        (self.root/'pure-service').chmod(0o700)
        source = (SCRIPTS / 'wg_hy_ctl.sh').read_text()
        source = source.replace('/etc/mnt/ikuai/wg-tcp', str(self.root/'tcp-registry'))
        source = source.replace('engine=/usr/ikuai/script/wg_hy_engine.sh', 'engine='+str(self.root/'engine'))
        source = source.replace('/usr/ikuai/script/wg_hyr_direction.sh', str(self.root/'direction'))
        source = source.replace('/usr/ikuai/script/wg_hyr_ports.sh', str(self.root/'ports'))
        source = source.replace('/usr/ikuai/script/wg_pure_service.sh', str(self.root/'pure-service'))
        source = source.replace('/etc/mnt/ikuai/wg-hyr', str(self.root/'reverse'))
        source = source.replace('/etc/mnt/ikuai/wg-hy', str(self.root/'retired'))
        source = source.replace('/tmp/iktmp/wg-hyr', str(self.root/'runtime-reverse'))
        source = source.replace('/tmp/iktmp/wg-hy-engine', str(self.root/'instances'))
        source = source.replace('/usr/bin/wg ', 'wg ')
        source = source.replace('export PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'export PATH="'+str(self.root)+':$PATH"')
        source = source.replace('/usr/bin/lua ', 'lua ')
        if os.uname().sysname == 'Darwin':
            source = source.replace("stat -c '%u:%a'", "stat -f '%u:%Lp'")
        source = source.replace('0:600', str(os.getuid())+':600').replace('0:700', str(os.getuid())+':700')
        self.controller = self.root/'controller'
        self.controller.write_text(source)

    def tool(self, name, body):
        path = self.root / name
        path.write_text('#!/bin/bash\n'+body+'\n')
        path.chmod(0o700)

    def prepare_reverse(self):
        self.data = self.root / 'reverse'
        self.data.mkdir(mode=0o700)
        self.state = self.data / 'state.json'
        self.state.write_text('{"enabled":true,"members":{}}')
        self.state.chmod(0o600)
        tls = self.data / 'tls'
        tls.mkdir(mode=0o700)
        for name in ('key.pem', 'cert.pem'):
            p = tls / name
            p.touch(mode=0o600)
        self.tool('engine', """
            [[ $1 = hyr-* ]] || exit 1
            echo "$2" >> "$OPERATIONS"
        """)
        self.tool('lua', """
            test "$3" = db || exit 1
            case "$2" in
                retire_wrapped) exit 0;;
                sync) cp "$4" "$5/next"; : >"$5/directions";;
                *) exit 1;;
            esac
        """)
        self.tool('wg', """
            test "$1" = show && test "$2" = wg8 || exit 1
            case "$3" in
                listen-port) echo 52820;;
                public-key) echo server-key;;
                peers) echo "$PHONE_KEY";;
                *) exit 1;;
            esac
        """)
        # OUTPUT is built in. Dedicated service chains have not been created yet.
        self.tool('iptables', '[[ "$*" = "-w 3 -S OUTPUT" ]] && echo "-P OUTPUT ACCEPT"')
        self.tool('ip6tables', 'echo "$*" >> "$V6LOG"; [[ "$*" = "-w 3 -S OUTPUT" ]] && echo "-P OUTPUT ACCEPT"')
        self.tool('iptables-restore', 'cat >"$RULES"')
        self.tool('ip6tables-restore','cat >"$V6LOG.rules"')

    def reverse(self, operation, key='phone-key', database='db', arguments=()):
        return subprocess.run(['bash', self.controller, 'hyr', database, operation, *arguments],
                              text=True, capture_output=True, env={**os.environ, 'PHONE_KEY':key,
                              'V6LOG':str(self.root/'v6'), 'OPERATIONS':str(self.log), 'RULES':str(self.root/'rules')})

    def test_editor_read_does_not_start_recovery_or_probe_runtime(self):
        self.prepare_reverse()
        self.tool('lua', """test "$2" = settings && test "$3" = db && test "$5" = - && test "$6" = 42 && test "$HY_CORE_LOCATION" = compact || exit 1
echo metadata""")
        self.tool('engine','[[ $1 = location ]] && { echo compact;exit 0; };echo unexpected >>"$OPERATIONS";exit 1')
        for cmd in ('ports','direction','iptables','ip6tables'):
            self.tool(cmd, 'echo unexpected >>"$OPERATIONS"; exit 1')
        result=self.reverse('settings',arguments=('42',))
        self.assertEqual((result.returncode,result.stdout.strip()),(0,'metadata'))
        (self.data/'change').mkdir(mode=0o700)
        refused=self.reverse('settings',arguments=('42',))
        self.assertNotEqual(refused.returncode,0)
        self.assertTrue((self.data/'change').exists())
        self.assertFalse(self.log.exists())

    def test_pure_center_cold_start_without_status_or_receiver(self):
        stage=self.root/'cold';stage.mkdir()
        (stage/'pure-bindings').write_text('wg7 7 51707 21707\n')
        (stage/'pure.7').write_text('{}\n')
        (stage/'admin.7').write_text('wg7 7 10.177.7.2 10.177.7.1 80 443\n')
        units=self.root/'instances'
        self.tool('iptables','[[ " $* " != *" -C "* ]]')
        self.tool('engine','if [ "$2" = stop ];then exit 0;fi; [[ "$1:$2" = puh-7:start && -s "$3" ]] && echo start >>"$OPERATIONS"')
        self.tool('net-setup','exit 0')
        self.tool('dns-setup','exit 0')
        script=(SCRIPTS/'wg_pure_service.sh').read_text().replace('/tmp/iktmp/wg-hy-engine',str(units))
        script=script.replace('/usr/ikuai/script/wg_hy_engine.sh',str(self.root/'engine'))
        script=script.replace('/usr/ikuai/script/wg_pure_ingress.sh',str(self.root/'net-setup')).replace('/usr/ikuai/script/native_dns_bind.sh',str(self.root/'dns-setup'))
        script=script.replace('export PATH=/usr/sbin:/usr/bin:/sbin:/bin','export PATH="'+str(self.root)+':$PATH"')
        if os.uname().sysname=='Darwin':script=script.replace("stat -c '%u:%a'", "stat -f '%u:%Lp'")
        script=script.replace('0:700',str(os.getuid())+':700')
        def run():
            return subprocess.run(['bash','-c',script,'service','sync',stage],
                env={**os.environ,'OPERATIONS':str(self.log)},text=True,capture_output=True)
        self.assertFalse(units.exists())
        initial=run();self.assertEqual(initial.returncode,0,initial.stdout+initial.stderr)
        self.assertEqual(self.log.read_text().splitlines(),['start'])
        self.assertEqual((units/'puh-7/policy').read_text().count('udp 51707'),3)
        units.rename(self.root/'old')
        units.symlink_to(self.root/'old',target_is_directory=True)
        self.assertNotEqual(run().returncode,0)
        self.assertEqual(self.log.read_text().splitlines(),['start'])

    def test_boot_retirement_runs_before_management_and_keeps_receiver_independent(self):
        rc=(SCRIPTS/'rc').read_text()
        self.assertLess(rc.index('wireguard.sh retire_transports_boot'),rc.index('\n\tstart_ikuai_services'))
        db=self.root/'retired.sqlite'
        with sqlite3.connect(db) as conn:
            conn.execute('CREATE TABLE wg_site_clients(transport TEXT)')
            conn.execute("INSERT INTO wg_site_clients VALUES('hysteria2')")
        state=self.root/'unsafe-registry';state.symlink_to(self.root/'missing')
        wg=wireguard_source().replace('/etc/mnt/ikuai/wg-hyr/state.json',str(state))
        helper=wg[wg.index('__wg_retire_wrapped(){'):wg.index('retire_transports_boot()(')]
        helper=helper.replace('/usr/bin/lua /usr/ikuai/script/wg_site_client.lua','test_receiver')
        source=helper+'\ntest_receiver(){ test "$1" = retire_wrapped && echo receiver; }; __wg_retire_wrapped'
        def run():return subprocess.run(['bash','-c',source],env={**os.environ,'IK_DB_CONFIG':str(db)},text=True,capture_output=True)
        partial=run();self.assertEqual((partial.returncode,partial.stdout.strip()),(1,'receiver'))
        state.unlink()
        healthy=run();self.assertEqual((healthy.returncode,healthy.stdout.strip()),(0,'receiver'))
        with sqlite3.connect(db) as conn:conn.execute("UPDATE wg_site_clients SET transport='native'")
        clear=run();self.assertEqual((clear.returncode,clear.stdout),(0,''))

    def test_native_router_export_reads_without_installing_the_hy_engine_or_tls(self):
        self.tool('lua', """
            [[ $2 = native_profile && $3 = db && $4 = - && -d $5 &&
                $6 = 3 && $7 = access && $8 = wg2 && $9 = client && ${10} = server ]] || exit 1
            echo native-snapshot
        """)
        for cmd in ('engine','openssl','ports','direction','iptables','ip6tables'):
            self.tool(cmd,'echo unexpected >>"$OPERATIONS";exit 1')
        args=('3','access','wg2','client','server')
        exported=self.reverse('native_profile',arguments=args)
        self.assertEqual((exported.returncode,exported.stdout.strip()),(0,'native-snapshot'))
        self.assertFalse((self.root/'reverse').exists())
        self.assertFalse(self.log.exists())

    def test_uri_uses_saved_private_identity_and_leaves_listeners_alone(self):
        self.prepare_reverse()
        self.tool('lua', '''
            [[ $2 = uri && $3 = db && -f $4 && -d $5 && $6 = 4 && $7 = token && $8 = access ]] || exit 1
            echo uri-snapshot
        ''')
        for cmd in ('engine', 'ports', 'direction', 'iptables', 'ip6tables'):
            self.tool(cmd, 'echo unexpected >>"$OPERATIONS";exit 1')
        def export():
            return self.reverse('uri', arguments=('4','token','access'))
        result=export()
        self.assertEqual((result.returncode,result.stdout.strip()), (0,'uri-snapshot'))
        change=self.data/'change'
        change.mkdir(mode=0o700)
        self.assertNotEqual(export().returncode,0)
        self.assertTrue(change.is_dir())
        change.rmdir()
        cert=self.data/'tls/cert.pem'
        cert.chmod(0o644)
        self.assertNotEqual(export().returncode,0)
        cert.unlink()
        cert.symlink_to(self.data/'tls/key.pem')
        self.assertNotEqual(export().returncode,0)
        cert.unlink()
        self.assertNotEqual(export().returncode,0)
        self.assertFalse(cert.exists())
        self.assertFalse(self.log.exists())

    def test_retired_registry_does_not_reserve_ports_or_expose_actions(self):
        self.prepare_reverse()
        old=self.root/'retired'
        old.mkdir(mode=0o700)
        registry=old/'state.json'
        registry.write_text(json.dumps({'enabled':True, 'settings':{'udp_port':8443}, 'members':{}}))
        before=registry.read_bytes()
        unit=self.root/'instances'/'hyr-8443'
        unit.mkdir(parents=True);(unit/'service.pid').touch()
        self.tool('engine','[[ "$1:$2" = hyr-8443:stop ]] || exit 1;echo stop >>"$OPERATIONS";rm -f "'+str(unit)+'/service.pid"')
        result=self.reverse('sync')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(self.log.read_text().splitlines(),['stop'])
        self.assertEqual(registry.read_bytes(),before)
        for action in ('status','enroll','profile','save','revoke','monitor'):
            rejected=subprocess.run(['bash', self.controller, action],capture_output=True)
            self.assertNotEqual(rejected.returncode,0)

    def test_api_save_uses_the_peer_wan_or_its_saved_address_mode(self):
        state=self.root/'reverse.json'
        script=wireguard_source().replace('/etc/mnt/ikuai/wg-hyr/state.json',str(state))
        script=script.replace('/usr/ikuai/script/wg_client_endpoint.sh',str(self.root/'detect'))
        script=script.replace('/usr/ikuai/script/wg_hy_engine.sh','/usr/bin/true')
        wireguard=self.root/'wireguard.sh';wireguard.write_text(script)
        self.tool('detect','test "$*" = "get_public wg1" || exit 1; echo probe >> "$OPERATIONS"; printf "%s" "$IP"')
        # Mirror the native jq 1.4 ENOENT behavior; newer jq exits nonzero here.
        cmd="""
            Include(){ :; };source "$1"
            jq(){ [ -e "$STATE" ] || return 0; command jq "$@"; }
            Lock(){ echo "selected:$hyr_public_ip:$client_endpoint"; return 1; }
            id=2;wg_transport=pure_hy2;wg_role=access;hyr_port_mode=wg;interface=wg1
            __wg_address_change edit
        """
        shared={'settings':{'public_ip':'1.1.1.1'}}
        peer={'id':'token','interface':'wg1'}
        for saved,mode,token,detected,wanted,probed in [
                (None,'','','8.8.8.8','8.8.8.8',True), ({},'','','8.8.4.4','8.8.4.4',True),
                (shared,'','','9.9.9.9','9.9.9.9',True), (shared,'shared','','','1.1.1.1',False),
                (dict(shared,members={'2':peer}),'','token','','1.1.1.1',False),
                (dict(shared,members={'2':dict(peer,addr_mode='auto',public_ip='8.8.4.4')}),
                 'auto','token','','8.8.4.4',False),
                (dict(shared,members={'2':dict(peer,addr_mode='auto',public_ip='8.8.4.4')}),
                 'auto','stale','9.9.9.9','9.9.9.9',True),
                (shared,'manual','','',None,False), (None,'','','',None,True)]:
            with self.subTest(saved=saved,mode=mode,token=token):
                state.unlink(missing_ok=True);self.log.unlink(missing_ok=True)
                if saved is not None: state.write_text(json.dumps(saved))
                result=subprocess.run(['bash','-c',cmd,'public-ip',wireguard],text=True,capture_output=True,
                    env={**os.environ,'STATE':str(state),'IP':detected,'OPERATIONS':str(self.log),
                         'hyr_addr_mode':mode,'hyr_id':token})
                if wanted:
                    self.assertIn(f'selected:{wanted}:{wanted}',result.stdout)
                else:
                    self.assertNotIn('selected:',result.stdout)
                    self.assertIn('未能检测到',result.stdout)
                self.assertEqual(self.log.exists(),probed)

    def test_vrrp_freezes_before_removing_interfaces_and_resumes_after_rebuild(self):
        reverse = self.root / 'reverse'
        reverse.mkdir()
        (reverse/'state.json').touch()
        self.tool('router-hy', 'echo "$3" >> "$OPERATIONS"')
        source = wireguard_source().replace('/usr/ikuai/script/wg_hy_ctl.sh', str(self.root/'router-hy'))
        source = source.replace('/usr/ikuai/script/wg_hyr_direction.sh', str(self.root/'direction'))
        source = source.replace('/etc/mnt/ikuai/wg-hyr', str(reverse))
        source = source.replace('/usr/ikuai/script/wg_site.sh', '/usr/bin/true').replace('/usr/ikuai/script/wg_native_role.sh','/usr/bin/true')
        wireguard=self.root/'wireguard.sh'
        wireguard.write_text(source)
        result=subprocess.run(['bash','-c', """
            Include(){ :; }
            source "$1"
            Lock(){ echo lock >> "$OPERATIONS"; }
            unLock(){ echo unlock >> "$OPERATIONS"; }
            __exec_rule_clean(){ echo remove >> "$OPERATIONS"; }
            __wg_iface_cache_update(){ :; }
            __wg_locked_init(){ echo rebuild >> "$OPERATIONS"; }
            sqlite3(){ cat >/dev/null; }
            vrrp_init
        """,'vrrp-test',wireguard], text=True, capture_output=True,cwd=self.root,
            stdin=subprocess.DEVNULL, env={**os.environ,'OPERATIONS':str(self.log),'IK_DB_CONFIG':'db'})
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(self.log.read_text().splitlines(), ['lock','hold','remove','rebuild','sync','unlock'])

    def projection_databases(self):
        fields = 'id interface exit_peer allowips peer_publickey peer_privatekey presharedkey client_dns keepalive enabled site_local site_remote native_role'
        content = (1,'wg8','yes','10.0.8.2/32','pub','synthetic','psk','10.0.8.1',25,'yes','','','')
        insert = 'INSERT INTO wireguard_peers VALUES('+','.join('?' for _ in content)+')'
        actual, shadow = self.root/'actual.db', self.root/'shadow.db'
        for database in [actual,shadow]:
            with sqlite3.connect(database) as db:
                db.execute('CREATE TABLE wireguard_peers('+','.join(fields.split())+')')
                if database==shadow: db.execute(insert,content)
        return actual, shadow, insert, content

    def test_cold_native_init_after_interrupted_cross_transport_save(self):
        reverse=self.root/'reverse';reverse.mkdir()
        (reverse/'state.json').write_text('{"members":{}}')
        tcp=self.root/'tcp-reg';tcp.mkdir()
        (tcp/'state.json').write_text('{"members":{}}')
        journal=reverse/'change'
        script=wireguard_source().replace('/etc/mnt/ikuai/wg-hyr',str(reverse))
        script=script.replace('/etc/mnt/ikuai/wg-tcp',str(tcp))
        for name in ['wg_hy_ctl.sh','wg_native_role.sh','wg_site.sh']:
            script=script.replace('/usr/ikuai/script/'+name,str(self.root/name))
        wireguard=self.root/'wireguard.sh';wireguard.write_text(script)
        self.tool('wg_hy_ctl.sh', """
            if test "$3" = sync && test -d "$JOURNAL"; then
                echo recover >>"$OPERATIONS"
                test "$DISK_OK" = 1 && rmdir "$JOURNAL"
                exit 1
            fi
            echo "hy-$3" >>"$OPERATIONS"
            test "$3" != sync || test -f "$LINK"
        """)
        self.tool('wg_native_role.sh', 'echo "role-$2" >> "$OPERATIONS"')
        self.tool('wg_site.sh','test -f "$LINK"')
        for disk_ok in [False,True]:
            journal.mkdir(exist_ok=True)
            env={**os.environ,'OPERATIONS':str(self.log),'JOURNAL':str(journal),
                 'LINK':str(self.root/'wg-up'),'DISK_OK':str(int(disk_ok))}
            result=subprocess.run(['bash','-c',"""
                Include(){ :; };source "$1";IK_DB_CONFIG=db
                Lock(){ :; };unLock(){ :; }
                __wg_retire_wrapped(){ echo retire >>"$OPERATIONS"; }
                __wg_locked_init(){ echo rebuild >>"$OPERATIONS";touch "$LINK"; }
                init
            """,'cold-boot',wireguard],text=True,capture_output=True,env=env,cwd=self.root)
            events=self.log.read_text().splitlines()
            self.assertEqual(result.returncode==0,disk_ok,result.stdout+result.stderr)
            self.assertEqual('rebuild' in events,disk_ok)
            if disk_ok:
                self.assertLess(events.index('recover'),events.index('retire'))
                self.assertLess(events.index('retire'),events.index('role-before'))
                self.assertLess(events.index('recover'),events.index('rebuild'))
                self.assertLess(events.index('recover'),events.index('role-migrate'))
                self.assertLess(events.index('role-before'),events.index('rebuild'))
                self.assertEqual(events[-2:],['hy-sync','role-after'])
            else:
                self.assertTrue(journal.exists())
            self.log.unlink()

    def test_interrupted_peer_change_applies_only_matching_native_row(self):
        self.prepare_reverse()
        old = '{"enabled":true,"members":{},"settings":{"udp_port":8443}}'
        self.state.write_text(old)
        self.tool('lua', """
            case "$2" in
                retire_wrapped) exit 0;;
                check_mode) test -z "$7";;
                set_mode) echo '{"enabled":true,"members":{},"settings":{"udp_port":8443},"applied":true}' > "$5/next";;
                sync) cat "$4" >"$5/next"; touch "$5/directions";;
                *) exit 1;;
            esac
        """)
        actual, shadow, insert, content = self.projection_databases()
        args = [shadow,'1','wg8','access','','','','wg','auto','','pure_hy2']
        for commit in [False,True]:
            result = self.reverse('prepare',database=actual,arguments=args)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertTrue((self.state.parent/'change/next').is_file())
            self.assertEqual(self.state.read_text(),old)
            if commit:
                with sqlite3.connect(actual) as db: db.execute(insert,content)
            result = self.reverse('sync',database=actual)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual(bool(json.loads(self.state.read_text()).get('applied')),commit)
            if commit:
                saved=json.loads(self.state.read_text())
                self.assertIs(saved['enabled'],True)
                self.assertNotIn('routed_enabled',saved)
            self.assertFalse((self.state.parent/'change').exists())

    def test_preflight_checks_projection_without_freezing_or_publishing(self):
        self.prepare_reverse()
        actual, shadow, _, _ = self.projection_databases()
        saved_state = self.state.read_bytes()
        saved_db = actual.read_bytes()
        self.tool('lua', '''
            case "$2" in
                check_mode) exit 0;;
                set_mode)
                    test "$3" = "$PROJECTED" || exit 1
                    test "$SCENARIO" != invalid || { echo invalid-fields;exit 1; }
                    echo '{"unpublished":"new-credentials"}' >"$5/next";;
                *) echo unexpected-model >>"$OPERATIONS";exit 1;;
            esac
        ''')
        self.tool('pure-service', '''
            test "$1" = check || { echo "pure-$1" >>"$OPERATIONS";exit 1; }
            test -f "$2/next" && test "$3" = wg8 || exit 1
            test "$SCENARIO" != conflict || { echo '反向映射端口已被占用';exit 1; }
        ''')
        for cmd in ('engine', 'ports', 'direction', 'iptables', 'ip6tables', 'fsync'):
            self.tool(cmd, 'echo unexpected-runtime >>"$OPERATIONS";exit 1')
        args = [shadow, '1', 'wg8', 'access', '', '', '', 'wg', 'auto', '', 'pure_hy2']
        for scenario in ('invalid', 'conflict', 'valid'):
            with self.subTest(scenario=scenario):
                result = subprocess.run(['bash', self.controller, 'hyr', actual, 'preflight', *args],
                    text=True, capture_output=True, env={**os.environ, 'PROJECTED':str(shadow),
                    'SCENARIO':scenario, 'OPERATIONS':str(self.log)})
                self.assertEqual(result.returncode == 0, scenario == 'valid', result.stdout + result.stderr)
                self.assertNotIn('new-credentials', result.stdout + result.stderr)
                self.assertEqual(self.state.read_bytes(), saved_state)
                self.assertEqual(actual.read_bytes(), saved_db)
                self.assertFalse(self.log.exists())
                self.assertFalse(list(self.data.glob('change*')))
                runtime = self.root/'runtime-reverse'
                self.assertFalse(list(runtime.glob('work.*')))
                self.assertFalse((runtime/'fence').exists())
                self.assertFalse((runtime/'scope').exists())

    def test_preflight_storage_and_tls_errors_do_not_stop_existing_workers(self):
        self.prepare_reverse()
        self.state.write_text('{"enabled":true,"members":{"1":{"transport":"pure_hy2","mode":"access"}}}')
        saved = self.state.read_bytes()
        for cmd in ('engine', 'pure-service', 'ports', 'direction', 'iptables', 'ip6tables', 'lua', 'fsync'):
            self.tool(cmd, 'echo unexpected-runtime >>"$OPERATIONS";exit 1')
        args = ['projected', '1', 'wg8', 'access', 'existing', '', '']
        for scenario in ('registry-permission', 'tls-permission', 'tls-missing', 'pending-journal'):
            with self.subTest(scenario=scenario):
                if scenario == 'registry-permission': self.state.chmod(0o644)
                if scenario == 'tls-permission': (self.data/'tls/key.pem').chmod(0o644)
                if scenario == 'tls-missing': (self.data/'tls').rename(self.data/'saved-tls')
                if scenario == 'pending-journal': (self.data/'change').mkdir(mode=0o700)
                result = self.reverse('preflight', arguments=args)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(self.log.exists())
                self.assertEqual(self.state.read_bytes(), saved)
                if scenario == 'registry-permission': self.state.chmod(0o600)
                if scenario == 'tls-permission': (self.data/'tls/key.pem').chmod(0o600)
                if scenario == 'tls-missing': (self.data/'saved-tls').rename(self.data/'tls')
                if scenario == 'pending-journal': (self.data/'change').rmdir()

    def peer_change_fixture(self, scenario, operation='edit'):
        case = self.root/(scenario+'-'+operation)
        case.mkdir()
        actual = case/'config.db'
        with sqlite3.connect(actual) as db:
            db.executescript("CREATE TABLE wireguard(id INTEGER PRIMARY KEY);"
                "CREATE TABLE wireguard_peers(id INTEGER PRIMARY KEY AUTOINCREMENT,interface,peer_publickey,comment);"
                "INSERT INTO wireguard_peers VALUES(1,'wg8','peer-key','old');"
                "CREATE TABLE wg_site_clients(relay_port INTEGER UNIQUE);"
                "INSERT INTO wg_site_clients VALUES(23000);")
        registry = case/'registry'
        registry.mkdir()
        state = registry/'state.json'
        state.write_text('{"members":{"1":{"id":"current","interface":"wg8","transport":"pure_hy2"}}}')
        saved_state = state.read_bytes()
        script = wireguard_source()
        for original, replacement in (
            ('/etc/mnt/ikuai/wg-hyr', registry),
            ('/etc/mnt/ikuai/wg-tcp', case/'tcp'),
            ('/tmp/iktmp/wg-mode.', str(case/'wg-mode.')),
            ('/tmp/iktmp/wg-site-client', case/'client'),
            ('/usr/ikuai/script/wg_hy_ctl.sh', self.root/'peer-hy'),
            ('/usr/ikuai/script/wg_hy_engine.sh', self.root/'installed'),
            ('/usr/ikuai/script/wg_native_role.sh', self.root/'peer-role'),
            ('/usr/ikuai/script/wg_site.sh', self.root/'peer-site'),
            (str(SCRIPTS/'wg_pure_routing.sh'), self.root/'peer-routing')):
            script = script.replace(str(original), str(replacement))
        wireguard = case/'wireguard.sh'
        wireguard.write_text(script)
        self.tool('installed', 'test "$1" = installed')
        self.tool('peer-role', 'echo "role-$2" >>"$OPERATIONS"')
        self.tool('peer-site', 'echo "site-$1" >>"$OPERATIONS"')
        self.tool('peer-routing', 'echo "routing-$1" >>"$OPERATIONS"')
        self.tool('peer-hy', '''
            case "$3" in
                check_mode) test "$5" = current;;
                preflight|prepare)
                    echo "$3" >>"$OPERATIONS"
                    test "$(sqlite3 "$4" "SELECT comment FROM wireguard_peers WHERE id=$5")" = new || exit 1
                    test "$(sqlite3 "$2" "SELECT comment FROM wireguard_peers WHERE id=1")" = old || exit 1
                    test "$(sqlite3 "$4" 'SELECT relay_port FROM wg_site_clients')" = 23000 || exit 1
                    if [ "$SCENARIO" = conflict ] || { [ "$SCENARIO" = late-failure ] && [ "$3" = prepare ]; };then
                        echo '反向映射端口已被占用';exit 1
                    fi;;
                hold|sync) echo "$3" >>"$OPERATIONS";;
                *) exit 1;;
            esac
        ''')
        log = case/'operations'
        result = subprocess.run(['bash', '-c', '''
            Include(){ :; };source "$1"
            Lock(){ echo lock >>"$OPERATIONS"; }
            unLock(){ echo unlock >>"$OPERATIONS"; }
            __wg_hyr_scope(){ echo "$interface"; }
            __wg_hyr_check_origin(){ :; };__wg_native_origin_ok(){ :; }
            __wg_native_edit_only_comment(){ return 1; }
            __wg_site_client_conflict(){ :; }
            __wg_site_client_sync(){ echo client-sync >>"$OPERATIONS"; }
            sql_config_get_list(){ echo old_interface=wg8 old_peer_publickey=peer-key old_presharedkey=psk; }
            __check_param_add(){
                if [ "$SCENARIO" = invalid ];then echo '字段无效';return 1;fi
            }
            __check_allowip_conflict(){ :; };__check_key_valid(){ :; }
            sql_config_update(){
                [ "$1" != "$IK_DB_CONFIG" ] || echo write >>"$OPERATIONS"
                sqlite3 "$1" "UPDATE wireguard_peers SET comment='new' WHERE $3"
            }
            sql_config_insert(){
                [ "$1" != "$IK_DB_CONFIG" ] || echo write >>"$OPERATIONS"
                sqlite3 "$1" "INSERT INTO wireguard_peers(interface,peer_publickey,comment) VALUES('wg9','new-key','new');SELECT last_insert_rowid()"
            }
            NewOldVarl(){ return 0; }
            __wg_apply_iface(){ echo apply >>"$OPERATIONS"; }
            __wg_iface_cache_update(){ echo cache >>"$OPERATIONS"; }
            IK_DB_CONFIG=$2;id=1;interface=wg8;hyr_id=current
            if [ "$3" = add ];then interface=wg9;hyr_id=;fi
            wg_transport=pure_hy2;wg_role=access;hyr_addr_mode=manual;hyr_public_ip=198.51.100.4
            client_dns=10.0.8.1;peer_publickey=peer-key;presharedkey=psk;peer_privatekey=synthetic
            allowips=10.0.8.2/32;comment=new
            "$3"
        ''', 'peer-change', wireguard, actual, operation], text=True, capture_output=True,
            env={**os.environ, 'SCENARIO':scenario, 'OPERATIONS':str(log)})
        self.assertEqual(state.read_bytes(), saved_state)
        self.assertFalse(list(case.glob('wg-mode.*')))
        return result, log.read_text().splitlines(), actual

    def test_rejected_peer_preflight_never_changes_existing_runtime_or_database(self):
        for operation in ('add', 'edit'):
            for scenario in ('invalid', 'conflict'):
                with self.subTest(operation=operation, scenario=scenario):
                    result, events, actual = self.peer_change_fixture(scenario, operation)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('字段无效' if scenario == 'invalid' else '端口已被占用', result.stdout)
                    self.assertEqual(events, ['lock', *(['preflight'] if scenario == 'conflict' else []), 'unlock'])
                    with sqlite3.connect(actual) as db:
                        self.assertEqual(db.execute('SELECT id,comment FROM wireguard_peers').fetchall(), [(1, 'old')])

    def test_successful_peer_save_fences_only_after_preflight(self):
        for operation in ('add', 'edit'):
            with self.subTest(operation=operation):
                result, events, actual = self.peer_change_fixture('valid', operation)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(events, ['lock', 'preflight', 'hold', 'role-before', 'prepare', 'write',
                    'apply', 'cache', 'site-sync', 'sync', 'client-sync', 'routing-sync', 'role-after', 'unlock'])
                with sqlite3.connect(actual) as db:
                    expected = [(1, 'old'), (2, 'new')] if operation == 'add' else [(1, 'new')]
                    self.assertEqual(db.execute('SELECT id,comment FROM wireguard_peers').fetchall(), expected)

    def test_second_prepare_failure_keeps_recovery_hooks_and_original_error(self):
        result, events, actual = self.peer_change_fixture('late-failure')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('端口已被占用', result.stdout)
        self.assertEqual(events, ['lock', 'preflight', 'hold', 'role-before', 'prepare',
            'sync', 'client-sync', 'routing-sync', 'role-after', 'unlock'])
        with sqlite3.connect(actual) as db:
            self.assertEqual(db.execute('SELECT id,comment FROM wireguard_peers').fetchall(), [(1, 'old')])

    def test_reverse_port_conflict_precedes_slow_carrier_checks(self):
        stage = self.root/'projected'
        stage.mkdir()
        (stage/'pure-bindings').write_text('wg7 7 51707 21707\n')
        (stage/'pure.7').write_text('{}\n')
        (stage/'reverse-server.7').write_text('{}\n')
        self.tool('reverse-check', 'echo reverse-check >>"$OPERATIONS";exit 1')
        self.tool('engine', 'echo unexpected-carrier-check >>"$OPERATIONS";exit 1')
        self.tool('management', 'echo unexpected-ingress-check >>"$OPERATIONS";exit 1')
        script = (SCRIPTS/'wg_pure_service.sh').read_text()
        script = script.replace('/usr/ikuai/script/wg_hy_reverse.sh', str(self.root/'reverse-check'))
        script = script.replace('/usr/ikuai/script/wg_hy_engine.sh', str(self.root/'engine'))
        script = script.replace('/usr/ikuai/script/wg_pure_ingress.sh', str(self.root/'management'))
        script = script.replace('/tmp/iktmp/wg-hy-engine', str(self.root/'instances'))
        result = subprocess.run(['bash', '-c', script, 'pure-check', 'check', stage, 'wg7'],
            text=True, capture_output=True, env={**os.environ, 'OPERATIONS':str(self.log)})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.log.read_text().splitlines(), ['reverse-check'])

    def test_interrupted_hy_to_native_role_waits_for_sqlite_authority(self):
        self.prepare_reverse()
        old='{"enabled":true,"members":{},"settings":{"udp_port":8443}}'
        self.state.write_text(old)
        self.tool('lua', """
            case "$2" in
                retire_wrapped) exit 0;;
                check_mode) exit 0;;
                set_mode) echo '{"enabled":true,"members":{},"applied":true}' > "$5/next";;
                sync) cat "$4" >"$5/next"; touch "$5/directions";;
                *) exit 1;;
            esac
        """)
        actual, shadow, insert, content=self.projection_databases()
        with sqlite3.connect(actual) as db: db.execute(insert,content)
        with sqlite3.connect(shadow) as db: db.execute("UPDATE wireguard_peers SET native_role='lend'")
        for committed in [False,True]:
            result=self.reverse('prepare',database=actual,arguments=[shadow,'1','wg8','off','','',''])
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            if committed:
                with sqlite3.connect(actual) as db:db.execute("UPDATE wireguard_peers SET native_role='lend'")
            result=self.reverse('sync',database=actual)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual(bool(json.loads(self.state.read_text()).get('applied')),committed)

    def test_direction_filters_decrypted_input_and_forwarded_and_local_output(self):
        runtime = self.root/'direction-runtime'
        runtime.mkdir()
        source = (SCRIPTS/'wg_hyr_direction.sh').read_text().replace('/tmp/iktmp/wg-hyr',str(runtime))
        source = source.replace('export PATH=/usr/sbin:/usr/bin:/sbin:/bin','export PATH="'+str(self.root)+':$PATH"')
        script = self.root/'permissions'
        script.write_text(source)
        listing='[[ "$*" = *" -S "* ]] || exit 1; echo "-P ${*: -1} ACCEPT"'
        self.tool('iptables',listing)
        self.tool('ip6tables',listing)
        self.tool('iptables-restore','cat >"$V4"')
        self.tool('ip6tables-restore','cat >"$V6"')
        snapshot=self.root/'devices'
        snapshot.write_text('wg1 lend 10.1.0.2/32\nwg2 access 10.2.0.2/32\nwg3 both 10.3.0.2/32\n'
                            'wg4 site 10.4.0.2/32 192.168.3.0/24,10.17.0.0/16\n')
        v4,v6=self.root/'v4',self.root/'v6'
        result=subprocess.run(['bash',script,snapshot],text=True,capture_output=True,
            env={**os.environ,'V4':str(v4),'V6':str(v6)})
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        rules=v4.read_text().splitlines()
        self.assertFalse(any(' -j ACCEPT' in rule for rule in rules))
        for head in ['INPUT','FORWARD','OUTPUT']: self.assertIn(f'-I {head} 1 -j NR_HYR_DIR',rules)
        self.assertIn('-A NR_HYR_REPLY -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN',rules)
        self.assertIn('-A NR_HYR_REPLY -j DROP',rules)
        self.assertIn('-A NR_HYR_REPLY -p icmp -m conntrack --ctstate RELATED --ctdir REPLY -j RETURN',rules)
        for prefix in ['','ppp']:
            self.assertIn(f'-A NR_HYR_DIR -i {prefix}wg1 -j NR_HYR_REPLY',rules)
            self.assertIn(f'-A NR_HYR_DIR -o {prefix}wg2 -j NR_HYR_REPLY',rules)
            self.assertIn(f'-A NR_HYR_DIR -i {prefix}wg2 ! -s 10.2.0.2/32 -j DROP',rules)
            self.assertIn(f'-A NR_HYR_DIR -i {prefix}wg3 ! -s 10.3.0.2/32 -j NR_HYR_REPLY',rules)
            site=f'-A NR_HYR_DIR -i {prefix}wg4'
            for source in ['10.4.0.2/32','192.168.3.0/24','10.17.0.0/16']:
                self.assertIn(f'-A NR_HYR_DIR -o {prefix}wg4 -d {source} -m mark ! --mark 0x57000000/0xffffffff -j NR_HYR_REPLY',rules)
                self.assertIn(f'{site} -s {source} -m mark --mark 0x57000000/0xffffffff -j RETURN',rules)
                for wan in ['wan+','vwan+','adsl+']:
                    self.assertIn(f'{site} -s {source} -o {wan} -j RETURN',rules)
            self.assertIn(f'{site} -j NR_HYR_REPLY',rules)
            self.assertNotIn(f'{site} -s 192.168.3.0/24 -j RETURN',rules)
            for n in [1,2,3,4]:
                self.assertIn(f'-A NR_HYR_DIR -i {prefix}wg{n} -j DROP',v6.read_text())
                self.assertIn(f'-A NR_HYR_DIR -o {prefix}wg{n} -j DROP',v6.read_text())

        # Simulate a previous firmware leaving seven duplicate jumps after an
        # ACCEPT rule. The restore transaction must place one jump before it.
        listing = """
            [[ "$*" = *" -S "* ]] || exit 1
            head=${*: -1}
            echo "-A $head -p udp -j ACCEPT"
            for i in {1..7}; do echo "[fastid: $i] -A $head -j NR_HYR_DIR"; done
        """
        self.tool('iptables',listing)
        self.tool('ip6tables',listing)
        result=subprocess.run(['bash',script,snapshot],text=True,capture_output=True,
            env={**os.environ,'V4':str(v4),'V6':str(v6)})
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        for rules in [v4.read_text().splitlines(),v6.read_text().splitlines()]:
            for head in ['INPUT','FORWARD','OUTPUT']:
                self.assertEqual(rules.count(f'-D {head} -j NR_HYR_DIR'),7)
                self.assertEqual(rules.count(f'-I {head} 1 -j NR_HYR_DIR'),1)

    def test_imported_router_roles_gate_authenticated_source_wan_and_replies(self):
        runtime = self.root/'client-directions'
        runtime.mkdir()
        source=(SCRIPTS/'wg_hyr_direction.sh').read_text().replace('/tmp/iktmp/wg-site-client',str(runtime))
        source=source.replace('export PATH=/usr/sbin:/usr/bin:/sbin:/bin','export PATH="'+str(self.root)+':$PATH"')
        script=self.root/'permissions';script.write_text(source)
        for name in ['iptables','ip6tables']:
            self.tool(name,'[[ "$*" = *" -S "* ]] || exit 1; echo "-P ${*: -1} ACCEPT"')
            self.tool(name+'-restore','cat >"'+str(runtime/name)+'"')
        snapshot=runtime/'roles'
        snapshot.write_text('wg1 access 10.1.0.1/32\nwg2 lend 10.2.0.1/32\nwg3 both 10.3.0.1/32\n')
        subprocess.run(['bash',script,snapshot,'client'],check=True)
        rules=(runtime/'iptables').read_text().splitlines()
        self.assertIn('-A NR_HYC_REPLY -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN',rules)
        self.assertIn('-A NR_HYC_REPLY -j DROP',rules)
        for i in [1,2,3]:
            for prefix in ['wg','pppwg']:
                dev=f'{prefix}{i}'
                inbound='-A NR_HYC_DIR -i '+dev
                self.assertIn(inbound+' -j NR_HYC_REPLY',rules)
                self.assertEqual(f'-A NR_HYC_DIR -o {dev} -j NR_HYC_REPLY' in rules,i==2)
                for wan in ['wan+','vwan+','adsl+']:
                    allowed=inbound+f' -s 10.{i}.0.1/32 -o {wan} -j RETURN'
                    self.assertEqual(allowed in rules,i in (2,3))
                    if i!=1:self.assertLess(rules.index(allowed),rules.index(inbound+' -j NR_HYC_REPLY'))
                self.assertNotIn(inbound+f' -s 10.{i}.0.1/32 -j RETURN',rules)
                self.assertIn(inbound+' -j DROP',(runtime/'ip6tables').read_text().splitlines())

    def test_direction_reconciles_actual_order_of_ipv4_and_ipv6_rules(self):
        runtime=self.root/'dir-runtime';runtime.mkdir()
        src=(SCRIPTS/'wg_hyr_direction.sh').read_text().replace('/tmp/iktmp/wg-site-client',str(runtime))
        src=src.replace('export PATH=/usr/sbin:/usr/bin:/sbin:/bin','export PATH="'+str(self.root)+':$PATH"')
        script=self.root/'directions';script.write_text(src)
        snapshot=self.root/'peers';snapshot.write_text('wg2 site 10.0.0.2/32 192.168.22.0/24\n')
        families=('iptables','ip6tables')
        for name in families:
            self.tool(name, """[[ $3 = -S ]] || exit 1
            f="$WORK/${0##*/}.$4";if [ -f "$f" ];then cat "$f";else echo "-P $4 ACCEPT";fi""")
            self.tool(name+'-restore','cat >"$WORK/${0##*/}.called"')
        def run():
            subprocess.run(['bash',script,snapshot,'client'],check=True,env={**os.environ,'WORK':str(self.root)})
        run()
        baseline={}
        for name in families:
            receipt=self.root/(name+'-restore.called')
            rules=receipt.read_text().splitlines();receipt.unlink()
            for hook in ('INPUT','FORWARD','OUTPUT'):
                (self.root/(name+'.'+hook)).write_text(f'-P {hook} ACCEPT\n[fastid: 1] -A {hook} -j NR_HYC_DIR\n')
            for chain in ('NR_HYC_REPLY','NR_HYC_DIR'):
                lines=[r for r in rules if r.startswith('-A '+chain+' ')]
                # Native -S can move addresses ahead of input interface, omit
                # /32 or the full mask, and quote the comment.
                for i,row in enumerate(lines):
                    row=row.replace('-i wg2 -s 10.0.0.2/32','-s 10.0.0.2 -i wg2')
                    row=row.replace('0x57000000/0xffffffff','0x57000000')
                    if '--comment nr-dir-' in row: row=row.replace('--comment nr-dir-','--comment "nr-dir-').replace(' -j RETURN','" -j RETURN')
                    lines[i]=row
                path=self.root/(name+'.'+chain)
                baseline[path]=['-N '+chain,*lines]
                path.write_text('\n'.join(baseline[path])+'\n')
        run()
        self.assertFalse(list(self.root.glob('*-restore.called')))
        for name in families:
            for chain,scenario in [('NR_HYC_REPLY','missing drop'),('NR_HYC_DIR','early return'),('NR_HYC_DIR','wrong order')]:
                with self.subTest(name=name,scenario=scenario):
                    path=self.root/(name+'.'+chain)
                    lines=baseline[path][:]
                    if scenario=='missing drop': lines.pop()
                    elif scenario=='early return': lines.insert(1,'-A '+chain+' -j RETURN')
                    else: lines[1],lines[-1]=lines[-1],lines[1]
                    path.write_text('\n'.join(lines)+'\n')
                    run()
                    receipt=self.root/(name+'-restore.called')
                    self.assertEqual(list(self.root.glob('*-restore.called')),[receipt])
                    self.assertIn('-A NR_HYC_REPLY -j DROP',receipt.read_text().splitlines())
                    receipt.unlink();path.write_text('\n'.join(baseline[path])+'\n')

    def test_native_direction_is_scoped_to_each_device(self):
        runtime=self.root/'native'
        runtime.mkdir()
        source=(SCRIPTS/'wg_hyr_direction.sh').read_text().replace('/tmp/iktmp/wg-native-role',str(runtime))
        source=source.replace('export PATH=/usr/sbin:/usr/bin:/sbin:/bin','export PATH="'+str(self.root)+':$PATH"')
        runner=self.root/'filter';runner.write_text(source)
        listing='[[ "$*" = *" -S "* ]] || exit 1; echo "-P ${*: -1} ACCEPT"'
        for tool in ['iptables','ip6tables']:
            self.tool(tool,listing)
            self.tool(tool+'-restore','cat >'+str(runtime/tool))
        snap=self.root/'snapshot'
        snap.write_text('wg1 access 10.1.0.2/32\nwg1 access 10.1.0.3/32\nwg2 lend 10.2.0.2/32\nwg3 both 10.3.0.2/32\n')
        result=subprocess.run(['bash',runner,snap,'native'],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        lines=(runtime/'iptables').read_text().splitlines()
        for prefix in ['','ppp']:
            for addr in ['10.1.0.2','10.1.0.3']:
                self.assertIn(f'-A NR_WG_DIR -o {prefix}wg1 -d {addr}/32 -j NR_WG_REPLY',lines)
            self.assertNotIn(f'-A NR_WG_DIR -o {prefix}wg1 -j NR_WG_REPLY',lines)
            self.assertFalse(any('wg1' in rule for rule in (runtime/'ip6tables').read_text().splitlines()))
            self.assertIn(f'-A NR_WG_DIR -i {prefix}wg2 -j NR_WG_REPLY',lines)
            self.assertIn(f'-A NR_WG_DIR -i {prefix}wg3 ! -s 10.3.0.2/32 -j NR_WG_REPLY',lines)
        self.assertFalse(any(' -j ACCEPT' in r for r in lines))
        snap.write_text('wg+ hold 0.0.0.0/32\n')
        result=subprocess.run(['bash',runner,snap,'native-hold'],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        for tool in ['iptables','ip6tables']:
            self.assertIn('-A NR_WG_FENCE -i wg+ -j DROP',(runtime/tool).read_text())

    def test_private_projected_database_contains_only_wg_tables_and_is_removed(self):
        actual=self.root/'config.db'
        with sqlite3.connect(actual) as db:
            db.executescript('CREATE TABLE wireguard(id INTEGER PRIMARY KEY);'
                             'CREATE TABLE wireguard_peers(id INTEGER PRIMARY KEY);'
                             'CREATE TABLE unrelated_account(secret);')
        self.tool('plan', """
            count=$(sqlite3 "$4" "SELECT count(*) FROM sqlite_master WHERE type='table' and name not like 'sqlite_%'")
            test "$count" = 2 && test "$5" = 401 || exit 1
            echo "$4" > "$SCRATCH_LOG"
            test "$FAIL_PLAN" = 0
        """)
        source=wireguard_source().replace('/usr/ikuai/script/wg_hy_ctl.sh',str(self.root/'plan'))
        source=source.replace('/tmp/iktmp/wg-mode.',str(self.root/'wg-mode.'))
        wireguard=self.root/'wireguard.sh'; wireguard.write_text(source)
        with sqlite3.connect(actual) as db:
            db.executescript("drop table wireguard_peers;create table wireguard_peers(id integer primary key autoincrement);"
                             "insert into wireguard_peers(id) values (400);delete from wireguard_peers;")
        for fail in [True,False]:
            result=subprocess.run(['bash','-c',"""
              Include(){ :; }
              source "$1"
              sql_config_insert(){ sqlite3 "$1" 'INSERT INTO wireguard_peers DEFAULT VALUES;SELECT last_insert_rowid()'; }
              hyr_mode=both;interface=wg1;IK_DB_CONFIG=$2;sql_param=id:null
              __wg_save_peer add
            """,'peer-write',wireguard,actual],text=True,capture_output=True,
                env={**os.environ,'SCRATCH_LOG':str(self.log),'FAIL_PLAN':str(int(fail))})
            self.assertEqual(result.returncode==0,not fail,result.stdout+result.stderr)
            self.assertFalse(Path(self.log.read_text().strip()).exists())
            self.assertEqual(list(self.root.glob('wg-mode.*')),[])

    def test_off_peer_does_not_stage_or_freeze_other_active_tunnels(self):
        registry=self.root/'roles.json'
        registry.write_text('{"enabled":true,"members":{"99":{"interface":"wg9"}}}')
        source=wireguard_source().replace('/etc/mnt/ikuai/wg-hyr/state.json',str(registry))
        wireguard=self.root/'wireguard.sh';wireguard.write_text(source)
        for operation in ['add','edit']:
            for phase in ['prepare','preflight']:
                for mode in ['off','legacy']:
                    with self.subTest(operation=operation,phase=phase,mode=mode):
                        result=subprocess.run(['bash','-c',"""
                            Include(){ :; }; source "$1"
                            __wg_peer_write(){ echo direct-native; }
                            mktemp(){ echo unexpected-projection;return 1; }
                            if [ "$4" = off ];then hyr_mode=off;else unset hyr_mode;fi
                            hyr_id='';interface=wg8;id=42;IK_DB_CONFIG=db
                            __wg_save_peer "$2" "$3"
                        """,'off-peer',wireguard,operation,phase,mode],text=True,capture_output=True,cwd=self.root)
                        self.assertEqual(result.returncode,0,result.stderr)
                        self.assertEqual(result.stdout.strip(),'direct-native' if phase=='prepare' else '')

    def test_metadata_edit_checks_hy_registration_before_writing(self):
        actual=self.root/'existing.db'
        with sqlite3.connect(actual) as db:
            db.executescript("create table wireguard_peers(id,interface,peer_publickey);"
                             "insert into wireguard_peers values(2,'wg2','peer-key');")
        ctl=wireguard_source()
        ctl=ctl.replace('/usr/ikuai/script/wg_hy_ctl.sh',str(self.root/'hy-cas'))
        ctl=ctl.replace('/usr/ikuai/script/wg_site.sh','/usr/bin/true').replace('/usr/ikuai/script/wg_native_role.sh','/usr/bin/true')
        ctl=ctl.replace('/etc/mnt/ikuai/wg-',str(self.root/'registry-'))
        f=self.root/'compat.sh';f.write_text(ctl)
        self.tool('hy-cas','test "$3" = check_mode && test "$5" = hy-old')
        for token,permitted in [('hy-old',True),('stale',False)]:
            result=subprocess.run(['bash','-c',"""
              Include(){ :; };source "$1"
              Lock(){ :; };unLock(){ :; }
              __wg_locked_edit(){ [ "${1:-}" = preflight ] || echo write >> "$OPERATIONS"; }
              id=2;IK_DB_CONFIG=$2;hyr_origin_key=peer-key;hyr_origin_iface=wg2
              hyr_id=$3;edit
            """,'legacy-edit',f,actual,token],text=True,capture_output=True,
            env={**os.environ,'OPERATIONS':str(self.log)})
            self.assertEqual(result.returncode==0,permitted,result.stderr)
            self.assertEqual(self.log.exists(),permitted)
            self.log.unlink(missing_ok=True)

    def test_new_role_edit_rejects_reused_unregistered_id_and_allows_key_change(self):
        dbfile=self.root/'row.db'
        with sqlite3.connect(dbfile) as db:
            db.executescript("create table wireguard_peers(id integer primary key,interface,peer_publickey);"
                             "insert into wireguard_peers values(7,'wg4','replacement');")
        wireguard=SCRIPTS/'wireguard.sh'
        for key,iface,expected in [('replacement','wg4',0),('old','wg4',1),('replacement','wg5',1),('','wg4',1)]:
            result=subprocess.run(['bash','-c',"""
                Include(){ :; }; source "$1"
                IK_DB_CONFIG=$2;id=7;hyr_origin_key=$3;hyr_origin_iface=$4;peer_publickey=changed
                __wg_hyr_check_origin
            """,'snapshot',wireguard,dbfile,key,iface],capture_output=True,text=True)
            self.assertEqual(result.returncode,expected,result.stderr)

if __name__ == '__main__':
    unittest.main()
