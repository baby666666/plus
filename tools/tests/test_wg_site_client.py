"""Run the firmware bundle importer on a disposable native-schema SQLite DB."""
import base64
import copy
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

from lupa.lua51 import LuaRuntime, LuaError
from wg_model_fixture import SCRIPTS, python_value


class SiteClient(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.stage = Path(temp.name)
        self.path = self.stage/'config.db'
        schema = (SCRIPTS.parents[2]/'etc/defaults/config_db.conf').read_text()
        with sqlite3.connect(self.path) as db:
            for name in ('wireguard', 'wireguard_peers'):
                sql = re.search(r'CREATE TABLE '+name+r'\(.*?\n\);', schema, re.S).group()
                db.execute(sql)
            db.execute('CREATE TABLE lan_config(name TEXT,ip_mask TEXT)')
            db.execute("INSERT INTO lan_config VALUES('lan1','192.168.77.1/24')")
            db.execute("INSERT INTO wireguard(name,local_address,local_listenport) VALUES('wg1','10.32.1.1/24',19000)")
        def key():
            return base64.b64encode(os.urandom(32)).decode()
        self.public = key()
        self.bundle = dict(format='nativerouting-hy2-wg-site', version=1,
            transport=dict(server='198.51.100.31', server_port=51820, target_port=51820,
                           password='7a'*32, certificate_public_key_sha256=key()),
            wireguard=dict(address='10.75.0.2/24', peer_address='10.75.0.1/32', private_key=key(),
                           public_key=key(), preshared_key=key(), keepalive=15, mtu=1280),
            site={'local':['192.168.77.0/24'], 'remote':['192.168.78.0/24']})

    def run_model(self, action, bundle=None, expected=None, enable=None):
        if bundle is not None:
            (self.stage/'bundle.hex').write_text(json.dumps(bundle).encode().hex())
        lua = LuaRuntime(unpack_returned_tuples=True)
        g = lua.globals()
        out = []
        with sqlite3.connect(self.path, isolation_level=None) as db:
            db.row_factory = sqlite3.Row
            def query(sql, *args):
                return lua.table_from([dict(r) for r in db.execute(sql, args)], recursive=True)
            def mutation(sql, *args):
                db.execute(sql, args)
                return 0
            def can_prepare(sql):
                try:
                    db.execute('EXPLAIN '+sql, (None,) * sql.count('?'))
                except sqlite3.OperationalError:
                    return False
                return True
            def derive(cmd):
                if cmd.startswith("umask 077; cd '") and '/usr/bin/wg genkey >anchor.key' in cmd:
                    self.assertIn("cd '"+str(self.stage)+"'",cmd)
                    for name in ('anchor.key','anchor.pub','anchor.peer'):
                        (self.stage/name).write_text(base64.b64encode(os.urandom(32)).decode()+'\n')
                    return 0
                if cmd.startswith('/usr/ikuai/script/wg_client_endpoint.sh check_outer '):
                    self.assertRegex(cmd,r'^/usr/ikuai/script/wg_client_endpoint\.sh check_outer [0-9.]+ wg[0-9]+ [0-9./]+ [0-9./]+ >/dev/null 2>&1$')
                    return getattr(self,'route_result',0)
                if action=='native_check':
                    self.assertEqual(cmd, f"/usr/bin/lua /usr/ikuai/script/wg_site_compile.lua '{self.path}' >/dev/null")
                    return 0
                if cmd.endswith(' status >/dev/null 2>&1'):
                    return 1
                self.assertEqual(cmd, f"/usr/bin/wg pubkey < '{self.stage}/key' > '{self.stage}/pub' 2>/dev/null")
                self.assertEqual((self.stage/'key').read_text().strip(), self.bundle['wireguard']['private_key'])
                (self.stage/'pub').write_text(self.public+'\n')
                return 0
            g.query,g.mutation,g.derive,g.can_prepare=query,mutation,derive,can_prepare
            g.dns_answer=getattr(self,'dns_answer','198.51.100.32')
            g.last_id=lambda _:db.execute('SELECT last_insert_rowid()').fetchone()[0]
            g.encode=lambda val:json.dumps(python_value(val),separators=(',',':'))
            g.decode=lambda val:lua.table_from(json.loads(val),recursive=True)
            g.out=out.append
            g.folder=str(SCRIPTS)
            g.registry_path=str(self.stage/'test-registry.json')
            model=SCRIPTS/('wg_peer_options.lua' if action in ('native_check','targets') else 'wg_site_client.lua')
            if action=='targets':
                g.input_hex=(self.stage/'bundle.hex').read_text()
                lua.execute('io.read=function(n) return input_hex:sub(1,n) end')
            g.arg=lua.table_from(['runtime',str(self.path),'wg2'] if action=='native_check' else [action,str(self.path),*(enable or [str(self.stage)])])
            lua.execute("""
              package.preload.cjson=function() return {encode=encode,decode=decode} end
              package.preload.lsqlite3=function()
                return {ROW=100,DONE=101,OK=0,open=function()
                  return {busy_timeout=function() end,close=function() end,exec=function(_,q)return mutation(q)end,
                    nrows=function(_,q) local r,i=query(q),0;return function() i=i+1;return r[i] end end,
                    last_insert_rowid=last_id,
                    prepare=function(_,q)
                      if not can_prepare(q) then return nil end
                      local args={}
                      return {bind_values=function(_,...) args={...} end,
                        nrows=function() local r,i=query(q,unpack(args)),0;return function() i=i+1;return r[i] end end,
                        step=function() mutation(q,unpack(args));return 101 end,finalize=function()end}
                    end} end}
              end
              local load=dofile;dofile=function(p) return load(folder..'/'..assert(p:match('/([^/]+)$'))) end
              io.popen=function(q)
                if q=='ip -o -4 addr show' then
                  local rows={'1: lo inet 127.0.0.1/8 scope host lo','4: lan1 inet 192.168.77.1/24 scope global lan1','2: wan1 inet 203.0.113.7/24 scope global wan1'}
                  local i=0;return {lines=function()return function() i=i+1;return rows[i] end end,close=function()end}
                end
                if q=='resolveip -4 -t 4 vpn.example.test 2>/dev/null' then
                  return {read=function()return dns_answer end,close=function()end}
                end
                assert(q:match('^ip '));return {lines=function()return function()end end,close=function()end}
              end
              local open=io.open;io.open=function(p,mode)
                if p=='/etc/mnt/ikuai/wg-hyr/state.json' then return open(registry_path,mode) end
                if p:match('^/proc/net/') then return {lines=function()return function()end end,close=function()end} end
                return open(p,mode)
              end
              os.execute=derive;print=out;io.write=out
              os.exit=function(code)error('exit '..code)end
            """)
            if expected:
                with self.assertRaisesRegex(LuaError,'exit 1'):
                    lua.execute(model.read_text().removeprefix('#!/usr/bin/lua\n'))
                self.assertTrue(any(expected in s for s in out),out)
                db.rollback()
            else:
                lua.execute(model.read_text().removeprefix('#!/usr/bin/lua\n'))
        return ''.join(out)

    def seed_wrapped(self, role='site'):
        # Restore exact rows written by RC16. The RC17 importer must refuse
        # these bundles even when a valid local configuration already exists.
        cfg=self.device(False,role if role!='site' else 'both')
        self.run_model('preflight',cfg)
        self.run_model('commit')
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE wireguard_peers SET endpoint='127.0.0.1',endpoint_port=20000,site_local=?,site_remote=?",
                       ('192.168.77.0/24' if role=='site' else '', '192.168.78.0/24' if role=='site' else ''))
            db.execute("UPDATE wg_site_clients SET transport='hysteria2',purpose=?,target_port=51820,relay_port=20000,password=?,pin=?",
                       (role,self.bundle['transport']['password'],self.bundle['transport']['certificate_public_key_sha256']))

    def test_wrapped_imports_and_legacy_receivers_are_fenced(self):
        for role in ('site','access','lend','both'):
            with self.subTest(purpose=role):
                old=self.bundle if role=='site' else self.device(True,role)
                self.run_model('preflight',old,expected='承载 WG 已停用')
                self.run_model('commit',old,expected='承载 WG 已停用')
                self.seed_wrapped(role)
                status=json.loads(self.run_model('status'))['members'][0]
                self.assertTrue(status['retired'])
                self.assertFalse(status['running'] or status['enabled'])
                for op,ids in [('up','4,1'),('iface_up','2')]:
                    self.assertEqual(self.run_model('enable_uses_core',enable=[op,ids]),'retired_wrapped')
                self.run_model('snapshot');self.run_model('snapshot')
                self.assertEqual((self.stage/'directions').read_text(),'wg2 pure 10.75.0.1/32\n')
                self.assertEqual((self.stage/'enabled').read_text(),'')
                self.assertEqual((self.stage/'pure_units').read_text(),'')
                self.assertFalse(any(self.stage.glob('unit.*')))
                with sqlite3.connect(self.path) as db:
                    self.assertEqual(db.execute('SELECT enabled,native_role FROM wireguard_peers').fetchone(),('no','site_client'))
                    self.assertEqual(db.execute('SELECT purpose,password,pin FROM wg_site_clients').fetchone(),(role,'',''))
                    db.execute('DELETE FROM wg_site_clients');db.execute('DELETE FROM wireguard_peers')
                    db.execute("DELETE FROM wireguard WHERE name='wg2'")

    def test_partial_restore_with_same_wrapped_receiver_keys_cannot_open_a_native_path(self):
        self.seed_wrapped('both')
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE wireguard_peers SET native_role='access',endpoint='198.51.100.9',exit_peer='no'")
        self.assertEqual(self.run_model('enable_uses_core',enable=['up','1']),'retired_wrapped')
        self.run_model('retire_wrapped');self.run_model('retire_wrapped')
        self.assertFalse((self.stage/'directions').exists())
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT enabled FROM wireguard_peers').fetchone(),('no',))
            db.execute("UPDATE wireguard_peers SET peer_publickey='replacement',enabled='yes'")
        self.assertEqual(self.run_model('enable_uses_core',enable=['up','1']),'no')
        self.run_model('snapshot')
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT enabled FROM wireguard_peers').fetchone(),('yes',))

    def pure_access_bundle(self):
        t = self.bundle['transport']
        return dict(format='nativerouting-pure-hy2-device', version=1, purpose='access',
                    transport=dict(server=t['server'], server_port=t['server_port'], password=t['password'],
                                   certificate_public_key_sha256=t['certificate_public_key_sha256']))

    def test_pure_import_only_accepts_access_without_reverse(self):
        bundle = self.pure_access_bundle()
        for role in ('lend', 'both'):
            self.run_model('preflight', {**bundle, 'purpose': role}, expected='仅支持让这台设备连接路由器上网')
        self.run_model('preflight', {**bundle, 'reverse': {}}, expected='纯 Hysteria 2 设备配置无效')
        injected = copy.deepcopy(bundle)
        injected['transport']['outbounds'] = [{'type': 'direct'}]
        self.run_model('preflight', injected, expected='纯 Hysteria 2 设备配置无效')
        self.run_model('preflight', bundle)
        config = json.loads((self.stage/'checked.json').read_text())
        self.assertEqual([i['type'] for i in config['inbounds']], ['tun'])
        self.assertEqual([o['type'] for o in config['outbounds']], ['hysteria2'])
        self.assertNotIn('wireguard', json.dumps(config))
        self.assertEqual(self.run_model('commit'), 'wg2')
        self.run_model('native_check')
        self.run_model('snapshot')
        self.assertEqual((self.stage/'pure_units').read_text(), 'wg2 1 ready\n')
        self.assertEqual(json.loads((self.stage/'pure.1').read_text()), config)
        self.assertIn(' pure ', (self.stage/'directions').read_text())
        self.assertEqual(self.run_model('enable_uses_core', enable=['up','1']), 'yes')
        self.assertEqual(self.run_model('enable_wait', enable=['up','1']), 'yes')
        self.assertEqual(self.run_model('enable_wait', enable=['iface_up','1']), 'no')
        self.run_model('preflight', bundle, expected='已导入')

    def test_wait_only_for_matching_receiver_or_listener(self):
        self.assertEqual(self.run_model('enable_wait', enable=['up','1']), 'no')
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE wireguard SET local_publickey=?,enabled='yes' WHERE id=1", (self.public,))
            db.execute("INSERT INTO wireguard_peers(interface,peer_publickey,enabled,exit_peer) VALUES('wg1',?,'no','no')",
                       (self.public,))
        state = dict(enabled=True, members={'1': dict(transport='pure_hy2', mode='access', interface='wg1',
                         iface_id=1, server_key=self.public, peer_key=self.public, exit=False)})
        registry = self.stage/'test-registry.json'
        registry.write_text(json.dumps(state))
        self.assertEqual(self.run_model('enable_wait', enable=['up','1,2']), 'yes')
        self.assertEqual(self.run_model('enable_wait', enable=['iface_up','1']), 'no')
        state['members']['1']['server_key'] = 'replaced'
        registry.write_text(json.dumps(state))
        self.assertEqual(self.run_model('enable_wait', enable=['up','1']), 'no')

    def test_api_wait_budget(self):
        lua = LuaRuntime(unpack_returned_tuples=True)
        calls = []
        def run(command, stdin, timeout, limit):
            calls.append((command, timeout))
            result = 'yes\n' if 'enable_wait' in command and command.endswith(' up 2') else 'no\n'
            return True, result, '', 'exit', 0
        lua.globals().run = run
        lua.globals().decode = lambda s: lua.table_from(json.loads(s), recursive=True)
        lua.execute('''
            package.preload['resty.shell']=function() return {run=run} end
            package.preload.ffi=function() return {cdef=function() end,new=function() end} end
            cjson={decode=decode}
        ''')
        rest = lua.execute((SCRIPTS.parents[1]/'openresty/lua/lib/ikngx.lua').read_text()).rest
        pure = dict(wg_transport='pure_hy2', wg_role='access')
        def bundle_hex(bundle):
            return json.dumps(bundle).encode().hex()
        for action, params, timeout in [
            ('add',pure,240000), ('edit',pure,240000), ('show',pure,60000),
            ('add',dict(wg_transport='native',wg_role='access',timeout=240000),60000),
            ('site_client_import',dict(config_hex=bundle_hex(self.pure_access_bundle())),240000),
            ('site_client_import',dict(config_hex=bundle_hex({'format':'nativerouting-wg-device'})),60000),
            ('site_client_import',dict(config_hex='00'),60000),
            ('up',dict(id='2'),240000), ('up',dict(id='3'),60000), ('down',dict(id='2'),60000),
        ]:
            with self.subTest(action=action,timeout=timeout):
                calls.clear()
                ok, _ = rest(lua.table_from(dict(func_name='wireguard',action=action,param=params), recursive=True), None)
                self.assertTrue(ok)
                self.assertEqual(calls[-1][1], timeout)
                self.assertEqual(len(calls), 2 if action=='up' else 1)

    def restore_pure_role(self, role):
        bundle = self.pure_access_bundle()
        self.run_model('preflight', bundle)
        self.run_model('commit')
        bundle['purpose'] = role
        if role == 'lend':
            del bundle['transport']['password']
        bundle['reverse'] = dict(realm_port=51820, stun_port=51821, realm_id='old-device', token='de'*32,
                                 password='be'*32, key_pem='old reverse identity', certificate_pem='old cert')
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE wg_site_clients SET purpose=?,pure_bundle=?", (role, json.dumps(bundle)))
            db.execute("UPDATE wireguard_peers SET exit_peer=?", ('no' if role == 'lend' else 'yes',))

    def test_existing_pure_both_keeps_forward_identity_and_pause(self):
        self.restore_pure_role('both')
        bundle = self.pure_access_bundle()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE wireguard_peers SET enabled='no'")
            original = db.execute('SELECT iface,peer_id,local_public,peer_public FROM wg_site_clients').fetchone()
        status = json.loads(self.run_model('status'))['members'][0]
        self.assertEqual(status['purpose'], 'access')
        self.assertFalse(status['enabled'])
        self.assertNotIn('stun_port', status)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT purpose FROM wg_site_clients').fetchone()[0], 'both')
        self.run_model('snapshot')
        self.assertEqual((self.stage/'pure_units').read_text(), '')
        with sqlite3.connect(self.path) as db:
            self.assertEqual(original, db.execute('SELECT iface,peer_id,local_public,peer_public FROM wg_site_clients').fetchone())
            purpose, raw = db.execute('SELECT purpose,pure_bundle FROM wg_site_clients').fetchone()
            self.assertEqual(purpose, 'access')
            self.assertEqual(json.loads(raw), bundle)
            db.execute("UPDATE wireguard_peers SET enabled='yes'")
        self.run_model('snapshot')
        conf = json.loads((self.stage/'pure.1').read_text())
        self.assertEqual(conf['outbounds'][0]['password'], bundle['transport']['password'])
        self.assertEqual([i['type'] for i in conf['inbounds']], ['tun'])
        self.assertNotIn('realm', json.dumps(conf))

    def test_existing_pure_lend_is_fenced_disabled_and_cannot_reenable(self):
        self.restore_pure_role('lend')
        for operation, row in [('up','1'),('iface_up','2')]:
            self.assertEqual(self.run_model('enable_uses_core', enable=[operation,row]), 'retired')
        status = json.loads(self.run_model('status'))['members'][0]
        self.assertTrue(status['retired'])
        self.assertFalse(status['enabled'] or status['running'])
        self.assertEqual(status['purpose'], 'lend')
        self.run_model('snapshot')
        self.run_model('snapshot')
        self.assertIn('wg2 pure ', (self.stage/'directions').read_text())
        self.assertEqual((self.stage/'pure_units').read_text(), '')
        self.assertEqual((self.stage/'enabled').read_text(), '')
        self.assertFalse((self.stage/'pure.1').exists())
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT enabled,native_role FROM wireguard_peers').fetchone(), ('no','site_client'))
            self.assertEqual(db.execute('SELECT pure_bundle FROM wg_site_clients').fetchone(), (None,))
        self.assertEqual(self.run_model('enable_uses_core', enable=['iface_up','2']), 'retired')
        self.run_model('preflight', self.pure_access_bundle())
        self.assertEqual(self.run_model('commit'), 'wg3')
        self.assertEqual(self.run_model('enable_uses_core', enable=['up','2,1']), 'retired')

    def test_hot_restore_only_retires_the_verified_old_kernel_singleton(self):
        source=(SCRIPTS/'wireguard.sh').read_text()
        helper=source[source.index('__wg_retire_missing_client_links(){'):source.index('site_client_import()(')]
        helper=helper.replace('/usr/bin/lua /usr/ikuai/script/wg_site_client.lua','orphan_model').replace('/usr/bin/wg ','kernel_wg ')
        program=helper+"""
          __wg_site_client_table(){ [ "$1" = populated ]; }
          orphan_model(){ [ "$1" = retired_links ] || return 1; printf '%s\n' 'wg2 old-local old-peer'; }
          kernel_wg(){
            [[ $1 = show && $2 = wg2 ]] || return 1
            if [[ $3 = public-key ]];then printf '%s\n' "$KEY";else printf '%s\n' "$PEERS";fi
          }
          __exec_rule_iface_del(){ echo retire-"$1"; }
          __wg_retire_missing_client_links
        """
        for local,peers,retire in [('old-local','old-peer',True),('other-local','old-peer',False),
                                  ('old-local','other-peer',False),('old-local','old-peer\nother-peer',False)]:
            actual=subprocess.run(['bash','-c',program],check=True,text=True,capture_output=True,
                                  env=dict(os.environ,KEY=local,PEERS=peers,IK_DB_CONFIG='config.db'))
            self.assertEqual(actual.stdout.strip(),'retire-wg2' if retire else '')

    def test_bulk_mutation_checks_exact_saved_identities_before_any_row(self):
        cfg=self.device(False,'both')
        self.run_model('preflight',cfg);self.run_model('commit')
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE wireguard SET local_publickey='public-1' WHERE id=1")
            db.execute("INSERT INTO wireguard_peers(id,interface,peer_publickey,allowips) VALUES(2,'wg1','peer-2','10.32.1.5/32')")
        peer=[dict(id=1,interface='wg2',public_key=cfg['wireguard']['public_key'],iface_id=2,server_key=self.public),
              dict(id='2',interface='wg1',public_key='peer-2',iface_id='1',server_key='public-1')]
        iface=[dict(id=1,interface='wg1',public_key='public-1'),dict(id='2',interface='wg2',public_key=self.public)]
        stale='设备已被删除或更改'
        for op in ('up','down','del','iface_up','iface_down','iface_del'):
            rows=iface if op.startswith('iface_') else peer
            self.run_model('targets',rows,enable=[op,'2,1'])
            for key in ('public_key','interface') if op.startswith('iface_') else ('public_key','interface','server_key','iface_id'):
                bad=copy.deepcopy(rows);bad[1][key]='replaced'
                self.run_model('targets',bad,expected=stale,enable=[op,'1,2'])
            for ids,expected_rows in [('1,1',rows),('1',rows),('1,2',rows[:1]),('1,2',[rows[0],rows[0]]),('1,9',rows)]:
                self.run_model('targets',expected_rows,expected=stale,enable=[op,ids])
        with sqlite3.connect(self.path) as db: db.execute('DELETE FROM wireguard WHERE id=1')
        self.run_model('targets',peer,expected=stale,enable=['del','1,2'])
        # A parent missing both on screen and at mutation time is an exact
        # observable identity, so the operator can still delete orphan rows.
        peer[1].update(iface_id=0,server_key='')
        self.run_model('targets',peer,enable=['del','1,2'])
        with sqlite3.connect(self.path) as db: db.execute("INSERT INTO wireguard(id,name,local_publickey) VALUES(1,'wg1','replacement')")
        self.run_model('targets',peer,expected=stale,enable=['del','1,2'])

    def test_allocation_skips_referenced_names_including_paused_rules(self):
        with sqlite3.connect(self.path) as db:
            db.executescript("""
                CREATE TABLE stream_ipport (interface TEXT, nr_ingress TEXT, enabled TEXT);
                INSERT INTO stream_ipport VALUES ('wan1,wg2','pppwg3','no');
                CREATE TABLE stream_layer7 (interface TEXT);
                INSERT INTO stream_layer7 VALUES ('wg4,wan2,wg6');
                CREATE TABLE stream_domain (interface TEXT,nr_ingress TEXT);
                INSERT INTO stream_domain VALUES ('blackhole','wg5');
                INSERT INTO wireguard_peers(interface,allowips) VALUES ('wg7','10.81.0.5/32');
            """)
        self.run_model('preflight', self.device(False,'both'))
        self.assertEqual(self.run_model('commit'), 'wg8')

    def test_native_restore_requires_the_original_branch_binding(self):
        self.run_model('preflight',self.device(False,'both'))
        self.run_model('commit')
        self.run_model('native_check')
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT native_role FROM wireguard_peers').fetchone(),('site_client',))
            db.execute("UPDATE wg_site_clients SET local_public='replacement'")
        self.run_model('native_check',expected='缺少匹配的中继配置')
        with sqlite3.connect(self.path) as db:
            # Native CSV and VRRP restore only the two WG tables.
            db.execute('DROP TABLE wg_site_clients')
        self.run_model('native_check',expected='缺少匹配的中继配置')
        with sqlite3.connect(self.path) as db:
            # A manually configured native loopback endpoint retains its semantics.
            db.execute("UPDATE wireguard_peers SET native_role=''")
        self.run_model('native_check')

    def test_only_explicit_enable_of_matching_active_pair_uses_core(self):
        self.run_model('preflight',self.pure_access_bundle())
        self.run_model('commit')
        def uses(op,ids):
            return self.run_model('enable_uses_core',enable=[op,ids])
        self.assertEqual(uses('iface_up','1'),'no')  # unrelated preexisting interface
        self.assertEqual(uses('up','7,8'),'no')
        self.assertEqual(uses('up','2,1'),'yes')
        self.assertEqual(uses('iface_up','2'),'yes')
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE wireguard SET enabled='no' WHERE name='wg2'")
        self.assertEqual(uses('up','1'),'no')
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE wireguard_peers SET enabled='no' WHERE id=1")
        self.assertEqual(uses('iface_up','2'),'no')
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE wireguard SET enabled='yes',local_publickey='replaced' WHERE name='wg2'")
        self.assertEqual(uses('up','1'),'no')

    def test_explicit_enable_installs_missing_core_once_and_propagates_failure(self):
        source=(SCRIPTS/'wireguard.sh').read_text()
        function=source[source.index('__wg_site_client_prepare_enable(){'):source.index('site_client_import()(')]
        function=function.replace('/usr/bin/lua /usr/ikuai/script/wg_site_client.lua','model')
        function=function.replace('/usr/ikuai/script/wg_hy_engine.sh','engine')
        driver=function+"""
          model(){ echo "$MATCH"; }
          engine(){ test -f "$STATE/installed"; }
          __wg_hyr_install(){ echo install >> "$STATE/calls"; test "$FAIL" = 0 && touch "$STATE/installed"; }
          __wg_site_client_prepare_enable up 1
        """
        def run(match,fail=0):
            env=dict(os.environ,STATE=str(self.stage),MATCH=match,FAIL=str(fail),IK_DB_CONFIG='fixture')
            return subprocess.run(['bash','-c',driver],env=env,check=False).returncode
        self.assertEqual(run('no'),0)
        self.assertFalse((self.stage/'calls').exists())
        self.assertNotEqual(run('yes',fail=1),0)
        self.assertFalse((self.stage/'installed').exists())
        self.assertEqual(run('yes'),0)
        self.assertEqual(run('yes'),0)
        self.assertEqual((self.stage/'calls').read_text().splitlines(),['install','install'])

    def device(self,hy,role):
        b=copy.deepcopy(self.bundle)
        b.pop('site');b['version']=2;b['purpose']=role
        w=b['wireguard'];w.update(address='10.75.0.2/32',keepalive=12 if role=='lend' else 0)
        if not hy:
            b['format']='nativerouting-wg-device'
            b['transport']={'server':'198.51.100.31','server_port':51820}
            w['mtu']=1420
        return b

    def test_three_native_router_device_profiles(self):
        for role in ['access','lend','both']:
            with self.subTest(purpose=role):
                b=self.device(False,role)
                self.run_model('preflight',b);self.run_model('commit')
                self.run_model('preflight',b,expected='已导入')
                self.run_model('native_check');self.run_model('snapshot')
                self.assertEqual((self.stage/'directions').read_text(),'wg2 '+role+' 10.75.0.1/32\n')
                self.assertEqual(self.run_model('enable_uses_core',enable=['up','1']),'no')
                with sqlite3.connect(self.path) as db:
                    self.assertEqual(db.execute('SELECT endpoint,endpoint_port,exit_peer,allowips,site_local,site_remote,keepalive FROM wireguard_peers').fetchone(),
                            ('198.51.100.31',51820,'no' if role=='lend' else 'yes','10.75.0.1/32','','',12 if role=='lend' else 0))
                    self.assertEqual(db.execute('SELECT transport,purpose,relay_port,password,pin FROM wg_site_clients').fetchone(),('native',role,None,None,None))
                    self.assertEqual(db.execute("SELECT mtu FROM wireguard WHERE name='wg2'").fetchone(),(1420,))
                self.assertFalse((self.stage/'guards').read_text())
                m=json.loads(self.run_model('status'))['members'][0]
                self.assertEqual((m['purpose'],m['transport']),(role,'native'))
                with sqlite3.connect(self.path) as db:
                    db.execute("UPDATE wireguard_peers SET exit_peer=CASE WHEN exit_peer='yes' THEN 'no' ELSE 'yes' END")
                self.run_model('native_check',expected='缺少匹配')
                with sqlite3.connect(self.path) as db:
                    db.execute('DELETE FROM wg_site_clients');db.execute('DELETE FROM wireguard_peers');db.execute("DELETE FROM wireguard WHERE name='wg2'")

    def test_reimport_after_both_native_identities_disappeared_preserves_replacements(self):
        cfg=self.device(False,'both')
        self.run_model('preflight',cfg);self.run_model('commit')
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE wireguard SET local_publickey='new-local',local_address='10.94.0.2/32' WHERE name='wg2'")
            db.execute("UPDATE wireguard_peers SET peer_publickey='new-peer',allowips='10.94.0.1/32',native_role='' WHERE interface='wg2'")
            before_iface=db.execute("SELECT * FROM wireguard WHERE name='wg2'").fetchone()
            before_peer=db.execute("SELECT * FROM wireguard_peers WHERE interface='wg2'").fetchone()
        self.assertEqual(json.loads(self.run_model('status'))['members'],[])
        self.assertEqual(self.run_model('retired_links'),f"wg2 {self.public} {cfg['wireguard']['public_key']}")
        self.run_model('preflight',cfg)
        with sqlite3.connect(self.path) as db:
            # Preflight must not mutate stale metadata, even when recovery is possible.
            self.assertEqual(db.execute('SELECT iface FROM wg_site_clients').fetchall(),[('wg2',)])
        self.assertEqual(self.run_model('commit'),'wg3')
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT iface FROM wg_site_clients').fetchall(),[('wg3',)])
            self.assertEqual(db.execute("SELECT * FROM wireguard WHERE name='wg2'").fetchone(),before_iface)
            self.assertEqual(db.execute("SELECT * FROM wireguard_peers WHERE interface='wg2'").fetchone(),before_peer)
        self.run_model('preflight',cfg,expected='已导入')

    def test_partial_restore_keeps_identity_and_reserves_ids_for_other_imports(self):
        cfg=self.device(False,'both')
        self.run_model('preflight',cfg);self.run_model('commit')
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM wireguard WHERE name='wg2'")
        self.assertEqual(json.loads(self.run_model('status'))['members'],[])
        self.run_model('preflight',cfg,expected='只恢复了一部分')
        self.assertEqual(self.run_model('retired_links'),'')
        self.run_model('native_check',expected='缺少匹配的中继配置')
        # A different valid device must not consume the missing device's name/ID
        # or be blocked by a UNIQUE constraint on its committed registry row.
        fresh=copy.deepcopy(cfg)
        key=lambda:base64.b64encode(os.urandom(32)).decode()
        self.bundle['wireguard']['private_key']=key()
        self.public=key()
        fresh['wireguard'].update(private_key=self.bundle['wireguard']['private_key'],public_key=key(),
                                  address='10.94.0.2/32',peer_address='10.94.0.1/32')
        self.run_model('preflight',fresh);self.assertEqual(self.run_model('commit'),'wg3')
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT iface_id,iface FROM wg_site_clients ORDER BY iface_id').fetchall(),[(2,'wg2'),(3,'wg3')])
            self.assertEqual(db.execute("SELECT peer_publickey FROM wireguard_peers WHERE interface='wg2'").fetchone()[0],cfg['wireguard']['public_key'])

    def test_interface_only_partial_restore_preserves_renumbered_original_key(self):
        cfg=self.device(False,'access')
        self.run_model('preflight',cfg);self.run_model('commit')
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM wireguard_peers WHERE interface='wg2'")
            db.execute("UPDATE wireguard SET name='wg20',id=20 WHERE name='wg2'")
        self.run_model('preflight',cfg,expected='只恢复了一部分')
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT iface FROM wg_site_clients').fetchall(),[('wg2',)])
            self.assertEqual(db.execute("SELECT local_publickey FROM wireguard WHERE name='wg20'").fetchone(),(self.public,))

    def test_legacy_site_survives_first_native_import(self):
        self.seed_wrapped()
        old_columns='peer_id,iface_id,iface,local_public,peer_public,relay_port,server,server_port,target_port,password,pin'
        with sqlite3.connect(self.path) as db:
            db.execute('ALTER TABLE wg_site_clients RENAME TO sample')
            db.execute('CREATE TABLE wg_site_clients AS SELECT '+old_columns+' FROM sample')
            db.execute('DROP TABLE sample')
            before=[(*row[:-2],'','') for row in db.execute('SELECT * FROM wg_site_clients')]
        self.run_model('native_check');self.run_model('snapshot')
        self.assertEqual(json.loads(self.run_model('status'))['members'][0]['purpose'],'site')
        b=self.device(False,'both')
        self.public=base64.b64encode(os.urandom(32)).decode()
        b['wireguard'].update(address='10.76.0.2/32',peer_address='10.76.0.1/32')
        self.run_model('preflight',b)
        with sqlite3.connect(self.path) as db:
            self.assertNotIn('transport',[r[1] for r in db.execute('PRAGMA table_info(wg_site_clients)')])
        self.run_model('commit')
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT "+old_columns+" FROM wg_site_clients WHERE purpose='site'").fetchall(),before)
            self.assertEqual(db.execute("SELECT purpose,transport FROM wg_site_clients ORDER BY peer_id").fetchall(),
                             [('site','hysteria2'),('both','native')])

    def test_device_scope_and_dns_validation(self):
        b=self.device(False,'lend')
        b['wireguard']['keepalive']=0
        self.run_model('preflight',b,expected='格式无效')
        b=self.device(False,'both');b['site']=self.bundle['site']
        self.run_model('preflight',b,expected='格式无效')
        b.pop('site'); b['wireguard']['address']='10.75.0.2/24'
        self.run_model('preflight',b,expected='格式无效')
        b=self.device(False,'access');b['transport']['server']='vpn.example.test'
        self.dns_answer='10.75.0.2'
        self.run_model('preflight',b,expected='隧道路由冲突')
        self.dns_answer='127.0.0.1'
        self.run_model('preflight',b,expected='无法解析')
        self.dns_answer='198.51.100.32'
        b['wireguard'].pop('mtu')
        self.run_model('preflight',b);self.run_model('commit')
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT endpoint FROM wireguard_peers').fetchone(),('vpn.example.test',))
            self.assertEqual(db.execute("SELECT mtu FROM wireguard WHERE name='wg2'").fetchone(),(1420,))

    def test_native_refresh_cannot_redirect_udp_into_its_own_tunnel(self):
        source=(SCRIPTS/'wg_client_endpoint.sh').read_text()
        funcs=source[source.index('__wce_ipv4()'):source.index('__wce_public_ipv4()')]
        script=funcs+"""
          ip(){ [[ "$*" = "-4 route get $REMOTE mark 0x56000000" ]] || exit 1; echo "$ROUTE"; }
          check_outer "$REMOTE" wg7 10.83.0.2/32 10.83.0.1/32
        """
        for ip,route,ok in [('198.51.100.6','198.51.100.6 via 10.1.1.1 dev wan2',True),
                            ('198.51.100.6','198.51.100.6 dev wg7',False),
                            ('198.51.100.6','198.51.100.6 dev pppwg7',False),
                            ('198.51.100.6','local 198.51.100.6 dev lo',False),
                            ('10.83.0.2','dev wan2',False),('10.83.0.1','dev wan2',False),
                            ('127.1.1.1','dev wan2',False),('230.1.1.1','dev wan2',False)]:
            with self.subTest(address=ip,route=route):
                result=subprocess.run(['bash','-c',script],env=dict(os.environ,REMOTE=ip,ROUTE=route))
                self.assertEqual(result.returncode==0,ok)

    def test_scoped_sync_with_mixed_receivers_and_failed_hy_worker(self):
        # Run the actual receiver supervisor. Model snapshots contain two HY
        # imports and one native import, as after mixed-router restoration.
        fake=self.stage/'tools';fake.mkdir()
        runtime=self.stage/'runtime';units=self.stage/'engine';units.mkdir()
        log=self.stage/'operations';log.touch()
        def tool(name,body):
            path=fake/name;path.write_text('#!/bin/bash\n'+body+'\n');path.chmod(0o755)
        tool('sqlite3','echo 1')
        tool('stat','echo 0:700')
        tool('flock','exit 0')
        tool('iptables','exit 0');tool('ip6tables','exit 0')
        tool('wg','exit 1');tool('ip','echo "ip $*" >>"$OPERATIONS"')
        tool('wg_hyr_direction.sh','test "$DENY_FENCE" != 1')
        tool('wg_hy_engine.sh',"""
            echo "$1:$2" >> "$OPERATIONS"
            [[ "$1:$2" != puc-1:start && "$1:$2" != hyc-29999:stop ]]
        """)
        tool('fixture-model',"""
            test "$2" = snapshot || exit 2
            stage=$4
            printf 'wg1 19001 20001\nwg2 19002 20002\n' > "$stage/guards"
            printf 'wg1 1 ready\nwg2 2 ready\n' > "$stage/pure_units"
            printf 'wg1 access 10.1.0.1/32\nwg2 lend 10.2.0.1/32\nwg3 both 10.3.0.1/32\n' > "$stage/directions"
            printf 'wg1\nwg2\nwg3\n' > "$stage/enabled"
            : > "$stage/owners"
            
            echo hy1 > "$stage/pure.1"; echo hy2 > "$stage/pure.2"
        """)
        script=self.stage/'supervisor'
        source=(SCRIPTS/'wg_site_client.sh').read_text().replace('/tmp/iktmp/wg-site-client',str(runtime))
        source=source.replace('/tmp/iktmp/wg-hy-engine',str(units)).replace('/tmp/iktmp/wireguard/',str(self.stage)+'/')
        source=source.replace('script=/usr/ikuai/script','script='+str(fake)).replace('/usr/bin/lua','fixture-model')
        source=source.replace('/usr/bin/wg','wg').replace('export PATH=/usr/sbin:/usr/bin:/sbin:/bin','export PATH='+str(fake)+':$PATH')
        script.write_text(source)
        def sync(scope,deny=False):
            log.write_text('')
            proc=subprocess.run(['bash',str(script),str(self.path),'sync',*scope],
                env=dict(os.environ,OPERATIONS=str(log),DENY_FENCE=str(int(deny))),capture_output=True,text=True)
            return proc.returncode,log.read_text().splitlines()
        self.assertEqual(sync(['wg3']),(0,[]))  # native import/up/down/delete
        self.assertEqual(sync(['wg2']),(0,['puc-2:start']))
        self.assertEqual(sync(['wg1']),(73,['puc-1:start','puc-1:stop']))
        for scope in ([],['*'],['wg1 wg2']):
            self.assertEqual(sync(scope),(73,['puc-1:start','puc-1:stop','puc-2:start']))
        self.assertEqual(sync(['']),(0,[]))       # deleted/absent row scope
        rc,operations=sync(['wg3'],deny=True)
        self.assertNotEqual(rc,0)
        self.assertIn('ip link set down dev wg3',operations)
        def monitored(deny=False):
            proc=subprocess.run(['bash',str(script),str(self.path),'monitor'],
                env=dict(os.environ,OPERATIONS=str(log),DENY_FENCE=str(int(deny))),capture_output=True,text=True)
            return proc.returncode,proc.stdout.splitlines()
        self.assertEqual(monitored(),(73,['wg2','wg3']))  # healthy HY + native, regardless of wg1
        self.assertEqual(monitored(True),(1,[]))
        stale=units/'hyc-29999';stale.mkdir();(stale/'service.pid').touch()
        self.assertEqual(sync(['wg3']),(1,['hyc-29999:stop']))  # revoked listener is a global fence
        self.assertEqual(monitored(),(1,[]))

    def test_recovery_monitor_reapplies_only_ready_devices_after_worker_fault(self):
        source=(SCRIPTS/'wireguard.sh').read_text()
        fn=source[source.index('hyr_monitor(){'):source.index('__wg_hyr_scope(){')]
        fn=fn.replace('/tmp/iktmp/',str(self.stage)+'/').replace('/etc/mnt/ikuai/',str(self.stage)+'/')
        fn=fn.replace('/usr/ikuai/script/wg_site_client.sh','supervisor').replace('/usr/ikuai/script/wg_site.sh','site')
        fn=fn.replace('/usr/ikuai/script/wg_pure_routing.sh','pure_routes')
        active=self.stage/'wg-site-client';active.mkdir();(active/'active').touch()
        (self.stage/'wireguard').mkdir();(self.stage/'wireguard/wg3.conf').write_text('existing')
        driver=fn+"""
         pure_routes(){ [ "$1" = sync ]; }; Lock(){ :; }; unLock(){ :; }; site(){ :; }; __wg_apply_iface(){ echo "APPLY $1"; }
         __wg_retire_missing_client_links(){ [ "${ORPHAN_FAILURE:-0}" = 0 ]; }
         supervisor(){ [[ "$2" = monitor ]] || return 2;printf '%s\n' "$READY";return "$RC"; }
         IK_DIR_TMP="$ROOT";IK_DB_CONFIG=fixture;hyr_monitor
        """
        for code,ready,expected in [('0','wg1\nwg2\nwg3',['APPLY wg1','APPLY wg2']),
                                   ('73','wg2\nwg3',['APPLY wg2']),('1','wg2\nwg3',[])]:
            proc=subprocess.run(['bash','-c',driver],env=dict(os.environ,ROOT=str(self.stage),RC=code,READY=ready),text=True,capture_output=True)
            self.assertEqual(proc.returncode==0,code=='0')
            self.assertEqual(proc.stdout.splitlines(),expected)
        blocked=subprocess.run(['bash','-c',driver],env=dict(os.environ,ROOT=str(self.stage),RC='0',READY='wg2',ORPHAN_FAILURE='1'),
                               text=True,capture_output=True)
        self.assertNotEqual(blocked.returncode,0)
        self.assertEqual(blocked.stdout,'')

    def test_local_or_missing_outer_route_is_rejected_before_any_mutation(self):
        b=self.device(False,'access')
        self.route_result=1
        self.run_model('preflight',b,expected='入口地址指向本机')
        self.route_result=0
        self.run_model('preflight',b)
        self.route_result=1
        self.run_model('commit',b,expected='入口地址指向本机')
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT name FROM wireguard').fetchall(),[('wg1',)])
            self.assertEqual(db.execute('SELECT count(*) FROM wireguard_peers').fetchone(),(0,))
            self.assertEqual(db.execute("SELECT count(*) FROM sqlite_master WHERE name='wg_site_clients'").fetchone(),(0,))

    def test_public_import_distinguishes_committed_errors_from_validation_and_write_failures(self):
        source=(SCRIPTS/'wireguard.sh').read_text()
        fn=source[source.index('__wg_apply_imported_device(){'):source.index('__wg_locked_init()')]
        fn=fn.replace('/tmp/iktmp/wg-site-import.',str(self.stage)+'/temp.')
        fn=fn.replace('/usr/ikuai/script/wg_site_client.sh','guard').replace('/usr/ikuai/script/wg_site.sh','site')
        fn=fn.replace('/usr/bin/lua /usr/ikuai/script/wg_site_client.lua','model')
        fn=fn.replace('/usr/ikuai/script/wg_pure_routing.sh','pure_routes')
        cmd=fn+"""
          pure_routes(){ noisy pure_routes; }
          config_hex=7b7d;IK_DIR_TMP="$TEST_ROOT";IK_DB_CONFIG=fixture
          Lock(){ :; }; unLock(){ :; }; __wg_before_carrier_action(){ :; }; __wg_retire_missing_client_links(){ :; }
          noisy(){ printf 'untrusted output\nNEVER_RETURN_THIS_SECRET\n';echo raw_stderr >&2;[ "$FAIL" != "$1" ]; }
          guard(){ noisy guard; }; __wg_apply_iface(){ noisy apply; }; site(){ noisy site; }
          __wg_apply_failed(){ noisy blocked; }
          __wg_iface_cache_update(){ noisy cache; }; __wg_site_client_sync(){ noisy sync; }
          mkdir(){ if [ "$FAIL" = mkdir ];then noisy mkdir;else command mkdir "$@";fi; }
          model(){
            [ "$FAIL" != "$1" ] || { echo '配置未保存';return 1; }
            if [ "$1" = preflight ];then echo native > "$3/transport"
            elif [ "$FAIL" = result ];then echo invalid-name
            else echo wg2;fi
          }
          site_client_import
        """
        saved='组网配置已保存，请返回列表检查隧道状态后重新启用'
        for failure in ('guard','apply','site','mkdir','cache','sync','pure_routes','result','preflight','commit','success'):
            with self.subTest(failure=failure):
                proc=subprocess.run(['bash','-c',cmd],env=dict(os.environ,FAIL=failure,TEST_ROOT=str(self.stage)),text=True,capture_output=True)
                self.assertEqual(proc.returncode==0,failure=='success')
                expected='wg2' if failure=='success' else ('配置未保存' if failure in ('preflight','commit') else saved)
                self.assertEqual(proc.stdout.splitlines(),[expected])
                self.assertNotIn('NEVER_RETURN_THIS_SECRET',proc.stdout+proc.stderr)

    def test_poisoned_bundle_overlap_and_atomic_rollback(self):
        cfg=self.device(False,'access')
        for outer in ('10.75.0.2','10.75.0.1'):
            b=copy.deepcopy(cfg);b['transport']['server']=outer
            self.run_model('preflight',b,expected='入口地址与隧道路由冲突')
        b=copy.deepcopy(cfg);b['transport']['outbounds']=[{'type':'direct'}]
        self.run_model('preflight',b,expected='格式无效')
        self.run_model('preflight',cfg)
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TRIGGER refused BEFORE INSERT ON wireguard_peers BEGIN SELECT RAISE(FAIL,'forced');END")
        self.run_model('commit',expected='导入失败')
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT name FROM wireguard').fetchall(),[('wg1',)])
            self.assertEqual(db.execute("SELECT count(*) FROM sqlite_master WHERE name='wg_site_clients'").fetchone()[0],0)


if __name__=='__main__':
    unittest.main()
