"""Validate explicit reverse authority, imported targets, and credential revocation."""
import copy
import json
import sqlite3
import unittest
import uuid
from pathlib import Path

from lupa.lua51 import LuaError, LuaRuntime
import test_wg_site_client as site_fixture
from wg_model_fixture import ADAPTERS, SCRIPTS, WireGuardModelFixture, python_value


def mappings():
    return [dict(id='1', protocol='tcp', listen_port=18080, target_ip='192.168.50.1',
                 target_port=80, sources=['198.51.100.9/24', '198.51.100.0/24'])]


class ReverseValidation(unittest.TestCase):
    def setUp(self):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        g = self.lua.globals()
        g.encode = lambda v: json.dumps(python_value(v), sort_keys=True, separators=(',', ':'))
        g.decode = lambda s: self.table(json.loads(s))
        self.lua.execute("package.preload.cjson=function()return {encode=encode,decode=decode}end")
        self.module = self.lua.execute((SCRIPTS/'wg_reverse_config.lua').read_text())

    def table(self, value):
        return self.lua.table_from(value, recursive=True)

    def test_canonicalization_and_independent_credential_lifetime(self):
        request = self.table(dict(enabled=True, mappings=mappings()))
        saved, changed = self.module.update(request, None, self.lua.globals().encode, False)
        first = python_value(saved)
        self.assertTrue(changed)
        self.assertRegex(first['token'], r'^[a-f0-9]{64}$')
        self.assertEqual(first['mappings'][0]['sources'], ['198.51.100.0/24'])
        kept, changed = self.module.update(request, saved, self.lua.globals().encode, False)
        self.assertFalse(changed)
        self.assertEqual(kept.token, saved.token)
        edited = mappings(); edited[0]['target_port'] = 8080
        changed_saved, changed = self.module.update(self.table(dict(enabled=True, mappings=edited)),
                                                   saved, self.lua.globals().encode, False)
        self.assertTrue(changed)
        self.assertNotEqual(changed_saved.token, saved.token)
        removed, changed = self.module.update(self.table(dict(enabled=False)), changed_saved,
                                              self.lua.globals().encode, False)
        self.assertIsNone(removed); self.assertTrue(changed)
        next_saved, _ = self.module.update(request, None, self.lua.globals().encode, False)
        self.assertNotEqual(next_saved.token, saved.token)
        self.assertNotIn('token', python_value(self.module.public(next_saved)))

    def test_invalid_sources_targets_extra_fields_and_duplicate_ports_rejected(self):
        cases = []
        for field, value in [('id', '01'), ('id', '33'), ('protocol', 'icmp'), ('listen_port', 0),
                             ('target_port', 65536), ('target_ip', '0.1.2.3'), ('target_ip', '224.0.0.1'),
                             ('target_ip', '192.168.01.1'), ('sources', []),
                             ('sources', ['198.51.100.1']), ('sources', ['1.2.3.4/33']),
                             ('sources', ['0.0.0.0/0']*17), ('exec', 'touch /tmp/injected')]:
            rows = mappings(); rows[0][field] = value; cases.append(rows)
        duplicates = mappings(); second = copy.deepcopy(duplicates[0]); second['id'] = '2'
        duplicates.append(second); cases.append(duplicates)
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(LuaError):
                self.module.mappings(self.table(rows))
        local = mappings(); local[0]['target_ip'] = '127.0.0.1'; local[0]['sources'] = ['0.0.0.0/0']
        self.assertEqual(python_value(self.module.mappings(self.table(local)))[0]['target_ip'], '127.0.0.1')

    def test_port_reservations_include_paused_peers_and_are_protocol_scoped(self):
        saved = dict(version=1, enabled=True, token='ab'*32, mappings=mappings())
        state = dict(settings={'udp_port': 8443}, members={'2': dict(paused=True, reverse=copy.deepcopy(saved))})
        with self.assertRaises(LuaError):
            self.module.conflicts(self.table(saved), self.table(state), '1', lambda _: False, 80, 443)
        for protocol, port in [('tcp', 80), ('tcp', 443), ('tcp', 49871), ('udp', 53),
                               ('tcp', 6153), ('udp', 8443), ('udp', 51820)]:
            row = copy.deepcopy(saved); row['mappings'][0].update(protocol=protocol, listen_port=port)
            with self.subTest(protocol=protocol, port=port), self.assertRaises(LuaError):
                self.module.conflicts(self.table(row), self.table(dict(settings={'udp_port':8443}, members={})),
                                      '1', lambda value: value==51820, 80, 443)
        other = copy.deepcopy(saved); other['mappings'][0]['protocol'] = 'udp'
        self.module.conflicts(self.table(other), self.table(state), '1', lambda _: False, 80, 443)

    def test_runtime_status_uses_verified_helper_and_drops_secrets(self):
        raw = dict(state='online', connected=True, updated_at=1700000000, token='secret',
                   error='safe_code', mappings=[dict(id='1', listening=True, active=2, rx_bytes=45,
                                                     tx_bytes=67, target='secret', last_error='')])
        self.lua.globals().status_text = json.dumps(raw)
        self.lua.execute("""io.popen=function(command)
          assert(command=='/usr/ikuai/script/wg_hy_reverse.sh status puh-4 2>/dev/null')
          return {read=function()return status_text end,close=function()end} end""")
        actual = python_value(self.module.status('puh-4'))
        self.assertTrue(actual['connected']); self.assertEqual(actual['mappings'][0]['rx_bytes'], 45)
        self.assertNotIn('secret', json.dumps(actual))
        self.lua.globals().status_text = '{"state":"stopped","connected":true}'
        self.assertFalse(self.module.status('puh-4').connected)
        self.lua.globals().status_text = 'not JSON'
        self.assertEqual(python_value(self.module.status('puh-4')), dict(connected=False,state='stopped'))
        self.lua.execute("io.popen=function()error('helper unavailable')end")
        self.assertFalse(self.module.status('puh-4').connected)


class ReverseCenter(WireGuardModelFixture):
    def setUp(self):
        super().setUp()
        self.interface(3); self.peer(4, 3)
        self.stage = self.folder/'stage'; self.stage.mkdir()
        self.pin = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc='
        (self.stage/'pin').write_text(self.pin)
        self.sql("ALTER TABLE wireguard_peers ADD COLUMN native_role TEXT DEFAULT ''")
        self.sql('CREATE TABLE remote_control(id INTEGER,http_port INTEGER,https_port INTEGER)')
        self.sql('INSERT INTO remote_control VALUES(1,80,443)')

    def call(self, action, *args, fails=None):
        # Same external adapters as the ordinary model fixture, with the real new
        # reverse module available. Only native network/process reads are mocked.
        for pattern in ('next','directions','placements','pure-bindings','reverse-bindings','pure.*','admin.*','reverse-server.*'):
            for path in self.stage.glob(pattern): path.unlink()
        if action!='status':
            for path in self.stage.glob('reverse-error.*'): path.unlink()
        lua = LuaRuntime(unpack_returned_tuples=True); g = lua.globals(); logs=[]
        g.output=logs.append; g.new_uuid=lambda: str(uuid.uuid4())
        g.encode=lambda v: json.dumps(python_value(v), separators=(',', ':'))
        g.decode=lambda s: lua.table_from(json.loads(s), recursive=True)
        db=sqlite3.connect(self.db,isolation_level=None); self.addCleanup(db.close);db.row_factory=sqlite3.Row
        def query(path, sql, *values):
            self.assertEqual(Path(path),self.db)
            return lua.table_from([dict(r) for r in db.execute(sql,values)],recursive=True)
        def preparable(path, sql):
            self.assertEqual(Path(path),self.db)
            try: db.execute('EXPLAIN '+sql)
            except sqlite3.ProgrammingError: return True
            except sqlite3.OperationalError: return False
            return True
        def discover(command):
            if command.startswith('/usr/ikuai/script/wg_pure_admin.sh probe '): return '80 443'
            if command in ('/usr/ikuai/script/wg_hy_reverse.sh status puh-4 2>/dev/null',
                           '/usr/ikuai/script/wg_hy_reverse.sh status puh-5 2>/dev/null'):
                return '{"state":"online","connected":true,"updated_at":1700000000,"token":"do-not-leak"}'
            self.fail('Unexpected external command: '+command)
        g.query=query;g.preparable=preparable;g.discovered=discover;g.derive=lambda _: self.fail('Unexpected command')
        g.arg=lua.table_from([action,str(self.db),str(self.state) if self.state.exists() else '-',str(self.stage),*map(str,args)])
        lua.execute(ADAPTERS);g.script_folder=str(SCRIPTS)
        lua.execute("""local load=dofile;dofile=function(path)
          local name=assert(path:match('^/usr/ikuai/script/([a-z_]+%.lua)$'))
          if name=='wg_pure_client.lua' then return {local_addresses=function()return {'192.0.2.1/32'}end} end
          return load(script_folder..'/'..name) end""")
        if fails:
            with self.assertRaisesRegex(LuaError,'model exited 1'): lua.execute(self.model.read_text())
            self.assertIn(fails,logs);self.assertFalse((self.stage/'next').exists());return
        lua.execute(self.model.read_text())
        if (self.stage/'next').exists(): (self.stage/'next').replace(self.state)
        return json.loads(logs[0]) if logs else None

    def save(self, request=None, expected=None, peer_id=4):
        old=json.loads(self.state.read_text())['members'].get(str(peer_id)) if self.state.exists() else None
        args=[peer_id,'access',expected if expected is not None else (old['id'] if old else ''),
              '198.51.100.1','','wg','manual','','pure_hy2',str(self.db)]
        if request is not None: args.append(json.dumps(request))
        self.call('set_mode',*args)
        return json.loads(self.state.read_text())['members'][str(peer_id)]

    def second_reverse(self):
        self.interface(4)
        # Native-role migration added a column after the base fixture was made.
        private,public=self.keypair()
        self.sql('INSERT INTO wireguard_peers VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                 (5,'wg4','10.44.4.7/32','yes','no',0,public,'','','',private,'',''))
        rows=mappings();rows[0]['listen_port']=18081
        return self.save(dict(enabled=True,mappings=rows),peer_id=5)

    def assert_forward_only(self, peer_id, error):
        self.assertEqual((self.stage/f'reverse-error.{peer_id}').read_text(),error+'\n')
        self.assertFalse((self.stage/f'reverse-server.{peer_id}').exists())
        config=json.loads((self.stage/f'pure.{peer_id}').read_text())
        self.assertFalse(any(rule.get('port')==[49871] for rule in config['route']['rules']))
        self.assertIn(f' {peer_id} ',(self.stage/'pure-bindings').read_text())

    def test_corrupt_saved_reverse_isolated_from_forwarding_and_other_device(self):
        first=self.save(dict(enabled=True,mappings=mappings()))
        other=self.second_reverse()
        state=json.loads(self.state.read_text())
        state['members']['4']['reverse']['token']='damaged-secret'
        self.state.write_text(json.dumps(state))
        for action in ('inspect','sync'):
            self.call(action)
            self.assert_forward_only(4,'config_invalid')
            self.assertTrue((self.stage/'pure.5').exists())
            self.assertTrue((self.stage/'reverse-server.5').exists())
            self.assertFalse((self.stage/'reverse-error.5').exists())
            self.assertEqual((self.stage/'reverse-bindings').read_text(),'wg4 5 10.44.4.1 10.44.4.7\n')
        (self.stage/'ready.4').touch();(self.stage/'ready.5').touch()
        status={row['peer_id']:row for row in self.call('status','yes','yes')['members']}
        self.assertTrue(status[4]['running'])
        self.assertEqual(status[4]['reverse_status'],dict(connected=False,state='error',error='config_invalid'))
        self.assertTrue(status[5]['reverse_status']['connected'])
        self.assertNotIn('damaged-secret',json.dumps(status))
        before=self.state.read_bytes()
        self.call('set_mode',4,'access',first['id'],'198.51.100.1','','wg','manual','','pure_hy2',str(self.db),
                  fails='反向端口映射配置无效')
        self.assertEqual(before,self.state.read_bytes())
        self.assertEqual(self.save(peer_id=5)['reverse']['token'],other['reverse']['token'])
        repaired=self.save(dict(enabled=True,mappings=mappings()))
        self.assertNotEqual(repaired['reverse']['token'],first['reverse']['token'])
        self.assertTrue((self.stage/'reverse-server.4').exists())
        self.assertFalse((self.stage/'reverse-error.4').exists())

    def test_later_management_port_conflict_revokes_only_reverse_and_rejects_save(self):
        first=self.save(dict(enabled=True,mappings=mappings()))
        self.second_reverse()
        self.sql('UPDATE remote_control SET http_port=18080 WHERE id=1')
        for action in ('inspect','sync'):
            self.call(action)
            self.assert_forward_only(4,'port_conflict')
            self.assertTrue((self.stage/'reverse-server.5').exists())
        (self.stage/'ready.4').touch()
        status=next(row for row in self.call('status','yes','yes')['members'] if row['peer_id']==4)
        self.assertTrue(status['running']);self.assertFalse(status['reverse_status']['connected'])
        self.assertEqual(status['reverse_status']['error'],'port_conflict')
        before=self.state.read_bytes()
        self.call('set_mode',4,'access',first['id'],'198.51.100.1','','wg','manual','','pure_hy2',str(self.db),
                  fails='反向映射端口与管理、DNS 或控制服务冲突')
        self.assertEqual(before,self.state.read_bytes())
        disabled=self.save(dict(enabled=False))
        self.assertNotIn('reverse',disabled)
        self.assertTrue((self.stage/'pure.4').exists())
        self.assertFalse((self.stage/'reverse-error.4').exists())

    def test_saved_reverse_roundtrip_phone_authority_and_precise_control_grant(self):
        member=self.save(dict(enabled=True,mappings=mappings()))
        first_token=member['reverse']['token']
        server=json.loads((self.stage/'reverse-server.4').read_text())
        self.assertEqual(server['control'],'10.44.3.1:49871')
        self.assertEqual(server['mappings'][0]['target'],'192.168.50.1:80')
        self.assertEqual((self.stage/'reverse-bindings').read_text(),'wg3 4 10.44.3.1 10.44.3.6\n')
        center=json.loads((self.stage/'pure.4').read_text())
        control=next(rule for rule in center['route']['rules'] if rule.get('port')==[49871])
        self.assertEqual(control,dict(ip_cidr=['10.44.3.1/32'],network='tcp',port=[49871],action='route',outbound='internet'))
        deny_index=next(i for i,rule in enumerate(center['route']['rules']) if rule.get('action')=='reject' and '10.44.3.1/32' in rule.get('ip_cidr',[]))
        self.assertLess(center['route']['rules'].index(control),deny_index)
        bundle=self.call('site_profile',4,member['id'],'access')
        self.assertEqual(bundle['version'],2);self.assertEqual(bundle['reverse']['token'],first_token)
        phone=self.call('profile',4,member['id'],'access')
        self.assertNotIn(first_token,json.dumps(phone));self.assertNotIn('reverse',json.dumps(phone))
        settings=self.call('settings',4)
        self.assertTrue(settings['members'][0]['reverse']['enabled'])
        self.assertNotIn(first_token,json.dumps(settings))
        self.assertNotIn('reverse_status',settings['members'][0])
        (self.stage/'ready.4').touch()
        status=self.call('status','yes','yes')['members'][0]
        self.assertTrue(status['running'] and status['reverse_status']['connected'])
        self.assertNotIn('do-not-leak',json.dumps(status))

    def test_absent_edit_preserves_explicit_disable_revokes_and_stale_editor_fails(self):
        first=self.save(dict(enabled=True,mappings=mappings()))
        kept=self.save();self.assertEqual(first['reverse']['token'],kept['reverse']['token'])
        rows=mappings();rows[0]['target_port']=8080
        changed=self.save(dict(enabled=True,mappings=rows))
        self.assertNotEqual(changed['reverse']['token'],first['reverse']['token'])
        self.assertNotEqual(changed['id'],first['id'])
        before=self.state.read_bytes()
        self.call('set_mode',4,'access',first['id'],'198.51.100.1','','wg','manual','','pure_hy2',str(self.db),
                  json.dumps(dict(enabled=False)),fails='设备隧道已变化，请刷新后重试')
        self.assertEqual(before,self.state.read_bytes())
        disabled=self.save(dict(enabled=False))
        self.assertNotIn('reverse',disabled);self.assertFalse((self.stage/'reverse-server.4').exists())
        bundle=self.call('site_profile',4,disabled['id'],'access');self.assertEqual(bundle['version'],1)
        again=self.save(dict(enabled=True,mappings=mappings()))
        self.assertNotEqual(again['reverse']['token'],first['reverse']['token'])


class ReverseImporter(unittest.TestCase):
    setUp=site_fixture.SiteClient.setUp
    pure_access_bundle=site_fixture.SiteClient.pure_access_bundle

    def run_model(self, action, *args, **kwargs):
        # Production snapshots use a fresh stage directory. Reproduce that
        # boundary without deleting this fixture's durable database or bundle.
        if action=='snapshot':
            for pattern in ('pure.*','reverse-client.*','reverse-error.*'):
                for path in self.stage.glob(pattern): path.unlink()
        return site_fixture.SiteClient.run_model(self,action,*args,**kwargs)

    def reverse_bundle(self):
        bundle=self.pure_access_bundle();bundle['version']=2
        bundle['reverse']=dict(version=1,token='cd'*32,server='10.44.3.1',server_port=49871,mappings=mappings())
        return bundle

    def test_imported_v2_creates_local_socks_and_safe_target_runtime(self):
        bundle=self.reverse_bundle()
        self.run_model('preflight',bundle)
        self.assertEqual(self.run_model('commit'),'wg2')
        self.run_model('snapshot')
        config=json.loads((self.stage/'pure.1').read_text())
        self.assertEqual(config['inbounds'][1],dict(type='socks',tag='reverse-control',listen='127.77.1.1',listen_port=1080))
        reverse=json.loads((self.stage/'reverse-client.1').read_text())
        self.assertEqual(reverse['socks'],'127.77.1.1:1080');self.assertEqual(reverse['target_mark'],0x56000000)
        self.assertEqual(reverse['control'],'10.44.3.1:49871')
        self.assertEqual(reverse['mappings'][0]['allow'],['198.51.100.0/24'])
        status=json.loads(self.run_model('status'))['members'][0]
        self.assertTrue(status['reverse']['enabled']);self.assertFalse(status['reverse_status']['connected'])
        self.assertNotIn(bundle['reverse']['token'],json.dumps(status))

    def test_version_and_reverse_mutation_are_not_silently_accepted(self):
        bundle=self.reverse_bundle()
        wrong=copy.deepcopy(bundle);wrong['version']=1
        self.run_model('preflight',wrong,expected='纯 Hysteria 2 设备配置无效')
        wrong=copy.deepcopy(bundle);del wrong['reverse']
        self.run_model('preflight',wrong,expected='反向端口映射配置无效')
        self.run_model('preflight',bundle)
        changed=copy.deepcopy(bundle);changed['reverse']['mappings'][0]['target_port']=8080
        self.run_model('commit',changed,expected='反向映射配置已变化，请重新导入')
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM wireguard_peers').fetchone()[0],0)

    def test_damaged_persisted_reverse_preserves_bound_hy2_but_fresh_import_rejects(self):
        bundle=self.reverse_bundle()
        self.run_model('preflight',bundle);self.run_model('commit');self.run_model('snapshot')
        for damage in ('token','sources','missing'):
            broken=copy.deepcopy(bundle)
            if damage=='token': broken['reverse']['token']='damaged-secret'
            elif damage=='sources': broken['reverse']['mappings'][0]['sources']=[]
            else: del broken['reverse']
            with self.subTest(damage=damage):
                with sqlite3.connect(self.path) as db:
                    db.execute('UPDATE wg_site_clients SET pure_bundle=? WHERE peer_id=1',(json.dumps(broken),))
                self.run_model('snapshot')
                self.assertEqual((self.stage/'pure_units').read_text(),'wg2 1 ready\n')
                self.assertEqual((self.stage/'reverse-error.1').read_text(),'config_invalid\n')
                self.assertFalse((self.stage/'reverse-client.1').exists())
                config=json.loads((self.stage/'pure.1').read_text())
                self.assertEqual([row['type'] for row in config['inbounds']],['tun'])
                self.assertEqual(config['outbounds'][0]['password'],bundle['transport']['password'])
                status=json.loads(self.run_model('status'))['members'][0]
                self.assertEqual(status['reverse_status'],dict(connected=False,state='error',error='config_invalid'))
                self.assertNotIn('damaged-secret',json.dumps(status))
                self.run_model('preflight',broken,expected='反向端口映射' if damage!='sources' else '每条反向映射')
        # A damaged HY2 identity must still fail closed; recovery is not a
        # generic bypass for transport validation or unrelated bundle fields.
        for change in ('transport','identity','extra'):
            broken=copy.deepcopy(bundle);broken['reverse']['token']='bad'
            if change=='transport': broken['transport']['password']='bad'
            elif change=='identity': broken['transport']['server']='198.51.100.99'
            else: broken['outbounds']=[dict(type='direct')]
            with self.subTest(change=change):
                with sqlite3.connect(self.path) as db:
                    db.execute('UPDATE wg_site_clients SET pure_bundle=? WHERE peer_id=1',(json.dumps(broken),))
                self.run_model('snapshot')
                self.assertEqual((self.stage/'pure_units').read_text(),'wg2 1 conflict\n')
                self.assertFalse((self.stage/'pure.1').exists())
                self.assertFalse((self.stage/'reverse-client.1').exists())


if __name__=='__main__': unittest.main()
