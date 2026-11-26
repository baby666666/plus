"""Verify an existing authenticated RC21 HY2 registration can reach native LANs."""
import base64
import json
import ipaddress
from lupa.lua51 import LuaRuntime
import unittest
from wg_model_fixture import SCRIPTS, WireGuardModelFixture


class ManagementAccess(WireGuardModelFixture):
    def setUp(self):
        super().setUp()
        self.sql('CREATE TABLE remote_control(id INTEGER PRIMARY KEY,http_port INTEGER,https_port INTEGER)')
        self.sql('INSERT INTO remote_control VALUES(1,80,443)')
        self.sql('CREATE TABLE lan_config(id INTEGER PRIMARY KEY,name,bandif,ip_mask)')
        self.sql("INSERT INTO lan_config VALUES(1,'lan1','02:00:00:00:00:01','192.168.8.1/24')")
        self.interface(3)
        self.peer(4,3)
        self.sql("ALTER TABLE wireguard_peers ADD COLUMN native_role TEXT DEFAULT ''")
        self.stage=self.folder/'stage'
        self.stage.mkdir()
        (self.stage/'pin').write_text(base64.b64encode(bytes(range(32))).decode())
        self.addresses='1: lan1 inet 192.168.8.1/24 scope global lan1\n2: wan1 inet 198.51.100.1/24 scope global wan1\n'
        self.ports='80 443'
        self.call('set_mode',4,'access','','198.51.100.1','','wg','manual','','pure_hy2')

    def discovered(self,command):
        if command.startswith('/usr/ikuai/script/wg_pure_admin.sh probe '): return self.ports
        if command=='ip -o -4 addr show up': return self.addresses
        if command.startswith('openssl x509 -in '): return 'sha256 Fingerprint='+':'.join(['AA']*32)
        return super().discovered(command)

    def status(self):
        return self.call('settings',4)['members'][0]

    def runtime(self):
        self.call('sync')
        return json.loads((self.stage/'pure.4').read_text())

    def test_no_second_permission_or_credential_change(self):
        doc=json.loads(self.state.read_text())
        member=doc['members']['4']
        self.assertNotIn('allow_management',member)
        before={action:self.call(action,4,member['id'],'access') for action in ('profile','site_profile','uri')}
        for historical in (None,False,True):
            if historical is not None: member['allow_management']=historical
            self.state.write_text(json.dumps(doc))
            connection=self.runtime()
            self.assertEqual(connection['inbounds'][0]['users'][0]['password'],member['password'])
            self.assertEqual(connection['route']['final'],'internet')
            self.assertEqual(connection['outbounds'],[{'type':'direct','tag':'internet','netns':'/var/run/netns/nrhy3'}])
            self.assertNotIn('default_mark',connection['route'])
            self.assertEqual(connection['dns']['servers'],[{'type':'udp','tag':'policy-dns','server':'1.1.1.1','netns':'/var/run/netns/nrhy3'}])
            self.assertEqual(self.status()['management_url'],'https://192.168.8.1/')
            self.assertNotIn('allow_management',self.status())
            for action,expected in before.items(): self.assertEqual(self.call(action,4,member['id'],'access'),expected)

    def test_registry_upgrade_preserves_enabled_state_and_credentials(self):
        original=json.loads(self.state.read_text())
        self.assertIs(original['enabled'],True)
        self.assertNotIn('routed_enabled',original)
        for enabled in (True,False):
            for gated in (False,True):
                with self.subTest(enabled=enabled,gated=gated):
                    old=dict(original,enabled=enabled)
                    if gated:
                        old.update(enabled=False,routed_enabled=enabled)
                    self.state.write_text(json.dumps(old))
                    self.call('sync')
                    saved=json.loads(self.state.read_text())
                    self.assertIs(saved['enabled'],enabled)
                    self.assertNotIn('routed_enabled',saved)
                    self.assertEqual(saved['members'],original['members'])
                    self.assertEqual((self.stage/'pure.4').exists(),enabled)

    def test_malformed_historical_gate_cannot_enable_worker(self):
        doc=json.loads(self.state.read_text())
        for origin,marker in [(True,True),(True,False),(False,1),(False,'true')]:
            invalid=dict(doc,enabled=origin,routed_enabled=marker)
            self.state.write_text(json.dumps(invalid))
            self.call('sync',fails='纯 HY2 分流保护状态无效')
            self.assertFalse((self.stage/'pure.4').exists())

    def test_gateway_lan_host_and_broadcast_order(self):
        connection=self.runtime()
        self.assertEqual((self.stage/'admin.4').read_text().splitlines(),[
            'wg3 4 10.44.3.6 10.44.3.1 80 443',
            'lan1 192.168.8.1 192.168.8.0/24 192.168.8.0 192.168.8.255'])
        rules=connection['route']['rules']
        self.assertEqual(rules[0]['action'],'resolve')
        self.assertEqual(rules[1],{'ip_version':6,'action':'reject'})
        self.assertEqual(rules[2],{'ip_cidr':['192.168.8.0/32','192.168.8.255/32'],'action':'reject'})
        gw=['10.44.3.1/32','192.168.8.1/32']
        self.assertEqual(rules[3],{'ip_cidr':gw,'port':[80,443],'network':'tcp','action':'route','outbound':'internet'})
        self.assertEqual(rules[4],{'ip_cidr':gw,'action':'reject'})
        self.assertEqual(rules[5],{'ip_cidr':['192.168.8.0/24'],'action':'route','outbound':'internet'})
        self.assertIn('198.51.100.1/32',rules[6]['ip_cidr'])

    def test_forwarded_private_unicast_uses_native_routing(self):
        connection=self.runtime()
        deny=connection['route']['rules'][-1]
        self.assertEqual(deny['action'],'reject')
        denied=[ipaddress.ip_network(prefix) for prefix in deny['ip_cidr']]
        for host in ('10.45.8.9','172.22.55.67','192.168.178.9','100.85.22.1','203.0.113.22'):
            self.assertFalse(any(ipaddress.ip_address(host) in block for block in denied),host)
        for host in ('127.0.0.1','169.254.252.1','224.0.0.1','255.255.255.255','198.51.100.1','192.0.2.1'):
            self.assertTrue(any(ipaddress.ip_address(host) in block for block in denied),host)
        self.assertEqual(connection['route']['final'],'internet')
        self.assertEqual(connection['outbounds'][0]['netns'],'/var/run/netns/nrhy3')

    def test_local_address_inventory_excludes_connected_and_static_prefixes(self):
        lua=LuaRuntime(unpack_returned_tuples=True)
        lua.globals().plan=lua.execute((SCRIPTS/'wg_address_plan.lua').read_text())
        lua.globals().rows=lua.table_from([
            '1: lo inet 127.0.0.1/8 scope host lo',
            '1: lo inet 169.254.252.4/32 scope global lo',
            '2: lan1 inet 192.168.8.1/24 scope global lan1',
            '3: wan1 inet 198.51.100.1/24 scope global wan1',
            '4: wg3 inet 10.44.3.1/24 scope global wg3',
            '5: ppphy3@if9 inet 10.44.3.1 peer 10.44.3.6/32 scope global ppphy3'])
        lua.execute("""dofile=function(path)
            assert(path=='/usr/ikuai/script/wg_address_plan.lua'); return plan end
            io.popen=function(command)
                assert(command=='ip -o -4 addr show', 'Routes are forwarding decisions, not local addresses')
                return {lines=function() local i=0;return function() i=i+1;return rows[i] end end,close=function() end}
            end""")
        client=lua.execute((SCRIPTS/'wg_pure_client.lua').read_text())
        self.assertEqual(list(client.local_addresses().values()),['10.44.3.1/32','192.168.8.1/32','198.51.100.1/32'])

    def test_disconnected_unconfigured_wan_overlap_and_ambiguous_networks(self):
        for addresses in [
            '', '3: lan1 inet 192.168.88.1/24 scope global lan1',
            self.addresses+'3: wan2 inet 192.168.8.45/28 scope global wan2',
            self.addresses+'4: lan2 inet 192.168.8.1/24 scope global lan2',
        ]:
            with self.subTest(addresses=addresses):
                self.addresses=addresses
                self.runtime()
                self.assertEqual(len((self.stage/'admin.4').read_text().splitlines()),1)
                self.assertEqual(self.status()['management_url'],'https://10.44.3.1/')

    def test_native_management_port_lifecycle_independent_of_lan(self):
        for http,https,probe,expected in [(8080,4443,'8080 4443','https://192.168.8.1:4443/'),
                                        (8080,4443,'8080 0','http://192.168.8.1:8080/'),
                                        (8080,4443,'0 0',None),(0,0,'0 0',None)]:
            self.sql('UPDATE remote_control SET http_port=?,https_port=?',(http,https))
            self.ports=probe
            self.assertEqual(self.status().get('management_url'),expected)
            connection=self.runtime()
            self.assertIn({'ip_cidr':['192.168.8.0/24'],'action':'route','outbound':'internet'},connection['route']['rules'])

    def test_stopping_device_removes_lan_binding(self):
        self.runtime()
        token=json.loads(self.state.read_text())['members']['4']['id']
        self.call('set_mode',4,'off',token);self.call('sync')
        self.assertFalse((self.stage/'admin.4').exists())
        self.assertFalse((self.stage/'pure.4').exists())

if __name__=='__main__': unittest.main()
