"""Native exports and retirement of pre-RC17 Hysteria 2 encapsulation."""
import base64
import json
import os
import unittest
import uuid

from wg_model_fixture import WireGuardModelFixture


class ReverseHysteriaModelTest(WireGuardModelFixture):
    def setUp(self):
        super().setUp()
        self.interface(3)
        self.peer(4, 3, reverse=True)
        self.pin = base64.b64encode(os.urandom(32)).decode()
        self.state.write_text(json.dumps(dict(version=1, enabled=True, members={},
                                              settings=dict(public_ip='192.0.2.6',udp_port=8443))))
        (self.folder/'stage').mkdir()
        (self.folder / 'stage/pin').write_text(self.pin)

    def seed_wrapped(self, device, role='both', transport=None):
        state=json.loads(self.state.read_text())
        row=self.sql('SELECT p.interface,w.id,w.local_publickey,p.peer_publickey,p.exit_peer,p.allowips,w.local_listenport '
                     'FROM wireguard_peers p JOIN wireguard w ON w.name=p.interface WHERE p.id=?',(device,))[0]
        m=dict(id=str(uuid.uuid4()), password=os.urandom(32).hex(), name=f'old-{device}',mode=role,interface=row[0],
               iface_id=row[1],server_key=row[2],peer_key=row[3],exit=row[4]=='yes',address=row[5],port=row[6])
        if transport: m['transport']=transport
        state['members'][str(device)]=m
        self.state.write_text(json.dumps(state))
        return m

    def members(self):
        return self.call('status', 'yes', 'yes')['members']

    def test_editor_metadata_includes_native_identity_without_credentials_or_health(self):
        self.sql("ALTER TABLE wireguard_peers ADD COLUMN native_role TEXT DEFAULT ''")
        self.sql("UPDATE wireguard_peers SET enabled='no',site_remote='10.80.0.0/24' WHERE id=1")
        self.seed_wrapped(3)
        selected=self.call('settings',1)
        key=self.sql('SELECT peer_publickey FROM wireguard_peers WHERE id=1')[0][0]
        self.assertEqual(selected['peer'],dict(id=1,interface='wg1',peer_publickey=key,
                                               allowips='10.44.1.3/32',native_role='',exit_peer='no',
                                               site_local='',site_remote='10.80.0.0/24'))
        self.assertNotIn('peers',selected)
        self.assertNotIn('running',selected)
        self.assertNotIn('running',selected['members'][0])
        member=self.members()[0]
        expected={k:v for k,v in member.items() if k!='running'}
        self.assertEqual(selected['members'],[expected])
        self.assertIsNone(self.call('settings',999).get('peer'))
        self.assertNotIn('peer',self.call('settings'))
        public=json.dumps(selected)
        self.assertNotIn(json.loads(self.state.read_text())['members']['3']['password'],public)
        for private in self.keys:
            self.assertNotIn(private,public)

    def test_saved_native_router_bundle_roles_endpoints_and_stale_identity(self):
        self.sql("ALTER TABLE wireguard ADD COLUMN mtu INTEGER")
        self.sql("ALTER TABLE wireguard_peers ADD COLUMN native_role TEXT DEFAULT ''")
        self.sql("ALTER TABLE wireguard_peers ADD COLUMN client_endpoint TEXT")
        self.sql("UPDATE wireguard_peers SET native_role='access',client_endpoint='branch.example.test:61000',client_dns='resolver.example.test' WHERE interface='wg1'")
        self.sql("UPDATE wireguard_peers SET native_role='lend',client_endpoint='192.0.2.3' WHERE id=3")
        self.sql("UPDATE wireguard_peers SET native_role='both' WHERE id=4")
        self.sql("UPDATE wireguard SET mtu=1380 WHERE name='wg1'")
        self.public_endpoint='198.51.100.4'
        psk=base64.b64encode(os.urandom(32)).decode()
        self.sql('UPDATE wireguard_peers SET presharedkey=? WHERE id=3',(psk,))
        for device,role in [(1,'access'),(2,'access'),(3,'lend'),(4,'both')]:
            iface,pub,private,address,server_pub,server_private,router_addr,port=self.sql(
                'SELECT p.interface,p.peer_publickey,p.peer_privatekey,p.allowips,w.local_publickey,w.local_privatekey,w.local_address,w.local_listenport '
                'FROM wireguard_peers p JOIN wireguard w ON p.interface=w.name WHERE p.id=?',(device,))[0]
            args=[device,role,iface,pub,server_pub]
            if role=='lend':
                self.call('native_profile',*args,fails='借用设备网络需要非零 WG 心跳，可设置为 25 秒')
                self.sql('UPDATE wireguard_peers SET keepalive=25 WHERE id=3')
            bundle=self.call('native_profile',*args)
            host={'access':'branch.example.test','lend':'192.0.2.3','both':'198.51.100.4'}[role]
            self.assertEqual(set(bundle),{'format','version','purpose','transport','wireguard'})
            self.assertEqual((bundle['format'],bundle['version'],bundle['purpose']),('nativerouting-wg-device',2,role))
            self.assertEqual(bundle['transport'],dict(server=host,server_port=61000 if role=='access' else port))
            expected=dict(address=address,peer_address=router_addr.split('/')[0]+'/32',private_key=private,
                public_key=server_pub,mtu=1380 if role=='access' else 1420,keepalive=25 if role=='lend' else 0)
            if role=='lend': expected['preshared_key']=psk
            self.assertEqual(bundle['wireguard'],expected)
            self.assertNotIn(server_private,json.dumps(bundle))
            self.call('native_profile',device,'site',iface,pub,server_pub,fails='导出类型与已保存的隧道用途不匹配')
            for pos in (2,3,4):
                stale=args[:];stale[pos]='stale'
                self.call('native_profile',*stale,fails='设备隧道已变化，请刷新后重试')
        self.public_endpoint=None
        self.call('native_profile',*args,fails='未能检测到此 WG 接口的公网 IPv4，请手动填写可从外网访问的地址')
        self.seed_wrapped(4)
        self.call('native_profile',*args,fails='设备隧道已变化，请刷新后重试')


    def test_retirement_and_explicit_conversion(self):
        first=self.seed_wrapped(3)
        second=self.seed_wrapped(4,'lend','hysteria2')
        retired='Hysteria 2 承载 WG 已停用，请选择原生 WG 或纯 HY2'
        for action in ('profile','site_profile','uri'):
            self.call(action,3,first['id'],fails=retired)
        self.call('set_mode',3,'both',first['id'],'','','shared','shared','','hysteria2',fails=retired)
        self.call('set_mode',3,'both',first['id'],fails=retired)
        self.call('check_enable','up','1,3',fails=retired)
        self.call('check_enable','iface_up','3',fails=retired)
        self.call('retire_wrapped');self.call('retire_wrapped');self.call('sync')
        self.assertEqual(self.sql('SELECT id,enabled FROM wireguard_peers ORDER BY id'),
                         [(1,'yes'),(2,'yes'),(3,'no'),(4,'no')])
        self.assertTrue(all(r['retired'] and r['paused'] and not r['active'] and not r['running'] for r in self.members()))
        self.assertNotIn('password',self.state.read_text())
        self.call('sync')
        stage=self.folder/'stage'
        self.assertEqual((stage/'directions').read_text(),'wg2 hold 10.44.2.5/32\nwg3 hold 10.44.3.6/32\n')
        self.assertFalse(any(stage.glob('unit.*')))
        self.assertFalse((stage/'relay').exists())
        self.assertFalse((stage/'pure-bindings').exists())
        self.call('check_mode',3,'stale',fails='设备隧道已变化，请刷新后重试')
        self.call('set_mode',3,'off',first['id'])
        self.call('check_enable','up','3')
        self.sql("UPDATE wireguard_peers SET exit_peer='no' WHERE id=4")
        self.call('set_mode',4,'access',second['id'],'192.0.2.6','','wg','manual','','pure_hy2')
        self.assertFalse((stage/'pure-bindings').exists())
        self.call('check_enable','up','4')
        self.sql("UPDATE wireguard_peers SET enabled='yes' WHERE id=4")
        self.call('sync')
        self.assertTrue((stage/'pure.4').exists())

    def test_retired_configuration_tracks_keys_across_address_changes(self):
        self.seed_wrapped(3,'site')
        self.sql("UPDATE wireguard SET local_listenport=59003 WHERE id=2")
        self.sql("UPDATE wireguard_peers SET allowips='10.44.2.55/32' WHERE id=3")
        self.call('sync')
        self.assertTrue(self.members()[0]['retired'])
        self.call('retire_wrapped')
        self.assertEqual(self.sql('SELECT enabled FROM wireguard_peers WHERE id=3'),[('no',)])
        self.sql("UPDATE wireguard_peers SET peer_publickey=?,enabled='yes' WHERE id=3",(self.keypair()[1],))
        self.call('retire_wrapped');self.call('sync')
        self.assertEqual(self.members(),[])
        self.assertEqual(self.sql('SELECT enabled FROM wireguard_peers WHERE id=3'),[('yes',)])


if __name__=='__main__':
    unittest.main()
