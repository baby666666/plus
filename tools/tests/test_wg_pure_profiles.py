"""Exercise access-only center registration, exported authority, and RC15 upgrades."""
import base64
import hashlib
import json
import secrets
import ssl
import subprocess
import unittest
from urllib.parse import parse_qs, unquote, urlsplit

from wg_model_fixture import WireGuardModelFixture


class PureProfiles(WireGuardModelFixture):
    def setUp(self):
        super().setUp()
        self.interface(3)
        self.peer(4, 3)
        self.stage = self.folder / 'stage'
        self.stage.mkdir()
        self.pin = base64.b64encode(secrets.token_bytes(32)).decode()
        (self.stage/'pin').write_text(self.pin)
        self.sql("ALTER TABLE wireguard_peers ADD COLUMN native_role TEXT DEFAULT ''")

    def discovered(self, command):
        finger='openssl x509 -in /etc/mnt/ikuai/wg-hyr/tls/cert.pem -noout -fingerprint -sha256 2>/dev/null'
        if command != finger:
            return super().discovered(command)
        result=subprocess.run(['openssl','x509','-in',self.folder/'cert.pem','-noout','-fingerprint','-sha256'],
                              capture_output=True,text=True)
        return result.stdout.rstrip() if result.returncode==0 else None

    def save(self, device, role, token='', fails=None):
        self.call('set_mode', device, role, token, '198.51.100.1', '', 'wg', 'manual', '', 'pure_hy2', fails=fails)

    def member(self, device):
        return json.loads(self.state.read_text())['members'][str(device)]

    def assert_access(self, device, token, password):
        self.call('sync')
        center = json.loads((self.stage/f'pure.{device}').read_text())
        self.assertIn('hold', (self.stage/'directions').read_text())
        phone = self.call('profile', device, token, 'access')
        bundle = self.call('site_profile', device, token, 'access')
        self.assertEqual([i['type'] for i in center['inbounds']], ['hysteria2'])
        self.assertEqual([i['type'] for i in center['outbounds']], ['direct'])
        self.assertEqual(center['inbounds'][0]['users'][0]['password'], password)
        self.assertTrue(any('192.0.2.0/24' in rule.get('ip_cidr', []) for rule in center['route']['rules']))
        self.assertEqual([i['type'] for i in phone['inbounds']], ['tun'])
        transport = next(o for o in phone['outbounds'] if o['type']=='hysteria2')
        self.assertEqual(transport['password'], password)
        self.assertEqual(transport['tls']['certificate_public_key_sha256'], [self.pin])
        self.assertEqual(bundle['purpose'], 'access')
        self.assertEqual(bundle['transport']['password'], password)
        for forbidden in ('realm', 'stun', 'reverse', 'wireguard', 'PRIVATE KEY'):
            self.assertNotIn(forbidden, json.dumps([center,phone,bundle]))

    def seed_rc15(self, role):
        self.save(4, 'access')
        doc = json.loads(self.state.read_text())
        member = doc['members']['4']
        member.update(mode=role, exit=True, realm_token='old-realm', reverse_password='old-secret',
                      reverse_key='old-key', reverse_cert='old-cert', reverse_pin='old-pin', stun_port=54001)
        self.sql("UPDATE wireguard_peers SET exit_peer='yes' WHERE id=4")
        self.state.write_text(json.dumps(doc))
        return member

    def test_access_registration_and_rejected_reverse_writes(self):
        self.save(4, 'access')
        m = self.member(4)
        self.assert_access(4, m['id'], m['password'])
        before = self.state.read_bytes()
        for role in ('lend','both','site'):
            with self.subTest(role=role):
                self.save(4,role,m['id'],fails='纯 HY2 只支持让这台设备连接路由器上网')
                self.assertEqual(self.state.read_bytes(),before)

    def test_uri_uses_actual_leaf_and_saved_phone_authority(self):
        self.save(4, 'access')
        doc=json.loads(self.state.read_text())
        doc['members']['4']['password']=':/@ ?#%+密'
        self.state.write_text(json.dumps(doc))
        m=self.member(4)
        cert, key=self.folder/'cert.pem', self.folder/'key.pem'
        subprocess.run(['openssl','genrsa','-out',key,'2048'],check=True,capture_output=True)
        pub=subprocess.check_output(['openssl','pkey','-in',key,'-pubout','-outform','DER'])
        spki=hashlib.sha256(pub).digest()
        (self.stage/'pin').write_text(base64.b64encode(spki).decode())
        phone=self.call('profile',4,m['id'],'access')
        hy=next(out for out in phone['outbounds'] if out['type']=='hysteria2')
        before=self.state.read_bytes()
        pins=[]
        for serial in ('1','2'):
            subprocess.run(['openssl','req','-new','-x509','-key',key,'-subj','/CN=test.invalid',
                            '-set_serial',serial,'-days','1','-out',cert],check=True,capture_output=True)
            result=self.call('uri',4,m['id'],'access')
            uri=urlsplit(result['uri'])
            self.assertEqual(set(result),{'uri','server','server_port'})
            self.assertEqual((result['server'],result['server_port']), (hy['server'],hy['server_port']))
            self.assertEqual((uri.scheme,uri.hostname,uri.port,unquote(uri.username),uri.path,unquote(uri.fragment)),
                             ('hysteria2',hy['server'],hy['server_port'],hy['password'],'/',m['name']))
            self.assertEqual(uri.username,'%3A%2F%40%20%3F%23%25%2B%E5%AF%86')
            self.assertIsNone(uri.password)
            digest=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
            self.assertEqual(parse_qs(uri.query),{'sni':[hy['tls']['server_name']],'insecure':['1'],'pinSHA256':[digest]})
            self.assertNotEqual(digest,spki.hex())
            pins.append(digest)
        self.assertNotEqual(*pins)
        self.assertEqual(self.state.read_bytes(),before)
        cert.write_text('invalid')
        self.call('uri',4,m['id'],'access',fails='Hysteria 2 证书不可用')
        cert.unlink()
        self.call('uri',4,m['id'],'access',fails='Hysteria 2 证书不可用')

    def test_uri_rejects_changed_or_inactive_devices(self):
        self.save(4,'access')
        saved=self.state.read_bytes()
        m=self.member(4)
        self.call('uri',4,'old-id','access',fails='设备隧道已变化，请刷新后重试')
        self.call('uri',4,m['id'],'lend',fails='导出类型与已保存的隧道用途不匹配')
        self.call('uri',4,m['id'],fails='导出类型与已保存的隧道用途不匹配')
        for field in ('paused','enabled'):
            doc=json.loads(saved)
            if field=='paused':
                doc['members']['4']['paused']=True
            else:
                doc['enabled']=False
            self.state.write_text(json.dumps(doc))
            self.call('uri',4,m['id'],'access',fails='请选择已启用的纯 HY2 隧道')
        self.state.write_bytes(saved)
        self.sql("UPDATE wireguard_peers SET enabled='no' WHERE id=4")
        self.call('uri',4,m['id'],'access',fails='请选择已启用的纯 HY2 隧道')
        self.sql("UPDATE wireguard_peers SET peer_publickey=?,enabled='yes' WHERE id=4",(self.keypair()[1],))
        self.call('uri',4,m['id'],'access',fails='设备隧道已变化，请刷新后重试')

    def test_rc15_both_retains_forward_identity_and_loses_reverse(self):
        old = self.seed_rc15('both')
        self.assert_access(4, old['id'], old['password'])
        row = self.call('settings',4)['members'][0]
        self.assertEqual(row['mode'],'access')
        self.assertFalse(row['exit'])
        self.assertNotIn('realm_port',row)
        self.assertNotIn('stun_port',row)
        self.call('profile',4,old['id'],'both',fails='导出类型与已保存的隧道用途不匹配')
        m = self.member(4)
        for key in ('realm_token','reverse_password','reverse_key','reverse_cert','reverse_pin','stun_port'):
            self.assertNotIn(key,m)
        self.assertEqual(m['id'],old['id'])
        self.assertEqual(m['port'],old['port'])

    def test_lend_only_never_acquires_access_and_keeps_wg_fence(self):
        old = self.seed_rc15('lend')
        self.call('sync')
        self.assertFalse((self.stage/'pure.4').exists())
        self.assertFalse((self.stage/'pure-bindings').exists())
        self.assertIn('wg3 hold ', (self.stage/'directions').read_text())
        self.assertIn('wg3 ', (self.stage/'placements').read_text())
        self.assertNotIn('password', self.member(4))
        status = self.call('status','yes','yes')['members'][0]
        self.assertTrue(status['retired'] and status['paused'])
        self.assertFalse(status['active'] or status['running'])
        self.assertEqual(status['id'],old['id'])
        for action in ('profile','site_profile','uri'):
            self.call(action,4,old['id'],'lend',fails='纯 HY2 借线已停用，请重新选择设备连接方式')
        self.save(4,'lend',old['id'],fails='纯 HY2 只支持让这台设备连接路由器上网')
        for op, selected in [('up','1,4'), ('iface_up','2,3')]:
            self.call('check_enable',op,selected,fails='纯 HY2 借线已停用，请重新选择设备连接方式')
        self.call('check_enable','up','1')
        self.sql("UPDATE wireguard_peers SET exit_peer='no', enabled='no' WHERE id=4")
        self.save(4,'access',old['id'])
        new = self.member(4)
        self.assertNotEqual(old['id'],new['id'])
        self.assertNotEqual(old['password'],new['password'])
        self.assertFalse((self.stage/'pure.4').exists())
        self.call('check_enable','up','4')
        self.sql("UPDATE wireguard_peers SET enabled='yes' WHERE id=4")
        self.assert_access(4,new['id'],new['password'])


if __name__ == '__main__':
    unittest.main()
