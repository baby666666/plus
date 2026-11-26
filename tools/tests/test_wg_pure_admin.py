"""Pure HY2 management grant, native socket identity and isolation fixtures.

No host kernel changes, network access, listeners, or user credentials.
"""
from pathlib import Path
import os, subprocess, tempfile, unittest
from lupa.lua51 import LuaError, LuaRuntime
SCRIPTS=Path(__file__).resolve().parents[2]/'materials/firmware/port-3726/files/usr/ikuai/script'
class AdminTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  self.conf=self.root/'conf';self.conf.mkdir();self.proc=self.root/'proc';(self.proc/'net').mkdir(parents=True)
  self.bin=self.root/'bin';self.bin.mkdir();self.cache=self.root/'cache'
  self.allowed=self.root/'allowed';self.allowed.write_text('80\n443\n')
  tool=self.bin/'ipset';tool.write_text('#!/bin/bash\n[ "$1 $2" = "test Linux_webport_default" ] && grep -Fx "$3" "$ALLOWED" >/dev/null\n');tool.chmod(0o755)
  self.env={**os.environ,'ALLOWED':str(self.allowed)}
  self.conf.joinpath('server.conf').write_text('include conf/webman_http.conf;\ninclude conf/webman_https.conf;\n')
  self.conf.joinpath('http_port.conf').write_text('listen 80;\nlisten [::]:80;\n')
  self.conf.joinpath('https_port.conf').write_text('listen 443 ssl;\nlisten [::]:443 ssl;\n')
  self.tcp('00000000:0050',100);self.tcp('00000000:01BB',101,append=True)
  self.owner(20,100);self.owner(20,101)
  text=(SCRIPTS/'wg_pure_admin.sh').read_text().replace('export PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'export PATH='+str(self.bin)+':$PATH').replace('conf=/usr/openresty/conf','conf='+str(self.conf)).replace('root=/tmp/iktmp/wg-pure-admin','root='+str(self.cache)).replace('/proc/',str(self.proc)+'/')
  if os.uname().sysname=='Darwin':text=text.replace("stat -c '%u:%a'", "stat -f '%u:%Lp'")
  text=text.replace('0:700',str(os.getuid())+':700')
  # /proc PID extraction must use the same redirected prefix as its glob.
  self.script=self.root/'helper';self.script.write_text(text)
 def tcp(self,endpoint,inode,append=False):
  with (self.proc/'net/tcp').open('a' if append else 'w') as out:out.write(f'0: {endpoint} 00000000:0000 0A 0 0 0 0 0 {inode}\n')
 def owner(self,pid,inode,exe='/usr/sbin/openresty'):
  p=self.proc/str(pid);(p/'fd').mkdir(parents=True,exist_ok=True)
  (p/'exe').unlink(missing_ok=True);(p/'exe').symlink_to(exe)
  (p/'fd'/str(inode)).unlink(missing_ok=True);(p/'fd'/str(inode)).symlink_to(f'socket:[{inode}]')
 def call(self,http=80,https=443,mode='probe'):
  r=subprocess.run(['bash',str(self.script),mode,'10.177.7.1',str(http),str(https)],env=self.env,text=True,capture_output=True)
  self.assertFalse(r.stderr,r.stderr);return r.returncode,r.stdout.strip()
 def test_native_listeners_and_read_only_probe(self):
  self.assertEqual(self.call(),(0,'80 443'));self.assertFalse(self.cache.exists())
  self.assertEqual(self.call(mode='refresh'),(0,'80 443'));self.assertTrue((self.cache/'sockets').exists())
  self.assertEqual(self.call(),(0,'80 443'))
 def test_current_dynamic_set_revokes_old_port(self):
  self.allowed.write_text('443\n');self.assertEqual(self.call(),(0,'0 443'))
 def test_disabled_config_or_unrelated_listener_does_not_authorize(self):
  self.conf.joinpath('server.conf').write_text('include conf/webman_https.conf;\n');self.assertEqual(self.call(),(0,'0 443'))
  self.owner(20,101,'/unrelated');self.assertEqual(self.call(),(0,'0 0'))
 def test_socket_conflicts_deleted_executable_and_cache_reuse(self):
  self.assertEqual(self.call(mode='refresh'),(0,'80 443'))
  self.owner(20,100,'/usr/sbin/openresty (deleted)');self.assertEqual(self.call(),(0,'0 0'))
  self.owner(20,100);self.owner(21,102,'/unrelated');self.tcp('0A000000:0050',102,append=True)
  # A listener on another address does not receive this gateway's traffic.
  self.assertEqual(self.call(),(0,'80 443'))
  self.tcp('014DB10A:0050',102,append=True) # 10.177.77.1 is not our gateway.
  self.assertEqual(self.call(),(0,'80 443'))
  self.tcp('0107B10A:0050',102,append=True)
  self.assertEqual(self.call(),(0,'0 443'))
 def test_missing_kernel_state_and_mismatched_runtime_port(self):
  self.proc.joinpath('net/tcp').write_text('');self.assertEqual(self.call(),(0,'0 0'))
  self.tcp('00000000:0050',100);self.conf.joinpath('http_port.conf').write_text('listen 8080;\n');self.assertEqual(self.call(),(0,'0 0'))
 def test_reserved_conflicting_and_malformed_ports(self):
  for bad in (53,6153,6199,6232,65536,'080','80;echo bad'):
   self.assertEqual(self.call(bad,443),(0,'0 443'))
  self.assertEqual(self.call(443,443),(0,'0 0'));self.assertEqual(self.call(0,0),(0,'0 0'))
 def test_profile_exception_is_device_gateway_tcp_and_backend_owned(self):
  lua=LuaRuntime(unpack_returned_tuples=True);profile=lua.execute((SCRIPTS/'wg_pure_profile.lua').read_text())
  member=lua.table_from({'mode':'access','password':'fixture','port':51707,'name':'fixture'})
  extra=lua.table_from(['10.177.7.1/32','192.0.2.1/32'])
  with self.assertRaises(Exception):profile.center(member,'198.51.100.1',extra)
  mg=lua.table_from({'gateway':'10.177.7.1','http_port':80,'https_port':443,'namespace':'/var/run/netns/nrhy7'})
  cfg=profile.center(member,'198.51.100.1',extra,mg)
  allow=cfg['route']['rules'][3]
  self.assertEqual(list(allow['ip_cidr'].values()),['10.177.7.1/32']);self.assertEqual(allow['network'],'tcp')
  self.assertEqual(list(allow['port'].values()),[80,443]);self.assertEqual(allow['outbound'],'internet')
  self.assertEqual(cfg['route']['rules'][4]['action'],'reject')
  self.assertEqual(cfg['outbounds'][1]['netns'],'/var/run/netns/nrhy7')
  for blocked in (53,6153,6199,6232):
   mg['http_port']=blocked
   cfg=profile.center(member,'198.51.100.1',extra,mg)
   self.assertEqual(list(cfg['route']['rules'][3]['port'].values()),[443])
  mg['gateway']='198.51.100.1'
  with self.assertRaises(Exception):profile.center(member,'198.51.100.1',extra,mg)
  with self.assertRaises(Exception):profile.center(member,'198.51.100.1',extra,None)
 def test_guard_scope_and_native_acl_continuation(self):
  text=(SCRIPTS/'wg_pure_ingress.sh').read_text().split('\nidentity ||',1)[0]
  cmd=text+'\nidentity;admin_http=80;admin_https=443;guards emit\n'
  r=subprocess.run(['bash','-c',cmd,'fixture','ready','wg7','7','10.177.7.2','10.177.7.1'],text=True,capture_output=True,check=True)
  grants=[line for line in r.stdout.splitlines() if 'Linux_webport_default' in line]
  self.assertEqual(len(grants),2)
  for line in grants:
   self.assertIn('-s 10.177.7.2/32 -d 10.177.7.1/32 -p tcp',line)
   self.assertIn('--ctorigdst 10.177.7.1 --ctorigdstport',line);self.assertTrue(line.endswith('-j RETURN'))
  self.assertIn('-A NHI7 -j DROP',r.stdout);self.assertIn('-A NHF7 -m addrtype --dst-type UNICAST -j RETURN',r.stdout)
  self.assertNotIn('-j ACCEPT',r.stdout)
 def test_management_refresh_revokes_only_input_and_skips_unchanged_rules(self):
  text=(SCRIPTS/'wg_pure_ingress.sh').read_text().split('\nidentity ||',1)[0]
  output=self.root/'rules';helper=self.root/'ports'
  helper.write_text('#!/bin/bash\nprintf "%s\\n" "$VERIFIED"\n');helper.chmod(0o755)
  stubs=r'''
read_record(){ saved_peer=$peer;saved_gateway=$gateway; }
owned_link(){ return 0; }; owned_ns(){ return 0; }
input_ready(){ [ "${UNCHANGED:-0}" = 1 ]; }
iptables-restore(){ cat > "$RULES"; }
'''
  commands=text+stubs+'\nidentity;admin_helper="$HELPER";management_ports;manage\n'
  env={**os.environ,'RULES':str(output),'HELPER':str(helper),'VERIFIED':'80 443'}
  args=['bash','-c',commands,'fixture','manage','wg7','7','10.177.7.2','10.177.7.1','1','80','443']
  r=subprocess.run(args,env=env,text=True,capture_output=True);self.assertEqual(r.returncode,0,r.stderr)
  self.assertIn('--dport 80',output.read_text());self.assertIn('--dport 443',output.read_text())
  env['VERIFIED']='0 443';r=subprocess.run(args,env=env,text=True,capture_output=True);self.assertEqual(r.returncode,0,r.stderr)
  rules=output.read_text();self.assertNotIn('--dport 80 ',rules);self.assertIn('--dport 443 ',rules)
  self.assertEqual([x for x in rules.splitlines() if x.startswith('-F ')],['-F NHI7'])
  self.assertNotIn('FORWARD',rules);self.assertNotIn('WEBACL',rules)
  env['VERIFIED']='0 0';r=subprocess.run(args,env=env,text=True,capture_output=True);self.assertEqual(r.returncode,0,r.stderr)
  self.assertNotIn('Linux_webport_default',output.read_text());self.assertIn('--dport 53 -m conntrack --ctstate DNAT --ctorigdstport 53 -j RETURN',output.read_text())
  self.assertIn('-A NHI7 -j DROP',output.read_text())
  output.unlink();env['UNCHANGED']='1';r=subprocess.run(args,env=env,text=True,capture_output=True)
  self.assertEqual(r.returncode,0,r.stderr);self.assertFalse(output.exists())
if __name__=='__main__':unittest.main()
