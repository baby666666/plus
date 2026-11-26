"""Protect the management-only namespace and its native firewall continuation."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[2] / 'materials/firmware/port-3726/files/usr/ikuai/script'


class ManagementNetworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tools = self.root / 'bin'
        self.tools.mkdir()
        self.log = self.root / 'calls'
        self.state = self.root / 'state.json'
        self.state.write_text('{}')
        self.env = {**os.environ, 'FIXTURE':str(self.state), 'CALLS':str(self.log),
                    'PATH':str(self.tools)+':'+os.environ['PATH']}
        self.stub('ip', '''
import json,os,sys
s=json.load(open(os.environ['FIXTURE']));a=sys.argv[1:]
with open(os.environ['CALLS'],'a') as f:f.write('ip '+ ' '.join(a)+'\\n')
if a==['-o','-4','addr','show']: print(s.get('addresses','1: wg7 inet 10.177.7.1/24 scope global wg7'));sys.exit(0)
if a==['-4','route','show','table','main','exact','10.177.7.2/32']: print(s.get('route',''));sys.exit(0)
if a==['link','show','dev','ppphy7']:sys.exit(0 if s.get('host') else 1)
if a==['netns','list']:print(s.get('namespace',''));sys.exit(0)
sys.exit(9)
''', python=True)
        self.stub('iptables','exit 1')
        self.stub('flock','exit 0')
        self.ingress = self.root/'ingress'
        self.ingress.write_text(self.adapt((SCRIPTS/'wg_pure_ingress.sh').read_text()).replace('root=/tmp/iktmp/wg-pure-ingress','root='+str(self.root/'runtime')))

    def stub(self,name,text,python=False):
        p=self.tools/name
        p.write_text(('#!'+os.sys.executable+'\n' if python else '#!/bin/bash\n')+text+'\n')
        p.chmod(0o700)

    def adapt(self,text):
        text=text.replace('export PATH=/usr/sbin:/usr/bin:/sbin:/bin','export PATH="'+str(self.tools)+':$PATH"')
        if os.uname().sysname=='Darwin':text=text.replace("stat -c '%u:%a'", "stat -f '%u:%Lp'")
        return text.replace('0:700',str(os.getuid())+':700').replace('0:600',str(os.getuid())+':600')

    def run_ingress(self,*args):
        return subprocess.run(['bash',str(self.ingress),*args],env=self.env,text=True,capture_output=True)

    def test_check_is_read_only_and_rejects_unrelated_resources(self):
        cases=[({},True),({'route':'10.177.7.2 dev lan2 scope link'},False),
               ({'host':True},False),({'namespace':'nrhy7'},False),
               ({'addresses':'1: wg7 inet 10.177.7.1/24\n2: lan1 inet 10.177.7.2/32'},False)]
        for state,ok in cases:
            with self.subTest(state=state):
                self.state.write_text(json.dumps(state))
                r=self.run_ingress('check','wg7','7','10.177.7.2','10.177.7.1')
                self.assertEqual(r.returncode==0,ok,r.stderr)
                self.assertFalse((self.root/'runtime').exists())
        self.assertNotIn(' add ',self.log.read_text())
        self.assertNotIn(' del ',self.log.read_text())

    def test_projected_native_route_is_allowed_only_during_check(self):
        self.state.write_text(json.dumps({'route':'10.177.7.2 dev wg7 scope link'}))
        r=self.run_ingress('check','wg7','7','10.177.7.2','10.177.7.1')
        self.assertEqual(r.returncode,0,r.stderr)
        r=self.run_ingress('up','wg7','7','10.177.7.2','10.177.7.1')
        self.assertNotEqual(r.returncode,0)
        self.assertNotIn(' add ',self.log.read_text())

    def test_eligible_lan_requires_unicast_correct_direction_and_established_reply(self):
        source=self.ingress.read_text().split('\nidentity ||',1)[0]
        binding=self.root/'binding'
        binding.write_text('wg7 7 10.177.7.2 10.177.7.1 80 443\n'
                           'lan1 192.168.8.1 192.168.8.0/24 192.168.8.0 192.168.8.255\n')
        code=source+'\nidentity;read_lans;admin_http=80;admin_https=443;guards emit\n'
        args=['bash','-c',code,'unit','ready','wg7','7','10.177.7.2','10.177.7.1','1','80','443',str(binding)]
        lines=subprocess.run(args,env=self.env,text=True,capture_output=True,check=True).stdout.splitlines()
        self.assertIn('-A NHF7 -m conntrack --ctstate DNAT -j DROP',lines)
        self.assertIn('-A NHF7 -d 192.168.8.255/32 -j DROP',lines)
        self.assertIn('-A NHF7 -s 10.177.7.2/32 -d 192.168.8.0/24 -o lan1 -m addrtype --dst-type UNICAST -j RETURN',lines)
        self.assertIn('-A NHR7 -s 192.168.8.0/24 -d 10.177.7.2/32 -i lan1 -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN',lines)
        self.assertFalse(any(' -j ACCEPT' in line or 'wan' in line for line in lines))
        self.assertIn('-A NHF7 -d 192.168.8.0/24 -j DROP',lines)
        self.assertNotIn('-A NHF7 -o lan+ -j DROP',lines)
        self.assertNotIn('-A NHR7 -i lan+ -j DROP',lines)
        for subnet in ('10.0.0.0/8','100.64.0.0/10','172.16.0.0/12','192.168.0.0/16'):
            self.assertNotIn(f'-A NHF7 -d {subnet} -j DROP',lines)
        forwards=[line for line in lines if line.startswith('-A NHF7 ')]
        self.assertEqual(forwards[-2:],['-A NHF7 -m addrtype --dst-type UNICAST -j RETURN','-A NHF7 -j DROP'])
        self.assertIn('-A NHR7 -d 10.177.7.2/32 -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN',lines)
        self.assertEqual(lines[-1],'-A NHR7 -j DROP')
        self.assertTrue(any('-d 192.168.8.1/32' in line and '--dport 443' in line for line in lines))
        binding.write_text(binding.read_text().replace('lan1','wan1'))
        self.assertNotEqual(subprocess.run(args,env=self.env,text=True,capture_output=True).returncode,0)

    def test_unsafe_identity_and_state_are_rejected(self):
        for peer in ('10.177.7.1','127.0.0.1','10.177.007.2','10.177.7.2;echo injected'):
            self.assertNotEqual(self.run_ingress('check','wg7','7',peer,'10.177.7.1').returncode,0)
        target=self.root/'other';target.mkdir(mode=0o700)
        (self.root/'runtime').symlink_to(target,target_is_directory=True)
        self.assertNotEqual(self.run_ingress('check','wg7','7','10.177.7.2','10.177.7.1').returncode,0)
        self.assertEqual(list(target.iterdir()),[])

    def test_vendor_firewall_snapshot_and_missing_or_reordered_guards(self):
        source=self.ingress.read_text().split('\nidentity ||',1)[0]
        commands=source+'\nidentity; printf -- "-N %s\\n" "$input" "$forward" "$reply";guards emit;hooks emit\n'
        expected=subprocess.run(['bash','-c',commands,'fixture','ready','wg7','7','10.177.7.2','10.177.7.1'],env=self.env,text=True,capture_output=True,check=True).stdout
        lines=[]
        for line in expected.splitlines():
            if line.startswith('-N '):lines.append(':'+line[3:]+' - [0:0]')
            else:lines.append('[fastid: 0] '+line.replace('--comment nr-pure-wg7-7','--comment "nr-pure-wg7-7"'))
        baseline='\n'.join(lines)+'\n';fixture=self.root/'filter';self.env['FILTER']=str(fixture)
        self.stub('iptables-save','cat "$FILTER"')
        command=source+'\nidentity;firewall_ready\n'
        def check(text):
            fixture.write_text(text)
            r=subprocess.run(['bash','-c',command,'fixture','ready','wg7','7','10.177.7.2','10.177.7.1'],env=self.env,text=True,capture_output=True)
            self.last_error=r.stderr
            return r.returncode
        self.assertEqual(check(baseline),0,self.last_error)
        self.assertNotEqual(check(baseline.replace('-A NHI7 ! -s 10.177.7.2/32 -j DROP','-A NHI7 ! -s 10.177.7.2/32 -j RETURN')),0)
        self.assertNotEqual(check(baseline+'[fastid: 9] -A NHF7 -j ACCEPT\n'),0)
        first='[fastid: 0] -A NHI7 ! -s 10.177.7.2/32 -j DROP\n'
        self.assertNotEqual(check(baseline.replace(first,'')+first),0)

    def test_policy_ready_requires_the_owned_default_route(self):
        source=self.ingress.read_text().split('\nidentity ||',1)[0]
        stubs=r'''
read_record(){ saved_peer=$peer;saved_gateway=$gateway; }
owned_link(){ return 0; }; owned_ns(){ return 0; }; route_free(){ return 0; }
neighbors_ready(){ return 0; }; firewall_ready(){ return 0; }
cat(){ echo 1; }
ip(){
 case "$*" in
  '-o -4 addr show dev ppphy7') echo '21: ppphy7 inet 10.177.7.1 peer 10.177.7.2/32';;
  'netns exec nrhy7 ip -o -4 addr show dev eth0') echo '22: eth0 inet 10.177.7.2 peer 10.177.7.1/32';;
  'netns exec nrhy7 ip -4 route show default') printf '%s' "${DEFAULT:-}";;
  'netns exec nrhy7 ip -4 route show exact 10.177.7.1/32') printf '%s' "${ROUTE:-10.177.7.1 dev eth0 scope link}";;
  'netns exec nrhy7 cat /proc/sys/net/ipv6/conf/all/disable_ipv6') echo 1;;
  *) return 99;;
 esac
}
'''
        command=source+stubs+'\nidentity;ready\n'
        args=['bash','-c',command,'fixture','ready','wg7','7','10.177.7.2','10.177.7.1']
        for default,route,ok in [('', '10.177.7.1 dev eth0 scope link',False),
                                 ('default via 10.177.7.1 dev eth0','10.177.7.1 dev eth0',True),
                                 ('default via 10.177.7.5 dev eth1','10.177.7.1 dev eth0',False),
                                 ('default via 10.177.7.1 dev eth0','10.177.7.1 dev other',False)]:
            with self.subTest(default=default,route=route):
                r=subprocess.run(args,env={**self.env,'DEFAULT':default,'ROUTE':route},text=True,capture_output=True)
                self.assertEqual(r.returncode==0,ok,r.stderr)

    def test_permanent_neighbors_use_actual_opposite_macs_and_reject_stale_state(self):
        source=self.ingress.read_text().split('\nidentity ||',1)[0]
        fake_ip=r'''
 ip(){
  case "$*" in
   '-o link show dev ppphy7') echo '21: ppphy7: <UP> link/ether 02:00:00:00:07:01';;
   'netns exec nrhy7 ip -o link show dev eth0') echo '22: eth0: <UP> link/ether 02:00:00:00:07:02';;
   '-4 neigh replace 10.177.7.2 lladdr 02:00:00:00:07:02 nud permanent dev ppphy7'|'netns exec nrhy7 ip -4 neigh replace 10.177.7.1 lladdr 02:00:00:00:07:01 nud permanent dev eth0') echo "$*" >>"$CALLS";;
   '-4 neigh show to 10.177.7.2 dev ppphy7') echo '10.177.7.2 lladdr 02:00:00:00:07:02 PERMANENT';;
   'netns exec nrhy7 ip -4 neigh show to 10.177.7.1 dev eth0')
    if [ "${BAD:-}" = yes ];then echo '10.177.7.1 lladdr 02:00:00:00:07:99 STALE'
    else echo '10.177.7.1 lladdr 02:00:00:00:07:01 PERMANENT';fi;;
   *) return 99;;
  esac
 }
'''
        code=source+fake_ip+'\nidentity;neighbors_up;neighbors_ready\n'
        r=subprocess.run(['bash','-c',code,'fixture','ready','wg7','7','10.177.7.2','10.177.7.1'],env=self.env,text=True,capture_output=True)
        self.assertEqual(r.returncode,0,r.stderr)
        lines=self.log.read_text().splitlines();self.assertEqual(len(lines),2)
        self.assertTrue(all('nud permanent' in line for line in lines))
        r=subprocess.run(['bash','-c',source+fake_ip+'\nidentity;neighbors_ready\n','fixture','ready','wg7','7','10.177.7.2','10.177.7.1'],env={**self.env,'BAD':'yes'},text=True,capture_output=True)
        self.assertNotEqual(r.returncode,0)


if __name__=="__main__": unittest.main()
