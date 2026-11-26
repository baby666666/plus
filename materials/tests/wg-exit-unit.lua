local m=dofile(arg[1]);local count=0
local function check(value,msg)assert(value,msg);count=count+1 end
local s={interfaces={{id=1,name='wg1',local_address='10.100.1.1/24',local_listenport=50001}},peers={},networks={}}
check(m.check_peer(s,'wg1','10.100.1.2/32','','K','yes','vpn.example.com:51820'))
check(not m.check_peer(s,'wg1','10.100.1.2/24','','K','yes',''))
check(not m.check_peer(s,'wg1','0.0.0.0/0','','K','yes',''))
check(not m.check_peer(s,'wg1','10.100.1.2/32','','K','bad',''))
s.peers={{id=1,interface='wg1',allowips='10.100.1.2/32',peer_publickey='K',exit_peer='yes'}}
check(not m.check_peer(s,'wg1','10.100.1.3/32','','L','no',''))
check(not m.peer_defaults(s,'wg1'))
check(m.check_peer(s,'wg1','10.100.1.2/32','1','K','yes',''))
check(m.check_peer(s,'wg1','10.100.1.2/32','1','K','no',''))
s.peers[2]={id=2,interface='wg1',allowips='10.100.1.3/32',peer_publickey='L',exit_peer='no'}
check(not m.check_peer(s,'wg1','10.100.1.2/32','1','K','yes',''))
for _,v in ipairs{'','vpn.example.com','8.8.8.8','10.0.0.1:12345','a-b.example.com:65535'}do check(m.client_endpoint(v))end
for _,v in ipairs{'https://vpn.example.com','v\nPostUp=bad','1.2.3.999','v.test:0','v.test:65536','v..test','-v.test','v-.test','a_b.test','::1','localhost',' v.test'}do check(not m.client_endpoint(v),v)end
print('PASS '..count..' exit role and endpoint cases')
