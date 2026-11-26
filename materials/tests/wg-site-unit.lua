local m=dofile(arg[1]);local n=0
local function check(v,msg)assert(v,msg);n=n+1 end
local s={interfaces={{id=1,name='wg2',local_address='10.100.2.1/24'}},peers={},networks={{name='lan1',address='192.168.10.1/24'},{name='wan1',address='10.46.0.15/24'}}}
local function ok(l,r,a)return m.check_peer(s,'wg2',a or '10.100.2.2/32','','K','yes','',l,r)end
check(ok('192.168.10.0/24','192.168.20.0/24'))
check(ok('',''))
for _,pair in ipairs{{'192.168.10.0/24',''},{'','192.168.20.0/24'},{'192.168.10.0/24','192.168.10.0/24'},{'192.168.11.0/24','192.168.20.0/24'},{'10.46.0.0/24','192.168.20.0/24'},{'192.168.10.0/24','10.100.2.0/24'},{'192.168.10.0/24','10.46.0.0/24'},{'192.168.10.0/24','0.0.0.0/0'},{'192.168.10.0/24','192.168.20.0/24; touch /tmp/oops'},{'192.168.10.0/24','192.168.20.0/24,192.168.20.1/32'},{'192.168.10.0/24','8.8.8.8/32'},{'192.168.10.0/24','::/0'}}do check(not ok(pair[1],pair[2]),table.concat(pair,' -> '))end
check(not ok('192.168.10.0/24','192.168.20.0/24','10.100.2.2/24'))
s.peers={{id=4,interface='wg3',allowips='10.100.3.2/32',site_remote='192.168.20.0/24'}}
check(not ok('192.168.10.0/24','192.168.20.0/24'))
check(not m.check_peer(s,'wg2','192.168.20.20/32','','K','no',''))
s.peers={{id=2,interface='wg2',allowips='10.100.2.2/32',peer_publickey='K',site_remote='192.168.20.0/24',site_local='192.168.10.0/24',exit_peer='yes'}}
check(not m.check_peer(s,'wg2','10.100.2.2/32','2','K','yes','','192.168.10.0/24','192.168.10.0/24'),'old row must not bypass new scope checks')
check(m.check_peer(s,'wg2','10.100.2.2/32','2','K','yes','','192.168.10.0/24','192.168.20.0/24'))
local b={interfaces={{name='wg1',local_address='10.100.2.2/32'}},peers={},networks={{name='lan1',address='192.168.20.1/24'}}}
check(m.check_peer(b,'wg1','10.100.2.1/32,192.168.10.0/24','','K','no','','192.168.20.0/24','192.168.10.0/24'))
check(not m.check_peer(b,'wg1','10.100.2.1/32,0.0.0.0/0','','K','no','','192.168.20.0/24','192.168.10.0/24'))
print('PASS '..n..' site scope validation cases')
