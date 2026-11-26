const assert=require('assert'),c=require('../src/wg-client-config.js'),p=require('../src/wg-paste-import.js');let n=0;
function check(f){f();n++;}
const k='A'.repeat(43)+'=',pub='B'.repeat(43)+'=';
const v={tableForm:{peer_privatekey:k,allowips:'10.100.2.2/32',exit_peer:'yes',site_local:'192.168.10.1/24',site_remote:'192.168.20.0/24',client_endpoint:'203.0.113.10',keepalive:0},getIfaceRow:()=>({local_publickey:pub,local_address:'10.100.2.1/24',local_listenport:50002}),wanEndpoint:{},makeQrSvg:()=>''};
check(()=>assert(c.build(v,true,()=>{throw Error('unexpected prompt')},e=>{throw Error(e)})));
let out=p.parse(v.tableForm.client_config);
check(()=>assert.equal(out.peer.allowips,'10.100.2.1/32\n192.168.10.0/24'));
check(()=>assert.equal(out.peer.site_local,'192.168.20.0/24'));
check(()=>assert.equal(out.peer.site_remote,'192.168.10.0/24'));
check(()=>assert.equal(out.peer.keepalive,25));
check(()=>assert(!v.tableForm.client_config.includes('0.0.0.0/0')));
check(()=>assert.throws(()=>p.parse(v.tableForm.client_config+'\n# iKuai-Site-Local = 192.168.30.0/24')));
for(let [l,r]of [['192.168.10.0/24',''],['','192.168.20.0/24'],['192.168.10.0/24','192.168.10.20/32'],['192.168.10.0/24','8.8.8.8/32'],['192.168.10.0/24','0.0.0.0/0'],['192.168.10.0/24','192.168.20.0/24;echo x'],['192.168.10.0/24','192.168.20.0/24,192.168.20.1/32']])check(()=>assert.throws(()=>c.siteFields(l,r)));
check(()=>assert.deepEqual(c.siteFields('',''),{local:[],remote:[]}));
console.log('PASS '+n+' site export/import cases');
