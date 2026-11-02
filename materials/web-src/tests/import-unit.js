'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs');
const api=require('../src/wg-paste-import.js');
const K=Buffer.alloc(32,7).toString('base64'),P=Buffer.alloc(32,9).toString('base64');
const full=`[Interface]\nPrivateKey = ${K}\nAddress = 10.77.0.2/32\n\n[Peer]\nPublicKey = ${P}\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.test:51820\n`;
const results=[];
function check(name,fn) {fn();results.push({name,pass:true});}
for(const sep of ['\n','\r\n','\r'])check('line ending '+JSON.stringify(sep),()=>assert.equal(api.parse(full.replace(/\n/g,sep)).local.local_address,'10.77.0.2/32'));
check('BOM and inline comments',()=>assert.equal(api.parse('\uFEFF'+full.replace('[Interface]','[ Interface ] # local').replace('10.77.0.2/32','10.77.0.2/32 # addr')).full,true));
check('PSK MTU explicit port keepalive zero',()=>{const p=api.parse(full.replace('[Peer]',`MTU=1280\nListenPort=52000\n[Peer]\nPresharedKey=${K}\nPersistentKeepalive=0`));assert.equal(p.local.mtu,1280);assert.equal(p.peer.keepalive,0);assert.equal(p.peer.presharedkey,K);});
for(const [name,bad]of Object.entries({missingAddress:full.replace('Address = 10.77.0.2/32\n',''),missingPrivate:full.replace(`PrivateKey = ${K}\n`,''),missingPublic:full.replace(`PublicKey = ${P}\n`,''),missingAllowed:full.replace('AllowedIPs = 0.0.0.0/0\n',''),flattened:full.replace(/\n/g,''),multiPeer:full+'[Peer]\nPublicKey='+P,multiInterface:full+'[Interface]\n',badAddress:full.replace('10.77.0.2','999.77.0.2'),badPort:full.replace('51820','65536'),duplicateKey:full.replace('[Peer]','PrivateKey='+K+'\n[Peer]'),pureIPv6:full.replace('10.77.0.2/32','fd00::2/128'),badKey:full.replace(K,'broken'),oversize:'a'.repeat(65537)}))check(name+' rejected',()=>assert.throws(()=>api.parse(bad)));
check('dual-stack with explicit note',()=>{const p=api.parse(full.replace('10.77.0.2/32','10.77.0.2/32,fd00::2/128').replace('0.0.0.0/0','0.0.0.0/0,::/0'));assert.equal(p.peer.allowips,'0.0.0.0/0');assert.equal(p.notes.length,2);});
check('hooks never executed',()=>assert.equal(api.parse(full.replace('[Peer]','PostUp=do-not-execute\n[Peer]')).notes.length,1));
function env(text=full,mode={}) {
 let rows=[{name:'wg1',local_address:'10.1.0.1/24',local_listenport:50001,local_publickey:P}], calls=[],success=[],reload=0;
 const v={wgImportText:text,wgImportFromPeer:true,wgImportBusy:false,wgImportPending:null,tableForm:{interface:'wg1'},$refs:{dtable:{reload:()=>reload++}},$set:(o,k,x)=>{o[k]=x;}};
 const post=async body=>{calls.push(body);const {action,param}=body; if(action==='iface_add'){ if(mode.reject)return {data:{Result:10001}};rows.push({...param});if(mode.lostResponse&&!mode.lostOnce){mode.lostOnce=true;throw new Error('simulated transport loss');}return {data:{Result:30000,Data:{}}};}if(param.TYPE==='gen_publickey')return {data:{Result:30000,Data:{pubkey:K}}};return {data:{Result:30000,Data:{iface_data:rows.map(x=>({...x})),wg_iface:rows.map(x=>x.name),iface_defaults:{local_listenport:50001}}}};};
 return {v,calls,success,get rows(){return rows;},get reload(){return reload;},run:()=>api.submit(v,post,x=>x,m=>success.push(m))};
}
(async()=>{
 let e=env();assert(await e.run());assert.equal(e.v.tableForm.interface,'wg2');assert.equal(e.rows[1].local_listenport,50002);assert.equal(e.rows[0].local_publickey,P);assert(e.reload);assert.equal(e.v.wgImportText,'');assert(e.v.tableRowEditing1);results.push({name:'new interface + preserve old + refresh + clear secret',pass:true});
 e=env();await Promise.all([e.run(),e.run()]);assert.equal(e.calls.filter(x=>x.action==='iface_add').length,1);results.push({name:'double submit only one create',pass:true});
 e=env(full,{reject:true});assert.equal(await e.run(),false);assert.equal(e.success.length,0);assert.equal(e.rows.length,1);results.push({name:'API failure never claims success',pass:true});
 e=env(full,{lostResponse:true});assert.equal(await e.run(),false);assert.equal(e.rows.length,2);assert(await e.run());assert.equal(e.rows.length,2);assert.equal(e.calls.filter(x=>x.action==='iface_add').length,1);results.push({name:'lost response retry reads back without duplicate',pass:true});
 e=env(full.replace('Address = 10.77.0.2/32\n',''));assert.equal(await e.run(),false);assert.equal(e.calls.length,0);assert.equal(e.success.length,0);results.push({name:'invalid config no API mutation',pass:true});
 e=env(full.slice(full.indexOf('[Peer]')));assert(await e.run());assert(!e.calls.some(x=>x.action==='iface_add'));assert(e.success[0].includes('填入'));results.push({name:'peer only uses existing interface explicitly',pass:true});
 e=env(full.slice(full.indexOf('[Peer]')));e.v.wgImportFromPeer=false;assert.equal(await e.run(),false);results.push({name:'peer only from list rejected',pass:true});
 e=env(full.replace('[Peer]','ListenPort=50001\n[Peer]'));assert.equal(await e.run(),false);assert(!e.calls.some(x=>x.action==='iface_add'));results.push({name:'explicit occupied listen port rejected',pass:true});
 fs.writeFileSync(require('node:path').join(require('node:os').tmpdir(), 'import-unit.json'),JSON.stringify({passed:results.length,cases:results},null,2)+'\n');console.log('PASS',results.length,'parser/import regression cases');
})().catch(e=>{console.error(e.message);process.exitCode=1;});
