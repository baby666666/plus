'use strict';
const assert=require('node:assert/strict'),zlib=require('node:zlib'),fs=require('node:fs');
const sb=require('../src/wg-singbox.js'),client=require('../src/wg-client-config.js');
const tests=[];function test(name,fn){tests.push({name,fn});}
const K=Buffer.alloc(32,1).toString('base64'),P=Buffer.alloc(32,2).toString('base64');
const clone=x=>JSON.parse(JSON.stringify(x));
function response(saved){return{data:{Result:30000,Data:{client_export:clone(saved)}}};}
function deferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return{promise,resolve,reject};}
function view(extra={}){
 const v={tableRowEditing1:true,tableForm:{id:7,enabled:'yes',interface:'wg2',exit_peer:'yes',allowips:'10.200.2.2/32',client_endpoint:'192.0.2.1',keepalive:0,peer_privatekey:K,peer_publickey:P,presharedkey:'',client_dns:'',site_local:'',site_remote:'',endpoint:'',endpoint_port:'',...extra},iface:{id:2,name:'wg2',enabled:'yes',interface:'auto',local_publickey:P,local_address:'10.200.2.1/24',local_listenport:51820},getIfaceRow(){return this.iface;},$set(o,k,v){o[k]=v;},makeQrSvg:()=>'<svg/>',tableOptions:{requests:{url:'/api'}},errors:[]};
 save(v);v.$http={post:async(url,q)=>{assert.equal(url,'/api');assert.deepEqual(q,{func_name:'wireguard',action:'show',param:{TYPE:'client_export',peer_id:String(v.tableForm.id)}});return response(v.saved);}};return v;
}
function save(v){v.saved={peer:clone(v.tableForm),iface:clone(v.iface),keypair_valid:true};}
function attempt(v,post){return sb.build(v,client,e=>v.errors.push(e),post);}
async function build(v){assert.equal(await attempt(v),true,v.errors.join(';'));return JSON.parse(v.wgSingbox.json);}
test('enabled saved snapshot exports reverse endpoint with direct final',async()=>{const c=await build(view());assert.equal(c.endpoints[0].system,false);assert.deepEqual(c.endpoints[0].peers[0].allowed_ips,['0.0.0.0/0']);assert.equal(c.route.final,'phone-internet');assert.deepEqual(c.outbounds,[{type:'direct',tag:'phone-internet'}]);assert.equal(c.endpoints[0].peers[0].persistent_keepalive_interval,25);assert(!c.outbounds.some(x=>x.type==='wireguard'));assert.equal(c.inbounds[0].stack,'gvisor');assert.equal(c.route.rules[0].inbound[0],'phone-tun');assert.equal(sb.matches(view()),false);});
test('peer /32, keys, saved current port and PSK exported',async()=>{const v=view({presharedkey:P,keepalive:40,allowips:'10.200.2.2'});v.iface.local_listenport=62000;save(v);const c=await build(v),e=c.endpoints[0];assert.deepEqual(e.address,['10.200.2.2/32']);assert.equal(e.private_key,K);assert.equal(e.peers[0].public_key,P);assert.equal(e.peers[0].pre_shared_key,P);assert.equal(e.peers[0].port,62000);assert.equal(e.peers[0].persistent_keepalive_interval,40);});
test('native explicit roles isolate local and router-initiated traffic',async()=>{
 for(const role of ['lend','both','access']){
  const v=view({native_role:role,exit_peer:role==='access'?'no':'yes',keepalive:25,client_dns:'10.100.2.1'});
  const c=await build(v),r=c.route.rules.find(r=>r.inbound==='router-wg');
  assert.equal(c.endpoints[0].peers[0].port,51820);
  assert.equal(c.route.final,role==='lend'?'phone-internet':'router-wg');
  assert.equal(r.action,role==='access'?'reject':'route');
  if(role==='lend')assert.equal(c.inbounds,undefined);
  else {assert(c.inbounds[0].route_exclude_address.includes(v.tableForm.client_endpoint+'/32'));assert.equal(c.dns.servers[0].detour,'router-wg');}
 }
});
test('dual DNS uses the first IPv4 for access and both and names invalid DNS',()=>{
 for(const role of ['access','both']){
  const v=view({native_role:role,exit_peer:role==='both'?'yes':'no',client_dns:'223.5.5.5,8.8.8.8'});
  assert.equal(sb.config(v,client).dns.servers[0].server,'223.5.5.5');
  v.tableForm.client_dns='bad,8.8.8.8';assert.throws(()=>sb.config(v,client),/DNS/);
 }
});
test('local tun address avoids WG endpoint collision',async()=>assert.notEqual((await build(view({allowips:'172.19.0.2/32'}))).inbounds[0].address[0],'172.19.0.1/30'));
for(const patch of [{exit_peer:'no'},{allowips:'10.200.2.0/24'},{allowips:'0.0.0.0/32'},{allowips:'127.0.0.1/32'},{peer_privatekey:''},{peer_privatekey:'wrong'},{presharedkey:'wrong'},{client_endpoint:'bad\nvalue'},{keepalive:-1},{site_local:'192.168.1.0/24',site_remote:'192.168.2.0/24'}])test('invalid draft rejected '+Object.keys(patch),async()=>{const v=view(patch);assert.equal(await attempt(v),false);assert(v.errors.length);assert.equal(v.wgSingbox,null);assert.equal(v.wgSingboxBusy,false);});
for(const field of ['id','enabled','interface','exit_peer','allowips','peer_privatekey','peer_publickey','presharedkey','client_endpoint','client_dns','keepalive','site_local','site_remote','endpoint','endpoint_port'])test('stale export hidden after '+field,async()=>{const v=view();await build(v);v.tableForm[field]='changed';assert.equal(sb.matches(v),false);});
for(const field of ['name','enabled','interface','local_publickey','local_address','local_listenport'])test('stale export hidden after service '+field,async()=>{const v=view();await build(v);v.iface[field]='changed';assert.equal(sb.matches(v),false);});
test('new unsaved form refuses without sending RPC',async()=>{for(const id of [undefined,0,'','1;echo secret',-1]){const v=view({id});let requests=0;assert.equal(await attempt(v,()=>{requests++;}),false);assert.equal(requests,0);assert.match(v.errors[0],/先保存/);}});
for(const field of ['peer_privatekey','peer_publickey','presharedkey','client_endpoint','client_dns','keepalive','endpoint','endpoint_port'])test('unsaved '+field+' refuses snapshot export',async()=>{const v=view();v.saved.peer[field]=field==='keepalive'?30:'changed';assert.equal(await attempt(v),false);assert.match(v.errors[0],/未保存/);assert.equal(v.wgSingbox,null);});
test('changed saved parent port refuses stale cached interface',async()=>{const v=view();v.saved.iface.local_listenport=62000;assert.equal(await attempt(v),false);assert.match(v.errors[0],/服务接口设置已变化/);});
test('backend keypair rejection cannot export plausible formatted keys',async()=>{const v=view();v.saved.keypair_valid=false;assert.equal(await attempt(v),false);assert.match(v.errors[0],/私钥.*公钥不匹配/);});
test('disabled peer or parent cannot export even with valid keys',async()=>{for(const where of ['peer','iface']){const v=view();v.saved[where].enabled='no';assert.equal(await attempt(v),false);assert.match(v.errors[0],/启用/);}});
test('numeric fields normalize API string types',async()=>{const v=view();v.saved.peer.id='7';v.saved.peer.keepalive='0';v.saved.iface.local_listenport='51820';await build(v);});
test('hidden unrelated parent and peer fields are not required',async()=>{const v=view();v.saved.peer.comment='saved comment';v.saved.iface.mtu=1420;v.saved.iface.keepalive='';await build(v);});
test('pending discovery or generation cannot export old data',async()=>{for(const flag of ['wgEndpointBusy','wgPlanBusy']){const v=view();await build(v);v[flag]=true;assert.equal(sb.matches(v),false);assert.equal(await attempt(v),false);}const v=view();v.wgKeyRequests={peer:{form:v.tableForm}};assert.equal(await attempt(v),false);assert.match(v.errors[0],/生成密钥/);});
test('manual endpoint edit and form close discard generated secrets',async()=>{const v=view();await build(v);client.manual(v,'192.0.2.2');assert.equal(v.wgSingbox,null);save(v);await build(v);client.cancel(v);assert.equal(v.wgSingbox,null);});
test('form replacement, close and cancel ignore pending response',async()=>{for(const change of [v=>v.tableForm={...v.tableForm},v=>v.tableRowEditing1=false,v=>client.cancel(v)]){const v=view(),d=deferred(),p=attempt(v,()=>d.promise);await Promise.resolve();change(v);d.resolve(response(v.saved));assert.equal(await p,false);assert.equal(v.wgSingbox,null);assert.equal(v.errors.length,0);assert.equal(v.wgSingboxBusy,false);}});
test('field change while lookup pending cannot publish snapshot',async()=>{const v=view(),d=deferred(),p=attempt(v,()=>d.promise);await Promise.resolve();v.tableForm.client_endpoint='192.0.2.2';d.resolve(response(v.saved));assert.equal(await p,false);assert.equal(v.wgSingbox,null);assert.match(v.errors[0],/参数已变化/);});
test('older response never replaces newer generation',async()=>{const v=view(),old=deferred(),fresh=deferred(),p=attempt(v,()=>old.promise);await Promise.resolve();const q=attempt(v,()=>fresh.promise);await Promise.resolve();fresh.resolve(response(v.saved));assert.equal(await q,true);const result=v.wgSingbox;old.resolve(response({...v.saved,keypair_valid:false}));assert.equal(await p,false);assert.equal(v.wgSingbox,result);assert.equal(v.errors.length,0);});
test('older failure cannot clear newer busy state or expose transport errors',async()=>{const v=view(),old=deferred(),fresh=deferred(),p=attempt(v,()=>old.promise);await Promise.resolve();const q=attempt(v,()=>fresh.promise);await Promise.resolve();old.reject(Error('private-sentinel'));assert.equal(await p,false);assert.equal(v.wgSingboxBusy,true);assert.deepEqual(v.errors,[]);fresh.resolve(response(v.saved));assert.equal(await q,true);});
test('native and transport failure messages remain generic',async()=>{for(const post of [async()=>{throw Error('private-sentinel');},()=>{throw Error('private-sentinel');},async()=>({data:{Result:30006,ErrMsg:'private-sentinel'}}),async()=>({data:{Result:30000,Data:{}}})]){const v=view();assert.equal(await attempt(v,post),false);assert(!v.errors.join('').includes('private-sentinel'));assert.equal(v.wgSingboxBusy,false);assert.equal(v.wgSingbox,null);}});
function decodeFile(data, filename, name){
 const metaLen=data.readUInt32BE(0),meta=JSON.parse(data.subarray(4,4+metaLen)),size=data.readUInt32BE(4+metaLen),profile=data.subarray(8+metaLen);assert.equal(profile.length,size);assert.equal(meta.filename,filename);assert.equal(profile[0],3);assert.equal(profile[1],1);
 const raw=zlib.gunzipSync(profile.subarray(2));let pos=0;
 function string(){let n=0,shift=0,b;do{b=raw[pos++];n+=(b&127)*2**shift;shift+=7;}while(b&128);const s=raw.subarray(pos,pos+n).toString('utf8');pos+=n;return s;}
 assert.equal(string(),name);assert.equal(raw.readInt32BE(pos),0);pos+=4;const config=JSON.parse(string());assert.equal(pos,raw.length);return config;
}
function decodeFrames(frames,{compressed,name,filename}){
 const packets=frames.map(frame=>Buffer.from(frame,'base64'));
 const first=packets[0],count=first.readUInt32LE(8),length=first.readUInt32LE(12),crc=first.readUInt32LE(16);
 const blocks=new Map();
 for(const packet of packets){
  assert.equal(packet.length,first.length);assert.equal(packet.readUInt32LE(0),1);
  const index=packet.readUInt32LE(4);assert(index<count);
  assert.equal(packet.readUInt32LE(8),count);assert.equal(packet.readUInt32LE(12),length);assert.equal(packet.readUInt32LE(16),crc);
  blocks.set(index,packet.subarray(20));
 }
 assert.equal(blocks.size,count);
 const assembled=Buffer.concat(Array.from({length:count},(_,i)=>blocks.get(i))).subarray(0,length);
 const data=compressed?zlib.inflateSync(assembled):assembled;
 assert.equal(crc,(sb.crc32(data.toString('binary'))^count)>>>0);
 return decodeFile(data,filename,name);
}
test('offline QRS contains a decodable local BPF profile with identical JSON',async()=>{
 const c=await build(view()),qrs=sb.qrs(c);
 assert.deepEqual(decodeFrames([qrs],{compressed:false,name:'iKuai phone exit',filename:'ikuai-phone-exit.bpf'}),c);
 assert(qrs.length<2200);assert(!qrs.startsWith('http'));assert.equal(sb.crc32('123456789'),0xcbf43926);
});
test('named phone packs a complete compressed profile in one QRS frame',async()=>{
 const name='Personal-5G',c=await build(view({presharedkey:P}));
 const frames=await sb.qrsFrames(c,name);
 assert.equal(frames.length,1);assert(frames[0].length<=2200);
 assert.deepEqual(decodeFrames(frames,{compressed:true,name,filename:name+'.bpf'}),c);
});
test('older browsers can scan a large profile over several frames in any order',async()=>{
 const saved=global.CompressionStream;
 try{
  global.CompressionStream=undefined;
  const name='Phone-2',c={comment:'测试 🚲'.repeat(512)};
  const frames=await sb.qrsFrames(c,name);
  assert(frames.length>1);assert(frames.every(f=>f.length<=700));
  const options={compressed:false,name,filename:name+'.bpf'};
  const backwards=frames.slice().reverse();
  assert.deepEqual(decodeFrames([backwards[0],...backwards],options),c);
  assert.throws(()=>decodeFrames(backwards.slice(1),options));
  const small=await sb.qrsFrames({},name);
  assert.equal(small.length,1);assert.deepEqual(decodeFrames(small,options),{});
 }finally{global.CompressionStream=saved;}
});
test('invalid enrollment name cannot be used as the BPF filename',async()=>{
 for(const name of [undefined,'','bad/name','a'.repeat(49)])await assert.rejects(sb.qrsFrames({},name));
});
test('export status and secrets stay outside native form payload',async()=>{const v=view(),before=clone(v.tableForm);await build(v);assert.deepEqual(v.tableForm,before);assert(!Object.keys(v.tableForm).some(k=>/^singbox|^wgSingbox/.test(k)));});
(async()=>{for(const t of tests){try{await t.fn();}catch(e){e.message=t.name+': '+e.message;throw e;}}console.log('SINGBOX_UNIT_PASS',tests.length);if(process.env.SINGBOX_TEST_DIR){const p=process.env.SINGBOX_TEST_DIR,v=view(),c=await build(v);fs.mkdirSync(p,{recursive:true});fs.writeFileSync(p+'/profile.json',JSON.stringify(c,null,2));fs.writeFileSync(p+'/qrs.txt',sb.qrs(c));}})().catch(e=>{console.error(e);process.exitCode=1;});
