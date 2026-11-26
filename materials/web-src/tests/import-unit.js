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
const site={format:'nativerouting-hy2-wg-site',version:1,
 transport:{server:'203.0.113.42',server_port:443,password:'f1'.repeat(32),certificate_public_key_sha256:K,target_port:51822},
 wireguard:{private_key:K,public_key:P,address:'10.77.0.2/24',peer_address:'10.77.0.1/32',mtu:1280,keepalive:25},
 site:{local:['192.168.2.0/24'],remote:['192.168.1.0/24']}};
check('retired wrapped site profile cannot preview or import',()=>{
 assert.throws(()=>api.parse(JSON.stringify(site)),/已停用/);
});
function router(purpose){
 const {site:lan,...bundle}=site;
 return {...bundle,version:2,purpose,wireguard:{...site.wireguard,address:'10.77.0.2/32',keepalive:purpose==='lend'?25:0}};
}
for(const purpose of ['access','lend','both'])check('router '+purpose+' direction with no LAN or secrets',()=>{
 assert.throws(()=>api.parse(JSON.stringify(router(purpose))),/已停用/);
});
for(const purpose of ['access','lend','both'])check('native WG '+purpose+' with preserved MTU and endpoint',()=>{
 const b=router(purpose);b.format='nativerouting-wg-device';b.transport={server:'edge.example.test',server_port:51820};b.wireguard.mtu=1450;
 assert.deepEqual(api.parse(JSON.stringify(b)).preview,{purpose,transport:'native',server:'edge.example.test',port:51820});
 for(const invalid of [{...b,version:1},{...b,site:site.site},{...b,transport:site.transport},
     {...b,transport:{...b.transport,server:'bad/endpoint'}},{...b,wireguard:{...b.wireguard,mtu:99999}}])
   assert.throws(()=>api.parse(JSON.stringify(invalid)));
});
check('pure HY2 access imports and reverse-purpose or extra reverse material cannot be imported',()=>{
 const transport={server:'203.0.113.7',server_port:51824,certificate_public_key_sha256:K,password:'ab'.repeat(32)};
 const b={format:'nativerouting-pure-hy2-device',version:1,purpose:'access',transport};
 assert.deepEqual(api.parse(JSON.stringify(b)).preview,{transport:'pure_hy2',purpose:'access',server:transport.server,port:51824});
 for(const purpose of ['lend','both'])assert.throws(()=>api.parse(JSON.stringify({...b,purpose})),/仅支持/);
 for(const bad of [{...b,reverse:{}},{...b,wireguard:{}},{...b,purpose:'site'},{...b,transport:{...transport,password:''}},
     {...b,transport:{...transport,certificate_public_key_sha256:''}}])assert.throws(()=>api.parse(JSON.stringify(bad)));
});
for(const [name,b] of Object.entries({unexpectedLAN:{...router('access'),site:site.site},siteV2:router('site'),
 missingPurpose:router(undefined),noKeepalive:{...router('lend'),wireguard:router('access').wireguard},
 subnetAddress:{...router('both'),wireguard:site.wireguard},purposeInV1:{...site,purpose:'site'}}))
 check('invalid router '+name,()=>assert.throws(()=>api.parse(JSON.stringify(b))));
for(const [label,change] of Object.entries({
 mobile:x=>({outbounds:[]}),format:x=>({...x,version:2}),pin:x=>({...x,transport:{...x.transport,certificate_public_key_sha256:''}}),
 arrayKey:x=>({...x,wireguard:{...x.wireguard,public_key:[P]}}),overlap:x=>({...x,site:{...x.site,remote:x.site.local}}),
 defaultRoute:x=>({...x,site:{...x.site,remote:['0.0.0.0/0']}})
}))check('reject '+label+' site configuration',()=>assert.throws(()=>api.parse(JSON.stringify(change(site)))));
check('orphan relay opens read-only without a secret or an HTTP request',()=>{
 const view={};api.managed(view,{id:4,interface:'wg1',native_role:'site_client',site_client:0},false,
   ()=>assert.fail('An orphan cannot request a managed profile'));
 assert.deepEqual(view.wgManagedSite,{name:'wg1',orphan:true});
});
function env(text=full,mode={}) {
 let rows=[{name:'wg1',local_address:'10.1.0.1/24',local_listenport:50001,local_publickey:P}], calls=[],success=[],reload=0;
 const v={wgImportText:text,wgImportFromPeer:true,wgImportBusy:false,wgImportPending:null,tableForm:{interface:'wg1'},$refs:{dtable:{reload:()=>reload++}},$set:(o,k,x)=>{o[k]=x;}};
 const post=async body=>{calls.push(body);const {action,param}=body; if(action==='iface_add'){ if(mode.reject)return {data:{Result:10001}};rows.push({...param});if(mode.lostResponse&&!mode.lostOnce){mode.lostOnce=true;throw new Error(K);}if(mode.applyError)throw {Result:30002,ErrMsg:K};return {data:{Result:30000,Data:{}}};}if(mode.unreadable && calls.some(q=>q.action==='iface_add') && param.TYPE!=='gen_publickey')throw Error(K);if(param.TYPE==='gen_publickey')return {data:{Result:30000,Data:{pubkey:K}}};return {data:{Result:30000,Data:{iface_data:rows.map(x=>({...x})),wg_iface:rows.map(x=>x.name),iface_defaults:{local_listenport:50001,name:mode.nextName}}}};};
 return {v,calls,success,get rows(){return rows;},get reload(){return reload;},run:()=>api.submit(v,post,x=>x,m=>success.push(m))};
}
(async()=>{
 let e=env();assert(await e.run());assert.equal(e.v.tableForm.interface,'wg2');assert.equal(e.rows[1].local_listenport,50002);assert.equal(e.rows[0].local_publickey,P);assert(e.reload);assert.equal(e.v.wgImportText,'');assert(e.v.tableRowEditing1);results.push({name:'new interface + preserve old + refresh + clear secret',pass:true});
 e=env();e.v.tableForm={id:44,interface:'wg1',peer_privatekey:P,presharedkey:P,comment:'original'};e.v.shouHint=true;
 const opened=e.v.tableForm;assert(await e.run());assert.equal(opened.interface,'wg1');assert.equal(opened.peer_privatekey,P);
 assert.equal(e.v.tableForm.id,undefined);assert.equal(e.v.shouHint,false);assert.equal(e.v.tableForm.peer_privatekey,'');
 results.push({name:'full paste from an existing peer editor starts a new peer instead of moving or overwriting the old peer',pass:true});
 e=env();await Promise.all([e.run(),e.run()]);assert.equal(e.calls.filter(x=>x.action==='iface_add').length,1);results.push({name:'double submit only one create',pass:true});
 e=env(full,{reject:true});assert.equal(await e.run(),false);assert.equal(e.success.length,0);assert.equal(e.rows.length,1);results.push({name:'API failure never claims success',pass:true});
 for(const mode of [{lostResponse:true},{applyError:true}]){
  e=env(full,mode);assert(await e.run());assert.equal(e.rows.length,2);assert.equal(e.success.length,0);
  assert.equal(e.v.tableForm.interface,'wg2');assert.match(e.v.wgIfaceNotice,/已保存.*运行状态/);
  assert(!e.v.wgIfaceNotice.includes(K));assert.equal(e.v.wgImportText,'');assert.equal(e.calls.filter(q=>q.action==='iface_add').length,1);
 }
 results.push({name:'error after persisted interface reads back exact settings with a runtime warning and no second write',pass:true});
 global.window={};
 require('node:vm').runInNewContext(fs.readFileSync(require.resolve('../src/wg-i18n.js'),'utf8'),{window:global.window});
 for(const rolledBack of [true,false]){
  const reply={Result:30002,ErrMsg:rolledBack?'已撤销本次新增；wg2 运行配置应用失败（创建运行目录）':
    '新接口已保存，联动策略未完全应用，请刷新后检查现有接口'};
  e=env();let writes=0;
  const post=async q=>{
   if(q.action==='iface_add'){writes++;throw reply;}
   if(writes)throw Error(K);
   if(q.param.TYPE==='gen_publickey')return {data:{Result:30000,Data:{pubkey:K}}};
   return {data:{Result:30000,Data:{iface_data:e.rows,wg_iface:['wg1'],iface_defaults:{name:'wg2',local_listenport:50002}}}};
  };
  assert.equal(await api.submit(e.v,post,x=>x,()=>assert.fail()),false);assert.equal(writes,1);
  assert.equal(e.v.wgImportPending===null,rolledBack);
  assert.match(e.v.wgImportError,rolledBack?/已撤销本次新增.*创建运行目录/:/已保存.*联动策略未完全应用/);
  assert(!e.v.wgImportError.includes(K));
 }
 delete global.window;
 results.push({name:'authoritative rollback or saved policy receipts survive failed paste readback without another write',pass:true});
 for(const changed of ['MTU=1300','ListenPort=52100']){
  const mode={lostResponse:true,unreadable:true};
  e=env(full,mode);assert.equal(await e.run(),false);assert(!e.v.wgImportError.includes(K));assert(!JSON.stringify(e.v.wgImportPending).includes('local_privatekey'));
  mode.unreadable=false;
  e.v.wgImportText=full.replace('[Peer]',changed+'\n[Peer]');assert.equal(await e.run(),false);
  assert.equal(e.calls.filter(x=>x.action==='iface_add').length,1);assert.equal(e.success.length,0);
  assert(e.v.wgImportError.includes('MTU'));assert.equal(e.v.tableRowEditing1,undefined);
 }
 const hidden={lostResponse:true,unreadable:true};e=env(full,hidden);await e.run();hidden.unreadable=false;
 const savedRow=e.rows.pop();assert.equal(await e.run(),false);assert.equal(e.calls.filter(q=>q.action==='iface_add').length,1);
 e.rows.push({...savedRow,mtu:1250});assert.equal(await e.run(),false);
 e.rows[1]=savedRow;assert(await e.run());assert.match(e.v.wgIfaceNotice,/已保存.*运行状态/);
 results.push({name:'missing readback waits for the matching full row across additional manual attempts and never resends',pass:true});
 e=env(full,{nextName:'wg8'});assert(await e.run());assert.equal(e.v.tableForm.interface,'wg8');
 assert.equal(e.calls.find(x=>x.action==='iface_add').param.wg_import_auto_name,'yes');
 e=env(full,{nextName:'wg1'});assert.equal(await e.run(),false);assert(!e.calls.some(x=>x.action==='iface_add'));
 results.push({name:'native paste uses server allocation including reserved interfaces and flags the locked create',pass:true});
 e=env(full.replace('Address = 10.77.0.2/32\n',''));assert.equal(await e.run(),false);assert.equal(e.calls.length,0);assert.equal(e.success.length,0);results.push({name:'invalid config no API mutation',pass:true});
 e=env(full.slice(full.indexOf('[Peer]')));assert(await e.run());assert(!e.calls.some(x=>x.action==='iface_add'));assert(e.success[0].includes('填入'));results.push({name:'peer only uses existing interface explicitly',pass:true});
 e=env(full.slice(full.indexOf('[Peer]')));e.v.wgImportFromPeer=false;assert.equal(await e.run(),false);results.push({name:'peer only from list rejected',pass:true});
 e=env(full.replace('[Peer]','ListenPort=50001\n[Peer]'));assert.equal(await e.run(),false);assert(!e.calls.some(x=>x.action==='iface_add'));results.push({name:'explicit occupied listen port rejected',pass:true});
 const profile={format:'nativerouting-pure-hy2-device',version:1,purpose:'access',
  transport:{server:'203.0.113.42',server_port:51820,password:'f1'.repeat(32),certificate_public_key_sha256:K}};
 e=env(JSON.stringify(site));assert.equal(await e.run(),false);assert.equal(e.calls.length,0);assert(!e.v.wgSitePreview);assert.match(e.v.wgImportError,/已停用/);
 for(const transport of ['hysteria2',undefined]){
  const view={};
  api.managed(view,{interface:'wg1',id:4},false,async()=>({data:{Data:{site_client_status:{members:[{interface:'wg1',id:4,transport,enabled:true,running:true}]}}}}));
  await Promise.resolve();assert.deepEqual(view.wgManagedSite,{name:'wg1',transport:'hysteria2',retired:true});
 }
 e=env(JSON.stringify(profile));assert.equal(await e.run(),false);assert.equal(e.calls.length,0);
 assert.equal(e.v.wgSitePreview.transport,'pure_hy2');assert(await e.run());
 assert.equal(e.calls.length,1);assert.equal(e.calls[0].action,'site_client_import');assert.deepEqual(JSON.parse(Buffer.from(e.calls[0].param.config_hex,'hex').toString('utf8')),profile);
 assert.equal(e.v.wgImportText,'');assert.equal(e.v.wgSitePreview,null);assert.equal(e.v.wgListRevision,1);
 results.push({name:'site import previews before post and clears private material after success',pass:true});
 e=env(JSON.stringify(profile));await e.run();
 assert.equal(await api.submit(e.v,()=>Promise.reject(new Error(profile.transport.password)),x=>x,()=>{}),false);
 assert(!e.v.wgImportError.includes(profile.transport.password));assert(e.v.wgSitePreview);assert(await e.run());
 results.push({name:'a failed site import exposes no request secrets and permits retry',pass:true});
 global.window={WGI18n:{knownText:x=>x==='test router error'?'translated router error':'',text:x=>x}};
 for(const expected of ['test router error',profile.transport.password]){
  e=env(JSON.stringify(profile));await e.run();
  assert.equal(await api.submit(e.v,()=>Promise.reject({Result:30002,ErrMsg:expected}),x=>x,()=>{}),false);
  if(expected==='test router error')assert.equal(e.v.wgImportError,'translated router error');
  else assert(!e.v.wgImportError.includes(profile.transport.password));
 }
 global.window.WGI18n.knownText=x=>x==='组网配置已保存，请返回列表检查隧道状态后重新启用'?'Saved; check the tunnel':'';
 global.window.WGI18n.text=x=>global.window.WGI18n.knownText(x)||x;
 e=env(JSON.stringify(profile));await e.run();let posted=0;
 assert(await api.submit(e.v,async q=>{if(q.action==='site_client_import'){posted++;throw {Result:30002,ErrMsg:'组网配置已保存，请返回列表检查隧道状态后重新启用'};}return {data:{Result:30000,Data:{}}};},x=>x,()=>assert.fail('must not report a fully active tunnel')));
 assert(e.v.wgImportSavedWarning);assert(!e.v.wgImportOpen);assert.equal(e.v.wgImportText,'');assert.equal(e.v.wgSitePreview,null);
 assert.equal(await e.run(),false);assert.equal(posted,1);
 results.push({name:'committed but inactive closes import, clears its keys, refreshes the list and preserves recovery guidance',pass:true});
 delete global.window;
 results.push({name:'native Axios logical error body is localized and unknown server strings stay private',pass:true});
 e=env(JSON.stringify(profile));await e.run();let writes=0,reads=0,rendered;
 const pg={currentPage:2,rowsPerPage:10},options={param:{TYPE:'total,data',KEYWORDS:'router'}};
 const grid={opt:{requests:options},paginationOptions:pg,orderBy:'id',sortOrder:'desc',
  $refs:{dpagination:{changeJumpPageNum:x=>assert.equal(x,2),changeCurrent:(i,n)=>{assert.equal(i,10);assert.equal(n,1);}}},
  customLoadData:r=>{rendered=r;},$emit:()=>{}};
 e.v.$refs.dtable1=grid;e.v.$nextTick=fn=>fn();
 const confirmed=await api.submit(e.v,async ({action,param})=>{
  if(action==='site_client_import'){writes++;return {data:{Result:30000}};}
  assert.deepEqual(param,{TYPE:'total,data',KEYWORDS:'router',ORDER_BY:'id',ORDER:'desc',limit:'10,10'});
  if(++reads===1)throw Error('socket not connected');
  return {headers:{'x-timestamp':'42'},data:{Result:30000,Data:{data:[{id:1,interface:'wg1'}],total:11}}};
 },x=>x,()=>{});
 assert(confirmed && writes===1 && reads===2);assert.equal(pg.totalPages,2);assert.equal(grid.xTimestamp,42);
 assert.deepEqual(rendered,[{id:1,interface:'wg1'}]);assert.equal(options.disableLoad,undefined);
 results.push({name:'committed import retries only its failed table read and preserves native filters, sort, pages and timestamp',pass:true});
 fs.writeFileSync(require('node:path').join(require('node:os').tmpdir(), 'import-unit.json'),JSON.stringify({passed:results.length,cases:results},null,2)+'\n');console.log('PASS',results.length,'parser/import regression cases');
})().catch(e=>{console.error(e.message);process.exitCode=1;});
