'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const Vue=require('./native-vue')(process.argv[2]);
const root=path.resolve(__dirname,'..');
const pending=[],requests=[],timers=new Set(),copied=[];
const browser={window:null,Blob,atob,btoa,
  document:{hidden:false,addEventListener(){},removeEventListener(){}},
  addEventListener(){},removeEventListener(){},
  navigator:{clipboard:{writeText:async value=>copied.push(value)}},
  setTimeout,clearTimeout,setInterval(fn){timers.add(fn);return fn;},clearInterval(fn){timers.delete(fn);},
  prompt(){assert.fail('Unexpected clipboard fallback');}
};
browser.window=browser;
for(const file of ['wg-i18n.js','wg-client-config.js','wg-paste-import.js','wg-native-tunnel.js'])
  vm.runInNewContext(fs.readFileSync(path.join(root,'src',file),'utf8'),browser,{filename:file});
const clone=value=>JSON.parse(JSON.stringify(value));
const key=Buffer.alloc(32,4).toString('base64');
const mapping={id:'1',protocol:'tcp',listen_port:18080,target_ip:'192.168.62.1',target_port:80,sources:['203.0.113.0/24']};
const reverse={enabled:true,mappings:[mapping]};
const original={id:'7',interface:'wg1',allowips:'10.177.1.2/32',peer_publickey:key,peer_privatekey:key,
  native_role:'',exit_peer:'no',site_local:'',site_remote:'',enabled:'yes',keepalive:0,
  client_endpoint:'198.51.100.9',presharedkey:'',client_dns:'',comment:'router-b'};
const member={peer_id:'7',id:'7ec75eba-1252-4510-a603-51b465d28d51',name:'router-b',interface:'wg1',address:original.allowips,
  peer_publickey:key,transport:'pure_hy2',mode:'access',addr_mode:'manual',port_mode:'wg',
  public_ip:'198.51.100.9',public_port:51820,active:true,paused:false,reverse};
const props={apiUrl:'/Action/call',listenPort:51820,serverKey:key,makeQrSvg:()=>'<svg/>'};
const ok=data=>({data:{Result:30000,Data:data}});
const http={post(url,body){
  assert.equal(url,props.apiUrl);requests.push(clone(body));assert(pending.length,'Unexpected request');
  const response=pending.shift();return response instanceof Error?Promise.reject(response):Promise.resolve(response);
}};
function settings(saved=reverse,peer=original,extra={}){
  return ok({hyr_settings:{enabled:true,public_ip:member.public_ip,peer:clone(peer),members:[{...clone(member),reverse:clone(saved)}],...extra}});
}
function nodes(view){const list=[];(function visit(node){list.push(node);(node.children||[]).forEach(visit);})(view._render());return list;}
function text(node){return node.text||(node.children||[]).map(text).join('');}
function button(view,name){const result=nodes(view).filter(n=>n.tag==='button'&&text(n)===name);assert.equal(result.length,1,'Missing or duplicate '+name);return result[0];}
function input(view,name){const result=nodes(view).find(n=>n.data && n.data.attrs && n.data.attrs['aria-label']===name);assert(result,'Missing '+name);return result;}
function set(view,name,value){input(view,name).data.on.input({target:{value}});}
function view(){
  const peerForm=new Vue({data:{form:clone(original)}}).form;
  const instance=new(Vue.extend(browser.WGNativeTunnel))({propsData:{...props,peerForm}});instance.$http=http;return instance;
}
function routerBundle(saved=reverse){return {format:'nativerouting-pure-hy2-device',version:2,purpose:'access',
  transport:{server:member.public_ip,server_port:51820,password:'ab'.repeat(32),certificate_public_key_sha256:key},
  reverse:{version:1,token:'cd'.repeat(32),server:'10.177.1.1',server_port:49871,mappings:clone(saved.mappings)}};}
const flush=()=>new Promise(resolve=>setImmediate(resolve));
let checks=0;
(async()=>{
  const editor=view();pending.push(settings());assert(await editor.loadTunnel());
  assert.equal(editor.reverseDraft.enabled,true);assert.equal(editor.reverseDraft.mappings[0].sources_text,'203.0.113.0/24');
  assert(editor.exportReady && editor.pureRouterReady);assert.equal(editor.reverseRuntime,null);
  assert(text(editor._render()).includes('反向通道 · 无记录'));
  assert(!text(editor._render()).includes('已认证连接'));
  const count=requests.length;await Vue.nextTick();await flush();assert.equal(requests.length,count);assert.equal(timers.size,0);checks++;

  // Local changes must not mutate the saved identity or hide independent phone exports.
  set(editor,'客户端目标 IPv4 1','192.168.62.10');set(editor,'允许访问的来源网段 1','203.0.113.9/24, 203.0.113.0/24');
  assert.equal(editor.member.reverse.mappings[0].target_ip,'192.168.62.1');assert.equal(mapping.target_ip,'192.168.62.1');
  assert.equal(editor.reverseUnchanged,false);assert.equal(editor.pureRouterReady,false);assert.equal(editor.exportReady,true);
  assert.equal(button(editor,'复制到路由器').data.attrs.disabled,true);assert.equal(button(editor,'复制 sing-box 配置').data.attrs.disabled,false);
  const params=editor.parameters();assert.equal(params.hyr_reverse,undefined);assert.match(params.hyr_reverse_hex,/^[0-9a-f]+$/);
  const submitted=JSON.parse(Buffer.from(params.hyr_reverse_hex,'hex').toString('utf8'));
  assert.deepEqual(submitted,{enabled:true,mappings:[{...mapping,target_ip:'192.168.62.10'}]});
  editor.peerForm.comment='updated comment';assert.equal(editor.commentEdit(params),null);checks++;

  // Invalid editor values cannot leave the transaction as a partially valid rule.
  for(const [field,value] of [['服务端映射端口 1','0'],['服务端映射端口 1','00180'],['服务端映射端口 1','65536'],['客户端目标 IPv4 1','224.0.0.1'],['允许访问的来源网段 1','']]){
    const old=input(editor,field).data.domProps.value;set(editor,field,value);assert.throws(()=>editor.parameters());set(editor,field,old);
  }
  assert.equal(editor.addReverseMapping(),true);assert.equal(editor.reverseDraft.mappings[1].id,'2');
  editor.removeReverseMapping('1');assert.equal(editor.reverseDraft.mappings[0].id,'2');
  assert(editor.addReverseMapping());assert.equal(editor.reverseDraft.mappings[1].id,'1');
  while(editor.reverseDraft.mappings.length<32)assert(editor.addReverseMapping());
  assert.equal(editor.addReverseMapping(),false);assert.equal(button(editor,'新增映射').data.attrs.disabled,true);checks++;

  // Reopening reads the saved rules into a fresh draft and clears all old runtime fields.
  pending.push(settings());assert(await editor.loadTunnel());
  assert.deepEqual(clone(editor.member.reverse),reverse);assert.equal(editor.reverseDraft.mappings.length,1);
  assert.equal(editor.reverseDraft.mappings[0].target_ip,mapping.target_ip);assert(editor.pureRouterReady);
  assert(editor.commentEdit(editor.parameters()),'A comment-only change stays comment-only when mappings are unchanged');checks++;

  // A process and a listener are not authenticated connectivity or target success.
  pending.push(ok({hyr_status:{members:[{...clone(member),running:true,reverse_status:{connected:false,state:'waiting',last_heartbeat:0,
    token:'must-never-retain',mappings:[{id:'1',listening:true,active:0,rx_bytes:0,last_success:0}]}}]}}));
  assert(await button(editor,'读取连接状态').data.on.click());
  assert.deepEqual(requests.at(-1).param,{TYPE:'hyr_status',peer_id:member.peer_id,id:member.id});
  const waiting=text(editor._render());
  for(const label of ['HY2 服务状态 · 服务运行中','反向通道 · 未连接','等待客户端连接','服务端端口监听已监听','活动连接数0','发送字节无记录','最近目标连接成功无记录'])assert(waiting.includes(label),label);
  assert(!waiting.includes('已认证连接'));assert(!JSON.stringify(editor.$data).includes('must-never-retain'));
  assert(editor.pureRouterReady);assert.deepEqual(clone(editor.member.reverse),reverse);checks++;

  pending.push(ok({hyr_status:{members:[{...clone(member),running:true,reverse_status:{connected:true,state:'online',last_heartbeat:1800000000,
    mappings:[{id:'1',listening:true,active:1,rx_bytes:128,tx_bytes:256,last_success:1800000000,last_error:'target_timeout'}]}}]}}));
  assert(await editor.readReverseStatus());
  const online=text(editor._render());assert(online.includes('已认证连接'));assert(online.includes('目标服务连接超时'));assert(online.includes('UTC'));
  assert.equal(editor.reverseRuntime.mappings[0].rx_bytes,128);assert.equal(editor.reverseRuntime.mappings[0].tx_bytes,256);checks++;

  pending.push(ok({hyr_status:{members:[{...clone(member),running:true}]}}));assert(await editor.readReverseStatus());
  assert.equal(editor.reverseRuntime,null);assert(text(editor._render()).includes('反向通道 · 无记录'));
  assert(!text(editor._render()).includes('已认证连接'));
  pending.push(new Error('secret upstream failure'));assert.equal(await editor.readReverseStatus(),false);
  assert.equal(editor.reverseServiceRunning,null);assert(!editor.reverseReading);assert(!text(editor._render()).includes('secret upstream failure'));checks++;

  // A late runtime response cannot cross an editor refresh or a different device.
  let finish;pending.push(new Promise(resolve=>{finish=resolve;}));const stale=editor.readReverseStatus();
  assert(editor.reverseReading);pending.push(settings());assert(await editor.loadTunnel());
  finish(ok({hyr_status:{members:[{...clone(member),running:true,reverse_status:{connected:true,state:'online'}}]}}));
  assert.equal(await stale,false);assert.equal(editor.reverseRuntime,null);assert.equal(editor.reverseServiceRunning,null);assert(!editor.reverseReading);checks++;

  // Native WG save payloads do not acquire reverse fields, even when a HY2 draft existed.
  editor.selectTransport('native');const native=editor.parameters();assert.equal(native.wg_transport,'native');assert(!('hyr_reverse_hex' in native));
  assert(!text(editor._render()).includes('反向端口映射'));editor.selectTransport('pure_hy2');assert.equal(editor.reverseDraft.mappings.length,1);
  editor.reverseDraft.enabled=false;assert.deepEqual(JSON.parse(Buffer.from(editor.parameters().hyr_reverse_hex,'hex').toString('utf8')),{enabled:false,mappings:[]});
  assert.equal(editor.member.reverse.enabled,true);assert.equal(editor.pureRouterReady,false);checks++;

  pending.push(settings());assert(await editor.loadTunnel());
  const exportStart=copied.length;pending.push(ok({hyr_site_profile:routerBundle()}));assert(await editor.exportMember('router'));
  assert.equal(copied.length,exportStart+1);assert.deepEqual(JSON.parse(copied.at(-1)),routerBundle());
  const wrong=routerBundle();wrong.reverse.mappings[0].target_port=81;pending.push(ok({hyr_site_profile:wrong}));
  assert.equal(await editor.exportMember('router'),false);assert(editor.stale);assert.equal(copied.length,exportStart+1);checks++;

  // Save readback uses the canonical submitted snapshot, not subsequently edited controls.
  pending.push(settings());assert(await editor.loadTunnel());set(editor,'客户端目标 IPv4 1','192.168.62.10');
  const payload={...clone(editor.peerForm),...clone(editor.parameters())};
  const expected={enabled:true,mappings:[{...mapping,target_ip:'192.168.62.10'}]};
  const savedPeer={...clone(editor.peerForm),native_role:''};
  pending.push(settings(expected,savedPeer));assert(await editor.saved(payload));
  assert.deepEqual(clone(editor.member.reverse),expected);assert.equal(editor.reverseDraft.mappings[0].target_ip,'192.168.62.10');
  assert(editor.pureRouterReady);assert.equal(editor.committed,false);checks++;

  // A mismatched save readback blocks export until the exact saved rules can be read.
  set(editor,'客户端目标 IPv4 1','192.168.62.11');const secondPayload={...clone(editor.peerForm),...clone(editor.parameters())};
  pending.push(settings(expected,savedPeer),settings(expected,savedPeer));assert.equal(await editor.saved(secondPayload),false);
  assert(editor.committed);assert.equal(editor.exportReady,false);assert.equal(editor.member,null);
  const exact={enabled:true,mappings:[{...mapping,target_ip:'192.168.62.11'}]};pending.push(settings(exact,savedPeer));assert(await editor.saved());
  assert.deepEqual(clone(editor.member.reverse),exact);assert(editor.pureRouterReady);checks++;

  // Imported routers keep process state separate and offer a manual status read.
  const imported={wgManagedSite:null,$nextTick:fn=>fn(),$refs:{},_e:()=>editor._e()};let reads=0;
  const importedReply=()=>({data:{Data:{site_client_status:{members:[{id:7,interface:'hy2c1',transport:'pure_hy2',purpose:'access',
    enabled:true,running:true,server:member.public_ip,server_port:51820,reverse,reverse_status:{connected:false,state:'connecting'},token:'drop-me'}]}}}});
  await browser.WGPasteImport.managed(imported,{id:7,interface:'hy2c1'},false,async()=>{reads++;return importedReply();});
  const importedText=text(browser.WGPasteImport.render(imported,editor.$createElement));
  assert(importedText.includes('客户端运行中'));assert(importedText.includes('反向通道 · 未连接'));
  assert(!JSON.stringify(imported.wgManagedSite).includes('drop-me'));assert.equal(reads,1);
  await imported._wgManagedReload();assert.equal(reads,2);
  assert(imported.wgManagedSite.reverse.enabled);assert.equal(imported.wgManagedSite.reverse_status.connected,false);checks++;

  assert.equal(timers.size,0);assert.equal(pending.length,0);editor.$destroy();
  console.log('PASS',checks,'reverse editor, payload, export, import and manual-status cases with native Vue',Vue.version);
})().catch(error=>{console.error(error);process.exitCode=1;});
