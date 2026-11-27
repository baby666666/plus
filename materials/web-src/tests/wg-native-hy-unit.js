'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const Vue = require('./native-vue')(process.argv[2]);
const root = path.resolve(__dirname, '..');
const web = path.join(root, '../firmware/port-3726/files/usr/ikuai/www');
const assets = JSON.parse(fs.readFileSync(path.join(root, 'wg-assets.json')));
const timers = new Set(), registeredHandlers = new Map(), files = [];
const modules = {};
const browser = {
  window: null, webpackJsonp(chunks, definitions) {Object.assign(modules, definitions);},
  customError() {}, customSuccess() {}, Blob, atob, btoa, confirm: () => true,
  addEventListener() {}, removeEventListener() {},
  document: {
    hidden: false,
    addEventListener(name, fn) {registeredHandlers.set(name, fn);},
    removeEventListener(name, fn) {if (registeredHandlers.get(name) === fn) registeredHandlers.delete(name);},
    createElement() {return {click() {files.at(-1).name = this.download;}};},
    body:{appendChild() {},removeChild() {}}
  },
  URL: {createObjectURL(blob) {files.push({blob});return 'blob:local';},revokeObjectURL() {}},
  setTimeout: fn => fn(), setInterval(fn) {timers.add(fn);return fn;}, clearInterval: fn => timers.delete(fn)
};
browser.window = browser;
const sourceFiles=['wg-i18n.js','wg-singbox.js','wg-client-config.js','wg-paste-import.js','wg-address-plan.js','wg-native-tunnel.js','wg-identity-table.js','wg-page.js'];
const sourceMode=process.argv.includes('--source');
for (const file of sourceMode?sourceFiles:[assets.i18n, assets.singbox, assets.client, assets.helper, assets.planner, assets.chunk]) {
  vm.runInNewContext(fs.readFileSync(sourceMode?path.join(root,'src',file):path.join(web,'static/js',file),'utf8'),browser,{filename:file});
}
const props = {apiUrl:'/Action/call',makeQrSvg: frame => {
  assert.match(frame,/^[a-z0-9+/]+=*$/i); return '<svg/>';
}};
assert.equal(browser.WGNativeTCP,undefined);
assert.equal(browser.WGNativeHY,undefined);
assert.equal(browser.WGNativeHYR,undefined);
const req = [], pending = [];
function ok(data) {return {data:{Result:30000,Data:data}};}
const off = {installed:false,running:false,enabled:false,public_ip:'',udp_port:443,members:[]};
const first = {id:'7ec75eba-1252-4510-a603-51b465d28d51',name:'phone-a'};
const second = {id:'24473a86-70c6-44a4-8553-4f19d3458674',name:'b'.repeat(48)};
const active = {...off,installed:true,enabled:true,public_ip:'203.0.113.5',udp_port:4443};
const pass = 'fixture-private-HY2-password';
const profile = {outbounds:[{type:'hysteria2',password:pass,tls:{enabled:true,certificate_public_key_sha256:[Buffer.alloc(32).toString('base64')]}}]};
const http={post(url,body,options) {
  assert.equal(url,props.apiUrl);assert.equal(body.func_name,'wireguard');
  req.push(JSON.parse(JSON.stringify({...body,timeout:options.timeout})));
  assert.ok(pending.length,'unexpected extra API call');
  return Promise.resolve(pending.shift());
}};
function nodes(component) {
  const list=[];
  (function visit(n){list.push(n);(n.children||[]).forEach(visit);})(component._render());
  return list;
}
function label(n){return n.text||(n.children||[]).map(label).join('');}
function controls(name, component){return nodes(component).filter(n=>n.tag==='button'&&label(n)===name);}
function click(name,idx=0,component) {
  const b=controls(name,component)[idx];assert.ok(b,'missing button '+name);assert.equal(b.data.attrs.disabled,false);
  return b.data.on.click();
}
function lastParams(){return req.at(-1).param;}
async function nativePhoneCopy(view, iface) {
  const wgButton='复制 WG 配置', jsonButton='复制 sing-box 配置';
  const flush=()=>new Promise(resolve=>setImmediate(resolve));
  function tap(name){
    const candidates=controls(name,view).filter(n=>!n.data.attrs.disabled);
    assert.equal(candidates.length,1,'expected one enabled native button: '+name);
    return candidates[0].data.on.click();
  }
  function inputFor(name){
    return nodes(view).find(n=>n.tag==='textarea' && n.data.attrs?.['aria-label']===name);
  }
  function saved(peer) {
    return ok({client_export:{peer:{...peer},iface:{...iface},keypair_valid:true}});
  }
  const original=view.tableForm;
  let copied, queries=0;
  browser.prompt=()=>assert.fail('native mobile copy opened the single-line prompt');
  browser.navigator={clipboard:{writeText:async text=>{copied=text;}}};
  view.$http={post:async(url,body)=>{
    assert.equal(url,props.apiUrl);assert.equal(body.action,'show');
    assert.deepEqual({...body.param},{TYPE:'client_export',peer_id:String(view.tableForm.id)});
    queries++;return saved(view.tableForm);
  }};
  for(const role of ['access','lend','both']){
    view.tableForm={...original,native_role:role,exit_peer:role==='access'?'no':'yes',keepalive:25,
      client_config:'',client_qr_svg:''};
    await Vue.nextTick();
    const count=queries;
    copied=undefined;tap(wgButton);await flush();
    const conf=copied;
    assert.match(conf,/^\[Interface\]\nPrivateKey = .+\nAddress = /);
    assert(view.buildClientConfig());
    assert.equal(conf,view.tableForm.client_config);
    const parsed=browser.WGPasteImport.parse(conf);
    assert.equal(parsed.peer.endpoint_port,Number(iface.local_listenport));
    assert.equal(parsed.peer.allowips,role==='lend'?iface.local_address.split('/')[0]+'/32':'0.0.0.0/0');
    assert.equal(queries,count,'standard WG text is built from the current editor');
    copied=undefined;tap(jsonButton);await flush();
    assert.equal(queries,count+1);
    const json=JSON.parse(copied);
    assert.equal(json.endpoints[0].private_key,view.tableForm.peer_privatekey);
    assert.equal(json.route.final,role==='lend'?'phone-internet':'router-wg');
    assert.equal(copied,JSON.stringify(json,null,2)+'\n','copy should use the complete download format');
  }

  // Do not discard local edits to the standard configuration. Denied writes
  // must leave the same multiline text selectable without a browser prompt.
  const lastJson=copied;
  view.tableForm.client_config+='\n# phone editor annotation';
  const edited=view.tableForm.client_config;
  browser.navigator.clipboard={writeText:async()=>{throw Error('permission denied');}};
  tap(wgButton);await flush();
  const field=inputFor('WireGuard .conf');
  assert(field);assert.equal(field.data.domProps.value,edited);
  let range=null;
  const input={value:edited,focus(){},select(){},setSelectionRange(start,end){range=[start,end];}};
  view.$refs[field.data.ref]=input;
  tap('全选配置');assert.deepEqual(range,[0,edited.length]);
  tap('关闭');await flush();
  assert.equal(controls('全选配置',view).length,0);
  delete browser.navigator.clipboard;
  tap(jsonButton);await flush();
  const jsonField=inputFor('sing-box JSON');
  assert(jsonField);
  assert.equal(jsonField.data.domProps.value,lastJson);
  assert.equal(controls('全选配置',view).length,1);
  tap('关闭');await flush();

  // The first clipboard call must start inside the user's tap even though
  // WebKit consumes the JSON later, after the saved profile arrives.
  let inTap=false,itemData,reply;
  browser.ClipboardItem=class {constructor(parts){this.parts=parts;}};
  browser.navigator.clipboard={write:async([item])=>{
    assert(inTap,'WebKit write must be started by the tap');
    itemData=item.parts['text/plain'];
    copied=await (await itemData).text();
  }};
  const previous=view.tableForm;
  view.tableForm={...previous,id:27,client_config:'',client_qr_svg:''};
  await Vue.nextTick();
  view.$http={post:()=>new Promise(resolve=>{reply=resolve;})};
  inTap=true;tap(jsonButton);inTap=false;
  assert(itemData);await flush();
  view.tableForm={...previous,id:28,client_config:'',client_qr_svg:''};
  copied=undefined;
  reply(saved({...previous,id:27}));await flush();
  assert.equal(copied,undefined,'late JSON must not be copied for a different device');
  assert.equal(controls('全选配置',view).length,0);
  delete browser.ClipboardItem;
  delete browser.navigator;
  delete browser.prompt;
  view.tableForm=original;
  await Vue.nextTick();
}
function managementPanels(component) {
  return nodes(component).map(node => node.componentOptions)
    .filter(options => options && ['WgNativeTcp','WgNativeHyr','WgNativeHy'].includes(options.Ctor.options.name));
}
(async()=>{
  // WG uses the existing native table renderer; only its six destructive/state actions carry row identities.
  const baseTable=Vue.extend({data(){return {rowChecking:[],listData:[],editingRow:null,paginationOptions:{currentPage:1}};},methods:{
    toggleCheckRow(r,e){if(e.target.checked)this.rowChecking.push(r.id);else this.rowChecking=this.rowChecking.filter(x=>x!==r.id);},
    toggleCheckAll(clear){this.rowChecking=clear?[]:this.listData.map(r=>r.id);},reload(){},$t:s=>s
  }});
  const guardedTable=browser.WGIdentityTable({$options:{components:{DTable:baseTable}}});
  const originalKey=Buffer.alloc(32,4).toString('base64'),replacementKey=Buffer.alloc(32,5).toString('base64'),serverKey=Buffer.alloc(32,6).toString('base64');
  let confirmation;browser.customConfirm=()=>new Promise(resolve=>{confirmation=resolve;});
  for(const ifaceGrid of [false,true]){
    const grid=new guardedTable();
    grid.opt={requests:{url:'/Action/call',enableRowAction:ifaceGrid?'iface_up':'up',disableRowAction:ifaceGrid?'iface_down':'down',delRowAction:ifaceGrid?'iface_del':'del'}};
    const r=ifaceGrid?{id:1,name:'wg4',local_publickey:originalKey}:{id:1,interface:'wg4',peer_publickey:originalKey,iface_id:9,server_key:serverKey};
    const b=ifaceGrid?{...r,local_publickey:replacementKey}:{...r,server_key:replacementKey,iface_id:10};
    const other=ifaceGrid?{...r,id:2,name:'wg5'}:{...r,id:2,peer_publickey:replacementKey};
    let sent,mutations=0;
    grid.$http={post:(u,body)=>{assert.equal(u,'/Action/call');mutations++;sent=body;
      return Promise.resolve(ok({}));}};
    const payload=()=>JSON.parse(Buffer.from(sent.param.expected_rows,'hex').toString('utf8'));
    const proof=ifaceGrid?{id:'1',interface:'wg4',public_key:originalKey}:{id:'1',interface:'wg4',public_key:originalKey,iface_id:'9',server_key:serverKey};
    grid.listData=[r];const delayed=grid.deleteRow(grid.listData[0]);grid.listData=[b];confirmation();assert(await delayed);
    assert.deepEqual(payload(),[proof]);assert.equal(sent.action,grid.opt.requests.delRowAction);
    assert.equal(grid.listData.length,1,'late success must not remove a replacement row');
    grid.listData=[r,other];grid.toggleCheckAll(false);grid.listData=[b,other];
    assert(await grid.batchDisableRows());assert.equal(sent.action,grid.opt.requests.disableRowAction);
    assert.equal(sent.param.id,'1,2');assert.deepEqual(payload()[0],proof);
    grid.toggleCheckRow(r,{target:{checked:true}});grid.toggleCheckRow(other,{target:{checked:true}});
    const batched=grid.batchDeleteRows();grid.toggleCheckAll(true);confirmation();assert(await batched);
    assert.equal(sent.param.id,'1,2');assert.deepEqual(payload()[0],proof);
    grid.listData=[r];assert(await grid.toggleRowsState('yes',r));assert.equal(sent.action,grid.opt.requests.enableRowAction);
    if(!ifaceGrid){
       const orphan={...r,iface_id:0,server_key:''};assert(await grid.toggleRowsState('no',orphan));assert.equal(payload()[0].iface_id,'0');
       const before=mutations;assert.equal(grid.toggleRowsState('no',{id:1,interface:'wg4',peer_publickey:originalKey}),false);
       assert.equal(mutations,before);
    }
    grid.$destroy();
  }
  assert.equal(baseTable.options.methods.deleteRow,undefined,'no global native table method was changed');
  // Exercise the native page render from the shipped WG webpack chunk.
  const pageModule = {exports:{}};
  modules[12282](pageModule);
  const dashboard = new Vue({
    data: {xEnterprise:true,wgListRevision:0,tableOptions:{requests:{url:props.apiUrl}}},
    methods: {$t:key => key},
    render: pageModule.exports.render
  });
  assert.deepEqual(nodes(dashboard).filter(n => n.tag === 'h4').map(label),
    ['wire_guard.interfaceList','wire_guard.tunnelList']);
  assert.equal(managementPanels(dashboard).length, 0, 'The WG list displays both tables without protocol managers');
  function tableKeys(){return nodes(dashboard).filter(n=>['dtable','dtable1'].includes(n.data?.ref)).map(n=>n.key);}
  assert.deepEqual(tableKeys(),['dtable-0','dtable1-0']);
  dashboard.wgListRevision++;assert.deepEqual(tableKeys(),['dtable-1','dtable1-1']);
  dashboard.$destroy();
  const dependencies = {10360:Set,11526:x=>Array.from(x),80:JSON.stringify,11525:Object.assign,78:{a:{apiUrl:props.apiUrl}},79:{},11053:{}};
  const requirePage = id => dependencies[id];requirePage.n = x => Object.assign(()=>x,{a:x});
  const pageDefinition={};modules[11749]({},pageDefinition,requirePage);
  const key = n => Buffer.alloc(32,n).toString('base64');
  const iface={id:2,name:'wg2',enabled:'yes',local_publickey:key(2),local_address:'10.100.2.1/24',local_listenport:51832};
  const peer={id:1,enabled:'yes',interface:'wg2',exit_peer:'no',native_role:'access',client_endpoint:'8.8.8.8',
    allowips:'10.100.2.2/32',peer_privatekey:key(1),peer_publickey:key(3),presharedkey:key(4),client_dns:'10.100.2.1',keepalive:25};
  const native = new Vue({data:{...pageDefinition.default.data.call({$t:k=>k}),xEnterprise:true,tableOptions:{requests:{url:props.apiUrl}},tableForm:peer,
      tableRowEditing1:true,shouHint:true,wgShowNative:true,wgPureMode:false,ifaceRows:[iface],interfaces1:['wg2'],wgPeerRole:'access'},
    computed:pageDefinition.default.computed,watch:pageDefinition.default.watch,
    methods:{...pageDefinition.default.methods,$t:k=>k,makeQrSvg:s=>s?'<svg/>':''},render:pageModule.exports.render});
  native.$validator={};native.errors={first:()=>'',has:()=>false};
  for (const [name,value] of [['preSharedKey',''],['heartbeatInterval','0']]) {
    native.buildClientConfig();assert(peer.client_config && peer.client_qr_svg);
    nodes(native).find(n=>n.data?.attrs?.name===name).data.on.input({target:{value,composing:false}});
    assert.equal(peer.client_config,'');assert.equal(peer.client_qr_svg,'');
  }
  native.buildClientConfig();assert(!peer.client_config.includes('PersistentKeepalive'));assert(!peer.client_config.includes('PresharedKey'));
  await nativePhoneCopy(native,iface);
  // Exercise the actual parent template. The editor survives the surrounding
  // native export and wire-field changes. The companion browser test checks the
  // mounted instance, its draft and actual radio events on the native firmware.
  const editorNode=()=>nodes(native).find(n=>n.data?.ref==='hyrTunnel');
  for(const pure of [true,false,true,false]){
    editorNode().componentOptions.listeners.transport(pure,!pure,false,pure);
    await Vue.nextTick();
    assert.equal(native.wgPureMode,pure);
    assert.equal(editorNode().key,'wg-device-editor');
    const wireRow=nodes(native).find(n=>n.tag==='div' && n.data?.staticClass==='line_edit' &&
      n.children?.some(c=>c.data?.staticClass==='input_tit' && label(c).includes('wire_guard.preSharedKey')));
    assert(wireRow);assert.equal(wireRow.data.style?.display,pure?'none':undefined);
  }
  native.wgTunnelOn=true;
  assert.equal(nodes(native).some(n=>n.data?.attrs?.name==='client_endpoint'),false);
  native.wgTunnelOn=false;
  iface.local_listenport=51842;await Vue.nextTick();
  assert.equal(peer.client_config,'');assert.equal(peer.client_qr_svg,'');
  native.buildClientConfig();iface.local_publickey=key(5);await Vue.nextTick();
  assert.equal(peer.client_config,'');assert.equal(peer.client_qr_svg,'');native.$destroy();
  const hyr=s=>ok({hyr_settings:s});
  const peera={peer_id:'13',interface:'wg5',address:'192.0.2.13/32',exit:true};
  const peerb={peer_id:'14',interface:'wg6',address:'192.0.2.14/32',exit:true};
  const h0={...off,peers:[peera,peerb,{...peera,peer_id:'15',exit:false}],udp_port:8443};
  const ha={...active,udp_port:8443,peers:h0.peers,members:[]};
  const m1={...first,...peera,active:true,peer_publickey:'first-pub'}, m2={...second,...peerb,active:true,port_mode:'wg',public_port:51826,peer_publickey:'test-public-key'};
  const hr={...ha,running:true,members:[m1,{...m2,password:pass}]};
  const client={inbounds:[{type:'tun'}],outbounds:[{...profile.outbounds[0],server:'8.8.8.8',server_port:51826}]};
  const peerForm=new Vue({data:{f:{id:'14',interface:'wg6',allowips:peerb.address,
    exit_peer:'no',keepalive:0,client_endpoint:'',peer_privatekey:'test-phone-key',peer_publickey:'test-public-key'}}}).f;
  const editor=new (Vue.extend(browser.WGNativeTunnel))({propsData:{...props,peerForm,listenPort:'51826'}});editor.$http=http;
  const edit=(name)=>click(name,0,editor);
  const choice=(name,value)=>nodes(editor).find(n=>n.data?.attrs?.name===name && (value===undefined||n.data.attrs.value===value));
  const origin={hyr_origin_key:'test-public-key',hyr_origin_iface:'wg6',hyr_id:'',native_origin_exit:'no',native_origin_role:''};
  const persisted={id:'14',interface:'wg6',allowips:peerb.address,peer_publickey:'test-public-key',native_role:'',exit_peer:'no'};
  function read(h=h0, saved=persisted){pending.push(hyr({...h,peer:{...saved}}));}
  function select(method){return choice('wg_transport',method).data.on.change();}
  function role(r){choice('wg_role',r).data.on.change();}
  const managers = () => managementPanels(editor).map(options => options.Ctor.options.name).sort();
  read();await editor.loadTunnel();
  assert.deepEqual(lastParams(),{TYPE:'hyr_settings',peer_id:'14'});
  assert.deepEqual(managers(), []);
  assert.equal(editor.transport,'native');assert.equal(choice('wg_transport','native').data.domProps.checked,true);
  assert.deepEqual(nodes(editor).filter(n=>n.data?.attrs?.name==='wg_transport').map(n=>n.data.attrs.value),['native','pure_hy2']);
  assert.deepEqual(nodes(editor).filter(n=>n.data?.attrs?.name==='wg_role').map(n=>n.data.attrs.value),['lend','access','both']);
  assert.deepEqual({...editor.parameters()},{...origin,wg_transport:'native',wg_role:'off'});
  editor.$set(peerForm,'comment','new note');
  assert.deepEqual({...editor.commentEdit(editor.parameters())},{id:'14',comment:'new note',comment_only:'yes',...origin});
  peerForm.keepalive=5;assert.equal(editor.commentEdit(editor.parameters()),null);peerForm.keepalive=0;
  peerForm.peer_publickey='new-key';peerForm.interface='wg7';read();await editor.loadTunnel();
  assert.deepEqual({...editor.parameters()},{...origin,wg_transport:'native',wg_role:'off'});
  peerForm.peer_publickey=origin.hyr_origin_key;peerForm.interface=origin.hyr_origin_iface;
  role('both');assert.equal(peerForm.native_role,'both');assert.equal(peerForm.exit_peer,'yes');
  assert.equal(editor.parameters().wg_role,'both');
  role('access');await Vue.nextTick();
  pending.push(ok({client_endpoint:{ip:'100.64.1.2',source:'wan',listen_port:51826}}));
  await select('pure_hy2');assert.equal(editor.mode,'access');assert.equal(peerForm.exit_peer,'no');
  assert.deepEqual(lastParams(),{TYPE:'client_endpoint',interface:'wg6'});
  assert.equal(editor.draft.public_ip,'');assert(editor.discoveryError);
  pending.push(ok({client_endpoint:{ip:'8.8.8.8',source:'public',listen_port:51826}}));
  await edit('重新获取');assert.equal(editor.draft.public_ip,'8.8.8.8');
  assert.deepEqual(lastParams(),{TYPE:'client_endpoint',interface:'wg6',force:'1'});
  assert.equal(choice('hyr_port_mode'),undefined);
  assert.equal(choice('wg_role','lend'),undefined);
  assert.deepEqual({...editor.parameters()},{...origin,wg_transport:'pure_hy2',wg_role:'access',hyr_public_ip:'8.8.8.8',hyr_addr_mode:'auto',hyr_port_mode:'wg',hyr_reverse_hex:Buffer.from('{"enabled":false,"mappings":[]}').toString('hex'),exit_peer:'no'});
  const long={...hr,members:[m1,{...m2,password:pass,transport:'pure_hy2',mode:'access',addr_mode:'auto',public_ip:'8.8.8.8'}]};
  read(long);assert.equal(await editor.saved(),true);
  assert.deepEqual(managers(), []);
  assert.equal(nodes(editor).some(n=>/登记手机|备用上网|管理共享入口|启用服务/.test(n.text||'')), false);
  const details=nodes(editor).find(n=>n.tag==='details');assert.equal(details.data.attrs.open,false);
  assert.match(label(details.children[0]),/8\.8\.8\.8/);
  assert.equal(editor.mode,'access');assert.equal(editor.member.id,m2.id);
  assert(!JSON.stringify(editor.$data).includes(pass));
  pending.push(ok({hyr_profile:client}));await edit('下载设备 JSON');
  assert.deepEqual(lastParams(),{TYPE:'hyr_profile',peer_id:'14',id:m2.id,expected_role:'access'});assert.equal(files.at(-1).name,'HY2-'+m2.name+'.json');
  assert.deepEqual(JSON.parse(await files.at(-1).blob.text()),client);
  pending.push(ok({hyr_profile:{...client,fixture:'x'.repeat(2400)}}));await edit('扫码导入');
  assert.equal(timers.size,1);await edit('暂停轮播');await edit('下一帧');assert.equal(timers.size,0);
  let finish;
  pending.push(new Promise(done=>{finish=done;}));const late=edit('扫码导入');
  editor.closeQr();finish(ok({hyr_profile:client}));assert.equal(await late,false);assert.equal(editor.qr,null);
  for(const tls of [{enabled:true},{...client.outbounds[0].tls,insecure:true}]){
    read(long);await editor.loadTunnel();
    const count=files.length;
    pending.push(ok({hyr_profile:{...client,outbounds:[{...client.outbounds[0],tls}]}}));
    assert.equal(await edit('下载设备 JSON'),false);assert.equal(files.length,count);assert(editor.error);
  }
  for(const storage of ['disk','memory','none',undefined]){
    read({...long,core_storage:storage});assert(await editor.loadTunnel());
    assert.equal(nodes(editor).some(n=>/88 MiB/.test(n.text || '')),storage==='memory');
  }
  for(const [storage,format,compressed] of [['disk','squashfs',true],['disk','raw',false],['memory','squashfs',false],['disk',undefined,false]]){
    read({...long,core_storage:storage,core_format:format});assert(await editor.loadTunnel());
    assert.equal(nodes(editor).some(n=>/从压缩磁盘/.test(n.text || '')),compressed);
  }
  // Ordinary authenticated pure HY2 uses the saved URL without an extra grant.
  {
    const authorized={...long,members:[m1,{...long.members[1],management_url:'https://192.0.2.1:44443/'}]};
    read(authorized);await editor.loadTunnel();
    assert.equal(choice('hyr_allow_management'),undefined);
    assert.equal('hyr_allow_management' in editor.parameters(),false);
    assert.equal(editor.managementAddress,'https://192.0.2.1:44443/');
    const info=nodes(editor).find(n=>n.tag==='p' && label(n).includes('分流入接口'));
    assert(info && label(info).includes('分流源地址'));
    assert.deepEqual(Array.from(info.children).filter(n=>n.tag==='code').map(label),[editor.member.interface,editor.member.address]);

    let copied;
    browser.navigator={clipboard:{writeText:async value=>{copied=value;}}};
    assert(await click('复制后台地址',0,editor));assert.equal(copied,editor.managementAddress);
    let selected=false;
    editor.$refs.managementAddress={value:editor.managementAddress,focus(){},select(){},setSelectionRange(a,b){assert.equal(a,0);assert.equal(b,this.value.length);selected=true;}};
    browser.navigator.clipboard={writeText:async()=>{throw Error('denied');}};
    assert.equal(await click('复制后台地址',0,editor),false);assert(selected);assert.match(editor.notice,/全选后台地址/);
    for(const bad of ['javascript:alert(1)','https://evil.example/','https://user@192.0.2.1/','https://192.0.2.1:65536/','https://192.0.2.1/extra']){
      read({...authorized,members:[{...authorized.members[1],management_url:bad}]});await editor.loadTunnel();assert.equal(editor.managementAddress,'');
    }
    read({...authorized,enabled:false});await editor.loadTunnel();assert.equal(editor.managementAddress,'');
    read(long);await editor.loadTunnel();assert.equal(editor.managementAddress,'');
  }
  const asleep={...long,enabled:false};
  read(asleep);await editor.loadTunnel();assert.equal(controls('扫码导入',editor).length,0);
  assert(!('hyr_resume' in editor.parameters()));
  choice('hyr_resume').data.on.change({target:{checked:true}});
  assert.equal(editor.parameters().hyr_resume,'yes');
  editor.$set(peerForm,'comment','wake device');assert.equal(editor.commentEdit(editor.parameters()),null);
  // Saving one device must not activate other paused peers.
  read({...long,members:[{...m1,paused:true},long.members[1]]});
  assert.equal(await editor.saved(),true);assert.equal(editor.resume,false);assert.equal(controls('扫码导入',editor).length,1);
  // RC16 and early registrations lacking a transport must not regain a native route or export.
  for(const old of [{...m2},{...m2,transport:'hysteria2',mode:'site'}]){
    read({...hr,members:[old]});await editor.loadTunnel();assert.equal(editor.transport,'hysteria2');
    assert(nodes(editor).some(n=>/已停用/.test(n.text||'')));
    assert.equal(nodes(editor).filter(n=>n.data?.attrs?.name==='wg_transport' && n.data.domProps.checked).length,0);
    assert.equal(choice('wg_role'),undefined);assert(!editor.exportReady && !editor.nativeRouterReady);
    assert.throws(()=>editor.parameters(),/已停用/);
    editor.selectTransport('hysteria2');assert.throws(()=>editor.parameters(),/已停用/);
    pending.push(ok({client_endpoint:{ip:'8.8.8.8',source:'public'}}));await select('pure_hy2');
    assert.equal(editor.parameters().hyr_id,m2.id);assert.equal(editor.parameters().hyr_resume,'yes');
    select('native');assert.equal(editor.parameters().wg_transport,'native');
  }
  // After add, read only the exact registered interface, address and public key. Never submit the add twice.
  delete peerForm.id;peerForm.native_role='';peerForm.exit_peer='no';read();await editor.loadTunnel();assert.deepEqual({...editor.parameters()},{wg_transport:'native',wg_role:'access'});
  pending.push(ok({client_endpoint:{ip:'8.8.8.8',source:'public'}}));await select('pure_hy2');role('access');
  const reused={...ha,members:[{...long.members[1],peer_publickey:'new-public-key'}]};
  read(reused);read(reused);assert.equal(await editor.saved(),false);
  assert.throws(()=>editor.parameters(),/隧道已保存/);assert.equal(controls('刷新状态',editor).length,1);
  read(long);assert.equal(await editor.saved(),true);
  assert.equal(editor.member.peer_id,'14');assert.equal(editor.mode,'access');
  // A second WAN must be probed even after the first device has set the shared address.
  read(ha);await editor.loadTunnel();
  pending.push(ok({client_endpoint:{ip:'9.9.9.9',source:'public'}}));await select('pure_hy2');
  assert.equal(editor.parameters().hyr_public_ip,'9.9.9.9');assert.notEqual(editor.parameters().hyr_public_ip,ha.public_ip);
  choice('hyr_addr_mode','manual').data.on.change();
  choice('hyr_public_ip').data.on.input({target:{value:'1.1.1.1'}});
  assert.equal(editor.parameters().hyr_addr_mode,'manual');assert.equal(editor.parameters().hyr_public_ip,'1.1.1.1');
  assert.equal(choice('hyr_addr_mode','shared'),undefined);
  // The saved table row can be deleted and its numeric ID reused while the list is open.
  const oldRow={...persisted,keepalive:25,enabled:'yes'};
  const stale=new (Vue.extend(browser.WGNativeTunnel))({propsData:{...props,peerForm:{...oldRow}}});
  stale.$http=http;
  let nativeVisible, refreshes=0;
  stale.$on('transport',(_hy,visible)=>{nativeVisible=visible;});
  stale.$on('reload-list',()=>{refreshes++;});
  const replacement={...oldRow,interface:'wg8',allowips:'10.55.8.2/32',peer_publickey:'replacement-public'};
  const newMember={...long.members[1],interface:replacement.interface,address:replacement.allowips,peer_publickey:replacement.peer_publickey};
  for(const current of [null,replacement,{...oldRow,native_role:'access'},{...oldRow,peer_publickey:'new-key'}]) {
    pending.push(hyr({...ha,peer:current,members:current===replacement?[newMember]:[]}));
    assert.equal(await stale.loadTunnel(),false);assert.equal(stale.stale,true);assert.equal(nativeVisible,false);
    assert.equal(controls('下载设备 JSON',stale).length,0);assert.throws(()=>stale.parameters(),/重新打开/);
    click('返回并刷新列表',0,stale);
  }
  assert.equal(refreshes,4);
  pending.push(hyr({...ha,peer:oldRow,members:[newMember]}));
  assert.equal(await stale.loadTunnel(),false);assert.equal(stale.member,null);
  stale.$destroy();
  const draft=new Vue({data:{form:{...oldRow}}}).form;
  const reopened=new (Vue.extend(browser.WGNativeTunnel))({propsData:{...props,peerForm:draft}});
  reopened.$http=http;
  pending.push(new Promise(resolve=>{finish=resolve;}));
  const opening=reopened.loadTunnel();
  draft.keepalive=99;
  finish(hyr({...long,peer:oldRow}));
  assert.equal(await opening,true);assert.equal(reopened.exportReady,false);
  draft.keepalive=oldRow.keepalive;await Vue.nextTick();assert.equal(reopened.exportReady,true);
  const count=files.length;
  pending.push(new Promise(resolve=>{finish=resolve;}));
  const lateDownload=click('下载设备 JSON',0,reopened);
  draft.keepalive=99;
  finish(ok({hyr_profile:client}));assert.equal(await lateDownload,false);assert.equal(files.length,count);
  draft.keepalive=oldRow.keepalive;await Vue.nextTick();
  const nativeWire={private_key:key(2),public_key:key(3),peer_address:'192.0.2.1/32'};
  let copied;
  const jsonClipboard={writeText:async text=>{copied=JSON.parse(text);}};
  browser.navigator={clipboard:jsonClipboard};
  pending.push(ok({hyr_profile:client}));assert.equal(await click('复制 sing-box 配置',0,reopened),true);assert.deepEqual(copied,client);
  const jsonAction='复制 sing-box 配置',uriAction='复制 HY2 链接';
  const phoneText=JSON.stringify(client,null,2)+'\n', host=long.members[1].public_ip;
  const uri='hysteria2://'+('ab'.repeat(32))+'@'+host+':51826/?sni='+host+'&insecure=1&pinSHA256='+('01'.repeat(32))+'#'+m2.name;
  const share={uri,server:host,server_port:51826};
  const manualField=()=>nodes(reopened).find(n=>n.tag==='textarea'&&n.data.ref==='phoneText');
  // Safari's clipboard write must be invoked by the tap itself, without waiting for the saved profile.
  let gesture=false,writes=0;
  browser.ClipboardItem=class {constructor(parts){this.parts=parts;}};
  browser.navigator.clipboard={write:async ([item])=>{
    assert(gesture);writes++;const blob=await item.parts['text/plain'];
    copied=await blob.text();
  }};
  for(const [action,type,document,expected] of [[jsonAction,'hyr_profile',client,phoneText],[uriAction,'hyr_uri',share,uri]]){
    copied=undefined;
    pending.push(new Promise(resolve=>{finish=resolve;}));
    gesture=true;const sent=click(action,0,reopened);gesture=false;
    assert.equal(writes,1);writes=0;assert.equal(copied,undefined);
    assert.deepEqual(lastParams(),{TYPE:type,expected_role:'access',peer_id:'14',id:m2.id});
    finish(ok({[type]:document}));assert(await sent);assert.equal(copied,expected);
    assert.equal(manualField(),undefined);
  }
  // Switch types while the first read is still pending. Its late secret must never be written.
  pending.push(new Promise(resolve=>{finish=resolve;}));gesture=true;
  const firstRead=click(jsonAction,0,reopened);
  pending.push(ok({hyr_uri:share}));const secondRead=click(uriAction,0,reopened);gesture=false;
  assert(await secondRead);finish(ok({hyr_profile:client}));assert.equal(await firstRead,false);assert.equal(copied,uri);
  browser.navigator.clipboard={write:async()=>{throw Error('permission denied');},writeText:async()=>{throw Error('permission denied');}};
  pending.push(ok({hyr_profile:client}));assert.equal(await click(jsonAction,0,reopened),false);
  assert.equal(manualField().data.domProps.value,phoneText);assert.equal(manualField().data.attrs.readonly,true);
  assert.equal(manualField().data.attrs['aria-label'],'sing-box JSON');assert.equal(reopened.notice,'');
  // No clipboard (plain HTTP). Both manual selections preserve the exact output.
  delete browser.navigator.clipboard;
  for(const [action,doc,expected,label] of [[uriAction,{hyr_uri:share},uri,'HY2 URI'],[jsonAction,{hyr_profile:client},phoneText,'sing-box JSON']]){
    pending.push(ok(doc));const reading=click(action,0,reopened);
    assert.equal(manualField(),undefined);assert.equal(await reading,false);
    const field=manualField();assert.equal(field.data.domProps.value,expected);assert.equal(field.data.attrs['aria-label'],label);
    let selected=false;
    reopened.$refs.phoneText={value:expected,focus(){},select(){},setSelectionRange(start,end){assert.equal(start,0);assert.equal(end,expected.length);selected=true;}};
    assert(click('全选配置',0,reopened));assert(selected);
    selected=false;browser.document.execCommand=command=>{assert.equal(command,'copy');assert(selected);return true;};
    assert(click(action,0,reopened));assert.equal(reopened.notice,'已复制');delete browser.document.execCommand;
  }
  click('关闭',0,reopened);assert.equal(manualField(),undefined);
  pending.push(ok({hyr_uri:share}));await click(uriAction,0,reopened);
  browser.document.hidden=true;reopened.onVisibility();assert.equal(manualField(),undefined);assert.equal(reopened.phoneText,'');browser.document.hidden=false;
  pending.push(ok({hyr_profile:client}));await click(jsonAction,0,reopened);
  draft.keepalive=99;await Vue.nextTick();assert.equal(reopened.phoneText,'');assert.equal(manualField(),undefined);
  draft.keepalive=oldRow.keepalive;await Vue.nextTick();
  delete browser.ClipboardItem;browser.navigator.clipboard={writeText:async text=>{copied=text;}};
  for(const invalid of [uri.replace('@'+host,'@1.1.1.1'),uri.replace(':51826/',':443/'),uri.replace('sni='+host,'sni=example.com'),
    uri.replace(/pinSHA256=[^#]+/,'pinSHA256=ab'),uri.replace('&pinSHA256=','&unexpected=1&pinSHA256='),
    uri.replace(/\/\/[^@]+@/,'//@'),uri+'\n',uri.replace('#'+m2.name,'#other-device')]){
    copied=undefined;pending.push(ok({hyr_uri:{...share,uri:invalid}}));
    assert.equal(await click(uriAction,0,reopened),false);assert.equal(copied,undefined);assert.equal(manualField(),undefined);assert(reopened.stale);
    pending.push(hyr({...long,peer:oldRow}));assert(await reopened.loadTunnel());
  }
  browser.navigator.clipboard=jsonClipboard;
  for(const role of ['access','lend','both']){
    const peer={...oldRow,keepalive:role==='lend'?25:0,native_role:role,exit_peer:role==='access'?'no':'yes',enabled:'yes',client_endpoint:'gw.example.test'};
    const f=new Vue({data:{f:{...peer}}}).f;
    const instance=new (Vue.extend(browser.WGNativeTunnel))({propsData:{...props,peerForm:f,serverKey:key(3),listenPort:51826}});
    instance.$http=http;pending.push(hyr({...h0,peer}));assert(await instance.loadTunnel());
    assert.equal(instance.nativeRouterReady,true);
    const conf={version:2,purpose:role,format:'nativerouting-wg-device',transport:{server:'gw.example.test',server_port:51826},
       wireguard:{...nativeWire,address:peerb.address,mtu:1420,keepalive:role==='lend'?25:0}};
    pending.push(ok({native_router_profile:conf}));assert(await click('复制到路由器',0,instance));assert.deepEqual(copied,conf);
    assert.deepEqual(lastParams(),{TYPE:'native_router_profile',expected_role:role,peer_id:String(peer.id),hyr_origin_key:peer.peer_publickey,hyr_origin_iface:peer.interface,expected_server_key:key(3)});
    f.client_endpoint='changed.example.test';assert.equal(instance.nativeRouterReady,false);
    f.client_endpoint=peer.client_endpoint;await Vue.nextTick();assert.equal(instance.nativeRouterReady,true);
    let reply;pending.push(new Promise(resolve=>{reply=resolve;}));copied=undefined;const waitCopy=click('复制到路由器',0,instance);
    f.keepalive=7;reply(ok({native_router_profile:conf}));assert.equal(await waitCopy,false);assert.equal(copied,undefined);
    instance.$destroy();
  }
  // A former bidirectional peer keeps its saved DB origin while exporting access only.
  for(const originExit of ['no','yes']){
    const peer={...oldRow,enabled:'yes',keepalive:0,exit_peer:originExit};
    const f=new Vue({data:{f:{...peer}}}).f;
    const inst=new (Vue.extend(browser.WGNativeTunnel))({propsData:{...props,peerForm:f,listenPort:51826}});
    inst.$http=http;
    const entry={...long.members[1],transport:'pure_hy2',mode:'access',public_port:51826};
    pending.push(hyr({...long,members:[entry],peer}));
    assert(await inst.loadTunnel());assert.equal(inst.transport,'pure_hy2');assert(inst.exportReady);
    assert.equal(inst.parameters().native_origin_exit,originExit);
    assert.equal(inst.parameters().exit_peer,'no');
    assert.deepEqual(nodes(inst).filter(n=>n.data?.attrs?.name==='wg_role').map(n=>n.data.attrs.value),['access']);
    assert.equal(nodes(inst).some(n=>n.data?.attrs?.name==='hyr_port_mode'),false);
    inst.selectMode('both');assert.equal(inst.mode,'access');
    const host=entry.public_ip;
    const outbound={type:'hysteria2',server:host,server_port:51826,password:'ab'.repeat(32),
      tls:{enabled:true,certificate_public_key_sha256:[key(4)]}};
    const profile={inbounds:[{type:'tun'}],outbounds:[outbound]};
    const bundle={format:'nativerouting-pure-hy2-device',version:1,purpose:'access',
      transport:{server:host,server_port:51826,certificate_public_key_sha256:key(4),password:outbound.password}};
    pending.push(ok({hyr_profile:profile}));assert(await click('复制 sing-box 配置',0,inst));assert.deepEqual(copied,profile);
    pending.push(ok({hyr_profile:profile}));assert(await click('扫码导入',0,inst));assert(inst.qr.name.startsWith('HY2-'));inst.closeQr();
    pending.push(ok({hyr_site_profile:bundle}));assert(await click('复制到路由器',0,inst));assert.deepEqual(copied,bundle);
    assert.equal(lastParams().expected_role,'access');
    copied=undefined;pending.push(ok({hyr_profile:{...profile,inbounds:[...profile.inbounds,{type:'hysteria2'}]}}));
    assert.equal(await click('复制 sing-box 配置',0,inst),false);assert.equal(copied,undefined);assert(inst.stale);
    inst.$destroy();
  }
  {
    const peer={...oldRow,enabled:'yes',keepalive:0,exit_peer:'yes'};
    const f=new Vue({data:{f:{...peer}}}).f;
    const inst=new (Vue.extend(browser.WGNativeTunnel))({propsData:{...props,peerForm:f,listenPort:51826}});
    inst.$http=http;
    const entry={...long.members[1],transport:'pure_hy2',mode:'lend',public_port:51826,retired:true,active:false,paused:true};
    pending.push(hyr({...long,members:[entry],peer}));
    assert(await inst.loadTunnel());assert(!inst.exportReady);
    assert.deepEqual(nodes(inst).filter(n=>n.data?.attrs?.name==='wg_role').map(n=>[n.data.attrs.value,n.data.domProps.checked]),[['access',false]]);
    assert.equal(nodes(inst).some(n=>n.data?.attrs?.name==='hyr_resume'),false);
    assert.throws(()=>inst.parameters(),/已停用/);
    inst.selectMode('access');
    assert.equal(inst.parameters().wg_role,'access');assert.equal(inst.parameters().hyr_resume,'yes');
    inst.$destroy();
  }
  // The same peer and service keys may outlive a public endpoint or PSK rotation.
  for(const changed of ['server','server_port','address','keepalive','preshared_key']){
    const peer={...oldRow,native_role:'access',exit_peer:'no',enabled:'yes',client_endpoint:'gw.example.test:51900',keepalive:25,presharedkey:key(4)};
    const f=new Vue({data:{f:{...peer}}}).f;
    const inst=new (Vue.extend(browser.WGNativeTunnel))({propsData:{...props,peerForm:f,serverKey:key(3),listenPort:51826}});inst.$http=http;
    pending.push(hyr({...h0,peer}));assert(await inst.loadTunnel());
    const doc={format:'nativerouting-wg-device',version:2,purpose:'access',transport:{server:'gw.example.test',server_port:51900},
      wireguard:{...nativeWire,address:peer.allowips,mtu:1420,keepalive:25,preshared_key:key(4)}};
    pending.push(ok({native_router_profile:doc}));assert(await click('复制到路由器',0,inst));
    const modified={server:'other.example.test',server_port:51001,address:'192.0.2.99/32',keepalive:4,preshared_key:key(1)};
    (changed.startsWith('server')?doc.transport:doc.wireguard)[changed]=modified[changed];
    copied=undefined;pending.push(ok({native_router_profile:doc}));
    assert.equal(await click('复制到路由器',0,inst),false);assert.equal(copied,undefined);assert(inst.stale);
    assert.equal(controls('返回并刷新列表',inst).length,1);assert.equal(controls('复制到路由器',inst).length,0);inst.$destroy();
  }
  reopened.selectMode('site');assert.equal(reopened.mode,'access');
  reopened.$set(draft,'site_local','192.168.11.0/24');
  assert.throws(()=>reopened.parameters(),/清空互访网段/);
  reopened.$destroy();
  editor.$destroy();
  assert.equal(timers.size,0);assert.equal(pending.length,0);
  console.log('PASS device tunnel editor, native WireGuard and HY2 exports, independent WAN and explicit per-device recovery (Vue '+Vue.version+')');
})().catch(err=>{console.error(err);process.exitCode=1;});
