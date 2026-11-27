'use strict';
const assert=require('node:assert/strict');
const api=require('../src/wg-paste-import.js');
const key=Buffer.alloc(32,4).toString('base64');
const secret='ab'.repeat(32),token='cd'.repeat(32);
const mapping={id:'1',protocol:'tcp',listen_port:18080,target_ip:'192.168.62.1',target_port:80,sources:['203.0.113.9/24','203.0.113.0/24']};
const normalized={...mapping,sources:['203.0.113.0/24']};
const basic={format:'nativerouting-pure-hy2-device',version:1,purpose:'access',transport:{server:'198.51.100.9',server_port:51820,password:secret,certificate_public_key_sha256:key}};
const reverse={version:1,server:'10.177.1.1',server_port:49871,token,mappings:[mapping]};
const bundle={...basic,version:2,reverse};
const clone=x=>JSON.parse(JSON.stringify(x));
let checks=0;
function test(name,run){run();checks++;}
test('v1 keeps its original preview and rejects extra reverse credentials',()=>{
  assert.deepEqual(api.parse(JSON.stringify(basic)).preview,{transport:'pure_hy2',purpose:'access',server:'198.51.100.9',port:51820});
  assert.throws(()=>api.parse(JSON.stringify({...basic,reverse})));
});
test('v2 validates every mapping and returns no credentials',()=>{
  const preview=api.parse(JSON.stringify(bundle)).preview;
  assert.deepEqual(preview.reverse,{enabled:true,mappings:[normalized]});
  assert(!JSON.stringify(preview).includes(token));assert(!JSON.stringify(preview).includes(secret));
  assert.deepEqual(mapping.sources,['203.0.113.9/24','203.0.113.0/24'],'validation must not mutate the incoming config');
});
for(const [name,change] of Object.entries({
  extraBundle:x=>{x.foo=true;},extraReverse:x=>{x.reverse.enabled=true;},
  missingReverse:x=>{delete x.reverse;},missingToken:x=>{delete x.reverse.token;},
  secretCase:x=>{x.reverse.token=token.toUpperCase();},wrongVersion:x=>{x.reverse.version=2;},
  badControlPort:x=>{x.reverse.server_port=7000;},sameControlEndpoint:x=>{x.reverse.server=x.transport.server;},
  unspecifiedGateway:x=>{x.reverse.server='0.0.0.1';},multicastGateway:x=>{x.reverse.server='224.1.2.3';},
  noncanonicalGateway:x=>{x.reverse.server='010.0.0.1';},extraRule:x=>{x.reverse.mappings[0].password=token;},
  badId:x=>{x.reverse.mappings[0].id='01';},numericId:x=>{x.reverse.mappings[0].id=1;},largeId:x=>{x.reverse.mappings[0].id='33';},
  dupId:x=>{x.reverse.mappings.push({...mapping,listen_port:18081});},
  dupPort:x=>{x.reverse.mappings.push({...mapping,id:'2'});},
  badProtocol:x=>{x.reverse.mappings[0].protocol='TCP';},
  zeroListen:x=>{x.reverse.mappings[0].listen_port=0;},stringListen:x=>{x.reverse.mappings[0].listen_port='18080';},
  floatTarget:x=>{x.reverse.mappings[0].target_port=80.5;},largeTarget:x=>{x.reverse.mappings[0].target_port=65536;},
  targetDNS:x=>{x.reverse.mappings[0].target_ip='router.local';},targetMulticast:x=>{x.reverse.mappings[0].target_ip='239.1.2.3';},
  sourceNotArray:x=>{x.reverse.mappings[0].sources='0.0.0.0/0';},emptySources:x=>{x.reverse.mappings[0].sources=[];},
  sourceHostOnly:x=>{x.reverse.mappings[0].sources=['203.0.113.1'];},badCIDR:x=>{x.reverse.mappings[0].sources=['203.0.113.1/33'];},
  sourceLeadingZero:x=>{x.reverse.mappings[0].sources=['203.00.113.1/24'];},
  tooManySources:x=>{x.reverse.mappings[0].sources=Array(17).fill('0.0.0.0/0');},
  emptyMappings:x=>{x.reverse.mappings=[];},tooManyMappings:x=>{x.reverse.mappings=Array(33).fill(mapping);}
}))test('reject '+name,()=>{const copy=clone(bundle);change(copy);assert.throws(()=>api.validateSite(copy));});
test('maximum mapping count and protocol-specific port uniqueness',()=>{
  const value={...bundle,reverse:{...reverse,mappings:Array.from({length:32},(_,i)=>({...mapping,id:String(i+1),listen_port:18080+i,sources:['0.0.0.0/0']}))}};
  assert.equal(api.validateSite(value).reverse.mappings.length,32);
  value.reverse.mappings=[mapping,{...mapping,id:'2',protocol:'udp'}];
  assert.equal(api.validateSite(value).reverse.mappings.length,2);
});
test('explicit loopback targets and all-source access remain user choices',()=>{
  assert.equal(api.reverseMappings([{...mapping,target_ip:'127.0.0.1',sources:['0.0.0.0/0']}])[0].target_ip,'127.0.0.1');
});
test('disabled settings remain canonical and cannot carry active mappings',()=>{
  assert.deepEqual(api.validateReverse(),{enabled:false,mappings:[]});
  assert.deepEqual(api.validateReverse({enabled:false}),{enabled:false,mappings:[]});
  assert.throws(()=>api.validateReverse({enabled:false,mappings:[mapping]}));
  assert.throws(()=>api.validateReverse({enabled:true,mappings:[mapping],token}));
});
test('native scalar API uses even lowercase hex and preserves canonical config',()=>{
  const text=api.reverseHex({enabled:true,mappings:[mapping]});
  assert.match(text,/^[a-f0-9]+$/);assert.equal(text.length%2,0);
  assert.deepEqual(JSON.parse(Buffer.from(text,'hex').toString('utf8')),{enabled:true,mappings:[normalized]});
  assert.deepEqual(api.reverseFromHex(text),{enabled:true,mappings:[normalized]});
  for(const bad of ['',text.slice(1),text.toUpperCase(),'{"enabled":false}','00','a'.repeat(131074)])assert.throws(()=>api.reverseFromHex(bad));
});
function h(tag,data,children){
  if(Array.isArray(data)||typeof data==='string'){children=data;data={};}
  return {tag,data:data||{},children:(children||[]).filter(x=>x!==null && x!==undefined)};
}
function text(node){return typeof node==='object'?node.children.map(text).join(''):String(node);}
test('import preview displays endpoints and source scopes without secrets',()=>{
  const view={wgImportOpen:true,wgSitePreview:api.validateSite(bundle),wgImportText:JSON.stringify(bundle),_e:()=>'',wgImportBusy:false};
  const rendered=text(api.render(view,h));
  for(const expected of ['反向端口映射','198.51.100.9:18080','192.168.62.1:80','203.0.113.0/24','指定服务'])assert(rendered.includes(expected));
  assert(!rendered.includes(secret));assert(!rendered.includes(token));
});
test('runtime data separates authenticated sessions and port listeners from target success',()=>{
  const status=api.reverseState({connected:true,state:'online',last_heartbeat:1800000000,password:secret,token,
    mappings:[{id:'1',listening:true,active:0,rx_bytes:0,tx_bytes:undefined,last_success:0,last_error:'target_timeout',target_password:secret}]});
  assert.equal(status.mappings[0].active,0);assert.equal(status.mappings[0].tx_bytes,null);assert.equal(status.mappings[0].last_success,null);
  const rendered=text(api.renderReverseStatus(h,status,[normalized]));
  for(const expected of ['已认证连接','已监听','目标服务连接超时','无记录','活动连接数0'])assert(rendered.includes(expected));
  assert(!JSON.stringify(status).includes(secret));assert(!JSON.stringify(status).includes(token));
});
test('missing and invalid runtime fields never become success or zero',()=>{
  assert.equal(api.reverseState(undefined),null);
  const status=api.reverseState({connected:'true',state:secret,error:secret,last_heartbeat:-1,mappings:[{id:'1',listening:'true',active:-1,rx_bytes:'0',tx_bytes:1e100,last_error:token,last_success:0}]});
  const rendered=text(api.renderReverseStatus(h,status,[normalized]));
  assert(!rendered.includes('已认证连接'));assert(!rendered.includes('已监听'));assert(!rendered.includes(token));assert(!rendered.includes(secret));
  assert.equal(status.mappings[0].rx_bytes,null);assert(rendered.includes('无记录'));
  assert(!text(api.renderReverseStatus(h,null,[normalized])).includes('未连接'),'no snapshot must not invent a disconnected state');
});
test('state text cannot substitute for authentication and saved-config failures stay readable',()=>{
  const unknown=api.reverseState({state:'online',mappings:[]});
  assert(!text(api.renderReverseStatus(h,unknown,[normalized])).includes('已认证连接'));
  const invalid=api.reverseState({connected:false,state:'error',error:'config_invalid',mappings:[]});
  assert(text(api.renderReverseStatus(h,invalid,[normalized])).includes('反向映射配置无效'));
  const occupied=api.reverseState({connected:false,state:'error',error:'port_conflict',mappings:[]});
  assert(text(api.renderReverseStatus(h,occupied,[normalized])).includes('映射端口已被占用'));
});
console.log('PASS',checks,'reverse configuration, preview and runtime cases');
