/* Local sing-box WireGuard endpoint export. See docs/SINGBOX-EXPORT.md for wire formats. */
(function(root,factory){var api=factory();if(typeof module==='object'&&module.exports)module.exports=api;else root.WGSingBox=api;}(this,function(){
 'use strict';
 function tr(s){return typeof window!=='undefined'&&window.WGI18n?window.WGI18n.text(s):s;}
 function base64(s){return typeof btoa==='function'?btoa(s):Buffer.from(s,'binary').toString('base64');}
 function unbase64(s){return typeof atob==='function'?atob(s):Buffer.from(s,'base64').toString('binary');}
 function key(s){return typeof s==='string'&&/^[A-Za-z0-9+/]{43}=$/.test(s)&&unbase64(s).length===32&&base64(unbase64(s))===s;}
 function config(v,client){
  if(v.wgPlanBusy)throw new Error(tr('正在分配地址，请稍候'));
  client.validate(v);
  var f=v.tableForm,i=v.getIfaceRow();
  if(f.exit_peer!=='yes')throw new Error(tr('请先勾选“用作分流出口”，并让此手机独占一个 WG 服务接口'));
  if(!key(f.peer_privatekey)||!key(i.local_publickey)||/^A{43}=$/.test(i.local_publickey))throw new Error(tr('对端私钥或服务接口公钥无效，请先生成并保存匹配的密钥'));
  if(f.presharedkey&&!key(f.presharedkey))throw new Error(tr('预共享密钥格式无效'));
  if(f.site_local||f.site_remote)throw new Error(tr('手机出口配置不支持两端内网互访，请使用单独的出口隧道并清空互访网段'));
  var address=client.endpointIP(String(f.allowips).trim().replace(/\/32$/,''))+'/32';
  var keep=Number(f.keepalive||25);
  if(!Number.isInteger(keep)||keep<0||keep>65535)throw new Error(tr('心跳间隔无效'));
  var peer={address:client.endpointIP(f.client_endpoint),port:Number(i.local_listenport),public_key:i.local_publickey,allowed_ips:['0.0.0.0/0'],persistent_keepalive_interval:keep||25};
  if(f.presharedkey)peer.pre_shared_key=f.presharedkey;
  // The userspace endpoint receives the router's flows. Only direct is an egress;
  // selecting the WG endpoint as final would send those flows back to the router.
  var tun=/^172\.19\.0\.[0-3]\//.test(address)?'172.19.0.5/30':'172.19.0.1/30';
  return {
   log:{level:'warn'},
   dns:{servers:[{type:'local',tag:'phone-dns'}]},
   inbounds:[{type:'tun',tag:'phone-tun',address:[tun],auto_route:true,stack:'gvisor'}],
   endpoints:[{type:'wireguard',tag:'router-wg',system:false,mtu:1408,address:[address],private_key:f.peer_privatekey,peers:[peer]}],
   outbounds:[{type:'direct',tag:'phone-internet'}],
   route:{rules:[{inbound:['phone-tun'],port:53,action:'hijack-dns'}],final:'phone-internet',default_domain_resolver:'phone-dns',auto_detect_interface:true}
  };
 }
 var peerFields=['id','interface','enabled','exit_peer','allowips','peer_privatekey','peer_publickey','presharedkey','client_endpoint','client_dns','keepalive','site_local','site_remote','endpoint','endpoint_port'];
 var ifaceFields=['name','enabled','interface','local_publickey','local_address','local_listenport'];
 function value(row,k){var s=String(row[k]==null?'':row[k]);return ['allowips','site_local','site_remote'].indexOf(k)>=0?s.split(/[,\s]+/).filter(Boolean).join(','):s;}
 function values(row,fields){return fields.map(function(k){return value(row,k);});}
 function signature(v){return JSON.stringify([values(v.tableForm,peerFields),values(v.getIfaceRow(),ifaceFields)]);}
 function matches(v){return !!v.wgSingbox&&v.wgSingbox.form===v.tableForm&&!v.wgSingboxBusy&&!v.wgEndpointBusy&&!v.wgPlanBusy&&v.wgSingbox.signature===signature(v);}
 function le(n){return String.fromCharCode(n&255,(n>>>8)&255,(n>>>16)&255,(n>>>24)&255);}
 function be(n){return String.fromCharCode((n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255);}
 function crc32(s){var c=0xffffffff;for(var i=0;i<s.length;i++){c^=s.charCodeAt(i);for(var j=0;j<8;j++)c=(c>>>1)^((c&1)?0xedb88320:0);}return (c^0xffffffff)>>>0;}
 function utf8(s){return unescape(encodeURIComponent(s));}
 function string(s){s=utf8(s);var n=s.length,out='';do{out+=String.fromCharCode((n&127)|(n>127?128:0));n=Math.floor(n/128);}while(n);return out+s;}
 // One stored DEFLATE block inside gzip: deterministic and no browser compression
 // API or third-party service. The bounded compact profile fits one QR symbol.
 function gzip(s){var n=s.length;if(n>65535)throw new Error('profile too large');return '\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x01'+String.fromCharCode(n&255,n>>>8,(~n)&255,((~n)>>>8)&255)+s+le(crc32(s))+le(n);}
 function profile(c){return '\x03\x01'+gzip(string('iKuai phone exit')+'\x00\x00\x00\x00'+string(JSON.stringify(c)));}
 function qrs(c){
  var p=profile(c),meta=utf8(JSON.stringify({filename:'ikuai-phone-exit.bpf',contentType:'application/octet-stream'}));
  var data=be(meta.length)+meta+be(p.length)+p;
  // QRS degree=1, index=0, k=1; CRC is over uncompressed data, XOR k.
  // The Apple in-app scanner accepts base64 directly. No web URL/upload is needed.
  var payload=base64(le(1)+le(0)+le(1)+le(data.length)+le(crc32(data)^1)+data);
  if(payload.length>2200)throw new Error(tr('配置超过单张二维码容量，请下载 JSON 文件导入'));
  return payload;
 }
 function build(v,client,error,post){
  var f=v.tableForm,token=(v.wgSingboxToken||0)+1,start,failure='';
  v.wgSingboxToken=token;v.wgSingbox=null;v.wgSingboxBusy=true;
  function alive(){return v.wgSingboxToken===token&&v.tableForm===f&&v.tableRowEditing1!==false;}
  function unchanged(){return signature(v)===start&&!v.wgEndpointBusy&&!v.wgPlanBusy&&!client.keyBusy(v);}
  function fail(message){failure=message;throw new Error('export validation failed');}
  return Promise.resolve().then(function(){
   if(!alive())return null;
   if(!/^[1-9][0-9]*$/.test(String(f.id||'')))fail(tr('请先保存隧道，再重新打开编辑页生成 sing-box 配置'));
   if(client.keyBusy(v))fail(tr('正在生成密钥，请稍候'));
   if(f.enabled!=='yes'||v.getIfaceRow().enabled!=='yes')fail(tr('请先启用隧道和服务接口，再生成 sing-box 配置'));
   try{config(v,client);}catch(e){fail(e.message||tr('生成配置失败'));}start=signature(v);
   var q={func_name:'wireguard',action:'show',param:{TYPE:'client_export',peer_id:String(f.id)}};
   return (post||function(request){return v.$http.post(v.tableOptions.requests.url,request);})(q);
  }).then(function(response){
   if(!alive())return false;
   if(!unchanged())fail(tr('隧道参数已变化，请重新生成 sing-box 配置'));
   var d=response&&response.data,saved=d&&d.Data&&d.Data.client_export;
   if(!d||d.Result!==30000||!saved||!saved.peer||!saved.iface)fail(tr('无法核对已保存配置，请确认隧道和服务接口已启用、密钥匹配，再保存并刷新后重试'));
   if(saved.keypair_valid!==true)fail(tr('对端私钥与已保存的公钥不匹配，请重新生成并保存密钥'));
   if(saved.peer.enabled!=='yes'||saved.iface.enabled!=='yes')fail(tr('请先启用隧道和服务接口，再生成 sing-box 配置'));
   if(JSON.stringify(values(f,peerFields))!==JSON.stringify(values(saved.peer,peerFields)))fail(tr('隧道存在未保存的更改，请先保存，再重新打开编辑页生成配置'));
   if(JSON.stringify(values(v.getIfaceRow(),ifaceFields))!==JSON.stringify(values(saved.iface,ifaceFields)))fail(tr('服务接口设置已变化，请刷新页面后重新生成配置'));
   // Only the locked, persisted snapshot supplies export data. The server has
   // checked both key pairs and that this enabled peer owns its exit interface.
   var c=config({tableForm:saved.peer,getIfaceRow:function(){return saved.iface;}},client),json=JSON.stringify(c,null,2),qr=v.makeQrSvg(qrs(c));
   if(!qr)fail(tr('二维码生成失败，请重新生成'));
   if(!alive())return false;
   if(!unchanged())fail(tr('隧道参数已变化，请重新生成 sing-box 配置'));
   v.wgSingbox={form:f,signature:start,json:json,qr:qr};return true;
  }).catch(function(){if(alive())error(failure||tr('无法核对已保存配置，请确认隧道和服务接口已启用、密钥匹配，再保存并刷新后重试'));return false;}).then(function(ok){if(v.wgSingboxToken===token)v.wgSingboxBusy=false;return ok;});
 }
 function download(v,error){
  if(!matches(v)){error(tr('隧道参数已变化，请重新生成 sing-box 配置'));return false;}
  var url=URL.createObjectURL(new Blob([v.wgSingbox.json+'\n'],{type:'application/json'}));
  var a=document.createElement('a');a.href=url;a.download='ikuai-phone-exit.json';document.body.appendChild(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(url);},1000);return true;
 }
 function render(v,h,client,error){
  var ok=matches(v),state=v.wgSingbox;
  return h('div',{staticClass:'wg-singbox'},[
   h('div',{staticClass:'line_edit'},[h('div',{staticClass:'input_tit'},[tr('iPhone 上网出口：')]),h('div',{staticClass:'input_group'},[
    h('button',{staticClass:'btn btn_blue',attrs:{type:'button',disabled:v.wgSingboxBusy||v.wgEndpointBusy||v.wgPlanBusy||client.keyBusy(v)},on:{click:function(){build(v,client,error);}}},[v.wgSingboxBusy?tr('正在核对已保存配置…'):tr('生成 sing-box JSON／二维码')]),
    h('button',{staticClass:'btn margin-l-10',attrs:{type:'button',disabled:!ok},on:{click:function(){download(v,error);}}},[tr('下载 JSON')]),
    h('p',{staticClass:'note'},[tr('适用于 sing-box MT 1.14.8。手机主动连接此路由器；异地设备经分流规则选择该 WG 出口，从手机当前的蜂窝网络或 Wi-Fi 上网。')]),
    h('p',{staticClass:'note'},[tr('请先保存出口隧道并重新打开编辑页，再生成配置；在分流设置中选择其 WG 接口。手机须独占本服务接口，其他接入设备使用另一个服务接口。')]),
    h('p',{staticClass:'note'},[tr('此配置会占用 iPhone 的 VPN 连接，不能与另一 VPN 同时运行；手机断网或 App 停止时出口不可用。当前转发范围为 IPv4 TCP／UDP。')]),
    h('p',{staticClass:'note'},[tr('iPhone 锁屏或切换 Wi-Fi／蜂窝网络后，请检查异地设备能否继续上网；若中断，请先在手机上重新连接。此配置不能保证后台持续转发。')]),
    state&&!ok?h('p',{staticClass:'error_tip',attrs:{role:'status'}},[tr('隧道参数已变化，请重新生成 sing-box 配置')]):null
   ])]),
   ok?h('div',{staticClass:'line_edit'},[h('div',{staticClass:'input_tit'},['sing-box JSON']),h('div',{staticClass:'input_group'},[h('textarea',{staticClass:'inptText',attrs:{rows:10,readonly:true,'aria-label':'sing-box JSON'},domProps:{value:state.json}})])]):null,
   ok?h('div',{staticClass:'line_edit'},[h('div',{staticClass:'input_tit'},[tr('sing-box 离线二维码：')]),h('div',{staticClass:'input_group'},[
    h('p',{staticClass:'note'},[tr('在 sing-box App 内使用“扫描二维码”导入。不要用系统相机或其他扫码网站；二维码和 JSON 含私钥，请妥善保管。也可下载 JSON 后从文件导入。')]),
    h('div',{staticClass:'wg-singbox-qr',style:{width:'min(100%, 620px)'},domProps:{innerHTML:state.qr}})
   ])]):null
  ]);
 }
 return {config:config,signature:signature,matches:matches,crc32:crc32,profile:profile,qrs:qrs,build:build,download:download,render:render};
}));
