/* client Endpoint IP discovery; service-interface port and explicit reverse-exit peer. */
(function(root,factory){var api=factory();if(typeof module==='object'&&module.exports)module.exports=api;else root.WGClientConfig=api;}(this,function(){
 'use strict';
 function tr(s){return typeof window!=='undefined'&&window.WGI18n?window.WGI18n.text(s):s;}
 function ipv4(s){var p=String(s).split('.');return p.length===4&&p.every(function(v){return /^\d{1,3}$/.test(v)&&Number(v)<=255;});}
 function endpointIP(value){
  value=String(value||'');
  if(!value)throw new Error(tr('请填写客户端 Endpoint IP，或点击重新获取'));
  if(!ipv4(value))throw new Error(tr('客户端 Endpoint IP 只支持 IPv4，不要填写域名、网址或端口'));
  var parts=value.split('.').map(Number);
  if(parts[0]===0||parts[0]===127||parts[0]>=224||(parts[0]===169&&parts[1]===254))throw new Error(tr('客户端 Endpoint IP 不能使用未指定、回环、链路本地或组播等保留地址'));
  return parts.join('.');
 }
 function endpoint(value,port){
  value=endpointIP(value);
  var p=Number(port);
  if(!Number.isInteger(p)||p<1||p>65535)throw new Error(tr('服务接口监听端口无效，请先保存服务接口'));
  return value+':'+p;
 }
 function resolve(form,iface){
  return {value:endpoint(form.client_endpoint,iface.local_listenport),note:tr('端口使用服务接口当前监听值：')+iface.local_listenport+'。'};
 }
 function invalidateSingbox(v){v.wgSingboxToken=(v.wgSingboxToken||0)+1;v.wgSingboxBusy=false;v.wgSingbox=null;}
 function invalidate(v){v.tableForm.client_config='';v.tableForm.client_qr_svg='';invalidateSingbox(v);}
 function fields(v){var f=v.tableForm;['client_endpoint','exit_peer','site_local','site_remote'].forEach(function(k){if(typeof f[k]==='undefined')v.$set(f,k,k==='exit_peer'?'no':'');});}
 function cancelEndpoint(v){v.wgEndpointToken=(v.wgEndpointToken||0)+1;v.wgEndpointBusy=false;invalidateSingbox(v);}
 function cancel(v){cancelEndpoint(v);v.wgKeyRequests={};}
 function keyBusy(v){return Object.keys(v.wgKeyRequests||{}).some(function(k){return v.wgKeyRequests[k]&&v.wgKeyRequests[k].form===v.tableForm;});}
 function generateKey(v,kind,post,error){
  var fields=kind==='private'?['local_publickey','local_privatekey']:kind==='peer'?['peer_publickey','peer_privatekey']:['presharedkey'];
  var f=v.tableForm,old=fields.map(function(k){return f[k];}),request={form:f},requests=v.wgKeyRequests||{};
  function clearExport(){if(kind==='private')invalidateSingbox(v);else invalidate(v);}
  v.wgKeyRequests=Object.assign({},requests);v.$set(v.wgKeyRequests,kind,request);clearExport();
  function current(){return v.wgKeyRequests[kind]===request&&v.tableForm===f&&(kind==='private'?v.tableRowEditing:v.tableRowEditing1)!==false;}
  function unchanged(){return fields.every(function(k,i){return f[k]===old[i];});}
  return Promise.resolve().then(function(){if(!current())return null;return post({func_name:'wireguard',action:'show',param:{TYPE:kind==='shared'?'gen_sharedkey':'gen_privatekey'}});}).then(function(response){
   if(!current()||!unchanged())return false;
   var d=response&&response.data,values=d&&d.Data;
   var result=kind==='shared'?[values&&values.presharedkey]:[values&&values.pubkey,values&&values.privatekey];
   if(!d||d.Result!==30000||!result.every(function(x){return typeof x==='string'&&/^[A-Za-z0-9+/]{43}=$/.test(x)&&!/^A{43}=$/.test(x);}))throw new Error('key generation failed');
   fields.forEach(function(k,i){v.$set(f,k,result[i]);});clearExport();return true;
  }).catch(function(){if(current()&&unchanged())error(tr('密钥生成失败，请点击生成密钥重试'));return false;}).then(function(ok){if(v.wgKeyRequests[kind]===request)v.$set(v.wgKeyRequests,kind,null);return ok;});
 }
 function manual(v,value){
  cancelEndpoint(v);v.$set(v.tableForm,'client_endpoint',value);v.wgEndpointManual=true;v.wgEndpointAuto='';v.wgEndpointError='';v.wgEndpointNote=tr('手动输入 IPv4，端口使用服务接口监听值。');invalidate(v);
 }
 function request(v,post,encode,force){
  var f=v.tableForm,iface=f.interface,old=f.client_endpoint||'',token=(v.wgEndpointToken||0)+1,failure='';
  v.wgEndpointToken=token;v.wgEndpointBusy=true;v.wgEndpointError='';v.wgEndpointNote=tr('正在获取所选服务接口 WAN 的公网 IP…');invalidate(v);
  function current(){return v.wgEndpointToken===token&&v.tableForm===f&&f.interface===iface&&v.tableRowEditing1!==false;}
  return Promise.resolve().then(function(){
   if(!current())return null;
   if(!iface)throw new Error(tr('请先选择服务接口'));
   var param={TYPE:'client_endpoint',interface:iface};if(force)param.force='1';
   return post({func_name:'wireguard',action:'show',param:encode(param)});
  }).then(function(response){
   if(!current()||f.client_endpoint!==old)return false;
   if(!response||!response.data||response.data.Result!==30000)throw new Error(tr('Endpoint IP 获取失败，请重试或手动填写 IPv4'));
   var d=(response.data.Data||{}).client_endpoint,port=Number(d&&d.listen_port);
   if(Number.isInteger(port)&&port>=1&&port<=65535)(v.ifaceRows||[]).forEach(function(row){if(row.name===iface)v.$set(row,'local_listenport',port);});
   if(d&&d.source==='unavailable'){
    // Only the API's endpoint status message is shown; transport errors stay generic.
    if(typeof d.message==='string')failure=d.message.replace(/[\x00-\x1f\x7f]/g,' ').slice(0,256);
    throw new Error('unavailable');
   }
   if(!d||['public','wan'].indexOf(d.source)<0)throw new Error('invalid endpoint response');
   var ip=endpointIP(d.ip);
   v.$set(f,'client_endpoint',ip);v.wgEndpointAuto=ip;v.wgEndpointManual=false;v.wgEndpointError='';
   v.wgEndpointNote=d.source==='public'?tr('已获取 ')+(d.wan||tr('所选 WAN'))+tr(' 公网 IP：')+ip+'。':tr('公网 IP 探测未成功，已回填 ')+(d.wan||tr('所选 WAN'))+tr(' 本机 IP：')+ip+'。';
   return true;
  }).catch(function(){
   if(current()){v.wgEndpointError=(failure||tr('Endpoint IP 获取失败，请重试或手动填写 IPv4。'))+(old?tr(' 已保留原有填写值。'):'');v.wgEndpointNote=old?tr('已保留原有填写值。'):'';}
   return false;
  }).then(function(ok){if(current())v.wgEndpointBusy=false;return ok;});
 }
 function open(v,post,encode){
  cancelEndpoint(v);fields(v);var f=v.tableForm,m=String(f.client_endpoint||'').match(/^([^:]+):[0-9]+$/);
  if(m&&ipv4(m[1]))v.$set(f,'client_endpoint',m[1]);
  v.wgEndpointForm=f;v.wgEndpointAuto='';v.wgEndpointManual=!!f.client_endpoint;v.wgEndpointError='';invalidate(v);
  if(!f.client_endpoint)return request(v,post,encode);
  v.wgEndpointNote=ipv4(f.client_endpoint)?tr('已保留原有 Endpoint IP；端口使用服务接口当前监听值。'):tr('原有 Endpoint 使用域名或旧格式。请手动改为 IPv4，或点击重新获取后再保存、生成配置。');
  return Promise.resolve(false);
 }
 function changed(v,post,encode){
  if(v.wgEndpointForm!==v.tableForm)return open(v,post,encode);
  cancelEndpoint(v);var f=v.tableForm;v.wgEndpointError='';invalidate(v);
  if(!v.wgEndpointManual&&(!f.client_endpoint||f.client_endpoint===v.wgEndpointAuto)){v.$set(f,'client_endpoint','');v.wgEndpointAuto='';return request(v,post,encode);}
  v.wgEndpointNote=tr('已保留手动 Endpoint；请确认它适用于当前服务接口，或点击重新获取。');
  return Promise.resolve(false);
 }
 function siteNets(value){
  value=String(value||'');if(!value)return [];
  if(value.length>1024||/[^0-9./,\s]/.test(value))throw new Error(tr('互访网段格式无效'));
  var list=value.split(/[,\s]+/).filter(Boolean),out=[];
  if(list.length>8)throw new Error(tr('每端最多填写 8 个互访网段'));
  list.forEach(function(v){var a=v.split('/'),bits=a.length===1?32:Number(a[1]);
   if(a.length>2||!ipv4(a[0])||!Number.isInteger(bits)||bits<0||bits>32||a.length===2&&!/^\d{1,2}$/.test(a[1]))throw new Error(tr('互访网段须为有效 IPv4 网段'));
   var host=a[0].split('.').reduce(function(n,x){return n*256+Number(x);},0),size=Math.pow(2,32-bits),lo=Math.floor(host/size)*size,hi=lo+size-1;
   if(![[167772160,184549375],[2886729728,2887778303],[3232235520,3232301055],[1681915904,1686110207]].some(function(r){return lo>=r[0]&&hi<=r[1];}))throw new Error(tr('互访网段只支持私有 IPv4 和 100.64.0.0/10'));
   if(out.some(function(r){return lo<=r.hi&&r.lo<=hi;}))throw new Error(tr('同侧互访网段不能重叠'));
   var n=lo,parts=[];[3,2,1,0].forEach(function(i){var x=Math.floor(n/Math.pow(256,i));parts.push(x);n-=x*Math.pow(256,i);});
   out.push({lo:lo,hi:hi,text:parts.join('.')+'/'+bits});
  });return out;
 }
 function siteFields(local,remote){
  var l=siteNets(local),r=siteNets(remote);
  if((l.length===0)!==(r.length===0))throw new Error(tr('请同时填写本端和对端互访网段；不需要互访时两项留空'));
  if(l.some(function(a){return r.some(function(b){return a.lo<=b.hi&&b.lo<=a.hi;});}))throw new Error(tr('两端互访网段不能重叠'));
  return {local:l.map(function(n){return n.text;}),remote:r.map(function(n){return n.text;})};
 }
 function validate(v){
  var f=v.tableForm,iface=v.getIfaceRow();
  if(keyBusy(v))throw new Error(tr('正在生成密钥，请稍候'));
  var site=siteFields(f.site_local,f.site_remote);f.site_local=site.local.join(',');f.site_remote=site.remote.join(',');
  if(v.wgEndpointBusy)throw new Error(tr('正在获取 Endpoint IP，请稍候或手动填写 IPv4'));
  endpoint(f.client_endpoint,iface.local_listenport);f.client_endpoint=endpointIP(f.client_endpoint);
  if(f.exit_peer==='yes'){
   var addresses=String(f.allowips||'').split(/[,\s]+/).filter(Boolean);
   if(addresses.length!==1||!ipv4(addresses[0].replace(/\/32$/,''))||addresses[0].indexOf('/')>=0&&!/\/32$/.test(addresses[0]))throw new Error(tr('分流出口隧道须使用独立的 /32 对端地址'));
  }
 }
 function exportMatches(v){
  try{
   var expected=endpoint(v.tableForm.client_endpoint,v.getIfaceRow().local_listenport),matches=String(v.tableForm.client_config||'').match(/^\s*Endpoint\s*=.*$/gmi)||[];
   return !v.wgEndpointBusy&&matches.length===1&&matches[0].replace(/^\s*Endpoint\s*=\s*/i,'').trim()===expected;
  }catch(e){return false;}
 }
 function validateExport(v){
  validate(v);
  if(!exportMatches(v))throw new Error(tr('配置中的 Endpoint 与当前 IP／监听端口不一致，请重新生成配置'));
 }
 function build(v,router,prompt,error){
  try{
   if(v.wgPlanBusy)throw new Error(tr('正在分配地址，请稍候'));
   var f=v.tableForm,iface=v.getIfaceRow();validate(v);
   if(!f.peer_privatekey)throw new Error(tr('缺少对端私钥，请先生成对端密钥或手动填写对端私钥'));
   if(!iface.local_publickey)throw new Error(tr('找不到服务接口参数，请先保存服务接口'));
   var addr=String(f.allowips||'').split(/[,\s]+/).filter(Boolean)[0];
   if(!addr||!ipv4(addr.split('/')[0])||/^0\.0\.0\.0(?:\/0)?$/.test(addr))throw new Error(tr('请填写对端 WireGuard 地址，不能把默认路由作为客户端地址'));
   var site=siteFields(f.site_local,f.site_remote),hasSite=site.local.length>0;
   var reverse=f.exit_peer==='yes',allowed='0.0.0.0/0',remote=String(iface.local_address||'').split('/')[0]+'/32';
   if(reverse||router||hasSite){
    if(!ipv4(remote.split('/')[0]))throw new Error(tr('服务接口地址无效'));
    allowed=[remote].concat(site.local).join(',');
    if(router&&!reverse&&!hasSite){var input=prompt(tr('填写对端导入后允许访问的本端网段，多个用逗号分隔'),remote);if(input===null)return false;allowed=(input||remote).replace(/[\n，]/g,',').replace(/\s+/g,'');}
   }
   if(!allowed.split(',').every(function(n){var p=n.split('/');return ipv4(p[0])&&(p.length===1||(p.length===2&&/^\d+$/.test(p[1])&&Number(p[1])<=32));}))throw new Error(tr('允许地址必须是 IPv4 地址或网段'));
   var ep=resolve(f,iface),keep=Number(f.keepalive||25);
   if(!Number.isInteger(keep)||keep<0||keep>65535)throw new Error(tr('心跳间隔无效'));
   if(reverse&&keep===0)keep=25;
   var lines=['[Interface]','PrivateKey = '+f.peer_privatekey,'Address = '+addr];
   if(f.client_dns){if(/[\r\n]/.test(f.client_dns))throw new Error(tr('DNS 地址格式无效'));lines.push('DNS = '+f.client_dns);}
   lines.push('','[Peer]','PublicKey = '+iface.local_publickey);
   if(f.presharedkey)lines.push('PresharedKey = '+f.presharedkey);
   lines.push('AllowedIPs = '+allowed);
   if(hasSite){lines.push('# iKuai-Site-Local = '+site.remote.join(','));lines.push('# iKuai-Site-Remote = '+site.local.join(','));}
   lines.push('Endpoint = '+ep.value);
   if(keep)lines.push('PersistentKeepalive = '+keep);
   f.client_config=lines.join('\n');f.client_qr_svg=router?'':v.makeQrSvg(f.client_config);return true;
  }catch(e){invalidate(v);error(e.message||tr('生成配置失败'));return false;}
 }
 function render(v,h){
  var f=v.tableForm,iface=v.getIfaceRow(),note=v.wgEndpointBusy?tr('正在获取所选服务接口 WAN 的公网 IP…'):v.wgEndpointError||v.wgEndpointNote||tr('请填写 IPv4，或点击重新获取。');
  var siteRows=[['site_local',tr('本端互访网段：'),tr('例如 192.168.10.0/24')],['site_remote',tr('对端互访网段：'),tr('例如 192.168.20.0/24')]].map(function(row){return h('div',{staticClass:'line_edit'},[h('div',{staticClass:'input_tit'},[row[1]]),h('div',{staticClass:'input_group'},[h('textarea',{staticClass:'inptText',attrs:{name:row[0],rows:2,placeholder:row[2],maxlength:1024},domProps:{value:f[row[0]]||''},on:{input:function(e){v.$set(f,row[0],e.target.value);invalidate(v);}}}),h('p',{staticClass:'note'},[row[0]==='site_local'?tr('选填，每行一个网段。两项同时填写，指定内网之间保留源 IP，直接经 WG 互访；其他流量仍按分流规则处理。'):tr('两端网段不能重叠。生成的组网配置会自动带上双方网段；也可同时勾选“用作分流出口”。')])])]);});
  return h('div',[
   h('div',{staticClass:'line_edit'},[
    h('div',{staticClass:'input_tit'},[tr('客户端 Endpoint IP：')]),
    h('div',{staticClass:'input_group'},[
     h('input',{staticClass:'inptText',attrs:{type:'text',name:'client_endpoint',placeholder:tr('IPv4，例如 203.0.113.10'),maxlength:259},domProps:{value:f.client_endpoint||''},on:{input:function(e){manual(v,e.target.value);}}}),
     h('button',{staticClass:'btn margin-l-10',attrs:{type:'button',disabled:v.wgEndpointBusy},on:{click:function(){v.refreshClientEndpoint();}}},[v.wgEndpointBusy?tr('获取中…'):tr('重新获取')]),
     h('p',{staticClass:v.wgEndpointError?'error_tip':'note',attrs:{role:'status','aria-live':'polite'}},[note]),
     h('p',{staticClass:'note'},[tr('Endpoint 端口：')+(iface.local_listenport||tr('未设置'))+tr('（取服务接口监听端口）')])
    ])
   ]),
   h('div',{staticClass:'line_edit'},[
    h('div',{staticClass:'input_tit'},[tr('分流出口：')]),
    h('div',{staticClass:'input_group'},[
     h('label',[
      h('input',{attrs:{type:'checkbox',name:'exit_peer'},domProps:{checked:f.exit_peer==='yes'},on:{change:function(e){v.$set(f,'exit_peer',e.target.checked?'yes':'no');invalidate(v);}}}), tr(' 用作分流出口')
     ]),
     h('p',{staticClass:'note'},[tr('对端路由器须独占本服务接口。开启后，本机可按分流规则经它上网；对端保持自己的 WAN 默认出口。')]),
     f.exit_peer==='yes'?h('p',{staticClass:'note'},[tr('生成的配置供出口路由器导入，保留其 WAN 默认路由并启用心跳。对端 IP／域名可留空，由对端主动连接。')]):null
    ])
   ])
  ].concat(siteRows));
 }
 return {siteFields:siteFields,siteNets:siteNets,endpoint:endpoint,endpointIP:endpointIP,resolve:resolve,open:open,changed:changed,request:request,cancel:cancel,manual:manual,validate:validate,validateExport:validateExport,exportMatches:exportMatches,build:build,render:render,fields:fields,invalidate:invalidate,keyBusy:keyBusy,generateKey:generateKey};
}));
