/* authoritative suggestions, race-safe form updates, no legacy renumbering. */
(function(root,factory){var api=factory();if(typeof module==='object'&&module.exports)module.exports=api;else root.WGAddressPlan=api;}(this,function(){
 'use strict';
 function tr(s){return typeof window!=='undefined'&&window.WGI18n?window.WGI18n.text(s):s;}
 function preserve(v){v.wgPlanToken=(v.wgPlanToken||0)+1;v.wgPlanBusy=false;v.wgPlanError='';v.wgAutoAddress='';v.wgAutoDns='';}
 function request(v,post,encode,kind,force){
  var form=v.tableForm,iface=kind==='peer'?form.interface:'',token=(v.wgPlanToken||0)+1;
  v.wgPlanToken=token;v.wgPlanBusy=true;v.wgPlanError='';
  var oldAddress=kind==='peer'?form.allowips:form.local_address,oldDns=form.client_dns;
  var replaceAddress=!!force||!oldAddress||(kind==='peer'&&oldAddress===v.wgAutoAddress);
  var replaceDns=!oldDns||oldDns===v.wgAutoDns;
  var payload={func_name:'wireguard',action:'show',param:encode({TYPE:'defaults',interface:iface})};
  return post(payload).catch(function(error){
   if(v.wgPlanToken!==token||v.tableForm!==form)throw error;
   // Retry a read-only suggestion once; never retry a configuration save.
   return post(payload);
  }).then(function(response){
   if(v.wgPlanToken!==token||v.tableForm!==form||(kind==='peer'&&form.interface!==iface))return false;
   if(!response||!response.data||response.data.Result!==30000)throw new Error(tr('地址规划读取失败，请重试'));
   var d=response.data.Data||{},p=kind==='peer'?d.peer_defaults:d.iface_defaults;
   if(!p||p.error)throw new Error((p&&p.error)||tr('没有可用的默认地址，请手动规划'));
   if(kind==='peer'){
    if(p.interface!==iface)throw new Error(tr('接口已变化，请重新分配地址'));
    if(replaceAddress&&form.allowips===oldAddress){v.$set(form,'allowips',p.allowips);v.wgAutoAddress=p.allowips;form.client_config='';form.client_qr_svg='';}
    if(replaceDns&&form.client_dns===oldDns){v.$set(form,'client_dns',p.client_dns);v.wgAutoDns=p.client_dns;}
    v.wgPlanNetwork=p.source_network||'';
   }else{
    if(!form.local_address)v.$set(form,'local_address',p.local_address);
    if(!form.local_listenport)v.$set(form,'local_listenport',p.local_listenport);
    if(!form.name||form.name==='wg')v.$set(form,'name',p.name);
   }
   return true;
  }).catch(function(error){
   if(v.wgPlanToken===token&&v.tableForm===form){
    v.wgPlanError=/network|timeout/i.test(error.message||'')?tr('地址规划请求未完成，请点击重新分配或手动填写'):(error.message||tr('地址规划失败，请重试'));
    // Never leave the previous interface's generated address on a new interface.
    if(kind==='peer'&&replaceAddress&&form.allowips===oldAddress){v.$set(form,'allowips','');v.wgAutoAddress='';}
   }
   return false;
  }).then(function(ok){if(v.wgPlanToken===token&&v.tableForm===form)v.wgPlanBusy=false;return ok;});
 }
 function openIface(v,post,encode){
  preserve(v);v.tableForm={name:'wg',local_address:'',interface:'auto',local_listenport:'',local_publickey:'',local_privatekey:'',mtu:1420,enabled:'yes'};
  v.shouHint=false;v.tableRowEditing=true;var form=v.tableForm;
  return request(v,post,encode,'iface',false).then(function(ok){if(v.tableForm===form&&!v.shouHint)v.getPrivateKey();return ok;});
 }
 function openPeer(v,post,encode){
  preserve(v);v.wgImportNote='';v.wgPlanNetwork='';
  if(!v.interfaces1.length){v.wgPlanError=tr('请先创建 WG 服务接口');return Promise.resolve(false);}
  v.tableForm={client_endpoint:'',exit_peer:'no',endpoint:'',interface:v.interfaces1[0],peer_publickey:'',peer_privatekey:'',presharedkey:'',endpoint_port:'',keepalive:25,allowips:'',enabled:'yes',comment:'',client_dns:'',client_config:'',client_qr_svg:''};
  v.shouHint=false;v.tableRowEditing1=true;var form=v.tableForm;
  return request(v,post,encode,'peer',false).then(function(ok){if(v.tableForm===form&&!v.shouHint)v.getPeerKey();return ok;});
 }
 function changed(v,post,encode){
  // Existing and imported addresses are deliberate. Automatic replacement is
  // limited to untouched suggestions in new-client forms.
  if(v.shouHint){preserve(v);v.tableForm.client_config='';v.tableForm.client_qr_svg='';return Promise.resolve(false);}
  return request(v,post,encode,'peer',false);
 }
 function render(v,h){
  return h('div',{staticClass:'line_edit'},[
   h('div',{staticClass:'input_tit'},[tr('地址规划：')]),
   h('div',{staticClass:'input_group'},[
    h('p',{staticClass:v.wgPlanError?'error_tip':'note',attrs:{role:'status'}},[v.wgPlanBusy?tr('正在查找未使用地址…'):v.wgPlanError||(v.wgPlanNetwork?tr('本接口源网段：')+v.wgPlanNetwork+tr('；客户端使用独立 /32 地址。'):tr('新增客户端按所选接口分配 /32 地址；手动输入和已有地址保留。'))]),
    h('button',{staticClass:'btn',attrs:{type:'button',disabled:v.wgPlanBusy},on:{click:function(){v.allocatePeerAddress();}}},[tr('分配可用地址')])
   ])
  ]);
 }
 return {preserve:preserve,request:request,openIface:openIface,openPeer:openPeer,changed:changed,render:render};
}));
