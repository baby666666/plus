webpackJsonp([115],{1668:function(e,t,a){"use strict";Object.defineProperty(t,"__esModule",{value:!0});var s=a(80),i=a.n(s),l=a(78);t.default={data:function(){return{tableOptions:{clickToEdit:!1,rowEditFormat:"tableForm",tableClass:"table table_w checkbox_checked",tableOperation:[{type:"addRow",disable:!1},{type:"importFile",disable:!1},{type:"exportFile",disable:!1},{type:"batchEnableRows",disable:!1},{type:"batchDisableRows",disable:!1},{type:"batchDeleteRows",disable:!1},{type:"reorderRows",disable:!1},{type:"autoRefresh",disable:!1}],pagination:{paginateable:!0},requests:{getInterface:!0,param:{TYPE:"total,data",ORDER_BY:"id",ORDER:"desc"},url:l.a.apiUrl,funcName:"stream_domain",listAction:"show",delRowAction:"del",enableRowAction:"up",disableRowAction:"down",addRowAction:"add",editRowAction:"edit"},fixColumns:["id","buttons","checkbox","enabled"],columns:[{name:"id",display:"id",headerLabel:"common.table_num",dataLabel:"",cls:{headerClass:"td_tc num",cellClass:"td_tc"}},{name:"interface",display:"interfaces",headerLabel:"network.flow.header_title.interface",validate:{reg:"required"},cls:{headerClass:"",cellClass:""},addDefault:"",orderable:!1},{name:"domain",display:"customHtmlFunction",headerLabel:"common.domain",validate:{reg:"required|domain|strLenBetween:0,500"},cls:{headerClass:"",cellClass:""},addDefault:"",dataFunction:function(e,t){for(var a=e.split(","),s="",i=Math.min(10,a.length),l=0;l<i;l++)s+="<span>"+a[l]+"</span><br>";return 10<a.length&&(s+="<span>...</span>"),s}},{name:"src_addr",display:"customHtmlFunction",headerLabel:"behavior.pro_control.header_title.src_addr",validate:{reg:"required|domain|strLenBetween:0,500"},cls:{headerClass:"",cellClass:""},addDefault:"",dataFunction:function(e,t){for(var a=e.split(","),s="",i=0;i<a.length;i++)s+="<span>"+a[i]+"</span><br>";return s}},{name:"week",display:"text",headerLabel:"service.url_jump.header_title.week",validate:{reg:"required"},cls:{headerClass:"",cellClass:""},addDefault:""},{name:"time",display:"text",headerLabel:"service.url_jump.header_title.time",validate:{reg:"required"},cls:{headerClass:"",cellClass:""},addDefault:""},{name:"comment",display:"text",headerLabel:"common.comment",validate:{reg:"strLenBetween:0,64"},cls:{headerClass:"",cellClass:""},addDefault:"",orderable:!1},{name:"enabled",headerLabel:"common.enabled",display:"enabled",cls:{headerClass:"",cellClass:""},addDefault:"yes"},{name:"buttons",headerLabel:"common.operation",display:"buttons",cls:{headerClass:"",cellClass:"td_opear"},buttonsList:[{type:"editRow",disable:!1},{type:"copyRow",disable:!1},{type:"disableRow",disable:!1},{type:"enableRow",disable:!1},{type:"deleteRow",disable:!1}]},{name:"checkbox",headerLabel:"",display:"checkbox",cls:{headerClass:"td_check tc tm",cellClass:"tc tm"}}]},tableRowEditing:!1,tableForm:{},interfaces:[],searchText:""}},created:function(){this.initPage()},methods:{initPage:function(){var e=this;e.$http.post(e.tableOptions.requests.url,{func_name:e.tableOptions.requests.funcName,action:"show",param:{TYPE:"interface"}}).then(function(t){e.interfaces=t.data.Data.interface})},newTableRow:function(){this.tableForm={interface:"",src_addr:"",domain:"",comment:"",week:"1234567",time:"00:00-23:59",enabled:"yes"},this.tableRowEditing=!0},saveForm:function(){if(""===this.tableForm.interface)return customError(this.$t("network.protocal.saveError.1")),!1;if(""===this.tableForm.week)return customError(this.$t("behavior.pro_control.error.week")),!1;var e=this,t=void 0==this.tableForm.id?this.tableOptions.requests.addRowAction:this.tableOptions.requests.editRowAction,a={func_name:e.tableOptions.requests.funcName,action:t,param:this.tableForm};return this.$validator.validateAll({comment:a.param.comment,src_addr:a.param.src_addr,domain:a.param.domain,time:a.param.time}).then(function(t){if(!t)return!1;var s=copyObj("encode",a);s.param.domain=s.param.domain.replace(/%20/g,",");return e.$http.post(l.a.apiUrl,s).then(function(r){if(r.data.Result!==30000)throw Error(r.data.ErrMsg||"保存未完成");var table=e.$refs.dtable,added=a.action===e.tableOptions.requests.addRowAction;if(added){/* reload(true) resets only the request offset and page input. */table.number_page=0;table.paginationOptions.currentPage=1;}e.tableRowEditing=!1,table.reload(added),customSuccess(e.$t("common.saveSuccess"))})})},editTableRow:function(e){this.tableRowEditing=!0;for(var t=e.domain.split(","),a="",s=0;s<t.length;s++)a+=t[s]+"\n";e.domain=a.substring("0",a.length-1),this.tableForm=JSON.parse(i()(e))},copyTableRow:function(e){this.tableRowEditing=!0;for(var t=e.domain.split(","),a="",s=0;s<t.length;s++)a+=t[s]+"\n";e.domain=a.substring("0",a.length-1),this.tableForm=JSON.parse(i()(e)),this.tableForm.id=void 0},cancel:function(){this.$refs.dtable.reload()},search:function(){this.tableOptions.requests.param.FINDS="src_addr,comment,domain",this.tableOptions.requests.param.KEYWORDS=this.searchText?this.searchText:"",this.$refs.dtable.search()}}}},1900:function(e,t,a){t=e.exports=a(759)(),t.push([e.i,"",""])},2068:function(e,t,a){var s=a(1900);"string"==typeof s&&(s=[[e.i,s,""]]),s.locals&&(e.exports=s.locals);a(760)("693faa85",s,!0)},2312:function(e,t){e.exports={render:function(){var e=this,t=e.$createElement,a=e._self._c||t;return a("div",{staticClass:"qaq3"},[a("div",{directives:[{name:"show",rawName:"v-show",value:!e.tableRowEditing,expression:"!tableRowEditing"}]},[a("sub-title-section",{attrs:{opturl:{helpUrl:"id=148&Itemid=255"},opt:{helpMessage:e.$t("helpTip.domainflowTip")}}}),e._v(" "),a("div",{staticClass:"wrapper row"},[a("div",{staticClass:"box clearfix"},[a("div",{staticClass:"h5"}),e._v(" "),a("d-table",{ref:"dtable",attrs:{opt:e.tableOptions},on:{tableLoaded:function(t){e.globalBus.$emit("loadComplete")},editTableRow:e.editTableRow,copyTableRow:e.copyTableRow,newTableRow:e.newTableRow}},[a("div",{staticClass:"fl table_refresh",slot:"searchArea"},[a("div",{staticClass:"search_list"},[a("input",{directives:[{name:"model",rawName:"v-model",value:e.searchText,expression:"searchText"}],staticClass:"focuseText inptText search_inpt search_inpt",attrs:{placeholder:e.$t("network.flow.header_title.domain_tip"),type:"text"},domProps:{value:e.searchText},on:{change:function(t){e.search()},input:function(t){t.target.composing||(e.searchText=t.target.value)}}}),e._v(" "),a("input",{staticClass:"search_icon",attrs:{type:"button"}})])])]),e._v(" "),a("div",{staticClass:"readme"},[a("span",{staticClass:"note"},[e._v(e._s(e.$t("domain_flow.help"))+"：")]),e._v(" "),a("div",[e._v(e._s(e.$t("domain_flow.helpTip1")))])])],1)])],1),e._v(" "),e.tableRowEditing?a("div",{staticClass:"main_section_edit"},[a("div",{staticClass:"title_h3"},[a("h3",[e._v(e._s(e.tableForm.id?e.$t("common.edit"):e.$t("common.add")))]),e._v(" "),a("div",{staticClass:"helpService"},[a("a",{staticClass:"close_edit close_ico",attrs:{href:"javascript:void(0)"},on:{click:function(t){e.tableRowEditing=!1,e.cancel()}}},[e._v("×")])])]),e._v(" "),a("div",{staticClass:"wrapper clearfix row"},[a("form",{on:{submit:function(t){t.preventDefault(),e.saveForm(t)}}},[a("div",{staticClass:"box"},[a("div",{staticClass:"box_block"},[a("div",{staticClass:"clearfix margin_phone col-lg-11 col-lg-offset-1 "},[a("div",{staticClass:"h40"}),e._v(" "),a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("network.flow.header_title.interface"))+"：")]),e._v(" "),a("multi-interface-select",{ref:"myInterface",attrs:{interfaces:e.interfaces},model:{value:e.tableForm.interface,callback:function(t){e.tableForm.interface=t},expression:"tableForm.interface"}}),e._v(" "),a("em",{staticClass:"colorR"},[e._v("*")])],1)])])]),e._v(" "),a("div",{staticClass:"box clearfix"},[a("div",{staticClass:"h20"}),e._v(" "),a("div",{staticClass:"title_h4 clearfix"},[a("h4",[e._v(e._s(e.$t("common.domain")))])]),e._v(" "),a("div",{staticClass:"clearfix margin_phone col-lg-11 col-lg-offset-1 opear_ip"},[a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_group"},[a("textarea",{directives:[{name:"model",rawName:"v-model",value:e.tableForm.domain,expression:"tableForm.domain"},{name:"validate",rawName:"v-validate",value:"required|maxListTotal:1000|domainList",expression:"'required|maxListTotal:1000|domainList'"}],staticClass:"inptText",staticStyle:{height:"100px"},attrs:{rows:"",name:"domain","data-vv-as":e.$t("common.domain")},domProps:{value:e.tableForm.domain},on:{input:function(t){t.target.composing||(e.tableForm.domain=t.target.value)}}}),e._v(" "),a("em",{staticStyle:{"vertical-align":"top"}},[e._v("*")])]),e._v(" "),a("div",{staticClass:"input_P"},[e.errors.has("domain")?a("p",{staticClass:"error_tip"},[e._v(e._s(e.errors.first("domain")))]):e._e()]),e._v(" "),a("br")])])]),e._v(" "),a("div",{staticClass:"box clearfix"},[a("div",{staticClass:"h20"}),e._v(" "),a("div",{staticClass:"title_h4 clearfix"},[a("h4",[e._v(e._s(e.$t("network.flow.header_title.src_addr")))])]),e._v(" "),a("div",{staticClass:"box_block"},[a("div",{staticClass:"clearfix margin_phone col-lg-11 col-lg-offset-1  opear_ip"},[a("div",{staticClass:"line_edit clearfix"},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("common.ip-group"))+"：")]),e._v(" "),a("ip-group",{attrs:{"func-name":"stream_layer7",alltypes:!0},model:{value:e.tableForm.src_addr,callback:function(t){e.tableForm.src_addr=t},expression:"tableForm.src_addr"}})],1),e._v(" "),a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("common.comment"))+"：")]),e._v(" "),a("div",{staticClass:"input_group"},[a("input",{directives:[{name:"validate",rawName:"v-validate",value:"strLenBetween2:0,64",expression:"'strLenBetween2:0,64'"},{name:"model",rawName:"v-model",value:e.tableForm.comment,expression:"tableForm.comment"}],staticClass:"inptText",attrs:{rows:"",name:"comment","data-vv-as":e.$t("common.comment")},domProps:{value:e.tableForm.comment},on:{input:function(t){t.target.composing||(e.tableForm.comment=t.target.value)}}})]),e._v(" "),a("div",{staticClass:"input_P"},[e.errors.has("comment")?a("p",{staticClass:"error_tip"},[e._v(e._s(e.errors.first("comment")))]):e._e()])]),e._v(" "),a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("service.url_jump.header_title.week"))+"：")]),e._v(" "),a("div",{staticClass:"input_group"},[a("weekday-select",{model:{value:e.tableForm.week,callback:function(t){e.tableForm.week=t},expression:"tableForm.week"}})],1)]),e._v(" "),a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_tit"},[e._v(e._s(e.$t("service.url_jump.header_title.time"))+"：")]),e._v(" "),a("div",{staticClass:"input_group"},[a("div",{staticClass:"search_list"},[a("input",{directives:[{name:"model",rawName:"v-model",value:e.tableForm.time,expression:"tableForm.time"},{name:"validate",rawName:"v-validate",value:"required|timeBucket",expression:"'required|timeBucket'"}],staticClass:"inptText w120",attrs:{type:"text",name:"time",placeholder:"00:00-23:59","data-vv-as":e.$t("service.url_jump.header_title.time")},domProps:{value:e.tableForm.time},on:{input:function(t){t.target.composing||(e.tableForm.time=t.target.value)}}})]),e._v(" "),a("em",[e._v("*")])]),e._v(" "),a("div",{staticClass:"input_P"},[e.errors.has("time")?a("p",{staticClass:"error_tip"},[e._v(e._s(e.errors.first("time")))]):e._e()])]),e._v(" "),a("div",{staticClass:"h20"}),e._v(" "),a("div",{staticClass:"line_edit"},[a("div",{staticClass:"input_group"},[a("button",{staticClass:"btn btn_green btn_confirm",attrs:{type:"submit",name:"button"}},[e._v("\n                                        "+e._s(e.$t("common.save"))+"\n                                    ")]),e._v(" "),a("button",{staticClass:"btn btn_cancel margin-l-10",attrs:{type:"button"},on:{click:function(t){e.tableRowEditing=!1,e.cancel()}}},[e._v("\n                                        "+e._s(e.$t("common.cancel"))+"\n                                    ")])])])])])])])])]):e._e()])},staticRenderFns:[]}},320010:function(t,e,a){t.exports=function(c){
var oldData=c.data,oldRender=c.render,methods=c.methods;
// Preserve the native multi-exit picker, including saved order and late data.
var pickerBase=a(341),picker={};Object.keys(pickerBase).forEach(function(key){if(key!=='_Ctor')picker[key]=pickerBase[key];});
picker.name='RoutingMultiInterfaceSelect';picker.watch={};
Object.keys(pickerBase.watch||{}).forEach(function(key){picker.watch[key]=pickerBase.watch[key];});
picker.watch.value=function(value){this.val=value||'';this.newVal=this.single?this.val:(this.val?this.val.split(','):[]);};
picker.watch.interfaces=function(value){this.newInterfaces=copyAry('decode',value||[]);};
c.components=c.components||{};c.components.MultiInterfaceSelect=picker;

c.data=function(){var d=oldData.call(this);d.nrSettings={domain_overrides:[],foreign_domains:[]};d.nrRevision='';d.nrLibrary=null;d.dlRows=[];d.dlState={};d.dlDirty=false;d.dlBusy=false;d.dlRevision="missing";d.dlMessage="";d.nrDialogs={cn:false,foreign:false};d.nrDraft={cn:'',foreign:''};d.nrDialogError='';d.nrDialogRevision='';d.nrDialogSettings=null;d.nrBusy=false;d.nrMessage='';d.nrSource='';d.nrSourceLoaded=false;d.nrForeignSource='';d.nrForeignSourceLoaded=false;d.nrTimer=null;d.nrDisposed=false;d.nrRuleSaving=false;
// The ID order is global for viewing; matching uses explicit-domain and fallback stages.
var dc=d.tableOptions.columns.find(function(x){return x.name==='domain';}),df=dc.dataFunction;
d.edConfig={enabled:false,ingress:'',sources:[],exceptions:[],allowed:[],custom:[],dot:true,doh:true,builtin:true};
d.edText={sources:'',exceptions:'',allowed:'',custom:''};d.edDirty=false;d.edBusy=false;d.edLoaded=false;d.edBase=null;d.edRevision='';d.edMessage='';d.edStats={};d.edSequence=0;
d.rsSnapshot=null;d.rsBusy=false;d.rsSequence=0;d.rsError='';
dc.dataFunction=function(v,row){
 var fallback=row&&row.nr_group==='fallback',value;
 if(row&&row.nr_group==='cn')value='中国大陆域名组';
 else if(row&&row.nr_group==='foreign')value='中国大陆以外域名组';
 else if(fallback)value=row.nr_target==='cn'?'未匹配流量〔兜底 · 大陆优先，未命中阻断〕':'未匹配流量〔兜底〕';
 else value=df(v,row);
 return '<span style="display:inline-block;padding:1px 6px;margin-bottom:4px;border-radius:3px;background:'+(fallback?'#fff0d2;color:#885900':'#e8f2ff;color:#205a94')+'">'+(fallback?'阶段 2 · 未匹配后兜底':'阶段 1 · 显式域名')+'</span><br>'+value;
};return d;};
// Editing is a draft: native edit/copy normalize domain strings in-place.
// Clone first so cancelling can keep the unchanged table without a reload.
var oldEdit=methods.editTableRow,oldCopy=methods.copyTableRow;
function ruleDraft(row){var draft=JSON.parse(JSON.stringify(row));if(draft.iface_band==null||draft.iface_band==='')draft.iface_band=1;return draft;}
methods.editTableRow=function(row){return oldEdit.call(this,ruleDraft(row));};
methods.copyTableRow=function(row){return oldCopy.call(this,ruleDraft(row));};
methods.cancel=function(){};
var oldNew=methods.newTableRow;methods.newTableRow=function(){oldNew.call(this);this.$set(this.tableForm,'nr_group','cn');this.$set(this.tableForm,'domain','group.invalid');this.$set(this.tableForm,'nr_dns','1.1.1.1');this.$set(this.tableForm,'nr_ingress','');this.$set(this.tableForm,'nr_route','fixed');this.$set(this.tableForm,'nr_target','any');this.$set(this.tableForm,'iface_band',0);};
var oldSave=methods.saveForm;methods.saveForm=function(){if(this.nrRuleSaving)return;var f=this.tableForm;if(f.iface_band==null||f.iface_band==='')f.iface_band=1;if(!/^\d{1,3}(\.\d{1,3}){3}$/.test(f.nr_dns||'')){customError('请填写该出口使用的 DNS IPv4 地址');return;}if(f.nr_group==='fallback'){f.nr_route='fixed';f.nr_target=f.nr_target||'any';}else f.nr_target='any';if(f.nr_group==='cn'||f.nr_group==='foreign'||f.nr_group==='fallback')f.domain='group.invalid';var self=this;this.nrRuleSaving=true;
 try{return Promise.resolve(oldSave.call(this)).then(function(value){self.nrRuleSaving=false;return value;},function(e){self.nrRuleSaving=false;if(!self.nrDisposed)customError(e.message||'保存失败，请检查当前规则');return false;});}
 catch(e){this.nrRuleSaving=false;customError(e.message||'保存失败');return false;}
};
methods.nrApi=function(action,param){return this.$http.post(this.tableOptions.requests.url,{func_name:'stream_domain',action:action,param:param||{}}).then(function(r){if(r.data.Result!==30000)throw Error(r.data.ErrMsg||'操作失败');return r.data.Data||{};});};

// Diagnostics are an explicit read, never part of library polling or probes.
methods.rsRefresh=function(){
 if(this.nrDisposed||this.rsBusy)return Promise.resolve(false);
 var self=this,sequence=++this.rsSequence,route=this.$route&&this.$route.fullPath;
 this.rsBusy=true;this.rsSnapshot=null;this.rsError='';
 function current(){return !self.nrDisposed&&sequence===self.rsSequence&&(!route||(self.$route&&self.$route.fullPath===route));}
 function number(v,max){return typeof v==='number'&&isFinite(v)&&v>=0&&Math.floor(v)===v&&v<=max?v:null;}
 function name(v){return typeof v==='string'&&/^[A-Za-z0-9_.-]{1,32}$/.test(v)?v:'';}
 function choice(v,options){return options.indexOf(v)>=0?v:'unknown';}
 function list(v,max){return Array.isArray(v)?v.slice(0,max).filter(function(r){return r&&typeof r==='object';}):[];}
 return Promise.resolve().then(function(){return self.nrApi('show',{TYPE:'runtime_status'});}).then(function(d){
  if(!current())return false;
  var s=d&&d.runtime_status;if(!s||s.version!==1)throw Error('invalid status');
  var out={phase:choice(s.phase,['busy','starting','applying','protected','running','inactive','unknown']),busy:s.busy===true,exits:[],workers:[],dns_front:choice(s.dns_front,['running','stopped','unknown']),quarantine:{available:false}};
  // Busy responses deliberately hide both previous and partial detail rows.
  if(!out.busy){
   out.exits=list(s.exits,132).map(function(r){return {interface:name(r.interface),health:choice(r.health,['reachable','failed','unknown']),probe_age_seconds:number(r.probe_age_seconds,4294967295),handshake_age_seconds:number(r.handshake_age_seconds,4294967295)};});
   out.workers=list(s.workers,32).map(function(r){var dns=typeof r.dns==='string'&&/^\d{1,3}(\.\d{1,3}){3}$/.test(r.dns)&&r.dns.split('.').every(function(n){return Number(n)<=255;})?r.dns:'';return {dns:dns,interface:name(r.interface),state:choice(r.state,['selected','blocked','unknown']),process:choice(r.process,['running','stopped','unknown'])};});
   var q=s.quarantine,entries=q&&number(q.entries,262144);
   if(q&&q.available===true&&entries!==null){out.quarantine={available:true,entries:entries,remaining_seconds:number(q.remaining_seconds,61)};}
  }
  self.rsSnapshot=out;return true;
 }).catch(function(){if(current()){self.rsSnapshot=null;self.rsError='read_failed';}return false;}).then(function(ok){
  if(!self.nrDisposed&&sequence===self.rsSequence)self.rsBusy=false;
  return ok;
 });
};
methods.rsRender=function(h){
 var self=this,s=this.rsSnapshot,busy=this.rsBusy||this.nrBusy||this.nrRuleSaving||this.edBusy;
 function tr(key,values){
  // The native translator does not interpolate named values. Render as text nodes.
  var text=self.$t('routing_runtime.'+key);
  return values?text.replace(/\{(seconds|count)\}/g,function(token,name){
   return Object.prototype.hasOwnProperty.call(values,name)?String(values[name]):token;
  }):text;
 }
 function unknown(value){return value||tr('unknown');}
 function age(value){return value===null||value===undefined?tr('not_available'):tr('age_seconds',{seconds:value});}
 function table(headers,rows){return h('div',{style:{overflowX:'auto'}},[h('table',{class:'table table-bordered',style:{width:'100%'}},[h('thead',[h('tr',headers.map(function(k){return h('th',[tr(k)]);}))]),h('tbody',rows.map(function(cells,i){return h('tr',{key:i},cells.map(function(value){return h('td',[value]);}));}))])]);}
 var body=[h('div',{class:'title_h4 clearfix'},[h('h4',[tr('title')])]),
  h('button',{class:'btn btn_green',attrs:{type:'button',disabled:this.rsBusy,'aria-label':tr('refresh')},on:{click:function(){self.rsRefresh();}}},[tr(this.rsBusy?'reading':'refresh')]),h('p',[tr('snapshot_note')])];
 if(busy){body.push(h('p',{attrs:{role:'status'}},[tr(this.rsBusy?'reading':'phase_busy')]));body.push(h('p',[tr('busy_note')]));}
 else if(this.rsError){body.push(h('p',{class:'error_tip',attrs:{role:'alert'}},[tr(this.rsError)]));}
 else if(!s){body.push(h('p',[tr('empty')]));}
 else{
  body.push(h('p',{attrs:{role:'status'}},[tr('phase_label')+' '+tr('phase_'+s.phase)]));
  if(s.busy){body.push(h('p',[tr('busy_note')]));}
  else{
   body.push(h('h5',[tr('exits_title')]),h('p',[tr('health_note')]));
   body.push(s.exits.length?table(['exit','health','probe_age','handshake_age'],s.exits.map(function(r){return [unknown(r.interface),tr('health_'+r.health),age(r.probe_age_seconds),age(r.handshake_age_seconds)];})):h('p',[tr('no_exits')]));
   body.push(h('h5',[tr('dns_title')]),h('p',[tr('dns_front')+' '+tr('process_'+s.dns_front)]));
   body.push(s.workers.length?table(['resolver','selected_exit','dns_state','process'],s.workers.map(function(r){return [unknown(r.dns),r.state==='selected'?unknown(r.interface==='main'?tr('default_exit'):r.interface):tr('not_selected'),tr('dns_'+r.state),tr('process_'+r.process)];})):h('p',[tr('no_workers')]));
   body.push(h('h5',[tr('quarantine_title')]));
   var q=s.quarantine;
   if(!q.available)body.push(h('p',[tr('quarantine_unknown')]));
   else if(q.entries===0)body.push(h('p',[tr('quarantine_none')]));
   else{body.push(h('p',[tr('quarantine_entries',{count:q.entries})]));body.push(h('p',[q.remaining_seconds!==null?tr('quarantine_remaining',{seconds:q.remaining_seconds}):tr('quarantine_no_time')]));}
   body.push(h('p',[tr('quarantine_note')]));
  }
 }
 return h('section',{attrs:{id:'routing-runtime-status','aria-label':tr('title')},class:'box clearfix',style:{margin:'20px 0',padding:'16px 24px'}},body);
};

methods.edAccept=function(config,revision){
 if(this.edDirty||this.edBusy||!config)return;
 this.edBase=JSON.parse(JSON.stringify(config));this.edRevision=revision;
 this.edConfig=JSON.parse(JSON.stringify(config.encrypted_dns||{enabled:false,ingress:'',sources:[],exceptions:[],allowed:[],custom:[],dot:true,doh:true,builtin:true}));
 var self=this;['sources','exceptions','allowed','custom'].forEach(function(k){self.edText[k]=(self.edConfig[k]||[]).join('\n');});this.edLoaded=true;
};
methods.edRefresh=function(){
 var self=this,sequence=++this.edSequence;
 return this.nrApi('show',{TYPE:'encrypted_dns_stats'}).then(function(d){if(!self.nrDisposed&&sequence===self.edSequence)self.edStats=d.encrypted_dns_stats||{};});
};
methods.edReload=function(){
 if(this.edBusy||this.nrBusy)return;
 var self=this,sequence=++this.edSequence;
 return this.nrApi('show',{TYPE:'native_settings,encrypted_dns_stats'}).then(function(d){
  if(self.nrDisposed||sequence!==self.edSequence)return;
  self.edDirty=false;self.edAccept(d.config,d.revision);self.edStats=d.encrypted_dns_stats||{};self.edMessage='已重新读取保存的设置。';
 }).catch(function(e){if(!self.nrDisposed)self.edMessage=e.message;});
};
methods.edSave=function(){
 if(this.edBusy||this.nrBusy||!this.edLoaded||this.nrDialogs.cn||this.nrDialogs.foreign)return;
 var self=this,cfg=JSON.parse(JSON.stringify(this.edBase)),ed=JSON.parse(JSON.stringify(this.edConfig));
 ['sources','exceptions','allowed','custom'].forEach(function(k){ed[k]=self.edText[k].split(/\r?\n/).map(function(x){return x.trim();}).filter(Boolean);});
 ed.ingress=ed.ingress.trim();
 if(ed.enabled&&!ed.sources.length&&!ed.ingress){this.edMessage='启用时必须填写来源地址或入接口。';return;}
 if(ed.enabled&&!ed.dot&&!ed.doh){this.edMessage='至少选择一种加密 DNS 限制。';return;}
 if(ed.enabled&&ed.doh&&!ed.builtin&&!ed.custom.length){this.edMessage='限制 DoH 时请选择内置服务或填写服务 IP。';return;}
 cfg.encrypted_dns=ed;delete cfg.foreign_policy_status;delete cfg.foreign_allowlist;cfg.foreign_policy='library';
 this.edBusy=true;this.edMessage='正在保存并应用，请稍候…';
 return this.nrApi('native_settings_save',{revision:this.edRevision,payload:btoa(unescape(encodeURIComponent(JSON.stringify(cfg))))}).then(function(){
  if(self.nrDisposed)return;
  self.edBusy=false;self.edDirty=false;return self.nrLoad().then(function(){return self.edRefresh();}).then(function(){if(!self.nrDisposed)self.edMessage='已保存并应用。计数为匹配到的拦截数据包，不是 DNS 查询次数。';});
 }).catch(function(e){if(!self.nrDisposed)self.edMessage=e.message+'；如设置已变化，请重新读取设置后重试。';}).then(function(){self.edBusy=false;});
};
methods.edRender=function(h){
 var self=this,ed=this.edConfig,stats=this.edStats||{},busy=this.edBusy||this.nrBusy||!this.edLoaded;
 function toggle(key,text){return h('label',{style:{display:'block',margin:'8px 0'}},[h('input',{attrs:{type:'checkbox',disabled:busy,'aria-label':text},domProps:{checked:ed[key]},on:{change:function(e){ed[key]=e.target.checked;self.edDirty=true;}}}), ' '+text]);}
 function entry(key,title,hint){return h('div',{style:{margin:'12px 0'}},[h('label',{attrs:{for:'edns-'+key}},[title]),h('textarea',{class:'inptText',attrs:{id:'edns-'+key,rows:3,disabled:busy,'aria-label':title,placeholder:hint},style:{display:'block',width:'640px',maxWidth:'100%',height:'72px'},domProps:{value:self.edText[key]},on:{input:function(e){self.edText[key]=e.target.value;self.edDirty=true;}}})]);}
 function button(text,fn,disabled){return h('button',{class:'btn btn_green margin-r-10',attrs:{type:'button',disabled:busy||disabled},on:{click:fn}},[text]);}
 return h('section',{attrs:{id:'encrypted-dns-settings'},style:{marginTop:'24px'}},[
  h('div',{class:'title_h4 clearfix'},[h('h4',['加密 DNS 限制'])]),
  h('p',['默认关闭。帮助指定客户端使用可参与域名分流的 DNS，但不能保证所有流量按域名识别；缓存、直接 IP、自建 DoH 和代理仍需兜底规则。仅限制转发的 IPv4 流量，原有 IPv6 策略保持不变。']),
  toggle('enabled','启用加密 DNS 限制'),
  entry('sources','来源 IPv4 / 网段（每行一项，最多 64 项）','例如 198.18.1.2/32；留空时必须指定入接口'),
  h('label',{attrs:{for:'edns-ingress'}},['入接口（可留空）']),h('input',{class:'inptText',attrs:{id:'edns-ingress',type:'text',disabled:busy,placeholder:'例如 wg1、lan1','aria-label':'加密 DNS 入接口'},style:{display:'block',margin:'8px 0'},domProps:{value:ed.ingress},on:{input:function(e){ed.ingress=e.target.value;self.edDirty=true;}}}),
  h('p',['来源与入接口同时填写时须同时满足；只填入接口时作用于该接口所有 IPv4 客户端。填写 WG 服务接口名，例如 wg1。']),
  toggle('dot','限制标准 DoT / DoQ（TCP / UDP 853）'),toggle('doh','限制指定 DoH 服务（TCP / UDP 443）'),
  toggle('builtin','包含内置 DoH 服务 IP（Cloudflare、Google）'),
  entry('custom','补充 DoH 服务 IPv4（每行一个地址，最多 128 项）','仅填写确认用于 DNS 的服务 IP，不支持域名或网段'),
  entry('exceptions','不限制的来源 IPv4 / 网段（最多 64 项）','例外来源不受本功能限制'),
  entry('allowed','允许的 DNS 服务 IPv4（最多 64 项）','这些目标地址的 853 和 443 端口不受本功能限制'),
  h('p',['不会解密 HTTPS，也不会整体封锁 HTTPS / QUIC。所列服务 IP 的 443 端口会整体受限，可能影响同 IP 的网页；仅使用加密 DNS 且不允许回退的客户端可能无法解析，需关闭客户端该选项或添加例外。路由器自身的 DNS 上游不受限制。']),
  button(this.edBusy?'正在应用…':'保存加密 DNS 限制',function(){self.edSave();},this.nrDialogs.cn||this.nrDialogs.foreign),
  button('重新读取设置',function(){self.edReload();},false),button('刷新拦截计数',function(){self.edRefresh().catch(function(e){self.edMessage=e.message;});},false),
  h('p',[stats.available?'拦截数据包：DoT '+(stats.dot||0)+'，DoQ '+(stats.doq||0)+'，DoH '+(stats.doh||0)+'；共 '+(stats.bytes||0)+' 字节。':'当前没有可读取的拦截计数。']),
  h('p',['重启或重新应用完整分流配置后计数清零；计数只表示端口和地址命中，不能证明每个数据包都是 DNS。保存时会应用分流配置，现有连接可能短暂中断。']),
  h('p',{attrs:{role:'status'}},[this.edMessage])]);
};

methods.dlLoad=function(){var self=this;return this.nrApi('show',{TYPE:'dns_limits'}).then(function(d){self.dlAccept(d.dns_limits);});};
methods.dlAccept=function(d){if(!d)return;this.dlState=d;if(!this.dlDirty){this.dlRevision=d.revision;this.dlRows=Array.isArray(d.config.rules)?JSON.parse(JSON.stringify(d.config.rules)):[];}};
methods.dlSave=function(){var self=this;if(this.dlBusy)return;this.dlBusy=true;this.dlMessage='';var cfg={rules:this.dlRows.map(function(r){return {cidr:r.cidr.trim(),enabled:r.enabled,concurrency:Number(r.concurrency),rate:Number(r.rate),burst:Number(r.burst)};})};return this.nrApi('dns_limits_save',{payload:btoa(unescape(encodeURIComponent(JSON.stringify(cfg)))),revision:this.dlRevision}).then(function(){self.dlDirty=false;return self.dlLoad();}).then(function(){self.dlMessage=self.dlState.running?'已保存并生效，DNS 服务未重启。':'已保存，将在 DNS 服务启动时生效。';}).catch(function(e){self.dlMessage=e.message;}).then(function(){self.dlBusy=false;});};
methods.dlRender=function(h){var self=this,s=this.dlState||{},stats=s.stats||{};
 function btn(text,fn){return h('button',{class:'btn btn_green margin-r-10',attrs:{type:'button',disabled:self.dlBusy},on:{click:fn}},[text]);}
 function field(r,key,lo,hi){return h('input',{class:'inptText',style:{width:key==='cidr'?'180px':'80px',maxWidth:'100%',boxSizing:'border-box'},attrs:{type:key==='cidr'?'text':'number',min:lo,max:hi,disabled:self.dlBusy,'aria-label':{cidr:'来源 IP 或网段',concurrency:'未完成请求上限',rate:'每秒额度',burst:'突发额度'}[key],placeholder:key==='cidr'?'10.10.1.2 或 10.10.1.0/24':null},domProps:{value:r[key]},on:{input:function(e){r[key]=e.target.value;self.dlDirty=true;}}});}
 return h('div',{attrs:{id:'dns-source-limits'},style:{marginTop:'24px'}},[
 h('div',{class:'title_h4 clearfix'},[h('h4',['DNS 请求保护'])]),
 h('p',['默认不按源 IP 限额；下级路由器后多台手机共享一个 IP 时，不会默认共用小额度。全局最多 512 个未完成请求，保留超时回收和异常报文检查。']),
 h('p',['仅以下来源启用限额。网段内每个源 IP 分别计数，地址范围更小的设置优先；取消“启用”可为该地址设置不限额例外。删除设置后恢复上级网段设置或默认不限额。最多 64 条。']),
 h('table',{class:'table table-bordered',style:{width:'100%'}},[
 h('thead',[h('tr',['来源 IP / 网段','启用限额','未完成请求','每秒额度','突发额度','操作'].map(function(t,i){return h('th',{style:{width:[26,12,16,16,16,14][i]+'%'}},[t]);}))]),
 h('tbody',this.dlRows.map(function(r,i){return h('tr',{key:i},[
 h('td',[field(r,'cidr')]),h('td',[h('input',{attrs:{type:'checkbox',disabled:self.dlBusy,'aria-label':'启用此来源限额'},domProps:{checked:r.enabled},on:{change:function(e){r.enabled=e.target.checked;self.dlDirty=true;}}})]),
 h('td',[field(r,'concurrency',1,384)]),h('td',[field(r,'rate',1,4096)]),h('td',[field(r,'burst',1,8192)]),h('td',[btn('删除',function(){self.dlRows.splice(i,1);self.dlDirty=true;})])]);}))]),
 h('p',['并发范围 1–384；每秒额度 1–4096；突发额度须不小于每秒额度，最大 8192。额度只限制 DNS 请求，不限制视频或下载带宽。']),
 btn('添加来源',function(){if(self.dlRows.length>=64){self.dlMessage='最多 64 条来源设置';return;}self.dlRows.push({cidr:'',enabled:true,concurrency:32,rate:64,burst:128});self.dlDirty=true;}),
 btn('保存 DNS 请求保护',function(){self.dlSave();}),btn('刷新计数',function(){self.dlLoad().catch(function(e){self.dlMessage=e.message;});}),
 h('p',['当前未完成：'+(stats.active||0)+' / 512；来源并发拒绝：'+(stats.source_drops||0)+'；速率拒绝：'+(stats.rate_drops||0)+'；全局队列拒绝：'+(stats.global_drops||0)+'；来源表满拒绝：'+(stats.table_drops||0)+'。计数在 DNS 服务重启后清零。']),
 h('p',{attrs:{role:'status'}},[this.dlMessage])]);};

methods.nrLoad=function(libraryOnly){var self=this;return this.nrApi('show',{TYPE:'native_settings,domain_library,dns_limits'}).then(function(d){if(self.nrDisposed)return;self.dlAccept(d.dns_limits);if(!libraryOnly){self.edAccept(d.config,d.revision);self.nrSettings=d.config;self.nrSettings.foreign_policy_status=d.foreign_policy||{};self.nrRevision=d.revision;}self.nrLibrary=d.domain_library;if(!self.nrSourceLoaded){self.nrSource=d.domain_library.source.url;self.nrSourceLoaded=true;}if(!self.nrForeignSourceLoaded){self.nrForeignSource=d.domain_library.source.groups.foreign.url;self.nrForeignSourceLoaded=true;}self.nrBusy=d.domain_library.job.state==='running';clearTimeout(self.nrTimer);if(self.nrBusy)self.nrTimer=setTimeout(function(){self.nrLoad(true).catch(function(e){self.nrMessage=e.message;self.nrBusy=false;});},2500);});};
methods.nrSourceSave=function(reset,group){group=group||'cn';var self=this,foreign=group==='foreign';this.nrBusy=true;return this.nrApi('domain_source_save',{payload:btoa(unescape(encodeURIComponent(JSON.stringify({group:group,url:reset?'':(foreign?this.nrForeignSource:this.nrSource).trim(),format:'auto'}))))}).then(function(){if(foreign)self.nrForeignSourceLoaded=false;else self.nrSourceLoaded=false;self.nrMessage=(foreign?'大陆以外':'大陆')+'下载源已保存；另一组不变，点击“更新域名库”应用。';return self.nrLoad(true);}).catch(function(e){self.nrMessage=e.message;}).then(function(){self.nrBusy=false;},function(e){self.nrBusy=false;self.nrMessage=e.message;});};
methods.nrGroups=function(cfg){var groups={cn:[],foreign:[]};(cfg.domain_overrides||[]).forEach(function(x){groups[x.group].push(x.domain);});(cfg.foreign_domains||[]).forEach(function(x){if(groups.foreign.indexOf(x)<0)groups.foreign.push(x);});return groups;};
methods.nrOpenGroup=function(group){if(this.nrBusy||this.edBusy||this.nrDialogs.cn||this.nrDialogs.foreign)return;this.nrDialogSettings=JSON.parse(JSON.stringify(this.nrSettings));this.nrDialogRevision=this.nrRevision;this.nrDraft[group]=this.nrGroups(this.nrDialogSettings)[group].join('\n');this.nrDialogError='';this.nrDialogs[group]=true;};
methods.nrCloseGroup=function(group){if(!this.nrBusy){this.nrDialogs[group]=false;this.nrDialogError='';}};
methods.nrSaveGroup=function(group){
 if(this.nrBusy||!this.nrDialogs[group])return;
 var self=this,other=group==='cn'?'foreign':'cn',cfg=JSON.parse(JSON.stringify(this.nrDialogSettings)),groups=this.nrGroups(cfg),seen=Object.create(null),opposite=Object.create(null),rows=[];
 groups[other].forEach(function(d){opposite[d.toLowerCase()]=true;});
 try{this.nrDraft[group].split(/\r?\n/).forEach(function(line,i){var d=line.trim().toLowerCase();if(!d)return;
  if(d.length>253||d.indexOf('.')<0||/^[0-9.]+$/.test(d)||d.split('.').some(function(x){return !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(x);}))throw Error('第 '+(i+1)+' 行域名无效，请每行只填写一个域名');
  if(seen[d])throw Error('重复域名：'+d);
  if(opposite[d])throw Error(d+' 已在'+(other==='cn'?'中国大陆':'中国大陆以外')+'分组中，请先从该组移除后再添加');
  seen[d]=true;rows.push({domain:d,group:group});
 });if(rows.length+groups[other].length>20000)throw Error('手动域名合计不能超过 20000 条');}
 catch(e){this.nrDialogError=e.message;return;}
 cfg.domain_overrides=rows.concat(groups[other].map(function(d){return {domain:d,group:other};}));cfg.foreign_domains=[];cfg.foreign_policy='library';cfg.version=3;delete cfg.foreign_allowlist;delete cfg.foreign_policy_status;
 this.nrDialogError='';this.nrBusy=true;
 return this.nrApi('native_settings_save',{revision:this.nrDialogRevision,payload:btoa(unescape(encodeURIComponent(JSON.stringify(cfg))))}).then(function(){self.nrDialogs[group]=false;self.nrMessage=(group==='cn'?'中国大陆':'中国大陆以外')+'手动域名已保存，另一组保持不变；在线更新不会覆盖。';return self.nrLoad();}).then(function(){self.nrBusy=false;},function(e){self.nrBusy=false;self.nrDialogError=e.message+'；如设置已被其他页面修改，请取消并刷新后重试。';});
};
methods.nrUpdate=function(action){var self=this;this.nrBusy=true;this.nrApi(action).then(function(){self.nrMessage='已开始处理，状态自动刷新';return self.nrLoad(true);}).catch(function(e){self.nrMessage=e.message;self.nrBusy=false;});};

c.computed=c.computed||{};c.computed.nrGroupValues=function(){return this.nrGroups(this.nrSettings);};
var mounted=c.mounted;c.mounted=function(){if(Array.isArray(mounted))mounted.forEach(function(f){f.call(this);},this);else if(mounted)mounted.call(this);this.nrLoad().catch(function(e){customError(e.message);});};
var destroy=c.beforeDestroy;c.beforeDestroy=function(){this.nrDisposed=true;clearTimeout(this.nrTimer);if(Array.isArray(destroy))destroy.forEach(function(f){f.call(this);},this);else if(destroy)destroy.call(this);};
c.render=function(h){var self=this,v=oldRender.call(this,h);function label(text,node){return h('div',{class:'line_edit clearfix'},[h('div',{class:'input_tit'},[text+'：']),h('div',{class:'input_group'},[node])]);}function input(value,fn){return h('input',{class:'inptText',attrs:{type:'text'},domProps:{value:value},on:{input:function(e){fn(e.target.value);}}});}
if(this.tableRowEditing){var added=false;function hasDomain(n){return !!(n&&((n.tag==='textarea'&&n.data&&n.data.attrs&&n.data.attrs.name==='domain')||(n.children||[]).some(hasDomain)));}function walk(n){if(!n||typeof n!=='object')return;
if(n.tag==='button'&&n.data&&n.data.attrs&&n.data.attrs.type==='submit'){n.data.attrs.disabled=self.nrRuleSaving;if(self.nrRuleSaving)n.children=[self._v('正在保存并应用…')];}
if(n.data&&n.data.on&&n.data.on.click&&((n.tag==='button'&&(n.data.staticClass||'').indexOf('btn_cancel')>=0)||(n.tag==='a'&&(n.data.staticClass||'').indexOf('close_edit')>=0))){var click=n.data.on.click;n.data.on.click=function(event){if(!self.nrRuleSaving)return click(event);};if(n.tag==='button')n.data.attrs.disabled=self.nrRuleSaving;}
if(self.tableForm.nr_group&&self.tableForm.nr_group!=='manual'&&n.tag==='div'&&n.data&&n.data.staticClass==='box clearfix'&&hasDomain(n)){n.data.style={display:'none'};}if(n.tag==='div'&&n.data&&(n.data.staticClass||'').indexOf('col-lg-offset-1')>=0&&!added){added=true;n.children=n.children||[];n.children.unshift(label('入接口（可留空）',input(self.tableForm.nr_ingress||'',function(x){self.$set(self.tableForm,'nr_ingress',x);})));if(self.tableForm.nr_route!=='dns_only')n.children.unshift(label('线路绑定',h('div',[h('d-switch',{attrs:{opt:{on:1,off:0}},model:{value:Number(self.tableForm.iface_band==null?1:self.tableForm.iface_band),callback:function(value){self.$set(self.tableForm,'iface_band',value);},expression:'tableForm.iface_band'}}),h('span',{class:'remark'},['开启：线路断开后禁止切换到其他线路；关闭：允许自动切换。'])])));n.children.unshift(label('访问方式',h('select',{class:'inptText',style:{width:'340px',height:'26px',backgroundColor:'#fff'},attrs:{disabled:self.tableForm.nr_group==='fallback'},domProps:{value:self.tableForm.nr_route||'fixed'},on:{change:function(e){self.$set(self.tableForm,'nr_route',e.target.value);}}},[h('option',{attrs:{value:'fixed'}},['按本条规则分流']),h('option',{attrs:{value:'dns_only'}},['仅 DNS 分流，访问继续按端口/IP规则'])])));n.children.unshift(label('DNS 上游',input(self.tableForm.nr_dns||'',function(x){self.$set(self.tableForm,'nr_dns',x);}))); n.children.unshift(label('域名类型',h('select',{class:'inptText',style:{width:'340px',height:'26px',backgroundColor:'#fff'},domProps:{value:self.tableForm.nr_group||'manual'},on:{change:function(e){self.$set(self.tableForm,'nr_group',e.target.value);if(e.target.value==='fallback')self.$set(self.tableForm,'nr_route','fixed');if(e.target.value!=='manual')self.$set(self.tableForm,'domain','group.invalid');else if(self.tableForm.domain==='group.invalid')self.$set(self.tableForm,'domain','');}}},(self.tableForm.nr_group==='manual'?['manual','cn','foreign','fallback']:['cn','foreign','fallback']).map(function(k){return h('option',{attrs:{value:k}},[{manual:'旧版自定义域名（保留）',cn:'中国大陆域名组',foreign:'中国大陆以外域名组',fallback:'未匹配流量〔兜底〕'}[k]]);})))) ;if(self.tableForm.nr_group==='fallback'){n.children.push(label('目标 IP 限制',h('select',{class:'inptText',style:{width:'340px',height:'26px',backgroundColor:'#fff'},attrs:{'aria-label':'目标 IP 限制'},domProps:{value:self.tableForm.nr_target||'any'},on:{change:function(e){self.$set(self.tableForm,'nr_target',e.target.value);}}},[h('option',{attrs:{value:'any'}},['不限制（默认）']),h('option',{attrs:{value:'cn'}},['大陆目标走本线路，其他匹配端口／协议'])])));n.children.push(label('限制说明',h('span',['仅约束本条兜底命中的流量。大陆目标走本条线路；海外、地区未知及非公网目标继续匹配端口、协议规则，均未命中才阻断，不走默认路由。IP 库异常时也只允许端口／协议明确匹配的流量。协议尚未识别时可能被阻断。当前受管 IPv6 保持阻断。'])));}n.children.push(label('出口策略',h('span',[self.tableForm.nr_group==='fallback'?'先匹配大陆、海外及自定义域名，再匹配本规则；均未适用才进入端口、协议分流。包含直接连接 IP 的流量。入接口和源地址均留空时接住全部剩余受管流量；同时填写需同时满足；断线后的行为由“线路绑定”控制。':'按所选出口分流；断线后的行为由“线路绑定”控制。选择“仅 DNS 分流”时，访问流量继续匹配端口/IP规则。'])));}
if(n.tag==='textarea'&&n.data&&n.data.attrs&&n.data.attrs.name==='domain'&&self.tableForm.nr_group&&self.tableForm.nr_group!=='manual'){n.data.style={display:'none'};}if(n.children)n.children.forEach(walk);}walk(v);return h('div',[v]);}
// Keep the new-rule-first list, but make the separate matching stages visible at the table.
function addStageNotice(node){
 if(!node||!node.children)return;
 for(var i=0;i<node.children.length;i++){
  var child=node.children[i];
  if(child&&child.data&&child.data.ref==='dtable'){
   node.children.splice(i,0,h('div',{attrs:{id:'routing-stage-order',role:'note'},style:{margin:'0 0 14px',padding:'12px 16px',background:'#eef5fc',borderLeft:'4px solid #428bca',lineHeight:'1.8'}},[
    h('strong',['匹配阶段：1 显式域名 → 2 适用的未匹配兜底 → 3 端口 → 4 协议']),
    h('div',['新添加的规则显示在列表顶部；同一阶段内从上到下匹配。兜底即使显示在上方，也在全部显式域名之后执行。']),
    h('div',['源地址只是匹配条件，不会自动优先；指定客户端的规则应在同阶段通用规则之前。仅 DNS 规则不固定访问出口，访问继续按后续分流规则处理。'])
   ]));return;
  }
  addStageNotice(child);
 }
}
addStageNotice(v);
var lib=this.nrLibrary||{},manifest=lib.manifest||{},job=lib.job||{},history=lib.update||{};
function button(text,fn){return h('button',{class:'btn btn_green margin-r-10',attrs:{type:'button',disabled:self.nrBusy},on:{click:fn}},[text]);}
return h('div',[v,this.rsRender(h),h('div',{class:'wrapper row'},[h('div',{class:'box clearfix'},[h('div',{class:'title_h4 clearfix'},[h('h4',['域名库与 DNS 设置'])]),h('div',{class:'box_block',style:{padding:'16px 24px'}},[
h('p',['规则直接使用上方原生列表。大陆／海外域名 → 未匹配流量 → 端口分流 → 协议分流。同一匹配阶段内按列表顺序匹配，兜底不会因显示在上方而先于显式域名执行。应用按原生协议分流设置；域名规则仅按地区分类，不再加载应用订阅。源地址和星期、时间条件同时用于 DNS 与访问分流。']),
h('p',['大陆与海外在线域名库自动参与分流，手动调整优先覆盖分类。顺序：大陆／海外域名 → 未匹配流量 → 端口分流 → 协议分流。未匹配规则入接口、源地址均留空时，端口和协议规则不会再处理已被它接住的流量。']),
h('p',['大陆库：'+((manifest.count||0)+(manifest.cn_exact_count||0))+' 条；版本：'+(manifest.version||'').slice(0,16)]),
label('大陆域名库地址',h('input',{class:'inptText',attrs:{id:'domain-source',type:'text',disabled:self.nrBusy,placeholder:'HTTPS 文件地址 / GitHub blob 链接'},style:{width:'640px',maxWidth:'95%'},domProps:{value:self.nrSource},on:{input:function(e){self.nrSource=e.target.value;}}})),
h('p',['默认综合库：大陆使用 dnsmasq-china-list + ChinaMax；大陆以外使用 MetaCubeX + Global。点击更新会同步下载、合并去重；任一源失败保留旧库。填写自定义地址后，该组只使用你的自定义源。']),
h('p',['自动识别每行一个域名或 dnsmasq 域名列表。请使用完整大陆域名列表，支持 HTTPS、GitHub raw 或 blob 文件链接；不支持 geosite.dat、广告过滤规则。大陆以外使用独立的已知海外列表，两组均支持 Mihomo / Clash Domain 域名列表；精确域名保持精确匹配，手动调整优先。']),
button('保存大陆源',function(){self.nrSourceSave(false,'cn');}),button('恢复大陆默认源',function(){self.nrSourceSave(true,'cn');}),
label('大陆以外库地址',h('input',{class:'inptText',attrs:{id:'domain-foreign-source',type:'text',disabled:self.nrBusy,placeholder:'留空恢复已知海外默认库；可填写自定义 GitHub 列表'},style:{width:'640px',maxWidth:'95%'},domProps:{value:self.nrForeignSource},on:{input:function(e){self.nrForeignSource=e.target.value;}}})),
button('保存大陆以外源',function(){self.nrSourceSave(false,'foreign');}),button('恢复大陆以外默认',function(){self.nrSourceSave(true,'foreign');}),
h('p',['海外域名库：'+((manifest.foreign_count||0)+(manifest.foreign_exact_count||0))+' 条，自动参与“中国大陆以外”规则；精确域名优先于后缀，后缀按最具体匹配，手动调整优先。']),
h('p',['最后检查：'+(history.last_attempt_at||'尚未检查')+'；最后更新成功：'+(history.last_success_at||'尚未在线更新')]),
button('更新域名库',function(){self.nrUpdate('domain_update');}),button('回退上一版',function(){self.nrUpdate('domain_rollback');}),button('刷新状态',function(){self.nrLoad();}),h('p',[job.message||'']),
h('div',{class:'title_h4 clearfix'},[h('h4',['手动调整分组'])]),
h('p',['两个对话框仅保存手动分类，每行一个域名，包含其子域名。手动分类优先于在线库，在线更新不会覆盖；删除手动项或清空对话框会恢复在线库分类，不会清空在线域名库。']),
label('中国大陆',h('div',[h('span',{style:{marginRight:'16px'}},['已手动设置 '+this.nrGroupValues.cn.length+' 个域名']),button('添加 / 编辑中国大陆',function(){self.nrOpenGroup('cn');})])),
label('中国大陆以外',h('div',[h('span',{style:{marginRight:'16px'}},['已手动设置 '+this.nrGroupValues.foreign.length+' 个域名']),button('添加 / 编辑中国大陆以外',function(){self.nrOpenGroup('foreign');})])),
['cn','foreign'].map(function(group){return h('el-dialog',{key:group,attrs:{title:(group==='cn'?'中国大陆 · 手动域名':'中国大陆以外 · 手动域名'),size:'small','modal-append-to-body':true,'close-on-click-modal':false,'close-on-press-escape':!self.nrBusy,'show-close':false},model:{value:self.nrDialogs[group],callback:function(value){if(!self.nrBusy)self.nrDialogs[group]=value;}}},[
 h('div',{class:'helpService',style:{position:'absolute',top:'15px',right:'20px'}},[h('a',{class:'close_edit close_ico',attrs:{href:'javascript:void(0)',role:'button','aria-label':'关闭'},on:{click:function(){self.nrCloseGroup(group);}}},['×'])]),
 h('div',{class:'tl',style:{width:'90%',margin:'0 auto'}},[
  h('p',['每行只填一个域名，例如 example.com；包含其子域名。删除行后保存可移除手动调整。']),
  h('textarea',{class:'inptText',attrs:{id:'manual-domains-'+group,rows:10,disabled:self.nrBusy,'aria-label':(group==='cn'?'中国大陆':'中国大陆以外')+'手动域名',placeholder:'example.com\nexample.net'},style:{width:'100%',height:'220px',boxSizing:'border-box'},domProps:{value:self.nrDraft[group]},on:{input:function(e){self.nrDraft[group]=e.target.value;}}}),
  h('p',{class:'error_tip',attrs:{role:'alert'},style:{minHeight:'22px'}},[self.nrDialogError]),
  h('div',{class:'line_edit'},[button('保存',function(){self.nrSaveGroup(group);}),h('button',{class:'btn btn_cancel',attrs:{type:'button',disabled:self.nrBusy},on:{click:function(){self.nrCloseGroup(group);}}},['取消'])])])]);}),
this.dlRender(h),this.edRender(h),h('p',[this.nrMessage]),h('p',['普通 IPv4 DNS（TCP/UDP 53）按规则处理。应用内加密 DNS 不提供域名分类信息；未识别流量按已配置的兜底、端口和协议规则处理。本功能无法保证识别所有应用，也不能保证 CDN 一定返回大陆地址。'])])])])]);};return c;
};
},846:function(e,t,a){a(2068);var s=a(23)(a(1668),a(2312),"data-v-7c492333",null);e.exports=a(320010)(s.exports)}});
