'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {makeInstance,createElement,treeText,treeNodes}=require('./routing-ui-unit.js');
const dictionary=JSON.parse(fs.readFileSync(path.join(__dirname,'../web-src/routing/status-translations.json'),'utf8'));
let checks=0;
function check(value,message){assert(value,message);checks++;}
function page(){
 const p=makeInstance('domain');p.instance.locale='zh-CN';p.instance.$route={fullPath:'/routing/domain'};
 p.instance.$t=function(key,args){
  if(!key.startsWith('routing_runtime.'))return key;
  let text=dictionary[this.locale][key.slice('routing_runtime.'.length)];assert.equal(typeof text,'string','missing translation '+key);
  // The firmware translator returns text and ignores named interpolation arguments.
  return text;
 };
 return p;
}
function response(extra={}){return {runtime_status:{version:1,phase:'running',busy:false,dns_front:'running',
 exits:[{id:3,interface:'wg3',health:'reachable',probe_age_seconds:2,handshake_age_seconds:25}],
 workers:[{id:1,policy:4,dns:'1.1.1.1',interface:'wg3',state:'selected',process:'running'},
  {id:2,policy:4,dns:'8.8.8.8',state:'blocked',process:'stopped'}],
 quarantine:{available:true,entries:4,remaining_seconds:32,window_seconds:61},...extra}};}
function text(p){return treeText(p.rsRender(createElement));}

(async()=>{
 const {instance:p,component}=page();let requests=[];
 p.nrApi=(action,param)=>{requests.push([action,param]);return Promise.resolve(response());};
 check(p.rsSnapshot===null&&!p.rsBusy,'initial state has no purported live result');
 check(text(p).includes('点击')&&requests.length===0,'rendering is a no-op until manual refresh');
 p.nrLoad=async()=>{};
 component.mounted.call(p);await Promise.resolve();
 check(requests.length===0,'mount and existing library load do not read runtime status');
 const refreshed=await p.rsRefresh();
 check(refreshed&&requests.length===1,'manual refresh sends one request');
 check(requests[0][0]==='show'&&requests[0][1].TYPE==='runtime_status','request is exactly the read-only status API');
 check(text(p).includes('wg3')&&text(p).includes('1.1.1.1')&&text(p).includes('8.8.8.8'),'exit and resolver names are visible');
 check(text(p).includes('检测可达')&&text(p).includes('25 秒前')&&text(p).includes('未运行'),'health, handshake age and stopped resolver appear separately');
 check(text(p).includes('暂不发送解析请求'),'blocked resolver is explicit');
 check(text(p).includes('最多还剩 32 秒')&&text(p).includes('不自动倒计时'),'quarantine estimate is identified as a refresh-time upper bound');
 check(text(p).includes('不代表所有网站'),'handshake and health do not claim website reachability');
 for(const locale of ['zh-CN','zh-TW','en-US']){
  p.locale=locale;
  for(const seconds of [0,1,59,86400,4294967295]){
   p.nrApi=async()=>response({exits:[{interface:'wg3',health:'reachable',probe_age_seconds:seconds,handshake_age_seconds:seconds}],quarantine:{available:true,entries:4,remaining_seconds:0}});
   await p.rsRefresh();const rendered=text(p);
   check(rendered.includes(locale==='en-US'?seconds+' seconds ago':seconds+' 秒前'),locale+' interpolates age '+seconds);
   check(!/\{(?:seconds|count)\}/.test(rendered),locale+' renders every numeric placeholder');
   check(rendered.includes(locale==='en-US'?'Protection records: 4.':locale==='zh-TW'?'保護記錄：4 筆。':'保护记录：4 条。'),locale+' interpolates protection count');
  }
  p.nrApi=async()=>response({exits:[{interface:'wg3',health:'unknown',probe_age_seconds:null,handshake_age_seconds:null}]});await p.rsRefresh();
  check(text(p).includes(dictionary[locale].not_available),locale+' keeps missing records distinct from zero seconds');
 }
 p.locale='zh-CN';p.nrApi=async()=>response();await p.rsRefresh();
 const buttons=treeNodes(p.rsRender(createElement)).filter(n=>n.tag==='button');
 check(buttons.length===1&&buttons[0].data.attrs.type==='button','one non-submitting manual action');
 check(!/setTimeout|setInterval/.test(p.rsRefresh.toString()+p.rsRender.toString()),'diagnostic functions create no polling or countdown timers');

 let deliver;requests=[];p.nrApi=(a,b)=>{requests.push([a,b]);return new Promise(r=>deliver=r);};
 const first=p.rsRefresh();await Promise.resolve();const duplicate=await p.rsRefresh();
 check(!duplicate&&requests.length===1,'repeated clicks share no extra request');
 check(p.rsBusy&&p.rsSnapshot===null&&!text(p).includes('wg3'),'refresh hides the prior snapshot while reading');
 check(treeNodes(p.rsRender(createElement)).find(n=>n.tag==='button').data.attrs.disabled,'button disabled while reading');
 deliver(response({phase:'applying',busy:true}));await first;
 check(!p.rsBusy&&p.rsSnapshot.exits.length===0&&p.rsSnapshot.workers.length===0,'server busy reply discards partial detail rows');
 check(text(p).includes('正在应用规则')&&!text(p).includes('wg3'),'busy phase shown without old exit success');

 p.nrApi=async()=>{throw Error('PRIVATE_KEY=/etc/private uid=48201 mark=0x55000101');};
 check(!await p.rsRefresh(),'read rejection is handled');
 check(p.rsSnapshot===null&&!p.rsBusy&&text(p).includes('稍后重试'),'failure hides stale success and permits retry');
 check(!/PRIVATE_KEY|\/etc|48201|0x55000101/.test(text(p)),'raw backend errors never reach the page');
 p.locale='en-US';check(text(p).includes('Unable to read')&&!/[\u3400-\u9fff]/.test(text(p)),'error translates when language changes');
 p.locale='zh-TW';check(text(p).includes('讀取')&&!text(p).includes('读取'),'Traditional Chinese uses its dictionary');
 p.locale='zh-CN';p.nrApi=()=>{throw Error('synchronous transport failure');};
 check(!await p.rsRefresh()&&!p.rsBusy,'synchronous API failure is also handled');

 for(const phase of ['busy','starting','applying','protected','running','inactive','unknown']){
  p.nrApi=async()=>response({phase});await p.rsRefresh();
  check(text(p).includes(dictionary['zh-CN']['phase_'+phase]),'localized phase '+phase);
 }
 p.nrApi=async()=>response({phase:'<secret>',reasons:['/tmp/private-state'],
  private_key:'KEEP_PRIVATE',uid:48201,mark:'0x55000101',
  exits:[{interface:'wg3',health:'secret',probe_age_seconds:-1,handshake_age_seconds:Infinity,private_key:'KEEP_PRIVATE'}],
  workers:[{dns:'<script>private</script>',interface:'/etc/private',state:'selected',process:'secret',secret:'KEEP_PRIVATE'}],
  quarantine:{available:true,entries:1,remaining_seconds:99}});
 await p.rsRefresh();
 check(!/KEEP_PRIVATE|\/tmp|\/etc|<script>|48201|0x55000101|<secret>/.test(text(p)+JSON.stringify(p.rsSnapshot)),'only bounded public fields are retained or rendered');
 check(p.rsSnapshot.phase==='unknown'&&p.rsSnapshot.exits[0].health==='unknown','unknown status enums cannot become arbitrary translation keys');
 check(p.rsSnapshot.exits[0].probe_age_seconds===null&&p.rsSnapshot.exits[0].handshake_age_seconds===null,'invalid ages become unavailable');
 check(text(p).includes('暂时无法估计剩余时间'),'unbounded quarantine estimate is not shown as a countdown');
 p.nrApi=async()=>response({quarantine:{available:true,entries:0,remaining_seconds:0}});await p.rsRefresh();
 check(text(p).includes('未发现旧地址保护记录'),'zero entries reported as no current records');
 p.nrApi=async()=>response({quarantine:{available:false}});await p.rsRefresh();
 check(text(p).includes('暂时无法读取旧地址保护状态'),'missing counters are not reported as zero');
 p.nrApi=async()=>response({exits:Array(200).fill({interface:'wg3',health:'unknown'}),workers:Array(40).fill({dns:'1.1.1.1',state:'unknown'})});await p.rsRefresh();
 check(p.rsSnapshot.exits.length===132&&p.rsSnapshot.workers.length===32,'oversized response arrays have bounded rendering');
 p.nrApi=async()=>({runtime_status:{version:2}});await p.rsRefresh();
 check(p.rsError==='read_failed'&&p.rsSnapshot===null,'unsupported response version fails visibly');

 p.nrApi=async()=>response();await p.rsRefresh();p.nrBusy=true;
 check(!text(p).includes('wg3')&&text(p).includes('正在处理设置'),'local apply hides an earlier snapshot');p.nrBusy=false;
 let oldDeliver,newDeliver;
 p.nrApi=()=>new Promise(r=>oldDeliver=r);const oldRequest=p.rsRefresh();await Promise.resolve();
 p.rsSequence++;p.rsBusy=false;p.nrApi=()=>new Promise(r=>newDeliver=r);
 const newRequest=p.rsRefresh();await Promise.resolve();newDeliver(response({phase:'protected'}));await newRequest;
 oldDeliver(response({phase:'running'}));await oldRequest;
 check(p.rsSnapshot.phase==='protected','late older sequence cannot replace a newer result');

 p.nrApi=()=>new Promise(r=>deliver=r);const leaving=p.rsRefresh();await Promise.resolve();p.$route.fullPath='/routing/port';
 deliver(response());await leaving;
 check(p.rsSnapshot===null&&!p.rsBusy,'late reply on another route is ignored and releases request state');
 p.$route.fullPath='/routing/domain';p.nrApi=()=>new Promise(r=>deliver=r);
 const destroyed=p.rsRefresh();await Promise.resolve();component.beforeDestroy.call(p);deliver(response());await destroyed;
 check(p.nrDisposed&&p.rsSnapshot===null,'late reply after component destruction is ignored');

 const keys=Object.keys(dictionary['zh-CN']).sort();
 for(const language of ['zh-TW','en-US'])check(JSON.stringify(Object.keys(dictionary[language]).sort())===JSON.stringify(keys),language+' covers every status message');
 console.log(JSON.stringify({passed:true,checks,translationKeys:keys.length}));
})().catch(e=>{console.error(e);process.exitCode=1;});
