'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=path.resolve(__dirname,'..'),web=path.resolve(source,'../firmware/port-3726/files/usr/ikuai/www');
const rows=JSON.parse(fs.readFileSync(path.join(source,'wg-translations.json')));
const dictionaries=Object.fromEntries(['zh-CN','zh-TW','en-US'].map(locale=>[locale,JSON.parse(fs.readFileSync(path.join(web,'static/i18n',locale+'.json'))).wire_guard.ext]));
let locale='zh-CN',checks=0;
const win={$t:key=>dictionaries[locale][key.replace('wire_guard.ext.','')]||key};
const context=vm.createContext({window:win,Promise,console,Number,Error});
for(const name of ['wg-i18n.js','wg-client-config.js','wg-singbox.js','wg-address-plan.js','wg-paste-import.js'])vm.runInContext(fs.readFileSync(path.join(source,'src',name),'utf8'),context);
function check(ok,msg){assert(ok,msg);checks++;}
for(locale of ['zh-CN','zh-TW','en-US']){
 for(const row of rows)check(win.WGI18n.text(row['zh-CN'])===row[locale],locale+' '+row.key);
 check(win.WGI18n.text('198.18.1.2/32')==='198.18.1.2/32','addresses unchanged');
 check(win.WGI18n.text('[Peer]\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820')==='[Peer]\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820','configuration syntax unchanged');
 try{context.WGClientConfig.endpointIP('');throw Error('expected validation');}catch(e){check(e.message===win.WGI18n.text('请填写客户端 Endpoint IP，或点击重新获取'),'client validation follows active locale');}
 try{context.WGPasteImport.parse('');throw Error('expected validation');}catch(e){check(e.message===win.WGI18n.text('请粘贴 WireGuard 配置。'),'import validation follows active locale');}
}
locale='en-US';check(!/[\u4e00-\u9fff]/.test(win.WGI18n.text('已新建服务接口 wg3，请保存隧道')),'dynamic interface notice translated');
const index=fs.readFileSync(path.join(web,'index.html'),'utf8'),assets=JSON.parse(fs.readFileSync(path.join(source,'wg-assets.json')));
check(index.indexOf(assets.i18n)<index.indexOf(assets.client),'translation helper precedes dependent helpers');
for(const name of ['wg-page.js','wg-client-config.js','wg-singbox.js','wg-address-plan.js','wg-paste-import.js']){
 const s=fs.readFileSync(path.join(source,'src',name),'utf8');
 for(const match of s.matchAll(/(["'])(?:\\.|(?!\1).)*?\1/g)){
  if(/[\u4e00-\u9fff]/.test(match[0]))check(s.slice(match.index-3,match.index)==='tr(','explicit product string is localized: '+name);
 }
}
console.log(JSON.stringify({passed:true,checks,locales:['zh-CN','zh-TW','en-US'],messages:rows.length}));
