'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../time/app.js'),'utf8');
const body=source.slice(source.indexOf('201:function'),source.indexOf(',309:function'));
const data={common:{title:'Working'},'left-menu':{home:'Home'}};
const tick=()=>new Promise(resolve=>setImmediate(resolve));

function setup(language, responses, initial={}) {
    const local={language}, session=Object.assign({},initial), urls=[], timers=[];
    function store(items) {
        return {getItem:key=>items[key] ?? null,setItem:(key,value)=>{items[key]=String(value);}};
    }
    const root={appendChild(button){this.retry=button;}}, window={localStorage:store(local), sessionStorage:store(session)};
    const http={get(url,opts) {
        urls.push(url);
        assert.equal(opts.timeout,8000);
        const reply=responses.shift();
        return reply instanceof Error ? Promise.reject(reply) : Promise.resolve({data:reply});
    }};
    function webpack(id){assert.equal(id,227);return http;}
    webpack.n=module=>({a:module});
    const document={currentScript:{src:'/static/js/app.A.js?v=1'},getElementById:()=>root,createElement:()=>({})};
    const fn=vm.runInNewContext('({'+body+'})[201]',{window,document,setTimeout:cb=>{timers.push(cb);}});
    const exports={};fn({},exports,webpack);
    class Vue {}
    exports.a.install(Vue);
    return {plugin:exports.a,local,session,urls,timers,root,Vue};
}

(async()=>{
    const a=setup('',[data],{translationFor:'zh-CN@/static/js/app.A.js',translation:'broken json'});
    await a.plugin.ready;
    assert.deepEqual(a.urls,['/static/i18n/zh-CN.json?v=rc21-hy2-policy']);assert.equal(a.local.language,'zh-CN');
    assert.equal(a.Vue.prototype.$t('common.title'),'Working');
    const b=setup('en-US',[new Error('lost'),'<html>', data],a.session);
    await tick();assert.equal(b.timers.length,1);b.timers.shift()();await tick();
    assert.equal(b.plugin.ok,false);assert.equal(b.timers.length,0);
    assert.equal(b.root.retry.textContent,'Retry');b.root.retry.onclick();await b.plugin.ready;
    assert.deepEqual(b.urls,Array(3).fill('/static/i18n/en-US.json?v=rc21-hy2-policy'));
    const cached=setup('en-US',[],b.session);await cached.plugin.ready;assert.equal(cached.urls.length,0);
    const other=setup('../bad',[data]);await other.plugin.ready;assert.equal(other.plugin.locale,'zh-CN');
    console.log('PASS management language fallback, bounded retry, manual recovery and language-specific cache');
})().catch(e=>{console.error(e);process.exitCode=1;});
