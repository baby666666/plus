const assert=require('node:assert/strict'),fs=require('node:fs');
const H=require('../src/ctpanel-source-files.js');const results=[];
function test(name,f){f();results.push({name,pass:true})}
const rows=[{name:'中文源,带"引号"',url:'https://example.test/repo?a=1&b=2',enabled:'no'},{name:'标准源',url:'https://example.org/repo',enabled:'yes'}];
for(const format of ['txt','csv'])test(format+' round trip with name punctuation and disabled state',()=>assert.deepEqual(H.parse(H.serialize(rows,format),'file.'+format),rows));
test('legacy TXT with spaces in name',()=>assert.deepEqual(H.parse('name=测试 软件源 url=https://example.test/repo\r\n','old.txt'),[{name:'测试 软件源',url:'https://example.test/repo',enabled:'yes'}]));
test('legacy CSV BOM CRLF escaped comma',()=>assert.equal(H.parse('\ufeffname,url\r\n"a,b","https://example.test/repo"\r\n','old.csv')[0].name,'a,b'));
for (const [name,text,file] of [
 ['bad CSV quote','name,url\na,"https://example.test','x.csv'],['bad CSV header','url,name\nx,y','x.csv'],['CSV trailing column','name,url\na,https://example.test,extra','x.csv'],['invalid scheme','name=a url=javascript:alert(1)','x.txt'],['credentials','name=a url=https://user:pass@example.test','x.txt'],['bad state','name,url,enabled\na,https://example.test,maybe','x.csv'],['empty','','x.txt'],['wrong format','whatever','x.json'],['too many',Array(201).fill('name=a url=https://example.test').join('\n'),'x.txt'],['oversize','x'.repeat(262145),'x.txt'],['invalid UTF8','name=\ufffd url=https://example.test','x.txt']]) test(name+' rejected',()=>assert.throws(()=>H.parse(text,file)));
(async()=>{
 let stored=[{name:'existing',url:'https://EXAMPLE.test/repo/',enabled:'no'}],writes=[];
 const request=async(a,p)=>{if(a==='show')return {sources:stored.map(x=>({...x}))};writes.push(p);stored.push({...p});return {};};
 let out=await H.append([{name:'duplicate',url:'https://example.test/repo',enabled:'yes'},rows[1],rows[1]],request);
 assert.deepEqual(out,{added:1,skipped:2,total:3});assert.equal(stored[0].enabled,'no');assert.equal(writes.length,1);results.push({name:'append deduplicates without changing existing source',pass:true});
 let count=0;await assert.rejects(H.append([rows[1],{name:'bad',url:'javascript:x'}],async()=>{count++;return {sources:[]}}));assert.equal(count,0);results.push({name:'complete validation before first API call',pass:true});
 let n=0;await assert.rejects(H.append(rows,async(a,p)=>{if(a==='show')return {sources:[]};if(++n===2)throw Error('offline');return {};}),e=>e.result.added===1&&e.message.includes('导入中断'));results.push({name:'partial transport failure reported without false success',pass:true});
 await assert.rejects(H.append([rows[1]],async(a)=>a==='show'?{sources:[]}:{}),/保存结果未确认/);results.push({name:'read back required before success',pass:true});
 fs.writeFileSync(require('node:path').join(require('node:os').tmpdir(), 'source-files-unit.json'),JSON.stringify({passed:results.length,cases:results},null,2)+'\n');console.log('PASS',results.length,'source import/export cases');
})().catch(e=>{console.error(e);process.exitCode=1});
