#!/usr/bin/ikluajit
local json=require('cjson')
local M={}
local resident_manifest,resident_decoded
local function read(p) local f=assert(io.open(p,'rb'));local s=f:read('*a');f:close();return s end
local function write(p,s) local f=assert(io.open(p,'wb'));assert(f:write(s));assert(f:close()) end
local function quote(s) return "'"..s:gsub("'","'\\''").."'" end
local function sha(p) local f=assert(io.popen('sha256sum '..quote(p)));local s=f:read('*l');f:close();assert(s and s:match('^[a-f0-9]+'));return s:sub(1,64) end
function M.valid(d,base)
 if type(d)~='string' or #d>253 or #d<1 or d:find('%.%.') or d:sub(1,1)=='.' or d:sub(-1)=='.' then return false end
 if not d:find('%.') and not (base and #d>=2) then return false end
 if d:match('^[%d.]+$') then return false end
 for s in d:gmatch('[^.]+') do if #s>63 or not s:match('^[a-z0-9][a-z0-9%-]*$') or s:sub(-1)=='-' then return false end end
 return true
end
local function excluded(d) local t=d:match('([^.]+)$');return t=='hk' or t=='mo' or t=='tw' end
local function reverse(d) local a={};for s in d:gmatch('[^.]+') do table.insert(a,1,s) end;return table.concat(a,'.') end
function M.domains(root,kind)
 kind=kind or 'cn';local raw=read(root..'/'..kind..'.frontcode');assert(#raw<=8388608,'domain database too large')
 local out={};local pos,prev=1,''
 while pos<=#raw do
  local common,size=raw:byte(pos,pos+1);assert(size and common<=#prev and pos+1+size<=#raw,'invalid domain encoding')
  local s=prev:sub(1,common)..raw:sub(pos+2,pos+1+size);assert(s>prev,'unsorted or duplicate domains')
  pos=pos+2+size;prev=s;local d=reverse(s);assert(M.valid(d,true) and (kind~='cn'or not excluded(d)),'invalid encoded domain')
  out[#out+1]=d;assert(#out<=500000,'too many domains')
 end
 assert(kind~='cn'or #out>=50000,'incomplete domain database');return out
end
function M.foreign(root)
 local m=json.decode(read(root..'/domain-manifest.json'));if m.format~=2 and m.format~=3 and m.format~=4 then return {}end
 return M.domains(root,'foreign')
end
function M.foreign_exact(root)
 local m=json.decode(read(root..'/domain-manifest.json'));if m.format~=3 and m.format~=4 then return {}end
 return M.domains(root,'foreign-exact')
end
function M.cn_exact(root)
 local m=json.decode(read(root..'/domain-manifest.json'));if m.format~=4 then return {}end
 return M.domains(root,'cn-exact')
end
function M.verify(root,cache)
 -- Optional compiler cache stores validated decoded data in RAM. Every call
 -- still hashes the source files and checks the original manifest below.
 local manifest=read(root..'/domain-manifest.json');local decoded={};local hit=false
 if resident_manifest==manifest then decoded=resident_decoded;hit=true end
 if cache and not hit then
  local ok,value=pcall(function()
   local meta=json.decode(read(cache..'.meta'))
   assert(meta.format==1 and meta.manifest==manifest)
   assert(sha(cache)==meta.sha256,'decoded cache checksum mismatch')
   return json.decode(read(cache))
  end)
  if ok and type(value)=='table'then decoded=value;hit=true end
 end
 local function values(kind)if not decoded[kind]then decoded[kind]=M.domains(root,kind)end;return decoded[kind]end
 local m=json.decode(manifest);local cn=sha(root..'/cn.frontcode')
 if m.format==1 then assert(m.version==cn,'domain checksum mismatch')
 else
  assert(m.format==2 or m.format==3 or m.format==4,'invalid domain format');local foreign=sha(root..'/foreign.frontcode')
  assert(m.cn_sha256==cn and m.foreign_sha256==foreign,'domain checksum mismatch')
  local identity=cn..'\n'..foreign..'\n'
  if m.format>=3 then local exact=sha(root..'/foreign-exact.frontcode');assert(exact==m.foreign_exact_sha256,'exact domain checksum mismatch');assert(m.foreign_exact_count==#values('foreign-exact'),'exact domain count mismatch');identity=identity..exact..'\n'end
  if m.format==4 then local exact=sha(root..'/cn-exact.frontcode');assert(exact==m.cn_exact_sha256,'mainland exact checksum mismatch');assert(m.cn_exact_count==#values('cn-exact'),'mainland exact count mismatch');identity=identity..exact..'\n'end
  local f=assert(io.popen('printf %s '..quote(identity)..' | sha256sum'));local hash=f:read('*l');f:close();assert(hash:sub(1,64)==m.version,'domain version mismatch')
  assert(m.foreign_count==#values('foreign'),'foreign domain count mismatch')
 end
 assert(m.count==#values('cn'),'domain count mismatch')
 if cache and not hit then
  write(cache..'.new',json.encode(decoded))
  write(cache..'.meta.new',json.encode({format=1,manifest=manifest,sha256=sha(cache..'.new')}))
  assert(os.rename(cache..'.new',cache));assert(os.rename(cache..'.meta.new',cache..'.meta'))
 end
 resident_manifest,resident_decoded=manifest,decoded
 return m,decoded
end
local function parse(input,format,kind,found,exact)
 local raw=input and read(input)or'';assert(#raw<=16777216,'domain download too large');found=found or {};exact=exact or {}
 assert(format=='auto'or format=='plain'or format=='dnsmasq'or format=='mihomo'or format=='clash_domain','unsupported domain format')
 if raw:sub(1,3)=='\239\187\191'then raw=raw:sub(4)end
 local detected=format~='auto'and format or (raw:match('^%+%.')or raw:match('\n%+%.'))and'mihomo'or (raw:match('^%.')or raw:match('\n%.'))and'clash_domain'or nil
 for line in (raw..'\n'):gmatch('(.-)\n')do
  line=line:match('^%s*(.-)%s*$')
  if line~=''and not line:match('^#')then
   if not detected then detected=line:match('^server=/')and'dnsmasq'or'plain'end
   local d,ip,full=nil,'0.0.0.0',false
   if detected=='mihomo'then full=line:sub(1,2)~='+.';d=full and line or line:sub(3)
   elseif detected=='clash_domain'then full=line:sub(1,1)~='.';d=full and line or line:sub(2)
   elseif detected=='plain'then d=line
   else d,ip=line:match('^server=/([^/]+)/([%d.]+)$')end
   if d then d=d:lower()end
   assert(d and M.valid(d,true)and ip:match('^%d+%.%d+%.%d+%.%d+$'),'unexpected '..kind..' domain source syntax')
   for n in ip:gmatch('%d+')do assert(#n<=3 and tonumber(n)<256,'invalid source resolver')end
   if kind~='cn'or not excluded(d)then if full then exact[d]=true else found[d]=true end end
  end
 end
 return found,exact
end
local function encode(found)
 local domains={};for d in pairs(found)do domains[#domains+1]=reverse(d)end
 assert(#domains<=500000,'too many domains');table.sort(domains);local bytes={};local prev=''
 for _,v in ipairs(domains)do local n=0;while n<#prev and n<#v and prev:byte(n+1)==v:byte(n+1)do n=n+1 end;bytes[#bytes+1]=string.char(n,#v-n)..v:sub(n+1);prev=v end
 return table.concat(bytes),#domains
end
function M.build(input,out,foreign_input)
 local cn,ce=parse(input,os.getenv('DOMAIN_SOURCE_FORMAT')or'dnsmasq','cn')
 local foreign,fe=parse(foreign_input,os.getenv('FOREIGN_SOURCE_FORMAT')or'plain','foreign')
 local primary_f,primary_fe={},{};for d in pairs(foreign)do primary_f[d]=true end;for d in pairs(fe)do primary_fe[d]=true end
 local cp,fp=os.getenv('DOMAIN_EXTRA_FILE'),os.getenv('FOREIGN_EXTRA_FILE')
 if cp and cp~=''then parse(cp,'clash_domain','cn',cn,ce)end
 if fp and fp~=''then parse(fp,'clash_domain','foreign',foreign,fe)end
 -- Preserve the existing known-overseas classification: acceleration lists
 -- include foreign services with mainland CDN nodes. Supplement-only conflicts
 -- prefer mainland; application/manual rules still precede these categories.
 local conflicts=0;local preserved=0
 for d in pairs(foreign)do if cn[d]or ce[d]then
  if primary_f[d]then cn[d]=nil;ce[d]=nil;preserved=preserved+1 else foreign[d]=nil end
  conflicts=conflicts+1
 end end
 for d in pairs(fe)do if cn[d]or ce[d]then
  if primary_fe[d]then ce[d]=nil;preserved=preserved+1 else fe[d]=nil end
  conflicts=conflicts+1
 end end
 local cbytes,count=encode(cn);local cebytes,ccount=encode(ce)
 local fbytes,fcount=encode(foreign);local febytes,fecount=encode(fe)
 assert(count>=55309 and cn.cn and cn['baidu.com'],'abnormal mainland domain database')
 assert(count+ccount<=500000 and fcount+fecount<=500000,'too many domains')
 if (os.getenv('FOREIGN_SOURCE_URL')or'')~=''then assert(fcount+fecount>0,'empty foreign domain database')end
 -- Parse every source before writing a candidate. A malformed supplement cannot
 -- replace a valid installed snapshot or erase manual rules.
 for name,data in pairs({['cn.frontcode']=cbytes,['cn-exact.frontcode']=cebytes,['foreign.frontcode']=fbytes,['foreign-exact.frontcode']=febytes})do write(out..'/'..name,data)end
 local csha,fsha,esha,cesha=sha(out..'/cn.frontcode'),sha(out..'/foreign.frontcode'),sha(out..'/foreign-exact.frontcode'),sha(out..'/cn-exact.frontcode')
 write(out..'/identity',csha..'\n'..fsha..'\n'..esha..'\n'..cesha..'\n');local version=sha(out..'/identity');os.remove(out..'/identity')
 local cs=os.getenv('LIBRARY_SOURCE_URL')or'https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf'
 local fs=os.getenv('FOREIGN_SOURCE_URL')or''
 write(out..'/domain-manifest.json',json.encode({format=4,version=version,count=count,cn_exact_count=ccount,foreign_count=fcount,foreign_exact_count=fecount,cn_sha256=csha,cn_exact_sha256=cesha,foreign_sha256=fsha,foreign_exact_sha256=esha,source=cs,foreign_source=fs,cn_supplement=os.getenv('DOMAIN_EXTRA_URL')or'',foreign_supplement=os.getenv('FOREIGN_EXTRA_URL')or'',same_name_conflicts=conflicts,preserved_foreign_conflicts=preserved,created=os.date('!%Y-%m-%d %H:%M:%S UTC')})..'\n')
 M.verify(out);print(version)
end
function M.manual(c)
 local m={}
 for _,list in ipairs{c.foreign_domains or {},c.domain_overrides or {}} do
  assert(type(list)=='table' and #list<=20000,'too many manual domains')
  for k in pairs(list) do assert(type(k)=='number' and k%1==0 and k>=1 and k<=#list,'manual domains must be an array') end
 end
 for _,d in ipairs(c.foreign_domains or {}) do assert(M.valid(d,false),'invalid foreign domain');assert(not m[d],'duplicate manual domain');m[d]='foreign' end
 assert(type(c.domain_overrides or {})=='table' and #(c.domain_overrides or {})<=20000,'too many manual domains')
 for _,v in ipairs(c.domain_overrides or {}) do
  assert(type(v)=='table' and M.valid(v.domain,false) and (v.group=='cn' or v.group=='foreign'),'invalid manual domain group')
  assert(not m[v.domain],'duplicate manual domain');m[v.domain]=v.group
 end
 return m
end
local function ancestor(map,d) while d do if map[d] then return map[d],d end;d=d:match('^[^.]+%.(.+)$') end end
function M.maps(c,sets)
 local manual=M.manual(c);local fixed={}
 for i,r in ipairs(c.rules) do if r.kind=='domain' then for _,d in ipairs(r.domains) do fixed[d]={id=r.exit,set=sets and sets[i],rule=i} end end end
 return manual,fixed
end
function M.routes(c,sets,root,route)
 local manual,fixed=M.maps(c,sets)
 for _,d in ipairs(M.domains(root)) do if not ancestor(manual,d) and not ancestor(fixed,d) then route(d,c.cn_dns,'sp_d_cn') end end
 for _,d in ipairs(M.foreign(root))do if not ancestor(manual,d)and not ancestor(fixed,d)then route(d,c.foreign_dns,'sp_d_foreign')end end
 for d,g in pairs(manual) do if not ancestor(fixed,d) then route(d,g=='cn' and c.cn_dns or c.foreign_dns,g=='cn' and 'sp_d_cn' or 'sp_d_foreign') end end
 for d,v in pairs(fixed) do route(d,v.id,v.set) end
end
function M.lookup(c,d,root)
 assert(M.valid(d,false),'invalid lookup domain');local manual,fixed=M.maps(c);local v,match=ancestor(fixed,d)
 if v then return {domain=d,source='fixed',matched=match,exit=v.id,rule=v.rule} end
 local g,match=ancestor(manual,d)
 if not g then
  local cn,foreign={},{};for _,s in ipairs(M.domains(root))do cn[s]=true end;for _,s in ipairs(M.foreign(root))do foreign[s]=true end
  local p=d;while p do if foreign[p]then g='foreign';match=p;break elseif cn[p]then g='cn';match=p;break end;p=p:match('^[^.]+%.(.+)$')end
  g=g or 'foreign'
 end
 return {domain=d,group=g,source=ancestor(manual,d) and 'manual' or (g=='cn' and 'database' or 'default'),matched=match or '',dns=g=='cn' and c.cn_dns or c.foreign_dns,exit=g=='cn' and c.cn_exit or c.foreign_exit}
end
function M.signature(c,root,sets)
 local a={'domain-format-4',read(root..'/domain-manifest.json')}
 local manual,fixed=M.maps(c,sets)
 for d,g in pairs(manual) do a[#a+1]='group:'..d..':'..g end
 for d,v in pairs(fixed) do a[#a+1]='set:'..d..':'..v.set end
 table.sort(a);return table.concat(a,'\n')..'\n'
end
if arg and arg[0] and arg[0]:match('/domain_lib%.lua$') then
 local ok,err=pcall(function()
  if arg[1]=='build' then M.build(arg[2],arg[3],arg[4])
  elseif arg[1]=='verify' then M.verify(arg[2]);print('valid')
  elseif arg[1]=='lookup' then print(json.encode(M.lookup(json.decode(read(arg[2])),arg[3],arg[4])))
  elseif arg[1]=='rename' then
   local target=arg[3];assert(target=='/etc/mnt/ikuai/domain-iplib/current' or target=='/etc/mnt/ikuai/domain-iplib/previous')
   assert(arg[2]:sub(1,#target+5)==target..'.new.' and arg[2]:sub(#target+6):match('^%d+$'));assert(os.rename(arg[2],target))
  elseif arg[1]=='state' then print(json.encode({state=arg[2],message=arg[3],time=arg[4]}))
  elseif arg[1]=='status' then
   local job={state='idle',message='尚未执行在线更新'};local f=io.open(arg[3]);if f then job=json.decode(f:read('*a'));f:close() end
   if job.state=='running' and arg[5]~='true' then job={state='failed',message='更新中断，继续使用原库或等待启动恢复'} end
   print(json.encode({manifest=json.decode(read(arg[2])),job=job,can_rollback=arg[4]=='true'}))
  else error('unknown action') end
 end)
 if not ok then io.stderr:write(tostring(err),'\n');os.exit(1) end
end
return M
