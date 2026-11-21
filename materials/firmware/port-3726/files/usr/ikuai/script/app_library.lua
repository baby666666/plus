#!/usr/bin/ikluajit
local j=require('cjson')
local M={cache_validation=true}
local validated_apps={}
local base='/usr/share/strict-routing/app-library.json'
local home='/etc/mnt/ikuai/app-library'
local catalog
local function defaults() if not catalog then catalog=j.decode((function() local f=assert(io.open(base));local s=f:read('*a');f:close();return s end)()).apps end;return catalog end
local function read(p) local f=assert(io.open(p));local s=f:read('*a');f:close();return s end
local function decode(p)return j.decode(read(p))end
local function write(p,t)local f=assert(io.open(p,'w'));assert(f:write(j.encode(t)..'\n'));assert(f:close())end
local function trim(s)return s:match('^%s*(.-)%s*$')end
function M.domain(s)
 if type(s)~='string' or #s>253 or not s:find('%.') or s:find('[^a-z0-9%.%-]') or s:match('^[%d%.]+$') then return false end
 for label in (s..'.'):gmatch('(.-)%.')do if #label<1 or #label>63 or not label:match('^[a-z0-9]') or not label:match('[a-z0-9]$')then return false end end
 return true
end
function M.url(s)
 assert(type(s)=='string' and #s<=2048 and not s:find('[%s%c]'),'订阅地址无效')
 local host,path=s:match('^https://([%w%.%-]+)(/[^#]*)$');assert(host and path,'请填写 HTTPS 文件地址，不支持账号密码或自定义端口')
 if host=='github.com'then local owner,repo,file=path:match('^/([%w_.%-]+)/([%w_.%-]+)/blob/(.+)$');assert(owner,'请选择 GitHub 具体文件的 blob 链接或 raw 地址');s='https://raw.githubusercontent.com/'..owner..'/'..repo..'/'..file end
 return s
end
local function rule(t,v)
 assert(t=='DOMAIN' or t=='DOMAIN-SUFFIX','仅支持 DOMAIN 和 DOMAIN-SUFFIX 域名匹配')
 v=v:lower();assert(M.domain(v),'无效域名：'..v);return {type=t,value=v}
end
function M.manual(text)
 assert(type(text)=='string' and #text<=60000,'手动内容过长');local out,seen={},{}
 for line in (text..'\n'):gmatch('(.-)\n')do
  line=trim(line);if line~=''then
   local t,v=line:match('^(DOMAIN%-?[%u]*),%s*(.+)$');local r=rule(t or 'DOMAIN-SUFFIX',v or line);local k=r.type..','..r.value
   assert(not seen[k],'重复条目：'..k);seen[k]=true;out[#out+1]=r;assert(#out<=1000,'手动条目最多 1000 条')
  end
 end
 return out
end
function M.parse(text,allow_references)
 assert(type(text)=='string' and #text<=2097152,'订阅文件超过 2 MiB')
 text=text:gsub('^\239\187\191','');local out,seen,ips={},{},{};local bad={};local n=0
 for line in (text..'\n'):gmatch('(.-)\n')do
  n=n+1;line=trim(line)
  if line~='' and line:sub(1,1)~='#'then
   local t,v,opt=line:match('^([A-Z0-9%-]+),([^,]+)(.*)$')
   if not t and not line:find(',') then
    if line:sub(1,2)=='+.'then t,v='DOMAIN-SUFFIX',line:sub(3)
    elseif line:sub(1,1)=='.'then t,v='DOMAIN-SUFFIX',line:sub(2)
    else t,v='DOMAIN',line end
    opt=''
   end
   if t=='DOMAIN' or t=='DOMAIN-SUFFIX'then
    assert(opt=='','第 '..n..' 行包含不支持的参数')
    if allow_references and not v:find('%.')and v:match('^[a-z0-9%-]+$')then ips[#ips+1]=t..':'..v
    else local r=rule(t,trim(v));local k=r.type..','..r.value;if not seen[k]then seen[k]=true;out[#out+1]=r end end
   elseif allow_references and (t=='DOMAIN-KEYWORD'or t=='PROCESS-NAME'or t=='IP-CIDR6')then
    assert((opt==''or opt==',no-resolve')and #v<=253 and v:match('^[%w%.%-%_:/*]+$'),'附带规则无效')
    ips[#ips+1]=t..':'..v
   elseif t=='IP-ASN'then
    assert((opt==''or opt==',no-resolve')and v:match('^%d+$')and tonumber(v)>0 and tonumber(v)<=4294967295,'ASN 条目无效')
    ips[#ips+1]='ASN:'..v
   elseif t=='IP-CIDR'then
    assert(opt==''or opt==',no-resolve','IP 条目参数无效')
    local a,b,c,d,bits=v:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)/(%d+)$')
    assert(a and tonumber(a)<256 and tonumber(b)<256 and tonumber(c)<256 and tonumber(d)<256 and tonumber(bits)<=32,'IPv4 网段无效')
    ips[#ips+1]=v
   else bad[#bad+1]='第 '..n..' 行 '..tostring(t or line:sub(1,32));if #bad==5 then break end end
  end
  assert(#out<=20000 and #ips<=20000,'单个应用最多 20000 条域名或 IPv4 条目')
 end
 assert(#bad==0,'订阅包含不支持的规则，未导入：'..table.concat(bad,'；'))
 assert(#out>0,'没有可用的应用域名；本版只应用域名规则')
 table.sort(out,function(a,b)return a.type..a.value<b.type..b.value end);return out,ips
end
local function suffix(q,d)return q==d or #q>#d and q:sub(-#d-1)=='.'..d end
function M.covers(a,b)return a.type=='DOMAIN' and b.type=='DOMAIN' and a.value==b.value or a.type=='DOMAIN-SUFFIX' and suffix(b.value,a.value)end
function M.intersects(a,b)
 local function covered(left,right)
  local exact,suffixes={},{}
  for _,r in ipairs(left)do if r.type=='DOMAIN'then exact[r.value]=true else suffixes[r.value]=true end end
  for _,r in ipairs(right)do
   if exact[r.value]then return true end
   local d=r.value
   while d do if suffixes[d]then return true end;d=d:match('^[^.]+%.(.+)$')end
  end
  return false
 end
 return covered(a,b)or covered(b,a)
end
-- Match exclusions by domain labels instead of scanning every exclusion for every rule.
local function exclusion_index(rules)
 local exact,suffixes={},{}
 for _,r in ipairs(rules)do (r.type=='DOMAIN' and exact or suffixes)[r.value]=true end
 return function(r)
  if r.type=='DOMAIN' and exact[r.value]then return true end
  local name=r.value
  while name do if suffixes[name]then return true end;name=name:match('^[^.]+%.(.+)$')end
  return false
 end
end
function M.effective(a)
 local out,seen={},{};local additions=M.manual(a.add or '');local excluded=M.manual(a.exclude or '');local covered=exclusion_index(excluded)
 for _,r in ipairs(a.rules or {})do if not covered(r)then local k=r.type..','..r.value;if not seen[k]then out[#out+1]=r;seen[k]=true end end end
 for _,r in ipairs(additions)do assert(not covered(r),'手动添加与排除冲突：'..r.value);local k=r.type..','..r.value;if not seen[k]then out[#out+1]=r;seen[k]=true end end
 return out,excluded
end
function M.validate(c)
 assert(type(c)=='table' and c.version==1 and type(c.apps)=='table','应用库配置无效');local count,total,names=0,0,{};local validated_next={}
 for key,a in pairs(c.apps)do
  count=count+1;assert(count<=64,'最多保存 64 个应用订阅')
  assert(type(key)=='string'and key:match('^[a-z][a-z0-9_]*$')and #key<=24,'应用标识无效')
  assert(type(a)=='table'and type(a.label)=='string'and #a.label>0 and #a.label<=60 and not a.label:find('[%c<>"\'&]'),'应用名称无效')
  assert(not names[a.label],'应用名称重复');names[a.label]=true
  assert(type(a.enabled)=='boolean','启用状态无效');a.url=M.url(a.url)
  assert(type(a.rules)=='table' and #a.rules<=20000,'应用条目过多');total=total+#a.rules;assert(total<=100000,'应用域名总数不能超过 100000 条')
  local signature=M.cache_validation and j.encode(a)or nil
  if not signature or validated_apps[key]~=signature then
   for _,r in ipairs(a.rules)do rule(r.type,r.value)end
   M.effective(a)
  end
  if signature then validated_next[key]=signature end
 end
 if M.cache_validation then validated_apps=validated_next end
 return c
end
local function builtin_url(a,d)
 if not d then return false end
 if a.url==d.url then return true end
 for _,u in ipairs(d.legacy_urls or {})do if a.url==u then return true end end
 return false
end
function M.load(path)
 local c=M.validate(decode(path or (os.getenv('APP_LIBRARY_FILE')or home..'/current.json')))
 local count,names=0,{};for _,a in pairs(c.apps)do count=count+1;names[a.label]=true end
 local upgrade=(tonumber(c.catalog_revision)or 0)<19;local changed=false
 for key,d in pairs(defaults())do
  local a=c.apps[key]
  if not a and not names[d.label]and count<64 then changed=true;c.apps[key]=j.decode(j.encode(d));count=count+1;names[d.label]=true
  elseif a and upgrade then
   changed=true
   -- One-time requested enablement; later user disablements survive reboot/update.
   a.enabled=true
   if builtin_url(a,d) then
    a.url=d.url;a.rules=j.decode(j.encode(d.rules));a.ips=j.decode(j.encode(d.ips or {}));a.supplements={};a.last_checked=nil;a.last_changed=d.last_changed
   end
  end
 end
 c.catalog_revision=19
 return changed and M.validate(c)or c
end
-- Shared by the CLI and serialized resident compiler. Always decode a fresh
-- document: a failed edit must never mutate a cached/live generation.
function M.save(current,input,output)
 local c=M.load(current);local p=decode(input);local key=p.key;assert(type(key)=='string','缺少应用标识');local old=c.apps[key]
 if p.remove then assert(not defaults()[key],'内置应用可停用，不能删除');c.apps[key]=nil
 else
  local oldurl=old and old.url or '';local a=old or {rules={},ips={},add='',exclude='',enabled=false}
  a.label=p.label;a.url=(p.reset and defaults()[key])and defaults()[key].url or p.url;a.enabled=p.enabled;a.add=p.add or '';a.exclude=p.exclude or ''
  if a.url~=oldurl then a.last_checked=nil end
  c.apps[key]=a
 end
 write(output,M.validate(c))
end
function M.sources(a,key)return {a.url}end
function M.scope(rules,key,url)
 local d=defaults()[key];if not d or url~=d.url or (not d.scope_domains and not d.scope_rules)then return rules end
 local scopes={};for _,v in ipairs(d.scope_domains or {})do scopes[#scopes+1]={type='DOMAIN-SUFFIX',value=v}end
 for _,r in ipairs(d.scope_rules or {})do scopes[#scopes+1]=r end
 local out,seen={},{}
 local function add(r)local k=r.type..','..r.value;if not seen[k]then seen[k]=true;out[#out+1]=r end end
 for _,r in ipairs(rules)do for _,scope in ipairs(scopes)do
  if M.covers(scope,r)then add(r)elseif M.covers(r,scope)then add(scope)end
 end end
 assert(#out>0,'应用专用范围内没有可用域名');table.sort(out,function(a,b)return a.type..a.value<b.type..b.value end);return out
end
-- Only effective rules referenced by enabled routing rows can affect runtime.
function M.impact(before,after,snapshot)
 local function signature(a)
  if not a then return 'missing' end
  local rules,exclude=M.effective(a);local rows={tostring(a.enabled)}
  for _,r in ipairs(rules)do rows[#rows+1]='R:'..r.type..','..r.value end
  for _,r in ipairs(exclude)do rows[#rows+1]='X:'..r.type..','..r.value end
  table.sort(rows);return table.concat(rows,'\n')
 end
 for _,r in ipairs(snapshot.domain or {})do if r.enabled=='yes'and r.nr_group=='app'and signature(before.apps[r.nr_app])~=signature(after.apps[r.nr_app])then return 'changed' end end
 return 'unchanged'
end
function M.current()
 local f=io.open(home..'/current.json');if f then f:close();return M.load(home..'/current.json')end;return M.load(base)
end
function M.summary(c)
 local apps={};for key,a in pairs(c.apps)do local rules=M.effective(a);local d=defaults()[key]or{};apps[#apps+1]={key=key,label=a.label,url=a.url,enabled=a.enabled,add=a.add,exclude=a.exclude,count=#rules,ip_count=#(a.ips or {}),last_checked=a.last_checked,last_changed=a.last_changed,default_url=d.url or '',builtin=d.url~=nil,category=d.category or '自定义',region=d.region or 'custom',provider=(a.url==d.url and d.provider) or '自定义',order=d.order or 999,note=d.note or '',sources=M.sources(a,key)}end
 table.sort(apps,function(a,b)if a.order~=b.order then return a.order<b.order end;return a.key<b.key end);return {apps=apps}
end
local function content(a)
 local rows={};for _,r in ipairs(a.rules or {})do rows[#rows+1]=r.type..','..r.value end
 for _,ip in ipairs(a.ips or {})do rows[#rows+1]='IP-CIDR,'..ip end
 table.sort(rows);return table.concat(rows,'\n')
end
function M.main()
 local action=arg[1]
 if action=='sources'then local a=assert(M.load(arg[2]).apps[arg[3]]);for _,u in ipairs(M.sources(a,arg[3]))do print(M.url(u))end
 elseif action=='init'then write(arg[2],M.validate(decode(base)))
 elseif action=='migrate'then write(arg[3],M.load(arg[2]))
 elseif action=='impact'then print(M.impact(M.load(arg[2]),M.load(arg[3]),decode(arg[4])))
 elseif action=='verify'then M.load(arg[2])
 elseif action=='status'then
  -- Cache only the UI summary, never compiled routing data or job state. The caller
  -- keys it by immutable input snapshot, catalog, and implementation hashes.
  local out;local cache,key,tmp=arg[5],arg[6],arg[7]
  if cache and key then local ok,c=pcall(decode,cache);if ok and type(c)=='table'and c.key==key and type(c.summary)=='table'and type(c.summary.apps)=='table'then out=c.summary end end
  if not out then
   out=M.summary(M.load(arg[2]))
   if cache and key and tmp then
    local ok=pcall(write,tmp,{key=key,summary=out})
    if ok then os.rename(tmp,cache)end;os.remove(tmp)
   end
  end
  out.revision=arg[3];out.job={};local f=io.open(arg[4]or'');if f then f:close();local ok,job=pcall(decode,arg[4]);if ok then out.job=job end end;print(j.encode(out))
 elseif action=='job'then print(j.encode({state=arg[2],message=arg[3],at=arg[4]}))
 elseif action=='detail'then local a=assert(M.load(arg[2]).apps[arg[3]],'应用不存在');local rules,exclude=M.effective(a);print(j.encode({rules=rules,exclude=exclude,ips=a.ips or {}}))
 elseif action=='save'then
  M.save(arg[2],arg[3],arg[4])
 elseif action=='download_plan'then
  local c=M.load(arg[2]);local keys={}
  if arg[3]=='all'then for key,a in pairs(c.apps)do if a.enabled then keys[#keys+1]=key end end;table.sort(keys)
  else assert(c.apps[arg[3]],'应用不存在');keys={arg[3]}end
  for _,key in ipairs(keys)do for _,u in ipairs(M.sources(c.apps[key],key))do print(key..'\t'..M.url(u))end end
 elseif action=='merge_all'then
  -- One immutable batch: parse every download before publishing any library.
  local c=M.load(arg[2]);local seen={};local count=0
  for line in (read(arg[3])..'\n'):gmatch('(.-)\n')do if line~=''then
   local key=line:match('^([a-z][a-z0-9_]*)\t');assert(key and #key<=24 and c.apps[key],'下载计划无效')
   if not seen[key]then
    seen[key]=true;count=count+1;local a=c.apps[key];local d=defaults()[key];local before=content(a)
    local rules,ips=M.parse(read(arg[4]..'/'..key..'.list'),d and a.url==d.url)
    a.rules=M.scope(rules,key,a.url);a.ips=ips;a.last_checked=arg[6];if before~=content(a)then a.last_changed=arg[6]end
   end
  end end
  assert(count>0,'没有启用的应用');write(arg[5],M.validate(c))
 elseif action=='merge'then
  local c=M.load(arg[2]);local key=arg[3];local a=assert(c.apps[key]);local d=defaults()[key];local builtin=d and a.url==d.url;local rules,ips=M.parse(read(arg[4]),builtin);local before=content(a)
  a.rules=M.scope(rules,key,a.url);a.ips=ips;a.last_checked=arg[6];if before~=content(a)then a.last_changed=arg[6]end
  write(arg[5],M.validate(c))
 else error('未知应用库操作')end
end
if arg and arg[0] and arg[0]:match('app_library%.lua$')then local ok,e=pcall(M.main);if not ok then io.stderr:write(tostring(e),'\n');os.exit(1)end end
return M
