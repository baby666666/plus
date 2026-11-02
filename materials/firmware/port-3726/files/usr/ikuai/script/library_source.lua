#!/usr/bin/ikluajit
local j=require('cjson')
local function read(p,default)local f=io.open(p);if not f then return default end;local s=f:read('*a');f:close();return j.decode(s)end
local function write(p,t)local tmp=p..'.new';local f=assert(io.open(tmp,'w'));assert(f:write(j.encode(t)..'\n'));assert(f:close());assert(os.rename(tmp,p))end
local defaults={region={url='https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz',format='country_tar_gz'},domain={url='https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf',format='auto'}}
local foreign_default='https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/geolocation-!cn.list'
local cn_extra='https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax_Domain.txt'
local foreign_extra='https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Global/Global_Domain.txt'
local regionkeys={'cn','foreign','asia','europe','americas','oceania','africa','hk','mo','tw'}
local function normalize(url)
 assert(type(url)=='string' and #url<=2048,'下载地址过长或无效')
 if url==''then return ''end
 assert(not url:find('[%s%c]') and url:sub(1,8)=='https://','请填写 HTTPS 文件下载地址')
 local host,path=url:match('^https://([^/]+)(/.*)$');assert(host and host:match('^[%w%.%-:]+$') and not host:find('@',1,true),'下载地址无效，不支持账号密码或缺少文件路径的 URL')
 if host=='github.com'then
  local owner,repo,file=path:match('^/([%w_.%-]+)/([%w_.%-]+)/blob/(.+)$');assert(owner and repo and file,'GitHub 地址需要是具体文件的 blob 链接或 raw 直链')
  url='https://raw.githubusercontent.com/'..owner..'/'..repo..'/'..file
 end
 return url
end
local function config(kind,c)
 local d=assert(defaults[kind]);c=c or {};local url=normalize(c.url or '');local fmt=c.format or d.format
 if url==''then url=d.url;fmt=d.format end
 assert(kind=='region' and fmt=='country_tar_gz' or kind=='domain' and (fmt=='auto'or fmt=='dnsmasq'or fmt=='plain'or fmt=='mihomo'or fmt=='clash_domain'),'不支持的库格式')
 local result={url=url,format=fmt,default_url=d.url,default_format=d.format,custom=url~=d.url or fmt~=d.format}
 if kind=='region'then
  local regions=c.regions or {};assert(type(regions)=='table','地区源设置无效');result.regions={}
  result.custom_groups={};local names={};local count=0
  for key,row in pairs(c.custom_groups or {})do
   assert(type(key)=='string'and key:match('^user_[a-z0-9_]+$')and #key<=17,'自定义分组标识无效')
   assert(type(row)=='table'and type(row.label)=='string'and #row.label>=1 and #row.label<=60 and not row.label:find("[%c<>\"'&]"),'分组名称无效（不能包含 HTML 字符）')
   assert(row.label~='中国大陆'and row.label~='中国大陆以外'and not names[row.label],'分组名称重复');names[row.label]=true;count=count+1;assert(count<=64,'最多保存 64 个自定义源')
   local u=normalize(row.url or '');assert(u~='','自定义分组必须填写下载地址');result.custom_groups[key]={label=row.label,url=u};result.custom=true
  end
  result.details={};local _,catalog=dofile('/usr/ikuai/script/region_detail.lua').catalog();for key,url in pairs(c.details or {})do assert(catalog[key],'未知细分分组');result.details[key]=normalize(url)end
  local known={};for _,key in ipairs(regionkeys)do known[key]=true;result.regions[key]=normalize(regions[key]or'');if result.regions[key]~=''then result.custom=true end end
  for key in pairs(regions)do assert(known[key],'未知地区：'..tostring(key))end
 else
  local foreign=(c.groups or {}).foreign or {};local furl=normalize(foreign.url or '');local fformat=foreign.format or 'auto'
  assert(fformat=='auto'or fformat=='plain'or fformat=='dnsmasq'or fformat=='mihomo'or fformat=='clash_domain','不支持的大陆以外域名格式')
  if furl==''then furl=foreign_default;fformat='auto'elseif furl~=foreign_default then result.custom=true end
  result.groups={cn={url=url,format=fmt,supplement=url==d.url and cn_extra or '',default_label='大陆综合库：dnsmasq-china-list + ChinaMax'},foreign={url=furl,format=fformat,default_url=foreign_default,supplement=furl==foreign_default and foreign_extra or '',default_label='海外综合库：MetaCubeX + Global'}}
 end
 return result
end
local function main()
 local action,kind,home=arg[1],arg[2],arg[3];assert(defaults[kind]);assert(home=='/etc/mnt/ikuai/'..(kind=='region'and'region' or'domain')..'-iplib')
 if action=='get'then print(j.encode(config(kind,read(home..'/source.json',{}))))
 elseif action=='status'then
  local data=j.decode(arg[4]);data.source=config(kind,read(home..'/source.json',{}));data.update=read(home..'/update-history.json',{});local deleted={};for name in (arg[5]or''):gmatch('[^,]+')do deleted[#deleted+1]=name end;data.deleted_groups=deleted;if kind=='region'then data.catalog=dofile('/usr/ikuai/script/region_detail.lua').catalog()end;print(j.encode(data))
 elseif action=='save'then
  local input=read(arg[4],{});local c
  if kind=='region'and input.custom_group then
   c=config(kind,read(home..'/source.json',{}));local key=input.custom_group
   assert(type(key)=='string'and key:match('^user_[a-z0-9_]+$')and #key<=17,'分组标识限 1～12 位小写字母、数字或下划线')
   c.custom_groups[key]={label=input.label,url=input.url};c=config(kind,c)
  elseif kind=='region'and input.detail then
   c=config(kind,read(home..'/source.json',{}));local _,catalog=dofile('/usr/ikuai/script/region_detail.lua').catalog();assert(catalog[input.detail],'未知细分分组');c.details[input.detail]=normalize(input.url or '');c=config(kind,c)
  elseif kind=='region'and input.region then
   c=config(kind,read(home..'/source.json',{}));assert(c.regions[input.region]~=nil,'未知地区');c.regions[input.region]=normalize(input.url or '');c=config(kind,c)
  elseif kind=='domain'then
   c=config(kind,read(home..'/source.json',{}));local group=input.group or 'cn';assert(group=='cn'or group=='foreign','未知域名分组')
   if group=='cn' then c.url=input.url or '';c.format=input.format or defaults.domain.format
   else c.groups.foreign={url=input.url or '',format=input.format or 'auto'}end
   c=config(kind,c)
  else c=config(kind,input)end
  write(home..'/source.json',c);print(j.encode(c))
 elseif action=='history'then
  local h=read(home..'/update-history.json',{});local state,now,source,version=arg[4],arg[5],arg[6],arg[7]
  local snapshot=arg[8]and read(arg[8],nil)or nil
  if state=='start'then h.last_attempt_sources=snapshot;h.last_attempt_at=now;h.attempt_source=source;h.status='running'
  elseif state=='success'then
   if kind=='region'then
    h.group_success_at=h.group_success_at or {};local requested=arg[9]or''
    if requested~=''then h.group_success_at[requested]=now
    else local manifest=read(home..'/current/region-manifest.json',nil)or read('/usr/share/strict-routing/region-manifest.json',{});for _,row in ipairs(manifest.regions or {})do h.group_success_at[row.key]=now end;h.group_success_at.foreign=now end
   end
   h.last_success_sources=snapshot;if h.version~=version then h.last_changed_at=now end;h.last_success_at=now;h.last_source=source;h.version=version;h.status='success'
  elseif state=='failed'then h.status='failed';h.last_error_at=now end
  write(home..'/update-history.json',h)
 else error('unknown operation')end
end
local ok,e=pcall(main);if not ok then io.stderr:write(tostring(e),'\n');os.exit(1)end
