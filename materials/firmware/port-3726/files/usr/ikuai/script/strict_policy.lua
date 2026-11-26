#!/usr/bin/ikluajit
-- Strict routing configuration compiler. No configuration value is executed as shell code.
local json=require('cjson')
local M={}
local domains=dofile('/usr/ikuai/script/domain_lib.lua')
local regions={cn=true,asia=true,europe=true,americas=true,oceania=true,africa=true,hk=true,mo=true,tw=true,unknown=true,any=true}
local function check(ok,msg) if not ok then error(msg,0) end end
local function arr(a,max) check(type(a)=='table' and #a<=max,'invalid list'); return a end
local function ipv4(s)
 if type(s)~='string' then return false end
 local a,b,c,d=s:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
 if not a then return false end
 for _,n in ipairs{a,b,c,d} do if #n>3 or tonumber(n)>255 then return false end end
 return true
end
local function cidr(s)
 if type(s)~='string' then return false end
 local ip,n=s:match('^([^/]+)/(%d+)$');return ip and ipv4(ip) and tonumber(n)<=32
end
local function domain(s)
 if type(s)~='string' or #s>253 or not s:find('%.') or s:find('%.%.') then return false end
 for label in s:gmatch('[^.]+') do if #label>63 or not label:match('^[a-z0-9][a-z0-9%-]*$') or label:sub(-1)=='-' then return false end end
 return s:sub(1,1)~='.' and s:sub(-1)~='.'
end
local function iface(s) return type(s)=='string' and #s<=15 and s:match('^[a-zA-Z][a-zA-Z0-9_.%-]*$') end
function M.validate(c)
 check(type(c)=='table' and c.version==1,'unsupported configuration version')
 check(type(c.enabled)=='boolean','enabled must be boolean')
 arr(c.scopes,32); arr(c.exits,32); arr(c.rules,128);arr(c.protected,64)
 local ids={}
 local explicit_domains={}
 for _,e in ipairs(c.exits) do
  check(type(e.id)=='number' and e.id%1==0 and e.id>=1 and e.id<=32 and not ids[e.id],'invalid or duplicate exit id')
  check(iface(e.interface),'invalid exit interface');check(ipv4(e.dns),'DNS must be an IPv4 address');ids[e.id]=e
 end
 local function exit(id,geo) check(id==0 or (geo and id=='geo') or ids[id],'unknown exit') end
 for _,s in ipairs(c.scopes) do check(iface(s.interface) and cidr(s.source),'invalid client scope') end
 for _,p in ipairs(c.protected) do check(cidr(p),'invalid protected network') end
 exit(c.default_exit);exit(c.cn_exit,true);exit(c.foreign_exit,true)
 check(ids[c.cn_dns] and ids[c.foreign_dns],'DNS exit must exist')
 check(c.unknown_dns=='cn' or c.unknown_dns=='foreign','invalid default DNS policy')
 arr(c.foreign_domains,20000)
 for _,d in ipairs(c.foreign_domains) do check(domain(d),'invalid foreign domain') end
 domains.manual(c)
 for _,r in ipairs(c.rules) do
  check(r.kind=='domain' or r.kind=='port' or r.kind=='region','invalid rule type');exit(r.exit)
  check(r.source==nil or r.source=='' or cidr(r.source),'invalid rule source')
  check(regions[r.region or 'any'],'invalid region')
  if r.kind=='domain' then
   check(ids[r.exit],'domain rules require an exit with DNS');arr(r.domains,1000);check(#r.domains>0,'empty domain rule')
   check(not r.source or r.source=='','domain DNS policies are global to the configured scopes')
   for _,d in ipairs(r.domains) do check(domain(d) and not explicit_domains[d],'invalid or duplicate custom domain');explicit_domains[d]=true end
  else
   check(r.protocol=='any' or r.protocol=='tcp' or r.protocol=='udp' or r.protocol=='both' or r.protocol=='icmp','invalid protocol')
   check(type(r.ports)=='string' and #r.ports<=128,'invalid ports')
   if r.ports~='' then
    check(r.protocol=='tcp' or r.protocol=='udp' or r.protocol=='both','ports need TCP/UDP')
    local n=0
    check(not r.ports:match('^,') and not r.ports:match(',$') and not r.ports:find(',,') and r.ports:match('^[%d,%-]+$'),'invalid port list')
    for x in r.ports:gmatch('[^,]+') do
     local a,b=x:match('^(%d+)%-(%d+)$');a=a or x;b=b or a
     check(tonumber(a) and tonumber(b) and tonumber(a)>=1 and tonumber(b)<=65535 and tonumber(a)<=tonumber(b),'invalid port range');n=n+(a==b and 1 or 2)
    end
    check(n<=15,'maximum 15 port slots per rule')
   end
   if r.kind=='port' then check(r.ports~='','port rule must specify ports') end
  end
 end
 if c.enabled then check(#c.scopes>0,'select client scopes first') end
 return c
end
local function read(p) local f=assert(io.open(p));local s=f:read('*a');f:close();return s end
local function write(p,s) local f=assert(io.open(p,'w'));f:write(s);f:close() end
local function q(s) return "'"..tostring(s):gsub("'","'\\''").."'" end
function M.compile(c,dir)
 M.validate(c)
 local setnames={}
 for i,r in ipairs(c.rules) do if r.kind=='domain' then
  local domains={};for _,d in ipairs(r.domains) do domains[#domains+1]=d end;table.sort(domains)
  local pipe=assert(io.popen('printf %s '..q(table.concat(domains,'\n'))..' | md5sum','r'))
  local hash=pipe:read('*a'):match('^([a-f0-9]+)');pipe:close();assert(hash and #hash==32,'domain identifier failed')
  setnames[i]='sp_d_'..hash:sub(1,24)
 end end
 local lines={'#!/bin/bash','set -e -o pipefail','source /usr/ikuai/script/strict_runtime.sh','sp_begin'}
 local function add(s) lines[#lines+1]=s end
 for _,s in ipairs(c.scopes) do add('sp_scope '..q(s.interface)..' '..q(s.source)) end
 for _,p in ipairs(c.protected) do add('sp_protect '..q(p)) end
 for _,e in ipairs(c.exits) do add('sp_exit '..e.id..' '..q(e.interface)..' '..q(e.dns)) end
 local used={}
 for _,r in ipairs(c.rules) do if r.region and r.region~='any' then used[r.region]=true end end
 if used.unknown then for k in pairs(regions) do if k~='any' and k~='unknown' then used[k]=true end end end
 for k in pairs(used) do if k~='unknown' then add('sp_region '..q(k)) end end
 -- Rules are terminated on a match, including a deny; failure cannot fall through.
 local function rule(r,i)
  local match=''
  if r.source and r.source~='' then match=match..' -s '..r.source end
  if r.kind=='domain' then
   add('sp_set '..setnames[i]..' hash:ip')
   match=match..' -m set --match-set '..setnames[i]..' dst'
  elseif r.region and r.region~='any' then
   if r.region=='unknown' then match=match..' -m set ! --match-set sp_known dst'
   else match=match..' -m set --match-set sp_r_'..r.region..' dst' end
  end
  local ps=r.protocol=='both' and {'tcp','udp'} or {r.protocol or 'any'}
  for _,p in ipairs(ps) do
   local m=match..(p=='any' and '' or ' -p '..p)
   if r.ports and r.ports~='' then m=m..' -m multiport --dports '..r.ports:gsub('%-',':') end
   add('sp_match '..q(m)..' '..r.exit)
  end
 end
 -- Ambiguous DNS-to-IP mappings fail closed instead of silently using another domain's exit.
 local domainsets={}
 for i,r in ipairs(c.rules) do if r.kind=='domain' then add('sp_set '..setnames[i]..' hash:ip');domainsets[#domainsets+1]={name=setnames[i],exit=r.exit} end end
 if c.cn_exit~='geo' then domainsets[#domainsets+1]={name='sp_d_cn',exit=c.cn_exit} end
 if c.foreign_exit~='geo' then domainsets[#domainsets+1]={name='sp_d_foreign',exit=c.foreign_exit} end
 add('sp_set sp_d_cn hash:ip');add('sp_set sp_d_foreign hash:ip')
 for i,a in ipairs(domainsets) do for j,b in ipairs(domainsets) do if j>i and a.exit~=b.exit then add('sp_conflict '..a.name..' '..b.name) end end end
 for i,r in ipairs(c.rules) do if r.kind=='domain' then rule(r,i) end end
 for i,r in ipairs(c.rules) do if r.kind=='port' then rule(r,i) end end
 add('sp_set sp_d_cn hash:ip');add('sp_set sp_d_foreign hash:ip')
 if c.cn_exit~='geo' then add("sp_match '-m set --match-set sp_d_cn dst' "..c.cn_exit) end
 if c.foreign_exit~='geo' then add("sp_match '-m set --match-set sp_d_foreign dst' "..c.foreign_exit) end
 for i,r in ipairs(c.rules) do if r.kind=='region' then rule(r,i) end end
 add("sp_match '' "..c.default_exit)
 add('sp_finish')
 write(dir..'/apply.sh',table.concat(lines,'\n')..'\n')
 -- Local fan-out resolver; each upstream worker owns a separate UID and egress policy.
 local f={'port=6153','listen-address=0.0.0.0','bind-interfaces','no-resolv','no-hosts','cache-size=0','max-ttl=60','filter-AAAA','user=root','pid-file='..dir..'/front.pid','log-facility='..dir..'/dns.log'}
 local function route(d,id,set)
  f[#f+1]='server=/'..d..'/127.0.0.1#'..(6200+id)
  if set then f[#f+1]='ipset=/'..d..'/'..set end
 end
 f[#f+1]='ipset=/#/sp_d_foreign'
 f[#f+1]='server=127.0.0.1#'..(6200+c.foreign_dns)
 local data=os.getenv('STRICT_DOMAIN_ROOT') or os.getenv('STRICT_DATA_ROOT') or '/usr/share/strict-routing'
 domains.routes(c,setnames,data,route)
 write(dir..'/domain-signature',domains.signature(c,data,setnames))
 write(dir..'/dns-front.conf',table.concat(f,'\n')..'\n')
 local ids={}
 for _,e in ipairs(c.exits) do
  ids[#ids+1]=e.id
  write(dir..'/dns-'..e.id..'.conf',table.concat({'port='..(6200+e.id),'listen-address=127.0.0.1','bind-interfaces','no-resolv','no-hosts','cache-size=2048','max-cache-ttl=60','max-ttl=60','user=spdns'..e.id,'group=root','server='..e.dns,'pid-file='..dir..'/dns-'..e.id..'.pid','log-facility='..dir..'/dns-'..e.id..'.log'},'\n')..'\n')
 end
 write(dir..'/dns-ids',table.concat(ids,'\n')..'\n')
 write(dir..'/scopes',json.encode(c.scopes));write(dir..'/config.json',json.encode(c))
end
if arg and arg[1] then
 local ok,err=pcall(function()
  local c=M.validate(json.decode(read(arg[2])))
  if arg[1]=='choices' then
   local rows={};local labels={cn='中国大陆',asia='亚洲（不含中国大陆）',europe='欧洲',americas='美洲',oceania='大洋洲',africa='非洲',hk='中国香港',mo='中国澳门',tw='中国台湾',unknown='未知地区',any='全部地区'}
   if c.enabled then for i,r in ipairs(c.rules) do if r.kind~='domain' and r.exit>0 then
    for _,e in ipairs(c.exits) do if e.id==r.exit then rows[#rows+1]={'sp_rule_'..i,(labels[r.region or 'any'] or '')..' '..r.protocol..' '..r.ports..' → '..e.interface} end end
   end end end
   print(#rows==0 and '[]' or json.encode(rows))
  elseif arg[1]=='compile' then M.compile(c,arg[3]) elseif arg[1]=='validate' then print('valid') else error('invalid action') end
 end)
 if not ok then io.stderr:write(tostring(err)..'\n');os.exit(1) end
end
return M
