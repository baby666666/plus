#!/usr/bin/ikluajit
local membership=dofile('/usr/ikuai/script/native_index.lua')
local allowlist=dofile('/usr/ikuai/script/domain_allowlist.lua')
local regional_cache,base_cache
local json=require('cjson');local lib=dofile('/usr/ikuai/script/domain_lib.lua')
local function read(p)local f=assert(io.open(p));local s=f:read('*a');f:close();return s end
local function write(p,s)local f=assert(io.open(p,'w'));assert(f:write(s));f:close()end
-- JSON object key order is not stable across LuaJIT processes. Compare the
-- complete address-group input in canonical key order, never raw JSON bytes.
local function canonical(v)
 if type(v)~='table'then return json.encode(v)end
 local keys={};for k in pairs(v)do keys[#keys+1]=k end
 table.sort(keys,function(a,b)return type(a)==type(b)and a<b or type(a)<type(b)end)
 local out={};for _,k in ipairs(keys)do out[#out+1]=json.encode(tostring(k))..':'..canonical(v[k])end
 return '{'..table.concat(out,',')..'}'
end
local function q(s)return "'"..tostring(s):gsub("'","'\\''").."'"end
local function list(s)local a={};for x in (s or ''):gmatch('[^,%s]+')do a[#a+1]=x end;return a end
local function ipv4(s)local a,b,c,d=(s or ''):match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$');if not a then return end;local n=0;for _,v in ipairs{a,b,c,d}do if tonumber(v)>255 then return end;n=n*256+tonumber(v)end;return n end
local function range(s)local a,b=s:match('^([^%-]+)%-(.+)$');if a then a,b=ipv4(a),ipv4(b);if a and b and a<=b then return a,b end;return end;local ip,mask=s:match('^([^/]+)/(.+)$');if ip then ip=ipv4(ip);local bits=tonumber(mask);if not bits then local m=ipv4(mask);if m then bits=32;while m%2==0 and bits>0 do m=m/2;bits=bits-1 end;if m~=2^bits-1 then return end end end;if not ip or not bits or bits<0 or bits>32 or bits%1~=0 then return end;local size=2^(32-bits);local start=math.floor(ip/size)*size;return start,start+size-1 end;local n=ipv4(s);return n,n end
local function iface(s)return type(s)=='string' and #s<=15 and s:match('^[%a][%w_.%-]*$')end
local function main(job)
 job=job or{}
 local dir=assert(job.dir or arg[1]);local live=job.live or arg[2]or dir;local c=json.decode(read(dir..'/snapshot.json'));local settings=json.decode(read(dir..'/settings.json'));lib.manual(settings)
 write(dir..'/address-inputs.json',canonical({ipgroup=c.ipgroup,macgroup=c.macgroup or {}}))
 local groups={};for _,g in ipairs(c.ipgroup)do groups[g.group_name]=g.addr_pool end;for _,g in ipairs(c.macgroup or {})do groups[g.group_name]=g.addr_pool end
 local function sources(s)
  if not s or s=='' then return {{0,4294967295}} end
  local out={};for _,v in ipairs(list(s))do
   local vs=groups[v] and list(groups[v]) or {v};assert(#vs>0,'IP分组为空：'..v)
   for _,x in ipairs(vs)do local a,b=range(x);if not a and x:match('^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$')then out[#out+1]={mac=x:lower()}else assert(a,'域名规则源地址需要 IPv4、MAC 或静态分组：'..v);out[#out+1]={a,b}end end
  end;return out
 end
 local function validate_addr(s)for _,v in ipairs(list(s))do assert(range(v) or groups[v]~=nil or v:match('^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$'),'未知 IP 分组或地址：'..v)end end
 local lines={'#!/bin/bash /etc/ikcommon','Include ipset.sh iptables.sh interface.sh iproute.sh','source /usr/ikuai/script/native_runtime.sh','source /usr/ikuai/script/native_domain_engine.sh','set -e -o pipefail','nr_begin','nr_native_begin'}
 local dns={};local flush={};local exits={};local workers={};local choices={};local nroute=0;local domainrules={};local policies={}
 local function add(s)lines[#lines+1]=s end
 -- Newline-separated alternatives form one logical rule (OR), with one mark.
 -- Prefix/suffix every alternative; concatenating onto the serialized string
 -- would silently leave the earlier time windows without source/destination.
 local function expressions(prefix,alternatives,suffix)
  local out={};for expr in (alternatives..'\n'):gmatch('(.-)\n')do out[#out+1]=prefix..expr..(suffix or '')end
  return table.concat(out,'\n')
 end
 local function schedule(r)
  local week=r.week or '1234567';local times=r.time or '00:00-23:59';assert(week:match('^[1-7]+$') and #week<=7,'星期无效')
  local exprs,ds={},{}
  for t in (times..','):gmatch('(.-),')do
   local h,m,H,M=t:match('^(%d%d):(%d%d)%-(%d%d):(%d%d)$');h,m,H,M=tonumber(h),tonumber(m),tonumber(H),tonumber(M)
   assert(h and h<24 and H<24 and m<60 and M<60,'时间无效');local a,b=h*60+m,H*60+M
   local expr='';if week~='1234567' or t~='00:00-23:59' then expr=' -m time --kerneltz --weekdays '..table.concat(list(week:gsub('(.)','%1,')),',')..' --timestart '..t:sub(1,5)..':00 --timestop '..t:sub(7)..':59' end
   exprs[#exprs+1]=expr
   -- Preserve xt_time's calendar-day semantics (no --contiguous): both
   -- halves of a wrapping interval belong to the selected weekday itself.
   for day in week:gmatch('.')do day=tonumber(day)-1;if a<=b then ds[#ds+1]='T '..(day*1440+a)..' '..(day*1440+b)else ds[#ds+1]='T '..day*1440 ..' '..(day*1440+b);ds[#ds+1]='T '..(day*1440+a)..' '..(day*1440+1439)end end
  end
  assert(#exprs>0,'时间无效');return table.concat(exprs,'\n'),ds
 end
 local function exitid(interface)
  if interface=='blackhole'then return 0 end
  assert(type(interface)~='string' or not interface:match('^pppwg%d+$'),'pppwg 为内部转发接口，不能配置为出口')
  assert(iface(interface),'出口接口无效')
  if not exits[interface]then local n=0;for _ in pairs(exits)do n=n+1 end;assert(n<32,'最多32个出口');exits[interface]=n+1;add('nr_exit '..(n+1)..' '..q(interface))end
  return exits[interface]
 end
 local function flush_sources(r)
  local ok,rs=pcall(sources,r.src_addr);if not ok then flush['0.0.0.0/0']=true;return end
  local function dotted(n)local out={};for i=3,0,-1 do local x=math.floor(n/256^i);out[#out+1]=x;n=n-x*256^i end;return table.concat(out,'.')end
  for _,v in ipairs(rs)do if v.mac then flush['0.0.0.0/0']=true;return end;local a,b=v[1],v[2];while a<=b do local bits=32;while bits>0 and a%2^(33-bits)==0 and a+2^(33-bits)-1<=b do bits=bits-1 end;flush[dotted(a)..'/'..bits]=true;a=a+2^(32-bits)end end
 end
 local function addrset(r,prefix,field,dir)
  local v=r[field] or '';if v=='' then return '' end;validate_addr(v);local name=prefix..r.id..'_'..dir;add('nr_addr '..name..' '..q(v));return ' -m set --match-set '..name..' '..dir
 end
 local function policy(r,kind)
  local interfaces=list(r.interface);assert(#interfaces>0,'规则必须指定出口接口')
  local mode=kind=='domain'and 0 or tonumber(r.mode or 0)
  local band;if r.iface_band==nil or r.iface_band=='' then band=kind=='domain'and 1 or 0 else band=tonumber(r.iface_band)end
  assert(mode==0 or mode==1 or mode==2 or mode==3 or mode==4 or mode==6,'出口负载模式无效')
  assert(band==0 or band==1,'线路绑定值无效')
  local ids,seen={},{};for _,interface in ipairs(interfaces)do
   assert(not seen[interface],'出口接口重复');seen[interface]=true
   assert(interface~='blackhole'or #interfaces==1,'黑洞不能与其他出口混用')
   ids[#ids+1]=exitid(interface)
  end
  nroute=nroute+1;assert(nroute<=65535,'分流规则过多')
  local p={id=nroute,interfaces=interfaces,exits=ids,mode=mode,iface_band=band,kind=kind,rule_id=r.id}
  p.base=(band==1 and 0x55000000 or 0x58000000)+p.id*256
  p.signature=table.concat(interfaces,',')..':'..mode..':'..band
  p.marks={};for _,eid in ipairs(ids)do p.marks[#p.marks+1]=p.base+eid end
  if band==0 and ids[1]~=0 then p.marks[#p.marks+1]=p.base end
  policies[#policies+1]=p
  add('nr_policy '..p.id..' '..q(table.concat(ids,','))..' '..mode..' '..band)
  return p
 end
 for _,scope in ipairs(settings.legacy_scopes or {})do for _,net in ipairs(settings.legacy_protected or {})do assert(iface(scope.interface) and range(scope.source) and range(net));add('nr_protect '..q(' -i '..scope.interface..' -s '..scope.source..' -d '..net))end end
 for _,r in ipairs(c.domain)do if r.enabled=='yes' then
  assert(tonumber(r.id) and r.id>0 and r.id<=999999,'规则编号无效');assert(#domainrules<256,'域名规则最多256条')
  flush_sources(r);local pol=policy(r,'domain');local eid=#pol.exits==1 and pol.exits[1]or 0;local up=r.nr_dns or '';assert(ipv4(up),'域名规则 '..r.id..' 需要填写该出口的 DNS IPv4 地址')
  local workerkey=pol.signature..':'..up;local wid=workers[workerkey];if not wid then wid=0;for _ in pairs(workers)do wid=wid+1 end;wid=wid+1;assert(wid<=32,'最多32种出口策略与 DNS 组合');workers[workerkey]=wid;add('nr_worker '..wid..' '..pol.id..' '..q(up));write(dir..'/dns-'..wid..'.conf',table.concat({'port='..(6200+wid),'listen-address=127.0.0.1','bind-interfaces','no-resolv','no-hosts','cache-size=256','max-tcp-connections=64','fast-dns-retry=750,4000','max-ttl=60','max-cache-ttl=60','filter-AAAA','user=nrdns'..wid,'group=root','server='..up,'pid-file='..live..'/dns-'..wid..'.pid','log-facility='..live..'/dns-'..wid..'.log'},'\n')..'\n')end
  local kind=r.nr_group or 'manual';local route=r.nr_route or 'fixed';assert(route=='fixed' or route=='dns_only','域名访问方式无效');assert(kind=='manual' or kind=='cn' or kind=='foreign'or kind=='fallback','域名分组无效')
  local target=r.nr_target or 'any';assert(target=='any'or target=='cn','目标 IP 限制无效');assert(target=='any'or kind=='fallback','目标 IP 限制仅适用于未匹配流量')
  if kind=='fallback'then
   assert(route=='fixed','未匹配流量必须按本条规则分流')
   for _,interface in ipairs(pol.interfaces)do assert(interface~=(r.nr_ingress or '')and ('ppp'..interface)~=(r.nr_ingress or ''),'兜底出口不能与入接口相同')end
  end
  local time,ds=schedule(r);local src=addrset(r,'nr_ds_', 'src_addr','src');local ingress=r.nr_ingress or '';assert(ingress=='' or iface(ingress),'入口接口无效');if ingress~=''then src=src..' -i '..(ingress:match('^wg%d+$') and 'ppp'..ingress or ingress) end
  local rule={r=r,policy=pol,eid=eid,mark=pol.marks[1],expr=expressions(src,time,' -m set --match-set nr_d_'..r.id..' dst,src'),time=time,kind=kind,route=route,scope=expressions(src,time)};domainrules[#domainrules+1]=rule
  add('nr_domain_set '..r.id);dns[#dns+1]='R '..r.id..' '..(6200+wid)..' '..(kind=='cn' and 1 or kind=='foreign' and 2 or kind=='fallback'and 4 or 0);if ingress~=''then dns[#dns+1]='I '..ingress end
  for _,p in ipairs(sources(r.src_addr))do dns[#dns+1]=p.mac and ('A '..p.mac)or('S '..string.format('%.0f %.0f',p[1],p[2]))end
  -- Dispatcher additionally enforces ingress when supplied by migrated rules via kernel DNS admission.
  for _,s in ipairs(ds)do dns[#dns+1]=s end
  if kind=='manual'then local dd=list(r.domain:lower());assert(#dd>0,'手动域名不能为空');for _,d in ipairs(dd)do assert(lib.valid(d,false),'域名无效：'..d);dns[#dns+1]='D '..d end end
  add('nr_dns_scope '..q(expressions(src,time)))
 end end
 local function overlap(a,b)
  local ia,ib=a.nr_ingress or '',b.nr_ingress or '';if ia~=''and ib~=''and ia~=ib then return false end
  local _,ta=schedule(a);local _,tb=schedule(b);local ts=false
  for _,x in ipairs(ta)do local l,h=x:match('T (%d+) (%d+)');for _,y in ipairs(tb)do local k,z=y:match('T (%d+) (%d+)');if tonumber(l)<=tonumber(z)and tonumber(k)<=tonumber(h)then ts=true end end end
  if not ts then return false end
  for _,x in ipairs(sources(a.src_addr))do for _,y in ipairs(sources(b.src_addr))do if x.mac or y.mac then return true elseif x[1]<=y[2]and y[1]<=x[2]then return true end end end
  return false
 end
 for i,a in ipairs(domainrules)do if a.kind=='fallback'then for k,b in ipairs(domainrules)do if k>i and b.kind=='fallback'and overlap(a.r,b.r)then assert(false,'未匹配流量规则的入口、源地址或时段重叠，请合并或缩小范围')end end end end
 -- Keep native suffix recognition in the same priority order as the DNS
 -- dispatcher. Exact-only entries and exclusions remain in the dispatcher;
 -- never widen an exact rule or let a native parent swallow an exception.
 local native_root=job.root or os.getenv('STRICT_DOMAIN_ROOT')or'/usr/share/strict-routing'
 local manifest,regional=lib.verify(native_root,job.cache or os.getenv('NATIVE_DECODE_CACHE'))
 local function copy(a)local b={};for i,v in ipairs(a or {})do b[i]=v end;return b end
 -- A suffix index needs two flat sets, not one Lua table per DNS label.
 -- parents answers "does this suffix cover any entry?"; exact plus suffix
 -- walking answers "is this name inside an entry?". This preserves the
 -- symmetric overlap checks used for native cross-rule exclusions.
 local function trie(values)
  local index={exact={},parents={}}
  for _,value in ipairs(values)do
   index.exact[value]=true
   local name=value
   while name do index.parents[name]=true;name=name:match('^[^.]+%.(.+)$')end
  end
  return index
 end
 local function ancestor(index,name)
  while name do if index.exact[name]then return true end;name=name:match('^[^.]+%.(.+)$')end
  return false
 end
 local function intersects(index,name)
  return index.parents[name]==true or ancestor(index,name)
 end
 local _,manual=allowlist.normalize(settings,lib)
 local manualkey=canonical(manual)
 if not regional_cache or regional_cache.version~=manifest.version or regional_cache.manual~=manualkey then
  local cn_native,foreign_native=copy(regional.cn),copy(regional.foreign)
  if not base_cache or base_cache.version~=manifest.version then
   local cn_all,foreign_all=copy(regional.cn),copy(regional.foreign)
   for _,d in ipairs(regional['cn-exact']or{})do cn_all[#cn_all+1]=d end
   for _,d in ipairs(regional['foreign-exact']or{})do foreign_all[#foreign_all+1]=d end
   base_cache={version=manifest.version,cn_block=trie(cn_all),foreign_block=trie(foreign_all),cn_tree=trie(regional.cn)}
  end
  local cn_block_names,foreign_block_names={},{}
  for name,group in pairs(manual)do
   local target=group=='cn'and cn_native or foreign_native;target[#target+1]=name
   local block=group=='cn'and cn_block_names or foreign_block_names;block[#block+1]=name
  end
  local function overlay(names,base)
   local index=trie(names);setmetatable(index.exact,{__index=base.exact});setmetatable(index.parents,{__index=base.parents});return index
  end
  regional_cache={version=manifest.version,manual=manualkey,cn=cn_native,foreign=foreign_native,
   cn_block=overlay(cn_block_names,base_cache.cn_block),cn_tree=overlay(cn_block_names,base_cache.cn_tree),foreign_block=overlay(foreign_block_names,base_cache.foreign_block)}
 end
 local cn_native,foreign_native=regional_cache.cn,regional_cache.foreign
 local foreign_exact,cn_exact=regional['foreign-exact']or{},regional['cn-exact']or{}
 local manual_count=0;for _ in pairs(manual)do manual_count=manual_count+1 end
 write(dir..'/foreign-policy.json',json.encode({policy='library',mainland=#regional.cn+#cn_exact,
  foreign=#regional.foreign+#foreign_exact,effective=#regional.foreign+#foreign_exact,manual=manual_count}))
 local cn_block,foreign_block=regional_cache.cn_block,regional_cache.foreign_block
 local ordered={};for _,d in ipairs(domainrules)do if d.kind~='fallback'then ordered[#ordered+1]=d end end
 local metadata={rules={},groups=0,selectors=0};local earlier={};local retained={};local indexstats={}
 local saved,used={},{};local sf=io.open(os.getenv('NATIVE_SLOT_STATE')or'/tmp/iktmp/native-rules/native-slots.json')
 if sf then local ok,data=pcall(json.decode,sf:read('*a'));sf:close();if ok then saved=data end end
 for _,d in ipairs(ordered)do local n=tonumber(saved[tostring(d.r.id)]);if n and n>=1 and n<=255 and not used[n]then used[n]=d.r.id end end
 local function slot(id)
  local n=tonumber(saved[tostring(id)]);if n and used[n]==id then return n end
  for k=1,255 do if not used[k]then used[k]=id;return k end end
  error('原生选择器容量不足')
 end
 for _,d in ipairs(ordered)do
  local candidates,all,excluded={},{},{}
  if d.kind=='manual'then candidates=list(d.r.domain:lower());all=candidates
  else candidates=d.kind=='cn'and cn_native or foreign_native;all=candidates end
  local ownblock=d.kind=='cn'and foreign_block or d.kind=='foreign'and cn_block or trie(excluded)
  local blockers={ownblock};local higher_names={};for _,higher in ipairs(earlier)do if overlap(d.r,higher.r)then blockers[#blockers+1]=higher.tree;for _,name in ipairs(higher.all)do higher_names[name]=true end end end
  local eligible=d.kind~='foreign'and d.route=='fixed'and d.eid>0 and (d.r.nr_ingress or '')==''
  local fallback_reason
  -- The native URL accelerator has one physical route per selector. Keep
  -- existing bound/single-exit acceleration; policy groups use acknowledged
  -- per-client DNS/history instead of silently choosing their first exit.
  if #d.policy.exits>1 then eligible=false;fallback_reason='multi_exit_policy'
  elseif d.policy.iface_band==0 then eligible=false;fallback_reason='unbound_policy' end
  -- The closed native group ABI documents one start/end pair only. Multiple
  -- windows use the same per-client DNS/history path as other ineligible
  -- rules; never flatten extra seconds into native weekday/exit arguments.
  if d.time:find('\n',1,true)then eligible=false;fallback_reason='multi_time_windows' end
  -- Global native address learning cannot distinguish two clients resolving
  -- different names to the same CDN IP. When regional exits differ, keep both
  -- regional decisions in acknowledged per-client DNS sets; unmatched traffic
  -- is still protected by the scoped fallback. Native protocol rules remain.
  if d.kind=='cn'then for _,other in ipairs(domainrules)do
   if other.kind=='foreign'and other.route=='fixed'and other.policy.signature~=d.policy.signature and overlap(d.r,other.r)then
    eligible=false;fallback_reason='per_client_regional_libraries';break
   end
  end end
  for _,source in ipairs(sources(d.r.src_addr))do if source.mac then eligible=false end end
  -- Domain rules precede port/protocol rules. Native learning may only
  -- accelerate that same decision, never introduce another priority stage.
  local selected,seen={},{}
  if eligible then
   local mode,touched
   selected,mode,touched=membership.select(d.r.id,candidates,ownblock,higher_names,function(name)
    for _,blocker in ipairs(blockers)do if intersects(blocker,name)then return true end end;return false
   end)
   retained[d.r.id]=true;indexstats[#indexstats+1]={id=d.r.id,mode=mode,rechecked=touched}

  end
  if metadata.groups+math.ceil(#selected/1000)>255 then selected={};eligible=false;fallback_reason='native_capacity' end
  local row={id=d.r.id,kind=d.kind,native_domains=#selected,eligible=eligible,fallback_reason=fallback_reason}
  if #selected>0 then
   metadata.selectors=metadata.selectors+1;assert(metadata.selectors<=255,'原生域名规则最多255个选择器')
   metadata.groups=metadata.groups+math.ceil(#selected/1000);assert(metadata.groups<=255,'域名库超过原生引擎255组容量，旧配置保留')
   d.native_slot=slot(d.r.id);local file=dir..'/native-domains-'..d.native_slot..'.txt';write(file,table.concat(selected,'\n')..'\n')
   add('nr_native_selector '..d.native_slot..' '..d.eid..' '..q(d.time)..' '..d.r.id)
   local weeks={};for value in d.r.week:gmatch('%d')do weeks[#weeks+1]=value end
   local times={};for first,last in d.r.time:gmatch('(%d%d:%d%d)%-(%d%d:%d%d)')do
    local h,m=first:match('(%d+):(%d+)');local z,n=last:match('(%d+):(%d+)');times[#times+1]=tonumber(h)*3600+tonumber(m)*60;times[#times+1]=tonumber(z)*3600+tonumber(n)*60+60
   end
   assert(#times>0,'原生域名时间范围无效')
   add('nr_native_group '..d.native_slot..' '..q((d.r.src_addr or '')~=''and 'nr_ds_'..d.r.id..'_src'or'null')..' '..q(table.concat(weeks,','))..' '..q(table.concat(times,' '))..' '..q(live..'/native-domains-'..d.native_slot..'.txt'))
   row.slot=d.native_slot
  end
  metadata.rules[#metadata.rules+1]=row
  earlier[#earlier+1]={r=d.r,tree=d.kind=='cn'and regional_cache.cn_tree or d.kind=='foreign'and regional_cache.foreign_block or trie(all),all=all}
 end
 -- Existing lower-priority domain connections fail closed if a preceding
 -- domain rule learns the same client/address. New connections use list order.
 for i,a in ipairs(ordered)do if a.route=='fixed'then
  for k,b in ipairs(ordered)do if k>i and b.route=='fixed'and a.policy.signature~=b.policy.signature and overlap(a.r,b.r)then
   local expr=expressions('',a.scope,' -m set --match-set nr_h_'..a.r.id..' dst,src')
   for _,mark in ipairs(b.policy.marks)do add('nr_conflict '..q(expressions('',expr,' -m connmark --mark '..mark)))end
   if b.native_slot then add('nr_conflict '..q(expressions('',expr,' -m connmark --mark '..(3011000+b.native_slot))))end
  end end
 end end
 membership.retain(retained)
 write(dir..'/index-stats.json',json.encode(indexstats))
 write(dir..'/native-engine.json',json.encode(metadata))
 local inputs={};for _,row in ipairs(metadata.rules)do if row.slot then inputs[#inputs+1]=row.id..' '..row.slot end end
 write(dir..'/native-inputs',table.concat(inputs,'\n')..(#inputs>0 and '\n'or''))
 local flowmarks={};for _,d in ipairs(domainrules)do if d.route=='fixed'then
  for _,mark in ipairs(d.policy.marks)do flowmarks[#flowmarks+1]=d.r.id..' '..mark..' '..(d.native_slot and 3011000+d.native_slot or 0)end
 end end
 write(dir..'/flow-marks',table.concat(flowmarks,'\n')..'\n')
 local function domain_rule(d)
  if d.route=='dns_only'then return end
  add('nr_policy_rule '..q(d.expr)..' '..d.policy.id..' '..q(d.time))
  if d.native_slot then add('nr_native_match '..q(d.scope)..' '..d.native_slot..' '..d.mark)
  else
   -- Match only this client's retained DNS evidence, at the same rule priority.
   -- This also preserves exact/ingress/MAC and oversized-library semantics.
   add('nr_policy_rule '..q(expressions('',d.scope,' -m set --match-set nr_h_'..d.r.id..' dst,src'))..' '..d.policy.id..' '..q(d.time))
  end
 end
 local function port_rules()
 for _,r in ipairs(c.port)do if r.enabled=='yes' and tonumber(r.type or 0)==0 then
  flush_sources(r);local pol=policy(r,'port');local time=schedule(r);local src=addrset(r,'nr_ps_', 'src_addr','src');local dst=''
  if tonumber(r.dst_type or 0)==1 then local codes=list(r.area_code);assert(#codes>0);for _,code in ipairs(codes)do assert(code:match('^%d+$'))end;dst=' -m location --location '..table.concat(codes,',')else dst=addrset(r,'nr_pd_','dst_addr','dst')end
  local ingress=r.nr_ingress or '';assert(ingress=='' or iface(ingress));if ingress~=''then src=src..' -i '..(ingress:match('^wg%d+$') and 'ppp'..ingress or ingress) end
  local proto=r.protocol;assert(proto=='any'or proto=='tcp'or proto=='udp'or proto=='tcp+udp'or proto=='icmp','不支持的协议')
  local ports='';for _,f in ipairs{'src_port','dst_port'}do local p=r[f]or'';if p~=''then assert(proto=='tcp'or proto=='udp'or proto=='tcp+udp');local slots=0;for _,s in ipairs(list(p))do local a,b=s:match('^(%d+)%-(%d+)$');a=tonumber(a or s);b=tonumber(b or a);assert(a and b and a>=1 and a<=b and b<=65535,'端口无效');slots=slots+(a==b and 1 or 2)end;assert(slots>0 and slots<=15);ports=ports..' -m multiport --'..(f=='src_port'and 'sports 'or'dports ')..p:gsub('%-',':')end end
  for _,p in ipairs(proto=='tcp+udp'and{'tcp','udp'}or{proto})do add('nr_policy_rule '..q(expressions(src..dst,time,(p=='any'and''or' -p '..p)..ports))..' '..pol.id..' '..q(time))end
  choices[#choices+1]={id=r.id,interface=r.interface,label=(r.comment~=''and r.comment or '端口规则 '..r.id)..' → '..r.interface}
 end end
 end
 -- Snapshot arrays follow each native page's rule ordering. Legacy nr_stage
 -- is retained as configuration data only; it no longer reorders port rows.
 for _,d in ipairs(ordered)do domain_rule(d)end
 -- DNS-only matches continue to port/protocol rules without being caught by
 -- the unmatched-domain fallback. A separate chain preserves this exception.
 local strict=false;for _,d in ipairs(domainrules)do if d.kind=='fallback'and d.r.nr_target=='cn' then strict=true end end
 if strict then local status=dofile('/usr/ikuai/script/native_strict_target.lua').prepare(dir,job.region_root);add('nr_strict_set '..q(live..'/strict-cn.restore')..' '..q(status.signature));add('nr_strict_continue')end
 add('nr_fallback_begin')
 for _,d in ipairs(ordered)do if d.route=='dns_only'then
  add('nr_fallback_skip '..q(d.expr))
  add('nr_fallback_skip '..q(expressions('',d.scope,' -m set --match-set nr_h_'..d.r.id..' dst,src')))
 end end
 for _,d in ipairs(domainrules)do if d.kind=='fallback'then
  if d.r.nr_target=='cn' then for _,mark in ipairs(d.policy.marks)do add('nr_strict_guard '..q(d.scope)..' '..mark)end end
  add('nr_policy_rule '..q(d.scope)..' '..d.policy.id..' '..q(d.time))
 end end
 add('nr_fallback_end')
 add('nr_lower_begin')
 port_rules()
 local apps={};local af=io.open('/tmp/iktmp/cache/appid.sh')
 if af then for line in af:lines()do local name,ids=line:match("^APPIDS%['(.-)'%]='([%d:,]+)'$");if name then apps[name]=ids end end;af:close()end
 for _,r in ipairs(c.protocol or {})do if r.enabled=='yes'then
  flush_sources(r);local pol=policy(r,'protocol');local tm=schedule(r);local src=addrset(r,'nr_as_','src_addr','src')
  local all=false;local p2p,other={},{}
  for _,name in ipairs(list(r.app_proto))do
   if name=='all'or name=='所有协议'then all=true
   else local ids=assert(apps[name],'原生协议库中找不到应用：'..name)
    for id in ids:gmatch('[^,]+')do local lo,hi=id:match('^(%d+):(%d+)$');lo=tonumber(lo or id);hi=tonumber(hi or lo);assert(lo and hi and lo<=hi,'应用编号无效')
     local dst=lo>=2000000 and hi<=2989999 and p2p or other;dst[#dst+1]=id
    end
   end
  end
  local function emit(extra)add('nr_policy_rule '..q(expressions(src,tm,extra))..' '..pol.id..' '..q(tm))end
  if all then emit(' -m conntrack --ctstate NEW')
  else
   if #p2p>0 then emit(' -m appmark --appid '..table.concat(p2p,','))end
   if #other>0 then emit(' -m conntrack --ctstate NEW -m appmark --appid '..table.concat(other,','))end
  end
 end end

 add('nr_lower_end')
 local flushlist={};for net in pairs(flush)do flushlist[#flushlist+1]=net end;table.sort(flushlist)
 for _,net in ipairs(flushlist)do add('conntrack -D -s '..q(net)..' >/dev/null 2>&1 || true')end
 write(dir..'/flush-sources',table.concat(flushlist,'\n')..'\n')
 add(dofile('/usr/ikuai/script/encrypted_dns.lua').command(settings.encrypted_dns))
 add('nr_ipv6 '..(nroute>0 and '1' or '0'));add('nr_finish');add('nr_native_finish')
 local manual=lib.manual(settings);local names={};for d in pairs(manual)do names[#names+1]=d end;table.sort(names);for _,d in ipairs(names)do dns[#dns+1]='M '..(manual[d]=='cn'and 1 or 2)..' '..d end
 local root=job.root or os.getenv('STRICT_DOMAIN_ROOT')or'/usr/share/strict-routing';for _,d in ipairs(regional.cn)do dns[#dns+1]='C '..d end
 for _,d in ipairs(regional.foreign)do dns[#dns+1]='F '..d end
 for _,d in ipairs(foreign_exact)do dns[#dns+1]='G '..d end
 for _,d in ipairs(cn_exact)do dns[#dns+1]='H '..d end
 local delta={'#!/bin/bash /etc/ikcommon','Include ipset.sh iptables.sh interface.sh iproute.sh','source /usr/ikuai/script/native_runtime.sh','source /usr/ikuai/script/native_domain_engine.sh','set -e -o pipefail','export NR_NATIVE_DELTA=1','nr_reset_evidence','nr_native_begin'};for _,line in ipairs(lines)do if line:match('^nr_native_group ')then delta[#delta+1]=line end end;delta[#delta+1]='nr_native_finish';write(dir..'/delta.sh',table.concat(delta,'\n')..'\n')
 local compact,global={},{};for _,line in ipairs(dns)do local t=line:sub(1,1);local dst=(t=='C'or t=='F'or t=='G'or t=='H'or t=='M')and global or compact;dst[#dst+1]=line end
 write(dir..'/dns-transition.rules',table.concat(compact,'\n')..'\n');write(dir..'/dns-global.rules',table.concat(global,'\n')..'\n')
 local small={};for _,line in ipairs(compact)do small[#small+1]=line end;for _,line in ipairs(global)do local t=line:sub(1,1);if t=='M'then small[#small+1]=line end end
 write(dir..'/dns-transition-regional.rules',table.concat(small,'\n')..'\n');write(dir..'/dns-base.version','library-v3\n'..manifest.version..'\n')
 write(dir..'/apply.sh',table.concat(lines,'\n')..'\n');write(dir..'/dns.rules',table.concat(dns,'\n')..'\n');write(dir..'/choices.json',json.encode(choices));write(dir..'/policy-plan.json',json.encode(policies))
 local ids={};for _,id in pairs(workers)do ids[#ids+1]=tostring(id)end;table.sort(ids);write(dir..'/dns-ids',table.concat(ids,'\n')..'\n')
end
if arg and arg[0]and arg[0]:match('/native_rules%.lua$')then local ok,e=pcall(main);if not ok then io.stderr:write(tostring(e),'\n');os.exit(1)end end
return {compile=main}
