-- Pure address planning. No keys, device writes, or implicit migration.
local M={}
local function ip(s)
 local a,b,c,d=tostring(s or ''):match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
 if not a then return end
 local n=0;for _,v in ipairs{a,b,c,d}do v=tonumber(v);if v>255 then return end;n=n*256+v end
 return n
end
local function dotted(n)
 local t={};for i=3,0,-1 do local v=math.floor(n/256^i);t[#t+1]=v;n=n-v*256^i end
 return table.concat(t,'.')
end
function M.net(s)
 local host,mask=tostring(s or ''):match('^([^/]+)/(.+)$');if not host then host=s;mask='32'end
 local n=ip(host);local bits=tonumber(mask)
 if not bits then
  local v=ip(mask);if v then bits=32;while bits>0 and v%2==0 do bits=bits-1;v=v/2 end;if v~=2^bits-1 then return end end
 end
 if not n or not bits or bits<0 or bits>32 or bits%1~=0 then return end
 local size=2^(32-bits);local lo=math.floor(n/size)*size
 return {host=n,lo=lo,hi=lo+size-1,bits=bits,text=dotted(lo)..'/'..bits}
end
function M.nets(value)
 local out={};for s in tostring(value or ''):gmatch('[^,%s]+')do local n=M.net(s);if not n then return nil,'允许地址必须是有效 IPv4 地址或网段'end;out[#out+1]=n end
 if #out==0 then return nil,'请填写允许地址'end
 return out
end
local function overlap(a,b)return a.lo<=b.hi and b.lo<=a.hi end
local function same(a,b)return tostring(a or '')==tostring(b or '')end
local function own(state,name)for _,v in ipairs(state.interfaces)do if v.name==name then return v end end end
local function ranges(state,skip)
 local out={}
 for _,v in ipairs(state.interfaces)do if v.name~=skip then local n=M.net(v.local_address);if n then out[#out+1]=n end end end
 for _,p in ipairs(state.peers)do for _,n in ipairs(M.nets((p.allowips or '')..','..(p.site_remote or ''))or{})do if n.bits>0 then out[#out+1]=n end end end
 for _,v in ipairs(state.networks or{})do if v.name~=skip and v.name~='ppp'..(skip or '') then local n=M.net(v.address);if n and n.bits>0 then out[#out+1]=n end end end
 return out
end
function M.next_iface_name(state)
 local names={}
 for _,v in ipairs(state.interfaces) do names[v.name]=true end
 local referenced=state.referenced_wg or {}
 local idx=1
 while names['wg'..idx] or referenced['wg'..idx] do idx=idx+1 end
 return 'wg'..idx
end
function M.iface_defaults(state)
 local used={};for _,v in ipairs(state.interfaces)do local port=tonumber(v.local_listenport);if port then used[port]=true end end
 local port=50001;while used[port]and port<=65535 do port=port+1 end
 if port>65535 then return nil,'WG 监听端口已用尽，请手动调整'end
 local reserved=ranges(state)
 for i=1,254 do
  local addr='10.100.'..i..'.1/24';local net=M.net(addr);local free=true
  for _,r in ipairs(reserved)do if overlap(net,r)then free=false;break end end
  if free then return {name=M.next_iface_name(state),local_address=addr,local_listenport=port}end
 end
 return nil,'10.100.1.0/24 至 10.100.254.0/24 均被占用，请手动规划接口地址'
end
function M.peer_defaults(state,name)
 local iface=own(state,name);if not iface then return nil,'请先选择已创建的 WG 服务接口'end
 for _,p in ipairs(state.peers)do if p.interface==name and p.exit_peer=='yes'then return nil,'该接口已专用于分流出口，请选择其他接入接口'end end
 local n=M.net(iface.local_address);if not n then return nil,'服务接口地址无效'end
 if n.bits==32 then return nil,'该接口使用 /32，无法自动分配同网段客户端地址，请手动填写或选择接入接口'end
 local reserved={}
 for _,v in ipairs(state.interfaces)do local net=M.net(v.local_address);if net then reserved[#reserved+1]={lo=net.host,hi=net.host}end end
 for _,p in ipairs(state.peers)do
  for _,r in ipairs(M.nets((p.allowips or '')..','..(p.site_remote or ''))or{})do
   if p.interface==name or r.bits>0 then reserved[#reserved+1]=r end
  end
 end
 for _,v in ipairs(state.networks or{})do if v.name~=name and v.name~='ppp'..name then local r=M.net(v.address);if r and r.bits>0 then reserved[#reserved+1]=r end end end
 table.sort(reserved,function(a,b)return a.lo<b.lo end)
 local candidate=n.lo+(n.bits<31 and 1 or 0);local last=n.hi-(n.bits<31 and 1 or 0)
 for _,r in ipairs(reserved)do if candidate>=r.lo and candidate<=r.hi then candidate=r.hi+1 end end
 if candidate>last then return nil,'所选接口没有可用客户端地址，请调整网段或手动填写'end
 return {interface=name,allowips=dotted(candidate)..'/32',client_dns=dotted(n.host),source_network=n.text}
end
function M.client_endpoint(value)
 value=value or ''
 if value==''then return true end
 if #value>259 or value:find('[%s%c]')then return nil,'客户端 Endpoint 只能填写 IPv4 或域名，可附加端口'end
 local host,port=value:match('^([^:]+):(%d+)$');host=host or value
 if port and (tonumber(port)<1 or tonumber(port)>65535)then return nil,'客户端 Endpoint 端口须为 1 至 65535'end
 local valid=false
 if host:match('^[%d.]+$')then valid=ip(host)~=nil
 elseif #host<=253 and host:find('.',1,true)then
  valid=true
  if host:sub(-1)=='.' or host:find('..',1,true)then valid=false end
  for label in host:gmatch('[^.]+')do
   if #label>63 or not label:match('^[%w%-]+$') or not label:match('^%w') or not label:match('%w$')then valid=false end
  end
 end
 if not valid then return nil,'客户端 Endpoint 须为有效 IPv4 或域名，可附加端口；不要填写网址或 IPv6'end
 return true
end
-- Explicit site-to-site scopes are independent of the Internet exit role.
function M.site_nets(value)
 if value==nil or value==''then return {}end
 if type(value)~='string' or #value>1024 or value:find('[^%d%./,%s]')then return nil,'互访网段格式无效'end
 local out,err=M.nets(value);if not out then return nil,err end
 if #out>8 then return nil,'每端最多填写 8 个互访网段'end
 local private={{167772160,184549375},{2886729728,2887778303},{3232235520,3232301055},{1681915904,1686110207}}
 for i,n in ipairs(out)do
  local valid=false;for _,r in ipairs(private)do if n.lo>=r[1]and n.hi<=r[2]then valid=true end end
  if not valid then return nil,'互访网段只支持私有 IPv4 和 100.64.0.0/10，不支持默认路由'end
  for j=1,i-1 do if overlap(n,out[j])then return nil,'同侧互访网段不能重复或重叠'end end
 end
 return out
end
function M.site_fields(local_value,remote_value)
 local l,err=M.site_nets(local_value);if not l then return nil,err end
 local r; r,err=M.site_nets(remote_value);if not r then return nil,err end
 if (#l==0)~=(#r==0)then return nil,'请同时填写本端和对端互访网段；不需要互访时两项留空'end
 for _,a in ipairs(l)do for _,b in ipairs(r)do if overlap(a,b)then return nil,'两端互访网段不能重叠'end end end
 return {local_nets=l,remote_nets=r}
end
function M.check_site(state,interface,allowips,id,local_value,remote_value)
 local site,err=M.site_fields(local_value,remote_value);if not site then return nil,err end
 if #site.local_nets==0 then return true end
 local nets=M.nets(allowips);if not nets or nets[1].bits~=32 then return nil,'启用互访时，允许地址首项须为对端隧道 /32 地址'end
 for i=2,#nets do local known=false;for _,r in ipairs(site.remote_nets)do if nets[i].lo>=r.lo and nets[i].hi<=r.hi then known=true end end
  if not known then return nil,'允许地址中的附加网段须包含在对端互访网段内'end
 end
 local iface=own(state,interface);local tunnel=iface and M.net(iface.local_address)
 for _,list in ipairs{site.local_nets,site.remote_nets}do for _,n in ipairs(list)do
  if tunnel and overlap(n,tunnel)or overlap(n,nets[1])then return nil,'互访网段不能包含本隧道地址'end
 end end
 for _,a in ipairs(site.remote_nets)do
  for _,v in ipairs(state.networks or{})do local b=M.net(v.address);if b and b.bits>0 and v.name~=interface and v.name~='ppp'..interface and overlap(a,b)then return nil,'对端互访网段与本地或静态路由冲突'end end
  for _,v in ipairs(state.interfaces)do local b=M.net(v.local_address);if b and overlap(a,b)then return nil,'对端互访网段与本地 WG 接口冲突'end end
  for _,p in ipairs(state.peers)do if not same(p.id,id)then
   for _,b in ipairs(M.nets((p.allowips or '')..','..(p.site_remote or ''))or{})do if b.bits>0 and overlap(a,b)then return nil,'对端互访网段与其他隧道冲突'end end
  end end
 end
 -- Local networks must have a configured non-WAN path; never invent a return route.
 for _,a in ipairs(site.local_nets)do
  local found=false
  for _,v in ipairs(state.networks or{})do local b=M.net(v.address);if b and b.bits>0 and v.name and not v.name:match('^wan') and v.name~=interface and v.name~='ppp'..interface and a.lo>=b.lo and a.hi<=b.hi then found=true end end
  for _,v in ipairs(state.interfaces)do local b=M.net(v.local_address);if v.name~=interface and b and a.lo>=b.lo and a.hi<=b.hi then found=true end end
  if not found then return nil,'本端互访网段须位于已配置的 LAN、其他 WG 或内网静态路由中'end
 end
 local count=0;for _,p in ipairs(state.peers)do if not same(p.id,id)and (p.site_local or '')~=''then count=count+1 end end
 if count>=16 then return nil,'最多配置 16 条互访隧道'end
 return true
end
function M.check_peer(state,interface,allowips,id,key,exit_peer,client_endpoint,site_local,site_remote)
 local iface=own(state,interface);if not iface then return nil,'所选 WG 服务接口不存在'end
 local nets,err=M.nets(allowips);if not nets then return nil,err end
 local valid,message=M.client_endpoint(client_endpoint);if not valid then return nil,message end
 exit_peer=exit_peer or 'no';if exit_peer==''then exit_peer='no'end
 if exit_peer~='yes'and exit_peer~='no'then return nil,'分流出口选项无效'end
 if exit_peer=='yes'and (#nets~=1 or nets[1].bits~=32)then return nil,'分流出口隧道须使用独立的 /32 对端地址'end
 for _,p in ipairs(state.peers)do if not same(p.id,id)and p.interface==interface and(exit_peer=='yes'or p.exit_peer=='yes')then
  return nil,'分流出口必须独占服务接口，请为该路由器创建单独的 WG 接口'
 end end
 local site_ok,site_err=M.check_site(state,interface,allowips,id,site_local,site_remote);if not site_ok then return nil,site_err end
 local old;for _,p in ipairs(state.peers)do if same(p.id,id)then old=p end end
 -- Upgrades and unrelated edits must preserve working legacy topology.
 if old and old.interface==interface and old.allowips==allowips and (not key or old.peer_publickey==key)then return true end
 for _,v in ipairs(state.interfaces)do
  local n=M.net(v.local_address)
  for _,r in ipairs(nets)do if n and r.bits==32 and r.host==n.host then return nil,'客户端地址与路由器接口地址重复'end end
 end
 for _,p in ipairs(state.peers)do if not same(p.id,id)then
  if key and key~=''and p.interface==interface and p.peer_publickey==key then return nil,'该接口已存在相同对端公钥，请为每台设备使用独立密钥'end
  for _,a in ipairs(nets)do for _,b in ipairs(M.nets((p.allowips or '')..','..(p.site_remote or ''))or{})do
   if overlap(a,b)and (p.interface==interface or(a.bits>0 and b.bits>0))then
    return nil,'允许地址与已有隧道重叠，请为客户端使用未占用的 /32 地址'
   end
  end end
 end end
 for _,a in ipairs(nets)do if a.bits>0 then
  for _,v in ipairs(state.interfaces)do if v.name~=interface then local b=M.net(v.local_address);if b and overlap(a,b)then return nil,'允许地址与其他 WG 接口网段重叠'end end end
  for _,v in ipairs(state.networks or{})do if v.name~=interface and v.name~='ppp'..interface then local b=M.net(v.address);if b and b.bits>0 and overlap(a,b)then return nil,'允许地址与其他本地或静态路由网段重叠'end end end
 end end
 return true
end
-- Validate the post-edit topology before changing either the database or links.
local function projected_state(state,removed,replacement)
 local next_state={interfaces={},peers=state.peers,networks={}}
 for _,v in ipairs(state.interfaces)do if not removed[v.name]then next_state.interfaces[#next_state.interfaces+1]=v end end
 if replacement then next_state.interfaces[#next_state.interfaces+1]=replacement end
 for _,v in ipairs(state.networks or{})do
  if not removed[v.name]and not removed[tostring(v.name):gsub('^ppp(wg%d+)$','%1')]then next_state.networks[#next_state.networks+1]=v end
 end
 return next_state
end
local function validate_site_dependencies(state)
 for _,p in ipairs(state.peers)do
  if (p.site_local or '')~=''or(p.site_remote or '')~=''then
   local ok,err=M.check_site(state,p.interface,p.allowips,p.id,p.site_local,p.site_remote)
   if not ok then return nil,'该操作会使隧道 '..tostring(p.interface)..' 的互访配置失效：'..tostring(err)end
  end
 end
 return true
end
function M.check_iface_delete(state,ids)
 if type(ids)~='string'or #ids>1024 or ids==''or ids:find('[^%d,%s]')then return nil,'接口编号无效'end
 local wanted={};for id in ids:gmatch('[^,%s]+')do
  local n=tonumber(id);if not n or n<1 or n%1~=0 then return nil,'接口编号无效'end
  wanted[tostring(n)]=true
 end
 local removed={};for _,v in ipairs(state.interfaces)do if wanted[tostring(v.id)]then removed[v.name]=true;wanted[tostring(v.id)]=nil end end
 if next(wanted)or not next(removed)then return nil,'服务接口不存在，请刷新后重试'end
 for _,p in ipairs(state.peers)do if removed[p.interface]then return nil,'接口 '..p.interface..' 仍有关联隧道，请先删除或迁移隧道'end end
 return validate_site_dependencies(projected_state(state,removed))
end
function M.check_iface(state,name,address,port,id)
 if type(name)~='string'or not name:match('^wg%d+$')or #name>12 then return nil,'服务接口名称须为 wg 加数字'end
 local n=M.net(address);if not n then return nil,'服务接口地址无效'end
 port=tonumber(port);if not port or port<1 or port>65535 or port%1~=0 then return nil,'监听端口无效'end
 local old
 for _,v in ipairs(state.interfaces)do
  if same(v.id,id)then old=v
  elseif v.name==name then return nil,'服务接口名称已存在'
  elseif tonumber(v.local_listenport)==port then return nil,'WG 监听端口已被占用'end
 end
 if old and old.name~=name then
  for _,p in ipairs(state.peers)do if p.interface==old.name then return nil,'接口仍有关联隧道，请先删除或迁移隧道后再改名'end end
 end
 if old and old.name==name and old.local_address==address then return true end
 if n.bits<31 and(n.host==n.lo or n.host==n.hi)then return nil,'服务接口不能使用网络地址或广播地址'end
 for _,v in ipairs(state.interfaces)do if not same(v.id,id)then local r=M.net(v.local_address);if r and overlap(n,r)then return nil,'服务接口与已有 WG 网段重叠'end end end
 for _,p in ipairs(state.peers)do if not old or p.interface~=old.name then for _,r in ipairs(M.nets((p.allowips or '')..','..(p.site_remote or ''))or{})do if r.bits>0 and overlap(n,r)then return nil,'服务接口与已有隧道网段重叠'end end end end
 for _,v in ipairs(state.networks or{})do if v.name~=name and v.name~='ppp'..name and(not old or(v.name~=old.name and v.name~='ppp'..old.name))then local r=M.net(v.address);if r and r.bits>0 and overlap(n,r)then return nil,'服务接口与本地或静态路由网段重叠'end end end
 for _,p in ipairs(state.peers)do for _,r in ipairs(M.nets(p.allowips)or{})do
  if r.bits==32 and r.host==n.host then return nil,'服务接口地址不能与已有对端隧道地址重复'end
 end end
 local removed={};if old then removed[old.name]=true end
 return validate_site_dependencies(projected_state(state,removed,{id=id,name=name,local_address=address,local_listenport=port}))
end
return M
