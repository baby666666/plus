#!/usr/bin/lua
local plan=dofile('/usr/ikuai/script/wg_address_plan.lua')
local function check_role(role,exit,ips,site_local,site_remote,keepalive)
 if (role or '')=='' then return true end
 if role~='lend' and role~='access' and role~='both' then return nil,'设备用途无效' end
 local nets=plan.nets(ips or '')
 if not nets or #nets~=1 or nets[1].bits~=32 or (site_local or '')~='' or (site_remote or '')~='' then
  return nil,'手机设备用途需要单个 /32 地址且不能设置互访网段'
 end
 if (role=='access')==(exit=='yes') then return nil,'设备用途和分流出口选项不匹配' end
 if role=='lend' and (tonumber(keepalive) or 0)==0 then return nil,'借用设备网络需要非零 WG 心跳，可设置为 25 秒' end
 return true
end
local function bound_site_clients(db)
 local peer=dofile('/usr/ikuai/script/wg_mobile_peer.lua')
 local owned={}
 -- The application marker survives native CSV and VRRP migration, even when
 -- the companion credential table does not. An orphan cannot load raw WG.
 local stmt=db:prepare('SELECT c.peer_id'..peer.site_client_binding(db))
 if stmt then
  for row in stmt:nrows() do owned[row.peer_id]=true end
  stmt:finalize()
 end
 return owned
end
-- Called under wireguard_address before any enable, disable or delete writes.
-- Compare the complete selected set in one DB snapshot; a stale row rejects
-- its whole batch. Only public WG identity fields ever enter this path.
local function check_targets(dbfile,action,ids)
 local iface=action=='iface_up' or action=='iface_down' or action=='iface_del' or action=='iface_edit'
 if not iface and action~='up' and action~='down' and action~='del' then return false end
 if type(ids)~='string' or #ids>131072 or not ids:match('^%d[%d,]*$') or ids:find(',,',1,true) or ids:sub(-1)==',' then return false end
 local remaining,count={},0
 for id in ids:gmatch('%d+') do
  if not id:match('^[1-9]%d*$') or #id>18 or remaining[id] then return false end
  remaining[id]=true;count=count+1
 end
 local hex=io.read(1048577)
 if not hex or #hex>1048576 or #hex%2~=0 or not hex:match('^[0-9a-f]+$') then return false end
 local raw=hex:gsub('..',function(b)return string.char(tonumber(b,16))end)
 local ok,rows=pcall(require('cjson').decode,raw)
 if not ok or type(rows)~='table' or #rows~=count then return false end
 local expected={}
 for index,r in pairs(rows) do
  if type(index)~='number' or index<1 or index>count or type(r)~='table' then return false end
  local id=tostring(r.id)
  if remaining[id]~=true or type(r.interface)~='string' or not r.interface:match('^wg%d+$') or
     type(r.public_key)~='string' or r.public_key=='' then return false end
  remaining[id]=false;expected[id]=r
 end
 local query
 if iface then
  query="SELECT CAST(id AS TEXT) AS id,name AS interface,local_publickey AS public_key FROM wireguard WHERE id IN ("..ids..")"
 else
  query=[[SELECT CAST(p.id AS TEXT) AS id,p.interface,p.peer_publickey AS public_key,
    CAST(coalesce(w.id,0) AS TEXT) AS iface_id,coalesce(w.local_publickey,'') AS server_key
    FROM wireguard_peers p LEFT JOIN wireguard w ON w.name=p.interface WHERE p.id IN (]]..ids..")"
 end
 local sqlite=require('lsqlite3')
 local db=assert(sqlite.open(dbfile));db:busy_timeout(10000)
 local valid,matches=true,0
 for actual in db:nrows(query) do
  local r=expected[actual.id]
  if not r or actual.interface~=r.interface or actual.public_key~=r.public_key or
     (not iface and (actual.iface_id~=tostring(r.iface_id) or actual.server_key~=r.server_key)) then
   valid=false
  end
  matches=matches+1
 end
 db:close()
 return valid and matches==count
end
local function main()
 if arg[1]=='targets' then
  return check_targets(arg[2],arg[3],arg[4]),'设备已被删除或更改，请返回列表并重新打开。'
 elseif arg[1]=='validate'then
  if arg[2]~='yes'and arg[2]~='no'then return nil,'分流出口选项无效'end
  local ok,err=plan.client_endpoint(arg[3]);if not ok then return nil,err end
  ok,err=check_role(arg[6],arg[2],arg[7],arg[4],arg[5],arg[8]);if not ok then return nil,err end
  return plan.site_fields(arg[4],arg[5])
 elseif arg[1]=='runtime'then
  local sqlite=require('lsqlite3');local db=assert(sqlite.open(arg[2]));db:busy_timeout(10000)
  local all=arg[3]=='*'
  local stmt=assert(db:prepare('select id,interface,allowips,exit_peer,site_local,site_remote,native_role,keepalive from wireguard_peers'..(all and ''or' where interface=?')));if not all then stmt:bind_values(arg[3])end
  local rows,counts,sites={},{},nil;for row in stmt:nrows()do rows[#rows+1]=row;counts[row.interface]=(counts[row.interface]or 0)+1 end;stmt:finalize()
  for _,row in ipairs(rows)do
   local valid,err=plan.site_fields(row.site_local,row.site_remote);if not valid then return nil,err end
   if row.native_role=='site_client' then
    sites=sites or bound_site_clients(db)
    if not sites[row.id] then return nil,'组网隧道缺少匹配的中继配置，请重新导入组网配置' end
   else
    valid,err=check_role(row.native_role,row.exit_peer,row.allowips,row.site_local,row.site_remote,row.keepalive);if not valid then return nil,err end
   end
   if row.exit_peer~='no'and row.exit_peer~=''and row.exit_peer~=nil and row.exit_peer~='yes'then return nil,'分流出口选项无效'end
   if row.exit_peer=='yes'then
    local nets=plan.nets(row.allowips)
    if counts[row.interface]~=1 or not nets or #nets~=1 or nets[1].bits~=32 then return nil,'分流出口必须独占接口并使用 /32 地址'end
   end
  end
  db:close()
  local path="'"..arg[2]:gsub("'","'\\''").."'"
  if os.execute('/usr/bin/lua /usr/ikuai/script/wg_site_compile.lua '..path..' >/dev/null')~=0 then return nil,'互访网段、路由或恢复配置冲突'end
  return true
 end
 return nil,'不支持的 WG 参数检查'
end
local ok,valid,message=pcall(main)
if not ok then print('WG 参数检查失败');os.exit(1)end
if not valid then print(message);os.exit(1)end
