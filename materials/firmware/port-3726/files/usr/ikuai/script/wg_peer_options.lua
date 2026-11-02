#!/usr/bin/lua
local plan=dofile('/usr/ikuai/script/wg_address_plan.lua')
local function main()
 if arg[1]=='validate'then
  if arg[2]~='yes'and arg[2]~='no'then return nil,'分流出口选项无效'end
  local ok,err=plan.client_endpoint(arg[3]);if not ok then return nil,err end
  return plan.site_fields(arg[4],arg[5])
 elseif arg[1]=='runtime'then
  local sqlite=require('lsqlite3');local db=assert(sqlite.open(arg[2]));db:busy_timeout(10000)
  local all=arg[3]=='*'
  local stmt=assert(db:prepare('select interface,allowips,exit_peer,site_local,site_remote from wireguard_peers'..(all and ''or' where interface=?')));if not all then stmt:bind_values(arg[3])end
  local rows,counts={},{};for row in stmt:nrows()do rows[#rows+1]=row;counts[row.interface]=(counts[row.interface]or 0)+1 end;stmt:finalize();db:close()
  for _,row in ipairs(rows)do
   local valid,err=plan.site_fields(row.site_local,row.site_remote);if not valid then return nil,err end
   if row.exit_peer~='no'and row.exit_peer~=''and row.exit_peer~=nil and row.exit_peer~='yes'then return nil,'分流出口选项无效'end
   if row.exit_peer=='yes'then
    local nets=plan.nets(row.allowips)
    if counts[row.interface]~=1 or not nets or #nets~=1 or nets[1].bits~=32 then return nil,'分流出口必须独占接口并使用 /32 地址'end
   end
  end
  local path="'"..arg[2]:gsub("'","'\\''").."'"
  if os.execute('/usr/bin/lua /usr/ikuai/script/wg_site_compile.lua '..path..' >/dev/null')~=0 then return nil,'互访网段、路由或恢复配置冲突'end
  return true
 end
 return nil,'不支持的 WG 参数检查'
end
local ok,valid,message=pcall(main)
if not ok then print('WG 参数检查失败');os.exit(1)end
if not valid then print(message);os.exit(1)end
