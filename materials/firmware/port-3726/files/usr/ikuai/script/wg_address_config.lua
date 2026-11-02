#!/usr/bin/lua
-- Read-only snapshot; caller serializes mutations through native Lock.
local json=require('cjson');local sqlite=require('lsqlite3')
local plan=dofile('/usr/ikuai/script/wg_address_plan.lua')
local function main()
 local mode,path=assert(arg[1]),assert(arg[2]);local f=assert(io.open(path,'rb'));f:close()
 local db=assert(sqlite.open(path));db:busy_timeout(10000);assert(db:exec('BEGIN')==sqlite.OK)
 local state={interfaces={},peers={},networks={}}
 for row in db:nrows('select id,name,local_address,local_listenport from wireguard order by id')do state.interfaces[#state.interfaces+1]=row end
 for row in db:nrows('select id,interface,allowips,peer_publickey,exit_peer,site_local,site_remote from wireguard_peers order by id')do state.peers[#state.peers+1]=row end
 for _,table_name in ipairs{'lan_config','wan_config'}do
  local cols={};for row in db:nrows('pragma table_info('..table_name..')')do cols[row.name]=true end
  if cols.ip_mask and cols.name then for row in db:nrows('select name,ip_mask from '..table_name)do
   for addr in tostring(row.ip_mask or ''):gmatch('[^,%s]+')do state.networks[#state.networks+1]={name=row.name,address=addr}end
  end end
 end
 assert(db:exec('COMMIT')==sqlite.OK);db:close()
 local pipe=assert(io.popen('ip -o -4 addr show 2>/dev/null'))
 for line in pipe:lines()do local name,address=line:match('^%d+:%s+(%S+)%s+inet%s+(%S+)');if name then state.networks[#state.networks+1]={name=name:gsub('@.*',''),address=address}end end;pipe:close()
 -- Connected routes are already covered by interface addresses. Reserve static
 -- remote networks, including route-only sites; ignore the system default.
 pipe=assert(io.popen('ip -4 route show table main 2>/dev/null'))
 for line in pipe:lines()do local address=line:match('^(%d+%.%d+%.%d+%.%d+/%d+)');local name=line:match(' dev (%S+)');if address and not line:find('proto kernel',1,true)and name and not name:match('^wg%d+$')then state.networks[#state.networks+1]={name=name,address=address}end end;pipe:close()
 if mode=='defaults'then
  local a,ae=plan.iface_defaults(state);local iface=arg[3]or''
  if iface==''then iface=state.interfaces[1]and state.interfaces[1].name or''end
  local p,pe=plan.peer_defaults(state,iface)
  print(json.encode({iface_defaults=a or{local_address='',error=ae},peer_defaults=p or{interface=iface,allowips='',client_dns='',error=pe}}));return
 end
 local ok,err
 if mode=='peer'then ok,err=plan.check_peer(state,arg[3],arg[4],arg[5],arg[6],arg[7],arg[8],arg[9],arg[10])
 elseif mode=='iface'then ok,err=plan.check_iface(state,arg[3],arg[4],arg[5],arg[6])
 elseif mode=='iface_delete'then ok,err=plan.check_iface_delete(state,arg[3])
 else error('不支持的地址规划操作')end
 if not ok then print(err);return false end
 return true
end
local ok,result=pcall(main)
if not ok then io.stderr:write('WG address planning failed\n');print('地址规划读取失败，请刷新后重试');os.exit(1)end
if result==false then os.exit(1)end
