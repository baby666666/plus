#!/usr/bin/lua
-- Read-only snapshot; caller serializes mutations through native Lock.
local json=require('cjson');local sqlite=require('lsqlite3')
local plan=dofile('/usr/ikuai/script/wg_address_plan.lua')
local function main()
 local mode,path=assert(arg[1]),assert(arg[2]);local f=assert(io.open(path,'rb'));f:close()
 local db=assert(sqlite.open(path));db:busy_timeout(10000);assert(db:exec('BEGIN')==sqlite.OK)
 local auto_name=mode=='iface' and (arg[6] or '')=='' and arg[7]=='yes'
 local state=dofile('/usr/ikuai/script/wg_address_inventory.lua')(db,mode=='defaults' or auto_name)
 assert(db:exec('COMMIT')==sqlite.OK);db:close()
 if mode=='defaults'then
  local a,ae=plan.iface_defaults(state);local iface=arg[3]or''
  if iface==''then iface=state.interfaces[1]and state.interfaces[1].name or''end
  local p,pe=plan.peer_defaults(state,iface)
  print(json.encode({iface_defaults=a or{name=plan.next_iface_name(state),local_address='',error=ae},peer_defaults=p or{interface=iface,allowips='',client_dns='',error=pe}}));return
 end
 if auto_name and state.referenced_wg[arg[3]] then print('接口名称仍被已有配置引用，请重新导入');return false end
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
