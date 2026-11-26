#!/usr/bin/lua
-- Emit validated, whitespace-delimited records. No keys or shell fragments.
local p=dofile('/usr/ikuai/script/wg_address_plan.lua')
local sqlite=require('lsqlite3')
local function main()
 local db=assert(sqlite.open(arg[1]));db:busy_timeout(10000)
 local state={interfaces={},peers={},networks={}};local ifaces={}
 for r in db:nrows('select id,name,local_address,local_listenport,enabled from wireguard')do state.interfaces[#state.interfaces+1]=r;ifaces[r.name]=r end
 for r in db:nrows('select id,interface,allowips,peer_publickey,exit_peer,site_local,site_remote,enabled from wireguard_peers')do state.peers[#state.peers+1]=r end
 for r in db:nrows('select name,ip_mask from lan_config')do for a in tostring(r.ip_mask or ''):gmatch('[^,%s]+')do state.networks[#state.networks+1]={name=r.name,address=a}end end
 db:close()
 local f=assert(io.popen('ip -o -4 addr show 2>/dev/null'))
 for line in f:lines()do local dev,addr=line:match('^%d+:%s+(%S+)%s+inet%s+(%S+)');if dev then state.networks[#state.networks+1]={name=dev:gsub('@.*',''),address=addr}end end;f:close()
 f=assert(io.popen('ip -4 route show table main 2>/dev/null'))
 for line in f:lines()do local addr=line:match('^(%d+%.%d+%.%d+%.%d+/%d+)');local dev=line:match(' dev (%S+)');local via=line:match(' via (%S+)');if addr and dev and not line:find('proto kernel',1,true) and not dev:match('^wg%d+$')then state.networks[#state.networks+1]={name=dev,address=addr,via=via}end end;f:close()
 for _,i in ipairs(state.interfaces)do state.networks[#state.networks+1]={name=i.name,address=i.local_address}end
 local output={};local function emit(...)
  local words={...};for _,w in ipairs(words)do assert(type(w)=='string' and w:match('^[%w%./_%-]+$'))end
  output[#output+1]=table.concat(words,' ')
 end
 local function route(n)
  local best
  for _,r in ipairs(state.networks)do local net=p.net(r.address)
   if net and not r.name:match('^wan')and not r.name:match('^pppwg')and n.lo>=net.lo and n.hi<=net.hi and(not best or net.bits>best.bits)then best={name=r.name,bits=net.bits,via=r.via}end
  end
  return best
 end
 local count=0
 for _,r in ipairs(state.peers)do
  if (r.site_local or '')~=''or(r.site_remote or '')~=''then
   count=count+1;assert(count<=16,'互访隧道过多')
   assert(r.interface:match('^wg%d+$')and #r.interface<=10,'接口名称无效')
   local valid,err=p.check_site(state,r.interface,r.allowips,r.id,r.site_local,r.site_remote);assert(valid,err)
   local site=assert(p.site_fields(r.site_local,r.site_remote));local iface=assert(ifaces[r.interface],'互访接口不存在')
   local a=assert(p.net(iface.local_address));local b=assert(p.nets(r.allowips))[1]
   local local_tunnel=assert(p.net(iface.local_address:match('^[^/]+')..'/32'))
   site.local_nets[#site.local_nets+1]=local_tunnel;site.remote_nets[#site.remote_nets+1]=b
   local enabled=(r.enabled=='yes'and iface.enabled=='yes')and'yes'or'no'
   for _,remote in ipairs(site.remote_nets)do emit('T',remote.text,r.interface,'-',enabled)end
   for _,localnet in ipairs(site.local_nets)do
    local dest=route(localnet);assert(dest,'本端互访网段没有路由')
    emit('T',localnet.text,dest.name,dest.via or '-','yes')
    for _,remote in ipairs(site.remote_nets)do
     emit('P',localnet.text,remote.text)
     emit('P',remote.text,localnet.text)
     if localnet~=local_tunnel then
      emit('I',dest.name,localnet.text,remote.text)
      if dest.name:match('^wg%d+$')then emit('I','ppp'..dest.name,localnet.text,remote.text)end
     end
     emit('I',r.interface,remote.text,localnet.text)
     emit('I','ppp'..r.interface,remote.text,localnet.text)
    end
   end
  end
 end
 table.sort(output);local prev;for _,line in ipairs(output)do if line~=prev then print(line);prev=line end end
end
local ok,err=pcall(main);if not ok then io.stderr:write('WG 互访计划无效: '..tostring(err)..'\n');os.exit(1)end
