-- Snapshot used by native WG mutations and router-to-router imports.
local function rule_interfaces(db)
 local names={}
 local function remember(list)
  for token in (list or ''):gmatch('[^,%s]+') do
   local dev=token:match('^(wg%d+)$') or token:match('^ppp(wg%d+)$')
   if dev then names[dev]=true end
  end
 end
 -- Include paused rules and every candidate exit. Their interface references
 -- survive peer deletion, and must not silently attach to a new identity.
 for _,tbl in ipairs{'stream_domain','stream_ipport','stream_layer7'} do
  local cols={}
  for row in db:nrows('PRAGMA table_info('..tbl..')') do cols[row.name]=true end
  if cols.interface then
   local fields=cols.nr_ingress and 'interface,nr_ingress' or 'interface'
   for row in db:nrows('SELECT DISTINCT '..fields..' FROM '..tbl) do
    remember(row.interface);remember(row.nr_ingress)
   end
  end
 end
 return names
end
return function(db,allocating)
 local state={interfaces={},peers={},networks={}}
 if allocating then state.referenced_wg=rule_interfaces(db) end
 for row in db:nrows('select id,name,local_address,local_listenport from wireguard order by id')do state.interfaces[#state.interfaces+1]=row end
 for row in db:nrows('select id,interface,allowips,peer_publickey,exit_peer,site_local,site_remote from wireguard_peers order by id')do
  state.peers[#state.peers+1]=row
  -- Restoring the peer table alone must not attach its rows to a new interface.
  if allocating and row.interface then state.referenced_wg[row.interface]=true end
 end
 for _,table_name in ipairs{'lan_config','wan_config'}do
  local cols={};for row in db:nrows('pragma table_info('..table_name..')')do cols[row.name]=true end
  if cols.ip_mask and cols.name then for row in db:nrows('select name,ip_mask from '..table_name)do
   for addr in tostring(row.ip_mask or ''):gmatch('[^,%s]+')do state.networks[#state.networks+1]={name=row.name,address=addr}end
  end end
 end
 local pipe=assert(io.popen('ip -o -4 addr show 2>/dev/null'))
 for line in pipe:lines()do local name,address=line:match('^%d+:%s+(%S+)%s+inet%s+(%S+)');if name then state.networks[#state.networks+1]={name=name:gsub('@.*',''),address=address}end end;pipe:close()
 -- Connected routes are already covered by interface addresses. Reserve static
 -- remote networks, including route-only sites; ignore the system default.
 pipe=assert(io.popen('ip -4 route show table main 2>/dev/null'))
 for line in pipe:lines()do local address=line:match('^(%d+%.%d+%.%d+%.%d+/%d+)');local name=line:match(' dev (%S+)');if address and not line:find('proto kernel',1,true)and name and not name:match('^wg%d+$')then state.networks[#state.networks+1]={name=name,address=address}end end;pipe:close()
 return state
end
