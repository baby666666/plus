local sqlite=require('lsqlite3')
local json=require('cjson')
local script='/usr/ikuai/script/'
local peer=dofile(script..'wg_mobile_peer.lua')
local plan=dofile(script..'wg_address_plan.lua')
local check=peer.check
local invalid='组网配置格式无效'
local action,dbfile,stage=unpack(arg,1,3)
local function number(v,lo,hi)
    return type(v)=='number' and peer.number(v,lo,hi)
end
local function fields(obj,names)
    check(type(obj)=='table',invalid)
    for k in pairs(obj) do
        check(type(k)=='string' and k:match('^[a-z0-9_]+$') and names:find(' '..k..' ',1,true),invalid)
    end
end
local function cidr(v)
    if type(v)~='string' then return end
    local host,bits=v:match('^([^/]+)/(%d+)$')
    return peer.ipv4(host) and tostring(tonumber(bits))==bits and plan.net(v)
end
local function read_bundle()
    -- The native HTTP dispatcher rejects JSON punctuation inside scalar
    -- parameters. Decode after the normal parameter filter, on the router.
    local hex=peer.read(stage..'/bundle.hex')
    check(#hex>0 and #hex<=32768 and #hex%2==0 and hex:match('^[0-9a-f]+$'),invalid)
    local text=hex:gsub('..',function(byte) return string.char(tonumber(byte,16)) end)
    local ok,b=pcall(json.decode,text)
    check(ok and type(b)=='table',invalid)
    return b
end
local function decode(b)
    check(b.format~='nativerouting-hy2-wg-site','Hysteria 2 承载 WG 已停用，请重新导出原生 WG 或纯 HY2 配置')
    check(b.version==2 and b.format=='nativerouting-wg-device','组网配置格式或版本不受支持')
    fields(b,' format version purpose transport wireguard ')
    local mode=b.purpose
    check(mode=='access' or mode=='lend' or mode=='both',invalid)
    local t,w=b.transport,b.wireguard
    fields(t,' server server_port ')
    fields(w,' private_key public_key preshared_key address peer_address mtu keepalive ')
    local outer_ip=peer.ipv4(t.server)
    check(number(t.server_port,1,65535),invalid)
    if not outer_ip then
        check(type(t.server)=='string' and not t.server:match('^[%d.]+$') and
            t.server:match('^[a-zA-Z0-9%.%-]+$') and plan.client_endpoint(t.server),invalid)
        -- Validated DNS labels contain only ASCII letters/digits, dots and
        -- hyphens, and cannot begin with a hyphen. Never run the pasted JSON.
        local f=assert(io.popen('resolveip -4 -t 4 '..t.server..' 2>/dev/null'))
        outer_ip=peer.ipv4(f:read('*l'))
        f:close()
        check(outer_ip,'无法解析路由器入口的 IPv4 地址')
    end
    local a,r=cidr(w.address),cidr(w.peer_address)
    if w.mtu==nil then w.mtu=1420 end
    local mtu=number(w.mtu,576,9000)
    local min_keep=mode=='lend' and 1 or 0
    check(a and r and r.bits==32 and a.host~=r.host and a.bits==32 and
        mtu and number(w.keepalive,min_keep,65535) and peer.wgkey(w.private_key) and peer.wgkey(w.public_key) and
        (w.preshared_key==nil or peer.wgkey(w.preshared_key)),invalid)
    local outer=plan.net(outer_ip)
    local function independent(net)
        return outer.host<net.lo or outer.host>net.hi
    end
    local conflict='WG 入口地址与隧道路由冲突'
    check(independent(a) and independent(r),conflict)
    peer.write(stage..'/key',w.private_key..'\n')
    local result=os.execute("/usr/bin/wg pubkey < '"..stage.."/key' > '"..stage.."/pub' 2>/dev/null")
    os.remove(stage..'/key')
    local pub=peer.read(stage..'/pub'):match('^(%S+)')
    check(result==0 and peer.wgkey(pub) and pub~=w.public_key,invalid)
    return t,w,pub,mode,outer_ip
end
local function insert(db,sql,...)
    local stmt=assert(db:prepare(sql))
    stmt:bind_values(...)
    local rc=stmt:step()
    stmt:finalize()
    assert(rc==sqlite.DONE)
    return db:last_insert_rowid()
end
local function schema(db)
    local existing,current=false,false
    for col in db:nrows('PRAGMA table_info(wg_site_clients)') do
        existing=true
        if col.name=='transport' then current=true end
    end
    if current then return end
    if existing then assert(db:exec('ALTER TABLE wg_site_clients RENAME TO wg_site_clients_rc12')==sqlite.OK) end
    assert(db:exec([[CREATE TABLE wg_site_clients(
        peer_id INTEGER PRIMARY KEY, iface_id INTEGER NOT NULL UNIQUE, iface TEXT NOT NULL UNIQUE,
        local_public TEXT NOT NULL UNIQUE, peer_public TEXT NOT NULL, relay_port INTEGER UNIQUE,
        server TEXT NOT NULL, server_port INTEGER NOT NULL, target_port INTEGER,
        password TEXT, pin TEXT, transport TEXT NOT NULL, purpose TEXT NOT NULL)]])==sqlite.OK)
    if existing then
        assert(db:exec([[INSERT INTO wg_site_clients(peer_id,iface_id,iface,local_public,peer_public,relay_port,server,
            server_port,target_port,password,pin,transport,purpose)
            SELECT peer_id,iface_id,iface,local_public,peer_public,relay_port,server,server_port,target_port,password,pin,
            'hysteria2','site' FROM wg_site_clients_rc12]])==sqlite.OK)
        assert(db:exec('DROP TABLE wg_site_clients_rc12')==sqlite.OK)
    end
end
local function allocate(db,state)
    local used,names={},{}
    for _,r in ipairs(state.interfaces) do names[r.name]=true; used[tonumber(r.local_listenport)]=true end
    for r in db:nrows('SELECT iface,relay_port FROM wg_site_clients') do
        names[r.iface]=true
        if r.relay_port then used[tonumber(r.relay_port)]=true end
    end
    local statefile='/etc/mnt/ikuai/wg-hyr/state.json'
    local f=io.open(statefile,'r')
    if f then
        f:close()
        local saved=json.decode(peer.read(statefile))
        for _,m in pairs(saved.members) do
            if m.transport=='pure_hy2' then
                used[m.port]=true
                if m.inner_port then used[m.inner_port]=true end
            end
        end
    end
    for _,path in ipairs{'/proc/net/udp','/proc/net/udp6'} do
        local sockets=assert(io.open(path,'r'))
        for line in sockets:lines() do
            local hex=line:match('^%s*%d+:%s+%x+:(%x+)')
            if hex then used[tonumber(hex,16)]=true end
        end
        sockets:close()
    end
    local function free(start)
        for p=start,28999 do if not used[p] then used[p]=true;return p end end
        check(false,'本机没有可用 UDP 端口')
    end
    for i=1,9999 do
        local dev='wg'..i
        local f=io.open('/sys/class/net/'..dev..'/ifindex','r')
        if f then f:close() elseif not names[dev] and not state.referenced_wg[dev] then return dev,free(19000) end
    end
    check(false,'本机没有可用 WG 接口')
end
-- Both the native controller and import use the same test for orphaned
-- identities. Row IDs and names can be reused by completely different keys.
local unowned=[[ WHERE NOT EXISTS (SELECT 1 FROM wireguard w WHERE w.local_publickey=wg_site_clients.local_public)
    AND NOT EXISTS (SELECT 1 FROM wireguard_peers p WHERE p.peer_publickey=wg_site_clients.peer_public
    AND (p.interface=wg_site_clients.iface OR p.id=wg_site_clients.peer_id))]]
local function retired_links(db)
    for r in db:nrows('SELECT iface,local_public,peer_public FROM wg_site_clients'..unowned) do
        assert(type(r.iface)=='string' and #r.iface<=12 and r.iface:match('^wg%d+$'))
        assert(peer.wgkey(r.local_public) and peer.wgkey(r.peer_public))
        print(table.concat({r.iface,r.local_public,r.peer_public},' '))
    end
end
local function reconcile_registrations(db,pub)
    -- Remove only stale metadata. The WG mutation lock also covers retiring
    -- an old matching kernel link before taking the live address inventory.
    assert(db:exec('DELETE FROM wg_site_clients'..unowned)==sqlite.OK)
    local bound='SELECT c.peer_id'..peer.site_client_binding(db)
    for saved in db:nrows('SELECT local_public,peer_id IN ('..bound..') AS bound FROM wg_site_clients') do
        if saved.local_public==pub then
            check(saved.bound==1,'组网配置只恢复了一部分，请先删除列表中残留的原 WG 隧道或接口，再重新导入')
            check(false,'这份组网配置已导入')
        end
    end
end
local function managed_id(db,table_name,owner_col)
    local sql='SELECT max(n)+1 AS id FROM (SELECT coalesce(max(id),0) AS n FROM '..table_name..
        ' UNION ALL SELECT coalesce(max('..owner_col..'),0) FROM wg_site_clients)'
    for row in db:nrows(sql) do return assert(tonumber(row.id)) end
    error('identity allocation')
end
-- Keep ordinary management ownership and optimistic-lock keys on the native
-- rows. The actual public transport profile contains no WireGuard endpoint.
local function anchor_keys()
    if action=='preflight' then
        local cmd="umask 077; cd '"..stage.."' && /usr/bin/wg genkey >anchor.key && /usr/bin/wg pubkey <anchor.key >anchor.pub && /usr/bin/wg genkey | /usr/bin/wg pubkey >anchor.peer"
        check(os.execute(cmd)==0,'无法创建设备身份')
    end
    local function key(file)
        local value=peer.read(stage..'/'..file):match('^(%S+)')
        return check(peer.wgkey(value),'设备身份无效') and value
    end
    return key('anchor.key'),key('anchor.pub'),key('anchor.peer')
end
local function import_pure(db,b)
    local pure=dofile(script..'wg_pure_client.lua')
    pure.validate(b,peer)
    local t=b.transport
    assert(db:exec('BEGIN IMMEDIATE')==sqlite.OK)
    schema(db)
    local extended=false
    for col in db:nrows('PRAGMA table_info(wg_site_clients)') do if col.name=='pure_bundle' then extended=true end end
    if not extended then assert(db:exec('ALTER TABLE wg_site_clients ADD COLUMN pure_bundle TEXT')==sqlite.OK) end
    local private,pub,remote=anchor_keys()
    reconcile_registrations(db,pub)
    for row in db:nrows("SELECT pure_bundle FROM wg_site_clients WHERE transport='pure_hy2' AND purpose IN ('access','both')") do
        local other=json.decode(row.pure_bundle)
        if other.transport.password==t.password then
            check(false,'这份纯 Hysteria 2 设备配置已导入')
        end
    end
    local state=dofile(script..'wg_address_inventory.lua')(db,true)
    local dev,port=allocate(db,state)
    local iface=check(plan.iface_defaults(state),'无法分配设备管理地址')
    local valid,err=plan.check_iface(state,dev,iface.local_address,port);check(valid,err)
    state.interfaces[#state.interfaces+1]={name=dev,local_address=iface.local_address,local_listenport=port}
    local branch=check(plan.peer_defaults(state,dev),'无法分配管理地址')
    valid,err=plan.check_peer(state,dev,branch.allowips,'',remote,'yes','','','');check(valid,err)
    local outer=table.concat({script..'wg_client_endpoint.sh check_outer',t.server,dev,iface.local_address,branch.allowips},' ')
    check(os.execute(outer..' >/dev/null 2>&1')==0,'入口地址指向本机、隧道或没有可用的 IPv4 路由')
    local pid=managed_id(db,'wireguard_peers','peer_id')
    local iid=managed_id(db,'wireguard','iface_id')
    check(pure.address_free(pid),'纯 Hysteria 2 接口地址冲突')
    local cfg=peer.encode(pure.config(b,pid))
    if action=='preflight' then
        peer.write(stage..'/transport','pure_hy2')
        peer.write(stage..'/checked.json',cfg)
        assert(db:exec('ROLLBACK')==sqlite.OK)
        return
    end
    check(peer.read(stage..'/transport')=='pure_hy2' and peer.read(stage..'/checked.json')==cfg,'设备或本机地址已变化，请重新导入')
    insert(db,[[INSERT INTO wireguard(id,enabled,name,interface,local_privatekey,local_publickey,local_address,local_listenport,mtu)
        VALUES(?,'yes',?,'auto',?,?,?,?,1500)]],iid,dev,private,pub,iface.local_address,port)
    insert(db,[[INSERT INTO wireguard_peers(id,enabled,interface,peer_publickey,allowips,endpoint,endpoint_port,keepalive,exit_peer,site_local,site_remote,native_role)
        VALUES(?,'yes',?,?,?,'',0,0,'yes','','','site_client')]],pid,dev,remote,branch.allowips)
    insert(db,[[INSERT INTO wg_site_clients(peer_id,iface_id,iface,local_public,peer_public,server,server_port,transport,purpose,pure_bundle)
        VALUES(?,?,?,?,?,?,?,'pure_hy2',?,?)]],pid,iid,dev,pub,remote,t.server,t.server_port,b.purpose,peer.encode(b))
    assert(db:exec('COMMIT')==sqlite.OK)
    print(dev)
end
local function import(db)
    local b=read_bundle()
    if b.format=='nativerouting-pure-hy2-device' then return import_pure(db,b) end
    local t,w,pub,mode,outer_ip=decode(b)
    local transport='native'
    local exit=mode=='lend' and 'no' or 'yes'
    assert(db:exec('BEGIN IMMEDIATE')==sqlite.OK)
    schema(db)
    reconcile_registrations(db,pub)
    local state=dofile(script..'wg_address_inventory.lua')(db,true)
    for a in db:nrows('SELECT local_publickey FROM wireguard') do
        check(a.local_publickey~=pub and a.local_publickey~=w.public_key,'组网密钥与本机 WG 接口冲突')
    end
    local dev,port=allocate(db,state)
    -- All four words have already been validated as IPs/CIDRs or allocated
    -- interface names. The shared FIB check never sends network traffic.
    local check_route=table.concat({script..'wg_client_endpoint.sh check_outer',outer_ip,dev,w.address,w.peer_address},' ')
    check(os.execute(check_route..' >/dev/null 2>&1')==0,'入口地址指向本机、隧道或没有可用的 IPv4 路由')
    local valid,err=plan.check_iface(state,dev,w.address,port)
    check(valid,err)
    state.interfaces[#state.interfaces+1]={name=dev,local_address=w.address,local_listenport=port}
    valid,err=plan.check_peer(state,dev,w.peer_address,'',w.public_key,exit,'','','')
    check(valid,err)
    if action=='preflight' then
        peer.write(stage..'/transport',transport)
        assert(db:exec('ROLLBACK')==sqlite.OK)
        return
    end
    -- A listener can appear during installation. Revalidate its chosen ports
    -- and config under the WG lock before committing any durable native row.
    check(peer.read(stage..'/transport')==transport,'本机 UDP 端口已变化，请重新导入')
    -- Reserve the IDs of either half of an incomplete registration. SQLite's
    -- default largest-rowid+1 would otherwise reuse them for an unrelated peer.
    local iid=insert(db,[[INSERT INTO wireguard(id,enabled,name,interface,local_privatekey,local_publickey,local_address,local_listenport,mtu)
        VALUES((SELECT max(n)+1 FROM (SELECT coalesce(max(id),0) AS n FROM wireguard
                 UNION ALL SELECT coalesce(max(iface_id),0) FROM wg_site_clients)),'yes',?,'auto',?,?,?,?,?)]],dev,w.private_key,pub,w.address,port,w.mtu)
    local pid=insert(db,[[INSERT INTO wireguard_peers(id,enabled,interface,peer_publickey,presharedkey,allowips,endpoint,endpoint_port,
        keepalive,exit_peer,site_local,site_remote,native_role)
        VALUES((SELECT max(n)+1 FROM (SELECT coalesce(max(id),0) AS n FROM wireguard_peers
                 UNION ALL SELECT coalesce(max(peer_id),0) FROM wg_site_clients)),'yes',?,?,?,?,?,?,?,?,?,?,'site_client')]],
        dev,w.public_key,w.preshared_key or '',w.peer_address,t.server,t.server_port,w.keepalive,exit,'','')
    insert(db,[[INSERT INTO wg_site_clients(peer_id,iface_id,iface,local_public,peer_public,
        server,server_port,transport,purpose) VALUES(?,?,?,?,?,?,?,?,?)]],pid,iid,dev,pub,w.public_key,t.server,t.server_port,transport,mode)
    assert(db:exec('COMMIT')==sqlite.OK)
    print(dev)
end
local function stored_pure(r,model)
    local b=json.decode(r.pure_bundle)
    check(type(b)=='table' and b.purpose==r.purpose and type(b.transport)=='table'
        and b.transport.server==r.server and b.transport.server_port==r.server_port,'纯 Hysteria 2 持久身份不匹配')
    if b.purpose=='both' then
        -- This branch runs only for an existing, bound RC15 database row.
        b={format=b.format,version=b.version,purpose='access',transport=b.transport}
    end
    return model.validate(b,peer)
end
-- Keep the durable retirement independent of worker validation and firewall
-- availability. Boot may publish the management API before network devices exist.
local function retire_wrapped(db)
    local binding,transport=peer.site_client_binding(db,true)
    local ids='SELECT c.peer_id'..binding..' AND '..transport.."='hysteria2'"
    assert(db:exec('BEGIN IMMEDIATE')==sqlite.OK)
    assert(db:exec("UPDATE wireguard_peers SET enabled='no' WHERE enabled='yes' AND id IN ("..ids..')')==sqlite.OK)
    assert(db:exec("UPDATE wg_site_clients SET password='',pin='' WHERE (ifnull(password,'')<>'' OR ifnull(pin,'')<>'') AND peer_id IN ("..ids..')')==sqlite.OK)
    assert(db:exec('COMMIT')==sqlite.OK)
end
local function snapshot(db)
    local rows,guards,dirs,enabled_devs,owners={},{},{},{},{}
    local pure_units,migrating={},{}
    local sql=[[SELECT c.*,w.local_listenport,w.enabled AS we,p.enabled AS pe,p.site_local,p.site_remote,p.allowips]]..peer.site_client_binding(db,true)..' ORDER BY c.peer_id'
    for r in db:nrows(sql) do
        local transport=r.transport or 'hysteria2'
        local hy=transport=='hysteria2'
        local direct=transport=='pure_hy2'
        local purpose=r.purpose or 'site'
        local safe=type(r.iface)=='string' and r.iface:match('^wg%d+$') and #r.iface<=12 and
            peer.number(r.local_listenport,1,65535) and (not hy or peer.number(r.relay_port,1,65535))
        assert(safe)
        local retired=hy or direct and purpose=='lend'
        local enabled=not retired and r.we=='yes' and r.pe=='yes'
        if action=='snapshot' and ((hy and (r.pe=='yes' or (r.password or '')~='' or (r.pin or '')~='')) or
            (direct and (purpose=='both' or (retired and (r.pe=='yes' or r.pure_bundle))))) then
            migrating[#migrating+1]=r
        end
        if action=='status' then
            local running=false
            if enabled and direct then
                running=os.execute(script..'wg_hy_engine.sh puc-'..r.peer_id..' status >/dev/null 2>&1')==0
            elseif enabled then
                local f=io.open('/sys/class/net/'..r.iface..'/flags','r')
                if f then
                    local flags=tonumber(f:read('*l')) or 0
                    f:close()
                    if flags%2==1 then
                        local wg=assert(io.popen('/usr/bin/wg show '..r.iface..' peers 2>/dev/null'))
                        running=wg:read('*l')==r.peer_public
                        wg:close()
                    end
                end
            end
            local status={id=r.peer_id,interface=r.iface,server=r.server,server_port=r.server_port,
                site_local=r.site_local,site_remote=r.site_remote,enabled=enabled,running=running,transport=transport,purpose=purpose}
            if retired then status.retired=true elseif direct then status.purpose='access' end
            rows[#rows+1]=status
        else
            assert(peer.wgkey(r.local_public) and peer.wgkey(r.peer_public))
            owners[#owners+1]=r.iface..' '..r.local_public..' '..r.peer_public
            local source=cidr(r.allowips)
            if hy then
                if not source or source.bits~=32 then source={text='0.0.0.0/32'} end
            else
                local site=assert(plan.site_fields(r.site_local,r.site_remote))
                assert(source and source.bits==32 and #site.remote_nets==0)
            end
            if hy then guards[#guards+1]=r.iface..' '..r.local_listenport..' '..r.relay_port end
            -- Keep fences installed even if disabled, so native "up" cannot
            -- briefly expose a wildcard WG listener or unauthenticated source.
            dirs[#dirs+1]=r.iface..' '..((direct or hy) and 'pure' or purpose)..' '..source.text
            if enabled then
                enabled_devs[#enabled_devs+1]=r.iface
            end
            if enabled and direct then
                local pure=dofile(script..'wg_pure_client.lua')
                -- A damaged restored identity must revoke this exact worker.
                -- Keep the other live units and the global firewall snapshot usable.
                local valid,cfg=pcall(function()
                    local b=stored_pure(r,pure)
                    assert(pure.address_free(r.peer_id))
                    return peer.encode(pure.config(b,r.peer_id))
                end)
                pure_units[#pure_units+1]=r.iface..' '..r.peer_id..' '..(valid and 'ready' or 'conflict')
                if valid then peer.write(stage..'/pure.'..r.peer_id,cfg) end
            end
        end
    end
    -- All rows were selected through site_client_binding, under the snapshot
    -- transaction. Keep a disabled lend-only owner so its anchor can never
    -- turn into an ordinary WireGuard peer. Remove its unused reverse secrets.
    for _,r in ipairs(migrating) do
        if (r.transport or 'hysteria2')=='hysteria2' then
            insert(db,"UPDATE wireguard_peers SET enabled='no' WHERE id=?",r.peer_id)
            insert(db,"UPDATE wg_site_clients SET password='',pin='' WHERE peer_id=?",r.peer_id)
        elseif r.purpose=='lend' then
            insert(db,"UPDATE wireguard_peers SET enabled='no' WHERE id=?",r.peer_id)
            insert(db,'UPDATE wg_site_clients SET pure_bundle=NULL WHERE peer_id=?',r.peer_id)
        else
            local ok,b=pcall(stored_pure,r,dofile(script..'wg_pure_client.lua'))
            if ok then insert(db,"UPDATE wg_site_clients SET purpose='access',pure_bundle=? WHERE peer_id=?",peer.encode(b),r.peer_id) end
        end
    end
    if action=='status' then io.write('{"members":[')
        for i,r in ipairs(rows) do if i>1 then io.write(',') end; io.write(peer.encode(r)) end
        io.write(']}');return
    end
    for name,lines in pairs({guards=guards,directions=dirs,enabled=enabled_devs,owners=owners,pure_units=pure_units}) do
        peer.write(stage..'/'..name,table.concat(lines,'\n')..(#lines>0 and '\n' or ''))
    end
end
-- Only a directly requested enable operation may install a missing core.
-- If the opposite end of the local peer/interface pair is disabled, this
-- action cannot bring a relay up. The subsequent enabling action may do so.
local function enable_uses_core(db,operation,ids,include_listener)
    check(operation=='up' or operation=='iface_up',invalid)
    check(type(ids)=='string' and #ids<=1024 and ids:match('^%d[%d,]*$') and not ids:match(',$') and not ids:find(',,',1,true),invalid)
    local wanted={}
    for id in ids:gmatch('%d+') do wanted[tonumber(id)]=true end
    if include_listener then
        local file=io.open('/etc/mnt/ikuai/wg-hyr/state.json','rb')
        if file then
            local text=file:read('*a');file:close()
            local state=json.decode(text)
            if state.enabled then
                local match=operation=='up' and "w.enabled='yes' AND p.id" or "p.enabled='yes' AND w.id"
                local sql=[[SELECT p.id,p.interface,p.peer_publickey,p.exit_peer,w.id AS iface_id,w.local_publickey AS server_key
                    FROM wireguard_peers p JOIN wireguard w ON w.name=p.interface WHERE ]]..match.." IN ("..ids..")"
                for r in db:nrows(sql) do
                    local m=state.members[tostring(r.id)]
                    r.exit=r.exit_peer=='yes'
                    if m and m.transport=='pure_hy2' and m.mode=='access' and not m.paused and peer.same_identity(m,r) then
                        return 'yes'
                    end
                end
            end
        end
        for row in db:nrows("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='wg_site_clients') AS present") do
            if row.present==0 then return 'no' end
        end
    end
    local binding,transport,purpose=peer.site_client_binding(db,true)
    local sql='SELECT c.peer_id,c.iface_id,p.enabled AS pe,w.enabled AS we,'..transport..' AS carrier,'..purpose..' AS mode'
        ..binding..' AND '..transport.." IN ('hysteria2','pure_hy2')"
    local uses='no'
    for r in db:nrows(sql) do
        local selected=operation=='up' and wanted[r.peer_id] or operation=='iface_up' and wanted[r.iface_id]
        if selected then
            if r.carrier=='hysteria2' then return 'retired_wrapped' end
            if r.mode=='lend' then return 'retired' end
            if (operation=='up' and r.we=='yes') or (operation=='iface_up' and r.pe=='yes') then uses='yes' end
        end
    end
    return uses
end
local function main()
    local db=assert(sqlite.open(dbfile))
    db:busy_timeout(10000)
    if action=='retire_wrapped' then retire_wrapped(db)
    elseif action=='retired_links' then retired_links(db)
    elseif action=='enable_uses_core' or action=='enable_wait' then
        print(enable_uses_core(db,stage,arg[4],action=='enable_wait'))
    elseif action=='preflight' or action=='commit' then import(db)
    elseif action=='status' or action=='snapshot' then
        assert(db:exec('BEGIN')==sqlite.OK)
        snapshot(db)
        assert(db:exec('COMMIT')==sqlite.OK)
    else error('operation') end
    db:close()
end
local ok,err=pcall(main)
if not ok then
    print(type(err)=='table' and err.message or '导入失败，请检查本机 WG 配置后重试')
    os.exit(1)
end
