-- Shared native WireGuard inventory, key validation and transport-independent phone profile.
local json = require('cjson')
local sqlite = require('lsqlite3')
local plan
local function fail(message) error({message=message}, 0) end
local function require_ok(value, message)
    if not value then fail(message) end
    return value
end
local function read(path)
    local f = assert(io.open(path,'rb'))
    local data = f:read(4194305) or ''
    f:close()
    assert(#data < 4194305)
    return data
end
local function write(path, text)
    local f = assert(io.open(path,'wb'))
    assert(f:write(text)); assert(f:close())
end
-- Native Lua hash iteration does not define object field order. Stable bytes allow
-- the supervisor to keep existing sessions when an unrelated WG peer is edited.
local function encode(value)
    if type(value)~='table' then return json.encode(value) end
    local fields={}
    if value[1]~=nil then
        for i,v in ipairs(value) do fields[i]=encode(v) end
        return '['..table.concat(fields,',')..']'
    end
    local keys={}
    for key in pairs(value) do keys[#keys+1]=key end
    table.sort(keys)
    for i,key in ipairs(keys) do fields[i]=json.encode(key)..':'..encode(value[key]) end
    return '{'..table.concat(fields,',')..'}'
end
local function ipv4(s)
    if type(s) ~= 'string' then return nil end
    local a,b,c,d = s:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
    if not a then return nil end
    a,b,c,d=tonumber(a),tonumber(b),tonumber(c),tonumber(d)
    if a==0 or a==127 or a>=224 or b>255 or c>255 or d>255 or (a==169 and b==254) then return nil end
    return s==table.concat({a,b,c,d},'.') and s or nil
end
local function number(s, min, max)
    local n=tonumber(s)
    return n and n==math.floor(n) and n>=min and n<=max and n or nil
end
local function wgkey(s)
    return type(s)=='string' and #s==44 and s:match('^[A-Za-z0-9/+]+[AEIMQUYcgkosw048]=$') and s~=string.rep('A',43)..'='
end
local zero = string.rep('A',43)..'='
local function valid_id(s)
    return type(s)=='string' and #s<=10 and s:match('^[1-9]%d*$') and tonumber(s) or nil
end
local function site_scope(r,include_sites)
    if (r.site_local or '')=='' and (r.site_remote or '')=='' then return false end
    if not include_sites then return nil end
    plan=plan or dofile('/usr/ikuai/script/wg_address_plan.lua')
    local s=plan.site_fields(r.site_local,r.site_remote)
    if not s then return nil end
    if #s.local_nets==0 then return false end
    local server=plan.net(r.local_address)
    local client=plan.net(r.allowips)
    local host=(r.local_address or ''):match('^[^/]+')
    if not server or not ipv4(host) or not client or client.bits~=32 or server.host==client.host then return nil end
    -- Use a host prefix for point-to-point addresses outside the server subnet.
    local bits=32
    if client.host>=server.lo and client.host<=server.hi then
        if server.bits<31 and (client.host==server.lo or client.host==server.hi) then return nil end
        bits=server.bits
    end
    local function networks(list)
        local out={}
        for i,net in ipairs(list) do out[i]=net.text end
        table.sort(out)
        return out
    end
    return {local_nets=networks(s.local_nets),remote_nets=networks(s.remote_nets),
            client_address=client.text:gsub('/32$','')..'/'..bits}
end
local function get_rows(dbfile, secret_id, source)
    local native=source=='native'
    assert(source=='hysteria2' or source=='retired' or (native and secret_id))
    local extra=native and 'p.native_role,p.client_endpoint,w.mtu,' or ''
    local db=assert(sqlite.open(dbfile))
    db:busy_timeout(10000)
    local sql=[[SELECT p.id,p.interface,p.allowips,p.enabled,p.exit_peer,p.keepalive,
        p.peer_publickey,p.client_dns,p.site_local,p.site_remote,]]..extra..[[
        CASE WHEN p.id=?1 THEN p.peer_privatekey END AS private_key,
        CASE WHEN p.id=?1 THEN p.presharedkey END AS psk,
        CASE WHEN p.id=?1 THEN w.local_privatekey END AS server_private,
        w.id AS iface_id,w.enabled AS iface_enabled,w.local_publickey AS server_key,
        w.local_listenport AS port,w.local_address,
        (SELECT count(*) FROM wireguard_peers s WHERE s.interface=p.interface) AS siblings,
        (SELECT count(*) FROM wireguard other WHERE
          CAST(other.local_listenport AS INTEGER)=CAST(w.local_listenport AS INTEGER)) AS owners
        FROM wireguard_peers p JOIN wireguard w ON p.interface=w.name]]
    if native then sql=sql..' WHERE p.id=?1' end
    local stmt=assert(db:prepare(sql..' ORDER BY p.id'))
    stmt:bind_values(secret_id or 0)
    local by_id, list={},{}
    local rc=stmt:step()
    while rc==sqlite.ROW do
        local r=stmt:get_named_values()
        local host=(r.allowips or ''):gsub('/32$','')
        local reverse=r.exit_peer=='yes'
        -- Even disabled interfaces and peers reserve their ports and interfaces.
        r.dedicated=tonumber(r.siblings)==1 and tonumber(r.owners)==1
        r.site=site_scope(r,source=='hysteria2')
        if (not r.exit_peer or r.exit_peer=='' or r.exit_peer=='no' or reverse) and ipv4(host) and r.site~=nil and
           wgkey(r.peer_publickey) and wgkey(r.server_key) and (r.interface or ''):match('^wg%d+$') and
           number(r.port,1,65535) and (native or r.dedicated) and (not reverse or tonumber(r.siblings)==1) then
            r.id=tonumber(r.id); r.port=tonumber(r.port); r.exit=reverse
            r.active=r.enabled=='yes' and r.iface_enabled=='yes'
            r.address=host..'/32'; by_id[tostring(r.id)]=r; list[#list+1]=r
        end
        rc=stmt:step()
    end
    assert(rc==sqlite.DONE)
    stmt:finalize(); db:close()
    return by_id,list
end
local function metadata(r)
    return {peer_id=r.id,interface=r.interface,port=r.port,address=r.address,exit=r.exit,active=r.active}
end
local function same_identity(m,r)
    return r and m.interface==r.interface and m.iface_id==r.iface_id and m.server_key==r.server_key
       and m.peer_key==r.peer_publickey and m.exit==r.exit
end
-- A retired transport remains owned across changes to addresses, roles or ports.
-- Reused numeric IDs with different keys belong to the replacement peer.
local function wrapped_identity(db,id,m)
    local stmt=assert(db:prepare([[SELECT p.enabled FROM wireguard_peers p
        JOIN wireguard w ON w.name=p.interface WHERE p.id=? AND w.id=?
        AND p.interface=? AND w.local_publickey=? AND p.peer_publickey=?]]))
    stmt:bind_values(assert(valid_id(id)),m.iface_id,m.interface,m.server_key,m.peer_key)
    local rc=stmt:step()
    assert(rc==sqlite.ROW or rc==sqlite.DONE)
    local enabled=rc==sqlite.ROW and stmt:get_named_values().enabled
    stmt:finalize()
    return rc==sqlite.ROW,enabled
end
local function verify_key(stage, private, public)
    require_ok(wgkey(private) and wgkey(public),'爱快对端或接口缺少有效密钥')
    write(stage..'/key',private..'\n')
    -- stage is a mktemp-created directory below a fixed system path.
    local ok=os.execute("/usr/bin/wg pubkey < '"..stage.."/key' > '"..stage.."/pub' 2>/dev/null")
    os.remove(stage..'/key')
    require_ok(ok==0 and read(stage..'/pub'):match('^(%S+)')==public,'已保存的 WG 公私钥不匹配')
end
local function validated_peer(stage, row, phone_dns)
    require_ok(row and row.active,'请选择已保存并启用的有效 WG 对端')
    verify_key(stage,row.private_key,row.peer_publickey); verify_key(stage,row.server_private,row.server_key)
    require_ok(not row.psk or row.psk=='' or row.psk==zero or wgkey(row.psk),'预共享密钥无效')
    local dns=(row.client_dns or ''):match('^%s*([^,%s]+)') or (row.local_address or ''):match('^[^/]+')
    if not row.site and phone_dns~=false then row.dns=require_ok(ipv4(dns),'请为此对端设置可通过 WG 访问的 IPv4 DNS') end
    row.keep=require_ok(number(row.keepalive~='' and row.keepalive or 0,0,65535),'已保存的心跳间隔无效')
    return row
end
local function site_client_binding(db,retire_wrapped)
    local has_transport=false
    for col in db:nrows('PRAGMA table_info(wg_site_clients)') do
        if col.name=='transport' then has_transport=true end
    end
    -- RC12 stored only HY2 site bundles, with neither transport nor purpose
    -- columns. Reading their binding must never require a migration/write.
    local transport=has_transport and 'c.transport' or "'hysteria2'"
    local purpose=has_transport and 'c.purpose' or "'site'"
    local identity=[[ FROM wg_site_clients c JOIN wireguard w ON w.id=c.iface_id AND w.name=c.iface AND w.local_publickey=c.local_public
        JOIN wireguard_peers p ON p.id=c.peer_id AND p.interface=w.name AND p.peer_publickey=c.peer_public
    ]]
    local strict=[[p.native_role='site_client' AND (SELECT COUNT(*) FROM wireguard_peers s WHERE s.interface=w.name)=1
        AND ((TRANSPORT='hysteria2' AND p.endpoint='127.0.0.1' AND p.endpoint_port=c.relay_port)
          OR (TRANSPORT='native' AND p.endpoint=c.server AND p.endpoint_port=c.server_port)
          OR (TRANSPORT='pure_hy2' AND p.endpoint='' AND ifnull(p.endpoint_port,0)=0))
        AND ((PURPOSE='site' AND TRANSPORT='hysteria2' AND p.exit_peer='yes' AND p.site_local<>'' AND p.site_remote<>'')
          OR (PURPOSE IN ('access','both','lend') AND p.site_local='' AND p.site_remote=''
              AND p.exit_peer=CASE WHEN PURPOSE='lend' THEN 'no' ELSE 'yes' END))]]
    -- Retirement needs matching keys/IDs even if a partial restore changed
    -- an endpoint or a role. These looser matches may only grant a deny rule.
    local sql=identity..' WHERE ('..(retire_wrapped and "TRANSPORT='hysteria2' OR " or '')..strict..')'
    return (sql:gsub('TRANSPORT',transport):gsub('PURPOSE',purpose)),transport,purpose
end

-- RC21 must see a paused registry when its original services run before the
-- plugin boot hook. Only the routed controller reads the effective enable bit.
local function routed_enabled(state)
    require_ok(type(state)=='table' and type(state.enabled)=='boolean','纯 HY2 登记状态无效')
    if state.routed_enabled==nil then return state.enabled end
    require_ok(type(state.routed_enabled)=='boolean' and state.enabled==false,'纯 HY2 分流保护状态无效')
    return state.routed_enabled
end

return {routed_enabled=routed_enabled,wrapped_identity=wrapped_identity,site_client_binding=site_client_binding,read=read,write=write,encode=encode,check=require_ok,ipv4=ipv4,number=number,valid_id=valid_id,
        get_rows=get_rows,metadata=metadata,same_identity=same_identity,validated_peer=validated_peer,
        zero=zero,wgkey=wgkey}
