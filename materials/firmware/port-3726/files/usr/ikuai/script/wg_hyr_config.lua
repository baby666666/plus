local json = require('cjson')
local sqlite = require('lsqlite3')
local peer = dofile('/usr/ikuai/script/wg_mobile_peer.lua')
local action, dbfile, statefile, stage = unpack(arg,1,4)
local check, encode = peer.check, peer.encode
local tls_dir = '/etc/mnt/ikuai/wg-hyr/tls/'

local function pure()
    return dofile('/usr/ikuai/script/wg_pure_profile.lua')
end
local function center_pin()
    local file=io.open(stage..'/pin')
    if not file then
        file=assert(io.popen('openssl x509 -in '..tls_dir..'cert.pem -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -binary | openssl enc -base64 -A'))
    end
    local pin=file:read('*a'):match('^([A-Za-z0-9+/]+=)%s*$'); file:close()
    assert(pin and #pin==44 and pin~='47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=')
    return pin
end
local function leaf_fingerprint()
    local f=io.popen('openssl x509 -in '..tls_dir..'cert.pem -noout -fingerprint -sha256 2>/dev/null')
    local line=f and f:read('*l')
    if f then f:close() end
    local hex=line and line:lower():match('^sha256 fingerprint=(%x%x'..string.rep(':%x%x',31)..')$')
    check(hex,'Hysteria 2 证书不可用')
    return (hex:gsub(':',''))
end
local function valid_name(s)
    return type(s)=='string' and #s<=48 and s:match('^[A-Za-z0-9][A-Za-z0-9._%-]*$')
end

local function credentials()
    local random=assert(io.open('/dev/urandom','rb'))
    local bytes=random:read(48)
    random:close()
    assert(bytes and #bytes==48)
    local hex=bytes:gsub('.',function(c) return string.format('%02x',c:byte()) end)
    local id=table.concat({hex:sub(1,8),hex:sub(9,12),'4'..hex:sub(14,16),
        string.format('%x',8+bytes:byte(9)%4)..hex:sub(18,20),hex:sub(21,32)},'-')
    return id,hex:sub(33)
end

local function wg_listen_port(port)
    local db=assert(sqlite.open(dbfile))
    db:busy_timeout(10000)
    local function exists(sql,value)
        local stmt=assert(db:prepare(sql))
        stmt:bind_values(value)
        local rc=stmt:step()
        assert(rc==sqlite.ROW or rc==sqlite.DONE)
        stmt:finalize()
        return rc==sqlite.ROW
    end
    local used=exists('SELECT 1 FROM wireguard WHERE CAST(local_listenport AS INTEGER)=?1 LIMIT 1',port)
        or (exists("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",'wg_site_clients')
            and exists('SELECT 1 FROM wg_site_clients WHERE relay_port=?1 LIMIT 1',port))
    db:close()
    return used
end

local function settings(ip, port)
    check(peer.ipv4(ip),'请填写可达的入口 IPv4')
    local n=peer.number(port,1,65535)
    check(n and tostring(n)==tostring(port),'UDP 端口范围为 1 至 65535')
    return {public_ip=ip,udp_port=n}
end

local retired_message='Hysteria 2 承载 WG 已停用，请选择原生 WG 或纯 HY2'
local function wrapped(m) return m and m.transport~='pure_hy2' end
local function same_binding(m,r)
    if wrapped(m) then
        return r and m.interface==r.interface and m.iface_id==r.iface_id
            and m.server_key==r.server_key and m.peer_key==r.peer_publickey
    end
    return m and peer.same_identity(m,r) and m.port==r.port and m.address==r.address
        and ((m.mode~='site' and not r.site) or (m.mode=='site' and r.site
            and m.local_address==r.local_address and m.site_local==table.concat(r.site.local_nets,',')
            and m.site_remote==table.concat(r.site.remote_nets,',')))
end

local function member_mode(m)
    local mode=m.mode or 'both' -- RC4 registrations carry both directions.
    assert(mode=='lend' or mode=='access' or mode=='both' or mode=='site')
    if m.transport=='pure_hy2' and mode=='both' then return 'access' end
    return mode
end

-- Ordinary/site/disabled native peers may not qualify for HY. Return the
-- selected saved row even then, to detect a reused numeric id in an old tab.
local function editor_peer(id)
    local db=assert(sqlite.open(dbfile))
    db:busy_timeout(10000)
    local stmt=assert(db:prepare([[SELECT id,interface,peer_publickey,allowips,
        coalesce(native_role,'') AS native_role,coalesce(site_local,'') AS site_local,coalesce(site_remote,'') AS site_remote,
        CASE WHEN exit_peer='yes' THEN 'yes' ELSE 'no' END AS exit_peer
        FROM wireguard_peers WHERE id=?1]]))
    stmt:bind_values(id)
    local result=stmt:step()
    assert(result==sqlite.ROW or result==sqlite.DONE)
    local row=result==sqlite.ROW and stmt:get_named_values() or json.null
    stmt:finalize(); db:close()
    return row
end

local function status(state,list,requested)
    local s=state.settings or {public_ip='',udp_port=8443}
    local live=action=='status'
    local out={enabled=state.enabled,public_ip=s.public_ip,udp_port=s.udp_port,members={}}
    local location=os.getenv('HY_CORE_LOCATION')
    if location=='compact' then
        out.core_storage='disk'; out.core_format='squashfs'
    elseif location=='plain' or location=='disk' then
        out.core_storage='disk'
    elseif location=='memory' then
        out.core_storage='memory'
    elseif location=='none' or location=='absent' then
        out.core_storage='none'
    end
    if live then
        out.installed=arg[5]=='yes';out.running=arg[6]=='yes';out.peers={}
    elseif requested then
        out.peer=editor_peer(requested)
    end
    for _,r in ipairs(list) do
        local m=state.members[tostring(r.id)]
        if live and r.active and not wrapped(m) then out.peers[#out.peers+1]=peer.metadata(r) end
        if same_binding(m,r) then
            local row=peer.metadata(r)
            row.name=m.name; row.id=m.id; row.mode=member_mode(m)
            if m.transport=='pure_hy2' then
                row.transport=m.transport;row.exit=false
                if row.mode=='lend' then row.retired=true;row.active=false end
            else
                row.transport='hysteria2';row.retired=true;row.active=false
            end
            row.peer_publickey=r.peer_publickey
            row.paused=row.retired==true or not state.enabled or m.paused==true
            row.port_mode=m.port_mode or 'shared'
            row.addr_mode=m.addr_mode or 'shared'
            row.public_ip=m.public_ip or s.public_ip
            if live then
                local ready=io.open(stage..'/ready.'..r.id,'r')
                row.running=ready~=nil and not row.retired
                if ready then ready:close() end
            end
            row.public_port=row.port_mode=='wg' and r.port or s.udp_port
            out.members[#out.members+1]=row
        end
    end
    io.write((encode(out):gsub('"peers":{}','"peers":[]'):gsub('"members":{}','"members":[]')))
end

local function port_mode(m)
    return m.port_mode or 'shared' -- RC7 and earlier expose the saved shared listener.
end

-- Select a free persistent backend port outside the normal ephemeral range.
-- Both IPv4 and IPv6 wildcard binds can occupy the same local UDP number.
local function reserved_ports(state)
    local reserved={}
    for _,m in pairs(state.members) do
        if not wrapped(m) then
            reserved[m.port]=true
            if m.inner_port then reserved[m.inner_port]=true end
        end
    end
    for _,p in ipairs({'/proc/net/udp','/proc/net/udp6'}) do
        local f=io.open(p,'r')
        if f then
            for line in f:lines() do
                local hex=line:match('^%s*%d+:%s+%x+:(%x+)')
                if hex then reserved[tonumber(hex,16)]=true end
            end
            f:close()
        end
    end
    return reserved
end

local function free_port(state,preferred)
    local reserved=reserved_ports(state)
    if preferred and not reserved[preferred] and not wg_listen_port(preferred) then return preferred end
    for n=21000,32000 do
        if not reserved[n] and not wg_listen_port(n) then return n end
    end
    check(false,'找不到可用的本机 UDP 端口')
end

local function enroll(state,r,name,mode,portmode,inner,transport,retired)
    assert(state.settings)
    check(transport=='pure_hy2',retired_message)
    check(mode=='access' and r and (r.active or retired) and r.dedicated and not r.site and not r.exit and portmode=='wg',
              '纯 HY2 只支持让这台设备连接路由器上网')
    local key=tostring(r.id)
    check(not state.members[key],'此 WG 对端已登记')
    local count,names=0,{}
    for id,m in pairs(state.members) do
        names[m.name]=true
        check(m.peer_key~=r.peer_publickey and m.address~=r.address,'WG 地址或密钥已登记')
        count=count+1
    end
    check(count<256,'最多支持 256 台 Hysteria 2 设备')
    -- A manually named peer in an old registry may already own the default.
    if not name then
        local base='wg-peer-'..key
        name=base
        local suffix=1
        while names[name] do
            name=base..'-'..suffix
            suffix=suffix+1
        end
    end
    assert(valid_name(name) and not names[name])
    local id,password=credentials()
    state.members[key]={id=id,name=name,password=password,interface=r.interface,iface_id=r.iface_id,
        server_key=r.server_key,peer_key=r.peer_publickey,exit=r.exit,address=r.address,port=r.port,mode=mode,port_mode=portmode,
        local_address=r.site and r.local_address or nil,site_local=r.site and table.concat(r.site.local_nets,',') or nil,
        site_remote=r.site and table.concat(r.site.remote_nets,',') or nil,
        inner_port=portmode=='wg' and (inner or free_port(state)) or nil}
    state.members[key].transport=transport
end

local function router_wireguard(r,mtu)
    local server=peer.ipv4((r.local_address or ''):match('^[^/]+'))
    check(server and server..'/32'~=r.address,'已保存的 WG 地址或端口无效，请保存并刷新后重试')
    -- A device-purpose bundle routes only the other WG host until the
    -- administrator selects the tunnel for Internet traffic on that router.
    local wg={address=r.site and r.site.client_address or r.address,peer_address=server..'/32',
        private_key=r.private_key,public_key=r.server_key,mtu=mtu,keepalive=r.keep}
    if r.psk and r.psk~='' and r.psk~=peer.zero then wg.preshared_key=r.psk end
    return wg
end

local function native_profile(state,id)
    check(id and state.members[tostring(id)]==nil,'设备隧道已变化，请刷新后重试')
    local rows=peer.get_rows(dbfile,id,'native')
    local r=rows[tostring(id)]
    check(r and r.active and r.interface==arg[7] and r.peer_publickey==arg[8] and r.server_key==arg[9],
        '设备隧道已变化，请刷新后重试')
    local mode=r.native_role
    check((mode=='access' or mode=='lend' or mode=='both') and mode==arg[6] and (mode=='access')==(not r.exit),
        '导出类型与已保存的隧道用途不匹配')
    peer.validated_peer(stage,r,false)
    check(mode~='lend' or r.keep>0,'借用设备网络需要非零 WG 心跳，可设置为 25 秒')
    local endpoint=r.client_endpoint
    if not endpoint or endpoint=='' then
        -- get_rows verifies the interface is a native wgN name before this call.
        local f=assert(io.popen('/usr/ikuai/script/wg_client_endpoint.sh get_public '..r.interface..' 2>/dev/null'))
        endpoint=f:read('*l');f:close()
        check(peer.ipv4(endpoint),'未能检测到此 WG 接口的公网 IPv4，请手动填写可从外网访问的地址')
    end
    local plan=dofile('/usr/ikuai/script/wg_address_plan.lua')
    local ok,err=plan.client_endpoint(endpoint)
    check(ok,err)
    local host,port=endpoint:match('^([^:]+):(%d+)$')
    host=host or endpoint
    check(not host:match('^[%d.]+$') or peer.ipv4(host),'已保存的 WG 地址或端口无效，请保存并刷新后重试')
    local mtu=peer.number(r.mtu~='' and r.mtu or 1420,576,9000)
    check(mtu,'MTU 无效')
    local wg=router_wireguard(r,mtu)
    check(host..'/32'~=wg.address and host..'/32'~=wg.peer_address,'WG 入口地址与隧道路由冲突')
    return {format='nativerouting-wg-device',version=2,purpose=mode,wireguard=wg,
        transport={server=host,server_port=tonumber(port) or r.port}}
end

local function profile(state,m,r)
    local mode=member_mode(m)
    check(m.transport=='pure_hy2',retired_message)
    check(mode=='access','纯 HY2 借线已停用，请重新选择设备连接方式')
    check(r and r.active and r.dedicated,'请选择已启用的纯 HY2 隧道')
    local ip=m.public_ip or state.settings.public_ip
    if action=='uri' then
        check(state.enabled and not m.paused,'请选择已启用的纯 HY2 隧道')
        check(peer.ipv4(ip),'请填写可达的入口 IPv4')
        return pure().uri(m,ip,leaf_fingerprint())
    end
    local pin=center_pin()
    if action=='site_profile' then return pure().bundle(m,ip,pin) end
    return pure().phone(m,ip,pin)
end

-- The native guard matches decrypted WireGuard traffic. Persist its direction
-- even when only the public Hysteria listener is switched off.
local function stage_directions(state,list)
    local lines={}
    for _,r in ipairs(list) do
        local m=state.members[tostring(r.id)]
        if m and (r.active or wrapped(m)) then
            local fields={r.interface,'hold',r.address}
            lines[#lines+1]=table.concat(fields,' ')..'\n'
        end
    end
    peer.write(stage..'/directions',table.concat(lines))
end

local function check_registration(m,expected)
    check(type(expected)=='string' and ((not m and expected=='') or (m and m.id==expected)),
          '设备隧道已变化，请刷新后重试')
end

local function stage_pure(state,list)
    local rows,placements,addresses={}, {}, nil
    for _,r in ipairs(list) do
        local m=state.members[tostring(r.id)]
        if m and m.transport=='pure_hy2' and r.active and not m.paused then
            -- Even a retired lending-only registration keeps its native WG
            -- anchor isolated; it never gains a public proxy or native peer.
            placements[#placements+1]=table.concat({r.interface,m.port,m.inner_port,r.server_key},' ')
            if member_mode(m)=='access' then
                addresses=addresses or dofile('/usr/ikuai/script/wg_pure_client.lua').networks()
                local ip=m.public_ip or state.settings.public_ip
                peer.write(stage..'/pure.'..r.id,encode(pure().center(m,ip,addresses))..'\n')
                rows[#rows+1]=table.concat({r.interface,r.id,m.port,m.inner_port},' ')
            end
        end
    end
    if #rows>0 then peer.write(stage..'/pure-bindings',table.concat(rows,'\n')..'\n') end
    if #placements>0 then
        local f=assert(io.open(stage..'/placements','a'))
        assert(f:write(table.concat(placements,'\n')..'\n'));assert(f:close())
    end
end

local function main()
    local state=statefile=='-' and {version=1,enabled=false,members={}} or json.decode(peer.read(statefile))
    assert(state.version==1 and type(state.members)=='table' and type(state.enabled)=='boolean')
    if state.settings then settings(state.settings.public_ip,state.settings.udp_port) end
    assert(not state.enabled or state.settings)
    if action=='retire_wrapped' then
        local db
        for id,m in pairs(state.members) do
            if wrapped(m) then
                if not db then
                    db=assert(sqlite.open(dbfile))
                    db:busy_timeout(10000)
                    assert(db:exec('BEGIN IMMEDIATE')==sqlite.OK)
                end
                local bound,enabled=peer.wrapped_identity(db,id,m)
                if bound and enabled=='yes' then
                    local stmt=assert(db:prepare("UPDATE wireguard_peers SET enabled='no' WHERE id=?"))
                    stmt:bind_values(tonumber(id))
                    assert(stmt:step()==sqlite.DONE);stmt:finalize()
                end
            end
        end
        if db then assert(db:exec('COMMIT')==sqlite.OK);db:close() end
        return
    end
    if action=='check_enable' then
        local op,ids=arg[5],arg[6]
        assert((op=='up' or op=='iface_up') and type(ids)=='string' and ids:match('^[%d,]+$'))
        local selected={}
        for n in ids:gmatch('[^,]+') do selected[assert(tonumber(n))]=true end
        local rows
        for id,m in pairs(state.members) do
            if wrapped(m) and selected[op=='up' and tonumber(id) or m.iface_id] then
                local db=assert(sqlite.open(dbfile))
                local bound=peer.wrapped_identity(db,id,m)
                db:close()
                check(not bound,retired_message)
            elseif m.transport=='pure_hy2' and m.mode=='lend' and selected[op=='up' and tonumber(id) or m.iface_id] then
                rows=rows or peer.get_rows(dbfile,nil,'hysteria2')
                check(not same_binding(m,rows[id]),'纯 HY2 借线已停用，请重新选择设备连接方式')
            end
        end
        return
    end
    local requested=peer.valid_id(arg[5])
    if action=='native_profile' then io.write(encode(native_profile(state,requested)));return end
    if action=='settings' then
        assert(not arg[5] or arg[5]=='' or requested)
        local list={}
        if next(state.members) then
            list=select(2,peer.get_rows(dbfile,nil,'hysteria2'))
        end
        status(state,list,requested);return
    end
    local export=action=='profile' or action=='site_profile' or action=='uri'
    local secret=action=='profile' or action=='site_profile' or action=='set_mode'
    local rows,list=peer.get_rows(dbfile,secret and requested,'hysteria2')
    if action=='status' then status(state,list); return end
    local key=tostring(requested)
    local previous=state.members[key]
    if action=='check_mode' then
        check(requested,'对端编号无效')
        check_registration(previous,arg[6])
        check(not previous or same_binding(previous,rows[key]),'设备隧道已变化，请刷新后重试')
        return
    end
    -- An observed loss of identity, exclusive port, or exit role invalidates the
    -- registration on sync. A replacement must explicitly obtain a new login.
    local registry_db
    for id,m in pairs(state.members) do
        if wrapped(m) then
            registry_db=registry_db or assert(sqlite.open(dbfile))
            if peer.wrapped_identity(registry_db,id,m) then
                m.password=nil
            else state.members[id]=nil end
        elseif not same_binding(m,rows[id]) then
            state.members[id]=nil
        elseif m.transport=='pure_hy2' then
            -- The saved mode and exit flag identify the exact RC15 peer.
            -- Dropping the registration would expose its underlying WG path.
            m.realm_token=nil;m.reverse_password=nil;m.reverse_key=nil
            m.reverse_cert=nil;m.reverse_pin=nil;m.stun_port=nil
            if m.mode=='lend' then m.password=nil end
        end
    end
    if registry_db then registry_db:close() end
    if action=='set_mode' then
        check(requested,'对端编号无效')
        local mode,expected=arg[6],arg[7]
        local resume=arg[12] or ''
        check(resume=='' or (resume=='yes' and previous and mode~='off'),'设备隧道已变化，请刷新后重试')
        check_registration(previous,expected)
        if mode=='off' then
            state.members[key]=nil
        else
            check(arg[13]=='pure_hy2',retired_message)
            if not state.settings then
                check(arg[8] and arg[8]~='','请填写可达的入口 IPv4')
                state.settings=settings(arg[8],8443)
            end
            -- Older registries paused every listener with one switch. When one
            -- device is enabled, preserve the pause on all other credentials.
            if not state.enabled and (not previous or wrapped(previous) or resume=='yes') then
                for _,saved in pairs(state.members) do saved.paused=true end
                state.enabled=true
            end
            local row=rows[key]
            local transport=arg[13]
            local pm=arg[10]
            if not pm or pm=='' then pm='wg' end
            check(pm=='wg' and mode=='access','纯 HY2 只支持让这台设备连接路由器上网')
            if state.members[key] and previous.transport==transport and member_mode(previous)==mode then
                check(row and row.active and row.dedicated,'请选择已启用的纯 HY2 隧道')
            else
                state.members[key]=nil
                enroll(state,row,previous and previous.name,mode,pm,previous and not wrapped(previous) and previous.inner_port,transport,
                    previous and (wrapped(previous) or previous.mode=='lend'))
            end
            local m=state.members[key]
            m.paused=previous and not wrapped(previous) and previous.paused and resume~='yes' or nil
            local am=arg[11]
            if not am or am=='' then am=(previous and previous.addr_mode) or 'shared' end
            check(am=='shared' or am=='manual' or am=='auto','公网地址方式无效')
            local ip
            if am~='shared' then
                ip=(arg[8] and arg[8]~='' and arg[8]) or (previous and previous.public_ip)
                check(peer.ipv4(ip),'请填写可达的入口 IPv4')
            end
            if m==previous and ((m.addr_mode or 'shared')~=am or m.public_ip~=ip) then
                m.id=credentials()
            end
            m.addr_mode=am; m.public_ip=ip
        end
    elseif export then
        local m=state.members[key]
        check(m and m.id==arg[6],'设备隧道已变化，请刷新后重试')
        check(not wrapped(m),retired_message)
        local router=action=='site_profile'
        local mode=member_mode(m)
        local role=arg[7] or ''
        check((router or mode~='site') and (role==mode or (role=='' and action~='uri')),
            '导出类型与已保存的隧道用途不匹配')
        io.write(encode(profile(state,m,rows[key])))
        return
    else
        assert(action=='sync' or action=='inspect')
    end
    stage_directions(state,list)
    if state.enabled then stage_pure(state,list) end
    peer.write(stage..'/next',encode(state)..'\n')
end

local ok,err=pcall(main)
if not ok then
    print(type(err)=='table' and err.message or '读取或生成 Hysteria 2 配置失败')
    os.exit(1)
end
