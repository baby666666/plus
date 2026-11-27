-- A pure device bundle carries credentials, never executable sing-box rules.
-- Both sides use the local peer row ID to give the TUN an independent /32.
local M={}
local script='/usr/ikuai/script/'
local function require_shape(value,keys)
    if type(value)~='table' then return false end
    for key in pairs(value) do
        if type(key)~='string' or not keys:find(' '..key..' ',1,true) then return false end
    end
    return true
end
local function secret(v)
    return type(v)=='string' and #v==64 and v:match('^[a-f0-9]+$')
end
local function port(v)
    return type(v)=='number' and math.floor(v)==v and v>0 and v<=65535
end
-- New bundles may only ask the branch to use the public router's Internet.
-- Older bidirectional bundles are narrowed by the saved-row migration.
function M.validate(b,peer)
    local invalid='纯 Hysteria 2 设备配置无效'
    local check=peer.check
    check(type(b)=='table' and b.format=='nativerouting-pure-hy2-device' and (b.version==1 or b.version==2),invalid)
    check(b.purpose=='access','纯 Hysteria 2 仅支持让这台设备连接路由器上网，请从对端重新导出')
    check(require_shape(b,b.version==1 and ' format version purpose transport ' or ' format version purpose transport reverse '),invalid)
    local t=b.transport
    check(require_shape(t,' server server_port certificate_public_key_sha256 password ') and peer.ipv4(t.server)
        and port(t.server_port) and peer.wgkey(t.certificate_public_key_sha256) and secret(t.password),invalid)
    if b.version==2 then
        b.reverse=dofile(script..'wg_reverse_config.lua').import(b.reverse,t.server)
    end
    return b
end
function M.tun_address(id)
    id=tonumber(id)
    if not id or math.floor(id)~=id or id<1 or id>64516 then return nil end
    return '169.254.'..(1+math.floor((id-1)/254))..'.'..(1+(id-1)%254)..'/32'
end
-- A connected subnet assigned to another live interface cannot supply our
-- private TUN source. Check at activation and recovery, not just at import.
function M.address_free(id)
    local address=M.tun_address(id)
    if not address then return false end
    local plan=dofile(script..'wg_address_plan.lua')
    local wanted=plan.net(address)
    local f=assert(io.popen('ip -o -4 addr show'))
    local free=true
    for line in f:lines() do
        local iface,cidr=line:match('^%d+:%s+(%S+)%s+inet%s+(%S+)')
        if iface and iface:gsub('@.*','')~='nph'..id then
            local net=plan.net(cidr)
            if net and wanted.host>=net.lo and wanted.host<=net.hi then free=false end
        end
    end
    f:close()
    return free
end
-- Router-owned addresses are protected separately from forwarded destinations.
-- A connected or static prefix is not itself a local address. Its forwarding
-- decision belongs to the native routing tables and firewall.
function M.local_addresses()
    local plan=dofile(script..'wg_address_plan.lua')
    local addresses,seen={},{}
    local scan=assert(io.popen('ip -o -4 addr show'))
    local inspected=false
    for line in scan:lines() do
        local cidr=line:match('^%d+:%s+%S+%s+inet%s+(%S+)')
        if cidr and plan.net(cidr) then
            inspected=true
            local host=cidr:match('^[^/]+')
            -- Both entire ranges are already denied, including ephemeral native DNS bindings.
            if not host:match('^169%.254%.') and not host:match('^127%.') and not seen[host] then
                addresses[#addresses+1]=host..'/32'
                seen[host]=true
            end
        end
    end
    scan:close()
    assert(inspected,'无法核对本机接口地址')
    table.sort(addresses)
    return addresses
end
function M.config(b,id)
    assert(b.purpose=='access')
    local t=b.transport
    local config={log={level='warn'},inbounds={{type='tun',tag='policy',interface_name='nph'..id,
            address={assert(M.tun_address(id))},stack='gvisor',mtu=1500,auto_route=false}},
        outbounds={{type='hysteria2',tag='via-router',server=t.server,server_port=t.server_port,password=t.password,
            routing_mark=1442840576,tls={enabled=true,server_name=t.server,certificate_public_key_sha256={t.certificate_public_key_sha256}}}},
        route={rules={{ip_version=6,action='reject'},{inbound='policy',action='route',outbound='via-router'}},final='via-router',default_mark=1442840576}}
    if b.reverse then
        assert(b.version==2)
        local reverse=dofile(script..'wg_reverse_config.lua')
        reverse.import(b.reverse,t.server)
        config.inbounds[#config.inbounds+1]={type='socks',tag='reverse-control',
            listen=reverse.socks_address(id),listen_port=1080}
        config.route.rules[#config.route.rules+1]={inbound='reverse-control',action='route',outbound='via-router'}
    end
    return config
end
return M
