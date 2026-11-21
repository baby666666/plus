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
    check(type(b)=='table' and b.format=='nativerouting-pure-hy2-device' and b.version==1,invalid)
    check(b.purpose=='access','纯 Hysteria 2 仅支持让这台设备连接路由器上网，请从对端重新导出')
    check(require_shape(b,' format version purpose transport '),invalid)
    local t=b.transport
    check(require_shape(t,' server server_port certificate_public_key_sha256 password ') and peer.ipv4(t.server)
        and port(t.server_port) and peer.wgkey(t.certificate_public_key_sha256) and secret(t.password),invalid)
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
local function networks()
    local plan=dofile(script..'wg_address_plan.lua')
    local list,used={},{}
    local function add(net)
        if not used[net] then used[net]=true;list[#list+1]=net end
    end
    for _,r in ipairs{'0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','224.0.0.0/4','240.0.0.0/4'} do add(r) end
    local f=assert(io.popen('ip -o -4 addr show'))
    local scanned=false
    for line in f:lines() do
        local name,cidr=line:match('^%d+:%s+(%S+)%s+inet%s+(%S+)')
        local range=cidr and plan.net(cidr)
        if range then
            scanned=true
            -- Every interface's local address, including public WG addresses,
            -- is private to the router. All link-local TUNs are already fenced
            -- as a block; adding a new private TUN must not restart this core.
            local addr=cidr:match('^[^/]+')
            local cover=false
            for _,prefix in ipairs(list) do
                local prior=plan.net(prefix)
                if prior.lo<=range.host and range.host<=prior.hi then cover=true;break end
            end
            if not cover then add(addr..'/32') end
            if name:match('^lan') or name:match('^br') then add(range.text) end
        end
    end
    f:close()
    assert(scanned,'无法核对本机接口地址')
    -- A LAN may route additional public-addressed subnets behind a gateway.
    -- Include those prefixes as well as the directly attached LAN addresses.
    local routes=assert(io.popen('ip -4 route show table main'))
    for line in routes:lines() do
        local cidr,name=line:match('^(%d+%.%d+%.%d+%.%d+[/%d]*) .-dev (%S+)')
        if name and (name:match('^lan') or name:match('^br')) then
            local net=plan.net(cidr)
            if net and net.bits>0 then add(net.text) end
        end
    end
    routes:close()
    table.sort(list)
    return list
end
M.networks=networks
function M.config(b,id)
    assert(b.purpose=='access' and b.reverse==nil)
    local t=b.transport
    return {log={level='warn'},inbounds={{type='tun',tag='policy',interface_name='nph'..id,
            address={assert(M.tun_address(id))},stack='gvisor',mtu=1500,auto_route=false}},
        outbounds={{type='hysteria2',tag='via-router',server=t.server,server_port=t.server_port,password=t.password,
            routing_mark=1442840576,tls={enabled=true,server_name=t.server,certificate_public_key_sha256={t.certificate_public_key_sha256}}}},
        route={rules={{ip_version=6,action='reject'},{inbound='policy',action='route',outbound='via-router'}},final='via-router',default_mark=1442840576}}
end
return M
