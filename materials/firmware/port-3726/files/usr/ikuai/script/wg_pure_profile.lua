-- NativeRouting pure HY2. The native WG row identifies the UI entry only.
local M={}
local function tls_client(name,pin)
    return {enabled=true,server_name=name,certificate_public_key_sha256={pin}}
end
local server_tls={enabled=true,certificate_path='/etc/mnt/ikuai/wg-hyr/tls/cert.pem',
    key_path='/etc/mnt/ikuai/wg-hyr/tls/key.pem'}
local function ipv4_rules(extra,native_forwarding)
    local networks={'0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16',
        '172.16.0.0/12','192.168.0.0/16','224.0.0.0/4','240.0.0.0/4'}
    if native_forwarding then networks={'0.0.0.0/8','127.0.0.0/8','169.254.0.0/16','224.0.0.0/4','240.0.0.0/4'} end
    local seen={};for _,net in ipairs(networks) do seen[net]=true end
    for _,net in ipairs(extra) do if not seen[net] then networks[#networks+1]=net;seen[net]=true end end
    return {{action='resolve',strategy='ipv4_only'},{ip_version=6,action='reject'},
        {ip_cidr=networks,action='reject'}}
end
local function base(extra,native_forwarding)
    return {log={level='warn'},dns={servers={{type='local',tag='local'}}},
        inbounds={},outbounds={{type='direct',tag='internet'}},
        route={default_domain_resolver='local',rules=ipv4_rules(extra,native_forwarding),final='internet'}}
end
local function carrier(m,ip,pin)
    return {type='hysteria2',tag='to-router',server=ip,server_port=m.port,password=m.password,
        tls=tls_client(ip,pin)}
end

-- RC15 'both' already granted access with this password. Its obsolete
-- reverse identity never enters the worker config or an exported profile.
local function require_access(m)
    assert((m.mode=='access' or m.mode=='both') and type(m.password)=='string' and m.password~='')
end

function M.phone(m,ip,pin)
    require_access(m)
    local c=base({ip..'/32'})
    c.route.auto_detect_interface=true
    local tun='198.18.0.1/30'; if ip:match('^198%.18%.0%.') then tun='198.18.1.1/30' end
    c.inbounds[1]={type='tun',tag='phone-tun',auto_route=true,strict_route=true,stack='gvisor',
        mtu=1280,address={tun,'fdfe:dcba:9876::1/126'},route_exclude_address={ip..'/32'}}
    c.outbounds[#c.outbounds+1]=carrier(m,ip,pin)
    c.dns.servers[#c.dns.servers+1]={type='udp',tag='remote-dns',server='1.1.1.1',detour='to-router'}
    c.dns.rules={{inbound='phone-tun',action='route',server='remote-dns'}}
    c.dns.final='local'; c.dns.strategy='ipv4_only'
    table.insert(c.route.rules,1,{inbound='phone-tun',action='route',outbound='to-router'})
    table.insert(c.route.rules,1,{inbound='phone-tun',ip_version=6,action='reject'})
    table.insert(c.route.rules,1,{inbound='phone-tun',port=53,action='hijack-dns'})
    return c
end

function M.bundle(m,ip,pin)
    require_access(m)
    return {format='nativerouting-pure-hy2-device',version=1,purpose='access',
        transport={server=ip,server_port=m.port,password=m.password,certificate_public_key_sha256=pin}}
end

local function uri_component(text)
    return (text:gsub('[^A-Za-z0-9._~%-]',function(byte)
        return string.format('%%%02X',byte:byte())
    end))
end

function M.uri(m,ip,fingerprint)
    require_access(m)
    assert(type(fingerprint)=='string' and #fingerprint==64 and fingerprint:match('^[a-f0-9]+$'))
    -- The router presents a self-signed leaf. The official Hysteria client
    -- replaces CA verification with an exact leaf match only with both options.
    local uri='hysteria2://'..uri_component(m.password)..'@'..ip..':'..m.port
        ..'/?sni='..uri_component(ip)..'&insecure=1&pinSHA256='..fingerprint..'#'..uri_component(m.name)
    return {uri=uri,server=ip,server_port=m.port}
end

function M.center(m,ip,local_ips,management)
    require_access(m)
    local denied={ip..'/32'}
    for _,addr in ipairs(local_ips) do denied[#denied+1]=addr end
    local c=base(denied,true)
    assert(type(management)=='table' and type(management.namespace)=='string')
    assert(type(management.gateway)=='string' and management.gateway~=ip and
        management.gateway:match('^%d+%.%d+%.%d+%.%d+$'),'纯 HY2 服务网关无效')
    local namespace=management.namespace
    local suffix=namespace:match('^/var/run/netns/nrhy(%d+)$')
    assert(suffix and #suffix<=10,'纯 HY2 分流入口无效')
    local ports={}
    for _,name in ipairs({'http_port','https_port'}) do
        local port=management[name]
        if type(port)=='number' and port%1==0 and port>0 and port<=65535 and port~=53 and
           (port<6153 or port>6232) then ports[#ports+1]=port end
    end
    local locals,nets,excluded={management.gateway..'/32'},{},{}
    for _,lan in ipairs(management.lans or {}) do
        locals[#locals+1]=lan.address..'/32'
        if lan.bits<32 then nets[#nets+1]=lan.net end
        if lan.bits<31 then
            excluded[#excluded+1]=lan.first..'/32';excluded[#excluded+1]=lan.last..'/32'
        end
    end
    if #nets>0 then table.insert(c.route.rules,3,{ip_cidr=nets,action='route',outbound='internet'}) end
    table.insert(c.route.rules,3,{ip_cidr=locals,action='reject'})
    if #ports>0 then
        table.insert(c.route.rules,3,{ip_cidr=locals,network='tcp',port=ports,action='route',outbound='internet'})
    end
    if #excluded>0 then table.insert(c.route.rules,3,{ip_cidr=excluded,action='reject'}) end
    -- Both policy sockets and the DNS lookup for a hostname enter the same
    -- registered client interface. Only the outer QUIC transport uses the WAN mark.
    c.outbounds[1].netns=namespace
    c.dns.servers={{type='udp',tag='policy-dns',server='1.1.1.1',netns=namespace}}
    c.route.default_domain_resolver='policy-dns'
    c.inbounds[1]={type='hysteria2',tag='from-device',listen='0.0.0.0',listen_port=m.port,routing_mark=0x56000000,
        users={{name=m.name,password=m.password}},tls=server_tls}
    return c
end
return M
