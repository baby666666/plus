-- Versioned, declarative reverse mappings. Never accept executable proxy rules.
local json=require('cjson')
local M={control_port=49871}
local function check(ok,message)
    if not ok then error({message=message or '反向端口映射配置无效'},0) end
    return ok
end
local function shape(value,keys)
    if type(value)~='table' then return false end
    for key in pairs(value) do
        if type(key)~='string' or not keys:find(' '..key..' ',1,true) then return false end
    end
    return true
end
local function integer(value,low,high)
    return type(value)=='number' and value==math.floor(value) and value>=low and value<=high
end
local function array(value,low,high)
    if type(value)~='table' or #value<low or #value>high then return false end
    local count=0
    for key in pairs(value) do
        if not integer(key,1,#value) then return false end
        count=count+1
    end
    return count==#value
end
local function ipv4(value)
    if type(value)~='string' or #value>15 then return nil end
    local a,b,c,d=value:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
    if not a then return nil end
    a,b,c,d=tonumber(a),tonumber(b),tonumber(c),tonumber(d)
    if a>255 or b>255 or c>255 or d>255 or value~=table.concat({a,b,c,d},'.') then return nil end
    return ((a*256+b)*256+c)*256+d,a,b
end
local function target(value)
    local n,a=ipv4(value)
    -- Loopback is intentionally allowed for an explicitly selected local service.
    return n and a>0 and a<224 and value or nil
end
local function gateway(value)
    local n,a,b=ipv4(value)
    return n and a>0 and a<224 and a~=127 and not (a==169 and b==254) and value or nil
end
local function cidr(value)
    if type(value)~='string' then return nil end
    local host,bits=value:match('^([^/]+)/(%d+)$')
    local n=ipv4(host)
    local count=tonumber(bits)
    if not n or not count or count<0 or count>32 or tostring(count)~=bits then return nil end
    n=math.floor(n/2^(32-count))*2^(32-count)
    local octets={}
    for i=4,1,-1 do octets[i]=n%256;n=math.floor(n/256) end
    return table.concat(octets,'.')..'/'..count
end
local function token(value)
    return type(value)=='string' and #value==64 and value:match('^[a-f0-9]+$')
end
local function mapping_id(value)
    return type(value)=='string' and value:match('^[1-9]%d*$') and
        #value<=2 and tonumber(value)<=32 and tostring(tonumber(value))==value
end
function M.mappings(value)
    check(array(value,1,32),'反向端口映射需要 1 至 32 条规则')
    local result,ids,ports={},{},{}
    for _,row in ipairs(value) do
        check(shape(row,' id protocol listen_port target_ip target_port sources '))
        check(mapping_id(row.id) and not ids[row.id],'反向映射编号必须为不重复的 1 至 32')
        check(row.protocol=='tcp' or row.protocol=='udp','反向映射只支持 TCP 或 UDP')
        check(integer(row.listen_port,1,65535) and integer(row.target_port,1,65535),'反向映射端口范围为 1 至 65535')
        check(target(row.target_ip),'反向映射目标必须是有效的单播 IPv4 地址')
        local endpoint=row.protocol..':'..row.listen_port
        check(not ports[endpoint],'反向映射监听端口重复')
        ids[row.id]=true;ports[endpoint]=true
        check(array(row.sources,1,16),'每条反向映射需要 1 至 16 个允许来源网段')
        local sources,seen={},{}
        for _,source in ipairs(row.sources) do
            local normalized=cidr(source)
            check(normalized,'反向映射来源必须是 IPv4 CIDR 网段')
            if not seen[normalized] then sources[#sources+1]=normalized;seen[normalized]=true end
        end
        table.sort(sources)
        result[#result+1]={id=row.id,protocol=row.protocol,listen_port=row.listen_port,
            target_ip=row.target_ip,target_port=row.target_port,sources=sources}
    end
    table.sort(result,function(a,b)return tonumber(a.id)<tonumber(b.id) end)
    return result
end
function M.saved(value)
    check(shape(value,' version enabled token mappings ') and value.version==1 and value.enabled==true and token(value.token))
    return {version=1,enabled=true,token=value.token,mappings=M.mappings(value.mappings)}
end
local function new_token()
    local random=assert(io.open('/dev/urandom','rb'))
    local bytes=random:read(32);random:close()
    assert(bytes and #bytes==32)
    return (bytes:gsub('.',function(c)return string.format('%02x',c:byte()) end))
end
function M.update(request,previous,encode,renew)
    check(shape(request,' enabled mappings ') and type(request.enabled)=='boolean')
    if request.enabled==false then return nil,previous~=nil end
    local mappings=M.mappings(request.mappings)
    local old
    if previous then
        local ok,value=pcall(M.saved,previous)
        -- An explicit repair must be possible without reusing an invalid token.
        if ok then old=value end
    end
    local same=old and not renew and encode(old.mappings)==encode(mappings)
    return {version=1,enabled=true,token=same and old.token or new_token(),mappings=mappings},not same
end
function M.public(value)
    if not value then return {enabled=false} end
    local saved=M.saved(value)
    return {enabled=true,mappings=saved.mappings}
end
function M.bundle(value,server)
    local saved=M.saved(value)
    check(gateway(server),'反向通道缺少有效的服务端内网地址')
    return {version=1,token=saved.token,server=server,server_port=M.control_port,mappings=saved.mappings}
end
function M.import(value,outer_server)
    check(shape(value,' version token server server_port mappings ') and value.version==1 and token(value.token))
    check(gateway(value.server) and value.server~=outer_server and value.server_port==M.control_port,
        '反向通道控制地址无效')
    return {version=1,token=value.token,server=value.server,server_port=M.control_port,mappings=M.mappings(value.mappings)}
end
-- Paused registrations reserve their mappings. Re-enabling one cannot take a
-- port from another device. Live socket ownership is verified by the supervisor.
function M.conflicts(value,state,id,udp_reserved,http_port,https_port)
    local saved=M.saved(value)
    for _,row in ipairs(saved.mappings) do
        local port=row.listen_port
        check(port~=53 and not (port>=6153 and port<=6232) and
            not (row.protocol=='tcp' and (port==M.control_port or port==http_port or port==https_port)),
            '反向映射端口与管理、DNS 或控制服务冲突')
        if row.protocol=='udp' then
            check(not udp_reserved(port),'反向映射端口与 WG 或 HY2 服务冲突')
            for _,member in pairs(state.members) do
                check(port~=member.port and port~=member.inner_port,'反向映射端口与 WG 或 HY2 服务冲突')
            end
            check(not state.settings or port~=state.settings.udp_port,'反向映射端口与 WG 或 HY2 服务冲突')
        end
        for owner,member in pairs(state.members) do
            if tostring(owner)~=tostring(id) and member.reverse then
                -- Damaged registrations cannot authorize a listener and are
                -- revoked independently by staging. They must not prevent an
                -- unrelated valid registration from recovering or being saved.
                local valid,other_saved=pcall(M.saved,member.reverse)
                if valid then
                    for _,other in ipairs(other_saved.mappings) do
                        check(other.protocol~=row.protocol or other.listen_port~=port,'反向映射监听端口已被其他设备使用')
                    end
                end
            end
        end
    end
    return saved
end
function M.socks_address(id)
    id=tonumber(id)
    check(integer(id,1,64516),'反向代理设备编号无效')
    return '127.77.'..(1+math.floor((id-1)/254))..'.'..(1+(id-1)%254)
end
local function runtime(mode,value,id)
    check(integer(tonumber(id),1,4294967295),'反向代理设备编号无效')
    local prefix=mode=='server' and 'puh-' or 'puc-'
    local mappings={}
    for _,row in ipairs(value.mappings) do
        mappings[#mappings+1]={id=row.id,protocol=row.protocol,listen='0.0.0.0:'..row.listen_port,
            target=row.target_ip..':'..row.target_port,allow=row.sources}
    end
    return {mode=mode,token=value.token,control=value.server..':'..value.server_port,
        status_file='/tmp/iktmp/wg-hy-reverse/'..prefix..id..'/status.json',mappings=mappings}
end
function M.server(value,id,server)
    return runtime('server',M.bundle(value,server),id)
end
function M.client(value,id,outer_server)
    local config=runtime('client',M.import(value,outer_server),id)
    config.socks=M.socks_address(id)..':1080'
    config.target_mark=1442840576
    return config
end
local states={initializing=true,waiting=true,connecting=true,online=true,error=true,stopped=true}
local function safe_code(value)
    return type(value)=='string' and #value<=64 and value:match('^[a-z0-9_]*$') and value or nil
end
-- The shell checks executable identity, PID start ticks, exact config digest
-- and freshness. Never trust a stale raw status file as proof of connection.
function M.status(unit)
    check(type(unit)=='string' and (unit:match('^puh%-%d+$') or unit:match('^puc%-%d+$')))
    local result={connected=false,state='stopped'}
    local opened,file=pcall(io.popen,'/usr/ikuai/script/wg_hy_reverse.sh status '..unit..' 2>/dev/null')
    if not opened or not file then return result end
    local read_ok,raw=pcall(file.read,file,32769);pcall(file.close,file)
    if not read_ok or type(raw)~='string' or #raw>32768 then return result end
    local ok,value=pcall(json.decode,raw)
    if not ok or type(value)~='table' or not states[value.state] or type(value.connected)~='boolean' then return result end
    result.state=value.state;result.connected=value.connected and value.state=='online'
    for _,key in ipairs({'last_heartbeat','updated_at'}) do
        if integer(value[key],0,9007199254740991) then result[key]=value[key] end
    end
    result.error=safe_code(value.error)
    if array(value.mappings,0,32) and #value.mappings>0 then
        result.mappings={}
        for _,row in ipairs(value.mappings) do
            if type(row)=='table' and mapping_id(row.id) then
                local out={id=row.id,listening=row.listening==true,last_error=safe_code(row.last_error)}
                for _,key in ipairs({'active','rx_bytes','tx_bytes','last_success'}) do
                    if integer(row[key],0,9007199254740991) then out[key]=row[key] end
                end
                result.mappings[#result.mappings+1]=out
            end
        end
        if #result.mappings==0 then result.mappings=nil end
    end
    return result
end
return M
