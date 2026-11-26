-- Derive grants from the saved native LAN and its currently active IPv4 address.
local plan=dofile('/usr/ikuai/script/wg_address_plan.lua')
local M={}
local function overlaps(a,b) return a.lo<=b.hi and b.lo<=a.hi end
local function dotted(value)
    return string.format('%d.%d.%d.%d',math.floor(value/16777216),math.floor(value/65536)%256,
        math.floor(value/256)%256,value%256)
end

function M.select(rows,addresses,public_ip,peer_ip,gateway)
    local live,blocked={},{}
    for _,address in ipairs({'0.0.0.0/8','127.0.0.0/8','169.254.0.0/16','224.0.0.0/4','240.0.0.0/4',
                             public_ip,peer_ip,gateway}) do
        local net=plan.net(address)
        if net then blocked[#blocked+1]=net end
    end
    for line in addresses:gmatch('[^\n]+') do
        local dev,cidr=line:match('^%d+:%s+([^%s@]+)@?%S*%s+inet%s+(%S+)')
        local net=cidr and plan.net(cidr)
        if net then
            live[#live+1]={dev=dev,net=net}
            if not dev:match('^lan%d+$') then blocked[#blocked+1]=net end
        end
    end
    local result,seen={},{}
    for _,row in ipairs(rows) do
        if type(row.name)=='string' and row.name:match('^lan%d+$') then
            for cidr in tostring(row.ip_mask or ''):gmatch('[^,%s]+') do
                local n=plan.net(cidr)
                if n and n.bits>0 then
                    local active=false
                    for _,link in ipairs(live) do
                        if link.dev==row.name and link.net.host==n.host and link.net.bits==n.bits then
                            active=true
                        elseif link.dev~=row.name and overlaps(link.net,n) then
                            active=false;break
                        end
                    end
                    for _,other in ipairs(blocked) do if overlaps(other,n) then active=false;break end end
                    local key=row.name..':'..n.host..'/'..n.bits
                    if active and not seen[key] then
                        seen[key]=true
                        result[#result+1]={dev=row.name,address=dotted(n.host),net=n.text,
                            first=dotted(n.lo),last=dotted(n.hi),bits=n.bits}
                    end
                end
            end
        end
    end
    table.sort(result,function(a,b)
        if a.dev~=b.dev then return a.dev<b.dev end
        if a.net~=b.net then return a.net<b.net end
        return a.address<b.address
    end)
    return result
end

function M.snapshot(dbfile,sqlite)
    local db=sqlite.open(dbfile)
    if not db then return {},'' end
    db:busy_timeout(10000)
    local rows={}
    local stmt=db:prepare("SELECT name,ip_mask FROM lan_config WHERE bandif<>'' AND ip_mask<>'' ORDER BY id")
    if stmt then
        stmt:bind_values()
        local rc=stmt:step()
        while rc==sqlite.ROW do rows[#rows+1]=stmt:get_named_values();rc=stmt:step() end
        if rc~=sqlite.DONE then rows={} end
        stmt:finalize()
    end
    db:close()
    if #rows==0 then return {},'' end
    local p=io.popen('ip -o -4 addr show up')
    if not p then return {},'' end
    local text=p:read('*a') or ''
    p:close()
    return rows,text
end
return M
