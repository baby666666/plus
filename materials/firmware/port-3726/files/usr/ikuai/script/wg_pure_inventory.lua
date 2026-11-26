-- Relate a logical exit to a pure HY2 worker only while the saved identities match.
local sqlite = require('lsqlite3')
local peer = dofile('/usr/ikuai/script/wg_mobile_peer.lua')
local dbfile,statefile,only = unpack(arg)
local db = assert(sqlite.open(dbfile))
db:busy_timeout(10000)
local entries = {}
local function add(dev,id,unit,allowed)
    id = assert(tonumber(id))
    assert(id > 0 and (id <= 64516 or not allowed) and id == math.floor(id) and dev:match('^wg%d+$'))
    if only and dev ~= only then return end
    assert(not entries[dev])
    entries[dev] = string.format('%s nph%d %s-%d %s',dev,id,unit,id,allowed and 'yes' or 'no')
end
if statefile ~= '-' then
    local state = require('cjson').decode(peer.read(statefile))
    local rows
    for id,m in pairs(state.members or {}) do
        if m.transport ~= 'pure_hy2' and (not only or m.interface == only) then
            if peer.wrapped_identity(db,id,m) then add(m.interface,id,'puh',false) end
        elseif not only or m.interface == only then
            rows = rows or peer.get_rows(dbfile,nil,'hysteria2')
            local row = rows[id]
            if peer.same_identity(m,row) and row.dedicated then
                add(row.interface,id,'puh',false)
            end
        end
    end
end
for t in db:nrows("SELECT 1 AS present FROM sqlite_master WHERE type='table' AND name='wg_site_clients'") do
    local from,transport,purpose = peer.site_client_binding(db,true)
    local sql = 'SELECT c.iface, c.peer_id, p.enabled AS pe, w.enabled AS we,'..purpose..' AS purpose,'..transport..' AS carrier'..from.." AND "..transport.." IN ('pure_hy2','hysteria2')"
    for row in db:nrows(sql) do
        add(row.iface,row.peer_id,'puc',row.carrier=='pure_hy2' and row.pe=='yes' and row.we=='yes' and row.purpose~='lend')
    end
end
assert(db:close()==sqlite.OK)
local names={}
for dev in pairs(entries) do names[#names+1]=dev end
table.sort(names)
for _,dev in ipairs(names) do print(entries[dev]) end
