-- Retire the removed carrier without dropping its existing WG permissions.
-- Identity is checked against the native row, never just a reusable numeric ID.
local json=require('cjson')
local sqlite=require('lsqlite3')
local peer=dofile('/usr/ikuai/script/wg_mobile_peer.lua')
local function load_registry(path)
    if path=='-' then return {} end
    local f=assert(io.open(path,'rb'))
    local data=f:read(4194305) or '';f:close()
    assert(#data<4194305)
    local state=json.decode(data)
    assert(state.version==1 and type(state.members)=='table' and type(state.enabled)=='boolean')
    return state.members
end
local function migrate()
    local prior=load_registry(arg[2])
    local hy=load_registry(arg[3])
    local rows=peer.get_rows(arg[1],nil,'retired')
    local db=assert(sqlite.open(arg[1]));db:busy_timeout(10000)
    local function sql(s) assert(db:exec(s)==sqlite.OK) end
    sql('BEGIN IMMEDIATE')
    for id,m in pairs(prior) do
        assert(peer.valid_id(id) and type(m)=='table')
        assert(type(m.interface)=='string' and m.interface:match('^wg%d+$') and
            m.iface_id~=nil and type(m.server_key)=='string' and type(m.peer_key)=='string' and
            #m.peer_key==44 and #m.server_key==44 and type(m.exit)=='boolean')
        if m.managed or m.mode~=nil then
            assert(m.managed==true and (m.mode=='lend' or m.mode=='access' or m.mode=='both'))
            local r=rows[id]
            if r and peer.same_identity(m,r) and m.address==r.address and m.port==r.port then
                assert((m.mode=='access')==(not r.exit))
                local h=hy[id]
                if h and peer.same_identity(h,r) and h.address==r.address and h.port==r.port then
                    local mode=h.mode or 'both'
                    assert((mode=='lend' or mode=='both' or mode=='access') and (mode=='access')==(not r.exit))
                else
                    -- Values interpolated here are an enum and a validated decimal ID.
                    sql("UPDATE wireguard_peers SET native_role='"..m.mode.."' WHERE id="..id)
                end
            else
                -- A reused peer ID with a different key never inherits old
                -- authority. An ambiguous same-key row is disabled for review.
                local stmt=assert(db:prepare("UPDATE wireguard_peers SET enabled='no' WHERE peer_publickey=?"))
                stmt:bind_values(m.peer_key);assert(stmt:step()==sqlite.DONE);stmt:finalize()
            end
        else
            assert((m.managed==nil or m.managed==false) and m.port==nil and m.address==nil)
            -- Earlier enroll-only registrations never restricted raw WG.
        end
    end
    sql('COMMIT');db:close()
end
if not pcall(migrate) then print('旧设备用途无法安全迁移，请检查已保存的登记；原生 WG 未启动');os.exit(1) end
