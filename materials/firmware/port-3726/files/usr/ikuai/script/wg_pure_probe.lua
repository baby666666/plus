-- An accepting local TUN socket (or a synthetic ICMP reply) does not prove
-- remote egress. Require the selected resolver to return our DNS transaction.
local peer=dofile('/usr/ikuai/script/wg_mobile_peer.lua')
local id,dev,target=tonumber(arg[1]),arg[2],arg[3]
assert(id and id>=1 and id<=32 and id==math.floor(id))
assert(dev:match('^nph%d+$') and peer.ipv4(target))
local random=assert(io.open('/dev/urandom','rb'))
local token=assert(random:read(2))
random:close()
local query=token..string.char(1,0,0,1,0,0,0,0,0,0,0,0,2,0,1)
local bytes=query:gsub('.',function(c) return string.format('\\%03o',c:byte()) end)
-- SO_MARK=36 at SOL_SOCKET=1. Bind the socket to this exact TUN in
-- addition to its policy mark, so a disappearing exit cannot use another WAN.
local cmd=string.format("printf '%s' | /usr/bin/socat -t1 -T1 - 'UDP4:%s:53,so-bindtodevice=%s,setsockopt-int=1:36:%d' 2>/dev/null",bytes,target,dev,0x55000000+id)
local input=assert(io.popen(cmd,'r'))
local packet=input:read(512) or ''
input:close()
if #packet<17 or packet:sub(1,2)~=token or packet:byte(3)<128 or packet:sub(5,6)~=string.char(0,1)
   or packet:sub(13,17)~=query:sub(13,17) then os.exit(1) end
