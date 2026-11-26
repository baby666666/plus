#!/usr/bin/ikluajit
-- Sorted IPv4 networks: unsigned LEB128 address delta followed by prefix byte.
local name=arg[1];assert(name and name:match('^[a-z]+$'))
local root=os.getenv('STRICT_REGION_ROOT') or os.getenv('STRICT_DATA_ROOT') or '/usr/share/strict-routing'
local f=assert(io.open(root..'/'..name..'.delta','rb'));local data=f:read('*a');f:close()
local pos,ip=1,0
while pos<=#data do
 local delta,factor=0,1
 repeat
  local n=assert(data:byte(pos));pos=pos+1;delta=delta+(n%128)*factor;factor=factor*128
  assert(factor<=34359738368);if n<128 then break end
 until false
 ip=ip+delta;assert(ip<=4294967295)
 local prefix=assert(data:byte(pos));pos=pos+1;assert(prefix<=32)
 local net=string.format('%d.%d.%d.%d/%d',math.floor(ip/16777216),math.floor(ip/65536)%256,math.floor(ip/256)%256,ip%256,prefix)
 io.write('add sp_r_',name,' ',net,'\nadd sp_known ',net,'\n')
end
