-- Convert untrusted firmware metadata to a fixed set of quoted shell values.
local json=require('cjson')
local f=assert(io.open(arg[1],'rb'));local raw=f:read(1048577);f:close();assert(#raw<=1048576,'header too large')
local h=json.decode(raw);assert(type(h)=='table','invalid header')
-- Validate arithmetic and identity fields before the shell parser sees them.
local function decimal(key,maximum)
 local v=h[key];assert(type(v)=='string' or type(v)=='number','missing numeric field')
 v=tostring(v);assert(v:match('^%d+$') and #v<=10,'invalid numeric field')
 assert(tonumber(v)>0 and tonumber(v)<=maximum,'numeric field out of range')
end
decimal('firmwareid',99999);decimal('length',2147483647)
assert(type(h.md5)=='string' and #h.md5==32 and h.md5:match('^[a-fA-F0-9]+$'),'invalid md5')
assert(type(h.sha256)=='string' and (#h.sha256==32 or #h.sha256==64) and h.sha256:match('^[a-fA-F0-9]+$'),'invalid sha256')
assert(type(h.version)=='string' and #h.version<=64 and h.version:match('^[A-Za-z0-9_.%-]+$'),'invalid version')
local keys={'filename','firmwarename','firmwareid','length','md5','sha256','sysbit','timestamp','version','oemname'}
local rows={}
for _,key in ipairs(keys)do
 local v=h[key]
 if v~=nil then
  assert(type(v)=='string' or type(v)=='number','invalid header field')
  v=tostring(v);assert(#v<=4096 and not v:find('%z'),'invalid header value')
  rows[#rows+1]=key.."='"..v:gsub("'","'\"'\"'").."'\n"
 end
end
local out=assert(io.open(arg[2],'w'));assert(out:write(table.concat(rows)));assert(out:close())
