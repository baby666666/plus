#!/usr/bin/ikluajit
-- Strict fallback uses authenticated local snapshot contents, not mutable UI groups.
-- On unreadable/corrupt input publish an empty allow set: never widen access.
local j=require('cjson');local M={};local cache
local function read(p)local f=assert(io.open(p,'rb'));local s=f:read('*a');f:close();return s end
local function write(p,s)local f=assert(io.open(p,'w'));assert(f:write(s));assert(f:close())end
local function q(s)return "'"..s:gsub("'","'\\''").."'"end
local function sha(p)local f=assert(io.popen('sha256sum '..q(p)));local s=f:read('*a');f:close();return assert(s:match('^([a-f0-9]+)'))end
local function current()
 local f=assert(io.popen("if [ -L /etc/mnt/ikuai/region-iplib/current ]; then readlink /etc/mnt/ikuai/region-iplib/current; else printf /usr/share/strict-routing; fi"))
 local s=f:read('*a'):gsub('%s+$','');f:close()
 assert(s=='/usr/share/strict-routing'or s:match('^/etc/mnt/ikuai/region%-iplib/versions/[a-f0-9]+$'),'invalid region root');return s
end
function M.prepare(dir,root)
 local status={enabled=true,available=false,count=0,signature='strict-cn-v1-invalid'};local restore=''
 local ok,err=pcall(function()
  root=root or current();local m=j.decode(read(root..'/region-manifest.json'));assert(m.format==1 and type(m.regions)=='table','invalid manifest')
  local rows={};for _,r in ipairs(m.regions)do assert(not rows[r.key],'duplicate region');rows[r.key]=r end
  local identity={};for _,key in ipairs{'cn','hk','mo','tw'}do
   local r=assert(rows[key],'missing region');assert(type(r.sha256)=='string'and #r.sha256==64 and r.sha256:match('^[a-f0-9]+$'),'invalid digest')
   assert(sha(root..'/'..key..'.delta')==r.sha256,'region checksum mismatch');identity[#identity+1]=key..':'..r.sha256..':'..tostring(r.count)..':'..tostring(r.addresses)
  end
  local sig='strict-cn-v1-'..table.concat(identity,'-')
  if not cache or cache.signature~=sig then
   local lib=dofile('/usr/ikuai/script/region_iplib.lua');local util=dofile('/usr/ikuai/script/region_custom.lua');local cn;local excluded=util.subtract({{0,4294967295}},util.foreign({}))
   for _,key in ipairs{'cn','hk','mo','tw'}do
    local nets=lib.decode(root..'/'..key..'.delta');local ranges={};local addresses=0
    for _,n in ipairs(nets)do local size=2^(32-n[2]);ranges[#ranges+1]={n[1],n[1]+size-1};addresses=addresses+size end
    assert(#nets==rows[key].count and addresses==rows[key].addresses,'region count mismatch')
    if key=='cn' then cn=ranges else for _,r in ipairs(ranges)do excluded[#excluded+1]=r end end
   end
   local nets=lib.networks(util.subtract(cn,util.merge(excluded)));assert(#nets>0,'no mainland public addresses');assert(#nets<=262144)
   local lines={};for _,n in ipairs(nets)do lines[#lines+1]='add nr_cn_stage '..lib.netstr(n[1],n[2]) end
   cache={signature=sig,restore=table.concat(lines,'\n')..'\n',count=#nets}
  end
  restore=cache.restore;status.available=true;status.count=cache.count;status.signature=cache.signature
 end)
 if not ok then status.reason='地区 IP 库缺失或校验失败，仅允许命中端口／协议规则的流量，其余阻断';cache=nil end
 write(dir..'/strict-cn.restore',restore);write(dir..'/strict-target.json',j.encode(status)..'\n');return status
end
return M
