#!/usr/bin/ikluajit
local json=require('cjson')
local function read(p) local f=assert(io.open(p));local s=f:read('*a');f:close();return s end
local function write(p,v) local s=json.encode(v);for _,key in ipairs{'scopes','exits','protected','rules','foreign_domains','domain_overrides','domains'} do s=s:gsub('\"'..key..'\":{}','\"'..key..'\":[]') end;local f=assert(io.open(p,'w'));assert(f:write(s..'\n'));assert(f:close()) end
if arg[1]=='snapshot' then
 local rows=json.decode(read(arg[2]));local out={}
 for _,row in ipairs(rows) do
  local values={};for _,key in ipairs{'id','enabled','comment','interface','domain','src_addr','week','time'} do values[#values+1]=json.encode(key)..':'..json.encode(row[key]) end
  out[#out+1]='{'..table.concat(values,',')..'}'
 end
 print('['..table.concat(out,',')..']');os.exit(0)
end
local ok,err=pcall(function()
 local previous=json.decode(read(arg[1]));local candidate=json.decode(read(arg[2]));local legacy=json.decode(read(arg[3]));local revision=arg[4]
 local actions=json.decode(read(arg[5]));assert(type(actions)=='table','invalid migration choices')
 local need=false;for _,row in ipairs(legacy) do if row.enabled=='yes' then need=true end end
 if previous.domain_unified==true and previous.legacy_domain_revision==revision then need=false end
 if need then
  local choices={};for _,a in ipairs(actions) do assert(type(a.id)=='number' and not choices[a.id],'duplicate migration choice');choices[a.id]=a end
  for _,row in ipairs(legacy) do if row.enabled=='yes' then
   local a=choices[tonumber(row.id)];assert(a,'Original domain rules require review in the domain page');choices[tonumber(row.id)]=nil
   assert(a.action=='merge' or a.action=='retire','Choose merge or archive for each original rule')
   if a.action=='merge' then
    assert(a.accept_scope==true,'Confirm unified client scopes and all-day schedule')
    assert(type(a.domains)=='table' and #a.domains>0,'Enter canonical domain names for migrated rule')
    candidate.rules[#candidate.rules+1]={kind='domain',domains=a.domains,exit=a.exit}
   end
  end end
  assert(next(choices)==nil,'Stale migration choice')
 else assert(#actions==0,'Migration snapshot has changed; reload first') end
 candidate.domain_overrides=candidate.domain_overrides or {};candidate.unknown_dns='foreign'
 candidate.domain_unified=true;candidate.legacy_domain_revision=revision
 write(arg[2],candidate)
end)
if not ok then io.stderr:write(tostring(err),'\n');os.exit(1) end
