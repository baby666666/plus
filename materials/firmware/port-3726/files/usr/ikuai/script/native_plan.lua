#!/usr/bin/ikluajit
-- Reuse kernel group membership for unchanged domains. At most 1000 per group.
local j=require('cjson')
local dir=assert(arg[1]);local old=arg[2]
local function read(p)local f=assert(io.open(p));local s=f:read('*a');f:close();return s end
local function write(p,s)local f=assert(io.open(p,'w'));assert(f:write(s));f:close()end
local meta=j.decode(read(dir..'/native-engine.json'))
local desired,slots,owners,counts,members={},{},{},{},{}
for _,r in ipairs(meta.rules)do if r.slot then
 slots[tostring(r.id)]=r.slot;desired[r.slot]={}
 for d in read(dir..'/native-domains-'..r.slot..'.txt'):gmatch('[^\n]+')do desired[r.slot][d]=true end
end end
local previous={};local lastdomain,lastgroup
local f=old and io.open(old)
if f then
 for line in f:lines()do
  local d,g,s=line:match('^(%S+) (%d+) (%d+)$');g=tonumber(g);s=tonumber(s)
  assert(d and g>=1 and g<=255 and s>=1 and s<=255,'Invalid native cache')
  assert(not lastdomain or d>lastdomain or(d==lastdomain and g>lastgroup),'Unsorted native cache');lastdomain,lastgroup=d,g
  previous[g]=previous[g]or{};previous[g][d]=true
  if desired[s]and desired[s][d]then
   assert(not owners[g]or owners[g]==s,'Group ownership conflict')
   owners[g]=s;counts[g]=(counts[g]or 0)+1;assert(counts[g]<=1000)
   members[#members+1]={d,g,s};desired[s][d]=nil
  end
 end;f:close()
end
local keepn=#members
local order={};for s in pairs(desired)do order[#order+1]=s end;table.sort(order)
for _,s in ipairs(order)do
 local domains={};for d in pairs(desired[s])do domains[#domains+1]=d end;table.sort(domains)
 for _,d in ipairs(domains)do
  local g
  for n=1,255 do if owners[n]==s and counts[n]<1000 then g=n;break end end
  if not g then for n=1,255 do if not owners[n]then g=n;owners[n]=s;counts[n]=0;break end end end
  assert(g,'Native group capacity exceeded');counts[g]=counts[g]+1;members[#members+1]={d,g,s}
 end
end
local function less(a,b)if a[1]~=b[1]then return a[1]<b[1]end;return a[2]<b[2]end
-- Kept entries retain the verified order of the loaded map. Sort only added
-- memberships, then merge; ordinary edits do not sort the entire regional DB.
local added={};for i=keepn+1,#members do added[#added+1]=members[i]end;table.sort(added,less)
local merged={};local a,b=1,1
while a<=keepn or b<=#added do
 if a<=keepn and(b>#added or less(members[a],added[b]))then merged[#merged+1]=members[a];a=a+1
 else merged[#merged+1]=added[b];b=b+1 end
end
members=merged
local lines={};for _,r in ipairs(members)do lines[#lines+1]=table.concat(r,' ')end
write(dir..'/native-desired.map',table.concat(lines,'\n')..(#lines>0 and '\n'or''))
lines={};for g=1,255 do if owners[g]then lines[#lines+1]=owners[g]..' '..g end end
write(dir..'/native-desired.groups',table.concat(lines,'\n')..(#lines>0 and '\n'or''))
write(dir..'/native-desired.slots',j.encode(slots)..'\n')

local nextgroups={};for _,r in ipairs(members)do nextgroups[r[2]]=nextgroups[r[2]]or{};nextgroups[r[2]][r[1]]=true end
lines={};for g=1,255 do
 local a,b=previous[g]or{},nextgroups[g]or{};local changed=false
 for d in pairs(a)do if not b[d]then changed=true;break end end
 if not changed then for d in pairs(b)do if not a[d]then changed=true;break end end end
 if changed then lines[#lines+1]=tostring(g)end
end
write(dir..'/native-changed.groups',table.concat(lines,'\n')..(#lines>0 and '\n'or''))
