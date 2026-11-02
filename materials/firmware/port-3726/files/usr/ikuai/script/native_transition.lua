#!/usr/bin/ikluajit
-- Conservative cache reuse for application-membership-only updates. The caller
-- additionally requires identical kernel plans, address groups and bindings.
-- A missing/empty preserve list means reset all evidence, as in the old engine.
local old,new,out=arg[1],assert(arg[2]),assert(arg[3])
local function save(s)local f=assert(io.open(out,'w'));assert(f:write(s));f:close()end
save('')
local changedpath=arg[4]
if changedpath then local f=assert(io.open(changedpath,'w'));f:close()end
local function load(path)
 local f=path and io.open(path);if not f then return end
 local c={rules={},order={},globals={},regions={[1]={},[2]={}}};local r
 for line in f:lines()do
  local tag=line:sub(1,1)
  if tag=='R'then
   local id,port,kind=line:match('^R (%d+) (%d+) (%d+)$');assert(id and not c.rules[id],'invalid rule header')
   r={id=id,kind=tonumber(kind),meta={line},patterns={},domains={}};c.rules[id]=r;c.order[#c.order+1]=id
  elseif tag=='D'or tag=='E'or tag=='X'or tag=='Y'then
   assert(r and line:sub(2,2)==' ','missing rule');r.patterns[line]=true
   if tag=='D'or tag=='E'then r.domains[#r.domains+1]={line:sub(3),tag=='D'}end
  elseif tag=='I'or tag=='S'or tag=='A'or tag=='T'then
   assert(r,'missing rule');r.meta[#r.meta+1]=line
  elseif tag=='C'or tag=='F'or tag=='H'or tag=='G'or tag=='M'then
   c.globals[line]=true
   local name,kind,wide
   if tag=='M'then local k,n=line:match('^M ([12]) (.+)$');kind=tonumber(k);name=n;wide=true
   else kind=(tag=='C'or tag=='H')and 1 or 2;name=line:sub(3);wide=tag=='C'or tag=='F'end
   assert(name and kind,'invalid regional entry');c.regions[kind][#c.regions[kind]+1]={name,wide}
  elseif line~=''then error('unknown DNS record')end
 end
 f:close();return c
end
local function same(a,b)
 for k,v in pairs(a)do if b[k]~=v then return false end end
 for k,v in pairs(b)do if a[k]~=v then return false end end
 return true
end
local function labels(name)
 local t={};for x in name:gmatch('[^.]+')do t[#t+1]=x end;return t
end
local a,b=load(old),assert(load(new),'new DNS config missing')
if not a or not same(a.order,b.order)then return end
local root={children={}};local changes=0;local changedlines={}
local function changed(line)
 local tag,name=line:sub(1,1),line:sub(3);local ls=labels(name);local n=root;n.any=true
 for i=#ls,1,-1 do local label=ls[i];n.children[label]=n.children[label]or{children={}};n=n.children[label];n.any=true end
 if tag=='D'or tag=='X'then n.wide=true else n.exact=true end
 changes=changes+1;changedlines[#changedlines+1]=line
end
for _,id in ipairs(a.order)do
 local x,y=a.rules[id],b.rules[id]
 if not y or not same(x.meta,y.meta)then return end
 if not same(x.patterns,y.patterns)then
  if x.kind~=3 and x.kind~=0 then return end
  for line in pairs(x.patterns)do if not y.patterns[line]then changed(line)end end
  for line in pairs(y.patterns)do if not x.patterns[line]then changed(line)end end
 end
end
-- Compare regional suffix/exact entries and manual category overrides.
-- Only the name is needed for invalidation: adding/removing either category
-- can change priority for that name and all of its descendants.
local globalchanges=0;local removedCN,removedForeign=false,false
local function changedglobal(line)
 local tag,name=line:sub(1,1),line:sub(3)
 if tag=='M'then name=assert(line:match('^M [12] (.+)$')) end
 changed(((tag=='G'or tag=='H')and'E 'or'D ')..name)
 globalchanges=globalchanges+1
end
for line in pairs(a.globals)do if not b.globals[line]then
 if line:match('^M 1 ')then removedCN=true else removedForeign=true end
 changedglobal(line)end end
for line in pairs(b.globals)do if not a.globals[line]then changedglobal(line)end end
local function intersects(name,wide)
 local ls=labels(name);local n=root
 for i=#ls,1,-1 do
  if n.wide then return true end
  n=n.children[ls[i]];if not n then return false end
 end
 return n.wide or n.exact or (wide and n.any) or false
end
local preserved={}
for _,id in ipairs(a.order)do
 local r=a.rules[id];local affected=false
 -- Preserve only rules whose old name set cannot intersect any changed name.
 -- Catch-all flows may have no DNS history and are conservatively invalidated.
 if changes>0 then
  if r.kind==4 then affected=true end
  if os.getenv('NR_COMPACT_TRANSITION')=='1'and(r.kind==1 or r.kind==2)then affected=true end
  if os.getenv('NR_COMPACT_REGIONAL')=='1'and(r.kind==1 or r.kind==2)then
   -- Either manual category can override either complete online library.
   -- Omitted immutable base entries cannot prove disjointness here; only
   -- complete paused DNS history may refine this conservative invalidation.
   affected=true
  end
  local domains=(r.kind==1 or r.kind==2)and a.regions[r.kind]or r.domains
  for _,p in ipairs(domains)do if intersects(p[1],p[2])then affected=true;break end end
 end
 if not affected then preserved[#preserved+1]=id end
end
table.sort(preserved,function(x,y)return tonumber(x)<tonumber(y)end)
save(table.concat(preserved,'\n')..(#preserved>0 and '\n'or''))

if changedpath then local f=assert(io.open(changedpath,'w'));f:write('V1\n'..table.concat(changedlines,'\n')..'\n');f:close()end
