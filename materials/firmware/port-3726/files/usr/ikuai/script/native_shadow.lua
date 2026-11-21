#!/usr/bin/ikluajit
-- Allocate inactive kernel groups without reusing any live group number.
-- Exit 3 is a safe fallback, before any live kernel mutation.
local root,nextdir=assert(arg[1]),assert(arg[2])
local function read(p)local f=assert(io.open(p));local s=f:read('*a');f:close();return s end
local function write(p,s)local f=assert(io.open(p,'w'));assert(f:write(s));f:close()end
local function lines(t)return table.concat(t,'\n')..(#t>0 and '\n'or'')end
local function map(path)
 local rows,groups={},{};local last,lg
 for line in read(path):gmatch('[^\n]+')do
  local d,g,s=line:match('^(%S+) (%d+) (%d+)$');g,s=tonumber(g),tonumber(s)
  assert(d and g>=1 and g<=255 and s>=1 and s<=255,'Invalid map')
  assert(not last or d>last or d==last and g>lg,'Unsorted map');last,lg=d,g
  local v=groups[g]or{slot=s,n=0,names={}};groups[g]=v
  assert(v.slot==s and not v.names[d]);v.names[d]=true;v.n=v.n+1;assert(v.n<=1000)
  rows[#rows+1]={d,g,s}
 end;return rows,groups
end
local old,og=map(root..'/native-loaded.map');local desired,ng=map(nextdir..'/native-desired.map')
local bindings,by_slot={},{}
for line in read(root..'/native-bindings'):gmatch('[^\n]+')do
 local g,b=line:match('^(%d+) (.+)$');g=tonumber(g);assert(g and og[g])
 bindings[g]=b;local s=tonumber(b:match('^(%d+) '));assert(s==og[g].slot)
 assert(not by_slot[s]or by_slot[s]==b,'Inconsistent bindings');by_slot[s]=b
end
local changed,retire,remap,newids={},{},{},{}
for g=1,255 do
 local a,b=og[g],ng[g];local same=a and b and a.slot==b.slot and a.n==b.n
 if same then for d in pairs(a.names)do if not b.names[d]then same=false;break end end end
 if not same and(a or b)then
  changed[g]=true
  if a then
   if not(bindings[g]or''):match('^%d+ null [1-7,]+ %d+ %d+ gate1$')then os.exit(3)end
   retire[#retire+1]=tostring(g)
  end
  if b and not(by_slot[b.slot]or''):match('^%d+ null [1-7,]+ %d+ %d+ gate1$')then os.exit(3)end
 end
end
for g=1,255 do if changed[g]and ng[g]then
 local free;for k=1,255 do if not og[k]and not newids[k]then free=k;break end end
 if not free then os.exit(3)end;remap[g]=free;newids[free]=true
end end
local staged,full,groups,bs,create={},{},{},{},{}
for _,r in ipairs(desired)do
 local g=remap[r[2]]or r[2];local row={r[1],g,r[3]};full[#full+1]=row;groups[g]=r[3]
 if newids[g]then staged[#staged+1]=row end
end
local function render(rows)
 table.sort(rows,function(a,b)return a[1]<b[1]or a[1]==b[1]and a[2]<b[2]end)
 local out={};for _,r in ipairs(rows)do out[#out+1]=table.concat(r,' ')end;return lines(out)
end
local gs={}
for g=1,255 do if groups[g]then
 local s=groups[g];local b=assert(by_slot[s]);bs[#bs+1]=g..' '..b;gs[#gs+1]=s..' '..g
 if newids[g]then create[#create+1]=g..' '..b:match('^(.-) gate1$')end
end end
write(nextdir..'/shadow-desired.map',render(full))
write(nextdir..'/shadow-stage.map',render(staged))
write(nextdir..'/shadow-groups',lines(gs));write(nextdir..'/shadow-bindings',lines(bs))
write(nextdir..'/shadow-create',lines(create));write(nextdir..'/shadow-retire',lines(retire))
write(nextdir..'/shadow-total',tostring(#old+#staged)..'\n')
