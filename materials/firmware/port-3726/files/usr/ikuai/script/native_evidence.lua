#!/usr/bin/ikluajit
-- Refine only a metadata-compatible membership delta using the stopped DNS
-- dispatcher's bounded history. Invalid/missing/overflowed history never grants
-- extra reuse. No source addresses are needed: affected names invalidate every
-- client tuple for that rule, including any shared destination address.
local changes,history,out,config=arg[1],arg[2],assert(arg[3]),assert(arg[4])
os.remove(out..'.all')
local function read(p)local f=io.open(p or '');if not f then return end;local s=f:read('*a');f:close();return s end
local c,h=read(changes),read(history)
if not c or c:sub(1,3)~='V1\n' or not h then return end
local u=read('/proc/uptime');local now=u and tonumber(u:match('^[%d.]+'));if not now then return end
local incomplete=h:match('^V1 (%d+)\n');if not incomplete or tonumber(incomplete)>now then return end
local root={children={}}
for line in c:sub(4):gmatch('[^\n]+')do
 local tag,name=line:match('^([DEXY]) ([a-z0-9_.%-]+)$');if not tag then return end
 local ls={};for label in name:gmatch('[^.]+')do ls[#ls+1]=label end
 local n=root;for i=#ls,1,-1 do n.children[ls[i]]=n.children[ls[i]]or{children={}};n=n.children[ls[i]]end
 if tag=='D'or tag=='X'then n.wide=true else n.exact=true end
end
local function intersects(name)
 local ls={};for label in name:gmatch('[^.]+')do ls[#ls+1]=label end
 local n=root;for i=#ls,1,-1 do if n.wide then return true end;n=n.children[ls[i]];if not n then return false end end
 return n.wide or n.exact or false
end
local affected={}
for line in h:sub((h:find('\n'))+1):gmatch('[^\n]+')do
 local id,until_,name=line:match('^(%d+) (%d+) ([a-z0-9_.%-]+)$')
 if not id or tonumber(id)<1 or tonumber(id)>999999 or tonumber(until_)>now+721 then return end
 if tonumber(until_)>now and intersects(name)then affected[id]=true end
end
local old={};for id in (read(out)or''):gmatch('%d+')do old[id]=true end
local ids={};local all=true;local text=read(config);if not text then return end
for id in text:gmatch('R (%d+) %d+ %d+\n')do
 if not affected[id]or old[id]then ids[#ids+1]=id else all=false end
end
table.sort(ids,function(a,b)return tonumber(a)<tonumber(b)end)
local f=assert(io.open(out,'w'));f:write(table.concat(ids,'\n')..(#ids>0 and '\n'or''));f:close()
if all then f=assert(io.open(out..'.all','w'));f:write('unchanged live evidence\n');f:close()end
