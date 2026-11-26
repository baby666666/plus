-- Resident native-membership index. A changed app only rechecks candidate
-- domains whose parent/child relationships intersect changed blockers.
local M={};local previous={};local MAX_CACHED_CANDIDATES=300000;local indexcache=setmetatable({},{__mode='k'})
local function reverse(s)local a={};for x in s:gmatch('[^.]+')do table.insert(a,1,x)end;return table.concat(a,'.')end
local function ancestor(set,name)while name do if set[name]then return true end;name=name:match('^[^.]+%.(.+)$')end;return false end
local function same(a,b)for k in pairs(a)do if not b[k]then return false end end;for k in pairs(b)do if not a[k]then return false end end;return true end
local function index(values)
 local found=indexcache[values];if found then return found end
 local idx={names={},reverse={}};for _,name in ipairs(values)do if not idx.names[name]then idx.names[name]=true;idx.reverse[#idx.reverse+1]=reverse(name)end end
 table.sort(idx.reverse);indexcache[values]=idx;return idx
end
local function affected(idx,name,out)
 local p=name;while p do if idx.names[p]then out[p]=true end;p=p:match('^[^.]+%.(.+)$')end
 local prefix=reverse(name)..'.';local a,b=1,#idx.reverse+1
 while a<b do local mid=math.floor((a+b)/2);if idx.reverse[mid]<prefix then a=mid+1 else b=mid end end
 while a<=#idx.reverse and idx.reverse[a]:sub(1,#prefix)==prefix do out[reverse(idx.reverse[a])]=true;a=a+1 end
end
function M.select(id,candidates,ownblock,higher,blocked)
 local idx=index(candidates);local old=previous[id];local changes={};local touched=0
 if old and old.index==idx and old.own==ownblock then
  for name in pairs(old.higher)do if not higher[name]then changes[name]=true end end
  for name in pairs(higher)do if not old.higher[name]then changes[name]=true end end
  if not next(changes)then return old.output,'reused',0 end
 else old=nil end
 local eligible,selected={},{}
 if old then
  local subset={};for n in pairs(changes)do affected(idx,n,subset)end
  local changeset={};for n in pairs(subset)do
   touched=touched+1;local wanted=not blocked(n)or nil
   if old.eligible[n]~=wanted then changeset[n]=wanted and 1 or 0 end
  end
  if not next(changeset)then old.higher=higher;return old.output,'incremental',touched end
  -- Copy before editing: an exception must not corrupt the reusable generation.
  for n in pairs(old.eligible)do eligible[n]=true end
  for n in pairs(old.selected)do selected[n]=true end
  local compact={};for n,v in pairs(changeset)do eligible[n]=v==1 or nil;affected(idx,n,compact)end
  for n in pairs(compact)do selected[n]=(eligible[n]and not ancestor(eligible,n:match('^[^.]+%.(.+)$')))or nil end
 else
  for n in pairs(idx.names)do touched=touched+1;if not blocked(n)then eligible[n]=true end end
  for n in pairs(eligible)do if not ancestor(eligible,n:match('^[^.]+%.(.+)$'))then selected[n]=true end end
 end
 local output={};for n in pairs(selected)do output[#output+1]=n end;table.sort(output)
 local used=#idx.reverse;for key,state in pairs(previous)do if key~=id then used=used+#state.index.reverse end end
 if used<=MAX_CACHED_CANDIDATES then previous[id]={index=idx,own=ownblock,higher=higher,eligible=eligible,selected=selected,output=output}else previous[id]=nil end
 return output,old and 'incremental'or'full',touched
end
function M.retain(ids)for id in pairs(previous)do if not ids[id]then previous[id]=nil end end end
return M
