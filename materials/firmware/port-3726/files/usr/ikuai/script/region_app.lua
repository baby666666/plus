#!/usr/bin/ikluajit
-- Application IP overlays live inside the immutable region snapshot. Updating
-- a subscription replaces its base only; user additions/exclusions survive.
local M={};local json=require('cjson')
local function read(p)local f=assert(io.open(p,'rb'));local s=f:read('*a');f:close();return s end
local function write(p,s)local f=assert(io.open(p,'wb'));assert(f:write(s));assert(f:close())end
local function util()return dofile('/usr/ikuai/script/region_custom.lua')end
local function key(k)
 assert(type(k)=='string'and k:match('^appip_[a-z0-9_]+$')and #k<=17,'请选择常用应用分组')
 local _,catalog=dofile('/usr/ikuai/script/region_detail.lua').catalog();assert(catalog[k]and catalog[k].kind=='app_ip','未知应用分组');return k
end
local function ranges(nets)local a={};for _,n in ipairs(nets)do a[#a+1]={n[1],n[1]+2^(32-n[2])-1}end;return a end
local function strings(r,codec)local a={};for _,n in ipairs(codec.networks(r))do a[#a+1]=codec.netstr(n[1],n[2])end;return a end
local function parseText(text,path,codec)
 assert(type(text)=='string'and #text<=49152,'手动网段文本过长')
 local count=0;for line in (text..'\n'):gmatch('(.-)\n')do if line:match('%S')then count=count+1 end end;assert(count<=2048,'手动调整每项最多 2048 个网段')
 if not text:match('%S')then return{}end
 write(path,text);local a=util().parse(path,'手动调整');os.remove(path);return strings(a,codec)
end
local function listRanges(items,path,codec)
 assert(type(items)=='table'and #items<=2048,'手动调整列表无效')
 for k,v in pairs(items)do assert(type(k)=='number'and k>=1 and k<=#items and type(v)=='string','手动调整列表无效')end
 if #items==0 then return{}end
 write(path,table.concat(items,'\n'));local a=util().parse(path,'手动调整');os.remove(path);return a
end
local function apply(row,dir,manual,codec)
 local k=row.key;local base=codec.decode(dir..'/'..k..'.base.delta');local extra=listRanges(manual.add,dir..'/manual-parse.tmp',codec);local excluded=listRanges(manual.exclude,dir..'/manual-parse.tmp',codec)
 local merged=ranges(base);for _,r in ipairs(extra)do merged[#merged+1]=r end
 local a=util().subtract(util().merge(merged),excluded);local nets=codec.networks(a);assert(#nets<=262144,'调整后网段过多')
 local bytes=codec.encode(nets);write(dir..'/'..k..'.delta',bytes);write(dir..'/'..k..'.manual.json',json.encode(manual)..'\n')
 row.base_sha256=codec.sha(dir..'/'..k..'.base.delta');row.manual_sha256=codec.sha(dir..'/'..k..'.manual.json');row.sha256=codec.sha(dir..'/'..k..'.delta')
 row.base_count=#base;row.base_addresses=0;for _,n in ipairs(base)do row.base_addresses=row.base_addresses+2^(32-n[2])end
 row.count=#nets;row.addresses=0;for _,n in ipairs(nets)do row.addresses=row.addresses+2^(32-n[2])end
 row.manual_added=#manual.add;row.manual_excluded=#manual.exclude
end
function M.carry(row,plan,old,dir,codec)
 if not plan.previous.base_sha256 then return end
 assert(old,'缺少原应用库');local k=row.key
 if plan.fetch then write(dir..'/'..k..'.base.delta',read(dir..'/'..k..'.delta'))else write(dir..'/'..k..'.base.delta',read(old..'/'..k..'.base.delta'))end
 apply(row,dir,json.decode(read(old..'/'..k..'.manual.json')),codec)
end
function M.prepare(root,input,out,codec)
 local p=json.decode(read(input));key(p.key);assert(type(p.version)=='string'and #p.version==64,'缺少版本，请刷新后重试')
 local m=json.decode(read(root..'/region-manifest.json'));assert(p.version==m.version,'IP 库已变化，请刷新后重试')
 local found=false;for _,r in ipairs(m.regions)do if r.key==p.key then found=true end end;assert(found,'请先添加并更新应用分组')
 local add=parseText(p.add or '',out..'.parse',codec);local exclude=parseText(p.exclude or '',out..'.parse',codec)
 write(out,json.encode({key=p.key,version=p.version,add=add,exclude=exclude})..'\n')
end
function M.edit(root,input,out,codec)
 local p=json.decode(read(input));key(p.key);local m=json.decode(read(out..'/region-manifest.json'));assert(p.version==m.version,'IP 库已变化，请刷新后重试')
 local row;for _,r in ipairs(m.regions)do if r.key==p.key then row=r end end;assert(row,'应用分组不存在')
 if not row.base_sha256 then write(out..'/'..p.key..'.base.delta',read(out..'/'..p.key..'.delta'))end
 apply(row,out,{add=p.add,exclude=p.exclude},codec);row.manual_updated=os.date('!%Y-%m-%d %H:%M:%S UTC')
 local identity={};for _,r in ipairs(m.regions)do identity[#identity+1]=r.key..':'..r.sha256..'\n';if r.base_sha256 then identity[#identity+1]=r.key..':base:'..r.base_sha256..'\n'..r.key..':manual:'..r.manual_sha256..'\n'end end
 write(out..'/identity',table.concat(identity));m.version=codec.sha(out..'/identity');os.remove(out..'/identity');m.created=os.date('!%Y-%m-%d %H:%M:%S UTC');write(out..'/region-manifest.json',json.encode(m)..'\n');print(m.version)
end
function M.view(root,k,offset,codec)
 key(k);offset=tonumber(offset or 0);assert(offset and offset>=0 and offset%1==0 and offset<=262144,'分页无效')
 local m=json.decode(read(root..'/region-manifest.json'));local row;for _,r in ipairs(m.regions)do if r.key==k then row=r end end
 local manual={add={},exclude={}};local nets={};if row then nets=codec.decode(root..'/'..k..'.delta',true);if row.base_sha256 then manual=json.decode(read(root..'/'..k..'.manual.json'))end end
 local rows={};for i=offset+1,math.min(#nets,offset+100)do rows[#rows+1]=codec.netstr(nets[i][1],nets[i][2])end
 print(json.encode({key=k,version=m.version,installed=row~=nil,total=#nets,offset=offset,limit=100,networks=rows,add=manual.add,exclude=manual.exclude,manual_updated=row and row.manual_updated or '',base_count=row and(row.base_count or row.count)or 0}))
end
if arg and arg[0]and arg[0]:match('/region_app%.lua$')then
 local args=arg;arg=nil;local lib=dofile('/usr/ikuai/script/region_iplib.lua');arg=args
 local ok,err=pcall(function()
  if arg[1]=='view'then M.view(arg[2],arg[3],arg[4],lib.codec)
  elseif arg[1]=='prepare'then M.prepare(arg[2],arg[3],arg[4],lib.codec)
  elseif arg[1]=='edit'then M.edit(arg[2],arg[3],arg[4],lib.codec);lib.verify(arg[4])
  else error('unknown application IP action')end
 end)
 if not ok then io.stderr:write(tostring(err),'\n');os.exit(1)end
end
return M
