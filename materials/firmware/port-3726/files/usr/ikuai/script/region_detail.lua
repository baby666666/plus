-- Optional country, province/city, operator and cloud lists. No downloaded code is executed.
local j=require('cjson');local M={}
local function read(p)local f=assert(io.open(p,'rb'));local s=f:read('*a');f:close();return s end
local function write(p,s)local f=assert(io.open(p,'wb'));assert(f:write(s));assert(f:close())end
function M.catalog()
 local rows=j.decode(read('/usr/share/strict-routing/detail-catalog.json'));local map={}
 for _,row in ipairs(rows)do
  if row.kind=='country'then row.url='https://www.ipdeny.com/ipblocks/data/countries/'..row.key:sub(9)..'.zone'
  elseif row.kind=='province'or row.kind=='city'then row.url='https://raw.githubusercontent.com/metowolf/iplist/master/data/cncity/'..row.key:sub(4)..'.txt'
  elseif row.kind=='operator'then row.url='https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/'..row.key:sub(5)..'.txt'
  elseif row.kind=='cloud'then row.url='https://raw.githubusercontent.com/metowolf/iplist/master/data/isp/'..(row.slug or row.key:sub(7))..'.txt'end
 end
 local extra={};for _,country in ipairs(rows)do if country.kind=='country'then for _,vendor in ipairs(rows)do if vendor.kind=='cloud'then extra[#extra+1]={key='cv_'..country.key:sub(9)..'_'..vendor.key:sub(7),label=country.label..' / '..vendor.label,parent=country.key,kind='country_cloud',url=vendor.url,boundary_key=country.key,boundary_url=country.url,continent=country.parent}end end end end
 for _,territory in ipairs{{'hk','香港'},{'mo','澳门'},{'tw','台湾'}}do for _,vendor in ipairs(rows)do if vendor.kind=='cloud'then extra[#extra+1]={key='cv_'..territory[1]..'_'..vendor.key:sub(7),label=territory[2]..' / '..vendor.label,parent='hmtclouds',kind='country_cloud',url=vendor.url,region_key=territory[1]}end end end
 for _,row in ipairs(extra)do rows[#rows+1]=row end
 local file=io.open('/etc/mnt/ikuai/region-iplib/source.json');if file then
  local config=j.decode(file:read('*a'));file:close()
  for key,c in pairs(config.custom_groups or {})do
   assert(key:match('^user_[a-z0-9_]+$')and #key<=17 and type(c.label)=='string'and type(c.url)=='string','自定义源无效')
   rows[#rows+1]={key=key,label=c.label,url=c.url,kind='custom',parent='custom'}
  end
 end
 for _,r in ipairs(rows)do assert(r.key:match('^[a-z][a-z0-9_]+$')and #r.key<=17 and not map[r.key]);map[r.key]=r end
 return rows,map
end
function M.plan(root,source,deleted,requested,out)
 local _,catalog=M.catalog();local config=j.decode(read(source));local previous=j.decode(read(root..'/region-manifest.json'))
 local excluded={};for group in (deleted or ''):gmatch('[^,]+')do excluded[group]=true end
 assert(requested==''or catalog[requested],'未知细分分组')
 local all={};for _,r in ipairs(previous.regions)do if catalog[r.key]and not excluded['geo_'..r.key]then all[r.key]=r end end
 if requested~=''then all[requested]=all[requested]or{key=requested}end
 local keys={};for key in pairs(all)do keys[#keys+1]=key end;table.sort(keys)
 local plan,lines,seenBoundary={},{},{};local active=0
 for _,key in ipairs(keys)do
  local fetch=(requested==''and not excluded['geo_'..key])or key==requested
  local c=catalog[key];local url=(config.details or {})[key]or'';if url==''then url=c.url end
  local row={key=key,fetch=fetch,url=url,previous=all[key],exclude_url=(url==c.url and c.exclude_url or nil)};plan[#plan+1]=row
  if fetch then
   active=active+1;lines[#lines+1]=key..'\t'..url
   if row.exclude_url then lines[#lines+1]='exclude_'..key..'\t'..row.exclude_url end
   if c.kind=='country_cloud'and not c.region_key and not all[c.boundary_key]and not seenBoundary[c.boundary_key]then
    local boundary=(config.details or {})[c.boundary_key]or'';if boundary==''then boundary=c.boundary_url end
    lines[#lines+1]='boundary_'..c.boundary_key..'\t'..boundary;seenBoundary[c.boundary_key]=true
   end
  end
 end
 assert(active<=64,'最多同时启用 64 个细分分组，请先删除不用的分组')
 write(out..'/detail-plan.json',j.encode(plan));write(out..'/detail-downloads',table.concat(lines,'\n')..(#lines>0 and'\n'or''))
end
function M.append(rows,dir,custom,regions,codec)
 if not custom then return end
 local f=io.open(custom..'/detail-plan.json');if not f then return end;local plan=j.decode(f:read('*a'));f:close()
 local _,catalog=M.catalog();local util=dofile('/usr/ikuai/script/region_custom.lua');local total=0;local boundaries={};local requested={}
 for _,p in ipairs(plan)do if p.fetch then requested[p.key]=true end end
 local function countryBoundary(key,continent)
  if boundaries[key]then return boundaries[key]end
  local file=(requested[key]and key or 'boundary_'..key)..'.txt'
  local a=util.parse(custom..'/'..file,key);a=util.subtract(a,util.subtract(a,regions[continent]))
  for other,b in pairs(boundaries)do util.disjoint(a,b,key,other)end
  boundaries[key]=a;return a
 end
 for _,p in ipairs(plan)do
  local c=assert(catalog[p.key]);local row
  if p.fetch then
   local a=util.parse(custom..'/'..p.key..'.txt',p.key,c.kind=='app_ip');if p.exclude_url then a=util.subtract(a,util.parse(custom..'/exclude_'..p.key..'.txt',p.key..' exclusions',true))end;local before=0;for _,r in ipairs(a)do before=before+r[2]-r[1]+1 end
   local boundary
   if c.kind=='operator'or c.kind=='province'or c.kind=='city'or c.kind=='cloud'then boundary=regions.cn
   elseif c.kind=='country'then boundary=countryBoundary(p.key,c.parent)
   elseif c.kind=='country_cloud'and c.region_key then boundary=regions[c.region_key]
   elseif c.kind=='country_cloud'then boundary=countryBoundary(c.boundary_key,c.continent)end
   if boundary then a=util.subtract(a,util.subtract(a,boundary))end
   local nets=codec.networks(a);assert(#nets>0,'细分库与所属地区没有交集：'..c.label)
   assert(#nets<=262144,'细分网段过多：'..c.label)
   local addresses=0;for _,n in ipairs(nets)do addresses=addresses+2^(32-n[2])end
   -- An existing list must not silently lose most of its coverage.
   if (p.previous.base_addresses or p.previous.addresses) then assert(addresses>=(p.previous.base_addresses or p.previous.addresses)*.25 and addresses<=(p.previous.base_addresses or p.previous.addresses)*4,'细分库覆盖变化过大：'..c.label)end
   write(dir..'/'..p.key..'.delta',codec.encode(nets))
   row={key=p.key,count=#nets,addresses=addresses,source=p.url,source_format=c.kind=='app_ip'and'ipv4_rules'or'cidr',updated=os.date('!%Y-%m-%d %H:%M:%S UTC'),filtered_addresses=before-addresses}
  else
   row=p.previous;write(dir..'/'..p.key..'.delta',read(custom..'/'..p.key..'.delta'))
  end
  if c.kind=='app_ip'then
   local previousRoot=os.getenv('REGION_PREVIOUS_ROOT')
   dofile('/usr/ikuai/script/region_app.lua').carry(row,p,previousRoot,dir,codec)
  end
  if p.exclude_url then row.exclude_source=p.exclude_url end
  row.sha256=codec.sha(dir..'/'..p.key..'.delta');rows[#rows+1]=row
  if p.fetch then total=total+row.count end
 end
 assert(total<=524288,'细分库合计超过 524288 个网段，请减少启用分组')
end
return M
