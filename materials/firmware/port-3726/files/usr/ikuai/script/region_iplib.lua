#!/usr/bin/ikluajit
-- Parse country archives without extracting paths or executing downloaded data.
local json=require('cjson')
local M={};local ambiguous_foreign_addresses=0;local base='/usr/share/strict-routing'
local keys={'cn','asia','europe','americas','oceania','africa','hk','mo','tw'}
local function read(p) local f=assert(io.open(p,'rb'));local s=f:read('*a');f:close();return s end
local function write(p,s) local f=assert(io.open(p,'wb'));assert(f:write(s));assert(f:close()) end
local function quote(s) return "'"..s:gsub("'","'\\''").."'" end
local function sha(p) local f=assert(io.popen('sha256sum '..quote(p)));local h=f:read('*l');f:close();assert(h and h:match('^[a-f0-9]+'));return h:sub(1,64) end
local function merge(a)
 table.sort(a,function(x,y)return x[1]<y[1] or x[1]==y[1] and x[2]<y[2] end)
 local out={}
 for _,v in ipairs(a) do local prev=out[#out];if prev and v[1]<=prev[2]+1 then prev[2]=math.max(prev[2],v[2]) else out[#out+1]={v[1],v[2]} end end
 return out
end
local function networks(ranges)
 local out={}
 for _,r in ipairs(ranges) do
  local start=r[1]
  while start<=r[2] do
   local size=1;while size<2147483648 and start%(size*2)==0 and start+size*2-1<=r[2] do size=size*2 end
   local prefix=32;local n=size;while n>1 do prefix=prefix-1;n=n/2 end
   out[#out+1]={start,prefix};start=start+size
  end
 end
 return out
end
local function netstr(n,p) return string.format('%d.%d.%d.%d/%d',math.floor(n/16777216),math.floor(n/65536)%256,math.floor(n/256)%256,n%256,p) end
local function decode(p,empty)
 local s=read(p);local pos,ip=1,0;local out={};local last=-1
 while pos<=#s do
  local delta,factor=0,1
  repeat local b=assert(s:byte(pos));pos=pos+1;delta=delta+b%128*factor;factor=factor*128;assert(factor<=34359738368,'oversized delta');if b<128 then break end until false
  ip=ip+delta;local prefix=assert(s:byte(pos));pos=pos+1
  assert(prefix>=1 and prefix<=32 and ip<=4294967295 and ip%2^(32-prefix)==0,'invalid network')
  assert(ip>last,'overlapping networks');last=ip+2^(32-prefix)-1
  out[#out+1]={ip,prefix};assert(#out<=262144,'too many networks')
 end
 assert(empty or #out>0,'empty region');return out
end
local function encode(a)
 local b={};local prev=0
 for _,n in ipairs(a) do
  local delta=n[1]-prev;prev=n[1]
  while delta>=128 do b[#b+1]=string.char(delta%128+128);delta=math.floor(delta/128) end
  b[#b+1]=string.char(delta,n[2])
 end
 return table.concat(b)
end
function M.verify(dir)
 local m=json.decode(read(dir..'/region-manifest.json'));assert(m.format==1 and type(m.version)=='string' and m.version:match('^[a-f0-9]+$') and #m.version==64,'invalid manifest')
 assert(#m.regions>=#keys and #m.regions<=4096,'missing regions');local identity={};local _,catalog=dofile('/usr/ikuai/script/region_detail.lua').catalog();local seen={}
 for i,row in ipairs(m.regions) do
  local key=row.key;assert(type(key)=='string' and not seen[key] and (i<=#keys and key==keys[i] or i>#keys and (catalog[key]or key=='foreign'or key:match('^user_[a-z0-9_]+$')and #key<=17)),'invalid region key');seen[key]=true;
  assert(row.key==key and row.sha256==sha(dir..'/'..key..'.delta'),'database checksum mismatch: '..key)
  local a=decode(dir..'/'..key..'.delta',key:match('^appip_')~=nil);local addresses=0
  for _,n in ipairs(a) do addresses=addresses+2^(32-n[2]) end
  assert(#a==row.count and addresses==row.addresses,'database count mismatch: '..key)
  identity[#identity+1]=key..':'..row.sha256..'\n'
  if row.base_sha256 then
   assert(catalog[key]and catalog[key].kind=='app_ip','manual changes require an application group')
   assert(row.base_sha256==sha(dir..'/'..key..'.base.delta')and row.manual_sha256==sha(dir..'/'..key..'.manual.json'),'manual database checksum mismatch')
   decode(dir..'/'..key..'.base.delta')
   identity[#identity+1]=key..':base:'..row.base_sha256..'\n'..key..':manual:'..row.manual_sha256..'\n'
  end
 end
 local pipe=assert(io.popen('printf %s '..quote(table.concat(identity))..' | sha256sum'));local hash=pipe:read('*l');pipe:close()
 assert(hash and hash:sub(1,64)==m.version,'invalid database version')
 return m
end
local function finish(regions,out,customdir)
 local original=json.decode(read(base..'/region-manifest.json'));local rows={};local identity={}
 local sources={}
 if customdir and customdir~=''then
  sources=json.decode(read(customdir..'/sources.json')).regions or {}
  regions=dofile('/usr/ikuai/script/region_custom.lua').apply(regions,sources,customdir)
 end
 for i,key in ipairs(keys) do
  local a=networks(regions[key]);assert(#a>=math.max(1,math.floor(original.regions[i].count/2)) and #a<=262144,'abnormal region size: '..key)
  local addresses=0;for _,n in ipairs(a) do addresses=addresses+2^(32-n[2]) end
  assert(addresses>=original.regions[i].addresses*.5 and addresses<=original.regions[i].addresses*1.5,'abnormal address coverage: '..key)
  local file=out..'/'..key..'.delta';write(file,encode(a));local hash=sha(file)
  rows[#rows+1]={key=key,count=#a,addresses=addresses,sha256=hash,source=sources[key]or'',source_format=sources[key]and sources[key]~=''and'cidr'or'country_tar_gz'};identity[#identity+1]=key..':'..hash..'\n'
 end
 local util=dofile('/usr/ikuai/script/region_custom.lua');local abroad=util.foreign(regions.cn)
 if sources.foreign and sources.foreign~=''then local requested=util.parse(customdir..'/foreign.txt','foreign');abroad=util.subtract(requested,util.subtract(requested,abroad))end
 local reuse=os.getenv('REGION_REUSE_ROOT');local oldForeign
 if reuse then local previous=json.decode(read(reuse..'/region-manifest.json'));for _,row in ipairs(previous.regions)do if row.key=='foreign'then oldForeign=row;abroad={};for _,n in ipairs(decode(reuse..'/foreign.delta'))do abroad[#abroad+1]={n[1],n[1]+2^(32-n[2])-1}end end end end
 local nets=networks(abroad);assert(#nets>0,'大陆以外源没有有效公网地址');local file=out..'/foreign.delta';write(file,encode(nets));local addresses=0;for _,n in ipairs(nets)do addresses=addresses+2^(32-n[2])end
 rows[#rows+1]={key='foreign',count=#nets,addresses=addresses,sha256=sha(file),source=oldForeign and oldForeign.source or sources.foreign or '',source_format='cidr'}
 dofile('/usr/ikuai/script/region_detail.lua').append(rows,out,customdir,regions,{networks=networks,encode=encode,decode=decode,sha=sha,netstr=netstr})
 identity={};for _,row in ipairs(rows)do identity[#identity+1]=row.key..':'..row.sha256..'\n';if row.base_sha256 then identity[#identity+1]=row.key..':base:'..row.base_sha256..'\n'..row.key..':manual:'..row.manual_sha256..'\n'end end
 write(out..'/identity',table.concat(identity));local version=sha(out..'/identity');os.remove(out..'/identity')
 write(out..'/region-manifest.json',json.encode({format=1,version=version,source=(os.getenv('REGION_ALL_CUSTOM')=='1'and'per-region HTTPS CIDR')or os.getenv('LIBRARY_SOURCE_URL') or 'https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz',created=os.date('!%Y-%m-%d %H:%M:%S UTC'),ambiguous_foreign_addresses=ambiguous_foreign_addresses,regions=rows})..'\n')
 M.verify(out);print(version)
end
function M.build(tarfile,out,customdir)
 if tarfile=='-'then
  local oldroot=os.getenv('REGION_REUSE_ROOT');if oldroot then ambiguous_foreign_addresses=json.decode(read(oldroot..'/region-manifest.json')).ambiguous_foreign_addresses or 0 end
  local regions={};for _,key in ipairs(keys)do local a={};for _,n in ipairs(decode((os.getenv('REGION_REUSE_ROOT')or base)..'/'..key..'.delta'))do a[#a+1]={n[1],n[1]+2^(32-n[2])-1}end;regions[key]=a end
  return finish(regions,out,customdir)
 end
 local raw=read(tarfile);assert(#raw<=16777216 and #raw%512==0,'invalid archive size')
 local countries={};local pos=1;local ended=false
 while pos+511<=#raw do
  local h=raw:sub(pos,pos+511);pos=pos+512
  if h==string.rep('\0',512) then ended=true;break end
  local sum=0;for i=1,512 do sum=sum+((i>=149 and i<=156) and 32 or h:byte(i)) end
  assert(sum==tonumber(h:sub(149,156):match('[0-7]+'),8),'invalid tar checksum')
  local name=h:sub(1,100):match('^[^%z]*'):gsub('^%./','');local prefix=h:sub(346,500):match('^[^%z]*')
  local size=tonumber(h:sub(125,136):match('[0-7]+'),8);assert(size and size<=8388608 and pos+size-1<=#raw,'invalid tar member')
  local kind=h:sub(157,157)
  if name=='.' or name=='' then assert(kind=='5' and size==0,'invalid archive directory')
  elseif name=='.zone' then
   assert(prefix=='' and kind=='0','invalid unassigned-country member')
  else
   assert(prefix=='' and name:match('^[a-z][a-z]%.zone$') and (kind=='0' or kind=='\0'),'unexpected archive member')
   local cc=name:sub(1,2);assert(not countries[cc],'duplicate country')
   local ranges={}
   for line in raw:sub(pos,pos+size-1):gmatch('[^\n]+') do
    line=line:gsub('\r$','')
    local a,b,c,d,p=line:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)/(%d+)$')
    assert(a and #a<=3 and #b<=3 and #c<=3 and #d<=3,'invalid CIDR in '..cc)
    a,b,c,d,p=tonumber(a),tonumber(b),tonumber(c),tonumber(d),tonumber(p)
    assert(a>0 and a<224 and b<256 and c<256 and d<256 and p>=1 and p<=32,'invalid IPv4 in '..cc)
    local n=((a*256+b)*256+c)*256+d;local span=2^(32-p);assert(n%span==0,'noncanonical CIDR in '..cc)
    for _,reserved in ipairs{{0,16777215},{167772160,184549375},{2130706432,2147483647},{2851995648,2852061183},{2886729728,2887778303},{3232235520,3232301055},{3758096384,4294967295}} do assert(n+span-1<reserved[1] or n>reserved[2],'non-public range in '..cc) end
    ranges[#ranges+1]={n,n+span-1};assert(#ranges<=262144,'oversized country')
   end
   assert(#ranges>0,'empty country');countries[cc]=merge(ranges)
  end
  pos=pos+math.ceil(size/512)*512
 end
 assert(ended,'truncated archive')
 for _,cc in ipairs(json.decode(read(base..'/region-countries.json'))) do assert(countries[cc],'missing country: '..cc) end
 -- Countries must not overlap. This also enforces mainland exclusion of HK/MO/TW.
 local groups=json.decode(read(base..'/regions.json'));local used={}
 for _,members in pairs(groups) do for cc in members:gmatch('%S+') do used[cc:lower()]=true end end
 local all={};for cc,a in pairs(countries) do if used[cc] then for _,v in ipairs(a) do all[#all+1]={v[1],v[2],cc} end end end
 table.sort(all,function(a,b)return a[1]<b[1] end)
 -- A provider may temporarily publish the same block under two foreign
 -- countries. Keep these addresses in the foreign total only; do not invent
 -- a country/continent owner. Any mainland overlap remains a hard failure.
 local ambiguity={};local far
 for _,v in ipairs(all)do
  if far and v[1]<=far[2]then
   assert(v[3]~='cn'and far[3]~='cn','overlapping mainland country: '..far[3]..'/'..v[3])
   ambiguity[#ambiguity+1]={v[1],math.min(v[2],far[2])}
  end
  if not far or v[2]>far[2]then far=v end
 end
 ambiguity=merge(ambiguity)
 local util=dofile('/usr/ikuai/script/region_custom.lua')
 for _,r in ipairs(ambiguity)do ambiguous_foreign_addresses=ambiguous_foreign_addresses+r[2]-r[1]+1 end
 if #ambiguity>0 then for cc,a in pairs(countries)do if used[cc]then countries[cc]=util.subtract(a,ambiguity)end end end
 local groups=json.decode(read(base..'/regions.json'));local regions={}
 for _,key in ipairs(keys)do local a={};for cc in groups[key]:gmatch('%S+')do for _,v in ipairs(countries[cc:lower()]or{})do a[#a+1]=v end end;regions[key]=merge(a)end
 return finish(regions,out,customdir)
end

function M.export(dir,out,alias,deleted)
 local excluded={};for name in (deleted or ""):gmatch("[^,]+") do excluded[name]=true end
 alias=alias or '';assert(alias=='' or #alias<=21 and alias:match('^[A-Za-z0-9_]+$'),'invalid legacy group')
 local m=M.verify(dir);local active={};for g in (os.getenv('RG_ACTIVE_GROUPS')or''):gmatch('[^,]+')do active[g]=true end
 local foreign=false;for _,row in ipairs(m.regions)do if row.key=='foreign'then foreign=true end end
 if not foreign then m.regions[#m.regions+1]={key='foreign',derived=true}end
 local sql={'.bail on','BEGIN IMMEDIATE;'};local restore={}
 for _,row in ipairs(m.regions) do
  local key=row.key;local group='geo_'..key;local pool={};local nets
  if row.derived then local ranges={};for _,n in ipairs(decode(dir..'/cn.delta'))do ranges[#ranges+1]={n[1],n[1]+2^(32-n[2])-1}end;nets=networks(dofile('/usr/ikuai/script/region_custom.lua').foreign(ranges))else nets=decode(dir..'/'..key..'.delta',key:match('^appip_')~=nil)end
  local optional=key~='cn'and key~='foreign';if optional and not active[group]and key~=(os.getenv('RG_RESTORE_KEY')or'')then excluded[group]=true end
  restore[#restore+1]='create rgstage_'..key..' hash:net family inet maxelem 262144\n'
  for _,n in ipairs(nets) do local cidr=netstr(n[1],n[2]);pool[#pool+1]=cidr;if not excluded[group] then restore[#restore+1]='add rgstage_'..key..' '..cidr..'\n' end end
  if not excluded[group] then
  local comment='Managed region IP library: '..key
  sql[#sql+1]="INSERT INTO ipgroup (group_name,addr_pool,comment,type) SELECT '"..group.."','','"..comment.."',0 WHERE NOT EXISTS(SELECT 1 FROM ipgroup WHERE group_name='"..group.."');"
  sql[#sql+1]="UPDATE ipgroup SET addr_pool='"..table.concat(pool,',').."',comment='"..comment.."',type=0 WHERE group_name='"..group.."';"
  end
  if key=='cn' and alias~='' then
   restore[#restore+1]='create rgstage_legacy hash:net family inet maxelem 262144\n'
   for _,cidr in ipairs(pool) do restore[#restore+1]='add rgstage_legacy '..cidr..'\n' end
   sql[#sql+1]="UPDATE ipgroup SET addr_pool='"..table.concat(pool,',').."',comment='Managed region IP library: cn (legacy alias)',type=0 WHERE group_name='"..alias.."';"
  end
 end
 if os.getenv('RG_RESTORE_DELETED')=='1' then sql[#sql+1]="DELETE FROM region_group_deleted WHERE group_name IN ('geo_cn','geo_foreign');" end
 local requested=os.getenv('RG_RESTORE_KEY')or'';if requested~=''then local _,catalog=dofile('/usr/ikuai/script/region_detail.lua').catalog();assert(catalog[requested]);sql[#sql+1]="DELETE FROM region_group_deleted WHERE group_name='geo_"..requested.."';"end
 sql[#sql+1]='COMMIT;';write(out..'/groups.sql',table.concat(sql,'\n')..'\n');write(out..'/groups.restore',table.concat(restore))
end
M.codec={decode=decode,encode=encode,networks=networks,netstr=netstr,sha=sha}
if arg and arg[1] then
 local ok,err=pcall(function()
  if arg[1]=='detail_plan'then dofile('/usr/ikuai/script/region_detail.lua').plan(arg[2],arg[3],arg[4],arg[5],arg[6])
  elseif arg[1]=='rename' then
   local target=arg[3];assert(target=='/etc/mnt/ikuai/region-iplib/current' or target=='/etc/mnt/ikuai/region-iplib/previous');assert(arg[2]:sub(1,#target+5)==target..'.new.' and arg[2]:sub(#target+6):match('^%d+$'));assert(os.rename(arg[2],target))
  elseif arg[1]=='state' then print(json.encode({state=arg[2],message=arg[3],time=arg[4]}))
  elseif arg[1]=='status' then
   local f=io.open(arg[3],'rb');local job={state='idle',message='尚未执行在线更新'};if f then job=json.decode(f:read('*a'));f:close() end
   if job.state=='running' and arg[5]~='true' then job={state='failed',message='更新已中断，当前库未完成切换时会回退'} end
   local manifest=json.decode(read(arg[2]));local found=false;for _,row in ipairs(manifest.regions)do if row.key=='foreign'then found=true end end
   if not found then local ranges={};for _,n in ipairs(decode(arg[2]:gsub('region%-manifest.json$','cn.delta')))do ranges[#ranges+1]={n[1],n[1]+2^(32-n[2])-1}end;local nets=networks(dofile('/usr/ikuai/script/region_custom.lua').foreign(ranges));manifest.regions[#manifest.regions+1]={key='foreign',count=#nets}end
   print(json.encode({manifest=manifest,job=job,can_rollback=arg[4]=='true',legacy_cn_group=arg[6] or ''}))
  elseif arg[1]=='build' then M.build(arg[2],arg[3],arg[4]) elseif arg[1]=='verify' then M.verify(arg[2]);print('valid') elseif arg[1]=='export' then M.export(arg[2],arg[3],arg[4],arg[5]) else error('unknown action') end
 end)
 if not ok then io.stderr:write(tostring(err),'\n');os.exit(1) end
end
M.decode=decode;M.networks=networks;M.netstr=netstr
return M
