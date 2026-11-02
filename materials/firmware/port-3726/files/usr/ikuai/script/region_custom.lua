-- Per-region CIDR sources. Never execute downloaded content.
local M={}
local reserved={{0,16777215},{167772160,184549375},{1681915904,1686110207},{2130706432,2147483647},{2851995648,2852061183},{2886729728,2887778303},{3221225472,3221225727},{3221225984,3221226239},{3227017984,3227018239},{3232235520,3232301055},{3323068416,3323199487},{3325256704,3325256959},{3405803776,3405804031},{3758096384,4294967295}}
local keys={'cn','asia','europe','americas','oceania','africa','hk','mo','tw'}
local function merge(a)
 table.sort(a,function(x,y)return x[1]<y[1]or x[1]==y[1]and x[2]<y[2]end)
 local out={};for _,v in ipairs(a)do local p=out[#out];if p and v[1]<=p[2]+1 then p[2]=math.max(p[2],v[2])else out[#out+1]={v[1],v[2]}end end;return out
end
local function union(...)
 local a={};for _,list in ipairs{...}do for _,r in ipairs(list)do a[#a+1]={r[1],r[2]}end end;return merge(a)
end
local function subtract(a,b)
 local out={};local k=1
 for _,r in ipairs(a)do
  local n=r[1];while k<=#b and b[k][2]<n do k=k+1 end;local i=k
  while i<=#b and b[i][1]<=r[2]do
   if b[i][1]>n then out[#out+1]={n,math.min(r[2],b[i][1]-1)}end
   n=math.max(n,b[i][2]+1);if n>r[2]then break end;i=i+1
  end
  if n<=r[2]then out[#out+1]={n,r[2]}end
 end;return out
end
local function parse(path,key,application)
 local f=assert(io.open(path,'rb'),'缺少地区下载文件：'..key);local raw=f:read('*a');f:close();assert(#raw<=4194304,'地区文件超过 4 MiB：'..key)
 -- Google's official service/cloud feeds use a bounded JSON prefix list.
 -- Only data fields are accepted; CIDRs still pass the same public-range
 -- and canonical-network validation as text sources below.
 if application and raw:match('^%s*{')then
  local data=require('cjson').decode(raw)
  assert(type(data)=='table'and type(data.prefixes)=='table','官方 IP JSON 格式无效：'..key)
  local lines={};local total=0
  for k,row in pairs(data.prefixes)do
   assert(type(k)=='number'and k%1==0 and k>=1 and k<=#data.prefixes and type(row)=='table','官方 IP 前缀格式无效：'..key)
   total=total+1;assert(total<=262144,'官方 IP 前缀过多')
   if row.ipv4Prefix~=nil then assert(type(row.ipv4Prefix)=='string','非法 IPv4 字段');lines[#lines+1]=row.ipv4Prefix
   else assert(type(row.ipv6Prefix)=='string'and row.ipv6Prefix:find(':',1,true),'缺少 IP 前缀')end
  end
  assert(total==#data.prefixes and #lines>0,'官方 IPv4 列表为空')
  raw=table.concat(lines,'\n')
 end
 local a={}
 for line in (raw..'\n'):gmatch('(.-)\n')do
  line=line:match('^%s*(.-)%s*$')
  if application and line~=''and not line:match('^#')then
   if line:match('^IP%-CIDR,')then
    local cidr,suffix=line:match('^IP%-CIDR,([^,]+)(.*)$');assert(cidr and(suffix==''or suffix==',no-resolve'),'应用 IP 规则格式无效：'..key);line=cidr
   elseif line:match('^[%x:]+/%d+$')and line:find(':',1,true)then line=''
   else
    local kind,value=line:match('^([A-Z%-0-9]+),(.+)$')
    local ignored={['DOMAIN']=true,['DOMAIN-SUFFIX']=true,['DOMAIN-KEYWORD']=true,['IP-CIDR6']=true,['IP-ASN']=true,['PROCESS-NAME']=true}
    if kind and ignored[kind]and value then line=''end
   end
  end
  if line~=''and not line:match('^#')then
   local A,B,C,D,p=line:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)/(%d+)$')
   assert(A and #A<=3 and #B<=3 and #C<=3 and #D<=3,'地区源必须每行一个 IPv4 CIDR：'..key)
   A,B,C,D,p=tonumber(A),tonumber(B),tonumber(C),tonumber(D),tonumber(p)
   assert(A>0 and A<224 and B<256 and C<256 and D<256 and p>=1 and p<=32,'非法 IPv4 CIDR：'..key)
   local n=((A*256+B)*256+C)*256+D;local span=2^(32-p);assert(n%span==0,'CIDR 不是网络地址：'..key)
   for _,r in ipairs(reserved)do assert(n+span-1<r[1]or n>r[2],'包含非公网地址：'..key)end
   a[#a+1]={n,n+span-1};assert(#a<=262144,'地区网段过多：'..key)
  end
 end
 assert(#a>0,'地区文件为空：'..key);return merge(a)
end
local function disjoint(a,b,left,right)
 local i,k=1,1
 while i<=#a and k<=#b do
  if a[i][2]<b[k][1]then i=i+1 elseif b[k][2]<a[i][1]then k=k+1 else error('地区源网段冲突：'..left..' / '..right)end
 end
end
function M.apply(regions,sources,dir)
 local baselineCN=union(regions.cn);local baselineHMT=union(regions.hk,regions.mo,regions.tw)
 local changed=false
 for _,key in ipairs(keys)do
  if sources and sources[key]and sources[key]~=''then regions[key]=parse(dir..'/'..key..'.txt',key);changed=true end
 end
 if not changed then return regions end
 disjoint(regions.hk,regions.mo,'香港','澳门');disjoint(regions.hk,regions.tw,'香港','台湾');disjoint(regions.mo,regions.tw,'澳门','台湾')
 local hmt=union(baselineHMT,regions.hk,regions.mo,regions.tw)
 local cn=union(baselineCN,regions.cn)
 regions.cn=subtract(regions.cn,hmt)
 regions.asia=union(subtract(regions.asia,cn),regions.hk,regions.mo,regions.tw)
 local continents={'cn','asia','europe','americas','oceania','africa'}
 for i=1,#continents do for k=i+1,#continents do local a,b=continents[i],continents[k];disjoint(regions[a],regions[b],a,b)end end
 return regions
end
function M.foreign(cn)

 return subtract(subtract({{0,4294967295}},merge(reserved)),cn)
end
M.parse=parse;M.subtract=subtract;M.merge=merge;M.disjoint=disjoint
return M
