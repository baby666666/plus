local json=require('cjson')
local function check(v,msg) assert(v,msg) end
local function number(v,lo,hi) check(type(v)=='number' and v==math.floor(v) and v>=lo and v<=hi,'额度数值超出范围');return v end
local function cidr(v)
 check(type(v)=='string' and #v<=32,'IP/网段格式错误')
 local ip,p=v:match('^([^/]+)/(%d+)$');if not ip then ip=v;p=32 end
 p=tonumber(p);check(p and p>=0 and p<=32,'网段前缀应为 0–32')
 local a,b,c,d=ip:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$');check(a,'请填写 IPv4 地址或网段')
 a,b,c,d=tonumber(a),tonumber(b),tonumber(c),tonumber(d);check(a<256 and b<256 and c<256 and d<256,'IPv4 地址无效')
 local n=((a*256+b)*256+c)*256+d;local size=2^(32-p);n=math.floor(n/size)*size
 return string.format('%d.%d.%d.%d/%d',math.floor(n/16777216),math.floor(n/65536)%256,math.floor(n/256)%256,n%256,p)
end
local function validate(cfg)
 check(type(cfg)=='table' and type(cfg.rules)=='table','配置格式错误');check(#cfg.rules<=64,'最多 64 条来源设置')
 for k in pairs(cfg)do check(k=='rules','未知配置字段')end
 local count=0;for k in pairs(cfg.rules)do count=count+1;check(type(k)=='number' and k>=1 and k<=#cfg.rules and k==math.floor(k),'规则必须是数组')end;check(count==#cfg.rules,'规则数组不连续')
 local seen={};local lines={'v1'}
 for _,r in ipairs(cfg.rules)do
  check(type(r)=='table','来源设置格式错误');for k in pairs(r)do check(k=='cidr' or k=='enabled' or k=='concurrency' or k=='rate' or k=='burst','未知规则字段')end
  r.cidr=cidr(r.cidr);check(not seen[r.cidr],'同一 IP/网段不能重复');seen[r.cidr]=true
  check(type(r.enabled)=='boolean','启用状态无效');number(r.concurrency,1,384);number(r.rate,1,4096);number(r.burst,r.rate,8192)
  lines[#lines+1]=string.format('%s %d %d %d %d',r.cidr,r.enabled and 1 or 0,r.concurrency,r.rate,r.burst)
 end
 return table.concat(lines,'\n')..'\n'
end
local function read(path)
 local f=io.open(path,'rb');if not f then return {rules={}} end
 local s=f:read(8193);f:close();check(#s<=8192,'配置过大');check(s:sub(1,3)=='v1\n','配置版本无效')
 local cfg={rules={}};for line in s:sub(4):gmatch('[^\n]+')do
  local ip,en,cap,rate,burst=line:match('^(%S+) ([01]) (%d+) (%d+) (%d+)$');check(ip,'保存的配置格式错误')
  cfg.rules[#cfg.rules+1]={cidr=ip,enabled=en=='1',concurrency=tonumber(cap),rate=tonumber(rate),burst=tonumber(burst)}
 end
 validate(cfg);return cfg
end
if arg[1]=='prepare' then
 local f=assert(io.open(arg[2],'rb'));local raw=f:read(32769);f:close();check(#raw<=32768,'请求过大')
 local data=validate(json.decode(raw));local o=assert(io.open(arg[3],'wb'));assert(o:write(data));assert(o:close())
elseif arg[1]=='status' then
 local stats={};for k,v in (arg[4]or''):gmatch('([a-z_]+)=(%d+)')do stats[k]=tonumber(v)end
 print(json.encode({config=read(arg[2]),revision=arg[3],running=(arg[4]or''):sub(1,3)=='OK ',stats=stats,global_max=512,default_enabled=false}))
end
