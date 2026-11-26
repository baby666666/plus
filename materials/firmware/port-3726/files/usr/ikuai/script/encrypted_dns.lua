-- Optional IPv4 client restriction. No DNS lookup or online list expansion.
local M={}
M.builtin={'1.1.1.1','1.0.0.1','1.1.1.2','1.0.0.2','1.1.1.3','1.0.0.3','8.8.8.8','8.8.4.4'}
local function keys(t,allowed)
 assert(type(t)=='table','加密 DNS 设置格式无效')
 for k in pairs(t)do assert(allowed[k],'加密 DNS 设置包含未知字段')end
end
local function address(v,net)
 assert(type(v)=='string'and #v<=18,'请填写 IPv4 地址或网段')
 local ip,bits=v:match('^([^/]+)/(%d+)$')
 if not ip then ip=v;bits=32 end
 bits=tonumber(bits);assert(bits and bits>=0 and bits<=32,'IPv4 网段前缀无效')
 assert(net or bits==32,'DNS 服务地址只能填写单个 IPv4，不能填写网段')
 local a,b,c,d=ip:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$');assert(a,'请填写 IPv4 地址或网段')
 local n=0;for _,x in ipairs{a,b,c,d}do assert(#x<=3 and tonumber(x)<256,'IPv4 地址无效');n=n*256+tonumber(x)end
 if not net then assert(n>0 and n<3758096384,'DNS 服务地址无效')end
 local size=2^(32-bits);n=math.floor(n/size)*size
 local s=string.format('%d.%d.%d.%d',math.floor(n/16777216),math.floor(n/65536)%256,math.floor(n/256)%256,n%256)
 return s..(net and '/'..bits or '')
end
local function addresses(t,net,limit)
 assert(type(t)=='table'and #t<=limit,'地址列表格式无效或超过上限')
 local count=0;for k in pairs(t)do count=count+1;assert(type(k)=='number'and k>=1 and k<=#t and k%1==0,'地址必须是连续数组')end
 assert(count==#t,'地址必须是连续数组')
 local out,seen={},{};for _,v in ipairs(t)do local s=address(v,net);assert(not seen[s],'地址列表存在重复项');seen[s]=true;out[#out+1]=s end
 table.sort(out);return out
end
function M.normalize(c)
 if c==nil then c={enabled=false,ingress='',sources={},exceptions={},allowed={},custom={},dot=true,doh=true,builtin=true}end
 keys(c,{enabled=true,ingress=true,sources=true,exceptions=true,allowed=true,custom=true,dot=true,doh=true,builtin=true})
 local out={}
 for _,k in ipairs{'enabled','dot','doh','builtin'}do assert(type(c[k])=='boolean','加密 DNS 开关值无效');out[k]=c[k]end
 local dev=c.ingress;assert(type(dev)=='string'and #dev<=15,'入接口无效')
 -- Only client-facing interface names. No wildcard or WAN scope.
 assert(dev==''or dev=='sovpn'or dev:match('^lan%d+$')or dev:match('^vlan%d+$')or dev:match('^ppp%d+$')or dev:match('^wg%d+$')or dev:match('^tap%d+$')or dev:match('^sdwan%d+$')or dev:match('^ikec%d+$')or dev:match('^doc_[%w_]+$'),'入接口请填写 LAN、WG 或客户端隧道接口名称')
 out.ingress=dev
 for _,k in ipairs{'sources','exceptions','allowed','custom'}do out[k]=addresses(c[k],k=='sources'or k=='exceptions',k=='custom'and 128 or 64)end
 if out.enabled then
  assert(#out.sources>0 or dev~='','启用时必须填写来源地址或入接口')
  assert(out.dot or out.doh,'至少选择一种加密 DNS 限制')
  assert(not out.doh or out.builtin or #out.custom>0,'限制 DoH 时请选择内置服务或填写服务 IP')
 end
 return out
end
local function quote(s)return "'"..s:gsub("'","'\\''").."'"end
function M.command(c)
 c=M.normalize(c);if not c.enabled then return 'nr_encrypted_dns_off' end
 local dest,seen={},{};for _,list in ipairs{c.builtin and M.builtin or {},c.custom}do for _,ip in ipairs(list)do if not seen[ip]then dest[#dest+1]=ip;seen[ip]=true end end end;table.sort(dest)
 return 'nr_encrypted_dns '..table.concat({quote(table.concat(c.sources,'\n')),quote(c.ingress),quote(table.concat(c.exceptions,'\n')),quote(table.concat(c.allowed,'\n')),quote(table.concat(dest,'\n')),c.dot and '1'or'0',c.doh and '1'or'0'},' ')
end
return M
