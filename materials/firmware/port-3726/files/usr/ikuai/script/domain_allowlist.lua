#!/usr/bin/ikluajit
-- Both online regional libraries are active. Saved manual entries override
-- classification; an empty manual list never disables either online library.
local j=require('cjson');local M={}
function M.normalize(c,lib)
 if c.encrypted_dns~=nil then c.encrypted_dns=dofile('/usr/ikuai/script/encrypted_dns.lua').normalize(c.encrypted_dns)end
 local manual=lib.manual(c)
 if c.foreign_policy~='library'and c.foreign_allowlist~=nil then
  local a=c.foreign_allowlist;assert(type(a)=='table'and #a<=20000,'旧海外名单无效')
  for k in pairs(a)do assert(type(k)=='number'and k%1==0 and k>=1 and k<=#a,'旧海外名单格式无效')end
  for _,name in ipairs(a)do assert(lib.valid(name,false),'旧海外域名无效');if not manual[name]then manual[name]='foreign'end end
 end
 local names={};for name in pairs(manual)do names[#names+1]=name end;table.sort(names);assert(#names<=20000,'手动域名最多 20000 条')
 c.domain_overrides={};for _,name in ipairs(names)do c.domain_overrides[#c.domain_overrides+1]={domain=name,group=manual[name]}end
 c.foreign_domains={};c.foreign_allowlist=nil;c.foreign_policy_status=nil;c.foreign_policy='library';c.version=3
 return c,manual
end
function M.encode(c)
 local s=j.encode(c)
 for _,key in ipairs{'foreign_domains','domain_overrides','legacy_scopes','legacy_protected','sources','exceptions','allowed','custom'}do
  s=s:gsub('"'..key..'":{}','"'..key..'":[]')
 end
 return s
end
if arg and arg[0]and arg[0]:match('/domain_allowlist%.lua$')then
 local ok,e=pcall(function()
  assert(arg[1]=='show'or arg[1]=='normalize');local path=arg[1]=='show'and'/etc/mnt/ikuai/native-routing.json'or assert(arg[2])
  local f=assert(io.open(path));local c=j.decode(f:read('*a'));f:close()
  if arg[1]=='normalize'then assert(c.foreign_policy=='library'and c.foreign_allowlist==nil,'页面版本已变化，请刷新后重试')end
  c=M.normalize(c,dofile('/usr/ikuai/script/domain_lib.lua'));local s=M.encode(c)
  if arg[1]=='show'then print(s)else local o=assert(io.open(assert(arg[3]),'w'));assert(o:write(s..'\n'));assert(o:close())end
 end);if not ok then io.stderr:write(tostring(e),'\n');os.exit(1)end
end
return M
