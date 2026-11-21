#!/usr/bin/ikluajit
-- One-time migration from the previous independent policy into native rows.
local j=require('cjson');local function read(p)local f=assert(io.open(p));local x=j.decode(f:read('*a'));f:close();return x end
local function write(p,s)local f=assert(io.open(p,'w'));assert(f:write(s));f:close()end
local function quote(x)return "'"..tostring(x):gsub("'","''").."'"end
local function ip(s)local n=0;for x in s:gmatch('%d+')do n=n*256+tonumber(x)end;return n end
local function network(s)local a,b=s:match('^([^/]+)/(%d+)$');assert(a and b);b=tonumber(b);return math.floor(ip(a)/2^(32-b))*2^(32-b),b end
local function intersect(a,b)if not b or b==''then return a end;local x,p=network(a);local y,q=network(b);local min=math.min(p,q);if math.floor(x/2^(32-min))~=math.floor(y/2^(32-min))then return end;return p>q and a or b end
local function main()
 local c=read(arg[1]);assert(c.version==1 and c.enabled);local settings=read(arg[2]);local out=arg[3];local ex={};for _,e in ipairs(c.exits)do ex[e.id]=e end
 local sql={'BEGIN;','create table if not exists native_migration_state (version integer primary key);'}
 sql[#sql+1]='update stream_ipport set id=-id;';sql[#sql+1]='update stream_ipport set id=10000-id;'
 sql[#sql+1]='update stream_domain set id=-id;';sql[#sql+1]='update stream_domain set id=10000-id;'
 if c.domain_unified then sql[#sql+1]="update stream_domain set enabled='no';"end
 local pid,did=0,0
 local function insert(tablename,t)
  local cols,vals={},{};for k,v in pairs(t)do cols[#cols+1]=k;vals[#vals+1]=quote(v)end
  sql[#sql+1]='insert into '..tablename..'('..table.concat(cols,',')..') values ('..table.concat(vals,',')..');'
 end
 local function dom(scope,group,domains,exit,dnsexit,mode,comment)
  did=did+1;assert(did<10000);local e=assert(ex[dnsexit]);assert(exit=='geo' or exit==dnsexit,'旧域名访问出口和 DNS 出口不同，请先统一后再升级')
  insert('stream_domain',{id=did,enabled='yes',domain=domains or 'group.invalid',nr_group=group,nr_route=mode,nr_dns=e.dns,interface=e.interface,src_addr=scope.source,nr_ingress=scope.interface,week='1234567',time='00:00-23:59',comment=comment})
 end
 local function port(scope,r,stage,comment)
  local src=intersect(scope.source,r.source);if not src then return end
  assert(r.region~='unknown','旧未知地区规则需要先改为明确的原生 IP 分组')
  pid=pid+1;assert(pid<10000)
  insert('stream_ipport',{id=pid,enabled='yes',type=0,interface=r.exit==0 and 'blackhole' or assert(ex[r.exit]).interface,src_addr=src,nr_ingress=scope.interface,dst_addr=r.region and r.region~='any'and 'geo_'..r.region or '',protocol=r.protocol=='both'and'tcp+udp'or(r.protocol or'any'),src_port='',dst_port=r.ports or'',week='1234567',time='00:00-23:59',nr_stage=stage,comment=comment})
 end
 for _,scope in ipairs(c.scopes)do
  for _,r in ipairs(c.rules)do if r.kind=='domain'then dom(scope,'manual',table.concat(r.domains,','),r.exit,r.exit,'fixed','迁移：手动域名')elseif r.kind=='port'then port(scope,r,0,'迁移：端口规则')else port(scope,r,1,'迁移：地区规则')end end
  for _,g in ipairs{'cn','foreign'}do local e=c[g..'_exit'];assert(e~=0,'旧域名组禁止联网策略需要先调整后再升级');dom(scope,g,nil,e,c[g..'_dns'],e=='geo'and'dns_only'or'fixed','迁移：域名与DNS分组')end
  port(scope,{exit=c.default_exit},2,'迁移：未匹配流量')
 end
 settings.domain_overrides=c.domain_overrides or {};settings.foreign_domains=c.foreign_domains or {};settings.legacy_protected=c.protected;settings.legacy_scopes=c.scopes
 sql[#sql+1]='insert into native_migration_state values(1);';sql[#sql+1]='COMMIT;'
 write(out..'/migration.sql',table.concat(sql,'\n')..'\n');write(out..'/settings.json',j.encode(settings))
end
local ok,e=pcall(main);if not ok then io.stderr:write(tostring(e),'\n');os.exit(1)end
