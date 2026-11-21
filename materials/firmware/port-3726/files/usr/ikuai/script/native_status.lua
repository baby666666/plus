-- Read-only, bounded routing diagnostics. No probes, configuration or key dumps.
local json=require('cjson')
local NR='/tmp/iktmp/native-rules'
local READ_LIMIT,COMMAND_LIMIT=32768,65536
local function collect(d,busy)
 local function bounded(s,limit)if type(s)=='string'and #s<=limit then return s end end
 local function read_path(path)return bounded(d.read(path),READ_LIMIT)end
 local function read(name)return read_path(NR..'/'..name)end
 local function command(cmd)return bounded(d.command(cmd),COMMAND_LIMIT)end
 local function exists(name)return d.exists(NR..'/'..name)end
 local function lines(s)local t={};for line in (s or ''):gmatch('[^\n]+')do t[#t+1]=line end;return t end
 local function uint(s,max)local n=tonumber(s);if n and n>=0 and n==math.floor(n)and n<=(max or 4294967295)then return n end end
 local now=uint((read_path('/proc/uptime')or''):match('^(%d+)'))
 local epoch=uint(d.time())
 local out={version=1,phase='unknown',busy=busy==true,guard='unknown',reasons={},exits={},workers={},quarantine={available=false,window_seconds=61}}
 local flags={{'boot.pending','starting'},{'commit.pending','applying'},{'native-stage.pending','protected'},{'native-dirty','protected'},{'policy-reconcile.failed','protected'}}
 for _,flag in ipairs(flags)do if exists(flag[1])then out.reasons[#out.reasons+1]=flag[1];if out.phase=='unknown'then out.phase=flag[2]end end end
 if busy then out.phase=out.phase=='unknown'and'busy'or out.phase;return out end
 local guarded,guard_known=false,true
 for _,chain in ipairs{{'iptables -t mangle -S NR_GUARD 2>/dev/null','NR_GUARD'},{'iptables -S NR_FORWARD_GUARD 2>/dev/null','NR_FORWARD_GUARD'},{'iptables -S NR_OUT_GUARD 2>/dev/null','NR_OUT_GUARD'}}do
  local text=command(chain[1]);local declared=false
  for _,line in ipairs(lines(text))do
   line=line:gsub('^%[fastid: %d+%] +','')
   if line=='-N '..chain[2]then declared=true
   elseif line:sub(1,#chain[2]+4)=='-A '..chain[2]..' 'then
    if(line..' '):find(' %-j DROP%s')then guarded=true end
   else guard_known=false end
  end
  if not text or not declared then guard_known=false end
 end
 out.guard=guarded and'active'or(guard_known and'clear'or'unknown')
 if not guard_known then out.reasons[#out.reasons+1]='guard_status_unavailable'end
 if guarded then out.reasons[#out.reasons+1]='forwarding_guard';if out.phase=='unknown'then out.phase='protected'end end
 if out.phase=='unknown'and guard_known then out.phase=exists('active/snapshot.json')and'running'or'inactive'end
 local function process(file,expected)
  local pid=uint((read(file)or''):match('^%s*(%d+)%s*$'),4194304)
  if not pid or pid==0 then return 'stopped'end
  local text=read_path('/proc/'..pid..'/cmdline')
  if not text then return 'unknown'end
  local executable=(text:match('^([^%z]+)')or''):match('([^/]+)$')
  if executable==expected then return 'running'end
  return 'stopped'
 end
 out.dns_front=process('active/front.pid','native-rule-dns')
 local health={}
 for _,line in ipairs(lines(read('exit-health-cache')))do
  local id,sig,stamp,value=line:match('^(%d+) (%x+) (%d+) ([01])$')
  id=uint(id,132);stamp=uint(stamp)
  if id and stamp and now and stamp>0 and stamp<=now and now-stamp<=60 then
   health[id]={health=value=='1'and'reachable'or'failed',probe_age_seconds=now-stamp}
  end
 end
 for _,line in ipairs(lines(read('exits')))do
  local id,iface,dev,available=line:match('^(%d+) ([%w_.-]+) ([%w_.-]+) ([01])$')
  id=uint(id,132)
  if id and id>0 and #out.exits<132 and #iface<=32 and #dev<=32 then
   local row={id=id,interface=iface,available=available=='1',health='unknown'}
   if health[id]then for k,v in pairs(health[id])do row[k]=v end end
   if iface:match('^wg%d+$')then
    local latest=0;local text=command('wg show '..iface..' latest-handshakes 2>/dev/null')
    for _,item in ipairs(lines(text))do local n=uint(item:match('%s(%d+)$'));if n and n>latest then latest=n end end
    if text and epoch and latest>0 and latest<=epoch then row.handshake_age_seconds=epoch-latest end
   end
   out.exits[#out.exits+1]=row
  end
 end
 for _,line in ipairs(lines(read('policy-workers')))do
  local id,policy,dns=line:match('^(%d+) (%d+) ([%d.]+)$');id=uint(id,32);policy=uint(policy,65535)
  if id and id>0 and policy and #dns<=15 and #out.workers<32 then
   local state=read('worker-state/'..id)
   local target=state and state:match('^([%w_.-]+) ')
   local row={id=id,policy=policy,dns=dns,process=process('active/dns-'..id..'.pid','strict-dnsmasq'),state='unknown'}
   if state and state:match('^%s+%d+ ')then row.state='blocked'
   elseif target and #target<=32 then row.state='selected';row.interface=target end
   out.workers[#out.workers+1]=row
  end
 end
 local terse=command('ipset list nr_quarantine -terse 2>/dev/null')
 local entries=terse and uint(terse:match('Number of entries:%s*(%d+)'),262144)
 if entries then
  out.quarantine.available=true;out.quarantine.entries=entries
  local until_at=uint((read('quarantine-window')or''):match('^(%d+)%s*$'))
  if entries==0 then out.quarantine.remaining_seconds=0
  elseif until_at and now and until_at>=now and until_at-now<=62 then out.quarantine.remaining_seconds=math.min(61,until_at-now) end
 end
 return out
end
local function read(path)
 local f=io.open(path,'rb');if not f then return nil end
 local s=f:read(READ_LIMIT);local extra=f:read(1);f:close()
 if extra then return nil end
 return s
end
local function command(cmd)
 -- Lua 5.1 pclose reports only that waitpid succeeded, not the child status.
 -- Capture the fixed command's exit status in-band and discard its trailer.
 local opened,p=pcall(io.popen,cmd.."; printf '\\n__NR_STATUS_RC:%s\\n' \"$?\"")
 if not opened or not p then return nil end
 local text=p:read(COMMAND_LIMIT+64);local extra=p:read(1);local ok=p:close()
 if extra or not(ok==true or ok==0)then return nil end
 text=text and text:match('^(.*)\n__NR_STATUS_RC:0\n$')
 if not text or #text>COMMAND_LIMIT then return nil end
 return text
end
if _G.NATIVE_STATUS_TEST then return {collect=collect,read=read,command=command}end
local deps={read=read,command=command,time=os.time,exists=function(path)local f=io.open(path,'rb');if f then f:close();return true end;return false end}
io.write(json.encode(collect(deps,arg[1]=='busy')))
