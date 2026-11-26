#!/usr/bin/ikluajit
-- Serialized resident compiler. Serving DNS/forwarding never waits on this
-- socket. Callers own STATE/lock until a complete candidate is verified.
local ffi=require('ffi')
ffi.cdef[[
 int socket(int,int,int); int bind(int,const void*,unsigned); int listen(int,int);
 int accept(int,void*,void*); long recv(int,void*,unsigned long,int);
 long send(int,const void*,unsigned long,int); int close(int); int unlink(const char*);
 int open(const char*,int,...); int flock(int,int); int getpid(void); unsigned int umask(unsigned int);
 int setsockopt(int,int,int,const void*,unsigned); int getsockopt(int,int,int,void*,unsigned*);
 struct sockaddr_un {unsigned short family;char path[108];};
 struct timeval {long sec;long usec;}; struct ucred {int pid;unsigned uid;unsigned gid;};
]]
local C=ffi.C;local root='/tmp/iktmp/native-rules';local path=root..'/compiler.sock'
-- Keep the flock descriptor alive until process exit.
local fdlock=C.open(root..'/compiler.lock',66,ffi.new('unsigned int',384));assert(fdlock>=0);assert(C.flock(fdlock,6)==0,'compiler already running')
local socket=C.socket(1,5,0);assert(socket>=0)
local address=ffi.new('struct sockaddr_un');address.family=1;ffi.copy(address.path,path)
C.unlink(path);local mask=C.umask(63);local bound=C.bind(socket,address,ffi.sizeof(address));C.umask(mask);assert(bound==0 and C.listen(socket,8)==0)
local version=assert(io.open(root..'/compiler.signature','w'));version:write(os.getenv('NATIVE_COMPILER_SIGNATURE')or'unknown','\n');version:close()
local f=assert(io.open(root..'/compiler.pid','w'));f:write(C.getpid(),'\n');f:close()
local compiler=dofile('/usr/ikuai/script/native_rules.lua')
local buffer=ffi.new('char[4096]');local cred=ffi.new('struct ucred');local credsize=ffi.new('unsigned[1]',ffi.sizeof(cred))
local timeout=ffi.new('struct timeval',{10,0})
while true do
 local fd=C.accept(socket,nil,nil)
 if fd>=0 then
  C.setsockopt(fd,1,20,timeout,ffi.sizeof(timeout));C.setsockopt(fd,1,21,timeout,ffi.sizeof(timeout))
  credsize[0]=ffi.sizeof(cred)
  local response='ERR unauthorized\n'
  if C.getsockopt(fd,1,17,cred,credsize)==0 and cred.uid==0 then
   local n=C.recv(fd,buffer,4095,32);response='ERR request\n'
   if n>0 and n<4096 then
    local request=ffi.string(buffer,n);local fields={};for word in request:gmatch('%S+')do fields[#fields+1]=word end
    if #fields==6 and fields[1]=='COMPILE'and fields[2]:match('^[%w_-]+$')then
     local dir,live,domainroot,cache=unpack(fields,3)
     -- Only transaction-private output; never allow a request to overwrite active.
     if dir==root..'/candidate'and live==root..'/active'and domainroot:sub(1,1)=='/'and cache==root..'/domain-decoded.json'then
      local started=os.clock()
      local ok,e=pcall(compiler.compile,{dir=dir,live=live,root=domainroot,cache=cache})
      response=ok and 'OK compiled\n'or 'ERR '..tostring(e):gsub('[\r\n]',' '):sub(1,220)..'\n'
      local stat=io.open(dir..'/compiler-time','w');if stat then stat:write(string.format('%.6f\n',os.clock()-started));stat:close()end
      -- Bound transient JSON and old generations between jobs.
      collectgarbage('collect')
     end
    end
   end
  end
  C.send(fd,response,#response,16384);C.close(fd)
 end
end
