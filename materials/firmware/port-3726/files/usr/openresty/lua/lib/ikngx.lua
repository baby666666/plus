
local shell = require "resty.shell"
local M = { cache={}, cookie={} }

local __DEBUG__  = false
local str_gsub   = string.gsub
local str_match  = string.match
local str_gmatch = string.gmatch
local str_find   = string.find
local str_format = string.format
local ffi = require "ffi"
local C = ffi.C

ffi.cdef [[
	typedef unsigned mode_t;
	int printf(const char *format, ...);
	int access(const char *pathname, int mode);

	struct timeval {
		unsigned long tv_sec;
		unsigned long tv_usec;
		};
	int gettimeofday(struct timeval *tv, void *tz);
	int utimes(const char *filename, const struct timeval times[2]);
	int mkdir(const char *pathname, mode_t mode);
	ssize_t readlink(const char *path, char *buf, size_t bufsiz);
]]

local ffi_tostring = ffi.string
local buf_size = 2048
local buf = ffi.new("char [?]", buf_size)

function M.readlink(path)
	local size = C.readlink(path, buf, buf_size)
        if size >= 0 then
		return ffi_tostring(buf, size)
        end
end

--usage: 
--     cookie = ikngx.cookie.new()
--     cookie:set({key="sess", value="123", path="/", domain="example.com", expires="Wed, 09 Jun 2021 10:18:14 GMT", max_age=50})
function M.cookie:set(tab)
	local cookie
	local k, v

	if not tab.key or not tab.value then
		return
	else
		cookie = tab.key .."=".. tab.value .."; "
	end

	if tab["domain"] then
		cookie = cookie .. "domain=" .. tab["domain"] .."; "
	end

	if tab["path"] then
		cookie = cookie .. "path=" .. tab["path"] .."; "
	end

	if tab["expires"] then
		cookie = cookie .. "expires=" .. tab["expires"] .. "; "
	end

	if tab["max_age"] then
		cookie = cookie .. "max-age=" .. tab["max_age"] .."; "
	end


 if tab.http_only then cookie=cookie.."HttpOnly; " end
 if tab.secure then cookie=cookie.."Secure; " end
 if tab.same_site=="Strict" or tab.same_site=="Lax" then cookie=cookie.."SameSite="..tab.same_site.."; " end
	table.insert(self.res_cookies, cookie)
	ngx.header["Set-Cookie"] = self.res_cookies
end


--usage: 
--     cookie = ikngx.cookie.new()
--     cookie:get("sess_key")
function M.cookie:get(key)
	return self.req_cookies[key]
end

--获取当前请求的cookie
--    cookies = ikngx.cookie.get_req_cookies()
--    ngx.say(cookies["sess_key"])
function M.cookie.get_req_cookies()
	local t = {}
	if ngx.var.http_cookie then
		str_gsub(ngx.var.http_cookie, "([^ ;]+)=([^;]+)", function (k, v) t[k] = v end)
	end
	return t
end

function M.cookie.new()
	return { set = M.cookie.set, res_cookies = {}, get = M.cookie.get, req_cookies = M.cookie.get_req_cookies()}
end

--自动获得一个全局cache, worker内的全局cache
function M.global_cache(key)
	if not M.cache[key] then
		M.cache[key] = {}
	end
	return M.cache[key]
end

--输出table内容
function M.dumptab(tab)
	if type(tab) ~= "table" then return end
	local t,v
	for k,v in pairs(tab) do
		local T = type(v)
		if T == "function" or T == "table" then
			ngx.say(str_format("%s = %s",k,T))
		else
			ngx.say(str_format("%s = %s",k,v))
		end
	end
end

--输出系统日志
local function shell_quote(value)
	value = tostring(value or "")
	return "'" .. value:gsub("'", "'\"'\"'") .. "'"
end

function M.logger(progress, content)
	if not progress or not content then
		return false
	end

	os.execute(str_format("logger -t %s %s >/dev/null 2>&1 &",
		shell_quote(progress), shell_quote(content)))
	return true
end

--判断文件是否存在
function M.file_exists(path)
	return C.access(path,0) == 0
end

--读取一个文件全部内容, 或者某一行
function M.readfile(file, line_n)
	local f = io.open(file)
	local data
	if f then
		if line_n and line_n > 0 then
			local n = 0
			for line in f:lines() do
				n = n + 1
				if n == line_n then
					data = line
					break
				end
			end
		else
			data = f:read("*a")
		end
		f:close()
	end

	return data
end

function M.writefile(data, file, m)
	local f = io.open(file, m or "w")
	if f then
		f:write(data)
		f:close()
		return true
	else
		return false
	end
end

function M.ip2int(ip)
	local ipnum=0
	local n=4
	str_gsub(ip,"([0-9]+)", function(i) n = n-1 ipnum = ipnum + i*256^n end)
	return ipnum
end

---0x01FF == 0777
function M.mkdir(pathname)
	return C.mkdir(pathname, 0x01FF) == 0
end
function M.split(str, delimiter)
	if str==nil or str=='' or delimiter==nil then
		return nil
	end
	local result = {}

	local __find = str:match(delimiter)

	if not __find then
		table.insert(result, str)
	else
		local s = str .. __find
		for r in s:gmatch("(.-)"..delimiter) do
			table.insert(result, r)
		end
	end
	return result
end


--发送错误消息
function M.senderror(codeid, errmsg, extend)
	local t = {}
	ngx.header["Content-Type"]  = "application/json"
	if codeid == 10000 then	errmsg = "Success" end
	if not errmsg then errmsg = "" end

	local t = {Result=codeid, ErrMsg=errmsg}
	--扩展其他的字段信息, 追加到后面
	if type(extend) == "table" then
		for k,v in pairs(extend) do
			t[k] = v
		end
	end

	ngx.print(cjson.encode(t))
	ngx.exit(0)
end

--发送错误消息
function M.senderror2(codeid, errmsg, extend)
	local t = {}
	ngx.header["Content-Type"]  = "application/json"
	if codeid == 10000 then	errmsg = "Success" end
	if not errmsg then errmsg = "" end

	local t = {Result=codeid, ErrMsg=errmsg}
	--扩展其他的字段信息, 追加到后面
	if type(extend) == "table" then
		for k,v in pairs(extend) do
			t[k] = v
		end
	end

	local buf = cjson.encode(t)
	ngx.header["Content-Length"] = #buf

	ngx.print(buf)
	ngx.exit(0)
end

function M.get_mac(ipaddr)
	local mac
	local iface
	if C.access("/tmp/iktmp/webauth/bypass_enabled", 0) == 0 then
		local f = io.open('/proc/ikuai/stats/host_stats')
		if f then
			for line in f:lines() do
				local ip, macaddr = str_match(line, "^(%d+%.%d+%.%d+%.%d+) +([^ ]+) +[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+")
				if ipaddr == ip then
					mac = macaddr
					break
				end
			end
			f:close()
		end
		return mac or nil,nil
	end

	local f = io.open('/proc/net/arp')
	if f then
		for line in f:lines() do
			local ip,flag,macaddr,interface = str_match(line, "^(%d+%.%d+%.%d+%.%d+) +[^ ]+ +([^ ]+) +([^ ]+) +[^ ]+ +([^ ]+)")
			if ipaddr == ip and flag ~= "0x0" then
				mac = macaddr
				iface = interface
				break
			end
		end
		f:close()
	end
	if C.access("/tmp/iktmp/cache/snmp_ipauth/is_enabled", 0) == 0 then
		local f = io.open('/tmp/iktmp/cache/snmp_ipauth/arp')
		if f then
			for line in f:lines() do
				local macaddr,ip = str_match(line, "([^ ]+) (%d+%.%d+%.%d+%.%d+)")
				if ipaddr == ip then
					mac = macaddr
					break
				end
			end
			f:close()
		end
	end

	return mac or nil,iface or nil
end

function M.get_language()
	local fp = io.popen("ls /tmp/iktmp/LANG")
	local L = fp:read("*a")
	fp:close()

	return tonumber(L)
end

function M.get_timezone()
	local f = io.open("/tmp/iktmp/cache/config/basic")
	local line
	if f then
		line = f:read("*l")
		f:close()
		local tz = line:match("time_zone_full=(%-?%d+)")
		return tz
	end

	return 0
end

--加载文件内的JSON
function M.load_json(file)
	local f = io.open(file)
	if f then
		local t = cjson.decode(f:read("*a"))
		f:close()

		return t
	end

	return nil
end

--读取iKuai release信息
function M.load_ikrelease()
	local f = io.open("/etc/release")
	local t = {}
	if f then
		for line in f:lines() do
			local key,val = line:match("^([^ ]+) *= *(.+)")
			if key then
				t[key] = val
			end
		end
		f:close()
	end
	return t
end

function M.load_ppp_passwd()
	local f = io.open("/tmp/iktmp/cache/config/ppp_passwd")
	local t = {}
	if f then
		for line in f:lines() do
			key,val = line:match("^([^ ]+) *= *(.+)")
			if key then
				t[key] = val
			end
		end
		f:close()
	end
	return t
end

function M.sock_timersql(sql)
	local sock = ngx.socket.stream()
	local ok, err = sock:connect("unix:/dev/iktimerd")
	if not ok then
		return nil, err
	end

	sock:settimeout(2000)
	local ok, err = sock:send(sql)
	if not ok then
		return nil, err
	end

	local line, err = sock:receive()
	sock:close()
	return line, err
end

function M.sock_iktimerd_send(data)
	local sock = ngx.socket.stream()
	local ok, err = sock:connect("unix:/dev/iktimerd")
	if not ok then
		return nil, err
	end

	sock:settimeout(1000)
	sock:send(data)
	sock:close()
	return 0
end

function M.debug(fmt, ...)
	local f = io.open('/var/log/openresty/ikdebug.log','a+')
	if f then
		f:write(str_format(fmt,...))
		f:close()
	end
end


--转换一个IP掩码或IP范围 为 整数范围
--192.168.1.1-192.168.1.100, return 3232235776, 3232236031 
--192.168.1.1/24或192.168.1.1/255.255.255.0, return 3232235776, 3232236031
local function __convert_ip_range(iprange)
	local ip2int = M.ip2int
	--192.168.1.1-192.168.1.200
	if str_find(iprange, "-", 1, true) then
		local ip_start, ip_end = str_match(iprange, "([^-]+)-([^-]+)")
		local ip_start_int  = ip2int(ip_start)
		local ip_end_int    = ip2int(ip_end)

		return ip_start_int, ip_end_int

	--192.168.1.1/24,192.168.1.1/255.255.255.0
	elseif str_find(iprange, "/", 1, true) then
		local ip, mask = str_match(iprange,"(%d+%.%d+%.%d+%.%d+)/(%d+%.%d+%.%d+%.%d+)") 
		if not ip then
			ip, mask = str_match(iprange,"^(%d+%.%d+%.%d+%.%d+)/(%d%d?)$")
		end
		if ip and mask then
			local safe_ipint = ip2int(ip)
			local netmask
			if tonumber(mask) then
				netmask = 0x100000000 - bit64.lshift(1,32-mask)
			else
				netmask = ip2int(mask)
			end
			local subnet     = bit64.band(safe_ipint, netmask)
			local broadcast  = bit64.bor(safe_ipint, (0x100000000 - 1 - netmask))

			return subnet, broadcast
		end
	else
		local ip = iprange:match("^(%d+%.%d+%.%d+%.%d+)")
		if ip then
			local ipint = ip2int(ip)
			return ipint,ipint
		end
	end

	return 0,0
end

--比较2组IP的互相包含, 第一个可以允许多个IP, 第二个只允许1个目标
--如: 192.168.0.0/24,192.168.1.200,192.168.1.1-192.168.1.200, 192.168.1.1/24
function M.check_ip_contain(ip_pool, ip_target)
	local iptaget_start, iptaget_end = __convert_ip_range(ip_target)

	for ipaddr in str_gmatch(ip_pool, "[^,]+") do
		if ipaddr == ip_target then
			return true
		end

		local ipaddr_start, ipaddr_end = __convert_ip_range(ipaddr)
		if (iptaget_start >= ipaddr_start and iptaget_start <= ipaddr_end) or 
		   (iptaget_end   >= ipaddr_start and iptaget_end   <= ipaddr_end) or 
		   (ipaddr_start >= iptaget_start and ipaddr_start <= iptaget_end) or
		   (ipaddr_end   >= iptaget_start and ipaddr_end   <= iptaget_end) then
				return true
		end
	end

	return false
end

function M.utimes(file, atime, mtime)
	local struct_timeval = ffi.new("struct timeval[2]")
	struct_timeval[0].tv_sec = atime
	struct_timeval[1].tv_sec = mtime
	C.utimes(file, struct_timeval)
end

function M.gettimeofday()
	local tm = ffi.new("struct timeval");
	C.gettimeofday(tm, nil)
	return tonumber(tm.tv_sec), tonumber(tm.tv_usec)
end

local function __rest_check_illegality_char(s)
	if type(s) == "string" then
		return str_match(s, "['\"`$&;\\|\r\n ]")
	end
end

-- Keep administrative writes synchronous. A cold HY2 core can need a 120 s
-- download plus verification, compression, mount and listener startup.
local function wg_prepares_core(action, param)
    if not param then return false end
    if action == "add" or action == "edit" then
        return param.wg_transport == "pure_hy2" and param.wg_role == "access"
    elseif action == "site_client_import" then
        local hex = param.config_hex
        if type(hex) ~= "string" or #hex > 32768 or #hex % 2 ~= 0 or not hex:match("^[0-9a-f]+$") then return false end
        local text = hex:gsub("..", function(byte) return string.char(tonumber(byte, 16)) end)
        local ok, bundle = pcall(cjson.decode, text)
        return ok and type(bundle) == "table" and bundle.format == "nativerouting-pure-hy2-device"
            and bundle.version == 1 and bundle.purpose == "access"
    elseif action == "up" or action == "iface_up" then
        local ids = tostring(param.id or "")
        if #ids > 1024 or not ids:match("^%d[%d,]*$") or ids:find(",,", 1, true) or ids:sub(-1) == "," then return false end
        local cmd = "/usr/bin/lua /usr/ikuai/script/wg_site_client.lua enable_wait /etc/mnt/ikuai/config.db " .. action .. " " .. ids
        local ok, result = shell.run(cmd, nil, 3000, 256)
        return ok and result == "yes\n"
    end
    return false
end

function M.rest(call_json_tab, env)
 if type(call_json_tab)~="table" then return false,"Invalid request" end
 if type(call_json_tab.func_name)~="string" or not call_json_tab.func_name:match("^[%w_%-]+$") or
    type(call_json_tab.action)~="string" or not call_json_tab.action:match("^[A-Za-z][A-Za-z0-9_.@%%]*$") then return false,"Invalid function or action" end
 if call_json_tab.param~=nil and type(call_json_tab.param)~="table" then return false,"Invalid parameters" end
	local stdin = nil
	local max_size = 10485760 --10Mbyte

	local func_name = call_json_tab["func_name"]
	if not func_name or func_name == "" then
		return false, 'Syntax error: func_name is null'
	end

	local action = call_json_tab["action"]
	if not action or action == "" then
		return false, 'Syntax error: action is null'
	end

	if __rest_check_illegality_char(func_name) then
		return false, "Invalid characters: " .. func_name
	end
	if __rest_check_illegality_char(action) then
		return false, "Invalid characters: " .. action
	end

	local param = call_json_tab["param"]

	local cmd = ""
	if env then
		for k,v in pairs(env) do
			cmd = string.format("%s%s=%s ",cmd,k,shell_quote(tostring(v)))
		end
	end

	cmd = string.format("%s/usr/ikuai/function/func_api.sh %s %s ", cmd, func_name, action)

	if param then
		for k,v in pairs(param) do
            if type(k)~="string" or not k:match("^[A-Za-z_][A-Za-z0-9_]*$") or (type(v)~="string" and type(v)~="number" and type(v)~="boolean") then return false,"Invalid parameter" end
			if __rest_check_illegality_char(k) then
				return false, "Invalid characters: " .. k
			end
			if __rest_check_illegality_char(v) then
				return false, "Invalid characters: " .. v
			end

			cmd = string.format("%s%s=%s ",cmd,k,shell_quote(tostring(v)))
		end
	end

	local timeout = func_name == "wireguard" and wg_prepares_core(action, param) and 240000 or 60000
	local ok, stdout, stderr, reason, status = shell.run(cmd, stdin, timeout, max_size)
	cmd = nil
	collectgarbage("collect")
	if reason == "exit" then
		return true, stdout
	else
		return false, reason
	end
end

return M
