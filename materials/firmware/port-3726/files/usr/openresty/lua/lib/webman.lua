local M = { }
local Session = ngx.shared.sess_key
local Limitd_access = ngx.shared.limited_accass
local upload  = require "resty.upload"
local vnc     = require "vnc"
local dkconsole = require "dkconsole"
local rtcollect = require "rtcollect"

local IKRELEASE    = ikngx.load_ikrelease()
local RootPath     = "/usr/ikuai/www"
local PermIDFile   = "/usr/ikuai/function/funcname_id.conf"
local UploadTmp    = "/tmp/iktmp/import/"
local UploadKvmImgPath    = "/tmp/storage/kvm_data/"
local FuncHideFile = "/etc/function_hide"

local Permission      = { IS_R="r", IS_X="x", IS_RX="rx" }
local UploadMaxLen    = 128*1024*1024  -- plugin package uploads
local UploadKvmImgMaxLen    = 8*1024*1024*1024  --2G
local Webuser         = {}
local UserGroup       = {}
local ActionUri       = {}
local VerifyExclUri   = {}
local LabelDict       = {}

local ResOK           = 10000  --验证账号密码成功
local ResAuthFail     = 10001  --验证账号密码失败
local ResAccDisable   = 10002  --账号是停用的
local ResInvalidIP    = 10003  --无效的IP
local ResPermNR       = 10004  --没有读权限
local ResPermNX       = 10005  --没有执行权限
local ResCallBodyErr  = 10006  --Body内容太大
local ResCallJsonErr  = 10007  --Json格式错误
local ResCallParamErr = 10008  --参数内容错误
local ResCallInternal = 10009  --服务器内部错误
local ResUpSvrErr     = 10010  --上传文件,服务器错误
local ResUpFormatErr  = 10011  --上传文件,FORM表单格式错误
local ResDownloadErr  = 10012  --下载文件,请求参数错误
local ResIkrestErr    = 10013  --ik_rest HTTP 状态错误 
local ResNoAuth       = 10014  --未认证/认证SESS过期
local ReslimitAuth    = 10015  --限制登录
local ResIllegality   = 10016  --非法操作

local ip_access_timeout		= 3600  --访问限制默认1小时
local ip_access_maxfail 	= 5	--账号密码登录失败的次数
local ip_access_limitd_timeout	= 300	--账号锁定五分钟

local VerifyReqExcl, VerifyReqPerm, VerifySafeAddr, VerifySesskey
local ActionHandle, ActionCall, ActionTag, ActionLogout, ActionLogin, ActionUpload, ActionDownload
local getUername, getUserConfig, init_load_webuser, label_link_funcname, init_create_menu_left, I18nError
local CheckReqMethod, CheckFuncnamePerm

local posix_stat = posix.lstat
local posix_islink = posix.S_ISLNK

--检查请求的URI 是否为排除的
function VerifyReqExcl()
	for uri, _ in pairs(VerifyExclUri) do
		if string.find(ngx.var.uri, uri) then
			return true
		end
	end
	return false
end

--验证请求URI访问权限 或者 Call 的权限
function VerifyReqPerm(username, func_name, expect_perm)
	if not func_name or not Webuser[username] then
		return false
	end
	
	local group_id = Webuser[username]["group_id"]
	local group_conf = UserGroup[group_id]
	
	if not group_conf then
		return false
	end

	local res = CheckFuncnamePerm(group_conf, func_name, expect_perm)

	return res
end

--验证请求的IP地址
function VerifySafeAddr(ip_addr)
	if not ip_addr then
		return false
	end
	if ip_addr == "0.0.0.0/0" or ip_addr == "0.0.0.0" then
		return true
	end

	return ikngx.check_ip_contain(ip_addr, ngx.var.remote_addr)
end

--验证session key 合法性
--验证错误 则跳转到/login
function VerifySesskey(cookie)
	if ngx.var.uri == "/login" then
		ngx.header["Content-Type"]  = "text/html;charset=UTF-8"
		ngx.req.set_uri("/index.html")
		ngx.exit(0)
	end

	--验证Session Key 是否存在,如果是过期的 查询结果是 nil
	local sess_key = cookie.req_cookies["sess_key"]
	local username, old_times = getUername(sess_key)
	if not username or not Webuser[username] then
		if ngx.var.request_method == "POST" then
			ikngx.senderror(ResNoAuth, "no login authentication")
		else
			ngx.redirect("/login")
			ngx.exit(0)
		end
	end
	local SessTimeout = tonumber(Webuser[username]["sesstimeout"]*60)

	--最后一次访问时间 大于 SessTimeout 的1/2的时间,那么我们就刷新一下他的超时
	-- old_times > now_times 有可能时间出错时,就 新的时间会小于老的时间
	local now_times = ngx.time()
	if old_times > now_times or now_times - old_times > SessTimeout/2 then
		local res, err = Session:set(sess_key, username.."&"..now_times, SessTimeout)
		if not res then
			ngx.log(ngx.ERR,"reset sess timeout fail for "..sess_key..", errmsg = " ..err)
		end
	end

	return username
end

function VerifyIllegality(s)
	if type(s) == "string" then
		if s:match("[%[%]()#*'!^\"`$&;\\|\r\n]") then
			ikngx.senderror(ResIllegality, "Illegality operation")
		end
	end
end

local function is_safe_filename(name)
	if type(name) ~= "string" or name == "" or name == "." or name == ".." then
		return false
	end
	if name:match("[/%z\r\n]") or name:match("%.%.") then
		return false
	end
	return true
end

local function is_safe_diskpath(path)
	if type(path) ~= "string" or path == "" then
		return false
	end
	if path:match("[%z\r\n]") or path:match("%.%.") then
		return false
	end
	return true
end

function ActionSessVerify(Cookie, SessKey)
	ikngx.senderror(ResOK)
end

--初始配置的时候,通过URL来自动配置
function AutoConfigure()
	local user_conf = Webuser["admin"]

	if user_conf and user_conf.group_id == 1 and user_conf.id == 1 and user_conf.passwd == "21232f297a57a5a743894a0e4a801fc3" then
		if IKRELEASE.ARCH == "x86" and not IKRELEASE.ENTERPRISE and not IKRELEASE.OEMNAME then
			ngx.exit(404)
		end

		ngx.header["Content-Type"]  = "text/plain;charset=UTF-8"
		local basebuf = ngx.decode_base64(ngx.var.args)
		if not basebuf then
			return ngx.say("parser base64 characters failed.")
		end
		if ikngx.writefile(basebuf, "/tmp/iktmp/AutoConfigure.txt") then
			local shell = require "resty.shell"
			local ok, stdout, stderr, reason, status = shell.run("/usr/ikuai/script/utils/autoconfig.sh /tmp/iktmp/AutoConfigure.txt", nil, 10000, 10485760)
			if ok then
				return ngx.say(stdout)
			else
				local err = stderr:gsub("/usr/ikuai/script/utils/autoconfig.sh","autoconfig")
				return ngx.say(err)
			end
		else
			return ngx.say("Write File failed.")
		end
	else
		return ngx.exit(400)
	end
end

local function verify_origin()
 local origin=ngx.var.http_origin
 if not origin and ngx.var.http_referer then origin=ngx.var.http_referer:match("^(https?://[^/]+)") end
 if not origin then return end -- Non-browser API clients may omit Origin.
 local expected=ngx.var.scheme.."://"..(ngx.var.http_host or ngx.var.host)
 if origin:lower()~=expected:lower() then ngx.exit(403) end
end
local function admin_only(username)
 if not username or not Webuser[username] or tonumber(Webuser[username].group_id)~=1 then ngx.exit(403) end
end
function ActionHandle(Cookie, SessKey)
	local username
	local ngx_var_uri = ngx.var.uri
 if ngx_var_uri:match("^/Action/") then verify_origin() end

	if ngx_var_uri == "/AutoConfigure" then
		return AutoConfigure()
	end

	--先检查请求的URI是否排除验证session
	if not VerifyReqExcl() then
		--验证Session
		username = VerifySesskey(Cookie)
	else
		username = getUername(SessKey)
	end

	VerifyIllegality(username)
 if ngx_var_uri:match("^/export/") or ngx_var_uri:match("^/disk/") or
    ngx_var_uri=="/Action/upload" or ngx_var_uri=="/Action/download" or
    ngx_var_uri:match("^/Action/disk/") or ngx_var_uri=="/Action/proxy" or
    ngx_var_uri=="/Action/vnc" or ngx_var_uri=="/Action/dkconsole" then admin_only(username) end

	check_temp_webport()

	if ActionUri[ngx_var_uri] then
		ActionUri[ngx_var_uri](Cookie, username)
	elseif string.find(ngx_var_uri, "^/json/menu.json") then
		local args = ngx.req.get_uri_args() or {}
		local group_id
		if username and Webuser[username] then
			group_id = Webuser[username]["group_id"]
			--url参数 full=true, 并且请求的是超级管理员, 可获得完整的 menu.json
			if not (args.full and group_id == 1) then
				ngx.req.set_uri("/dynamic/menu/"..group_id..".json")
			end
		else
			ngx.exit(404)
		end
	end

	if ngx_var_uri == "/" then
		ngx.header["Content-Type"]  = "text/html"
	elseif ngx_var_uri:sub(0,6) == "/disk/" then
		ngx.header["Content-Type"]  = "application/octet-stream"
		local stat = posix_stat(ngx.var.request_filename)
		if stat and posix_islink(stat.st_mode) == 1 then
			ngx.exit(403)
		end
	end

end

--调用Shell脚本
function ActionCall(cookie, username)
	CheckReqMethod("POST")
	ngx.req.read_body()
	if not ngx.var.request_body then
		ikngx.senderror(ResCallBodyErr, "Post body too large")
	end

	--页面自己加debug调试
	if ngx.var.args == "debug" then
		ngx.header["Content-Type"]  = "application/json;charset=UTF-8"
		ngx.say(ngx.var.request_body)
		ngx.exit(0)
	end

	local res, call_json_tab = pcall(cjson.decode, ngx.var.request_body)
	if not res or type(call_json_tab)~="table" then
		ikngx.senderror(ResCallJsonErr, "decode json fail")
	end

	local func_name = call_json_tab["func_name"]
	if type(func_name)~="string" or not func_name:match("^[%w_%-]+$") then
		ikngx.senderror(ResCallParamErr, 'func_name is null')
	end

	local action = call_json_tab["action"]
	if type(action)~="string" or not action:match("^[A-Za-z][A-Za-z0-9_.@%%]*$") then
		ikngx.senderror(ResCallParamErr, 'action is null')
	end

	if action == "show" then
		--验证账号对应的功能是否可读权限
		if not VerifyReqPerm(username, func_name, Permission.IS_R) then
			ikngx.senderror(ResPermNR, I18nError("perm_not_read"), {Label = LabelDict[func_name]})
		end
	else
		if not VerifyReqPerm(username, func_name, Permission.IS_X) then
			ikngx.senderror(ResPermNX, I18nError("perm_not_exec"), {Label = LabelDict[func_name]})
		end
	end

	local env = {
		IKREST_USER = username,
		IKREST_REFERER = "ik-http-server",
		IKREST_REMOTE_ADDR = ngx.var.remote_addr,
	}


	local ok, buf = ikngx.rest(call_json_tab, env)
	ngx.header["Content-Type"]  = "application/json;charset=UTF-8"

	if ok then	
		ngx.header["Content-Length"] = #buf
		ngx.print(buf)
	else
		ikngx.senderror2(ResIkrestErr, buf)
	end

	ngx.exit(0)
end

function ActionTag(cookie, username)
	CheckReqMethod("POST")
	local uri_args = ngx.req.get_uri_args() or {}
	if not uri_args.id then
		ikngx.senderror(ResCallBodyErr, "not found tagid")
	end
	local data = string.format(".tagid; %s", uri_args.id)
	ikngx.sock_iktimerd_send(data)

	ngx.header["Content-Type"]  = "text/plain;charset=UTF-8"
	ngx.print("success")
	ngx.exit(0)
end

function ActionLogout(cookie, username)
	local sess_key  = cookie.req_cookies["sess_key"]
	if sess_key then
		Session:delete(sess_key)
	end
	ngx.header["Content-Type"]  = "text/html"
	cookie:set({key="sess_key", value="", path="/", max_age=0, http_only=true, same_site="Strict", secure=ngx.var.scheme=="https"})

	if username then
		local logmsg = string.format("%s %s -- %s",username, ngx.var.remote_addr, I18nError("logout") )
		ikngx.logger("webadmin",logmsg)
	end
	ngx.redirect("/login")
	ngx.exit(0)
end

--WEB管理登陆验证
function ActionLogin(cookie, username)
	local json_auth
	local res

	CheckReqMethod("POST")

	ngx.req.read_body()
	if ngx.var.request_body then
		res, json_auth = pcall(cjson.decode, ngx.var.request_body)
	end

	if not res or type(json_auth)~="table" or type(json_auth.username)~="string" or type(json_auth.passwd)~="string" then
		ikngx.senderror(ResAuthFail, "Post data error")
	end

	if check_userip_is_limitd(ngx.var.remote_addr) then
		ikngx.senderror(ReslimitAuth, I18nError("user_login_fails"))
	end

	VerifyIllegality(json_auth["username"])

	--根据请求的账号名称,查询数据的用户资料,同时比较他的密码
	local user_conf = getUserConfig(json_auth["username"])
	if user_conf and user_conf["passwd"] == json_auth["passwd"] then
		--GroupID == 1 它是超级管理员,不需要验证安全地址
		if user_conf["group_id"] > 1 then
			if user_conf["enabled"] ~= "yes" then
				ikngx.senderror(ResAccDisable, I18nError("user_is_disable"))
			end
		end

		if ngx.var.remote_addr ~= "127.0.0.1" then
			if not VerifySafeAddr(user_conf["ip_addr"]) then
				ikngx.senderror(ResInvalidIP, I18nError("ip_is_forbidden"))
			end
		end

		local SessTimeout = tonumber(user_conf["sesstimeout"]*60)
		local now_times = ngx.time()
		local random=io.open("/dev/urandom","rb")
        local bytes=random and random:read(32)
        if random then random:close() end
        if not bytes or #bytes~=32 then ngx.exit(503) end
        local key=(bytes:gsub(".",function(c)return string.format("%02x",string.byte(c))end))

		Session:set(key, json_auth["username"].."&"..now_times, SessTimeout)
		cookie:set({key="sess_key", value=key, path="/", http_only=true, same_site="Strict", secure=ngx.var.scheme=="https"})

		Del_limitd_access(ngx.var.remote_addr)

		if ngx.var.host ~= "127.0.0.1" then
			local logmsg = string.format("%s %s -- %s",json_auth["username"], ngx.var.remote_addr , I18nError("login"))		
			ikngx.logger("webadmin",logmsg)
		end
		ikngx.senderror(ResOK)
	else
		check_limitd_access(ngx.var.remote_addr)
		--忽略local.ikuai8.com登录失败日志
		--ikuai app使用默认用户名密码的方式登录设备,来探测设备是不是新设备,是否启用自动配网流程
		--避免不是新设备时，页面显示登录失败日志
		if ngx.var.host ~= "local.ikuai8.com" then
			local logmsg = string.format("%s %s -- %s",json_auth["username"], ngx.var.remote_addr , I18nError("user_pass_incorr"))
			ikngx.logger("webadmin",logmsg)
		end
		ikngx.senderror(ResAuthFail, I18nError("user_pass_incorr"))
	end
end

function ActionUpload(cookie, username)
	CheckReqMethod("POST")
	
	if ngx.var.content_length then
		if tonumber(ngx.var.content_length) > UploadMaxLen then
			ngx.exit(413)
		end
	else
		ngx.exit(400)
	end

	local chunk_size = 2048
	local form, err = upload:new(chunk_size)

	if not form then
		ikngx.senderror(ResUpSvrErr,"Server error, failed to new upload: " .. err or "")
	end

	form:set_timeout(3000) -- socket timeout 3 sec


	local filename, content_type
	local tmpfile = UploadTmp .. "." ..ngx.md5(ngx.var.remote_addr .. ngx.var.remote_port .. ngx.time())
	local f = io.open(tmpfile,"w")
	if not f then
		ikngx.senderror(ResUpSvrErr,"Server error, open file fail")
	end

	while true do
		local typ, data, err = form:read()
		if not typ then
			ikngx.senderror(ResUpSvrErr,"Server error, failed to read: ".. err or "")
		
		elseif typ == "header" then
			if data[1] == "Content-Disposition" then
				if data[2] then
					filename = getUploadHead(data[2]).name
					if filename then
						filename = filename:gsub("[ `;]+/","_")
						if not is_safe_filename(filename) then
							ikngx.senderrmsg("errcode_param_error")
						end
					end
				end
			end
		
		elseif typ == "body" then
			if not filename then break end
			f:write(data)

		elseif typ == "part_end" then
			if f then
				f:close()
				f = nil
			end
			if not filename then break end
			os.execute("rm -f "..UploadTmp.."/*")
			os.rename(tmpfile,UploadTmp .. filename)
			ikngx.senderror(ResOK)
		elseif typ == "eof" then
			break
		end
	end

	if f then f:close()	end
	os.remove(tmpfile)
	ikngx.senderror(ResUpFormatErr,"form format err")
end


function ActionDiskUpload(cookie, username)
	CheckReqMethod("POST")

	if not ngx.var.content_length then
		ngx.exit(400)
	end

	local chunk_size = 2048
	local form, err = upload:new(chunk_size)

	if not form then
		ikngx.senderror(ResUpSvrErr,"Server error, failed to new upload: " .. err or "")
	end

	form:set_timeout(3000) -- socket timeout 3 sec

	local args = ngx.req.get_uri_args()
	local diskpath = args["path"]
	local lastmodified = tonumber(args["lastmodified"])
	if not diskpath then
		ikngx.senderror(ResUpSvrErr,"Need param name: path")
	end

	if not is_safe_diskpath(diskpath) then
		ikngx.senderror(ResUpSvrErr,"Need param name: path")
	end

	if not lastmodified then
		lastmodified = 0
	end

	local filename, content_type
	local tmpfile = string.format( "%s/disk/%s/%s.uptemp" , RootPath, diskpath, ngx.md5(ngx.var.remote_addr .. ngx.var.remote_port .. ngx.time()))
	local f = io.open(tmpfile,"w")
	if not f then
		ikngx.senderror(ResUpSvrErr,"not exist path: " .. diskpath)
	end

	while true do
		local typ, data, err = form:read()
		if not typ then
			ikngx.senderror(ResUpSvrErr,"Server error, failed to read: ".. err or "")

		elseif typ == "header" then
			if data[1] == "Content-Disposition" then
				if data[2] then
					filename = getUploadHead(data[2]).name
					if filename then
						filename = filename:gsub("[ `;]+/","_")
						if not is_safe_filename(filename) then
							ikngx.senderrmsg("errcode_param_error")
						end
					end
				end
			end

		elseif typ == "body" then
			if not filename then break end
			f:write(data)

		elseif typ == "part_end" then
			if f then
				f:close()
				f = nil
			end
			if not filename then break end
			local savefile = string.format( "%s/disk/%s/%s" , RootPath, diskpath, filename)
			if lastmodified > 0 then
				ikngx.utimes(tmpfile, lastmodified, lastmodified)
			end

			os.rename(tmpfile,savefile)
			ikngx.senderror(ResOK)
		elseif typ == "eof" then
			break
		end
	end

	if f then f:close()	end
	os.remove(tmpfile)
	ikngx.senderror(ResUpFormatErr,"form format err")
end

function ActionDownload(cookie, username)
	CheckReqMethod("GET")

	local args = ngx.req.get_uri_args()
	local filename = args["filename"]

	if not filename then
		ikngx.senderror(ResDownloadErr,"param error")
	end

	if not is_safe_filename(filename) then
		ikngx.senderror(ResDownloadErr,"param error")
	end

	if ikngx.file_exists(ngx.var.document_root .. "/export/" .. filename) then
		ngx.header["Content-Type"]  = "application/octet-stream"
		ngx.header["Content-Disposition"]  = 'attachment; filename="'..filename..'"'
		ngx.req.set_uri("/export/"..filename)
	else
		ngx.exit(404)
	end
end

function ActionDiskDownload(cookie, username)
	CheckReqMethod("GET")
	local args = ngx.req.get_uri_args()
	local filename = args["filename"]
	local diskpath = args["path"]

	if not filename or not diskpath then
		ikngx.senderror(ResDownloadErr,"param error")
	end

	if not is_safe_filename(filename) then
		ikngx.senderror(ResDownloadErr,"param error")
	end

	if not is_safe_diskpath(diskpath) then
		ikngx.senderror(ResDownloadErr,"param error")
	end

	ngx.header["Content-Type"]  = "application/octet-stream"
	ngx.header["Content-Disposition"]  = 'attachment; filename="'..filename..'"'
	ngx.req.set_uri("/disk/" .. diskpath .. "/" ..filename)
end

function ActionProxy(cookie, username)
    -- Fixed service operations only. Never accept an arbitrary proxy URL.
    local op=ngx.var.args
    if op~="sms_easy_bind" and op~="get_sms_code" then
        ngx.status=400
        ngx.say('{"Result":10001,"ErrMsg":"Unsupported proxy operation"}')
        return ngx.exit(400)
    end
    ngx.var.proxy_url="https://yun.ikuai8.com/api/v3/router_bind/"..op
end

function ActionVnc()
	vnc.start()
end

--路由发现websocket方法调用
function ActionRtWebsocket()
	rtcollect.websocket_evn()
end

function ActionDockerConsole()
	local args = ngx.req.get_uri_args() or {}
	if not args.id then
		ngx.say("Need container ID")
		ngx.exit(400)
	end

	dkconsole.start(args.id)
end

function getUploadHead(head_data)
	local t = {}
	t.type = head_data:match("([^;]+);")
	for key,val in head_data:gmatch("; (%w+)=\"([^\"]+)\"") do
		t[key] = val
	end
	return t
end
--获取用户权限信息
function getUserConfig(username)
	local t = {}
	local user_config = Webuser[username]

	if IKRELEASE.CURRENT_APMODE then
		local f = io.open("/tmp/patch/webpasswd")

		--passwd: admin
		local passwd = "21232f297a57a5a743894a0e4a801fc3"
		if f then
			passwd = f:read("*l")
			f:close()
		end

		t.username = "admin"
		t.enabled  = "yes"
		t.group_id = 1
		t.passwd   = passwd
		t.sesstimeout = 0
		t.ip_addr  = "0.0.0.0/0"
		return t
	else
		if user_config then
			t.username   = username
			t.enabled    = user_config["enabled"]
			t.group_id   = user_config["group_id"]
			t.passwd     = user_config["passwd"]
			t.sesstimeout= user_config["sesstimeout"]

			local group_conf  = UserGroup[t.group_id]
			if group_conf then
				t.ip_addr     = group_conf["ip_addr"]
				t.perm_config = group_conf["perm_config"]
				t.group_name  = group_conf["group_name"]
			end
			return t
		else
			return nil
		end
	end
end

--根据session key 获得用户名
function getUername(sess_key)
	if not sess_key then
		return nil
	end

	local user_and_times = Session:get(sess_key)
	if not user_and_times then
		return nil
	end

	local username, old_times = string.match(user_and_times, "([^&]+)&([0-9]+)")
	return username, tonumber(old_times)
end

function check_userip_is_limitd(userip)
	local is_limitd, err = Limitd_access:get("limitd_" .. userip)
	if is_limitd == 1 then
		return true
	end
	return false
end

function check_limitd_access(userip)
	local ip_count, err = Limitd_access:get("count_"..userip)

	if ip_count then
		if ip_count >= ip_access_maxfail then
			Limitd_access:set("limitd_" .. userip, 1, ip_access_limitd_timeout)	
			Limitd_access:set("count_" .. userip, 1, ip_access_timeout)
		else
			Limitd_access:incr("count_" .. userip, ip_count, 1)
		end
	else
		Limitd_access:set("count_" .. userip, 1, ip_access_timeout)
	end
end

function Del_limitd_access(userip)
	local ip_count, err = Limitd_access:get("count_"..userip)

	if ip_count then
		Limitd_access:delete("count_" .. userip)
		Limitd_access:delete("limitd_" .. userip)	
	end
end

--云平台直连的端口检查
function check_temp_webport()
	if ngx.var.temp_webport and ngx.var.temp_webport ~= "" then
		local time_old = Session:get("temp_webport")
		if ngx.var.uri == "/check_temp_webport" then
			ngx.say(time_old)
			ngx.exit(0)
		else
			local time_now = os.time()
			if time_old and time_now - 30 < time_old then
				return
			end

			Session:set("temp_webport", time_now)
		end
	end
end

--检查请求必须是指定的模式,如 GET POST
function CheckReqMethod(m, exit_num)
	exit_num = exit_num or 401
	if ngx.var.request_method ~= m then
		ngx.exit(exit_num)
	end
end

--检查功能的权限
function CheckFuncnamePerm(group_conf, func_name, expect_perm)
	if not group_conf or not func_name then
		return false
	end

	--group id == 1 它是超级管理员,不受限制
	if group_conf["id"] == 1 then
		return true
	else
		local perm_config = group_conf["perm_config"]
		for func, perm in perm_config:gmatch("([%w_-]+):([%w]*)") do
			--找到该功能名称,进行权限比对
			if (func_name == func) then
				return perm:match(expect_perm) and true or false
			end
		end

		--如果没有找到func_name的权限设置,那么它是一个新页面功能,处于未设置状态
		--那么我们根据它的权限组设置的默认权限进行比较
		if group_conf.perm_default then
			return group_conf.perm_default:match(expect_perm) and true or false
		end

		return false
	end
end

--加载用户密码+权限
function init_load_webuser()
	for row in IKDB:nrows("select * from webuser") do
		Webuser[row.username] = row
	end

	for row in IKDB:nrows("select * from usergroup") do
		UserGroup[row.id] = row
	end
end

function label_link_funcname(t)
	for k,v in pairs(t) do
		if k == "label" and t.func_name then
			LabelDict[t.func_name] = v
		elseif type(v) == "table" then
			label_link_funcname(v)
		end
	end
end

--自动生成左边菜单JS文件, 位置 /dynamic/menu/xx.json
function __init_create_menu_left(tab, group_conf, funcore_config, func_hide)
	local new_tab = {}
	local new_tab_is_null = true
	for i,t in pairs(tab) do
		
		local child_tab = {}
		local is_null = true
		local is_child = false
		for key, val in pairs(t) do
			if key == "children" then
				is_child = true
				child_tab[key], is_null = __init_create_menu_left(val, group_conf, funcore_config, func_hide)
			else
				child_tab[key] = val
			end
		end

		--如果有子级,那么继续检查 子级的内容是否为空,如果子级是空的,那么也应该隐藏父级菜单
		--否则在页面会看到一个菜单,却点击不了
		if is_child then
			if not is_null then
				table.insert(new_tab,child_tab)
				new_tab_is_null = false
			end
		else
			--检查每一个功能是否有可读权限,如果不可读,那么就隐藏menu.json内容
			--funcore_config 是功能中心的配置,如果设置为0表示隐藏,默认没有配置都认为可显示
			if not func_hide[t.func_name] and funcore_config[t.func_name] ~= "0" and CheckFuncnamePerm(group_conf, t["func_name"], Permission.IS_R) then
				table.insert(new_tab,child_tab)
				new_tab_is_null = false
			end
		end
	end

	return new_tab, new_tab_is_null
end

function init_create_menu_left()
	local menu_data
	local menu_json_tab
	local menu_file = RootPath .. "/json/menu.json"
	local dynamic_menu_dir_save = RootPath .. "/dynamic/menu/"
	local dynamic_menu_dir_tmp  = RootPath .. "/dynamic/menu.tmp/"

	--读取功能中心的配置
	local funcore_config = {}
	for row in IKDB:nrows("select * from funcore where id = 1") do
		local config = row.config
		for name, val in config:gmatch("([%w_-]+):(%d)") do
			funcore_config[name] = val
		end
	end

	--读取隐藏功能配置文件
	local func_hide = {}
	local f = io.open(FuncHideFile)
	if f then
		for line in f:lines() do
			func_hide[line] = true
		end
		f:close()
	end

	--读取menu.json文件
	local f = io.open(menu_file, "r")
	if f then
		menu_data = cjson.decode(f:read("*a"))
		f:close()
	end

	
	if not menu_data then
		return
	end
	--标签名称 和 funcname 关联, 在抛出错误时,有的地方需要用到它
	label_link_funcname(menu_data)

	--循环加载每一个权限组的配置,并且与功能中心的配置结合 生成menu.json
	ikngx.mkdir(dynamic_menu_dir_tmp)
	for _, group_conf in pairs(UserGroup) do
		menu_json_tab = __init_create_menu_left(menu_data, group_conf, funcore_config, func_hide)
		local f = io.open(dynamic_menu_dir_tmp .. group_conf["id"] .. ".json", "w")
		if f then
			f:write(cjson.encode(menu_json_tab))
			f:close()
		end
	end

	os.execute("rm -rf "..dynamic_menu_dir_save)
	os.rename(dynamic_menu_dir_tmp, dynamic_menu_dir_save)

end

--自动输入I18N内容,如果没有找到对应语言,自动选择英文(LANG = 2)
function I18nError(name)
	return I18NERR_WEBMAN[name][GLOBAL.LANG] or I18NERR_WEBMAN[name][2]
end

local function init()
	ikngx.mkdir(RootPath .. "/dynamic/")

	init_load_webuser()
	init_create_menu_left()

	ActionUri["/Action/disk/upload"]      = ActionDiskUpload
	ActionUri["/Action/disk/download"]    = ActionDiskDownload
	ActionUri["/Action/vnc"]         = ActionVnc
	ActionUri["/Action/dkconsole"]   = ActionDockerConsole
	ActionUri["/Action/call"]        = ActionCall
	ActionUri["/Action/tag"]         = ActionTag
	ActionUri["/Action/login"]       = ActionLogin
	ActionUri["/Action/logout"]      = ActionLogout
	ActionUri["/Action/upload"]      = ActionUpload
	ActionUri["/Action/download"]    = ActionDownload
	ActionUri["/Action/proxy"]       = ActionProxy
	ActionUri["/Action/session"]     = ActionSessVerify
	--路由感知页面访问websocket实时数据传输方法调用
	ActionUri["/Action/rtcollect/websocket"]	= ActionRtWebsocket


	--排除验证Uri(SessKey 和 权限)
	VerifyExclUri["^/static/"]        = true
	VerifyExclUri["^/Action/login$"]  = true
	VerifyExclUri["^/favicon.ico"]    = true
	VerifyExclUri["^/check_temp_webport$"]	= true
end

init()

M.ActionHandle = ActionHandle
M.I18nError = I18nError
return M
