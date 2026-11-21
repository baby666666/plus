#导出 export_txt DB sql_cmd <txt/csv> <file> <format_timestamp>
export_txt_sql()
{
	Include sqlite.sh
	local sql_cmd
	local DB=$1 sql_cmd=$2 format=$3 file=$4 format_timestamp="$5"
	if [ ! -f "$DB" ] ;then
		echo "not found db $DB"
		return 1
	fi

	if [ "$format_timestamp" = "null" ];then
		format_timestamp=""
	fi

	local tmp_filename=${file##*/}
	local tablename="${tmp_filename//\.*/}"
	local exclude_names
	case $tablename in
	pppuser) exclude_names="last_conntime,last_offtime" ;;
	esac

	case $format in
	txt|csv) ;;
	*) echo "error format, need format txt/csv" ;return 1;;
	esac

	if [ "$format" = "csv" ];then
		sql_config_get_csv $DB "$sql_cmd" format_timestamp="$format_timestamp" exclude_names="$exclude_names" |iconv -c -f UTF-8 -t GBK | awk '{printf "%s\r\n",$0}' > $file
	else
		sql_config_get_list $DB "$sql_cmd" format_timestamp="$format_timestamp" exclude_names="$exclude_names" | awk '{printf "%s\r\n",$0}' > $file
	fi
}

#导出 export_txt DB tablename <txt/csv> <file> <sql_where_param> <format_timestamp>
#sql_where_param 表示sql的where的参数,如: "where test='aaa' and test2='123'"
#format_timestamp 表示要将数据库的时间戳格式化成 可视化的时间,字段之间用逗号隔开,如 "time1,time2,time3"
export_txt()
{
	Include sqlite.sh
	local sql_cmd
	local DB=$1 tablename=$2 format=$3 file=$4 where=$5 format_timestamp="$6"
	if [ "$where" = "null" ];then
		where=""
	fi

	if [ "$format_timestamp" = "null" ];then
		format_timestamp=""
	fi

	if [ "$DB" = "$IK_DB_CONFIG" ];then
		case $tablename in
		arp)
			local sql_arp_columns="arp.id,arp.ip_addr,arp.mac,arp.interface,arp.bind_type,mac_comment.comment"
			sql_cmd="select $sql_arp_columns from arp left join mac_comment on arp.mac=mac_comment.mac;"
			;;
		dhcp_static)
			local sql_dhcp_columns="dhcp_static.id,dhcp_static.enabled,dhcp_static.interface,dhcp_static.ip_addr,dhcp_static.mac,dhcp_static.cl_name,mac_comment.comment,dhcp_static.gateway,dhcp_static.dns1,dhcp_static.dns2"
			sql_cmd="select $sql_dhcp_columns from dhcp_static left join mac_comment on dhcp_static.mac=mac_comment.mac;"
			;;
		acl_mac_black|acl_mac_white)
			sql_cmd="select $tablename.id,$tablename.enabled,$tablename.mac,$tablename.week,$tablename.time,mac_comment.comment from $tablename left join mac_comment on $tablename.mac=mac_comment.mac;"
			;;
		dhcp_acl_mac_black|dhcp_acl_mac_white)
			sql_cmd="select $tablename.id,$tablename.enabled,$tablename.mac,mac_comment.comment from $tablename left join mac_comment on $tablename.mac=mac_comment.mac;"
			;;
		"") return 1;;
		*) sql_cmd="select * from $tablename ${where:+where $where};"  ;;
		esac
	elif [ "$DB" = "$IK_DB_COLLECTION" ];then
		case $tablename in
		daytime_record|daytime_record6|daytime_record_vpn)
			sql_cmd="select daytime,ip_addr,mac,systype,devtype,comment,sum(total_up-base_total_up) sum_total_up,sum(total_down-base_total_down) sum_total_down,sum(online_time) sum_online from $tablename ${where:+where $where};" 
			;;
		*)
			sql_cmd="select * from $tablename ${where:+where $where};"
			;;
		esac
	else
		sql_cmd="select * from $tablename ${where:+where $where};" 
	fi

	if [ ! -f "$DB" ] ;then
		echo "not found db $DB"
		return 1
	fi

	case $format in
	txt|csv) ;;
	*) echo "error format, need format txt/csv" ;return 1;;
	esac

	local exclude_names
	case $tablename in
	ac_server) exclude_names="firmware,oemname" ;;
	esac

	if [ "$format" = "csv" ];then
		sql_config_get_csv $DB "$sql_cmd" format_timestamp="$format_timestamp" exclude_names="$exclude_names" |iconv -c -f UTF-8 -t GBK | awk '{printf "%s\r\n",$0}' > $file
	else
		sql_config_get_list $DB "$sql_cmd" format_timestamp="$format_timestamp" exclude_names="$exclude_names" | awk '{printf "%s\r\n",$0}' > $file
	fi
}

#导入 import_txt DB tablename file [ check_func ] [ clean_func ] [ sql_where ] [format_timestamp]
# check_func 它是检查参数的回调函数,在导入数据之前,执行检查参数命令, 等于 null 或者 等于空的 表示不回调
# clean_func 它是清除回调函数,有的功能在导入之前 需要做清理动作，等于 null 或者 等于空的 表示不回调
import_txt()
{

	I18nload import_export.json
	local DB="$1" tablename="$2" file="$3" append="$4" check_func="$5" clean_func="$6" where="$7" format_timestamp="$8"
	
	if [ ! -f "$DB" ] ;then
		[ "$IKDEBUG" = "1" ] &&　echo "not found db $DB"
		return 1
	fi

	if [ ! -f "$file" ];then
		[ "$IKDEBUG" = "1" ] &&　echo "not found file $file"
		return 1
	fi

	if [ "$where" = "null" ];then
		where=""
	fi

	if [ "$format_timestamp" = "null" ];then
		format_timestamp=""
	fi

	other_enc=$'\xef\xbb\xbf' #不知道windows什么文本编辑器会产生一个这个包头
	sed -i "s/^$other_enc//;s/\r$//g" $file

	#check source is GBK
	if ! iconv -f UTF-8 -t GBK $file >/dev/null ;then
		iconv -c -f GBK -t UTF-8 $file >$file.tmp
		mv $file.tmp $file
	fi

	if [ "${file##*.}" = "csv" ];then
	#CSV to TXT
	lua <<!LuaEof1!
		local file="$file"
		local file_tmp="$file.tmp"
		f = io.open(file)
		f_tmp = io.open(file_tmp, "w")
		if not f or not f_tmp then
			os.exit(1)
		end

		line_num=0
		header = {}
		for line in f:lines() do
			if line_num == 0 then
				f_tmp:write("\n")
				for key in line:gmatch("[^,\r]+") do
					table.insert(header, key)
				end
			else
				i = 0
				s = nil
				is_eye = false
				VAL = {}
				for val in line:gmatch("([^,\r]*),?") do
					if is_eye == false then
						if val:sub(0,1) == "\"" then
							if #val > 1 and val:sub(-1) == "\"" then
								table.insert(VAL, val:sub(2,-2))
								is_eye = false
							else
								table.insert(VAL, val:sub(2))
								is_eye = true
							end
						else
							table.insert(VAL, val)
						end
					else
						if val:sub(-1) == "\"" then
							table.insert(VAL, val:sub(0,-2))
							is_eye = false
						else
							table.insert(VAL, val)
						end
					end


					if is_eye == false then
						i = i+1
						local __KEY = header[i]
						if not __KEY then break end

						local __VAL = table.concat(VAL,",")

						if __VAL:match("%d%d%d%d/%d%d/%d%d") then
							__VAL = __VAL:gsub("/","-")
						end

						if __KEY:match("time") and __VAL:match("^%d:%d%d$") then
							__VAL = "0" .. __VAL
						end

						s = (s and (s.." ") or "") ..__KEY.."="..__VAL
						VAL = {}
					end
				end
				s = s:gsub("\"","")
				f_tmp:write(s.."\n")
			end
			line_num = line_num+1
		end
		f:close()
		f_tmp:close()
		os.rename(file_tmp, file)
!LuaEof1!
	#CSV to TXT end
	fi

	if [ -n "$check_func" -a "${check_func,,}" != "null" ];then
		if ! declare -F $check_func >/dev/null 2>&1 ;then
			[ "$IKDEBUG" = "1" ] && echo "not found function <$check_func>"
			return 1
		fi

		if [ "$format_timestamp" ];then
			gawk -v fmt_ts="^(${format_timestamp//,/|})=([0-9]{4}-[0-9]{2}-[0-9]{2}/[0-9][0-9]:[0-9][0-9]:[0-9][0-9])$" '{for(i=1;i<=NF;i++){ if(match($i,fmt_ts,a)){gsub("[-/:]"," ",a[2]);printf " %s=%s",a[1],mktime(a[2])} else {printf " %s",$i} };print ""}' $file >$file.tmp
			mv $file.tmp $file
		fi
		_______CHECK_VARL_IMPORT_FILE_______=$file $check_func || exit 1
	fi

	local TEMP_FILE=/tmp/import.temp.conf.$$
	local ErrorMsg
	ErrorMsg=$(

	lua <<!LuaEof!
	ikdebug = "$IKDEBUG"
	sqlite3 = require "lsqlite3"
	ikdb    = sqlite3.open("$DB")
	tmpdb	= sqlite3.open_memory()
	file    = "$file"
	append  = "$append"
	types = {}

	$__import_implant_code__

	local import = {}

	if not ikdb then
		print($(Iecho i18n_import_export_error_opendb))
		os.exit(1)
	end

	ikdb:busy_timeout(10000)
	for row in ikdb:urows("select sql FROM sqlite_master where tbl_name='$tablename'") do
		tbl_struct = row
	end
	ikdb:close()

	if tmpdb then
		local fp = io.popen("sqlite3 $DB '.dump $tablename'")
		if fp then
			local data = fp:read("*a")
			tmpdb:exec(data)
			if append ~= "1" then
				tmpdb:exec("delete from $tablename ${where:+where $where};")
			end
			fp:close()
		end

		--tmpdb:exec(tbl_struct)
	else
		print($(Iecho i18n_import_export_error_malloc))
		os.exit(1)
	end

	--获得表结构的字段和类型
	local types = {}
	if "$tablename" == "stream_domain" then
		-- ALTER TABLE appends native-routing columns on one line. Parse their
		-- actual metadata so an explicit imported policy is not silently lost.
		for row in tmpdb:nrows("PRAGMA table_info(stream_domain)") do
			types[row.name] = string.lower(row.type or "")
		end
	else
		tbl_struct=tbl_struct:match("%((.*)%)")
		for k,v in tbl_struct:gmatch("([%w_]+)[\t ]*(%w*)[^\n]+\n") do
			types[k] = string.lower(v or "")
		end
	end

	--解析导入文件
	t = {}
	local f = io.open(file)
	if f then
		local line = f:read('*l')
		local n = 0
		while line do
			n = n + 1
			t[n] = {}
			for k,v in line:gmatch("([^ =]+)=([^ ]*)") do
				t[n][k] = v or ""
			end
			line = f:read('*l')
		end
		f:close()
	else
		print($(Iecho i18n_import_export_error_openfile))
		os.exit(1)
	end

	local need_comment = false
	if "$tablename" == "arp" or "$tablename" == "dhcp_static" or
	   "$tablename" == "acl_mac_black" or "$tablename" == "acl_mac_white" or
	   "$tablename" == "dhcp_acl_mac_black" or "$tablename" == "dhcp_acl_mac_white" then
		need_comment = true
	end

	for line, _t in pairs(t) do
		local mac_comment_k = nil
		local mac_comment_v = nil
		local keys = nil
		local vals = nil
		local flags = nil
		for k, v in pairs(_t) do
			if k == "mac" then
				v = string.lower(v)
			end
			if k == "id" then
				flags = 1
				keys = (keys and (keys .. "," ) or "" )..k
				vals = (vals and (vals .. "," ) or "" ) .. "NULL"
			else
				--如果用户传来的字段,在数据结构没有定义,那么就跳过它
				if v ~= "" and ( types[k] or (need_comment and k == "comment") ) then
					--ARP有关联,mac备注的表,所以在遇到arp导入时,需要把MAC 备注也导入过去.
					if need_comment then
						if k == "comment" or k == "mac" then
							mac_comment_k = (mac_comment_k and (mac_comment_k .. "," ) or "" )..k
							mac_comment_v = (mac_comment_v and (mac_comment_v .. "," ) or "" ).."'"..v.."'"
						end
					end

					if not (need_comment and k == "comment") then
						--检查字段类型,如果字段是数字类型,它的值不是一个数字,那么就返回错误
						if types[k] == "integer" or types[k] == "numeric" or types[k] == "real" then
							if v == "" or not tonumber(v) then
								print($(Iecho i18n_import_export_error_param))
								os.exit(1)
							else
								vals = (vals and (vals .. "," ) or "" )..v
							end
						else
							vals = (vals and (vals .. "," ) or "" ).."'"..v.."'"
						end
						flags = 1
						keys = (keys and (keys .. "," ) or "" )..k
					end

				end
			end
		end
		if flags then
			local sql_cmd = string.format("insert into %s(%s) values(%s);","$tablename",keys,vals)

			res = tmpdb:exec(sql_cmd)
			if res ~= 0 then
				local err = tmpdb:error_message()
				local tbname,key = err:match("UNIQUE constraint failed: (.+)%.(.+)")
				if ikdebug ~= "" then
					print(err)
				end

				if tbname then
					print($(Iecho i18n_import_export_error_unique))
				else
					print($(Iecho i18n_import_export_error_import))
				end
				os.exit(1)
			else
				if ( "$tablename" == "arp" or "$tablename" == "dhcp_static" or "$tablename" == "acl_mac_black" or "$tablename" == "acl_mac_white" or "$tablename" == "dhcp_acl_mac_black" or "$tablename" == "dhcp_acl_mac_white") and mac_comment_k and mac_comment_v then
					sql_cmd = sql_cmd .. string.format("insert into %s(%s) values(%s);","mac_comment",mac_comment_k,mac_comment_v)
				end
				table.insert(import,sql_cmd)
			end
		end
	end

	tmpdb:close()


	local f = io.open("$TEMP_FILE","w")
	if f then
		f:write("PRAGMA foreign_keys=OFF;\n")
		f:write("BEGIN TRANSACTION;\n")
		if append ~= "1" then
			f:write("delete from $tablename ${where:+where $where};\n")
		end
		for i, sql_cmd in pairs(import) do
			f:write(sql_cmd.."\n")
		end
		f:write("COMMIT;\n")
		f:close()
	end
	os.exit(0)
!LuaEof!
	)
	if [ -n "$ErrorMsg" ];then
		if [ "${ErrorMsg::4}" = "lua:" ];then
			[ "$IKDEBUG" = "1" ] && echo "$ErrorMsg"
		else
			echo "$ErrorMsg"
		fi
		rm -f $TEMP_FILE $file
		return 1
	else

		if [ -n "$clean_func" -a "${clean_func,,}" != "null" ];then
			if ! declare -F $clean_func >/dev/null 2>&1 ;then
				[ "$IKDEBUG" = "1" ] && echo "not found function <$clean_func>"
				return 1
			fi
			$clean_func >/dev/null 2>&1
		fi
		sqlite3 $DB < $TEMP_FILE
		rm -f $TEMP_FILE $file
		return 0
	fi

}
