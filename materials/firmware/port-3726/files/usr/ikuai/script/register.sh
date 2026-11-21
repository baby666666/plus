#!/bin/bash /etc/ikcommon

Include ifether.sh, sys/sysstat.sh, json.sh
I18nload register.json

boot()
{
	init
}

init()
{
	sql_config_get_list $IK_DB_CONFIG "select * from register"|\
	while read config ;do
		local $config
		if [ "$ENTERPRISE" -o "$ARCH" != "x86" -o "$OEMNAME" ];then
			echo "${node:-0}" >/tmp/iktmp/cache/cloud_node
		else
			#如果是x86的普通版本,强制指定
			echo "0" >/tmp/iktmp/cache/cloud_node
		fi
		if [ -n "$code" ];then
			__bind_ok
		else
			__bind_fail
		fi
	done

	local res
	while :;do
		__check_bind
		case $? in
		0) break ;;
		1) sleep 10 ;;
		2) break ;;
		*) sleep 1;;
		esac
	done

	##如果没有绑定的情况下，并且有自动配置,则使用自动配置绑定
	local __register_status=$(cat /tmp/iktmp/register_status)
	if [ -f /etc/mnt/ikuai/auto_bind_cloud  -a "$__register_status" != 1 ];then
		__auto_config_bind
	fi
}

save()
{
	__check_param || exit 1
	local MAC=$DEVICE_MAC
	encrypt="$(echo -n "${GWID::9}${code:10:14}"|md5sum)"

	if [ "$ARCH" = "x86" -a "$ENTERPRISE" = "" ];then
		if [ "$gwid" != "$GWID" ];then
			local Type=restore
		else
			local Type=bind
		fi
	else
		local gwid=$GWID
		local Type=bind
	fi
	post_sting="type=$Type&version=$VERSION&build_date=$BUILD_DATE&sysbit=$SYSBIT&oemname=$OEMNAME&developer=$DEVELOPER&enterprise=$ENTERPRISE&gwid=$gwid&account_code=$code&encrypt=${encrypt:0:32}&comment=$comment&firmware=$FIRMWARENAME&mac=$MAC"

	if [ "$ENTERPRISE" -o "$ARCH" != "x86" -o "$OEMNAME" ];then
		local old_cloud_node=$(cat /tmp/iktmp/cache/cloud_node)
		if [ "$old_cloud_node" != "${node:-0}" ];then
			echo "${node:-0}" >/tmp/iktmp/cache/cloud_node
			$IK_DIR_SCRIPT/utils/update_hosts.sh __update_host >/dev/null 2>&1
		fi
	fi

	local __http_status
	local __wget_res

	if [ "$OEMCLOUD" ];then
		local hosts="${OEMCLOUD//,/ }"
	else
		local hosts="$(cat $IK_DIR_HOSTS/register 2>/dev/null)"
	fi

	if [ "$OEM_CLOUD_BIND" ];then
		local bind_path=$OEM_CLOUD_BIND
	else
		local bind_path="bind2"
	fi

	if [ "$node" != "0" ]; then
		local hosts="$(cat $IK_DIR_HOSTS/register 2>/dev/null)"
		local bind_path="bind2"
	fi

	for host in $hosts ;do
		if json_res=$(wget -4 -O- -S -q -t 1 -T 30 --connect-timeout=30 --dns-timeout=20 "https://$host/$bind_path" --post-data="${post_sting}" 2>/tmp/.register_bind_error.$$ ) ;then
			__wget_res="ok"
			break
		else
			__http_status=$(awk 'NR==1 && ($1=="HTTP/1.1" || $1=="HTTP/1.0"){print $2}' /tmp/.register_bind_error.$$)
			if [ "$__http_status" ];then
				break;
			fi
		fi
		rm -f /tmp/.register_bind_error.$$
	done

	if [ "$__wget_res" = "ok" ] ;then
		wget_res=0
		json_decode register_res json_res
	else
		if [ "$__http_status" ];then
			local_errmsg="$(Iecho i18n_register_server_internal_error $__http_status)"
		else
			wget_res=-1
			ping -i 0.3 -c 5 -w 3 114.114.114.114 >/dev/null 2>/dev/null || \
			ping -i 0.3 -c 5 -w 3 223.5.5.5 >/dev/null 2>/dev/null || \
			ikcheck dns www.baidu.com -d 114.114.114.114 -c 1 -t 1 >/dev/null 2>/dev/null

			if [ "$?" != "0" ] ;then
				local_errmsg="$(Iecho i18n_register_connect_net_error)"
			else
				local_errmsg="$(Iecho i18n_register_connect_server_error)"
			fi
		fi
	fi

	if [ "$wget_res" = "0" ] ;then
		if [ "$register_res_status" = "0" ] ;then
			local SqlMsg
			if SqlMsg=$(sql_config_update $IK_DB_CONFIG register "id=1" node:int code:str comment:str) ;then
				__bind_ok
				if [ "$Type" = "restore" ];then
					__reset_gwid
				fi
				return 0
			else
				echo "$SqlMsg"
				__bind_fail
				return 1
			fi
		else
			local LANG=$(GetLang)
			eval __errmsg=\$register_res_errmsg_$LANG
			#如果指定语言找不到, 自动找英文
			echo "${__errmsg:-$register_res_errmsg_2}, errnum = $register_res_status"
			__bind_fail
			return 1
		fi
	else
		echo "$local_errmsg"
		return 1
	fi
}

__connect_scode_server()
{
	if [ "$1" = "create" ];then
		local u="createdServerCode"
	else
		local u="terminationServerCode"
	fi
	local ts=$(date +%s)
	local code=$(sqlite3 $IK_DB_CONFIG "select code from register")
	local md5=`echo -n ${ts:3}_serve_code_${GWID}_${code}|md5sum `
	wget -4 -O- -q -t 1 -T 20 --connect-timeout=20 --dns-timeout=10 \
		https://yun.ikuai8.com/api/v3/serverCode/$u --header="Content-Type:application/json;charset=utf8" \
		--post-data="{\"gwid\":\"$GWID\",\"timestamp\":$ts,\"secretkey\":\"${md5:0:32}\"}"
}

__request_scode()
{
	rm -f /tmp/iktmp/scode_result

	__scode_request
	local result=$(__connect_scode_server create)
	if [ "$result" ];then
		local uptime=$(cat /proc/uptime)
		json_decode scode result
		local res
		res+="serve_uptime=${uptime//.*}\n"
		res+="serve_errcode=\"$scode_code\"\n"
		res+="serve_errmsg=\"$scode_message\"\n"
		res+="serve_number=\"$scode_data_code\"\n"
		res+="serve_timeout=\"$scode_data_expiration_at\"\n"

		echo -e "$res" > /tmp/iktmp/scode_result
		__scode_success
	else
		__scode_error
	fi
}

request_scode()
{
	__request_scode >/dev/null 2>&1 &
}

disable_scode()
{
	rm -f /tmp/iktmp/scode_result
	__scode_disable
	__connect_scode_server termination >/dev/null 2>&1 &
}

show()
{
	Show __json_result__
}

__show_data()
{
	__check_bind_async
	local sql_show="select * from register"
	local data=$(sql_config_get_json $IK_DB_CONFIG "$sql_show")
	json_append __json_result__ data:json

	return 0
}

__show_gwid()
{
	local gwid=$GWID
	json_append __json_result__ gwid:str

	return 0
}

__show_bind_addr()
{
	local qraddr=""
	local yunaddr=""
	if [ "$OEM_CLOUD_QRADDR" ]; then
		qraddr="$OEM_CLOUD_QRADDR"
	fi
	if [ "$OEMCLOUD" ]; then
		yunaddr="$OEMCLOUD"
	fi
	json_append __json_result__ qraddr:str yunaddr:str

	return 0
}


__show_scode()
{
	local status=$(cat /tmp/iktmp/scode_status 2>/dev/null)
	local uptime=$(cat /proc/uptime)
	. /tmp/iktmp/scode_result
	
	if [ "$serve_timeout" ];then
		local x=$((${uptime//.*} - serve_uptime))
		##如果已经超时了
		if [ "$x" -ge "$serve_timeout" ];then
			rm -f /tmp/iktmp/scode_status /tmp/iktmp/scode_result
			unset serve_errcode serve_errmsg serve_number serve_timeout
		else
			serve_timeout=$((serve_timeout - x))
		fi
	fi

	local scode=$(json_output status:int serve_errcode:str serve_errmsg:str serve_timeout:str serve_number:str)
	json_append __json_result__ scode:json
}

__show_customer_service()
{
	local online_cs_url="https://www.ikuai8.com/templates/ikuaitemplate/support.php?ac=api"
	local customer_service=$(curl -4 -X GET  -s --connect-timeout 10 $online_cs_url)
	json_append __json_result__ customer_service:json
}

#异步检查绑定, 在页面访问的时候,需要触发异步检查
__check_bind_async()
{
	__check_bind >/dev/null 2>&1 &
}

#检查GWID 是否已经绑定
#检查动作 一次只有一个任务在进行, 如果多个检查任务并行, 那么后面一个是 return 0
#每次检查 的时间
__check_bind()
{
	local last_uptime code comment
	[ -f /tmp/.on_register_check_bind ]&& return 0
	touch /tmp/.on_register_check_bind

	local uptime=$(sysstat_get_uptime)
	#开机也会做检查, 这时候uptime的差值 可能会 低于30秒,所以直接检查是否有缓存文件,避免开机不自动检查的bug
	if [ -f /tmp/.register_check_bind_last_uptime ];then
		. /tmp/.register_check_bind_last_uptime
		if [ "$((uptime - last_uptime))" -lt 20 ];then
			rm -f /tmp/.on_register_check_bind
			return 0
		fi
	fi

	local config
	local __wget_res
	if [ "$OEMCLOUD" ];then
		local hosts="${OEMCLOUD//,/ }"
		local node=$(cat /tmp/iktmp/cache/cloud_node)
	else
		local node=$(cat /tmp/iktmp/cache/cloud_node)
		local hosts="$(cat $IK_DIR_HOSTS/register 2>/dev/null)"
	fi
	local now_node=${node:-0}
	local node=${node:-0}

	if [ "$OEM_CLOUD_CHECK" ];then
		local check_bind_path=$OEM_CLOUD_CHECK
	else
		local check_bind_path="bind2/checkbind"
	fi
	if [ "$node" != "0" ]; then
		local hosts="$(cat $IK_DIR_HOSTS/register 2>/dev/null)"
		local check_bind_path="bind2/checkbind"
	fi

	for host in $hosts ;do
		if config=$(wget -4 -O- -q -t 1 -T 20 --connect-timeout=20 --dns-timeout=10 "https://$host/$check_bind_path" --post-data="gwid=$GWID" ) ;then
			local ${config:-Null} 2>/dev/null
			if [ "$status" -o "$code" ]; then
				__wget_res="ok"	
			fi
			break
		fi
	done

	if [ "$__wget_res" = "ok" ];then
		if [ "${status:-0}" = "0" ];then
			__bind_fail
			local return_res=2
		else
			__bind_ok
			local return_res=0
		fi
		if [ "$now_node" != "$node" ]; then
			echo "${node:-0}" >/tmp/iktmp/cache/cloud_node
			$IK_DIR_SCRIPT/utils/update_hosts.sh __update_host >/dev/null 2>&1
		fi
		sql_config_update $IK_DB_CONFIG register "id=1" code:str comment:str ${node:+node:int} >/dev/null 2>&1
	else
		__bind_connect_fail
		local return_res=1
	fi

	rm -f /tmp/.on_register_check_bind
	echo "last_uptime=$uptime" >/tmp/.register_check_bind_last_uptime
	return $return_res
}

__check_param()
{
	check_varl \
		'gwid != "" and match "[a-f0-9]" and length == 32'\
		'node >= 0 and <= 2 '\
		'code != ""'\
		'comment != ""'
}

__check_param_change_bind()
{
	check_varl \
		'target_phone	!= "" and match "[0-9]" and length == 11 '\
		'sms_code != ""'\
		'sess_id != ""'\
		'remark != ""'
}



__reset_gwid()
{
	if [ "$gwid" = "" ];then
		local gwid=$(date +%s%N|md5sum)
		local gwid=${gwid:0:32}
	fi

	if ! [[ "$gwid" =~ ^[0-9a-f]{32}$ ]];then
		echo "Invalid GWID"
		return 1
	fi

	case "$ARCH" in
	x86|arm)
		if [ "$BOOTGUIDE" = "flash" ];then
			Include sys/mtd_control.sh
			mtd_set_gwid $gwid
		else
			Include sys/hdd_control.sh
			hdd_set_gwid $BOOTHDD $gwid
		fi
		;;
	mips)
		Include sys/mtd_control.sh
		mtd_set_gwid $gwid
		;;
	*) return 1;
	esac

	sed -i "s/^GWID=.*/$gwid/" /etc/release
	(sleep 3; reboot) >/dev/null 2>&1 &
}

__bind_ok() { echo 1 >/tmp/iktmp/register_status ; }
__bind_fail() { echo 0 >/tmp/iktmp/register_status ; }
__bind_connect_fail() { echo 2 >/tmp/iktmp/register_status ; }

__socde_error()   { echo -1 >/tmp/iktmp/scode_status ; }
__scode_disable() { echo 0 >/tmp/iktmp/scode_status ; }
__scode_request() { echo 1 >/tmp/iktmp/scode_status ; }
__scode_success() { echo 2 >/tmp/iktmp/scode_status ; }



__auto_config_bind()
{
	local MAC=$DEVICE_MAC
	local gwid=$GWID
	local Type=bind

	local code=$(awk 'NR==1{print }' /etc/mnt/ikuai/auto_bind_cloud)
	local comment=$(awk 'NR==2{print }' /etc/mnt/ikuai/auto_bind_cloud)
	local node=$(awk 'NR==3{print }' /etc/mnt/ikuai/auto_bind_cloud)
	local encrypt="$(echo -n "${GWID::9}${code:10:14}"|md5sum)"
	local __http_status
	local __wget_res
	post_sting="type=$Type&version=$VERSION&build_date=$BUILD_DATE&sysbit=$SYSBIT&oemname=$OEMNAME&developer=$DEVELOPER&enterprise=$ENTERPRISE&gwid=$gwid&account_code=$code&encrypt=${encrypt:0:32}&comment=$comment&firmware=$FIRMWARENAME&mac=$MAC"

	local node=${node:-0}
	if [ "$node" != "0" ]; then
		echo "${node:-0}" >/tmp/iktmp/cache/cloud_node
		$IK_DIR_SCRIPT/utils/update_hosts.sh __update_host >/dev/null 2>&1
	fi

	while :;do 
		if [ "$OEMCLOUD" ];then
			local hosts="${OEMCLOUD//,/ }"
		else
			local hosts="$(cat $IK_DIR_HOSTS/register 2>/dev/null)"
		fi
		[ "$hosts" ] && break
	done

	if [ "$OEM_CLOUD_BIND" ];then
		local bind_path=$OEM_CLOUD_BIND
	else
		local bind_path="bind2"
	fi

	if [ "$node" != "0" ]; then
		local hosts="$(cat $IK_DIR_HOSTS/register 2>/dev/null)"
		local bind_path="bind2"
	fi

	local continuex=1
	while :;do
		for host in $hosts ;do
			if json_res=$(wget -4 -O- -S -q -t 1 -T 30 --connect-timeout=30 --dns-timeout=20 "https://$host/$bind_path" --post-data="${post_sting}" 2>/var/log/auto_config_bind.log ) ;then
				__wget_res="ok"
				continuex=0
				break
			else
				__http_status=$(awk 'NR==1 && ($1=="HTTP/1.1" || $1=="HTTP/1.0"){print $2}' /var/log/auto_config_bind.log)
				if [ "$__http_status" ];then
					continuex=0
					break;
				fi
			fi
		done

		if [ "$continuex" = "1" ];then
			sleep 10
		else
			break
		fi
	done

	rm -f /etc/mnt/ikuai/auto_bind_cloud
	if [ "$__wget_res" = "ok" ] ;then
		json_decode register_res json_res
		if [ "$register_res_status" = "0" ] ;then
			local SqlMsg
			if SqlMsg=$(sql_config_update $IK_DB_CONFIG register "id=1" code:str comment:str node:int) ;then
				__bind_ok
				return 0
			else
				__bind_fail
				return 1
			fi
		else
			__bind_fail
			return 1
		fi
	else
		echo "request info:" >>/var/log/auto_config_bind.log
		echo "url: https://$host/$bind_path" >>/var/log/auto_config_bind.log
		echo "post: ${post_sting}" >>/var/log/auto_config_bind.log
		return 1
	fi

}


__get_cloud_services()
{
	local account_code=$(sqlite3 $IK_DB_CONFIG "select code from register;")
	if [ "$account_code" == "" ];then
		return 1
	fi

	local hosts=""
	if [ "$OEMCLOUD" ];then
		hosts="${OEMCLOUD//,/ }"
	else
		hosts="$(cat $IK_DIR_HOSTS/register 2>/dev/null)"
	fi

	local post_sting="gwid=$GWID&account_code=$account_code"
	local json_res=""
	for host in $hosts ;do
		if json_res=$(wget -4 -O- -S -q -t 1 -T 10 --connect-timeout=10 --dns-timeout=20 "https://$host/api/v3/router_subscription?${post_sting}" 2>/tmp/.register_cloud_business_error.$$ );then
			break
		fi
	done
	rm -rf /tmp/.register_cloud_business_error.$$
	echo $json_res
	return 0
}

__show_services()
{
	local status=1
	local errinfo=""
	local subscription="[]"
	local otherTips="[]"
	local msg=$(__get_cloud_services)

	if [ "$msg" != "" ];then
		local code=$(echo "$msg"|jq .code)
		if [ "$code" = "2000" ]; then
			status=1
			local errinfo="success"
			subscription=$(echo "$msg"|jq .data.subscription)
			otherTips=$(echo "$msg"|jq .data.otherTips)
		else
			errinfo=$(echo "$msg" | jq -r .messag)
			status=2
		fi
	else
		ping -i 0.3 -c 5 -w 3 114.114.114.114 >/dev/null 2>/dev/null || \
		ping -i 0.3 -c 5 -w 3 223.5.5.5 >/dev/null 2>/dev/null || \
		ikcheck dns www.baidu.com -d 114.114.114.114 -c 1 -t 1 >/dev/null 2>/dev/null

		if [ "$?" != "0" ] ;then
			errinfo="$(Iecho i18n_register_connect_error)"
		else
			errinfo="$(Iecho i18n_register_connect_server_error)"
		fi
		status=3
	fi
	local services=$(json_output status:int errinfo:str subscription:json otherTips:json)
	json_append __json_result__ services:json
}


__get_sms_code()
{
	local account_code=$(sqlite3 $IK_DB_CONFIG "select code from register;")
	if [ "$account_code" == "" ];then
		return 1
	fi
	local hosts=""
	if [ "$OEMCLOUD" ];then
		hosts="${OEMCLOUD//,/ }"
	else
		hosts="$(cat $IK_DIR_HOSTS/register 2>/dev/null)"
	fi

	local body="{\"gwid\":\"$GWID\", \"source_account_code\":\"$account_code\",\"target_phone\":\"$target_phone\"}"
	local res=""
	for host in $hosts ;do
		if res=$(curl -4 -X POST -s --connect-timeout 10 https://$host/api/v3/router_bind/change_bind/get_sms_code -H 'Accept: */*' -H 'Content-Type: application/json' -d "$body") ;then
			break
		fi
	done
	echo $res
}
__show_sms_code()
{
	if [ "$target_phone" == "" ]; then
		errinfo="Mobile phone number cannot be empty"
		status=2
		sess_id=""
		local sms_code=$(json_output status:int errinfo:str sess_id:str)
		json_append __json_result__ sms_code:json
		return 1
	fi
	local errinfo=""
	local sess_id=""
	local code=0
	local msg=$(__get_sms_code)
	if [ "$msg" != "" ];then
		local code=$(echo "$msg"|jq .code)
		if [ "$code" = "2000" ]; then
			status=1
			errinfo="success"
			sess_id=$(echo "$msg"|jq -r .data.sess_id)
		else
			errinfo=$(echo "$msg" | jq -r .message)
			status=2
		fi
	else
		ping -i 0.3 -c 5 -w 3 114.114.114.114 >/dev/null 2>/dev/null || \
		ping -i 0.3 -c 5 -w 3 223.5.5.5 >/dev/null 2>/dev/null || \
		ikcheck dns www.baidu.com -d 114.114.114.114 -c 1 -t 1 >/dev/null 2>/dev/null

		if [ "$?" != "0" ] ;then
			errinfo="$(Iecho i18n_register_connect_error)"
		else
			errinfo="$(Iecho i18n_register_connect_server_error)"
		fi
		status=3
	fi
	local sms_code=$(json_output status:int errinfo:str sess_id:str code:int)
	json_append __json_result__ sms_code:json
}

bind_update(){
	__check_param_change_bind || exit 1
	local hosts=""
	if [ "$OEMCLOUD" ];then
		hosts="${OEMCLOUD//,/ }"
	else
		hosts="$(cat $IK_DIR_HOSTS/register 2>/dev/null)"
	fi

	sql_config_get_list  $IK_DB_CONFIG "select * from register where id=1;" |\
	while read config ;do
		local $config
		if [ "$code" == "" ];then
			return 1
		fi
		local body="{\"gwid\":\"$GWID\", \"source_account_code\":\"$code\",\"target_phone\":\"$target_phone\",\"sms_code\":\"$sms_code\",\"sess_id\":\"$sess_id\",\"remark\":\"$remark\"}"
		local res=""
		for host in $hosts ;do
			if res=$(curl -4 -X POST  -s --connect-timeout 10 https://$host/api/v3/router_bind/change_bind/bind  -H 'Content-Type: application/json'  -d "$body");then
				break
			fi
		done
		if [ "$res" != "" ];then
			local res_code=$(echo "$res"|jq .code)
			if  [ "$res_code" = "2000" ]; then
				local SqlMsg
				local code=$(echo "$res" | jq -r .data.account_code)
				local new_node=$(echo "$res" | jq -r .data.node)
				if [ "$new_node" != "$node" ]; then
					echo "${new_node:-0}" >/tmp/iktmp/cache/cloud_node
					$IK_DIR_SCRIPT/utils/update_hosts.sh __update_host >/dev/null 2>&1
				fi
				comment=$remark
				node=${newnode:-0}
				if SqlMsg=$(sql_config_update $IK_DB_CONFIG register "id=1" node:int code:str comment:str) ;then
					return 0
				else
					echo "$SqlMsg"
					return 1
				fi
				return 0
			else
				echo $res | jq -r .message
				return 1
			fi
		else
			local errinfo=""
			ping -i 0.3 -c 5 -w 3 114.114.114.114 >/dev/null 2>/dev/null || \
			ping -i 0.3 -c 5 -w 3 223.5.5.5 >/dev/null 2>/dev/null || \
			ikcheck dns www.baidu.com -d 114.114.114.114 -c 1 -t 1 >/dev/null 2>/dev/null

			if [ "$?" != "0" ] ;then
				errinfo="$(Iecho i18n_register_connect_error)"
			else
				errinfo="$(Iecho i18n_register_connect_server_error)"
			fi
			echo $errinfo
			return 1
		fi
	done
}

cloud_async()
{
	local node=$(sqlite3 $IK_DB_CONFIG "select node from register;")
	__bind_fail
	sql_config_update $IK_DB_CONFIG register "id=1" code:str comment:str node:int >/dev/null 2>&1
	#删除体验版标志
	if [ -f "/etc/mnt/ikuai/user_accept" ];then
		rm /etc/mnt/beta/user_accept >/dev/null
	fi
	if [ -f "/etc/mnt/ikuai/beta_flag" ];then
		rm /etc/mnt/ikuai/beta_flag >/dev/null
	fi
	#__check_bind >/dev/null 2>&1 &
}
