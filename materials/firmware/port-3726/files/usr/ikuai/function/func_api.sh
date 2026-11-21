#!/bin/bash
export IK_FUNC_API=1
S0="$*"
IK_DIR_FUNCAPI=/usr/ikuai/function

#DEBUG=1
DEBUG_OUTPUT_FILE="/tmp/func_api_debug.log"

ResOK=30000
ResAddErr=30001
ResModErr=30002
ResNotFunc=30003
ResImportErr=30004
ResExportErr=30005
ResShowErr=30006

NORETURN=0

if [ ! -f "$IK_DIR_FUNCAPI/$1" ];then
	echo "{\"Result\":$ResModErr,\"ErrMsg\":\"Not found funcname($1)\"}"
	exit
else
	#检查调用的函数是否公开的并合法有效, 函数中带有 下划线开头的, 表示该函数是内部使用
	check_res=""
	while read line;do
		if [[ "$line" =~ ^([A-Za-z][A-Za-z0-9._@%]+)" "*\(\) ]]&& [ "${BASH_REMATCH[1]}" = "$2" ] ;then
			check_res="ok"
			break
		fi
	done < $IK_DIR_FUNCAPI/$1

	if [ "$check_res" != "ok" ];then
		echo "{\"Result\":$ResModErr,\"ErrMsg\":\"invalid action\"}"
		exit
	fi
fi


for i in $(ls /proc/self/fd 2>/dev/null);do
	[ "$i" -ge 3 ] && eval "exec $i<&-"
done

Debug()
{
	if [ ! "$DEBUG" ];then
		return
	fi
	echo "sciprt: $IK_DIR_FUNCAPI/$S0" >>$DEBUG_OUTPUT_FILE
}

#master
Exec_Vrrp()
{
	local IK_DIR_VRRP="/tmp/iktmp/vrrp"

	if [ ! -f $IK_DIR_VRRP/is_enabled ]; then
		return
	fi

	if [ ! -f $IK_DIR_VRRP/auto_sync ]; then
		return
	fi

	[ -f "$IK_DIR_VRRP/status" ] && {
		local status="$(cat $IK_DIR_VRRP/status)"
	}
	if ! [ "$status" = "master" -o "$status" = "load" ]; then
		return
	fi
	
	if [ "$status" = "load" -a ! -f "$IK_DIR_VRRP/load_is_master" ]; then
		return
	fi

	if [ "$NORETURN" = "0" -a "$Result" != "$ResOK" ]; then
		return
	fi
	local vrrp_config=($S0)
	local module="${vrrp_config[0]}"
	local action="${vrrp_config[1]}"
	local params name

	local VRRP_INCL_FUNC="acl acl_l2route acl_l7 acl_mac acl_qq ac_server ac_group advanced arp audit audit_white conn_limit coupon custom_isp \
			      dhcp_acl_mac dhcp_lease dhcp_server dnat dns dns_replace domain_blacklist domain_group dprotos dprotos_l7 dt_mac_qos ipgroup ipv6group\
			      ipsec-vpn ipv6 l2tp_client l2tp_server lb_pcc mac_comment macgroup mac_qos nat_rule notice_cycle notice_expires notice_remind notice_temp \
			      openvpn-server pppoe_server ppp_package ppp_passwd pppuser pptp_client pptp_server simple_qos static_rt stream_domain stream_ipport stream_layer7 stream_updown \
			      upnpd url_black url_keywords url_redirect url_replace vlan webauth wifi wls_black wls_mvlan ike_server ike_client openvpn-client wireguard"
	local allow=0
	for mod in ${VRRP_INCL_FUNC}; do
		if [ "$mod" = "$module" ]; then
			allow=1
		fi
	done
	if [ "$allow" != "1" ]; then
		return
	fi

	if echo "$VRRP_EXCL_FUNC"| grep -q "$module"; then
		return
	fi

	if [ "$action" = "show" -o "$action" = "EXPORT" ]; then
		return
	fi
	
	local $(cat $IK_DIR_VRRP/config)

	if [ "$action" = "IMPORT" ]; then
		ik_confsync_client -t table -c "modules=$module" >/dev/null 2>&1
	else
		for ((i=2; i<${#vrrp_config[*]};i++))
		do 
			params+="${vrrp_config[i]} "
		done

		if ! ik_confsync_client -t conf -d $remote_addr -m $module -a $action -c "$params"  >/dev/null 2>&1; then
			echo "$module" >> $IK_DIR_VRRP/sync_failed_modules
		fi
	fi
}

Exec_NoReturn()
{
	NORETURN=1
	echo "{\"Result\":$ResOK,\"ErrMsg\":\"Success\"}"
	exec 1>/dev/null
	$IK_DIR_FUNCAPI/$S0 >/dev/null 2>/dev/null
}

Exec_NoReturn_Back()
{
	NORETURN=1
	echo "{\"Result\":$ResOK,\"ErrMsg\":\"Success\"}"
	exec 1>/dev/null 
	$IK_DIR_FUNCAPI/$S0 >/dev/null 2>/dev/null &
}

Exec_Return_Id()
{
	if ErrMsg=$($IK_DIR_FUNCAPI/$S0 2>/dev/null) ;then
		Result=$ResOK
		RowId=$ErrMsg
		ErrMsg="Success"
	else
		Result=$ResAddErr
		rowid=0
	fi
	if [[ "$ErrMsg" =~ ^\((.+)\)已有相同内容存在 ]] || [[ "$ErrMsg" =~ ^\((.+)\)"is already has the same content, it is unique" ]] ;then
		echo "{\"Result\":$Result,\"ErrMsg\":\"$ErrMsg\",\"ErrKeyUnique\":\"${BASH_REMATCH[1]}\",\"RowId\":${RowId:-0}}"
	else
		echo "{\"Result\":$Result,\"ErrMsg\":\"$ErrMsg\",\"RowId\":${RowId:-0}}"
	fi
}

Exec_Return()
{
	if ErrMsg=$($IK_DIR_FUNCAPI/$S0 2>/dev/null) ;then
		Result=$ResOK
		ErrMsg="Success"
	else
		Result=$ResModErr
	fi

	if [[ "$ErrMsg" =~ ^\((.+)\)已有相同内容存在 ]] || [[ "$ErrMsg" =~ ^\((.+)\)"is already has the same content, it is unique" ]] ;then
		echo "{\"Result\":$Result,\"ErrMsg\":\"$ErrMsg\",\"ErrKeyUnique\":\"${BASH_REMATCH[1]}\"}"
	else
		echo "{\"Result\":$Result,\"ErrMsg\":\"$ErrMsg\"}"
	fi
}

Exec_Import()
{
	if ErrMsg=$($IK_DIR_FUNCAPI/$S0 2>/dev/null) ;then
		Result="$ResOK"
		ErrMsg="Success"
	else
		Result="$ResImportErr"
	fi
	echo "{\"Result\":$Result,\"ErrMsg\":\"${ErrMsg//\*/\\\*}\"}"
}

Exec_Export()
{
	if ErrMsg=$($IK_DIR_FUNCAPI/$S0 2>/dev/null) ;then
		Result="$ResOK"
		Filename="$ErrMsg"
		ErrMsg="Success"
	else
		Result="$ResExportErr"
	fi
	echo "{\"Result\":$Result,\"ErrMsg\":\"$ErrMsg\",\"Filename\":\"$Filename\"}"
}

Show()
{
	if Data=$($IK_DIR_FUNCAPI/$S0 2>/dev/null) ;then
		echo "{\"Result\":$ResOK,\"ErrMsg\":\"Success\",\"Data\":$Data}"
	else
		echo "{\"Result\":$ResShowErr,\"ErrMsg\":\"$Data\"}"
	fi
}

Debug

if [ "${1:0:7}" = "docker_" ];then
	case $2 in
		show) 
			Show
		;;
		add)
			Exec_Return_Id
		;;
		*)
			Exec_Return
		;;
	esac
else
	case $2 in
		show) 
			Show
		;;
		create)
			if [ "$1" = "lan" -o "$1" = "wan" ];then
				Exec_Return_Id
			else
				Exec_Return
			fi
		;;
		delete)
			if [ "$1" = "lan" -o "$1" = "wan" ];then
				Exec_NoReturn_Back
			else
				Exec_Return
			fi
		;;
		add)
			Exec_Return_Id
		;;
		down|up|del|clean)
			# WG mutations must finish before success is returned; propagate apply failures.
			if [ "$1 $2" = "ppp_package del" -o "$1 $2" = "qemu up" -o "$1 $2" = "ike_client up" -o "$1 $2" = "wireguard up" -o "$1 $2" = "wireguard down" -o "$1 $2" = "wireguard del" ];then
				Exec_Return
			else
				Exec_NoReturn_Back
			fi
		;;
		dump_info)
			Exec_Export
		;;
		EXPORT|EXPORT_lan|EXPORT_EXTEND)
			Exec_Export
		;;
		IMPORT|IMPORT_lan|IMPORT_EXTEND)
			Exec_Import
			sleep 1
		;;
		*)
			Exec_Return
		;;
	esac
fi

Exec_Vrrp
