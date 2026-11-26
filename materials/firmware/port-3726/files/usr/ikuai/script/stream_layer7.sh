#!/bin/bash /etc/ikcommon
Include ipset.sh interface.sh iproute.sh lock.sh iptables.sh ipmacgroup.sh dpi/appid.sh
LOCKUP="Lock stream_layer7"
UNLOCK="unLock stream_layer7"
proto_list=/tmp/iktmp/protocols

INIT_CONFIG="/tmp/stream_layer7.iptables"
boot()
{
	init
}
# Validate each ordered exit with the native checker. The native ifnames_*
# predicates require a homogeneous list, so WAN+VPN must be checked itemwise.
# IMPORT is checked per input row; shell defaults are not the import contents.
nr_check_exit_interfaces(){
 local allow_blackhole="$1" allow_nexthop="$2" input="${S0:-}" file="${_______CHECK_VARL_IMPORT_FILE_______:-}"
 local line field exits rowtype item
 local -a fields parts
 if [ -n "$file" ];then input=$(cat "$file") || return 1;fi
 # Keep serialized validation local; never rewrite the stored interface list.
 local S0='' _______CHECK_VARL_IMPORT_FILE_______=''
 while IFS= read -r line;do
  [ -n "${line//[[:space:]]/}" ] || continue
  exits='';rowtype=''
  read -r -a fields <<< "$line"
  for field in "${fields[@]}";do
   case "$field" in interface=*) exits="${field#*=}";;type=*) rowtype="${field#*=}";;esac
  done
  [ "$allow_nexthop" != 1 ] || [ "$rowtype" != 1 ] || continue
  case "$exits" in ''|,*|*,|*,,*) echo '出口接口列表无效';return 1;;esac
  if [ "$allow_blackhole" = 1 ] && [ "$exits" = blackhole ];then continue;fi
  IFS=, read -r -a parts <<< "$exits"
  for item in "${parts[@]}";do
   interface_check_routing_exit "$item" || return 1
   S0="interface=$item"
   check_varl 'interface ifnames_wan or ifnames_vpn' || return 1
  done
 done <<< "$input"
}
__check_param()
{
	interface_check_routing_exit "$interface" || return 1
	check_varl \
		'interface not match "^pppwg%d+$" and not match "^pppwg%d+," and not match ",pppwg%d+$" and not match ",pppwg%d+,"'\
		'enabled == "yes" or == "no"'\
		'interface != ""'\
		'app_proto != "" ' \
		'week		week' \
		'time		timeranges' || return 1
 nr_check_exit_interfaces 0 0
}

__check_interface_nums()
{
	local tmp_array=(${interface//,/ })
	local count=${#tmp_array[*]}
	if [ "$count" -gt "256" ]; then
		Autoiecho param ifaces_limit	
		return 1
	fi
	return 0
}

init() {
	syn_proxy=$(sqlite3 $IK_DB_CONFIG "select syn_proxy from global_config" )
	[ "$syn_proxy" = "1" ]&&ik_cntl syn_proxy enable >/dev/null 2>/dev/null

	iptables -w -t mangle -F STREAM_LAYER7_ALL
	$LOCKUP
	__exec_rule_clean
	sql_config_get_list $IK_DB_CONFIG "select * from stream_layer7" |\
	while read config ;do
		src= connmark_ids= nr_ingress=
		if [ -n "$config" ];then
			local $config
			src=$(__format_ipset src)
			[ "$enabled" = "yes" ]&& {
				__exec_rule_add >/dev/null 2>/dev/null
			}
		fi
	done
	__exec_rule_commit >/dev/null 2>/dev/null
	$UNLOCK
}

nr_original_vrrp_init()
{
	__clean
	ik_cntl syn_proxy disable >/dev/null 2>/dev/null
	sqlite3 $IK_DB_CONFIG "delete from stream_layer7; delete from global_config"	
	sqlite3 $IK_DIR_LOG/vrrp/conf/config.db ".dump global_config" |grep "^INSERT"| sqlite3 $IK_DB_CONFIG
	sqlite3 $IK_DIR_LOG/vrrp/conf/config.db ".dump stream_layer7" |grep "^INSERT"| sqlite3 $IK_DB_CONFIG
	init
}

__exec_rule_clean()
{
	> /tmp/iktmp/ipt_rule_id/stream_layer7_id_rule
}

__exec_rule_commit()
{
	iptables -w -t mangle -F STREAM_LAYER7_NEW

	> $INIT_CONFIG
	echo "*mangle" >> $INIT_CONFIG
	sort -n -r -k1 /tmp/iktmp/ipt_rule_id/stream_layer7_id_rule |while read rule;do
		echo "${rule//*-t mangle}" >> $INIT_CONFIG
	done
	echo "COMMIT" >> $INIT_CONFIG
	iptables-restore -n -T mangle $INIT_CONFIG >/dev/null 2>&1
	rm $INIT_CONFIG
}

__exec_rule_add() {
	# Scoped rules are compiled in NR_LOWER with their logical ingress aliases.
	# A broad vendor copy would match another input after NR_LOWER returns.
	[ -z "${nr_ingress:-}" ] || return 0

	#封装规则变量
	connmark_ids=
	mark_ids=
	domain_num=

	COMMENT="-m comment --comment $id"
	IPTABLES_RULE_ALL="iptables -w -t mangle -A STREAM_LAYER7_ALL"
	IPTABLES_RULE_NEW="iptables -w -t mangle -A STREAM_LAYER7_NEW"

	local ipt_time=$(ipt_format_time "$week" "$time")
	local appids=""
	local app
	for app in ${app_proto//,/ } ;do
		if [ "${APPIDS[$app]}" ];then
			appids+="${appids:+$LINE_N}${APPIDS[$app]}"
		fi
	done

	appid_p2p=$(echo "$appids" | awk '{if($1>=2000000 && $1 <=2989999){if(a==1)printf ",";printf "%s",$1;a=1}}')
	appid_other=$(echo "$appids" | awk ' {if($1!="" && ($1<2000000 || $1 >2989999)){if(a==1)printf ",";printf "%s",$1;a=1}}')
	#自定义协议 和 默认协议ID 合并
	appid="${appid_other:+$appid_other,}${appid_d}"
	#循环加载规则 读取CONNMARK ID
	for iface in ${interface//,/ };do
		mark_id=$(iproute_get_markid $iface)
		auto_get_id=$(awk 'END{print $1+1,'$id'>>"/tmp/iktmp/ipt_rule_id/stream_layer7_id";print $1+1}' /tmp/iktmp/ipt_rule_id/stream_layer7_id 2>/dev/null)
		connmark_id=$((IPT_CONNMARK_STREAM_LAYER7+auto_get_id))
		connmark_ids="${connmark_ids:+$connmark_ids,}${connmark_id}"
		mark_ids="${mark_ids:+$mark_ids,}${mark_id}"
		#$IPTABLES_RULE_ALL -m connmark --mark $connmark_id $COMMENT -j MARK --set-mark $mark_id

	done
	local BAND_FLAGS="--set-band-flag ${iface_band:-0}"
	local MODE_FLAGS="--set-mode ${mode:-0}"

	ik_cntl new_tc mark_rule add id $((IPT_CONNMARK_STREAM_LAYER7+id)) connmark ${connmark_ids} skbmark ${mark_ids} >/dev/null
	if [[ "$app_proto" =~ "所有协议" || "$app_proto" =~ "all" ]];then
			CTSTATE="-m conntrack --ctstate NEW"
			echo $id $IPTABLES_RULE_NEW $ipt_time $src $CTSTATE $COMMENT -j NTH_CONNMARK --set-mark ${connmark_ids} --set-ifname $interface $BAND_FLAGS $MODE_FLAGS >>/tmp/iktmp/ipt_rule_id/stream_layer7_id_rule
	else
		if [ -n "$appid_p2p" ];then
			CTSTATE=""
			MATCH_COUNT="-m matchcount --count 1"
			echo $id $IPTABLES_RULE_NEW $ipt_time $src $CTSTATE $COMMENT -m appmark --appid $appid_p2p $MATCH_COUNT  -j NTH_CONNMARK --set-mark ${connmark_ids} --set-ifname $interface $BAND_FLAGS $MODE_FLAGS >>/tmp/iktmp/ipt_rule_id/stream_layer7_id_rule
		fi
		if [ -n "$appid" ];then
			CTSTATE="-m conntrack --ctstate NEW"
			MATCH_COUNT=""
			echo $id $IPTABLES_RULE_NEW $ipt_time $src $CTSTATE $COMMENT -m appmark --appid ${appid%,} $MATCH_COUNT  -j NTH_CONNMARK --set-mark ${connmark_ids} --set-ifname $interface $BAND_FLAGS $MODE_FLAGS >>/tmp/iktmp/ipt_rule_id/stream_layer7_id_rule
		fi
	fi
	
}

__exec_rule_del() {
	local ipt_time=$(ipt_format_time "$week" "$time")
	
	sed -i -r "/^[0-9]+ (${id//,/|})$/d" /tmp/iktmp/ipt_rule_id/stream_layer7_id
	sed -i -r "/^(${id//,/|}) /d" /tmp/iktmp/ipt_rule_id/stream_layer7_id_rule

	num=0
	line_num=`iptables -w -t mangle -L STREAM_LAYER7_NEW -n --line-numbers |awk '$0~/\/\* ('${id//,/|}') \*\//{print $1}'`
	for line in $line_num ;do
		iptables -w -t mangle -D STREAM_LAYER7_NEW $ipt_time $((line-$((num++)))) 2>/dev/null
	done

	for i in ${id//,/ };do
		ik_cntl new_tc mark_rule del id $((IPT_CONNMARK_STREAM_LAYER7+i)) >/dev/null
	done

}

__format_ipset() {
	if [ "$1" = "src" ] ;then
		[ -n "$src_addr" ]&&{
			#循环判断地址类型（普通IP/群组名称）
			ipset_rule_add slayer7_src_$id $src_addr
			echo "-m set --match-set slayer7_src_$id src"
		}
	elif [ "$1" = "dst" ] ;then
		[ -n "$dst_addr" ]&&{
			ipset_rule_add slayer7_dst_$id $dst_addr
			echo "-m set --match-set slayer7_dst_$id dst"
		}
	fi
}

nr_original_add() {
	__check_param || exit 1
	__check_interface_nums || exit 1
	local sql_param='id:null enabled:str comment:str mode:int iface_band:int interface:str src_addr:str app_proto:str week:str time:str nr_ingress:str'
	if SqlMsg=$(sql_config_insert $IK_DB_CONFIG stream_layer7 $sql_param);then
		id=$SqlMsg
		src=$(__format_ipset src)
		[ "$enabled" = "yes" ]&& {
			$LOCKUP
			__exec_rule_add >/dev/null 2>/dev/null
			__exec_rule_commit >/dev/null 2>/dev/null
			$UNLOCK
		}
		$IK_DIR_SCRIPT/stream_domain.sh rule_switch
		echo "$SqlMsg"
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi

}
nr_original_del() {
	sql_config_exec $IK_DB_CONFIG "delete from stream_layer7 where id in ($id);"	
	
	$LOCKUP
	__exec_rule_del >/dev/null 2>/dev/null
	$UNLOCK
	for ID in ${id//,/ };do
		ipset_rule_del slayer7_src_$ID
	done
	$IK_DIR_SCRIPT/stream_domain.sh rule_switch
}
nr_original_up() {
	sql_config_get_list $IK_DB_CONFIG "select * from stream_layer7 where id in ($id) and enabled='no';update stream_layer7 set enabled='yes' where id in ($id);"|while read config ;do
		src= connmark_ids= nr_ingress=
		local $config 
		[ -n "$src_addr" ]&&src="-m set --match-set slayer7_src_$id src"
		$LOCKUP
		__exec_rule_add >/dev/null 2>/dev/null
		$UNLOCK
	done
	__exec_rule_commit >/dev/null 2>/dev/null

	$IK_DIR_SCRIPT/stream_domain.sh rule_switch
}
nr_original_down() {
	sql_config_exec $IK_DB_CONFIG "update stream_layer7 set enabled='no' where id in ($id) ;" 
	$LOCKUP
	__exec_rule_del >/dev/null 2>/dev/null
	$UNLOCK

	$IK_DIR_SCRIPT/stream_domain.sh rule_switch

}
nr_original_edit() {
	__check_param || exit 1
	__check_interface_nums || exit 1
	local sql_param="enabled:str comment:str mode:int iface_band:int interface:str src_addr:str app_proto:str week:str time:str nr_ingress:str"
	res=$(sql_config_get_list $IK_DB_CONFIG "select * from stream_layer7 where id=$id" prefix=old_)
	if [ "$res" = "" ];then
		return 0
	fi
	local $res
	if SqlMsg=$(sql_config_update $IK_DB_CONFIG stream_layer7 "id=$id" $sql_param);then
		if ! NewOldVarl interface mode iface_band src_addr app_proto week time nr_ingress;then
			src=$(__format_ipset src)
			[ "$enabled" = "yes" ]&&{
				$LOCKUP
				__exec_rule_del >/dev/null 2>/dev/null
				__exec_rule_add >/dev/null 2>/dev/null
				__exec_rule_commit >/dev/null 2>/dev/null
				$UNLOCK
			}
		fi
		$IK_DIR_SCRIPT/stream_domain.sh rule_switch
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi
}
__syn_proxy() {
	if [ "$1" = "1" ];then
		ik_cntl syn_proxy enable >/dev/null 2>/dev/null
	else
		ik_cntl syn_proxy disable >/dev/null 2>/dev/null
	fi
}
seting()
{
	local sql_param
	if [ "${CHECK_IS_SETING[syn_proxy]}" ];then
		check_varl 'syn_proxy == 0 or == 1' || exit 1
		sql_param+=" syn_proxy:int"
	fi
	local SqlMsg
	if SqlMsg=$(sql_config_update $IK_DB_CONFIG global_config "id=1" $sql_param) ;then
		__syn_proxy $syn_proxy
		return 0
	else
		echo  "$SqlMsg"
		return 1
	fi
}
__clean() {
	$LOCKUP
	sql_config_get_list $IK_DB_CONFIG "select * from stream_layer7;" |\
	while read config; do
		local $config
		__exec_rule_del >/dev/null 2>/dev/null
		ipset_rule_del slayer7_src_$id
	done
	$UNLOCK
	$IK_DIR_SCRIPT/stream_domain.sh rule_switch
}

EXPORT() {
	Include import_export.sh
	local format=${format:-txt}
	if errmsg=$(export_txt $IK_DB_CONFIG stream_layer7 $format $IK_DIR_EXPORT/stream_layer7.$format) ;then
		echo "stream_layer7.$format"
		return 0
	else
		echo "$errmsg"
		return 1
	fi
}
nr_original_IMPORT() {
	Include import_export.sh
	if errmsg=$(import_txt $IK_DB_CONFIG stream_layer7 $IK_DIR_IMPORT/$filename "$append"  __check_param __clean) ;then
		init >/dev/null 2>/dev/null
		return 0
	else
		echo "$errmsg"
		return 1
	fi
}
show()
{
	local __filter=$(sql_auto_get_filter)
	local __order="order by id desc" # Display the effective first-match priority.
	local __limit=$(sql_auto_get_limit)
	local __where="$__filter $__order $__limit"
	Show __json_result__
}
__show_total()
{
	local total=$(sqlite3 $IK_DB_CONFIG "select count() from stream_layer7 $__filter")
	json_append __json_result__ total:int
}
__show_data()
{
	local sql_show="select * from stream_layer7 $__where"
	local data=$(sql_config_get_json $IK_DB_CONFIG "$sql_show")
	json_append __json_result__ data:json
	return 0;
}
__show_interface()
{
	interface_get_name_to_cache_wan >/dev/null 2>&1
	interface_get_name_to_cache_pptp >/dev/null 2>&1
	interface_get_name_to_cache_l2tp >/dev/null 2>&1
	interface_get_name_to_cache_ovpn >/dev/null 2>&1
	interface_get_name_to_cache_wg >/dev/null 2>&1
	interface_get_name_to_cache_iked >/dev/null 2>&1
	local interface=$(interface_get_ifname_comment_json wan,vpn,sdwan,sdsaas -sdwan)
	interface=$(interface_append_wireguard_comment_json "$interface")
	json_append __json_result__ interface:json
}
__show_syn_proxy()
{
	local syn_proxy=$(sqlite3 $IK_DB_CONFIG "select syn_proxy from global_config" )
	json_append __json_result__ syn_proxy:int
}
__show_ipgroup()
{
	local ipgroup=$(ipgroup_get_groupname_json)
	json_append __json_result__ ipgroup:json
}

__show_macgroup()
{
        local macgroup=$(macgroup_get_groupname_json)
        json_append __json_result__ macgroup:json
}

__show_dtgroup()
{
        local dtgroup=$(dtgroup_get_groupname_json)
        json_append __json_result__ dtgroup:json
}

# Single native table is the source of truth; serialize edits and roll back failed applies.
/usr/ikuai/script/native_rules.sh ensure_conf >/dev/null 2>&1 || exit 1
nr_native_change(){
 local action="$1" n result status
 case "$action" in add|edit) interface_check_routing_exit "$interface" || return 1;;esac
 mkdir -p /tmp/iktmp/native-rules
 for n in $(seq 1 600);do mkdir /tmp/iktmp/native-rules/edit-lock 2>/dev/null && break;sleep .1;done
 [ "$n" != 600 ] || { echo 'Another native rule edit is running';return 1; }
 trap 'rmdir /tmp/iktmp/native-rules/edit-lock 2>/dev/null' EXIT
 /usr/ikuai/script/native_rules.sh guard || return 1
 sqlite3 "$IK_DB_CONFIG" '.dump stream_layer7' > /tmp/iktmp/native-rules/edit-backup.sql
 result=$(nr_original_$action);status=$?
 if [ "$status" = 0 ] && /usr/ikuai/script/native_rules.sh apply >/tmp/iktmp/native-rules/edit-result.log 2>&1;then
  rmdir /tmp/iktmp/native-rules/edit-lock;trap - EXIT;printf '%s
' "$result";return 0
 fi
 { echo 'drop table stream_layer7;';cat /tmp/iktmp/native-rules/edit-backup.sql; }|sqlite3 "$IK_DB_CONFIG"
 init >/dev/null 2>&1
 /usr/ikuai/script/native_rules.sh apply >/tmp/iktmp/native-rules/restore.log 2>&1 || true
 rmdir /tmp/iktmp/native-rules/edit-lock;trap - EXIT
 # The native RPC envelope does not JSON-escape command output. Keep raw
 # diagnostics local, and never append stale successful compilation output.
 if [ "$status" != 0 ];then printf '%s\n' "$result" > /tmp/iktmp/native-rules/edit-error.log
 else tail -8 /tmp/iktmp/native-rules/edit-result.log > /tmp/iktmp/native-rules/edit-error.log;fi
 echo '分流规则校验或应用失败，请检查规则设置及分流日志'
 return 1
}

add() { nr_native_change add; }

edit() { nr_native_change edit; }

del() { nr_native_change del; }

up() { nr_native_change up; }

down() { nr_native_change down; }

IMPORT() { nr_native_change IMPORT; }

vrrp_init() { nr_native_change vrrp_init; }

