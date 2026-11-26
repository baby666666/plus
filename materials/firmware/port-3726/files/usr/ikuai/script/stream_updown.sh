#!/bin/bash /etc/ikcommon
Include ipset.sh interface.sh iproute.sh lock.sh iptables.sh ipmacgroup.sh
CONFIG_FILE="/tmp/iktmp/stream_updown.txt"
LOCKUP="Lock stream_updown"
UNLOCK="unLock stream_updown"

boot()
{
	init
}
__check_param()
{
	check_varl \
		'enabled == "yes" or == "no"'\
		'upiface ifnames_wan'\
		'downiface ifnames_wan'\
		'protocol == "any" or == "tcp" or == "udp" or == "tcp+udp" or == "icmp" ' \
		'src_port ports or == ""' \
		'dst_port ports or == ""'
}

__exec_rule_add() {
	in_iface= out_iface= sport= dport= proto=
	if [ "$upiface" = "" -o "$downiface" = "" ];then
		return 0
	else
		for i in ${upiface//,/ } ;do
			if interface_check_is_wanpppoe $i ;then
				iface=${i}_ad
			else
				iface=$i
			fi
			out_iface+="out:\"$iface\" "
		done
		for i in ${downiface//,/ } ;do
			if interface_check_is_wanpppoe $i ;then
				iface=${i}_ad
			else
				iface=$i
			fi
			in_iface+="in:\"$iface\" "
		done
	fi

	if [ "$protocol" = "tcp+udp" -o "$protocol" = "tcp" -o "$protocol" = "udp" -o "$protocol" = "icmp" ];then
		proto="proto:\"$protocol\""
		if [ "$protocol" != "icmp" ];then
			for i in ${src_port//,/ } ;do
				sport+="sport_range { start:${i%-*} end:${i#*-} } "
			done

			for i in ${dst_port//,/ } ;do
				dport+="dport_range { start:${i%-*} end:${i#*-} } "
			done
		fi
	fi

	echo "$id node { $proto $sport $dport $src $dst $out_iface $in_iface }" >>$CONFIG_FILE
	__init_bin
}

__init_bin() {
	if [ -n "$(cat $CONFIG_FILE)" ];then
		sort -n -r -k1 $CONFIG_FILE | sed -r "s/^[0-9]+ node/node/g" >$CONFIG_FILE.tmp
		protoc-c --encode=wans_snat_list --proto_path=/usr/lib/ /usr/lib/libsnat_proto.so.2   < $CONFIG_FILE.tmp  > $CONFIG_FILE.bin && ik_cntl wans-snat $CONFIG_FILE.bin
	else
		ik_cntl wans-snat >/dev/null 2>&1
	fi
}

__exec_rule_del() {
	sed -i -r "/^(${id//,/|}) /d" $CONFIG_FILE
	__init_bin
}

__format_ipset() {
	if [ "$1" = "src" ] ;then
		[ -n "$src_addr" ]&&{
			#循环判断地址类型（普通IP/群组名称）
			ipset_rule_add updown_src_$id $src_addr
			echo "src_ip:\"updown_src_$id\""
		}
	elif [ "$1" = "dst" ] ;then
		[ -n "$dst_addr" ]&&{
			ipset_rule_add updown_dst_$id $dst_addr
			echo "dst_ip:\"updown_dst_$id\""
		}
	fi
}
init() {
	>$CONFIG_FILE
	$LOCKUP
	sql_config_get_list $IK_DB_CONFIG "select * from stream_updown" |\
	while read config ;do
		[ -n "$config" ]&&{
			local $config
			src= dst=
			src=$(__format_ipset src)
			dst=$(__format_ipset dst)
			[ "$enabled" = "yes" ]&& {
				__exec_rule_add >/dev/null 2>/dev/null
			}
		}
	done
	$UNLOCK
	__init_bin
}

vrrp_init()
{
	__clean
	sqlite3 $IK_DB_CONFIG "delete from stream_updown"
	sqlite3 $IK_DIR_LOG/vrrp/conf/config.db ".dump stream_updown" |grep "^INSERT"| sqlite3 $IK_DB_CONFIG
	init
}

add() {
	__check_param || exit 1
	local sql_param="id:null enabled:str comment:str upiface:str downiface:str src_addr:str dst_addr:str protocol:str src_port:str dst_port:str"
	if SqlMsg=$(sql_config_insert $IK_DB_CONFIG stream_updown $sql_param);then
		id=$SqlMsg
		src=$(__format_ipset src)
		dst=$(__format_ipset dst)
		[ "$enabled" = "yes" ]&& {
			$LOCKUP
			__exec_rule_add >/dev/null 2>/dev/null
			$UNLOCK
		}
		echo "$SqlMsg"
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi
}

del() {
	sql_config_exec $IK_DB_CONFIG "delete from stream_updown where id in ($id);"

	$LOCKUP
	__exec_rule_del >/dev/null 2>/dev/null
	$UNLOCK
	for ID in ${id//,/ };do
		ipset_rule_del updown_dst_$ID
		ipset_rule_del updown_src_$ID
	done
}

down() {
	sql_config_exec $IK_DB_CONFIG "update stream_updown set enabled='no' where id in ($id) ;"
	$LOCKUP
	__exec_rule_del >/dev/null 2>/dev/null
	$UNLOCK
}

up() {
	sql_config_get_list $IK_DB_CONFIG "select * from stream_updown where id in ($id) and enabled='no';update stream_updown set enabled='yes' where id in ($id);"|while read config ;do
		local $config
		src= dst=
		[ -n "$src_addr" ]&&src="src_ip:\"updown_src_$id\""
		[ -n "$dst_addr" ]&&dst="dst_ip:\"updown_dst_$id\""
		$LOCKUP
		__exec_rule_add >/dev/null 2>/dev/null
		$UNLOCK
	done
}

edit() {
	__check_param || exit 1
	local sql_param="enabled:str comment:str upiface:str downiface:str src_addr:str dst_addr:str protocol:str src_port:str dst_port:str"
	res=$(sql_config_get_list $IK_DB_CONFIG "select * from stream_updown where id=$id" prefix=old_)
	if [ "$res" = "" ];then
		return 0
	fi
	local $res
	if SqlMsg=$(sql_config_update $IK_DB_CONFIG stream_updown "id=$id" $sql_param);then
		if ! NewOldVarl upiface downiface src_addr dst_addr protocol src_port dst_port;then
			src=$(__format_ipset src)
			dst=$(__format_ipset dst)
			[ "$enabled" = "yes" ]&&{
				$LOCKUP
				__exec_rule_del >/dev/null 2>/dev/null
				__exec_rule_add >/dev/null 2>/dev/null
				$UNLOCK
			}
		fi
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi
}
__clean() {
	$LOCKUP
	sql_config_get_list $IK_DB_CONFIG "select * from stream_updown;" |\
	while read config ;do
		local $config
		__exec_rule_del >/dev/null 2>/dev/null
		ipset_rule_del updown_dst_$id
		ipset_rule_del updown_src_$id
	done
	$UNLOCK
}

EXPORT() {
	Include import_export.sh
	local format=${format:-txt}
	if errmsg=$(export_txt $IK_DB_CONFIG stream_updown $format $IK_DIR_EXPORT/stream_updown.$format) ;then
		echo "stream_updown.$format"
		return 0
	else
		echo "$errmsg"
		return 1
	fi
}
IMPORT() {
	Include import_export.sh
	if errmsg=$(import_txt $IK_DB_CONFIG stream_updown $IK_DIR_IMPORT/$filename "$append"  __check_param __clean) ;then
		init >/dev/null 2>/dev/null &
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
	local total=$(sqlite3 $IK_DB_CONFIG "select count() from stream_updown $__filter")
	json_append __json_result__ total:int
}
__show_data()
{
	local sql_show="select * from stream_updown $__where"
	local data=$(sql_config_get_json $IK_DB_CONFIG "$sql_show")
	json_append __json_result__ data:json
	return 0;
}
__show_interface()
{
	local interface=$(interface_get_ifname_comment_json wan)
	json_append __json_result__ interface:json
}
__show_protocol()
{
	local protocol="[\"tcp\",\"udp\",\"tcp+udp\",\"icmp\",\"any\"]"
	json_append __json_result__ protocol:json
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
