#!/bin/bash /etc/ikcommon
Include ipset.sh interface.sh iproute.sh lock.sh iptables.sh ipmacgroup.sh
Include route_rule.sh
LOCKUP="Lock stream_ipport"
UNLOCK="unLock stream_ipport"

STREAM_IPPORT_LANID=15000

INIT_CONFIG="/tmp/stream_ipport.iptables"
WG_STREAM_PREROUTE_RULE="/tmp/iktmp/ipt_rule_id/wg_stream_preroute_rule"
WG_STREAM_PREROUTE_CHAIN="WG_STREAM_PREROUTE"
WG_STREAM_MARK_CHAIN="WG_STREAM_MARK"
WG_STREAM_MARK_RULE="/tmp/iktmp/ipt_rule_id/wg_stream_mark_rule"

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
	[ "${type:-0}" = 1 ] || interface_check_routing_exit "$interface" || return 1
	check_varl \
		'[ type == 0 ] && interface not match "^pppwg%d+$" and not match "^pppwg%d+," and not match ",pppwg%d+$" and not match ",pppwg%d+,"' \
		'enabled 	== "yes" or == "no"'\
		'type		== 0 or == 1' \
		'[ type == 0 ] && {
			interface != "" ;
		}' \
		'[ type == 1 ] && {
			nexthop ip ;
		}' \
		'protocol 	== "any" or == "tcp" or == "udp" or == "tcp+udp" or == "icmp" ' \
		'src_port 	ports or == ""' \
		'dst_port 	ports or == ""' \
		'week		week' \
		'time		timeranges' || return 1
 nr_check_exit_interfaces 1 1
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

__wg_stream_iface()
{
	echo "$1" | grep -Eq '^wg[0-9]+$'
}

__wg_stream_ensure_route()
{
	local iface="$1" mark_id="$2"
	__wg_stream_iface "$iface" || return 1
	echo "$mark_id" | grep -Eq '^[0-9]+$' || return 1

	ip rule add from all fwmark "$mark_id" table "$iface" prio 10000 >/dev/null 2>&1 || true
	if [ -e "/sys/class/net/$iface" ]; then
		ip route replace default dev "$iface" table "$iface" metric 100 >/dev/null 2>&1 || true
	fi
}

__wg_stream_ensure_nat()
{
	local iface="$1" comment
	__wg_stream_iface "$iface" || return 1
	comment="wg-stream-nat:$iface"
	iptables -w -t nat -C POSTROUTING -o "$iface" -m comment --comment "$comment" -j MASQUERADE >/dev/null 2>&1 || 		iptables -w -t nat -A POSTROUTING -o "$iface" -m comment --comment "$comment" -j MASQUERADE >/dev/null 2>&1
}

__wg_stream_ingress_list()
{
	{
		sqlite3 "$IK_DB_CONFIG" "select name from wireguard where name like 'wg%';" 2>/dev/null
		for path in /sys/class/net/wg*; do
			[ -e "$path" ] && echo "${path##*/}"
		done
	} | awk '/^wg[0-9]+$/ && !seen[$1]++'
}

__wg_stream_preroute_queue_one()
{
	local input_match="$1" route_guard="$2" iface="$3" mark_id="$4" source_name="$5"
	local rule_comment="wg-stream:$id:$iface:$source_name"
	echo $id.10 iptables -w -t mangle -A "$WG_STREAM_PREROUTE_CHAIN" $input_match $route_guard $src $dst $dst_area $PROTO $sport $dport $ipt_time -m mark --mark 0 -m comment --comment "$rule_comment" -j MARK --set-mark "$mark_id" >> "$WG_STREAM_PREROUTE_RULE"
}

__wg_stream_preroute_add_mark()
{
	local iface="$1" mark_id="$2" ingress_wg
	__wg_stream_iface "$iface" || return 1
	echo "$mark_id" | grep -Eq '^[0-9]+$' || return 1

	# This includes LAN, PPTP/L2TP (ppp*), OpenVPN (tap0), IPsec and the
	# other VPN-server inputs already recognized by iKuai.
	__wg_stream_preroute_queue_one "$IPT_LAN_IFACE_IN" 		"$IPT_NOT_LAN_DST $IPT_NOT_LOCAL_DST $IPT_LAN_SRC_CAN_ROUTE $IPT_NOT_WAN_DST" 		"$iface" "$mark_id" "vpn-lan"

	__wg_stream_preroute_add_ingress "$iface" "$mark_id"
}

__wg_stream_preroute_add_ingress()
{
	local iface="$1" mark_id="$2" ingress_wg
	echo "$mark_id" | grep -Eq '^[0-9]+$' || return 1
	# WireGuard server interfaces are absent from IPT_LAN_IFACE_IN. Add each
	# configured/live wgN input except the selected output, preventing wg2->wg2
	# return loops while allowing a phone on wg1 to be routed out through wg2.
	for ingress_wg in $(__wg_stream_ingress_list); do
		[ "$ingress_wg" = "$iface" ] && continue
		# iKuai's local_host matcher does not classify decrypted wgN packets as
		# routable LAN sources. Standard kernel matches are required here.
		__wg_stream_preroute_queue_one "-i $ingress_wg" 			"$IPT_NOT_LOCAL_DST $IPT_NOT_WAN_DST" 			"$iface" "$mark_id" "$ingress_wg"
	done
}

__wg_stream_preroute_commit()
{
	iptables -w -t mangle -N "$WG_STREAM_PREROUTE_CHAIN" >/dev/null 2>&1 || true
	while iptables -w -t mangle -D PREROUTING -j "$WG_STREAM_PREROUTE_CHAIN" >/dev/null 2>&1; do :; done
	iptables -w -t mangle -I PREROUTING 1 -j "$WG_STREAM_PREROUTE_CHAIN" >/dev/null 2>&1
	iptables -w -t mangle -F "$WG_STREAM_PREROUTE_CHAIN" >/dev/null 2>&1
	[ -s "$WG_STREAM_PREROUTE_RULE" ] || return 0
	sort -n -r -k1 "$WG_STREAM_PREROUTE_RULE" | while read rule; do
		${rule#* } >/dev/null 2>&1
	done
}

# Explicitly translate the native selected connection ID to its route-table
# mark for WG input. Do not restore the raw connmark: 6000000-based policy IDs
# and 10000-based routing table IDs are different namespaces.
__wg_stream_mark_queue()
{
	local connmark_id="$1" mark_id="$2" iface="$3" loop_guard=""
	echo "$connmark_id:$mark_id" | grep -Eq '^[0-9]+:[0-9]+$' || return 1
	__wg_stream_iface "$iface" && loop_guard="! -i $iface"
	echo $id iptables -w -t mangle -A "$WG_STREAM_MARK_CHAIN" $loop_guard -m connmark --mark "$connmark_id" -m mark --mark 0 -m comment --comment "wg-stream-map:$id:$iface" -j MARK --set-mark "$mark_id" >> "$WG_STREAM_MARK_RULE"
}

__wg_stream_mark_commit()
{
	iptables -w -t mangle -N "$WG_STREAM_MARK_CHAIN" >/dev/null 2>&1 || true
	iptables -w -t mangle -F "$WG_STREAM_MARK_CHAIN"
	if [ -s "$WG_STREAM_MARK_RULE" ]; then
		sort -n -r -k1 "$WG_STREAM_MARK_RULE" | while read rule; do
			${rule#* } || return 1
		done
	fi
	# Move this hook after the native selector; apply to original-direction
	# packets of existing connections too, without marking VPN return traffic.
	while iptables -w -t mangle -D PREROUTING -i wg+ -m conntrack --ctdir ORIGINAL $IPT_NOT_LOCAL_DST $IPT_NOT_WAN_DST -j "$WG_STREAM_MARK_CHAIN" >/dev/null 2>&1; do :; done
	iptables -w -t mangle -A PREROUTING -i wg+ -m conntrack --ctdir ORIGINAL $IPT_NOT_LOCAL_DST $IPT_NOT_WAN_DST -j "$WG_STREAM_MARK_CHAIN"
}

# Use the native connmark selector for other WG port-routing policies.
# Retain native multi-exit selection, with explicit packet-mark translation.
__wg_stream_ingress_commit()
{
	# Preserve the known single-WG exit path. A connmark alone is not the
	# packet fwmark consumed by Linux policy routing for decrypted WG input.
	__wg_stream_preroute_commit

	while iptables -w -t mangle -D PREROUTING -i wg+ $IPT_CONNTRACK_NEW \
		-m conntrack --ctdir ORIGINAL $IPT_NOT_LAN_DST $IPT_NOT_LOCAL_DST $IPT_NOT_WAN_DST \
		-j STREAM_IPPORT_NEW >/dev/null 2>&1; do :; done

	# Destination guards are retained. The proprietary LAN source/interface
	# classifiers exclude decrypted WG packets, so use the kernel interface
	# and conntrack matches for this additional ingress only. wg+ also covers
	# interfaces created after rules were loaded.
	iptables -w -t mangle -C PREROUTING -i wg+ -m mark --mark 0 $IPT_CONNTRACK_NEW \
		-m conntrack --ctdir ORIGINAL $IPT_NOT_LAN_DST $IPT_NOT_LOCAL_DST $IPT_NOT_WAN_DST \
		-j STREAM_IPPORT_NEW >/dev/null 2>&1 || \
	iptables -w -t mangle -A PREROUTING -i wg+ -m mark --mark 0 $IPT_CONNTRACK_NEW \
		-m conntrack --ctdir ORIGINAL $IPT_NOT_LAN_DST $IPT_NOT_LOCAL_DST $IPT_NOT_WAN_DST \
		-j STREAM_IPPORT_NEW
	__wg_stream_mark_commit
}

__exec_rule_clean()
{
	> /tmp/iktmp/ipt_rule_id/stream_ipport_id_rule
	> "$WG_STREAM_PREROUTE_RULE"
	> "$WG_STREAM_MARK_RULE"
}

__exec_rule_commit()
{
	#重新排序规则
	iptables -w -t mangle -F STREAM_IPPORT_NEW

	> $INIT_CONFIG
	echo "*mangle" >> $INIT_CONFIG
	sort -n -r -k1 /tmp/iktmp/ipt_rule_id/stream_ipport_id_rule |while read rule;do
		echo "${rule//*-t mangle}" >> $INIT_CONFIG
	done
	echo "COMMIT" >> $INIT_CONFIG
	iptables-restore -n -T mangle $INIT_CONFIG >/dev/null 2>&1
	rm $INIT_CONFIG
	__wg_stream_ingress_commit
}

nr_base_rule_add() {
	#封装规则变量
	local connmark_ids=
	local mark_ids=
	local PROTO

	local ipt_time=$(ipt_format_time "$week" "$time")
	COMMENT="-m comment --comment ${id}_${comment}"
	IPTABLES_RULE_ALL="iptables -w -t mangle -A STREAM_IPPORT_ALL"
	IPTABLES_RULE_NEW="iptables -w -t mangle -A STREAM_IPPORT_NEW"

	if [ "$protocol" != "any"  ];then
		local PROTO="-p $protocol"
	fi

	if [ "$protocol" = "tcp+udp" -o "$protocol" = "tcp" -o "$protocol" = "udp" ];then
		[ -n "$src_port" ]&& sport="-m multiport --sports ${src_port//-/:}"
		[ -n "$dst_port" ]&& dport="-m multiport --dports ${dst_port//-/:}"
	else
		sport=""
		dport=""
	fi

	if [ "$type" = "1" ]; then
		###lan forward
		mark_ids=$((STREAM_IPPORT_LANID+id))
		auto_get_id=$(awk 'END{print $1+1,'$id'>>"/tmp/iktmp/ipt_rule_id/stream_ipport_id";print $1+1}' /tmp/iktmp/ipt_rule_id/stream_ipport_id 2>/dev/null)
		connmark_id=$((IPT_CONNMARK_STREAM_IPPORT+auto_get_id))
		connmark_ids="${connmark_id}"
		__wg_stream_mark_queue "$connmark_id" "$mark_ids" "nexthop"
		__wg_stream_preroute_add_ingress "nexthop" "$mark_ids"
		ip rule add from all fwmark $mark_ids table $mark_ids prio 15000
		ip route add default via "$nexthop" table "$mark_ids"
		route_rule_insert stream_ipport stream_default "$id" "$nexthop" "$mark_ids"
		local IFNAMES=""
		local BAND_FLAGS=""
		local MODE_FLAGS=""
	else
		#循环加载规则 读取CONNMARK ID
		local iface_count=0 wg_iface_count=0 single_wg_iface= single_wg_mark=
		local single_iface= single_mark=
		for iface in ${interface//,/ };do
			mark_id=$(iproute_get_markid $iface)
			iface_count=$((iface_count+1))
			single_iface="$iface"
			single_mark="$mark_id"
			if __wg_stream_iface "$iface"; then
				wg_iface_count=$((wg_iface_count+1))
				single_wg_iface="$iface"
				single_wg_mark="$mark_id"
				__wg_stream_ensure_route "$iface" "$mark_id"
				__wg_stream_ensure_nat "$iface"
			fi
			auto_get_id=$(awk 'END{print $1+1,'$id'>>"/tmp/iktmp/ipt_rule_id/stream_ipport_id";print $1+1}' /tmp/iktmp/ipt_rule_id/stream_ipport_id 2>/dev/null)
			connmark_id=$((IPT_CONNMARK_STREAM_IPPORT+auto_get_id))
			__wg_stream_mark_queue "$connmark_id" "$mark_id" "$iface"
			connmark_ids="${connmark_ids:+$connmark_ids,}${connmark_id}"
			mark_ids="${mark_ids:+$mark_ids,}${mark_id}"
			#$IPTABLES_RULE_ALL -m connmark --mark $connmark_id $COMMENT -j MARK --set-mark $mark_id
		done
		if [ "$iface_count" = "1" -a "$wg_iface_count" = "1" ]; then
			echo $id $IPTABLES_RULE_NEW $src $dst $dst_area $PROTO $sport $dport $COMMENT $ipt_time -m mark --mark 0 -j MARK --set-mark "$single_wg_mark" >>/tmp/iktmp/ipt_rule_id/stream_ipport_id_rule
			__wg_stream_preroute_add_mark "$single_wg_iface" "$single_wg_mark"
		elif [ "$iface_count" = "1" ]; then
			__wg_stream_preroute_add_ingress "$single_iface" "$single_mark"
		fi
		local IFNAMES="--set-ifname $interface"
		local BAND_FLAGS="--set-band-flag ${iface_band:-0}"
		local MODE_FLAGS="--set-mode ${mode:-0}"
	fi

	ik_cntl new_tc mark_rule add id $((IPT_CONNMARK_STREAM_IPPORT+id)) connmark ${connmark_ids} skbmark ${mark_ids} >/dev/null
	echo $id $IPTABLES_RULE_NEW $src $dst $dst_area $PROTO $sport $dport $COMMENT $ipt_time -j NTH_CONNMARK --set-mark ${connmark_ids} $IFNAMES $BAND_FLAGS $MODE_FLAGS >>/tmp/iktmp/ipt_rule_id/stream_ipport_id_rule
}
__exec_rule_del() {
	local ipt_time=$(ipt_format_time "$week" "$time")
	
	sed -i -r "/^[0-9]+ (${id//,/|})$/d" /tmp/iktmp/ipt_rule_id/stream_ipport_id
	sed -i -r "/^(${id//,/|}) /d" /tmp/iktmp/ipt_rule_id/stream_ipport_id_rule
	sed -i -r "/^(${id//,/|})(\.[0-9]+)? /d" "$WG_STREAM_PREROUTE_RULE"
	sed -i -r "/^(${id//,/|}) /d" "$WG_STREAM_MARK_RULE"
	__wg_stream_mark_commit
	# Rebuild the compatibility chain after disable/delete as well as edits.
	__wg_stream_preroute_commit
	line_num=`iptables -w -t mangle -L STREAM_IPPORT_NEW -n --line-numbers |awk '$0~/\/\* ('${id//,/|}')_.* \*\//{print $1}'`
	num=0
	for line in $line_num ;do
		iptables -w -t mangle -D STREAM_IPPORT_NEW  $ipt_time $((line-$((num++)))) 2>/dev/null
	done

	for i in ${id//,/ };do
		ik_cntl new_tc mark_rule del id $((IPT_CONNMARK_STREAM_IPPORT+i)) >/dev/null
	done

	if [ "$type" = "1" ]; then
		local mark_ids=$((STREAM_IPPORT_LANID+id))
		ip route del default via $nexthop table $mark_ids
		ip rule del from all fwmark $mark_ids table $mark_ids
	fi
}
__format_ipset() {
	if [ "$1" = "src" ] ;then
		[ -n "$src_addr" ]&&{
			#循环判断地址类型（普通IP/群组名称）
			ipset_rule_new_add sipport_src_$id $src_addr
			echo "-m set --match-set sipport_src_$id src"
		}
	elif [ "$1" = "dst" ] ;then
		[ -n "$dst_addr" ]&&{
			ipset_rule_new_add sipport_dst_$id $dst_addr
			echo "-m set --match-set sipport_dst_$id dst"
		}
	fi
}

__format_area() {
	local code=$1
	local code_all=""
	if [ "$code" != "" ];then
		for code_one in ${code//,/ } ;do
			local code_num=""
			code_num=$(($code_one))
			code_all=${code_all:+$code_all,}$code_num
		done
	fi

	if [ "$code_all"  != "" ];then
		echo "-m location --location $code_all"
	fi
}

nr_original_init() {
	iptables -w -t mangle -F STREAM_IPPORT_NEW
	iptables -w -t mangle -F STREAM_IPPORT_ALL
	$LOCKUP
	route_rule_clean stream_ipport
	__exec_rule_clean
	sql_config_get_list $IK_DB_CONFIG "select * from stream_ipport" |\
	while read config ;do
		sport= dport= src= dst= connmark_ids= PROTO=
		[ -n "$config" ]&&{
			local $config
			src=$(__format_ipset src)
			if [ "$dst_type" == "0" ];then
				dst=$(__format_ipset dst)
				dst_area=""
			else
				dst_area=$(__format_area $area_code)
				dst=""
			fi
			[ "$enabled" = "yes" ]&& {
				__exec_rule_add >/dev/null 2>/dev/null
			}
		}
	done
	__exec_rule_commit >/dev/null 2>/dev/null
	route_rule_commit
	$UNLOCK
}

nr_original_vrrp_init() {
	__clean
	sqlite3 $IK_DB_CONFIG "delete from stream_ipport"	
	sqlite3 $IK_DIR_LOG/vrrp/conf/config.db ".dump stream_ipport" |grep "^INSERT"| sqlite3 $IK_DB_CONFIG
	init
}

nr_original_add() {
	__check_param || exit 1
	__check_interface_nums || exit 1
	sport= dport= src= dst= connmark_ids= PROTO= dst_area=
	dst_type=${dst_type:-0}
	local sql_param="id:null enabled:str comment:str type:str nexthop:str interface:str mode:int iface_band:int src_addr:str dst_addr:str protocol:str src_port:str dst_port:str week:str time:str dst_type:int area_code:str nr_ingress:str nr_stage:int"
	if SqlMsg=$(sql_config_insert $IK_DB_CONFIG stream_ipport $sql_param);then
		local id=$SqlMsg
		src=$(__format_ipset src)
		#判断目的类型 0-地址 1-地区
		if [ "$dst_type" == "0" ];then
			dst=$(__format_ipset dst)
			dst_area=""
		else
			dst_area=$(__format_area $area_code)
			dst=""
		fi
		[ "$enabled" = "yes" ]&& {
			$LOCKUP
			__exec_rule_add >/dev/null 2>/dev/null
			__exec_rule_commit >/dev/null 2>/dev/null
			$UNLOCK
		}
		route_rule_commit
		echo "$SqlMsg"
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi
}

nr_original_del() {
	sql_config_get_list $IK_DB_CONFIG "select * from stream_ipport where id in ($id); delete from stream_ipport where id in ($id);" | \
	while read config; do
		local $config
		$LOCKUP
		__exec_rule_del >/dev/null 2>/dev/null
		$UNLOCK
		for ID in ${id//,/ };do
			ipset_rule_new_del sipport_src_$ID
			ipset_rule_new_del sipport_dst_$ID
		done
	done
	route_rule_delete stream_ipport "$id"
	route_rule_commit
}

nr_original_down() {
	sql_config_get_list $IK_DB_CONFIG "select * from stream_ipport where id in ($id) and enabled='yes'; update stream_ipport set enabled='no' where id in ($id) ;" | \
	while read config; do
		local $config
		$LOCKUP
		__exec_rule_del >/dev/null 2>/dev/null
		$UNLOCK
	done
	route_rule_delete stream_ipport "$id"
	route_rule_commit
}

nr_original_up() {
	sql_config_get_list $IK_DB_CONFIG "select * from stream_ipport where id in ($id) and enabled='no';update stream_ipport set enabled='yes' where id in ($id);"|while read config ;do
		sport= dport= src= dst= connmark_ids= PROTO=
		local $config 
		[ -n "$src_addr" ]&&src="-m set --match-set sipport_src_$id src"
		#判断目的类型 0-地址 1-地区
		if [ "$dst_type" == "0" ];then
			[ -n "$dst_addr" ]&&dst="-m set --match-set sipport_dst_$id dst"
			dst_area=""
		else
			dst_area=$(__format_area $area_code)
			dst=""
		fi
		$LOCKUP
		__exec_rule_add >/dev/null 2>/dev/null
		$UNLOCK
	done
	__exec_rule_commit >/dev/null 2>/dev/null
	route_rule_commit
}

nr_original_edit() {
	__check_param || exit 1
	__check_interface_nums || exit 1
	dst_type=${dst_type:-0}
	local sql_param="enabled:str comment:str type:str nexthop:str interface:str mode:int iface_band:int src_addr:str dst_addr:str protocol:str src_port:str dst_port:str week:str time:str dst_type:int area_code:str nr_ingress:str nr_stage:int"
	res=$(sql_config_get_list $IK_DB_CONFIG "select * from stream_ipport where id=$id" prefix=old_)
	if [ "$res" = "" ];then
		return 0
	fi
	local $res
	if SqlMsg=$(sql_config_update $IK_DB_CONFIG stream_ipport "id=$id" $sql_param);then
		if ! NewOldVarl type nexthop interface mode iface_band src_addr dst_addr protocol src_port dst_port week time dst_type area_code; then
			src=$(__format_ipset src)
			#判断目的类型 0-地址 1-地区
			if [ "$dst_type" == "0" ];then
				dst=$(__format_ipset dst)
				dst_area=""
			else
				dst_area=$(__format_area $area_code)
				dst=""
			fi

			[ "$enabled" = "yes" ]&&{
				$LOCKUP
				type=$old_type nexthop=$old_nexthop __exec_rule_del >/dev/null 2>/dev/null
				route_rule_delete stream_ipport "$id"
				__exec_rule_add >/dev/null 2>/dev/null
				__exec_rule_commit >/dev/null 2>/dev/null
				route_rule_commit
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
	sql_config_get_list $IK_DB_CONFIG "select * from stream_ipport;" |\
	while read config; do
		local $config
		__exec_rule_del >/dev/null 2>/dev/null
		ipset_rule_new_del sipport_src_$id
		ipset_rule_new_del sipport_dst_$id
	done
	$UNLOCK
	route_rule_clean stream_ipport
	route_rule_commit
}

EXPORT() {
	Include import_export.sh
	local format=${format:-txt}
	if errmsg=$(export_txt $IK_DB_CONFIG stream_ipport $format $IK_DIR_EXPORT/stream_ipport.$format) ;then
		echo "stream_ipport.$format"
		return 0
	else
		echo "$errmsg"
		return 1
	fi
}

nr_original_IMPORT() {
	Include import_export.sh
	if errmsg=$(import_txt $IK_DB_CONFIG stream_ipport $IK_DIR_IMPORT/$filename "$append"  __check_param __clean) ;then
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
	local total=$(sqlite3 $IK_DB_CONFIG "select count() from stream_ipport $__filter")
	json_append __json_result__ total:int
}
__show_data()
{
	local sql_show="select * from stream_ipport $__where"
	local data=$(sql_config_get_json $IK_DB_CONFIG "$sql_show")
	json_append __json_result__ data:json
	return 0;
}
__show_interface()
{
	local interface=$(interface_get_ifname_comment_json wan,vpn,sdwan,sdsaas -sdwan)
	local wg_items tmpfile
	tmpfile=$(sql_config_get_list $IK_DB_CONFIG "select name from wireguard")
	while read config; do
		[ "$config" ] || continue
		local $config
		[ "$name" ] || continue
		interface_is_wg_ingress_helper "$name" && continue
		case "$interface" in
			*"[\"$name\"]"*) continue ;;
		esac
		wg_items+="${wg_items:+,}[\"$name\"]"
	done <<EOF
	$tmpfile
EOF
	if [ "$wg_items" ]; then
		if [ "$interface" = "[]" ]; then
			interface="[$wg_items]"
		else
			interface="${interface%]},$wg_items]"
		fi
	fi
	interface="${interface%]},[\"blackhole\",\"禁止联网\"]]"
	json_append __json_result__ interface:json
	__wg_stream_policy_status
}
__wg_stream_policy_status()
{
	local iface mark rule_ok route_ok nat_ok status="" ingress_ok=0
	iptables -w -t mangle -C PREROUTING -i wg+ -m mark --mark 0 $IPT_CONNTRACK_NEW \
		-m conntrack --ctdir ORIGINAL $IPT_NOT_LAN_DST $IPT_NOT_LOCAL_DST $IPT_NOT_WAN_DST \
		-j STREAM_IPPORT_NEW >/dev/null 2>&1 && ingress_ok=1
	status="wg_in=native chain=$ingress_ok"
	for iface in $(sqlite3 "$IK_DB_CONFIG" "select interface from stream_ipport where enabled='yes' and type='0';" 2>/dev/null | tr ',' '\n' | sort -u); do
		__wg_stream_iface "$iface" || continue
		mark=$(awk -v iface="$iface" '$2==iface{print $1;exit}' /etc/iproute2/rt_tables 2>/dev/null)
		rule_ok=0 route_ok=0 nat_ok=0
		[ "$mark" ] && ip rule show 2>/dev/null | grep -q "lookup $iface" && rule_ok=1
		ip route show table "$iface" 2>/dev/null | grep -Eq '^default( .*)? dev '"$iface"'( |$)' && route_ok=1
		iptables -w -t nat -C POSTROUTING -o "$iface" -m comment --comment "wg-stream-nat:$iface" -j MASQUERADE >/dev/null 2>&1 && nat_ok=1
		status="$status;$iface mark=${mark:-missing} rule=$rule_ok route=$route_ok nat=$nat_ok"
	done
	local wg_policy="$status"
	json_append __json_result__ wg_policy:str
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

__show_iplib()
{
	if [ ! -f "/etc/log/iplocal/iplocal_status" ];then
		iplib_status=0
	else
		iplib_status=$(cat /etc/log/iplocal/iplocal_status)
	fi
	json_append __json_result__ iplib_status:int
}

__exec_rule_add(){ [ "${type:-0}" != 1 ] || nr_base_rule_add; }

# Single native table is the source of truth; serialize edits and roll back failed applies.
/usr/ikuai/script/native_rules.sh ensure_conf >/dev/null 2>&1 || exit 1
nr_native_change(){
 local action="$1" n result status
 case "$action" in add|edit) [ "${type:-0}" = 1 ] || interface_check_routing_exit "$interface" || return 1;;esac
 mkdir -p /tmp/iktmp/native-rules
 for n in $(seq 1 600);do mkdir /tmp/iktmp/native-rules/edit-lock 2>/dev/null && break;sleep .1;done
 [ "$n" != 600 ] || { echo 'Another native rule edit is running';return 1; }
 trap 'rmdir /tmp/iktmp/native-rules/edit-lock 2>/dev/null' EXIT
 /usr/ikuai/script/native_rules.sh guard || return 1
 sqlite3 "$IK_DB_CONFIG" '.dump stream_ipport' > /tmp/iktmp/native-rules/edit-backup.sql
 result=$(nr_original_$action);status=$?
 if [ "$status" = 0 ] && /usr/ikuai/script/native_rules.sh apply >/tmp/iktmp/native-rules/edit-result.log 2>&1;then
  rmdir /tmp/iktmp/native-rules/edit-lock;trap - EXIT;printf '%s
' "$result";return 0
 fi
 { echo 'drop table stream_ipport;';cat /tmp/iktmp/native-rules/edit-backup.sql; }|sqlite3 "$IK_DB_CONFIG"
 nr_original_init >/dev/null 2>&1
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

init(){ nr_original_init || return 1; /usr/ikuai/script/native_rules.sh apply; }
