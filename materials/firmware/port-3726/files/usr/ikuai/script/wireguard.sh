#!/bin/bash /etc/ikcommon
Include interface.sh, check.sh, ifether.sh, iproute.sh, crond.sh, lock.sh
boot()
{
	mkdir -p /tmp/iktmp/wireguard/config

	crond_clean wireguard
	crond_insert wireguard "*/3 * * * * $IK_DIR_SCRIPT/wireguard.sh resolve_flush"
	crond_commit

	__wg_iface_cache_update
	__wg_iface_repair_keys
	__wg_disable_peer_wan_policy
	init
}

init() { __wg_address_change init; }

__wg_locked_init()
{
 local rows config status=0
 rows=$(sql_config_get_list "$IK_DB_CONFIG" "select * from wireguard where enabled='yes'") || return 1
 while read -r config;do
  [ "$config" ] || continue
  local $config
  __exec_rule_restart_one "$name" || status=1
 done <<< "$rows"
 return "$status"
}

updatedb()
{
        if [ "$old_sysver" -lt 300070015 ];then
                sql_config_get_list $IK_DB_CONFIG "select * from wireguard" |\
                while read config; do
                        [ "$config" ] || continue
                        local $config
                        local enabled="yes" interface=$name peer_publickey=$peer_publickey presharedkey=$presharedkey 
			local allowips=$allowips endpoint=$endpoint endpoint_port=$endpoint_port keepalive=$keepalive
			local sql_param="enabled:str interface:str peer_publickey:str presharedkey:str allowips:str endpoint:str endpoint_port:str keepalive:str"
                        sql_config_insert $IK_DB_CONFIG wireguard_peers $sql_param
                done
        fi
	sqlite3 $IK_DB_CONFIG "alter table wireguard_peers add column out_mode text default 'auto';" >/dev/null 2>&1
	sqlite3 $IK_DB_CONFIG "alter table wireguard_peers add column out_wans text default '';" >/dev/null 2>&1
	sqlite3 $IK_DB_CONFIG "alter table wireguard_peers add column out_balance text default 'failover';" >/dev/null 2>&1
	sqlite3 $IK_DB_CONFIG "alter table wireguard_peers add column peer_privatekey text default '';" >/dev/null 2>&1
	sqlite3 $IK_DB_CONFIG "alter table wireguard_peers add column client_dns text default '';" >/dev/null 2>&1
	sqlite3 $IK_DB_CONFIG "alter table wireguard_peers add column client_endpoint text default '';" >/dev/null 2>&1
	sqlite3 $IK_DB_CONFIG "alter table wireguard_peers add column exit_peer text default 'no';" >/dev/null 2>&1
	for column in site_local site_remote;do sqlite3 $IK_DB_CONFIG "alter table wireguard_peers add column $column text default '';" >/dev/null 2>&1;done
	__wg_disable_peer_wan_policy
}

vrrp_init()
{
	__exec_rule_clean
	sqlite3 $IK_DIR_LOG/vrrp/conf/config.db ".dump wireguard" |grep "^INSERT"| sqlite3 $IK_DB_CONFIG
	sqlite3 $IK_DIR_LOG/vrrp/conf/config.db ".dump wireguard_peers" |grep "^INSERT"| sqlite3 $IK_DB_CONFIG
	__wg_iface_cache_update
	init
}

__wg_iface_cache_update()
{
	interface_get_name_to_cache_wan >/dev/null 2>&1 || true
	interface_get_name_to_cache_pptp >/dev/null 2>&1 || true
	interface_get_name_to_cache_l2tp >/dev/null 2>&1 || true
	interface_get_name_to_cache_ovpn >/dev/null 2>&1 || true
	interface_get_name_to_cache_iked >/dev/null 2>&1 || true
	interface_get_name_to_cache_wg >/dev/null 2>&1 || true
}

__wg_bin()
{
	if [ -x /usr/bin/wg ]; then
		echo /usr/bin/wg
	else
		command -v wg 2>/dev/null
	fi
}

__wg_fill_local_keys()
{
	mkdir -p /tmp/iktmp/wireguard
	local wg_bin=$(__wg_bin)
	[ "$wg_bin" ] || return
	if [ -z "$local_privatekey" ]; then
		local_privatekey=$("$wg_bin" genkey 2>/dev/null)
	fi
	if [ -z "$local_publickey" -a "$local_privatekey" ]; then
		local_publickey=$(echo "$local_privatekey" | "$wg_bin" pubkey 2>/dev/null)
	fi
}

__wg_iface_repair_keys()
{
	sql_config_get_list $IK_DB_CONFIG "select id,local_privatekey,local_publickey from wireguard where ifnull(local_privatekey,'')='' or ifnull(local_publickey,'')=''" |\
	while read config; do
		[ "$config" ] || continue
		local $config
		__wg_fill_local_keys
		[ "$local_privatekey" -a "$local_publickey" ] || continue
		sqlite3 $IK_DB_CONFIG "update wireguard set local_privatekey='$local_privatekey',local_publickey='$local_publickey' where id=$id"
	done
}

__check_param_add()
{
	check_varl \
		'enabled	== "yes" or == "no"' \
		'peer_publickey	!= ""' \
		'allowips	ipmaskbs' \
		'endpoint_port	== "" or ikports' \
		'out_mode	== "" or == "auto" or == "single" or == "multi"' \
		'out_balance	== "" or == "failover" or == "ecmp"' \
		'exit_peer == "" or == "no" or == "yes"' || return 1
	/usr/bin/lua /usr/ikuai/script/wg_peer_options.lua validate "${exit_peer:-no}" "$client_endpoint" "$site_local" "$site_remote"
}

__check_param_iface_add()
{
	# Also used by file import, which does not call iface_add/iface_edit.
	interface_check_routing_exit "$interface" || return 1
	check_varl \
		'enabled	== "yes" or == "no"' \
		'interface	!= "" and not match "^pppwg%d+$" and not match "^pppwg%d+," and not match ",pppwg%d+$" and not match ",pppwg%d+,"' \
		'local_privatekey	!= ""' \
		'local_publickey	!= ""' \
		'local_address		ipmaskb' \
		'local_listenport	ikports'
}

__wg_route_iface_list()
{
	__wg_iface_cache_update
	{
		interface_get_ifname wan,vpn 2>/dev/null
		sqlite3 $IK_DB_CONFIG "select name from wireguard where name like 'wg%' order by name" 2>/dev/null
		sqlite3 $IK_DB_CONFIG "select distinct interface from wireguard_peers where interface like 'wg%' order by interface" 2>/dev/null
		for wg_if in /sys/class/net/wg* /sys/class/net/ovpn* /sys/class/net/tun[0-9]* /sys/class/net/tap[0-9]* /sys/class/net/pptp* /sys/class/net/l2tp* /sys/class/net/iked* /sys/class/net/ipsec* /sys/class/net/ppp*; do
			[ -e "$wg_if" ] && echo "${wg_if##*/}"
		done
	} | awk 'NF && $1 !~ /^pppwg[0-9]+$/ && !seen[$1]++'
}

__wg_route_iface_json()
{
	local data=""
	local name
	local comment

	while read name comment; do
		[ "$name" ] || continue
		interface_is_wg_ingress_helper "$name" && continue
		data="${data:+$data,}[\"$name\"${comment:+,\"$comment\"}]"
	done <<EOF
	$(interface_get_ifname wan,vpn "" true 2>/dev/null)
EOF

	for name in $(__wg_route_iface_list); do
		echo "$data" | grep -q "\"$name\"" && continue
		data="${data:+$data,}[\"$name\"]"
	done
	echo "[$data]"
}

__wg_check_route_iface()
{
	local iface="$1"
	interface_check_routing_exit "$iface" || return 1
	[ "$iface" = "auto" ] && return 0
	[ "$iface" ] || return 1
	__wg_route_iface_list | grep -qx "$iface" && return 0
	Autoiecho param interface "$iface"
	return 1
}

__check_key_valid()
{
 local key="$1"
 [ "$key" ] || return 0
 # WireGuard keys are 32 bytes in canonical Base64. Never echo invalid key
 # material into an API response or a log, including a user-pasted secret.
 if ! [[ "$key" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ]];then
  echo "WG 密钥格式错误：请使用完整的 32 字节 Base64 密钥"
  return 1
 fi
 return 0
}

#检查配置的地址池与本地接口网段是否冲突
__check_vlan_addr_pool_is_valid()
{
	if ! res=$(check_interface_addrpool "$1" "$2"); then
		Autoiecho param addr_pool_conflict "$res"
		return 1
	fi
	return 0
}

__format_ipmask()
{
	local ipmask="$1"

	local output=""
	for ipmask_one in ${ipmask//,/ }; do
		local $($IK_DIR_SCRIPT/ipcalc.sh $ipmask_one)

		if [ "$NETWORK" -a "$PREFIX" ]; then
			case ",$output," in *",$NETWORK/$PREFIX,"*) continue;; esac
			output+="${output:+,}$NETWORK/$PREFIX"
		fi
	done
	echo $output
}

#ipmask=192.168.1.0/24,192.168.2.0/24
__check_allowip_conflict()
{
 /usr/bin/lua /usr/ikuai/script/wg_address_config.lua peer "$IK_DB_CONFIG" "$interface" "$1" "$2" "$peer_publickey" "${exit_peer:-no}" "$client_endpoint" "$site_local" "$site_remote"
}
__wg_check_iface_address()
{
 /usr/bin/lua /usr/ikuai/script/wg_address_config.lua iface "$IK_DB_CONFIG" "$name" "$local_address" "$local_listenport" "$1"
}

# Try to resolve specified address to IP
# $1: domain name or IP
try_get_ip_of_address()
{
	local addr="$1"
	if expr "$addr" : '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+$' >/dev/null; then
		echo "$addr"
	else
		local ip=`resolveip -4 "$addr" | head -n1`
		if [ -z "$ip" ]; then
			ip=`resolveip -6 "$addr" | head -n1`
			if [ -z "$ip" ]; then
				ip="$addr"
			fi
		fi
		echo "$ip"
	fi
}

# Cache is data, never shell input. It is committed only after a successful apply.
__wg_endpoint_identity()
{
 printf '%s\t%s\t%s\t%s' "$interface" "$peer_publickey" "$endpoint" "$endpoint_port"
}

__wg_is_endpoint_ip()
{
 local ip="$1" part left right count=0
 if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  for part in ${ip//./ }; do
   [ "${#part}" -le 3 ] && [ "$((10#$part))" -le 255 ] || return 1
  done
  return 0
 fi
 [[ "$ip" = *:* && -z "${ip//[0-9a-fA-F:]/}" ]] || return 1
 if [[ "$ip" = *::* ]]; then
  left=${ip%%::*};right=${ip#*::}
  [[ "$left" != :* && "$left" != *: && "$right" != :* && "$right" != *: && "$right" != *::* ]] || return 1
 else
  left=$ip;right=""
  [[ "$left" != :* && "$left" != *: ]] || return 1
 fi
 for part in ${left//:/ } ${right//:/ }; do
  [ "${#part}" -ge 1 ] && [ "${#part}" -le 4 ] || return 1
  count=$((count+1))
 done
 if [[ "$ip" = *::* ]];then [ "$count" -lt 8 ];else [ "$count" -eq 8 ];fi
}

__wg_resolve_address()
{
 local host="$1" result
 if __wg_is_endpoint_ip "$host"; then printf '%s\n' "$host";return 0;fi
 result=$(resolveip -4 -t 4 "$host" 2>/dev/null | head -n 1)
 if ! __wg_is_endpoint_ip "$result"; then
  result=$(resolveip -6 -t 4 "$host" 2>/dev/null | head -n 1)
 fi
 __wg_is_endpoint_ip "$result" || return 1
 printf '%s\n' "$result"
}

__wg_endpoint_socket()
{
 case "$1" in *:*) printf '[%s]:%s' "$1" "$2";; *) printf '%s:%s' "$1" "$2";; esac
}

__del_config_cache()
{
	if [ "$id" ]; then
		rm -f "$IK_DIR_TMP/wireguard/config/$id" 
	fi
}

__wg_policy_comment()
{
	echo "wg-wan-policy:$1"
}

__wg_inbound_comment()
{
	echo "wg-inbound-policy:$1"
}

__wg_iface_comment()
{
	echo "wg-iface-policy:$1"
}

__wg_policy_del()
{
	local peer_id="$1"
	[ "$peer_id" ] || return
	local comment=$(__wg_policy_comment "$peer_id")

	iptables -t mangle -S OUTPUT 2>/dev/null | grep -- "$comment" | sed 's/^-A /-D /' |\
	while read rule; do
		iptables -t mangle $rule >/dev/null 2>&1
	done
}

__wg_disable_peer_wan_policy()
{
	sqlite3 $IK_DB_CONFIG "update wireguard_peers set out_mode='auto',out_wans='',out_balance='failover' where ifnull(out_mode,'auto')!='auto' or ifnull(out_wans,'')!='' or ifnull(out_balance,'failover')!='failover';" >/dev/null 2>&1
	iptables -t mangle -S OUTPUT 2>/dev/null | grep -- "wg-wan-policy:" | sed 's/^-A /-D /' |\
	while read rule; do
		iptables -t mangle $rule >/dev/null 2>&1
	done
}

__wg_policy_wan_is_alive()
{
	local wan="$1"
	local link_status
	[ -f /tmp/iktmp/monitor-link/$wan ] || return 0
	read _ _ _ _ _ _ _ link_status _ < /tmp/iktmp/monitor-link/$wan
	[ "$link_status" != "fail" ]
}

__wg_policy_wan_mark()
{
	local wan="$1"
	[ "$wan" ] || return
	iproute_get_markid "$wan"
}

__wg_policy_ensure_rule()
{
	local mark_id="$1" wan="$2"
	interface_check_routing_exit "$wan" || return 1
	[ "$mark_id" -a "$wan" ] || return
	ip rule show 2>/dev/null | grep -q "fwmark .*0x$(printf '%x' $mark_id).*lookup $wan" || \
		ip rule add from all fwmark $mark_id table $wan prio 10000 >/dev/null 2>&1
	ip -6 rule show 2>/dev/null | grep -q "fwmark .*0x$(printf '%x' $mark_id).*lookup $wan" || \
		ip -6 rule add from all fwmark $mark_id table $wan prio 10000 >/dev/null 2>&1
	if [ -e "/sys/class/net/$wan" ] && ! echo "$wan" | grep -Eq '^(wan|vwan|adsl)'; then
		ip route show table "$wan" 2>/dev/null | grep -q '^default ' || \
			ip route replace default dev "$wan" table "$wan" metric 100 >/dev/null 2>&1
	fi
}

__wg_inbound_policy_del()
{
	local iface_name="$1"
	[ "$iface_name" ] || return
	local comment=$(__wg_inbound_comment "$iface_name")
	local iface_comment=$(__wg_iface_comment "$iface_name")

	iptables -t mangle -S PREROUTING 2>/dev/null | grep -E -- "$comment|$iface_comment" | sed 's/^-A /-D /' |\
	while read rule; do
		iptables -t mangle $rule >/dev/null 2>&1
	done
	iptables -t mangle -S OUTPUT 2>/dev/null | grep -E -- "$comment|$iface_comment" | sed 's/^-A /-D /' |\
	while read rule; do
		iptables -t mangle $rule >/dev/null 2>&1
	done
}

__wg_inbound_policy_apply()
{
	local iface_name="$1" listen_port="$2" bind_wan="$3"
	[ "$iface_name" -a "$listen_port" ] || return
	local comment=$(__wg_inbound_comment "$iface_name")
	local iface_comment=$(__wg_iface_comment "$iface_name")

	__wg_inbound_policy_del "$iface_name"

	local wan
	for wan in $(__wg_route_iface_list); do
		[ "$wan" = "auto" -o "$wan" = "all" -o "$wan" = "any" ] && continue
		local mark_id=$(__wg_policy_wan_mark "$wan")
		[ "$mark_id" ] || continue
		__wg_policy_ensure_rule "$mark_id" "$wan"
		iptables -t mangle -A PREROUTING -i "$wan" -p udp --dport "$listen_port" \
			-m comment --comment "$comment" -j CONNMARK --set-mark "$mark_id" >/dev/null 2>&1
	done

	iptables -t mangle -A OUTPUT -p udp --sport "$listen_port" -m connmark ! --mark 0 \
		-m comment --comment "$comment" -j CONNMARK --restore-mark >/dev/null 2>&1

		if [ "$bind_wan" -a "$bind_wan" != "auto" ]; then
			local mark_id=$(__wg_policy_wan_mark "$bind_wan")
			if [ "$mark_id" ]; then
				__wg_policy_ensure_rule "$mark_id" "$bind_wan"
				iptables -t mangle -A PREROUTING -i "$iface_name" \
					-m connmark --mark 0 -m mark --mark 0 \
					-m comment --comment "$iface_comment" -j MARK --set-mark "$mark_id" >/dev/null 2>&1
				iptables -t mangle -A OUTPUT -p udp --sport "$listen_port" \
					-m comment --comment "$iface_comment" -j MARK --set-mark "$mark_id" >/dev/null 2>&1
			fi
		fi
}

__wg_policy_add_mark_rule()
{
	local peer_id="$1" remote_addr="$2" remote_port="$3" mark_id="$4" extra="$5"
	local comment=$(__wg_policy_comment "$peer_id")

	[ "$remote_addr" -a "$remote_port" -a "$mark_id" ] || return
	iptables -t mangle -A OUTPUT -p udp -d "$remote_addr" --dport "$remote_port" \
		$extra -m comment --comment "$comment" -j MARK --set-mark "$mark_id" >/dev/null 2>&1
}

__wg_policy_apply()
{
	local peer_id="$id"
	local mode="${out_mode:-auto}"
	local wans="$out_wans"
	local balance="${out_balance:-failover}"

	__wg_policy_del "$peer_id"

	[ "$mode" = "auto" -o "$mode" = "" ] && return
	[ "$endpoint" -a "$endpoint_port" -a "$wans" ] || return

	local remote_addr="$1"
	[ "$remote_addr" ] || remote_addr=$(try_get_ip_of_address "$endpoint")
	[ "$remote_addr" ] || return

	local wan_list="${wans//,/ }"
	local selected_wans=""
	local wan
	for wan in $wan_list; do
		__wg_policy_wan_is_alive "$wan" || continue
		selected_wans="${selected_wans:+$selected_wans }$wan"
		[ "$mode" = "single" -o "$balance" != "ecmp" ] && break
	done
	[ "$selected_wans" ] || selected_wans="$wan_list"

	local count=$(echo $selected_wans | wc -w)
	if [ "$balance" = "ecmp" -a "$count" -gt 1 ]; then
		local i=1
		for wan in $selected_wans; do
			local mark_id=$(__wg_policy_wan_mark "$wan")
			[ "$mark_id" ] || continue
			__wg_policy_ensure_rule "$mark_id" "$wan"
			if [ "$i" -lt "$count" ]; then
				local probability=$(awk -v i="$i" -v c="$count" 'BEGIN{printf "%.8f", 1/(c-i+1)}')
				__wg_policy_add_mark_rule "$peer_id" "$remote_addr" "$endpoint_port" "$mark_id" "-m statistic --mode random --probability $probability"
			else
				__wg_policy_add_mark_rule "$peer_id" "$remote_addr" "$endpoint_port" "$mark_id"
			fi
			i=$((i + 1))
		done
	else
		for wan in $selected_wans; do
			local mark_id=$(__wg_policy_wan_mark "$wan")
			[ "$mark_id" ] || continue
			__wg_policy_ensure_rule "$mark_id" "$wan"
			__wg_policy_add_mark_rule "$peer_id" "$remote_addr" "$endpoint_port" "$mark_id"
			break
		done
	fi
}

resolve_flush()
{
 local rows config interface peer_publickey endpoint endpoint_port id identity resolved status=0
 # DNS may take seconds. Read a candidate snapshot without holding the mutation
 # lock, then recheck each complete peer identity under that lock before apply.
 rows=$(sql_config_get_list "$IK_DB_CONFIG" "select p.* from wireguard_peers p join wireguard w on w.name=p.interface where p.enabled='yes' and w.enabled='yes' and ifnull(p.endpoint,'')<>'' and ifnull(p.endpoint_port,'')<>''") || return 1
 while read -r config;do
  [ "$config" ] || continue
  local $config
  case "$id" in ''|*[!0-9]*) status=1;continue;; esac
  identity=$(__wg_endpoint_identity)
  resolved=$(__wg_resolve_address "$endpoint") || { status=1;continue; }
  Lock wireguard_address excl 20 || { status=1;continue; }
  __wg_resolve_flush_locked "$id" "$identity" "$resolved" || status=1
  unLock wireguard_address
 done <<< "$rows"
 return "$status"
}

__wg_resolve_flush_locked()
{
 local wanted_id="$1" expected_identity="$2" resolved="$3"
 local config interface peer_publickey endpoint endpoint_port id cache identity value wg_bin current status=0
 case "$wanted_id" in ''|*[!0-9]*) return 1;; esac
 config=$(sql_config_get_list "$IK_DB_CONFIG" "select p.* from wireguard_peers p join wireguard w on w.name=p.interface where p.id=$wanted_id and p.enabled='yes' and w.enabled='yes' and ifnull(p.endpoint,'')<>'' and ifnull(p.endpoint_port,'')<>''") || return 1
 [ "$config" ] || return 0
 local $config
 identity=$(__wg_endpoint_identity)
 # Deleted, disabled, moved or edited while resolving/waiting: discard the
 # stale answer. A future refresh will resolve the current configuration.
 [ "$identity" = "$expected_identity" ] || return 0
 wg_bin=$(__wg_bin);[ "$wg_bin" ] || return 1
 # wg set can CREATE a peer: require membership in the current kernel first.
 current=$("$wg_bin" show "$interface" peers 2>/dev/null) || return 1
 printf '%s\n' "$current" | grep -Fxq "$peer_publickey" || return 0
 value=$(printf '%s\t%s' "$identity" "$resolved")
 cache="$IK_DIR_TMP/wireguard/config/$id"
 [ "$(cat "$cache" 2>/dev/null)" != "$value" ] || return 0
 "$wg_bin" set "$interface" peer "$peer_publickey" endpoint "$(__wg_endpoint_socket "$resolved" "$endpoint_port")" || return 1
 (umask 077;printf '%s\n' "$value" > "$cache.new" && mv -f "$cache.new" "$cache") || status=1
 __wg_policy_apply "$resolved"
 return "$status"
}

__exec_rule_clean()
{
	sql_config_get_list $IK_DB_CONFIG "select * from wireguard;" |\
	while read config ;do
		if [ -n "$config" ];then
			local $config
			__exec_rule_iface_del $name
		fi
	done
}

__exec_rule_peers_clean()
{
	sql_config_get_list $IK_DB_CONFIG "select * from wireguard_peers;" |\
	while read config ;do
		if [ -n "$config" ];then
			local $config
			__exec_rule_iface_del $name
			__del_config_cache
		fi
	done
}

__wg_client_dns_for_iface()
{
	local iface="$1"
	local addr=""

	[ "$iface" ] || {
		echo "223.5.5.5,8.8.8.8"
		return
	}
	addr=$(sqlite3 "$IK_DB_CONFIG" "select local_address from wireguard where name='$iface' limit 1;" 2>/dev/null)
	addr="${addr%%/*}"
	echo "${addr:-223.5.5.5,8.8.8.8}"
}

__wg_locked_add() {
	exit_peer=${exit_peer:-no}
	client_endpoint=${client_endpoint:-}
	site_local=${site_local:-}
	site_remote=${site_remote:-}
	out_mode="auto"
	out_wans=""
	out_balance="failover"
	[ "$client_dns" ] || client_dns=$(__wg_client_dns_for_iface "$interface")

	__check_param_add || exit 1

	__check_allowip_conflict "$allowips" || exit 1

	__check_key_valid "$peer_publickey" || exit 1
	__check_key_valid "$presharedkey" || exit 1
	__check_key_valid "$peer_privatekey" || exit 1

	local sql_param=" enabled:str comment:str interface:str peer_publickey:str peer_privatekey:str presharedkey:str allowips:str endpoint:str endpoint_port:str keepalive:int out_mode:str out_wans:str out_balance:str client_dns:str client_endpoint:str exit_peer:str site_local:str site_remote:str"
	if SqlMsg=$(sql_config_insert $IK_DB_CONFIG wireguard_peers $sql_param);then
		id="$SqlMsg"

		__wg_apply_iface "$interface" || return 1

		__wg_iface_cache_update
		echo "$id"
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi
}
__wg_valid_ids()
{
 [[ "$1" =~ ^[0-9]+(,[0-9]+)*$ ]] && return 0
 echo "请选择有效的 WG 配置记录"
 return 1
}

__wg_write_config()
{
 # Read the pre-change rows first, then check the database mutation before changing runtime state.
 sqlite3 -cmd '.timeout 10000' "$IK_DB_CONFIG" "$1" >/dev/null 2>&1 && return 0
 echo "WG 配置保存失败，请重试"
 return 1
}

__wg_locked_del() {
 __wg_valid_ids "$id" || return 1
 local requested_ids="$id"
 local rows config ifaces="" interface
 rows=$(sql_config_get_list "$IK_DB_CONFIG" "select * from wireguard_peers where id in ($requested_ids)") || return 1
 __wg_write_config "delete from wireguard_peers where id in ($requested_ids)" || return 1
 while read -r config;do
  [ "$config" ] || continue
  local $config
  __wg_policy_del "$id";__del_config_cache
  ifaces="$ifaces $interface"
 done <<< "$rows"
 __wg_apply_interfaces "$ifaces" || return 1
 __wg_iface_cache_update
 return 0
}
__wg_locked_down() {
 __wg_valid_ids "$id" || return 1
 local requested_ids="$id"
 local rows config ifaces="" interface
 rows=$(sql_config_get_list "$IK_DB_CONFIG" "select * from wireguard_peers where id in ($requested_ids)") || return 1
 __wg_write_config "update wireguard_peers set enabled='no' where id in ($requested_ids)" || return 1
 while read -r config;do
  [ "$config" ] || continue
  local $config
  __wg_policy_del "$id";__del_config_cache
  ifaces="$ifaces $interface"
 done <<< "$rows"
 __wg_apply_interfaces "$ifaces" || return 1
 __wg_iface_cache_update
 return 0
}
__wg_locked_up() {
 __wg_valid_ids "$id" || return 1
 local requested_ids="$id"
 local rows config ifaces="" interface
 rows=$(sql_config_get_list "$IK_DB_CONFIG" "select * from wireguard_peers where id in ($requested_ids)") || return 1
 __wg_write_config "update wireguard_peers set enabled='yes' where id in ($requested_ids)" || return 1
 while read -r config;do
  [ "$config" ] || continue
  local $config
  ifaces="$ifaces $interface"
 done <<< "$rows"
 __wg_apply_interfaces "$ifaces" || return 1
 __wg_iface_cache_update
 return 0
}

__wg_apply_interfaces()
{
 local iface seen=' ' status=0
 for iface in $1;do
  case "$seen" in *" $iface "*) continue;; esac
  seen="$seen$iface "
  __wg_apply_iface "$iface" || status=1
 done
 return "$status"
}

__wg_locked_edit() {
	res=$(sql_config_get_list $IK_DB_CONFIG "select * from wireguard_peers where id=$id" prefix=old_)
	if [ "$res" = "" ];then
		return 0
	fi
	local $res
	exit_peer=${exit_peer-${old_exit_peer:-no}}
	client_endpoint=${client_endpoint-${old_client_endpoint:-}}
	site_local=${site_local-${old_site_local:-}}
	site_remote=${site_remote-${old_site_remote:-}}

	out_mode="auto"
	out_wans=""
	out_balance="failover"
	[ "$client_dns" ] || client_dns=$(__wg_client_dns_for_iface "$interface")

	__check_param_add || exit 1

	__check_allowip_conflict "$allowips" "$id" || exit 1

	__check_key_valid "$peer_publickey" || exit 1
	__check_key_valid "$presharedkey" || exit 1
	__check_key_valid "$peer_privatekey" || exit 1


	local sql_param=" comment:str interface:str peer_publickey:str peer_privatekey:str presharedkey:str allowips:str endpoint:str endpoint_port:str keepalive:int out_mode:str out_wans:str out_balance:str client_dns:str client_endpoint:str exit_peer:str site_local:str site_remote:str"

	if SqlMsg=$(sql_config_update $IK_DB_CONFIG wireguard_peers "id=$id" $sql_param) ;then 
        local rekey_endpoints=""
        if ! NewOldVarl presharedkey;then
            # Updating the PSK alone leaves existing transport keys alive in
            # this kernel. Revoke only this peer before installing new keys.
            rekey_endpoints=$(__wg_revoke_peer_sessions "$old_interface" "$old_peer_publickey") || { __wg_apply_failed "$old_interface";return 1; }
        fi

		if ! NewOldVarl interface; then
			__del_config_cache
			__wg_apply_iface "$old_interface" || { __wg_apply_failed "$interface";return 1; }	
			__wg_apply_iface "$interface" || return 1
		else
			# peer_privatekey/client_dns are client-export metadata; changing them
			# alone must not tear down every live peer on this shared interface.
			if ! NewOldVarl enabled interface local_privatekey local_publickey local_address local_listenport peer_publickey presharedkey allowips endpoint endpoint_port keepalive out_mode out_wans out_balance exit_peer site_local site_remote ;then
				__wg_apply_iface "$interface" || return 1
			fi
		fi

        if [ "$rekey_endpoints" ] && ip link show dev "$interface" >/dev/null 2>&1;then
            __wg_restore_learned_endpoints "$interface" "$rekey_endpoints" || { __wg_apply_failed "$interface";return 1; }
        fi
		__wg_iface_cache_update
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi

}

__exec_rule_iface_del()
{
 local iface_name="$1"
 [ "$iface_name" ] || return 0
 /usr/ikuai/script/native_ingress.sh down "$iface_name" >/dev/null 2>&1 || true
 __wg_inbound_policy_del "$iface_name"
 if ip link show dev "$iface_name" >/dev/null 2>&1;then
  ip route flush dev "$iface_name" metric 100 >/dev/null 2>&1
  ip link del dev "$iface_name" || { __wg_apply_failed "$iface_name";return 1; }
 fi
 rm -f "$IK_DIR_TMP/wireguard/$iface_name.conf"
}

__init_iface_config()
{
	local res=$(sql_config_get_list $IK_DB_CONFIG "select * from wireguard where name='$iface' and enabled='yes'")
	if [ -z "$res" ]; then
		return
	fi
	local $res
	# Refuse invalid restored configurations; never silently fall back to auto.
	interface_check_routing_exit "$interface" || return 1

	if [ "${interface:-auto}" != "auto" ];then
		local fwmark=$(iproute_get_markid $interface)
		__wg_policy_ensure_rule "$fwmark" "$interface"
	fi

	ip link add dev "$name" type wireguard || return 1
	ip address add dev "$name" "$local_address" || return 1
	ip link set mtu "${mtu:-1420}" dev "$name" || return 1
	/usr/ikuai/script/native_ingress.sh up "$name" || return 1

	__wg_inbound_policy_apply "$name" "$local_listenport" "$interface"
}

__wg_build_iface_config()
{
 local iface="$1" stage="$2" rows config res fwmark
 res=$(sql_config_get_list "$IK_DB_CONFIG" "select * from wireguard where name='$iface' and enabled='yes'") || return 1
 [ "$res" ] || return 1
 local $res
 interface_check_routing_exit "$interface" || return 1
 [ "${interface:-auto}" = auto ] || fwmark=$(iproute_get_markid "$interface")
 {
  printf '[Interface]\nListenPort = %s\nPrivateKey = %s\nFwMark = %s\n' "$local_listenport" "$local_privatekey" "${fwmark:-0}"
 } > "$stage/iface.conf" || return 1
 : > "$stage/routes"
 rows=$(sql_config_get_list "$IK_DB_CONFIG" "select * from wireguard_peers where interface='$iface' and enabled='yes' order by id") || return 1
 local endpoints wg_bin=$(__wg_bin)
 endpoints=$("$wg_bin" show "$iface" endpoints 2>/dev/null) || endpoints=""
 while read -r config;do
  [ "$config" ] || continue
  local $config
  local format_ips=$(__format_ipmask "$allowips${site_remote:+,$site_remote}") runtime_ips identity cached resolved current socket
  runtime_ips="$format_ips";[ "$exit_peer" != yes ] || runtime_ips='0.0.0.0/0'
  socket=""
  if [ "$endpoint" -a "$endpoint_port" ];then
   identity=$(__wg_endpoint_identity)
   cached=$(cat "$IK_DIR_TMP/wireguard/config/$id" 2>/dev/null)
   current=$(printf '%s\n' "$endpoints" | awk -v k="$peer_publickey" '$1==k{print $2}')
   if [[ "$cached" = "$identity"$'\t'* ]] && [ "$current" -a "$current" != '(none)' ];then
    # Preserve roaming endpoints and avoid repeated DNS work on unrelated edits.
    socket="$current";resolved=${cached##*$'\t'}
   else
    resolved=$(__wg_resolve_address "$endpoint") || return 1
    socket=$(__wg_endpoint_socket "$resolved" "$endpoint_port")
   fi
   printf '%s\t%s\n' "$identity" "$resolved" > "$stage/cache-$id" || return 1
  fi
  {
   printf '\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\nPersistentKeepalive = %s\n' "$peer_publickey" "${presharedkey:-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}" "$runtime_ips" "${keepalive:-0}"
   [ -z "$socket" ] || printf 'Endpoint = %s\n' "$socket"
   printf '\n'
  } >> "$stage/iface.conf" || return 1
  for allow in ${format_ips//,/ };do
   [ "${allow##*/}" = 0 ] || printf '%s\n' "${allow%/32}" >> "$stage/routes"
  done
 done <<< "$rows"
 sort -u "$stage/routes" -o "$stage/routes" || return 1
 printf '%s\n' "$rows" > "$stage/rows"
}

__wg_apply_iface()
{
 local iface="$1" stage wg_bin config rows allow old_routes name interface enabled count
 [[ "$iface" =~ ^wg[0-9]+$ ]] || return 1
 count=$(sqlite3 "$IK_DB_CONFIG" "select count(*) from wireguard where name='$iface' and enabled='yes'") || { __wg_apply_failed "$iface";return 1; }
 if [ "$count" != 1 ];then
  __exec_rule_iface_del "$iface"
  return $?
 fi
 /usr/bin/lua /usr/ikuai/script/wg_peer_options.lua runtime "$IK_DB_CONFIG" "$iface" || { __wg_apply_failed "$iface";return 1; }
 stage=$(mktemp -d "$IK_DIR_TMP/wireguard/apply.XXXXXX") || { __wg_apply_failed "$iface";return 1; }
 chmod 700 "$stage" || { rm -rf "$stage";__wg_apply_failed "$iface";return 1; }
 (umask 077;__wg_build_iface_config "$iface" "$stage") || { rm -rf "$stage";__wg_apply_failed "$iface";return 1; }
 local mode=syncconf was_up=no
 if ! ip link show dev "$iface" >/dev/null 2>&1;then
  __init_iface_config >/dev/null 2>&1 || { rm -rf "$stage";__wg_apply_failed "$iface";return 1; }
  mode=setconf
 fi
 if [ -r "/sys/class/net/$iface/flags" ];then
  local flags=$(cat "/sys/class/net/$iface/flags")
  [ "$((flags & 1))" = 0 ] || was_up=yes
 fi
 wg_bin=$(__wg_bin)
 if ! "$wg_bin" "$mode" "$iface" "$stage/iface.conf" >/dev/null 2>&1;then
  rm -rf "$stage";__wg_apply_failed "$iface";return 1
 fi
 # The kernel rejects a unicast route to a DOWN WG device. Activate only
 # nonempty interfaces after WG configuration succeeds, before adding routes.
 rows=$(cat "$stage/rows")
 if [ "$rows" -a "$was_up" = no ];then
  /usr/ikuai/script/native_ingress.sh up "$iface" && ip link set up dev "$iface" || { rm -rf "$stage";__wg_apply_failed "$iface";return 1; }
 fi
 # Reconcile only metric-100 WG routes; do not flush working routes for peers
 # that were unchanged. Explicitly remove obsolete destinations.
 old_routes=$(ip route show table main dev "$iface" | awk '/metric 100( |$)/{print $1}')
 while read -r allow;do
  [ "$allow" ] || continue
  if ! grep -Fxq "$allow" "$stage/routes";then
   ip route del "$allow" dev "$iface" metric 100 >/dev/null 2>&1 || { rm -rf "$stage";__wg_apply_failed "$iface";return 1; }
  fi
 done <<< "$old_routes"
 while read -r allow;do
  [ "$allow" ] || continue
  printf '%s\n' "$old_routes" | grep -Fxq "$allow" && continue
  if ! ip route replace "$allow" dev "$iface" metric 100;then
   rm -rf "$stage";__wg_apply_failed "$iface";return 1
  fi
 done < "$stage/routes"
 if [ "$rows" ];then
  iproute_get_markid "$iface" >/dev/null 2>&1
  ip route replace default dev "$iface" table "$iface" metric 100 >/dev/null 2>&1 || { rm -rf "$stage";__wg_apply_failed "$iface";return 1; }
 fi
 while read -r config;do
  [ "$config" ] || continue
  local $config
  __wg_policy_apply
 done <<< "$rows"
 # Publish configuration and DNS cache only after all runtime operations succeed.
 mv -f "$stage/iface.conf" "$IK_DIR_TMP/wireguard/$iface.conf" || { rm -rf "$stage";__wg_apply_failed "$iface";return 1; }
 for config in "$stage"/cache-*;do
  [ -f "$config" ] || continue
  mv -f "$config" "$IK_DIR_TMP/wireguard/config/${config##*/cache-}" || { rm -rf "$stage";__wg_apply_failed "$iface";return 1; }
 done
 rm -rf "$stage"
 return 0
}

__wg_apply_failed()
{
 ip link set down dev "$1" >/dev/null 2>&1 || true
 rm -f "$IK_DIR_TMP/wireguard/$1.conf"
 logger -t wireguard "Configuration saved but runtime apply failed on $1; interface blocked"
 echo "配置已保存，但 $1 运行配置应用失败；接口已阻断，请修正后重新启用"
}

__init_iface_peers_config()
{
 __wg_apply_iface "$iface"
}

# Deleting/readding one peer invalidates its existing transport keypairs.
# Return only that peer's public-key/Endpoint snapshot, never private keys or PSK.
__wg_revoke_peer_sessions()
{
 local iface="$1" key="$2" wg_bin endpoints
 ip link show dev "$iface" >/dev/null 2>&1 || return 0
 wg_bin=$(__wg_bin);[ "$wg_bin" ] || return 1
 endpoints=$("$wg_bin" show "$iface" endpoints 2>/dev/null) || return 1
 "$wg_bin" set "$iface" peer "$key" remove >/dev/null 2>&1 || return 1
 printf '%s\n' "$endpoints" | awk -v key="$key" '$1==key{print}'
}

# Preserve authenticated, learned endpoints across an in-place rebuild. A
# passive peer behind NAT may otherwise remain unreachable until it initiates
# a new handshake. Never overwrite an explicitly configured endpoint, and never
# recreate a peer that is absent from the newly applied runtime configuration.
__wg_restore_learned_endpoints()
{
	local iface="$1" previous="$2" wg_bin current
	local saved_key saved_endpoint current_key current_endpoint
	[ "$previous" ] || return 0
	wg_bin=$(__wg_bin)
	[ "$wg_bin" ] || return 1
	current=$("$wg_bin" show "$iface" endpoints 2>/dev/null) || return 1
	while read -r saved_key saved_endpoint; do
		[ "$saved_key" -a "$saved_endpoint" ] || continue
		[ "$saved_endpoint" != '(none)' ] || continue
		while read -r current_key current_endpoint; do
			[ "$current_key" = "$saved_key" ] || continue
			if [ "$current_endpoint" = '(none)' ]; then
				"$wg_bin" set "$iface" peer "$saved_key" endpoint "$saved_endpoint" || return 1
			fi
			break
		done <<< "$current"
	done <<< "$previous"
	return 0
}

#interface=wg11
__exec_rule_restart_one()
{
	local iface=$1
	if [ -z "$iface" ]; then
		return
	fi
	local wg_bin=$(__wg_bin) learned_endpoints
	learned_endpoints=$("$wg_bin" show "$iface" endpoints 2>/dev/null) || learned_endpoints=""
	__exec_rule_iface_del "$iface" >/dev/null 2>&1 || return 1
	__init_iface_config >/dev/null 2>&1 || return 1
	__init_iface_peers_config >/dev/null 2>&1 || return 1
	if [ -e "/sys/class/net/$iface" ]; then
		__wg_restore_learned_endpoints "$iface" "$learned_endpoints" || {
			ip link set down dev "$iface"
			return 1
		}
	fi
	return 0
}

__exec_rule_restart_all()
{
	sql_config_get_list $IK_DB_CONFIG "select name from wireguard where enabled='yes'" |\
	while read config; do
		[ "$config" ] || continue
		local $config
		__exec_rule_restart_one "$name" || return 1
	done
}

__wg_locked_iface_add() {
	__wg_check_iface_address "" || return 1
	__wg_fill_local_keys
	__check_param_iface_add || exit 1
	__wg_check_route_iface "$interface" || exit 1

	__check_key_valid "$local_privatekey" || exit 1
	__check_key_valid "$local_publickey" || exit 1

	local sql_param="id:null enabled:str interface:str name:str mtu:str local_privatekey:str local_publickey:str local_address:str local_listenport:int "
	if SqlMsg=$(sql_config_insert $IK_DB_CONFIG wireguard $sql_param);then
		id="$SqlMsg"
		__exec_rule_restart_one "$name" || return 1

		__wg_iface_cache_update
		echo "$id"
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi
}
__wg_locked_iface_del() {
 __wg_valid_ids "$id" || return 1
 local requested_ids="$id"
 /usr/bin/lua /usr/ikuai/script/wg_address_config.lua iface_delete "$IK_DB_CONFIG" "$id" || return 1
 local rows config status=0
 rows=$(sql_config_get_list "$IK_DB_CONFIG" "select * from wireguard where id in ($requested_ids)") || return 1
 __wg_write_config "delete from wireguard where id in ($requested_ids)" || return 1
 while read -r config;do
  [ "$config" ] || continue
  local $config
  __exec_rule_iface_del "$name" || status=1
 done <<< "$rows"
 __wg_iface_cache_update
 return "$status"
}
__wg_locked_iface_down() {
 __wg_valid_ids "$id" || return 1
 local requested_ids="$id"
 local rows config status=0
 rows=$(sql_config_get_list "$IK_DB_CONFIG" "select * from wireguard where id in ($requested_ids)") || return 1
 __wg_write_config "update wireguard set enabled='no' where id in ($requested_ids)" || return 1
 while read -r config;do
  [ "$config" ] || continue
  local $config
  __exec_rule_iface_del "$name" || status=1
 done <<< "$rows"
 __wg_iface_cache_update
 return "$status"
}
__wg_locked_iface_up() {
 __wg_valid_ids "$id" || return 1
 local requested_ids="$id"
 local rows config status=0
 rows=$(sql_config_get_list "$IK_DB_CONFIG" "select * from wireguard where id in ($requested_ids)") || return 1
 __wg_write_config "update wireguard set enabled='yes' where id in ($requested_ids)" || return 1
 while read -r config;do
  [ "$config" ] || continue
  local $config
  __exec_rule_restart_one "$name" || status=1
 done <<< "$rows"
 __wg_iface_cache_update
 return "$status"
}

__wg_locked_iface_edit() {
	__wg_check_iface_address "$id" || return 1
	__wg_fill_local_keys
	__check_param_iface_add || exit 1
	__wg_check_route_iface "$interface" || exit 1

	__check_key_valid "$local_privatekey" || exit 1
	__check_key_valid "$local_publickey" || exit 1

	res=$(sql_config_get_list $IK_DB_CONFIG "select * from wireguard where id=$id" prefix=old_)
	if [ "$res" = "" ];then
		return 0
	fi
	local $res

	local sql_param="enabled:str name:str interface:str mtu:str local_privatekey:str local_publickey:str local_address:str local_listenport:int "

	if SqlMsg=$(sql_config_update $IK_DB_CONFIG wireguard "id=$id" $sql_param) ;then 
		if ! NewOldVarl name; then
			__exec_rule_iface_del "$old_name" || return 1
			__exec_rule_restart_one "$name" || return 1
		else
			if ! NewOldVarl mtu ;then
				ip link set mtu ${mtu:-1420} dev $name
				/usr/ikuai/script/native_ingress.sh up "$name" || return 1
			fi
			if ! NewOldVarl interface local_privatekey local_publickey local_address local_listenport ;then
				__exec_rule_restart_one "$name" || return 1
			fi
		fi
		__wg_iface_cache_update
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi

}



EXPORT()
{
	Include import_export.sh
	local format=${format:-txt}
	if errmsg=$(export_txt $IK_DB_CONFIG wireguard $format $IK_DIR_EXPORT/wireguard.$format) ;then
		echo "wireguard.$format"
		return 0
	else
		echo "$errmsg"
		return 1
	fi
}

EXPORT_EXTEND()
{
	Include import_export.sh
	local format=${format:-txt}
	if errmsg=$(export_txt $IK_DB_CONFIG wireguard_peers $format $IK_DIR_EXPORT/wireguard_peers.$format) ;then
		echo "wireguard_peers.$format"
		return 0
	else
		echo "$errmsg"
		return 1
	fi
}


__wg_locked_IMPORT() {
	I18nload import_export.json
	Include import_export.sh

	if errmsg=$(import_txt $IK_DB_CONFIG wireguard $IK_DIR_IMPORT/$filename "1"  __check_param_iface_add __exec_rule_clean) ;then
		__wg_locked_init || return 1
		return 0
	else
		echo "$errmsg"
		return 1
	fi
}

__wg_locked_IMPORT_EXTEND() {
	I18nload import_export.json
	Include import_export.sh
	# Native import appends rows. Preflight the whole batch on a private copy so
	# two imported peers cannot quietly compete for one exit interface.
	local suffix="${filename##*.}" scratch errmsg
	case "$suffix" in csv|txt) ;; *) echo "只支持 CSV 或 TXT 配置"; return 1;; esac
	scratch=$(mktemp -d /tmp/iktmp/wg-import.XXXXXX) || return 1
	chmod 700 "$scratch"
	if ! sqlite3 "$IK_DB_CONFIG" ".backup '$scratch/config.db'" || ! cp "$IK_DIR_IMPORT/$filename" "$scratch/input.$suffix"; then
		rm -rf "$scratch"; return 1
	fi
	chmod 600 "$scratch/config.db" "$scratch/input.$suffix"
	if ! errmsg=$(import_txt "$scratch/config.db" wireguard_peers "$scratch/input.$suffix" "1" __check_param_add null); then
		rm -rf "$scratch"; echo "$errmsg"; return 1
	fi
	if ! errmsg=$(/usr/bin/lua /usr/ikuai/script/wg_peer_options.lua runtime "$scratch/config.db" '*'); then
		rm -rf "$scratch"; echo "$errmsg"; return 1
	fi
	rm -rf "$scratch"
	if errmsg=$(import_txt $IK_DB_CONFIG wireguard_peers $IK_DIR_IMPORT/$filename "1" __check_param_add __exec_rule_peers_clean); then
		__wg_locked_init || return 1
		return 0
	else
		echo "$errmsg"
		return 1
	fi
}

__wg_center_conf()
{
	echo /etc/mnt/ikuai/wg_center.conf
}

__wg_center_quote()
{
	echo "$1" | sed "s/'/'\\\\''/g"
}

__wg_center_defaults()
{
	local conf=$(__wg_center_conf)
	[ -f "$conf" ] && return
	mkdir -p /etc/mnt/ikuai 2>/dev/null
	cat > "$conf" <<EOF
ENABLE='0'
CLIENT_SRC='10.100.10.0/24'
CHINA_IFACE='wg_to_A'
OVERSEA_IFACE='wg_to_C'
ROUTE_NON_CHINA='1'
CHINA_URL='https://ispip.clang.cn/all_cn.txt'
NAT_ENABLE='0'
NAT_SRC='10.100.10.0/24'
NAT_WAN='wan1'
EOF
}

__show_center_config()
{
	__wg_center_defaults
	local conf=$(__wg_center_conf)
	local ENABLE=0 CLIENT_SRC="10.100.10.0/24" CHINA_IFACE="wg_to_A" OVERSEA_IFACE="wg_to_C" ROUTE_NON_CHINA=1 CHINA_URL="https://ispip.clang.cn/all_cn.txt" NAT_ENABLE=0 NAT_SRC="10.100.10.0/24" NAT_WAN="wan1"
	. "$conf" 2>/dev/null
	local last_update=""
	local last_apply=""
	[ -f /etc/mnt/ikuai/wg_center/last_update.log ] && last_update=$(cat /etc/mnt/ikuai/wg_center/last_update.log)
	[ -f /etc/mnt/ikuai/wg_center/last_apply.log ] && last_apply=$(cat /etc/mnt/ikuai/wg_center/last_apply.log)
	local center_config="{\"enable\":\"$ENABLE\",\"client_src\":\"$CLIENT_SRC\",\"china_iface\":\"$CHINA_IFACE\",\"oversea_iface\":\"$OVERSEA_IFACE\",\"route_non_china\":\"$ROUTE_NON_CHINA\",\"china_url\":\"$CHINA_URL\",\"nat_enable\":\"$NAT_ENABLE\",\"nat_src\":\"$NAT_SRC\",\"nat_wan\":\"$NAT_WAN\",\"last_update\":\"$last_update\",\"last_apply\":\"$last_apply\"}"
	json_append __json_result__ center_config:json
}

center_save()
{
	mkdir -p /etc/mnt/ikuai 2>/dev/null
	local conf=$(__wg_center_conf)
	local enable="${enable:-0}"
	local route_non_china="${route_non_china:-1}"
	local nat_enable="${nat_enable:-0}"
	[ "$enable" = "1" ] || enable=0
	[ "$route_non_china" = "1" ] || route_non_china=0
	[ "$nat_enable" = "1" ] || nat_enable=0
	cat > "$conf" <<EOF
ENABLE='$( __wg_center_quote "$enable" )'
CLIENT_SRC='$( __wg_center_quote "${client_src:-10.100.10.0/24}" )'
CHINA_IFACE='$( __wg_center_quote "${china_iface:-wg_to_A}" )'
OVERSEA_IFACE='$( __wg_center_quote "${oversea_iface:-wg_to_C}" )'
ROUTE_NON_CHINA='$( __wg_center_quote "$route_non_china" )'
CHINA_URL='$( __wg_center_quote "${china_url:-https://ispip.clang.cn/all_cn.txt}" )'
NAT_ENABLE='$( __wg_center_quote "$nat_enable" )'
NAT_SRC='$( __wg_center_quote "${nat_src:-10.100.10.0/24}" )'
NAT_WAN='$( __wg_center_quote "${nat_wan:-wan1}" )'
EOF
	[ -x /usr/ikuai/script/wg_center_route.sh ] && /usr/ikuai/script/wg_center_route.sh apply >/tmp/iktmp/wg_center_web_apply.log 2>&1 || true
	return 0
}

center_update_apply()
{
	if [ -x /usr/ikuai/script/wg_center_route.sh ]; then
		/usr/ikuai/script/wg_center_route.sh update_apply >/tmp/iktmp/wg_center_web_update_apply.log 2>&1 &
		return 0
	fi
	echo "wg_center_route.sh not found"
	return 1
}

#显示VLAN数组
show() {
	local __filter=$(sql_auto_get_filter)
	local __order=$(sql_auto_get_order)
	local __limit=$(sql_auto_get_limit)
	local __where="$__filter $__order $__limit"
	local wg_show_type wg_show_result
	# Native Show ignores errors from known __show_* functions. These export/
	# generation types must discard partial data and propagate failure instead.
	for wg_show_type in ${TYPE//,/ };do
		case "$wg_show_type" in client_export|gen_privatekey|gen_publickey|gen_sharedkey|all)
			wg_show_result=$(__wg_checked_show) || { echo 'WG 配置读取或密钥生成失败，请检查已保存配置后重试';return 1; }
			printf '%s' "$wg_show_result"
			return 0
		;;esac
	done
	Show __json_result__
}

__wg_checked_show()
{
 local wg_show_type wg_show_func __json_result__=''
 for wg_show_type in ${TYPE//,/ };do
  if [ "$wg_show_type" = all ];then
   for wg_show_func in $(declare -F);do
    case "$wg_show_func" in __show_all) ;; __show_*) "$wg_show_func" || return 1;;esac
   done
  else
   wg_show_func="__show_$wg_show_type"
   declare -F "$wg_show_func" >/dev/null || return 1
   "$wg_show_func" || return 1
  fi
 done
 [ "$__json_result__" ] || __json_result__='{}'
 printf '%s' "$__json_result__"
}

__implant_code()
{
cat -<<EOF
        -- Scoped to this SQL query. Both counters and all peers of an interface
        -- observe the same sample; the next request always reads fresh counters.
        local transfer_cache = {}
        local function transfers(name)
                if type(name) ~= "string" or not name:match("^wg%d+$") then return {} end
                if transfer_cache[name] then return transfer_cache[name] end
                local rows = {}
                transfer_cache[name] = rows
                local fp = io.popen("wg show " .. name .. " transfer 2>/dev/null")
                if fp then
                        for line in fp:lines() do
                                local pub, download, upload = line:match("^(%S+)\t(%d+)\t(%d+)$")
                                if pub then rows[pub] = {download=download, upload=upload} end
                        end
                        fp:close()
                end
                return rows
        end
        function create_fc(col, typ, key)
                ikdb:create_function(col,2,
                function (ctx, name, pubkey)
                        local row = transfers(name)[pubkey]
                        ctx:result(row and row[key] or "")
                        return 0
                end)
        end

	create_fc("upload", "text", "upload")
	create_fc("download", "text", "download")
EOF
}

__show_total()
{
	local total=$(sqlite3 $IK_DB_CONFIG "select count() from wireguard_peers $__filter")
	json_append __json_result__ total:int
}

__show_data()
{
	local sql_show="select *,upload(interface,peer_publickey) as upload,download(interface,peer_publickey) as download from wireguard_peers $__where"

	local __sql_implant_code__=$(__implant_code)
	local data=$(sql_config_get_json $IK_DB_CONFIG "$sql_show")
	json_append __json_result__ data:json

	return 0
}

__show_iface_total()
{
	local iface_total=$(sqlite3 $IK_DB_CONFIG "select count() from wireguard $__filter")
	json_append __json_result__ iface_total:int
}


__show_iface_data()
{
	__wg_iface_repair_keys
	local sql_show="select * from wireguard $__where"

	local iface_data=$(sql_config_get_json $IK_DB_CONFIG "$sql_show")
	json_append __json_result__ iface_data:json

	return 0
}

__show_defaults()
{
 local result
 result=$(/usr/bin/lua /usr/ikuai/script/wg_address_config.lua defaults "$IK_DB_CONFIG" "${interface:-}") || return 1
 local iface_defaults=$(printf '%s' "$result" | jq -c .iface_defaults)
 local peer_defaults=$(printf '%s' "$result" | jq -c .peer_defaults)
 json_append __json_result__ iface_defaults:json peer_defaults:json
}

__wan_endpoint_host()
{
	local wan="$1"
	local ip_addr=""
	local internet=""
	local ip_mask=""
	[ "$wan" ] || return

	if [ -f "$IK_DIR_CACHE/config/wan_config.$wan" ]; then
		local $(cat "$IK_DIR_CACHE/config/wan_config.$wan")
	fi

	case "$internet" in
	$INTERNET_STATIC)
		ip_addr="${ip_mask%%/*}"
		;;
	$INTERNET_DHCP)
		if [ -f "/tmp/iktmp/dhcpc/$wan" ]; then
			. "/tmp/iktmp/dhcpc/$wan"
			ip_addr="$dhcp_ip_addr"
		fi
		;;
	$INTERNET_PPPOE)
		if [ -f "/tmp/iktmp/pppoe/$wan" ]; then
			. "/tmp/iktmp/pppoe/$wan"
			ip_addr="$pppoe_ip_addr"
		fi
		;;
	esac

	[ "$ip_addr" ] && echo "$ip_addr"
}

__show_client_endpoint()
{
 # Client-export metadata only: never update a live peer or hold the WG edit lock.
 local client_endpoint
 client_endpoint=$(/usr/ikuai/script/wg_client_endpoint.sh get "${interface:-}" "${force:-0}") || return 1
 json_append __json_result__ client_endpoint:json
}

# A saved export is read under the same lock as peer/interface edits. This is
# read-only: unlike __wg_address_change it must not sync/reconfigure anything.
__show_client_export()
{
 [[ "$peer_id" =~ ^[1-9][0-9]{0,18}$ ]] || { echo '请先保存隧道，再生成配置';return 1; }
 Lock wireguard_address excl 20 || { echo '另一项 WG 配置正在保存，请稍后重试';return 1; }
 local client_export status
 client_export=$(__wg_saved_client_export "$peer_id");status=$?
 unLock wireguard_address
 if [ "$status" != 0 ];then printf '%s\n' "$client_export";return "$status";fi
 json_append __json_result__ client_export:json
}

__wg_saved_client_export()
{
 local wanted_id="$1" snapshot peer_private peer_public parent_private parent_public derived
 local saved_interface saved_address saved_endpoint saved_port saved_keepalive
 # The join and sibling count are one SQLite read snapshot, even for callers
 # outside the normal edit path. Do not return the parent interface private key.
 snapshot=$(sql_config_get_json "$IK_DB_CONFIG" "select p.id,p.interface,p.enabled,p.exit_peer,p.allowips,p.peer_privatekey,p.peer_publickey,ifnull(p.presharedkey,'') as presharedkey,ifnull(p.client_endpoint,'') as client_endpoint,ifnull(p.client_dns,'') as client_dns,p.keepalive,ifnull(p.site_local,'') as site_local,ifnull(p.site_remote,'') as site_remote,ifnull(p.comment,'') as comment,p.out_mode,p.out_wans,p.out_balance,p.endpoint,p.endpoint_port,w.id as iface_id,w.name as iface_name,w.enabled as iface_enabled,w.interface as iface_interface,w.local_address,w.local_listenport,w.local_publickey,w.local_privatekey,w.keepalive as iface_keepalive,w.mtu as iface_mtu,(select count(*) from wireguard_peers s where s.interface=p.interface) as iface_peer_count from wireguard_peers p join wireguard w on w.name=p.interface where p.id=$wanted_id") || { echo '读取已保存的 WG 配置失败，请刷新后重试';return 1; }
 if ! printf '%s' "$snapshot" | jq -e '
  type=="array" and length==1 and (.[0] |
   .enabled=="yes" and .iface_enabled=="yes" and .exit_peer=="yes" and .iface_peer_count==1 and
   (.interface|type=="string") and .interface==.iface_name and
   .site_local=="" and .site_remote=="" and
   (.allowips|type=="string") and (.client_endpoint|type=="string"))' >/dev/null 2>&1;then
  echo '仅支持已启用且独占接口的手机出口隧道，请保存并刷新后重试';return 1
 fi
 # The firmware ships jq 1.4 (without test/sub/all). Keep strict lexical and
 # numeric checks in Bash; jq only selects/serializes the saved JSON fields.
 saved_interface=$(printf '%s' "$snapshot" | jq -r '.[0].interface') || return 1
 saved_address=$(printf '%s' "$snapshot" | jq -r '.[0].allowips') || return 1
 saved_endpoint=$(printf '%s' "$snapshot" | jq -r '.[0].client_endpoint') || return 1
 saved_port=$(printf '%s' "$snapshot" | jq -r '.[0].local_listenport') || return 1
 saved_keepalive=$(printf '%s' "$snapshot" | jq -r '.[0].keepalive') || return 1
 if ! [[ "$saved_interface" =~ ^wg[0-9]+$ ]] ||
    ! __wg_export_ipv4 "${saved_address%/32}" || ! __wg_export_ipv4 "$saved_endpoint" ||
    ! [[ "$saved_port" =~ ^[0-9]{1,5}$ && "$saved_keepalive" =~ ^[0-9]{1,5}$ ]] ||
    [ "$((10#$saved_port))" -lt 1 ] || [ "$((10#$saved_port))" -gt 65535 ] || [ "$((10#$saved_keepalive))" -gt 65535 ];then
  echo '已保存的 WG 地址或端口无效，请保存并刷新后重试';return 1
 fi
 peer_private=$(printf '%s' "$snapshot" | jq -r '.[0].peer_privatekey // ""') || return 1
 peer_public=$(printf '%s' "$snapshot" | jq -r '.[0].peer_publickey // ""') || return 1
 parent_private=$(printf '%s' "$snapshot" | jq -r '.[0].local_privatekey // ""') || return 1
 parent_public=$(printf '%s' "$snapshot" | jq -r '.[0].local_publickey // ""') || return 1
 if ! derived=$(__wg_public_from_private "$peer_private") || [ "$derived" != "$peer_public" ] ||
    ! derived=$(__wg_public_from_private "$parent_private") || [ "$derived" != "$parent_public" ];then
  echo 'WG 密钥不匹配，请重新生成并保存匹配的密钥';return 1
 fi
 local psk
 psk=$(printf '%s' "$snapshot" | jq -r '.[0].presharedkey') || return 1
 __check_key_valid "$psk" >/dev/null || { echo 'WG 密钥格式无效，请保存并刷新后重试';return 1; }
 printf '%s' "$snapshot" | jq -c '.[0] | {
  peer:{id,interface,enabled,exit_peer,allowips,peer_privatekey,peer_publickey,presharedkey,client_endpoint,client_dns,keepalive,site_local,site_remote,comment,out_mode,out_wans,out_balance,endpoint,endpoint_port},
  iface:{id:.iface_id,name:.iface_name,enabled:.iface_enabled,interface:.iface_interface,local_address,local_listenport,local_publickey,keepalive:.iface_keepalive,mtu:.iface_mtu},
  keypair_valid:true}'
}

__wg_export_ipv4()
{
 local a b c d
 [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
 a=$((10#${BASH_REMATCH[1]}));b=$((10#${BASH_REMATCH[2]}))
 c=$((10#${BASH_REMATCH[3]}));d=$((10#${BASH_REMATCH[4]}))
 [ "$a" -gt 0 ] && [ "$a" -ne 127 ] && [ "$a" -lt 224 ] &&
 [ "$b" -le 255 ] && [ "$c" -le 255 ] && [ "$d" -le 255 ] &&
 { [ "$a" -ne 169 ] || [ "$b" -ne 254 ]; }
}

__show_wan_endpoint()
{
	local wan
	local ip_addr
	local data=""

	for wan in $(interface_get_ifname wan); do
		[ "$wan" = "auto" -o "$wan" = "all" -o "$wan" = "any" ] && continue
		ip_addr=$(__wan_endpoint_host "$wan")
		data="${data:+$data,}[\"$wan\",\"$ip_addr\"]"
	done
	local wan_endpoint="[$data]"
	json_append __json_result__ wan_endpoint:json
}

__show_interface()
{
	local interface=$(__wg_route_iface_json)
	json_append __json_result__ interface:json
}

__show_wg_iface()
{
	local tmp_data
	local tmpfile=$(sql_config_get_list $IK_DB_CONFIG "select name from wireguard")
	while read config; do
		[ "$config" ] || continue
		local $config
		tmp_data+="${tmp_data:+,}\"$name\""
	done <<EOF
	$tmpfile
EOF
	local wg_iface="[$tmp_data]"
	json_append __json_result__ wg_iface:json
}


__show_gen_privatekey()
{
 local wg_bin privatekey pubkey
 wg_bin=$(__wg_bin)
 if [ -z "$wg_bin" ] || ! privatekey=$("$wg_bin" genkey 2>/dev/null) ||
    ! pubkey=$(__wg_public_from_private "$privatekey");then
  echo 'WG 密钥生成失败，请重试';return 1
 fi
 json_append __json_result__ pubkey:str privatekey:str
}

__wg_public_from_private()
{
 local private="$1" wg_bin pub
 [ -n "$private" ] && __check_key_valid "$private" >/dev/null || return 1
 wg_bin=$(__wg_bin);[ -n "$wg_bin" ] || return 1
 pub=$(printf '%s\n' "$private" | "$wg_bin" pubkey 2>/dev/null) || return 1
 [ -n "$pub" ] && [ "$pub" != AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= ] && __check_key_valid "$pub" >/dev/null || return 1
 printf '%s\n' "$pub"
}

__show_gen_publickey()
{
 local pubkey
 pubkey=$(__wg_public_from_private "$privatekey") || { echo 'WG 公钥生成失败，请检查私钥后重试';return 1; }
 json_append __json_result__ pubkey:str
}

__show_gen_sharedkey()
{
 local wg_bin presharedkey
 wg_bin=$(__wg_bin)
 if [ -z "$wg_bin" ] || ! presharedkey=$("$wg_bin" genpsk 2>/dev/null) ||
    [ -z "$presharedkey" ] || ! __check_key_valid "$presharedkey" >/dev/null;then
  echo 'WG 预共享密钥生成失败，请重试';return 1
 fi
 json_append __json_result__ presharedkey:str
}

#name=
__show_wg_detail()
{
	
	local wg_bin=$(__wg_bin)
	local endpoints="$([ "$wg_bin" ] && "$wg_bin" show $name endpoints 2>/dev/null| awk '{print $2}')"	
	local latest="$([ "$wg_bin" ] && "$wg_bin" show $name latest-handshakes 2>/dev/null| awk '{print $2}')"	
	local transfer="$([ "$wg_bin" ] && "$wg_bin" show $name transfer 2>/dev/null| awk '{print "download="$2,"upload="$3}')"
	if [ "$transfer" ]; then
		local $transfer
	fi
	
	json_append __json_result__ endpoints:str latest:str download:str upload:str
}

__wg_remove_peer_runtime(){
 local peer_iface="$1" peer_key="$2" old_allowips="$3" wg_bin allow
 ip link show dev "$peer_iface" >/dev/null 2>&1 || return 0
 wg_bin=$(__wg_bin)
 "$wg_bin" set "$peer_iface" peer "$peer_key" remove || return 1
 for allow in $(__format_ipmask "$old_allowips" | tr ',' ' ');do
  [ "${allow##*/}" = 0 ] && continue
  ip route del "$allow" dev "$peer_iface" metric 100 >/dev/null 2>&1 || true
 done
 sql_config_get_list "$IK_DB_CONFIG" "select allowips,site_remote from wireguard_peers where interface='$peer_iface' and enabled='yes'" | while read config;do
  [ "$config" ] || continue
  local $config
  for allow in $(__format_ipmask "$allowips${site_remote:+,$site_remote}" | tr ',' ' ');do
   [ "${allow##*/}" = 0 ] && continue
   ip route replace "$allow" dev "$peer_iface" metric 100 >/dev/null 2>&1 || true
  done
 done
 return 0
}

__wg_address_change(){
 local action="$1" status;shift
 Lock wireguard_address excl 20 || { echo '另一项 WG 配置正在保存，请稍后重试';return 1; }
 local output
 output=$("__wg_locked_$action" "$@");status=$?
 if [ "$status" = 0 ];then /usr/ikuai/script/wg_site.sh sync >/dev/null || { status=1;output="配置已保存，但互访策略应用失败，相关接口已阻断；请刷新后检查"; };fi
 unLock wireguard_address
 [ -z "$output" ] || printf '%s\n' "$output"
 return "$status"
}
add(){ __wg_address_change add "$@"; }
edit(){ __wg_address_change edit "$@"; }
del(){ __wg_address_change del "$@"; }
up(){ __wg_address_change up "$@"; }
down(){ __wg_address_change down "$@"; }
iface_add(){ __wg_address_change iface_add "$@"; }
iface_edit(){ __wg_address_change iface_edit "$@"; }
iface_del(){ __wg_address_change iface_del "$@"; }
iface_up(){ __wg_address_change iface_up "$@"; }
iface_down(){ __wg_address_change iface_down "$@"; }
IMPORT(){ __wg_address_change IMPORT "$@"; }
IMPORT_EXTEND(){ __wg_address_change IMPORT_EXTEND "$@"; }
