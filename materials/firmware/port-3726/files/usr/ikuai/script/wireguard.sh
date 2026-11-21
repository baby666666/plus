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

# The receiver table is created on the first successful bundle import. Native
# exports and list responses retain their original schema on other routers.
__wg_site_client_table(){
 local n
 n=$(sqlite3 -cmd '.timeout 10000' "$IK_DB_CONFIG" "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='wg_site_clients'") || return 2
 [ "$n" = 1 ] || return 1
 if [ "${1:-}" = populated ];then
  n=$(sqlite3 -cmd '.timeout 10000' "$IK_DB_CONFIG" "SELECT EXISTS (SELECT 1 FROM wg_site_clients)") || return 2
  [ "$n" = 1 ]
 fi
}
__wg_site_client_conflict(){
 local op=$1 q='' count
 case "$op" in
  add|edit)
   [[ ${interface:-} =~ ^wg[0-9]{1,10}$ ]] && q="iface='$interface'"
   if [ "$op" = edit ] && [[ ${id:-} =~ ^[1-9][0-9]{0,9}$ ]];then q="${q:+$q OR }peer_id=$id";fi;;
  iface_add|iface_edit)
   [[ ${local_listenport:-} =~ ^[0-9]{1,5}$ ]] && q="relay_port=$((10#$local_listenport))"
   if [ "$op" = iface_edit ] && [[ ${id:-} =~ ^[1-9][0-9]{0,9}$ ]];then q="${q:+$q OR }iface_id=$id";fi;;
 esac
 [ "$q" ] || return 0
 count=$(sqlite3 -cmd '.timeout 10000' "$IK_DB_CONFIG" "SELECT count(*) FROM wg_site_clients WHERE $q") || return 1
 [ "$count" = 0 ] || { echo '导入的组网隧道请通过启用、禁用或删除操作管理';return 1; }
}
__wg_site_client_prepare_enable(){
 local action=$1 rows=$2 uses
 uses=$(/usr/bin/lua /usr/ikuai/script/wg_site_client.lua enable_uses_core "$IK_DB_CONFIG" "$action" "$rows") ||
   { echo '无法核对已保存的组网隧道';return 1; }
 case "$uses" in
  retired_wrapped) echo 'Hysteria 2 承载 WG 已停用，请删除并重新导入原生 WG 或纯 HY2 配置';return 1;;
  retired) echo '纯 HY2 借线已停用，请重新选择设备连接方式';return 1;;
  no) return 0;;
  yes) /usr/ikuai/script/wg_hy_engine.sh installed >/dev/null 2>&1 || __wg_hyr_install;;
  *) return 1;;
 esac
}
__wg_site_client_sync(){
 local scope=$1 rc
 /usr/ikuai/script/wg_site_client.sh "$IK_DB_CONFIG" sync "$scope" >/dev/null && return 0
 rc=$?
 if [ "$rc" = 73 ];then echo '组网配置已保存，但本机 Hysteria 2 中继启动失败'
 else echo '组网隧道运行配置应用失败，请检查用途保护和中继状态';fi
 return 1
}
__wg_apply_imported_device(){
 local dev=$1 sync_rc=0
 [[ $dev =~ ^wg[0-9]{1,10}$ ]] || return 1
 if ! mkdir -p "$IK_DIR_TMP/wireguard/config" ||
    ! /usr/ikuai/script/wg_site_client.sh "$IK_DB_CONFIG" guard || ! __wg_apply_iface "$dev" ||
    ! /usr/ikuai/script/wg_site.sh sync;then
  __wg_apply_failed "$dev";return 1
 fi
 __wg_iface_cache_update || return 1
 __wg_site_client_sync "$dev" || sync_rc=1
 /usr/ikuai/script/wg_pure_routing.sh sync "$IK_DB_CONFIG" || return 1
 return "$sync_rc"
}
__wg_retire_missing_client_links(){
 local rows dev saved_local saved_peer current_local current_peers rc
 if __wg_site_client_table populated;then :;else rc=$?;[ "$rc" = 1 ];return;fi
 rows=$(/usr/bin/lua /usr/ikuai/script/wg_site_client.lua retired_links "$IK_DB_CONFIG") || return 1
 while read -r dev saved_local saved_peer;do
  [ "$dev" ] || continue
  # A DOWN WG link and its ingress helper still own IPv4 addresses. Remove
  # only the precise old singleton, never a live replacement at the same name.
  current_local=$(/usr/bin/wg show "$dev" public-key 2>/dev/null) || continue
  [ "$current_local" = "$saved_local" ] || continue
  current_peers=$(/usr/bin/wg show "$dev" peers) || return 1
  [ "$current_peers" = "$saved_peer" ] || continue
  __exec_rule_iface_del "$dev" || return 1
 done <<< "$rows"
}
site_client_import()(
 local stage dev
 [ -n "${config_hex:-}" ] && [ "${#config_hex}" -le 32768 ] && [[ $config_hex =~ ^[0-9a-f]+$ ]] && ((${#config_hex}%2==0)) || { echo '组网配置格式无效';return 1; }
 umask 077
 stage=$(mktemp -d /tmp/iktmp/wg-site-import.XXXXXX) || return 1
 trap 'rm -rf "$stage"' EXIT
 printf '%s' "$config_hex" >"$stage/bundle.hex" || return 1
 unset config_hex
 Lock wireguard_address excl 20 || { echo '另一项 WG 配置正在保存，请稍后重试';return 1; }
 trap 'unLock wireguard_address; rm -rf "$stage"' EXIT
 __wg_before_carrier_action import || return 1
 __wg_retire_missing_client_links || { echo '无法核对已保存的组网隧道';return 1; }
 /usr/bin/lua /usr/ikuai/script/wg_site_client.lua preflight "$IK_DB_CONFIG" "$stage" || return 1
 case "$(cat "$stage/transport")" in
  pure_hy2)
   if ! /usr/ikuai/script/wg_hy_engine.sh installed >/dev/null 2>&1;then __wg_hyr_install || return 1;fi
   /usr/ikuai/script/wg_hy_engine.sh check "$stage/checked.json" >/dev/null || { echo 'Hysteria 2 配置校验失败';return 1; };;
  native) ;;
  *) return 1;;
 esac
 dev=$(/usr/bin/lua /usr/ikuai/script/wg_site_client.lua commit "$IK_DB_CONFIG" "$stage") || { printf '%s\n' "$dev";return 1; }
 # The row is durable from here on. All activation errors must return the
 # same one-line result so the native UI can reload it and prevent a replay.
 if ! __wg_apply_imported_device "$dev" >/dev/null 2>&1;then
  echo '组网配置已保存，请返回列表检查隧道状态后重新启用';return 1
 fi
 printf '%s\n' "$dev"
)

__wg_retire_wrapped(){
 local state=/etc/mnt/ikuai/wg-hyr/state.json center=0 receiver columns condition=1 failed=0
 if [ -e "$state" ] || [ -L "$state" ];then
  if [ -f "$state" ] && [ ! -L "$state" ] && [ "$(stat -c '%u:%a' "$state")" = 0:600 ] &&
     center=$(jq -r '[.members[] | select(.transport!="pure_hy2")] | length' "$state") && [[ $center =~ ^[0-9]+$ ]];then
   if [ "$center" != 0 ];then
    /usr/bin/lua /usr/ikuai/script/wg_hyr_config.lua retire_wrapped "$IK_DB_CONFIG" "$state" - || failed=1
   fi
  else failed=1;fi
 fi
 # Independently retire receivers, including the original schema with no transport column.
 columns=$(sqlite3 -cmd '.timeout 10000' "$IK_DB_CONFIG" 'PRAGMA table_info(wg_site_clients);') || return 1
 if [ -n "$columns" ];then
  [[ $columns != *'|transport|'* ]] || condition="transport='hysteria2'"
  receiver=$(sqlite3 -cmd '.timeout 10000' "$IK_DB_CONFIG" "SELECT EXISTS(SELECT 1 FROM wg_site_clients WHERE $condition)") || return 1
  if [ "$receiver" = 1 ];then
   /usr/bin/lua /usr/ikuai/script/wg_site_client.lua retire_wrapped "$IK_DB_CONFIG" || failed=1
  fi
 fi
 return "$failed"
}

retire_transports_boot()(
 Lock wireguard_address excl 20 || return 1
 trap 'unLock wireguard_address' EXIT
 # A pending cross-store edit must first compare its pre-migration row hash.
 # Native init settles that edit before running this same retirement step.
 [ ! -d /etc/mnt/ikuai/wg-hyr/change ] || return 0
 __wg_retire_wrapped
)

__wg_locked_init()
{
 local rows config status=0
 # Imports/VRRP may replace the underlying database inside the current lock.
 if [ "${action:-}" != init ];then __wg_retire_wrapped || return 1;fi
 if __wg_site_client_table populated || [ -f /tmp/iktmp/wg-site-client/active ];then
  /usr/ikuai/script/wg_site_client.sh "$IK_DB_CONFIG" guard || return 1
 fi
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
	for column in site_local site_remote native_role;do sqlite3 $IK_DB_CONFIG "alter table wireguard_peers add column $column text default '';" >/dev/null 2>&1;done
	__wg_disable_peer_wan_policy
}

vrrp_init() { __wg_address_change vrrp_init; }

__wg_locked_vrrp_init()
{
	__exec_rule_clean
	sqlite3 $IK_DIR_LOG/vrrp/conf/config.db ".dump wireguard" |grep "^INSERT"| sqlite3 $IK_DB_CONFIG
	sqlite3 $IK_DIR_LOG/vrrp/conf/config.db ".dump wireguard_peers" |grep "^INSERT"| sqlite3 $IK_DB_CONFIG
	__wg_iface_cache_update
	__wg_locked_init
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
	/usr/bin/lua /usr/ikuai/script/wg_peer_options.lua validate "${exit_peer:-no}" "$client_endpoint" "$site_local" "$site_remote" "${native_role:-}" "$allowips" "$keepalive"
}

__check_param_iface_add()
{
	# Legacy imports may omit MTU (runtime default: 1420).
	if [ -n "${mtu:-}" ] && ! [[ $mtu =~ ^[1-9][0-9]{2,3}$ && $mtu -ge 576 && $mtu -le 9000 ]];then
		echo 'MTU 须为 576 至 9000 的整数';return 1
	fi
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
 /usr/bin/lua /usr/ikuai/script/wg_address_config.lua iface "$IK_DB_CONFIG" "$name" "$local_address" "$local_listenport" "$1" "${wg_import_auto_name:-}"
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

# Generated rules use simple arguments. Match the whole comment token, then
# delete by rule specification so a concurrent line-number change is harmless.
__wg_delete_policy_rules()
(
 set -o pipefail
 local chain="$1" first="$2" second="${3:-}"
 local -a rule
 iptables -w 3 -t mangle -S "$chain" 2>/dev/null | awk -v first="$first" -v second="$second" '
  {sub(/^\[fastid: [0-9]+\] /,"")}
  $1=="-A" {
   for(i=2;i<NF;i++) if($i=="--comment"){
    tag=$(i+1)
    if(tag~/^"/){if(tag!~/"$/)break;tag=substr(tag,2,length(tag)-2)}
    owned=(tag==first || (second!="" && tag==second))
    if(first=="wg-wan-policy:*")owned=(tag~/^wg-wan-policy:[0-9]+$/)
    if(owned){
     $1="-D";$(i+1)=tag;print
    }
    break
   }
  }' | while read -r -a rule;do
   iptables -w 3 -t mangle "${rule[@]}" >/dev/null 2>&1 || return 1
  done
)

__wg_policy_del()
{
 [ "$1" ] || return 1
 __wg_delete_policy_rules OUTPUT "$(__wg_policy_comment "$1")"
}

__wg_disable_peer_wan_policy()
{
 sqlite3 "$IK_DB_CONFIG" "update wireguard_peers set out_mode='auto',out_wans='',out_balance='failover' where ifnull(out_mode,'auto')!='auto' or ifnull(out_wans,'')!='' or ifnull(out_balance,'failover')!='failover';" >/dev/null 2>&1 || return 1
 __wg_delete_policy_rules OUTPUT 'wg-wan-policy:*'
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
 local iface_name="$1" comment iface_comment
 [ "$iface_name" ] || return 1
 comment=$(__wg_inbound_comment "$iface_name")
 iface_comment=$(__wg_iface_comment "$iface_name")
 __wg_delete_policy_rules PREROUTING "$comment" "$iface_comment" &&
  __wg_delete_policy_rules OUTPUT "$comment" "$iface_comment"
}

__wg_inbound_policy_apply()
{
	local iface_name="$1" listen_port="$2" bind_wan="$3"
	[ "$iface_name" -a "$listen_port" ] || return
	local comment=$(__wg_inbound_comment "$iface_name")
	local iface_comment=$(__wg_iface_comment "$iface_name")

	__wg_inbound_policy_del "$iface_name" || return 1

	local wan
	for wan in $(__wg_route_iface_list); do
		[ "$wan" = "auto" -o "$wan" = "all" -o "$wan" = "any" ] && continue
		local mark_id=$(__wg_policy_wan_mark "$wan")
		[ "$mark_id" ] || continue
		__wg_policy_ensure_rule "$mark_id" "$wan"
		iptables -w 3 -t mangle -A PREROUTING -i "$wan" -p udp --dport "$listen_port" \
			-m comment --comment "$comment" -j CONNMARK --set-mark "$mark_id" >/dev/null 2>&1 || return 1
	done

	iptables -w 3 -t mangle -A OUTPUT -p udp --sport "$listen_port" -m connmark ! --mark 0 \
		-m comment --comment "$comment" -j CONNMARK --restore-mark >/dev/null 2>&1 || return 1

		if [ "$bind_wan" -a "$bind_wan" != "auto" ]; then
			local mark_id=$(__wg_policy_wan_mark "$bind_wan")
			if [ "$mark_id" ]; then
				__wg_policy_ensure_rule "$mark_id" "$bind_wan"
				iptables -w 3 -t mangle -A PREROUTING -i "$iface_name" \
					-m connmark --mark 0 -m mark --mark 0 \
					-m comment --comment "$iface_comment" -j MARK --set-mark "$mark_id" >/dev/null 2>&1 || return 1
				iptables -w 3 -t mangle -A OUTPUT -p udp --sport "$listen_port" \
					-m comment --comment "$iface_comment" -j MARK --set-mark "$mark_id" >/dev/null 2>&1 || return 1
			fi
		fi
}

__wg_policy_add_mark_rule()
{
	local peer_id="$1" remote_addr="$2" remote_port="$3" mark_id="$4" extra="$5"
	local comment=$(__wg_policy_comment "$peer_id")

	[ "$remote_addr" -a "$remote_port" -a "$mark_id" ] || return
	iptables -w 3 -t mangle -A OUTPUT -p udp -d "$remote_addr" --dport "$remote_port" \
		$extra -m comment --comment "$comment" -j MARK --set-mark "$mark_id" >/dev/null 2>&1 || return 1
}

__wg_policy_apply()
{
	local peer_id="$id"
	local mode="${out_mode:-auto}"
	local wans="$out_wans"
	local balance="${out_balance:-failover}"

	__wg_policy_del "$peer_id" || return 1

	[ "$mode" = "auto" -o "$mode" = "" ] && return 0
	[ "$endpoint" -a "$endpoint_port" -a "$wans" ] || return 0

	local remote_addr="$1"
	[ "$remote_addr" ] || remote_addr=$(try_get_ip_of_address "$endpoint")
	[ "$remote_addr" ] || return 0

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
				__wg_policy_add_mark_rule "$peer_id" "$remote_addr" "$endpoint_port" "$mark_id" "-m statistic --mode random --probability $probability" || return 1
			else
				__wg_policy_add_mark_rule "$peer_id" "$remote_addr" "$endpoint_port" "$mark_id" || return 1
			fi
			i=$((i + 1))
		done
	else
		for wan in $selected_wans; do
			local mark_id=$(__wg_policy_wan_mark "$wan")
			[ "$mark_id" ] || continue
			__wg_policy_ensure_rule "$mark_id" "$wan"
			__wg_policy_add_mark_rule "$peer_id" "$remote_addr" "$endpoint_port" "$mark_id" || return 1
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
 if [[ ${native_role:-} = site_client && $endpoint != 127.0.0.1 ]];then
  local device_address
  device_address=$(sqlite3 "$IK_DB_CONFIG" "SELECT w.local_address FROM wireguard w JOIN wg_site_clients c ON w.id=c.iface_id WHERE c.peer_id=$wanted_id") || return 1
  [ "$device_address" ] && /usr/ikuai/script/wg_client_endpoint.sh check_outer "$resolved" "$interface" "$device_address" "$allowips" || return 1
 fi
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

# Apply the same native SQL operation on a private snapshot before committing
# a role-bearing peer. The projected and actual rows must have the same ID.
__wg_peer_write(){
 local operation=$1 database=$2
 if [ "$operation" = add ]; then
  sql_config_insert "$database" wireguard_peers $sql_param
 else
  sql_config_update "$database" wireguard_peers "id=$id" $sql_param
 fi
}
__wg_save_peer()(
 local operation=$1 stage projected actual target registry=/etc/mnt/ikuai/wg-hyr/state.json
 if [ -z "${wg_transport:-}" ] && [ -z "${hyr_mode:-}" ]; then __wg_peer_write "$operation" "$IK_DB_CONFIG";return;fi
 if [ "${hyr_mode:-}" = off ] && [ -z "${hyr_id:-}" ] && [ ! -d "${registry%/*}/change" ]; then
  if [ "$operation" = add ] || [ ! -f "$registry" ] ||
     jq -e --arg peer "$id" '.members[$peer] == null' "$registry" >/dev/null 2>&1; then
   __wg_peer_write "$operation" "$IK_DB_CONFIG";return
  fi
 fi
 stage=$(mktemp -d /tmp/iktmp/wg-mode.XXXXXX) || return 1
 trap 'rm -rf "$stage"' EXIT
 # Only these two tables are needed for peer and listener validation. Bound the
 # copy in tmpfs and preserve the native primary keys, constraints and defaults.
 (
  set -o pipefail
  ulimit -f 32768 || exit 1
  { sqlite3 -cmd '.timeout 10000' "$IK_DB_CONFIG" '.dump wireguard' &&
    sqlite3 -cmd '.timeout 10000' "$IK_DB_CONFIG" '.dump wireguard_peers'; } |
    sqlite3 -bail "$stage/config.db" >/dev/null || exit 1
  if __wg_site_client_table;then
   { echo 'CREATE TABLE wg_site_clients(relay_port INTEGER UNIQUE);'
     sqlite3 -cmd '.timeout 10000' "$IK_DB_CONFIG" "SELECT 'INSERT INTO wg_site_clients VALUES('||CAST(relay_port AS INTEGER)||');' FROM wg_site_clients"; } |
     sqlite3 -bail "$stage/config.db" >/dev/null || exit 1
  fi
  if [ "$(sqlite3 "$stage/config.db" "select count(*) from sqlite_master where name='sqlite_sequence'")" = 1 ];then
   { echo "delete from sqlite_sequence where name in ('wireguard','wireguard_peers');"
     sqlite3 "$IK_DB_CONFIG" "select 'insert into sqlite_sequence(name,seq) values('||quote(name)||','||quote(seq)||');' from sqlite_sequence where name in ('wireguard','wireguard_peers')"; } |
     sqlite3 -bail "$stage/config.db" >/dev/null || exit 1
  fi
 ) ||
  { echo '无法核对已保存的 WG 隧道';return 1; }
 projected=$(__wg_peer_write "$operation" "$stage/config.db") || { printf '%s\n' "$projected";return 1; }
 if [ "$operation" = add ]; then target=$projected; else target=$id; fi
 [[ $target =~ ^[1-9][0-9]{0,9}$ ]] || { echo '对端编号无效';return 1; }
 /usr/ikuai/script/wg_hy_ctl.sh hyr "$IK_DB_CONFIG" prepare "$stage/config.db" "$target" "$interface" "$hyr_mode" "${hyr_id:-}" "${hyr_public_ip:-}" "${hyr_udp_port:-}" "${hyr_port_mode:-}" "${hyr_addr_mode:-}" "${hyr_resume:-}" "${wg_transport:-}" || return 1
 actual=$(__wg_peer_write "$operation" "$IK_DB_CONFIG") || { printf '%s\n' "$actual";return 1; }
 if [ "$operation" = add ] && [ "$actual" != "$target" ]; then echo 'WG 隧道编号已变化，请刷新后重试';return 1; fi
 printf '%s\n' "$actual"
)

__wg_locked_add() {
	local native_role=${requested_role:-}
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

	local sql_param=" enabled:str comment:str interface:str peer_publickey:str peer_privatekey:str presharedkey:str allowips:str endpoint:str endpoint_port:str keepalive:int out_mode:str out_wans:str out_balance:str client_dns:str client_endpoint:str exit_peer:str site_local:str site_remote:str native_role:str"
	if SqlMsg=$(__wg_save_peer add);then
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
 if __wg_site_client_table;then
  # Delete only the exact dedicated interface created with these peers. A
  # stale numeric id in a restored config cannot delete a replacement device.
  __wg_write_config "BEGIN IMMEDIATE;
   DELETE FROM wireguard WHERE id IN (SELECT c.iface_id FROM wg_site_clients c
    JOIN wireguard w ON w.id=c.iface_id AND w.name=c.iface AND w.local_publickey=c.local_public
    JOIN wireguard_peers p ON p.id=c.peer_id AND p.interface=c.iface AND p.peer_publickey=c.peer_public
    WHERE c.peer_id IN ($requested_ids) AND (SELECT count(*) FROM wireguard_peers o WHERE o.interface=w.name)=1);
   DELETE FROM wg_site_clients WHERE peer_id IN ($requested_ids);
   DELETE FROM wireguard_peers WHERE id IN ($requested_ids); COMMIT;" || return 1
 else
  __wg_write_config "delete from wireguard_peers where id in ($requested_ids)" || return 1
 fi
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
	local native_role=${requested_role-${old_native_role:-}}
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


	local sql_param=" comment:str interface:str peer_publickey:str peer_privatekey:str presharedkey:str allowips:str endpoint:str endpoint_port:str keepalive:int out_mode:str out_wans:str out_balance:str client_dns:str client_endpoint:str exit_peer:str site_local:str site_remote:str native_role:str"

	if SqlMsg=$(__wg_save_peer edit);then
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
			if [ "${wg_transport:-}" = pure_hy2 ] || [ -n "${prior_transport:-}" ] || ! NewOldVarl enabled interface local_privatekey local_publickey local_address local_listenport peer_publickey presharedkey allowips endpoint endpoint_port keepalive out_mode out_wans out_balance exit_peer site_local site_remote ;then
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
 /usr/ikuai/script/native_ingress.sh down "$iface_name" >/dev/null 2>&1 || { __wg_apply_failed "$iface_name" '清理接入接口';return 1; }
 __wg_inbound_policy_del "$iface_name" || { __wg_apply_failed "$iface_name" '清理回包策略';return 1; }
 if ip link show dev "$iface_name" >/dev/null 2>&1;then
  ip link del dev "$iface_name" >/dev/null 2>&1 || { __wg_apply_failed "$iface_name" '删除内核接口';return 1; }
 fi
 rm -f "$IK_DIR_TMP/wireguard/$iface_name.conf"
}

__init_iface_config()
{
 local res fwmark failed
 res=$(sql_config_get_list "$IK_DB_CONFIG" "select * from wireguard where name='$iface' and enabled='yes'") && [ "$res" ] ||
  { __wg_apply_failed "$iface" '读取接口配置';return 1; }
 local $res
 interface_check_routing_exit "$interface" >/dev/null 2>&1 || { __wg_apply_failed "$iface" '校验绑定出口';return 1; }
 if [ "${interface:-auto}" != auto ];then
  fwmark=$(iproute_get_markid "$interface") && [ "$fwmark" ] && __wg_policy_ensure_rule "$fwmark" "$interface" ||
   { __wg_apply_failed "$iface" '准备绑定出口';return 1; }
 fi
 ip link add dev "$name" type wireguard >/dev/null 2>&1 || { __wg_apply_failed "$iface" '创建内核接口';return 1; }
 if ! ip address add dev "$name" "$local_address" >/dev/null 2>&1;then failed='设置接口地址'
 elif ! ip link set mtu "${mtu:-1420}" dev "$name" >/dev/null 2>&1;then failed='设置接口 MTU'
 elif ! /usr/ikuai/script/native_ingress.sh up "$name" >/dev/null 2>&1;then failed='配置接入接口'
 elif ! __wg_inbound_policy_apply "$name" "$local_listenport" "$interface" >/dev/null 2>&1;then failed='应用回包策略'
 else return 0;fi
 # The partial device has no valid ingress/address. A subsequent apply must
 # create it again instead of treating it as an initialized live interface.
 __exec_rule_iface_del "$name" >/dev/null 2>&1
 __wg_apply_failed "$iface" "$failed"
 return 1
}

__wg_build_iface_config()
{
 local iface="$1" stage="$2" rows config res fwmark
 res=$(sql_config_get_list "$IK_DB_CONFIG" "select * from wireguard where name='$iface' and enabled='yes'") || return 1
 [ "$res" ] || return 1
 local $res
 interface_check_routing_exit "$interface" || return 1
 if [ "${interface:-auto}" != auto ];then
  fwmark=$(iproute_get_markid "$interface") && [ -n "$fwmark" ] || return 1
 fi
 if [ -f /etc/mnt/ikuai/wg-hyr/state.json ]; then
  local_listenport=$(/usr/ikuai/script/wg_hyr_ports.sh resolve "$iface" "$local_listenport" "$local_publickey") || return 1
 fi
 if [ -f /tmp/iktmp/wg-site-client/active ];then
  local managed_native
  managed_native=$(sqlite3 "$IK_DB_CONFIG" "SELECT EXISTS(SELECT 1 FROM wireguard_peers WHERE interface='$iface' AND native_role='site_client' AND endpoint!='127.0.0.1')") || return 1
  [ "$managed_native" != 1 ] || fwmark=0x56000000
 fi
 {
  printf '[Interface]\nListenPort = %s\nPrivateKey = %s\nFwMark = %s\n' "$local_listenport" "$local_privatekey" "${fwmark:-0}"
 } > "$stage/iface.conf" || return 1
 : > "$stage/routes"
 rows=$(sql_config_get_list "$IK_DB_CONFIG" "select * from wireguard_peers where interface='$iface' and enabled='yes' order by id") || return 1
 local endpoints pure_binding= wg_bin=$(__wg_bin)
 if [ -f /etc/mnt/ikuai/wg-hyr/state.json ] || [ -d /etc/mnt/ikuai/wg-hyr/change ] || __wg_site_client_table populated;then
  pure_binding=$(/usr/ikuai/script/wg_pure_routing.sh projected "$IK_DB_CONFIG" "$iface") || return 1
 fi
 endpoints=$("$wg_bin" show "$iface" endpoints 2>/dev/null) || endpoints=""
 while read -r config;do
  [ "$config" ] || continue
  local $config
  # A pure HY2 row owns only a logical policy interface. Omit its native peer
  # from the kernel, including when converting a previously connected device.
  if [ -n "$pure_binding" ];then
   [[ $pure_binding = "$iface nph$id "* ]] || return 1
   continue
  fi
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
   if [[ ${native_role:-} = site_client && $endpoint != 127.0.0.1 ]];then
    /usr/ikuai/script/wg_client_endpoint.sh check_outer "$resolved" "$iface" "$local_address" "$allowips" || return 1
    # The assigned UDP endpoint is authoritative for an outbound router-peer.
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
(
 local iface="$1" stage wg_bin config rows allow old_routes name interface enabled count
 [[ "$iface" =~ ^wg[0-9]+$ ]] || return 1
 count=$(sqlite3 -cmd '.timeout 10000' "$IK_DB_CONFIG" "select count(*) from wireguard where name='$iface' and enabled='yes'") ||
  { __wg_apply_failed "$iface" '读取接口配置';return 1; }
 if [ "$count" != 1 ];then __exec_rule_iface_del "$iface";return $?;fi
 /usr/bin/lua /usr/ikuai/script/wg_peer_options.lua runtime "$IK_DB_CONFIG" "$iface" >/dev/null 2>&1 ||
  { __wg_apply_failed "$iface" '校验对端配置';return 1; }
 umask 077
 mkdir -p "$IK_DIR_TMP/wireguard/config" && stage=$(mktemp -d "$IK_DIR_TMP/wireguard/apply.XXXXXX") ||
  { __wg_apply_failed "$iface" '创建运行目录';return 1; }
 trap 'rm -rf "$stage"' EXIT
 chmod 700 "$stage" && __wg_build_iface_config "$iface" "$stage" >/dev/null 2>&1 ||
  { __wg_apply_failed "$iface" '生成 WireGuard 配置';return 1; }
 local mode=syncconf was_up=no flags
 if ! ip link show dev "$iface" >/dev/null 2>&1;then
  __init_iface_config || return 1
  mode=setconf
 fi
 flags=$(cat "/sys/class/net/$iface/flags") && [[ "$flags" =~ ^0x[0-9a-fA-F]+$ ]] ||
  { __wg_apply_failed "$iface" '读取接口状态';return 1; }
 [ "$((flags & 1))" = 0 ] || was_up=yes
 wg_bin=$(__wg_bin) && [ "$wg_bin" ] && "$wg_bin" "$mode" "$iface" "$stage/iface.conf" >/dev/null 2>&1 ||
  { __wg_apply_failed "$iface" '载入 WireGuard 配置';return 1; }
 # A unicast route requires an UP device. Empty interfaces remain down.
 rows=$(cat "$stage/rows") || { __wg_apply_failed "$iface" '读取对端配置';return 1; }
 if [ "$rows" -a "$was_up" = no ];then
  /usr/ikuai/script/native_ingress.sh up "$iface" >/dev/null 2>&1 || { __wg_apply_failed "$iface" '配置接入接口';return 1; }
  ip link set up dev "$iface" >/dev/null 2>&1 || { __wg_apply_failed "$iface" '启用内核接口';return 1; }
 fi
 old_routes=$(ip route show table main dev "$iface") || { __wg_apply_failed "$iface" '读取接口路由';return 1; }
 old_routes=$(printf '%s\n' "$old_routes" | awk '/metric 100( |$)/{print $1}')
 while read -r allow;do
  [ "$allow" ] || continue
  if ! grep -Fxq "$allow" "$stage/routes";then
   ip route del "$allow" dev "$iface" metric 100 >/dev/null 2>&1 || { __wg_apply_failed "$iface" '清理对端路由';return 1; }
  fi
 done <<< "$old_routes"
 while read -r allow;do
  [ "$allow" ] || continue
  printf '%s\n' "$old_routes" | grep -Fxq "$allow" && continue
  ip route replace "$allow" dev "$iface" metric 100 >/dev/null 2>&1 || { __wg_apply_failed "$iface" '应用对端路由';return 1; }
 done < "$stage/routes"
 if [ "$rows" ];then
  iproute_get_markid "$iface" >/dev/null 2>&1 && ip route replace default dev "$iface" table "$iface" metric 100 >/dev/null 2>&1 ||
   { __wg_apply_failed "$iface" '应用出口默认路由';return 1; }
 fi
 while read -r config;do
  [ "$config" ] || continue
  local $config
  __wg_policy_apply || { __wg_apply_failed "$iface" '应用对端出口策略';return 1; }
 done <<< "$rows"
 mv -f "$stage/iface.conf" "$IK_DIR_TMP/wireguard/$iface.conf" || { __wg_apply_failed "$iface" '保存运行快照';return 1; }
 for config in "$stage"/cache-*;do
  [ -f "$config" ] || continue
  mv -f "$config" "$IK_DIR_TMP/wireguard/config/${config##*/cache-}" || { __wg_apply_failed "$iface" '保存对端缓存';return 1; }
 done
 return 0
)

__wg_apply_failed()
{
 local iface="$1" step="${2:-应用运行配置}"
 ip link set down dev "$iface" >/dev/null 2>&1 || true
 rm -f "$IK_DIR_TMP/wireguard/$iface.conf"
 logger -t wireguard "$iface 运行配置应用失败（$step）"
 printf '%s 运行配置应用失败（%s）\n' "$iface" "$step"
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
	__exec_rule_iface_del "$iface" || return 1
	__wg_apply_iface "$iface" || return 1
	if [ -e "/sys/class/net/$iface" ]; then
		__wg_restore_learned_endpoints "$iface" "$learned_endpoints" >/dev/null 2>&1 || {
			__wg_apply_failed "$iface" '恢复对端端点'
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

# A copied public key must describe the private key that the kernel will use.
__wg_check_iface_keys() {
 local bin derived
 __check_key_valid "$local_privatekey" && __check_key_valid "$local_publickey" || return 1
 bin=$(__wg_bin) && [ "$bin" ] && derived=$(printf '%s\n' "$local_privatekey" | "$bin" pubkey 2>/dev/null) && [ "$derived" ] || {
  echo '无法验证接口密钥，请重新生成';return 1
 }
 [ "$derived" = "$local_publickey" ] || { echo '接口公钥与私钥不匹配，请重新生成';return 1; }
}
__wg_iface_name_free() {
 if ip link show dev "$1" >/dev/null 2>&1;then
  echo '接口名称已被系统使用，请换一个名称';return 1
 fi
}
__wg_locked_iface_add() {
 local id SqlMsg detail
 __wg_check_iface_address "" || return 1
 __wg_fill_local_keys
 __check_param_iface_add && __wg_check_route_iface "$interface" && __wg_check_iface_keys || return 1
 __wg_iface_name_free "$name" || return 1
 local sql_param="id:null enabled:str interface:str name:str mtu:str local_privatekey:str local_publickey:str local_address:str local_listenport:int "
 if ! SqlMsg=$(sql_config_insert "$IK_DB_CONFIG" wireguard $sql_param);then
  echo '无法写入新接口配置，请刷新接口列表';return 1
 fi
 id=$SqlMsg
 if ! [[ $id =~ ^[1-9][0-9]*$ ]];then
  echo '未取得新接口编号，请刷新列表确认保存结果';return 1
 fi
 if [ "$enabled" = yes ] && ! detail=$(__wg_apply_iface "$name");then
  # The writer lock covers both steps. Never remove peers or any other row.
  if __exec_rule_iface_del "$name" >/dev/null && __wg_write_config "delete from wireguard where id=$id and name='$name'" >/dev/null;then
   __wg_iface_cache_update
   echo "已撤销本次新增；${detail:-接口运行配置应用失败}";return 1
  fi
  __wg_iface_cache_update
  echo "新增未完成，清理失败，请刷新接口列表检查；${detail:-接口运行配置应用失败}";return 1
 fi
 __wg_iface_cache_update
 echo "$id"
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
 local res SqlMsg detail status=0
 [[ $id =~ ^[1-9][0-9]*$ ]] || { echo '接口编号无效，请刷新接口列表';return 1; }
 res=$(sql_config_get_list "$IK_DB_CONFIG" "select * from wireguard where id=$id" prefix=old_) || {
  echo '无法读取接口，请刷新接口列表';return 1
 }
 [ "$res" ] || { echo '接口不存在，请刷新接口列表';return 1; }
 local $res
 __wg_check_iface_address "$id" || return 1
 __wg_fill_local_keys
 __check_param_iface_add && __wg_check_route_iface "$interface" && __wg_check_iface_keys || return 1
 if [ "$old_name" != "$name" ];then __wg_iface_name_free "$name" || return 1;fi
 local sql_param="enabled:str name:str interface:str mtu:str local_privatekey:str local_publickey:str local_address:str local_listenport:int "
 if ! SqlMsg=$(sql_config_update "$IK_DB_CONFIG" wireguard "id=$id" $sql_param);then
  echo '无法保存接口配置，请刷新接口列表';return 1
 fi
 if [ "$old_name" != "$name" ];then detail=$(__exec_rule_iface_del "$old_name") || status=1;fi
 if [ "$status" = 0 ];then
  if [ "$enabled" != yes ];then
   # A disabled row does not own a newly chosen name in the kernel.
   if [ "$old_name" = "$name" ] && [ "$old_enabled" = yes ];then detail=$(__exec_rule_iface_del "$name") || status=1;fi
  elif ! NewOldVarl name enabled interface local_privatekey local_publickey local_address local_listenport ||
       ! ip link show dev "$name" >/dev/null 2>&1 || [ ! -s "$IK_DIR_TMP/wireguard/$name.conf" ];then
   detail=$(__exec_rule_restart_one "$name") || status=1
  elif ! NewOldVarl mtu;then
   if ! ip link set mtu "${mtu:-1420}" dev "$name" >/dev/null 2>&1 || ! /usr/ikuai/script/native_ingress.sh up "$name" >/dev/null;then
    detail=$(__wg_apply_failed "$name" '设置 MTU');status=1
   fi
  fi
 fi
 __wg_iface_cache_update
 [ "$status" = 0 ] || { echo "接口配置已保存；${detail:-接口运行配置应用失败}";return 1; }
 return 0
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
(
	mkdir -p /etc/mnt/ikuai 2>/dev/null
	local conf=$(__wg_center_conf) staged
	umask 077
	staged=$(mktemp "$conf.XXXXXX") || { echo "无法保存中心分流配置";return 1; }
	trap 'rm -f "$staged"' EXIT
	local enable="${enable:-0}"
	local route_non_china="${route_non_china:-1}"
	local nat_enable="${nat_enable:-0}"
	[ "$enable" = "1" ] || enable=0
	[ "$route_non_china" = "1" ] || route_non_china=0
	[ "$nat_enable" = "1" ] || nat_enable=0
	cat > "$staged" <<EOF
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
	if [ $? != 0 ] || ! mv -f "$staged" "$conf";then echo "无法保存中心分流配置";return 1;fi
	if ! /usr/ikuai/script/wg_center_route.sh apply >/tmp/iktmp/wg_center_web_apply.log 2>&1;then
		echo '中心分流配置已保存，但策略未完全应用，请检查出口和 IP 库';return 1
	fi
	return 0
)

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
    # Explicit admin requests only. Do not enumerate phone profiles through show/all.
    case "${TYPE:-}" in
        site_client_status)
            local response
            response=$(/usr/ikuai/script/wg_site_client.sh "$IK_DB_CONFIG" status) || { echo '无法读取组网中继状态';return 1; }
            printf '{"site_client_status":%s}\n' "$response";return 0;;
        native_router_profile)
            local response
            if ! response=$(__wg_hyr_locked native_profile "${peer_id:-}" "${expected_role:-}" "${hyr_origin_iface:-}" "${hyr_origin_key:-}" "${expected_server_key:-}"); then
                printf '%s\n' "${response:-WG 配置读取或密钥生成失败，请检查已保存配置后重试}"; return 1
            fi
            printf '{"native_router_profile":%s}\n' "$response"; return 0;;
        hyr_status|hyr_settings|hyr_profile|hyr_site_profile|hyr_uri)
            local response
            if ! response=$(__wg_hyr_locked "${TYPE#hyr_}" "${peer_id:-}" "${id:-}" "${expected_role:-}"); then
                printf '%s\n' "${response:-读取 Hysteria 2 信息失败}"; return 1
            fi
            printf '{"%s":%s}\n' "$TYPE" "$response"; return 0;;
    esac
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
	local owner=''
	if __wg_site_client_table populated;then owner=",CASE WHEN EXISTS(SELECT 1 FROM wg_site_clients c WHERE c.peer_id=wireguard_peers.id AND c.iface=wireguard_peers.interface AND c.peer_public=wireguard_peers.peer_publickey) THEN 1 ELSE 0 END AS site_client";fi
	local parent=",coalesce((select w.id from wireguard w where w.name=wireguard_peers.interface),0) as iface_id,coalesce((select w.local_publickey from wireguard w where w.name=wireguard_peers.interface),'') as server_key"
	local sql_show="select *$parent$owner,upload(interface,peer_publickey) as upload,download(interface,peer_publickey) as download from wireguard_peers $__where"

	local __sql_implant_code__=$(__implant_code)
	local data=$(sql_config_get_json $IK_DB_CONFIG "$sql_show")
	if [ "$owner" ];then
		data=$(printf '%s' "$data" | jq -c 'map(if (.site_client|tostring)=="1" then del(.peer_privatekey)|del(.presharedkey) else . end)') || return 1
	fi
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
	local owner=''
	if __wg_site_client_table populated;then owner=",CASE WHEN EXISTS(SELECT 1 FROM wg_site_clients c WHERE c.iface_id=wireguard.id AND c.iface=wireguard.name AND c.local_public=wireguard.local_publickey) THEN 1 ELSE 0 END AS site_client";fi
	local sql_show="select *$owner from wireguard $__where"

	local iface_data=$(sql_config_get_json $IK_DB_CONFIG "$sql_show")
	if [ "$owner" ];then
		iface_data=$(printf '%s' "$iface_data" | jq -c 'map(if (.site_client|tostring)=="1" then del(.local_privatekey)|del(.presharedkey) else . end)') || return 1
	fi
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
 local registry=/etc/mnt/ikuai/wg-hyr/state.json
 if [ -d "${registry%/*}/change" ] ||
    { [ -e "$registry" ] && ! jq -e --arg row "$wanted_id" '.members[$row]==null' "$registry" >/dev/null; };then
  echo '请使用此设备已保存的连接方式导出配置';return 1
 fi
 # The join and sibling count are one SQLite read snapshot, even for callers
 # outside the normal edit path. Do not return the parent interface private key.
 snapshot=$(sql_config_get_json "$IK_DB_CONFIG" "select p.id,p.interface,p.enabled,p.exit_peer,ifnull(p.native_role,'') as native_role,p.allowips,p.peer_privatekey,p.peer_publickey,ifnull(p.presharedkey,'') as presharedkey,ifnull(p.client_endpoint,'') as client_endpoint,ifnull(p.client_dns,'') as client_dns,p.keepalive,ifnull(p.site_local,'') as site_local,ifnull(p.site_remote,'') as site_remote,ifnull(p.comment,'') as comment,p.out_mode,p.out_wans,p.out_balance,p.endpoint,p.endpoint_port,w.id as iface_id,w.name as iface_name,w.enabled as iface_enabled,w.interface as iface_interface,w.local_address,w.local_listenport,w.local_publickey,w.local_privatekey,w.keepalive as iface_keepalive,w.mtu as iface_mtu,(select count(*) from wireguard_peers s where s.interface=p.interface) as iface_peer_count from wireguard_peers p join wireguard w on w.name=p.interface where p.id=$wanted_id") || { echo '读取已保存的 WG 配置失败，请刷新后重试';return 1; }
 if ! printf '%s' "$snapshot" | jq -e '
  type=="array" and length==1 and (.[0] |
   .enabled=="yes" and .iface_enabled=="yes" and
   ((.exit_peer=="yes" and .iface_peer_count==1 and (.native_role=="" or .native_role=="lend" or .native_role=="both")) or (.exit_peer=="no" and .native_role=="access")) and
   (.interface|type=="string") and .interface==.iface_name and
   .site_local=="" and .site_remote=="" and
   (.allowips|type=="string") and (.client_endpoint|type=="string"))' >/dev/null 2>&1;then
  echo '请先启用并保存具有有效设备用途的手机隧道';return 1
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
  peer:{id,interface,enabled,exit_peer,native_role,allowips,peer_privatekey,peer_publickey,presharedkey,client_endpoint,client_dns,keepalive,site_local,site_remote,comment,out_mode,out_wans,out_balance,endpoint,endpoint_port},
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

# The WG controller and enrollment share this lock, so a phone export can
# never mix keys or ports from two different saved peer/interface snapshots.
__wg_finish_pending_rows(){
 # A cold boot can commit the HY registry and its permissions before wgN
 # exists. Native init must then build the links before the final relay sync.
 /usr/ikuai/script/wg_hy_ctl.sh hyr "$IK_DB_CONFIG" sync >/dev/null
 [ ! -d /etc/mnt/ikuai/wg-hyr/change ] && return 0
 echo 'WG 隧道设置正在恢复，请刷新后重试';return 1
}
__wg_before_carrier_action(){
 local cmd=$1
 if [ -d /etc/mnt/ikuai/wg-hyr/change ];then
  case $cmd in status|settings|profile|site_profile|uri|native_profile) echo 'WG 隧道设置正在恢复，请刷新后重试';return 1;;
   *) __wg_finish_pending_rows || return 1;;
  esac
 fi
 return 0
}
__wg_hyr_install(){
 local messages line reason=
 messages=$(/usr/ikuai/script/wg_hy_engine.sh install 2>&1) && return 0
 # curl, filesystem and native shell diagnostics can contain untrusted text.
 # Return only known literal errors to the native web message formatter.
 while IFS= read -r line;do
  case "$line" in
   'Hysteria 2 安装包 SHA256 校验失败'|'Hysteria 2 缓存目标必须是普通文件'|'Hysteria 2 运行目录权限异常') reason="$line";break;;
   'Hysteria 2 安装空间不足，请在爱快挂载至少有 40 MiB 可用空间的 ext 数据盘'|'下载或写入 Hysteria 2 安装包失败，请检查磁盘、DNS、系统时间及 HTTPS 出站') reason="$line";;
  esac
 done <<< "$messages"
 printf '%s\n' "${reason:-Hysteria 2 安装失败，请检查可用数据磁盘、空间及官方资源连接}"
 return 1
}
__wg_hyr_locked(){
 local status
 Lock wireguard_address excl 20 || { echo '另一项 WG 配置正在保存，请稍后重试';return 1; }
 __wg_before_carrier_action "$1" &&
  /usr/ikuai/script/wg_hy_ctl.sh hyr "$IK_DB_CONFIG" "$@";status=$?
 unLock wireguard_address
 return "$status"
}
# A same-port request can be saved while the inner socket cannot be bound.
# Reapply the native interface (keys, cryptokey routes, link and policy) before
# a listener is allowed to use it. Never resurrect a disabled/replaced row.
__wg_hyr_needs_apply(){
 local state=/etc/mnt/ikuai/wg-hyr/state.json records row dev token active
 [ -f "$state" ] && [ ! -d "${state%/*}/change" ] || return 0
 records=$(jq -r 'select(.enabled==true) | .members | to_entries[] | select(.value.transport=="pure_hy2" and .value.paused!=true and .value.mode!="lend") | .key+"|"+.value.interface+"|"+.value.id' "$state") || return 1
 while IFS='|' read -r row dev token; do
  [ -n "$row" ] || continue
  [[ "$row" =~ ^[1-9][0-9]{0,9}$ && "$dev" =~ ^wg[0-9]{1,10}$ && -n "$token" ]] || return 1
  # __wg_apply_failed removes this cache. An external manual link-down
  # keeps it: revoke delivery, but do not undo the operator's action.
  [ ! -s "$IK_DIR_TMP/wireguard/$dev.conf" ] || continue
  active=$(sqlite3 -cmd '.timeout 10000' "$IK_DB_CONFIG" "select p.interface from wireguard_peers p join wireguard w on w.name=p.interface where p.id=$row and p.enabled='yes' and w.enabled='yes'") || return 1
  [ "$active" = "$dev" ] || continue
  /usr/ikuai/script/wg_hy_ctl.sh hyr "$IK_DB_CONFIG" check_mode "$row" "$token" >/dev/null || continue
  printf '%s\n' "$dev"
 done <<< "$records"
}
hyr_monitor(){
 local result=0 restore dev role_ctl=/usr/ikuai/script/wg_native_role.sh
 Lock wireguard_address excl 20 || return 1
 if [ -f /etc/mnt/ikuai/wg-hyr/state.json ] || [ -f /tmp/iktmp/wg-hy-engine/hyr/live.json ] ||
    [ -d /etc/mnt/ikuai/wg-hyr/change ] || [ -f /tmp/iktmp/wg-hyr/scope ];then
  if ! restore=$(__wg_hyr_needs_apply);then
   result=1
  elif [ "$restore" ];then
   restore=${restore//$'\n'/ }
   if /usr/ikuai/script/wg_hy_ctl.sh hyr "$IK_DB_CONFIG" hold "$restore";then
    __wg_apply_interfaces "$restore" || result=1
   else
    result=1
   fi
  fi
  /usr/ikuai/script/wg_hy_ctl.sh hyr "$IK_DB_CONFIG" monitor || result=1
 fi
 if [ -f /tmp/iktmp/wg-site-client/active ];then
  local client_rc=0
  if __wg_retire_missing_client_links;then
   restore=$(/usr/ikuai/script/wg_site_client.sh "$IK_DB_CONFIG" monitor) || client_rc=$?
  else client_rc=1;fi
  [ "$client_rc" = 0 ] || result=1
  # 73 means global protections succeeded and some individual HY workers
  # could not start. Only verified ready peers appear in this result.
  if [[ $client_rc = 0 || $client_rc = 73 ]];then
   while read -r dev;do
    [ "$dev" ] || continue
    [[ $dev =~ ^wg[0-9]{1,10}$ ]] || { result=1;continue; }
    # Only repair explicit failed applies. Manual link-down retains its cache.
    if [ ! -s "$IK_DIR_TMP/wireguard/$dev.conf" ];then
     __wg_apply_iface "$dev" && /usr/ikuai/script/wg_site.sh sync >/dev/null || result=1
    fi
   done <<< "$restore"
  fi
 fi
 if [ -f /tmp/iktmp/wg-native-role/active ]; then
  if restore=$("$role_ctl" "$IK_DB_CONFIG" refresh); then
   # Never re-enable a link while an interrupted WG edit is still pending.
   if [ ! -d /etc/mnt/ikuai/wg-hyr/change ]; then
    for dev in $restore; do
     [[ $dev =~ ^wg[0-9]{1,10}$ ]] && __wg_apply_iface "$dev" &&
       "$role_ctl" "$IK_DB_CONFIG" recovered "$dev" || result=1
    done
   fi
  else
   result=1
  fi
 fi
 /usr/ikuai/script/wg_pure_routing.sh sync "$IK_DB_CONFIG" || result=1
 unLock wireguard_address
 return "$result"
}

# Limit the temporary filter to WG interfaces whose peer IDs, keys or listener
# can actually change. A restore/import can replace the complete inventory.
__wg_hyr_scope(){
 local action=$1 saved
 case "$action" in
  add) printf '%s' "${interface:-}";;
  edit|del|up|down|iface_down|iface_del|iface_up|iface_edit)
   [[ ${id:-} =~ ^[0-9]+(,[0-9]+)*$ ]] || return 1
   case "$action" in
    iface_*) saved=$(sqlite3 "$IK_DB_CONFIG" "select name from wireguard where id in ($id)") || return 1
             [ "$action" != iface_edit ] || saved="$saved ${name:-}";;
    *) saved=$(sqlite3 "$IK_DB_CONFIG" "select distinct interface from wireguard_peers where id in ($id)") || return 1
       [ "$action" != edit ] || saved="$saved ${interface:-}";;
   esac
   printf '%s' "${saved//$'\n'/ }";;
  iface_add) printf '%s' "${name:-}";;
  *) printf '*';;
 esac
}
__wg_hyr_check_origin(){
 local prior
 [[ ${id:-} =~ ^[1-9][0-9]{0,9}$ && ${hyr_origin_iface:-} =~ ^wg[0-9]+$ && -n ${hyr_origin_key:-} ]] &&
  prior=$(sqlite3 -cmd '.timeout 10000' "$IK_DB_CONFIG" "select interface||' '||peer_publickey from wireguard_peers where id=$id") &&
  [ "$prior" = "$hyr_origin_iface $hyr_origin_key" ] && return 0
 echo '原 WG 对端已变化，请刷新后重试';return 1
}
# Compare the role under the writer lock. An old editor has no role snapshot;
# it can retain or narrow a managed native role, but must reread before widening.
__wg_native_origin_ok(){
 local saved role requested=${wg_role:-${hyr_mode:-}}
 [[ ${id:-} =~ ^[1-9][0-9]{0,9}$ ]] || return 1
 if [ "${native_origin_role+x}${native_origin_exit+x}" ]; then
  case "${native_origin_role-INVALID}" in ''|access|lend|both) ;; *) return 1;; esac
  case "${native_origin_exit:-}" in yes|no) ;; *) return 1;; esac
  saved=$(sqlite3 -cmd '.timeout 10000' "$IK_DB_CONFIG" "select ifnull(native_role,'')||'|'||ifnull(nullif(exit_peer,''),'no') from wireguard_peers where id=$id") &&
    [ "$saved" = "$native_origin_role|$native_origin_exit" ]
  return
 fi
 case "$requested" in access|lend|both|site) ;; *) return 0;; esac
 role=$(sqlite3 -cmd '.timeout 10000' "$IK_DB_CONFIG" "select ifnull(native_role,'') from wireguard_peers where id=$id") || return 1
 [ -z "$role" ] || [ "$role" = both ] || [ "$role" = "$requested" ]
}
__wg_native_edit_only_comment(){
 local field old res
 [[ ${id:-} =~ ^[1-9][0-9]{0,9}$ ]] && [ "${comment+x}" ] || return 1
 [ "${hyr_mode:-off}" = off ] && [ -z "${hyr_id:-}" ] || return 1
 # The older full-form API must also preserve a registered transport.
 if [ -f "$hyr_state" ]; then
  [ "$(jq -r --arg peer "$id" '.members[$peer] == null' "$hyr_state")" = true ] || return 1
 fi
 res=$(sql_config_get_list "$IK_DB_CONFIG" "select * from wireguard_peers where id=$id" prefix=old_) && [ "$res" ] || return 1
 local $res
 for field in interface allowips peer_publickey peer_privatekey presharedkey endpoint endpoint_port keepalive client_dns;do
  old=old_$field
  [ "${!field-}" = "${!old-}" ] || return 1
 done
 for field in client_endpoint exit_peer site_local site_remote;do
  old=old_$field
  [ "${!field-${!old-}}" = "${!old-}" ] || return 1
 done
 [ "${requested_role-${old_native_role:-}}" = "${old_native_role:-}" ] &&
   [ "${old_out_mode:-auto}" = auto ] && [ -z "${old_out_wans:-}" ] && [ "${old_out_balance:-failover}" = failover ]
}
__wg_address_change(){
 local action="$1" status requested_role;shift
 unset requested_role
 if [[ $action = add || $action = edit ]] && [ "${wg_transport+x}" ];then
  case "$wg_transport" in
   native)
    hyr_mode=off
    case "${wg_role:-off}" in
     off) ;; # Old editor: no explicitly selected native role.
     access) requested_role=access;exit_peer=no;;
     lend|both) requested_role=$wg_role;exit_peer=yes;;
     *) echo '隧道用途与传输方式不匹配';return 1;;
    esac;;
   pure_hy2)
    [ "${wg_role:-}" = access ] || { echo '纯 HY2 只支持让这台设备连接路由器上网';return 1; }
    hyr_mode=access
    [ "${hyr_port_mode:-wg}" = wg ] || { echo '纯 Hysteria 2 需要独立接口端口';return 1; }
    hyr_port_mode=wg;;
   hysteria2) echo 'Hysteria 2 承载 WG 已停用，请选择原生 WG 或纯 HY2';return 1;;
   *) echo '隧道传输方式无效';return 1;;
  esac
 fi
 if [[ $action = add || $action = edit ]] && [ "${hyr_mode+x}" ];then
  if [[ "$hyr_mode" != off && ${wg_transport:-} != pure_hy2 ]];then
   echo 'Hysteria 2 承载 WG 已停用，请选择原生 WG 或纯 HY2';return 1
  fi
  case "$hyr_mode" in
   off) ;;
   access) requested_role=;exit_peer=no;;
   *) echo 'Hysteria 2 隧道用途无效';return 1;;
  esac
  if [ "$hyr_mode" != off ]; then
   local registry=/etc/mnt/ikuai/wg-hyr/state.json saved_addr_mode= saved_ip=
   if [ -s "$registry" ] && [ -n "${hyr_id:-}" ]; then
    # Use only this device's saved override, never a recycled row or another WAN.
    local prior
    prior=$(jq -r --arg row "${id:-}" --arg token "$hyr_id" --arg dev "$interface" \
      '.members[$row] | select(.id==$token and .interface==$dev) | (.addr_mode // "shared")+"|"+(.public_ip // "")' "$registry") || return 1
    if [ "$prior" ]; then saved_addr_mode=${prior%%|*};saved_ip=${prior#*|}; fi
   fi
   hyr_addr_mode=${hyr_addr_mode:-${saved_addr_mode:-auto}}
   case "$hyr_addr_mode" in auto|manual|shared) ;; *) echo 'Hysteria 2 公网地址方式无效';return 1;; esac
   if [ -z "${hyr_public_ip:-}" ]; then
    if [ "$hyr_addr_mode" = shared ] && [ -s "$registry" ]; then
     hyr_public_ip=$(jq -r '.settings.public_ip // ""' "$registry") || return 1
    elif [ "$hyr_addr_mode" = "$saved_addr_mode" ]; then
     hyr_public_ip=$saved_ip
    fi
    # Native jq 1.4 can succeed with no bytes. Test the value before using it.
    if [ -z "${hyr_public_ip:-}" ]; then
     if [ "$hyr_addr_mode" = manual ] || ! hyr_public_ip=$(/usr/ikuai/script/wg_client_endpoint.sh get_public "$interface") || [ -z "$hyr_public_ip" ]; then
      echo '未能检测到此 WG 接口的公网 IPv4，请手动填写可从外网访问的地址';return 1
     fi
    fi
   fi
  fi
  if [ "$hyr_mode" != off ] && [ -z "${client_endpoint:-}" ]; then client_endpoint=$hyr_public_ip;fi
  if [ "$hyr_mode" != off ] && ! /usr/ikuai/script/wg_hy_engine.sh installed >/dev/null 2>&1; then
   __wg_hyr_install || return 1
  fi
 fi
 Lock wireguard_address excl 20 || { echo '另一项 WG 配置正在保存，请稍后重试';return 1; }
 local output scope client_active=no iface_local_error= iface_saved=no
 case "$action" in up|down|del|iface_up|iface_down|iface_del|iface_edit)
  if [ "${expected_rows+x}" ];then
   if ! printf '%s' "$expected_rows" | /usr/bin/lua /usr/ikuai/script/wg_peer_options.lua targets "$IK_DB_CONFIG" "$action" "${id:-}" >/dev/null;then
    unLock wireguard_address;echo '设备已被删除或更改，请返回列表并重新打开。';return 1
   fi
  fi;;
 esac
 if __wg_site_client_table populated || [ -f /tmp/iktmp/wg-site-client/active ];then
  client_active=yes
  __wg_site_client_conflict "$action" || { unLock wireguard_address;return 1; }
  if [[ $action = up || $action = iface_up ]];then
   __wg_site_client_prepare_enable "$action" "${id:-}" || { unLock wireguard_address;return 1; }
  fi
 fi
 local hyr_state=/etc/mnt/ikuai/wg-hyr/state.json hyr_live=/tmp/iktmp/wg-hy-engine/hyr/live.json hyr_sync=no
 local role_ctl=/usr/ikuai/script/wg_native_role.sh native_scope proposed=
 if [ "$action" = init ]; then
  "$role_ctl" "$IK_DB_CONFIG" schema || { unLock wireguard_address;echo '无法更新原生 WG 设备用途字段';return 1; }
 fi
 if [ -d "${hyr_state%/*}/change" ];then
  __wg_finish_pending_rows || { unLock wireguard_address;return 1; }
 fi
 if [ "$action" = init ];then
  __wg_retire_wrapped || { unLock wireguard_address;echo '旧 Hysteria 2 隧道停用失败';return 1; }
 fi
 if [[ $action = up || $action = iface_up ]] && [ -f "$hyr_state" ];then
  /usr/bin/lua /usr/ikuai/script/wg_hyr_config.lua check_enable "$IK_DB_CONFIG" "$hyr_state" - "$action" "$id" ||
   { unLock wireguard_address;return 1; }
 fi
 if [ -e /etc/mnt/ikuai/wg-tcp/state.json ] || [ -L /etc/mnt/ikuai/wg-tcp/state.json ];then
  "$role_ctl" "$IK_DB_CONFIG" migrate || { unLock wireguard_address;echo '无法迁移旧设备用途，WG 配置未应用';return 1; }
 fi
 local prior_transport=
 if [ "$action" = edit ]; then
  if [ -s "$hyr_state" ] && [[ ${id:-} =~ ^[1-9][0-9]*$ ]];then
   prior_transport=$(jq -r --arg row "$id" '.members[$row] | select(.!=null) | (.transport // "hysteria2")' "$hyr_state") || { unLock wireguard_address;return 1; }
  fi
  if [ -n "$prior_transport" ] && [[ -z ${wg_transport:-} || -z ${hyr_id:-} ]] &&
     ! [[ $prior_transport = pure_hy2 && ${comment_only:-} = yes && -n ${hyr_id:-} ]];then
   unLock wireguard_address;echo '请刷新后明确选择连接方式';return 1
  fi
  if [ "${hyr_mode+x}${hyr_id+x}${native_origin_role+x}${native_origin_exit+x}" ] || [ "${comment_only:-}" = yes ]; then
   __wg_hyr_check_origin || { unLock wireguard_address;return 1; }
   __wg_native_origin_ok || { unLock wireguard_address;echo '设备用途已改变，请刷新后再保存';return 1; }
  fi
  if [ "${hyr_id+x}" ] && { [ -n "${hyr_id:-}" ] || [ -e "$hyr_state" ] || [ -L "$hyr_state" ]; }; then
   /usr/ikuai/script/wg_hy_ctl.sh hyr "$IK_DB_CONFIG" check_mode "$id" "$hyr_id" || { unLock wireguard_address;return 1; }
  fi
  # Explicit sparse edits never apply fields from an old form. For native
  # full-form saves, compare all affected columns before skipping the fence.
  if [ "${comment_only:-}" = yes ] || __wg_native_edit_only_comment; then
   if [ "${comment_only:-}" = yes ] && { [ -z "${hyr_id+x}" ] || [ -z "${native_origin_role+x}" ] || [ -z "${native_origin_exit+x}" ] || [ -z "${comment+x}" ]; }; then
    unLock wireguard_address;echo '请刷新隧道后再保存备注';return 1
   fi
   sql_config_update "$IK_DB_CONFIG" wireguard_peers "id=$id" comment:str;status=$?
   unLock wireguard_address;return "$status"
  fi
 fi
 if [ -f "$hyr_state" ] || [ -f "$hyr_live" ];then
  if [[ "$action" = iface_add || "$action" = iface_edit ]] && [[ "${local_listenport:-}" =~ ^[0-9]{1,5}$ ]] &&
     { [ "$((10#$local_listenport))" = "$(jq -e -r 'select([.members[] | select(.transport=="pure_hy2" and (.port_mode // "shared")=="shared")] | length>0) | .settings.udp_port' "$hyr_state" 2>/dev/null)" ] ||
       jq -e --arg port "$((10#$local_listenport))" '.members[] | select(.transport=="pure_hy2" and (.inner_port|tostring)==$port)' "$hyr_state" >/dev/null 2>&1; };then
   unLock wireguard_address
   echo 'WG 监听端口与Hysteria 2 入口冲突';return 1
  fi
  local own_id=
  [ "$action" != edit ] || own_id=${id:-}
  scope=$(__wg_hyr_scope "$action") || { unLock wireguard_address;echo '无法核对已保存的 WG 隧道';return 1; }
  if [[ "$action" = add || "$action" = edit ]] && [ -f "$hyr_state" ] &&
     jq -e --arg dev "${interface:-}" --arg own "$own_id" \
       '.members | to_entries[] | select(.value.interface==$dev and .key!=$own)' "$hyr_state" >/dev/null 2>&1; then
   unLock wireguard_address;echo '请为此对端分配独立 WG 接口和监听端口';return 1
  fi
  if [ -f "$hyr_state" ] || [ -f "$hyr_live" ];then
   /usr/ikuai/script/wg_hy_ctl.sh hyr "$IK_DB_CONFIG" hold "$scope" || { unLock wireguard_address;return 1; }
   hyr_sync=yes
  fi
 fi
 if [[ "$action" = add || "$action" = edit ]] && [ -n "${hyr_mode:-}" ] && [ "$hyr_mode" != off ];then hyr_sync=yes;fi
 case "$action" in
  IMPORT|IMPORT_EXTEND|vrrp_init) native_scope=restore;;
  *) native_scope=$(__wg_hyr_scope "$action") || { unLock wireguard_address;return 1; };;
 esac
 [ -z "${requested_role:-}" ] || proposed=${interface:-}
 if [ "$client_active" = yes ] && [[ $action = up || $action = iface_up ]];then
  /usr/ikuai/script/wg_site_client.sh "$IK_DB_CONFIG" guard || { unLock wireguard_address;return 1; }
 fi
 "$role_ctl" "$IK_DB_CONFIG" before "$native_scope" "$proposed" || { unLock wireguard_address;echo '原生 WG 用途保护未就绪，配置未应用';return 1; }
 output=$("__wg_locked_$action" "$@");status=$?
 if [ "$action" = iface_add ];then
  if [ "$status" = 0 ];then iface_saved=yes;else iface_local_error=${output:-新增接口未完成，请刷新接口列表检查};fi
 fi
 if [ "$status" = 0 ];then /usr/ikuai/script/wg_site.sh sync >/dev/null || { status=1;output="配置已保存，但互访策略应用失败，相关接口已阻断；请刷新后检查"; };fi
 if [ "$hyr_sync" = yes ] || [ -d "${hyr_state%/*}/change" ];then
  if ! /usr/ikuai/script/wg_hy_ctl.sh hyr "$IK_DB_CONFIG" sync "${scope:-*}" >/dev/null && [ "$status" = 0 ];then
   status=1;output='原生 WG 配置已处理，但Hysteria 2 同步失败，请检查接口和端口'
  fi
 fi
 if [ "$client_active" = yes ];then
  local client_scope="$native_scope" client_error
  [ "$client_scope" != restore ] || client_scope='*'
  if ! client_error=$(__wg_site_client_sync "$client_scope");then
   if [ "$status" != 0 ] && [ "$output" ];then output="$output；$client_error";else output="$client_error";fi
   status=1
  fi
 fi
 if ! /usr/ikuai/script/wg_pure_routing.sh sync "$IK_DB_CONFIG"; then status=1;output='设备已保存，纯 HY2 出口路由应用失败';fi
 if ! "$role_ctl" "$IK_DB_CONFIG" after; then status=1;output='原生 WG 设备用途未能应用，相关接口已阻断';fi
 if [ "$iface_local_error" ];then
  output="$iface_local_error"
 elif [ "$iface_saved" = yes ] && [ "$status" != 0 ];then
  output="新接口已保存，联动策略未完全应用，请刷新后检查现有接口"
 fi
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
