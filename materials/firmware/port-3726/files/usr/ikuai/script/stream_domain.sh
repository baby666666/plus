#!/bin/bash /etc/ikcommon
Include ipset.sh interface.sh iproute.sh lock.sh iptables.sh ipmacgroup.sh
boot()
{
	init
}

updatedb()
{
	local STREAM_DOMAIN_TMP=/tmp/stream_domain.tmp
	rm -f ${STREAM_DOMAIN_TMP}
	if [ "$old_sysver" -lt 300010004 ];then
		sql_config_get_list $IK_DB_CONFIG "select enabled,GROUP_CONCAT(domain) as domain,interface from stream_domain GROUP BY interface,enabled" > $STREAM_DOMAIN_TMP 
		sql_config_exec $IK_DB_CONFIG "delete from stream_domain"

		while read config; do
			local $config
			local sql_param="id:null enabled:str comment:str interface:str domain:str src_addr:str"
			sql_config_insert $IK_DB_CONFIG stream_domain $sql_param
		done < ${STREAM_DOMAIN_TMP}

		rm -f ${STREAM_DOMAIN_TMP}
	fi
}
# The native importer converts CSV to its key=value TXT format before calling
# validation once. Shell defaults do not apply to individual imported rows.
nr_import_exit_policy(){
 local file="$1" temporary="$1.nr-policy.$$"
 if ! awk '
  { sub(/\r$/, ""); if ($0 ~ /^[ \t]*$/) {print; next}
    seen=0; line=""
    for (i=1;i<=NF;i++) {
     field=$i
     if (field ~ /^iface_band=/) {
      if (++seen>1) exit 1
      value=substr(field,12)
      if (value=="") field="iface_band=1"
      else if (value!="0" && value!="1") exit 1
     }
     if (i>1) line=line " "
     line=line field
    }
    if (!seen) line=line " iface_band=1"
    print line
  }' "$file" > "$temporary";then
  rm -f "$temporary";echo '导入文件中的线路绑定选项无效';return 1
 fi
 mv "$temporary" "$file"
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
 [ -z "${_______CHECK_VARL_IMPORT_FILE_______:-}" ] || nr_import_exit_policy "$_______CHECK_VARL_IMPORT_FILE_______" || return 1
 # Older API clients omit this field. An edit must retain the stored choice;
 # old exported rules retain their previous fixed-exit behavior on import.
 if [ -z "${iface_band:-}" ];then
  case "${nr_action:-}" in
   edit)
    [[ "$id" =~ ^[0-9]+$ ]] || return 1
    iface_band=$(sqlite3 "$IK_DB_CONFIG" "SELECT iface_band FROM stream_domain WHERE id=$id;")
    iface_band=${iface_band:-1};;
   IMPORT) iface_band=1;;
   *) iface_band=0;;
  esac
 fi
 case "$iface_band" in 0|1) ;; *) echo '线路绑定选项无效';return 1;;esac
 nr_group=${nr_group:-manual};nr_dns=${nr_dns:-1.1.1.1};nr_ingress=${nr_ingress:-};nr_route=${nr_route:-fixed};nr_app=;nr_app_first=0;nr_target=${nr_target:-any}
 case "$nr_group" in manual|cn|foreign|fallback) ;; *) echo '域名分流仅支持中国大陆、中国大陆以外和未匹配流量；旧自定义域名仍保留';return 1;;esac

 case "$nr_target" in any|cn) ;; *) echo '目标 IP 限制无效';return 1;;esac
 [ "$nr_target" = any ] || [ "$nr_group" = fallback ] || { echo '目标 IP 限制仅适用于未匹配流量';return 1; }

	check_varl \
		'interface not match "^pppwg%d+$" and not match "^pppwg%d+," and not match ",pppwg%d+$" and not match ",pppwg%d+,"'\
		'enabled == "yes" or == "no"'\
		'iface_band == "" or == 0 or == 1'\
		'interface != ""'\
		'domain != "" '	\
		'week		week' \
		'time		timeranges' || return 1
 nr_check_exit_interfaces 0 0
}

__format_ipset() {
	if [ "$1" = "src" ] ;then
		[ -n "$src_addr" ]&&{
			#循环判断地址类型（普通IP/群组名称）
			ipset_rule_add sdomain_src_$id $src_addr
			echo "sdomain_src_$id"
		}
	elif [ "$1" = "dst" ] ;then
		[ -n "$dst_addr" ]&&{
			ipset_rule_add sdomain_dst_$id $dst_addr
			echo "sdomain_dst_$id"
		}
	fi
}

nr_original_init() {
	ik_cntl url_route group clear >/dev/null 2>/dev/null
	ik_cntl url_route enable >/dev/null 2>/dev/null
	sql_config_get_list $IK_DB_CONFIG "select * from stream_domain where enabled='yes'" |\
	while read config ;do
		local $config
		__exec_rule_add >/dev/null 2>/dev/null
	done
	rule_switch
}

nr_original_vrrp_init() {
	__clean
	sqlite3 $IK_DB_CONFIG "delete from stream_domain"	
	sqlite3 $IK_DIR_LOG/vrrp/conf/config.db ".dump stream_domain" |grep "^INSERT"| sqlite3 $IK_DB_CONFIG
	init
}

__exec_rule_add() {
    local mark_id mark_ids
	for iface in ${interface//,/ }; do
		mark_id=$(iproute_get_markid $iface):${iface}
		mark_ids="${mark_ids:+$mark_ids,}${mark_id}"
	done
	src_name=$(__format_ipset src)
	times="$(echo ${time:-00:00-23:59}|awk -F "[:-]"  '{if(NR>1)printf ",";printf "%s %s",$1*3600+$2*60,$3*3600+$4*60+60}')"
	weeks="$(echo ${week:-1234567}|awk -F "" '{week=$1","$2","$3","$4","$5","$6","$7;gsub(/,*$/,"",week);print week}')"
	ik_cntl url_route group add $id ${src_name:-null} $times $weeks ${mark_ids//,/ }
	
	for url in ${domain//,/ }; do
		ik_cntl url_route add $url group $id
	done
}

__exec_rule_del() {
	ik_cntl url_route group del $id
}
nr_original_add() {
	__check_param || exit 1
	local sql_param="id:null enabled:str comment:str interface:str domain:str src_addr:str week:str time:str nr_group:str nr_dns:str nr_ingress:str nr_route:str nr_app:str nr_app_first:int nr_target:str iface_band:int"
	if SqlMsg=$(sql_config_insert $IK_DB_CONFIG stream_domain $sql_param);then
		local id=$SqlMsg
		[ "$enabled" = "yes" ]&&{
			__exec_rule_add >/dev/null 2>/dev/null
			rule_switch
		}
		echo "$SqlMsg"
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi
}
nr_original_del() {
	sql_config_get_list $IK_DB_CONFIG "select * from stream_domain where id in ($id) ;delete from stream_domain where id in ($id);" |
	while read config; do
		local $config
		[ "$enabled" = "yes" ]&&{
			__exec_rule_del >/dev/null 2>/dev/null
		}
		ipset_rule_del sdomain_src_$id
	done
	rule_switch	
}
nr_original_up() {
	sql_config_get_list $IK_DB_CONFIG "select * from stream_domain where id in ($id) and enabled='no';update stream_domain set enabled='yes' where id in ($id);"|while read config ;do
		local $config
		[ "$enabled" = "no" ]&&{
			__exec_rule_add >/dev/null 2>/dev/null
		}
	done
	rule_switch
}
nr_original_down() {
	sql_config_get_list $IK_DB_CONFIG "select * from stream_domain where id in ($id) and enabled='yes';update stream_domain set enabled='no' where id in ($id);"|while read config ;do
		local $config

		__exec_rule_del >/dev/null 2>/dev/null
	done
	rule_switch	
}
nr_original_edit() {
	__check_param || exit 1
	local sql_param="enabled:str comment:str interface:str domain:str src_addr:str week:str time:str nr_group:str nr_dns:str nr_ingress:str nr_route:str nr_app:str nr_app_first:int nr_target:str iface_band:int"
	res=$(sql_config_get_list $IK_DB_CONFIG "select * from stream_domain where id=$id" prefix=old_)
	if [ "$res" = "" ];then
		return 0
	fi
	local $res
	if SqlMsg=$(sql_config_update $IK_DB_CONFIG stream_domain "id=$id" $sql_param);then
		if ! NewOldVarl interface domain src_addr week time nr_group nr_dns nr_ingress nr_route nr_target iface_band;then
			[ "$enabled" = "yes" ]&&{
				__exec_rule_del >/dev/null 2>/dev/null
				__exec_rule_add >/dev/null 2>/dev/null
				rule_switch
			}
		fi
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi
}

create_config_to_cache()
{
	local filename="$IK_DIR_TMP/.stream_domain.$$"
	> $filename
	sql_config_get_list $IK_DB_CONFIG "select * from stream_domain where enabled='yes'" |\
	while read config ;do
		[ "$config" ] || continue
		local $config
		local iface_marks=""
		for iface_one in ${interface//,/ }; do
			local markid=$(iproute_get_markid $iface_one)
			iface_marks+="${iface_marks:+,}$markid"
		done
		echo "$interface $iface_marks $domain" >> $filename
	done
	mv $filename $IK_DIR_TMP/.stream_domain
}

rule_switch()
{
	local ik_summary=$(cat /proc/ikuai/stats/ik_summary)
	if echo "$ik_summary" | grep -q "TYPE: .*URL_ROUTE" ;then
		echo "$ik_summary" |grep -q "URL Route: enable" || ik_cntl url_route enable >/dev/null 2>/dev/null 
	else
		ik_cntl url_route disable >/dev/null 2>/dev/null
	fi
	create_config_to_cache
}
__clean() {
	sql_config_get_list $IK_DB_CONFIG "select * from stream_domain;" |\
	while read config; do
		local $config
		[ "$enabled" = "yes" ]&&{
			__exec_rule_del >/dev/null 2>/dev/null
			#ik_cntl url_route del $domain >/dev/null 2>/dev/null
		}
		ipset_rule_del sdomain_src_$id
	done
	rule_switch	
}

EXPORT() {
	Include import_export.sh
	local format=${format:-txt}
	if errmsg=$(export_txt $IK_DB_CONFIG stream_domain $format $IK_DIR_EXPORT/stream_domain.$format) ;then
		echo "stream_domain.$format"
		return 0
	else
		echo "$errmsg"
		return 1
	fi
}
nr_original_IMPORT() {
	Include import_export.sh
	if errmsg=$(import_txt $IK_DB_CONFIG stream_domain $IK_DIR_IMPORT/$filename "$append"  __check_param __clean) ;then
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
	local total=$(sqlite3 $IK_DB_CONFIG "select count() from stream_domain $__filter")
	json_append __json_result__ total:int
}
__show_data()
{
	local sql_show="select * from stream_domain $__where"
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
	local interface=$(interface_get_ifname_comment_json wan,vpn,sdwan,accel,sdsaas -sdwan)
	interface=$(interface_append_wireguard_comment_json "$interface")
	json_append __json_result__ interface:json
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

__exec_rule_add(){ :; }
__exec_rule_del(){ :; }
rule_switch(){ :; }

# Single native table is the source of truth; serialize edits and roll back failed applies.
/usr/ikuai/script/native_rules.sh ensure_conf >/dev/null 2>&1 || exit 1
nr_native_change(){
 local action="$1" nr_action="$1" n result status before after
 mkdir -p /tmp/iktmp/native-rules
 for n in $(seq 1 600);do mkdir /tmp/iktmp/native-rules/edit-lock 2>/dev/null && break;sleep .1;done
 [ "$n" != 600 ] || { echo 'Another native rule edit is running';return 1; }
 trap 'rmdir /tmp/iktmp/native-rules/edit-lock 2>/dev/null' EXIT
 before=$(sqlite3 "$IK_DB_CONFIG" "select id,enabled,interface,domain,src_addr,week,time,nr_group,nr_dns,nr_ingress,nr_route,nr_app,nr_app_first,nr_target,iface_band from stream_domain order by id;"|sha256sum)
 sqlite3 "$IK_DB_CONFIG" '.dump stream_domain' > /tmp/iktmp/native-rules/edit-backup.sql
 result=$(nr_original_$action);status=$?
 after=$(sqlite3 "$IK_DB_CONFIG" "select id,enabled,interface,domain,src_addr,week,time,nr_group,nr_dns,nr_ingress,nr_route,nr_app,nr_app_first,nr_target,iface_band from stream_domain order by id;"|sha256sum)
 if [ "$status" != 0 ] && [ "$before" = "$after" ];then
  rmdir /tmp/iktmp/native-rules/edit-lock;trap - EXIT
  printf '%s\n' "$result" > /tmp/iktmp/native-rules/edit-error.log
  echo '分流规则校验失败，请检查出口和规则参数';return "$status"
 fi
 if [ "$status" = 0 ] && [ "$before" = "$after" ] && [ -s /tmp/iktmp/native-rules/dns-signature ] && [ ! -f /tmp/iktmp/native-rules/boot.pending ] && [ ! -f /tmp/iktmp/native-rules/native-dirty ] && [ ! -f /tmp/iktmp/native-rules/native-stage.pending ] && [ ! -f /tmp/iktmp/native-rules/commit.pending ];then
  rmdir /tmp/iktmp/native-rules/edit-lock;trap - EXIT;printf '%s\n' "$result";return 0
 fi
 if [ "$status" = 0 ] && /usr/ikuai/script/native_rules.sh apply >/tmp/iktmp/native-rules/edit-result.log 2>&1;then
  rmdir /tmp/iktmp/native-rules/edit-lock;trap - EXIT;printf '%s
' "$result";return 0
 fi
 { echo 'drop table stream_domain;';cat /tmp/iktmp/native-rules/edit-backup.sql; }|sqlite3 "$IK_DB_CONFIG"
 :
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

init(){  /usr/ikuai/script/native_rules.sh apply; }

__show_native_settings(){
 local config=$(/usr/bin/ikluajit /usr/ikuai/script/domain_allowlist.lua show) || return 1
 local revision=$(sha256sum /etc/mnt/ikuai/native-routing.json|cut -d' ' -f1)
 # Apply logs can contain quotes and newlines; the native :str helper does not
 # escape them. Encode once so a successful edit cannot corrupt the next show.
 local result=$(tail -5 /tmp/iktmp/native-rules/apply.log 2>/dev/null | jq -Rs .)
 local foreign_policy=$(cat /tmp/iktmp/native-rules/active/foreign-policy.json 2>/dev/null);foreign_policy=${foreign_policy:-'{"policy":"allowlist"}'}
 json_append __json_result__ config:json revision:str result:json foreign_policy:json
}
__show_runtime_status(){
 local runtime_status=$(/usr/ikuai/script/native_status.sh) || return 1
 json_append __json_result__ runtime_status:json
}
native_settings_save(){ /usr/ikuai/script/native_rules.sh settings_save "payload=$payload" "revision=$revision"; }
__show_domain_library(){ local domain_library=$(/usr/ikuai/script/domain_update.sh status);json_append __json_result__ domain_library:json; }
domain_update(){ /usr/ikuai/script/domain_update.sh request operation=update; }
domain_source_save(){ /usr/ikuai/script/domain_update.sh source_save "payload=$payload"; }
domain_rollback(){ /usr/ikuai/script/domain_update.sh request operation=rollback; }

# Reject stale browsers/API clients explicitly; no app catalogue is loaded.
__show_app_library(){ local app_library='{"apps":[],"removed":true,"revision":"disabled","job":{"state":"idle"}}';json_append __json_result__ app_library:json; }
__show_app_job(){ local app_job='{"state":"idle","removed":true}';json_append __json_result__ app_job:json; }
app_library_save(){ echo '应用规则库已移除，请使用原生协议分流';return 1; }
app_library_update(){ app_library_save; }
app_library_detail(){ app_library_save; }
__show_app_detail(){ app_library_save; }

__show_dns_limits(){ local dns_limits;dns_limits=$(/usr/ikuai/script/dns_limits.sh status) || return 1;json_append __json_result__ dns_limits:json; }
dns_limits_save(){ /usr/ikuai/script/dns_limits.sh save "payload=$payload" "revision=$revision"; }

__show_encrypted_dns_stats(){
 local encrypted_dns_stats counters
 if counters=$(iptables -w -n -v -x -L NR_EDNS_DROP 2>/dev/null);then
  encrypted_dns_stats=$(printf '%s\n' "$counters" | awk '
   /nr-edns-dot/ {dot+=$1;bytes+=$2}
   /nr-edns-doq/ {doq+=$1;bytes+=$2}
   /nr-edns-doh/ {doh+=$1;bytes+=$2}
   END {printf "{\"available\":true,\"dot\":%.0f,\"doq\":%.0f,\"doh\":%.0f,\"bytes\":%.0f}",dot,doq,doh,bytes}')
 else encrypted_dns_stats='{"available":false}';fi
 json_append __json_result__ encrypted_dns_stats:json
}
