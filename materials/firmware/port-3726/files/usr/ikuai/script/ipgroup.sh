#!/bin/bash /etc/ikcommon
Include ipset.sh, ipmacgroup.sh

boot()
{
	init
}

init()
{
	ipgroup_get_name_to_cache
	addrgroup_get_name_to_cache
	sql_config_get_list $IK_DB_CONFIG "select * from ipgroup where not ((group_name glob 'geo_*' and coalesce(comment,'') like 'Managed region IP library: %') or coalesce(comment,'')='Managed region IP library: cn (legacy alias)')" |\
	while read config ;do
		if [ -n "$config" ];then
			local $config
			if [ "$type" = "1" ]; then
				__addrpool_rule_add
			fi
			__exec_rule_batch_add
		fi
	done
 if [ ! -f /etc/mnt/ikuai/region-iplib/defaults-v11 ];then
  local legacy_id
  for legacy_id in $(sqlite3 "$IK_DB_CONFIG" "select id from ipgroup where group_name in ('geo_asia','geo_europe','geo_americas','geo_oceania','geo_africa','geo_hk','geo_mo','geo_tw') and comment='Managed region IP library: '||substr(group_name,5);");do
   /usr/ikuai/script/ipgroup.sh del "id=$legacy_id" >>/tmp/iktmp/region-defaults-v11.log 2>&1 || true
  done
  mkdir -p /etc/mnt/ikuai/region-iplib;touch /etc/mnt/ikuai/region-iplib/defaults-v11
 fi
	/usr/ikuai/script/strict_policy.sh region_restore >>/tmp/iktmp/region-restore.log 2>&1 || true
}

add() {
	__check_param || exit 1
	__check_addr_pool_is_valid || exit 1
	__check_group_name || exit 1
	local sql_param="comment:str group_name:str addr_pool:str type:int"
	if SqlMsg=$(sql_config_insert $IK_DB_CONFIG ipgroup $sql_param) ;then
		local id=$SqlMsg

		if [ "$type" = "1" ]; then
			__addrpool_rule_add >/dev/null 2>&1
			addrgroup_get_name_to_cache
		fi
		__exec_rule_batch_add >/dev/null 2>&1 &
		ipgroup_get_name_to_cache
		echo "$id"
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi
}

del()
{
 . /usr/ikuai/script/region_delete.sh
 region_delete_prepare || return 1
	sql_config_get_list $IK_DB_CONFIG "BEGIN IMMEDIATE;select type,group_name from ipgroup where id in ($id);INSERT OR IGNORE INTO region_group_deleted SELECT group_name FROM ipgroup WHERE id IN ($id) AND comment LIKE 'Managed region IP library: %';delete from ipgroup where id in ($id);COMMIT;" |\
	while read config ;do
		if [ -n "$config" ];then
			local $config
		
			__exec_rule_del >/dev/null 2>&1
			if [ "$type" = "1" ]; then
				__addrpool_rule_del >/dev/null 2>&1
			fi
		fi
	done
	ipgroup_get_name_to_cache
	addrgroup_get_name_to_cache
}

edit()
{
	__region_check_mutable || return 1
	__check_param || exit 1
	__check_addr_pool_is_valid || exit 1
	__check_group_name || exit 1
	local sql_param="comment:str group_name:str addr_pool:str type:int"
	local res=$(sql_config_get_list $IK_DB_CONFIG "select * from ipgroup where id=$id" prefix=old_)
	if [ "res" = "" ];then
		return 0
	fi
	local $res
	if SqlMsg=$(sql_config_update $IK_DB_CONFIG ipgroup "id=$id" $sql_param);then
		if ! NewOldVarl group_name type ;then
			if [ "$old_type" = "1" ]; then
				group_name=$old_group_name __addrpool_rule_del 2>/dev/null
			fi
			group_name=$old_group_name __exec_rule_del 2>/dev/null
		fi
		if [ "$type" = "1" ]; then
			__addrpool_rule_add >/dev/null 2>&1
		fi
		__exec_rule_batch_add >/dev/null 2>&1 &
		ipgroup_get_name_to_cache
		addrgroup_get_name_to_cache
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi
}

vrrp_init()
{
	__clean
	sqlite3 $IK_DB_CONFIG "delete from ipgroup"	
	sqlite3 $IK_DIR_LOG/vrrp/conf/config.db ".dump ipgroup" |grep "^INSERT"| sqlite3 $IK_DB_CONFIG
	init
}

show()
{
	local __filter=$(sql_auto_get_filter)
	local __order=$(sql_auto_get_order)
	local __limit=$(sql_auto_get_limit)
	local __where="$__filter $__order $__limit"
	Show __json_result__
}

__show_total()
{
	local total=$(sqlite3 $IK_DB_CONFIG "select count() from ipgroup $__filter")
	json_append __json_result__ total:int
}

__show_data()
{
	local sql_show="select * from ipgroup $__where"
	local data=$(sql_config_get_json $IK_DB_CONFIG "$sql_show")
	json_append __json_result__ data:json
	return 0;
}


EXPORT()
{
	Include import_export.sh
	local format=${format:-txt}
	if errmsg=$(export_txt $IK_DB_CONFIG ipgroup $format $IK_DIR_EXPORT/ipgroup.$format "not ((group_name glob 'geo_*' and coalesce(comment,'') like 'Managed region IP library: %') or coalesce(comment,'')='Managed region IP library: cn (legacy alias)')") ;then
		echo "ipgroup.$format"
		return 0
	else
		echo "$errmsg"
		return 1
	fi
}

IMPORT()
{
	Include import_export.sh
	if errmsg=$(import_txt $IK_DB_CONFIG ipgroup $IK_DIR_IMPORT/$filename "$append"  __check_param __clean "not ((group_name glob 'geo_*' and coalesce(comment,'') like 'Managed region IP library: %') or coalesce(comment,'')='Managed region IP library: cn (legacy alias)')") ;then
		init >/dev/null 2>/dev/null &
		return 0
	else
		echo "$errmsg"
		return 1
	fi
}


#检查配置的地址池与本地接口网段是否冲突
__check_addr_pool_is_valid()
{
	[ "$type" != "1" ] && return 0

	if ! res=$(check_interface_addrpool "$addr_pool"); then
		Autoiecho param addr_pool_conflict "$res"
		return 1
	fi
	return 0
}

__check_group_name()
{
	if res=$(check_group_name_used ipgroup $group_name 2>/dev/null); then
		Autoiecho ipgroup group_name_inused "$res"	
		return 1
	fi
	return 0
}

__check_param()
{
 [[ "$group_name" =~ ^geo_(foreign|appip_[a-z0-9_]+|user_[a-z0-9_]+|country_[a-z]{2}|cn_[0-9]{6}|isp_[a-z0-9]+|cloud_[a-z0-9]+|cv_[a-z]{2}_[a-z0-9]+)$ ]] && { echo '该名称保留给细分地区库';return 1; }
	check_varl \
		'group_name not macs and not ipall and != "geo_cn" and != "geo_asia" and != "geo_europe" and != "geo_americas" and != "geo_oceania" and != "geo_africa" and != "geo_hk" and != "geo_mo" and != "geo_tw" and length >= 1 and length <= 21' \
		'addr_pool ipall' 
}


__clean()
{
	sql_config_get_list $IK_DB_CONFIG "select group_name from ipgroup where not ((group_name glob 'geo_*' and coalesce(comment,'') like 'Managed region IP library: %') or coalesce(comment,'')='Managed region IP library: cn (legacy alias)')" |\
	while read config ;do
		if [ -n "$config" ];then
			local $config
			__exec_rule_del
		fi
	done
}

__exec_rule_add()
{
	ipset -N group_$group_name hash:net 2>/dev/null
	ipset -F group_$group_name 2>/dev/null
	ipset_add group_$group_name $addr_pool 2>/dev/null 
}

__exec_rule_del()
{
	ipset -F group_$group_name 2>/dev/null
	ipset -X group_$group_name 2>/dev/null
}

__exec_rule_batch_add()
{
	local cachefile="$IK_DIR_TMP/.ip_${group_name}.$$"

	ipset -N group_$group_name hash:net 2>/dev/null
	ipset -F group_$group_name 2>/dev/null

	> $cachefile
	for ip in ${addr_pool//,/ } ;do
		echo "-! add group_$group_name $ip" >> $cachefile
	done

	ipset_restore "$cachefile"
}

__addrpool_rule_add()
{
	$IK_DIR_SCRIPT/utils/addrpool.lua set "$group_name" "$addr_pool" >/dev/null 2>&1
}

__addrpool_rule_del()
{
	$IK_DIR_SCRIPT/utils/addrpool.lua set "$group_name" "" >/dev/null 2>&1
}

__region_check_mutable() {
 [[ "$id" =~ ^[0-9]+(,[0-9]+)*$ ]] || return 1
 local count=$(sqlite3 "$IK_DB_CONFIG" "select count(*) from ipgroup where id in ($id) and comment like 'Managed region IP library: %';")
 [ "$count" = 0 ] || { echo 'Managed region IP groups can only be changed by the region database updater';return 1; }
}
__show_region_iplib() {
 local region_iplib=$(/usr/ikuai/script/region_iplib.sh status)
 [ -n "$region_iplib" ] || return 1
 json_append __json_result__ region_iplib:json
}
region_update() { /usr/ikuai/script/region_iplib.sh request operation=update "detail_key=${detail_key:-}"; }
region_rollback() { /usr/ikuai/script/region_iplib.sh request operation=rollback; }

region_source_save() { /usr/ikuai/script/region_iplib.sh source_save "payload=$payload"; }

# Use a synchronous action so reference errors reach the native table.
region_delete() {
 local message rc
 message=$(del 2>&1);rc=$?
 printf '%s' "${message//$'\n'/；}"
 return "$rc"
}

__show_app_ip() {
 [[ "$detail_key" =~ ^appip_[a-z0-9_]{1,11}$ ]] || return 1
 local root=/etc/mnt/ikuai/region-iplib/current app_ip
 [ -L "$root" ] || root=/usr/share/strict-routing
 app_ip=$(/usr/bin/ikluajit /usr/ikuai/script/region_app.lua view "$root" "$detail_key" "${offset:-0}") || return 1
 local active=$(sqlite3 "$IK_DB_CONFIG" "select count(*) from ipgroup where group_name='geo_$detail_key' and comment='Managed region IP library: $detail_key';")
 [ "$active" = 1 ] && active=true || active=false
 app_ip=$(printf '%s' "$app_ip" | jq -c --arg active "$active" '.active=($active=="true")') || return 1
 json_append __json_result__ app_ip:json
}
app_ip_save() { /usr/ikuai/script/region_iplib.sh request operation=manual "payload=$payload"; }
