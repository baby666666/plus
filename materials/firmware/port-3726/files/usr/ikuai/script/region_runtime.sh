#!/bin/bash
RG_BASE=/usr/share/strict-routing
RG_HOME=/etc/mnt/ikuai/region-iplib
RG_TMP=/tmp/iktmp/region-iplib
RG_KEYS='cn asia europe americas oceania africa hk mo tw'
rg_valid_root() {
 [ "$1" = "$RG_BASE" ] && return 0
 [[ "$1" =~ ^/etc/mnt/ikuai/region-iplib/versions/[a-f0-9]{64}$ ]]
}
rg_current() {
 local root
 if [ -L "$RG_HOME/current" ];then root=$(readlink "$RG_HOME/current");else root=$RG_BASE;fi
 rg_valid_root "$root" && [ -f "$root/region-manifest.json" ] || return 1
 printf '%s\n' "$root"
}
rg_pointer() {
 rg_valid_root "$2" || return 1
 mkdir -p "$RG_HOME" || return 1
 rm -f "$RG_HOME/$1.new.$$"
 ln -s "$2" "$RG_HOME/$1.new.$$" && /usr/bin/ikluajit /usr/ikuai/script/region_iplib.lua rename "$RG_HOME/$1.new.$$" "$RG_HOME/$1"
}
rg_alias() {
 local name count
 name=$(sed -n "s/^GROUP_NAME='\([A-Za-z0-9_]*\)'$/\1/p" /etc/mnt/ikuai/china_iplib.conf 2>/dev/null | head -1)
 name=${name:-china_auto}
 [[ "$name" =~ ^[A-Za-z0-9_]{1,21}$ ]] || return 0
 [[ "$name" =~ ^geo_(cn|asia|europe|americas|oceania|africa|hk|mo|tw)$ ]] && return 0
 count=$(sqlite3 "$IK_DB_CONFIG" "select count(*) from ipgroup where group_name='$name' and (comment like 'China IP auto %' or comment='Managed region IP library: cn (legacy alias)');")
 [ "$count" != 1 ] || echo "$name"
}
rg_prepare() {
 local dir="$1" key count alias deleted
 sqlite3 "$IK_DB_CONFIG" "CREATE TABLE IF NOT EXISTS region_group_deleted(group_name TEXT PRIMARY KEY);" || return 1
 deleted=$(sqlite3 "$IK_DB_CONFIG" "select group_concat(group_name) from region_group_deleted;") || return 1
 deleted=,$deleted,
 if [ "${restore_deleted:-0}" = 1 ];then for key in cn foreign;do deleted=${deleted//,geo_$key,/,};done;fi
 if [ -n "${detail_key:-}" ];then [[ "$detail_key" =~ ^[a-z][a-z0-9_]{1,16}$ ]] || return 1;deleted=${deleted//,geo_$detail_key,/,};fi
 deleted=${deleted#,};deleted=${deleted%,}
 rg_valid_root "$dir" || return 1
 NR_WORK_CPU_PERCENT=15 /usr/sbin/native-work-run /usr/bin/ikluajit /usr/ikuai/script/region_iplib.lua verify "$dir" >/dev/null || return 1
 export RG_ACTIVE_GROUPS=$(sqlite3 "$IK_DB_CONFIG" "select group_concat(group_name) from ipgroup where comment like 'Managed region IP library: %';") || return 1
 RG_KEYS=$(jq -r '[.regions[].key,"foreign"]|unique[]' "$dir/region-manifest.json") || return 1
 mkdir -p "$RG_TMP/transaction" || return 1
 for key in $RG_KEYS;do
  count=$(sqlite3 "$IK_DB_CONFIG" "select count(*) from ipgroup where group_name='geo_$key' and coalesce(comment,'')!='Managed region IP library: $key';") || return 1
  [ "$count" = 0 ] || { echo "IP group geo_$key already exists; rename the custom group first";return 1; }
  ipset destroy "rgstage_$key" 2>/dev/null || true
 done
 alias=$(rg_alias)
 printf '%s\n' "$alias" > "$RG_TMP/transaction/alias"
 ipset destroy rgstage_legacy 2>/dev/null || true
 NR_WORK_CPU_PERCENT=15 /usr/sbin/native-work-run /usr/bin/ikluajit /usr/ikuai/script/region_iplib.lua export "$dir" "$RG_TMP/transaction" "$alias" "$deleted" || return 1
 ipset restore -file "$RG_TMP/transaction/groups.restore" || return 1
}
rg_groups() {
 local key
 for key in $RG_KEYS;do
  ipset list "group_geo_$key" -terse >/dev/null 2>&1 || ipset create "group_geo_$key" hash:net family inet maxelem 262144 || return 1
  ipset swap "rgstage_$key" "group_geo_$key" || return 1
 done
 local alias=$(cat "$RG_TMP/transaction/alias")
 if [ -n "$alias" ];then
  ipset list "group_$alias" -terse >/dev/null 2>&1 || ipset create "group_$alias" hash:net family inet maxelem 262144 || return 1
  ipset swap rgstage_legacy "group_$alias" || return 1
 fi
 sqlite3 "$IK_DB_CONFIG" < "$RG_TMP/transaction/groups.sql" || return 1
 Include ipmacgroup.sh
 ipgroup_get_name_to_cache
}
rg_cleanup() {
 local key
 for key in $RG_KEYS legacy;do ipset destroy "rgstage_$key" 2>/dev/null || true;done
}
# Runs under strict_policy's existing policy lock; interrupted commits roll back on boot.
region_restore() {
 ensure_conf;lock_action || return 1
 local root pending=0
 if [ -f "$RG_HOME/pending" ];then
  read -r root < "$RG_HOME/pending";rg_valid_root "$root" || return 1
  [ ! -f "$RG_HOME/pending-groups.sql" ] || sqlite3 "$IK_DB_CONFIG" < "$RG_HOME/pending-groups.sql" || return 1
  rg_pointer current "$root" || return 1;pending=1
 else root=$(rg_current) || return 1;fi
 rg_prepare "$root" && rg_groups || { rg_cleanup;return 1; }
 rg_cleanup
 if [ "$pending" = 1 ];then
  local live=0
  if [ "$(jq -r .enabled "$CONF")" = true ] && [ -f "$STATE/active/config.json" ];then
   export SP_HOLD_GUARD=1 RG_TRANSACTION=1
   apply_config "$CONF" || return 1;live=1
   unset SP_HOLD_GUARD RG_TRANSACTION STRICT_REGION_ROOT
  fi
  rm -f "$RG_HOME/pending" "$RG_HOME/pending-groups.sql";sync
  [ "$live" != 1 ] || { unguard;start_monitor; }
 fi
 touch "$RG_TMP/restored"
}
# An unreferenced group update cannot change this engine's route decisions.
# Keep serving when only the group catalogue changes. Any uncertainty, legacy
# engine, pending commit, or group reference falls back to the guarded path.
rg_policy_uses_groups() {
 [ -f "$NR/active/apply.sh" ] && [ ! -f "$NR/commit.pending" ] && [ ! -f "$NR/native-dirty" ] && [ ! -f "$NR/native-stage.pending" ] || return 0
 [ "$(jq -r .enabled /etc/mnt/ikuai/strict-routing.json 2>/dev/null)" != true ] || return 0
 local refs key alias
 local strict_count
 strict_count=$(sqlite3 "$IK_DB_CONFIG" "select count(*) from stream_domain where enabled='yes' and nr_group='fallback' and nr_target='cn';") || return 0
 [ "$strict_count" = 0 ] || return 0
 refs=$(sqlite3 "$IK_DB_CONFIG" "select coalesce(src_addr,'')||','||coalesce(dst_addr,'') from stream_ipport union all select coalesce(src_addr,'') from stream_domain union all select coalesce(src_addr,'') from stream_layer7;") || return 0
 for key in $RG_KEYS;do [[ "$refs" != *"geo_$key"* ]] || return 0;done
 alias=$(cat "$RG_TMP/transaction/alias") || return 0
 [ -z "$alias" ] || [[ "$refs" != *"$alias"* ]] || return 0
 return 1
}
region_install() {
 ensure_conf;lock_action || return 1
 local old new="$candidate" enabled changed=0 route_update=1
 [ ! -f "$RG_HOME/pending" ] && [ ! -f /etc/mnt/ikuai/domain-iplib/pending ] || { echo "Incomplete database transaction; recover before updating";return 1; }
 rg_valid_root "$new" || { echo 'Invalid database path';return 1; }
 old=$(rg_current) || return 1
 NR_WORK_CPU_PERCENT=15 /usr/sbin/native-work-run /usr/bin/ikluajit /usr/ikuai/script/region_iplib.lua verify "$new" || return 1
 # A rollback cannot remove an active fine group, including groups referenced by disabled rules.
 local existing key
 existing=$(sqlite3 "$IK_DB_CONFIG" "select substr(group_name,5) from ipgroup where comment like 'Managed region IP library: %' and (group_name glob 'geo_country_*' or group_name glob 'geo_cn_*' or group_name glob 'geo_isp_*' or group_name glob 'geo_cloud_*' or group_name glob 'geo_cv_*' or group_name glob 'geo_appip_*' or group_name glob 'geo_user_*');") || return 1
 for key in $existing;do
  jq -e --arg key "$key" '.regions[] | select(.key==$key)' "$new/region-manifest.json" >/dev/null || { echo '回退版本缺少已启用的细分分组，请先删除对应分组（被规则引用时不能删除）';return 1; }
 done
 if [ -z "${detail_key:-}" ] && [ "$(jq -r .version "$new/region-manifest.json")" = "$(jq -r .version "$old/region-manifest.json")" ];then
  if [ "${restore_deleted:-0}" != 1 ] || [ "$(sqlite3 "$IK_DB_CONFIG" "select count(*) from ipgroup where group_name in ('geo_cn','geo_foreign') and comment like 'Managed region IP library: %';")" = 2 ];then echo "Database is already current";return 0;fi
 fi
 export RG_RESTORE_DELETED="${restore_deleted:-0}" RG_RESTORE_KEY="${detail_key:-}"
 rg_prepare "$new" || { rg_cleanup;return 1; }
 enabled=$(jq -r .enabled "$CONF")
 rg_policy_uses_groups || route_update=0
 [ "$enabled" != true ] || [ "$route_update" = 0 ] || guard || return 1
 mkdir -p "$RG_HOME"
 { echo 'BEGIN IMMEDIATE;';echo 'DELETE FROM region_group_deleted;';sqlite3 "$IK_DB_CONFIG" "select 'INSERT INTO region_group_deleted VALUES('||quote(group_name)||');' from region_group_deleted;";echo "DELETE FROM ipgroup WHERE comment LIKE 'Managed region IP library: %';";sqlite3 "$IK_DB_CONFIG" "select 'INSERT INTO ipgroup(id,group_name,addr_pool,comment,type) VALUES('||quote(id)||','||quote(group_name)||','||quote(addr_pool)||','||quote(comment)||','||quote(type)||');' from ipgroup where comment like 'Managed region IP library: %';";echo 'COMMIT;';} > "$RG_HOME/pending-groups.sql" || return 1
 printf '%s\n' "$old" > "$RG_HOME/pending.new" && mv "$RG_HOME/pending.new" "$RG_HOME/pending" || return 1
 sync
 export SP_HOLD_GUARD=1 RG_TRANSACTION=1
 if rg_pointer current "$new" && rg_groups;then
  if [ "$enabled" != true ] || [ "$route_update" = 0 ] || apply_config "$CONF";then changed=1;fi
 fi
 if [ "$changed" = 1 ] && [ "$new" != "$old" ];then
  rg_pointer previous "$old" || changed=0
 fi
 if [ "$changed" != 1 ];then
  # Retain the guard until both native IP groups and strict routing are restored.
  for key in $RG_KEYS;do
   case "$key" in country_*|cn_*|isp_*|cloud_*|cv_*|appip_*|user_*) jq -e --arg key "$key" '.regions[] | select(.key==$key)' "$old/region-manifest.json" >/dev/null || { ipset flush "group_geo_$key" 2>/dev/null;ipset destroy "group_geo_$key" 2>/dev/null; };;esac
  done
  rg_cleanup
  unset RG_RESTORE_DELETED RG_RESTORE_KEY;restore_deleted=0;detail_key=""
  if sqlite3 "$IK_DB_CONFIG" < "$RG_HOME/pending-groups.sql" && rg_pointer current "$old" && rg_prepare "$old" && rg_groups;then
   if [ "$enabled" != true ] || [ "$route_update" = 0 ] || apply_config "$CONF";then
    rm -f "$RG_HOME/pending" "$RG_HOME/pending-groups.sql";sync
    unset SP_HOLD_GUARD RG_TRANSACTION STRICT_REGION_ROOT
    [ "$enabled" != true ] || [ "$route_update" = 0 ] || { unguard;start_monitor; }
   fi
  fi
  rg_cleanup;echo 'Database apply failed; old database restored or managed traffic remains blocked';return 1
 fi
 for key in $(jq -r '.regions[].key' "$old/region-manifest.json");do
  case "$key" in country_*|cn_*|isp_*|cloud_*|cv_*|appip_*|user_*) jq -e --arg key "$key" '.regions[] | select(.key==$key)' "$new/region-manifest.json" >/dev/null || { ipset flush "group_geo_$key" 2>/dev/null;ipset destroy "group_geo_$key" 2>/dev/null; };;esac
 done
 sync
 rm -f "$RG_HOME/pending" "$RG_HOME/pending-groups.sql";sync;rg_cleanup
 unset SP_HOLD_GUARD RG_TRANSACTION STRICT_REGION_ROOT
 [ "$enabled" != true ] || [ "$route_update" = 0 ] || { unguard;start_monitor; }
 echo 'Region database and routing applied'
}
