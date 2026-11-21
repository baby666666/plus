#!/bin/bash
# Called from the native IP-group delete action. Hold the same locks as rule edits and updates.
region_delete_prepare(){
 [[ "$id" =~ ^[0-9]+(,[0-9]+)*$ ]] || { echo '请选择有效分组';return 1; }
 local dir n owner table columns col query='' refs 
 owner=$(cat /tmp/iktmp/region-iplib/job.lock/pid 2>/dev/null)
 if [ -n "$owner" ] && kill -0 "$owner" 2>/dev/null;then echo '地区库正在更新，请完成后再删除分组';return 1;fi
 mkdir -p /tmp/iktmp/native-rules /tmp/iktmp/strict-routing
 for dir in /tmp/iktmp/native-rules/edit-lock /tmp/iktmp/strict-routing/lock;do
  for n in $(seq 1 600);do
   if mkdir "$dir" 2>/dev/null;then echo $$ > "$dir/pid";break;fi
   owner=$(cat "$dir/pid" 2>/dev/null)
   if [ -n "$owner" ] && ! kill -0 "$owner" 2>/dev/null;then rm -rf "$dir";fi
   sleep .1
  done
  [ "$n" != 600 ] || { echo '另一项规则或数据库操作尚未完成';return 1; }
  if [[ "$dir" == */edit-lock ]];then trap 'rm -rf /tmp/iktmp/native-rules/edit-lock' EXIT
  else trap 'rm -rf /tmp/iktmp/native-rules/edit-lock /tmp/iktmp/strict-routing/lock' EXIT;fi
 done
 [ ! -f /etc/mnt/ikuai/region-iplib/pending ] || { echo '地区库切换尚未恢复，请重启后再删除';return 1; }
 sqlite3 "$IK_DB_CONFIG" 'CREATE TABLE IF NOT EXISTS region_group_deleted(group_name TEXT PRIMARY KEY);' || return 1
 # Search address/group columns in all native tables, including disabled rules.
 for table in $(sqlite3 "$IK_DB_CONFIG" "select name from sqlite_master where type='table' and name not like 'sqlite_%' and name not in ('ipgroup','region_group_deleted','nr_retired_app_rules');");do
  [[ "$table" =~ ^[A-Za-z0-9_]+$ ]] || continue
  columns=$(sqlite3 "$IK_DB_CONFIG" "pragma table_info('$table');" | awk -F '|' '$2 ~ /(addr|group|ip_list|iprange|ip_range)/ {print $2}')
  for col in $columns;do
   [[ "$col" =~ ^[A-Za-z0-9_]+$ ]] || continue
   [ -z "$query" ] || query="$query UNION ALL "
   query="$query SELECT g.group_name||' → $table.$col (记录 '||r.rowid||')' FROM ipgroup g JOIN \"$table\" r ON instr(','||replace(replace(coalesce(r.\"$col\",''),' ',','),char(10),',')||',',','||g.group_name||',')>0 WHERE g.id IN ($id)"
  done
 done
 if [ -n "$query" ];then refs=$(sqlite3 "$IK_DB_CONFIG" "$query LIMIT 12;") || return 1;fi
 [ -z "$refs" ] || { printf '以下分组仍被规则引用，请先修改或删除对应规则：\n%s\n' "$refs";return 1; }
}
