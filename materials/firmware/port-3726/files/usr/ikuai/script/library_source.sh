#!/bin/bash
source_config(){ /usr/bin/ikluajit /usr/ikuai/script/library_source.lua get "$LIB_KIND" "$HOME_DIR"; }
source_save(){
 mkdir -p "$HOME_DIR" "$TMP_DIR"
 local owner
 if [ -d "$TMP_DIR/job.lock" ];then
  owner=$(cat "$TMP_DIR/job.lock/pid" 2>/dev/null)
  [ -z "$owner" ] || kill -0 "$owner" 2>/dev/null || rm -rf "$TMP_DIR/job.lock"
 fi
 if ! mkdir "$TMP_DIR/job.lock" 2>/dev/null;then echo '正在更新或保存源，请稍后再试';return 1;fi
 echo $$ > "$TMP_DIR/job.lock/pid"
 trap 'rm -rf "$TMP_DIR/job.lock";rm -f "$TMP_DIR/source-input.$$"' EXIT
 printf '%s' "$payload" | base64 -d > "$TMP_DIR/source-input.$$" || return 1
 /usr/bin/ikluajit /usr/ikuai/script/library_source.lua save "$LIB_KIND" "$HOME_DIR" "$TMP_DIR/source-input.$$" || return 1
 sync
}
source_snapshot(){
 mkdir -p "$HOME_DIR" "$TMP_DIR"
 source_config > "$TMP_DIR/job-source.json" || return 1
 /usr/bin/ikluajit /usr/ikuai/script/library_source.lua history "$LIB_KIND" "$HOME_DIR" start "$(date '+%F %T %z')" "$(jq -r .url "$TMP_DIR/job-source.json")" '' "$TMP_DIR/job-source.json"
}
source_worker(){
 SOURCE_URL=$(jq -r .url "$TMP_DIR/job-source.json") || return 1
 DOMAIN_SOURCE_FORMAT=$(jq -r .format "$TMP_DIR/job-source.json") || return 1
 FOREIGN_SOURCE_URL=$(jq -r ".groups.foreign.url // empty" "$TMP_DIR/job-source.json")
 FOREIGN_SOURCE_FORMAT=$(jq -r ".groups.foreign.format // \"plain\"" "$TMP_DIR/job-source.json")
 DOMAIN_EXTRA_URL=$(jq -r '.groups.cn.supplement // empty' "$TMP_DIR/job-source.json")
 FOREIGN_EXTRA_URL=$(jq -r '.groups.foreign.supplement // empty' "$TMP_DIR/job-source.json")
 export DOMAIN_EXTRA_URL FOREIGN_EXTRA_URL
 export LIBRARY_SOURCE_URL="$SOURCE_URL" DOMAIN_SOURCE_FORMAT FOREIGN_SOURCE_URL FOREIGN_SOURCE_FORMAT
}
source_history(){
 local version='' root="$HOME_DIR/current" origin
 [ -L "$root" ] || root=/usr/share/strict-routing
 [ "$1" != success ] || version=$(jq -r .version "$root/$LIB_KIND-manifest.json")
 origin=$(jq -r .url "$TMP_DIR/job-source.json" 2>/dev/null)
 /usr/bin/ikluajit /usr/ikuai/script/library_source.lua history "$LIB_KIND" "$HOME_DIR" "$1" "$(date '+%F %T %z')" "${origin:-}" "$version" "$TMP_DIR/job-source.json" "${detail_key:-}"
}
source_status(){
 local base="$1" deleted=''
 if [ "$LIB_KIND" = region ];then deleted=$(sqlite3 "$IK_DB_CONFIG" "select group_concat(group_name) from region_group_deleted;" 2>/dev/null);fi
 if [ "$LIB_KIND" = region ];then
  local active=$(sqlite3 "$IK_DB_CONFIG" "select group_concat(group_name) from ipgroup where comment like 'Managed region IP library: %';")
  base=$(printf '%s' "$base" | jq --arg active "$active" '.active_groups=($active|split(","))') || return 1
 fi
 /usr/bin/ikluajit /usr/ikuai/script/library_source.lua status "$LIB_KIND" "$HOME_DIR" "$base" "$deleted"
}
