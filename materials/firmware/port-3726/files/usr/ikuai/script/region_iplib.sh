#!/bin/bash /etc/ikcommon
HOME_DIR=/etc/mnt/ikuai/region-iplib
TMP_DIR=/tmp/iktmp/region-iplib
LIB_KIND=region
. /usr/ikuai/script/library_source.sh
state() {
 mkdir -p "$TMP_DIR" "$HOME_DIR"
 [ "${operation:-update}" = manual ] || { [ "$1" != success ] && [ "$1" != failed ] || source_history "$1" || return 1; }
 /usr/bin/ikluajit /usr/ikuai/script/region_iplib.lua state "$1" "$2" "$(date '+%F %T')" > "$TMP_DIR/status.new.$$" && mv "$TMP_DIR/status.new.$$" "$TMP_DIR/status.json"
 cp "$TMP_DIR/status.json" "$HOME_DIR/last-job.json.new" && mv "$HOME_DIR/last-job.json.new" "$HOME_DIR/last-job.json"
 [ "$1" != success ] && [ "$1" != failed ] || sync
}
request() {
 local op="${operation:-update}" pid
 [ -z "${detail_key:-}" ] || [[ "$detail_key" =~ ^[a-z][a-z0-9_]{1,16}$ ]] || return 1
 [ ! -f "$HOME_DIR/pending" ] || { echo "上次数据库切换未完成，请重启恢复后再更新";return 1; }
 [ "$op" = update ] || [ "$op" = rollback ] || [ "$op" = manual ] || return 1
 mkdir -p "$TMP_DIR"
 if ! mkdir "$TMP_DIR/job.lock" 2>/dev/null;then
  pid=$(cat "$TMP_DIR/job.lock/pid" 2>/dev/null)
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && { echo 'Another database update is running';return 1; }
  # A newly launched worker must have time to write its PID.
  [ -n "$pid" ] || { echo 'Database worker is starting';return 1; }
  rm -f "$TMP_DIR/job.lock/pid";rmdir "$TMP_DIR/job.lock" || return 1
  mkdir "$TMP_DIR/job.lock" || return 1
 fi
 echo $$ > "$TMP_DIR/job.lock/pid"
 if [ "$op" = manual ];then
  local current="$HOME_DIR/current"
  [ -L "$current" ] || current=/usr/share/strict-routing
  if [ "${#payload}" -gt 140000 ] || ! printf '%s' "$payload" | base64 -d > "$TMP_DIR/manual-input.json" ||
   ! /usr/bin/ikluajit /usr/ikuai/script/region_app.lua prepare "$current" "$TMP_DIR/manual-input.json" "$TMP_DIR/manual-job.json";then
   rm -f "$TMP_DIR/manual-input.json" "$TMP_DIR/manual-job.json";rm -rf "$TMP_DIR/job.lock";return 1
  fi
  detail_key=$(jq -r .key "$TMP_DIR/manual-job.json")
  local active=$(sqlite3 "$IK_DB_CONFIG" "select count(*) from ipgroup where group_name='geo_$detail_key' and comment='Managed region IP library: $detail_key';")
  [ "$active" = 1 ] || { echo '请先添加应用分组';rm -rf "$TMP_DIR/job.lock";return 1; }
  source_config > "$TMP_DIR/job-source.json" || { rm -rf "$TMP_DIR/job.lock";return 1; }
 else source_snapshot || { rm -rf "$TMP_DIR/job.lock";return 1; };fi
 state running '正在准备地区 IP 库'
 /usr/ikuai/script/region_iplib.sh worker "operation=$op" "detail_key=${detail_key:-}" > "$TMP_DIR/job.log" 2>&1 &
 echo $! > "$TMP_DIR/job.lock/pid"
 return 0
}
worker() {
 local op="${operation:-update}" dir="$TMP_DIR/download.$$" version candidate previous
 echo $$ > "$TMP_DIR/job.lock/pid"
 trap "rm -f '$TMP_DIR/job.lock/pid';rmdir '$TMP_DIR/job.lock' 2>/dev/null;rm -rf '$dir'" EXIT
 source_worker || return 1
 mkdir -p "$dir" "$HOME_DIR/versions" || { state failed '无法创建数据库目录';return 1; }
 if [ "$op" = rollback ];then
  previous=$(readlink "$HOME_DIR/previous")
  /usr/ikuai/script/strict_policy.sh region_install "candidate=$previous" > "$dir/apply.log" 2>&1 || { cat "$dir/apply.log";state failed '回退失败，旧策略已恢复或保持阻断；请查看更新日志';return 1; }
  state success '已回退上一版，IP 分组和分流规则已同步';return 0
 fi
 local current="$HOME_DIR/current" deleted archive
 [ -L "$current" ] || current=/usr/share/strict-routing
 export REGION_PREVIOUS_ROOT="$current"
 if [ "$op" = manual ];then
  mkdir "$dir/candidate" || return 1
  cp "$current/"*.delta "$current/region-manifest.json" "$dir/candidate/" || return 1
  for manual in "$current/"*.manual.json;do [ ! -f "$manual" ] || cp "$manual" "$dir/candidate/" || return 1;done
  version=$(NR_WORK_CPU_PERCENT=15 /usr/sbin/native-work-run /usr/bin/ikluajit /usr/ikuai/script/region_app.lua edit "$current" "$TMP_DIR/manual-job.json" "$dir/candidate") || { state failed '手动调整校验失败，原分组保持不变';return 1; }
 else
 if [ -n "${detail_key:-}" ];then
  archive='-';export REGION_REUSE_ROOT="$current"
  mkdir "$dir/custom"
  jq '.regions={}' "$TMP_DIR/job-source.json" > "$dir/custom/sources.json" || return 1
 else
 local use_default=0 key url archive="$dir/archive.tar"
 for key in cn asia europe americas oceania africa hk mo tw;do url=$(jq -r ".regions.$key // empty" "$TMP_DIR/job-source.json");[ -n "$url" ] || use_default=1;done
 if [ "$use_default" = 1 ];then
 state running '正在通过 HTTPS 下载完整国家 IP 库'
 if ! (ulimit -f 4096;/usr/sbin/native-safe-fetch "$SOURCE_URL" "$dir/archive.gz" 2097152);then
  state failed '下载失败，继续使用原有地区库';return 1
 fi
 # Bound decompression and let the parser validate tar checksums, types and country completeness.
 if ! (set -o pipefail;gzip -dc "$dir/archive.gz" | head -c 16777217 > "$dir/archive.tar");then state failed '压缩包无效或过大，继续使用原有地区库';return 1;fi
 else archive='-';export REGION_ALL_CUSTOM=1;fi
 mkdir "$dir/custom"
 cp "$TMP_DIR/job-source.json" "$dir/custom/sources.json" || return 1
 local key url
 for key in cn foreign asia europe americas oceania africa hk mo tw;do
  url=$(jq -r ".regions.$key // empty" "$TMP_DIR/job-source.json")
  [ -n "$url" ] || continue
  state running "正在下载地区 $key 的自定义 CIDR 源"
  if ! (ulimit -f 8192;/usr/sbin/native-safe-fetch "$url" "$dir/custom/$key.txt" 4194304);then
   state failed "地区 $key 源下载失败，全部分组保持原库";return 1
  fi
 done
 fi
 deleted=$(sqlite3 "$IK_DB_CONFIG" 'select group_concat(group_name) from region_group_deleted;') || { state failed '读取分组状态失败';return 1; }
 NR_WORK_CPU_PERCENT=15 /usr/sbin/native-work-run /usr/bin/ikluajit /usr/ikuai/script/region_iplib.lua detail_plan "$current" "$TMP_DIR/job-source.json" "$deleted" "${detail_key:-}" "$dir/custom" || { state failed '细分分组计划无效或超过启用数量限制';return 1; }
 # Carry deleted lists for rollback metadata; they are not loaded into the live sets.
 for key in $(jq -r '.[] | select(.fetch==false) | .key' "$dir/custom/detail-plan.json");do cp "$current/$key.delta" "$dir/custom/$key.delta" || { state failed '读取已有细分库失败';return 1; };done
 while IFS=$'\t' read -r key url;do
  [ -n "$key" ] || continue
  state running "正在下载细分分组 $key"
  if ! (ulimit -f 8192;/usr/sbin/native-safe-fetch "$url" "$dir/custom/$key.txt" 4194304);then state failed "细分分组 $key 下载失败，全部分组保持原库";return 1;fi
 done < "$dir/custom/detail-downloads"
 mkdir "$dir/candidate"
 state running '正在校验国家完整性、地区边界和地址数量'
 version=$(NR_WORK_CPU_PERCENT=15 /usr/sbin/native-work-run /usr/bin/ikluajit /usr/ikuai/script/region_iplib.lua build "$archive" "$dir/candidate" "$dir/custom" 2> "$dir/validate.log") || {
  cat "$dir/validate.log";local reason=$(tail -1 "$dir/validate.log" | cut -c1-240)
  state failed "地区库校验失败，保留原库：$reason";return 1
 }
 fi
 [[ "$version" =~ ^[a-f0-9]{64}$ ]] || { state failed '数据库版本无效';return 1; }
 candidate="$HOME_DIR/versions/$version"
 if [ -d "$candidate" ];then NR_WORK_CPU_PERCENT=15 /usr/sbin/native-work-run /usr/bin/ikluajit /usr/ikuai/script/region_iplib.lua verify "$candidate" || { state failed '已存数据库损坏，更新未应用';return 1; };else mv "$dir/candidate" "$candidate" || { state failed '保存数据库失败';return 1; };fi
 state running '正在切换数据库并同步 IP 分组和分流规则'
 /usr/ikuai/script/strict_policy.sh region_install "candidate=$candidate" restore_deleted=1 "detail_key=${detail_key:-}" > "$dir/apply.log" 2>&1 || { cat "$dir/apply.log";state failed '应用失败，旧策略已恢复或保持阻断；请查看更新日志';return 1; }
 local ambiguity=$(jq -r '.ambiguous_foreign_addresses // 0' "$candidate/region-manifest.json")
 if [ "$op" = manual ];then state success '应用网段手动调整已生效，在线更新会保留调整'
 elif [ "$ambiguity" -gt 0 ];then state success "IP 库已更新；$ambiguity 个归属冲突的海外地址仅归入大陆以外总组"
 else state success '地区 IP 库已更新，IP 分组和分流规则已同步';fi
 # Keep only the current and previous immutable snapshots. No user files reside here.
 local current=$(readlink "$HOME_DIR/current") old=$(readlink "$HOME_DIR/previous") p
 for p in "$HOME_DIR"/versions/*;do
  [[ "${p##*/}" =~ ^[a-f0-9]{64}$ ]] || continue
  [ "$p" = "$current" ] || [ "$p" = "$old" ] || rm -rf "$p"
 done
}
status() {
 mkdir -p "$TMP_DIR"
 . /usr/ikuai/script/region_runtime.sh
 local root="$HOME_DIR/current" pid alive=false rollback=false
 [ -L "$root" ] || root=/usr/share/strict-routing
 pid=$(cat "$TMP_DIR/job.lock/pid" 2>/dev/null)
 [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null || alive=true
 [ ! -L "$HOME_DIR/previous" ] || rollback=true
 [ -f "$TMP_DIR/status.json" ] || cp "$HOME_DIR/last-job.json" "$TMP_DIR/status.json" 2>/dev/null || true
 local result
 result=$(/usr/bin/ikluajit /usr/ikuai/script/region_iplib.lua status "$root/region-manifest.json" "$TMP_DIR/status.json" "$rollback" "$alive" "$(rg_alias)") || return 1
 source_status "$result"
}
