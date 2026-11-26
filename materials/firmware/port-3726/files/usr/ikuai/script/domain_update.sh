#!/bin/bash /etc/ikcommon
HOME_DIR=/etc/mnt/ikuai/domain-iplib
TMP_DIR=/tmp/iktmp/domain-iplib
LIB_KIND=domain
. /usr/ikuai/script/library_source.sh
state() {
 mkdir -p "$TMP_DIR" "$HOME_DIR"
 [ "$1" != success ] && [ "$1" != failed ] || source_history "$1" || return 1
 /usr/bin/ikluajit /usr/ikuai/script/domain_lib.lua state "$1" "$2" "$(date '+%F %T')" > "$TMP_DIR/status.new.$$" && mv "$TMP_DIR/status.new.$$" "$TMP_DIR/status.json"
 cp "$TMP_DIR/status.json" "$HOME_DIR/last-job.json.new" && mv "$HOME_DIR/last-job.json.new" "$HOME_DIR/last-job.json"
 [ "$1" != success ] && [ "$1" != failed ] || sync
}
request() {
 local op="${operation:-update}" pid
 [ ! -f "$HOME_DIR/pending" ] || { echo "上次数据库切换未完成，请重启恢复后再更新";return 1; }
 [ "$op" = update ] || [ "$op" = rollback ] || return 1
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
 source_snapshot || { rm -rf "$TMP_DIR/job.lock";return 1; }
 state running '正在准备域名库'
 /usr/ikuai/script/domain_update.sh worker "operation=$op" > "$TMP_DIR/job.log" 2>&1 &
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
  /usr/ikuai/script/strict_policy.sh domain_install "candidate=$previous" > "$dir/apply.log" 2>&1 || { cat "$dir/apply.log";state failed '回退失败，旧策略已恢复或保持阻断；请查看更新日志';return 1; }
  state success '已回退上一版，域名及 DNS 分流规则已同步';return 0
 fi
 state running '正在通过 HTTPS 下载大陆域名库'
 if ! (ulimit -f 32768;/usr/sbin/native-safe-fetch "$SOURCE_URL" "$dir/domains.conf" 16777216);then
  state failed '下载失败，继续使用原有域名库';return 1
 fi
 if [ -n "$FOREIGN_SOURCE_URL" ];then
  state running '正在通过 HTTPS 下载大陆以外域名库'
  if ! (ulimit -f 32768;/usr/sbin/native-safe-fetch "$FOREIGN_SOURCE_URL" "$dir/foreign.conf" 16777216);then
   state failed '大陆以外域名源下载失败，两组域名库保持原版本';return 1
  fi
 else : > "$dir/foreign.conf";fi
 # Supplements belong only to the built-in composite sources. Custom sources
 # stay independent. One failed download rejects the entire two-library update.
 local extra_url extra_file
 for extra in DOMAIN FOREIGN;do
  if [ "$extra" = DOMAIN ];then extra_url="$DOMAIN_EXTRA_URL";extra_file="$dir/cn-extra.txt";else extra_url="$FOREIGN_EXTRA_URL";extra_file="$dir/foreign-extra.txt";fi
  [ -n "$extra_url" ] || continue
  state running '正在下载默认综合库的补充来源'
  if ! (ulimit -f 32768;/usr/sbin/native-safe-fetch "$extra_url" "$extra_file" 16777216);then
   state failed '补充源下载失败，两组域名库保持原版本';return 1
  fi
  if [ "$extra" = DOMAIN ];then export DOMAIN_EXTRA_FILE="$extra_file";else export FOREIGN_EXTRA_FILE="$extra_file";fi
 done
 mkdir "$dir/candidate"
 state running '正在校验域名格式、数量和内容'
 version=$(/usr/bin/ikluajit /usr/ikuai/script/domain_lib.lua build "$dir/domains.conf" "$dir/candidate" "$dir/foreign.conf") || { state failed '域名库校验失败，继续使用原有域名库';return 1; }
 [[ "$version" =~ ^[a-f0-9]{64}$ ]] || { state failed '数据库版本无效';return 1; }
 candidate="$HOME_DIR/versions/$version"
 if [ -d "$candidate" ];then /usr/bin/ikluajit /usr/ikuai/script/domain_lib.lua verify "$candidate" || { state failed '已存数据库损坏，更新未应用';return 1; };else mv "$dir/candidate" "$candidate" || { state failed '保存数据库失败';return 1; };fi
 state running '正在切换数据库并同步 域名及 DNS 分流规则'
 /usr/ikuai/script/strict_policy.sh domain_install "candidate=$candidate"  > "$dir/apply.log" 2>&1 || { cat "$dir/apply.log";state failed '应用失败，旧策略已恢复或保持阻断；请查看更新日志';return 1; }
 state success '域名库已更新，域名及 DNS 分流规则已同步'
 # Keep only the current and previous immutable snapshots. No user files reside here.
 local current=$(readlink "$HOME_DIR/current") old=$(readlink "$HOME_DIR/previous") p
 for p in "$HOME_DIR"/versions/*;do
  [[ "${p##*/}" =~ ^[a-f0-9]{64}$ ]] || continue
  [ "$p" = "$current" ] || [ "$p" = "$old" ] || rm -rf "$p"
 done
}
status() {
 mkdir -p "$TMP_DIR"
 . /usr/ikuai/script/domain_runtime.sh
 local root="$HOME_DIR/current" pid alive=false rollback=false
 [ -L "$root" ] || root=/usr/share/strict-routing
 pid=$(cat "$TMP_DIR/job.lock/pid" 2>/dev/null)
 [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null || alive=true
 [ ! -L "$HOME_DIR/previous" ] || rollback=true
 [ -f "$TMP_DIR/status.json" ] || cp "$HOME_DIR/last-job.json" "$TMP_DIR/status.json" 2>/dev/null || true
 local result
 result=$(/usr/bin/ikluajit /usr/ikuai/script/domain_lib.lua status "$root/domain-manifest.json" "$TMP_DIR/status.json" "$rollback" "$alive" "$(dm_current)") || return 1
 source_status "$result"
}
