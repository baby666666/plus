#!/bin/bash /etc/ikcommon
Include interface.sh iproute.sh ipset.sh iptables.sh
CONF=/etc/mnt/ikuai/native-routing.json
STATE=/tmp/iktmp/strict-routing
NR=/tmp/iktmp/native-rules
. /usr/ikuai/script/native_runtime.sh
. /usr/ikuai/script/native_shadow.sh
. /usr/ikuai/script/region_runtime.sh
. /usr/ikuai/script/domain_runtime.sh
ensure_conf(){
 mkdir -p "$STATE" "$NR" /etc/mnt/ikuai
 [ -s "$CONF" ] || printf '%s\n' '{"version":2,"enabled":true,"domain_overrides":[],"foreign_domains":[]}' > "$CONF"
 if [ ! -f "$NR/schema" ];then
  local table col
  for table in stream_domain stream_ipport;do
   sqlite3 "$IK_DB_CONFIG" "pragma table_info($table);" | grep -q '|nr_ingress|' || sqlite3 "$IK_DB_CONFIG" "alter table $table add column nr_ingress text default '';" || return 1
  done
  sqlite3 "$IK_DB_CONFIG" 'pragma table_info(stream_domain);'|grep -q '|nr_group|' || sqlite3 "$IK_DB_CONFIG" "alter table stream_domain add column nr_group text default 'manual';" || return 1
  sqlite3 "$IK_DB_CONFIG" 'pragma table_info(stream_domain);'|grep -q '|nr_dns|' || sqlite3 "$IK_DB_CONFIG" "alter table stream_domain add column nr_dns text default '1.1.1.1';" || return 1
  sqlite3 "$IK_DB_CONFIG" 'pragma table_info(stream_domain);'|grep -q '|nr_route|' || sqlite3 "$IK_DB_CONFIG" "alter table stream_domain add column nr_route text default 'fixed';" || return 1
  sqlite3 "$IK_DB_CONFIG" 'pragma table_info(stream_ipport);'|grep -q '|nr_stage|' || sqlite3 "$IK_DB_CONFIG" "alter table stream_ipport add column nr_stage integer default 0;" || return 1
  sqlite3 "$IK_DB_CONFIG" 'pragma table_info(stream_domain);'|grep -q '|nr_app|' || sqlite3 "$IK_DB_CONFIG" "alter table stream_domain add column nr_app text default '';" || return 1
  sqlite3 "$IK_DB_CONFIG" 'pragma table_info(stream_domain);'|grep -q '|nr_app_first|' || sqlite3 "$IK_DB_CONFIG" "alter table stream_domain add column nr_app_first integer default 0;" || return 1
  sqlite3 "$IK_DB_CONFIG" 'pragma table_info(stream_domain);'|grep -q '|nr_target|' || sqlite3 "$IK_DB_CONFIG" "alter table stream_domain add column nr_target text default 'any';" || return 1
  retire_app_rules || return 1
  touch "$NR/schema"
 fi
 # A restored config database can predate protocol ingress while /tmp survives.
 if ! sqlite3 "$IK_DB_CONFIG" 'pragma table_info(stream_layer7);' | grep '|nr_ingress|' >/dev/null;then
  sqlite3 -cmd '.timeout 10000' "$IK_DB_CONFIG" "ALTER TABLE stream_layer7 ADD COLUMN nr_ingress TEXT DEFAULT '';" ||
   sqlite3 "$IK_DB_CONFIG" 'pragma table_info(stream_layer7);' | grep '|nr_ingress|' >/dev/null || return 1
 fi
 # Domain rules without a binding field have an implicit fixed exit. Preserve
 # behavior exactly once; newly created rules use the native unbound default.
 # Keep this versioned check separate from the older in-memory schema marker.
 if [ ! -f "$NR/schema-exit-policy" ] || ! sqlite3 "$IK_DB_CONFIG" 'pragma table_info(stream_domain);' | grep -q '|iface_band|';then
  if ! sqlite3 "$IK_DB_CONFIG" 'pragma table_info(stream_domain);' | grep -q '|iface_band|';then
   sqlite3 -cmd '.timeout 10000' "$IK_DB_CONFIG" "BEGIN IMMEDIATE; ALTER TABLE stream_domain ADD COLUMN iface_band INTEGER DEFAULT 0; UPDATE stream_domain SET iface_band=1; COMMIT;" || {
    # Another management request may have completed the same atomic migration.
    # Never replay the UPDATE against already explicit choices.
    sqlite3 "$IK_DB_CONFIG" 'pragma table_info(stream_domain);' | grep -q '|iface_band|' || return 1
   }
  fi
  sqlite3 "$IK_DB_CONFIG" 'pragma table_info(nr_retired_app_rules);' | grep -q '|iface_band|' || sqlite3 "$IK_DB_CONFIG" "ALTER TABLE nr_retired_app_rules ADD COLUMN iface_band INTEGER DEFAULT 1;" || return 1
  touch "$NR/schema-exit-policy"
 fi
}
# Archive only retired domain-app rows in the same durable SQLite transaction.
# Never expand them into regional overrides or mutate native protocol/port rules.
retire_app_rules(){
 local columns
 sqlite3 "$IK_DB_CONFIG" "CREATE TABLE IF NOT EXISTS nr_retired_app_rules AS SELECT *, '' AS retired_at FROM stream_domain WHERE 0;" || return 1
 sqlite3 "$IK_DB_CONFIG" 'pragma table_info(nr_retired_app_rules);'|grep -q '|nr_target|' || sqlite3 "$IK_DB_CONFIG" "alter table nr_retired_app_rules add column nr_target text default 'any';" || return 1
 if sqlite3 "$IK_DB_CONFIG" 'pragma table_info(stream_domain);' | grep -q '|iface_band|';then
  sqlite3 "$IK_DB_CONFIG" 'pragma table_info(nr_retired_app_rules);' | grep -q '|iface_band|' || sqlite3 "$IK_DB_CONFIG" "ALTER TABLE nr_retired_app_rules ADD COLUMN iface_band INTEGER DEFAULT 1;" || return 1
 fi
 columns=$(sqlite3 "$IK_DB_CONFIG" "pragma table_info(stream_domain);" | awk -F '|' '{s=s sep $2;sep=","}END{print s}') || return 1
 sqlite3 -cmd '.timeout 10000' "$IK_DB_CONFIG" "BEGIN IMMEDIATE;
 CREATE TABLE IF NOT EXISTS nr_retired_app_rules AS SELECT *, '' AS retired_at FROM stream_domain WHERE 0;
 INSERT INTO nr_retired_app_rules($columns,retired_at) SELECT $columns, datetime('now') FROM stream_domain WHERE nr_group='app';
 DELETE FROM stream_domain WHERE nr_group='app';
 UPDATE stream_domain SET nr_app='',nr_app_first=0 WHERE coalesce(nr_app,'')!='' OR coalesce(nr_app_first,0)!=0;
 COMMIT;" || return 1
}

lock_action(){
 local n owner
 for n in $(seq 1 600);do
  if mkdir "$STATE/lock" 2>/dev/null;then echo $$ > "$STATE/lock/pid";trap 'cleanup_staged;rm -rf "$STATE/lock"' EXIT;return 0;fi
  owner=$(cat "$STATE/lock/pid" 2>/dev/null)
  if [ "$owner" ] && ! kill -0 "$owner" 2>/dev/null;then rm -rf "$STATE/lock";fi
  sleep .1
 done
 echo '另一项规则或数据库操作尚未完成';return 1
}
guard(){
 local hold_dns="${1:-0}" preserve_file="${2:-}" dev mark rest value
 local -a preserved_marks=()
 # Only the strict delta caller supplies these marks. Route plans, address
 # groups and worker identity must match. History may expand this list only
 # when neither generation has native selectors and every DNS set is retained.
 if [ "$hold_dns" = 1 ] && [ -n "$preserve_file" ];then
  [ -f "$preserve_file" ] || return 1
  while read -r mark rest;do
   [ -z "$rest" ] && [ "${#mark}" -le 10 ] || return 1
   case "$mark" in ''|*[!0-9]*) return 1;;esac
   value=$((10#$mark))
   [ "$value" -le 4294967295 ] || return 1
   if [ "$((value & 4278190080))" != 1426063360 ] &&
      [ "$((value & 4278190080))" != 1476395008 ] &&
      [ "$((value & 4294963200))" != 3010560 ] &&
      [ "$((value & 4278190080))" != 1392508928 ];then return 1;fi
   preserved_marks+=("$value")
   [ "${#preserved_marks[@]}" -le 1024 ] || return 1
  done < "$preserve_file"
 fi
 mkdir -p "$NR"
 nr_ipv6 1 || return 1
 nr_ipt -t mangle -N NR_GUARD 2>/dev/null || true
 nr_ipt -t mangle -C PREROUTING -j NR_GUARD 2>/dev/null || nr_ipt -t mangle -I PREROUTING 1 -j NR_GUARD || return 1
 nr_ipt -N NR_FORWARD_GUARD 2>/dev/null || true
 nr_ipt -N NR_OUT_GUARD 2>/dev/null || true
 nr_hook filter FORWARD NR_FORWARD_GUARD || return 1
 nr_hook filter OUTPUT NR_OUT_GUARD || return 1
 {
  printf '%s\n' '*filter' '-F NR_FORWARD_GUARD' '-F NR_OUT_GUARD'
  for mark in "${preserved_marks[@]}";do
   printf '%s\n' "-A NR_FORWARD_GUARD -m conntrack --ctstate ESTABLISHED -m connmark --mark $mark/0xffffffff -j RETURN"
  done
  for dev in $NR_IFACES;do printf '%s\n' "-A NR_FORWARD_GUARD -i $dev -j DROP";done
  # A strict membership delta cannot change worker identity, DNS endpoint,
  # marks, routing or the permanent NR_OUTPUT exit guard. Keep already issued
  # upstream queries alive; the acknowledged front barrier holds their replies.
  if [ "$hold_dns" != 1 ];then printf '%s\n' '-A NR_OUT_GUARD -m owner --uid-owner 48201-48232 ! -o lo -j DROP';fi
  printf '%s\n' COMMIT
 } | iptables-restore -w 5 -n || return 1
 {
  printf '%s\n' '*mangle' '-F NR_GUARD'
  for mark in "${preserved_marks[@]}";do
   printf '%s\n' "-A NR_GUARD -m conntrack --ctstate ESTABLISHED -m connmark --mark $mark/0xffffffff -j RETURN"
  done
  for dev in $NR_IFACES;do
   # Only an unchanged DNS admission plan may queue queries at the live
   # front's acknowledged reply barrier. New and affected flows remain blocked.
   if [ "$hold_dns" = 1 ];then
    printf '%s\n' "-A NR_GUARD -i $dev -p udp --dport 53 -j RETURN" "-A NR_GUARD -i $dev -p tcp --dport 53 -j RETURN"
   else
    printf '%s\n' "-A NR_GUARD -i $dev -p udp --dport 53 -j DROP" "-A NR_GUARD -i $dev -p tcp --dport 53 -j DROP"
   fi
   printf '%s\n' "-A NR_GUARD -i $dev -m addrtype ! --dst-type LOCAL -j DROP"
  done
  printf '%s\n' COMMIT
 } | iptables-restore -w 5 -n
}
unguard(){
 [ ! -f "$NR/boot.pending" ] || return 0
 printf '%s\n' '*mangle' '-F NR_GUARD' COMMIT '*filter' '-F NR_OUT_GUARD' '-F NR_FORWARD_GUARD' COMMIT | iptables-restore -w 5 -n
}
snapshot(){
 local dest="${1:-$NR/active}"
 /usr/bin/lua /usr/ikuai/script/native_snapshot.lua "$IK_DB_CONFIG" "$dest/snapshot.json" || return 1
 cp "$CONF" "$dest/settings.json"
}
stop_dns(){
 local f pid
 for f in "$NR/active/"*.pid;do
  [ -f "$f" ] || continue;pid=$(cat "$f")
  if [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' < "/proc/$pid/cmdline"|grep -Eq 'native-rule-dns|strict-dnsmasq';then kill "$pid" 2>/dev/null || true;fi
 done
 for n in $(seq 1 20);do
  local live=0;for f in "$NR/active/"*.pid;do [ -f "$f" ] || continue;pid=$(cat "$f");[ ! -r "/proc/$pid/cmdline" ] || live=1;done
  [ "$live" = 0 ] && break;sleep .1
 done
 [ "$live" = 0 ] || return 1
 rm -f "$NR/active/"*.pid
}
stop_workers(){
 local f pid n live
 for f in "$NR/active/"dns-*.pid;do
  [ -f "$f" ] || continue;pid=$(cat "$f")
  if [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' < "/proc/$pid/cmdline"|grep -q strict-dnsmasq;then kill "$pid" 2>/dev/null || true;fi
 done
 for n in $(seq 1 50);do
  live=0;for f in "$NR/active/"dns-*.pid;do [ -f "$f" ] || continue;pid=$(cat "$f");[ ! -r "/proc/$pid/cmdline" ] || live=1;done
  [ "$live" != 0 ] || { rm -f "$NR/active/"dns-*.pid;return 0; };sleep .1
 done
 return 1
}
restart_changed_workers(){
 local pending="$NR/worker-restart.ids" wid pid config n executable
 [ -s "$pending" ] || return 0
 sort -u "$pending" > "$pending.next" && mv "$pending.next" "$pending" || return 1
 while [ -s "$pending" ];do
  read -r wid < "$pending"
  [[ "$wid" =~ ^[0-9]+$ ]] && [ "$wid" -ge 1 ] && [ "$wid" -le 32 ] || return 1
  awk -v id="$wid" '$1==id{found=1}END{exit !found}' "$NR/policy-workers" || return 1
  config="$NR/active/dns-$wid.conf"
  /usr/sbin/strict-dnsmasq --test -C "$config" >> "$NR/dns.log" 2>&1 || return 1
  pid=$(cat "$NR/active/dns-$wid.pid" 2>/dev/null)
  [ -z "$pid" ] || [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ];then
   # A stale PID file must never authorize killing another process.
   read -r -d '' executable < "/proc/$pid/cmdline"
   [ "$executable" = /usr/sbin/strict-dnsmasq ] || return 1
   tr '\0' '\n' < "/proc/$pid/cmdline" | grep -Fx "$config" >/dev/null || return 1
   kill "$pid" 2>/dev/null || return 1
   for n in $(seq 1 50);do [ ! -r "/proc/$pid/cmdline" ] && break;sleep .1;done
   [ ! -r "/proc/$pid/cmdline" ] || return 1
  fi
  rm -f "$NR/active/dns-$wid.pid"
  /usr/sbin/strict-dnsmasq -C "$config" >> "$NR/dns.log" 2>&1 || return 1
  pid=$(cat "$NR/active/dns-$wid.pid" 2>/dev/null)
  [[ "$pid" =~ ^[0-9]+$ ]] && [ -r "/proc/$pid/cmdline" ] || return 1
  read -r -d '' executable < "/proc/$pid/cmdline"
  [ "$executable" = /usr/sbin/strict-dnsmasq ] || return 1
  tr '\0' '\n' < "/proc/$pid/cmdline" | grep -Fx "$config" >/dev/null || return 1
  # Complete one worker at a time. A later failure retries only pending IDs.
  sed '1d' "$pending" > "$pending.next" && mv "$pending.next" "$pending" || return 1
 done
 rm -f "$pending"
}
start_workers(){
 # Basic WG DNS must not depend on the presence of domain rules. Unmatched
 # queries use system resolvers and normal routing. Matched queries use the
 # rule's own exit policy, including its explicit line-binding choice.
 grep -q '^nrbase:' /etc/passwd || printf 'nrbase:x:48300:0:Native default DNS:/nonexistent:/bin/false\n' >> /etc/passwd
 cat > "$NR/active/dns-base.conf" <<EOF
port=6199
listen-address=127.0.0.1
bind-interfaces
no-hosts
resolv-file=/etc/resolv.conf
cache-size=256
max-tcp-connections=64
fast-dns-retry=750,4000
max-ttl=60
max-cache-ttl=60
user=nrbase
group=root
pid-file=$NR/active/dns-base.pid
log-facility=$NR/active/dns-base.log
EOF
 /usr/sbin/strict-dnsmasq --test -C "$NR/active/dns-base.conf" || return 1
 /usr/sbin/strict-dnsmasq -C "$NR/active/dns-base.conf" || return 1
 local id
 while read -r id;do
  [ "$id" ] || continue
  /usr/sbin/strict-dnsmasq --test -C "$NR/active/dns-$id.conf" || return 1
  /usr/sbin/strict-dnsmasq -C "$NR/active/dns-$id.conf" || return 1
 done < "$NR/active/dns-ids"
}
start_dns(){
 start_workers || return 1
 rm -f "$NR/active/front.ready"
 export TZ=$(cat /etc/TZ)
 NR_DNS_GLOBAL="$NR/active/dns-global.rules" NR_DNS_CONTROL="$NR/dns.control" /usr/sbin/native-rule-dns "$NR/active/dns-transition.rules" "$NR/active/front.ready" "$NR/active/dns-bindings" >> "$NR/dns.log" 2>&1 &
 local pid=$! n;unset NR_EVIDENCE_EMPTY;echo "$pid" > "$NR/active/front.pid"
 for n in $(seq 1 200);do kill -0 "$pid" 2>/dev/null || return 1;[ ! -f "$NR/active/front.ready" ] || return 0;sleep .1;done
 return 1
}
old_engine_off(){
 local pid f spec
 if [ -f /etc/mnt/ikuai/strict-routing.json ] && [ "$(jq -r .enabled /etc/mnt/ikuai/strict-routing.json)" = true ];then
  native_migrate || return 1
 fi
 pid=$(cat "$STATE/monitor.pid" 2>/dev/null);[ ! "$pid" ] || kill "$pid" 2>/dev/null || true
 for f in "$STATE/active/"*.pid;do [ -f "$f" ] || continue;pid=$(cat "$f");if [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' < "/proc/$pid/cmdline"|grep -q strict-dnsmasq;then kill "$pid" 2>/dev/null || true;fi;done
 for spec in 'mangle PREROUTING SP_SCOPE' 'mangle OUTPUT SP_OUT' 'mangle FORWARD SP_FAST' 'filter FORWARD SP_FWD' 'filter INPUT SP_DNSIN' 'filter OUTPUT SP_DNSOUT' 'nat PREROUTING SP_DNS' 'nat POSTROUTING SP_NAT';do set -- $spec;while nr_ipt -t "$1" -D "$2" -j "$3" 2>/dev/null;do :;done;done
 nr_ipt -t mangle -F SP_GUARD 2>/dev/null || true;nr_ipt -F SP_OUT_GUARD 2>/dev/null || true
 ik_cntl url_route disable >/dev/null 2>&1
 : > /tmp/iktmp/.stream_domain
}
compiler_request(){
 local pid n signature reply
 signature=$(sha256sum /usr/ikuai/script/{native_rules,native_index,domain_lib,domain_allowlist,native_compiler}.lua | sha256sum | cut -d' ' -f1) || return 1
 pid=$(cat "$NR/compiler.pid" 2>/dev/null)
 if [ "$pid" ] && [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' < "/proc/$pid/cmdline"|grep -q native_compiler.lua && [ "$(cat "$NR/compiler.signature" 2>/dev/null)" != "$signature" ];then
  kill -CONT "$pid" 2>/dev/null || true;kill "$pid" 2>/dev/null || true
  for n in $(seq 1 100);do [ ! -r "/proc/$pid/cmdline" ] && break;sleep .05;done
  [ ! -r "/proc/$pid/cmdline" ] || return 1
 fi
 if [ ! "$pid" ] || [ ! -r "/proc/$pid/cmdline" ] || ! tr '\0' ' ' < "/proc/$pid/cmdline"|grep -q native_compiler.lua;then
  rm -f "$NR/compiler.pid"
  NATIVE_COMPILER_SIGNATURE="$signature" /usr/sbin/native-work-run /usr/bin/ikluajit /usr/ikuai/script/native_compiler.lua </dev/null >> "$NR/compiler.log" 2>&1 &
  for n in $(seq 1 100);do [ ! -s "$NR/compiler.pid" ] || break;sleep .05;done
 fi
 pid=$(cat "$NR/compiler.pid" 2>/dev/null)
 [ "$pid" ] && kill -0 "$pid" 2>/dev/null || return 1
 if reply=$(NR_CONTROL_TIMEOUT=300 /usr/sbin/native-rule-dns --control "$NR/compiler.sock" "$@");then
  printf '%s\n' "$reply";return 0
 else
  printf '%s\n' "$reply"
  # A bounded ERR packet is sent only after pcall and cleanup have finished.
  # Keep validated caches after a rejected edit; no writer is outstanding.
  case "$reply" in 'ERR '*) return 1;;esac
  # Never rebuild/delete candidate while an unacknowledged worker may write it.
  kill -CONT "$pid" 2>/dev/null || true;kill "$pid" 2>/dev/null || true
  for n in $(seq 1 100);do [ ! -r "/proc/$pid/cmdline" ] && return 1;sleep .05;done
  kill -KILL "$pid" 2>/dev/null || true;return 1
 fi
}
compile_resident(){
 compiler_request COMPILE "$$-${RANDOM}" "$1" "$NR/active" "$STRICT_DOMAIN_ROOT" "$NATIVE_DECODE_CACHE"
}
# Compile into a private generation while the previous generation keeps serving.
# Callers hold STATE/lock across prepare and commit, including subscription edits.
prepare_config(){
 local next="$1" reuse_snapshot="${NR_PREPARED_SNAPSHOT:-}"
 [ ! -f "$RG_HOME/pending" ] || [ "${RG_TRANSACTION:-0}" = 1 ] || return 1
 [ ! -f "$DM_HOME/pending" ] || [ "${DM_TRANSACTION:-0}" = 1 ] || return 1
 # Legacy migration changes the authoritative snapshot; finish it before compile.
 if [ -f /etc/mnt/ikuai/strict-routing.json ] && [ "$(jq -r .enabled /etc/mnt/ikuai/strict-routing.json)" = true ];then
  guard && native_migrate || return 1
  reuse_snapshot=''
 fi
 cleanup_staged || return 1
 rm -rf "$next";mkdir -p "$next" "$STATE/active"
 date +%s > "$next/prepare-times"
 retire_app_rules || return 1
 snapshot "$next" || return 1
 export STRICT_DOMAIN_ROOT=$(dm_current)
 export NATIVE_DECODE_CACHE="$NR/domain-decoded.json"
 compile_resident "$next" || return 1
 date +%s >> "$next/prepare-times"
 if ! /usr/sbin/native-work-run /usr/sbin/native-group-plan "$next" "$NR/native-loaded.map";then
  /usr/sbin/native-work-run /usr/sbin/native-group-plan "$next" || return 1
  touch "$next/cold-native"
 fi
 date +%s >> "$next/prepare-times"
 if [ -f "$NR/active/dns-transition.rules" ] && cmp -s "$NR/active/dns-global.rules" "$next/dns-global.rules";then
  NR_COMPACT_TRANSITION=1 /usr/sbin/native-work-run /usr/bin/ikluajit /usr/ikuai/script/native_transition.lua "$NR/active/dns-transition.rules" "$next/dns-transition.rules" "$next/dns-preserve.ids" "$next/dns-changed.patterns" || return 1
 elif [ -f "$NR/active/dns-transition-regional.rules" ] && cmp -s "$NR/active/dns-base.version" "$next/dns-base.version";then
  # The large mainland base is immutable here; compare only manual additions
  # from both immutable regional libraries. Removing an entry still invalidates
  # that category's existing flows, even when no DNS history is available.
  NR_COMPACT_REGIONAL=1 /usr/sbin/native-work-run /usr/bin/ikluajit /usr/ikuai/script/native_transition.lua "$NR/active/dns-transition-regional.rules" "$next/dns-transition-regional.rules" "$next/dns-preserve.ids" "$next/dns-changed.patterns" || return 1
 else
  # Regional/manual classification edits need their exact changed names,
  # otherwise an unrelated addition quarantines every client's address for 61s.
  # The transition verifier still rejects changed rule order, scope or metadata.
  /usr/sbin/native-work-run /usr/bin/ikluajit /usr/ikuai/script/native_transition.lua "$NR/active/dns.rules" "$next/dns.rules" "$next/dns-preserve.ids" "$next/dns-changed.patterns" || return 1
 fi
 date +%s >> "$next/prepare-times"
 # This list is deliberately captured before DNS history refinement: history
 # can preserve address sets, but cannot prove every existing flow's hostname.
 cp "$next/dns-preserve.ids" "$next/flow-preserve.ids" || return 1
 awk 'FILENAME==ARGV[1]{keep[$1]=1;next} ($1 in keep){print $2;if($3>0)print $3}' "$next/flow-preserve.ids" "$next/flow-marks" > "$next/flow-preserve.marks" || return 1
 # URL membership changes are serialized by STATE/lock; ordinary DNS learning
 # only updates address caches. Count before entering the global traffic guard.
 if [ "${NR_PREPARE_DELTA:-0}" != 1 ];then
  /usr/sbin/native-work-run /usr/sbin/native-url-count > "$next/native-count-before" || return 1
 fi
 date +%s >> "$next/prepare-times"
 # Resolver caches and learned addresses belong to both the domain policy
 # and its upstream/exit identity, not just the local worker port number.
 sed -n '/^nr_exit /p;/^nr_policy /p;/^nr_worker /p' "$next/apply.sh" > "$next/dns-worker.routes"
 { cat "$next/dns.rules" "$next/dns-worker.routes";local id;while read -r id;do [ ! "$id" ] || cat "$next/dns-$id.conf";done < "$next/dns-ids"; } | sha256sum | cut -d' ' -f1 > "$next/dns-signature"
}

# Only the dispatcher changes for membership-only updates. Keep identical
# upstream workers (and their caches) alive; prepare the replacement off-line.
dns_control(){ /usr/sbin/native-rule-dns --control "$NR/dns.control" "$@"; }
cleanup_staged(){
 local token status n
 [ -f "$NR/dns-stage.ticket" ] || return 0
 token=$(cat "$NR/dns-stage.ticket")
 if [ ! -S "$NR/dns.control" ];then rm -f "$NR/dns-stage.ticket";return 0;fi
 for n in $(seq 1 600);do
  status=$(dns_control STATUS "$token" 2>/dev/null)
  case "$status" in
   'OK preparing') sleep .1;;
   'OK paused') return 0;; # Kernel rollback must keep this reply barrier.
   'OK ready'|'ERR invalid-policy') dns_control ABORT "$token" >/dev/null || return 1;rm -f "$NR/dns-stage.ticket";return 0;;
   'OK committed'|'ERR ticket') rm -f "$NR/dns-stage.ticket";return 0;;
   *) return 1;;
  esac
 done
 return 1
}
stage_dns(){
 local next="$1" token status n
 cleanup_staged || return 1
 [ ! -f "$NR/dns-stage.ticket" ] || return 1
 token="$(date +%s)-$$-${RANDOM}"
 printf '%s\n' "$token" > "$NR/dns-stage.ticket"
 dns_control PREPARE "$token" "$next/dns-transition.rules" "$next/dns-global.rules" >/dev/null || return 1
 for n in $(seq 1 600);do
  status=$(dns_control STATUS "$token") || return 1
  [ "$status" != 'OK ready' ] || return 0
  [ "$status" = 'OK preparing' ] || return 1
  sleep .1
 done
 return 1
}
stop_front(){
 # Acknowledgement means no response can cross the kernel commit barrier.
 dns_control PAUSE "$(cat "$NR/dns-stage.ticket")" >/dev/null
}
activate_dns(){
 local token status
 token=$(cat "$NR/dns-stage.ticket")
 # Only the strict delta path preserves these exact kernel sets. Keep the
 # matching acknowledged tuples with their original ages; never extend TTLs.
 if [ "${NR_PRESERVE_EVIDENCE:-0}" = 1 ];then
  dns_control RETAIN "$token" "$NR/active/dns-preserve.ids" >/dev/null || return 1
 fi
 if ! dns_control COMMIT "$token" >/dev/null;then
  status=$(dns_control STATUS "$token") || return 1
  [ "$status" = 'OK committed' ] || return 1
 fi
 rm -f "$NR/dns-stage.ticket"
}
same_front(){
 local pid=$(cat "$NR/active/front.pid" 2>/dev/null)
 [ "$pid" ] && cmp -s "/proc/$pid/exe" /usr/sbin/native-rule-dns && [ "$(dns_control PING version 2>/dev/null)" = 'OK hot-v2' ]
}
same_workers(){
 local next="$1" id pid
 cmp -s "$next/dns-ids" "$NR/active/dns-ids" || return 1
 for id in $(cat "$next/dns-ids");do
  cmp -s "$next/dns-$id.conf" "$NR/active/dns-$id.conf" || return 1
 done
 for id in base $(cat "$next/dns-ids");do
  pid=$(cat "$NR/active/dns-$id.pid" 2>/dev/null)
  [ "$pid" ] && [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' < "/proc/$pid/cmdline"|grep -q strict-dnsmasq || return 1
 done
}

commit_config(){
 local next="$1" signature delta=0 hot=0 restart_workers=0 shadow_rc evidence_neutral=0
 export NR_SHADOW=0
 [ -s "$next/apply.sh" ] && [ -f "$next/dns-signature" ] || return 1
 signature=$(cat "$next/dns-signature")
 export NR_RESET=0
 [ "$(cat "$NR/dns-signature" 2>/dev/null)" = "$signature" ] || NR_RESET=1
 # Only exact kernel plans qualify. Group members are in separate files;
 # routes, marks, scopes, time windows and set definitions must be unchanged.
 local delta_reason=eligible
 if [ "${NR_ALLOW_DELTA:-0}" != 1 ];then delta_reason=transaction
 elif [ -f "$NR/commit.pending" ];then delta_reason=incomplete-commit
 elif [ -f "$NR/native-dirty" ] || [ -f "$NR/native-stage.pending" ];then delta_reason=native-dirty
 elif [ -f "$next/cold-native" ] || [ ! -s "$NR/active/delta.sh" ];then delta_reason=cold-native
 elif ! cmp -s "$next/apply.sh" "$NR/active/apply.sh";then delta_reason=kernel-plan
 elif ! cmp -s "$next/address-inputs.json" "$NR/active/address-inputs.json";then delta_reason=address-groups
 elif ! same_workers "$next";then delta_reason=workers
 elif ! same_front;then delta_reason=front
 elif ! /usr/ikuai/script/native_dns_bind.sh check;then delta_reason=bindings
 else delta=1;fi
 printf '%s\n' "$delta_reason" > "$NR/commit-delta-reason"
 # Keep DNS listener sockets across ordinary rule/exit edits. When worker
 # identities change, restart only upstream workers behind the reply barrier
 # and replay pending queries instead of releasing answers from old upstreams.
 if [ ! -f "$NR/commit.pending" ] && [ ! -f "$NR/native-dirty" ] &&
    [ ! -f "$NR/native-stage.pending" ] && same_front &&
    /usr/ikuai/script/native_dns_bind.sh check;then
  hot=1
  if ! same_workers "$next" || ! cmp -s <(sed -n '/^nr_exit /p;/^nr_policy /p;/^nr_worker /p' "$next/apply.sh") <(sed -n '/^nr_exit /p;/^nr_policy /p;/^nr_worker /p' "$NR/active/apply.sh");then restart_workers=1;NR_RESET=1;fi
 fi
 [ "$delta" != 1 ] || hot=1
 export NR_PRESERVE_EVIDENCE="$delta"
 printf '%s\n' "$delta" > "$NR/commit-delta"
 if [ "$hot" = 1 ];then stage_dns "$next" || return 1;fi
 printf '%s\n' "$hot" > "$NR/commit-hot-dns"
 if [ "$delta" = 1 ];then
  nr_shadow_stage "$next";shadow_rc=$?
  if [ "$shadow_rc" = 0 ];then export NR_SHADOW=1
  elif [ "$shadow_rc" != 3 ];then return 1;fi
 fi
 if [ "$NR_SHADOW" != 1 ] && [ ! -s "$next/native-count-before" ];then
  /usr/sbin/native-work-run /usr/sbin/native-url-count > "$next/native-count-before" || return 1
 fi
 date +%s > "$NR/commit-start"
 touch "$NR/commit.pending"
 if [ "$hot" = 1 ];then stop_front || return 1;fi
 if [ "$delta" = 1 ];then
  # PAUSE has durably published complete bounded name history. With no native
  # selectors in either generation, unchanged DNS address sets are the entire
  # domain classifier. An unused-name edit then changes no current packet's
  # route decision. Do not extend this proof to native URL learning or partial
  # history, and never retain sets containing a changed live name.
  /usr/bin/ikluajit /usr/ikuai/script/native_evidence.lua "$next/dns-changed.patterns" "$NR/active/front.ready.evidence" "$next/dns-preserve.ids" "$next/dns.rules" || return 1
  if [ -f "$next/dns-preserve.ids.all" ] && [ -f "$next/native-inputs" ] && [ ! -s "$next/native-inputs" ] && [ -f "$NR/active/native-inputs" ] && [ ! -s "$NR/active/native-inputs" ];then
   evidence_neutral=1
   cp "$next/dns-preserve.ids" "$next/flow-preserve.ids" || return 1
   awk 'FILENAME==ARGV[1]{keep[$1]=1;next} ($1 in keep){print $2;if($3>0)print $3}' "$next/flow-preserve.ids" "$next/flow-marks" > "$next/flow-preserve.marks" || return 1
  fi
 fi
 printf '%s\n' "$evidence_neutral" > "$NR/commit-evidence-neutral"
 guard "$delta" "$next/flow-preserve.marks" || return 1
 if [ "$delta" != 1 ];then
  /usr/ikuai/script/native_ingress.sh sync || return 1
  old_engine_off || return 1
 fi
 if [ "$hot" = 1 ];then
  /usr/ikuai/script/native_dns_bind.sh check || return 1
  [ "$restart_workers" != 1 ] || stop_workers || return 1
 else stop_dns || return 1;fi
 # Publish inside the guard. A delta keeps the DNS front and workers alive;
 # the front is at its acknowledged reply barrier until kernel activation.
 rm -rf "$NR/previous"
 [ ! -d "$NR/active" ] || mv "$NR/active" "$NR/previous" || return 1
 mv "$next" "$NR/active" || return 1
 [ ! -f "$NR/active/cold-native" ] || touch "$NR/native-dirty"
 if [ "$hot" = 1 ];then
  cp "$NR/previous/front.pid" "$NR/previous/front.ready" "$NR/active/" || return 1
  cp "$NR/previous/dns-bindings" "$NR/active/dns-bindings" || return 1
  if [ "$restart_workers" != 1 ];then cp "$NR/previous/"dns-*.pid "$NR/active/" || return 1;fi
  [ ! -f "$NR/previous/front.ready.evidence" ] || cp "$NR/previous/front.ready.evidence" "$NR/active/front.ready.evidence" || return 1
 fi
 export NR_KEEP_POLICY_WORKERS=0
 if [ "$hot" = 1 ] && [ "$restart_workers" != 1 ];then export NR_KEEP_POLICY_WORKERS=1;fi
 if [ "$delta" = 1 ];then
  /bin/bash /etc/ikcommon "$NR/active/delta.sh" > "$NR/apply.log" 2>&1 || { cat "$NR/apply.log";return 1; }
 else
  /usr/ikuai/script/native_dns_bind.sh prepare || return 1
  while nr_ipt -t nat -D PREROUTING -j NR_DNS 2>/dev/null;do :;done
  /bin/bash /etc/ikcommon "$NR/active/apply.sh" > "$NR/apply.log" 2>&1 || { cat "$NR/apply.log";return 1; }
 fi
 local keep_connections=0 connections_pruned=0
 # Native URL learning requires the conservative mark list. The additional
 # evidence-neutral case above is restricted to a DNS-only classifier with
 # every live address set unchanged; a changed active name cannot qualify.
 if [ "$delta" = 1 ] && { [ "$NR_RESET" = 0 ] || [ "$evidence_neutral" = 1 ]; };then keep_connections=1;fi
 if [ "$delta" = 1 ] && [ "$keep_connections" != 1 ];then
  /usr/sbin/native-conntrack-prune "$NR/active/flush-sources" "$NR/active/flow-preserve.marks" > "$NR/conntrack-prune.log" || return 1
  connections_pruned=1
 fi
 if [ "$hot" = 1 ];then
  if [ "$restart_workers" = 1 ];then start_workers >> "$NR/apply.log" 2>&1 || return 1;dns_control RESTART "$(cat "$NR/dns-stage.ticket")" >/dev/null || return 1;fi
  if [ "$restart_workers" != 1 ] && [ -s "$NR/worker-restart.ids" ];then
   restart_changed_workers >> "$NR/apply.log" 2>&1 || return 1
   dns_control RESTART "$(cat "$NR/dns-stage.ticket")" >/dev/null || return 1
  fi
  if [ "$delta" != 1 ] && [ "$NR_RESET" = 1 ];then dns_control RESET "$(cat "$NR/dns-stage.ticket")" >/dev/null || return 1;fi
  activate_dns >> "$NR/apply.log" 2>&1 || { cat "$NR/apply.log";return 1; }
 else
  # An identical DNS signature keeps address evidence even on a full apply.
  # Carry its bounded history too; otherwise the next membership edit must
  # quarantine unrelated addresses for lack of proof. Missing history remains
  # conservative in the dispatcher; a changed signature still resets all sets.
  if [ "$NR_RESET" = 0 ] && [ -f "$NR/previous/front.ready.evidence" ];then
   cp "$NR/previous/front.ready.evidence" "$NR/active/front.ready.evidence" || return 1
  fi
  # Full signature changes reset every evidence set before DNS is started.
  if [ "$NR_RESET" = 1 ];then export NR_EVIDENCE_EMPTY=1;else unset NR_EVIDENCE_EMPTY;fi
  start_dns >> "$NR/apply.log" 2>&1 || { cat "$NR/apply.log";return 1; }
 fi
 printf '%s\n' "$signature" > "$NR/dns-signature"
 if [ "$keep_connections" != 1 ] && [ "$connections_pruned" != 1 ];then
 conntrack -D --mark 0x2df000/0xfffff000 >/dev/null 2>&1 || true
 conntrack -D --mark 0x55000000/0xff000000 >/dev/null 2>&1 || true
 conntrack -D --mark 0x58000000/0xff000000 >/dev/null 2>&1 || true
 conntrack -D --mark 0x53000000/0xff000000 >/dev/null 2>&1 || true
 fi
 printf '%s\n' "$keep_connections" > "$NR/commit-preserved-connections"
 printf '%s\n' "$connections_pruned" > "$NR/commit-pruned-connections"
 rm -f "$NR/commit.pending" "$NR/policy-reconcile.failed"
 cp "$CONF" "$STATE/active/config.json"
 date +%s > "$NR/commit-finish"
 if [ "${SP_HOLD_GUARD:-0}" != 1 ] && [ ! -f "$NR/boot.pending" ];then unguard;nr_shadow_retire || { guard;return 1; };start_monitor;fi
}
apply_config(){
 local next="$NR/candidate"
 # Ordinary settings edits also qualify for the existing strict delta path.
 # commit_config still compares the complete kernel plan, groups, bindings
 # and worker identities. Region transactions change live ipsets separately
 # and must retain their full guard/rebuild path.
 local NR_PREPARE_DELTA=1 NR_ALLOW_DELTA=1
 [ "${RG_TRANSACTION:-0}" != 1 ] || NR_ALLOW_DELTA=0
 export NR_PREPARE_DELTA NR_ALLOW_DELTA
 prepare_config "$next" || return 1
 commit_config "$next"
}

apply(){ ensure_conf || return 1;lock_action || return 1;apply_config "$CONF"; }
early_guard(){ ensure_conf || return 1;local n=$(sqlite3 "$IK_DB_CONFIG" "select (select count(*) from stream_ipport where enabled='yes')+(select count(*) from stream_domain where enabled='yes')+(select count(*) from stream_layer7 where enabled='yes');");[ "$(jq -r .enabled /etc/mnt/ikuai/strict-routing.json 2>/dev/null)" != true ] || n=1;[ "$(jq -r .encrypted_dns.enabled "$CONF" 2>/dev/null)" != true ] || n=1;[ "${n:-0}" = 0 ] || { touch "$NR/boot.pending";guard; }; }
boot(){ ensure_conf || return 1;guard;local n=$(sqlite3 "$IK_DB_CONFIG" "select count(*) from stream_domain where enabled='yes';");[ "$(jq -r .enabled /etc/mnt/ikuai/strict-routing.json 2>/dev/null)" != true ] || n=1;[ "${n:-0}" = 0 ] || sleep 61;rm -f "$NR/boot.pending";apply; }
start_monitor(){ local pid=$(cat "$NR/monitor.pid" 2>/dev/null);if [ "$pid" ] && [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' < "/proc/$pid/cmdline"|grep -q 'native_rules.sh monitor';then return;fi;/usr/ikuai/script/native_rules.sh monitor >/dev/null 2>&1 & echo $! > "$NR/monitor.pid"; }
monitor(){ while sleep 3;do [ ! -d "$STATE/lock" ] || continue;/usr/ikuai/script/native_rules.sh reconcile >/dev/null 2>&1;done; }
# A lost local-reply filter can leave a WG handshake alive while bound DNS
# and health sockets never receive replies. Audit only failed WG exits, at
# most four per pass, oldest attempt first. Successful checks wait 30 seconds;
# failures remain eligible on the next pass and a new ifindex bypasses the wait.
# A healthy exit adds no tc scans or probes.
# The ingress helper validates live kernel state and writes only differences.
nr_failed_ingress_reconcile(){
 [ -f "$NR/exit-health" ] && [ -f "$NR/exits" ] || return 0
 local failed now iface stamp age ifindex saved_index result extra queue= priority count=0 was_failed pending_failures=0
 failed=$(awk 'FNR==NR{if($2==0&&$3==1)bad[$1]=1;next}
  bad[$1]&&$2~/^wg[0-9]+$/&&$2==$3&&$4==1&&!seen[$2]++{print $2}' "$NR/exit-health" "$NR/exits") || return 1
 [ -n "$failed" ] || return 0
 now=$(awk '{printf "%.0f\n",$1}' /proc/uptime) || return 1
 case "$now" in ''|*[!0-9]*) return 1;;esac
 mkdir -p "$NR/ingress-recovery" || return 1
 while read -r iface;do
  [ -e "/sys/class/net/$iface" ] || continue
  read -r ifindex < "/sys/class/net/$iface/ifindex" || return 1
  case "$ifindex" in ''|*[!0-9]*|0) return 1;;esac
  stamp= saved_index= result= extra= priority=0 was_failed=0
  read -r stamp saved_index result extra 2>/dev/null < "$NR/ingress-recovery/$iface" || true
  if [ "$result" = 0 ] && [ -n "$saved_index" ] && [ -z "$extra" ];then
   was_failed=1;pending_failures=$((pending_failures+1))
  fi
  case "$stamp" in ''|*[!0-9]*) ;; *)
   if [ "${#stamp}" -le 12 ] && [ "$saved_index" = "$ifindex" ] && [ -z "$extra" ] && { [ "$result" = 0 ] || [ "$result" = 1 ]; };then
    age=$((now-10#$stamp))
    if [ "$age" -ge 0 ];then
     [ "$result" != 1 ] || [ "$age" -ge 30 ] || continue
     priority=$stamp
    fi
   fi;;
  esac
  queue="$queue$priority $iface $ifindex $was_failed
"
 done <<< "$failed"
 [ -n "$queue" ] || return 0
 queue=$(printf '%s' "$queue" | sort -n) || return 1
 while read -r priority iface ifindex was_failed;do
  result=0
  /usr/ikuai/script/native_ingress.sh up "$iface" && result=1
  # Record failed attempts too, without suppressing their next retry. This
  # prevents a persistently broken first interface from starving other exits.
  printf '%s %s %s\n' "$now" "$ifindex" "$result" > "$NR/ingress-recovery/$iface" || return 1
  [ "$result" = 1 ] || return 1
  pending_failures=$((pending_failures-was_failed))
  count=$((count+1));[ "$count" -lt 4 ] || break
 done <<< "$queue"
 # Successful work on other exits must not release a guard while a previous
 # failed repair is still waiting for its turn in the bounded queue.
 [ "$pending_failures" = 0 ]
}
reconcile(){
 ensure_conf;lock_action || return 1
 # An incomplete kernel commit must never be unguarded by a DNS-only
 # restart. The transaction performs rollback; a failed rollback stays closed
 # until an explicit apply/boot, avoiding a costly compile loop every 3s.
 [ ! -f "$NR/commit.pending" ] && [ ! -f "$NR/native-dirty" ] && [ ! -f "$NR/native-stage.pending" ] || { guard;return 1; }
 local pid f bad=0 id iface dev available wg_globals_ready=0 route_snapshot
 /usr/ikuai/script/native_dns_bind.sh check || { apply_config "$CONF";return; }
 [ ! -f "$RG_HOME/pending" ] && [ ! -f "$DM_HOME/pending" ] || { guard;return 1; }
 while read -r id iface dev available;do
  if [ "$available" = 0 ] && grep -Eq "[[:space:]]${iface}([[:space:]]|$)" /etc/iproute2/rt_tables;then apply_config "$CONF";return;fi
  case "$iface" in wg[0-9]*)
  if { [ "$iface" != "$dev" ] || [ -r /tmp/iktmp/wg-pure-routing/map ]; } &&
     [ "$(nr_wg_egress_device "$iface")" != "$dev" ];then apply_config "$CONF";return;fi
  if [ -e "/sys/class/net/$iface" ];then
   [ "$(wg show "$iface" fwmark)" != off ] || wg set "$iface" fwmark 0x56000000
   if [ "$wg_globals_ready" = 0 ];then
    nr_ipt -t mangle -C NR_OUT -m mark --mark 0x56000000 -j RETURN 2>/dev/null || nr_ipt -t mangle -I NR_OUT 1 -m mark --mark 0x56000000 -j RETURN || { touch "$NR/policy-reconcile.failed";guard;return 1; }
    nr_ipt -C NR_OUTPUT -m mark --mark 0x56000000 -j RETURN 2>/dev/null || nr_ipt -I NR_OUTPUT 1 -m mark --mark 0x56000000 -j RETURN || { touch "$NR/policy-reconcile.failed";guard;return 1; }
    wg_globals_ready=1
   fi
   ip -o link show "$iface"|grep -q '[,<]UP[,>]' && ip route replace default dev "$iface" table "$iface" metric 100
  fi;;esac;done < "$NR/exits"
 # Kernel reloads can lose rules while our plan/cache files remain intact.
 # Share one fresh route inventory and repair only the active plan's owned
 # state before probing. Failed reads/repairs must not publish a usable exit.
 if ! route_snapshot=$(ip rule show) || ! nr_failed_ingress_reconcile ||
    ! nr_probe_owner_routes_sync "$route_snapshot" || ! nr_wg_transport_sync "$route_snapshot";then
  touch "$NR/policy-reconcile.failed";guard;return 1
 fi
 # Refresh only this plan's exit choices and unbound recovery connections.
 # Bound policies and the physical probe UIDs keep their terminal guards.
 if ! nr_policy_reconcile || ! restart_changed_workers;then
  touch "$NR/policy-reconcile.failed";guard;return 1
 fi
 local front="$NR/active/front.pid $NR/active/dns-base.pid"
 for f in $front $(sed "/^[0-9]/!d;s|^|$NR/active/dns-|;s|$|.pid|" "$NR/active/dns-ids");do pid=$(cat "$f" 2>/dev/null);if [ ! "$pid" ] || [ ! -r "/proc/$pid/cmdline" ];then bad=1;fi;done
 if [ "$bad" = 1 ];then guard;stop_dns || return 1;start_dns || return 1;unguard;fi
 # Retry a transient policy/worker failure under the same guard. Clear only
 # the guard installed by this path, after routing and all DNS processes agree.
 if [ -f "$NR/policy-reconcile.failed" ];then rm -f "$NR/policy-reconcile.failed";unguard;fi
}
settings_save(){
 ensure_conf;lock_action || return 1
 local old=$(sha256sum "$CONF"|cut -d' ' -f1)
 [ "$revision" = "$old" ] || { echo '配置已变化，请刷新页面';return 1; }
 printf '%s' "$payload"|base64 -d > "$NR/settings-new.json" || return 1
 /usr/bin/ikluajit /usr/ikuai/script/domain_allowlist.lua normalize "$NR/settings-new.json" "$NR/settings-normalized.json" >/dev/null 2>&1 || { echo '域名或加密 DNS 设置无效，旧设置保留';return 1; }
 mv "$NR/settings-normalized.json" "$NR/settings-new.json"
 cp "$CONF" "$NR/settings-old.json"
 cp "$NR/settings-new.json" "$CONF"
 # The native error envelope is not JSON-escaping stdout. Keep diagnostics in
 # a local log and return a single safe message on rejected settings.
 if ! apply_config "$CONF" > "$NR/settings-result.log" 2>&1;then cp "$NR/settings-old.json" "$CONF";apply_config "$CONF" >/dev/null 2>&1 || true;echo '配置无效或应用失败，已恢复旧设置';return 1;fi
}
ping_choices(){
 ensure_conf
 [ ! -f "$NR/active/choices.json" ] || jq -c '[.[] | . as $r | (.interface | split(",")[]) | select(. != "blackhole") | ["nr_port_"+($r.id|tostring)+"_"+., $r.label+"（测试线路："+.+"）"]]' "$NR/active/choices.json"
}
ping_resolve(){
 [[ "$choice" =~ ^nr_port_([0-9]+)(_([A-Za-z][A-Za-z0-9_.-]{0,14}))?$ ]] || return 1
 local rid=${BASH_REMATCH[1]} iface=${BASH_REMATCH[3]} dns id dev configured available
 configured=$(sqlite3 "$IK_DB_CONFIG" "select interface from stream_ipport where id=$rid and enabled='yes' and type=0;")
 [ "$configured" ] && [ "$configured" != blackhole ] || return 1
 # Preserve old single-exit diagnostic links. A legacy multi-exit link is
 # ambiguous; the caller must choose one of the explicit per-line entries.
 if [ -z "$iface" ];then
  case "$configured" in *,*) echo '请选择具体测试线路' >&2;return 1;;esac
  iface=$configured
 fi
 [[ "$iface" =~ ^[A-Za-z][A-Za-z0-9_.-]{0,14}$ ]] || return 1
 case ",$configured," in *",$iface,"*) ;; *) return 1;;esac
 read -r id iface dev available <<< "$(awk -v iface="$iface" '$2==iface{print;exit}' "$NR/exits")"
 [ "$id" ] && [ -e "/sys/class/net/$dev" ] || return 1
 dns=$(sqlite3 "$IK_DB_CONFIG" "select nr_dns from stream_domain where instr(','||interface||',',',$iface,')>0 and enabled='yes' order by id desc limit 1;")
 dns=${dns:-1.1.1.1}
 printf '%s %s %s\n' "$dev" "$dns" "$id"
}

native_migrate(){
 local home=/etc/mnt/ikuai/native-migration
 mkdir -p "$home"
 if ! sqlite3 "$IK_DB_CONFIG" 'select version from native_migration_state where version=1;' 2>/dev/null|grep -qx 1;then
  cp /etc/mnt/ikuai/strict-routing.json "$home/strict-routing.json" || return 1
  sqlite3 "$IK_DB_CONFIG" '.dump stream_ipport' > "$home/stream_ipport.sql"
  sqlite3 "$IK_DB_CONFIG" '.dump stream_domain' > "$home/stream_domain.sql"
  /usr/bin/ikluajit /usr/ikuai/script/native_migrate.lua "$home/strict-routing.json" "$CONF" "$home" || return 1
  sqlite3 "$IK_DB_CONFIG" < "$home/migration.sql" || return 1
 fi
 cp "$home/settings.json" "$CONF" || return 1
 jq '.enabled=false | .native_migrated=true' /etc/mnt/ikuai/strict-routing.json > "$home/retired.json" && cp "$home/retired.json" /etc/mnt/ikuai/strict-routing.json || return 1
 sync
}

app_restore(){ return 0; }
app_install(){ echo '应用规则库已移除，请使用原生协议分流';return 1; }
