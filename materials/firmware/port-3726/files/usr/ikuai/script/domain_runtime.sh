#!/bin/bash
DM_BASE=/usr/share/strict-routing
DM_HOME=/etc/mnt/ikuai/domain-iplib
dm_snapshot() {
 sql_config_get_json "$IK_DB_CONFIG" "select id,enabled,comment,interface,domain,src_addr,week,time from stream_domain order by id;" > "$1.raw"
 [ -s "$1.raw" ] || printf '[]\n' > "$1.raw"
 /usr/bin/ikluajit /usr/ikuai/script/domain_merge.lua snapshot "$1.raw" > "$1" || return 1
 rm -f "$1.raw"
}
dm_check_legacy() {
 local file="$1" count expected actual
 count=$(sqlite3 "$IK_DB_CONFIG" "select count(*) from stream_domain where enabled='yes';") || return 1
 [ "$count" != 0 ] || return 0
 dm_snapshot "$STATE/legacy-check.json" || return 1
 actual=$(sha256sum "$STATE/legacy-check.json" | cut -d' ' -f1)
 expected=$(jq -r .legacy_domain_revision "$file")
 [ "$(jq -r .domain_unified "$file")" = true ] && [ "$expected" = "$actual" ] || { echo 'Original domain rules require review in the domain page';return 1; }
}
dm_prepare_candidate() {
 local current
 dm_snapshot "$STATE/legacy-candidate.json" || return 1
 current=$(sha256sum "$STATE/legacy-candidate.json" | cut -d' ' -f1)
 if [ -n "$migration_payload" ];then
  [ "$legacy_revision" = "$current" ] || { echo 'Legacy configuration changed; reload before saving';return 1; }
  printf '%s' "$migration_payload" | base64 -d > "$STATE/legacy-actions.json" || return 1
 else printf '[]\n' > "$STATE/legacy-actions.json";fi
 /usr/bin/ikluajit /usr/ikuai/script/domain_merge.lua "$CONF" "$STATE/candidate.json" "$STATE/legacy-candidate.json" "$current" "$STATE/legacy-actions.json" || return 1
 mkdir -p /etc/mnt/ikuai/domain-legacy || return 1
 cp "$STATE/legacy-candidate.json" "/etc/mnt/ikuai/domain-legacy/$current.json" || return 1
 if [ ! -f /etc/mnt/ikuai/domain-legacy-backup.json ];then
  cp "$STATE/legacy-candidate.json" /etc/mnt/ikuai/domain-legacy-backup.json.new && mv /etc/mnt/ikuai/domain-legacy-backup.json.new /etc/mnt/ikuai/domain-legacy-backup.json || return 1
 fi
}
dm_native_off() {
 touch "$STATE/domain-owned" || return 1
 ik_cntl url_route group clear >/dev/null 2>&1 || return 1
 ik_cntl url_route disable >/dev/null 2>&1 || return 1
 : >/tmp/iktmp/.stream_domain
}
dm_native_restore() {
 [ "$(jq -r .domain_unified "$CONF")" = true ] && return 0
 rm -f "$STATE/domain-owned"
 /usr/ikuai/script/stream_domain.sh init
}
dm_valid_root() { [ "$1" = "$DM_BASE" ] || [[ "$1" =~ ^/etc/mnt/ikuai/domain-iplib/versions/[a-f0-9]{64}$ ]]; }
dm_current() {
 local root=$DM_BASE
 [ ! -L "$DM_HOME/current" ] || root=$(readlink "$DM_HOME/current")
 dm_valid_root "$root" && [ -f "$root/domain-manifest.json" ] || return 1
 printf '%s\n' "$root"
}
dm_pointer() {
 dm_valid_root "$2" || return 1
 mkdir -p "$DM_HOME" || return 1
 rm -f "$DM_HOME/$1.new.$$"
 ln -s "$2" "$DM_HOME/$1.new.$$" && /usr/bin/ikluajit /usr/ikuai/script/domain_lib.lua rename "$DM_HOME/$1.new.$$" "$DM_HOME/$1"
}
domain_restore() {
 ensure_conf;lock_action || return 1
 [ -f "$DM_HOME/pending" ] || return 0
 local root;read -r root < "$DM_HOME/pending"
 dm_valid_root "$root" && /usr/bin/ikluajit /usr/ikuai/script/domain_lib.lua verify "$root" || return 1
 dm_pointer current "$root" || return 1
 if [ "$(jq -r .enabled "$CONF")" = true ] && [ -f "$STATE/active/config.json" ];then
  export DM_TRANSACTION=1 SP_HOLD_GUARD=1
  apply_config "$CONF" || return 1
  unset DM_TRANSACTION SP_HOLD_GUARD
  rm -f "$DM_HOME/pending";sync;unguard;start_monitor
 else rm -f "$DM_HOME/pending";sync;fi
}
domain_install() {
 ensure_conf;lock_action || return 1
 [ ! -f "$DM_HOME/pending" ] && [ ! -f "$RG_HOME/pending" ] || { echo 'Database recovery pending';return 1; }
 local old new="$candidate" enabled changed=0
 dm_valid_root "$new" || return 1
 /usr/bin/ikluajit /usr/ikuai/script/domain_lib.lua verify "$new" || return 1
 old=$(dm_current) || return 1
 [ "$(jq -r .version "$new/domain-manifest.json")" != "$(jq -r .version "$old/domain-manifest.json")" ] || { echo 'Domain database is already current';return 0; }
 enabled=$(jq -r .enabled "$CONF")
 [ "$enabled" != true ] || guard || return 1
 mkdir -p "$DM_HOME"
 printf '%s\n' "$old" >"$DM_HOME/pending.new" && mv "$DM_HOME/pending.new" "$DM_HOME/pending" || return 1
 sync;export DM_TRANSACTION=1 SP_HOLD_GUARD=1
 if dm_pointer current "$new";then
  if [ "$enabled" != true ] || apply_config "$CONF";then dm_pointer previous "$old" && changed=1;fi
 fi
 if [ "$changed" != 1 ];then
  if dm_pointer current "$old";then
   if [ "$enabled" != true ] || apply_config "$CONF";then
    rm -f "$DM_HOME/pending";sync;unset DM_TRANSACTION SP_HOLD_GUARD
    [ "$enabled" != true ] || { unguard;start_monitor; }
   fi
  fi
  echo 'Domain update failed; previous database restored or traffic remains blocked';return 1
 fi
 sync;rm -f "$DM_HOME/pending";sync
 unset DM_TRANSACTION SP_HOLD_GUARD
 [ "$enabled" != true ] || { unguard;start_monitor; }
 echo 'Domain database applied; manual adjustments preserved'
}
