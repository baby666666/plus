#!/bin/sh
# Independent of routing-library compilation; serialize save/status snapshots.
CFG=/etc/mnt/ikuai/dns-limits.conf
LUA=/usr/ikuai/script/dns_limits.lua
CTL=/tmp/iktmp/native-rules/dns.control
TMP=/tmp/iktmp/dns-limits
op=$1;shift
for arg in "$@";do case "$arg" in payload=*) payload=${arg#payload=};; revision=*) revision=${arg#revision=};; *) exit 1;; esac;done
mkdir -p "$TMP" || exit 1
umask 077
revision_now(){ if [ -f "$CFG" ];then sha256sum "$CFG"|cut -d' ' -f1;else printf missing;fi; }
(
 flock -x 9 || exit 1
 case "$op" in
 status)
  stats=$(/usr/sbin/native-rule-dns --control "$CTL" LIMITSTATS view 2>/dev/null) || stats=
  /usr/bin/lua "$LUA" status "$CFG" "$(revision_now)" "$stats"
  ;;
 save)
  [ "$revision" = "$(revision_now)" ] || { echo '设置已被修改，请刷新后重试';exit 1; }
  [ "${#payload}" -le 44000 ] || { echo '请求过大';exit 1; }
  file="$TMP/request.$$";trap 'rm -f "$file" "$CFG.pending"' EXIT HUP INT TERM
  printf '%s' "$payload" | base64 -d > "$file" || exit 1
  /usr/bin/lua "$LUA" prepare "$file" "$CFG.pending" || exit 1
  chmod 600 "$CFG.pending" || exit 1
  # Do not silently persist when an existing daemon fails to acknowledge.
  if pidof native-rule-dns >/dev/null;then
   /usr/sbin/native-rule-dns --control "$CTL" LIMITS apply || { echo '未确认应用结果，请刷新状态核对；未重启 DNS';exit 1; }
  else
   mv "$CFG.pending" "$CFG" || exit 1
  fi
  ;;
 *) exit 1;;
 esac
) 9> "$TMP/settings.lock"
