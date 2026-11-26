#!/bin/bash /etc/ikcommon
# Upgrade-only cleanup for the retired WireGuard DNS resolver. Never load its config as shell.
cleanup() {
 local conf=/etc/mnt/ikuai/wg_dns_split.conf
 local tmp=/tmp/iktmp/retire-wg-dns proc pid table hook chain key iface mark prio
 mkdir -p "$tmp"
 for proc in /proc/[0-9]*;do
  [ -r "$proc/cmdline" ] || continue
  if tr '\0' '\n' < "$proc/cmdline" | grep -Fxq '/usr/ikuai/script/wg_dns_split.lua';then
   pid=${proc##*/};kill "$pid" 2>/dev/null || true
  fi
 done
 for spec in 'nat PREROUTING WG_DNS_SPLIT' 'mangle OUTPUT WG_DNS_OUTPUT' 'mangle PREROUTING WG_DNS_ROUTE' 'nat POSTROUTING WG_DNS_MASQ';do
  set -- $spec;table=$1;hook=$2;chain=$3
  while iptables -w -t "$table" -D "$hook" -j "$chain" 2>/dev/null;do :;done
  iptables -w -t "$table" -F "$chain" 2>/dev/null || true
  iptables -w -t "$table" -X "$chain" 2>/dev/null || true
 done
 # Delete only old DNS rule identities, never a whole routing table or priority range.
 if [ -f "$conf" ];then
  for spec in 'CHINA_IFACE 10031' 'OVERSEA_IFACE 10032';do
   set -- $spec;key=$1;prio=$2
   iface=$(sed -n "s/^${key}='\([a-zA-Z][a-zA-Z0-9_.-]*\)'$/\1/p" "$conf" | head -1)
   [ -n "$iface" ] && [ "${#iface}" -le 15 ] || continue
   mark=$(awk -v iface="$iface" '$2==iface{print $1;exit}' /etc/iproute2/rt_tables)
   [[ "$mark" =~ ^[0-9]+$ ]] || continue
   while ip rule del pref "$prio" fwmark "$mark" table "$iface" 2>/dev/null;do :;done
  done
  if [ ! -e "$conf.retired" ];then mv "$conf" "$conf.retired";else mv "$conf" "$conf.retired.$(date +%s).$$";fi
 fi
 # The old resolver may briefly be finishing a request; reap only its exact script argv.
 for proc in /proc/[0-9]*;do
  [ -r "$proc/cmdline" ] || continue
  if tr '\0' '\n' < "$proc/cmdline" | grep -Fxq '/usr/ikuai/script/wg_dns_split.lua';then kill -9 "${proc##*/}" 2>/dev/null || true;fi
 done
 rm -f /tmp/iktmp/wg_dns_split/split.pid
 ipset destroy wg_dns_china_v4 2>/dev/null || true
 ipset destroy wg_dns_oversea_v4 2>/dev/null || true
 if crontab -l > "$tmp/cron.$$" 2>/dev/null && grep -Fq '/usr/ikuai/script/wg_dns_split.sh' "$tmp/cron.$$";then
  awk 'index($0,"/usr/ikuai/script/wg_dns_split.sh")==0' "$tmp/cron.$$" > "$tmp/cron-new.$$"
  crontab "$tmp/cron-new.$$" || return 1
 fi
 rm -f "$tmp/cron.$$" "$tmp/cron-new.$$"
 echo 'Retired WireGuard DNS; DNS routing is managed by stream_domain' > "$tmp/status"
}
