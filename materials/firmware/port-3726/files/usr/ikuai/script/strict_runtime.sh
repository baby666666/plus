#!/bin/bash
# Reserved mark namespace 0x53xxxxxx; unrelated native iKuai connmarks are never restored.
SP_DIR=/tmp/iktmp/strict-routing
SP_MARK=1392508928
sp_ipt() { iptables -w "$@"; }
sp_set() { local expiry="";case "$1" in sp_d_*) expiry="timeout 3600";;esac;ipset create "$1" "$2" family inet maxelem 262144 $expiry -exist; }
sp_chain() { sp_ipt -t "$1" -N "$2" 2>/dev/null || true; sp_ipt -t "$1" -F "$2"; }
sp_hook() {
 local position=1
 # Keep the populated guard before the accepting policy chain until DNS and
 # route setup complete. This also applies on first activation.
 if [ "$1" = mangle ] && [ "$2" = PREROUTING ];then position=2;fi
 sp_ipt -t "$1" -C "$2" -j "$3" 2>/dev/null || sp_ipt -t "$1" -I "$2" "$position" -j "$3"
}
sp_begin() {
 mkdir -p "$SP_DIR"
 sp_set sp_clients hash:net
 sp_set sp_local hash:net
 sp_set sp_known hash:net
 ipset create sp_quarantine hash:ip family inet maxelem 1048576 timeout 61 -exist
 if [ "${SP_RESET_DOMAINS:-0}" = 1 ];then
  local oldset
  for oldset in $(ipset list -name | grep -E "^sp_d_(cn|foreign|[a-f0-9]{24})$");do
   ipset save "$oldset" | awk '$1=="add"{print "add sp_quarantine " $3 " timeout 61"}' | ipset restore -exist
   ipset flush "$oldset"
  done
 fi
 # Caller holds a fail-closed guard while preparing these chains.
 for spec in 'mangle SP_CLASS' 'mangle SP_SCOPE' 'mangle SP_OUT' 'mangle SP_FAST' 'filter SP_FWD' 'filter SP_DNSOUT' 'filter SP_DNSIN' 'nat SP_DNS' 'nat SP_NAT'; do sp_chain $spec; done
 ipset flush sp_clients;ipset flush sp_local;ipset flush sp_known
 sp_ipt -t mangle -A SP_CLASS -m conntrack --ctdir REPLY -j RETURN
 sp_ipt -t mangle -A SP_CLASS -m addrtype --dst-type LOCAL -j RETURN
 sp_ipt -t mangle -A SP_CLASS -m set --match-set sp_local dst -j RETURN
 sp_ipt -t mangle -A SP_CLASS -m set --match-set sp_quarantine dst -j DROP
 sp_ipt -t mangle -A SP_CLASS -m connmark --mark 0x53000000/0xff000000 -j CONNMARK --restore-mark
 sp_ipt -t mangle -A SP_CLASS -m mark --mark 0x53000000/0xff000000 -j ACCEPT
 # Never accelerate policy connections: every packet must pass the egress guard.
 sp_ipt -t mangle -A SP_FAST -m connmark --mark 0x53000000/0xff000000 -j ACCEPT
 sp_ipt -t filter -A SP_FWD -m conntrack --ctdir REPLY -j RETURN
 sp_ipt -t filter -A SP_DNSOUT -o lo -j RETURN
 : > "$SP_DIR/exits"
}
sp_scope() {
 local dev="$1" src="$2" proto
 ipset add sp_clients "$src" -exist
 sp_ipt -t mangle -A SP_SCOPE -i "$dev" -s "$src" -j SP_CLASS
 for proto in udp tcp; do
  sp_ipt -t nat -A SP_DNS -i "$dev" -s "$src" -p "$proto" --dport 53 -j REDIRECT --to-ports 6153
  sp_ipt -t filter -A SP_DNSIN -i "$dev" -s "$src" -p "$proto" --dport 6153 -j ACCEPT
 done
 # IPv6 is explicitly closed for managed ingress until an equally strict IPv6 engine is shipped.
 ip6tables -w -C FORWARD -i "$dev" -m comment --comment strict-routing-v6 -j DROP 2>/dev/null || ip6tables -w -I FORWARD 1 -i "$dev" -m comment --comment strict-routing-v6 -j DROP
}
sp_protect() { ipset add sp_local "$1" -exist; }
sp_exit() {
 local id="$1" iface="$2" dns="$3" dev="$2" mark=$((SP_MARK+$1)) uid=$((48000+$1)) prio=$((100+$1*2))
 # Native PPPoE interface names use the _ad suffix.
 [ -e "/sys/class/net/${iface}_ad" ] && dev="${iface}_ad"
 grep -q "^spdns$id:" /etc/passwd || printf 'spdns%s:x:%s:0:Strict DNS:/nonexistent:/bin/false\n' "$id" "$uid" >> /etc/passwd
 grep -Eq "[[:space:]]${iface}([[:space:]]|$)" /etc/iproute2/rt_tables || { echo "Missing route table for $iface" >&2; return 1; }
 # A permanent prohibit rule follows the designated table lookup. A deleted/empty table cannot fall through.
 while ip rule del pref "$prio" fwmark "$mark" 2>/dev/null; do :; done
 while ip rule del pref "$((prio+1))" fwmark "$mark" 2>/dev/null; do :; done
 ip rule add pref "$((prio+1))" fwmark "$mark" prohibit
 ip rule add pref "$prio" fwmark "$mark" lookup "$iface"
 case "$iface" in wg[0-9]*)
  sp_transport "$iface"
  [ ! -e "/sys/class/net/$dev" ] || ip route replace default dev "$dev" table "$iface" metric 100
 esac
 sp_ipt -t filter -A SP_FWD -m connmark --mark "$mark" ! -o "$dev" -j DROP
 sp_ipt -t filter -A SP_FWD -m connmark --mark "$mark" -o "$dev" -j RETURN
 sp_ipt -t mangle -A SP_OUT -m owner --uid-owner "$uid" ! -o lo -j MARK --set-mark "$mark"
 sp_ipt -t mangle -A SP_OUT -m owner --uid-owner "$uid" ! -o lo -j CONNMARK --save-mark
 sp_ipt -t mangle -A SP_OUT -m owner --uid-owner "$uid" ! -o lo -j ACCEPT
 sp_ipt -t filter -A SP_DNSOUT -m owner --uid-owner "$uid" ! -o "$dev" -j DROP
 sp_ipt -t filter -A SP_DNSOUT -m owner --uid-owner "$uid" ! -d "$dns" -j DROP
 sp_ipt -t filter -A SP_DNSOUT -m owner --uid-owner "$uid" -j RETURN
 local probe_uid=$((48100+id))
 sp_ipt -t mangle -A SP_OUT -m owner --uid-owner "$probe_uid" ! -o lo -j MARK --set-mark "$mark"
 sp_ipt -t mangle -A SP_OUT -m owner --uid-owner "$probe_uid" ! -o lo -j CONNMARK --save-mark
 sp_ipt -t mangle -A SP_OUT -m owner --uid-owner "$probe_uid" ! -o lo -j ACCEPT
 sp_ipt -t filter -A SP_DNSOUT -m owner --uid-owner "$probe_uid" ! -o "$dev" -j DROP
 sp_ipt -t filter -A SP_DNSOUT -m owner --uid-owner "$probe_uid" -j RETURN
 # NAT only selected original-direction policy traffic; do not change unowned traffic.
 sp_ipt -t nat -A SP_NAT -m connmark --mark "$mark" -o "$dev" -j MASQUERADE
 printf '%s %s %s %s\n' "$id" "$iface" "$dev" "$dns" >> "$SP_DIR/exits"
}
sp_region() {
 local name="$1" line
 sp_set "sp_r_$name" hash:net
 # Packaged country lists are validated during the build. Reload under the guard.
 ipset flush "sp_r_$name"
 (set -o pipefail; /usr/bin/ikluajit /usr/ikuai/script/strict_ipset.lua "$name" | ipset restore -exist)
}
sp_conflict() { sp_ipt -t mangle -I SP_CLASS 4 -m set --match-set "$1" dst -m set --match-set "$2" dst -j DROP; }
sp_match() {
 local expr="$1" id="$2" mark=$((SP_MARK+$2))
 # expr is produced exclusively by the validated compiler, never raw configuration text.
 if [ "$id" = 0 ]; then sp_ipt -t mangle -A SP_CLASS $expr -j DROP; return; fi
 sp_ipt -t mangle -A SP_CLASS $expr -j MARK --set-mark "$mark"
 sp_ipt -t mangle -A SP_CLASS $expr -j CONNMARK --save-mark
 sp_ipt -t mangle -A SP_CLASS $expr -j ACCEPT
}
sp_finish() {
 sp_ipt -t filter -A SP_DNSOUT -m owner --uid-owner 48001-48032 -j DROP
 sp_ipt -t filter -A SP_DNSOUT -m owner --uid-owner 48101-48132 -j DROP
 sp_ipt -t filter -A SP_FWD -m connmark --mark 0x53000000/0xff000000 -j DROP
 sp_ipt -t filter -A SP_DNSIN -i lo -j RETURN
 sp_ipt -t filter -A SP_DNSIN -p udp --dport 6153:6232 -j DROP
 sp_ipt -t filter -A SP_DNSIN -p tcp --dport 6153:6232 -j DROP
 sp_hook filter FORWARD SP_FWD
 sp_hook filter OUTPUT SP_DNSOUT
 sp_hook filter INPUT SP_DNSIN
 sp_hook mangle PREROUTING SP_SCOPE
 sp_hook mangle OUTPUT SP_OUT
 sp_hook mangle FORWARD SP_FAST
 sp_hook nat PREROUTING SP_DNS
 sp_hook nat POSTROUTING SP_NAT
}

sp_transport() {
 local iface="$1" mark
 [ -e "/sys/class/net/$iface" ] || return 0
 mark=$(wg show "$iface" fwmark 2>/dev/null) || return 1
 if [ "$mark" = off ] || [ "$mark" = 0 ]; then
  wg set "$iface" fwmark 0x54000000 || return 1
  mkdir -p /etc/mnt/ikuai/strict-routing
  touch "/etc/mnt/ikuai/strict-routing/owned-wg-$iface"
  mark=0x54000000
 fi
 # WireGuard's encrypted transport can inherit the DNS worker's socket owner.
 # It must retain its underlay mark, never the decrypted payload's exit mark.
 iptables -w -t mangle -C SP_OUT -m mark --mark "$mark" -j RETURN 2>/dev/null || iptables -w -t mangle -I SP_OUT 1 -m mark --mark "$mark" -j RETURN
 iptables -w -C SP_DNSOUT -m mark --mark "$mark" -j RETURN 2>/dev/null || iptables -w -I SP_DNSOUT 1 -m mark --mark "$mark" -j RETURN
}
