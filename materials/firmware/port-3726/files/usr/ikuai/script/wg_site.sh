#!/bin/bash /etc/ikcommon
Include lock.sh
# Only explicit site pairs use this mark/table. Never install an Internet default.
ROOT=/tmp/iktmp/wg-site
MARK=0x57000000
mkdir -p "$ROOT"
site_hooks(){
 local table parent child
 for spec in 'mangle PREROUTING WG_SITE_PRE' 'mangle OUTPUT WG_SITE_OUT' 'mangle FORWARD WG_SITE_FAST' 'mangle POSTROUTING WG_SITE_FAST' 'nat PREROUTING WG_SITE_NAT' 'nat POSTROUTING WG_SITE_NAT';do
  set -- $spec;table=$1;parent=$2;child=$3
  iptables -w -t "$table" -S "$child" >/dev/null 2>&1 || continue
  # Do not reorder on every read/tick. Native rebuild calls hooks explicitly.
  while iptables -w -t "$table" -D "$parent" -j "$child" 2>/dev/null;do :;done
  iptables -w -t "$table" -I "$parent" 1 -j "$child" || return 1
 done
}
block(){
 local table dev
 for table in 42746 42747;do ip route flush table "$table" 2>/dev/null;ip route replace prohibit default table "$table";done
 sqlite3 "$IK_DB_CONFIG" "select distinct interface from wireguard_peers where ifnull(site_local,'')!='' or ifnull(site_remote,'')!='';" | while read -r dev;do
  [[ "$dev" =~ ^wg[0-9]+$ ]] && ip link set down dev "$dev" 2>/dev/null || true
 done
 logger -t wireguard 'WG site policy failed; affected WG interfaces blocked'
}
sync_site(){
 local old gen table other dev src dst kind via enabled setname prefix n=0
 old=$(cat "$ROOT/generation" 2>/dev/null);gen=a;[ "$old" != a ] || gen=b
 table=42746;other=42747;[ "$gen" = a ] || { table=42747;other=42746; }
 /usr/bin/lua /usr/ikuai/script/wg_site_compile.lua "$IK_DB_CONFIG" > "$ROOT/next" || return 1
 awk '$1=="T"{print $3}' "$ROOT/next" | sort -u | while read -r dev;do ip -o link show dev "$dev" 2>/dev/null || true;done > "$ROOT/links.next"
 if cmp -s "$ROOT/next" "$ROOT/active" && cmp -s "$ROOT/links.next" "$ROOT/links";then return 0;fi
 # A clean boot without site peers does not add chains, sets or policy rules.
 if [ ! -s "$ROOT/next" ] && [ ! -f "$ROOT/generation" ];then return 0;fi
 ip route flush table "$table" 2>/dev/null || true
 ip route replace prohibit default table "$table" || return 1
 while read -r kind dst dev via enabled;do
  [ "$kind" = T ] || continue
  [ "$enabled" = yes ] || continue
  ip -o link show dev "$dev" 2>/dev/null | grep '[,<]UP[,>]' >/dev/null || continue
  if [ "$via" = - ];then ip route replace "$dst" dev "$dev" table "$table" || return 1
  else ip route replace "$dst" via "$via" dev "$dev" onlink table "$table" || return 1;fi
 done < "$ROOT/next"
 # Both tables always terminate; switching generations can block, never fall back to WAN.
 ip rule show | grep -E "^85:.*fwmark 0x57000000.*lookup $table([[:space:]]|$)" >/dev/null || ip rule add pref 85 fwmark "$MARK/0xffffffff" table "$table" || return 1
 while ip rule del pref 85 fwmark "$MARK/0xffffffff" table "$other" 2>/dev/null;do :;done
 prefix="wgs_${gen}_$$"
 : > "$ROOT/sets.next"
 setname="${prefix}_out"
 ipset create "$setname" hash:net,net family inet maxelem 8192 || return 1
 printf '%s\n' "$setname" >> "$ROOT/sets.next"
 while read -r kind src dst;do [ "$kind" != P ] || ipset add "$setname" "$src,$dst" -exist || return 1;done < "$ROOT/next"
 {
  printf '%s\n' '*mangle' ':WG_SITE_PRE - [0:0]' ':WG_SITE_OUT - [0:0]' ':WG_SITE_MARK - [0:0]' ':WG_SITE_FAST - [0:0]' ':WG_SITE_PASS - [0:0]' '-F WG_SITE_PASS' '-F WG_SITE_PRE' '-F WG_SITE_OUT' '-F WG_SITE_MARK' '-F WG_SITE_FAST'
  printf '%s\n' '-A WG_SITE_MARK -j CONNMARK --set-mark 0' "-A WG_SITE_MARK -j MARK --set-mark $MARK" '-A WG_SITE_MARK -j ACCEPT' "-A WG_SITE_FAST -m mark ! --mark $MARK/0xffffffff -j RETURN" '-A WG_SITE_PASS -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu' '-A WG_SITE_PASS -j ACCEPT' 
  printf '%s\n' "-A WG_SITE_OUT -m set --match-set $setname src,dst -j WG_SITE_MARK"
 } > "$ROOT/rules.next"
 for dev in $(awk '$1=="I"{print $2}' "$ROOT/next" | sort -u);do
  n=$((n+1));setname="${prefix}_$n"
  ipset create "$setname" hash:net,net family inet maxelem 8192 || return 1
  printf '%s\n' "$setname" >> "$ROOT/sets.next"
  awk -v dev="$dev" '$1=="I"&&$2==dev{print $3","$4}' "$ROOT/next" | while read -r pair;do ipset add "$setname" "$pair" -exist || exit 1;done || return 1
  printf '%s\n' "-A WG_SITE_PRE -i $dev -m set --match-set $setname src,dst -j WG_SITE_MARK" >> "$ROOT/rules.next"
 done
 # Independent egress guard also covers higher-priority admin routes and
 # router-originated sockets that cannot be rerouted by an OUTPUT mark.
 for dev in $(awk '$1=="T"&&$5=="yes"{print $3}' "$ROOT/next" | sort -u);do
  n=$((n+1));setname="${prefix}_route$n"
  ipset create "$setname" hash:net family inet maxelem 8192 || return 1
  printf '%s\n' "$setname" >> "$ROOT/sets.next"
  awk -v dev="$dev" '$1=="T"&&$3==dev&&$5=="yes"{print $2}' "$ROOT/next" | while read -r dst;do ipset add "$setname" "$dst" -exist || exit 1;done || return 1
  printf '%s\n' "-A WG_SITE_FAST -o $dev -m set --match-set $setname dst -j WG_SITE_PASS" >> "$ROOT/rules.next"
 done
 printf '%s\n' '-A WG_SITE_FAST -j DROP' >> "$ROOT/rules.next"
 # Preserve original source and remote LAN DNS. Router-local destinations must
 # still reach native service redirects (including DNS on the WG address).
 printf '%s\n' 'COMMIT' '*nat' ':WG_SITE_NAT - [0:0]' '-F WG_SITE_NAT' "-A WG_SITE_NAT -m mark --mark $MARK/0xffffffff -m addrtype ! --dst-type LOCAL -j ACCEPT" 'COMMIT' >> "$ROOT/rules.next"
 iptables-restore -w --noflush < "$ROOT/rules.next" || return 1
 site_hooks || return 1
 printf '%s\n' "$gen" > "$ROOT/generation"
 mv "$ROOT/next" "$ROOT/active"
 mv "$ROOT/sets.next" "$ROOT/sets"
 mv "$ROOT/links.next" "$ROOT/links"
 for setname in $(ipset list -name | grep '^wgs_');do grep -Fxq "$setname" "$ROOT/sets" || ipset destroy "$setname" 2>/dev/null || true;done
}
hooks(){
 Lock wg_site excl 30 || return 1
 site_hooks;local status=$?
 unLock wg_site
 return "$status"
}
sync(){
 Lock wg_site excl 30 || return 1
 local status=0
 sync_site || { block;status=1; }
 unLock wg_site
 return "$status"
}
