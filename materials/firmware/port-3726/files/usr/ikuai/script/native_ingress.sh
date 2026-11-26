#!/bin/bash
# Internal L3 receive adapter. Original wgN devices, keys, routes and names remain intact.
# PPP-prefixed L3 input is recognized by the native host/DPI engine; raw wgN is not.
# The IPIP device is only an ingress sink: no extra encryption or UDP listener.
set -e
ROOT=/tmp/iktmp/native-wg-ingress
# Read only this interface. Existing root/clsact qdiscs belong to their owner;
# use the current ingress parent instead of assuming an ffff: ingress qdisc.
ingress_parent(){
 local output
 output=$(tc qdisc show dev "$1") || return 1
 printf '%s\n' "$output" | awk '
  $1=="qdisc"&&($2=="ingress"||$2=="clsact"){
   if($3!~/^[[:xdigit:]]+:$/)exit 1;
   parent=$3;if($2=="clsact")parent=parent"fff2";n++
  }END{if(n>1)exit 1;if(n==1)print parent}'
}
local_rule_matches(){
 local address="$1" output="$2" hex a b c d
 IFS=. read -r a b c d <<< "$address"
 printf -v hex '%02x%02x%02x%02x' "$((10#$a))" "$((10#$b))" "$((10#$c))" "$((10#$d))"
 printf '%s\n' "$output" | awk -v expected="$hex/ffffffff" '
  $1=="match"{matches++;if(tolower($2)==expected&&$3=="at"&&$4==16&&NF==4)good++}
  /action order [0-9]+:/{actions++;s=$0;sub(/^.*action order [0-9]+:[[:space:]]*/,"",s);sub(/[[:space:]]*$/,"",s);if(s=="gact action pass")pass++}
  END{exit !(matches==1&&good==1&&actions==1&&pass==1)}'
}
redirect_rule_matches(){
 printf '%s\n' "$2" | awk -v expected="mirred (Ingress Redirect to device $1) stolen" '
  $1=="match"{matches++;if($2=="00000000/00000000"&&$3=="at"&&$4==12&&NF==4)good++}
  /action order [0-9]+:/{actions++;s=$0;sub(/^.*action order [0-9]+:[[:space:]]*/,"",s);sub(/[[:space:]]*$/,"",s);if(s==expected)redirect++}
  END{exit !(matches==1&&good==1&&actions==1&&redirect==1)}'
}
# Populate invocation-local variables declared by up/check. Cache files never
# substitute for live kernel filter, link, address or tunnel identity checks.
read_device(){
 local output
 [[ "$dev" =~ ^wg[0-9]+$ ]] && [ "${#helper}" -le 15 ] || return 1
 [ -e "/sys/class/net/$dev" ] || return 1
 idx=$(cat "/sys/class/net/$dev/ifindex");mtu=$(cat "/sys/class/net/$dev/mtu")
 [[ "$idx" =~ ^[0-9]+$ && "$mtu" =~ ^[0-9]+$ ]] && [ "$idx" -gt 0 ] && [ "$idx" -lt 65536 ] || return 1
 hi=$((idx / 256));lo=$((idx % 256))
 output=$(ip -o -4 addr show dev "$dev") || return 1
 address=$(printf '%s\n' "$output" | awk 'NR==1{split($4,a,"/");print a[1]}')
 [[ "$address" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
 record="$ROOT/$dev"
 parent=$(ingress_parent "$dev") || return 1
 local_filter='';redirect_filter=''
 if [ "$parent" ];then
  local_filter=$(tc filter show dev "$dev" parent "$parent" protocol ip pref 49200) || return 1
  redirect_filter=$(tc filter show dev "$dev" parent "$parent" protocol ip pref 49201) || return 1
 fi
}
check(){
 local dev="$1" helper="ppp$1" mtu idx record address hi lo parent local_filter redirect_filter output flags
 read_device || return 1
 [ -f "$record" ] && [ "$(cat "$record")" = "$idx" ] && [ -e "/sys/class/net/$helper" ] || return 1
 [ "$parent" ] || return 1
 [ "$(cat "/sys/class/net/$helper/mtu")" = "$mtu" ] || return 1
 flags=$(cat "/sys/class/net/$helper/flags") || return 1
 [[ "$flags" =~ ^0x[0-9a-fA-F]+$ ]] && [ "$((flags & 1))" = 1 ] || return 1
 output=$(ip -o -4 addr show dev "$helper") || return 1
 [ "$(printf '%s\n' "$output" | awk '{print $4}')" = "$address/32" ] || return 1
 output=$(ip tunnel show "$helper") || return 1
 printf '%s\n' "$output" | awk -v local_ip="127.252.$hi.$lo" -v remote_ip="127.253.$hi.$lo" '
  ($2=="ip/ip"||$2=="any/ip"){for(i=1;i<NF;i++){if($i=="local")l=$(i+1);if($i=="remote")r=$(i+1);if($i=="dev")d=$(i+1)}if(l==local_ip&&r==remote_ip&&d=="lo")good++}
  END{exit !(NR==1&&good==1)}' || return 1
 local_rule_matches "$address" "$local_filter" && redirect_rule_matches "$helper" "$redirect_filter"
}
up(){
 local dev="$1" helper="ppp$1" mtu idx record address hi lo parent local_filter redirect_filter output
 [[ "$dev" =~ ^wg[0-9]+$ ]] && [ "${#helper}" -le 15 ] || return 1
 [ -e "/sys/class/net/$dev" ] || return 0
 if check "$dev";then return 0;fi
 read_device || return 1
 if [ ! -f "$record" ] && { [ "$local_filter" ] || [ "$redirect_filter" ]; };then
  echo "Reserved ingress filters already exist: $dev" >&2;return 1
 fi
 if [ -e "/sys/class/net/$helper" ];then
  [ -f "$record" ] || { echo "Reserved ingress device already exists: $helper" >&2;return 1; }
 else
  ip link add "$helper" type ipip local "127.252.$hi.$lo" remote "127.253.$hi.$lo" dev lo
  printf '%s\n' "$idx" > "$record"
 fi
 ip tunnel change "$helper" mode ipip local "127.252.$hi.$lo" remote "127.253.$hi.$lo" dev lo
 # REDIRECT requires an IPv4 address on the receiving device. A /32 copy
 # supplies local DNS without moving the original WG connected route.
 output=$(ip -o -4 addr show dev "$helper") || return 1
 if [ "$(printf '%s\n' "$output" | awk '{print $4}')" != "$address/32" ];then
  ip -4 addr flush dev "$helper"
  ip addr add "$address/32" dev "$helper"
 fi
 ip link set "$helper" mtu "$mtu" up
 if [ -z "$parent" ];then tc qdisc add dev "$dev" handle ffff: ingress;parent=ffff:;fi
 # Router-originated sockets may bind to wgN. Redirecting their replies to
 # pppwgN changes skb_iif and breaks SO_BINDTODEVICE (Ping and bound DNS/TCP).
 # Keep packets to this WG address on wgN; they still traverse the normal
 # netfilter routing/DNS guards. Forwarded client packets retain the adapter.
 if ! local_rule_matches "$address" "$local_filter";then
  tc filter del dev "$dev" parent "$parent" protocol ip pref 49200 >/dev/null 2>&1 || true
  tc filter add dev "$dev" parent "$parent" protocol ip pref 49200 u32 match ip dst "$address/32" action gact pass
  printf '%s\n' "$address" > "$record.local-address"
 fi
 if ! redirect_rule_matches "$helper" "$redirect_filter";then
  tc filter del dev "$dev" parent "$parent" protocol ip pref 49201 >/dev/null 2>&1 || true
  tc filter add dev "$dev" parent "$parent" protocol ip pref 49201 u32 match ip src 0.0.0.0/0 action mirred ingress redirect dev "$helper"
 fi
 printf '%s\n' "$idx" > "$record"
 check "$dev"
}
down(){
 local dev="$1" parent
 [[ "$dev" =~ ^wg[0-9]+$ ]] || return 1
 [ -f "$ROOT/$dev" ] || return 0
 if [ -e "/sys/class/net/$dev" ];then
  parent=$(ingress_parent "$dev") || return 1
  if [ "$parent" ];then
   tc filter del dev "$dev" parent "$parent" protocol ip pref 49200 >/dev/null 2>&1 || true
   tc filter del dev "$dev" parent "$parent" protocol ip pref 49201 >/dev/null 2>&1 || true
  fi
 fi
 ip link del "ppp$dev" >/dev/null 2>&1 || true
 rm -f "$ROOT/$dev" "$ROOT/$dev.local-address"
}
case "$1" in
 check) check "$2";;
 up) mkdir -p "$ROOT";up "$2";;
 down) down "$2";;
 sync)
  mkdir -p "$ROOT"
  for f in "$ROOT"/wg*;do [[ "${f##*/}" =~ ^wg[0-9]+$ ]] || continue;[ -f "$f" ] || continue;[ -e "/sys/class/net/${f##*/}" ] || down "${f##*/}";done
  for f in /sys/class/net/wg*;do [ -e "$f" ] || continue;up "${f##*/}";done;;
 *) exit 2;;
esac
