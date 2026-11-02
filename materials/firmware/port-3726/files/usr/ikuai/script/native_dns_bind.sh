#!/bin/bash
# Bind the unified DNS dispatcher to per-ingress internal port 53 addresses.
set -e -o pipefail
NR=/tmp/iktmp/native-rules
interfaces(){
 local dev parent
 while read -r dev;do
  case "$dev" in pppnrd*)continue;;lan*|vlan*|ppp*|tap*|sovpn|sdwan*|ikec*|doc_*|wg*) ;; *)continue;;esac
  # A newly created WG interface has no enabled peer and remains DOWN, while
  # its internal pppwg adapter can already be UP. Neither can receive client
  # DNS in that state. Including them caused unrelated empty-interface edits
  # to trigger a global DNS rebuild and traffic guard several seconds later.
  if [[ "$dev" =~ ^(ppp)?(wg[0-9]+)$ ]];then
   parent="${BASH_REMATCH[2]}"
   ip -o link show dev "$parent" 2>/dev/null | grep -E '[,<]UP[,>]' >/dev/null || continue
  fi
  # Consume every address: grep -q can close the pipe after the first address,
  # making ip exit with SIGPIPE under pipefail and hiding a live interface.
  ip -o -4 addr show dev "$dev" | grep . >/dev/null || continue
  printf '%s\n' "$dev"
 done < <(ip -o link show | awk -F ': ' '{sub(/@.*/,"",$2);print $2}' | sort)
}
prepare(){
 mkdir -p "$NR/active"
 local old="$NR/dns-bindings" next="$NR/active/dns-bindings" plan="$NR/dns-bindings.next" dev addr index=0 existing
 : > "$plan"
 # Validate the complete plan before adding any addresses. Ownership is stored
 # before each add, so an interrupted apply can safely recover its own aliases.
 while read -r dev;do
  index=$((index+1));[ "$index" -le 128 ] || { echo 'DNS 入接口超过 128 个';return 1; }
  addr="169.254.252.$index"
  existing=$(ip -o -4 addr show | awk -v ip="$addr" '{split($4,a,"/");if(a[1]==ip)print $2" "$4}')
  if [ "$existing" ];then
   [ "$existing" = "lo $addr/32" ] && [ -f "$old" ] && awk -v ip="$addr" '$1==ip{found=1}END{exit !found}' "$old" || { echo '内部 DNS 地址冲突';return 1; }
  fi
  if ip -4 route show table all | awk -v ip="$addr" '
   function number(s, a){split(s,a,".");return ((a[1]*256+a[2])*256+a[3])*256+a[4]}
   {p=$1;if(p=="local"||p=="broadcast"||p=="unreachable"||p=="prohibit"||p=="blackhole")p=$2;
    if(p !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/)next;
    split(p,a,"/");bits=a[2]==""?32:a[2];if(bits==0)next;
    if(bits==32&&a[1]==ip&&$0~/ dev lo( |$)/)next;
    size=2^(32-bits);if(int(number(ip)/size)==int(number(a[1])/size))found=1}
   END{exit !found}';then echo '内部 DNS 网段与现有网络冲突';return 1;fi
  printf '%s %s\n' "$addr" "$dev" >> "$plan"
 done < <(interfaces)
 touch "$old"
 while read -r addr dev;do
  if ! ip -o -4 addr show dev lo | awk -v ip="$addr/32" '$4==ip{found=1}END{exit !found}';then
   awk -v ip="$addr" '$1==ip{found=1}END{exit !found}' "$old" || printf '%s %s\n' "$addr" "$dev" >> "$old"
   ip addr add "$addr/32" dev lo
  fi
 done < "$plan"
 while read -r addr dev;do
  if ! awk -v ip="$addr" '$1==ip{found=1}END{exit !found}' "$plan";then ip addr del "$addr/32" dev lo 2>/dev/null || true;fi
 done < "$old"
 cp "$plan" "$next";mv "$plan" "$old"
}
check(){ [ -f "$NR/dns-bindings" ] && [ "$(interfaces)" = "$(awk '{print $2}' "$NR/dns-bindings")" ]; }
case "${1:-}" in prepare)prepare;;check)check;;*)exit 2;;esac
