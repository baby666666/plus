#!/bin/bash
# Bind the unified DNS dispatcher to per-ingress internal port 53 addresses.
set -e -o pipefail
NR=/tmp/iktmp/native-rules
interfaces(){
 local dev parent
 while read -r dev;do
  case "$dev" in pppnrd*)continue;;lan*|vlan*|ppp*|tap*|sovpn|sdwan*|ikec*|doc_*|wg*) ;; *)continue;;esac
  # Pure HY2 uses its own UP veth even while the associated WG socket is down.
  if [[ "$dev" == ppphy* ]];then
   [[ "$dev" =~ ^ppphy[0-9]+$ ]] || continue
   ip -o link show dev "$dev" 2>/dev/null | grep -E '[,<]UP[,>]' >/dev/null || continue
  fi
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
ready(){
 local dev="$1" address pid a b c d endpoint protocol inode fd owned
 [[ "$dev" =~ ^ppphy[0-9]+$ ]] || return 1
 check || return 1
 [ -f "$NR/active/front.ready" ] && [ -f "$NR/active/front.pid" ] || return 1
 [ ! -f "$NR/commit.pending" ] && [ ! -f "$NR/native-dirty" ] && [ ! -f "$NR/native-stage.pending" ] || return 1
 [ ! -f "$NR/boot.pending" ] && [ ! -f "$NR/policy-reconcile.failed" ] || return 1
 cmp -s "$NR/dns-bindings" "$NR/active/dns-bindings" || return 1
 address=$(awk -v dev="$dev" '$2==dev{print $1}' "$NR/active/dns-bindings")
 [[ "$address" =~ ^169\.254\.252\.([0-9]{1,3})$ ]] || return 1
 read -r pid < "$NR/active/front.pid"
 [[ "$pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$pid" 2>/dev/null || return 1
 [ "$(tr '\0' '\n' < "/proc/$pid/cmdline" | head -n 1)" = /usr/sbin/native-rule-dns ] || return 1
 IFS=. read -r a b c d <<< "$address"
 printf -v endpoint '%02X%02X%02X%02X:0035' "$d" "$c" "$b" "$a"
 # The ready file alone can be stale after a crash. Both sockets must be
 # listening at this binding and belong to the current dispatcher process.
 for protocol in udp tcp;do
  inode=$(awk -v ep="$endpoint" -v state="$([ "$protocol" = tcp ] && echo 0A || echo 07)" '$2==ep&&$4==state{print $10}' "/proc/net/$protocol")
  [[ "$inode" =~ ^[1-9][0-9]*$ ]] || return 1
  owned=0
  for fd in "/proc/$pid/fd/"*;do
   if [ "$(readlink "$fd" 2>/dev/null)" = "socket:[$inode]" ];then owned=1;break;fi
  done
  [ "$owned" = 1 ] || return 1
 done
}
ensure(){
 [[ "$1" =~ ^ppphy[0-9]+$ ]] || return 1
 interfaces | grep -Fx "$1" >/dev/null || return 1
 # Invoke the serialized transaction, which installs capture rules and
 # starts the matching listeners before allowing the HY2 core to start.
 # The calling HY2 controller owns fd 9; the engine uses fd 8. A native
 # transaction can spawn DNS/compiler/monitor daemons. Their inherited copies
 # would keep the parent locks held after this synchronous call returns.
 # Close only the child copies: the controller still owns its transaction.
 if [ -f "$NR/active/snapshot.json" ];then /usr/ikuai/script/native_rules.sh reconcile 8>&- 9>&- || return 1
 else /usr/ikuai/script/native_rules.sh apply 8>&- 9>&- || return 1;fi
 ready "$1"
}
case "${1:-}" in prepare)prepare;;check)check;;ready)ready "$2";;ensure)ensure "$2";;*)exit 2;;esac
