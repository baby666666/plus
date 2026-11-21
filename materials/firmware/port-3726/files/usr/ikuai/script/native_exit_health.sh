#!/bin/bash
# Physical-exit health is shared, policy binding/fallback decisions are not.
# Called with the native rules state lock held, after complete exit/transport
# guards are installed. Both apply and reconcile sample at most four due exits.
nr_health_now(){ awk '{printf "%.0f\n",$1}' /proc/uptime; }
nr_health_ipv4(){
 awk -F. 'NF==4 {for(i=1;i<=4;i++)if($i!~/^[0-9]+$/ || $i>255)exit 1;
  if($1==0 || $1==127 || $1>=224)exit 1;ok=1}END{if(!ok)exit 1}' <<< "$1"
}
nr_health_targets(){
 local eid="$1" local_addresses="$2" target
 # Policy DNS is authoritative. Only when absent use the router's configured
 # upstreams (including DHCP-generated default_resolv); never invent a target.
 local selected=$(awk -v eid="$eid" 'FNR==NR{n=split($2,a,",");for(i=1;i<=n;i++)if(a[i]==eid)p[$1]=1;next}
  p[$2]&&!seen[$3]++{print $3}' "$NR/policies" "$NR/policy-workers" 2>/dev/null)
 if [ -z "$selected" ];then
  selected=$({ sqlite3 "${IK_DB_CONFIG:-/etc/mnt/ikuai/config.db}" 'select dns1 from dns_config union all select dns2 from dns_config;' 2>/dev/null;
   awk '$1=="nameserver"{print $2}' /etc/default_resolv.conf 2>/dev/null; } | awk '!seen[$0]++')
 fi
 while read -r target;do
  nr_health_ipv4 "$target" || continue
  grep -Fx "$target" "$local_addresses" >/dev/null 2>&1 && continue
  printf '%s\n' "$target"
 done <<< "$selected" | awk '!seen[$0]++ && ++n<=2'
}
# All devices in one health cycle use the same public inventory. These files
# live only in the caller's private temporary directory, never across cycles.
# Do not use `wg show all dump`: that output also contains private/PSK keys.
nr_health_inventory(){
 local dir="$1" field
 ip -o link show > "$dir/links" || return 1
 ip -o -4 addr show > "$dir/addresses" || return 1
 for field in peers allowed-ips endpoints;do : > "$dir/wg-$field" || return 1;done
 if awk 'FNR==NR{used[$1]=1;next} ($1 in used)&&$2~/^wg[0-9]+$/{found=1}END{exit !found}' "$dir/used" "$dir/exits";then
  for field in peers allowed-ips endpoints;do
   wg show all "$field" > "$dir/wg-$field" 2>/dev/null || return 1
  done
 fi
}
nr_health_device(){
 local iface="$1" dev="$2"
 if [ -n "${NR_HEALTH_SNAPSHOT:-}" ];then
  awk -v dev="$dev" '{name=$2;sub(/:$/,"",name);sub(/@.*/,"",name);if(name==dev&&$0~/[,<]UP[,>]/)up=1}END{exit !up}' "$NR_HEALTH_SNAPSHOT/links" || return 1
  awk -v dev="$dev" '{name=$2;sub(/@.*/,"",name);if(name==dev&&$3=="inet")address=1}END{exit !address}' "$NR_HEALTH_SNAPSHOT/addresses"
  return
 fi
 ip -o link show "$dev" 2>/dev/null | grep '[,<]UP[,>]' >/dev/null || return 1
 ip -o -4 addr show dev "$dev" 2>/dev/null | grep ' inet ' >/dev/null || return 1
 # PPPoE's logical wanN may have no address; native NTH uses the real _ad dev.
 return 0
}
nr_health_signature(){
 local id="$1" iface="$2" dev="$3" available="$4" targets="$5"
 { printf '%s %s %s %s %s\n' "$id" "$iface" "$dev" "$available" "$targets"
   if [ -n "${NR_HEALTH_SNAPSHOT:-}" ];then
    awk -v dev="$dev" '{name=$2;sub(/:$/,"",name);sub(/@.*/,"",name);if(name==dev){sub(/:$/,"",$1);print $1;exit}}' "$NR_HEALTH_SNAPSHOT/links"
    awk -v dev="$dev" '{name=$2;sub(/@.*/,"",name);if(name==dev)print}' "$NR_HEALTH_SNAPSHOT/addresses"
    case "$iface" in wg[0-9]*)
     local field
     for field in peers allowed-ips endpoints;do
      awk -v iface="$iface" '$1==iface{sub(/^[^ \t]+[ \t]/,"");print}' "$NR_HEALTH_SNAPSHOT/wg-$field"
     done;;
    esac
   else
    cat "/sys/class/net/$dev/ifindex" 2>/dev/null
    ip -o -4 addr show dev "$dev" 2>/dev/null
    case "$iface" in wg[0-9]*)
     # Public peer identity only; no dump/showconf/private or preshared keys.
     wg show "$iface" peers;wg show "$iface" allowed-ips;wg show "$iface" endpoints;;
    esac
   fi
 } 2>/dev/null | sha256sum | awk '{print $1}'
}
nr_health_native(){
 local iface="$1" dev="$2" status
 status=$(awk 'NR==1{print $8}' "/tmp/iktmp/monitor-link/$dev" 2>/dev/null)
 [ "$status" ] || status=$(awk 'NR==1{print $8}' "/tmp/iktmp/monitor-link/$iface" 2>/dev/null)
 case "$status" in success) return 0;;fail) return 1;;*) return 2;;esac
}
# These device-direction hooks may run before NR_OUTPUT. Inspect actual
# rules, including their one allowed child. A chain name alone proves nothing.
nr_health_direction_prefix(){
 local dir=$1 chain=$2 reply= child
 case "$chain" in
  NR_HYR_DIR|NR_HYR_FENCE) reply=NR_HYR_REPLY;;
  NR_WG_DIR|NR_WG_FENCE) reply=NR_WG_REPLY;;
  NR_HYC_DIR) reply=NR_HYC_REPLY;;
  *) return 1;;
 esac
 iptables -w -S "$chain" > "$dir/$chain" 2>/dev/null || return 1
 child=$(awk -v name="$chain" -v reply="$reply" '
  {sub(/^\[fastid: [0-9]+\] /,"")}
  $0=="-N "name{declared=1;next}
  NF {
   if($1!="-A" || $2!=name || $(NF-1)!="-j")bad=1
   else if($NF==reply)ref=1
   else if($NF!="DROP" && $NF!="REJECT" && $NF!="RETURN")bad=1
  }
  END{if(!declared || bad)exit 1;print ref+0}' "$dir/$chain") || return 1
 [ "$child" = 1 ] || return 0
 iptables -w -S "$reply" > "$dir/$reply" 2>/dev/null || return 1
 awk -v name="$reply" '
  {sub(/^\[fastid: [0-9]+\] /,"")}
  $0=="-N "name{declared=1;next}
  NF && !($1=="-A" && $2==name && $(NF-1)=="-j" && ($NF=="DROP" || $NF=="RETURN" || $NF=="REJECT")){bad=1}
  END{exit !declared || bad}' "$dir/$reply"
}
# Guard state is read once, lazily when a WG sample is due. The snapshot is
# private to this health invocation, including a failed/partial read result.
nr_health_guard_inventory(){
 local dir="$1"
 ip rule show > "$dir/guard.rules" || return 1
 iptables -w -S OUTPUT > "$dir/guard.output" 2>/dev/null || return 1
 iptables -w -S NR_OUTPUT > "$dir/guard.chain" 2>/dev/null || return 1
 : > "$dir/guard.prefix" || return 1
 # guard()/unguard() can leave this owned, empty or drop-only chain ahead of
 # NR_OUTPUT. It is safe only after reading its actual contents as well.
 if awk '{sub(/^\[fastid: [0-9]+\] /,"")}$0=="-A OUTPUT -j NR_OUTPUT"{exit}$0=="-A OUTPUT -j NR_OUT_GUARD"{found=1}END{exit !found}' "$dir/guard.output";then
  iptables -w -S NR_OUT_GUARD > "$dir/guard.prefix" 2>/dev/null || return 1
 fi
 local hooks verified='' hook
 hooks=$(awk '{sub(/^\[fastid: [0-9]+\] /,"")} $0=="-A OUTPUT -j NR_OUTPUT"{exit}
  $1=="-A" && $2=="OUTPUT" && $3=="-j" && NF==4 && $4~/^NR_(HYR_(DIR|FENCE)|HYC_DIR|WG_(DIR|FENCE))$/ && !seen[$4]++{print $4}' "$dir/guard.output") || return 1
 for hook in $hooks;do
  nr_health_direction_prefix "$dir" "$hook" || return 1
  verified="$verified $hook"
 done
 awk -v verified=" $verified " '
  {sub(/^\[fastid: [0-9]+\] /,"")}
  FILENAME==ARGV[1]{if($1~/^[0-9]+$/)table[$2]=$1;next}
  FILENAME==ARGV[2]{
   if(NF==4 && $1~/^[0-9]+$/ && $1>0 && 140+$1<180 && $2~/^wg[0-9]+$/ && $4==1){
    id=$1;name[id]=$2;dev[id]=$3;uid[id]=48100+id
   }next
  }
  FILENAME==ARGV[3]{
   if($0~/^180:[[:space:]]+from all uidrange 48101-48232 prohibit$/)terminal=1
   for(id in name)if($1==(140+id)":" && $4=="uidrange" && $5==uid[id]"-"uid[id]){
    routes[id]++
    if(NF==7 && $2=="from" && $3=="all" && $6=="lookup" &&
       (name[id] in table) && ($7==name[id] || $7==table[name[id]]))correct[id]++
   }next
  }
  FILENAME==ARGV[4]{
   if(NF && !(($1=="-P" && $2=="OUTPUT" && NF==3 && ($3=="ACCEPT" || $3=="DROP")) || ($1=="-A" && $2=="OUTPUT")))output_bad=1
   if($1=="-A" && !hook){
    if($0=="-A OUTPUT -j NR_OUTPUT")hook=1
    else if($0=="-A OUTPUT -j NR_OUT_GUARD")prefix=1
    else if(NF==4 && $3=="-j" && index(verified," "$4" "))next
    else output_bad=1
   }
   next
  }
  FILENAME==ARGV[5]{
   if($0=="-N NR_OUT_GUARD")prefix_declared=1
   else if(NF && !($1=="-A" && $2=="NR_OUT_GUARD" && $(NF-1)=="-j" &&
      ($NF=="DROP" || $NF=="REJECT" || $NF=="RETURN")))prefix_bad=1
   next
  }
  FILENAME==ARGV[6]{
   if(!NF)next
   iface=$2;sub(/@.*/,"",iface);if(iface!~/^(wg|nph)[0-9]+$/)next
   if($3!="inet"){bad=1;next}
   split($4,p,"/");n=split(p[1],a,".");if(n!=4){bad=1;next}
   for(i=1;i<=4;i++)if(a[i]!~/^[0-9]+$/ || a[i]>255)bad=1
   if((p[1] in address_owner) && address_owner[p[1]]!=iface)bad=1
   address_owner[p[1]]=iface;address[iface SUBSEP p[1]]=1
   next
  }
  $0=="-N NR_OUTPUT"{declared=1;next}
  NF && !($1=="-A" && $2=="NR_OUTPUT"){bad=1;next}
  $1=="-A" && $2=="NR_OUTPUT"{
   # Ownerless INVALID resets need their own source/device guard, before any
   # possible bypass. Reuse the invocation address inventory; do not probe
   # until every current local WG IPv4 address has this narrow protection.
   line=$0;sub(/--comment "nr-wg-probe-reset"/,"--comment nr-wg-probe-reset",line)
   if(line~/^-A NR_OUTPUT -s [0-9.]+\/32 ! -o (wg|nph)[0-9]+ -p tcp( -m tcp)? --dport 53 --tcp-flags RST RST -m conntrack --ctstate INVALID -m comment --comment nr-wg-probe-reset -j DROP$/){
    ip=$4;sub(/\/32$/,"",ip);if(!reset_blocked)reset[$7 SUBSEP ip]=1
   }
   if(!(line=="-A NR_OUTPUT -o lo -j RETURN" || (line~/ -p udp / && line!~/ ! -p udp /) ||
      line~/ -j (DROP|REJECT)$/ || line~/^-A NR_OUTPUT -m mark --mark 0x56000000(\/0xffffffff)? -j RETURN$/))reset_blocked=1
   # UDP-only transport permissions cannot match either probe protocol.
   # Other preceding rules must be provably unrelated to this owner, or an
   # exact non-policy WG mark/loopback exemption. Unknown bypasses fail closed.
   owner=proto=target="";negated=0
   for(i=3;i<=NF;i++){
    if($i=="--uid-owner")owner=$(i+1)
    if($i=="-p")proto=$(i+1)
    if($i=="-j" || $i=="-g")target=$(i+1)
    if($i=="!")negated=1
   }
   safe=($0=="-A NR_OUTPUT -o lo -j RETURN" || (proto=="udp" && !negated) || target=="DROP" || target=="REJECT")
   if(NF==8 && $3=="-m" && $4=="mark" && $5=="--mark" && $7=="-j" && $8=="RETURN"){
    mark=tolower($6);sub(/\/0xffffffff$/,"",mark)
    policy=(length(mark)==10 && (substr(mark,3,2)=="55" || substr(mark,3,2)=="58"))
    if(mark~/^0x[0-9a-f]+$/ && mark!~/^0x0+$/ && !policy)safe=1
   }
   for(id in name)if(!guard[id] && !blocked[id]){
    expected="-A NR_OUTPUT -m owner --uid-owner "uid[id]" ! -o "dev[id]" -j DROP"
    canonical="-A NR_OUTPUT ! -o "dev[id]" -m owner --uid-owner "uid[id]" -j DROP"
    if($0==expected || $0==canonical){guard[id]=1;continue}
    if(safe)continue
    if(owner~/^[0-9]+(-[0-9]+)?$/ && !negated){
     split(owner,range,"-");hi=(range[2]==""?range[1]:range[2])
     if(uid[id]<range[1] || uid[id]>hi)continue
    }
    blocked[id]=1
   }
  }
  END{
   if(!terminal || !hook || output_bad || !declared || bad || (prefix && (!prefix_declared || prefix_bad)))exit 1
   for(id in name){
    count=0;missing=0
    for(key in address){split(key,p,SUBSEP);if(p[1]==dev[id]){count++;if(!(key in reset))missing=1}}
    if(count && !missing && routes[id]==1 && correct[id]==1 && guard[id] && !blocked[id])print id,dev[id]
   }
  }' /etc/iproute2/rt_tables "$dir/exits" "$dir/guard.rules" "$dir/guard.output" "$dir/guard.prefix" "$dir/addresses" "$dir/guard.chain" > "$dir/guard.allowed"
}
nr_health_guarded(){
 local dir="${NR_HEALTH_SNAPSHOT:-}"
 [ -n "$dir" ] && [ -d "$dir" ] || return 1
 if [ ! -e "$dir/guard.checked" ];then
  : > "$dir/guard.checked" || return 1
  if nr_health_guard_inventory "$dir";then : > "$dir/guard.ready";fi
 fi
 [ -f "$dir/guard.ready" ] || return 1
 grep -Fx "$1 $2" "$dir/guard.allowed" >/dev/null
}
# These two functions are started with '&' below. Do not add a second (...) 
# function subshell: $! would name its waiting wrapper, not the trap owner.
nr_health_probe_one(){
 local child='' id="$1" dev="$2" target="$3" kind="$4" success="$5"
 local bind=(-I "$dev")
 # The dedicated UID route and checked output guard select/confine WG probes.
 # Forced socket binding can make the native WG path fail despite valid data
 # forwarding. Leave physical-interface callers unchanged.
 case "$dev" in wg[0-9]*) bind=();;esac
 trap '[ -z "$child" ] || { kill -KILL "$child" 2>/dev/null;wait "$child" 2>/dev/null; };true' EXIT
 trap '[ -z "$child" ] || { kill -KILL "$child" 2>/dev/null;wait "$child" 2>/dev/null; };child="";exit 1' HUP INT TERM
 if [ "$kind" = dns ];then
  /usr/bin/lua /usr/ikuai/script/wg_pure_probe.lua "$id" "$dev" "$target" >/dev/null 2>&1 &
 elif [ "$kind" = ping ];then
  /usr/sbin/strict-probe "$id" ikcheck ping "$target" "${bind[@]}" -c 1 -t 1 >/dev/null 2>&1 &
 else
  /usr/sbin/strict-probe "$id" ikcheck tcpping "$target" "${bind[@]}" -c 1 -p 53 -t 1 >/dev/null 2>&1 &
 fi
 child=$!
 if wait "$child";then : > "$success";fi
 child=''
}
nr_health_probe(){
 local id="$1" dev="$2" targets="$3" output="$4" target kind pid pids='' n running
 trap 'for pid in $pids;do kill "$pid" 2>/dev/null || true;done;for pid in $pids;do wait "$pid" 2>/dev/null || true;done' EXIT
 trap 'for pid in $pids;do kill "$pid" 2>/dev/null || true;done;for pid in $pids;do wait "$pid" 2>/dev/null || true;done;pids="";exit 1' HUP INT TERM
 local kinds="ping tcpping"
 [[ "$dev" != nph[0-9]* ]] || kinds=dns
 for target in ${targets//,/ };do for kind in $kinds;do
  nr_health_probe_one "$id" "$dev" "$target" "$kind" "$output.ok" & pids="$pids $!"
 done;done
 # Four exits run concurrently, each at most two targets and two protocols.
 # The native timeout is one second; also bound helper hangs to ~two seconds.
 for n in $(seq 1 20);do
  [ ! -e "$output.ok" ] || break
  running=0;for pid in $pids;do kill -0 "$pid" 2>/dev/null && running=1;done
  [ "$running" = 1 ] || break
  sleep .1
 done
 if [ -e "$output.ok" ];then echo 1 > "$output";else echo 0 > "$output";fi
 # Reap while function-local PIDs still exist; EXIT runs after return and Bash
 # may already have restored the caller's local-variable scope.
 for pid in $pids;do kill "$pid" 2>/dev/null || true;done
 for pid in $pids;do wait "$pid" 2>/dev/null || true;done
 pids='';trap - EXIT HUP INT TERM
}
nr_exit_health_sync()(
 umask 077
 local mode="${1:-}" dir now id iface dev available targets sig stamp value oldsig age due pid known pids='' count=0
 mkdir -p "$NR" || return 1
 dir=$(mktemp -d "$NR/.health.XXXXXX") || return 1
 trap 'for pid in $pids;do kill "$pid" 2>/dev/null || true;done;for pid in $pids;do wait "$pid" 2>/dev/null || true;done;rm -rf "$dir"' EXIT
 trap 'exit 1' HUP INT TERM
 now=$(nr_health_now);case "$now" in ''|*[!0-9]*) return 1;;esac
 # Inventory is copied once, not queried per peer or per packet.
 cp "$NR/exits" "$dir/exits" || return 1
 awk '{n=split($2,a,",");for(i=1;i<=n;i++)if(a[i]!=0)print a[i]}' "$NR/policies" | sort -un > "$dir/used"
 nr_health_inventory "$dir" || return 1
 local NR_HEALTH_SNAPSHOT="$dir"
 awk '{split($4,a,"/");print a[1]}' "$dir/addresses" > "$dir/local"
 : > "$dir/cache";: > "$dir/due";: > "$dir/health"
 while read -r id iface dev available;do
  grep -Fx "$id" "$dir/used" >/dev/null || continue
  targets='';case "$iface" in wg[0-9]*)
   # Keep local address exclusion private to this invocation.
   targets=$(nr_health_targets "$id" "$dir/local" | awk '{s=s sep $0;sep=","}END{print s}');;
  esac
  sig=$(nr_health_signature "$id" "$iface" "$dev" "$available" "$targets")
  oldsig='';stamp=0;value=0
  if [ -f "$NR/exit-health-cache" ];then
   read -r oldsig stamp value < <(awk -v id="$id" '$1==id{print $2,$3,$4;exit}' "$NR/exit-health-cache") || true
  fi
  case "$stamp" in ''|*[!0-9]*) stamp=0;;esac
  case "$value" in 0|1) ;; *) value=0;;esac
  age=$((now-stamp))
  if [ "$oldsig" != "$sig" ] || [ "$age" -lt 0 ] || [ "$age" -gt 60 ];then stamp=0;value=0;fi
  if [ "$available" != 1 ] || ! nr_health_device "$iface" "$dev";then
   value=0;stamp="$now"
  else case "$iface" in
   wg[0-9]*)
    if [ -z "$targets" ];then value=0;stamp=0
    elif [ "$stamp" = 0 ] || [ "$((now-stamp))" -ge 10 ];then
     printf '%s %s %s %s\n' "$stamp" "$id" "$dev" "$targets" >> "$dir/due"
    fi;;
   *) if nr_health_native "$iface" "$dev";then value=1;stamp="$now"
      else case "$?" in 1) stamp="$now";;*) stamp=0;;esac;value=0;fi;;
  esac;fi
  printf '%s %s %s %s\n' "$id" "$sig" "$stamp" "$value" >> "$dir/cache"
 done < "$dir/exits"
 # Oldest-first bounds work without starving the fifth or later exit.
 sort -n "$dir/due" > "$dir/order"
 while read -r stamp id dev targets;do
  [ "$count" -lt 4 ] || break
  if nr_health_guarded "$id" "$dev";then
   count=$((count+1))
   nr_health_probe "$id" "$dev" "$targets" "$dir/result.$id" & pids="$pids $!"
  else : > "$dir/unknown.$id";fi
 done < "$dir/order"
 for pid in $pids;do wait "$pid" || true;done;pids=''
 : > "$dir/next"
 while read -r id sig stamp value;do
  if [ -f "$dir/result.$id" ];then read -r value < "$dir/result.$id";stamp="$now";fi
  if [ -f "$dir/unknown.$id" ];then value=0;stamp=0;fi
  case "$value" in 1) ;; *) value=0;;esac
  known=0;[ "$stamp" = 0 ] || known=1
  printf '%s %s %s %s\n' "$id" "$sig" "$stamp" "$value" >> "$dir/next"
  printf '%s %s %s\n' "$id" "$value" "$known" >> "$dir/health"
 done < "$dir/cache"
 # Caller holds STATE lock. Do not publish if its inventory changed anyway.
 cmp -s "$dir/exits" "$NR/exits" || return 1
 mv "$dir/next" "$NR/exit-health-cache" || return 1
 mv "$dir/health" "$NR/exit-health" || return 1
 # nr_exit registers WG candidates; native monitoring does not scan WG.
 # Keep the native NTH second-stage check consistent with our prefilter.
 while read -r id iface dev available;do case "$iface" in wg[0-9]*)
  value=$(awk -v id="$id" '$1==id{print $2;exit}' "$NR/exit-health")
  [ "$value" ] || continue
  ik_cntl iface_band set "$iface" "$value" >/dev/null 2>&1 || return 1;;
 esac;done < "$dir/exits"
)
