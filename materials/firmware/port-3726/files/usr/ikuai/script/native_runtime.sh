#!/bin/bash
NR=/tmp/iktmp/native-rules
# Health sampling is separate from policy selection; both apply and reconcile use it.
source /usr/ikuai/script/native_exit_health.sh
NR_IFACES='lan+ vlan+ ppp+ tap+ sovpn sdwan+ ikec+ doc_+ wg+'
nr_ingress(){ local dev;for dev in $NR_IFACES;do nr_ipt -t "$1" -A "$2" -i "$dev" -j "$3";done; }
nr_ipt(){ iptables -w "$@"; }
nr_chain(){ nr_ipt -t "$1" -N "$2" 2>/dev/null || true;nr_ipt -t "$1" -F "$2"; }
nr_hook(){ while nr_ipt -t "$1" -D "$2" -j "$3" 2>/dev/null;do :;done;nr_ipt -t "$1" -I "$2" 1 -j "$3"; }
# Dedicated DNS/probe UIDs must select the table on the initial route lookup.
# This kernel does not reliably reroute locally generated packets after OUTPUT MARK.
# Keep a terminal rule across applies so removed/missing exits cannot use main.
nr_owner_routes_begin(){
 # Consume the full producer output: grep -q can cause SIGPIPE under pipefail,
 # misreport an existing rule and abort apply with EEXIST, leaving the guard set.
 ip rule show | grep -E '^180:.*uidrange 48101-48232.*prohibit' >/dev/null || ip rule add pref 180 uidrange 48101-48232 prohibit
 local pref uid
 if [ -f "$NR/owner-routes" ];then
  while read -r pref uid;do
   while ip rule del pref "$pref" uidrange "$uid-$uid" 2>/dev/null;do :;done
  done < "$NR/owner-routes"
 fi
 : > "$NR/owner-routes"
}
nr_owner_route(){
 local uid="$1" iface="$2" pref="$3"
 if grep -Eq "[[:space:]]${iface}([[:space:]]|$)" /etc/iproute2/rt_tables;then
  ip rule add pref "$pref" uidrange "$uid-$uid" table "$iface"
  printf '%s %s\n' "$pref" "$uid" >> "$NR/owner-routes"
 fi
}
# Reconcile the dedicated probe routes against kernel state, not owner-routes
# bookkeeping. DNS worker routes remain controlled by their selected policy.
# The optional snapshot belongs to this call only and can also be passed to the
# transport synchronizer, keeping a reconcile cycle to one ip-rule inventory.
nr_probe_owner_routes_sync(){
 local rules plan action pref uid iface count n
 if [ "$#" -gt 0 ];then rules="$1";else rules=$(ip rule show) || return 1;fi
 [ -n "$rules" ] || return 1
 plan=$(printf '%s\n' "$rules" | awk '
  FILENAME==ARGV[1] {if($1~/^[0-9]+$/ && $2~/^[A-Za-z][A-Za-z0-9_.-]*$/)tables[$2]=$1;next}
  FILENAME==ARGV[2] {
   if(NF!=4 || $1!~/^[0-9]+$/ || $1<1 || 140+$1>=180 || 48100+$1>=48201 ||
      $2!~/^[A-Za-z][A-Za-z0-9_.-]*$/ || ($4!=0 && $4!=1) || seen[$1]++)exit 1
   if($4==1 && !($2 in tables))exit 1
   order[++n]=$1;names[$1]=$2;available[$1]=$4;next
  }
  {
   if($1=="180:" && NF==6 && $2=="from" && $3=="all" && $4=="uidrange" &&
      $5=="48101-48232" && $6=="prohibit")terminal=1
   if($1=="180:")for(i=4;i<NF;i++)if($i=="uidrange" && $(i+1)=="48101-48232" &&
      !(NF==6 && $2=="from" && $3=="all" && $4=="uidrange" && $6=="prohibit"))badterminal=1
   for(i=4;i<NF;i++)if($i=="uidrange"){
    split($(i+1),u,"-");id=u[1]-48100
    if(u[1]==u[2] && (id in names) && $1==(140+id)":"){
     count[id]++
     if(NF==7 && $2=="from" && $3=="all" && $4=="uidrange" && $6=="lookup" &&
        ($7==names[id] || $7==tables[names[id]]))correct[id]++
    }
   }
  }
  END {
   if(badterminal)exit 1
   if(!terminal)print "B 180 48101-48232 prohibit"
   for(j=1;j<=n;j++){id=order[j];uid=48100+id;pref=140+id
    if(available[id]==0){if(count[id])print "D",pref,uid,names[id],count[id]}
    else if(count[id]!=1 || correct[id]!=1)print "R",pref,uid,names[id],count[id]+0
   }
  }' /etc/iproute2/rt_tables "$NR/exits" -) || return 1
 while read -r action pref uid iface count;do
  [ -n "$action" ] || continue
  if [ "$action" = B ];then
   ip rule add pref "$pref" uidrange "$uid" prohibit || return 1
  else
   # This pref+UID pair is reserved by nr_exit. Do not touch another UID,
   # another priority, a DNS worker, or any user's ordinary routing rule.
   for ((n=0;n<count;n++));do ip rule del pref "$pref" uidrange "$uid-$uid" || return 1;done
   [ "$action" != R ] || ip rule add pref "$pref" uidrange "$uid-$uid" table "$iface" || return 1
  fi
 done <<< "$plan"
}
# An INVALID TCP reset has neither its original socket UID nor conntrack mark.
# Protect only local WG DNS-reset traffic sent to a different output device.
nr_wg_probe_reset_install(){
 local dev="$1" snapshot addresses addr
 snapshot=$(ip -o -4 addr show dev "$dev") || return 1
 addresses=$(printf '%s\n' "$snapshot" | awk -v dev="$dev" '
  NF {name=$2;sub(/@.*/,"",name);if(name!=dev || $3!="inet"){bad=1;next}
   split($4,p,"/");n=split(p[1],a,".");if(n!=4){bad=1;next}
   for(i=1;i<=4;i++)if(a[i]!~/^[0-9]+$/ || a[i]>255)bad=1
   if(!seen[p[1]]++)print p[1]
  }END{if(bad)exit 1}') || return 1
 while read -r addr;do
  [ -n "$addr" ] || continue
  nr_ipt -I NR_OUTPUT 2 -s "$addr/32" ! -o "$dev" -p tcp --dport 53 --tcp-flags RST RST -m conntrack --ctstate INVALID -m comment --comment nr-wg-probe-reset -j DROP || return 1
 done <<< "$addresses"
}
# Both inventories belong to this synchronization call. Retain old-address
# guards for late packets, but transfer a reused address to its current WG.
nr_wg_probe_reset_sync(){
 local kernel="$1" addresses="$2" managed="$3" plan action addr dev copies n
 plan=$(awk -v managed="$managed" '
  BEGIN{n=split(managed,m," ");for(i=1;i<=n;i++)if(m[i]!="")used[m[i]]=1}
  FILENAME==ARGV[1]{
   if(!NF)next
   name=$2;sub(/@.*/,"",name);if(name!~/^wg[0-9]+$/)next
   if($3!="inet"){bad=1;next}
   split($4,p,"/");n=split(p[1],a,".");if(n!=4){bad=1;next}
   for(i=1;i<=4;i++)if(a[i]!~/^[0-9]+$/ || a[i]>255)bad=1
   ip=p[1];if((ip in current) && current[ip]!=name)bad=1
   current[ip]=name;if(name in used)wanted[ip" "name]=1
   next
  }
  {sub(/^\[fastid: [0-9]+\] /,"")}
  $0=="-N NR_OUTPUT"{declared=1;next}
  NF && !($1=="-A" && $2=="NR_OUTPUT"){bad=1;next}
  $1=="-A" && $2=="NR_OUTPUT"{
   position++;line=$0;sub(/--comment "nr-wg-probe-reset"/,"--comment nr-wg-probe-reset",line)
   if(line~/^-A NR_OUTPUT -s [0-9.]+\/32 ! -o wg[0-9]+ -p tcp( -m tcp)? --dport 53 --tcp-flags RST RST -m conntrack --ctstate INVALID -m comment --comment nr-wg-probe-reset -j DROP$/){
    ip=$4;sub(/\/32$/,"",ip);key=ip" "$7;count[key]++;if(!first[key])first[key]=position;oldip[key]=ip;olddev[key]=$7;next
   }
   # UDP encapsulation, loopback and a terminal DROP cannot bypass this
   # TCP-only guard. The reserved WG outer mark is never an inner TCP reset.
   if(line=="-A NR_OUTPUT -o lo -j RETURN" || (line~/ -p udp / && line!~/ ! -p udp /) ||
      line~/ -j (DROP|REJECT)$/ || line~/^-A NR_OUTPUT -m mark --mark 0x56000000(\/0xffffffff)? -j RETURN$/)next
   if(!barrier)barrier=position
  }
  END{
   if(!declared || bad)exit 1
   for(key in count)if((oldip[key] in current) && current[oldip[key]]!=olddev[key])wanted[oldip[key]" "current[oldip[key]]]=1
   for(key in wanted)if(!count[key] || (barrier && first[key]>=barrier)){
    if(barrier==1)exit 1
    print "A",key
   }
   for(key in count)if((oldip[key] in current) && current[oldip[key]]!=olddev[key])print "D",key,count[key]
  }' <(printf '%s\n' "$addresses") <(printf '%s\n' "$kernel")) || return 1
 while read -r action addr dev copies;do
  [ -n "$action" ] || continue
  if [ "$action" = A ];then
   # Add before removing conflicting old ownership. A late duplicate DROP is
   # harmless and retained, avoiding any gap during ordering repair.
   nr_ipt -I NR_OUTPUT 2 -s "$addr/32" ! -o "$dev" -p tcp --dport 53 --tcp-flags RST RST -m conntrack --ctstate INVALID -m comment --comment nr-wg-probe-reset -j DROP || return 1
  else
   for ((n=0;n<copies;n++));do
    nr_ipt -D NR_OUTPUT -s "$addr/32" ! -o "$dev" -p tcp --dport 53 --tcp-flags RST RST -m conntrack --ctstate INVALID -m comment --comment nr-wg-probe-reset -j DROP || return 1
   done
  fi
 done <<< "$plan"
}
# WG encapsulation can retain the originating DNS socket owner. Native WG
# OUTPUT policy restores a WAN connmark after NR_OUT, replacing the WG fwmark.
# Permit only active WG listen ports with an exact native transport mark.
# Plain managed DNS/probes retain 0x55xxxxxx and must still pass exit guards.
nr_wg_transport_sync(){
 local next="$NR/wg-transport.next" state="$NR/wg-transport" iface port mark id dev available
 local rule_dump rule_marks='' rule_marks_ready=0 kernel present missing copies n managed='' addresses=''
 : > "$next"
 while read -r id iface dev available;do
  case "$iface" in wg[0-9]*) ;; *) continue;;esac
  managed="${managed:+$managed }$iface"
  ip -o link show "$iface" 2>/dev/null | grep '[,<]UP[,>]' >/dev/null || continue
  port=$(wg show "$iface" listen-port 2>/dev/null)
  case "$port" in ''|*[!0-9]*|0) continue;;esac
  # All exits consult the same policy table. Read it lazily once per call,
  # never across calls: WAN recovery and mark changes must remain visible.
  if [ "$rule_marks_ready" = 0 ];then
   if [ "$#" -gt 0 ];then rule_dump="$1";else rule_dump=$(ip rule show) || { rm -f "$next";return 1; };fi
   rule_marks=$(set -o pipefail;printf '%s\n' "$rule_dump" | awk '{for(i=1;i<NF;i++)if($i=="fwmark" && $(i+1)~/^0x[0-9a-fA-F]+$/ && $(i+2)=="lookup")print $(i+1)}' | sort -u) || { rm -f "$next";return 1; }
   rule_marks_ready=1
  fi
  while read -r mark;do
   [ -n "$mark" ] || continue
   case "$((mark & 0xff000000))" in "$((0x55000000))"|"$((0x58000000))") continue;;esac
   [ "$mark" != 0x0 ] || continue
   printf '%s %s\n' "$port" "$mark" >> "$next"
  done <<< "$rule_marks"
 done < "$NR/exits"
 sort -u "$next" -o "$next"
 if [ -n "$managed" ];then
  addresses=$(ip -o -4 addr show) || { rm -f "$next";return 1; }
  [ -n "$addresses" ] || { rm -f "$next";return 1; }
 fi
 # A surviving text cache does not prove that a firewall reload preserved the
 # kernel exceptions or their position before probe/worker owner guards. One
 # chain inventory replaces per-pair -C calls; normal state performs no writes.
 if [ -n "$managed" ] || [ -s "$next" ] || [ -s "$state" ];then
  kernel=$(nr_ipt -S NR_OUTPUT) || { rm -f "$next";return 1; }
  present=$(printf '%s\n' "$kernel" | awk '
   {sub(/^\[fastid: [0-9]+\] /,"")}
   $0=="-N NR_OUTPUT" {declared=1;next}
   NF && !($1=="-A" && $2=="NR_OUTPUT") {bad=1;next}
   $1=="-A" && $2=="NR_OUTPUT" {
    position++;port=mark=owner=comment=target=proto="";valid=1;negated=0
    for(i=3;i<=NF;i++){
     if($i=="-p")proto=$(++i)
     else if($i=="--sport")port=$(++i)
     else if($i=="--mark")mark=$(++i)
     else if($i=="--uid-owner")owner=$(++i)
     else if($i=="--comment"){comment=$(++i);gsub(/"/,"",comment)}
     else if($i=="-j")target=$(++i)
     else if($i=="-m"){module=$(++i);if(module!="udp" && module!="mark" && module!="owner" && module!="comment")valid=0}
     else {valid=0;if($i=="!")negated=1}
    }
    sub(/\/0xffffffff$/,"",mark);mark=tolower(mark)
    exact=(valid && proto=="udp" && port~/^[0-9]+$/ && mark~/^0x[0-9a-f]+$/ &&
       owner=="48101-48232" && comment=="nr-wg-transport" && target=="RETURN")
    if(exact)print "E",port,mark,position
    else if(owner!="" && !barrier){
     split(owner,range,"-");lo=range[1];hi=range[2]==""?lo:range[2]
     if(negated || owner!~/^[0-9]+(-[0-9]+)?$/ || (lo<=48232 && hi>=48101))barrier=position
    }
   }
   END{if(!declared || bad)exit 1;if(barrier)print "B",barrier}') || { rm -f "$next";return 1; }
  missing=$(printf '%s\n' "$present" | awk '
   FILENAME==ARGV[1]{if($1=="B")barrier=$2;else if($1=="E"){key=$2" "$3;count[key]++;if(!first[key])first[key]=$4}next}
   {key=$0;if(count[key]!=1 || (barrier && first[key]>=barrier)){
    # Slot 2 must precede owner control. An unexpected first-row owner rule is
    # ambiguous; fail for the caller guard instead of adding a broad bypass.
    if(barrier==1)bad=1
    print $1,$2,count[key]+0
   }}END{if(bad)exit 1}' - "$next") || { rm -f "$next";return 1; }
  while read -r port mark copies;do
   [ -n "$port" ] || continue
   # Remove only identical owned permissions. Delete-before-insert can briefly
   # block this transport but cannot open an inner DNS/probe path to another WAN.
   for ((n=0;n<copies;n++));do
    nr_ipt -D NR_OUTPUT -p udp --sport "$port" -m mark --mark "$mark" -m owner --uid-owner 48101-48232 -m comment --comment nr-wg-transport -j RETURN || { rm -f "$next";return 1; }
   done
   nr_ipt -I NR_OUTPUT 2 -p udp --sport "$port" -m mark --mark "$mark" -m owner --uid-owner 48101-48232 -m comment --comment nr-wg-transport -j RETURN || { rm -f "$next";return 1; }
  done <<< "$missing"
  [ -z "$managed" ] || nr_wg_probe_reset_sync "$kernel" "$addresses" "$managed" || { rm -f "$next";return 1; }
 fi
 cmp -s "$next" "$state" && { rm -f "$next";return 0; }
 if [ -f "$state" ];then
  while read -r port mark;do
   grep -Fxq "$port $mark" "$next" && continue
   # Use the same actual-chain inventory for retired entries. A missing rule
   # needs no deletion; a real deletion failure must retain the old cache so
   # the caller guards traffic and the next cycle can retry it.
   copies=$(printf '%s\n' "$present" | awk -v port="$port" -v mark="$mark" '$1=="E" && $2==port && $3==mark{n++}END{print n+0}')
   for ((n=0;n<copies;n++));do
    nr_ipt -D NR_OUTPUT -p udp --sport "$port" -m mark --mark "$mark" -m owner --uid-owner 48101-48232 -m comment --comment nr-wg-transport -j RETURN || { rm -f "$next";return 1; }
   done
  done < "$state"
 fi
 mv "$next" "$state"
}

# Runs inside the existing routing transaction/guard. It never changes INPUT,
# OUTPUT, DNS upstreams, connmarks, or the user-selected failover policy.
nr_edns_set(){
 local name="$1" type="$2" entries="$3" item
 ipset create "$name" "$type" family inet maxelem 256 -exist || return 1
 ipset flush "$name" || return 1
 while read -r item;do
  [ -n "$item" ] || continue
  # hash:net does not accept /0; retain an explicitly entered whole IPv4 scope.
  if [ "$item" = 0.0.0.0/0 ];then
   ipset add "$name" 0.0.0.0/1 || return 1
   ipset add "$name" 128.0.0.0/1 || return 1
  else ipset add "$name" "$item" -exist || return 1;fi
 done <<< "$entries"
}
nr_encrypted_dns_off(){
 NR_EDNS_ENABLED=0
 while nr_ipt -D FORWARD -j NR_EDNS 2>/dev/null;do :;done
 local chain name
 for chain in NR_EDNS NR_EDNS_DROP;do nr_ipt -F "$chain" 2>/dev/null || true;done
 for chain in NR_EDNS NR_EDNS_DROP;do nr_ipt -X "$chain" 2>/dev/null || true;done
 for name in nr_edns_src nr_edns_except nr_edns_allow nr_edns_dest;do ipset destroy "$name" 2>/dev/null || true;done
}
nr_encrypted_dns(){
 local sources="$1" ingress="$2" exceptions="$3" allowed="$4" destinations="$5" dot="$6" doh="$7" dev
 NR_EDNS_ENABLED=1
 nr_edns_set nr_edns_src hash:net "$sources" || return 1
 nr_edns_set nr_edns_except hash:net "$exceptions" || return 1
 nr_edns_set nr_edns_allow hash:ip "$allowed" || return 1
 nr_edns_set nr_edns_dest hash:ip "$destinations" || return 1
 nr_chain filter NR_EDNS
 nr_chain filter NR_EDNS_DROP
 nr_ipt -A NR_EDNS -m conntrack --ctdir REPLY -j RETURN
 [ -z "$sources" ] || nr_ipt -A NR_EDNS -m set ! --match-set nr_edns_src src -j RETURN
 nr_ipt -A NR_EDNS -m set --match-set nr_edns_except src -j RETURN
 nr_ipt -A NR_EDNS -m set --match-set nr_edns_allow dst -j RETURN
 if [ -n "$ingress" ];then
  nr_ipt -A NR_EDNS -i "$ingress" -j NR_EDNS_DROP
  case "$ingress" in wg[0-9]*) nr_ipt -A NR_EDNS -i "ppp$ingress" -j NR_EDNS_DROP;;esac
 else nr_ingress filter NR_EDNS NR_EDNS_DROP;fi
 if [ "$dot" = 1 ];then
  nr_ipt -A NR_EDNS_DROP -p tcp --dport 853 -m comment --comment nr-edns-dot -j DROP
  nr_ipt -A NR_EDNS_DROP -p udp --dport 853 -m comment --comment nr-edns-doq -j DROP
 fi
 if [ "$doh" = 1 ];then
  for dev in tcp udp;do nr_ipt -A NR_EDNS_DROP -p "$dev" --dport 443 -m set --match-set nr_edns_dest dst -m comment --comment nr-edns-doh -j DROP;done
 fi
}

nr_reset_evidence(){
 ipset create nr_quarantine hash:net,net timeout 61 maxelem 262144 -exist
 if [ "${NR_RESET:-0}" = 1 ];then
 for s in $(ipset list -name|grep -E '^nr_[dh]_[0-9]');do
  if [ "${NR_PRESERVE_EVIDENCE:-0}" = 1 ] && [ -f "$NR/active/dns-preserve.ids" ] &&
     grep -Fxq "${s##*_}" "$NR/active/dns-preserve.ids";then continue;fi
  ipset save "$s"|awk '$1=="add"{print "add nr_quarantine "$3" timeout 61"}'|ipset restore -exist
  ipset flush "$s"
 done
 # Record after inserting all entries, rounding uptime upward by one second.
 # Diagnostic upper bound only; the actual per-entry ipset expiry is unchanged.
 # No entries/addresses are copied into the UI and a reporting failure must not
 # change enforcement. Updates that preserve every set may overestimate time.
 local quarantine_now quarantine_rest
 if read -r quarantine_now quarantine_rest < /proc/uptime;then
  quarantine_now=${quarantine_now%%.*}
  case "$quarantine_now" in ''|*[!0-9]*) ;; *)
   if printf '%s\n' "$((quarantine_now+62))" > "$NR/.quarantine-window.$$";then
    mv "$NR/.quarantine-window.$$" "$NR/quarantine-window" 2>/dev/null || rm -f "$NR/.quarantine-window.$$"
   fi;;esac
 fi
 fi
}

nr_begin(){
 # Classifier alternatives may share a complete exit guard within this apply.
 # Never carry installation state across a kernel-chain rebuild.
 NR_GUARD_KEYS=()
 nr_owner_routes_begin
 rm -f "$NR/wg-transport" "$NR/wg-transport.next"
 for spec in 'mangle NR_SCOPE' 'mangle NR_CLASS' 'mangle NR_FALLBACK' 'mangle NR_LOWER' 'mangle NR_STRICT' 'mangle NR_OUT' 'mangle NR_FAST' 'mangle NR_EGRESS' 'filter NR_FWD' 'filter NR_INPUT' 'filter NR_OUTPUT' 'nat NR_DNS' 'nat NR_DNS_I' 'nat NR_DNS53' 'nat NR_NAT';do nr_chain $spec;done
 # Standard chains no longer reference the previous policy/worker chains.
 local pid eids mode band wid dns table chain
 if [ -f "$NR/policies" ];then while read -r pid eids mode band;do
  for table in mangle filter;do for chain in "NR_P$pid" "NR_B$pid";do nr_ipt -t "$table" -F "$chain" 2>/dev/null || true;nr_ipt -t "$table" -X "$chain" 2>/dev/null || true;done;done
 done < "$NR/policies";fi
 if [ -f "$NR/policy-workers" ];then while read -r wid pid dns;do
  nr_ipt -t mangle -F "NR_W$wid" 2>/dev/null || true;nr_ipt -t mangle -X "NR_W$wid" 2>/dev/null || true
  nr_ipt -t mangle -F "NR_E$wid" 2>/dev/null || true;nr_ipt -t mangle -X "NR_E$wid" 2>/dev/null || true
  nr_ipt -F "NR_D$wid" 2>/dev/null || true;nr_ipt -X "NR_D$wid" 2>/dev/null || true
 done < "$NR/policy-workers";fi
 : > "$NR/policies";: > "$NR/policy-workers"
 if [ "${NR_KEEP_POLICY_WORKERS:-0}" != 1 ];then
  rm -f "$NR/worker-restart.ids"
  rm -rf "$NR/worker-state"
 fi
 rm -rf "$NR/policy-state"
 mkdir -p "$NR/policy-state" "$NR/worker-state"
 nr_reset_evidence
 local bindaddr bindiface proto
 while read -r bindaddr bindiface;do
  for proto in udp tcp;do
   nr_ipt -t nat -A NR_DNS53 -i "$bindiface" -p "$proto" --dport 53 -j DNAT --to-destination "$bindaddr:53"
   nr_ipt -A NR_INPUT -i "$bindiface" -d "$bindaddr" -p "$proto" --dport 53 -j ACCEPT
  done
  nr_ipt -A NR_INPUT -d "$bindaddr" -j DROP
 done < "$NR/active/dns-bindings"
 # An admitted DNS scope with a missing listener must fail closed.
 for proto in udp tcp;do nr_ipt -t nat -A NR_DNS53 -p "$proto" -j REDIRECT --to-ports 6153;done
 nr_ingress mangle NR_SCOPE NR_CLASS
 nr_ingress nat NR_DNS_I NR_DNS
 nr_ipt -t mangle -A NR_CLASS -m conntrack --ctdir REPLY -j RETURN
 nr_ipt -t mangle -A NR_CLASS -m addrtype --dst-type LOCAL -j RETURN
 nr_ipt -t mangle -A NR_CLASS -m local_host --dir dst -j RETURN
 nr_ipt -t mangle -A NR_CLASS -m set --match-set nr_quarantine dst,src -j DROP
 nr_ipt -t mangle -A NR_CLASS -i pppwg+ -j DPROTO
 nr_ipt -t mangle -A NR_CLASS -m connmark --mark 0x55000000/0xff000000 -j CONNMARK --restore-mark
 nr_ipt -t mangle -A NR_CLASS -m mark --mark 0x55000000/0xff000000 -j ACCEPT
 nr_ipt -t mangle -A NR_FAST -m connmark --mark 0x55000000/0xff000000 -j ACCEPT
 nr_ipt -t mangle -A NR_CLASS -m connmark --mark 0x58000000/0xff000000 -j CONNMARK --restore-mark
 nr_ipt -t mangle -A NR_CLASS -m mark --mark 0x58000000/0xff000000 -j ACCEPT
 nr_ipt -t mangle -A NR_FAST -m connmark --mark 0x58000000/0xff000000 -j ACCEPT
 nr_ipt -A NR_OUTPUT -o lo -j RETURN
 nr_ipt -A NR_INPUT -i lo -j RETURN
 for dev in $NR_IFACES;do nr_ipt -A NR_INPUT -i "$dev" -p udp --dport 6153 -j ACCEPT;nr_ipt -A NR_INPUT -i "$dev" -p tcp --dport 6153 -j ACCEPT;done
 # An upstream query can randomly use a protected listener port as its source.
 # Let only tracked replies continue through the remaining native INPUT rules.
 # New inbound connections to worker ports must remain blocked below.
 for proto in udp tcp;do
  nr_ipt -A NR_INPUT -p "$proto" --dport 6153:6232 -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN
 done
 nr_ipt -A NR_INPUT -p udp --dport 6153:6232 -j DROP
 nr_ipt -A NR_INPUT -p tcp --dport 6153:6232 -j DROP
 : > "$NR/exits"
}
nr_addr(){ (set +e;ipset_rule_new_add "$1" "$2";exit 0);ipset list "$1" -terse >/dev/null; }
nr_domain_set(){ ipset create "nr_d_$1" hash:net,net timeout 120 maxelem 262144 -exist;ipset create "nr_h_$1" hash:net,net timeout 720 maxelem 262144 -exist; }
nr_exit(){
 local id="$1" iface="$2" dev="$2" mask=0xff0000ff mark=$((0x55000000+$1)) pref=$((500+$1*2))
 interface_check_routing_exit "$iface" || return 1
 [ ! -e "/sys/class/net/${iface}_ad" ] || dev="${iface}_ad"
 # Missing routes remain prohibited. Create a named table only for configured WG interfaces.
 local available=0
 grep -Eq "[[:space:]]${iface}([[:space:]]|$)" /etc/iproute2/rt_tables && available=1
 while ip rule del pref "$pref" 2>/dev/null;do :;done
 while ip rule del pref "$((pref+1))" 2>/dev/null;do :;done
 ip rule add pref "$((pref+1))" fwmark "$mark/$mask" prohibit
 if [ "$available" = 1 ];then ip rule add pref "$pref" fwmark "$mark/$mask" table "$iface";fi
 # A selected unbound candidate is still confined to its physical route. Only
 # that policy's explicit eid=0 fallback may use the native default table.
 local freepref=$((600+id*2)) freemark=$((0x58000000+id))
 while ip rule del pref "$freepref" 2>/dev/null;do :;done
 while ip rule del pref "$((freepref+1))" 2>/dev/null;do :;done
 ip rule add pref "$((freepref+1))" fwmark "$freemark/$mask" prohibit
 if [ "$available" = 1 ];then ip rule add pref "$freepref" fwmark "$freemark/$mask" table "$iface";fi
 case "$iface" in wg[0-9]*)
  # Native NTH also consults iface_band for multi-candidate selection. WG has
  # no native monitor loop; register its existing route identity here, then
  # the physical health helper publishes its probed status after each sample.
  if [ "$available" = 1 ];then
   local native_id=$(awk -v iface="$iface" '$2==iface && $1~/^[0-9]+$/{print $1;exit}' /etc/iproute2/rt_tables)
   [ -n "$native_id" ] || return 1
   ik_cntl iface_band add "$iface" "$native_id" >/dev/null || return 1
  fi
  if [ -e "/sys/class/net/$iface" ];then
   local wm=$(wg show "$iface" fwmark)
   if [ "$wm" = off ] || [ "$wm" = 0 ];then wg set "$iface" fwmark 0x56000000;wm=0x56000000;fi
   nr_ipt -t mangle -A NR_OUT -m mark --mark "$wm" -j RETURN
   nr_ipt -A NR_OUTPUT -m mark --mark "$wm" -j RETURN
   nr_wg_probe_reset_install "$dev" || return 1
   [ "$available" != 1 ] || ip route replace default dev "$iface" table "$iface" metric 100
  fi;;esac
 nr_ipt -t mangle -A NR_EGRESS -m connmark --mark "$mark" -m conntrack --ctdir REPLY -j RETURN
 nr_ipt -t mangle -A NR_EGRESS -m connmark --mark "$mark" -o "$dev" -j RETURN
 nr_ipt -t mangle -A NR_EGRESS -m connmark --mark "$mark" -j DROP
 # Randomize TCP to avoid rapid tuple reuse; this kernel conflicts on random UDP NAT.
 nr_ipt -t nat -A NR_NAT -m connmark --mark "$mark/$mask" -o "$dev" -p tcp -j MASQUERADE --random-fully
 nr_ipt -t nat -A NR_NAT -m connmark --mark "$mark/$mask" -o "$dev" -j MASQUERADE
 local uid=$((48100+id))
 nr_owner_route "$uid" "$iface" "$((140+id))"
 nr_ipt -t mangle -A NR_OUT -m owner --uid-owner "$uid" ! -o lo -j MARK --set-mark "$mark"
 nr_ipt -t mangle -A NR_OUT -m owner --uid-owner "$uid" ! -o lo -j ACCEPT
 nr_ipt -A NR_OUTPUT -m owner --uid-owner "$uid" ! -o "$dev" -j DROP
 nr_ipt -A NR_OUTPUT -m owner --uid-owner "$uid" -j RETURN
 printf '%s %s %s %s\n'  "$id" "$iface" "$dev" "$available" >> "$NR/exits"
}
nr_worker(){
 local id="$1" pid="$2" dns="$3" uid=$((48200+$1)) band base
 band=$(awk -v id="$pid" '$1==id{print $4;exit}' "$NR/policies");base=$(nr_policy_base "$pid" "$band")
 printf '%s %s %s\n' "$id" "$pid" "$dns" >> "$NR/policy-workers"
 grep -q "^nrdns$id:" /etc/passwd || printf 'nrdns%s:x:%s:0:Native DNS:/nonexistent:/bin/false\n' "$id" "$uid" >> /etc/passwd
 nr_chain mangle "NR_W$id";nr_ipt -t mangle -A "NR_W$id" -j DROP
 nr_chain mangle "NR_E$id";nr_ipt -t mangle -A "NR_E$id" -j DROP
 nr_chain filter "NR_D$id";nr_ipt -A "NR_D$id" -j DROP
 nr_ipt -t mangle -A NR_OUT -m owner --uid-owner "$uid" ! -o lo -j "NR_W$id"
 nr_ipt -A NR_OUTPUT -m owner --uid-owner "$uid" -g "NR_D$id"
 # Native routing can copy the local packet mark into conntrack before
 # POSTROUTING. DNS-only policies have no data-rule egress allowance, so each
 # private worker needs its own exact guard. Outer WG transport and forwarded
 # client packets cannot use this owner + policy-connmark entry.
 nr_ipt -t mangle -A NR_EGRESS -m owner --uid-owner "$uid" -m connmark --mark "$base/0xffffff00" -g "NR_E$id"
 # DNS routing is selected before OUTPUT by its private owner rule. Its mark
 # preserves strategy identity and remains distinct from all bound workers.
 nr_ipt -t nat -A NR_NAT -m mark --mark "$base/0xffffff00" -p tcp -j MASQUERADE --random-fully
 nr_ipt -t nat -A NR_NAT -m mark --mark "$base/0xffffff00" -j MASQUERADE
}
nr_policy(){
 local pid="$1" eids="$2" mode="$3" band="$4"
 printf '%s %s %s %s\n' "$pid" "$eids" "$mode" "$band" >> "$NR/policies"
 nr_chain mangle "NR_P$pid";nr_ipt -t mangle -A "NR_P$pid" -j DROP
 nr_chain mangle "NR_B$pid";nr_ipt -t mangle -A "NR_B$pid" -j DROP
 nr_chain filter "NR_B$pid";nr_ipt -A "NR_B$pid" -j DROP
}
nr_policy_base(){ if [ "$2" = 1 ];then echo $((0x55000000+$1*256));else echo $((0x58000000+$1*256));fi; }
nr_guard_emitted(){
 local key="$1" saved
 for saved in "${NR_GUARD_KEYS[@]}";do [ "$saved" != "$key" ] || return 0;done
 return 1
}
# Deduplicate complete, byte-identical guard bundles only. The full policy
# mark, actual device and unmodified OR-window string are all part of identity;
# different policies/binding modes/windows remain independent and ordered.
nr_exit_guard(){
 local mark="$1" dev="$2" windows="$3" key table chain time
 printf -v key 'exit %q %q %q' "$mark" "$dev" "$windows"
 nr_guard_emitted "$key" && return 0
 for table in filter mangle;do
  chain=NR_FWD;[ "$table" != mangle ] || chain=NR_EGRESS
  while IFS= read -r time;do
   nr_ipt -t "$table" -A "$chain" -m connmark --mark "$mark" $time -m conntrack --ctdir REPLY -j RETURN || return 1
   nr_ipt -t "$table" -A "$chain" -m connmark --mark "$mark" $time -o "$dev" -j RETURN || return 1
  done <<< "$windows"
  nr_ipt -t "$table" -A "$chain" -m connmark --mark "$mark" -j DROP || return 1
 done
 NR_GUARD_KEYS+=("$key")
}
nr_fallback_guard(){
 local pid="$1" base="$2" windows="$3" key table chain time
 printf -v key 'fallback %q %q %q' "$pid" "$base" "$windows"
 nr_guard_emitted "$key" && return 0
 for table in filter mangle;do
  chain=NR_FWD;[ "$table" != mangle ] || chain=NR_EGRESS
  while IFS= read -r time;do
   # Goto + RETURN preserves the native firewall. Health controls this gate.
   nr_ipt -t "$table" -A "$chain" -m connmark --mark "$base" $time -g "NR_B$pid" || return 1
  done <<< "$windows"
  nr_ipt -t "$table" -A "$chain" -m connmark --mark "$base" -j DROP || return 1
 done
 nr_ipt -t nat -A NR_NAT -m connmark --mark "$base/0xffffff00" -p tcp -j MASQUERADE --random-fully || return 1
 nr_ipt -t nat -A NR_NAT -m connmark --mark "$base/0xffffff00" -j MASQUERADE || return 1
 NR_GUARD_KEYS+=("$key")
}
nr_policy_rule(){
 local expression="$1" pid="$2" windows="$3" eids mode band base eid dev mark expr
 read -r pid eids mode band <<< "$(awk -v id="$pid" '$1==id{print;exit}' "$NR/policies")"
 [ -n "$eids" ] || return 1
 base=$(nr_policy_base "$pid" "$band")
 if [ "$eids" = 0 ];then nr_rule "$expression" "$base" 0 "$windows";return;fi
 # Preserve the established single bound path and its exact exit/time guards.
 if [ "$band" = 1 ] && [[ "$eids" != *,* ]];then nr_rule "$expression" "$((base+eids))" "$eids" "$windows";return;fi
 while IFS= read -r expr;do nr_ipt -t mangle -A "${NR_RULE_CHAIN:-NR_CLASS}" $expr -j "NR_P$pid";done <<< "$expression"
 for eid in ${eids//,/ };do
  dev=$(awk -v id="$eid" '$1==id{print $3;exit}' "$NR/exits");[ -n "$dev" ] || return 1
  mark=$((base+eid))
  nr_exit_guard "$mark" "$dev" "$windows" || return 1
 done
 if [ "$band" = 0 ];then
  nr_fallback_guard "$pid" "$base" "$windows" || return 1
 fi
}
# Rebuild one selector in an atomic mangle transaction. There is no empty-chain
# interval in which a matching policy can fall through to a later rule.
nr_policy_select_sync(){
 local pid="$1" eids="$2" mode="$3" band="$4" healthy='' marks='' ifaces='' eid iface base old state gate=DROP allknown=1 status known
 base=$(nr_policy_base "$pid" "$band")
 for eid in ${eids//,/ };do
  [ "$eid" != 0 ] || continue
  read -r status known <<< "$(awk -v id="$eid" '$1==id{print $2,$3;exit}' "$NR/exit-health")"
  if [ "$known" != 1 ];then allknown=0;continue;fi
  [ "$status" = 1 ] || continue
  iface=$(awk -v id="$eid" '$1==id{print $2;exit}' "$NR/exits");[ -n "$iface" ] || return 1
  healthy="${healthy:+$healthy,}$eid";marks="${marks:+$marks,}$((base+eid))";ifaces="${ifaces:+$ifaces,}$iface"
 done
 state="$eids $mode $band $allknown $healthy"
 old=$(cat "$NR/policy-state/$pid" 2>/dev/null || true)
 [ "$old" != "$state" ] || return 0
 # Close fallback first, before changing route selection or removing old flows.
 printf '*filter\n-F NR_B%s\n-A NR_B%s -j DROP\nCOMMIT\n' "$pid" "$pid" | iptables-restore -w 5 -n || return 1
 if [ -z "$healthy" ] && [ "$allknown" = 1 ] && [ "$band" = 0 ] && [ "$eids" != 0 ];then gate=RETURN;fi
 {
  printf '*mangle\n-F NR_P%s\n-F NR_B%s\n' "$pid" "$pid"
  if [ -n "$healthy" ];then
   # NTH supplies only the native balancing algorithm. Its legacy band=1
   # callback also activates vendor routing metadata, incompatible with these
   # independent full policy marks. Binding is enforced below by each policy's
   # mark, physical table+prohibit, exact egress guards and closed main gate.
   printf -- '-A NR_P%s -j NTH_CONNMARK --set-mark %s --set-ifname %s --set-band-flag 0 --set-mode %s\n' "$pid" "$marks" "$ifaces" "$mode"
   printf -- '-A NR_P%s -j CONNMARK --restore-mark\n' "$pid"
   printf -- '-A NR_P%s -m mark --mark %s/0xffffff00 -j ACCEPT\n' "$pid" "$base"
   # Native selection may return no result (e.g. carrier changed mid-update).
   # It must not escape to a lower rule or prematurely use main.
   printf -- '-A NR_P%s -j DROP\n' "$pid"
  elif [ "$gate" = RETURN ];then
   printf -- '-A NR_P%s -j MARK --set-mark %s\n-A NR_P%s -j CONNMARK --save-mark\n-A NR_P%s -j ACCEPT\n' "$pid" "$base" "$pid" "$pid"
  else printf -- '-A NR_P%s -j DROP\n' "$pid";fi
  printf -- '-A NR_B%s -j %s\nCOMMIT\n' "$pid" "$gate"
 } | iptables-restore -w 5 -n || return 1
 if [ "$gate" = RETURN ];then printf '*filter\n-F NR_B%s\n-A NR_B%s -j RETURN\nCOMMIT\n' "$pid" "$pid" | iptables-restore -w 5 -n || return 1;fi
 # Preserve bound and unrelated connections. Unbound reconnects re-enter NTH
 # when a chosen candidate fails, or main fallback is no longer necessary.
 if [ "$band" = 0 ] && [ -n "$old" ];then
  local oldids oldmode oldband oldknown oldhealthy
  read -r oldids oldmode oldband oldknown oldhealthy <<< "$old"
  for eid in ${oldhealthy//,/ };do case ",$healthy," in *",$eid,"*) ;; *) conntrack -D --mark "$((base+eid))/0xffffffff" >/dev/null 2>&1 || true;;esac;done
  if [ -z "$oldhealthy" ] && [ -n "$healthy" ];then conntrack -D --mark "$base/0xffffffff" >/dev/null 2>&1 || true;fi
 fi
 printf '%s\n' "$state" > "$NR/policy-state/$pid"
}
nr_policy_worker_sync(){
 local wid="$1" pid="$2" dns="$3" uid=$((48200+$1)) eids mode band healthy eid iface dev base mark target state old pref=$((100+$1)) allknown=1 status known
 read -r pid eids mode band <<< "$(awk -v id="$pid" '$1==id{print;exit}' "$NR/policies")"
 [ -n "$eids" ] || return 1
 base=$(nr_policy_base "$pid" "$band");target='';dev='';mark="$base"
 for eid in ${eids//,/ };do
  [ "$eid" != 0 ] || continue
  read -r status known <<< "$(awk -v id="$eid" '$1==id{print $2,$3;exit}' "$NR/exit-health")"
  if [ "$known" != 1 ];then allknown=0;continue;fi
  [ "$status" = 1 ] || continue
  read -r eid iface dev _ <<< "$(awk -v id="$eid" '$1==id{print;exit}' "$NR/exits")"
  target="$iface";mark=$((base+eid));break
 done
 if [ -z "$target" ] && [ "$allknown" = 1 ] && [ "$band" = 0 ] && [ "$eids" != 0 ];then target=main;fi
 state="$target $dev $mark $dns"
 old=$(cat "$NR/worker-state/$wid" 2>/dev/null || true)
 # Full kernel rebuilds recreate DROP-only chains even when DNS sockets stay
 # alive. Reinstall the same route without restarting an unchanged worker.
 [ "$old" != "$state" ] || [ "${4:-}" = apply ] || return 0
 printf '*filter\n-F NR_D%s\n-A NR_D%s -j DROP\nCOMMIT\n' "$wid" "$wid" | iptables-restore -w 5 -n || return 1
 while ip rule del pref "$pref" uidrange "$uid-$uid" 2>/dev/null;do :;done
 if [ -n "$target" ];then ip rule add pref "$pref" uidrange "$uid-$uid" table "$target" || return 1;fi
 grep -Fxq "$pref $uid" "$NR/owner-routes" || printf '%s %s\n' "$pref" "$uid" >> "$NR/owner-routes"
 {
  printf '*mangle\n-F NR_W%s\n-F NR_E%s\n' "$wid" "$wid"
  if [ -n "$target" ];then printf -- '-A NR_W%s -j MARK --set-mark %s\n-A NR_W%s -j ACCEPT\n' "$wid" "$mark" "$wid";else printf -- '-A NR_W%s -j DROP\n' "$wid";fi
  if [ -n "$target" ];then
   printf -- '-A NR_E%s -m connmark ! --mark %s -j DROP\n' "$wid" "$mark"
   printf -- '-A NR_E%s ! -d %s -j DROP\n' "$wid" "$dns"
   if [ -n "$dev" ];then printf -- '-A NR_E%s ! -o %s -j DROP\n' "$wid" "$dev";fi
   printf -- '-A NR_E%s -j RETURN\n' "$wid"
  else printf -- '-A NR_E%s -j DROP\n' "$wid";fi
  printf 'COMMIT\n*filter\n-F NR_D%s\n' "$wid"
  if [ -n "$target" ];then
   printf -- '-A NR_D%s ! -d %s -j DROP\n' "$wid" "$dns"
   if [ -n "$dev" ];then printf -- '-A NR_D%s ! -o %s -j DROP\n' "$wid" "$dev";fi
   printf -- '-A NR_D%s -j RETURN\n' "$wid"
  else printf -- '-A NR_D%s -j DROP\n' "$wid";fi
  printf 'COMMIT\n'
 } | iptables-restore -w 5 -n || return 1
 # Restart only this resolver after a route change: an old UDP/TCP socket
 # could otherwise retain the prior exit's NAT tuple. The caller consumes this
 # durable queue; failed restarts leave it pending without affecting peers.
 if [ -n "$old" ] && [ "$old" != "$state" ];then printf '%s\n' "$wid" >> "$NR/worker-restart.ids";fi
 printf '%s\n' "$state" > "$NR/worker-state/$wid"
}
nr_policy_reconcile(){
 [ -f "$NR/policies" ] || return 0
 nr_exit_health_sync "${1:-}" || return 1
 local pid eids mode band wid dns
 while read -r pid eids mode band;do nr_policy_select_sync "$pid" "$eids" "$mode" "$band" || return 1;done < "$NR/policies"
 while read -r wid pid dns;do nr_policy_worker_sync "$wid" "$pid" "$dns" "${1:-}" || return 1;done < "$NR/policy-workers"
}
# Compiler expressions are newline-separated OR alternatives. The empty
# alternative means unrestricted, so every loop must also process that line.
nr_dns_scope(){
 local expr p
 while IFS= read -r expr;do for p in udp tcp;do nr_ipt -t nat -A NR_DNS $expr -p "$p" --dport 53 -j NR_DNS53;done;done <<< "$1"
}
nr_conflict(){
 local expr
 while IFS= read -r expr;do
  nr_ipt -t mangle -I NR_CLASS 5 $expr -j DROP
  nr_ipt -I NR_FWD 1 -m conntrack --ctdir ORIGINAL $expr -j DROP
  nr_ipt -t mangle -I NR_EGRESS 1 -m conntrack --ctdir ORIGINAL $expr -j DROP
 done <<< "$1"
}
# Load into a detached set, then swap under the existing transaction guard.
# Existing fallback connections are also checked in FORWARD/POSTROUTING.
nr_strict_set(){
 ipset create nr_cn_target hash:net family inet maxelem 262144 -exist
 ipset create nr_cn_stage hash:net family inet maxelem 262144 -exist
 ipset flush nr_cn_stage
 ipset restore -file "$1" || return 1
 ipset swap nr_cn_stage nr_cn_target || return 1
 ipset destroy nr_cn_stage
}
nr_strict_guard(){
 local expr mark="$2" table chain
 while IFS= read -r expr;do nr_ipt -t mangle -A NR_FALLBACK $expr -m set ! --match-set nr_cn_target dst -j NR_STRICT;done <<< "$1"
 for table in filter mangle;do
  chain=NR_FWD;[ "$table" != mangle ] || chain=NR_EGRESS
  nr_ipt -t "$table" -A "$chain" -m connmark --mark "$mark" -m conntrack --ctdir ORIGINAL -m set ! --match-set nr_cn_target dst -j DROP
 done
}
# Port/protocol decisions ACCEPT or DROP in NR_LOWER. Only a miss returns to
# NR_STRICT and is dropped. Keep this continuation local to the chain: no
# temporary packet/connection mark may escape into native routing or replies.
nr_strict_continue(){
 nr_ipt -t mangle -A NR_STRICT -j NR_LOWER
 nr_ipt -t mangle -A NR_STRICT -j DROP
}
nr_fallback_begin(){ NR_RULE_CHAIN=NR_FALLBACK;nr_ipt -t mangle -A NR_CLASS -j NR_FALLBACK; }
nr_fallback_skip(){ local expr;while IFS= read -r expr;do nr_ipt -t mangle -A NR_FALLBACK $expr -j RETURN;done <<< "$1"; }
nr_fallback_end(){ unset NR_RULE_CHAIN; }
nr_lower_begin(){ NR_RULE_CHAIN=NR_LOWER;nr_ipt -t mangle -A NR_CLASS -j NR_LOWER; }
nr_lower_end(){ unset NR_RULE_CHAIN; }
nr_rule(){
 local expr mark="$2" exit="$3" dev rulechain="${NR_RULE_CHAIN:-NR_CLASS}"
 if [ "$exit" = 0 ];then while IFS= read -r expr;do nr_ipt -t mangle -A "$rulechain" $expr -j DROP;done <<< "$1";return;fi
 dev=$(awk -v id="$exit" '$1==id{print $3}' "$NR/exits");[ "$dev" ]
 while IFS= read -r expr;do
  nr_ipt -t mangle -A "$rulechain" $expr -j MARK --set-mark "$mark"
  nr_ipt -t mangle -A "$rulechain" $expr -j CONNMARK --save-mark
  nr_ipt -t mangle -A "$rulechain" $expr -j ACCEPT
 done <<< "$1"
 nr_exit_guard "$mark" "$dev" "$4"
}
nr_finish(){
 # Supply DNS on router-owned WG addresses even with no domain rules. This is
 # appended after explicit DNS scopes and does not hijack external DNS traffic.
 local proto
 for proto in udp tcp;do
  nr_ipt -t nat -A NR_DNS -i wg+ -m addrtype --dst-type LOCAL -p "$proto" --dport 53 -j NR_DNS53
  nr_ipt -t nat -A NR_DNS -i pppwg+ -m addrtype --dst-type LOCAL -p "$proto" --dport 53 -j NR_DNS53
 done
 nr_wg_transport_sync
 nr_ipt -A NR_FWD -m connmark --mark 0x2df000/0xfffff000 -j DROP
 nr_ipt -t mangle -A NR_EGRESS -m connmark --mark 0x2df000/0xfffff000 -j DROP
 nr_ipt -A NR_FWD -m connmark --mark 0x55000000/0xff000000 -j DROP
 nr_ipt -t mangle -A NR_EGRESS -m connmark --mark 0x55000000/0xff000000 -j DROP
 nr_ipt -A NR_FWD -m connmark --mark 0x58000000/0xff000000 -j DROP
 nr_ipt -t mangle -A NR_EGRESS -m connmark --mark 0x58000000/0xff000000 -j DROP
 nr_ipt -A NR_OUTPUT -m owner --uid-owner 48201-48232 -j DROP
 for spec in 'mangle PREROUTING NR_SCOPE' 'mangle OUTPUT NR_OUT' 'mangle FORWARD NR_FAST' 'filter FORWARD NR_FWD' 'mangle POSTROUTING NR_EGRESS' 'filter OUTPUT NR_OUTPUT' 'filter INPUT NR_INPUT' 'nat PREROUTING NR_DNS_I' 'nat POSTROUTING NR_NAT';do nr_hook $spec;done
 # Ahead of native established-flow ACCEPTs, including already open DoH.
 [ "${NR_EDNS_ENABLED:-0}" != 1 ] || nr_hook filter FORWARD NR_EDNS
 # Keep the temporary guard ahead of accepting policy hooks.
 nr_ipt -t mangle -D PREROUTING -j NR_GUARD 2>/dev/null || true
 nr_ipt -t mangle -I PREROUTING 1 -j NR_GUARD
 /usr/ikuai/script/wg_site.sh hooks || return 1
 nr_policy_reconcile apply || return 1
}

nr_protect(){ nr_ipt -t mangle -I NR_CLASS 4 $1 -j RETURN; }

nr_ipv6(){
 local on="$1" dev proto
 ip6tables -w -N NR_V6 2>/dev/null || true
 ip6tables -w -N NR_V6DNS 2>/dev/null || true
 {
  printf '%s\n' '*filter' '-F NR_V6' '-F NR_V6DNS'
  if [ "$on" = 1 ];then
   for dev in $NR_IFACES;do
    printf '%s\n' "-A NR_V6 -i $dev -j DROP"
    for proto in udp tcp;do printf '%s\n' "-A NR_V6DNS -i $dev -p $proto --dport 53 -j DROP";done
   done
  fi
  printf '%s\n' COMMIT
 } | ip6tables-restore -w 5 -n || return 1
 ip6tables -w -C FORWARD -j NR_V6 2>/dev/null || ip6tables -w -I FORWARD 1 -j NR_V6 || return 1
 ip6tables -w -C INPUT -j NR_V6DNS 2>/dev/null || ip6tables -w -I INPUT 1 -j NR_V6DNS
}
