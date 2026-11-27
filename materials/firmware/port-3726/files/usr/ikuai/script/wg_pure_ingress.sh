#!/bin/bash
# All authenticated data and resolver sockets enter the registered client namespace.
# The outer QUIC listener remains on the host WAN.
set -eu
set -o pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
root=/tmp/iktmp/wg-pure-ingress
op=${1:-}; dev=${2:-}; id=${3:-}; peer=${4:-}; gateway=${5:-}
admin=${6:-0}; requested_http=${7:-0}; requested_https=${8:-0}
admin_helper=/usr/ikuai/script/wg_pure_admin.sh
admin_http=0;admin_https=0
binding=${9:-}; reverse_port=${10:-0}; lan_rows=()
read_lans(){
    [ -n "$binding" ] || return 0
    [ -f "$binding" ] && [ ! -L "$binding" ] || return 1
    local line ldev addr prefix first last extra bits
    while IFS= read -r line;do
        read -r ldev addr prefix first last extra <<<"$line"
        [[ $ldev =~ ^lan[0-9]+$ && -z $extra && $prefix = */* ]] || return 1
        bits=${prefix##*/}
        [[ $bits =~ ^([1-9]|[12][0-9]|3[012])$ && ${prefix%/*} = "$first" ]] || return 1
        ipv4 "$addr" && ipv4 "$first" && ipv4 "$last" || return 1
        lan_rows+=("$ldev $addr $prefix $first $last")
    done < <(tail -n +2 "$binding")
}
fail(){ echo '纯 HY2 管理网络未就绪或存在资源冲突' >&2; return 1; }
ipv4(){
    local value=$1 a b c d part
    [[ $value =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    IFS=. read -r a b c d <<< "$value"
    for part in "$a" "$b" "$c" "$d";do
        [[ $part = 0 || $part != 0* ]] && [ "$((10#$part))" -le 255 ] || return 1
    done
    [ "$a" -gt 0 ] && [ "$a" -lt 224 ] && [ "$a" != 127 ] && [ "$a.$b" != 169.254 ]
}
identity(){
    [[ $dev =~ ^wg[0-9]{1,10}$ && $id =~ ^[1-9][0-9]{0,9}$ ]] || return 1
    # A separate native-client ingress preserves the registered peer source.
    suffix=${dev#wg}; host=ppphy$suffix; ns=nrhy$suffix; alias=nr-pure-$dev-$id
    input=NHI$suffix; forward=NHF$suffix; reply=NHR$suffix; record=$root/$dev
    [ "${#host}" -le 15 ] && [ "${#ns}" -le 15 ]
}
private_root(){
    [ -d "$root" ] && [ ! -L "$root" ] && [ "$(stat -c '%u:%a' "$root")" = 0:700 ]
}
link_exists(){ ip link show dev "$host" >/dev/null 2>&1; }
ns_exists(){ ip netns list | awk -v n="$ns" '$1==n{found=1}END{exit !found}'; }
owned_link(){ [ "$(cat /sys/class/net/"$host"/ifalias 2>/dev/null)" = "$alias" ]; }
read_record(){
    [ -f "$record" ] && [ ! -L "$record" ] && [ "$(stat -c '%u:%a' "$record")" = 0:600 ] || return 1
    read -r saved_id saved_peer saved_gateway saved_inode extra < "$record" || return 1
    [[ $saved_id = "$id" && -z $extra && $saved_inode =~ ^[0-9]+$ ]] && ipv4 "$saved_peer" && ipv4 "$saved_gateway"
}
ns_inode(){ stat -Lc '%i' "/var/run/netns/$ns"; }
owned_ns(){ ns_exists && [ "$saved_inode" != 0 ] && [ "$(ns_inode)" = "$saved_inode" ]; }
route_free(){
    local routes
    routes=$(ip -4 route show table main exact "$peer/32") || return 1
    if [ -z "$routes" ];then [ "${require_route:-0}" = 0 ];return;fi
    if [ "$op" = check ] && printf '%s\n' "$routes" | awk -v dev="$dev" '{n++;ok=0;for(i=1;i<NF;i++)if($i=="dev"&&$(i+1)==dev)ok=1;if(!ok)bad=1}END{exit !(n==1&&!bad)}';then return 0;fi
    [ -f "$record" ] && owned_link || return 1
    printf '%s\n' "$routes" | awk -v dev="$host" '
      {n++;ok=0;for(i=1;i<NF;i++)if($i=="dev"&&$(i+1)==dev)ok=1;if(!ok)bad=1}
      END{exit !(n==1&&!bad)}'
}
preflight(){
    local locals chain
    ipv4 "$peer" && ipv4 "$gateway" && [ "$peer" != "$gateway" ] || return 1
    locals=$(ip -o -4 addr show) || return 1
    if printf '%s\n' "$locals" | awk -v helper="ppp$dev" -v gw="$gateway" '{name=$2;sub(/@.*/,"",name);if(name==helper)for(i=1;i<NF;i++)if($i=="inet"){split($(i+1),a,"/");if(a[1]==gw)found=1}}END{exit !found}';then
        /usr/ikuai/script/native_ingress.sh check "$dev" || return 1
    fi
    # Only the saved native anchor and its verified adapter may own the gateway. The peer must never
    # coincide with a router address, even when a stale route looks harmless.
    printf '%s\n' "$locals" | awk -v peer="$peer" -v gw="$gateway" -v dev="$dev" -v own="$host" '
      {name=$2;sub(/@.*/,"",name);for(i=1;i<NF;i++)if($i=="inet"){
        split($(i+1),a,"/");if(a[1]==peer)bad=1;if(a[1]==gw&&name!=dev&&name!=own&&name!="ppp"dev)bad=1;if(a[1]==gw&&name==dev)anchor=1}}
      END{exit !(anchor&&!bad)}' || return 1
    route_free || return 1
    if [ -e "$record" ] || [ -L "$record" ];then
        read_record || return 1
        if link_exists;then owned_link || return 1;fi
        if ns_exists;then owned_ns || return 1;fi
    else
        ! link_exists && ! ns_exists || return 1
        for chain in "$input" "$forward" "$reply";do
            if iptables -w 3 -S "$chain" >/dev/null 2>&1;then return 1;fi
        done
    fi
}
rule(){
    local chain=$1;shift
    if [ "$mode" = emit ];then printf -- '-A %s' "$chain";printf ' %s' "$@";printf '\n'
    else iptables -w 3 -A "$chain" "$@";fi
}
management_ports(){
    local answer extra mode=probe
    admin_http=0;admin_https=0
    [[ $admin = 0 || $admin = 1 ]] || return 1
    [[ $requested_http =~ ^(0|[1-9][0-9]{0,4})$ && $requested_https =~ ^(0|[1-9][0-9]{0,4})$ ]] &&
        [ "$requested_http" -le 65535 ] && [ "$requested_https" -le 65535 ] || return 1
    [ "$admin" = 1 ] || { [ "$requested_http" = 0 ] && [ "$requested_https" = 0 ];return; }
    [[ $op != up && $op != manage ]] || mode=refresh
    # A disabled/unverified listener denies management only. Normal internet
    # access is independent of the web service's health or reload window.
    answer=$("$admin_helper" "$mode" "$gateway" "$requested_http" "$requested_https" 2>/dev/null) || return 0
    read -r admin_http admin_https extra <<< "$answer"
    [[ -z $extra && $admin_http =~ ^(0|[1-9][0-9]{0,4})$ && $admin_https =~ ^(0|[1-9][0-9]{0,4})$ ]] &&
        { [ "$admin_http" = 0 ] || [ "$admin_http" = "$requested_http" ]; } &&
        { [ "$admin_https" = 0 ] || [ "$admin_https" = "$requested_https" ]; } || { admin_http=0;admin_https=0; }
}
input_guards(){
    local mode=$1 port
    rule "$input" ! -s "$peer/32" -j DROP || return 1
    # Only the authenticated device's namespace may reach its dedicated
    # reverse control listener. This is never a general router-service grant.
    if [ "$reverse_port" = 49871 ];then
        rule "$input" -s "$peer/32" -d "$gateway/32" -p tcp -m tcp --dport 49871 \
            -m conntrack --ctorigdst "$gateway" --ctorigdstport 49871 -j ACCEPT || return 1
    elif [ "$reverse_port" != 0 ];then return 1;fi
    local dst line ldev addr rest
    local destinations=("$gateway")
    for line in ${lan_rows[@]+"${lan_rows[@]}"};do
        read -r ldev addr rest <<<"$line";destinations+=("$addr")
    done
    for dst in "${destinations[@]}";do
        for port in "$admin_http" "$admin_https";do
            [ "$port" != 0 ] || continue
            # Continue through native WEBACL. The original target must match to exclude DNAT.
            rule "$input" -s "$peer/32" -d "$dst/32" -p tcp -m tcp --dport "$port" \
                -m set --match-set Linux_webport_default dst -m conntrack --ctorigdst "$dst" --ctorigdstport "$port" -j RETURN || return 1
        done
    done
    local proto
    for proto in udp tcp;do
        rule "$input" -p "$proto" -m "$proto" --dport 53 -m conntrack --ctstate DNAT --ctorigdstport 53 -j RETURN || return 1
        rule "$input" -p "$proto" -m "$proto" --dport 6153 -m conntrack --ctstate DNAT --ctorigdstport 53 -j RETURN || return 1
    done
    rule "$input" -j DROP || return 1
}
guards(){
    local mode=$1
    input_guards "$mode" || return 1
    local line ldev addr prefix first last net
    rule "$forward" ! -s "$peer/32" -j DROP || return 1
    rule "$forward" -m conntrack --ctstate DNAT -j DROP || return 1
    for line in ${lan_rows[@]+"${lan_rows[@]}"};do
        read -r ldev addr prefix first last <<<"$line"
        [ "${prefix##*/}" != 32 ] || continue
        if [ "${prefix##*/}" -lt 31 ];then
            rule "$forward" -d "$first/32" -j DROP || return 1
            rule "$forward" -d "$last/32" -j DROP || return 1
        fi
        # A route changing to WAN or another LAN can never match this grant.
        rule "$forward" -s "$peer/32" -d "$prefix" -o "$ldev" -m addrtype --dst-type UNICAST -j RETURN || return 1
        rule "$reply" -s "$prefix" -d "$peer/32" -i "$ldev" -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN || return 1
    done
    for net in 0.0.0.0/8 127.0.0.0/8 169.254.0.0/16 224.0.0.0/4 240.0.0.0/4;do
        rule "$forward" -d "$net" -j DROP || return 1
    done
    for line in ${lan_rows[@]+"${lan_rows[@]}"};do
        read -r ldev addr prefix first last <<<"$line"
        rule "$forward" -d "$prefix" -j DROP || return 1
    done
    # Forward every other unicast through the native firewall and routing policy.
    # A subnet behind a downstream router has an ordinary LAN/VLAN egress here.
    rule "$forward" -m addrtype --dst-type UNICAST -j RETURN || return 1
    rule "$forward" -j DROP || return 1
    rule "$reply" -d "$peer/32" -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN || return 1
    rule "$reply" -j DROP || return 1
}
hooks(){
    local mode=$1 spec chain direction target
    local specs=("INPUT -i $input" "FORWARD -i $forward" "FORWARD -o $reply")
    if [ "$mode" = emit ];then specs=("INPUT -i $input" "FORWARD -o $reply" "FORWARD -i $forward");fi
    for spec in "${specs[@]}";do
        read -r chain direction target <<< "$spec"
        if [ "$mode" = emit ];then
            printf -- '-A %s %s %s -m comment --comment %s -j %s\n' "$chain" "$direction" "$host" "$alias" "$target"
        elif [ "$mode" = install ];then
            iptables -w 3 -I "$chain" 1 "$direction" "$host" -m comment --comment "$alias" -j "$target" || return 1
        elif [ "$mode" = check ];then
            iptables -w 3 -C "$chain" "$direction" "$host" -m comment --comment "$alias" -j "$target" || return 1
        else
            while iptables -w 3 -C "$chain" "$direction" "$host" -m comment --comment "$alias" -j "$target" 2>/dev/null;do
                iptables -w 3 -D "$chain" "$direction" "$host" -m comment --comment "$alias" -j "$target" || return 1
            done
        fi
    done
}
firewall_ready(){
    local expected
    expected=$(printf -- '-N %s\n' "$input" "$forward" "$reply";guards emit;hooks emit) || return 1
    iptables-save -t filter | NR_HY_EXPECTED="$expected" awk -v i="$input" -v f="$forward" -v r="$reply" -v tag="$alias" '
      BEGIN{n=split(ENVIRON["NR_HY_EXPECTED"],lines,"\n");for(k=1;k<=n;k++){split(lines[k],a," ");want[a[2]]=want[a[2]] lines[k] "\n"}}
      {sub(/^\[fastid: [0-9]+\] /,"")}
      /^:/ {name=$1;sub(/^:/,"",name);if(name==i||name==f||name==r)got[name]=got[name] "-N " name "\n";next}
      $1=="-A" && ($2==i||$2==f||$2==r||index($0,"--comment " tag " ")||index($0,"--comment \"" tag "\" ")) {
        line=$0;gsub(/"/,"",line);gsub(/ESTABLISHED,RELATED/,"RELATED,ESTABLISHED",line);got[$2]=got[$2] line "\n"
      }
      END{for(chain in want)if(want[chain]!=got[chain])exit 1;for(chain in got)if(!(chain in want))exit 1}'
}
endpoint_macs(){
    host_mac=$(ip -o link show dev "$host" | awk '{for(i=1;i<NF;i++)if($i=="link/ether"){print $(i+1);exit}}') || return 1
    namespace_mac=$(ip netns exec "$ns" ip -o link show dev eth0 | awk '{for(i=1;i<NF;i++)if($i=="link/ether"){print $(i+1);exit}}') || return 1
    [[ $host_mac =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ && $namespace_mac =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]]
}
neighbors_up(){
    local host_mac namespace_mac
    endpoint_macs || return 1
    # The gateway is also present on the native WG anchor. Router ARP policy
    # may reject duplicate-address ARP on a veth, so do not rely on discovery.
    # Both entries belong exclusively to this link pair and vanish with it.
    ip -4 neigh replace "$peer" lladdr "$namespace_mac" nud permanent dev "$host" &&
        ip netns exec "$ns" ip -4 neigh replace "$gateway" lladdr "$host_mac" nud permanent dev eth0
}
neighbors_ready(){
    local host_mac namespace_mac
    endpoint_macs || return 1
    ip -4 neigh show to "$peer" dev "$host" | awk -v address="$peer" -v mac="$namespace_mac" '
      $1==address{n++;for(i=1;i<=NF;i++){if($i=="lladdr"&&$(i+1)==mac)matched=1;if($i=="PERMANENT")permanent=1}}
      END{exit !(n==1&&matched&&permanent)}' || return 1
    ip netns exec "$ns" ip -4 neigh show to "$gateway" dev eth0 | awk -v address="$gateway" -v mac="$host_mac" '
      $1==address{n++;for(i=1;i<=NF;i++){if($i=="lladdr"&&$(i+1)==mac)matched=1;if($i=="PERMANENT")permanent=1}}
      END{exit !(n==1&&matched&&permanent)}'
}

direct_pairs(){
    local action=$1 line ldev addr prefix first last
    if [ "$action" = remove ];then
        [ ! -f "$record.lans" ] || while read -r prefix;do
            ipset del nr_hy_direct "$saved_peer/32,$prefix" -exist || return 1
        done < "$record.lans"
        rm -f "$record.lans";return
    fi
    if [ "$action" = install ];then
        ipset create nr_hy_direct hash:net,net family inet maxelem 65536 -exist || return 1
        : > "$record.lans" || return 1
    fi
    for line in ${lan_rows[@]+"${lan_rows[@]}"};do
        read -r ldev addr prefix first last <<<"$line"
        if [ "$action" = install ];then
            printf '%s\n' "$prefix" >> "$record.lans" && ipset add nr_hy_direct "$peer/32,$prefix" -exist || return 1
        else
            ipset test nr_hy_direct "$peer,$addr" >/dev/null 2>&1 || return 1
        fi
    done
}

ready(){
    local require_route=1 routes
    read_record && [ "$peer" = "$saved_peer" ] && [ "$gateway" = "$saved_gateway" ] &&
        owned_link && owned_ns && route_free || return 1
    [ "$(( $(cat /sys/class/net/"$host"/flags) & 1 ))" = 1 ] &&
        [ "$(cat /sys/class/net/"$host"/carrier)" = 1 ] || return 1
    ip -o -4 addr show dev "$host" | awk -v local_ip="$gateway" -v remote="$peer/32" '{for(i=1;i<NF;i++){if($i=="inet"){split($(i+1),a,"/");if(a[1]==local_ip)local_ok=1}if($i=="peer"&&$(i+1)==remote)peer_ok=1}}END{exit !(local_ok&&peer_ok)}' || return 1
    ip netns exec "$ns" ip -o -4 addr show dev eth0 | awk -v local_ip="$peer" -v remote="$gateway/32" '{for(i=1;i<NF;i++){if($i=="inet"){split($(i+1),a,"/");if(a[1]==local_ip)local_ok=1}if($i=="peer"&&$(i+1)==remote)peer_ok=1}}END{exit !(local_ok&&peer_ok)}' || return 1
    routes=$(ip netns exec "$ns" ip -4 route show default) || return 1
    printf '%s\n' "$routes" | awk -v gw="$gateway" '$1=="default"{n++;for(i=1;i<NF;i++){if($i=="via"&&$(i+1)==gw)via=1;if($i=="dev"&&$(i+1)=="eth0")dev=1}}END{exit !(n==1&&via&&dev)}' || return 1
    ip netns exec "$ns" ip -4 route show exact "$gateway/32" | awk -v gw="$gateway" '
      ($1==gw || $1==gw"/32"){n++;for(i=1;i<NF;i++)if($i=="dev"&&$(i+1)=="eth0")dev=1}
      END{exit !(n==1&&dev)}' || return 1
    [ "$(ip netns exec "$ns" cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" = 1 ] || return 1
    direct_pairs check && neighbors_ready && firewall_ready
}
input_ready(){
    local expected actual
    expected=$(printf -- '-N %s\n' "$input";input_guards emit) || return 1
    actual=$(iptables -w 3 -S "$input" | sed 's/^\[fastid: [0-9]*\] //') || return 1
    [ "$actual" = "$expected" ]
}
manage(){
    read_record && [ "$peer" = "$saved_peer" ] && [ "$gateway" = "$saved_gateway" ] &&
        owned_link && owned_ns || return 1
    input_ready && return 0
    # Atomic replacement removes old grants without disturbing the namespace,
    # QUIC session, forwarding guards, native WEBACL or management identity.
    { printf '%s\n' '*filter' "-F $input";input_guards emit;printf '%s\n' COMMIT; } |
        iptables-restore -w 3 -n
}
down(){
    [ -e "$record" ] || [ -L "$record" ] || return 0
    read_record || return 1
    # Refuse to delete a recycled name. Keep the marker/guards for recovery.
    if link_exists;then owned_link || return 1;ip link set "$host" down || return 1;fi
    if ns_exists;then owned_ns || return 1;ip netns del "$ns" || return 1;fi
    if link_exists;then ip link del "$host" || return 1;fi
    direct_pairs remove && hooks remove || return 1
    local chain
    for chain in "$input" "$forward" "$reply";do
        if iptables -w 3 -S "$chain" >/dev/null 2>&1;then
            iptables -w 3 -F "$chain" && iptables -w 3 -X "$chain" || return 1
        fi
    done
    rm -f "$record"
}
up(){
    if ready >/dev/null 2>&1;then return 0;fi
    # Worker is stopped by the caller before this repair. No socket can use a
    # partially rebuilt namespace; every error leaves the link down.
    if [ -e "$record" ] || [ -L "$record" ];then down || return 1;fi
    preflight || return 1
    printf '%s %s %s 0\n' "$id" "$peer" "$gateway" > "$record" || return 1
    local chain
    for chain in "$input" "$forward" "$reply";do iptables -w 3 -N "$chain" || return 1;done
    guards install && hooks install || return 1
    ip netns add "$ns" || return 1
    saved_inode=$(ns_inode) || return 1
    printf '%s %s %s %s\n' "$id" "$peer" "$gateway" "$saved_inode" > "$record" || return 1
    ip link add "$host" type veth peer name eth0 netns "$ns" || return 1
    ip link set "$host" alias "$alias" || return 1
    ip netns exec "$ns" ip link set eth0 alias "$alias" || return 1
    echo 1 > /proc/sys/net/ipv6/conf/"$host"/disable_ipv6 || return 1
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 || return 1
    ip addr add "$gateway/32" peer "$peer/32" dev "$host" || return 1
    ip netns exec "$ns" ip addr add "$peer/32" peer "$gateway/32" dev eth0 || return 1
    ip netns exec "$ns" ip link set lo up || return 1
    ip netns exec "$ns" ip link set eth0 up || return 1
    ip link set "$host" up || return 1
    neighbors_up && direct_pairs install || return 1
    ip netns exec "$ns" ip route add default via "$gateway" dev eth0 onlink || return 1
    ready
}
check(){ preflight; }
identity || { fail;exit 1; }
[[ $reverse_port = 0 || $reverse_port = 49871 ]] || { fail;exit 1; }
read_lans || { fail;exit 1; }
management_ports || { fail;exit 1; }
case "$op" in check|ready)
    if [ -e "$root" ] || [ -L "$root" ];then private_root || { fail;exit 1; };fi
    "$op" 2>/dev/null && exit 0 || { fail;exit 1; };;
 up|down|manage) ;;
 *) exit 2;;
esac
if [ "$op" = down ] && [ ! -e "$root" ];then exit 0;fi
mkdir -m 700 "$root" 2>/dev/null || :
private_root || { fail;exit 1; }
exec 9>"$root/lock"
flock -x 9
if [ "$op" = manage ];then manage || { fail;exit 1; }
elif [ "$op" = down ];then down || { fail;exit 1; }
elif ! up;then
    if owned_link;then ip link set "$host" down 2>/dev/null || :;fi
    down 2>/dev/null || :
    fail;exit 1
fi
