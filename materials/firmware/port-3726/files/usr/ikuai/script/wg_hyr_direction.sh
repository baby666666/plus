#!/bin/bash
# Apply the permissions of the decrypted WG tunnels. The caller holds the HYR
# lock. The WAN QUIC socket and native WireGuard listener are outside this path.
set -u
set -o pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
runtime=/tmp/iktmp/wg-hyr
chain=NR_HYR_DIR
reply=NR_HYR_REPLY
snapshot=$1
case ${2:-} in
    client) runtime=/tmp/iktmp/wg-site-client;chain=NR_HYC_DIR;reply=NR_HYC_REPLY;;
    hold) chain=NR_HYR_FENCE;;
    native|native-hold) runtime=/tmp/iktmp/wg-native-role;chain=NR_WG_DIR;reply=NR_WG_REPLY
        [ "$2" != native-hold ] || chain=NR_WG_FENCE;;
    '') ;;
    *) exit 2;;
esac
table_rules=$(mktemp "$runtime/direction.XXXXXX") || exit 1
trap 'rm -f "$table_rules" "$table_rules.apply" "$table_rules.hooks" "$table_rules.rules" "$table_rules.expected"' EXIT
valid_host(){
    local pattern='^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/32$' octet
    [[ $1 =~ $pattern ]] || return 1
    for octet in "${BASH_REMATCH[@]:1}"; do [[ $octet != 0?* ]] && [ "$((10#$octet))" -le 255 ] || return 1; done
}
valid_site_net(){
    local ip=${1%/*} bits=${1##*/} a b
    [[ $1 = */* && $bits =~ ^([1-9]|[12][0-9]|3[0-2])$ ]] && valid_host "$ip/32" || return 1
    IFS=. read -r a b _ <<< "$ip"
    [[ $a = 10 && $bits -ge 8 || $a = 172 && $b -ge 16 && $b -le 31 && $bits -ge 12 ||
       $a = 192 && $b = 168 && $bits -ge 16 || $a = 100 && $b -ge 64 && $b -le 127 && $bits -ge 10 ]]
}
render(){
    local dev mode source scopes extra name net wan
    local -a networks
    while read -r dev mode source scopes extra; do
        { [[ "$dev" =~ ^wg[0-9]{1,10}$ ]] || [[ "$dev:$mode:$chain" = "wg+:hold:NR_WG_FENCE" ]]; } &&
            [ -z "$extra" ] && valid_host "$source" || return 1
        if [ "$mode" = site ]; then
            [[ $chain = NR_HYR_DIR || $chain = NR_HYC_DIR ]] && [[ -n $scopes && $scopes != ,* && $scopes != *, && $scopes != *,,* ]] || return 1
            IFS=, read -ra networks <<< "$scopes"
            [ "${#networks[@]}" -le 8 ] || return 1
            for net in "${networks[@]}"; do valid_site_net "$net" || return 1; done
        else
            [ -z "$scopes" ] || return 1
        fi
        for name in "$dev" "ppp$dev"; do
            if [ "$chain" = NR_HYC_DIR ] && [ "$mode" != site ];then
                case "$mode" in
                    pure)
                        # This name only anchors the policy. The sing-box TUN
                        # carries the data; the native WG path stays closed.
                        printf -- '-A %s -i %s -j DROP\n-A %s -o %s -j DROP\n' "$chain" "$name" "$chain" "$name"
                        continue;;
                    access|both|lend) ;;
                    *) return 1;;
                esac
                if [ "$mode" != access ];then
                    # The remote router SNATs its selected traffic to its WG
                    # identity. Only a real WAN forwarding path can start NEW.
                    for wan in wan+ vwan+ adsl+;do
                        printf -- '-A %s -i %s -s %s -o %s -j RETURN\n' "$chain" "$name" "$source" "$wan"
                    done
                fi
                printf -- '-A %s -i %s -j %s\n' "$chain" "$name" "$reply"
                if [ "$mode" = lend ];then printf -- '-A %s -o %s -j %s\n' "$chain" "$name" "$reply";fi
                continue
            fi
            case $mode in
                lend)
                    printf -- '-A %s -i %s -j %s\n' "$chain" "$name" "$reply";;
                access)
                    if [ "$chain" = NR_WG_DIR ]; then
                        # Same WG interface may serve several access phones.
                        # Kernel AllowedIPs already authenticates this /32.
                        printf -- '-A %s -o %s -d %s -j %s\n' "$chain" "$name" "$source" "$reply"
                        continue
                    fi
                    printf -- '-A %s -i %s ! -s %s -j DROP\n' "$chain" "$name" "$source"
                    printf -- '-A %s -o %s -j %s\n' "$chain" "$name" "$reply";;
                both)
                    printf -- '-A %s -i %s ! -s %s -j %s\n' "$chain" "$name" "$source" "$reply";;
                site)
                    # Native site marks authorize the declared LAN/tunnel pairs. For
                    # Internet access permit these sources to forward through a WAN.
                    for net in "$source" "${networks[@]}"; do
                        # Check before POSTROUTING SNAT: a broad Internet exit
                        # policy must not turn an undeclared source into the
                        # trusted tunnel /32 on a packet aimed at the other LAN.
                        printf -- '-A %s -o %s -d %s -m mark ! --mark 0x57000000/0xffffffff -j %s\n' "$chain" "$name" "$net" "$reply"
                        printf -- '-A %s -i %s -s %s -m mark --mark 0x57000000/0xffffffff -j RETURN\n' "$chain" "$name" "$net"
                        for wan in wan+ vwan+ adsl+; do
                            printf -- '-A %s -i %s -s %s -o %s -j RETURN\n' "$chain" "$name" "$net" "$wan"
                        done
                    done
                    printf -- '-A %s -i %s -j %s\n' "$chain" "$name" "$reply";;
                hold)
                    printf -- '-A %s -i %s -j DROP\n-A %s -o %s -j DROP\n' "$chain" "$name" "$chain" "$name";;
                *) return 1;;
            esac
        done
    done < "$snapshot"
}
render > "$table_rules" || exit 1
hash=$(sha256sum "$table_rules") || exit 1
tag=nr-dir-${hash%% *}
# iptables -S prints address, interface and protocol matches in kernel
# order, which can differ from restore input. Each rule keeps its place.
# An unfamiliar option cannot silently disappear from the comparison.
canonical_rules(){
    awk -v dir="$chain" -v reply="$reply" '
        {sub(/^\[fastid: [0-9]+\] /,"")}
        $1=="-N" && NF==2 && ($2==dir || $2==reply) {next}
        $1!="-A" || ($2!=dir && $2!=reply) {exit 1}
        {
            delete part
            for(i=3;i<=NF;i++){
                opt=$i;neg=""
                if(opt=="!"){neg="! ";opt=$(++i)}
                if(opt=="-m" || opt=="-j"){if(neg!="")exit 1;break}
                if(opt!="-i" && opt!="-o" && opt!="-s" && opt!="-d" && opt!="-p")exit 1
                if((opt in part) || ++i>NF)exit 1
                value=$i
                if((opt=="-s" || opt=="-d") && value~/^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$/)value=value"/32"
                part[opt]=" "neg opt" "value
            }
            line="-A "$2 part["-s"] part["-d"] part["-i"] part["-o"] part["-p"]
            for(;i<=NF;i++){
                value=$i
                if($(i-1)=="--mark")sub(/\/0xffffffff$/,"",value)
                if($(i-1)=="--comment" && value~/^"nr-dir-[0-9a-f]+"$/)gsub(/"/,"",value)
                line=line" "value
            }
            print line
        }'
}
apply(){
    local cmd=$1 restore=$2 v6=$3 head name dev mode source
    local hooks=(INPUT FORWARD OUTPUT)
    if [ ! -s "$table_rules" ] && ! "$cmd" -w 3 -S "$chain" >/dev/null 2>&1; then return 0; fi
    local count ready state
    : >"$table_rules.hooks" || return 1
    for head in "${hooks[@]}"; do
        state=$("$cmd" -w 3 -S "$head") || return 1
        read -r count ready < <(printf '%s\n' "$state" | awk -v head="$head" -v chain="$chain" '
            {sub(/^\[fastid: [0-9]+\] /,"")}
            $1=="-A" && $2==head {
                if(NF==4 && $3=="-j" && $4==chain){count++;if(!other)ready=1}
                else if($NF !~ /^NR_(HY(R_(FENCE|DIR|WG|PAUSE)|C_DIR|_WAN)|WG_(DIR|FENCE))$/)other=1
            }
            END{print count+0,ready+0}')
        if [ -s "$table_rules" ] && [ "$count:$ready" = 1:1 ]; then continue; fi
        while [ "$count" -gt 0 ]; do
            printf -- '-D %s -j %s\n' "$head" "$chain" >>"$table_rules.hooks" || return 1
            count=$((count-1))
        done
        if [ -s "$table_rules" ]; then printf -- '-I %s 1 -j %s\n' "$head" "$chain" >>"$table_rules.hooks" || return 1; fi
    done
    {
        printf -- '-A %s -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN\n' "$reply"
        if [ "$v6" = no ]; then
            # Related IPv4 ICMP errors carry PMTU and unreachable feedback for
            # an existing outbound flow. Unrelated ICMP cannot open a path.
            printf -- '-A %s -p icmp -m conntrack --ctstate RELATED --ctdir REPLY -j RETURN\n' "$reply"
        fi
        printf -- '-A %s -j DROP\n' "$reply"
        if [ "$v6" = no ]; then
            cat "$table_rules"
        else
            # All supported WG addresses, AllowedIPs and degree of access are IPv4.
            while read -r dev mode source; do
                # Native shared access has IPv4-only cryptokey routes; do not
                # apply an interface-wide IPv6 drop to an unrelated sibling.
                [[ "$chain:$mode" != NR_WG_DIR:access ]] || continue
                for name in "$dev" "ppp$dev"; do printf -- '-A %s -i %s -j DROP\n-A %s -o %s -j DROP\n' "$chain" "$name" "$chain" "$name"; done
            done < "$snapshot"
        fi
        printf -- '-A %s -m comment --comment %s -j RETURN\n' "$chain" "$tag"
    } >"$table_rules.rules" || return 1
    canonical_rules <"$table_rules.rules" >"$table_rules.expected" || return 1
    if { "$cmd" -w 3 -S "$reply" && "$cmd" -w 3 -S "$chain"; } 2>/dev/null |
           canonical_rules | cmp -s "$table_rules.expected" -; then
        [ -s "$table_rules.hooks" ] || return 0
        { printf '*filter\n'; cat "$table_rules.hooks"; printf 'COMMIT\n'; } | "$restore" -w 5 -n
        return
    fi
    {
        printf '*filter\n:%s - [0:0]\n:%s - [0:0]\n-F %s\n-F %s\n' "$chain" "$reply" "$chain" "$reply"
        cat "$table_rules.rules" "$table_rules.hooks"
        printf 'COMMIT\n'
    } >"$table_rules.apply" || return 1
    "$restore" -w 5 -n <"$table_rules.apply"

}
apply iptables iptables-restore no && apply ip6tables ip6tables-restore yes
