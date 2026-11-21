#!/bin/bash
# In same-port mode Hysteria owns the real public socket. Only loopback may
# reach the relocated inner WG socket. No NAT or INPUT ACCEPT rules are used.
set -eu
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
state=/etc/mnt/ikuai/wg-hyr/state.json
runtime=/tmp/iktmp/wg-hyr-ports
wg=/usr/bin/wg

valid_dev(){ [[ $1 =~ ^wg[0-9]{1,10}$ ]]; }
valid_port(){ [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && [ "$1" -le 65535 ]; }
init(){
    mkdir -m 700 "$runtime" 2>/dev/null || [ -d "$runtime" ]
    [ ! -L "$runtime" ] && [ "$(stat -c '%u:%a' "$runtime")" = 0:700 ]
    exec 9>"$runtime/lock"
    flock -x 9
}
guard_rule(){
    local action=$1 proto=$2 chain=$3
    shift 3
    local rule=("$chain" "$@" -m comment --comment nr-hyr-private-wg -j DROP)
    if "$proto" -w 3 -t mangle -C "${rule[@]}" 2>/dev/null; then
        if [ "$action" = remove ]; then "$proto" -w 3 -t mangle -D "${rule[@]}"; fi
    elif [ "$action" = install ]; then
        "$proto" -w 3 -t mangle -I "$chain" 1 "${rule[@]:1}"
    fi
}
guards(){
    local action=$1 port=$2
    # mangle precedes the normal INPUT/OUTPUT filter, including user ACCEPT
    # rules. A stale roaming endpoint must not send raw WG to the WAN either.
    guard_rule "$action" iptables INPUT ! -i lo -p udp --dport "$port" &&
        guard_rule "$action" iptables OUTPUT ! -o lo -p udp --sport "$port" &&
        guard_rule "$action" ip6tables INPUT ! -i lo -p udp --dport "$port" &&
        guard_rule "$action" ip6tables OUTPUT ! -o lo -p udp --sport "$port"
}
remember(){
    local dev=$1 public=$2 inner=$3 key=$4
    valid_dev "$dev" && valid_port "$public" && valid_port "$inner" && [ "$inner" != "$public" ] || return 1
    if ! grep -Fqx "$dev $public $inner $key" "$runtime/$dev.$inner" 2>/dev/null; then
        printf '%s %s %s %s\n' "$dev" "$public" "$inner" "$key" >"$runtime/pending" &&
            mv -f "$runtime/pending" "$runtime/$dev.$inner" || return 1
    fi
    guards install "$inner"
}
valid_target(){ [[ $1 =~ ^fd72:6e72:6879:2::([0-9a-f]{1,4}:){0,2}[0-9a-f]{1,4}$ ]]; }
clear_gate(){
    local dev=$1 addr
    if [ -f "$runtime/$dev.arming" ];then
        read -r addr <"$runtime/$dev.arming" && valid_target "$addr" &&
            {
                local rule=(OUTPUT -o lo -d "$addr/128" -p udp -m owner --gid-owner 49319 -m comment --comment nr-hyr-arm -j DROP)
                if ip6tables -w 3 -t mangle -C "${rule[@]}" 2>/dev/null;then
                    ip6tables -w 3 -t mangle -D "${rule[@]}" || return 1
                else
                    local hooks
                    hooks=$(ip6tables -w 3 -t mangle -S OUTPUT) || return 1
                    ! printf '%s\n' "$hooks" | awk -v a="$addr/128" 'index($0,"-d "a" ") && /nr-hyr-arm/{found=1}END{exit !found}' || return 1
                fi
                rm -f "$runtime/$dev.arming"
            }
    fi
}
drop_target(){
    local dev=$1 target
    valid_dev "$dev" || return 1
    if [ -f "$runtime/$dev.target" ]; then
        read -r target <"$runtime/$dev.target" && valid_target "$target" || return 1
        if ip -6 addr show dev "$dev" 2>/dev/null | grep -Fq "inet6 $target/128 "; then
            ip -6 addr del "$target/128" dev "$dev" || return 1
        fi
        rm -f "$runtime/$dev.target" || return 1
    fi
    if [ "${2:-}" = retire ] && [ -f "$runtime/$dev.arming" ];then
        read -r target <"$runtime/$dev.arming" && valid_target "$target" || return 1
        local still
        still=$(ip -6 route show table local exact "$target/128") && [ -z "$still" ] && clear_gate "$dev"
    fi
}
case $1 in
hold|prune)
    [ -d "$runtime" ] || exit 0
    init
    for record in "$runtime"/wg*.target "$runtime"/wg*.arming; do
        [ -f "$record" ] || continue
        dev=${record##*/};dev=${dev%.*}
        if [ "$1" = prune ];then
            read -r target <"$record"
            if [ -s "$2" ] && awk -v d="$dev" -v a="$target" '$1==d && $5==a {found=1} END{exit !found}' "$2";then continue;fi
            drop_target "$dev" retire
        elif [[ $2 = '*' || " $2 " = *" $dev "* ]];then drop_target "$dev";fi
    done;;
resolve)
    dev=$2 public=$3 key=$4
    valid_dev "$dev" && valid_port "$public" || exit 1
    if [ ! -f "$state" ]; then echo "$public"; exit; fi
    # While replacing a server key the running old HY instance can still own
    # the public port. Keep the inner port protected until inventory sync
    # invalidates the old binding and restores the native public listener.
    inner=$(jq -r --arg d "$dev" --arg p "$public" '
        select(.enabled == true) | .members[] | select(.transport=="pure_hy2" and .paused!=true and .port_mode=="wg" and .interface==$d and (.port|tostring)==$p) | .inner_port' "$state")
    if [ -z "$inner" ]; then echo "$public"; exit; fi
    init; remember "$dev" "$public" "$inner" "$key"
    echo "$inner";;
apply)
    plan=$2 db=$3
    if [ ! -s "$plan" ] && [ ! -d "$runtime" ]; then exit 0; fi
    init
    if [ -s "$plan" ]; then
        while read -r dev public inner key; do
            # Native initialization can follow journal recovery on cold boot.
            remember "$dev" "$public" "$inner" "$key"
            if ! ip link show dev "$dev" >/dev/null 2>&1; then continue; fi
            if [ "$("$wg" show "$dev" public-key)" != "$key" ];then
                # Never move the replacement's socket. Revoke delivery to
                # this device now; other verified WG interfaces can keep serving.
                drop_target "$dev" || exit 1
                continue
            fi
            if [ "$("$wg" show "$dev" listen-port)" != "$inner" ]; then
                # A collision can affect one device. Its later exact-binding
                # check stays closed; continue preparing independent peers.
                "$wg" set "$dev" listen-port "$inner" || continue
            fi
        done <"$plan"
    fi
    for record in "$runtime"/wg*.[0-9]*; do
        [ -f "$record" ] || continue
        read -r dev public inner key <"$record"
        valid_dev "$dev" && valid_port "$public" && valid_port "$inner" || exit 1
        if [ -s "$plan" ] && grep -Fqx "$dev $public $inner $key" "$plan"; then continue; fi
        if [ "$("$wg" show "$dev" listen-port 2>/dev/null || true)" = "$inner" ]; then
            # An interface edit can also change the native public port. Restore
            # what is saved now rather than a stale pre-edit setting.
            current=$(sqlite3 -cmd '.timeout 10000' "$db" "SELECT local_listenport FROM wireguard WHERE name='$dev' AND enabled='yes'")
            # A disabled/deleted interface may still be winding down. Its
            # socket stays private until the native teardown has finished.
            if ! valid_port "$current"; then continue; fi
            "$wg" set "$dev" listen-port "$current"
        fi
        # Never expose a port reallocated to another pending same-port peer.
        if ! awk -v p="$inner" '$3==p{found=1} END{exit !found}' "${plan:-/dev/null}" 2>/dev/null; then guards remove "$inner"; fi
        rm -f "$record"
    done;;
*) exit 2;;
esac
