#!/bin/bash
# Called under the HY registry lock. Unit identities never contain user-supplied shell.
set -u
set -o pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
engine=/usr/ikuai/script/wg_hy_engine.sh
stun=/usr/sbin/nr-hy2-stun
units=/tmp/iktmp/wg-hy-engine
op=${1:-}
stage=${2:--}
scope=${3:-*}
case "$op" in check|sync|status|stop|hold) ;; *) exit 2;; esac
fail(){ printf '%s\n' "$*" >&2; return 1; }
selected(){ [[ "$scope" = '*' || " $scope " = *" $1 "* ]]; }
valid_port(){ [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && [ "$1" -le 65535 ]; }
stun_pid(){
    local pid ticks exe
    read -r pid ticks < "$unit/stun.pid" 2>/dev/null || return 1
    [[ $pid =~ ^[1-9][0-9]*$ && $ticks =~ ^[0-9]+$ ]] &&
        exe=$(readlink /proc/"$pid"/exe) && { [ "$exe" = "$stun" ] || [ "$exe" = "$stun (deleted)" ]; } &&
        [ "$(awk '{print $22}' /proc/"$pid"/stat 2>/dev/null)" = "$ticks" ] || return 1
    echo "$pid"
}
# Remove an RC15 process during a live restore. New units never start STUN.
stop_stun(){
    local pid i
    if [ -s "$unit/stun.pid" ] && pid=$(stun_pid);then
        kill "$pid" 2>/dev/null || { stun_pid >/dev/null && return 1; }
        for ((i=0;i<20;i++));do stun_pid >/dev/null 2>&1 || break;sleep .1;done
        stun_pid >/dev/null 2>&1 && return 1
    fi
    rm -f "$unit/stun.pid"
}
# Run native access-control chains before an explicit public listener permit.
# Scoping the rules to WAN interfaces leaves LAN and management grants unchanged.
firewall(){
    local action=$1 proto port wan result
    [ -s "$unit/policy" ] || return 0
    while read -r proto port wan;do
        [[ $proto = udp || $proto = tcp ]] && valid_port "$port" && [[ $wan =~ ^[A-Za-z0-9_.+-]+$ ]] || return 1
        local rule=(INPUT -i "$wan" -p "$proto" --dport "$port" -m comment --comment "nr-pure-$id" -j ACCEPT)
        if iptables -w 3 -C "${rule[@]}" 2>/dev/null;then
            if [ "$action" = remove ];then iptables -w 3 -D "${rule[@]}" || return 1;fi
        else
            result=$?
            [ "$result" = 1 ] || return 1
            case "$action" in install) iptables -w 3 -A "${rule[@]}" || return 1;; inspect) return 1;; esac
        fi
    done <"$unit/policy"
}
stop_unit(){
    "$engine" "puh-$id" stop >/dev/null && stop_stun && firewall remove &&
        rm -f "$unit/device" "$unit/policy"
}
# On a cold boot a persisted server can start before any receiver or
# management request creates the shared runtime directory.
if [ "$op" = sync ] && [ -s "$stage/pure-bindings" ];then
    mkdir -m 700 "$units" 2>/dev/null || :
fi
if [ -e "$units" ] || [ -L "$units" ];then
    [ -d "$units" ] && [ ! -L "$units" ] && [ "$(stat -c '%u:%a' "$units")" = 0:700 ] || exit 1
fi
if [[ "$op" = stop || "$op" = hold || "$op" = sync ]];then
    for unit in "$units"/puh-[0-9]*;do
        [ -d "$unit" ] || continue
        id=${unit##*/puh-}
        [[ $id =~ ^[1-9][0-9]{0,9}$ ]] || exit 1
        [ -f "$unit/device" ] || [ -f "$unit/live.json" ] || [ -f "$unit/stun.pid" ] || continue
        dev=$(cat "$unit/device" 2>/dev/null) || dev=
        if [ "$op" = hold ] && [ "$dev" ] && ! selected "$dev";then continue;fi
        if [ "$op" = sync ] && [ -s "$stage/pure.$id" ] && [ -s "$unit/policy" ] && [ ! -e "$unit/stun.pid" ] &&
            cmp -s "$stage/pure.$id" "$unit/live.json";then continue;fi
        stop_unit || exit 1
    done
fi
[[ "$op" != stop && "$op" != hold ]] || exit 0
[ -f "$stage/pure-bindings" ] || exit 0
rc=0
while read -r dev id port inner extra;do
    [[ $dev =~ ^wg[0-9]{1,10}$ && $id =~ ^[1-9][0-9]{0,9}$ && -z $extra ]] &&
        valid_port "$port" && valid_port "$inner" && [ -s "$stage/pure.$id" ] || exit 1
    unit="$units/puh-$id"
    if [ "$op" = check ];then
        selected "$dev" || continue
        "$engine" check "$stage/pure.$id" || exit 1
        # The native anchor or a previous carrier can still own the original UDP
        # number during the projected-db validation.
        if ! "$engine" "puh-$id" available "$port";then
            [ "$(/usr/bin/wg show "$dev" listen-port 2>/dev/null)" = "$port" ] ||
                { fail '纯 HY2 数据端口已被占用';exit 1; }
        fi
        continue
    fi
    if [ "$op" = status ];then
        "$engine" "puh-$id" status >/dev/null 2>&1 && cmp -s "$stage/pure.$id" "$unit/live.json" &&
            [ -s "$unit/policy" ] && firewall inspect &&
            touch "$stage/ready.$id"
        continue
    fi
    mkdir -m 700 "$unit" 2>/dev/null || :
    [ ! -L "$unit" ] && [ "$(stat -c '%u:%a' "$unit")" = 0:700 ] || exit 1
    echo "$dev" >"$unit/device" || exit 1
    if [ ! -s "$unit/policy" ];then
        for wan in wan+ vwan+ adsl+;do
            echo "udp $port $wan"
        done >"$unit/policy" || exit 1
    fi
    if ! firewall install ||
        { ! { cmp -s "$stage/pure.$id" "$unit/live.json" && "$engine" "puh-$id" status >/dev/null 2>&1; } &&
          ! "$engine" "puh-$id" start "$stage/pure.$id"; };then
        stop_unit || exit 1
        if selected "$dev";then rc=1;fi
    fi
done <"$stage/pure-bindings"
[ "$rc" = 0 ] || fail '纯 HY2 进程或网络接口未就绪，请检查公网端口'
