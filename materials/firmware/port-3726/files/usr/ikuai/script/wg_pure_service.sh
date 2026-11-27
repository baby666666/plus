#!/bin/bash
# Called under the HY registry lock. Unit identities never contain user-supplied shell.
set -u
set -o pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
engine=/usr/ikuai/script/wg_hy_engine.sh
stun=/usr/sbin/nr-hy2-stun
management=/usr/ikuai/script/wg_pure_ingress.sh
admin_root=/tmp/iktmp/wg-pure-ingress
dns=/usr/ikuai/script/native_dns_bind.sh
units=/tmp/iktmp/wg-hy-engine
reverse=/usr/ikuai/script/wg_hy_reverse.sh
reverse_units=/tmp/iktmp/wg-hy-reverse
op=${1:-}
stage=${2:--}
scope=${3:-*}
case "$op" in check|sync|status|stop|hold) ;; *) exit 2;; esac
fail(){ printf '%s\n' "$*" >&2; return 1; }
selected(){ [[ "$scope" = '*' || " $scope " = *" $1 "* ]]; }
reverse_stop(){
    [ -e "$reverse_units/$1" ] || [ -L "$reverse_units/$1" ] || return 0
    "$reverse" stop "$1"
}
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
read_admin(){
    admin_peer=;admin_gateway=;admin_http=;admin_https=
    [ -s "$stage/admin.$id" ] || return 1
    local saved_dev saved_id extra
    read -r saved_dev saved_id admin_peer admin_gateway admin_http admin_https extra < "$stage/admin.$id" || return 1
    [[ $saved_dev = "$dev" && $saved_id = "$id" && -z $extra ]] || return 1
    [[ $admin_http =~ ^(0|[1-9][0-9]{0,4})$ && $admin_https =~ ^(0|[1-9][0-9]{0,4})$ ]] &&
        [ "$admin_http" -le 65535 ] && [ "$admin_https" -le 65535 ]
}
admin_call(){
    local control=0
    [ ! -s "$stage/reverse-server.$id" ] || control=49871
    "$management" "$1" "$dev" "$id" "$admin_peer" "$admin_gateway" 1 "$admin_http" "$admin_https" "$stage/admin.$id" "$control"
}
admin_cleanup(){
    if [[ $dev =~ ^wg[0-9]{1,10}$ ]] &&
        { [ -e "$admin_root/$dev" ] || [ -L "$admin_root/$dev" ] || [ -e "$unit/admin-binding" ]; };then
        "$management" down "$dev" "$id" || return 1
    fi
    rm -f "$unit/admin-binding"
}
admin_ready(){
    if [ -e "$stage/admin.$id" ];then
        read_admin && cmp -s "$stage/admin.$id" "$unit/admin-binding" && admin_call ready
    else
        [ ! -e "$unit/admin-binding" ] && [ ! -e "$admin_root/$dev" ] && [ ! -L "$admin_root/$dev" ]
    fi
}
admin_sync(){
    read_admin || return 1
    if cmp -s "$stage/admin.$id" "$unit/admin-binding" && admin_call manage && admin_call ready;then return 0;fi
    "$engine" "puh-$id" stop >/dev/null || return 1
    admin_cleanup && admin_call up || return 1
    cp "$stage/admin.$id" "$unit/admin-binding"
}
stop_unit(){
    reverse_stop "puh-$id" && "$engine" "puh-$id" stop >/dev/null && stop_stun && admin_cleanup && firewall remove &&
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
    # Mapping edits may leave the normal HY2 JSON identical; independently
    # revoke changed/orphaned reverse workers before exposing new settings.
    for reverse_unit in "$reverse_units"/puh-[0-9]*;do
        [ -d "$reverse_unit" ] || continue
        reverse_id=${reverse_unit##*/puh-}
        [[ $reverse_id =~ ^[1-9][0-9]{0,9}$ ]] || exit 1
        reverse_dev=$(cat "$reverse_unit/device" 2>/dev/null) || reverse_dev=
        if [ "$op" = hold ] && [ "$reverse_dev" ] && ! selected "$reverse_dev";then continue;fi
        if [ "$op" = sync ] && [ -s "$stage/reverse-server.$reverse_id" ] &&
            cmp -s "$stage/reverse-server.$reverse_id" "$reverse_unit/live.json";then continue;fi
        "$reverse" stop "puh-$reverse_id" || exit 1
    done
    for unit in "$units"/puh-[0-9]*;do
        [ -d "$unit" ] || continue
        id=${unit##*/puh-}
        [[ $id =~ ^[1-9][0-9]{0,9}$ ]] || exit 1
        [ -f "$unit/device" ] || [ -f "$unit/live.json" ] || [ -f "$unit/stun.pid" ] || [ -f "$unit/admin-binding" ] || continue
        dev=$(cat "$unit/device" 2>/dev/null) || dev=
        if [ -z "$dev" ] && [ -s "$unit/admin-binding" ];then
            read -r dev saved_id _ < "$unit/admin-binding" || exit 1
            [[ $dev =~ ^wg[0-9]{1,10}$ && $saved_id = "$id" ]] || exit 1
        fi
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
        [ ! -e "$stage/reverse-error.$id" ] || { fail 'HY2 反向映射配置或端口不可用';exit 1; }
        "$engine" check "$stage/pure.$id" || exit 1
        read_admin || exit 1
        # A projected new interface may not exist yet. Synchronization checks real
        # ownership, routing and DNS before exposing any authenticated traffic.
        if ip link show dev "$dev" >/dev/null 2>&1;then admin_call check || exit 1;fi
        # The native anchor or a previous carrier can still own the original UDP
        # number during the projected-db validation.
        if ! "$engine" "puh-$id" available "$port";then
            [ "$(/usr/bin/wg show "$dev" listen-port 2>/dev/null)" = "$port" ] ||
                { fail '纯 HY2 数据端口已被占用';exit 1; }
        fi
        if [ -s "$stage/reverse-server.$id" ];then
            "$reverse" check "puh-$id" "$stage/reverse-server.$id" "$dev" || exit 1
        fi
        continue
    fi
    if [ "$op" = status ];then
        if "$engine" "puh-$id" status >/dev/null 2>&1 && [ -s "$unit/policy" ] && firewall inspect &&
            cmp -s "$stage/pure.$id" "$unit/live.json" && admin_ready && "$dns" ready "ppphy${dev#wg}";then
            touch "$stage/ready.$id"
        fi
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
    config="$stage/pure.$id"
    # Never launch or restore a host-direct path. Native policy owns the DNS,
    # egress marks, ordered fallback, and prohibit routes for every client.
    if ! admin_sync;then stop_unit || exit 1;rc=1;continue;fi
    if ! "$dns" ready "ppphy${dev#wg}" && ! "$dns" ensure "ppphy${dev#wg}";then
        reverse_stop "puh-$id" && "$engine" "puh-$id" stop >/dev/null && firewall remove || exit 1
        rc=1;continue
    fi
    if ! firewall install ||
        { ! { cmp -s "$config" "$unit/live.json" && "$engine" "puh-$id" status >/dev/null 2>&1; } &&
          ! "$engine" "puh-$id" start "$config"; };then
        stop_unit || exit 1
        if selected "$dev";then rc=1;fi
        continue
    fi
    if [ -s "$stage/reverse-server.$id" ];then
        # A reverse failure leaves ordinary HY2 egress intact, but is returned
        # to the caller and cannot be displayed as a successful reverse link.
        if ! "$reverse" start "puh-$id" "$stage/reverse-server.$id" "$dev";then
            "$reverse" stop "puh-$id" || exit 1
            rc=1
        fi
    fi
    # Saved reverse data can become unusable after a different native setting
    # changes. Report the failure without stopping this peer's normal HY2 path.
    [ ! -e "$stage/reverse-error.$id" ] || rc=1
done <"$stage/pure-bindings"
[ "$rc" = 0 ] || fail '纯 HY2 进程或网络接口未就绪，请检查公网端口'
