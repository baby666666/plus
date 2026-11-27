#!/bin/bash
# Private per-device reverse workers; called under wireguard_address.
# Reading status never creates state or starts a process.
set -u
set -o pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
root=/tmp/iktmp/wg-hy-reverse
binary=/usr/sbin/nr-hy2-reverse
op=${1:-}; name=${2:-}; config=${3:-}; device=${4:-}
[[ $name =~ ^(puh|puc)-[1-9][0-9]{0,9}$ ]] || exit 2
case "$op" in check|start|stop|status) ;; *) exit 2;; esac
unit=$root/$name
live=$unit/live.json
pidfile=$unit/service.pid
private_dir(){ [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]; }
private_file(){ [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:600 ]; }
fail(){ printf '%s\n' 'HY2 反向映射未就绪，请检查端口和连接状态' >&2; return 1; }
stopped(){ printf '%s\n' '{"connected":false,"state":"stopped","mappings":[]}'; }
running_pid(){
    local pid ticks inode extra actual
    private_file "$pidfile" || return 1
    read -r pid ticks inode extra <"$pidfile" || return 1
    [[ $pid =~ ^[1-9][0-9]*$ && $ticks =~ ^[0-9]+$ && $inode =~ ^[0-9]+:[0-9]+$ && -z $extra ]] || return 1
    [ "$pid" -gt 1 ] && [ "$(awk '{print $22}' /proc/"$pid"/stat 2>/dev/null)" = "$ticks" ] || return 1
    actual=$(readlink /proc/"$pid"/exe 2>/dev/null) || return 1
    { [ "$actual" = "$binary" ] || [ "$actual" = "$binary (deleted)" ]; } &&
        [ "$(stat -Lc '%d:%i' /proc/"$pid"/exe 2>/dev/null)" = "$inode" ] || return 1
    printf '%s\n' "$pid"
}
status(){
    local pid hash now result
    if ! pid=$(running_pid) || ! private_file "$live" || ! private_file "$unit/status.json";then stopped;return;fi
    [ "$(wc -c <"$unit/status.json")" -le 32768 ] || { stopped;return; }
    hash=$(sha256sum "$live") || { stopped;return; };hash=${hash%% *}
    now=$(date +%s) || { stopped;return; }
    # A valid PID alone is insufficient: stale snapshots/configurations never
    # retain an online badge. Construct the response explicitly; no credentials.
    result=$(jq -c --arg pid "$pid" --arg hash "$hash" --arg now "$now" '
        select(.pid==($pid|tonumber) and .config_sha256==$hash and
          (.updated_at|type)=="number" and .updated_at>=($now|tonumber)-30 and .updated_at<=($now|tonumber)+5) |
        {connected:(.connected==true),state:.state,error:.error,last_heartbeat:.last_heartbeat,
         updated_at:.updated_at,mappings:[.mappings[] |
           {id:.id,listening:.listening,active:.active,rx_bytes:.rx_bytes,tx_bytes:.tx_bytes,
            last_error:.last_error,last_success:.last_success}]}' "$unit/status.json" 2>/dev/null) || result=
    [ -n "$result" ] && printf '%s\n' "$result" || stopped
}
valid_port(){ [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && [ "$1" -le 65535 ]; }
policy(){
    local action=$1 kind a b c extra result wan
    [ -f "$unit/policy" ] || return 0
    private_file "$unit/policy" || return 1
    while read -r kind a b c extra;do
        [ -z "$extra" ] || return 1
        case "$kind" in
            public)
                [[ $a = tcp || $a = udp ]] && valid_port "$b" && [[ $c =~ ^[0-9.]+/[0-9]+$ ]] || return 1
                for wan in wan+ vwan+ adsl+;do
                    local rule=(INPUT -i "$wan" -p "$a" --dport "$b" -s "$c" -m comment --comment "nr-reverse-$name" -j ACCEPT)
                    if iptables -w 3 -C "${rule[@]}" 2>/dev/null;then
                        [ "$action" != remove ] || iptables -w 3 -D "${rule[@]}" || return 1
                    else
                        result=$?;[ "$result" = 1 ] || return 1
                        [ "$action" != install ] || iptables -w 3 -A "${rule[@]}" || return 1
                    fi
                done;;
            control)
                [[ $a =~ ^[0-9.]+$ && $b =~ ^wg[0-9]{1,10}$ && -z $c ]] || return 1
                local rule=(INPUT ! -i "ppphy${b#wg}" -d "$a/32" -p tcp --dport 49871 -m comment --comment "nr-reverse-$name" -j DROP)
                if iptables -w 3 -C "${rule[@]}" 2>/dev/null;then
                    [ "$action" != remove ] || iptables -w 3 -D "${rule[@]}" || return 1
                else
                    result=$?;[ "$result" = 1 ] || return 1
                    [ "$action" != install ] || iptables -w 3 -I "${rule[@]:0:1}" 1 "${rule[@]:1}" || return 1
                fi;;
            socks)
                [[ $a =~ ^127\.77\.[0-9]+\.[0-9]+$ ]] && valid_port "$b" && [ -z "$c" ] || return 1
                local rule=(INPUT ! -i lo -d "$a/32" -p tcp --dport "$b" -m comment --comment "nr-reverse-$name" -j DROP)
                if iptables -w 3 -t mangle -C "${rule[@]}" 2>/dev/null;then
                    [ "$action" != remove ] || iptables -w 3 -t mangle -D "${rule[@]}" || return 1
                else
                    result=$?;[ "$result" = 1 ] || return 1
                    [ "$action" != install ] || iptables -w 3 -t mangle -I "${rule[@]:0:1}" 1 "${rule[@]:1}" || return 1
                fi;;
            *) return 1;;
        esac
    done <"$unit/policy"
}
stop(){
    local pid i
    if pid=$(running_pid);then
        if ! kill -TERM "$pid" 2>/dev/null;then running_pid >/dev/null && return 1;fi
        for ((i=0;i<50;i++));do running_pid >/dev/null || break;sleep .1;done
        if running_pid >/dev/null;then
            kill -KILL "$pid" || return 1
            for ((i=0;i<20;i++));do running_pid >/dev/null || break;sleep .1;done
        fi
        running_pid >/dev/null && return 1
    fi
    policy remove || return 1
    rm -f "$pidfile" "$live" "$unit/status.json" "$unit/policy" "$unit/device"
}
check(){
    local expected pid
    expected=server;[[ $name != puc-* ]] || expected=client
    private_file "$config" && [ -x "$binary" ] &&
        jq -e --arg mode "$expected" --arg path "$unit/status.json" '.mode==$mode and .status_file==$path' "$config" >/dev/null &&
        "$binary" check -config "$config" >/dev/null 2>&1 || return 1
    pid=$(running_pid) || pid=0
    "$binary" check-ports -config "$config" -exclude-pid "$pid" >/dev/null 2>&1
}
start(){
    local pid ticks inode fd fdnum i kind
    check || return 1
    [[ $device =~ ^wg[0-9]{1,10}$ ]] || return 1
    if cmp -s "$config" "$live" && running_pid >/dev/null;then policy install;return $?;fi
    stop || return 1
    cp "$config" "$live" && chmod 600 "$live" && printf '%s\n' "$device" >"$unit/device" || return 1
    case "$name" in
        puh-*)
            jq -r '.mappings[] | . as $m | .allow[] | "public "+$m.protocol+" "+($m.listen|split(":")[1])+" "+.' "$live" >"$unit/policy" || return 1
            printf 'control %s %s\n' "$(jq -r '.control|split(":")[0]' "$live")" "$device" >>"$unit/policy" || return 1;;
        puc-*)
            jq -r '"socks "+(.socks|split(":")|join(" "))' "$live" >"$unit/policy" || return 1;;
    esac
    policy install || { stop;return 1; }
    inode=$(stat -Lc '%d:%i' "$binary") || { stop;return 1; }
    (
        exec </dev/null >/dev/null 2>&1
        for fd in /proc/self/fd/*;do
            fdnum=${fd##*/}
            if [[ $fdnum =~ ^[0-9]+$ ]] && [ "$fdnum" -gt 2 ];then eval "exec ${fdnum}>&-";fi
        done
        export GOMAXPROCS=2 GOMEMLIMIT=32MiB
        exec "$binary" run -config "$live"
    ) &
    pid=$!
    ticks=$(awk '{print $22}' /proc/"$pid"/stat 2>/dev/null)
    if [ -z "$ticks" ] || ! printf '%s %s %s\n' "$pid" "$ticks" "$inode" >"$pidfile";then
        kill -TERM "$pid" 2>/dev/null;wait "$pid" 2>/dev/null;stop;return 1
    fi
    for ((i=0;i<40;i++));do
        if running_pid >/dev/null && private_file "$unit/status.json";then return 0;fi
        kill -0 "$pid" 2>/dev/null || break
        sleep .1
    done
    stop
    return 1
}
if [ -e "$root" ] || [ -L "$root" ];then private_dir "$root" || exit 1;fi
if [ -e "$unit" ] || [ -L "$unit" ];then private_dir "$unit" || exit 1;fi
case "$op" in
    status) status;exit $?;;
    check) check || { fail;exit 1; };exit 0;;
    stop) [ -d "$unit" ] || exit 0;;
    start)
        mkdir -m 700 "$root" 2>/dev/null || :
        private_dir "$root" || exit 1
        mkdir -m 700 "$unit" 2>/dev/null || :
        private_dir "$unit" || exit 1;;
esac
exec 8>"$unit/lock"
flock -x 8 || exit 1
"$op" || { fail;exit 1; }
