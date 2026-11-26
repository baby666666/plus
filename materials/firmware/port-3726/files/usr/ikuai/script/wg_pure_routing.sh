#!/bin/bash
# Keep logical WG table names for saved policies. A pure worker alone owns
# the preferred IPv4 default. The next priority prohibits unintended fallback.
set -eu
set -o pipefail
umask 077
run=/tmp/iktmp/wg-pure-routing
state=/etc/mnt/ikuai/wg-hyr/state.json
inventory=/usr/ikuai/script/wg_pure_inventory.lua
units=/tmp/iktmp/wg-hy-engine
db=$2
[[ "$1" = sync || "$1" = projected ]] || exit 2
if [ "$1" = projected ];then
    [[ "$3" =~ ^wg[0-9]+$ ]] || exit 2
    # Called only under wireguard_address, after the projected native row
    # has committed. Other readers continue to use the applied inventory.
    if [ -f "${state%/*}/change/next" ];then state=${state%/*}/change/next;fi
    [ -f "$state" ] || state=-
    exec /usr/bin/lua "$inventory" "$db" "$state" "$3"
fi
[ -f "$state" ] || state=-
if [ "$state" = - ] && [ ! -e "$run/map" ] && [ ! -e /tmp/iktmp/wg-site-client/active ];then exit 0;fi
mkdir -p -m 700 "$run"
exec 8>"$run/lock"
flock -x 8
stage=$(mktemp "$run/map.XXXXXX")
trap 'rm -f "$stage"' EXIT
/usr/bin/lua "$inventory" "$db" "$state" > "$stage"
owns_tun(){
    local unit=$1 dev=$2 pid ticks observed info
    [ -r "$units/$unit/service.pid" ] && [ -e "/sys/class/net/$dev/tun_flags" ] || return 1
    read -r pid ticks < "$units/$unit/service.pid" || return 1
    [[ "$pid" =~ ^[1-9][0-9]*$ && "$ticks" =~ ^[0-9]+$ ]] || return 1
    observed=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null) && [ "$observed" = "$ticks" ] || return 1
    for info in /proc/"$pid"/fdinfo/*;do
        awk -v dev="$dev" '$1=="iff:" && $2==dev{found=1}END{exit !found}' "$info" 2>/dev/null && return 0
    done
    return 1
}
table_exists(){ awk -v name="$1" '$2==name && $1~/^[0-9]+$/{found=1}END{exit !found}' /etc/iproute2/rt_tables; }
while read -r iface dev unit allowed;do
    table_exists "$iface" || continue
    ip -4 route replace prohibit default table "$iface" metric 42
    if [ "$allowed" = yes ] && owns_tun "$unit" "$dev";then
        ip -4 route replace default dev "$dev" table "$iface" metric 41
    else
        ip -4 route del default dev "$dev" table "$iface" metric 41 2>/dev/null || :
    fi
done < "$stage"
if [ -f "$run/map" ];then
    while read -r iface dev unit allowed;do
        if awk -v name="$iface" '$1==name{found=1}END{exit !found}' "$stage";then continue;fi
        table_exists "$iface" || continue
        ip -4 route del default dev "$dev" table "$iface" metric 41 2>/dev/null || :
        ip -4 route del prohibit default table "$iface" metric 42 2>/dev/null || :
    done < "$run/map"
fi
if [ -s "$stage" ];then
    cmp -s "$stage" "$run/map" || mv -f "$stage" "$run/map"
else
    rm -f "$run/map"
fi
