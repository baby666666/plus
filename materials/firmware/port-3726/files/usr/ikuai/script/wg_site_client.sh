#!/bin/bash
# Called under wireguard_address. Persist only generated NativeRouting data in
# config.db; private process configs and socket guards are reconstructed on boot.
set -eu
set -o pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
script=/usr/ikuai/script
engine=$script/wg_hy_engine.sh
model=$script/wg_site_client.lua
runtime=/tmp/iktmp/wg-site-client
units=/tmp/iktmp/wg-hy-engine
db=$1 action=$2
scope=${3-'*'}
has_table(){
    local count
    count=$(sqlite3 -cmd '.timeout 10000' "$db" "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='wg_site_clients'") || return 2
    [ "$count" = 1 ]
}
case $action in
    status)
        if has_table; then exec /usr/bin/lua "$model" status "$db"; else rc=$?;[ "$rc" = 1 ] && echo '{"members":[]}'; exit "$((rc==1?0:1))";fi;;
    shutdown)
        [ -d "$runtime" ] || exit 0
        exec 7>"$runtime/service.lock";flock -x 7
        : > "$runtime/shutdown"
        for unit in "$units"/hyc-[0-9]* "$units"/puc-[0-9]*;do
            [ -f "$unit/service.pid" ] || continue
            "$engine" "${unit##*/}" stop
        done
        exit 0;;
    monitor)
        # Only the final validated list is returned to the WG monitor. Native
        # tools and a failed precondition must not publish partial evidence.
        exec 3>&1 >/dev/null;;
    sync|guard) ;;
    *) exit 2;;
esac
if has_table; then exists=yes
else rc=$?; [ "$rc" = 1 ] || exit 1; exists=no; [ -d "$runtime" ] || exit 0; fi
mkdir -m 700 "$runtime" 2>/dev/null || :
[ ! -L "$runtime" ] && [ "$(stat -c '%u:%a' "$runtime")" = 0:700 ]
exec 7>"$runtime/service.lock";flock -x 7
[ ! -f "$runtime/shutdown" ] || exit 0
touch "$runtime/active"
stage=$(mktemp -d "$runtime/apply.XXXXXX")
trap 'rm -rf "$stage"' EXIT
if [ "$exists" = yes ]; then /usr/bin/lua "$model" snapshot "$db" "$stage"
else : >"$stage/guards"; : >"$stage/pure_units"; : >"$stage/directions"; : >"$stage/enabled"; : >"$stage/owners"; fi

guard_rule(){
    local op=$1 cmd=$2 chain=$3;shift 3
    local spec=("$@" -m comment --comment nr-hyc-loopback -j DROP)
    if "$cmd" -w 3 -t mangle -C "$chain" "${spec[@]}" 2>/dev/null;then
        [ "$op" != remove ] || "$cmd" -w 3 -t mangle -D "$chain" "${spec[@]}"
    elif [ "$op" = install ];then
        "$cmd" -w 3 -t mangle -I "$chain" 1 "${spec[@]}"
    fi
}
protect(){
    local op=$1 inner=$2 relay=$3 cmd
    for cmd in iptables ip6tables;do
        guard_rule "$op" "$cmd" INPUT ! -i lo -p udp --dport "$inner" || return 1
        guard_rule "$op" "$cmd" OUTPUT ! -o lo -p udp --sport "$inner" || return 1
    done
    # Even with route_localnet enabled by a different system feature, remote
    # LAN/WAN clients cannot inject packets into the private UDP relay.
    guard_rule "$op" iptables INPUT ! -i lo -p udp -d 127.0.0.1 --dport "$relay"
}
valid_record(){
    [[ $1 =~ ^wg[0-9]{1,10}$ && $2 =~ ^[1-9][0-9]{0,4}$ && $3 =~ ^[1-9][0-9]{0,4}$ ]] &&
        [ "$2" -le 65535 ] && [ "$3" -le 65535 ] && [ "$2" != "$3" ]
}
# A partial external restore can orphan a *running* native receiver while
# its kernel WG session is still valid. Retire that exact peer before lifting
# its permissions. A numeric id/name reused by other keys is left alone.
if [ -s "$runtime/owners" ];then
    while read -r dev local_pub remote_pub;do
        [[ $dev =~ ^wg[0-9]{1,10}$ ]] || exit 1
        grep -Fqx "$dev $local_pub $remote_pub" "$stage/owners" && continue
        [ "$(/usr/bin/wg show "$dev" public-key 2>/dev/null || true)" = "$local_pub" ] || continue
        if /usr/bin/wg show "$dev" peers | grep -Fxq "$remote_pub";then
            ip link set down dev "$dev" || exit 1
            rm -f "/tmp/iktmp/wireguard/$dev.conf"
        fi
    done < "$runtime/owners"
fi
while read -r dev inner relay;do
    valid_record "$dev" "$inner" "$relay"
    # Record intent before changing either family. An interrupted operation can
    # be completed or rolled back on the next sync.
    printf '%s %s %s\n' "$dev" "$inner" "$relay" > "$runtime/guard.$relay"
    if ! protect install "$inner" "$relay";then
        ip link set down dev "$dev" >/dev/null 2>&1 || :
        rm -f "/tmp/iktmp/wireguard/$dev.conf"
        exit 1
    fi
done < "$stage/guards"
if ! "$script/wg_hyr_direction.sh" "$stage/directions" client;then
    while read -r dev rest;do
        [[ $dev =~ ^wg[0-9]{1,10}$ ]] || continue
        ip link set down dev "$dev" >/dev/null 2>&1 || :
        rm -f "/tmp/iktmp/wireguard/$dev.conf"
    done < "$stage/directions"
    exit 1
fi
mv -f "$stage/owners" "$runtime/owners"
# An RC15 worker can still own a reverse listener during a live restore.
# Revoke stale configs before returning from guard, even for another scope.
for unit in "$units"/puc-[0-9]*;do
    [ -d "$unit" ] || continue
    peer_id=${unit##*puc-}
    [[ $peer_id =~ ^[1-9][0-9]{0,4}$ ]] || exit 1
    [ -f "$unit/service.pid" ] || [ -f "$unit/live.json" ] || continue
    if ! cmp -s "$stage/pure.$peer_id" "$unit/live.json";then
        "$engine" "puc-$peer_id" stop
    fi
done
for unit in "$units"/hyc-[0-9]*;do
    [ -d "$unit" ] || continue
    port=${unit##*hyc-}
    [[ $port =~ ^[1-9][0-9]{0,4}$ ]] || exit 1
    if [ -f "$unit/service.pid" ] || [ -f "$unit/live.json" ];then
        "$engine" "hyc-$port" stop
    fi
done
[ "$action" != guard ] || exit 0
pending=no
for record in "$runtime"/guard.*;do
    [ -f "$record" ] || continue
    read -r dev inner relay < "$record"
    valid_record "$dev" "$inner" "$relay"
    grep -Fqx "$dev $inner $relay" "$stage/guards" && continue
    # Keep the raw port fenced if native teardown failed part-way through.
    if [ "$(/usr/bin/wg show "$dev" listen-port 2>/dev/null || true)" = "$inner" ];then pending=yes;continue;fi
    protect remove "$inner" "$relay"
    rm -f "$record"
done
failed=0
: > "$stage/unready"
# Firewall snapshots, stale-worker revocations and port fences above always
# cover the entire saved inventory. A scoped mutation starts only its own
# workers. The boot / monitor invocation retries all enabled receivers.
while read -r dev peer_id readiness;do
    [[ $dev =~ ^wg[0-9]{1,10}$ && $peer_id =~ ^[1-9][0-9]{0,4}$ ]] || exit 1
    [[ $scope = '*' || " $scope " = *" $dev "* ]] || continue
    unit=puc-$peer_id
    if [ "$readiness" != ready ];then
        printf '%s\n' "$dev" >>"$stage/unready"
        failed=73
        continue
    fi
    if cmp -s "$units/$unit/live.json" "$stage/pure.$peer_id" && "$engine" "$unit" status >/dev/null;then continue;fi
    if ! "$engine" "$unit" start "$stage/pure.$peer_id" >/dev/null;then
        "$engine" "$unit" stop >/dev/null || exit 1
        printf '%s\n' "$dev" >>"$stage/unready"
        failed=73
    fi
done < "$stage/pure_units"
if [ ! -s "$stage/directions" ] && [ "$pending" = no ];then rm -f "$runtime/active";fi
if [ "$action" = monitor ];then
    # No output is produced until every global protection and revocation
    # succeeded. A safely stopped HY relay blocks only its own kernel peer.
    awk 'FILENAME==ARGV[1]{missing[$1]=1;next} !($1 in missing){print $1}' "$stage/unready" "$stage/enabled" >&3 || exit 1
fi
exit "$failed"
