#!/bin/bash
# Called under wireguard_address. Fence only interfaces whose native peer
# permissions can change before allowing WG to load the new cryptokey routes.
set -eu
set -o pipefail
umask 077
db=$1
step=$2
scope=${3:-}
proposed=${4:-}
dir=/tmp/iktmp/wg-native-role
direction=/usr/ikuai/script/wg_hyr_direction.sh
old=/etc/mnt/ikuai/wg-tcp/state.json
backup=/etc/mnt/ikuai/wg-hyr/state.json
query(){ sqlite3 -bail -cmd '.timeout 10000' "$db" "$1"; }
private_file(){ [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:600 ]; }
if [[ "$step" = migrate || "$step" = schema ]]; then
    # NativeRouting upgrades may preserve the vendor version number. Migrate
    # the live DB as well as the new-install template before any WG link loads.
    if ! query 'select native_role from wireguard_peers limit 0' >/dev/null 2>&1; then
        query "alter table wireguard_peers add column native_role text default ''" >/dev/null
    fi
    [ "$step" != schema ] || exit 0
    if [ -e "$old" ] || [ -L "$old" ]; then
        private_file "$old"
        current=-
        if [ -e "$backup" ] || [ -L "$backup" ]; then private_file "$backup"; current=$backup;fi
        /usr/bin/lua /usr/ikuai/script/wg_role_migrate.lua "$db" "$old" "$current"
        fsync "$db" "${db%/*}"
        rm "$old"
        fsync "${old%/*}"
    fi
    exit 0
fi
snapshot=$(query "select p.interface||' '||p.native_role||' '||case when instr(p.allowips,'/')=0 then p.allowips||'/32' else p.allowips end from wireguard_peers p join wireguard w on w.name=p.interface where p.enabled='yes' and w.enabled='yes' and ifnull(p.native_role,'') not in ('','site_client') order by p.id")
# The controller never creates a chain or directory for unmodified, legacy WG.
if [ ! -d "$dir" ] && [ -z "$snapshot" ] && [ -z "$proposed" ] && [ "$scope" != restore ]; then exit 0; fi
mkdir -p -m 700 "$dir"
[ ! -L "$dir" ] && [ "$(stat -c '%u:%a' "$dir")" = 0:700 ] || exit 1
work=$(mktemp -d "$dir/rules.XXXXXX")
trap 'rm -rf "$work"' EXIT
# A fail-closed monitor may bring down an interface that the administrator
# enabled. The marker is scoped to this boot, kernel link instance and saved
# server identity. Interface delete/recreate and explicit disable invalidate it.
identity(){
    local dev=$1 row index public
    [[ $dev =~ ^wg[0-9]{1,10}$ ]] || return 1
    row=$(query "select id||'|'||local_publickey from wireguard where name='$dev' and enabled='yes' and exists (select 1 from wireguard_peers where interface='$dev' and enabled='yes')") || return 1
    [ -n "$row" ] && index=$(cat "/sys/class/net/$dev/ifindex") &&
        public=$(/usr/bin/wg show "$dev" public-key) && [ -n "$public" ] && [ "${row#*|}" = "$public" ] || return 1
    printf '%s|%s\n' "$index" "$row"
}
up(){
    local flags
    flags=$(cat "/sys/class/net/$1/flags" 2>/dev/null) && (( flags & 1 ))
}
track(){
    local flag
    for flag in "$dir"/blocked-wg*; do [ ! -f "$flag" ] || return 0; done
    [ -n "$snapshot" ]
}
: > "$work/snapshot"
if [ "$snapshot" ]; then printf '%s\n' "$snapshot" > "$work/snapshot"; fi
case "$step" in
    before)
        if [ "$scope" = restore ]; then
            printf '%s\n' 'wg+ hold 0.0.0.0/32' > "$work/fence"
        else
            : > "$work/fence"
            while read -r dev role host; do
                [ "$dev" ] || continue
                if [[ " $scope " = *" $dev "* ]]; then printf '%s hold 0.0.0.0/32\n' "$dev";fi
            done < "$work/snapshot" > "$work/fence"
            # A previously disabled peer or interface may be about to become live.
            if [ "$scope" != '*' ] && [ "$scope" ]; then
                all=$(query "select distinct interface from wireguard_peers where ifnull(native_role,'') not in ('','site_client')")
                for dev in $scope; do
                    [[ $dev =~ ^wg[0-9]{1,10}$ ]] || exit 1
                    if [[ "$proposed" = "$dev" || $'\n'"$all"$'\n' = *$'\n'"$dev"$'\n'* ]]; then
                        printf '%s hold 0.0.0.0/32\n' "$dev" >> "$work/fence"
                    fi
                done
            fi
        fi
        # Replace the prior stable rules only while new surfaces are fenced.
        # In particular cold init is permitted to load keys only after this.
        sort -u "$work/fence" > "$work/unique"
        "$direction" "$work/unique" native-hold
        "$direction" "$work/snapshot" native
        if [ "$snapshot" ] || [ "$proposed" ]; then : >"$dir/active"; fi
        ;;
    after)
        "$direction" "$work/snapshot" native
        "$direction" /dev/null native-hold
        if track; then : >"$dir/active";else rm -f "$dir/active";fi
        ;;
    refresh)
        # Vendor firewall rebuilds can prepend rules or reset hooks. Use the
        # existing process monitor and the WG lock; never thaw a pending edit.
        if ! "$direction" "$work/snapshot" native; then
            while read -r dev role host; do
                [[ $dev =~ ^wg[0-9]{1,10}$ ]] && up "$dev" || continue
                # Write before taking the link down; another failure may prevent
                # recording the marker, but must never leave an unguarded link up.
                if stamp=$(identity "$dev") && printf '%s\n' "$stamp" >"$work/marker"; then
                    mv -f "$work/marker" "$dir/blocked-$dev" || :
                fi
                ip link set down dev "$dev" || :
            done < "$work/snapshot"
            exit 1
        fi
        for flag in "$dir"/blocked-wg*; do
            [ -f "$flag" ] || continue
            dev=${flag##*/blocked-}
            [[ $dev =~ ^wg[0-9]{1,10}$ ]] || exit 1
            if [ ! -e "/sys/class/net/$dev/ifindex" ]; then rm -f "$flag";continue;fi
            # DB failures are retryable. Only permanently discard a marker
            # after confirming that the kernel link or its saved identity changed.
            current=$(query "select id||'|'||local_publickey from wireguard where name='$dev' and enabled='yes' and exists (select 1 from wireguard_peers where interface='$dev' and enabled='yes')")
            index=$(cat "/sys/class/net/$dev/ifindex") || exit 1
            if [ -z "$current" ] || [ "$index|$current" != "$(cat "$flag")" ]; then rm -f "$flag";continue;fi
            public=$(/usr/bin/wg show "$dev" public-key) || exit 1
            if [ "${current#*|}" != "$public" ]; then rm -f "$flag";continue;fi
            printf '%s\n' "$dev"
        done
        if ! track; then rm -f "$dir/active";fi
        ;;
    recovered)
        [[ $scope =~ ^wg[0-9]{1,10}$ ]] && up "$scope" || exit 1
        rm -f "$dir/blocked-$scope"
        if ! track; then rm -f "$dir/active";fi
        ;;
    *) exit 2;;
esac
