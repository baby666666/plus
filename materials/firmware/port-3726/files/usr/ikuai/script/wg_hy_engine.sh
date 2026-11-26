#!/bin/bash
# Verified disk-backed sing-box installation for pure Hysteria 2 devices.
set -u
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
release=sing-box-1.14.4-linux-amd64-musl
archive=$release.tar.gz
url=https://github.com/SagerNet/sing-box/releases/download/v1.14.4/$archive
archive_sha=8f7c5f0651238850d96a0e488e5473cd77ec1a0098f63942e943f475a12057ca
binary_sha=fe23d7000aaaa91f40b63641a65a1a84d96b5f179c65b63f34893e238884cd5c
archive_bytes=32555215
archive_kib=$(((archive_bytes + 1023) / 1024))
binary_bytes=92070560
binary_kib=$(((binary_bytes + 1023) / 1024))
# Fingerprint of the reproducible read-only image of the same pinned executable.
packed_sha=e275c824b7ba81e14806aedcfbb7e9f300501df6d7a2b366566ca3935b98c1f1
packed_bytes=29552640
packed_kib=$(((packed_bytes + 1023) / 1024))
pack_tool=/usr/sbin/nr-hy2-corepack
packed=sing-box-$binary_sha.squashfs
rescue=$archive.migration
run=/tmp/iktmp/wg-hy-engine
# Retain the pinned archive installed by an earlier firmware.
cache_name=.nr-wg-reality
core=sing-box-$binary_sha
compact_root=$run/compact
binary=
# Open the exact inode verified by prepare when checking or launching it.
exec_binary=/proc/self/fd/7
service=$run
service_gid=
case ${1:-} in
    hyr-[1-9]*)
        unit=${1#hyr-}
        [[ $unit =~ ^[1-9][0-9]{0,4}$ ]] && [ "$unit" -le 65535 ] || exit 2
        service=$run/$1; service_gid=49319; shift;;
    hyc-[1-9]*)
        unit=${1#hyc-}
        [[ $unit =~ ^[1-9][0-9]{0,4}$ ]] && [ "$unit" -le 65535 ] || exit 2
        service=$run/$1; service_gid=49320; shift;;
    puh-[1-9]*|puc-[1-9]*)
        unit=${1#*-}
        [[ $unit =~ ^[1-9][0-9]{0,9}$ ]] || exit 2
        service=$run/$1
        case $1 in puh-*) service_gid=49322;; *) service_gid=49323;; esac
        shift;;
    hyr) service=$run/hyr; service_gid=49319; shift;;
esac
pidfile=$service/service.pid
live=$service/live.json
next=$service/next.json

error() { printf '%s\n' "$*" >&2; return 1; }
secure_dir() {
    [ ! -L "$1" ] && [ -d "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]
}
private_dir() {
    mkdir -m 700 "$1" 2>/dev/null || :
    secure_dir "$1"
}
runtime_dir() {
    case $2 in
        status|available|storage|installed|location)
            { [ ! -e "$1" ] && [ ! -L "$1" ]; } || secure_dir "$1";;
        *) private_dir "$1";;
    esac
}
verify() {
    local hash
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    hash=$(sha256sum "$1") && [ "${hash%% *}" = "$2" ]
}
free_kib() { df -Pk "$1" | awk 'END { print $4+0 }'; }
ram_at_least() {
    awk -v required="$1" '$1=="MemAvailable:" {ok=($2>=required)} END{exit !ok}' /proc/meminfo
}

# iKuai mounts ext data volumes by UUID. Never write into an unmounted directory,
# network share, RAM-backed configuration directory or the firmware boot disk.
volumes() {
    awk -v need_exec="${1:-no}" '$1 ~ /^\/dev\// && $3 ~ /^ext[234]$/ && $4 ~ /(^|,)rw(,|$)/ {
        if (need_exec == "yes" && $4 ~ /(^|,)noexec(,|$)/) next
        if ($2 ~ /^\/etc\/disk\/[a-fA-F0-9-]+$/) print $2
        if ($2 == "/etc/log") logvol=$2
        if ($2 == "/etc/mnt") cfgvol=$2
    } END { if(logvol) print logvol; if(cfgvol) print cfgvol }' /proc/mounts
}
# Store only the authenticated executable on capable volumes. RC16 archives on
# noexec or smaller media remain usable for a restart with a memory-backed ELF.
with_cache() (
    local volume=$1 action=$2 reserve=8192 filename=${3:-$archive}
    cd -P "$volume" && [ "$PWD" = "$volume" ] && mountpoint -q . || exit 2
    case $action in
        store|rescue|unpack|pack) private_dir "$cache_name" || exit 2;;
        *) [ -d "$cache_name" ] && [ ! -L "$cache_name" ] || exit 1;;
    esac
    cd -P "$cache_name" && [ "$PWD" = "$volume/$cache_name" ] &&
        [ "$(stat -c '%u:%a' .)" = 0:700 ] || exit 2
    case $action in
        locate|locate_archive|locate_packed)
            local mode=600
            case $action in
                locate) filename=$core; mode=500;;
                locate_packed)
                    filename=$packed; mode=400
                    [ "$(stat -c '%s' "$filename" 2>/dev/null)" = "$packed_bytes" ] || exit 1;;
            esac
            [ -f "$filename" ] && [ ! -L "$filename" ] &&
                [ "$(stat -c '%u:%a:%h' "$filename")" = "0:$mode:1" ] && printf '%s/%s\n' "$PWD" "$filename";;
        store|rescue)
            case $volume:$action in /etc/log:store) reserve=20480;; /etc/mnt:store) reserve=49152;; esac
            rm -f .partial || exit 2
            [ "$(free_kib .)" -ge $((archive_kib + reserve)) ] || exit 2
            [ ! -L "$filename" ] && [ ! -d "$filename" ] || exit 2
            trap 'rm -f .partial' EXIT
            (ulimit -f "$archive_kib"; cat /proc/self/fd/6 >.partial) &&
                verify .partial "$archive_sha" && mv -f .partial "$filename";;
        unpack|pack)
            case $volume in /etc/log) reserve=20480;; /etc/mnt) reserve=49152;; esac
            if [ "$action" = unpack ]; then
                unpack_here "$core" "$reserve"
            else
                # A busy loop device or a missing mount must not rewrite a valid image.
                if [ -f "$packed" ] && [ ! -L "$packed" ] &&
                        [ "$(stat -c '%u:%a:%h:%s' "$packed")" = "0:400:1:$packed_bytes" ] &&
                        verify "$packed" "$packed_sha"; then exit 0; fi
                # Budget for the bounded XZ encoder, dirty image pages and other services.
                ram_at_least 65536 || exit 2
                if [ "$(compact_backing "$(compact_mount_id)")" = "$PWD/$packed" ]; then
                    # Never unlink an image while running peers still use its mount.
                    umount "$compact_root" || exit 2
                fi
                [ ! -L "$packed" ] && { [ ! -e "$packed" ] || [ -f "$packed" ]; } || exit 2
                # A bad cache cannot be used. Reclaim it before staging a replacement
                # so recovery needs only one image's worth of free space.
                rm -f .packing "$packed" && [ "$(free_kib .)" -ge $((packed_kib + reserve)) ] || exit 2
                trap 'rm -f .packing' EXIT
                set -o pipefail
                (ulimit -f "$packed_kib"; tar -xzOf /proc/self/fd/6 "$release/sing-box" | "$pack_tool" .packing) &&
                    verify .packing "$packed_sha" && chmod 400 .packing && mv -f .packing "$packed"
            fi;;
        remove)
            [ -f "$filename" ] && [ ! -L "$filename" ] && rm -f "$filename";;
    esac
)
unpack_here() {
    local dest=$1 reserve=$2
    rm -f .unpack || return 1
    [ "$(free_kib .)" -ge $((binary_kib + reserve)) ] &&
        [ ! -L "$dest" ] && [ ! -d "$dest" ] || return 1
    trap 'rm -f .unpack' EXIT
    (ulimit -f "$binary_kib"; tar -xzOf /proc/self/fd/6 "$release/sing-box" >.unpack) &&
        verify .unpack "$binary_sha" && chmod 500 .unpack && mv -f .unpack "$dest"
}
open_archive() {
    local digest
    [ -f "$1" ] && [ ! -L "$1" ] && exec 6<"$1" && digest=$(sha256sum /proc/self/fd/6) &&
        [ "${digest%% *}" = "$archive_sha" ]
}
find_archive() {
    local vol name path
    while read -r vol; do
        for name in "$archive" "$rescue"; do
            path=$(with_cache "$vol" locate_archive "$name") && open_archive "$path" &&
                { source=$path; return 0; }
        done
    done < <(volumes)
    return 1
}
open_binary() {
    local path=$1 digest
    [ -f "$path" ] && [ ! -L "$path" ] && exec 7<"$path" &&
        [ "$(stat -Lc '%u:%a:%h' "$exec_binary")" = 0:500:1 ] &&
        digest=$(sha256sum "$exec_binary") && [ "${digest%% *}" = "$binary_sha" ] || return 1
    binary=$path
}
disk_binary() {
    local vol path
    while read -r vol; do
        path=$(with_cache "$vol" locate) && open_binary "$path" && return 0
    done < <(volumes yes)
    return 1
}
# Only mount images whose complete bytes match the pinned SHA. The readonly
# filesystem contains no device nodes or setuid files. Each worker inherits
# an already open descriptor for the one packed ELF. Reading and hashing the
# entire uncompressed file here would defeat on-demand decompression.
compact_mount_id() {
    awk -v dest="$compact_root" '$5==dest && $6~/(^|,)ro(,|$)/ &&
        $6~/(^|,)nosuid(,|$)/ && $6~/(^|,)nodev(,|$)/ && $6!~/(^|,)noexec(,|$)/ &&
        $(NF-2)=="squashfs" && $(NF-1)~/^\/dev\/loop[0-9]+$/ {print $1 ":" $3}' /proc/self/mountinfo
}
compact_backing() {
    [ -n "$1" ] && cat "/sys/dev/block/${1#*:}/loop/backing_file" 2>/dev/null
}
open_packed() {
    local path
    path=$(with_cache "$1" locate_packed) && open_image "$path" 5<"$path"
}
open_image() {
    # Close the backing descriptor on every return. Keeping a rejected inode
    # open would prevent reclaiming its space for an immediate repair.
    local path=$1 identity mount_id prior digest created=
    [ "$(stat -Lc '%u:%a:%h:%s' /proc/self/fd/5)" = "0:400:1:$packed_bytes" ] || return 1
    identity=$(stat -Lc '%d:%i:%s:%Y:%Z' /proc/self/fd/5) || return 1
    mount_id=$(compact_mount_id)
    prior=$(cat "$run/compact.seal" 2>/dev/null) || prior=
    if [ -z "$mount_id" ] || [ "$prior" != "$mount_id $identity" ]; then
        digest=$(sha256sum /proc/self/fd/5) && [ "${digest%% *}" = "$packed_sha" ] || return 1
        if mountpoint -q "$compact_root"; then
            # Recover a killed install between mount and seal, only after verifying
            # both the backing path and the complete ELF already on that mount.
            [ "$(compact_backing "$mount_id")" = "$path" ] &&
                open_binary "$compact_root/sing-box" || return 1
        else
            private_dir "$compact_root" && mount -i -t squashfs -o loop,ro,nodev,nosuid \
                /proc/self/fd/5 "$compact_root" || return 1
            mount_id=$(compact_mount_id)
            created=yes
        fi
        if [ "$(compact_backing "$mount_id")" != "$path" ] ||
                ! { printf '%s %s\n' "$mount_id" "$identity" >"$run/compact.new" &&
                    mv -f "$run/compact.new" "$run/compact.seal"; }; then
            [ -z "$created" ] || umount "$compact_root"
            return 1
        fi
    fi
    path=$compact_root/sing-box
    [ ! -L "$path" ] && [ -f "$path" ] && exec 7<"$path" &&
        [ "$(stat -Lc '%u:%a:%h:%s' "$exec_binary")" = "0:500:1:$binary_bytes" ] || return 1
    binary=$path
}
compact_binary() {
    local vol
    while read -r vol; do open_packed "$vol" && return 0; done < <(volumes yes)
    return 1
}
disk_ready() {
    local vol
    while read -r vol; do
        with_cache "$vol" locate >/dev/null && return 0
        if [ "${1:-}" != plain ]; then with_cache "$vol" locate_packed >/dev/null && return 0; fi
    done < <(volumes yes)
    return 1
}
remember() {
    local kind=$1 previous=
    [ ! -f "$run/storage" ] || read -r previous <"$run/storage"
    [ "$previous" != "$kind" ] || return 0
    printf '%s\n' "$kind" >"$run/storage.new" && mv -f "$run/storage.new" "$run/storage" || return 1
    if [ "$kind" = memory ] && [ "$previous" != memory ]; then
        logger -t native-hy2 'Hysteria 2 is using an 88 MiB memory-backed core because a verified disk-backed core could not be activated.'
    fi
}
finish_disk() {
    # Flush the executable before removing a rescue archive from another volume.
    # A power interruption at any earlier point leaves a verified source intact.
    if [ "$binary" != "$compact_root/sing-box" ] && [ -f "/etc/mnt/$cache_name/$rescue" ]; then
        sync && with_cache /etc/mnt remove "$rescue" || :
    fi
    rm -f "$run/sing-box"
    if [ "$binary" = "$compact_root/sing-box" ]; then remember compact; else remember disk; fi
}
prepare() {
    local action=$1 input=${2:-} source= persisted= vol path oldfree downloaded=$run/install.tgz
    if [ -n "$input" ]; then
        [[ $input = /* ]] && open_archive "$input" || {
            error '离线包必须是固定版本的官方 linux-amd64-musl 安装包'; return 1; }
    fi
    if disk_binary || compact_binary; then finish_disk; return $?; fi
    if find_archive; then
        persisted=yes
    else
        if [ "$action" != install ]; then error '缺少已校验的 Hysteria 2 核心，请安装核心并确认原数据盘已挂载'; return 1; fi
        if [ -n "$input" ]; then
            source=$input; open_archive "$source" || return 1
        else
            rm -f "$downloaded"
            ram_at_least $((archive_kib + 16384)) || { error '下载 Hysteria 2 安装包的可用内存不足'; return 1; }
            [ "$(free_kib "$run")" -ge $((archive_kib + 8192)) ] &&
                (ulimit -f "$archive_kib"; curl -q -4 -fsSL --proto '=https' --proto-redir '=https' \
                    --connect-timeout 10 --max-time 120 --max-filesize "$archive_bytes" \
                    --cacert /etc/ssl/certs/ca-certificates.crt -o "$downloaded" "$url") &&
                open_archive "$downloaded" || { error 'Hysteria 2 安装包下载或校验失败'; return 1; }
            source=$downloaded
        fi
    fi
    while read -r vol; do
        if with_cache "$vol" unpack && path=$(with_cache "$vol" locate) && open_binary "$path"; then
            finish_disk; return $?
        fi
        # On the standard small log volume an existing RC16 package and ELF
        # cannot coexist. The temporary rescue on cfg survives a power loss.
        if [ "$vol" = /etc/log ] && [ "$source" = "$vol/$cache_name/$archive" ] &&
                volumes | grep -Fxq /etc/mnt; then
            oldfree=$(free_kib "$vol")
            if [ $((oldfree + archive_kib)) -ge $((binary_kib + 20480)) ] &&
                    { { path=$(with_cache /etc/mnt locate_archive "$rescue") && (open_archive "$path"); } ||
                      { with_cache /etc/mnt rescue "$rescue" && sync; }; } &&
                    path=$(with_cache /etc/mnt locate_archive "$rescue") && open_archive "$path"; then
                source=$path
                with_cache "$vol" remove "$archive" &&
                    with_cache "$vol" unpack && path=$(with_cache "$vol" locate) && open_binary "$path" &&
                    { finish_disk; return $?; }
            fi
        fi
    done < <(volumes yes)
    # Keep a verified archive for cold boot even if loop devices are unavailable.
    if [ -z "$persisted" ]; then
        while read -r vol; do
            if with_cache "$vol" store && path=$(with_cache "$vol" locate_archive) && open_archive "$path"; then
                persisted=yes
                # fd 6 now references the persistent archive. Release our tmpfs
                # download before allocating the encoder or the fallback ELF.
                if [ "$source" = "$downloaded" ]; then rm -f "$downloaded" || return 1; fi
                source=$path
                break
            fi
        done < <(volumes)
        [ "$persisted" ] || { error 'Hysteria 2 安装空间不足，请挂载至少有 40 MiB 可用空间的 ext 数据盘'; return 1; }
    fi
    if [ -x "$pack_tool" ] && grep -qw squashfs /proc/filesystems; then
        while read -r vol; do
            if with_cache "$vol" pack && open_packed "$vol"; then finish_disk; return $?; fi
        done < <(volumes yes)
    fi
    if ! open_binary "$run/sing-box"; then
        ram_at_least $((binary_kib + 16384)) &&
            (cd "$run" && unpack_here sing-box 8192) && open_binary "$run/sing-box" ||
            { error 'Hysteria 2 的磁盘和运行内存空间不足'; return 1; }
    fi
    remember memory
}
running_pid() {
    local pid ticks inode current exe
    [ -f "$pidfile" ] && read -r pid ticks inode <"$pidfile" || return 1
    [[ $pid =~ ^[1-9][0-9]*$ && $ticks =~ ^[0-9]+$ ]] || return 1
    current=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null) && [ "$current" = "$ticks" ] || return 1
    if [ -n "$inode" ]; then
        [ "$(stat -Lc '%d:%i' "/proc/$pid/exe" 2>/dev/null)" = "$inode" ] || return 1
    else
        # Only recognize the RAM executable from a previous firmware for cleanup.
        exe=$(readlink "/proc/$pid/exe") &&
            { [ "$exe" = "$run/sing-box" ] || [ "$exe" = "$run/sing-box (deleted)" ]; } || return 1
    fi
    printf '%s\n' "$pid"
}
stop_process() {
    local pid i
    if pid=$(running_pid); then
        if ! kill -TERM "$pid" 2>/dev/null; then running_pid >/dev/null && return 1; fi
        for ((i=0; i<50; i++)); do running_pid >/dev/null || break; sleep 0.1; done
        if running_pid >/dev/null; then
            kill -KILL "$pid" || return 1
            for ((i=0; i<20; i++)); do running_pid >/dev/null || break; sleep 0.1; done
        fi
        running_pid >/dev/null && { error 'Hysteria 2 服务停止超时'; return 1; }
    fi
    rm -f "$pidfile"
}
listening() {
    local pid=$1 port=$2 inodes inode link fd
    local state=07 files="/proc/net/udp /proc/net/udp6"
    if [ "${3:-udp}" = tcp ];then state=0A; files="/proc/net/tcp /proc/net/tcp6"; fi
    inodes=$(awk -v p="$port" -v s="$state" '$4==s && $2 ~ ":"p"$" {print $10}' $files 2>/dev/null)
    [ -n "$inodes" ] || return 1
    for fd in /proc/"$pid"/fd/*; do
        link=$(readlink "$fd") || continue
        for inode in $inodes; do [ "$link" = "socket:[$inode]" ] && return 0; done
    done
    return 1
}
config_ports() {
    jq -r '.inbounds[] | if .type=="tun" then ("tun:"+.interface_name)
           elif .type=="hysteria2" then ("udp:"+(.listen_port|tostring))
           else empty end' "$1"
}
all_listening() {
    local pid=$1 ports=$2 port dev n
    while IFS= read -r port; do
        case $port in
            tun:*) dev=${port#*:}
                [[ $dev =~ ^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$ ]] && [ -e "/sys/class/net/$dev/tun_flags" ] &&
                    grep -h -E "^iff:[[:space:]]+$dev$" /proc/"$pid"/fdinfo/* >/dev/null 2>&1 || return 1;;
            udp:*) n=${port#*:}; [[ $n =~ ^[1-9][0-9]{0,4}$ ]] && [ "$n" -le 65535 ] &&
                    listening "$pid" "$(printf '%04X' "$n")" || return 1;;
            *) return 1;;
        esac
    done <<< "$ports"
}
launch() {
    local config=$1 ports pid ticks inode i fd fdnum
    ports=$(config_ports "$config") && [ -n "$ports" ] || return 1
    inode=$(stat -Lc '%d:%i' "$exec_binary") || return 1
    (
        # In particular, do not keep an inherited WG mutation lock or API pipe.
        exec </dev/null >/dev/null 2>&1
        for fd in /proc/self/fd/*; do
            fdnum=${fd##*/}
            if [[ $fdnum =~ ^[0-9]+$ ]] && [ "$fdnum" -gt 2 ] && [ "$fdnum" -ne 7 ]; then eval "exec ${fdnum}>&-"; fi
        done
        # Keep only the verified executable descriptor and the unit's socket GID.
        exec start-stop-daemon -S -c "0:$service_gid" -p /dev/null -x "$exec_binary" -- run -c "$config"
    ) &
    pid=$!
    ticks=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null)
    if [ -z "$ticks" ] || ! printf '%s %s %s\n' "$pid" "$ticks" "$inode" >"$pidfile"; then
        kill -TERM "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; return 1
    fi
    for ((i=0; i<100; i++)); do
        kill -0 "$pid" 2>/dev/null || break
        all_listening "$pid" "$ports" && return 0
        sleep 0.1
    done
    stop_process || return 1
    return 1
}
check_config() {
    [ -f "$1" ] && "$exec_binary" check -c "$1" >/dev/null 2>&1 || error 'Hysteria 2 配置校验失败'
}
apply_config() {
    local prior=
    cp "$1" "$next" && check_config "$next" || return 1
    if running_pid >/dev/null; then
        [ "$(stat -Lc '%d:%i' "/proc/$(running_pid)/exe")" = "$(stat -Lc '%d:%i' "$exec_binary")" ] &&
            cmp -s "$next" "$live" && all_listening "$(running_pid)" "$(config_ports "$live")" && return 0
        prior=yes
    fi
    stop_process || return 1
    if launch "$next" && mv -f "$next" "$live"; then return 0; fi
    stop_process || return 1
    if [ "$prior" ]; then
        launch "$live" || { error 'Hysteria 2 配置及原配置均未能恢复监听'; return 1; }
    fi
    error 'Hysteria 2 无法启动监听，请检查 UDP 端口是否被其他服务占用'
}

runtime_dir "$run" "${1:-}" || { error 'Hysteria 2 运行目录权限异常'; exit 1; }
if [ "$service" != "$run" ]; then
    case $service_gid in 49319|49320) [ "${1:-}" = stop ] || exit 2;; esac
    runtime_dir "$service" "${1:-}" || { error 'Hysteria 2 运行目录权限异常'; exit 1; }
fi
case ${1:-} in
    status|available|start|stop) [ "$service_gid" ] || exit 2;;
esac
case ${1:-} in
    status)
        pid=$(running_pid) || exit 1
        case $(cat "$run/storage" 2>/dev/null) in
            disk|compact) case $(readlink "/proc/$pid/exe") in "$run/sing-box"*) exit 1;; esac;;
        esac
        ports=$(config_ports "$live") && all_listening "$pid" "$ports"; exit $?;;
    installed) disk_ready || find_archive; exit $?;;
    storage|location)
        selected=$(cat "$run/storage" 2>/dev/null)
        mode=none
        if [ "$selected" = memory ] && [ -f "$run/sing-box" ]; then
            mode=memory
        elif disk_ready; then
            mode=disk
            if [ "$1" = location ]; then
                case $selected in
                    disk) disk_ready plain && mode=plain;;
                    compact)
                        mount_id=$(compact_mount_id)
                        backing=$(compact_backing "$mount_id")
                        if [ -n "$backing" ] && [ -f "$backing" ] && [ ! -L "$backing" ]; then
                            identity=$(stat -c '%d:%i:%s:%Y:%Z' "$backing")
                            [ "$(cat "$run/compact.seal" 2>/dev/null)" != "$mount_id $identity" ] || mode=compact
                        fi;;
                esac
            fi
        fi
        echo "$mode"; exit 0;;
    available)
        [[ ${2:-} =~ ^[1-9][0-9]{0,4}$ ]] && [ "$2" -le 65535 ] || exit 2
        port=$(printf '%04X' "$2")
        proto=${3:-udp}
        case "$proto" in tcp) state=0A;files="/proc/net/tcp /proc/net/tcp6";; udp) state=07;files="/proc/net/udp /proc/net/udp6";; *) exit 2;; esac
        if pid=$(running_pid) && listening "$pid" "$port" "$proto"; then exit 0; fi
        awk -v p="$port" -v s="$state" '$2~":"p"$" && $4==s{used=1} END{exit used+0}' $files
        exit $?;;
    install|path|check|start|stop) ;;
    *) error 'Usage: wg_hy_engine.sh install [absolute-offline-archive] | path | check CONFIG | start CONFIG | stop | status | installed | storage | location'; exit 2;;
esac
exec 8>"$run/engine.lock"
flock -x 8 || exit 1
trap 'rm -f "$next" "$run/install.tgz"' EXIT
case $1 in
    install) prepare install "${2:-}";;
    path) prepare cached && printf '%s\n' "$binary";;
    check) [ "$#" -eq 2 ] && prepare cached && check_config "$2";;
    start) [ "$#" -eq 2 ] && prepare cached && apply_config "$2";;
    stop) rm -f "$live" && stop_process;;
esac
