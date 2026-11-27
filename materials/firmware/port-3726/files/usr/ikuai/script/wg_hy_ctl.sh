#!/bin/bash
# Manage Hysteria 2 listeners bound to individual WG peers under wireguard_address.
set -u
set -o pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
engine=/usr/ikuai/script/wg_hy_engine.sh
[ "${1:-}" = hyr ] && [ "$#" -ge 3 ] || exit 2
db=$2
shift 2
model=/usr/ikuai/script/wg_hyr_config.lua
data=/etc/mnt/ikuai/wg-hyr
runtime=/tmp/iktmp/wg-hyr
guard=NR_HYR_WG
gid=49319
live=/tmp/iktmp/wg-hy-engine/hyr/live.json
state=$data/state.json
change=$data/change
direction=/usr/ikuai/script/wg_hyr_direction.sh
pure=/usr/ikuai/script/wg_pure_service.sh
port_manager=/usr/ikuai/script/wg_hyr_ports.sh
tls=$data/tls
action=${1:-}
shift || exit 2
case $action in hold|prepare|check_mode|status|settings|profile|site_profile|uri|native_profile|sync|monitor|shutdown) ;; *) exit 2;; esac
fail(){ printf '%s\n' "$1"; exit 1; }
private_dir(){
    [ -d "$1" ] || mkdir -m 700 "$1" 2>/dev/null || return 1
    [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:700 ]
}
private_file(){ [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u:%a' "$1")" = 0:600 ]; }
units=/tmp/iktmp/wg-hy-engine
stop_stale(){
    local unit name
    # An RC8 process may still hold several public sockets on a live migration.
    if [ -e "$live" ] || [ -e "${live%/*}/service.pid" ];then "$engine" hyr stop >/dev/null || return 1;fi
    for unit in "$units"/hyr-[0-9]*;do
        [ -f "$unit/service.pid" ] || [ -f "$unit/live.json" ] || continue
        name=${unit##*/}
        "$engine" "$name" stop >/dev/null || return 1
    done
}
stop_service(){
    "$pure" stop - || fail '纯 Hysteria 2 停止失败'
    stop_stale || fail 'Hysteria 2 停止失败'
}

# QUIC replies follow the native firewall; new datagrams can only reach verified WG sockets.
pause_chain=NR_HYR_PAUSE
pause_rule=(OUTPUT -o lo -p udp -d 127.0.0.1/32 -m owner --gid-owner "$gid" -j "$pause_chain")
release_hold(){
    if iptables -w 3 -C "${pause_rule[@]}" 2>/dev/null; then
        iptables -w 3 -D "${pause_rule[@]}" || return 1
    fi
    rm -f "$runtime/scope" || return 1
    "$direction" /dev/null hold
}
# Kernel WG interfaces must still own their exact single-peer, loopback UDP
# destinations. A saved port alone could belong to a different local daemon.
apply_ports(){
    local plan=$1
    if [ -s "$plan" ] || [ -d /tmp/iktmp/wg-hyr-ports ]; then
        "$port_manager" apply "$plan" "$db"
    fi
}
remove_guard(){
    if ip6tables -w 3 -C OUTPUT -m owner --gid-owner "$gid" -j "$guard" 2>/dev/null; then
        ip6tables -w 3 -D OUTPUT -m owner --gid-owner "$gid" -j "$guard" &&
            ip6tables -w 3 -F "$guard" && ip6tables -w 3 -X "$guard" || return 1
    fi
    if ip6tables -w 3 -C OUTPUT -m owner --gid-owner "$gid" -j DROP 2>/dev/null; then
        ip6tables -w 3 -D OUTPUT -m owner --gid-owner "$gid" -j DROP || return 1
    fi
    if iptables -w 3 -C OUTPUT -m owner --gid-owner "$gid" -j "$guard" 2>/dev/null; then
        iptables -w 3 -D OUTPUT -m owner --gid-owner "$gid" -j "$guard" 2>/dev/null || return 1
    fi
    if iptables -w 3 -S "$guard" >/dev/null 2>&1; then
        iptables -w 3 -F "$guard" && iptables -w 3 -X "$guard"
    fi
}
# The WG row and the private registration are on separate databases. The native
# mutation stages its validated registration and projected row hash first. A
# restart can finish precisely the row that was written, or retain its old state.
row_hash(){
    local database=$1 row=$2 role_column=
    # The old firmware did not store the role in SQLite. Preserve its digest
    # for outstanding journals, and include it for every new proposal.
    case ${3:-} in '') ;; role-v2) role_column=',quote(native_role)';; *) return 1;; esac
    [[ $row =~ ^[1-9][0-9]{0,9}$ ]] || return 1
    sqlite3 -cmd '.timeout 10000' "$database" "SELECT quote(id),quote(interface),quote(exit_peer),quote(allowips),quote(peer_publickey),quote(peer_privatekey),quote(presharedkey),quote(client_dns),quote(keepalive),quote(enabled),quote(site_local),quote(site_remote)$role_column FROM wireguard_peers WHERE id=$row" | sha256sum
}
restore_direction()(
    local current_state=$1 work
    if [ "$current_state" = - ]; then "$direction" /dev/null;exit $?;fi
    # An interrupted write or restored database may differ from the proposal.
    # Reconcile the actual rows before keys are loaded into kernel WG links.
    work=$(mktemp -d "$runtime/policy.XXXXXX") || exit 1
    trap 'rm -rf "$work"' EXIT
    /usr/bin/lua "$model" sync "$db" "$current_state" "$work" && "$direction" "$work/directions"
)
freeze_directions(){
    local scope=$1 extra=${2:-} dev
    stop_stale || return 1
    "$port_manager" hold "$scope" || return 1
    : >"$runtime/fence" || return 1
    if [ -f "$state" ]; then
        jq -r '.members[] | .interface' "$state" >"$runtime/targets" || return 1
        while read -r dev;do
            [[ $dev =~ ^wg[0-9]{1,10}$ ]] || return 1
            if [[ "$scope" = '*' || " $scope " = *" $dev "* ]]; then
                printf '%s hold 0.0.0.0/32\n' "$dev" >>"$runtime/fence" || return 1
            fi
        done < "$runtime/targets"
    fi
    if [ -d "$change" ]; then cat "$change/fence" >>"$runtime/fence" || return 1; fi
    if [ "$extra" ]; then printf '%s hold 0.0.0.0/32\n' "$extra" >>"$runtime/fence" || return 1; fi
    "$direction" "$runtime/fence" hold
}
# Avoid creating runtime or persisted service state on a default installation.
if [ "$action" = monitor ] && [ ! -d "$change" ] && [ ! -e "$state" ] && [ ! -d "$runtime" ]; then exit 0; fi
if [ -d "$change" ]; then
    case "$action" in
        # A read-only status request never commits an interrupted update.
        status|hold|shutdown|monitor|sync|check_mode) ;;
        settings|profile|site_profile|uri|native_profile) fail 'WG 隧道设置正在恢复，请刷新后重试';;
        *) "$0" hyr "$db" sync >/dev/null || fail 'WG 隧道设置正在恢复，请刷新后重试';;
    esac
fi
private_dir "$runtime" || fail 'Hysteria 2 运行目录权限异常'
exec 9>"$runtime/controller.lock" || exit 1
if [ "$action" = monitor ]; then flock -xn 9 || exit 0; else flock -x 9 || exit 1; fi
if [ "$action" = shutdown ]; then
    # The ordinary process monitor may still be ticking during system teardown.
    : >"$runtime/shutdown" || exit 1
    stop_service; remove_guard && release_hold; exit $?
fi
[ ! -f "$runtime/shutdown" ] || exit 0
if [ "$action" = hold ]; then
    scope=${1-'*'}
    printf '%s\n' "$scope" >"$runtime/scope" || exit 1
    "$pure" hold - "$scope" || fail '纯 Hysteria 2 暂停失败'
    freeze_directions "$scope" || { stop_service; fail '无法冻结 WG 隧道方向'; }
    exit 0
fi
current=-
if [ -e "$data" ] || [ -L "$data" ]; then
    private_dir "$data" || { [[ $action = native_profile || $action = uri ]] || stop_service; fail 'Hysteria 2 存储权限异常'; }
fi
if [ -e "$state" ] || [ -L "$state" ]; then
    private_file "$state" || { [[ $action = native_profile || $action = uri ]] || stop_service; fail 'Hysteria 2 存储权限异常'; }
    current=$state
fi
# Editing reads the persisted peer under both locks. It needs no
# service probe, certificate, temporary configuration or credential export.
if [[ $action = settings || $action = status ]];then
    HY_CORE_LOCATION=$("$engine" location 2>/dev/null) || HY_CORE_LOCATION=absent
    export HY_CORE_LOCATION
fi
if [ "$action" = settings ]; then
    /usr/bin/lua "$model" settings "$db" "$current" - "${1:-}"
    exit $?
fi
# The outer wireguard_address lock also serializes recovery with the native write.
if [[ $action = sync || $action = monitor ]] && [ -d "$change" ]; then
    private_dir "$change" && { private_file "$change/next" || private_file "$change/dual"; } && private_file "$change/expected" &&
        private_file "$change/row" || { stop_service; fail 'Hysteria 2 存储权限异常'; }
    format=
    if [ -e "$change/role-v2" ]; then private_file "$change/role-v2" || fail 'Hysteria 2 存储权限异常';format=role-v2;fi
    actual=$(row_hash "$db" "$(cat "$change/row")" "$format") || { stop_service; fail '无法核对已保存的 WG 隧道'; }
    expected_row=$(cat "$change/expected") || exit 1
    if [ "$actual" = "$expected_row" ]; then
        # An interrupted older two-carrier edit can contain revised WG
        # permissions. Migrate those only if its projected native row committed.
        if [ -e "$change/tcp.next" ]; then
            retired=/etc/mnt/ikuai/wg-tcp
            private_file "$change/tcp.next" && private_dir "$retired" &&
                cp "$change/tcp.next" "$retired/recovery" && fsync "$retired/recovery" &&
                mv -f "$retired/recovery" "$retired/state.json" && fsync "$retired" ||
                fail '旧设备用途无法安全迁移'
        fi
        if [ -f "$change/next" ] && { [ "$current" = - ] || ! cmp -s "$change/next" "$current"; }; then
            # The affected targets were fenced before the native write. Unrelated
            # workers stay live; retire changed accounts before reopening the fence.
            # Keep the journal intact until the atomic rename is durable/retryable.
            cp "$change/next" "$change/commit" && fsync "$change/commit" && mv -f "$change/commit" "$state" || fail '保存 Hysteria 2 设置失败'
            current=$state
        fi
    fi
    if [ "$current" != - ]; then fsync "$state" "$data" || fail '保存 Hysteria 2 设置失败'; fi
    # The shared fence may also protect the native (unwrapped) WG path. Put
    # the recovered direction rules in place before allowing it to thaw.
    if [ -f "$change/next" ]; then
        restore_direction "$current" || { stop_service;fail 'WG 隧道方向规则应用失败'; }
    fi
    rm -rf "$data/change.applied" && mv "$change" "$data/change.applied" && fsync "$data" &&
        rm -rf "$data/change.applied" || fail '保存 Hysteria 2 设置失败'
fi
# Reboot and monitor always use the saved registry, never stale runtime secrets.
if [[ $action = sync || $action = monitor ]] && [ "$current" = - ]; then
    stop_service
    remove_guard && apply_ports /dev/null && "$direction" /dev/null && release_hold
    exit $?
fi
stage=$(mktemp -d "$runtime/work.XXXXXX") || exit 1
pending=; identity=; journal=
trap 'rm -rf "$stage"; [ -z "$pending" ] || rm -f "$pending"; [ -z "$identity" ] || rm -rf "$identity"; [ -z "$journal" ] || rm -rf "$journal"' EXIT
trap 'exit 1' HUP INT TERM

run_model(){
    local cmd=$1; shift
    /usr/bin/lua "$model" "$cmd" "$db" "$current" "$stage" "$@"
}
status(){
    local installed=no running=no
    "$engine" installed >/dev/null 2>&1 && installed=yes
    run_model inspect || return 1
    "$pure" status "$stage" || return 1
    for n in "$stage"/ready.*;do [ ! -f "$n" ] || running=yes;done
    run_model status "$installed" "$running"
}
if [ "$action" = status ]; then status; exit $?; fi
if [[ $action = check_mode || $action = native_profile ]]; then run_model "$action" "$@";exit $?;fi
if [ "$action" = uri ]; then
    [ "$current" != - ] || fail '设备隧道已变化，请刷新后重试'
    [ -d "$tls" ] && private_dir "$tls" && private_file "$tls/key.pem" && private_file "$tls/cert.pem" ||
        fail 'Hysteria 2 证书不可用'
    run_model uri "$@"; exit $?
fi
private_dir "$data" || fail 'Hysteria 2 存储权限异常'
if [[ $action = sync || $action = monitor ]];then
    run_model retire_wrapped || { stop_service; fail '旧 Hysteria 2 隧道停用失败'; }
fi
need_tls=yes
if [[ $action = sync || $action = monitor ]] &&
    ! jq -e '.members[] | select(.transport=="pure_hy2" and .mode!="lend")' "$state" >/dev/null;then need_tls=no;fi
if [ "$action" = prepare ] && [ "${4:-}" = off ]; then need_tls=no; fi
if [ "$need_tls" = yes ] && [ ! -d "$tls" ] && [ ! -L "$tls" ]; then
    case "$action" in
        prepare)
            if [ "$current" != - ] && jq -e '.members[] | select(.transport=="pure_hy2" and .mode!="lend")' "$current" >/dev/null;then
                stop_service; fail 'Hysteria 2 证书不可用'
            fi
            identity=$(mktemp -d "$data/tls.XXXXXX") || exit 1
            serial=$(cat /proc/sys/kernel/random/uuid) || exit 1
            if ! openssl req -new -newkey rsa:2048 \
                -x509 -nodes -sha256 -days 3650 -subj "/CN=$serial" -keyout "$identity/key.pem" \
                -out "$identity/cert.pem" </dev/null >/dev/null 2>&1 ||
                ! mv "$identity" "$tls"; then fail 'Hysteria 2 证书创建失败'; fi
            identity=;;
        *) stop_service; fail 'Hysteria 2 证书不可用';;
    esac
fi
if [ "$need_tls" = yes ]; then
    private_dir "$tls" && private_file "$tls/key.pem" && private_file "$tls/cert.pem" ||
        { stop_service; fail 'Hysteria 2 证书不可用'; }
fi
if [[ $action = profile || $action = site_profile ]]; then
    openssl x509 -in "$tls/cert.pem" -pubkey -noout 2>/dev/null |
        openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -binary |
        openssl enc -base64 -A >"$stage/pin" || fail 'Hysteria 2 证书不可用'
    run_model "$action" "$@"; exit $?
fi
[ "$action" != monitor ] || action=sync
if [ "$action" = prepare ]; then
    # Actual and projected databases are both private and under the WG lock.
    [[ "$#" -ge 7 && "$#" -le 12 ]] || exit 2
    projected=$1; row=$2; iface=$3; mode=$4; expected=$5; first_ip=$6; first_port=$7; port_mode=${8:-}; addr_mode=${9:-}; resume=${10:-}
    [[ $iface =~ ^wg[0-9]{1,10}$ ]] || fail '请选择已保存的 WG 接口'
    run_model check_mode "$row" "$expected" || exit 1
    actual_db=$db
    db=$projected
    run_model set_mode "$row" "$mode" "$expected" "$first_ip" "$first_port" "$port_mode" "$addr_mode" "$resume" "${11:-}" "$actual_db" "${12:-}" || exit 1
    "$pure" check "$stage" "$iface" || fail '纯 HY2 配置或端口不可用，请检查 UDP 端口'
elif ! run_model "$action" "$@"; then
    [ "$action" != sync ] || stop_service
    exit 1
fi
if [ "$action" = prepare ]; then
    journal=$(mktemp -d "$data/change.XXXXXX") || fail '保存 Hysteria 2 设置失败'
    : >"$journal/role-v2" && row_hash "$projected" "$row" role-v2 >"$journal/expected" &&
        printf '%s\n' "$row" >"$journal/row" &&
        printf '%s hold 0.0.0.0/32\n' "$iface" >"$journal/fence" || fail '保存 Hysteria 2 设置失败'
    if [ -f "$stage/next" ]; then cp "$stage/next" "$journal/next" || exit 1; fi
    scope=$iface
    if [ -f "$runtime/scope" ]; then scope=$(cat "$runtime/scope"); fi
    freeze_directions "$scope" "$iface" || { stop_service; fail '无法冻结 WG 隧道方向'; }
    fsync "$journal"/* "$journal" && mv "$journal" "$change" && fsync "$data" || fail '保存 Hysteria 2 设置失败'
    journal=; exit 0
fi
if [ "$current" = - ] || ! cmp -s "$state" "$stage/next"; then
    pending=$(mktemp "$data/state.XXXXXX") && cat "$stage/next" >"$pending" ||
        fail '保存 Hysteria 2 设置失败'
    # Remove all old sessions and the recoverable process snapshot before
    # committing a revocation. No old config can recover after this point.
    stop_stale || fail 'Hysteria 2 停止失败'
    fsync "$pending" && mv -f "$pending" "$state" && fsync "$state" "$data" || fail '保存 Hysteria 2 设置失败'
    pending=
fi
stop_stale || fail 'Hysteria 2 停止失败'
"$port_manager" prune /dev/null || { stop_service;fail 'Hysteria 2 内部 WG 端口保护未就绪'; }
apply_ports "$stage/placements" || { stop_service; fail '无法应用 Hysteria 2 同号端口及内部 WG 保护'; }
if ! "$direction" "$stage/directions"; then stop_service; fail 'WG 隧道方向规则应用失败'; fi
"$pure" sync "$stage" "${1:-*}" || fail '纯 Hysteria 2 启动失败，请检查接口、端口和运行状态'
remove_guard && release_hold
