#!/bin/sh

STATE_DIR="/etc/mnt/ikuai"
STATE_FILE="$STATE_DIR/ctpanel_cloud_remote.conf"
BACKUP_FILE="$STATE_DIR/ctpanel_cloud_register.backup"
DB_FILE="$STATE_DIR/config.db"
CHAIN_NAME="CLOUD_REMOTE_BLOCK"
REG_SCRIPT="/usr/ikuai/script/register.sh"
CLIENT_SCRIPT="/usr/ikuai/script/client.sh"
MONITOR_SCRIPT="/usr/ikuai/script/utils/monitor_process.sh"
HOSTS_DIR="/tmp/iktmp/ik_hosts"
REGISTER_HOSTS="$HOSTS_DIR/register"

ensure_defaults()
{
    mkdir -p "$STATE_DIR" /tmp/iktmp 2>/dev/null
    [ -f "$STATE_FILE" ] || echo "RCSTATUS=off" > "$STATE_FILE"
}

load_state()
{
    ensure_defaults
    # Read data, never execute persisted configuration. Invalid state stays off.
    RCSTATUS="off"
    local state
    state=$(cat "$STATE_FILE" 2>/dev/null)
    case "$state" in
        RCSTATUS=on) RCSTATUS="on" ;;
        RCSTATUS=off) RCSTATUS="off" ;;
    esac
}

save_state()
{
    mkdir -p "$STATE_DIR" 2>/dev/null
    echo "RCSTATUS=$RCSTATUS" > "$STATE_FILE"
}

sql_quote()
{
    echo "$1" | sed "s/'/''/g"
}

backup_register()
{
    [ -f "$DB_FILE" ] || return 0
    local tmp="/tmp/iktmp/ctpanel_cloud_register.backup.$$"
    sqlite3 -separator '|' "$DB_FILE" "select ifnull(code,''),ifnull(comment,''),ifnull(node,0) from register where id=1;" > "$tmp" 2>/dev/null || true
    if [ -s "$tmp" ] && ! grep -q '^||0$' "$tmp" 2>/dev/null && ! grep -q '^ForceBindCloud|IK-Router|0$' "$tmp" 2>/dev/null; then
        cat "$tmp" > "$BACKUP_FILE" 2>/dev/null || true
    fi
    rm -f "$tmp" 2>/dev/null || true
}

clear_fake_register()
{
    [ -f "$DB_FILE" ] || return 0
    local code comment
    code=$(sqlite3 "$DB_FILE" "select ifnull(code,'') from register where id=1;" 2>/dev/null)
    comment=$(sqlite3 "$DB_FILE" "select ifnull(comment,'') from register where id=1;" 2>/dev/null)
    if [ "$code" = "ForceBindCloud" -a "$comment" = "IK-Router" ]; then
        sqlite3 "$DB_FILE" "update register set code='',comment='',node=0 where id=1;" >/dev/null 2>&1 || true
        mkdir -p /tmp/iktmp/cache 2>/dev/null
        echo 0 >/tmp/iktmp/register_status 2>/dev/null || true
        echo 0 >/tmp/iktmp/cache/cloud_node 2>/dev/null || true
    fi
}

disable_register()
{
    [ -f "$DB_FILE" ] || return 0
    backup_register
    sqlite3 "$DB_FILE" "update register set code='',comment='',node=0 where id=1;" >/dev/null 2>&1 || true
    mkdir -p /tmp/iktmp/cache 2>/dev/null
    echo 0 >/tmp/iktmp/register_status 2>/dev/null || true
    echo 0 >/tmp/iktmp/scode_status 2>/dev/null || true
    echo 0 >/tmp/iktmp/cache/cloud_node 2>/dev/null || true
    rm -f /tmp/iktmp/scode_result /etc/mnt/ikuai/auto_bind_cloud 2>/dev/null || true
}

restore_register()
{
    [ -f "$DB_FILE" ] || return 0
    if [ -s "$BACKUP_FILE" ]; then
        IFS='|' read code comment node < "$BACKUP_FILE"
        [ "$code" = "ForceBindCloud" -a "$comment" = "IK-Router" ] && return 0
        code=$(sql_quote "$code")
        comment=$(sql_quote "$comment")
        case "$node" in ''|*[!0-9]*) node=0 ;; esac
        sqlite3 "$DB_FILE" "update register set code='$code',comment='$comment',node=$node where id=1;" >/dev/null 2>&1 || true
        [ "$code" ] && echo 1 >/tmp/iktmp/register_status 2>/dev/null || echo 0 >/tmp/iktmp/register_status 2>/dev/null || true
        echo "$node" >/tmp/iktmp/cache/cloud_node 2>/dev/null || true
    fi
    echo 0 >/tmp/iktmp/scode_status 2>/dev/null || true
}

normalize_register_script()
{
    [ -f "$REG_SCRIPT" ] || return 0
    awk '
        /^request_scode\(\)$/ { print; fn="request_scode"; next }
        /^__check_bind\(\)$/ { print; fn="__check_bind"; next }
        fn && /^\{/ {
            print
            in_fn=fn
            fn=""
            next
        }
        in_fn == "request_scode" && /^[[:space:]]*return 0[[:space:]]*$/ { next }
        in_fn == "request_scode" && /^}/ { in_fn=""; print; next }
        in_fn == "__check_bind" && /^[[:space:]]*local code='\''ForceBindCloud'\''[[:space:]]*$/ { drop_force=1; next }
        drop_force && /^[[:space:]]*return 0[[:space:]]*$/ { drop_force=0; next }
        drop_force { next }
        in_fn == "__check_bind" && /^}/ { in_fn=""; print; next }
        { print }
    ' "$REG_SCRIPT" > /tmp/iktmp/register.sh.normalized 2>/dev/null && \
        cat /tmp/iktmp/register.sh.normalized > "$REG_SCRIPT" 2>/dev/null && \
        chmod 755 "$REG_SCRIPT" 2>/dev/null || true
}

patch_register_script()
{
    [ -f "$REG_SCRIPT" ] || return 0
    if grep -q 'CTPANEL_CLOUD_REMOTE_GUARD' "$REG_SCRIPT" 2>/dev/null; then
        sed 's@grep -q "^RCSTATUS=off" /etc/mnt/ikuai/ctpanel_cloud_remote.conf 2>/dev/null@[ "$(/usr/ikuai/script/cloud_remote_guard.sh status)" != "on" ]@' "$REG_SCRIPT" > /tmp/iktmp/register.sh.ctpanel_guard &&
            cat /tmp/iktmp/register.sh.ctpanel_guard > "$REG_SCRIPT"
        return 0
    fi
    awk '
        /^I18nload register\.json/ {
            print
            print ""
            print "__ctpanel_cloud_remote_disabled() {"
            print "    [ \"$(/usr/ikuai/script/cloud_remote_guard.sh status)\" != \"on\" ]"
            print "}"
            print "__ctpanel_cloud_remote_guard() {"
            print "    __ctpanel_cloud_remote_disabled || return 1"
            print "    mkdir -p /tmp/iktmp/cache 2>/dev/null"
            print "    echo 0 >/tmp/iktmp/register_status 2>/dev/null"
            print "    echo 0 >/tmp/iktmp/scode_status 2>/dev/null"
            print "    echo 0 >/tmp/iktmp/cache/cloud_node 2>/dev/null"
            print "    rm -f /tmp/iktmp/scode_result /etc/mnt/ikuai/auto_bind_cloud 2>/dev/null"
            print "    return 0"
            print "}"
            print "# CTPANEL_CLOUD_REMOTE_GUARD"
            next
        }
        /^init\(\)$/ { print; fn="init"; next }
        /^save\(\)$/ { print; fn="save"; next }
        /^request_scode\(\)$/ { print; fn="request_scode"; next }
        /^__check_bind\(\)$/ { print; fn="__check_bind"; next }
        /^__auto_config_bind\(\)$/ { print; fn="__auto_config_bind"; next }
        /^__get_cloud_services\(\)$/ { print; fn="__get_cloud_services"; next }
        /^bind_update\(\)$/ { print; fn="bind_update"; next }
        fn && /^\{/ {
            print
            if (fn == "init") print "    __ctpanel_cloud_remote_guard && return 0"
            else if (fn == "__check_bind") print "    __ctpanel_cloud_remote_guard && return 2"
            else if (fn == "request_scode") print "    __ctpanel_cloud_remote_guard && return 0"
            else if (fn == "__get_cloud_services") print "    __ctpanel_cloud_remote_guard && { echo \"{\\\"code\\\":403,\\\"message\\\":\\\"cloud remote disabled\\\",\\\"data\\\":{\\\"subscription\\\":[],\\\"otherTips\\\":[]}}\"; return 0; }"
            else print "    __ctpanel_cloud_remote_guard && { echo \"cloud remote disabled\"; return 1; }"
            fn=""
            next
        }
        { print }
    ' "$REG_SCRIPT" > /tmp/iktmp/register.sh.ctpanel_guard 2>/dev/null && \
        cat /tmp/iktmp/register.sh.ctpanel_guard > "$REG_SCRIPT" 2>/dev/null && \
        chmod 755 "$REG_SCRIPT" 2>/dev/null || true
}

cleanup_chain()
{
    while iptables -w -D OUTPUT -j "$CHAIN_NAME" >/dev/null 2>&1; do :; done
    while iptables -w -D INPUT -j "$CHAIN_NAME" >/dev/null 2>&1; do :; done
    iptables -w -F "$CHAIN_NAME" >/dev/null 2>&1 || true
    iptables -w -X "$CHAIN_NAME" >/dev/null 2>&1 || true
}

cleanup_legacy_cloud_drop()
{
    while iptables -w -D OUTPUT -j cloud_DROP >/dev/null 2>&1; do :; done
    while iptables -w -D INPUT -j cloud_DROP >/dev/null 2>&1; do :; done
    iptables -w -F cloud_DROP >/dev/null 2>&1 || true
    iptables -w -X cloud_DROP >/dev/null 2>&1 || true
}

apply_chain()
{
    iptables -w -N "$CHAIN_NAME" >/dev/null 2>&1 || true
    iptables -w -F "$CHAIN_NAME" >/dev/null 2>&1 || true

    # A DNS/HTTP client may choose one of these ports as its ephemeral source.
    # Permit only the tracked reply direction; new connections and original
    # outbound remote-control traffic still hit the port blocks below.
    iptables -w -A "$CHAIN_NAME" -p tcp -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN >/dev/null 2>&1 || return 1

    iptables -w -A "$CHAIN_NAME" -p tcp --dport 9443 -j DROP >/dev/null 2>&1 || true
    iptables -w -A "$CHAIN_NAME" -p tcp --dport 1853 -j DROP >/dev/null 2>&1 || true
    iptables -w -A "$CHAIN_NAME" -p tcp --dport 1863 -j DROP >/dev/null 2>&1 || true
    iptables -w -A "$CHAIN_NAME" -p tcp --dport 15602 -j DROP >/dev/null 2>&1 || true
    iptables -w -A "$CHAIN_NAME" -p tcp --dport 2016 -j DROP >/dev/null 2>&1 || true
    iptables -w -A "$CHAIN_NAME" -p tcp --dport 2010:2020 -j DROP >/dev/null 2>&1 || true
    iptables -w -A "$CHAIN_NAME" -p tcp --dport 2500:2510 -j DROP >/dev/null 2>&1 || true
    iptables -w -A "$CHAIN_NAME" -p tcp --dport 32015:32017 -j DROP >/dev/null 2>&1 || true

    iptables -w -C OUTPUT -j "$CHAIN_NAME" >/dev/null 2>&1 || \
        iptables -w -I OUTPUT 1 -j "$CHAIN_NAME" >/dev/null 2>&1 || true
    iptables -w -C INPUT -j "$CHAIN_NAME" >/dev/null 2>&1 || \
        iptables -w -I INPUT 1 -j "$CHAIN_NAME" >/dev/null 2>&1 || true
}

restore_client_helpers()
{
    [ -f "$CLIENT_SCRIPT" ] || return 0
    if ! grep -q '^get_config()' "$CLIENT_SCRIPT" 2>/dev/null; then
        awk '
            /^gwid=/ && !done {
                print
                print ""
                print "get_config() {"
                print "    echo '\\''{"
                print "        \"collect_info\":["
                print "            {\"info_name\":\"brief/router\", \"cmd\":\"get_sys_info\"},"
                print "            {\"info_name\":\"brief/ap\", \"cmd\":\"get_ap_info\"},"
                print "            {\"info_name\":\"client\", \"cmd\":\"get_client_status\"}],"
                print "        \"report_interval\":5,"
                print "        \"sdomain\":[{\"domain\":\"coll.ikuai8.com\",\"port\":2016},"
                print "            {\"domain\":\"59.110.6.135\",\"port\":2016}]"
                print "    }'\''"
                print "}"
                done=1
                next
            }
            { print }
        ' "$CLIENT_SCRIPT" > /tmp/iktmp/client.sh.ctpanel_cloud 2>/dev/null && \
            cat /tmp/iktmp/client.sh.ctpanel_cloud > "$CLIENT_SCRIPT" 2>/dev/null || true
    fi
    if ! grep -q '^get_remote_host()' "$CLIENT_SCRIPT" 2>/dev/null; then
        cat >> "$CLIENT_SCRIPT" <<'CLIENT_REMOTE_HOST_EOF'

get_remote_host() {
    echo '[{"domain":"coll.ikuai8.com","port":2016}]'
}
CLIENT_REMOTE_HOST_EOF
    fi
    chmod 755 "$CLIENT_SCRIPT" 2>/dev/null || true
}

patch_monitor_process()
{
    [ -f "$MONITOR_SCRIPT" ] || return 0
    grep -q 'CTPANEL_CLOUD_REMOTE_MONITOR' "$MONITOR_SCRIPT" 2>/dev/null && return 0
    awk '
        /^[[:space:]]*### test code/ && !done {
            print ""
            print "        ## CTPANEL_CLOUD_REMOTE_MONITOR"
            print "        if ! __get_process_status pmd ;then"
            print "            cgroup_exec /usr/sbin/pmd >/dev/null 2>/dev/null &"
            print "        fi"
            print "        if ! __get_process_status ik_rc_client ;then"
            print "            cgroup_exec /usr/sbin/ik_rc_client >/dev/null 2>/dev/null &"
            print "        fi"
            print "        if ! __get_process_status cre ;then"
            print "            cgroup_exec /usr/sbin/cre >/dev/null 2>/dev/null &"
            print "        fi"
            print "        if [ -z \"$OEMNAME\" -o \"$OEMNAME\" = \"oem\" ]; then"
            print "            if ! __get_process_status get_hosts.sh ;then"
            print "                cgroup_exec /usr/ikuai/script/utils/get_hosts.sh boot >/dev/null 2>/dev/null &"
            print "            fi"
            print "        fi"
            done=1
        }
        { print }
    ' "$MONITOR_SCRIPT" > /tmp/iktmp/monitor_process.sh.ctpanel_cloud 2>/dev/null && \
        cat /tmp/iktmp/monitor_process.sh.ctpanel_cloud > "$MONITOR_SCRIPT" 2>/dev/null && \
        chmod 755 "$MONITOR_SCRIPT" 2>/dev/null || true
}

refresh_cloud_hosts()
{
    mkdir -p "$HOSTS_DIR" /tmp/iktmp/cache 2>/dev/null
    [ -s /tmp/iktmp/cache/cloud_node ] || echo 0 >/tmp/iktmp/cache/cloud_node 2>/dev/null || true
    if [ -x /usr/ikuai/script/utils/update_hosts.sh ]; then
        /usr/ikuai/script/utils/update_hosts.sh __update_host >/dev/null 2>&1 || true
    fi
    if [ ! -s "$REGISTER_HOSTS" ] && [ -x /usr/ikuai/script/utils/get_hosts.sh ]; then
        /usr/ikuai/script/utils/get_hosts.sh boot >/dev/null 2>&1 || true
    fi
    [ -s "$REGISTER_HOSTS" ] || echo "yun.ikuai8.com" > "$REGISTER_HOSTS" 2>/dev/null || true
}

start_remote_services()
{
    local start_log="/tmp/iktmp/cloud_remote_guard.start.log"
    mkdir -p /tmp/ik_lua_files 2>/dev/null
    mkdir -p /etc/pmd.d /etc/cre.d /tmp/iktmp 2>/dev/null
    echo "$(date '+%F %T') start_remote_services begin" >> "$start_log" 2>/dev/null || true
    [ -f /etc/http_lua/ik_lua.data ] && ln -sf /etc/http_lua/ik_lua.data /tmp/ik_lua_files 2>/dev/null || true
    [ -s /etc/pmd.d/pmd_host ] || {
        echo 'pkgmanager.ikuai8.com:1863' > /etc/pmd.d/pmd_host
        echo 'pkgmanager.ikuai8.com:15602' >> /etc/pmd.d/pmd_host
    }
    [ -s /etc/cre.d/cre_host ] || echo 'dis.ikuai8.com:1853' > /etc/cre.d/cre_host
    refresh_cloud_hosts
    start_one()
    {
        local name="$1"
        local bin="$2"
        if pidof "$name" >/dev/null 2>&1; then
            echo "$(date '+%F %T') $name already running: $(pidof "$name" 2>/dev/null)" >> "$start_log" 2>/dev/null || true
            return 0
        fi
        if [ ! -x "$bin" ]; then
            echo "$(date '+%F %T') $name missing or not executable: $bin" >> "$start_log" 2>/dev/null || true
            return 0
        fi
        "$bin" >> "$start_log" 2>&1 &
        local pid="$!"
        sleep 1
        if pidof "$name" >/dev/null 2>&1; then
            echo "$(date '+%F %T') $name started pid=$pid live=$(pidof "$name" 2>/dev/null)" >> "$start_log" 2>/dev/null || true
        else
            echo "$(date '+%F %T') $name exited after start pid=$pid" >> "$start_log" 2>/dev/null || true
        fi
    }
    start_one pmd /usr/sbin/pmd
    start_one ik_rc_client /usr/sbin/ik_rc_client
    start_one cre /usr/sbin/cre
    if [ -x /usr/ikuai/script/utils/monitor_process.sh ]; then
        /usr/ikuai/script/utils/monitor_process.sh boot >/dev/null 2>&1 || true
    fi
    echo "$(date '+%F %T') start_remote_services end" >> "$start_log" 2>/dev/null || true
}

apply_state()
{
    load_state
    normalize_register_script
    patch_register_script
    cleanup_chain
    cleanup_legacy_cloud_drop
    if [ "$RCSTATUS" = "off" ]; then
        disable_register
        apply_chain
        killall -q pmd >/dev/null 2>&1 || true
        killall -q ik_rc_client >/dev/null 2>&1 || true
        killall -q cre >/dev/null 2>&1 || true
        echo "$(date '+%F %T') rcstatus=off" > /tmp/iktmp/cloud_remote_guard.status 2>/dev/null || true
    else
        restore_register
        clear_fake_register
        start_remote_services
        echo "$(date '+%F %T') rcstatus=on" > /tmp/iktmp/cloud_remote_guard.status 2>/dev/null || true
    fi
}

set_state()
{
    case "$1" in
        off|on) RCSTATUS="$1" ;;
        true|1|yes) RCSTATUS="off" ;;
        false|0|no) RCSTATUS="on" ;;
        *) load_state ;;
    esac
    save_state
    apply_state
}

status()
{
    load_state
    echo "$RCSTATUS"
}

case "$1" in
    set) set_state "$2" ;;
    on) set_state on ;;
    off) set_state off ;;
    status) status ;;
    *) apply_state ;;
esac
