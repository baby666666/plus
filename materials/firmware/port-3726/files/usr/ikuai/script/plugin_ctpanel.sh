#!/bin/bash /etc/ikcommon
PLUGIN_NAME="01.ctpanel"
. /etc/release
. /etc/mnt/plugins/configs/config.sh

Include urlcode.sh

STATE_FILE="/etc/mnt/ikuai/ctpanel_cloud_remote.conf"
STATE_SCRIPT="/usr/ikuai/script/cloud_remote_guard.sh"

show()
{
    Show __json_result__
}

__ensure_repos()
{
    mkdir -p "$RMT_PLUGIN_REPOS_DIR" 2>/dev/null
    [ -f "$RMT_PLUGIN_REPOS_DIR/repos.json" ] || echo "[]" > "$RMT_PLUGIN_REPOS_DIR/repos.json"
}

__load_state()
{
    mkdir -p /etc/mnt/ikuai 2>/dev/null
    [ -f "$STATE_FILE" ] || echo "RCSTATUS=off" > "$STATE_FILE"
    . "$STATE_FILE" 2>/dev/null
    case "$RCSTATUS" in
        off|on) ;;
        *) RCSTATUS="on" ;;
    esac
}

__check_param()
{
    check_varl \
        'id  UUID match "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$"'
}

__show_data()
{
    __ensure_repos
    __load_state
    local sources=$(cat "$RMT_PLUGIN_REPOS_DIR/repos.json")
    local rcstatus="$RCSTATUS"
    local arch="${ARCH:-x86}"
    local gwid="${GWID:-}"
    local resetstatus="on"
    local wifistatus="off"
    local enterprise="on"
    local allowSwitchEnt="off"
    json_append __json_result__ sources:json rcstatus:str arch:str gwid:str resetstatus:str wifistatus:str enterprise:str allowSwitchEnt:str
    return 0
}

__show_regInfo()
{
    local mac="${DEVICE_MAC:-}"
    local regInfo="{\"mac\":\"$mac\"}"
    json_append __json_result__ regInfo:json
    return 0
}

set_rc_trunoff()
{
    case "$status" in
        true|1|yes|on) "$STATE_SCRIPT" set off >/dev/null 2>&1 || exit 1 ;;
        false|0|no|off) "$STATE_SCRIPT" set on >/dev/null 2>&1 || exit 1 ;;
        *)
            if [ "$status" = "True" -o "$status" = "TRUE" ]; then
                "$STATE_SCRIPT" set off >/dev/null 2>&1 || exit 1
            else
                "$STATE_SCRIPT" set on >/dev/null 2>&1 || exit 1
            fi
            ;;
    esac
}

set_rc_turnoff()
{
    set_rc_trunoff
}

__one_line()
{
    tr '\n' ';' | sed 's/"/\\"/g'
}

diag_cloud()
{
    __load_state
    local rcstatus="$RCSTATUS"
    local register_row="$(sqlite3 -separator '|' /etc/mnt/ikuai/config.db "select ifnull(id,''),ifnull(node,''),ifnull(code,''),ifnull(comment,'') from register where id=1;" 2>/dev/null | __one_line)"
    local cloud_node="$(cat /tmp/iktmp/cache/cloud_node 2>/dev/null | __one_line)"
    local hosts_register="$(cat /tmp/iktmp/ik_hosts/register 2>/dev/null | __one_line)"
    local hosts_files="$(ls -l /tmp/iktmp/ik_hosts /tmp/iktmp/ik_hosts/register /etc/get_hosts/hosts.conf /usr/ikuai/script/utils/get_hosts.sh /usr/ikuai/script/utils/update_hosts.sh 2>/dev/null | __one_line)"
    local remote_files="$(ls -l /usr/sbin/pmd /usr/sbin/ik_rc_client /usr/sbin/cre /etc/remote2/ikuai.conf /etc/remote2/ca-certificates.d/ikuai /etc/ssl/32015 /etc/ssl/32016 /etc/ssl/32017 /etc/pmd.d/pmd_host /etc/cre.d/cre_host 2>/dev/null | __one_line)"
    local remote_conf="$(cat /etc/remote2/ikuai.conf /etc/pmd.d/pmd_host /etc/cre.d/cre_host 2>/dev/null | __one_line)"
    local cloud_process="$(ps | grep -E 'ik_rc_client|pmd| cre|update_hosts|get_hosts|monitor_process' | grep -v grep | __one_line)"
    local cloud_netstat="$(netstat -tnp 2>/dev/null | grep -E 'ik_rc_client|pmd|cre|:9443|:1863|:1853|:2016|:15602' | __one_line)"
    local client_helpers="$(grep -n '^get_config\|^get_remote_host' /usr/ikuai/script/client.sh 2>/dev/null | __one_line)"
    local iptables_cloud="$((iptables -S OUTPUT 2>/dev/null; iptables -S INPUT 2>/dev/null; iptables -S cloud_DROP 2>/dev/null; iptables -S CLOUD_REMOTE_BLOCK 2>/dev/null) | grep -E 'cloud_DROP|CLOUD_REMOTE' | __one_line)"
    local start_log="$(tail -80 /tmp/iktmp/cloud_remote_guard.start.log 2>/dev/null | __one_line)"
    local install_log="$(cat /tmp/iktmp/ordinary_cloud_restore.log /tmp/iktmp/cloud_remote_guard.log /tmp/iktmp/ctpanel_fix_cloud.log 2>/dev/null | tail -120 | __one_line)"
    local cloud_test="$({ wget -4 -O- -S -q -t 1 -T 10 --connect-timeout=10 --dns-timeout=10 https://yun.ikuai8.com/bind2/checkbind --post-data="gwid=$GWID" 2>/tmp/ctpanel_cloud_wget.err; echo "rc=$?"; cat /tmp/ctpanel_cloud_wget.err 2>/dev/null; } | __one_line)"
    json_append __json_result__ rcstatus:str register_row:str cloud_node:str hosts_register:str hosts_files:str remote_files:str remote_conf:str cloud_process:str cloud_netstat:str client_helpers:str iptables_cloud:str start_log:str install_log:str cloud_test:str
}

__fix_cloud_collect()
{
    "$STATE_SCRIPT" set on >/tmp/iktmp/ctpanel_fix_cloud.log 2>&1 || true
    diag_cloud
}

fix_cloud()
{
    __fix_cloud_collect
    Show __json_result__
}

__show_diag_cloud()
{
    diag_cloud
}

# Cloud repair changes state. Keep it only under the fix_cloud write action;
# show (including TYPE=all) must never enable cloud remote control.

__decode_source_params()
{
    if [ "$encoding" = "url" ]; then
        name="$(url_decode_noeval_raw "$name")"
        url="$(url_decode_noeval_raw "$url")"
    fi
    [ "${#name}" -le 512 ] && [ "${#url}" -le 8192 ] || return 1
    [[ "$name$url" =~ [[:cntrl:]] ]] && return 1
    return 0
}

add()
{
    __ensure_repos
    check_varl \
        'name  Name != ""' \
        'url  Url != ""' || exit 1

    __decode_source_params || exit 1
    id=$(cat /proc/sys/kernel/random/uuid)
    repos=$(cat "$RMT_PLUGIN_REPOS_DIR/repos.json")
    repos="${repos%]}"
    [ "$repos" != "[" ] && repos="$repos,"

    repo_info=''
    enabled="${enabled:-yes}"
    case "$enabled" in yes|no) ;; *) exit 1 ;; esac
    json_append repo_info id:str name:str url:str enabled:str
    echo "${repos}${repo_info}]" > "$RMT_PLUGIN_REPOS_DIR/repos.json"
}

edit()
{
    __ensure_repos
    __check_param || exit 1
    check_varl \
        'name  Name != ""' \
        'url  Url != ""' || exit 1

    __decode_source_params || exit 1
    local edit_id="$id"
    local edit_name="$name"
    local edit_url="$url"
    json_decode_file repo_info "$RMT_PLUGIN_REPOS_DIR/repos.json"

    repos=''
    i=1
    while true; do
        eval id=\$repo_info_${i}_id
        eval name=\$repo_info_${i}_name
        eval url=\$repo_info_${i}_url
        eval enabled=\$repo_info_${i}_enabled
        [ -z "$id" ] && break
        [ "$id" = "$edit_id" ] && name="$edit_name" && url="$edit_url"
        repo_info=''
        json_append repo_info id:str name:str url:str enabled:str
        repos+="${repos:+,}$repo_info"
        i=$((i+1))
    done
    echo "[$repos]" > "$RMT_PLUGIN_REPOS_DIR/repos.json"
}

del()
{
    __ensure_repos
    __check_param || exit 1
    local del_id="$id"
    json_decode_file repo_info "$RMT_PLUGIN_REPOS_DIR/repos.json"

    repos=''
    i=1
    while true; do
        eval id=\$repo_info_${i}_id
        eval name=\$repo_info_${i}_name
        eval url=\$repo_info_${i}_url
        eval enabled=\$repo_info_${i}_enabled
        [ -z "$id" ] && break
        if [ "$id" = "$del_id" ]; then
            rm -rf "/etc/mnt/plugins/configs/img/$id"
            rm -f "$RMT_PLUGIN_REPOS_DIR/$id/release" "$RMT_PLUGIN_REPOS_DIR/$id/plugins.json"
            i=$((i+1))
            continue
        fi
        repo_info=''
        json_append repo_info id:str name:str url:str enabled:str
        repos+="${repos:+,}$repo_info"
        i=$((i+1))
    done
    echo "[$repos]" > "$RMT_PLUGIN_REPOS_DIR/repos.json"
}

__set_enabled()
{
    __ensure_repos
    __check_param || exit 1
    local target_id="$id"
    local target_enabled="$1"
    json_decode_file repo_info "$RMT_PLUGIN_REPOS_DIR/repos.json"

    repos=''
    i=1
    while true; do
        eval id=\$repo_info_${i}_id
        eval name=\$repo_info_${i}_name
        eval url=\$repo_info_${i}_url
        eval enabled=\$repo_info_${i}_enabled
        [ -z "$id" ] && break
        [ "$id" = "$target_id" ] && enabled="$target_enabled"
        repo_info=''
        json_append repo_info id:str name:str url:str enabled:str
        repos+="${repos:+,}$repo_info"
        i=$((i+1))
    done
    echo "[$repos]" > "$RMT_PLUGIN_REPOS_DIR/repos.json"
}

enable()
{
    __set_enabled yes
}

disable()
{
    __set_enabled no
}

# Native authenticated export contract: the RPC wraps stdout in Filename.
# File paths are fixed by the validated format; no caller-supplied path is used.
EXPORT()
{
    local format="${format:-txt}" target tmp
    case "$format" in csv|txt) ;; *) echo "Unsupported export format"; return 1 ;; esac
    __ensure_repos || return 1
    [ -n "$IK_DIR_EXPORT" ] || return 1
    mkdir -p "$IK_DIR_EXPORT" || return 1
    target="software_sources.$format"
    tmp=$(mktemp "$IK_DIR_EXPORT/.software-sources.XXXXXX") || return 1
    if ! jq -e -r --arg format "$format" '
        if type != "array" then error("invalid source list") else . end
        | map(if (.name|type) != "string" or (.url|type) != "string"
              then error("invalid source entry")
              else {name:.name, url:.url, enabled:(if .enabled == "no" or .enabled == false then "no" else "yes" end)} end)
        | if $format == "csv" then
            "\uFEFFname,url,enabled\r\n" + (map([.name,.url,.enabled] | @csv) | join("\r\n")) + "\r"
          else
            map("name=" + (.name|@json) + " url=" + (.url|@json) + " enabled=" + .enabled) | join("\n")
          end
    ' "$RMT_PLUGIN_REPOS_DIR/repos.json" > "$tmp"; then
        rm -f "$tmp"
        echo "Software source export failed"
        return 1
    fi
    chmod 600 "$tmp" && mv -f "$tmp" "$IK_DIR_EXPORT/$target" || {
        rm -f "$tmp"
        echo "Cannot save software source export"
        return 1
    }
    echo "$target"
}
