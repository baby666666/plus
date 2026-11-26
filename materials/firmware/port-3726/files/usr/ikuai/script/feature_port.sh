#!/bin/bash /etc/ikcommon
init()
{
    mkdir -p /etc/mnt/ikuai /tmp/iktmp
    local db=/etc/mnt/ikuai/config.db column
    [ -s "$db" ] || return 1
    for column in out_mode out_wans out_balance peer_privatekey client_dns client_endpoint exit_peer site_local site_remote; do
        if ! sqlite3 "$db" 'pragma table_info(wireguard_peers)' | cut -d '|' -f2 | grep -qx "$column"; then
            local default=''
            [ "$column" = out_mode ] && default=auto
            [ "$column" = out_balance ] && default=failover
            [ "$column" = exit_peer ] && default=no
            sqlite3 "$db" "alter table wireguard_peers add column $column text default '$default';" || return 1
        fi
    done
    [ -f /etc/mnt/ikuai/ctpanel_cloud_remote.conf ] || echo RCSTATUS=off >/etc/mnt/ikuai/ctpanel_cloud_remote.conf
    echo '3.7.26 Enterprise native feature port; donor 97b01fb5' >/etc/mnt/ikuai/feature_port_version
}
boot()
{
    /usr/ikuai/script/retire_wg_dns.sh cleanup || return 1
    init || return 1
    /usr/ikuai/script/init_plugins.sh boot
    /usr/ikuai/script/cloud_remote_guard.sh apply
    /usr/ikuai/script/wg_center_route.sh boot
    [ -f /tmp/iktmp/region-iplib/restored ] || /usr/ikuai/script/strict_policy.sh region_restore >>/tmp/iktmp/region-restore.log 2>&1
    /usr/ikuai/script/strict_policy.sh domain_restore >>/tmp/iktmp/domain-restore.log 2>&1
    /usr/ikuai/script/strict_policy.sh boot
}
