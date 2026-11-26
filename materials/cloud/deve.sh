#!/bin/sh
# Only initialize a fresh cloud install. Never overwrite later user WAN/Web settings.
[ "$1" = boot_begin ] || exit 0
DB=/etc/mnt/ikuai/config.db
MARK=/etc/mnt/ikuai/cloud-firstboot-v1.done
[ -f "$DB" ] || exit 0
[ ! -f "$MARK" ] || exit 0
mac=$(awk '$1=="eth0"{print $2;exit}' /tmp/iktmp/cache/ether_info 2>/dev/null)
case "$mac" in
    ??:??:??:??:??:??) ;;
    *) exit 1 ;;
esac
# Defaults have already been created; WAN/LAN services have not yet started.
[ "$(sqlite3 "$DB" 'select count(*) from wan_config where id=1;')" = 1 ] || exit 1
sqlite3 "$DB" "BEGIN;
UPDATE lan_config SET bandif='',bandeth='' WHERE id=1;
UPDATE wan_config SET name='wan1',bandif='$mac',bandeth='eth0',modified_time=1,internet=1,default_route=1 WHERE id=1;
UPDATE remote_control SET open_wanweb=1;
COMMIT;" || exit 1
rm -f /etc/mnt/ikuai/reset_default.flag /etc/mnt/ikuai/reset_default.ip
printf 'cloud image 3.7.26: eth0=%s, DHCP WAN, WAN Web enabled\n' "$mac" > "$MARK"
sync
exit 0
