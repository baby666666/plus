#!/bin/bash /etc/ikcommon
shopt -s expand_aliases
alias getpid="awk '\$1==\"PPid:\"{print \$2;exit}' /proc/self/status"

Include lock.sh ik_hosts.sh sys/cgroup_control.sh
I18nload sys_event.json

# Only execute regular files at the configured path; do not follow symlinks.
__is_regular_file()
{
	local file="$1"
	[ -f "$file" ] && [ ! -L "$file" ]
}

__is_safe_executable()
{
	local executable="$1"

	if __is_regular_file "$executable" && [ -x "$executable" ]; then
		return 0
	fi

	# ikdnsx is the only allowed symlink and must resolve to the real ikdnsd binary.
	[ "$executable" = "/usr/sbin/ikdnsx" ] || return 1
	[ -L "$executable" ] || return 1
	[ "$(readlink -f "$executable")" = "/usr/sbin/ikdnsd" ] || return 1
	__is_regular_file /usr/sbin/ikdnsd && [ -x /usr/sbin/ikdnsd ]
}

__exec_safe()
{
	local executable="$1"
	shift
	__is_safe_executable "$executable" || return 126
	"$executable" "$@"
}

__exec_safe_bg()
{
	local executable="$1"
	shift
	__is_safe_executable "$executable" || return 126
	exec "$executable" "$@"
}

__cgroup_exec_safe()
{
	local executable="$1"
	shift
	__is_safe_executable "$executable" || return 126
	cgroup_exec "$executable" "$@"
}

__cgroup_exec_safe_bg()
{
	local executable="$1"
	shift
	__is_safe_executable "$executable" || return 126
	cgroup_exec "$executable" "$@" &
}

boot()
{
	start >/dev/null 2>&1 &
}

__get_process_status() {
	for process in $all_process ;do
		if [ "$process" = "(${1:0:15})" ] ;then
			return 0
		fi
	done
	return 1
}

__memory_balloon()
{
	local value=$(awk 'BEGIN{count=0}{if(NR>1){a=$12+$13+$14+$15; count=count+a}}END{print count}' /proc/buddyinfo)
	if [ "$value" = "0" ]; then
		count=$((count+1))
		if [[ "$count" -ge 5 ]]; then
			count=0
			echo 3 > /proc/sys/vm/drop_caches
		else
			echo 1 > /proc/sys/vm/drop_caches
		fi
		echo 1 > /proc/sys/vm/compact_memory
	fi
}

__check_acpi_interrupts()
{
	[ "$ARCH" != "x86" ] && return

	awk '$NF=="unmasked"&&$1>1000{line=NF-1; print FILENAME,$line}' /sys/firmware/acpi/interrupts/* |
	while read filename status; do
		[ "$status" = "disabled" ] && continue
		echo "disable" > $filename
	done
}

__tso_off()
{
	ethtool -K eth0 tso off >/dev/null 2>&1
	ethtool -K eth1 tso off >/dev/null 2>&1
	ethtool -K eth0 gro off >/dev/null 2>&1
	ethtool -K eth1 gro off >/dev/null 2>&1
	while read name other; do
		ethtool -K "$name" tso off >/dev/null 2>&1
		ethtool -K "$name" gro off >/dev/null 2>&1
	done < /tmp/iktmp/cache/ether_info
}

__check_tso_align()
{
	[ "$ARCH" = "x86" ] && return

	if [ -n "$1" -a -e "/etc/log/.tso_set" ]; then
		__tso_off
	fi

	[ -e "/etc/log/.tso_set" ] && return

	local current_timestamp=$(date +%s)
	local check_timestamp=$((current_timestamp-600))

	local res=$(sqlite3 $IK_DB_SYSLOG "select id from kernel where timestamp > ${check_timestamp} and content like '%Detect reset event: TSO Align%'")
	if [ -n "$res" ]; then
		#disable tso
		__tso_off
		touch /etc/log/.tso_set
	fi
}

#专门使用hosts同步的程序监控, 如果hosts没有更新下来, 我们就没必要反复的检测
using_hosts_update_process()
{
	if [ ! -f "/tmp/iktmp/ik_hosts/__comment__" ];then
		return 0
	fi

	#远控
	#根据hosts 的变动，自动重启进ik_route_collect
}

#进程服务监视
start() {
	#进程查看时，最大长度是15字符，当有进程超过15字节长度时需要注意
	LOCKUP="Lock moni_process"
	UNLOCK="unLock moni_process"
	pid=$(getpid)
	echo $pid > /var/run/moni_process.pid
	sleep 60

	__check_tso_align init

	local count=0
	while : ;do
		$LOCKUP

		all_process="`cat /proc/[0-9]*/stat 2>/dev/null|cut -d " " -f2 `"

		if ! __get_process_status openresty ;then
			__exec_safe /usr/sbin/openresty
		fi

		#ikdnsd
		if [ -e /tmp/iktmp/ikdnsx.status ]&& ! __get_process_status ikdnsx ;then
			__exec_safe /usr/sbin/ikdnsx -C /tmp/hosts_conf -S /tmp/hosts_ikuai8 -P /var/run/ikdnsx.hosts.pid
			Syslog $(Iecho i18n_sys_event_monitor_process 'DNS')
		fi
		if [ -e /tmp/iktmp/ikdnsd.status ]&& ! __get_process_status ikdnsd ;then
			__exec_safe /usr/sbin/ikdnsd -C /tmp/iktmp/ikdnsd.conf -S /tmp/iktmp/ikdnsd.static.conf -P /var/run/ikdnsd.pid
			Syslog $(Iecho i18n_sys_event_monitor_process 'DNS')
		fi

		#DHCPserver
		if [ -e /tmp/iktmp/dhcp-server.status ]&& ! __get_process_status ik_dhcpd ;then
			if __exec_safe /usr/sbin/ik_dhcpd -c /tmp/iktmp/ik_dhcpd.conf -s /tmp/iktmp/ik_dhcpd_static.conf -l /var/db/leases.db; then
				Syslog $(Iecho i18n_sys_event_monitor_process 'DHCPD')
				##路由感知
				__exec_safe_bg /usr/ikuai/script/rt_collect.sh add_db_send \
					server_name="dhcp_server" action="restart" priority=3 \
					append_detail="monitor_process restart" >/dev/null 2>&1 &
			fi
		fi

		#ik_kernel_event
		if ! __get_process_status ik_kernel_event ;then
			__exec_safe_bg /usr/sbin/ik_kernel_event >/dev/null 2>/dev/null &
			Syslog $(Iecho i18n_sys_event_ik_kernel_event)
		fi

		if [ -z "$SUPPORT_MINI_FUNC" ]; then
			#ik_black
			if ! __get_process_status ik_black ;then
				__exec_safe_bg /usr/bin/ik_black >/dev/null 2>/dev/null &
				Syslog $(Iecho i18n_sys_event_ik_black)
			fi
			##lldpd
			if ! __get_process_status lldpd  ;then
				__exec_safe_bg /usr/sbin/lldpd -s >/dev/null 2>&1 &
			fi
		fi

		#ik_stats_collect
		if ! __get_process_status ik_stats_collect ;then
			__exec_safe_bg /usr/sbin/ik_stats_collect -ds /proc/ikuai/stats/ik_proto_stats >/dev/null 2>/dev/null &
			Syslog $(Iecho i18n_sys_event_ik_stats_collect)
		fi

		#ikstats: cpu, iface
		if ! __get_process_status ikstats ;then
			__exec_safe_bg /usr/sbin/ikstats >/dev/null 2>/dev/null &
			Syslog $(Iecho i18n_sys_event_ikifstat)
		fi
		#iksyslogd
		if ! __get_process_status iksyslogd ;then
			__exec_safe_bg /usr/sbin/iksyslogd >/dev/null 2>/dev/null &
			Syslog $(Iecho i18n_sys_event_iksyslogd)
		fi

		if [ -e "$IK_DIR_VRRP/is_enabled" ] && ! __get_process_status ik_confsync_server ;then
			__exec_safe /usr/bin/ik_confsync_server >/dev/null 2>&1
		fi

		#AC
		if [ -e /tmp/iktmp/AC.status ]&& ! __get_process_status AC ;then
			local $(cat /tmp/iktmp/cache/config/basic)
			local branch=""
			if [ "$link_mode" = "1" ];then
				branch="-b"
			fi
			__exec_safe /usr/bin/AC $branch -c /usr/ikuai/ac

			Syslog $(Iecho i18n_sys_event_ik_ac)
		fi
		if [ -e /tmp/iktmp/AC.mesh ]&& ! __get_process_status AC ;then
			local $(cat /tmp/iktmp/cache/config/basic)
			local branch=""
			if [ "$link_mode" = "1" ];then
				branch="-b"
			fi
			__exec_safe /usr/bin/AC $branch -c /usr/ikuai/ac

			Syslog $(Iecho i18n_sys_event_ik_ac)
		fi

		#auditd url
		if [ -e /tmp/iktmp/audit.open_url_record ]&& ! __get_process_status ik_url_auditd ;then
			rm /usr/ikuai/www/audit_url
			if [ -e "/etc/disk_sys/audit" ]; then
				ln -s /etc/disk_sys/audit/stream /usr/ikuai/www/audit_url
				__cgroup_exec_safe_bg /usr/bin/ik_url_auditd -l /etc/disk_sys/audit >/dev/null 2>/dev/null
			else
				ln -s /etc/log/audit/stream /usr/ikuai/www/audit_url
				__cgroup_exec_safe_bg /usr/bin/ik_url_auditd -l /etc/log/audit >/dev/null 2>/dev/null
			fi
			Syslog $(Iecho i18n_sys_event_ik_auditd_url)
		fi
		if [ -e /tmp/iktmp/ik_web_radius.status ]&& ! __get_process_status ik_web_radius;then
			rm /tmp/webradius_fifo
			__exec_safe_bg /usr/bin/ik_web_radius >/dev/null 2>/dev/null &
			sleep 1
			__exec_safe_bg "$IK_DIR_SCRIPT/webauth.sh" radius_macbind_request >/dev/null 2&1 &
			Syslog $(Iecho i18n_sys_event_ik_web_radius)
		fi
		#auth sync
#		if [ -e /tmp/iktmp/ik_sync_server.status ]&& ! __get_process_status ik_sync_server;then
#			sync_server_cmd=$(cat /tmp/iktmp/ik_sync_server.status)
#			cgroup_exec $sync_server_cmd &
#			Syslog $(Iecho i18n_sys_event_ik_sync_server)
#		fi
		#ik_ua_parser
		if ! __get_process_status ik_host_ua ;then
			__exec_safe_bg /usr/bin/ik_host_ua >/dev/null 2>/dev/null &
			Syslog $(Iecho i18n_sys_event_ik_host_ua)
		fi

		#iktimerd
		if ! __get_process_status iktimerd ;then
			__exec_safe_bg /usr/sbin/iktimerd >/dev/null 2>/dev/null &
		fi

		#ikwecom
		if [ -e "/tmp/iktmp/cache/wecom/is_bind" ] && ! __get_process_status ik_wecom ;then
			__cgroup_exec_safe_bg /usr/sbin/ik_wecom &
		fi

		#hostapd
#		if [ -e /tmp/iktmp/hostapd.status ]&& ! __get_process_status hostapd;then
#			cmd=$(cat /tmp/iktmp/hostapd.status)
#			$cmd >/dev/null 2>/dev/null &
#		fi

		#ik_wpa_ppsk
		if [ -e /tmp/iktmp/ik_wpa_ppsk.status ]&& ! __get_process_status ik_wpa_ppsk;then
			local rk_seed=$(sqlite3 $IK_DB_CONFIG "select rk_seed from ac_randkey limit 1")
			local rk_timeout=$(sqlite3 $IK_DB_CONFIG "select rk_timeout from ac_randkey limit 1")
			__cgroup_exec_safe /usr/sbin/ik_wpa_ppsk -r -s /tmp/iktmp/ik_wpa_ppsk.ssid -S $rk_seed -t $rk_timeout
			Syslog $(Iecho i18n_sys_event_ik_wpa_ppsk)
		fi

		if [ -e /tmp/iktmp/cache/snmp_ipauth/is_enabled ] && ! __get_process_status ik_switch_arp ;then
			__cgroup_exec_safe_bg /usr/bin/ik_switch_arp >/dev/null 2>&1
			Syslog $(Iecho i18n_sys_event_ik_switch_arp)
		fi

		if [ -e /tmp/iktmp/upnpd_enabled ] && ! __get_process_status miniupnpd ;then
			__cgroup_exec_safe_bg /usr/sbin/miniupnpd -f /tmp/iktmp/miniupnpd.conf >/dev/null 2>&1
		fi

		if [ -e /tmp/iktmp/cache/ik_webauth_roaming/is_enabled ] && ! __get_process_status ik_webauth_server ;then
			local $(cat /tmp/iktmp/cache/ik_webauth_roaming/config)
			__cgroup_exec_safe_bg /usr/bin/ik_webauth_server -r $roaming_ip -p $roaming_port >/dev/null 2>&1
		fi

		#ik_audit,3th verison
		if [ -e /tmp/iktmp/ik_audit_client.status ]; then
			if ! __get_process_status ik_audit_publisher || ! __get_process_status ik_audit_client ; then
				killall ik_audit_publisher 2>/dev/null
				killall ik_audit_client 2>/dev/null
				__exec_safe_bg /usr/bin/ik_audit_publisher >/dev/null 2>/dev/null &
				sleep 1
				__exec_safe_bg /usr/bin/ik_audit_client -l 0 >/dev/null 2>/dev/null &
				Syslog $(Iecho i18n_sys_event_ik_audit_publisher)
				Syslog $(Iecho i18n_sys_event_ik_audit)
			fi

			if ! pidof ikaudit_update.sh  >/dev/null;then
				rm -f /tmp/ikaudit_update.lock 2>/dev/null
				if __is_safe_executable /usr/ikuai/script/ikaudit_update.sh; then
					start-stop-daemon -S -x /usr/ikuai/script/ikaudit_update.sh -b >/dev/null 2>&1
				fi
			fi
		fi

		if [ "$SUPPORT_LCD" ] && ! __get_process_status lcd.sh ;then
			__exec_safe_bg /usr/ikuai/script/lcd.sh >/dev/null 2>&1 &
		fi

		## pacakge manager daemon
		if [ "$(cat /etc/mnt/ikuai/ctpanel_cloud_remote.conf 2>/dev/null)" != "RCSTATUS=on" ]; then
			killall -q pmd >/dev/null 2>&1 || true
		elif ! __get_process_status pmd ;then
			__cgroup_exec_safe_bg /tmp/ikpkg/pmd/pmd >/dev/null 2>/dev/null
		fi

		## 2nd remote control client
		if [ "$(cat /etc/mnt/ikuai/ctpanel_cloud_remote.conf 2>/dev/null)" != "RCSTATUS=on" ]; then
			killall -q ik_rc_client >/dev/null 2>&1 || true
		elif ! __get_process_status ik_rc_client ;then
			if __is_regular_file /usr/sbin/ik_rc_client; then
				chmod 755 /usr/sbin/ik_rc_client 2>/dev/null
				__cgroup_exec_safe_bg /usr/sbin/ik_rc_client >/dev/null 2>/dev/null
			fi
#			Syslog $(Iecho i18n_sys_event_ik_remote_ikuai)
		fi

		## collect report engine daemon
		if [ "$(cat /etc/mnt/ikuai/ctpanel_cloud_remote.conf 2>/dev/null)" != "RCSTATUS=on" ]; then
			killall -q cre >/dev/null 2>&1 || true
		elif ! __get_process_status cre ;then
			__cgroup_exec_safe_bg /tmp/ikpkg/cre/cre >/dev/null 2>/dev/null
			Syslog $(Iecho i18n_sys_event_ik_route_collect)
		fi

		## cre client for ome
#		if [ "$OEM_CRE_MONITOR" ];then
#			if ! __get_process_status cre_client ;then
#				cgroup_exec cre_client start  >/dev/null 2>/dev/null &
#			fi
#		fi

		## get_hosts
		if [ -z "$OEMNAME" -o "$OEMNAME" = "oem" ]; then
			if ! __get_process_status get_hosts.sh ;then
				__cgroup_exec_safe_bg /usr/ikuai/script/utils/get_hosts.sh boot \
					>/dev/null 2>/dev/null
			fi
		fi

		### test code
		#if __get_process_status qemu-system-x86_64 || __get_process_status containerd || [ -e "/etc/disk_notify/youyu" ] ; then
		#	__memory_balloon
		#fi

		#qemu
		__get_qemu_status

		using_hosts_update_process
#		__monitor_cache_service  /tmp/monitor_cache
#		__monitor_cache_service  /tmp/monitor_dtalk_cache
		__check_acpi_interrupts
		__check_tso_align

		[ -e /var/log/iksyslog.log ]&&[ "` wc -l  /var/log/iksyslog.log |cut -d " " -f1`" -gt 2000 ] && cp /var/log/iksyslog.log /var/log/iksyslog.log.1 && echo > /var/log/iksyslog.log

		$UNLOCK
		sleep 30
	done
}

 __get_qemu_status(){
	filedir="/tmp/iktmp/qemu"
	for index in $(ls $filedir);
	do
		if [ -e "$filedir/$index/name" ] ;then
			local pid=$(cat $filedir/$index/pid)
			local temp=$(ps -w | awk '$1 == "'$pid'" && $5~/^qemu-system+/{print $1}')
			if [ -z $temp ];then
				__exec_safe_bg /usr/ikuai/script/qemu.sh up id=$index >/dev/null 2>/dev/null &
			fi
		fi
	done
}

__monitor_cache_service ()
{
	local monitored_serv=$1
	__is_safe_executable "$monitored_serv" || return

	if pidof nginx ;then
		local master_pid=`cat /var/run/nginx.pid 2>/dev/null`
		local master_exist=""
		[ -n "${master_pid}" ] && master_exist=$(pidof nginx | grep "${master_pid}" )
		if [ -z "${master_exist}" ] ;then
			## master process lost,then must firstly kill all nginx child process
			kill -9 `pidof nginx`
			local n=10
			while [ "$((n--))" -gt 0 ] && pidof nginx;do
				sleep 1
			done
		else
			## all nginx process are active
			return
		fi
	fi

	__exec_safe_bg "$monitored_serv" start 2>/dev/null >/dev/null &
	Syslog $(Iecho i18n_sys_event_ik_cache_servcie)
}
