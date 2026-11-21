#!/bin/bash /etc/ikcommon
Include interface.sh
I18nload syscheck.json  

IKSYSCHECK_DIR="/tmp/iktmp/iksyscheck"
IKSYSCHECK_LOG="/etc/log/iksyscheck"
IKCLOUD_SERVICE_URL="http://youyu.api.ikuai8.com/business-api/ik_business_status_for_router.php"

boot() {
	init
}

init() {
	mkdir -p $IKSYSCHECK_DIR
	mkdir -p $IKSYSCHECK_LOG
	touch $IKSYSCHECK_DIR/{disk,disk.status}
	touch $IKSYSCHECK_DIR/{memory,memory.status}
	touch $IKSYSCHECK_DIR/{internet,internet.status}
	touch $IKSYSCHECK_DIR/{dhcp_discover,dhcp_discover.status}
	touch $IKSYSCHECK_DIR/{pppoe_discover,pppoe_discover.status}
	touch $IKSYSCHECK_DIR/{arp,arp.status}
	touch $IKSYSCHECK_DIR/{cloud_link,cloud_link.status}
}

__get_elapsed_time() {
	echo "$1" |awk '$0~/time = /{for(i=1;i<=NF;i++)if($i=="time" && $(i+1)=="="){print $(i+2);exit}}'
}

__disk_status() {
	disk=$(df |awk '{if($NF=="/etc/mnt" || $NF=="/etc/log"){print substr($1,0,8);exit} }')

	if [ -n "$disk" ];then
		if ! fdisk -l |grep -q $disk ;then
			echo "disk_lost=1"
			return
		fi
	else
		echo "disk_not_found=1"
		return
	fi
}

__disk_used_info() {
	df |awk '
	function unit_conver(x) {
		if(x>=PB)x=sprintf("%.1fPB",x/PB)
		else if(x>=TB)x=sprintf("%.1fTB",x/TB)
		else if(x>=GB)x=sprintf("%.1fGB",x/GB)
		else if(x>=MB)x=sprintf("%.1fMB",x/MB)
		else x=x"KB"
		return x
	}
	BEGIN {
		while(getline<"/proc/mounts" ){
			mount[$1]=$2
			type[$1]=$3
			rw[$1]=substr($4,0,2)
		}
		MB=1024
		GB=1024*1024
		TB=1024*1024*1024
		PB=1024*1024*1024*1024
	}
	{
		if($NF=="/etc/log" || $NF=="/etc/mnt"){
			if($NF=="/etc/log")logpart=1
			if($NF=="/etc/mnt")confpart=1
			total=unit_conver($2)
			use=unit_conver($3)
			free=unit_conver($2-$3)

			printf "disk_used=1 confpart=%s  total=%-8s used=%-8s free=%-8s userate=%-5s\n",$1,total,use,free,$5
			if(rw[$1]=="ro") {
				printf "disk_mode_ro=1 diskname=%s\n",$1
			}
		}
	} END {
		if(!confpart){
			printf "disk_confparts_not_found=1\n"
		}
		if(!logpart){
			printf "disk_logparts_not_found=1\n"
		}
	}'
}

__check_disk() {
	Iecho i18n_syscheck_check_disk
	status=$(__disk_status)
	if [ -n "$status"];then
		local $status

		if [ "$disk_lost" = "1" ];then
			Iecho i18n_syscheck_disk_lost_exception
		fi
		if [ "$disk_not_found" = "1" ]; then
			Iecho i18n_syscheck_disk_not_found
		fi
	fi
	__disk_used_info | while read config; do
		if [ -n "$config" ];then
			local $config
			if [ "$disk_used" = "1" ];then
				Iecho i18n_syscheck_disk_used "$confpart" "$total" "$used" "$free" "$userate"
			fi		
			if [ "$disk_mode_ro" = "1" ];then
				Iecho i18n_syscheck_disk_mode_ro_exception "$diskname"
			fi
			if [ "$disk_confparts_not_found" = "1" ];then
				Iecho i18n_syscheck_disk_confparts_not_found
			fi
			if [ "$disk_logparts_not_found" = "1" ];then
				Iecho i18n_syscheck_disk_logparts_not_found
			fi

		fi
	done
}

__memory_used_info() {
	awk -v sysbit=$SYSBIT '
	{
		gsub(/\(.+\)|:/,"")
		name[$1]=$2
	}
	END{
		total  = name["MemTotal"]
		free   = name["MemFree"]
		buffer = name["Buffers"]
		cache  = name["Cached"]
		ioused = name["Buffers"] + name["Cached"]
		available = free + ioused
		used   = total - available
		use    = used/total*100
		printf "memory_used=1 total=%.1fMB used=%.1fMB ioused=%.1fMB free=%.1fMB userate=%.1f%%\n",total/1024,used/1024,ioused/1024,free/1024,use

		if(sysbit=="x64"){
			if(total<1800000) {
				printf "memory_small_64=1\n"
				exit
			}
		} else {
			if(total<400000) {
				printf "memory_small_32=1\n"
				exit
			}
		}

		if(use >= 90){
			printf "memory_used_warning=1\n"
		}
		while("ps"|getline){
			if($3/total*100 >= 10){
				gsub("{","",$5)
				gsub("}","",$5)
				gsub(/.+\//,"",$5)
				printf "memory_suspect_process=1 process_name=%s pid=%s memused=%.fMB\n",$5,$1,$3/1024
			}
		}
	}' /proc/meminfo
}

__check_memory() {
	Iecho i18n_syscheck_check_memory
	__memory_used_info | while read config; do
		if [ -n "$config" ]; then
			local $config
		fi
		if [ "$memory_used" = "1" ];then
			Iecho i18n_syscheck_memory_used "$total" "$used" "$ioused" "$free" "$userate"	
		fi
		if [ "$memory_small_64" = "1" ];then
			Iecho i18n_syscheck_memory_small_64_exception
		fi
		if [ "$memory_small_32" = "1" ];then
			Iecho i18n_syscheck_memory_small_32_exception
		fi
		if [ "$memory_used_warning" = "1" ];then
			Iecho i18n_syscheck_memory_used_warning
		fi
		if [ "$memory_suspect_process" = "1" ];then
			Iecho i18n_syscheck_memory_process_suspect "$process_name" "$pid" "$memused"	
		fi
	done
}

__check_arp() {
	Iecho i18n_syscheck_check_arp
	ip add show up|awk '{gsub("secondary","");gsub(":","",$2);gsub("@.*","",$2);iif[$2]=1; gsub("/.*","",$2);if($0~/global (vlan|lan)/ && iif[$7]==1)print $2,$7}' |while read ip iface ;do
		if status=$(ikcheck arping $ip -I $iface -C -c 3 -t 1 2>/dev/null) ;then
			status=($status)
			illegality_mac=${status[2]}
			Iecho i18n_syscheck_arp_state_exception "$iface" "$ip" "$illegality_mac"
		else
			Iecho i18n_syscheck_arp_state_normal "$iface" "$ip"
		fi
	done
}

__check_internet_http() {
	local host=$1 iface=$2
	if status=$(ikcheck dns $host -d 114.114.114.114 -I $iface) ;then
		dns_time=$(__get_elapsed_time "$status")
	else
		Iecho i18n_syscheck_internet_dns_lookup_err "$iface" "$host"
		return 1
	fi
	
	if status=$(ikcheck http $host -d 114.114.114.114 -I $iface ) ;then
		http_time=$(__get_elapsed_time "$status")
		Iecho i18n_syscheck_internet_access_ok "$iface" "$host" "$dns_time" "$http_time"
	else
		Iecho i18n_syscheck_internet_access_err "$iface" "$host" "$dns_time"
	fi
}

__check_internet() {
	Iecho i18n_syscheck_check_internet
	Iecho i18n_syscheck_intertnet_use_dns

	interface_get_ifname wan,vpn | while read iface ;do
		if interface_check_is_wanpppoe $iface;then
			iface=${iface}_ad
		fi
		__check_internet_http www.qq.com $iface
		__check_internet_http www.baidu.com $iface
	done
}

__check_dhcp_discover() {
	Iecho i18n_syscheck_check_dhcp_discover
	interface_get_ifname lan,vlan |while read iface ;do
		status=$(udhcpc  -i $iface -s /usr/ikuai/script/iksyscheck.sh -t 2 -T 2 -q -n 2>/dev/null)
		status=($(echo "$status"|tail -n 1))
		local ikflags=${status[0]}
		local server_ip=${status[2]}
		local server_mac=${status[3]}
		local netmask=${status[4]}
		local gateway=${status[5]}
		if [ "$ikflags" = "iKuaiCheck:" ];then
			Iecho i18n_syscheck_dhcp_discover_err "$iface" "${server_ip:-0.0.0.0    }" "${server_mac:---}" "${netmask:-0.0.0.0}" "${gateway:-0.0.0.0}"
		else
			Iecho i18n_syscheck_dhcp_discover_ok "$iface"
		fi
	done
}

__check_pppoe_discover() {
	local pppoe_ac_name pppoe_service_name pppoe_server_mac
	Iecho i18n_syscheck_check_pppoe_discover
	interface_get_ifname lan,vlan |while read iface ;do
		if status=$(pppoe-discovery -I $iface 2>/dev/null) ;then
			pppoe_ac_name="" pppoe_service_name="" pppoe_server_mac=""
			local $(echo "$status" |awk '{name[$1]=$2}END{printf "pppoe_ac_name=%s pppoe_service_name=%s pppoe_server_mac=%s",name["Access-Concentrator:"],name["Service-Name:"],name["AC-Ethernet-Address:"]}') >/dev/null 2>/dev/null
			if [ -n "$pppoe_ac_name" ];then
				Iecho i18n_syscheck_pppoe_discover_err "$iface" "$pppoe_ac_name" "$pppoe_service_name" "$pppoe_server_mac"
			else
				Iecho i18n_syscheck_pppoe_discover_ok "$iface"
			fi
		else
			Iecho i18n_syscheck_pppoe_discover_ok "$iface"
		fi
	done
}

__check_cloud_link()
{
	Include json.sh
	$IK_DIR_SCRIPT/register.sh __check_bind >/dev/null 2>&1	
	local register_status=$(cat /tmp/iktmp/register_status)
	if [ "$register_status" = "0" ]; then
		Iecho i18n_syscheck_cloud_link_bind_err
	elif [ "$register_status" = "1" ]; then
		Iecho i18n_syscheck_cloud_link_bind_ok
	elif [ "$register_status" = "2" ]; then
		Iecho i18n_syscheck_cloud_link_connect_err
	fi
	#绑定云账号成功的才去获取增值服务的状态
	[ "$register_status" != "1" ] && return
	if config=$(wget -4 -O- -q -t 1 -T 20 --connect-timeout=20 --dns-timeout=10 "$IKCLOUD_SERVICE_URL?gwid=$GWID" ); then
		json_decode test config
		[ "$test_err" != "0" ] && return
		Iecho i18n_syscheck_cloud_link_bussiness
		if [ "$test_business_status_cloud_back" = "1" ];then
			Iecho i18n_syscheck_cloud_link_bussiness_status_cloud_back "$(Iecho i18n_syscheck_cloud_link_bussiness_status_on)"	
		else
			Iecho i18n_syscheck_cloud_link_bussiness_status_cloud_back "$(Iecho i18n_syscheck_cloud_link_bussiness_status_off)"	
		fi 
		if [ "$test_business_status_speedup" = "1" ];then
			Iecho i18n_syscheck_cloud_link_bussiness_status_speedup "$(Iecho i18n_syscheck_cloud_link_bussiness_status_on)"	
		else
			Iecho i18n_syscheck_cloud_link_bussiness_status_speedup "$(Iecho i18n_syscheck_cloud_link_bussiness_status_off)"	
		fi 
		if [ "$test_business_status_network" = "1" ];then
			Iecho i18n_syscheck_cloud_link_bussiness_status_network "$(Iecho i18n_syscheck_cloud_link_bussiness_status_on)"	
		else
			Iecho i18n_syscheck_cloud_link_bussiness_status_network "$(Iecho i18n_syscheck_cloud_link_bussiness_status_off)"	
		fi 
		if [ "$test_business_status_miner" = "1" ];then
			Iecho i18n_syscheck_cloud_link_bussiness_status_miner "$(Iecho i18n_syscheck_cloud_link_bussiness_status_on)"	
		else
			Iecho i18n_syscheck_cloud_link_bussiness_status_minier "$(Iecho i18n_syscheck_cloud_link_bussiness_status_off)"	
		fi 
		if [ "$test_business_status_star" = "1" ];then
			Iecho i18n_syscheck_cloud_link_bussiness_status_star "$(Iecho i18n_syscheck_cloud_link_bussiness_status_on)"	
		else
			Iecho i18n_syscheck_cloud_link_bussiness_status_star "$(Iecho i18n_syscheck_cloud_link_bussiness_status_off)"	
		fi 
	fi
}

__check_all() {
	cd $IKSYSCHECK_DIR
	__check_disk
	__check_memory
	__check_internet
	__check_dhcp_discover
	__check_arp
	__check_cloud_link
}

bound() {
	#udhcpc
	local servermac res
	if res=$(ikcheck arping $serverid -I $interface -C -c 3 -t 2 ) ;then
		res=($res)
		servermac=${res[2]}
	fi
	echo "iKuaiCheck: $interface $serverid ${servermac:---} $subnet $router"
}

deconfig() {
	#udhcpc
	return 0
}

leasefail() {
	#udhcpc
	return 0
}
nak() {
	#udhcpc bug
	kill -9 $PPID
	local servermac res
	if res=$(ikcheck arping $serverid -I $interface -C -c 3 -t 2 ) ;then
		res=($res)
		servermac=${res[2]}
	fi
	echo "iKuaiCheck: $interface $serverid ${servermac:---} ${subnet:-0.0.0.0} ${router:-0.0.0.0}"
	return 0
}

#获取状态和结果，status = -1未检测,0正在检测,1检测结束
__get_disk() {
	disk_status=$(cat $IKSYSCHECK_DIR/disk.status)
	if [ "$disk_status" = "1" ]; then
		while read config
		do
			if [ -n "$config" ];then
				disk_res+="${disk_res:+,}\"$config\""
			fi
		done < $IKSYSCHECK_DIR/disk
	fi
	disk_res="[$disk_res]"
	disk_status=${disk_status:--1}
}

__get_memory() {
	memory_status=$(cat $IKSYSCHECK_DIR/memory.status)
	if [ "$memory_status" = "1" ]; then
		while read config
		do
			if [ -n "$config" ];then
				memory_res+="${memory_res:+,}\"$config\""
			fi
		done < $IKSYSCHECK_DIR/memory
	fi
	memory_res="[$memory_res]"
	memory_status=${memory_status:--1}
}

__get_internet() {
	internet_status=$(cat $IKSYSCHECK_DIR/internet.status)
	if [ "$internet_status" = "1" ]; then
		while read config
		do
			if [ -n "$config" ];then
				internet_res+="${internet_res:+,}\"$config\""
			fi
		done < $IKSYSCHECK_DIR/internet
	fi
	internet_res="[$internet_res]"
	internet_status=${internet_status:--1}
}

__get_dhcp_discover() {
	dhcp_discover_status=$(cat $IKSYSCHECK_DIR/dhcp_discover.status)
	if [ "$dhcp_discover_status" = "1" ];then
		while read config
		do
			if [ -n "$config" ];then
				dhcp_discover_res+="${dhcp_discover_res:+,}\"$config\""
			fi
		done < $IKSYSCHECK_DIR/dhcp_discover
	fi
	dhcp_discover_res="[$dhcp_discover_res]"
	dhcp_discover_status=${dhcp_discover_status:--1}
}

__get_pppoe_discover() {
	pppoe_discover_status=$(cat $IKSYSCHECK_DIR/pppoe_discover.status)
	if [ "$pppoe_discover_status" = "1" ]; then
		while read config
		do
			if [ -n "$config" ];then
				pppoe_discover_res+="${pppoe_discover_res:+,}\"$config\""
			fi
		done < $IKSYSCHECK_DIR/pppoe_discover
	fi
	pppoe_discover_res="[$pppoe_discover_res]"
	pppoe_discover_status=${pppoe_discover_status:--1}
}


__get_arp() {
	arp_status=$(cat $IKSYSCHECK_DIR/arp.status)
	if [ "$arp_status" = "1" ]; then
		while read config
		do
			if [ -n "$config" ];then
				arp_res+="${arp_res:+,}\"$config\""
			fi
		done < $IKSYSCHECK_DIR/arp
	fi
	arp_res="[$arp_res]"
	arp_status=${arp_status:--1}
}

__get_cloud_link() {
	while read config
	do
		if [ -n "$config" ];then
			cloud_link_res+="${cloud_link_res:+,}\"$config\""
		fi
	done < $IKSYSCHECK_DIR/cloud_link
	cloud_link_res="[$cloud_link_res]"
	cloud_link_status=$(cat $IKSYSCHECK_DIR/cloud_link.status)
	cloud_link_status=${cloud_link_status:--1}
}

show() {
	Show __json_result__
}

__show_data() {
	__get_disk
	__get_memory
	__get_internet
	__get_dhcp_discover
	__get_pppoe_discover
	__get_arp
	__get_cloud_link
	json_append __json_result__ disk_res:json disk_status:str memory_res:json memory_status:str \
				    internet_res:json internet_status:str dhcp_discover_res:json dhcp_discover_status:str \
				    pppoe_discover_res:json pppoe_discover_status:str arp_res:json arp_status:str \
				    cloud_link_res:json cloud_link_status:str
}

__show_disk() {
	__get_disk
	json_append __json_result__ disk_res:json disk_status:str	
	if [ "$disk_status" = "1" ];then
		json_append disk_result disk_res:json disk_status:str	
		echo "$disk_result" > $IKSYSCHECK_LOG/disk
	fi
}

__show_memory() {
	__get_memory
	json_append __json_result__ memory_res:json memory_status:str
	if [ "$memory_status" = "1" ];then
		json_append memory_result memory_res:json memory_status:str
		echo "$memory_result" > $IKSYSCHECK_LOG/memory
	fi
}

__show_internet() {
	__get_internet
	json_append __json_result__ internet_res:json internet_status:str 
	if [ "$internet_status" = "1" ];then
		json_append internet_result internet_res:json internet_status:str 
		echo "$internet_result" > $IKSYSCHECK_LOG/internet
	fi
}

__show_dhcp_discover() {
	__get_dhcp_discover
	json_append __json_result__ dhcp_discover_res:json dhcp_discover_status:str
	if [ "$dhcp_discover_status" = "1" ];then
		json_append dhcp_result dhcp_discover_res:json dhcp_discover_status:str
		echo "$dhcp_result" > $IKSYSCHECK_LOG/dhcp_discover
	fi
}

__show_pppoe_discover() {
	__get_pppoe_discover
	json_append __json_result__ pppoe_discover_res:json pppoe_discover_status:str
	if [ "$pppoe_discover_status" = "1" ];then
		json_append pppoe_result pppoe_discover_res:json pppoe_discover_status:str
		echo "$pppoe_result" > $IKSYSCHECK_LOG/pppoe_discover	
	fi
}

__show_arp() {
	__get_arp
	json_append __json_result__ arp_res:json arp_status:str
	if [ "$arp_status" = "1" ];then
		json_append arp_result arp_res:json arp_status:str
		echo "$arp_result" > $IKSYSCHECK_LOG/arp
	fi
}

__show_cloud_link() {
	__get_cloud_link
	json_append __json_result__ cloud_link_res:json cloud_link_status:str
	if [ "$cloud_link_status" = "1" ];then
		json_append cloud_result cloud_link_res:json cloud_link_status:str
		echo "$cloud_result" > $IKSYSCHECK_LOG/cloud_link
	fi
}


__show_recent_data()
{
	local recent_data
	cd $IKSYSCHECK_LOG
	for file in $(ls $IKSYSCHECK_LOG); do
		recent_data="${recent_data:+${recent_data},}$(cat $file)"
	done
	recent_data="[$recent_data]"
	json_append __json_result__ recent_data:json
}

start_disk() {
	cd $IKSYSCHECK_DIR
	echo 0 > disk.status
	__check_disk > disk
	echo 1 > disk.status
}
start_memory() {
	cd $IKSYSCHECK_DIR
	echo 0 > memory.status
	__check_memory > memory
	echo 1 > memory.status
}
start_internet() {
	cd $IKSYSCHECK_DIR
	echo 0 > internet.status
	__check_internet > internet
	echo 1 > internet.status
}
start_dhcp_discover() {
	cd $IKSYSCHECK_DIR
	echo 0 > dhcp_discover.status
	__check_dhcp_discover > dhcp_discover
	echo 1 > dhcp_discover.status
}
start_pppoe_discover() {
	cd $IKSYSCHECK_DIR
	echo 0 > pppoe_discover.status
	__check_pppoe_discover > pppoe_discover
	echo 1 > pppoe_discover.status
}
start_arp() {
	cd $IKSYSCHECK_DIR
	echo 0 > arp.status
	__check_arp > arp
	echo 1 > arp.status
}

start_cloud_link() {
	cd $IKSYSCHECK_DIR
	echo 0 > cloud_link.status
	__check_cloud_link > cloud_link
	echo 1 > cloud_link.status
}

__start() {
	cd $IKSYSCHECK_DIR

	if [ -e /var/run/iksyscheck.pid ];then
		return
	fi

	echo $$ >/var/run/iksyscheck.pid
	if [ "$type" = "" -o "$type" = "all" ];then
		start_disk
		start_memory
		start_internet
		start_dhcp_discover
		start_pppoe_discover
		start_arp
		start_cloud_link
	else
		for i in ${type//,/ };do
			case $i in
				disk) start_disk ;;
				memory) start_memory ;;
				internet) start_internet ;;
				dhcp_discover) start_dhcp_discover ;;
				pppoe_discover) start_pppoe_discover ;;
				arp) start_arp ;;
				cloud_link) start_cloud_link ;;
			esac
		done
	fi
	rm -f /var/run/iksyscheck.pid
}

start() {
	__start >/dev/null 2>&1 &
}

stop() {
	ps | awk '{if ($5=="{iksyscheck}"&&$9=="start"){system("kill "$1)}}'
	rm -f /var/run/iksyscheck.pid
	for file in $(ls /tmp/iktmp/iksyscheck/*.status) ;do
		echo -1 >$file
	done
}

restart() {
	stop
	start
}

