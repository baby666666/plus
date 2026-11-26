#!/bin/bash /etc/ikcommon
Include json.sh sqlite.sh timersql.sh sys/sysstat.sh

time_now=$(date +"%F %T")
timestamp=`date +"%s" `
date=${time_now// */}

gwid=$GWID

get_config() {
	#需要收集的路由信息 要执行的具体指令
	#信息上报周期
	echo '{
		"collect_info":[
			{"info_name":"brief/router", "cmd":"get_sys_info"},
			{"info_name":"brief/ap", "cmd":"get_ap_info"},
			{"info_name":"client", "cmd":"get_client_status"}],
		"report_interval":5,
		"sdomain":[{"domain":"coll.ikuai8.com","port":2016},
			{"domain":"59.110.6.135","port":2016}]
	}'
}

get_sys_info() {
	firmware=$FIRMWARENAME
	hostname=$(hostname)

	#当前在线终端
	###排除掉ap的个数
	local $(iktimerc ".load_hosts; select count() as total from online_user")
	terminal=$total
	#在线时长
	runtime=$(awk -F '[\.| ]' '{print $1}' /proc/uptime)
	runtime=${runtime:-0}
	#获取特征库版本
	protocol_version=$(awk -F= '$1=="Version"{print $2;exit}' /usr/libproto/protocols )

	#内存使用率
	sysstat_get_mem
	local memtotal="${SYSSTAT_MEM[MemTotal]}"
	local memavailable="${SYSSTAT_MEM[MemAvailable]}"
	memrate="$(( (memtotal - memavailable) * 100 /memtotal ))"

	#cpu使用率
	cpurate_per=$(awk '{print $2;exit}' /tmp/iktmp/monitor-ikstat/cpu)
	cpurate=${cpurate_per%?}
	#统计状态
	local $(sql_config_get_list $IK_DB_COLLECTION "select * from every_day_stats")
	#语言，上网模式
	local $(sql_config_get_list $IK_DB_CONFIG "select switch_nat as net_mode,language from basic")
	#web认证开关
	auth_status=0
	if [ -e "/tmp/iktmp/webauth/auth_switch" ];then
		auth_status=1
	fi

#	auth_state=$(sqlite3 $IK_AC_PSK_DB "select enabled from ac_wechat_auth")
#	if [ "$auth_state" = "yes" ];then
#		auth_status=1
#	fi

	#上下行流量
	local $(awk '$1=="Total"{printf "upload=%.f download=%.f\n",$3,$4}' /proc/ikuai/stats/ik_proto_stats) >/dev/null 2>/dev/null
	#AP数量
	ap_num="$(wum -c wtps 2>/dev/null |wc -l)"
	system_version="${VERSTRING}"
	js_count=${js_inform:-0}
	
	#客户端系统类型统计
	local $(client_type_statistics) >/dev/null 2>/dev/null

	##交换机在线数量统计
	local switch_onlie=0 switch_total=0
	local cloud_filelist=$(find /tmp/iktmp/cache/cloud_switch/ -name "[0-9]*" -type d)	
	for fileone in ${cloud_filelist}; do
		((switch_total++))
		local res=$(cat $fileone/status 2>/dev/null)
		## 1:代表snmp和ping都通  2: 代表ping通
		[ "$res" = "1" -o "$res" = "2" ] && ((switch_online++))
	done 
	
	#物联管理上报
	local dev_control_total=0 dev_control_online=0
	for tmpfile in $(ls /tmp/iktmp/cache/dev_control/status.*); do
		((dev_control_total++))
		local res=$(cat $tmpfile 2>/dev/null)
		[ "$res" = "1" ] && ((dev_control_online++))
	done

	#检查是否可自动升级
	#TODO:/tmp/patch/firmware 不存在
	#upgrade="$(ls /tmp/patch/firmware)"
	upgrade=""
	wifi=${wifi:-0}
	protocol=$(get_app_status)
	today_top10_app=$(get_app_top10)
	js_stats=$(get_jsinform_info)
	today_client_linux=0

	sysstat_get_stream
	connect_num=${SYSSTAT_STREAM[conn_num]}
	day_auths=0

	json_output upgrade:str today_client_other:int today_client_mac:int today_client_windows:int today_client_android:int today_client_ios:int today_client_linux:int protocol_version:str system_version:str gwid:str cpurate:str memrate:str wifi:int js_count:int upload:int download:int terminal:int runtime:int auth_status:int ap_num:int firmware:str protocol:json today_top10_app:json js_stats:json mac:str ssid1:str ssid2:str bssid1:str bssid2:str ssid1_5g:str ssid2_5g:str bssid1_5g:str bssid2_5g:str timestamp:int connect_num:int day_auths:int switch_online:int switch_total:int dev_control_total:int dev_control_online:int
}

client_type_statistics() {
	#客户端系统类型统计
	if [ -e /etc/log/client_type/clean_time ];then
		awk -v ios=0 -v windows=0 -v android=0 -v mac=0 -v other=0 '{
			IGNORECASE=1
			if($0~/^android/){android+=1}
			else if($0~/^windows/){windows+=1}
			else if($0~/^mac/){mac+=1}
			else if($0~/^ios/){ios+=1}
			else {other+=1} 
		}END{
			printf "today_client_android=%s today_client_windows=%s today_client_ios=%s today_client_mac=%s today_client_other=%s" ,android,windows,ios,mac,other
		}' /etc/log/client_type/* || \
		echo today_client_ios=0 today_client_windows=0 today_client_android=0  today_client_mac=0 today_client_other=0
	else
		echo today_client_ios=0 today_client_windows=0 today_client_android=0  today_client_mac=0 today_client_other=0
	fi
}
get_jsinform_info() {
	local data
#	local sql_show="select id,count from js_inform2"
#	data="$(sql_config_get_json $IK_DB_CONFIG "$sql_show")"
	echo "[$data]"
}

get_ap_info() {
#ip, on_channel, on_channel_5g, upload, download, online--terminal, bssid,online_5g,
	data=$($IK_DIR_SCRIPT/ac_server.sh show TYPE=all)
	echo "$data" | jq --arg gwid ${GWID} --arg timestamp ${timestamp} '[.data[] + {"gwid":$gwid, "timestamp":$timestamp|tonumber, "password":""}]'
}

get_app_status() {
	local now_timestamp=$(date +%s)
	time_red_30m=$((now_timestamp-30*60))
	echo -n "{"
	sqlite3 /etc/log/collection.db "select sum(HTTP) HTTP,sum(Download) Download,sum(Transport) Transport,sum(IM) IM,sum(Video)  Video,sum(Common) Common,sum(Game) Game,sum(Others) Others,sum(Test) Test,sum(Unknown) Unknown,sum(HTTP + Download + Transport + IM + Video + Common + Game + Others + Test + Unknown) as total from app_flow where timestamp>='$time_red_30m' "   -line |\
	awk '{if(NR>1)printf ",";if(NF<3)$3=0;printf "\x22%s\x22:%s",$1,$3}'
	echo -n "}"
}

get_app_top10() {
	date=$(date +"%F")
	filename="/tmp/iktmp/active_apps/"${date}
	if [ -f $filename ];then
		top10_app=$(cat ${filename} | awk '{if(NR<=10)printf "\x22%s\x22:\x22%s\x22,",$1,$2}')
		top10_app=${top10_app%*,}
	fi
	echo "{${top10_app}}"
}

get_remote_host() {
	echo '[{"domain":"coll.ikuai8.com","port":2016}]'

}

get_client_status() {
	declare -A APP_TOP
	declare -A OLD_MAC

	while read mac; do
		[ "$mac" ] || continue
		OLD_MAC[$mac]=1	
	done < /tmp/iktmp/active_mac/$date

	cp /proc/ikuai/stats/host_active_apps /tmp/.host_active_apps.$$
	while read ipaddress appids; do
		[ "$ipaddress" -a "$appids" ] || continue
		APP_TOP[${ipaddress//:/}]=$appids
	done < /tmp/.host_active_apps.$$
	rm -f /tmp/.host_active_apps.$$

	local tmpfile=$(iktimerc ".load_hosts; select * from online_user")

	local json_data json_result

	while read config; do
		[ "$config" ] || continue
		local $config >/dev/null 2>&1

		if [ "${OLD_MAC[$mac]}" = "1" ]; then
			local old_mac=1
		fi
		local apptop="[${APP_TOP[$ip_addr]}]"
		local ip=$ip_addr
		local logtime=$timestamp
		local timestamp=$(date +%s)
		local online_time=$((timestamp-logtime))
		json_data=$(json_output old_mac:int gwid:str hostname:str apptop:json apmac:str apname:str ssid:str bssid:str ip:str mac:str connect_num:int upload:int download:int total_up:int total_down:int auth_type:str logtime:int online_time:int timestamp:int comment:str signal:str client_type:str client_device:str)
		json_result+="${json_result:+,}$json_data"
	done <<EOF
	$tmpfile
EOF
	echo "[$json_result]"
	active_mac
}

active_mac() {
	if [ ! -e /tmp/iktmp/active_mac/$date ];then
		rm -f /tmp/iktmp/active_mac/*
	fi
	(
		awk '{print $2}' /proc/ikuai/stats/host_stats
		if [ -f "/tmp/iktmp/cache/snmp_ipauth/is_enabled" ]; then
			awk '{print $1}' /tmp/iktmp/cache/snmp_ipauth/arp
		fi
		cat /tmp/iktmp/active_mac/$date
	)|sort|uniq > /tmp/iktmp/active_mac/$date
}
