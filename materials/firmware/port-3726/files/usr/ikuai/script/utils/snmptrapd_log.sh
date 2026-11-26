#!/bin/bash /etc/ikcommon
Include sys/sysstat.sh

read host
read ip

##告警关键字，和warning表一致
##端口状态告警 | 端口速率超门限告警 | 端口无流量告警 | 端口丢包率高告警 | 端口双工变化告警 | 端口环路告警
declare -A switch_event=(
	["switch_port_status"]="switch_port_status"
	["switch_port_rate"]="switch_port_rate"
	["switch_port_no_flow"]="switch_port_no_flow"
	["switch_port_high_packet_loss_rate"]="switch_port_high_packet_loss_rate"
	["switch_port_duplex_mode"]="switch_port_duplex_mode"
	["switch_loop"]="switch_loop"
)

##3.交换机trap的时间，4.日志类型，5.告警内容
trap_point=(
	[3]="switch_time"
	[4]="log_type"
	[5]="warning"
)

##设备ip 设备型号 路由时间 告警描述 事件 事件类型
declare -A convert_point=(
	["device_name"]="device_name"
	["router_time"]="router_time"
	["desc"]="desc"
	["event"]="event"
	["type"]="type"
)


#三层设备型号IK-J7052的公共oid节点和二层设备相同
declare -A info_${switch_event["switch_port_status"]}
eval info_${switch_event["switch_port_status"]}[IK-J7052]=".1.3.6.1.2.1.2.2.1.2.0"
eval info_${switch_event["switch_port_status"]}[IK-J7028E]=".1.3.6.1.2.1.2.2.1.2.0"
eval info_${switch_event["switch_port_status"]}[3ndlevel]=".1.3.6.1.2.1.2.2.1.2.0"
eval info_${switch_event["switch_port_status"]}[2ndlevel]=".1.3.6.1.2.1.2.2.1.2.0"
eval info_${switch_event["switch_port_status"]}[desc]="端口状态变化告警" ##在原来5个的基础上新增
eval info_${switch_event["switch_port_status"]}[key]="switch_port_status"
eval info_${switch_event["switch_port_status"]}[wildcard]="abnormal' 'port"
eval info_${switch_event["switch_port_status"]}[start]="Interface"
eval info_${switch_event["switch_port_status"]}[end1]="link' 'up"
eval info_${switch_event["switch_port_status"]}[end2]="link' 'down"

#三层设备型号IK-J7052的私有oid节点和二层设备不同，下同
declare -A info_${switch_event["switch_port_rate"]}
eval info_${switch_event["switch_port_rate"]}[IK-J7052]=".1.3.6.1.4.1.27282.1.3.2.1.5.5"
eval info_${switch_event["switch_port_rate"]}[IK-J7028E]=".1.3.6.1.4.1.27282.1.3.2.1.5.5"
eval info_${switch_event["switch_port_rate"]}[3ndlevel]=".1.3.6.1.4.1.27282.1.3.2.1.5.5"
eval info_${switch_event["switch_port_rate"]}[2ndlevel]=".1.3.6.1.4.1.27282.1.1.2.1.5.5"
eval info_${switch_event["switch_port_rate"]}[desc]="端口速率超门限告警"
eval info_${switch_event["switch_port_rate"]}[key]="switch_port_rate"
eval info_${switch_event["switch_port_rate"]}[wildcard]="port' 'traffic' 'alarm"
eval info_${switch_event["switch_port_rate"]}[start]="port"
eval info_${switch_event["switch_port_rate"]}[end1]="is' 'busy,' 'port' 'traffic' 'more' 'than' 'threshold"

declare -A info_${switch_event["switch_port_no_flow"]}
eval info_${switch_event["switch_port_no_flow"]}[IK-J7052]=".1.3.6.1.4.1.27282.1.3.2.1.5.4"
eval info_${switch_event["switch_port_no_flow"]}[IK-J7028E]=".1.3.6.1.4.1.27282.1.3.2.1.5.4"
eval info_${switch_event["switch_port_no_flow"]}[3ndlevel]=".1.3.6.1.4.1.27282.1.3.2.1.5.4"
eval info_${switch_event["switch_port_no_flow"]}[2ndlevel]=".1.3.6.1.4.1.27282.1.1.2.1.5.4"
eval info_${switch_event["switch_port_no_flow"]}[desc]="端口无流量告警"
eval info_${switch_event["switch_port_no_flow"]}[key]="switch_port_no_flow"
eval info_${switch_event["switch_port_no_flow"]}[wildcard]="Port' 'traffic' 'is' 'zero' 'alarm"
eval info_${switch_event["switch_port_no_flow"]}[start]="port"
eval info_${switch_event["switch_port_no_flow"]}[end1]="traffic' 'is' 'zero"

declare -A info_${switch_event["switch_port_high_packet_loss_rate"]}
eval info_${switch_event["switch_port_high_packet_loss_rate"]}[IK-J7052]=".1.3.6.1.4.1.27282.1.3.2.1.5.6"
eval info_${switch_event["switch_port_high_packet_loss_rate"]}[IK-J7028E]=".1.3.6.1.4.1.27282.1.3.2.1.5.6"
eval info_${switch_event["switch_port_high_packet_loss_rate"]}[3ndlevel]=".1.3.6.1.4.1.27282.1.3.2.1.5.6"
eval info_${switch_event["switch_port_high_packet_loss_rate"]}[2ndlevel]=".1.3.6.1.4.1.27282.1.1.2.1.5.6"
eval info_${switch_event["switch_port_high_packet_loss_rate"]}[desc]="端口丢包率高告警"
eval info_${switch_event["switch_port_high_packet_loss_rate"]}[key]="switch_port_high_packet_loss_rate"
eval info_${switch_event["switch_port_high_packet_loss_rate"]}[wildcard]="port' 'discarded' 'packets' 'alarm"
eval info_${switch_event["switch_port_high_packet_loss_rate"]}[start]="port"
eval info_${switch_event["switch_port_high_packet_loss_rate"]}[end1]="discarded' 'packets' 'more' 'than' 'threshold"

declare -A info_${switch_event["switch_port_duplex_mode"]}
eval info_${switch_event["switch_port_duplex_mode"]}[IK-J7052]=".1.3.6.1.4.1.27282.1.3.2.1.5.3"
eval info_${switch_event["switch_port_duplex_mode"]}[IK-J7028E]=".1.3.6.1.4.1.27282.1.3.2.1.5.3"
eval info_${switch_event["switch_port_duplex_mode"]}[3ndlevel]=".1.3.6.1.4.1.27282.1.3.2.1.5.3"
eval info_${switch_event["switch_port_duplex_mode"]}[2ndlevel]=".1.3.6.1.4.1.27282.1.1.2.1.5.3"
eval info_${switch_event["switch_port_duplex_mode"]}[desc]="端口双工变化告警"
eval info_${switch_event["switch_port_duplex_mode"]}[key]="switch_port_duplex_mode"
eval info_${switch_event["switch_port_duplex_mode"]}[wildcard]="port' 'duplex' 'alarm"
eval info_${switch_event["switch_port_duplex_mode"]}[start]="port"
eval info_${switch_event["switch_port_duplex_mode"]}[end1]="duplex' 'Half' 'changed' 'to' 'duplex' 'Full"
eval info_${switch_event["switch_port_duplex_mode"]}[end2]="duplex' 'Full' 'changed' 'to' 'duplex' 'Half"


declare -A info_${switch_event["switch_loop"]}
eval info_${switch_event["switch_loop"]}[IK-J7052]=".1.3.6.1.4.1.27282.1.3.2.1.5.7"
eval info_${switch_event["switch_loop"]}[IK-J7028E]=".1.3.6.1.4.1.27282.1.3.2.1.5.7"
eval info_${switch_event["switch_loop"]}[3ndlevel]=".1.3.6.1.4.1.27282.1.3.2.1.5.7"
eval info_${switch_event["switch_loop"]}[2ndlevel]=".1.3.6.1.4.1.27282.1.1.2.1.5.7"
eval info_${switch_event["switch_loop"]}[desc]="端口环路告警"
eval info_${switch_event["switch_loop"]}[key]="switch_loop"
eval info_${switch_event["switch_loop"]}[wildcard]="Port' 'loopback' 'change' 'alarm"
eval info_${switch_event["switch_loop"]}[start]="port"
eval info_${switch_event["switch_loop"]}[end1]="change' 'to' 'Blocking"
eval info_${switch_event["switch_loop"]}[end2]="change' 'to' 'Forwarding"

skip=0
router_time=$(date +"%Y%m%d%H%M%S") ##路由时间

device_name=""	##设备型号
desc=""		##告警描述
log_type=""
data_json=""	##最终向页面调用的json数据

ip=$(echo $ip| awk -F] '{print $1}')
ipaddress=${ip//*[/}
ip=${ipaddress//\./_}

## 恢复原来记录日志的操作，测试版发现问题增补三期以前的实现
## 云平台三期原方案为直接将要加的内容直接推送给云平台，路由器不再缓存
## 测试版发布后发现又确定为原来有的让然不变，所以将原来的实现，移植回只推送到云平台的版本
## 使推送到云平台和原有的功能兼备

time=$(date +%s)
func=
event=
log_type_old=0 ##云平台三期占用了原来的变量名，把原来的变量名调整加后缀

output_test_log()
{
	##echo $1 >> /tmp/log/snmptrap.test.log
	return
}

output_data_json_log()
{
	##echo "{$data_json}"  >> /tmp/log/snmptrap.test.log
	return
}


get_interface_status()
{
        ## eval start='$'"{info_${i}[start]}"
        ## eval end1='$'"{info_${i}[end1]}"
        ## eval end2='$'"{info_${i}[end2]}"
        ## interface=${1#${start}}
        ## interface=${interface%${end1}}
        ## interface=${interface%${end2}}

        local tmp
        status=2
        eval start='$'"{info_${i}[start]}"
        eval end1='$'"{info_${i}[end1]}"
        eval end2='$'"{info_${i}[end2]}"

	interface=${1//\"/} ##去掉两端无用引号
        interface=${interface#${start}}

        ##每次截断之前记录字符串，计算长度，变短，则说明发生了截断，是该匹配项对应的状态
        tmp=${interface}
        interface=${interface%${end1}}
        if [[ ${#tmp} -gt ${#interface} ]]; then
                status=1 ##端口对应up，其他状态对应发生
        fi

        tmp=${interface}
        interface=${interface%${end2}}
        if [[ ${#tmp} -gt ${#interface} ]]; then
                status=0 ##端口起停对应down，其他状态对应消除，没有该状态的不会进入该分支
        fi
        echo ${interface// /}
        echo ${status}

	Append data_json  "," "\"interface\":\"${interface// /}\""
        Append data_json  "," "\"status\":\"${status}\""
}

check_device_ikuai()
{
	while read config; do
		local $config
		output_test_log "$ip_addr = $ipaddress"
		if [ "$ip_addr" = "$ipaddress" -a "${device:0:3}" = "IK-" ]; then
			Append data_json  "," "\"ip_addr\":\"${ip_addr}\""
			Append data_json  "," "\"mac\":\"${mac}\""
			device_name=${device} ##后续用设备型号确定oid节点分类取值，json和后续统一
			return 0
		fi	
	done < /tmp/iktmp/cache/cloud_switch/config
	return 1
}

send_warning()
{
	md5_value=$(echo -n "key=ikuai_alerm_2016&event_id=$1" | md5sum | cut -d ' ' -f1)
        post_string="warning_info={\"event_id\":$1,\"gwid\":\"$GWID\",\"sign\":\"$md5_value\",\"warning\":${3:-'{}'} }"
	if [ -n "$2" ];then
		wget -4 -O- -q -t 3 -T 30 --connect-timeout=30 --dns-timeout=20 $2 --post-data="$post_string"
		output_test_log  " wget -4 -O- -q -t 3 -T 30 --connect-timeout=30 --dns-timeout=20 $2 --post-data=\"$post_string\" "
	fi
}

send_message()
{
	local $(cat /tmp/iktmp/cache/cloud_switch/warning_${1} 2>/dev/null)
	set_convert_point
	if [ -n "$data_json" -a -n "$id" -a -n "$url" ];then
		send_warning $id $url "{$data_json}"
		output_data_json_log
	fi
	output_test_log "url:$url"
}

set_convert_point()
{
	for i in ${convert_point[@]}; do
		##取本地需要的变量数据，插入到上报的json
		local key = "", value = ""
		key=${i}
		eval value='$'"${i}"
		if [[ "event" == "${key}" ]]; then
			value=${value^^} ##json数据中事件要求为大写
		fi
		output_test_log value:$value
		Append data_json  "," "\"${key}\":\"${value}\""
	done
}

if  ! check_device_ikuai >/dev/null 2>&1; then 
	exit 0
fi

##恢复原来记录日志的操作，测试版发现问题增补三期以前的实现
log_reciev_snmp_trapd()
{
	if [[ "$oid" = ".1.3.6.1.6.3.1.1.4.1.0"
	&& ( "$val" = ".1.3.6.1.4.1.27282.1.1.2.1.4.4" || "$val" = ".1.3.6.1.4.1.27282.1.3.2.1.4.4" ) ]]; then
		log_type_old=1
	fi
	if [[ "$skip" -le "3" ]]; then
		return
	fi
	if [ "$oid" = ".1.3.6.1.6.3.1.1.4.3.0" ]; then
		return
	fi

	if [ "${oid:0:-2}" = ".1.3.6.1.2.1.2.2.1.1" ]; then
		val="ifindex: $val"
	elif [ "${oid:0:-2}" = ".1.3.6.1.2.1.2.2.1.7" ]; then
		val="enabled: $val"
	elif [ "${oid:0:-2}" = ".1.3.6.1.2.1.2.2.1.8" ]; then
		val="link: $val"
	fi

	if [ "$func" = "" ]; then
		func="$val"
	else
		event+=" $val"
	fi
}

while read oid val; do

	((skip++))

	##恢复原来记录日志的操作，测试版发现问题增补三期以前的实现
	log_reciev_snmp_trapd

	output_test_log "skip $skip"
	output_test_log "$oid $val"
	##需要的三行：时间，日志类型及告警内容
	if [[ "$skip" -lt "3" || "$skip" -gt "5" ]]; then
		continue
	fi

	##保存日志类型描述的内容，用于后续判断比较是否为需要的告警
	if [[ "$skip" -eq "4" ]]; then
		log_type=${val//\"/}
	fi
	##取对应点数组的预设作为描述插入
	Append data_json  "," "\"${trap_point[$skip]}\":\"${val//\"/}\""

	##如果不是处理警告描述的的记录则进行下一次，以下循环在skip=5时进行：告警内容
	if [[ "$skip" -ne "5" ]]; then
		continue
	fi

	if [[ "$device_name" == "IK-J7052" ]]; then
		##设备是IK-J7052走三层交换机的oid节点
		switch_type="IK-J7052"
	elif [[ "$device_name" == "IK-J7028E" ]]; then
		##设备是IK-J7028E走三层交换机的oid节点
		switch_type="IK-J7028E"
	elif [[ "$device_name" == "IK-J7028ES" ]]; then
		##设备是IK-J7028E走三层交换机的oid节点
		switch_type="3ndlevel"
	else
		##不是IK-J7052都是二层交换机oid节点
		switch_type="2ndlevel"
	fi

	##遍历告警类型数组，判断是哪个告警
	for i in ${switch_event[@]}; do
		##取关联数组中告警内容的oid及日志类型描述，使用二次解析先取switch_event值，拼接取关联数组的值
		eval final_oid='$'"{info_${i}[${switch_type}]}"
		eval wildcard='$'"{info_${i}[wildcard]}"
		##比较告警描述的oid节点，同时比较日志类型字符串，是当前告警需要的关键内容则通过，其他不要
		if [[ "${final_oid}" == "${oid}" && -n $wildcard && "$log_type" == *"$wildcard"* ]];then
			eval desc='$'"{info_${i}[desc]}"
			get_interface_status "${val}"
			##找到上报告警类型的关键字
			warning_point=${i}
			##找到停止循环
			break
		fi
	done
done


##恢复原来记录日志的操作，测试版发现问题增补三期以前的实现
if [  "$func" -a "$event" ]; then
	sqlite3 /etc/log/switch.db "insert into log_$ip values(NULL, $time, $log_type_old, '$func', '$event')"
fi

if [[ "${warning_point}" != "" ]];then
	send_message ${warning_point}
	output_test_log "${warning_point}"
fi
