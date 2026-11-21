#!/bin/bash /etc/ikcommon
Include sys/sysstat.sh

add()
{
        del
        if [ -z "$total" ];then
                exit
        fi
        for i in `seq $total`
        do
                miss="miss$i"
                config=$(eval echo \$$miss)
                if [ -n "$config" ];then
			config=$(echo "$config"|base64 -d)
                        local ${config//&&/ }
                        sqlite3 $IK_DB_CONFIG "insert into warning(id,event,interval,type,value,url) values($id,'$event',${interval:-300},'${type:-null}',${value:-0},'$url')"
                fi
        done
	$IK_DIR_SCRIPT/utils/ik_warning.sh init >/dev/null 2>&1 &
	exit
}

del()
{
	killall -9 ik_warning.sh
        sqlite3 $IK_DB_CONFIG "delete from warning"
}

boot() {
	init
}

init()
{
	local run_flag=0
	rm -f /tmp/iktmp/monitor-alarm/tmp/*
	rm -f /tmp/iktmp/cache/cloud_switch/warning_switch*
	local tmpfile=$(sql_config_get_list $IK_DB_CONFIG "select * from warning")
	local loopback_set_status=0;
	while read config; do
		if [ -n "$config" ];then
			run_flag=1	
			local $config
			if [[ "${event:0:6}" == "switch" ]]; then
				mkdir -p /tmp/iktmp/cache/cloud_switch/
				echo "${config}" > /tmp/iktmp/cache/cloud_switch/warning_${event}
				if [[ "switch_loop" == "${event}" ]]; then
					##在配置表中如果进行了配置，则设置标志为设置
					loopback_set_status=1;
				fi
				continue
			fi
			declare -A WARNING_$event
			eval WARNING_$event[event]=$event
			eval WARNING_$event[interval]=$interval
			eval WARNING_$event[type]=$type
			eval WARNING_$event[value]=$value
			eval WARNING_$event[url]="\"$url\""
			eval WARNING_$event[id]=$id

			eval WARNING_$event[cycle_num]=$((interval/30))	
			eval WARNING_$event[count]=0
		fi
	done << EOF
	$tmpfile
EOF
	set_snmp_switch_warning_option

	if [ "$run_flag" = "1" ]; then
		event_run >/dev/null 2>&1 &
	fi
}

event_run()
{

	while true; do
		### 30s 一个数据检查周期
		sleep 30

		check_cpu
		check_cputemp
		check_ap_offline
		check_ap_stat
		check_mem
		check_drop
		check_loop
		check_cloud_switch
		check_dhcp_pool
		check_iface_drop
		check_dev_control
		check_camera_control
	done
}

#cpu使用率检测
check_cpu()
{
	[ "${WARNING_cpu[event]}" != "cpu" ] && return

	local count=${WARNING_cpu[count]}
	local cycle_num=${WARNING_cpu[cycle_num]}
	local cpu_result=${WARNING_cpu[result]}
	local last_status=${WARNING_cpu[last_status]}
	local type=${WARNING_cpu[type]}
	local value=${WARNING_cpu[value]}

	sysstat_get_cpu

	local curr_value="${SYSSTAT_CPU[0]//\.*}"
	if [ "$type" = "big" ];then
		if [ "$curr_value" -gt "$value" ];then
			cpu_result+="1"
		else
			cpu_result+="0"
		fi
	else
		if [ "$curr_value" -lt "$value" ];then
			cpu_result+="1"
		else
			cpu_result+="0"
		fi
	fi

	count=$((count+1))

	if [ "$count" = "$cycle_num" ]; then
		cpu_post_statu=$(echo $cpu_result | awk -v num=$count  -F "" '{for(i=1;i<NF;i++){if($i=="1")hit=hit+1}}END{ if((100*hit/num)>70){print "error"}else{print "ok"}}' )
		if [ "error" = "$cpu_post_statu" ];then
			if [ "$last_status" != "error" ]; then
				local id=${WARNING_cpu[id]}
				local url=${WARNING_cpu[url]}
				send_warning $id $url  {\"cpu\":\"error\"}
			fi
			WARNING_cpu[last_status]="error"
		else
			WARNING_cpu[last_status]="ok"	
		fi
		WARNING_cpu[count]=0
		WARNING_cpu[result]=""
		
	else
		WARNING_cpu[count]=$count
		WARNING_cpu[result]="$cpu_result"
	fi

}

#cpu 温度检测
check_cputemp()
{

	[ "${WARNING_cputemp[event]}" != "cputemp" ] && return
	local count=${WARNING_cputemp[count]}
	local cycle_num=${WARNING_cputemp[cycle_num]}
	local cputemp_result=${WARNING_cputemp[result]}
	local last_status=${WARNING_cputemp[last_status]}
	local type=${WARNING_cputemp[type]}
	local value=${WARNING_cputemp[value]}


	for file in $(ls /tmp/iktmp/cputemp) ;do
		local temp=$(cat /tmp/iktmp/cputemp/$file 2>/dev/null)
		if [[ "$temp" =~ ^[0-9]+$ ]];then
			temp=$((temp/1000))
		else
			temp=0
		fi

		if [ "$type" = "big" ];then
			if [ "$temp" -gt "$value" ];then
				cputemp_result+="1"
				break
			else
				cputemp_result+="0"
			fi
		fi
	done

	count=$((count+1))

	if [ "$count" = "$cycle_num" ]; then
		cputemp_post_statu=$(echo $cputemp_result | awk -v num=$count  -F "" '{for(i=1;i<NF;i++){if($i=="1")hit=hit+1}}END{ if((100*hit/num)>70){print "error"}else{print "ok"}}' )
		if [ "error" = "$cputemp_post_statu" ];then
			if [ "$last_status" != "error" ]; then
				local id=${WARNING_cputemp[id]}
				local url=${WARNING_cputemp[url]}
				send_warning $id $url  {\"cputemp\":\"error\"}
			fi
			WARNING_cputemp[last_status]="error"
		else
			WARNING_cputemp[last_status]="ok"
		fi
		WARNING_cputemp[count]=0
		WARNING_cputemp[result]=""

	else
		WARNING_cputemp[count]=$count
		WARNING_cputemp[result]="$cputemp_result"
	fi

}

#物联管理 掉线检测
check_dev_control()
{
	[ "${WARNING_dev_control[event]}" != "dev_control" ] && return
	local count=${WARNING_dev_control[count]}
	local cycle_num=10
	local link_err=0

	count=$((count+1))

	if [ "$count" != "$cycle_num" ]; then
		WARNING_dev_control[count]=$count
		return 
	fi
	local device_info


	for tmpfile in $(ls /tmp/iktmp/cache/dev_control/status.*); do
		local id=${tmpfile//*status.}
		[ ! -e "/tmp/iktmp/cache/dev_control/config.$id" ] && continue

		local $(cat /tmp/iktmp/cache/dev_control/config.$id)

		local res=$(cat $tmpfile 2>/dev/null)
		if [ "$res" != "0" ]; then
			WARNING_dev_control[${id}_result_last]="ok"
			continue
		fi
		local result_last=${WARNING_dev_control[${id}_result_last]}
		if [ "$result_last" != "error" ]; then
			device_info+="${device_info:+,}$(json_output name:str ip_addr:str mac:str)"
		fi
		WARNING_dev_control[${id}_result_last]="error"
	done

	if [ -n "$device_info" ]; then
		local id=${WARNING_dev_control[id]}
		local url=${WARNING_dev_control[url]}
		local device_offline="error"
		local device_info="[$device_info]"
		local send_device_info=$(json_output device_info:json device_offline:str)
		send_warning $id $url  "$send_device_info"
	fi

	WARNING_dev_control[count]=0
}

#摄像头 掉线检测
check_camera_control()
{
	[ "${WARNING_camera_control[event]}" != "camera_control" ] && return
	local count=${WARNING_camera_control[count]}
	local cycle_num=10
	local link_err=0

	count=$((count+1))

	if [ "$count" != "$cycle_num" ]; then
		WARNING_camera_control[count]=$count
		return
	fi
	local camera_info


	for tmpfile in $(ls /tmp/iktmp/cache/camera_control/status.*); do
		local id=${tmpfile//*status.}
		[ ! -e "/tmp/iktmp/cache/camera_control/config.$id" ] && continue

		local $(cat /tmp/iktmp/cache/camera_control/config.$id)

		local res=$(cat $tmpfile 2>/dev/null)
		if [ "$res" != "0" ]; then
			WARNING_camera_control[${id}_result_last]="ok"
			continue
		fi
		local result_last=${WARNING_camera_control[${id}_result_last]}
		if [ "$result_last" != "error" ]; then
			camera_info+="${camera_info:+,}$(json_output name:str ip_addr:str mac:str comment:str)"
		fi
		WARNING_camera_control[${id}_result_last]="error"
	done

	if [ -n "$camera_info" ]; then
		local id=${WARNING_camera_control[id]}
		local url=${WARNING_camera_control[url]}
		local camera_offline="error"
		local camera_info="[$camera_info]"
		local send_camera_info=$(json_output camera_info:json camera_offline:str)
		send_warning $id $url  "$send_camera_info"
	fi

	WARNING_camera_control[count]=0
}

#云交换机 掉线检测
check_cloud_switch()
{
	[ "${WARNING_cloud_switch[event]}" != "cloud_switch" ] && return
	local count=${WARNING_cloud_switch[count]}
	local cycle_num=10
	local link_err=0

	count=$((count+1))

	if [ "$count" != "$cycle_num" ]; then
		WARNING_cloud_switch[count]=$count
		return 
	fi

	local switch_info

	local tmpfile=$(sql_config_get_list $IK_DB_CONFIG "select id,name,oemname,ip_addr from switch_dev")
	while read config; do
		[ "$config" ] || continue
		local $config
		
		local res=$(cat /tmp/iktmp/cache/cloud_switch/$id/status 2>/dev/null)
		if [ "$res" != "0" ]; then
			WARNING_cloud_switch[${id}_result_last]="ok"
			continue
		fi
		if [ "$oemname" ]; then
			name="$oemname"
		fi

		local result_last=${WARNING_cloud_switch[${id}_result_last]}
		if [ "$result_last" != "error" ]; then
			switch_info+="${switch_info:+,}$(json_output name:str ip_addr:str)"
		fi
		WARNING_cloud_switch[${id}_result_last]="error"

	done <<EOF
	$tmpfile
EOF

	if [ -n "$switch_info" ]; then
		local id=${WARNING_cloud_switch[id]}
		local url=${WARNING_cloud_switch[url]}
		local switch_offline="error"
		local switch_info="[$switch_info]"
		local send_switch_info=$(json_output switch_info:json switch_offline:str)
		send_warning $id $url  "$send_switch_info"
	fi

	WARNING_cloud_switch[count]=0
}


#ap 掉线检测
check_ap_offline()
{
	[ "${WARNING_ap_offline[event]}" != "ap_offline" ] && return
	local count=${WARNING_ap_offline[count]}
	local cycle_num=10

	count=$((count+1))

	if [ "$count" != "$cycle_num" ]; then
		WARNING_ap_offline[count]=$count
		return 
	fi

	local tempfile=$(ls /tmp/iktmp/cache/config/AC/config |awk 'BEGIN{ while("wum -c wtps" |getline){status[$2]=1} ;while("cat /tmp/iktmp/apname"|getline){comment[$1]=$2} }{if(status[$1]){s=1}else{s=0}; print $1,s,comment[$1]}')
	local apinfo apmac status comment apinfo_online
	local link_err=0

	while read apmac status comment ;do
		#is online
		[ "$apmac" ] || continue
		if [ "$status" = "1" ]; then
			if [ "${WARNING_ap_offline[$apmac]}" = "1" ]; then
				link_err=1
				apinfo_online+="${apinfo_online:+,}$(json_output apmac:str comment:str)"
			fi
			WARNING_ap_offline[$apmac]=0
			continue
		elif [ "${WARNING_ap_offline[$apmac]}" = "0" ]; then
			link_err=1
			WARNING_ap_offline[$apmac]=1
			apinfo+="${apinfo:+,}$(json_output apmac:str comment:str)"
		fi
	done << EOF
	$tempfile
EOF

	apinfo="[$apinfo]"
	apinfo_online="[$apinfo_online]"

	if [ "$link_err" = "1" ]; then
		local id=${WARNING_ap_offline[id]}
		local url=${WARNING_ap_offline[url]}
		local ap_offline="error"
		local send_apinfo=$(json_output apinfo:json apinfo_online:json ap_offline:str)
		send_warning $id $url  "$send_apinfo"
	fi

	WARNING_ap_offline[count]=0
}


check_ap_stat()
{
	local tmpfile=$(wum -c wtps 2>/dev/null | awk '{print "apmac="$2, "ap_cpuuse="$18, "chutil_2g="$26, "chutil_5g="$28, "channf_2g="$27, "channf_5g="$29}')
	check_ap_chutil
	check_ap_channf
	check_ap_cpuuse

}
#ap 信道利用率告警
check_ap_chutil()
{
	[ "${WARNING_ap_chutil[event]}" != "ap_chutil" ] && return
	local cycle_num=${WARNING_ap_chutil[cycle_num]}
	local value=${WARNING_ap_chutil[value]}

	local ap_chutil_info

	while read config; do
		[ "$config" ] || continue
		local $config

		[ "$apmac" ] || continue

		local count=${WARNING_ap_chutil[${apmac}_count]}
		count=$((count+1))

		local chutil_2g=${chutil_2g:-0} chutil_5g=${chutil_5g:-0}
		if [ "$chutil_2g" = "--" ]; then
			chutil_2g=0
		fi
		if [ "$chutil_5g" = "--" ]; then
			chutil_5g=0
		fi

		if [ "$((chutil_2g*100/255))" -gt "$value" ]; then
			WARNING_ap_chutil[${apmac}_err]+="1"
		elif [ "$((chutil_5g*100/255))" -gt "$value" ]; then
			WARNING_ap_chutil[${apmac}_err]+="1"
		else
			WARNING_ap_chutil[${apmac}_err]+="0"
		fi
		if [ "$count" = "$cycle_num" ]; then

			local ap_post_statu=$(echo ${WARNING_ap_chutil[${apmac}_err]} | awk -v num=$count  -F "" '{for(i=1;i<NF;i++){if($i=="1")hit=hit+1}}END{ if((100*hit/num)>70){print "error"}else{print "ok"}}' )

			if [ "$ap_post_statu" = "error" ]; then
				result_last=${WARNING_ap_chutil[${apmac}_result_last]}
		
				if [ "$result_last" != "fail" ]; then
					local comment=$(awk -v apmac="$apmac" '$1==apmac{print $2;exit}' /tmp/iktmp/apname)
					ap_chutil_info+="${ap_chutil_info:+,}$(json_output apmac:str comment:str)"
				fi
				WARNING_ap_chutil[${apmac}_result_last]="fail"
			else
				WARNING_ap_chutil[${apmac}_result_last]="ok"

			fi
			WARNING_ap_chutil[${apmac}_count]=0
			WARNING_ap_chutil[${apmac}_err]=""
		else
			WARNING_ap_chutil[${apmac}_count]=$count

		fi

	done << EOF
	$tmpfile
EOF
	if [ -n "$ap_chutil_info" ];then
		local id=${WARNING_ap_chutil[id]}
		local url=${WARNING_ap_chutil[url]}
		send_warning $id $url "[$ap_chutil_info]"
	fi

}

#ap 底噪检测
check_ap_channf()
{
	[ "${WARNING_ap_channf[event]}" != "ap_channf" ] && return
	local cycle_num=${WARNING_ap_channf[cycle_num]}
	local value=${WARNING_ap_channf[value]}

	local ap_channf_info

	while read config; do
		[ "$config" ] || continue
		local $config

		[ "$apmac" ] || continue

		local count=${WARNING_ap_channf[${apmac}_count]}
		count=$((count+1))
		local channf_2g=${channf_2g:--200} channf_5g=${channf_5g:--200}
	
		if [ "$channf_2g" = "--" ]; then
			channf_2g="-200"
		fi
		if [ "$channf_5g" = "--" ]; then
			channf_5g="-200"
		fi

		if [ "$channf_2g" -gt "$value" ]; then
			WARNING_ap_channf[${apmac}_err]+="1"
		elif [ "$channf_5g" -gt "$value" ]; then
			WARNING_ap_channf[${apmac}_err]+="1"
		else
			WARNING_ap_channf[${apmac}_err]+="0"
		fi

		if [ "$count" = "$cycle_num" ]; then

			local ap_post_statu=$(echo ${WARNING_ap_channf[${apmac}_err]} | awk -v num=$count  -F "" '{for(i=1;i<NF;i++){if($i=="1")hit=hit+1}}END{ if((100*hit/num)>70){print "error"}else{print "ok"}}' )

			if [ "$ap_post_statu" = "error" ]; then
				result_last=${WARNING_ap_channf[${apmac}_result_last]}
				if [ "$result_last" != "fail" ]; then
					local comment=$(awk -v apmac="$apmac" '$1==apmac{print $2;exit}' /tmp/iktmp/apname)
					ap_channf_info+="${ap_channf_info:+,}$(json_output apmac:str comment:str)"
				fi
				WARNING_ap_channf[${apmac}_result_last]="fail"
			else
				WARNING_ap_channf[${apmac}_result_last]="ok"
			fi
			WARNING_ap_channf[${apmac}_count]=0
			WARNING_ap_channf[${apmac}_err]=""
		else
			WARNING_ap_channf[${apmac}_count]=$count

		fi

	done << EOF
	$tmpfile
EOF
	if [ -n "$ap_channf_info" ];then
		local id=${WARNING_ap_channf[id]}
		local url=${WARNING_ap_channf[url]}
		send_warning $id $url "[$ap_channf_info]"
	fi

}

#ap cpu使用率告警
check_ap_cpuuse()
{
	## date +%Y%M%d%H%m%S >> /tmp/check_ap_cpuuse.log

	local type=${WARNING_ap_cpuuse[type]}
	local cmp
	if [ "$type" = "big" ];then
		cmp="-gt"
	else
		cmp="-lt"
	fi

	[ "${WARNING_ap_cpuuse[event]}" != "ap_cpuuse" ] && return
	local cycle_num=${WARNING_ap_cpuuse[cycle_num]}
	local value=${WARNING_ap_cpuuse[value]}

	local ap_cpuuse_info

	while read config; do
		[ "$config" ] || continue
		local $config

		[ "$apmac" ] || continue

		local count=${WARNING_ap_cpuuse[${apmac}_count]}
		count=$((count+1))

		ap_cpuuse=${ap_cpuuse%\%}

		if [ "$ap_cpuuse" $cmp "$value" ]; then
			WARNING_ap_cpuuse[${apmac}_err]+="1"
		else
			WARNING_ap_cpuuse[${apmac}_err]+="0"
		fi

		## echo "WARNING_ap_cpuuse[${apmac}_count]:${WARNING_ap_cpuuse[${apmac}_count]},cycle_num:$cycle_num, ap_cpuuse:$ap_cpuuse" >> /tmp/check_ap_cpuuse.log

		if [ "$count" = "$cycle_num" ]; then

			local ap_post_statu=$(echo ${WARNING_ap_cpuuse[${apmac}_err]} | awk -v num=$count  -F "" '{for(i=1;i<NF;i++){if($i=="1")hit=hit+1}}END{ if((100*hit/num)>70){print "error"}else{print "ok"}}' )

			if [ "$ap_post_statu" = "error" ]; then
				result_last=${WARNING_ap_cpuuse[${apmac}_result_last]}
				if [ "$result_last" != "fail" ]; then
					local comment=$(awk -v apmac="$apmac" '$1==apmac{print $2;exit}' /tmp/iktmp/apname)
					ap_cpuuse_info+="${ap_cpuuse_info:+,}$(json_output apmac:str comment:str)"
				fi
				WARNING_ap_cpuuse[${apmac}_result_last]="fail"
			else
				WARNING_ap_cpuuse[${apmac}_result_last]="ok"
			fi
			WARNING_ap_cpuuse[${apmac}_count]=0
			WARNING_ap_cpuuse[${apmac}_err]=""
		else
			WARNING_ap_cpuuse[${apmac}_count]=$count

		fi
		## echo "$ap_cpuuse $cmp $value ${WARNING_ap_cpuuse[${apmac}_result_last]} ${WARNING_ap_cpuuse[${apmac}_err]} ${WARNING_ap_cpuuse[${apmac}_result_last]}" >> /tmp/check_ap_cpuuse.log

	done << EOF
	$tmpfile
EOF
	if [ -n "$ap_cpuuse_info" ];then
		local id=${WARNING_ap_cpuuse[id]}
		local url=${WARNING_ap_cpuuse[url]}
		send_warning $id $url "[$ap_cpuuse_info]"
		## echo "send_warning $id $url \"[$ap_cpuuse_info]\"" >> /tmp/check_ap_cpuuse.log
	fi

}

#内存使用率检测
check_mem()
{
	[ "${WARNING_memory[event]}" != "memory" ] && return
	local count=${WARNING_memory[count]}
	local cycle_num=${WARNING_memory[cycle_num]}
	local mem_sum=${WARNING_memory[result]}
	local last_status=${WARNING_memory[last_status]}
	local value=${WARNING_memory[value]}
	local type=${WARNING_memory[type]}


	sysstat_get_mem
	local mem_total=${SYSSTAT_MEM[MemTotal]}
	local mem_avail=${SYSSTAT_MEM[MemAvailable]}
	local mem_sum=$(((mem_total - mem_avail) * 100 /mem_total + mem_sum))

	count=$((count+1))

	if [ "$count" = "$cycle_num" ]; then

		if [ "$type" = "big" ];then
			mem_post_statu=$(echo "$mem_sum $count $value"|awk '{if($1/$2>$3){print "error"}else{print "ok"}}' )
		else
			mem_post_statu=$(echo "$mem_sum $count $value"|awk '{if($1/$2<$3){print "error"}else{print "ok"}}' )
		fi

		if [ "error" = "$mem_post_statu" ];then
			if [ "$last_status" != "error" ]; then
				local id=${WARNING_memory[id]}
				local url=${WARNING_memory[url]}
				send_warning $id $url  {\"mem\":\"error\"}
			fi
			WARNING_memory[last_status]="error"
		else
			WARNING_memory[last_status]="ok"
		fi
		WARNING_memory[count]=0
		WARNING_memory[result]=0

	else
		WARNING_memory[count]=$count
		WARNING_memory[result]=$mem_sum
	fi
}

##dhcp地址池检测
check_dhcp_pool()
{
	[ "${WARNING_dhcp_pool[event]}" != "dhcp_pool" ] && return
	local cycle_num=10
	local count=${WARNING_dhcp_pool[count]}
	local last_status=${WARNING_dhcp_pool[last_status]}

	count=$((count+1))

	if [ "$count" != "$cycle_num" ]; then
		WARNING_dhcp_pool[count]=$count
		return
	fi

	local available_num=0
	if  [ -e "/tmp/iktmp/ik_dhcpd.status" ]; then
		available_num=$(awk 'BEGIN{ total=0 }{total=total+$2}END{print total}' /tmp/iktmp/ik_dhcpd.status)
	fi

	local dhcp_pool_info
	while read id num; do
		[ "$num" != "0" ] && continue
		local $(sql_config_get_list $IK_DB_CONFIG "select interface from dhcp_server where id=$id")
		dhcp_pool_info+="${dhcp_pool_info:+,}$(json_output interface:str)"
	done < /tmp/iktmp/ik_dhcpd.status
	
	if [ -n "$dhcp_pool_info" ];then
		if [ "$last_status" != "error" ]; then
			local id=${WARNING_dhcp_pool[id]}
			local url=${WARNING_dhcp_pool[url]}
			send_warning $id $url  "[$dhcp_pool_info]"
		fi
			
		WARNING_dhcp_pool[last_status]="error"
	else
		WARNING_dhcp_pool[last_status]="ok"
	fi
	
	WARNING_dhcp_pool[count]=0
}

##外网丢包检测
check_iface_drop()
{
	[ "${WARNING_iface_drop[event]}" != "iface_drop" ] && return
	local count=${WARNING_iface_drop[count]}
	local cycle_num=${WARNING_iface_drop[cycle_num]}
	local last_status=${WARNING_iface_drop[last_status]}
	local value=${WARNING_iface_drop[value]}

	count=$((count+1))

	if [ "$count" != "$cycle_num" ]; then
		WARNING_iface_drop[count]=$count
		return
	fi

	local drop_info=$($IK_DIR_SCRIPT/monitor_iface.sh iface_drop_info_get $value)
	
	if [ -n "$drop_info" -a "$drop_info" != "[]" ];then
		if [ "$last_status" != "error" ]; then
			local id=${WARNING_iface_drop[id]}
			local url=${WARNING_iface_drop[url]}
			send_warning $id $url  "$drop_info"
		fi
			
		WARNING_iface_drop[last_status]="error"
	else
		WARNING_iface_drop[last_status]="ok"
	fi
	
	WARNING_iface_drop[count]=0
}


##环路检测
check_loop()
{
	[ "${WARNING_loop[event]}" != "loop" ] && return
	local cycle_num=10
	local count=${WARNING_loop[count]}
	local last_status=${WARNING_loop[last_status]}

	if [ "$count" = "0" ]; then
		start_time=$(date +%s)
	fi

	count=$((count+1))

	if [ "$count" != "$cycle_num" ]; then
		WARNING_loop[count]=$count
		return
	fi
	
	loop_post_statu=$(sqlite3 /etc/log/syslog.db "select content from sys_event where content like '%with own address as source address%' and timestamp > $start_time")
	if [ -n "$loop_post_statu" ];then
		if [ "$last_status" != "error" ]; then
			local id=${WARNING_loop[id]}
			local url=${WARNING_loop[url]}
			send_warning $id $url  {\"loop\":\"error\"}
		fi
			
		WARNING_loop[last_status]="error"
	else
		WARNING_loop[last_status]="ok"
	fi
	
	WARNING_loop[count]=0
}



#外网掉线检测
check_drop()
{

	[ "${WARNING_wan_off[event]}" != "wan_off" ] && return
	local ifaces=${WARNING_wan_off[type]}
	local max_err_num=5
	local max_ok_num=5
	local disconnect_timeout=120

	#进入待处理目录,该内容是由 monitor 脚本 的 monitor_link(线路检测功能发送过来)
	cd /tmp/iktmp/monitor-alarm/iface-result

	uptime=$(sysstat_get_uptime)
	data_json=""
	#只对云平台上配置的接口线路进行告警处理
	for interface in ${ifaces//,/ };do
		[ -e "$interface" ] || continue
		read interface parent_interface ipaddr gateway _ _ _ result errmsg _  <$interface
		rm -f $interface
		if [ "$result" != "success" -a "$errmsg" != "--" ];then
			#检测报告周期是30秒
			#当这条线路超过指定时间(disconnect_timeout) 没有收到检测报告,则把失败累计归0

			uptime_last=${WARNING_wan_off[${interface}_uptime]}
			uptime_diff=$((uptime-uptime_last))
			if [ "$uptime_diff" -ge "$disconnect_timeout" ];then
				WARNING_wan_off[${interface}_err_sum]=0
			fi

			#获取失败累计次数
			local err_sum=${WARNING_wan_off[${interface}_err_sum]}
			err_sum=$((err_sum+1))

			#失败次数达到上限,则发送给云服务,同时失败累计值归0
			if [ "$err_sum" -ge "$max_err_num" ];then
				WARNING_wan_off[${interface}_err_sum]=0
				
				#获取上一次的检测结果,如果上一次也是失败,则不需要再连接发送报告给云端
				result_last=${WARNING_wan_off[${interface}_result_last]}
			
				if [ "$result_last" != "fail" ];then
					WARNING_wan_off[${interface}_result_last]="fail"
					Append data_json "," "\"$interface\":\"$errmsg\""
				fi
			else
				WARNING_wan_off[${interface}_err_sum]=$err_sum
			fi
			WARNING_wan_off[${interface}_ok_sum]=0
		else
			#线路检测正常时,要把错误累计归0,最后一次结果标记为正常
			local ok_sum=${WARNING_wan_off[${interface}_ok_sum]}
			ok_sum=$((ok_sum+1))

			if [ "$ok_sum" -ge "$max_ok_num" ];then
				result_last=${WARNING_wan_off[${interface}_result_last]}
				if [ "$result_last" == "fail" ];then
					Append data_json  "," "\"$interface\":\"ok\""
				fi
				WARNING_wan_off[${interface}_result_last]="ok"
				WARNING_wan_off[${interface}_ok_sum]=0
			else
				WARNING_wan_off[${interface}_ok_sum]=$ok_sum
			fi
			WARNING_wan_off[${interface}_err_sum]=0
		fi

		WARNING_wan_off[${interface}_uptime]=$uptime
	done

	if [ -n "$data_json" ];then
		local id=${WARNING_wan_off[id]}
		local url=${WARNING_wan_off[url]}
		send_warning $id $url "{$data_json}"
	fi
}

send_warning()
{
	md5_value=$(echo -n "key=ikuai_alerm_2016&event_id=$1" | md5sum | cut -d ' ' -f1)
        post_string="warning_info={\"event_id\":$1,\"gwid\":\"$GWID\",\"sign\":\"$md5_value\",\"warning\":${3:-'{}'} }"
	if [ -n "$2" ];then
		wget -4 -O- -q -t 3 -T 30 --connect-timeout=30 --dns-timeout=20 $2 --post-data="$post_string"
	fi
}

### dstip oid snmpblukwalk 从cloud_switch.sh文件中直接复制的函数，构造snmp参数
__snmp_option_init()
{
	if [ -z "$dstip" ]; then
		return 1
	fi
	local default_options=""
	if [ "$snmp_version" = "v2c" ]; then
		default_options="-c $community -v2c "
	else
		default_options=" -v 3 -u $username"
		if [ "$security" = "authNoPriv" ]; then
			default_options+=" -l authNoPriv -a $auth_proto -A $auth_pass"
		else
			default_options+="  -l authPriv -a $auth_proto -A $auth_pass -x $priv_proto -X $priv_pass"
		fi
	fi

	option="$default_options $dstip"
}

declare -A switch_type=(
	["IK_J7052"]="IK_J7052"
	["IK_J7028E"]="IK_J7028E" ##临时增加交换机IK-J7028E同IK_J7052
	["3ndlevel"]="3ndlevel"
	["2ndlevel"]="2ndlevel"
)

declare -A switch_event=(
	["switch_port_rate"]="switch_port_rate"
	["switch_port_high_packet_loss_rate"]="switch_port_high_packet_loss_rate"
)

##三层交换机IK-J7052与其他二层交换机oid节点不同，分型分别取oid节点
declare -A oidset_${switch_type["IK_J7052"]}
eval oidset_${switch_type["IK_J7052"]}["switch_port_rate"]=".1.3.6.1.4.1.27282.1.3.1.14.1.0"
eval oidset_${switch_type["IK_J7052"]}["switch_port_high_packet_loss_rate"]=".1.3.6.1.4.1.27282.1.3.1.14.2.0"

##临时增加交换机IK-J7028E同IK_J7052
declare -A oidset_${switch_type["IK_J7028E"]}
eval oidset_${switch_type["IK_J7028E"]}["switch_port_rate"]=".1.3.6.1.4.1.27282.1.3.1.14.1.0"
eval oidset_${switch_type["IK_J7028E"]}["switch_port_high_packet_loss_rate"]=".1.3.6.1.4.1.27282.1.3.1.14.2.0"

declare -A oidset_${switch_type["3ndlevel"]}
eval oidset_${switch_type["3ndlevel"]}["switch_port_rate"]=".1.3.6.1.4.1.27282.1.3.1.14.1.0"
eval oidset_${switch_type["3ndlevel"]}["switch_port_high_packet_loss_rate"]=".1.3.6.1.4.1.27282.1.3.1.14.2.0"

declare -A oidset_${switch_type["2ndlevel"]}
eval oidset_${switch_type["2ndlevel"]}["switch_port_rate"]=".1.3.6.1.4.1.27282.1.1.1.14.1.0"
eval oidset_${switch_type["2ndlevel"]}["switch_port_high_packet_loss_rate"]=".1.3.6.1.4.1.27282.1.1.1.14.2.0"

declare -A loop_oid=(
	["IK_J7052"]=".1.3.6.1.4.1.27282.1.3.1.15.1.0"
	["IK_J7028E"]=".1.3.6.1.4.1.27282.1.3.1.15.1.0"
	["3ndlevel"]=".1.3.6.1.4.1.27282.1.3.1.15.1.0"
	["2ndlevel"]=".1.3.6.1.4.1.27282.1.1.1.15.1.0"
)

##获取ikuai交换机loopback状态，云管平台三期
get_loopback_status()
{
	local ret=$(snmpget $option ${loop_oid[$1]} 2>/dev/null |awk '{print $4}')
	if [[ "$ret" == "0" || "$ret" == "1" ]]; then
		##获取到值直接返回值
		return $ret
	else
		##当获取失败时，返回2
		return 2
	fi
}

##设置ikuai交换机loopback状态，云管平台三期
set_loopback_status()
{
	snmpset $option ${loop_oid[$1]} i $2 >/dev/null 2>&1
}

set_snmp_switch_warning_option()
{
	##准备好缓存中对应事件设置的值
	declare -A switch_value
	for event in ${switch_event[@]}; do
		if [ -e /tmp/iktmp/cache/cloud_switch/warning_${event} ];then
			local $(cat /tmp/iktmp/cache/cloud_switch/warning_${event})
			switch_value[$event]=$value
		else
			switch_value[$event]=0
		fi
		##echo "${switch_value[$event]}"
	done

	while read config ; do
		local $config
		[ -z "$ip_addr" ] && continue
		[ "${device:0:3}" != "IK-" -a "${oemname:0:3}" != "IK-" ] && continue
		local dstip=$ip_addr
		local option
		local type

		##决定交换类型
		if [[ "${device}" == "IK-J7052" ]]; then
			type="IK_J7052"
		elif [[ "${device}" == "IK-J7028E" ]]; then
			type="IK_J7028E"
		elif [[ "${device}" == "IK-J7028ES" ]]; then
			type="3ndlevel"
		else
			type="2ndlevel"
		fi

		##设置snmp参数选项
		__snmp_option_init

		##轮询事件
		for event in ${switch_event[@]}; do
			##echo ${event}
			eval oid='$'"{oidset_${switch_type[${type}]}[${event}]}"
			##echo "oid:$oid"
			##echo "snmpset $option $oid i ${switch_value[$event]} >/dev/null 2>/dev/null"
			##通过snmp协议对告警进行对应设置
			snmpset $option $oid i ${switch_value[$event]} >/dev/null 2>/dev/null
		done

		##对loopback全局标志位进行设置

		##获取已设置的状态
		get_loopback_status $type
		sw_loopbackp_status=$?

		##当前设备loopback状态为可以正常获取，且与设置状态不符，则按需要设置的状态进行设置
		if [[ "$sw_loopbackp_status" -ne "2" && "$loopback_set_status" -ne "$sw_loopbackp_status" ]]; then
			set_loopback_status $type $loopback_set_status
		fi

	done < /tmp/iktmp/cache/cloud_switch/config
	##echo "set_snmp_switch_warning_option"
}
