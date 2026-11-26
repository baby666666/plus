#!/bin/bash /etc/ikcommon
Include interface.sh,iproute.sh

IPERF_LOG="/tmp/iperf.log"
IPERF_CONF="/tmp/iperf.conf"

boot()
{
	init
}

init()
{
	echo  "host= l3proto=ipv4 l4proto=udp bandwidth=100 interface=auto time=10 interval=1 port=5201 dir=upload threads=1" > $IPERF_CONF
	local res=$(sql_config_get_list $IK_DB_CONFIG "select * from iperf3_server where enabled='yes'")
	if [ "$res" ]; then
		local $res
		__server_start
	fi
}


__check_param()
{
	local wg_source="" original_s0="$S0" validation_interface
	if interface_is_wireguard_tool_source "$interface"; then
		wg_source="$interface"
		validation_interface="auto"
		S0="${S0/interface=$interface/interface=$validation_interface}"
		interface="$validation_interface"
	fi
	check_varl \
        	'host		!= ""' \
		'port		ikports' \
		'dir		== "upload" or == "download"' \
		'threads	> 0 and <= 32' \
        	'l4proto	== "tcp" or == "udp"' \
		'l3proto	== "ipv4" or == "ipv6"' \
        	'bandwidth	!= ""' \
        	'interface 	ifname or == "auto"' \
        	'time	 	> 0 and <= 60' \
        	'interval 	> 0 and <= 10'
	local check_result=$?
	[ "$wg_source" ] && interface="$wg_source"
	S0="$original_s0"
	return "$check_result"
}

__check_param_save()
{
	check_varl \
		'enabled	== "yes" or == "no"' \
		'port		ikports'
}

__server_start()
{
	iperf3 -s -D -p $port	
}

__server_stop()
{
	ps| grep iperf3 | awk '{if($5=="iperf3"&&$6=="-s"){system("kill "$1)}}'
}

__server_restart()
{
	__server_stop
	__server_start
}

save()
{
	__check_param_save || exit 1

	local sql_param="enabled:str port:int"

	local res=$(sql_config_get_list $IK_DB_CONFIG "select * from iperf3_server where id=1" prefix=old_)
	if [ -z "$res" ]; then
		return 0
	fi

	local $res
	
	if SqlMsg=$(sql_config_update $IK_DB_CONFIG iperf3_server "id=1" $sql_param) ;then
		if ! NewOldVarl enabled port; then
			if [ "$enabled" = "yes" ]; then
				__server_restart >/dev/null 2>&1 &
			else
				__server_stop >/dev/null 2>&1 &
			fi

		fi

	fi
	
}

start()
{
	__check_param || exit 1

	stop
	touch /tmp/.on_iperf
	> $IPERF_LOG
	local params=""

	echo  "host=$host l3proto=$l3proto l4proto=$l4proto bandwidth=$bandwidth interface=$interface time=$time interval=$interval port=$port dir=$dir threads=$threads" > $IPERF_CONF

	local mark
	params+=" -c $host -p $port"
	if [ "${interface}" != "auto" ];then
		if [ "$l3proto" = "ipv6" ]; then
			local bind_addr=$(interface_get_ipv6addr $interface)
		else
			local bind_addr=$(interface_get_ipaddr $interface)
			local mark=$(iproute_get_markid $interface)
		fi
		if [ "$bind_addr" ] ;then
			params+=" -B $bind_addr"
		fi
		if [ "$mark" ]; then
			params+=" -m $mark"
		fi
	fi

	if [ "$l4proto" = "udp" ]; then
		params+=" -u"
		if [ "$bandwidth" ]; then
			params+=" -b ${bandwidth}M"
		fi
	fi

	if [ "$l3proto" = "ipv6" ]; then
		params+=" -6"
	fi
	params+=" -t $time -i $interval -P $threads"
	if [ "$dir" = "download" ]; then
		params+=" -R"
	fi
	params+=" --logfile $IPERF_LOG --connect-timeout 1000"

	(iperf3 $params ; rm -f /tmp/.on_iperf) >/dev/null 2>&1 &
}

stop()
{
	local $(cat $IPERF_CONF) >/dev/null 2>&1
	
	ps| grep iperf3 | awk -v host="$host" '{if($5=="iperf3"&&$7==host){system("kill "$1)}}'
	
	rm -f /tmp/.on_iperf
	> $IPERF_LOG
}

show()
{
	Show __json_result__
}

__show_interface()
{
	local interface=$(interface_append_wireguard_json "$(interface_get_ifname_comment_json wan,vpn auto)")
	json_append __json_result__ interface:json
}

__show_data()
{
	if [ -e "$IPERF_CONF" ]; then
		local $(cat $IPERF_CONF)
	fi

	[ -e /tmp/.on_iperf ] && status=1||status=0
	
	if [ -e "$IPERF_LOG" ]; then
		local response="$(awk '$1!='\x00'{gsub(/\t/,"\\t");printf "%s\\n",$0}' $IPERF_LOG)"
	fi
	local data=$(json_output status:int response:str)
	local data="[$data]"
	json_append __json_result__ host:str port:int threads:int dir:str interface:str l3proto:str l4proto:str time:int interval:int bandwidth:str data:json
}

__show_service()
{
	local service=$(sql_config_get_json $IK_DB_CONFIG "select * from iperf3_server")
	json_append __json_result__ service:json
}
