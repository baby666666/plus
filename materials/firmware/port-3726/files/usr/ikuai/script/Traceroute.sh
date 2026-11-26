#!/bin/bash  /etc/ikcommon
Include interface.sh

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
		'host != ""' \
		'interface ifname or == "auto"' \
		'dns == "" or ip' \
		'wait > 0' \
		'max > 0'
	local check_result=$?
	[ "$wg_source" ] && interface="$wg_source"
	S0="$original_s0"
	return "$check_result"
}

__start()
{
	if res=$(ikcheck dns $host $check_interface $dns -c 1 -t 1); then
		local host=$(echo $res | awk '{if(NR=1){print $4;exit}}')
		(traceroute -I -w $wait $interface -m $max -n $host >/tmp/traceroute 2>/tmp/traceroute; rm -f /tmp/on_traceroute) >/dev/null 2>&1 &
		(sleep $((max*wait)) && rm -f /tmp/on_traceroute && killall -q traceroute) >/dev/null 2>&1 &
	else
		echo $res >/tmp/traceroute
		rm -f /tmp/on_traceroute
	fi
}

__start()
{
	if res=$(ikcheck dns $host $check_interface $dns -c 1 -t 1); then
		local host=$(echo $res | awk '{if(NR=1){print $4;exit}}')
		(traceroute -I -w $wait $interface -m $max -n $host >/tmp/traceroute 2>/tmp/traceroute; rm -f /tmp/on_traceroute) >/dev/null 2>&1 &
		(sleep $((max*wait)) && rm -f /tmp/on_traceroute && killall -q traceroute) >/dev/null 2>&1 &
	else
		echo $res >/tmp/traceroute
		rm -f /tmp/on_traceroute
	fi
}

start()
{
	__check_param || exit 1
	stop
	touch /tmp/on_traceroute
	echo -e "host=$host\ninterface=$interface\nmax=$max\nwait=$wait\ndns=$dns" >/tmp/traceroute.host
	if [ "${interface}" != "auto" ];then
		if interface_check_is_wanpppoe ${interface} ;then
		    interface=${interface}_ad
		fi
		if ip add show dev ${interface} 2>/dev/null |grep -q inet ;then
		    check_interface="-I $interface"
		    interface="-i $interface"
		else
		    Autoiecho ping no_ip_assigned "$interface" >/tmp/traceroute
		    rm -f /tmp/on_traceroute
		    exit 0
		fi
	else
		interface=""
	fi
	if [ "$dns" ]; then
		dns="-d $dns"
	fi
	__start >/dev/null 2>&1 &
}

stop()
{
	killall -q traceroute
	rm -f /tmp/on_traceroute
	> /tmp/traceroute
	return 0
}

show()
{
	Show __json_result__
}

__show_data()
{
	[ -f /tmp/traceroute.host ] && local `cat /tmp/traceroute.host` 
	[ -e /tmp/on_traceroute ]&&status=1||status=0
	response="$(awk -v domain="$host"  '{gsub(/\t/,"\\t");if(NR==1){sub(/([0-9]+\.){3}[0-9]+/, domain, $3)};printf "%s\\n",$0}' /tmp/traceroute )"
	data=$(json_output status:int response:str)
	data="[$data]"
	json_append __json_result__ host:str interface:str max:int wait:int dns:str data:json 
}

__show_interface()
{
	local interface=$(interface_append_wireguard_json "$(interface_get_ifname_comment_json all auto)")
	json_append __json_result__ interface:json
}

