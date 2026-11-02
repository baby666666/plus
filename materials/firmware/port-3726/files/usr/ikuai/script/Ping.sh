#!/bin/bash /etc/ikcommon
Include interface.sh

__check_param()
{
    case "$interface" in nr_port_*)
        local selected="" old_choice="$interface"
        selected=$(/usr/ikuai/script/strict_policy.sh ping_resolve "choice=$interface") || return 1
        read -r interface dns strict_probe_id <<< "$selected"
        S0="${S0/interface=$old_choice/interface=$interface} dns=$dns"
        [ "$proto" != ipv6 ] || { echo 'Managed regional probes use IPv4';return 1; }
        ;;
    esac
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
        'count > 0 and <= 1000'
	local check_result=$?
	[ "$wg_source" ] && interface="$wg_source"
	S0="$original_s0"
	return "$check_result"
}


# Try to resolve specified address to IP
# $1: domain name or IP
try_get_ip_of_address()
{
	local addr="$1" ifname="$2"
	if expr "$addr" : '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+$' >/dev/null; then
		echo "$addr"
	else
		local param=""
		if [ "$ifname" != "auto" ] ; then
			local param="-I $ifname"
		fi
		local ip=$(ikcheck dns $host $param | awk 'NR==2{print $1}')
		[ -n "$ip" ] || ip="$addr"
		echo "$ip"
	fi
}

start()
{
    __check_param || exit 1
    stop
    touch /tmp/on_ping
    rm -f /tmp/ping
    local l4proto=${l4proto:-icmp}
    local probe=""
    [ ! "$strict_probe_id" ] || probe="/usr/sbin/strict-probe $strict_probe_id"
    echo -e "host=$host\ninterface=$interface\ncount=$count\nproto=$proto l4proto=$l4proto port=$port dns=$dns" >/tmp/ping.host

    if interface_check_is_wanpppoe ${interface} ;then
	interface=${interface}_ad
    fi
    if [ "$l4proto" = "tcp" ] && [ ! "$strict_probe_id" ]; then
    	local remote_addr=$(try_get_ip_of_address $host $interface)
    fi

    if [ "${interface}" != "auto" ];then
	local saddr=$(interface_get_ipaddr $interface)
        if [ "$saddr" ] ;then
            interface="-I $interface"
        else
            Autoiecho ping no_ip_assigned "$interface" > /tmp/ping
            rm -f /tmp/on_ping
            exit 0
        fi
    else
        interface=""
	local res=$(ip route get $remote_addr | awk 'NR==1{if($2=="via"){print $5}else{print $3}}')
	if [ "$res" ]; then
		local saddr=$(interface_get_ipaddr $res)
	fi
    fi
    if [ "$dns" ]; then
    	local dns="-d $dns"
    fi

    if [ "$proto" = "ipv6" ]; then
	(ping6 ${interface} -c ${count} ${host} >/tmp/ping 2>/tmp/ping; rm -f /tmp/on_ping) >/dev/null 2>&1 &
    else
	if [ "$l4proto" = "tcp" ]; then
    		($probe ikcheck tcpping ${host} ${interface} -c ${count} -p $port $dns >/tmp/ping 2>/tmp/ping; rm -f /tmp/on_ping) >/dev/null 2>&1 &
	else
    		($probe ikcheck ping ${host} ${interface} -c ${count} ${dns} >/tmp/ping 2>/tmp/ping; rm -f /tmp/on_ping) >/dev/null 2>&1 &
	fi
    fi
}

stop()
{
    if [ ! -e "/tmp/ping.host" ]; then
	return
    fi
    local $(cat /tmp/ping.host)
    if interface_check_is_wanpppoe ${interface} ;then
        interface=${interface}_ad
    fi
    if [ "$proto" = "ipv6" ]; then
	ps| grep ping6 | awk -v host="$host" '{if($NF==host){system("kill "$1)}}'
    else
	killall ik_portscanner	>/dev/null 2>&1
    	if [ "$interface" != "auto" ]; then
		interface="-I $interface"
		ps -w |grep "ikcheck dns $host $interface"|awk '$5=="{ikcheck}"{system ("kill "$1)}'
		ps -w |grep "ikcheck ping $host $interface -c $count"|awk '$5=="{ikcheck}"{system ("kill "$1)}'
	else
		ps -w |grep "ikcheck dns $host"|awk '$5=="{ikcheck}"{system ("kill "$1)}'
		ps -w |grep "ikcheck ping $host -c $count"|awk '$5=="{ikcheck}"{system ("kill "$1)}'
    	fi
    fi
    rm -f /tmp/on_ping
}

show()
{
    Show __json_result__
}

__show_interface()
{
    local interface=$(interface_append_wireguard_json "$(interface_get_ifname_comment_json all auto)")
    local choices=$(/usr/ikuai/script/strict_policy.sh ping_choices 2>/dev/null)
    [ ! "$choices" ] || interface=$(printf '%s\n%s\n' "$interface" "$choices" | jq -c -s '.[0]+.[1]')
    json_append __json_result__ interface:json
}

__show_data()
{
    local `cat /tmp/ping.host`
    [ -e /tmp/on_ping ]&&status=1||status=0
    response="$(awk '$1!='\x00'{gsub(/\t/,"\\t");printf "%s\\n",$0}' /tmp/ping)"
    data=$(json_output status:int response:str)
    data="[$data]"
    json_append __json_result__ host:str interface:str proto:str count:int l4proto:str port:str dns:str data:json
}
