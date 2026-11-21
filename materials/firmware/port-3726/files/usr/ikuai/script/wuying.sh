#!/bin/bash /etc/ikcommon

Include check.sh interface.sh json.sh iproute.sh lock.sh
Include ifether.sh brctl.sh monitor_link.sh urlcode.sh

RICK_HOME=/etc/log/wuying
RICK_CLI_PATH=$RICK_HOME/bin
RICK_LOG_PATH=/tmp/iktmp/wuying/logs
RICK_CONF_PATH=$RICK_HOME/config
RICK_TMP_CLI_PATH=/tmp/iktmp/wuying/bin
LOCKUP_NB="LockNonblock wuying"
LOCKUP="Lock wuying"
UNLOCK="unLock wuying"

boot()
{
	mkdir -p $RICK_HOME
	mkdir -p $RICK_CLI_PATH
	mkdir -p $RICK_LOG_PATH
	mkdir -p $RICK_CONF_PATH
	mkdir -p $RICK_TMP_CLI_PATH
	sleep 5
	wget_bin >/dev/null 2>&1 
	init boot
}

init()
{
	sqlite3 $IK_DB_CONFIG "update wuying set interface='from_wuying'"
	__rick_init

	return
}

__rick_init()
{
	local $(sql_config_get_list $IK_DB_CONFIG "select * from wuying")

	__exec_env_init >/dev/null 2>&1
	sleep 1
	__check_async >/dev/null 2>&1
	

	if [ -z "$api_token" ]; then
		return
	fi

	sleep 1

	if [ "$enabled" = "yes" ]; then
		local runcmd="$RICK_CLI_PATH/rick-cli -d $GWID -l $RICK_LOG_PATH -c $RICK_CONF_PATH $iface_param "
		$runcmd >/dev/null 2>&1 &
	fi

	return
}

wget_bin()
{
	if [ -e "$RICK_CLI_PATH/rick-cli" ]; then
		return
	fi
	while true; do
		if ikcheck ping 223.5.5.5 -C -c 3 >/dev/null 2>&1; then
			break
		fi
		if ikcheck ping www.baidu.com -C -c 3 >/dev/null 2>&1; then
			break
		fi
		sleep 5
	done

	local rick_arch=""
	if [ "$ARCH" = "x86" -a "$SYSBIT" = "x32" ]; then
		rick_arch="386"
	elif [ "$ARCH" = "x86" -a "$SYSBIT" = "x64" ]; then
		rick_arch="amd64"
	elif [ "$ARCH" = "arm" -a "$SYSBIT" = "x64" ]; then
		rick_arch="arm64"
	fi
	if [ -z "$rick_arch" ]; then
		return
	fi
		
	while true; do
		rm $RICK_TMP_CLI_PATH/rick-cli.tmp
		if wget -4 -S -q -t 5 -T 60 --connect-timeout=30 --dns-timeout=20 "https://wuying-assistant-ota.oss-cn-hangzhou.aliyuncs.com/rick-cli/latest/rick-cli-linux-$rick_arch" -O $RICK_TMP_CLI_PATH/rick-cli.tmp; then
			chmod 755 $RICK_TMP_CLI_PATH/rick-cli.tmp
			
			mv $RICK_TMP_CLI_PATH/rick-cli.tmp $RICK_TMP_CLI_PATH/rick-cli

			if ! cp $RICK_TMP_CLI_PATH/rick-cli $RICK_CLI_PATH; then
				rm $RICK_CLI_PATH/rick-cli
				ln -sf $RICK_TMP_CLI_PATH/rick-cli $RICK_CLI_PATH/rick-cli
			fi
			break
		fi
		sleep 5
	done

}

__parser_res()
{
	local filestatus="/tmp/iktmp/wuying_status"
	local check_res="$1"
	local code=$(echo $check_res| jq .code)
	if [ "$code" = "200" ] ;then
		local res_line=$(echo $check_res|jq -r .data.Line)	
		local res_comment=$(echo $check_res|jq -r .data.Comment)	
		local res_libver=$(echo $check_res|jq -r .data.Version)	
		echo "status=1 code=$code libver=$res_libver message=success" > ${filestatus}.$$
		local timestamp=$(date +%s)
		local token=$(sqlite3 $IK_DB_CONFIG "select api_token from wuying")
		if [ -z "$token" ]; then
			sqlite3 $IK_DB_CONFIG "update wuying set api_token='$GWID',comment='$res_comment',timestamp=$timestamp"
			restart_service >/dev/null 2>&1 &
		fi 
	else
		local message="$(echo $check_res|jq -r .message)"
		local message="${message// /%20}"
		echo "status=0 code=$code libver= message=$message " > ${filestatus}.$$
		if [ "$code" = "2100" ]; then
			killall rick-cli
			sqlite3 $IK_DB_CONFIG "update wuying set api_token='',comment='',timestamp=0"
		fi
	fi
	mv ${filestatus}.$$ $filestatus
}

__check_async()
{
	if $LOCKUP_NB ;then
		local $(sql_config_get_list $IK_DB_CONFIG "select * from wuying")

#		if [ -z "$api_token" ]; then
#			return
#		fi

		if [ -z "$interface" -o "$interface" = "auto" ]; then
			iface_param=""
		else
			iface_param="-i $interface"
		fi
		local checkcmd="$RICK_CLI_PATH/rick-cli -m check -d $GWID -l $RICK_LOG_PATH -c $RICK_CONF_PATH $iface_param"
		local check_res=$($checkcmd)
		if [ "$check_res" ]; then
			__parser_res "$check_res"
		fi
		$UNLOCK
	fi
}

check_async()
{
	__check_async >/dev/null 2>&1 &

}

__auto_gen_addr()
{
	for i in {20..200}; do
		local vipaddr="10.30.$i.0/24"
		if res=$(check_interface_addrpool "$vipaddr" "to_wuying"); then
			sqlite3 $IK_DB_CONFIG "update wuying set wan_addr='$vipaddr'"
			break
		fi
	done

	for i in {20..200}; do
		local vipaddr="10.31.$i.0/24"
		if res=$(check_interface_addrpool "$vipaddr" "to_wuying"); then
			sqlite3 $IK_DB_CONFIG "update wuying set lan_addr='$vipaddr'"
			break
		fi
	done

	for i in {20..200}; do
		local vipaddr="10.32.$i.0/24"
		if res=$(check_interface_addrpool "$vipaddr" "to_wuying"); then
			sqlite3 $IK_DB_CONFIG "update wuying set bind_wan_addr='$vipaddr'"
			break
		fi
	done

	for i in {20..200}; do
		local vipaddr="10.33.$i.0/24"
		if res=$(check_interface_addrpool "$vipaddr" "lan99"); then
			sqlite3 $IK_DB_CONFIG "update wuying set bind_lan_addr='$vipaddr'"
			break
		fi
	done
}

__get_wuying_addr()
{
        local addr="$1"
        if [ -z "$addr" ]; then
                return 0
        fi  

        local info=(${addr//\./ })
            
        local tmpaddr1="${info[0]}.${info[1]}.${info[2]}.1"
        local tmpaddr2="${info[0]}.${info[1]}.${info[2]}.2"

        echo "addr1="$tmpaddr1" addr2=$tmpaddr2"
        return 0
}

__create_wuying_wan()
{
	local i=99
	local interface=wan$i
	sqlite3 $IK_DB_CONFIG "insert into wan_config(id,name) values($i,'$interface');"

	brctl addbr $interface >/dev/null 2>&1
	ifconfig $interface up >/dev/null 2>&1
	iproute_ipt_rule_add $interface  >/dev/null 2>&1

	monitor_link_reset_all $interface
}

__create_wuying_lan()
{
	local i=99
	local interface=lan$i
	local bandif="$mac"
	local ip_mask="${veth7_addr}/255.255.255.0"

	sqlite3 $IK_DB_CONFIG "insert into lan_config(id,name,bandif,ip_mask,comment) values($i,'$interface','$bandif','$ip_mask','无影虚拟专线'); " >/dev/null 2>&1

	brctl addbr $interface >/dev/null 2>&1
	ifconfig $interface up >/dev/null 2>&1
	ip addr add ${veth7_addr}/24 dev lan99
	interface_get_name_to_cache_lan

	sql_config_get_list $IK_DB_CONFIG "select * from lan_config where id=99" |\
        while read config ;do
                local $config
                echo "$config" >$IK_DIR_CACHE/config/lan_config.lan$id.tmp
                mv $IK_DIR_CACHE/config/lan_config.lan$id.tmp $IK_DIR_CACHE/config/lan_config.lan$id
        done
}


__exec_from_env_init()
{
        local res=$(__get_wuying_addr $bind_wan_addr)
        if [ "$res" ]; then
                local $res
                veth4_addr=$addr1
                veth5_addr=$addr2
        fi

        local res=$(__get_wuying_addr $bind_lan_addr)
        if [ "$res" ]; then
                local $res
                veth6_addr=$addr2
                veth7_addr=$addr1
        fi

	ip netns add ns2
	ip link add veth$veth4_index type veth peer name veth$veth5_index
	ip link add veth$veth6_index type veth peer name veth$veth7_index
	local client_mac=$(cat /sys/class/net/veth${veth6_index}/address)

	sqlite3 $IK_DB_CONFIG "delete from mac_comment where comment='无影虚拟专线-回流'"
	/usr/ikuai/script/mac_comment.sh add mac=$client_mac comment=无影虚拟专线-回流 >/dev/null 2>&1

	ip link set veth${veth5_index} netns ns2
	ip link set veth${veth6_index} netns ns2

	local veth_mac=$(sqlite3 $IK_DB_CONFIG "select bandif from lan_config where id=99")
	if [ "$veth_mac" ]; then
		ip link set dev veth${veth7_index} address $veth_mac up
	else
		ip link set veth${veth7_index} up
	fi
	
	local lan_index=99
	local lan_exist=0
	if [ "$veth_mac" ]; then
		lan_exist=1
	fi

	local mac=$(cat /sys/class/net/veth${veth7_index}/address)
	if [ "$lan_exist" = "0" ]; then
		__create_wuying_lan
		ip link set veth${veth7_index} up
		ip addr add ${veth7_addr}/24 dev lan99
	fi
	ip link set lan99 up
	brctl addif lan99 veth${veth7_index}
	
	ip netns exec ns2 ip addr add ${veth5_addr}/24 dev veth${veth5_index}
	ip netns exec ns2 ip addr add ${veth6_addr}/24 dev veth${veth6_index}
	ip netns exec ns2 ip link set veth${veth5_index} up
	ip netns exec ns2 ip link set veth${veth6_index} up	

	ip netns exec ns2 ip route add default via ${veth7_addr} dev veth${veth6_index}
	ip netns exec ns2 iptables -t nat -A POSTROUTING -o veth${veth6_index} -j MASQUERADE
	ip netns exec ns2 iptables -t nat -A PREROUTING -d ${veth6_addr}/32 -i veth${veth5_index} -m conntrack --ctstate NEW -m addrtype --dst-type LOCAL -j NETMAP --to ${veth7_addr}/32

	echo "veth${veth7_index} $mac viface wuying Virtual Bridge Enternet Controller" >> $IK_DIR_CACHE/ether_info

	brctl addbr from_wuying
	brctl addif from_wuying veth${veth4_index}
	ip link set veth${veth4_index} up
	ip addr add ${veth4_addr}/24 dev from_wuying
	ip link set from_wuying up
	
	local markid=$(iproute_get_markid from_wuying)
	ip  route add default via $veth5_addr dev from_wuying metric 99	
	ip  route add default via $veth5_addr dev from_wuying table from_wuying metric 50

}

__exec_to_env_init()
{
        local res=$(__get_wuying_addr $wan_addr)
        if [ "$res" ]; then
                local $res
                veth0_addr=$addr1
                veth1_addr=$addr2
        fi

        local res=$(__get_wuying_addr $lan_addr)
        if [ "$res" ]; then
                local $res
                veth2_addr=$addr2
                veth3_addr=$addr1
        fi

	ip netns add ns1
	ip link add veth$veth0_index type veth peer name veth$veth1_index
	ip link add veth$veth2_index type veth peer name veth$veth3_index

	ip link set veth${veth1_index} netns ns1
	ip link set veth${veth2_index} netns ns1

#	ip addr add 192.168.198.1/24 dev veth$veth0_index
	local veth_mac=$(sqlite3 $IK_DB_CONFIG "select bandif from wan_config where id=99")
	if [ "$veth_mac" ]; then
		ip link set dev veth${veth0_index} address $veth_mac up
	else
		ip link set veth${veth0_index} up
	fi
#	ip addr add 192.168.199.1/24 dev veth${veth3_index}
	ip link set veth${veth3_index} up
	brctl addbr to_wuying
	brctl addif to_wuying veth${veth3_index}
	ip addr add ${veth3_addr}/24 dev to_wuying
	ip link set to_wuying up
	
	ip netns exec ns1 ip addr add ${veth1_addr}/24 dev veth${veth1_index}
	ip netns exec ns1 ip addr add ${veth2_addr}/24 dev veth${veth2_index}
	ip netns exec ns1 ip link set veth${veth1_index} up
	ip netns exec ns1 ip link set veth${veth2_index} up	

	ip netns exec ns1 ip route add default via ${veth3_addr} dev veth${veth2_index}
	ip netns exec ns1 iptables -t nat -A POSTROUTING -o veth${veth2_index} -j MASQUERADE

	local wan_exist=0
	local wan_index=99
	if [ "$veth_mac" ]; then
		wan_exist=1
	fi
	local mac=$(cat /sys/class/net/veth${veth0_index}/address)
	echo "veth${veth0_index} $mac viface wuying Virtual Bridge Enternet Controller" >> $IK_DIR_CACHE/ether_info

	if [ "$wan_exist" = "0" ]; then
		local wan_index=99
		__create_wuying_wan
		sqlite3 $IK_DB_CONFIG "update wan_config set internet=0,ip_mask='${veth0_addr}/255.255.255.0',gateway='${veth1_addr}',check_link_mode=5,check_link_host='${veth1_addr}',comment='无影虚拟专线' where id=$wan_index"

		$IK_DIR_SCRIPT/wan.sh add_band id=$wan_index bandif=$mac >/dev/null 2>&1
	else
		brctl addif wan${wan_index} veth${veth0_index}
	fi

	local markid=$(iproute_get_markid wuying)
	ip route add local 0.0.0.0/0 dev lo table wuying

	__exec_enable_to_wuying >/dev/null 2>&1

	echo "ethname=veth${veth0_index} mac=$mac wan_ifname=wan${wan_index} fwmark=$markid" > /tmp/iktmp/wuying.config
	sqlite3 $IK_DB_CONFIG "update wuying set veth_mac='$mac'"

}

__exec_env_init()
{

	if [ -e "/tmp/iktmp/wuying.config" ]; then
		return
	fi
	__auto_gen_addr

	local $(sql_config_get_list $IK_DB_CONFIG "select bind_lan_addr,bind_wan_addr,lan_addr,wan_addr from wuying")
	> /tmp/iktmp/wuying.config
	local veth0_index=0
	local veth1_index=1
	local veth2_index=2
	local veth3_index=3
	local veth4_index=4
	local veth5_index=5
	local veth6_index=6
	local veth7_index=7
	if [ "$EMBED_ETHNUM" ]; then
		local veth0_index=$((EMBED_ETHNUM+1))
		local veth1_index=$((EMBED_ETHNUM+2))
		local veth2_index=$((EMBED_ETHNUM+3))
		local veth3_index=$((EMBED_ETHNUM+4))
		local veth4_index=$((EMBED_ETHNUM+5))
		local veth5_index=$((EMBED_ETHNUM+6))
		local veth6_index=$((EMBED_ETHNUM+7))
		local veth7_index=$((EMBED_ETHNUM+8))
	fi

        local veth0_addr="10.30.20.1"
        local veth1_addr="10.30.20.2"
        local veth2_addr="10.31.20.2"
        local veth3_addr="10.31.20.1"
        local veth4_addr="10.32.20.1"
        local veth5_addr="10.32.20.2"
        local veth6_addr="10.33.20.2"
        local veth7_addr="10.34.20.1"
	
	__exec_to_env_init
	__exec_from_env_init

}

__exec_env_lan_init()
{

	if [ -e "/tmp/iktmp/wuying.config" ]; then
		return
	fi
	__auto_gen_addr

	local $(sql_config_get_list $IK_DB_CONFIG "select lan_addr,wan_addr from wuying")
	> /tmp/iktmp/wuying.config
	local veth0_index=0
	local veth1_index=1
	local veth2_index=2
	local veth3_index=3
	if [ "$EMBED_ETHNUM" ]; then
		local veth0_index=$((EMBED_ETHNUM+1))
		local veth1_index=$((EMBED_ETHNUM+2))
		local veth2_index=$((EMBED_ETHNUM+3))
		local veth3_index=$((EMBED_ETHNUM+4))
	fi

        local veth0_addr="10.30.20.1"
        local veth1_addr="10.30.20.2"
        local veth2_addr="10.31.20.2"
        local veth3_addr="10.31.20.1"

        local res=$(__get_wuying_addr $wan_addr)
        if [ "$res" ]; then
                local $res
                veth0_addr=$addr1
                veth1_addr=$addr2
        fi

        local res=$(__get_wuying_addr $lan_addr)
        if [ "$res" ]; then
                local $res
                veth2_addr=$addr2
                veth3_addr=$addr1
        fi

	ip netns add ns1
	ip link add veth$veth0_index type veth peer name veth$veth1_index
	ip link add veth$veth2_index type veth peer name veth$veth3_index

	ip link set veth${veth1_index} netns ns1
	ip link set veth${veth2_index} netns ns1

#	ip addr add 192.168.198.1/24 dev veth$veth0_index
	local veth_mac=$(sqlite3 $IK_DB_CONFIG "select bandif from wan_config where id=99")
	if [ "$veth_mac" ]; then
		ip link set dev veth${veth0_index} address $veth_mac up
	else
		ip link set veth${veth0_index} up
	fi
#	ip addr add 192.168.199.1/24 dev veth${veth3_index}
	ip link set veth${veth3_index} up
	brctl addbr to_wuying
	brctl addif to_wuying veth${veth3_index}
	ip addr add ${veth3_addr}/24 dev to_wuying
	ip link set to_wuying up
	
	ip netns exec ns1 ip addr add ${veth1_addr}/24 dev veth${veth1_index}
	ip netns exec ns1 ip addr add ${veth2_addr}/24 dev veth${veth2_index}
	ip netns exec ns1 ip link set veth${veth1_index} up
	ip netns exec ns1 ip link set veth${veth2_index} up	

	ip netns exec ns1 ip route add default via ${veth3_addr} dev veth${veth2_index}
	ip netns exec ns1 iptables -t nat -A POSTROUTING -o veth${veth2_index} -j MASQUERADE

	local wan_exist=0
	local wan_index=99
	if [ "$veth_mac" ]; then
		wan_exist=1
	fi
	local mac=$(cat /sys/class/net/veth${veth0_index}/address)
	echo "veth${veth0_index} $mac viface wuying Virtual Bridge Enternet Controller" >> $IK_DIR_CACHE/ether_info

	if [ "$wan_exist" = "0" ]; then
		local wan_index=99
		__create_wuying_wan
		sqlite3 $IK_DB_CONFIG "update wan_config set internet=0,ip_mask='${veth0_addr}/255.255.255.0',gateway='${veth1_addr}',check_link_mode=5,check_link_host='${veth1_addr}',comment='无影虚拟专线' where id=$wan_index"

		$IK_DIR_SCRIPT/wan.sh add_band id=$wan_index bandif=$mac >/dev/null 2>&1
	else
		brctl addif wan${wan_index} veth${veth0_index}
	fi

	local markid=$(iproute_get_markid wuying)
	ip route add local 0.0.0.0/0 dev lo table wuying

	__exec_enable_to_wuying >/dev/null 2>&1

	echo "ethname=veth${veth0_index} mac=$mac wan_ifname=wan${wan_index} fwmark=$markid" > /tmp/iktmp/wuying.config
	sqlite3 $IK_DB_CONFIG "update wuying set veth_mac='$mac'"
}


__exec_env_uninit()
{
	killall rick-cli
	local $(cat /tmp/iktmp/wuying.config)
	ip netns del ns1
	ip netns del ns2
	ip link del to_wuying
	ip link del from_wuying

	local bandif=$(sqlite3 $IK_DB_CONFIG "select bandif from lan_config where id=99")
	if [ "$bandif" ]; then
		sed -i "/$bandif/d" /tmp/iktmp/cache/ether_info
	fi

	local bandif=$(sqlite3 $IK_DB_CONFIG "select bandif from wan_config where id=99")
	if [ "$bandif" ]; then
		sed -i "/$bandif/d" /tmp/iktmp/cache/ether_info
	fi


	local wan_index=$(sqlite3 $IK_DB_CONFIG "select id from wan_config where id=99")
	if [ "$wan_index" ]; then
		$IK_DIR_SCRIPT/wan.sh del_band id=$wan_index >/dev/null 2>&1
		$IK_DIR_SCRIPT/wan.sh delete id=$wan_index >/dev/null 2>&1
	fi

	local lan_index=$(sqlite3 $IK_DB_CONFIG "select id from lan_config where id=99")
	if [ "$lan_index" ]; then
		$IK_DIR_SCRIPT/lan.sh del_band id=$lan_index >/dev/null 2>&1
		$IK_DIR_SCRIPT/lan.sh delete id=$lan_index >/dev/null 2>&1
	fi

	$IK_DIR_SCRIPT/wan.sh __delete_config_to_cache 99 >/dev/null 2>&1
	$IK_DIR_SCRIPT/lan.sh __delete_config_to_cache 99 >/dev/null 2>&1

	__exec_disable_to_wuying

	sqlite3 $IK_DB_CONFIG "update wuying set api_token='',comment='',timestamp=0"
	rm /tmp/iktmp/wuying.config
}


__exec_enable_to_wuying()
{
	local markid=$(iproute_get_markid wuying)
	iptables -t mangle -N Morty
	iptables -t mangle -F Morty
	iptables -t mangle -D PREROUTING -i to_wuying -j Morty
	
	iptables -t mangle -A PREROUTING -i to_wuying -j Morty
	iptables -t mangle -A Morty -i to_wuying -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port 2004 --tproxy-mark $markid
	iptables -t mangle -A Morty -i to_wuying -p udp -j TPROXY --on-ip 127.0.0.1 --on-port 2004 --tproxy-mark $markid
}

__exec_disable_to_wuying()
{
	iptables -t mangle -F Morty
	iptables -t mangle -D PREROUTING -i to_wuying -j Morty
	iptables -t mangle -X Morty
}

__exec_rule_init()
{
	if [ -z "$interface" -o "$interface" = "auto" ]; then
		iface_param=""
	else
		iface_param="-i $interface"
	fi
	local comment="$(url_decode $comment)"
	local nodestr="cn-hangzhou"
	if [ "$node" = "1" ]; then
		nodestr="ap-southeast-1"	
	fi
	
	local bindstr="$comment|$interface|$api_token|$nodestr"

	local cmd="$RICK_CLI_PATH/rick-cli -m bind -d $GWID -l $RICK_LOG_PATH -c $RICK_CONF_PATH $iface_param -b \"$bindstr\""
	local runcmd="$RICK_CLI_PATH/rick-cli -d $GWID -l $RICK_LOG_PATH -c $RICK_CONF_PATH $iface_param "
	
	if json_res=$($RICK_CLI_PATH/rick-cli -m bind -d $GWID -l $RICK_LOG_PATH -c $RICK_CONF_PATH $iface_param -b "$bindstr"); then
		local code=$(echo $json_res| jq .code)
		if [ "$code" = "200" ] ;then
			killall rick-cli
			$runcmd >/dev/null 2>&1 &
			__exec_env_init >/dev/null 2>&1 &
			return 0
		else
			local errmsg=$(echo $json_res| jq -r .message)
			echo "$errmsg"
			return 1
		fi
	fi
	echo "Network failure: No response received"	
	return 1
}

restart_service()
{
	killall rick-cli
	local $(sql_config_get_list $IK_DB_CONFIG "select * from wuying")
	if [ -z "$interface" -o "$interface" = "auto" ]; then
		iface_param=""
	else
		iface_param="-i $interface"
	fi
	
	local runcmd="$RICK_CLI_PATH/rick-cli -d $GWID -l $RICK_LOG_PATH -c $RICK_CONF_PATH $iface_param "
	$runcmd >/dev/null 2>&1 &
	
	check_async
}

stop()
{
	sqlite3 $IK_DB_CONFIG "update wuying set enabled='no'"
	killall rick-cli
	__exec_disable_to_wuying
}

start()
{
	sqlite3 $IK_DB_CONFIG "update wuying set enabled='yes'"
	restart_service >/dev/null 2>&1

	__exec_enable_to_wuying
}

__check_addr_param()
{
	if [ "$wan_addr" ]; then
		if ! res=$(check_interface_addrpool "$wan_addr" "to_wuying"); then
			Autoiecho param addr_pool_conflict "$res"
			return 1
		fi
	fi

	if [ "$lan_addr" ]; then
		if ! res=$(check_interface_addrpool "$lan_addr" "to_wuying"); then
			Autoiecho param addr_pool_conflict "$res"
			return 1
		fi
	fi
	return 0
}

save()
{
#	__check_addr_param || exit 1

	local $(sql_config_get_list $IK_DB_CONFIG "select * from wuying" prefix=old_)

	local timestamp=$(date +%s)
	local enabled=${enabled:-yes}
	local interface="from_wuying"
	local sql_param="enabled:str timestamp:int api_token:str node:int comment:str interface:str"
	if SqlMsg=$(sql_config_update $IK_DB_CONFIG wuying "id=1" $sql_param) ;then
#                if ! NewOldVarl lan_addr wan_addr; then
#                        __exec_env_uninit
#                        __exec_env_init
#                fi
		if ! res=$(__exec_rule_init); then
			echo "$res"
			sqlite3 $IK_DB_CONFIG "update wuying set api_token='',comment='',timestamp=0"
			return 1
		fi
		echo "status=1 code=200 libver=1.0.0.1 message=success" > /tmp/iktmp/wuying_status
		(sleep 2; __check_async) >/dev/null 2>&1 &
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi
}

__implant_code()
{
cat -<<EOF
	local errno
	local code
	local message
	local libver
	local pstatus=0
	local f = io.open("/tmp/iktmp/wuying_status")
	if f then
		for line in f:lines() do
			errno, code, libver, message = line:match("^status=([^ ]*) code=([^ ]*) libver=([^ ]*) message=(.*)")
		end
		f:close()
	end

	local f = io.open("/tmp/iktmp/wuying_process_status")
	if f then
		pstatus = f:read("*l")
		f:close()
	end
	if message then
		message = string.gsub(message, "%%20", " ")
	end

	ikdb:create_function('errno',1,
		function (ctx, id)
			if tonumber(pstatus) == 1 and tonumber(errno) == 0 then
				pstatus=0
			end	
			ctx:result_int(tonumber(pstatus) or 0) 
		end
	)
	ikdb:create_function('libver',1,
		function (ctx, id)
			ctx:result_text(libver or '') 
		end
	)
	ikdb:create_function('message',1,
		function (ctx, id)
			ctx:result_text(message or '') 
		end
	)
	ikdb:create_function('tocloud',1,
		function (ctx, id)
			ctx:result_int(1) 
		end
	)
EOF
}

EXPORT()
{
	if [ -e "$RICK_LOG_PATH" ]; then
		cd /tmp/iktmp/wuying
		tar -czvf wuying.tar.gz logs >/dev/null 2>&1
		cp wuying.tar.gz $IK_DIR_EXPORT/
	else
		touch $IK_DIR_EXPORT/wuying.tar.gz
	fi
	echo "wuying.tar.gz"
	return 0
}


show()
{
	Show __json_result__
}

__show_data() {

	local res=$(pidof morty-cli)
	if [ "$res" ]; then
		echo "1" > /tmp/iktmp/wuying_process_status
	else
		echo "0" > /tmp/iktmp/wuying_process_status
	fi
	check_async >/dev/null 2>&1

	local routeid=$GWID

	local __sql_implant_code__=$(__implant_code)
	local sql_show="select *,errno(id) status,libver(id) libver,message(id) message,tocloud(id) tocloud from wuying"
	local data=$(sql_config_get_json $IK_DB_CONFIG "$sql_show")

	json_append __json_result__ data:json routeid:str
}

__show_interface()
{
	local interface=$(interface_get_ifname_comment_json wan,vpn auto)
	json_append __json_result__ interface:json
}

#ip= proto= maxnum= wan_ifname=
__show_conn() {
	local $(cat /tmp/iktmp/wuying.config) 2>/dev/null

	if [ "$wan_ifname" ]; then
		local interface=$wan_ifname
	else
		local conn="[]"
		json_append __json_result__ conn:json
		return 0
	fi


	json='{"protocol":"%s","status":"%s","dst_addr":"%s","src_addr":"%s","src_port":%s,"dst_port":%s,"forward_addr":"%s","app_name":"%s","interface":"%s","total_up":%s,"total_down":%s}'
	if [ -e "/tmp/iktmp/LANG/1" ];then
		proto_list="/tmp/iktmp/cache/appid_cn.txt"
		language="cn"
	else
		proto_list="/tmp/iktmp/cache/appid_en.txt"
		language="en"
	fi
	local PROTO
	if [ "$proto" -a "$proto" != "all" ]; then
		PROTO="-p $proto" 
	fi
	
	if [[ "$interface" =~ ^(wan|vwan|adsl) ]]; then
		local routeid=$(iproute_get_markid $interface)
		local MARK="-m $routeid"
	fi

	if [ "$maxnum" ]; then
		local MAXNUM="-k $maxnum"
	else
		local MAXNUM="-k 500"
	fi

	if [ "$ip" ]; then
		local src_param="-s $ip"
	fi


	conn=$(echo -n "["
	conntrack -L $src_param $PROTO $MARK $MAXNUM 2>/dev/null |gawk -v ip=$ip  -v interface="$interface" -v json="$json" -v proto_list="$proto_list" -v language="$language" '
	BEGIN {
		if(language=="cn"){
			status["SYN_SENT"]="请求连接"
			status["FIN_WAIT"]="回复等待"
			status["ESTABLISHED"]="已连接"
			status["TIME_WAIT"]="等待"
			status["CLOSE"]="关闭连接"
			status["CLOSE_WAIT"]="关闭连接"
		}else{
			status["SYN_SENT"]="SYN_SENT"
			status["FIN_WAIT"]="FIN_WAIT"
			status["ESTABLISHED"]="ESTABLISHED"
			status["TIME_WAIT"]="TIME_WAIT"
			status["CLOSE"]="CLOSE"
			status["CLOSE_WAIT"]="CLOSE_WAIT"
		}
		while(getline<proto_list)appid_name[$2]=$1
	}
	{
		orig_srcip="--"; orig_dstip="--"; orig_sport=0; orig_dport=0; orig_packets="--"; orig_bytes="--"
		reply_srcip="--"; reply_dstip="--"; reply_sport=0; reply_dport=0; reply_packets="--"; reply_bytes="--"
		orig_type="--"; orig_code="--"; orig_id="--"; reply_type="--"; reply_code="--"; reply_id="--"
		orig_srckey="--"; orig_dstkey="--"; reply__srckey="--"; reply__dstkey="--"
		app_name="--"; remote_if="--"

		proto=$1
		timeout=$3
		if(proto=="tcp"){
			stat=status[$4]
		} else {
			stat="--"
		}
		
		if(proto=="tcp" || proto=="udp"){
			match($0,"src=([0-9\\.]+) dst=([0-9\\.]+) sport=([0-9]+) dport=([0-9]+) packets=([0-9]+) bytes=([0-9]+).* src=([0-9\\.]+) dst=([0-9\\.]+) sport=([0-9]+) dport=([0-9]+) packets=([0-9]+) bytes=([0-9]+).* appid=([0-9]+)",conntrack)
			match($0,"remote_if=([^ ]+)",ifname)
			orig_srcip=conntrack[1]
			orig_dstip=conntrack[2]
			orig_sport=conntrack[3]
			orig_dport=conntrack[4]
			orig_packets=conntrack[5]
			orig_bytes=conntrack[6]
			reply_srcip=conntrack[7]
			reply_dstip=conntrack[8]
			reply_sport=conntrack[9]
			reply_dport=conntrack[10]
			reply_packets=conntrack[11]
			reply_bytes=conntrack[12]
			app_name=appid_name[conntrack[13]]
			remote_if=ifname[1]
		} else {
			next
		}

		if(!orig_srcip)
			next

		if(match(remote_if, /^wan[0-9]+_ad$/)){
			remote_if=substr(remote_if,0,length(remote_if)-3)
		}
		if(interface && remote_if!=interface)
			next

		if(n++>0)printf ","
		printf json,proto,stat,orig_dstip,orig_srcip,orig_sport,orig_dport,reply_dstip,app_name,remote_if,orig_bytes,reply_bytes
		#print proto,timeout,stat,orig_srcip,orig_dstip,orig_sport,orig_dport,orig_packets,orig_bytes,reply_srcip,reply_dstip,reply_sport,reply_dport,reply_packets,reply_bytes,app_name
	}'
	echo "]")
	json_append __json_result__ conn:json
}

