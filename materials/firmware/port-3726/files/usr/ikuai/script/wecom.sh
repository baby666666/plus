#!/bin/bash /etc/ikcommon

Include sys/sysstat.sh, interface.sh, ifether.sh
Include version_all.sh, appbind.sh, urlcode.sh

WECOM_DIR="/tmp/iktmp/cache/wecom"
WECOM_STATUS="$WECOM_DIR/is_bind"
WECOM_ENABLE="$WECOM_DIR/is_enable"
WECOM_CONFIG="/etc/mnt/ikuai/wecom.db"

WECOM_SSID_CONF="$WECOM_DIR/default_ssid"
WECOM_CACHE_CONF="$WECOM_DIR/config"

#DEV_TYPE=3 云AP   DEV_TYPE=1 AC
[ "$MIPS_WIFI_SUPPORT_2G" ] && DEV_TYPE=3 || DEV_TYPE=1

boot()
{
	mkdir -p $WECOM_DIR
	ipset -N Linux_blockmac_default hash:mac
	init
}

init()
{
	local res=$(sql_config_get_list $WECOM_CONFIG "select * from wecom")
	if [ -z "$res" ]; then
		return
	fi
	local $res

	## 自动解绑无效的sn,  存在恢复其他的配置导致gwid不同，sn相同
	local tmp_sn="$(__gen_sn)"
	if [ "$sn" -a "$tmp_sn" != "$sn" ]; then
		uninitialize	
		return
	fi
	

	if [ "$staff_wlan_enable" != "yes" ]; then
		if [ "$OEMNAME" = "wecom" ]; then
			$IK_DIR_SCRIPT/wifi.sh down >/dev/null 2>&1 & 
			$IK_DIR_SCRIPT/ac_status.sh seting ac_server=0 >/dev/null 2>&1 &
		fi
		return	
	fi

	ipset -F Linux_blockmac_default

	touch $WECOM_ENABLE
	echo 1 > $WECOM_STATUS

	__start
}

updatedb()
{
	##之前版本配置重置 企业微信上线 SN需要改变，以前测试用的SN 不可用
	if [ "$old_sysver" -lt 300050007 ];then
		local enable="no"
		local staff_wlan_enable="no"
		local guest_wlan_enable="no"
		local guest_psk_enable="no"
		local qr="" sn=""
		local staff_ssid="" guest_ssid="" guest_passwd="" guest_psk=""
		local sql_param="enable:str sn:str qr:str staff_wlan_enable:str guest_wlan_enable:str guest_psk_enable:str "
		sql_param+="staff_ssid:str guest_ssid:str guest_passwd:str guest_psk:str"

		sql_config_update $WECOM_CONFIG wecom "id=1" $sql_param
	fi
}

show() {
        Show __json_result__
}

__check_is_bind()
{
	if [ -e "$WECOM_STATUS" ]; then
		return 0
	fi
	return 1
}

__phy_iface_get()
{
	local phy_info
	local data data_one stat
	
	while read eth mac driver model;do
		if [ "${eth:0:3}" != "eth" -a "${eth:0:4}" != "veth" ]; then
			continue
		fi
		local res=($(ether_get_work_status $eth))
		local name=$eth enable=${res[0]} status=${res[1]} max_bit_rate=${res[2]} duplex_mode=${res[3]} interface=${res[4]}
		local alias=$name
		if [ "$enable" = "1" ]; then
			enable="true"
		else
			enable="false"
		fi
		if [ "$status" = "1" ]; then
			status="Up"
		else
			status="Down"
		fi
		if [ "$duplex_mode" = "1" ]; then
			duplex_mode="Duplex"
		else
			duplex_mode="Auto"
		fi
		local mac_address=${mac^^}

		local phy_name="${name}:"
		local res=$(awk -v name="$phy_name" '{if($1==name){print "bytes_received="$2,"packets_received="$3, "bytes_sent="$10,"packets_sent="$11;exit}}' /proc/net/dev) 
		if [ "$res" ]; then
			local $res
		fi
		local stats=$(json_output bytes_sent:int packets_sent:int bytes_received:int packets_received:int)

		data_one=$(json_output name:str enable:bool status:str duplex_mode:str max_bit_rate:int mac_address:str alias:str stats:json)
		if [ "${eth:0:4}" = "veth" ]; then
			local index=${name//veth}
			local data+="${data:+,}\"$index\":$data_one"
		elif [ "${eth:0:3}" = "eth" ]; then
			local index=${name//eth}
			local index=$((index+1))
			local data+="${data:+,}\"$index\":$data_one"
		fi
	done < $IK_DIR_CACHE/ether_info
	echo "{$data}"
}

__br_iface_get()
{
	local data
	local tmpfile=$(interface_get_ifname "lan,wan_phy" "" "true")
	while read name comment; do
		local x_ethernet_members
		local ifindex=$(cat /sys/class/net/$name/ifindex)
		local default_route=$(cat /tmp/iktmp/cache/default_route 2>/dev/null)
		local x_default_gateway="false"
		if [ "${name:0:3}" = "wan" ]; then
			local x_type="br-wan"
		else
			local x_type="br-lan"
		fi
		if [ "$default_route" = "$name" ]; then
			local x_default_gateway="true"
		fi
		local alias="$name"
		local x_comment="$comment" 
		local res=$(awk -v ifname="$name" '{if($1==ifname){print "bps_sent="$2*1000,"bps_recevied="$3*1000;exit}}' /tmp/iktmp/monitor-ikstat/iface)
		if [ "$res" ]; then
			local $res
		fi
		local members=""
		for eth in $(ls /sys/class/net/$name/brif 2>/dev/null); do
			if [ "${eth:0:4}" = "veth" ]; then
				local index=${eth//veth}
				members+="${members:+,}\"Device.Ethernet.Interface.$index\""	
			elif [ "${eth:0:3}" = "eth" ]; then
				local index=${eth//eth}
				local index=$((index+1))
				members+="${members:+,}\"Device.Ethernet.Interface.$index\""	
			fi
		done
		x_ethernet_members="[$members]"
		local data_one=$(json_output x_type:str x_default_gateway:bool x_comment:str name:str alias:str bps_sent:int bps_recevied:int x_ethernet_members:json)
	
		local data+="${data:+,}\"$ifindex\":$data_one"
	done <<EOF
	$tmpfile
EOF
	echo "{$data}"
}

__network_iface_get()
{
	local data
	
	local tmpfile=$(interface_get_ifname "lan" "" "true")
	while read name comment; do
		local ifindex=$(cat /sys/class/net/$name/ifindex)
		local $(cat /tmp/iktmp/cache/config/lan_config.$name 2>/dev/null)
		if [ "$bandif" != "" ]; then
			local enable="true"
		fi
		local max_mtu_size=$(cat /sys/class/net/$name/mtu 2>/dev/null)
		local res=$(ls /sys/class/net/$name/brif 2>/dev/null)
		if [ "$res" ]; then
			local status="Up"
		else
			local status="Down"
		fi
		local lower_layers="Device.Bridging.Bridge.$ifindex"

		local index=0
		local addr=""
		for ip_mask_one in ${ip_mask//,/ }; do
			local ip_address="${ip_mask_one%%/*}"
			local subnet_mask="${ip_mask_one##*/}"
			local addressing_type="Static"
			index=$((index+1))
			local addr_one=$(json_output ip_address:str subnet_mask:str addressing_type:str)
			local addr+="${addr:+,}\"$index\":$addr_one"
		done
		local ipv4_address="{$addr}"

		local data_one=$(json_output enable:bool status:str lower_layers:str max_mtu_size:int ipv4_address:json)
		local data+="${data:+,}\"$ifindex\":$data_one"
	done <<EOF
	$tmpfile
EOF

	declare -A IFACE_SET
	local index=0
	local tmpfile=$(interface_get_ifname "wan" "" "true")
	while read name comment; do
		if [ "${name:0:3}" = "wan" ]; then
			local $(cat /tmp/iktmp/cache/config/wan_config.$name 2>/dev/null)

			local ifindex=$(cat /sys/class/net/$name/ifindex)
			local lower_layers="Device.Bridging.Bridge.$ifindex"
			if [ "$bandif" != "" ]; then
				local enable="true"
			fi
			local addr=""
			if [ "$internet" = "$INTERNET_STATIC" ]; then
				if [ "$ip_mask" ]; then
					local status="Up"
					local ip_mask=${ip_mask//,*}	
					local ip_address="${ip_mask%%/*}"
					local subnet_mask="${ip_mask##*/}"
					local addressing_type="Static"
					local index=1
					local addr_one=$(json_output ip_address:str subnet_mask:str addressing_type:str)
					local addr+="${addr:+,}\"$index\":$addr_one"
				else
					local addr=""
					local status="Down"
				fi

				local ipv4_address="{$addr}"
			
			elif [ "$internet" = "$INTERNET_DHCP" ]; then
				if [ -e "/tmp/iktmp/dhcpc/$name" ]; then
					local status="Up"
					local $(cat /tmp/iktmp/dhcpc/$name 2>/dev/null)

					local ip_address="$dhcp_ip_addr"
					local subnet_mask="$dhcp_netmask"
					local addressing_type="Dhcp"
					local index=1
					local addr_one=$(json_output ip_address:str subnet_mask:str addressing_type:str)
					local addr+="${addr:+,}\"$index\":$addr_one"
				else
					local addr=""
					local status="Down"
				fi
				local ipv4_address="{$addr}"

			elif [ "$internet" = "$INTERNET_PPPOE" ]; then
				if [ -e "/tmp/iktmp/pppoe/$name" ]; then
					local status="Up"	
					local $(cat /tmp/iktmp/pppoe/$name 2>/dev/null)
					local ip_address="$pppoe_ip_addr"
					local subnet_mask="$pppoe_netmask"
					local addressing_type="Pppoe"
					local index=1
					local addr_one=$(json_output ip_address:str subnet_mask:str addressing_type:str)
					local addr+="${addr:+,}\"$index\":$addr_one"
					name="${name}_ad"
				else
					local addr=""
					local enable="false"
					local status="Down"
				fi
				local ipv4_address="{$addr}"
			fi
			local max_mtu_size=$(cat /sys/class/net/$name/mtu 2>/dev/null)
			local data_one=$(json_output enable:bool status:str lower_layers:str max_mtu_size:int ipv4_address:json)
			local data+="${data:+,}\"$ifindex\":$data_one"
		elif [ "${name:0:4}" = "vwan" ]; then
			local $(cat /tmp/iktmp/cache/config/wan_vlan.$name 2>/dev/null)
			
			if [ "${IFACE_SET[$interface]}" = "1" ]; then
				continue
			fi

			local ifindex=$(cat /sys/class/net/$interface/ifindex)
			local lower_layers="Device.Bridging.Bridge.$ifindex"
			local addr=""
			if [ "$vlan_internet" = "$INTERNET_STATIC" ]; then
				if [ "$ip_mask" ]; then
					local enable="true"
					local status="Up"
					local ip_mask=${ip_mask//,*}	
					local ip_address="${ip_mask%%/*}"
					local subnet_mask="${ip_mask##*/}"
					local addressing_type="Static"
					local index2=1
					local addr_one=$(json_output ip_address:str subnet_mask:str addressing_type:str)
					local addr+="${addr:+,}\"$index2\":$addr_one"

					IFACE_SET[$interface]=1
				else
					local addr=""
					local status="Down"
					local enable="false"
				fi

				local ipv4_address="{$addr}"
			
			elif [ "$vlan_internet" = "$INTERNET_DHCP" ]; then
				if [ -e "/tmp/iktmp/dhcpc/$name" ]; then
					local enable="true"
					local status="Up"
					local $(cat /tmp/iktmp/dhcpc/$name 2>/dev/null)

					local ip_address="$dhcp_ip_addr"
					local subnet_mask="$dhcp_netmask"
					local addressing_type="Dhcp"
					local index2=1
					local addr_one=$(json_output ip_address:str subnet_mask:str addressing_type:str)
					local addr+="${addr:+,}\"$index2\":$addr_one"
					IFACE_SET[$interface]=1
				else
					local addr=""
					local status="Down"
					local enable="false"
				fi
				local ipv4_address="{$addr}"
			fi
			local max_mtu_size=$(cat /sys/class/net/$name/mtu 2>/dev/null)
			local data_one=$(json_output enable:bool status:str lower_layers:str max_mtu_size:int ipv4_address:json)
			local data+="${data:+,}\"$ifindex\":$data_one"

		elif [ "${name:0:3}" = "ads" ]; then
			local $(cat /tmp/iktmp/cache/config/wan_vlan.$name 2>/dev/null)

			if [ "${IFACE_SET[$interface]}" = "1" ]; then
				continue
			fi

			local ifindex=$(cat /sys/class/net/$interface/ifindex)
			local lower_layers="Device.Bridging.Bridge.$ifindex"
			local addr=""
			if [ -e "/tmp/iktmp/pppoe/$name" ]; then
				local $(cat /tmp/iktmp/pppoe/$name 2>/dev/null)
				local ip_address="$pppoe_ip_addr"
				local subnet_mask="$pppoe_netmask"
				local addressing_type="Pppoe"
				local index3=1
				local addr_one=$(json_output ip_address:str subnet_mask:str addressing_type:str)
				local addr+="${addr:+,}\"$index3\":$addr_one"
				
				local max_mtu_size=$(cat /sys/class/net/$name/mtu 2>/dev/null)
				local enable="true"
				local status="Up"
				IFACE_SET[$interface]=1
			else
				local addr=""
				local enable="false"
				local status="Down"
			fi
			local ipv4_address="{$addr}"
			local data_one=$(json_output enable:bool status:str lower_layers:str max_mtu_size:int ipv4_address:json)
			local data+="${data:+,}\"$ifindex\":$data_one"

		fi
	done <<EOF
	$tmpfile
EOF
	unset IFACE_SET
	echo "{$data}"
}

__iface_info_get()
{
	local layer1=$(__phy_iface_get)
	local layer2=$(__br_iface_get)
	local layer3=$(__network_iface_get)
	local res=$(json_output layer1:json layer2:json layer3:json)
	echo $res
}

__dns_info_get()
{
	local data data_one
	local $(sql_config_get_list $IK_DB_CONFIG "select dns1,dns2 from dns_config")

	local dns_server="$dns1"
	local interface=""
	local index=1
	data_one=$(json_output dns_server:str interface:str)	
	data+="${data:+,}\"$index\":$data_one"

	local dns_server="$dns2"
	local index=2
	data_one=$(json_output dns_server:str interface:str)	
	data+="${data:+,}\"$index\":$data_one"
	
	echo "{$data}"	
}

__route_info_get()
{
	local index=0
	local route
	declare -A IFACE_SET_ROUTE
	local tmpfile=$(interface_get_ifname "wan" "" "true")
	while read name comment; do
		if [ "${name:0:3}" = "wan" ]; then
			local $(cat /tmp/iktmp/cache/config/wan_config.$name 2>/dev/null)

			if [ "$bandif" = "" ]; then
				continue
			fi
			local ifindex
			for ethx in $(ls /sys/class/net/$name/brif); do
				if [ "${ethx:0:3}" = "eth" ]; then
					ifindex=${ethx:3}
					ifindex=$((ifindex+1))
				elif [ "${ethx:0:4}" = "veth" ]; then
					ifindex=${ethx:4}
				fi
			done
			local interface="Device.IP.Interface.$ifindex"

			if [ "$internet" = "$INTERNET_STATIC" ]; then
				if [ "$ip_mask" -a "$gateway" ]; then
					local index=$((index+1))
					local gateway_ip_address=$gateway
					local route_one=$(json_output interface:str gateway_ip_address:str)
					route+="${route:+,}\"$index\":$route_one"
				fi

			elif [ "$internet" = "$INTERNET_DHCP" ]; then
				if [ -e "/tmp/iktmp/dhcpc/$name" ]; then
					local $(cat /tmp/iktmp/dhcpc/$name 2>/dev/null)
					local index=$((index+1))
					local gateway_ip_address=$dhcp_gateway
					local route_one=$(json_output interface:str gateway_ip_address:str)
					route+="${route:+,}\"$index\":$route_one"
				fi

			elif [ "$internet" = "$INTERNET_PPPOE" ]; then
				if [ -e "/tmp/iktmp/pppoe/$name" ]; then
					local $(cat /tmp/iktmp/pppoe/$name 2>/dev/null)
					local index=$((index+1))
					local gateway_ip_address=$pppoe_gateway
					local route_one=$(json_output interface:str gateway_ip_address:str)
					route+="${route:+,}\"$index\":$route_one"
				fi
			fi
		elif [ "${name:0:4}" = "vwan" ]; then
			local $(cat /tmp/iktmp/cache/config/wan_vlan.$name 2>/dev/null)
			local iface=$interface
			if [ "${IFACE_SET_ROUTE[$iface]}" = "1" ]; then
				continue
			fi

			local ifindex
			for ethx in $(ls /sys/class/net/$interface/brif); do
				if [ "${ethx:0:3}" = "eth" ]; then
					ifindex=${ethx:3}
					ifindex=$((ifindex+1))
				elif [ "${ethx:0:4}" = "veth" ]; then
					ifindex=${ethx:4}
				fi
			done
			local interface="Device.IP.Interface.$ifindex"
			if [ "$vlan_internet" = "$INTERNET_STATIC" ]; then
				if [ "$ip_mask" -a "$gateway" ]; then
					local gateway_ip_address=$gateway
					local route_one=$(json_output interface:str gateway_ip_address:str)
					local index=$((index+1))
					route+="${route:+,}\"$index\":$route_one"
					IFACE_SET_ROUTE[$iface]=1
				fi
			
			elif [ "$vlan_internet" = "$INTERNET_DHCP" ]; then
				if [ -e "/tmp/iktmp/dhcpc/$name" ]; then
					local $(cat /tmp/iktmp/dhcpc/$name 2>/dev/null)
					local gateway_ip_address=$dhcp_gateway
					local index=$((index+1))
					local route_one=$(json_output interface:str gateway_ip_address:str)
					route+="${route:+,}\"$index\":$route_one"
					IFACE_SET_ROUTE[$iface]=1
				fi
			fi
		elif [ "${name:0:3}" = "ads" ]; then
			local $(cat /tmp/iktmp/cache/config/wan_vlan.$name 2>/dev/null)

			local iface=$interface
			if [ "${IFACE_SET_ROUTE[$iface]}" = "1" ]; then
				continue
			fi

			local ifindex
			for ethx in $(ls /sys/class/net/$interface/brif); do
				if [ "${ethx:0:3}" = "eth" ]; then
					ifindex=${ethx:3}
					ifindex=$((ifindex+1))
				elif [ "${ethx:0:4}" = "veth" ]; then
					ifindex=${ethx:4}
				fi
			done
			local interface="Device.IP.Interface.$ifindex"
			if [ -e "/tmp/iktmp/pppoe/$name" ]; then
				local $(cat /tmp/iktmp/pppoe/$name 2>/dev/null)
				local gateway_ip_address=$pppoe_gateway
				local route_one=$(json_output interface:str gateway_ip_address:str)
				local index=$((index+1))
				route+="${route:+,}\"$index\":$route_one"
				IFACE_SET_ROUTE[$iface]=1
			fi
		fi
	done <<EOF
	$tmpfile
EOF
	unset IFACE_SET_ROUTE
	echo "{$route}"	
}

# 射频信息获取
__rf_info_get()
{
	#RF_id RF_status RF_channel RF_brandwidth RF_power
	if [ ! -e "/tmp/iktmp/cache/config/wifi" ]; then
		echo "[]"
		return 0
	fi

	local rf_info rf_info_one
	local $(cat /tmp/iktmp/cache/config/wifi)

	if [ "$open2g" = "yes" ]; then
		local RF_id="2.4G"
		local RF_status="on"
		if [ "$channel" = "0" ]; then
			local RF_channel="auto"
		else
			local RF_channel="$channel"
		fi
		local RF_brandwidth="20MHz"
		if [ "$htbw" = "0" ]; then
			RF_brandwidth="20MHz"
		elif [ "$htbw" = "1" ]; then
			RF_brandwidth="40MHz"
		fi
		local  RF_power="100%"
		if [ "$txpower" = "0" ]; then
			RF_power="100%"
		elif [ "$txpower" = "1" ]; then
			RF_power="50%"
		else
			RF_power="25%"
		fi
		local RF_power=""
	else
		local RF_id="2.4G"
		local RF_status="off"
		local RF_channel=""
		local RF_brandwidth=""
		local RF_power=""
	fi

	rf_info_one="$(json_output RF_id:str RF_status:str RF_channel:str RF_brandwidth:str RF_power:str)"
	rf_info+="${rf_info:+,}$rf_info_one"	

	if [ "$open5g" = "yes" ]; then
		local RF_id="5G"
		local RF_status="on"
		if [ "$channel_5g" = "0" ]; then
			local RF_channel="auto"
		else
			local RF_channel="$channel_5g"
		fi
		local RF_brandwidth="40MHz"
		if [ "$htbw_5g" = "0" ]; then
			RF_brandwidth="40MHz"
		elif [ "$htbw_5g" = "1" ]; then
			RF_brandwidth="80MHz"
		else
			RF_brandwidth="160MHz"
		fi
		local  RF_power="100%"
		if [ "$txpower_5g" = "0" ]; then
			RF_power="100%"
		elif [ "$txpower_5g" = "1" ]; then
			RF_power="50%"
		else
			RF_power="25%"
		fi
		local RF_power=""
	else
		local RF_id="5G"
		local RF_status="off"
		local RF_channel=""
		local RF_brandwidth=""
		local RF_power=""
		
	fi

	rf_info_one="$(json_output RF_id:str RF_status:str RF_channel:str RF_brandwidth:str RF_power:str)"
	rf_info+="${rf_info:+,}$rf_info_one"	
	echo "[$rf_info]"
}

#topic=/cloud_ap/{sn}
__show_basic()
{
	local SN="$GWID"
	local MAC="$DEVICE_MAC"
	local name="$HOSTNAME"
	local hardware_version="$LINUX_VERSION"
	local software_version="$VERSION"
	local dev_type="$DEV_TYPE"
	
	sysstat_get_cpu
	local CPU_usage="${SYSSTAT_CPU[0]}"

	sysstat_get_mem
	local total="${SYSSTAT_MEM[MemTotal]}"
	local available="${SYSSTAT_MEM[MemAvailable]}"
	local memory_usage="$(( (total - available) * 100 /total ))%"
	local memory_size=$((total/1024))

	local $(df | awk '$NF=="/etc/log"{print "disk_size="$4,"disk_usage="$5; exit}')
	local disk_size=$((disk_size/1024))

	local dev_model="${MODELNAME:-x86}"
	local online_duration=0
	local running_duration=$(sysstat_get_uptime)
	local online_status="online"

	sysstat_get_stream
	local speed_up="${SYSSTAT_STREAM[upload]}"
	local speed_down="${SYSSTAT_STREAM[download]}"
	if [ "$speed_up" -gt "0" -a "$speed_up" -lt "1024" ]; then
		speed_up=1
	else
		speed_up=$((speed_up/1024))
	fi
	if [ "$speed_down" -gt "0" -a "$speed_down" -lt "1024" ]; then
		speed_down=1
	else
		speed_down=$((speed_down/1024))
	fi

	local bind_status=0
	if [ -e "$WECOM_STATUS" ]; then
		bind_status=$(cat $WECOM_STATUS)
		local online_duration=$(sysstat_get_uptime)
	fi

	local $(sql_config_get_list $WECOM_CONFIG "select * from wecom")
	local staff_ssid=$(url_decode "$staff_ssid")
	local guest_ssid=$(url_decode "$guest_ssid")
	if [ "$staff_wlan_enable" = "yes" ]; then
		staff_wlan_enable="true"
	else
		staff_wlan_enable="false"
	fi
	if [ "$guest_wlan_enable" = "yes" ]; then
		guest_wlan_enable="true"
	else
		guest_wlan_enable="false"
	fi
	if [ "$guest_psk_enable" = "yes" ]; then
		guest_psk_enable="true"
	else
		guest_psk_enable="false"
	fi
	local guest_psk="$guest_passwd"
	local tmplist
	local block_list=$(sqlite3 $WECOM_CONFIG "select mac from  wecom_block_list" -newline ",")
	for mac in ${block_list//,/ }; do
		mac="${mac^^}"
		tmplist+="${tmplist:+,}\"$mac\""
	done
	block_list="[$tmplist]"

	local interface_list="$(__iface_info_get)"
	local dns=$(__dns_info_get)
	local route="$(__route_info_get)"
	local RF_info="$(__rf_info_get)"
	local mesh="{\"work_mode\":0,\"master_SN\":\"\"}"
	local extend=

	local basic=$(json_output dev_type:int interface_list:json dns:json route:json RF_info:json mesh:json SN:str MAC:str name:str name:str hardware_version:str software_version:str CPU_usage:str memory_usage:str disk_usage:str dev_model:str online_duration:int running_duration:int memory_size:int disk_size:int online_status:str speed_down:int speed_up:int bind_status:int staff_wlan_enable:bool staff_ssid:str guest_wlan_enable:bool guest_ssid:str guest_psk_enable:bool guest_psk:str block_list:json)
	json_append __json_result__ basic:json
}

__show_fitap()
{
	__check_is_bind || return 0

	declare -A AP_COMMENT
	while read apmac comment; do
		[ "$apmac" -a "$comment" ] || continue
		AP_COMMENT[$apmac]=$comment
	done < /tmp/iktmp/apname

	local fitap=""
	local tmpfile=$(wum -c wtps 2>/dev/null| awk '{print "MAC="$2,"IP="$3,"dev_model="$4,"software_version="$5,"uptime="$12,"cpu_used="$18,"mem_used="$19,"rate_up="$20,"rate_down="$21,"channel2="$6,"channel5="$14,"channeld5="$32}')
	while read config; do
		[ "$config" ] || continue
		local $config
		if [ ! -e "/tmp/iktmp/cache/config/AC/config/$MAC" ]; then
			continue
		fi
		local $(cat /tmp/iktmp/cache/config/AC/config/$MAC)
		
		local Name="${MAC}"
		local SN="${GWID:20}${MAC//:/}"	
		local MAC="${MAC^^}"
		local IP="$IP"
		local hardware_version=""
		local CPU_usage="$cpu_used"
		local memory_usage="$mem_used"
		if [ -z "$ap_model" ]; then
			local ap_model=$(sqlite3 $IK_DB_CONFIG "select ap_model from ac_server where mac='$MAC'")
		fi
		local dev_model="$ap_model"
		local online_duration=$uptime
		local running_duration=$uptime
		local speed_down="$((rate_down/1024))"
		local speed_up="$((rate_up/1024))"

		local data="" 
		if [ "$channel2" != "--" ]; then
			local RF_id="2.4G"
			local RF_status="on"
			local RF_channel="$channel2"
			local RF_brandwidth="${channel_width_2g}MHz"
			local signal_str="$signal_str"
			if [ "$signal_str" = "0" ]; then
				local RF_power=27
			elif [ "$signal_str" = "1" ]; then
				local RF_power=21
			elif [ "$signal_str" = "2" ]; then
				local RF_power=15
			elif [ "$signal_str" = "3" ]; then
				local RF_power=8
			elif [ "$signal_str" = "4" ]; then
				local RF_power=3
			elif [ "$signal_str" = "5" ]; then
				local RF_power=1
			fi
			local tmp_data=$(json_output RF_id:str RF_channel:str RF_brandwidth:str RF_status:str RF_power:str)
			data+="${data:+,}$tmp_data"
		fi

		if [ "$channel5" != "--" ]; then
			local RF_id="5G"
			local RF_status="on"
			local RF_channel="$channel5"
			local RF_brandwidth="${channel_width_5g}MHz"
			local signal_str="$signal_str_5g"
			if [ "$signal_str" = "0" ]; then
				local RF_power=23
			elif [ "$signal_str" = "1" ]; then
				local RF_power=17
			elif [ "$signal_str" = "2" ]; then
				local RF_power=11
			elif [ "$signal_str" = "3" ]; then
				local RF_power=8
			elif [ "$signal_str" = "4" ]; then
				local RF_power=3
			elif [ "$signal_str" = "5" ]; then
				local RF_power=1
			fi
			local tmp_data=$(json_output RF_id:str RF_channel:str RF_brandwidth:str RF_status:str RF_power:str)
			data+="${data:+,}$tmp_data"
		fi

		if [ "$channeld5" != "--" ]; then
			local RF_id="D5G"
			local RF_status="on"
			local RF_channel="$channeld5"
			local RF_brandwidth="${channel_width_d5g}MHz"
			local signal_str="$signal_str_d5g"
			if [ "$signal_str" = "0" ]; then
				local RF_power=23
			elif [ "$signal_str" = "1" ]; then
				local RF_power=17
			elif [ "$signal_str" = "2" ]; then
				local RF_power=11
			elif [ "$signal_str" = "3" ]; then
				local RF_power=8
			elif [ "$signal_str" = "4" ]; then
				local RF_power=3
			elif [ "$signal_str" = "5" ]; then
				local RF_power=1
			fi
			local tmp_data=$(json_output RF_id:str RF_channel:str RF_brandwidth:str RF_status:str RF_power:str)
			data+="${data:+,}$tmp_data"
		fi
		local RF_info="[$data]"
		local ap_one=$(json_output SN:str MAC:str IP:str Name:str hardware_version:str software_version:str CPU_usage:str memory_usage:str dev_model:str online_duration:int running_duration:int speed_down:int speed_up:int RF_info:json)
		local fitap+="${fitap:+,}\"$SN\":$ap_one"
	done <<EOF
	$tmpfile
EOF
	if [ "$fitap" ]; then
		local fitap="{\"SN\":\"$GWID\",$fitap}"
		json_append __json_result__ fitap:json
	fi

}

#{manu}/{ac_sn}/psk
__show_psk_sync()
{
	__check_is_bind || return 0

	local dev_type=$DEV_TYPE
	
	local psk_info=""
	local tmpfile=$(sql_config_get_list $WECOM_CONFIG "select passwd,psk from wecom_psk_config where type=0")
	while read config; do
		[ "$config" ] || continue
		local $config
		if [ "$psk" ]; then
			psk_info+="${psk_info:+,}\"$passwd\""	
		fi
	done <<EOF
	$tmpfile
EOF
	psk="[$psk_info]"

	local SN="$GWID"
	local psk_sync=$(json_output SN:str dev_type:int psk:json)
	
	json_append __json_result__ psk_sync:json
}

__ap_hosts_get()
{
lua<<EOF
	local sqlite3 = require "lsqlite3"
	local cjson = require "cjson"
	local STAFF_SSID="$wecom_ssid1"
	local GUEST_SSID="$wecom_ssid2"
	
	local PSKINFO = {}
	local f = io.open("/tmp/db/leases.db")
	if f then
		local __ikdb = sqlite3.open("/etc/mnt/ikuai/wecom.db")
		if __ikdb then
			for psk,mac in __ikdb:urows("select psk,mac from wecom_psk_status where mac != ''") do
				PSKINFO[mac] = psk
			end
			__ikdb:close()
		end

		f:close()
	end

	local RELEASE = {}
	local f = io.open("/etc/release")
	if f then
		for line in f:lines() do
			local k, v = line:match("^([^ ]+)=([^ ]+)")
			if k and v then
				RELEASE[k] = v
			end
		end
	end

	local cmd_str="iktimerc \".json;select *,get_upload(mac) upload, get_download(mac) download, get_comment(mac) comment,get_ipaddr(mac) ipaddr  from ac_online_user\""

	local gwid = RELEASE["GWID"]
	local hosts = {}
	hosts["SN"] = gwid

	local fp = io.popen(cmd_str)
	if fp then
		local res = fp:read("*a")
		fp:close()

		local res_json
		if res ~= "" then
			res_json= cjson.decode(res)
		else
			res_json="[]"
		end
		for k, LINE in pairs(res_json) do
			local ap_sn
			local apmac
			if LINE["is_local_wifi"] == 1 then
				ap_sn = gwid	
			else
				apmac = LINE["apmac"]
				ap_sn = apmac:gsub(":", "")
				ap_sn = string.format("%s%s", string.sub(gwid,21), ap_sn)
			end
			if hosts[ap_sn] == nil then
				hosts[ap_sn] = {}
			end
			if hosts[ap_sn]["data"] == nil then
				hosts[ap_sn]["data"] = {}
				hosts[ap_sn]["count"] = 0
			end
			hosts[ap_sn]["count"] = hosts[ap_sn]["count"] + 1
			
			local mac = LINE["mac"]
			local MAC = string.upper(mac) 
			local IP = LINE["ipaddr"]
			local alias = LINE["comment"]
			local SSID = string.gsub(LINE["ssid"], "2G:", "")
			local SSID = string.gsub(SSID, "5G:", "") 
			
			local SSID_TYPE=""
			if SSID == GUEST_SSID then
				SSID_TYPE = "guest"
			elseif SSID == STAFF_SSID then
				SSID_TYPE = "staff"
			end
			local link_type=""
			if LINE["frequencies"] == "2g" then
				link_type = "2.4G"
			elseif LINE["frequencies"] == "5g" then
				link_type = "5G"
			end
			local speed_down = math.floor(LINE["download"]/1024)
			local speed_up = math.floor(LINE["upload"]/1024)
			local online_duration = tonumber(LINE["connect_time"])
			local RSSI = tonumber(LINE["signal"])
			local Vendor = LINE["manufacturer"]
			local psk = PSKINFO[mac] or ""

			local host_one = {psk=psk, alias=alias, SSID_TYPE=SSID_TYPE, SSID=SSID, MAC=MAC, IP=IP, link_type=link_type, speed_up=speed_up, speed_down=speed_down, online_duration=online_duration, RSSI=RSSI, Vendor=Vendor}
			
			table.insert(hosts[ap_sn]["data"], host_one)
		end
	end

	print(cjson.encode(hosts))	
EOF
}

__show_ap_hosts()
{
	__check_is_bind || return 0
	if [ -e "$WECOM_DIR/default_ssid" ]; then
		local $(cat $WECOM_DIR/default_ssid)
	fi
	local hostinfo=$(__ap_hosts_get)

	json_append __json_result__ hostinfo:json
}


#只在开启启动的时候调用
__show_online_event()
{
	local SN="$GWID"
	local event="online"
	local now=$(date +%s)		
	local diff=$(sysstat_get_uptime)
	local time="$((now-diff))"

	local data="$(json_output time:int)"
	local online_event=$(json_output SN:str event:str data:json)

	json_append __json_result__ online_event:json
}

__show_ap_online_event()
{
	local SN="$GWID"

	local now_timestamp=$(date +%s)
	local time_start=$((now_timestamp-120))
	local tmpfile=$(sqlite3 /etc/log/syslog.db "select timestamp,apmac,msg from ap_event where timestamp>$time_start" -separator " ")
	while read timestamp apmac msg; do
		[ "$timestamp" -a "$apmac" -a "$msg" ] || continue	
		local ap_sn="${GWID:20}${apmac//:/}"			
		local time=$timestamp
		if [ "$msg" = "设备上线" -o "$msg" = "Device online" ]; then
			local event="online"
		else
			local event="offline"
		fi
		local data="$(json_output time:int)"
		local tmp_event="$(json_output event:str data:json)"

		local event_one+="${event_one:+,}\"$ap_sn\":$tmp_event" 
	done <<EOF
	$tmpfile
EOF
	if [ -z "$event_one" ]; then
		return
	fi
	local event_all="{$event_one}"

	local ap_online_event=$(json_output SN:str event_all:json)

	json_append __json_result__ ap_online_event:json
}

__show_new_version()
{
	__check_is_bind || return 0

	version_all_load
	local SN="$GWID"
	local version=${VERSION_ALL[system_ver]}
	local desc=${VERSION_ALL[update_content]}
	local dev_type=$DEV_TYPE
	local time="$(date +%s)"

	if [ "$(Version $version)" -gt "$VERSION_NUM" ];then
		local new_version=$(json_output SN:str dev_type:int time:int version:str desc:str)
		json_append __json_result__ new_version:json 
	fi	
}

__show_psk_config()
{
	local psk_config=$(sql_config_get_json $WECOM_CONFIG "select black_mac,passwd,limited_num from wecom_psk_config")	
	local wecom_staff_ssid=$(sqlite3 $WECOM_CONFIG "select staff_ssid from wecom")

	json_append __json_result__ psk_config:json wecom_staff_ssid:str
}

__show_data()
{
	local status=0
	local res=$(sql_config_get_list $WECOM_CONFIG "select enable,sn,qr from wecom")	
	[ "$res" ] || return 1

	local $res
	if [ -e "$WECOM_STATUS" ]; then
		status=1
	fi
	local url=$qr

	json_append __json_result__ enable:str sn:str url:str status:int
}

__show_bindid()
{
	local bindid="$(get_appbind_status)"
	json_append __json_result__ bindid:int
}

basic()
{
	[ -e "$WECOM_ENABLE" ] || return 0
	$IK_DIR_SCRIPT/wecom.sh show TYPE=basic,fitap,psk_sync,ap_hosts,new_version,ap_online_event
	return 0
}

__start()
{
	local $(sql_config_get_list $WECOM_CONFIG "select * from wecom")

	> $WECOM_SSID_CONF
	if [ "$staff_wlan_enable" = "yes" ]; then
		echo "wecom_ssid1=$staff_ssid wecom_guest1=0 wecom_encryption1=1" >> $WECOM_SSID_CONF
	fi
	
	if [ "$guest_wlan_enable" = "yes" ];then
		if [ "$guest_psk_enable" = "yes" ]; then
			echo "wecom_ssid2=$guest_ssid wecom_guest2=1 wecom_encryption2=1" >> $WECOM_SSID_CONF
		else
			echo "wecom_ssid2=$guest_ssid wecom_guest2=1 wecom_encryption2=0" >> $WECOM_SSID_CONF
		fi
	fi

	(
		echo -n "enable=$enable "
		echo -n "staff_wlan_enable=$staff_wlan_enable "
		echo -n "staff_ssid=$(url_decode $staff_ssid) "
		echo -n "guest_wlan_enable=$guest_wlan_enable "
		echo -n "guest_ssid=$(url_decode $guest_ssid) "
		echo -n "guest_psk_enable=$guest_psk_enable "
		echo -n "guest_passwd=$guest_passwd "
		echo -n "guest_psk=$guest_psk "
		echo ""
	) > $WECOM_CACHE_CONF 

	for i in 1 2 3; do
		killall -q ik_wecom || break
		sleep 1
	done
	ik_wecom

	if [ -e "$WECOM_STATUS" ]; then
		killall dtalkd
		killall -q ik_wpa_ppsk
		rm -f /tmp/iktmp/ik_wpa_ppsk.status /tmp/iktmp/ik_wpa_ppsk.ssid
	fi

    iptables -w -F WECOM_BLOCK_MAC
	iptables -w -A WECOM_BLOCK_MAC -m ifaces --ifaces lan*,vlan* --dir in  $IPT_NOT_LAN_IFACE_OUT \
		-m set --match-set Linux_blockmac_default src -j DROP
	__block_list_init

	if WIFI_SUPPORT_2G ;then
		$IK_DIR_SCRIPT/wifi.sh reload >/dev/null 2>&1 &
	fi
	wum -c reload >/dev/null 2>&1
	$IK_DIR_SCRIPT/utils/hosts_kick.sh clean_wifi_user >/dev/null 2>&1 &
}

__stop()
{
	> $WECOM_SSID_CONF
	iptables -w -F WECOM_BLOCK_MAC

	for i in 1 2 3; do
		killall -q ik_wecom || break
		sleep 1
	done

	__block_list_uninit
	if WIFI_SUPPORT_2G ;then
		$IK_DIR_SCRIPT/wifi.sh reload >/dev/null 2>&1 &
	fi
	wum -c reload >/dev/null 2>&1
}

__clean()
{
	sqlite3 $WECOM_CONFIG "delete from wecom_block_list; delete from wecom_psk_status; delete from wecom_psk_config"
}

__gen_sn()
{
	#key="2021.ikuai8.com." key hex: 323032312e696b756169382e636f6d2e
	local tmp_value=""
	for ((i=0;i<=30;i=i+2)); do  tmp_value+="\x${GWID:i:2}"; done
	local sn_str="$(echo -ne "$tmp_value" | openssl enc -aes-128-ecb  -e -K "323032312e696b756169382e636f6d2e" -nopad -nosalt |hexdump -e '16/1 "%02X"')"
#	sn="$(echo -n "$GWID" | openssl enc -aes-128-ecb  -e -K "323032312e696b756169382e636f6d2e" -nopad -nosalt |hexdump -e '16/1 "%02X"')"
	echo "$sn_str"
}

#企业微信SN注册接口
__add_sn_to_tencent()
{
	sn="$(__gen_sn)"
	local timestamp=$(date +%s)
	local dev_model=${MODELNAME:-X86}
	local manufacturer_id="ikuai"
	local nonce="$RANDOM"
	local version="v0.0.1"
	local type="cloud_ap"
	local env="test"

	local signature=$(echo -e "1\n$timestamp\n$nonce\n$manufacturer_id\n" |sort |awk 'BEGIN{a=""}{ a=a""$1 }END{printf a}'|sha1sum)

	local signature=${signature// *}
	local data="$(json_output sn:str version:str type:str dev_model:str)"
	local data="[$data]"
	local body="$(json_output data:json timestamp:str nonce:str manufacturer_id:str signature:str env:str)"

	qr=$(curl -4 -q  -X POST -u ikuai:ch43f6d1 -d "$body" https://web.wlanns.tencent-cloud.com/sn/add_device 2>/dev/null| jq .data[0].qr 2>/dev/null)

	qr=${qr//\"/}
	if [ -z "$qr" -o "$qr" = "null" ]; then
		return 1
	fi
	return 0
}

#wecom组注册接口
__sn_to_wecom()
{
	local ACTION="$1"

	local itoken=$(tkgen 2>/dev/null)
	if [ -z "$itoken" ]; then
		return 1
	fi
	local remote_host=$(cat /tmp/ikpkg/ik_host/iapi_host/host 2>/dev/null)
	local remote_host=${remote_host:-"iapi.ikuai8.com:21422"}

	local res=$(curl -4 --fail --connect-timeout 5 -m 20 --retry 3 --retry-delay 3  -ks "https://$remote_host/dis/groups/wecom/routers/$GWID?itoken=$itoken&mac=$DEVICE_MAC"  -X $ACTION)
	if [ -z "$res" ]; then
		return 1
	fi
	local code=$(echo $res |jq .code 2>/dev/null)
	if [ "$code" != "200" ]; then
		return 1	
	fi

	killall -s SIGHUP cre
	return 0
}

__add_sn_to_wecom()
{
	local res=$(cre -L | awk '{if($2=="wecom"){print $0}}')
	[ "$res" ] && return 0

	if ! __sn_to_wecom "POST"; then
		return 1
	fi
	return 0
}

__del_sn_to_wecom()
{
	if ! __sn_to_wecom "DELETE"; then
		return 1
	fi
	return 0
}

save()
{
	local res=$(sql_config_get_list $WECOM_CONFIG "select * from wecom" prefix=old_)
	if [ "$res" = "" ];then
		return 0
	fi
	local $res
	local sql_param="enable:str sn:str qr:str"

	local qr=$old_qr
	local sn=$old_sn
	if [ "$enable" = "yes" -a "$qr" = "" ]; then
		if ! __add_sn_to_tencent ; then
			Autoiecho wecom add_tencent_fail
			return 1
		fi
		touch $WECOM_ENABLE
	fi
	
	if [ "$enable" = "yes" ]; then
		if ! __add_sn_to_wecom ; then
			Autoiecho wecom add_wecom_fail
			return 1
		fi 
	else
		if [ -e "$WECOM_STATUS" ]; then
			Autoiecho wecom unbind_wecom
			return 1
		fi
		__del_sn_to_wecom
	fi

	if SqlMsg=$(sql_config_update $WECOM_CONFIG wecom "id=1" $sql_param) ;then 
		if ! NewOldVarl enable sn qr;then
			if [ "$enable" = "yes" ]; then
				touch $WECOM_ENABLE
				__start
			else
				rm $WECOM_ENABLE
				__stop
			fi
		fi
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi
}

__initialize()
{
	local res=$(sql_config_get_list $WECOM_CONFIG "select * from wecom" prefix=old_)
	if [ "$res" = "" ];then
		return 0
	fi
	local $res
	local enable="yes"
	local sql_param="enable:str staff_wlan_enable:str staff_ssid:str guest_wlan_enable:str guest_ssid:str guest_psk_enable:str guest_passwd:str guest_psk:str"

	killall dtalkd
	echo 1 > $WECOM_STATUS
	touch $WECOM_ENABLE

	if [ "$OEMNAME" = "wecom" -a -e "$WECOM_STATUS" ]; then
		$IK_DIR_SCRIPT/wifi.sh up >/dev/null 2>&1 & 
		$IK_DIR_SCRIPT/ac_status.sh seting ac_server=1 >/dev/null 2>&1 
		sleep 1
	fi
	if SqlMsg=$(sql_config_update $WECOM_CONFIG wecom "id=1" $sql_param) ;then 
		if ! NewOldVarl staff_wlan_enable staff_ssid guest_wlan_enable guest_ssid guest_psk_enable guest_passwd guest_psk ;then
			__start >/dev/null 2>&1 &	
		fi
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi
}

initialize()
{
	__initialize >/dev/null 2>&1 &
	return 0
}
__uninitialize()
{
	local enable="no"
	local staff_wlan_enable="no"
	local guest_wlan_enable="no"
	local guest_psk_enable="no"
	local qr=""
	local sn=""
	local sql_param="enable:str sn:str qr:str staff_wlan_enable:str guest_wlan_enable:str guest_psk_enable:str"

	sql_config_update $WECOM_CONFIG wecom "id=1" $sql_param

	if [ "$OEMNAME" = "wecom" ]; then
		$IK_DIR_SCRIPT/wifi.sh down >/dev/null 2>&1 & 
		$IK_DIR_SCRIPT/ac_status.sh seting ac_server=0 >/dev/null 2>&1 &
		sleep 1
	fi


	rm $WECOM_STATUS 2>/dev/null
	rm $WECOM_ENABLE 2>/dev/null

	__stop
	__clean
	return 0
}

uninitialize()
{
	__uninitialize >/dev/null 2>&1 &
	return 0
}

#dev_type=  ap_name=
reboot()
{
	if [ "$ap_name" ]; then
		wum -c set -m $ap_name -s "reboot" >/dev/null 2>/dev/null
		wum -c delete -m $ap_name
	else
		(sleep 1; /sbin/reboot) >/dev/null 2>&1 &
	fi
	return 0
}

#version= url= file_size=
upgrade()
{
	if [ "$(Version $version)" -gt "$VERSION_NUM" ];then
		$IK_DIR_SCRIPT/upgrade.sh update_auto type=system >/dev/null 2>&1 &
	fi
	return 0
}

#passwd=xx,xx psk=xx,xx limited_num=xx,xx mac=aa@bb,xx,xx
update_staff_psk()
{
	local black_mac="$mac"

	local psk_info=(${psk//,/ })
	local limited_info=(${limited_num//,/ })
	local mac_info=(${mac//,/ })
	local passwd_info=(${passwd//,/ })

	rule_num=${#psk_info[*]}
	echo "BEGIN TRANSACTION;" > /tmp/wecom_psk.temp.$$
	echo "delete from wecom_psk_config;" >> /tmp/wecom_psk.temp.$$

	for((i=0;i<$rule_num;i++)); do
		local mac_one="${mac_info[$i]}"
		local mac_one="${mac_one//@/,}"
		local limited_one="${limited_info[$i]}"
		local psk_one="${psk_info[$i]}"
		local passwd_one="${passwd_info[$i]}"
		echo "insert into wecom_psk_config(id,black_mac,limited_num,passwd,psk) values(NULL,'$mac_one',$limited_one, '$passwd_one', '$psk_one');" >>/tmp/wecom_psk.temp.$$
	done
	echo "COMMIT;" >> /tmp/wecom_psk.temp.$$
	sqlite3 $WECOM_CONFIG < /tmp/wecom_psk.temp.$$
	rm /tmp/wecom_psk.temp.$$

	return 0
}

__add_staff_psk()
{
	local black_mac="$mac"

	local psk_info=(${psk//,/ })
	local limited_info=(${limited_num//,/ })
	local mac_info=(${mac//,/ })
	local passwd_info=(${passwd//,/ })

	local staff_ssid=$(sqlite3 $WECOM_CONFIG "select staff_ssid from wecom")
	local staff_ssid=$(url_decode "$staff_ssid")

	rule_num=${#passwd_info[*]}
	echo "BEGIN TRANSACTION;" > /tmp/wecom_psk.temp.$$

	for((i=0;i<$rule_num;i++)); do
		local mac_one="${mac_info[$i]}"
		local mac_one="${mac_one//@/,}"
		local limited_one="${limited_info[$i]}"
		local passwd_one="${passwd_info[$i]}"
		if [ "$enc_passwd" = "1" ]; then
			local psk_one="$(ik_psk $staff_ssid $passwd_one)"
		else
			local psk_one="${psk_info[$i]}"
		fi
		echo "update wecom_psk_config set psk='$psk_one' where passwd='$passwd_one';" >> /tmp/wecom_psk.temp.$$
		echo "insert into wecom_psk_config(id,black_mac,limited_num,passwd,psk) values(NULL,'$mac_one',$limited_one, '$passwd_one', '$psk_one');" >>/tmp/wecom_psk.temp.$$
	done
	echo "COMMIT;" >> /tmp/wecom_psk.temp.$$
	sqlite3 $WECOM_CONFIG < /tmp/wecom_psk.temp.$$
	rm /tmp/wecom_psk.temp.$$

	return 0
}

#passwd=xx,xx psk=xx,xx limited_num=xx,xx mac=aa@bb,xx,xx enc_passwd=0/1
add_staff_psk()
{
	__add_staff_psk &
	return 0
}

#psk=xx,xx
__delete_staff_psk()
{
	echo "BEGIN TRANSACTION;" > /tmp/wecom_psk.temp.$$

	local kick_macs=""
	for psk_one in ${psk//,/ }; do
		local client_mac=$(sqlite3 $WECOM_CONFIG "select mac from wecom_psk_status where psk='$psk_one'")	
		local kick_macs="${kick_macs:+,}$client_mac"
		echo "delete from wecom_psk_config where passwd='$psk_one';" >>/tmp/wecom_psk.temp.$$
		echo "delete from wecom_psk_status where psk='$psk_one';" >>/tmp/wecom_psk.temp.$$
	done
	echo "COMMIT;" >> /tmp/wecom_psk.temp.$$
	sqlite3 $WECOM_CONFIG < /tmp/wecom_psk.temp.$$
	rm /tmp/wecom_psk.temp.$$

	if [ "$kick_macs" ]; then
		for kick_mac in ${kick_macs//,/ }; do
			$IK_DIR_SCRIPT/ac_online_clt.sh kickuser mac="$kick_mac" >/dev/null 2>&1
		done
	fi

	return 0
}

delete_staff_psk()
{
	__delete_staff_psk >/dev/null 2>&1 &
	return 0
}

delete_all_staff_psk()
{
	kick_staff_ssid_user
	##清掉psk密码
	sqlite3 $WECOM_CONFIG "delete from wecom_psk_status; delete from wecom_psk_config"
	return 0
}

#psk= guest_psk_enable=yes/no
set_guest_psk()
{
	local guest_passwd="$psk"
	local res=$(sql_config_get_list $WECOM_CONFIG "select * from wecom" prefix=old_)
	if [ "$res" = "" ];then
		return 0
	fi
	local $res

	local sql_param=" guest_psk_enable:str"
	if [ "$guest_psk_enable" = "yes" -a "$psk" ]; then
		local old_guest_ssid=$(url_decode "$old_guest_ssid")
		local guest_psk=$(ik_psk "$old_guest_ssid" "$guest_passwd")
		sql_param+=" guest_psk:str guest_passwd:str"
	fi

	if SqlMsg=$(sql_config_update $WECOM_CONFIG wecom "id=1" $sql_param) ;then 
		if ! NewOldVarl guest_psk_enable guest_psk guest_passwd ;then
			__start >/dev/null 2>&1 &
		fi
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi
}

update_all_staff_psk()
{
	local TMPFILE="/tmp/wecom_staff_psk.temp.$$"
	echo "BEGIN TRANSACTION;" > $TMPFILE

	local staff_ssid=$(url_decode "$staff_ssid")
	local tmpfile=$(sql_config_get_list $WECOM_CONFIG "select id,passwd from wecom_psk_config")
	while read config; do
		[ "$config" ] || continue
		local $config
		local psk_one=$(ik_psk "$staff_ssid" "$passwd")
		echo "update wecom_psk_config set psk='$psk_one' where id=$id;" >> $TMPFILE
	done <<EOF
	$tmpfile
EOF

	echo "COMMIT;" >> $TMPFILE
	sqlite3 $WECOM_CONFIG < $TMPFILE
	rm $TMPFILE

}

kick_staff_ssid_user()
{
	local staff_ssid=$(sqlite3 $WECOM_CONFIG "select staff_ssid from wecom")
	if [ "$staff_ssid" ]; then
		$IK_DIR_SCRIPT/ac_online_clt.sh kickssid ssid=$staff_ssid >/dev/null 2>&1 &
	fi
	return 0
}

kick_guest_ssid_user()
{
	local guest_ssid=$(sqlite3 $WECOM_CONFIG "select guest_ssid from wecom")
	if [ "$guest_ssid" ]; then
		$IK_DIR_SCRIPT/ac_online_clt.sh kickssid ssid=$guest_ssid >/dev/null 2>&1 &
	fi
	return 0
}

#
set_staff_psk_null()
{
	sqlite3 $WECOM_CONFIG "update wecom_psk_config set psk=''" 
	return 0
}

#ssid_type=staff/guest ssid=  guest_psk_enable=yes/no
set_ssid()
{
	local res=$(sql_config_get_list $WECOM_CONFIG "select * from wecom" prefix=old_)
	if [ "$res" = "" ];then
		return 0
	fi
	local $res

	local ssid_changed=0
	
	local sql_param=" "
	if [ "$ssid_type" = "staff" ]; then
		local staff_ssid="$ssid"
		if ! NewOldVarl staff_ssid; then
			if [ "$ARCH" = "mips" ]; then
				set_staff_psk_null >/dev/null 2>&1 &
			else
				update_all_staff_psk >/dev/null 2>&1 &	
			fi
			kick_staff_ssid_user
			ssid_changed=1
		fi
		local sql_param+=" staff_ssid:str"
	elif [ "$ssid_type" = "guest" ]; then
		local guest_ssid="$ssid"
		if ! NewOldVarl guest_ssid; then
			kick_guest_ssid_user
			ssid_changed=1
		fi
		local sql_param+=" guest_ssid:str"
	else
		return 0
	fi

	if SqlMsg=$(sql_config_update $WECOM_CONFIG wecom "id=1" $sql_param) ;then 
		if [ "$ssid_changed" = "1" ];then
			__start >/dev/null 2>&1 &
		fi
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi
}

#ssid= staff_wlan_enable=yes/no
enable_staff_wlan()
{
	local res=$(sql_config_get_list $WECOM_CONFIG "select * from wecom" prefix=old_)
	if [ "$res" = "" ];then
		return 0
	fi
	local $res

	local staff_ssid="$ssid"

	if [ "$staff_wlan_enable" = "yes" ]; then
		local sql_param="staff_wlan_enable:str staff_ssid:str"
	else
		local sql_param="staff_wlan_enable:str"
	fi

	if SqlMsg=$(sql_config_update $WECOM_CONFIG wecom "id=1" $sql_param) ;then 
		if ! NewOldVarl staff_wlan_enable ;then
			if [ "$staff_wlan_enable" = "no" ]; then
				kick_staff_ssid_user
			fi
			__start >/dev/null 2>&1 &
		fi
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi
}

#ssid= psk= passwd= guest_psk_enable=yes/no guest_wlan_enable=yes/no
enable_guest_wlan()
{
	local res=$(sql_config_get_list $WECOM_CONFIG "select * from wecom" prefix=old_)
	if [ "$res" = "" ];then
		return 0
	fi
	local $res

	local guest_ssid="$ssid"
	local guest_psk="$psk"
	local guest_passwd="$passwd"

	local sql_param="guest_wlan_enable:str guest_ssid:str guest_psk_enable:str guest_psk:str guest_passwd:str"

	if SqlMsg=$(sql_config_update $WECOM_CONFIG wecom "id=1" $sql_param) ;then 
		if ! NewOldVarl guest_wlan_enable guest_ssid guest_psk_enable guest_psk guest_passwd;then
			if [ "$guest_wlan_enable" = "no" ]; then
				kick_guest_ssid_user
			fi
			__start >/dev/null 2>&1 &
		fi
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi
}

#mac=xx,xx
__add_block_list()
{
	local TMPFILE="/tmp/wecom_block.temp.$$"
	echo "BEGIN TRANSACTION;" > $TMPFILE
	for mac_one in ${mac//,/ };do
		local mac_one="${mac_one,,}"
		echo "insert into wecom_block_list(id,mac) values(NULL,'$mac_one');" >> $TMPFILE
	done
	echo "COMMIT;" >> $TMPFILE
	sqlite3 $WECOM_CONFIG < $TMPFILE
	rm $TMPFILE

	for kick_mac in ${mac//,/ }; do
		local kick_mac="${kick_mac,,}"
		$IK_DIR_SCRIPT/ac_online_clt.sh kickuser mac="$kick_mac" >/dev/null 2>&1
	done

	__block_list_init
}

add_block_list()
{
	__add_block_list >/dev/null 2>&1 &
	return 0
}

#mac=xx,xx
__delete_block_list()
{
	local TMPFILE="/tmp/wecom_block.temp.$$"
	echo "BEGIN TRANSACTION;" > $TMPFILE
	for mac_one in ${mac//,/ };do
		local mac_one="${mac_one,,}"
		echo "delete from wecom_block_list where mac='$mac_one';" >> $TMPFILE
	done
	echo "COMMIT;" >> $TMPFILE
	sqlite3 $WECOM_CONFIG < $TMPFILE
	rm $TMPFILE
	__block_list_init
}

delete_block_list()
{
	__delete_block_list >/dev/null 2>&1 &
	return 0
}

__block_list_init()
{
	ipset -F Linux_blockmac_default	
	sql_config_get_list $WECOM_CONFIG "select * from wecom_block_list" | \
	while read config; do
		[ "$config" ] || continue
		local $config
		ipset -A Linux_blockmac_default $mac
	done
}

__block_list_uninit()
{
	ipset -F Linux_blockmac_default	
}

