#!/bin/bash /etc/ikcommon

Include check.sh, interface.sh

ROOT_PATH="/etc/disk_user"
FILE_TMP_PATH="/tmp/pcap"
#超过100M的剩余空间, 最多抓8万个报文数
hit_maxnum=80000

__check_param()
{
	local wg_source="" original_s0="$S0" validation_interface
	if interface_is_wireguard_tool_source "$interface"; then
		wg_source="$interface"
		validation_interface="$(interface_get_ifname all | head -1)"
		S0="${S0/interface=$interface/interface=$validation_interface}"
		interface="$validation_interface"
	fi
	check_varl \
		'interface	ifname' \
		'ip_addr	ip or == ""' \
		'mac		mac or == ""' \
		'hit_num	> 0'
	local check_result=$?
	[ "$wg_source" ] && interface="$wg_source"
	S0="$original_s0"
	return "$check_result"
}

__pkts_num_check()
{
	local avail_mem=$(df | awk '$NF=="/tmp"{print $4;exit}')

	if [ "$avail_mem" -lt "10" ]; then
		Autoiecho param disk_space
		return 1
	fi

	if [ "$((avail_mem/2))" -gt "100" ]; then
		if [ "$hit_num" -gt "$hit_maxnum" ]; then
			echo "$hit_maxnum"
		else
			echo "$hit_num"
		fi
		return 0
	fi

	local tmp_pkts_num=$((avail_mem*1024*1024/1500/2))

	if [ "$hit_num" -gt "$tmp_pkts_num" ]; then
		echo "$tmp_pkts_num"
		return 0
	fi

	echo "$hit_num"
	return 0	

}

__init_options()
{
	local ip_option port_option proto_option mac_option
	local port_prefix proto_prefix mac_prefix

	if [ -n "$ip_addr" ]; then
		ip_option="host $ip_addr"
	fi

	if [ -n "$port" ]; then
		if [ "$ip_option" ]; then
			port_prefix="and"
		fi
		port_option="port $port"
	fi

	if [ -n "$proto" ]; then
		if [ "$ip_option" -o "$port_option" ]; then
			proto_prefix="and"
		fi
		proto_option="-p $proto"

	fi

	if [ -n "$mac" ]; then
		if [ "$ip_option" -o "$port_option" -o "$proto_option" ]; then
			mac_prefix="and"
		fi
		mac_option=" ether host $mac "
	fi

	local iface=$interface
	if interface_check_is_wanpppoe ${iface} ;then
		iface=${iface}_ad
	fi

	options="-c ${hit_num:-1000} -i ${iface} $ip_option $port_prefix $port_option $proto_prefix $proto_option $mac_prefix $mac_option -w ${new_filename}.pcap"
}


start()
{
	__check_param || return 1

	mkdir -p $FILE_TMP_PATH
	
	if [ ! -e "/usr/ikuai/www/pcap" ]; then
		ln -s $FILE_TMP_PATH /usr/ikuai/www/
	fi

	stop

	local flag_sys=1

	if [ "$filename" ]; then
		local home_dir="${filename%/*}"
		if [ "$home_dir" = "" ]; then
			Autoiecho param filename_error
			return 1
		fi
		if [ "$home_dir" = "/" ]; then
			Autoiecho param dir_permission_error
			return 1
		fi
		##禁止 /a/../b 此种目录形式下发
		local tmp_dir=${home_dir//\.\./}
		if [ "$tmp_dir" != "$home_dir" ]; then
			Autoiecho param dir_path_error
			return 1
		fi
		
		local abs_path="${ROOT_PATH}${home_dir}"

		if [ ! -d "$abs_path" ]; then
			Autoiecho param dir_not_found
			return 1
		fi

		local new_filename="${ROOT_PATH}${filename}"
		flag_sys=0
	else
		if hit_num=$(__pkts_num_check); then
			local new_filename="${FILE_TMP_PATH}/tcpdump"
		else
			return 1
		fi
	fi

	local options=""
	__init_options	

	if [ "$interface" = "any" ]; then
		return
	fi

	if ! tcpdump -Z root -s0 $options -d >/dev/null 2>&1 ; then
		Autoiecho param proto_err
		return 1
	fi

	tcpdump -Z root -s0 $options >/dev/null 2>&1 &
	if [ "$flag_sys" = "1" ]; then
		filename=""
	fi
	echo "interface=$interface ip_addr=$ip_addr port=$port proto=$proto mac=$mac filename=$filename hit_num=$hit_num" > /tmp/iktmp/tcpdump.conf
	return 0
}

stop()
{
    ps |awk '$5~/tcpdump/ && $6=="-Z" && $7=="root" {system("kill "$1)}'
}

delete()
{
	if [ -e "${FILE_TMP_PATH}/tcpdump.pcap" ]; then
		rm -f ${FILE_TMP_PATH}/tcpdump.pcap
	fi
	rm -f /tmp/iktmp/tcpdump.conf >/dev/null 2>&1
	return 0
}

show() {
	Show __json_result__
}

__show_status()
{
	local status=0
	
	status=$(ps |awk '$5~/tcpdump/ && $6=="-Z" && $7=="root" {print 1; exit}')

	json_append __json_result__ status:int
}

__show_data()
{
	local interface="" hit_num="100"  proto=""
	local ip_addr port filename mac
	local size=0
	if [ -e "/tmp/iktmp/tcpdump.conf" ]; then
		local $(cat /tmp/iktmp/tcpdump.conf)

		if [ "$filename" = "" ]; then
			if [ -e "${FILE_TMP_PATH}/tcpdump.pcap" ]; then
				local $(stat -c "%Y %s" ${FILE_TMP_PATH}/tcpdump.pcap | awk '{print "last_time="$1, "size="$2}')
			fi
		else
			local new_filename="${ROOT_PATH}${filename}"
			if [ -e "${new_filename}.pcap" ]; then
				local $(stat -c "%Y %s" ${new_filename}.pcap | awk '{print "last_time="$1, "size="$2}')
			fi
		fi
	fi

	data=$(json_output interface:str mac:str hit_num:str proto:str ip_addr:str port:str filename:str size:str last_time:str)
	data="[$data]"
	
	json_append __json_result__ data:json
}

__show_partname()
{
	local partname
	while read config; do
		local $config
		if [ "$mt_purpose" = "1" -a -n "$mt_name" ]; then
			partname+="${partname:+,}\"$mt_name\""
		fi
	done < /tmp/iktmp/cache/disk_mount
	partname="[$partname]"

	json_append __json_result__ partname:json	
}

__show_interface()
{
	local interface=$(interface_append_wireguard_json "$(interface_get_ifname_comment_json all)")
	json_append __json_result__ interface:json
}

