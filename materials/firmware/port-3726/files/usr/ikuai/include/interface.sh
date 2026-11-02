INTERNET_STATIC=0
INTERNET_DHCP=1
INTERNET_PPPOE=2
INTERNET_MACVLAN=3
INTERNET_VLAN=4

INTERNET_PPTP=10
INTERNET_L2TP=11
INTERNET_OVPN=12
INTERNET_IKED=13


##############扩展新网卡类型注意事项#########################
#  由于页面 要求网卡展示的排序要 lan vlan wan adsl vwan pptp l2tp ovpn ...
#  由于这些排序是人为判断，所以在扩展时 要注意 《线路监控》的页面的展示,那边代码也有一份单独的排列顺序
##############扩展新网卡类型注意事项#########################


#获取网卡列表
#interface_get_ifname lan,wan,vlan,pptp,l2tp,ovpn,wg,vpn/all auto/all/any
#参数1: vpn = pptp,l2tp,ovpn,wg   all = 显示全部
#参数2: auto自动/all全部/any任意, 关键字会自动填充到你指定类型的前面
#参数3: true 返回的接口包含备注信息, 默认不返回
interface_get_ifname()
{
	local type=$1 pad=$2 comment=$3
	local typ
	local unpad

	if [ "$type" = "all" ];then
		type="lan,vlan,wan,vpn,sdwan,doc,sovpn,sdsaas"
	fi
	if [ "$pad" = "all" -o "$pad" = "auto" -o "$pad" = "any" ];then
		echo $pad
	fi

	#删除模式
	if [ "${pad:0:1}" = "-" ];then
		unpad="${pad:1}"
	fi

	if [[ "$type" =~ sovpn ]]; then
		type=${type//sovpn/}
		type=${type//vpn/pptp,l2tp,ovpn,wg,iked}
		type="${type},sovpn"
	else
		type=${type//vpn/pptp,l2tp,ovpn,wg,iked}
	fi

	# WireGuard is injected by the image hook, so its interface cache can be
	# missing during early boot. Refresh it on demand before pages read lines.
	if [[ "$type" =~ wg ]]; then
		__interface_get_name_to_cache wg >/dev/null 2>&1
	fi

	if [ "$comment" = "true" ]; then
		cd $IK_DIR_CACHE/ifname_comment
	else
		cd $IK_DIR_CACHE/ifname
	fi

	##docker lan
	if [[ "$type" =~ doc ]]; then
		for doc_if in $(ls -d /sys/class/net/doc_* 2>/dev/null); do
			echo "${doc_if##*/}"
		done
		type=${type//doc/}
		[ -z "$type" ] && return
	fi
	
	gawk -v unpad="${unpad//+/}" -vis_fuzzy="${unpad: -1}" '
	BEGINFILE{
		if(ERRNO!="")nextfile
	}
	{
		if (unpad != "") {
			if (is_fuzzy == "+") {
				if ($1~"^"unpad) next
			} else {
				if (unpad == $1) next
			}
		}

		prefix=substr($1,0,3)
		if(prefix=="lan") lan[lan_n++]=$0
		if(prefix=="vla") vlan[vlan_n++]=$0
		if(prefix=="wan") wan[wan_n++]=$0
		if(prefix=="ads") adsl[adsl_n++]=$0
		if(prefix=="vwa") vwan[vwan_n++]=$0
		if(prefix=="ppt") pptp[pptp_n++]=$0
		if(prefix=="l2t") l2tp[l2tp_n++]=$0
		if(prefix=="ovp") ovpn[ovpn_n++]=$0
		if($1~/^wg/) wg[wg_n++]=$0
		if(prefix=="sdw") sdwan[sdwan_n++]=$0
		if(prefix=="sds") sdsaas[sdsaas_n++]=$0
		if(prefix=="sov") sovpn[sovpn_n++]=$0
		if(prefix=="ike") iked[iked_n++]=$0
	}END{
		#asort(lan)
		asort(vlan)
		#asort(wan)
		asort(adsl)
		asort(vwan)
		asort(pptp)
		asort(l2tp)
		asort(ovpn)
		asort(wg)
		asort(sdwan)
		asort(sdsaas)
		asort(iked)
		for(i in lan) print lan[i]
		for(i in vlan) print vlan[i]
		for(i in wan) print wan[i]
		for(i in adsl) print adsl[i]
		for(i in vwan) print vwan[i]
		for(i in pptp) print pptp[i]
		for(i in l2tp) print l2tp[i]
		for(i in ovpn) print ovpn[i]
		for(i in wg) print wg[i]
		for(i in sdwan) print sdwan[i]
		for(i in sdsaas) print sdsaas[i]
		for(i in sovpn) print sovpn[i]
		for(i in iked) print iked[i]
	}'  ${type//,/ }
}

#解释同上,这个返回的是json格式
interface_is_wg_ingress_helper()
{
	[[ "$1" =~ ^pppwg[0-9]+$ ]]
}

# Validate exit choices only. The helper must remain usable by native ingress/DPI.
interface_check_routing_exit()
{
	local item
	for item in ${1//,/ }; do
		if interface_is_wg_ingress_helper "$item"; then
			echo 'pppwg 为内部转发接口，不能配置为出口；请选择实际的 WAN 或 VPN 线路'
			return 1
		fi
	done
	return 0
}

interface_get_ifname_json()
{
	local ifname
	local ifnames
	for ifname in $(interface_get_ifname $*) ;do
		interface_is_wg_ingress_helper "$ifname" && continue
		ifnames+="${ifnames:+,}\"$ifname\""
	done
	echo "[$ifnames]"
}

#解释同上,这个返回的是带comment的json格式
interface_get_ifname_comment_json()
{
	local ifname_comment
	local ifnames_comment
	local tmpfile=$(interface_get_ifname "$1" "$2" "true")

	while read ifname_comment; do
		[ "$ifname_comment" = "" ] && continue
		interface_is_wg_ingress_helper "${ifname_comment%%[[:space:]]*}" && continue
		ifnames_comment+="${ifnames_comment:+,}[\"${ifname_comment// /\",\"}\"]"	
	done << EOF
	$tmpfile
EOF
	echo "[$ifnames_comment]"
}

interface_append_wireguard_comment_json()
{
	local interface="$1"
	local wg_list
	local name
	local comment
	local item

	wg_list=$(
		{
			sqlite3 $IK_DB_CONFIG -separator "|" "select name,comment from wireguard where name like 'wg%' order by name" 2>/dev/null
			sqlite3 $IK_DB_CONFIG -separator "|" "select distinct interface,'' from wireguard_peers where interface like 'wg%' order by interface" 2>/dev/null
			for wg_if in /sys/class/net/wg*; do
				[ -e "$wg_if" ] && echo "${wg_if##*/}|"
			done
		} | awk -F'|' '$1!="" && !seen[$1]++'
	)
	while IFS='|' read name comment; do
		[ "$name" = "" ] && continue
		echo "$interface" | grep -q "\"$name\"" && continue
		item="[\"$name\""
		[ "$comment" != "" ] && item="$item,\"$comment\""
		item="$item]"
		if [ "$interface" = "" -o "$interface" = "[]" ]; then
			interface="[$item]"
		else
			interface="${interface%]},$item]"
		fi
	done << EOF
$wg_list
EOF
	echo "${interface:-[]}"
}


__interface_get_name_to_cache()
{
	local sql_cmd n
	case $1 in
	lan) n=4; sql_cmd="select name,comment from lan_config" ;;
	wan) n=4; sql_cmd="select name,comment from wan_config where bandif != '' and (internet=$INTERNET_STATIC or internet=$INTERNET_DHCP or internet=$INTERNET_PPPOE) ;select wan_vlan.vlan_name,wan_vlan.comment from wan_config left join wan_vlan on wan_config.name=wan_vlan.interface where (wan_config.internet=$INTERNET_MACVLAN or wan_config.internet=$INTERNET_VLAN) and wan_config.bandif!=''" ;;
	wan_all) n=4; sql_cmd="select name,comment from wan_config where bandif != '' ;select wan_vlan.vlan_name,wan_vlan.comment from wan_config left join wan_vlan on wan_config.name=wan_vlan.interface where (wan_config.internet=$INTERNET_MACVLAN or wan_config.internet=$INTERNET_VLAN) and wan_config.bandif!=''" ;;
	wan_phy) n=4; sql_cmd="select name,comment from wan_config where bandif != ''" ;;
	vlan) n=5; sql_cmd="select vlan_name,comment from vlan_config where enabled = 'yes'" ;;
	pptp) n=5; sql_cmd="select name,comment from pptp_client where enabled = 'yes'" ;;
	l2tp) n=5; sql_cmd="select name,comment from l2tp_client where enabled = 'yes'" ;;
	ovpn) n=5; sql_cmd="select name,comment from openvpn_client where enabled = 'yes'" ;;
	wg) n=3; sql_cmd="select name,comment from wireguard where name like 'wg%'" ;;
	iked) n=5; sql_cmd="select name,comment from ike_client where enabled = 'yes'" ;;
	*) return 1 ;
	esac

	local res_line=$(sqlite3 $IK_DB_CONFIG -separator " " "$sql_cmd" |sort -n -k1.$n) 
	echo "${res_line}"|awk '{print $1}'>$IK_DIR_CACHE/ifname/$1.tmp
	mv $IK_DIR_CACHE/ifname/$1.tmp $IK_DIR_CACHE/ifname/$1

	echo "${res_line}">$IK_DIR_CACHE/ifname_comment/$1.tmp
	mv $IK_DIR_CACHE/ifname_comment/$1.tmp $IK_DIR_CACHE/ifname_comment/$1

}

#将网卡名称写到缓存
interface_get_name_to_cache_wan()
{
	__interface_get_name_to_cache wan >/dev/null 2>&1
	__interface_get_name_to_cache wan_phy >/dev/null 2>&1
	__interface_get_name_to_cache wan_all >/dev/null 2>&1
}
interface_get_name_to_cache_lan()  { __interface_get_name_to_cache lan >/dev/null 2>&1 ;}
interface_get_name_to_cache_vlan() { __interface_get_name_to_cache vlan >/dev/null 2>&1 ;}
interface_get_name_to_cache_pptp() { __interface_get_name_to_cache pptp >/dev/null 2>&1 ;}
interface_get_name_to_cache_l2tp() { __interface_get_name_to_cache l2tp >/dev/null 2>&1 ;}
interface_get_name_to_cache_ovpn() { __interface_get_name_to_cache ovpn >/dev/null 2>&1 ;}
interface_get_name_to_cache_wg() { __interface_get_name_to_cache wg >/dev/null 2>&1 ;}
interface_get_name_to_cache_iked() { __interface_get_name_to_cache iked >/dev/null 2>&1 ;}
interface_get_name_to_cache_sovpn()
{
	local res=$(sqlite3 $IK_DB_CONFIG "select enabled from openvpn_server where enabled = 'yes'")
	if [ "$res" ]; then
		echo "sovpn" > $IK_DIR_CACHE/ifname/sovpn		
		echo "sovpn" > $IK_DIR_CACHE/ifname_comment/sovpn		
	else
		echo "" > $IK_DIR_CACHE/ifname/sovpn
		echo "" > $IK_DIR_CACHE/ifname_comment/sovpn
	fi
}

interface_get_name_to_cache_accel()
{
	local res=$(readlink /usr/ikuai/function/accelerator 2>/dev/null)
	if [ "$res" ]; then
		echo "ovpn_accel" > $IK_DIR_CACHE/ifname/accel	
		echo "ovpn_accel" > $IK_DIR_CACHE/ifname_comment/accel
	else
		echo "" > $IK_DIR_CACHE/ifname/accel	
		echo "" > $IK_DIR_CACHE/ifname_comment/accel
	fi
}

#扫描所有的wan口静态IP,把他加入到ipset(Linux_wan_default)
interface_scan_wanaddr_to_ipset()
{
	local tmpfile="/tmp/.interface_scan_wanaddr_to_set.${RANDOM}.$$"
	echo "flush Linux_wan_default" >$tmpfile
	local res
	if res=$(ip -4 addr | awk '{if($NF~/^(v?wan|adsl|pptp|l2tp|ovpn)/)print "add Linux_wan_default "$2}') ;then
		echo "$res" >>$tmpfile
		ipset -! restore -f $tmpfile
	fi

	rm -f $tmpfile
}

interface_add_wanaddr_to_ipset()
{
	ipset -! -A Linux_wan_default $1 2>/dev/null
}

interface_del_wanaddr_to_ipset()
{
	ipset -! -D Linux_wan_default $1 2>/dev/null
}

interface_get_internet()
{
	cat $IK_DIR_CACHE/internet/$1 2>/dev/null
}

interface_check_is_running()
{
	[ "$(cat /sys/class/net/$1/carrier 2>/dev/null)" = "1" ]
}

#检查接口(如 wan1)的PPPOE,如果是的话 那么他的接口名称是 wan1_ad
#在某些情况下需要用到wan1_ad 名称
interface_check_is_wanpppoe()
{
	local interface=$1
	if [ "${interface::3}" = "wan" ];then
		if [ "$__WAN_SET_INTERNET__" ];then
			local internet=$__WAN_SET_INTERNET__
		else
			local internet=$(interface_get_internet $interface)
		fi
		if [ "$internet" = "$INTERNET_PPPOE" ];then
			return 0
		else
			return 1
		fi
	else
		return 1
	fi
}

interface_check_is_bandif()
{
	local interface_member=$(ls /sys/class/net/$1/brif 2>/dev/null)
	[ "$interface_member" ]
}

interface_check_is_default_route()
{
	local interface_member=$(cat $IK_DIR_CACHE/default_route)
	[ "$interface_member" = "$1" ]
}

interface_check_ifaces_num()
{
	local tmp_ifaces=(${1//,/ })

	if [ "${#tmp_ifaces[*]}" -gt "64" ]; then
		return 0
	fi
	return 1
}

interface_get_bonding_member()
{
	local interface_member=$(cat /sys/class/net/$1/bonding/slaves)
	if [ "$interface_member" ]; then
		echo "\"${interface_member// /\",\"}\""
	fi
}

interface_get_member()
{
	local member=""
	for eth in $(ls /sys/class/net/$1/brif 2>/dev/null); do
		if [ "${eth:0:4}" = "bond" ]; then
			local member_one=$(interface_get_bonding_member $eth)
			if [ "$member_one" ]; then
				member+="${member:+,}"${member_one}
			fi
		else
			member+="${member:+,}\"$eth\""
		fi
	done
	if [ "$2" ]; then
		member+="${member:+,}\"$2\""
	fi
	echo "[$member]"
}

# interface_get_ipaddr wan1 --> 192.168.1.1
interface_get_ipaddr()
{
	local interface=$1
	if [ "$interface" ];then
		if interface_check_is_wanpppoe $interface ;then
			local iface=${interface}_ad
		else
			local iface=$interface
		fi
		ip -4 addr list dev $iface |awk '$1=="inet"{gsub("/[0-9]*","",$2);print $2 ;exit}'
	fi
}

interface_get_ipv6addr()
{
	local interface=$1
	if [ "$interface" ];then
		if interface_check_is_wanpppoe $interface ;then
			local iface=${interface}_ad
		else
			local iface=$interface
		fi
		ip -6 addr list dev $iface |awk '$1=="inet6" && $4=="global"{gsub("/[0-9]*","",$2);print $2 ;exit}'
	fi
}

interface_get_ipv6addr_mask()
{
	local interface=$1
	if [ "$interface" ];then
		if interface_check_is_wanpppoe $interface ;then
			local iface=${interface}_ad
		else
			local iface=$interface
		fi
		ip -6 addr list dev $iface |awk '$1=="inet6" && $4=="global"{print $2}'
	fi
}

interface_get_ipv6addr_mask_one()
{
	local interface=$1
	if [ "$interface" ];then
		if interface_check_is_wanpppoe $interface ;then
			local iface=${interface}_ad
		else
			local iface=$interface
		fi
		ip -6 addr list dev $iface |awk '$1=="inet6" && $4=="global"{print $2; exit}'
	fi
}

interface_get_ipv6_linkaddr()
{
	local interface=$1
	if [ "$interface" ];then
		if interface_check_is_wanpppoe $interface ;then
			local iface=${interface}_ad
		else
			local iface=$interface
		fi
		ip -6 addr list dev $iface |awk '$1=="inet6" && $4=="link"{gsub("/[0-9]*","",$2);print $2 ;exit}'
	fi
}

interface_get_if_driver()
{
	local mac="$1"
	local if_driver=$(awk -v mac="$mac" '$2==mac{print $3;exit}' /tmp/iktmp/cache/ether_info)
	echo "$if_driver"
}

lte_get_isp_info()
{
	[ "$SUPPORT_LTE" ] || return

	local if_driver=$(interface_get_if_driver $bandif)
	if [ "$if_driver" != "lte" ]; then
		return
	fi

	local isp=$(ether_get_lte_isp)
	local imei=$(ether_get_lte_imei)
	local power=$(ether_get_lte_csq)
	local ccid=$(ether_get_lte_ccid)
	local qnw=$(ether_get_lte_qnwinfo)
	local qeng=$(ether_get_lte_qeng)
	if [ "$qeng" ]; then
		local $qeng
	fi

	echo "power=$power isp=$isp imei=$imei qnw=$qnw ccid=$ccid isnr=$isnr pcid=$pcid"
}

check_include_vnet()
{
	local macs="$1"
	for mac_one in ${macs//,/ }; do
		if [ "$mac_one" = "00:00:00:00:00:00" ]; then
			return 0
		fi
	done
	return 1
}

interface_get_snapshoot_wan()
{
	cd $IK_DIR_CACHE/config
	declare -A wan_vlan_count
	declare -A wan_vlan_fail_count
	for file in $(ls wan_vlan.*) ;do
		[ ! -f $file ] && continue
		local buf=$(cat $file)
		if [ "$buf" ] ;then
			local $buf
			if read _ _ _ _ _ _ _ check_result errmsg other < /tmp/iktmp/monitor-link/$vlan_name ;then
				if [ "$check_result" != "success" ];then
					wan_vlan_fail_count[$interface]=$((${wan_vlan_fail_count[$interface]} + 1))
				fi
			fi
			wan_vlan_count[$interface.$vlan_internet]=$((${wan_vlan_count[$interface.$vlan_internet]} + 1))
		fi
	done

	local n=0
	printf [
	for file in $(ls -v $IK_DIR_CACHE/config/wan_config.*) ;do
		ip_addr= netmask= gateway= default_route= updatetime=0 dns1= dns2= errmsg=
		count_static=0 count_dhcp=0 count_pppoe=0 count_check_fail=0 check_res=0
		imei= power= isp=
		[ ! -f $file ] && continue
		local buf=$(cat $file)
		if [ "$buf" ] ;then
			local $buf
			interface=$name 
			if [ "$bandif" ];then
				mac=${mac:-${bandif%%,*}}
				local other_member=""
				if check_include_vnet $bandif; then
					other_member="vnet"
				fi
				member=$(interface_get_member "$interface" $other_member)
			else
				member="[]"
			fi
			if [ "$member" != "[]" ];then
				case $internet in
				$INTERNET_STATIC)
					ip_mask=${ip_mask//,*}
					ip_addr=${ip_mask%%/*}
					netmask=${ip_mask##*/}
					;;
				 $INTERNET_PPPOE)
					if . /tmp/iktmp/pppoe/$interface ;then
						ip_addr=$pppoe_ip_addr
						netmask=$pppoe_netmask
						gateway=$pppoe_gateway
						updatetime=$pppoe_updatetime
						dns1=$pppoe_dns1
						dns2=$pppoe_dns2
					else
						ip_addr= netmask= gateway= updatetime= dns1= dns2=
					fi
					local ispinfo=$(lte_get_isp_info)
					[ "$ispinfo" ] && local $ispinfo
					;;
				  $INTERNET_DHCP)
					if . /tmp/iktmp/dhcpc/$interface ;then
						ip_addr=$dhcp_ip_addr
						netmask=$dhcp_netmask
						gateway=$dhcp_gateway
						updatetime=$dhcp_updatetime
						dns1=$dhcp_dns1
						dns2=$dhcp_dns2
					else
						ip_addr= netmask= gateway= updatetime= dns1= dns2=
					fi
					local ispinfo=$(lte_get_isp_info)
					[ "$ispinfo" ] && local $ispinfo
					;;
				esac

				updatetime=${updatetime:-0}

				if [ "$internet" = "$INTERNET_STATIC" -o "$internet" = "$INTERNET_PPPOE" -o "$internet" = "$INTERNET_DHCP" ];then
					if read _ _ _ _ _ _ _ check_result errmsg other < /tmp/iktmp/monitor-link/$interface ;then
						if [ "$check_result" != "success" ];then
							check_res=1
						fi
					fi
				else
					default_route=0
					count_static=${wan_vlan_count[$interface.$INTERNET_STATIC]}
					count_dhcp=${wan_vlan_count[$interface.$INTERNET_DHCP]}
					count_pppoe=${wan_vlan_count[$interface.$INTERNET_PPPOE]}
					count_check_fail=${wan_vlan_fail_count[$interface]}
				fi
			fi

			[ "$((n++))" -gt 0 ]&& printf ,

			
			json_output id:int comment:str interface:str mac:str member:json bandmode:int default_route:int internet:int ip_addr:str netmask:str gateway:str dns1:str dns2:str count_static:int count_dhcp:int count_pppoe:int count_check_fail:int updatetime:int check_res:int errmsg:str power:str isp:str imei:str qnw:str ccid:str isnr:str pcid:str
		fi

	done < $IK_DIR_CACHE/ifname/wan_phy
	echo ]
}


interface_get_snapshoot_lan()
{
	cd $IK_DIR_CACHE/config
	local n=0
	printf [
	while read ifname ;do
		local file=$IK_DIR_CACHE/config/lan_config.$ifname
		[ ! -f $file ] && continue
		local buf=$(cat $file)
		if [ "$buf" ] ;then
			local $buf
			interface=$ifname 
			if [ -n "$bandif" ];then
				mac=${mac:-${bandif%%,*}}
				local other_member=""
				if check_include_vnet $bandif; then
					other_member="vnet"
				fi
				member=$(interface_get_member $interface $other_member)
			else
				member="[]"
			fi
			ip_mask=${ip_mask//,*}
			ip_addr=${ip_mask%%/*}
			netmask=${ip_mask##*/}

			[ "$((n++))" -gt 0 ]&& printf ,
			json_output id:int comment:str interface:str bandmode:int linkmode:int mac:str member:json ip_addr:str netmask:str
		fi

	done < $IK_DIR_CACHE/ifname/lan
	echo ]
}

interface_append_wireguard_json()
{
	local json="$1" name path names
	[ "$json" ] || json="[]"
	names=$(sqlite3 "$IK_DB_CONFIG" "select name from wireguard where name like 'wg%' order by name;" 2>/dev/null)
	for path in /sys/class/net/wg*; do
		[ -e "$path" ] && names="$names
${path##*/}"
	done
	for name in $(printf '%s\n' "$names" | awk 'NF && !seen[$1]++'); do
		echo "$json" | grep -Fq "[\"$name\"]" && continue
		json="${json%?}"
		[ "$json" = "[" ] || json="$json,"
		json="$json[\"$name\"]]"
	done
	echo "$json"
}

interface_is_wireguard_tool_source()
{
	local name="$1" count
	echo "$name" | grep -Eq '^wg[0-9]+$' || return 1
	[ -e "/sys/class/net/$name" ] && return 0
	count=$(sqlite3 "$IK_DB_CONFIG" "select count(*) from wireguard where name='$name';" 2>/dev/null)
	[ "${count:-0}" -gt 0 ]
}
