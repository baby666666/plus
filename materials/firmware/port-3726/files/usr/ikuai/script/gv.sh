#!/bin/bash /etc/ikcommon
if [ ! "$ENTERPRISE" ] || [ "$SUPPORT_APT" = "true" ] ; then
	exit 0
fi

Include sys/hdd_control.sh
I18nload upgrade.json

GV_SERVER_ALIVE=/tmp/.gv_server_alive
WGET="wget -t 3 -T 10 --connect-timeout=10 --read-timeout=10 --dns-timeout=10 -q -O-"

boot()
{
	local sn_ret
	local sn=$(hdd_get_sn $BOOTHDD)

	#如果验证失败, 那么继续往下
	if [ "$sn" ];then
		#读取machine_code值
		echo clean > /proc/genuine_verification
		if res=$(__get_proc_gv) ;then
			local $res
		fi

		__set_proc_gv $sn

		if __get_gv_status ;then
			__auto_check_gv >/dev/null 2>&1 &
			return 0
		fi

		#没有写过SN， 走工厂的自动激活流程
		if [ "$sn" = "00000000000000000000000000000000" ];then
			activation
		fi
	fi

	__auto_register_gv >/dev/null 2>&1 &
}

__show_data()
{
	if res=$(__get_proc_gv) ;then
		local $res
		local mc=$machine_code
		local err=0
	else
		local err=3
	fi

	if [ "$(cat $GV_SERVER_ALIVE)" == "0" ] ;then
		local err=2
	fi

	local mac=$DEVICE_MAC
	local gwid=$GWID

	local data=$(json_output mc:str mac:str gwid:str genuine:int err:int)
	json_append __json_result__ data:json

	return 0
}

#写入版本号和序列号到/proc/gv
__set_proc_gv()
{
	echo $1 > /proc/genuine_verification
	usleep 300000
}

#查看/proc/gv
__get_proc_gv()
{
	cat /proc/genuine_verification
}

__get_gv_status()
{
	local res genuine
	if res=$(__get_proc_gv) ;then
		local $res
	fi

	if [ "$genuine" = "1" ];then
		return 0
	else
		return 1
	fi
}

__auto_check_gv()
{
	local status=$(hdd_get_sn_status $BOOTHDD)
	# 0 is confirmed
	if [ "$status" = 0 ];then
		return
	fi

	while :;do
		sleep 10
		##result = ok
		if ! res=$($WGET "https://genuine.ikuai8.com/gv.php?ac=check&mCode=$machine_code&gwid=$GWID&mac=$DEVICE_MAC") ;then
			continue
		fi

		if [ "$res" == "ok" ];then
			return
		elif [ "$res" == "confirmed" ];then
			hdd_set_sn_status $BOOTHDD 0
			return
		else
			clean_sn
			return
		fi
		sleep 20
	done
}


#自动激活正版
__auto_register_gv()
{
	while :;do
		sleep 5

		if ret=$(__get_proc_gv) ;then
			local $ret
		fi

		if __get_gv_status ;then
			echo 1 > $GV_SERVER_ALIVE
			return 0
		fi

		#向服务器发送gwid，版本号，机器码，获得序列号
		if ! sn_ret=$($WGET "https://genuine.ikuai8.com/gv.php?ac=get&mCode=$machine_code&gwid=$GWID") ;then
			echo 0 > $GV_SERVER_ALIVE
			continue
		fi
		echo 1 > $GV_SERVER_ALIVE

		if [[ "$sn_ret" =~ "sn=" ]];then
			sn=""
			local $sn_ret

			if [ "${#sn}" = "32" ];then
				__set_proc_gv $sn
				if __get_gv_status ;then
					#将新的SN写入到磁盘中
					hdd_set_sn $BOOTHDD $sn
				fi
			fi
			return 0
		fi
		sleep 25
	done
}

__echo_tty()
{
	echo "$*" > /dev/tty0
}

show()
{
	Show __json_result__
}

save()
{
	local res

	#已经是激活成功的,无需再重新激活
	if __get_gv_status ;then
		return 0
	fi

	__set_proc_gv $sn
	if __get_gv_status ;then
		hdd_set_sn $BOOTHDD $sn >/dev/null 2>&1
		return 0
	else
		Iecho i18n_upgrade_check_sn_fail
		return 1
	fi
}

clean_sn()
{
	hdd_clean_sn $BOOTHDD
	echo clean > /proc/genuine_verification
}

clean_sn_and_reboot()
{
	clean_sn
	reboot
}

get_sn()
{
	hdd_get_sn $BOOTHDD
}


create()
{
	if [ "$name" = "" -o "${hdd}" = "" ];then
		echo "Need param 'name' and 'hdd'"
		return 1
	fi
	if [ "${#name}" -gt 16 ];then
		echo "param length > 16"
		return
	fi

	local k=$(printf "%-16s" $name |hexdump -n 16 -e '16/1 "%02x"')
	#local k=$(date +%s|md5sum)
	#local k=${k:0:32}
	local k2=$(echo -n "$k"|md5sum)

	if [ -e /dev/${hdd} ] ;then
		for((i=0;i<32;i+=2));do
			printf "\x${k:i:2}"
		done |dd of=/dev/${hdd} bs=16 seek=0 >/dev/null 2>&1
		for((i=0;i<32;i+=2));do
			c=$(printf "%02x" $(( 0x${k2:i:2} ^ 0x${k:i:2})) )
			printf "\x$c"
		done |dd of=/dev/${hdd} bs=16 seek=1 >/dev/null 2>&1

		echo $k
	else
		echo "Error: /dev/${hdd} not found"
	fi
}

#for udhcpc
bound()
{
	echo "activationing: $ip/$mask $router"
}

confeth1()
{
	echo "自动激活: 正在配置为eth1配置DHCP网络."

	local ifname=eth1
	local max=10
	ifconfig $ifname up
	while [ $((max--)) -gt 0 ];do
		local status=$(udhcpc  -i $ifname -s /usr/ikuai/script/gv.sh -t 2 -T 2 -q -n |tail -1)
		local status=($status)
		local ikflags=${status[0]}
		local ipaddr=${status[1]}
		local gateway=${status[2]}
		if [ "$ikflags" = "activationing:" ];then
			echo "自动激活: 获取IP成成功"
			echo " Address: $ipaddr"
			echo " Gateway: $gateway"
			ip add add $ipaddr dev $ifname
			ip route add default via $gateway
			return 0
		else
			echo "自动激活: 获取IP失败, 继续尝试 $max 次"
			sleep 1
		fi
	done

	echo "自动激活: 停止获取DHCP地址, 停止激活"
	return 1
}

activationing()
{
	echo 2 0 0 0 >/proc/sys/kernel/printk
	clear
	if ret=$(__get_proc_gv) ;then
		local $ret
	fi
	local key=$1 name=$2
	local sign=$(echo -n "key=$key&ac=submit&mCode=$machine_code&gwid=$GWID&mac=$DEVICE_MAC" |md5sum)
	local sign=${sign:0:32}

	__echo_tty "==========($name)专用激活程序=========="
	__echo_tty "自动激活: 开始进入自动联网激活配置."
	if confeth1 ;then
		#向服务器发送gwid，版本号，机器码，获得序列号
		if ! sn_ret=$($WGET "https://genuine.ikuai8.com/gv.php?ac=submit&mCode=$machine_code&gwid=$GWID&mac=$DEVICE_MAC&sign=$sign") ;then
			__echo_tty "自动激活: 请求服务器失败"
		else
			if [[ "$sn_ret" =~ "sn=" ]];then
				sn=""
				local $sn_ret

				if [ "${#sn}" = "32" ];then
					__set_proc_gv $sn
					if __get_gv_status ;then
						hdd_set_sn_status $BOOTHDD 1
						hdd_set_sn $BOOTHDD $sn
						__echo_tty hdd_set_sn $BOOTHDD $sn
						echo -e "自动激活: \033[33m激活成功\033[0m" > /dev/tty0
					else
						__echo_tty "自动激活: 校验失败的返回结果"
						__echo_tty "$sn_ret"
					fi
				else
					__echo_tty "自动激活: 无效的返回结果"
					__echo_tty "$sn_ret"
				fi
			else
				__echo_tty "自动激活: 无效的返回结果"
				__echo_tty "$sn_ret"
			fi
		fi
	fi

	__echo_tty ""
	__echo_tty "10秒后自动重启系统"
	sleep 10
	reboot -f
	sleep 999
}

activation()
{
	[ "$VIRTUAL_DEVICE" ] && return
	[ "$BOOTGUIDE" != "hd" ] && return
	[ ! "$ENTERPRISE" ] && return

	cd /sys/block
	local HDD
	for hdd in $(ls -d sd[a-z]) ;do
		[ "$BOOTHDD" = "$hdd" ]&& continue
		if readlink -f $hdd |grep -q usb ;then
			HDD=$hdd
			break
		fi
	done
	if [ "$HDD" ];then
		local name=$(hexdump  /dev/$HDD -n 16 -e '16/1 "%c"')
		local key=$(hexdump  /dev/$HDD -n 16 -e '16/1 "%02x"')
		local key2=$(echo -n $key|md5sum)
		local key2=${key2:0:32}
		local N=($(hexdump  /dev/$HDD -n 32 -e '32/1 "%u "'))
		local x
		for((i=0;i<16;i++));do
			x=$x$(printf "%02x" $((${N[i]} ^ ${N[i+16]})))
		done

		[ "$x" = "$key2" ]&& activationing $key $name
	fi
}
