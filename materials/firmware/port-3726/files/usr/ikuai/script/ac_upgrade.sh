#!/bin/bash /etc/ikcommon
#Internal_operator=1

Include version_all.sh

__upgrade_download_progress()
{
	if [ -f /tmp/apupdate/download.status ];then
		tail /tmp/apupdate/download.status |awk 'BEGIN{res="0%"} {for(i=1;i<=NF;i++){if($i~/[0-9]%/)res=$i}}END{print res}'
	else
		echo "100%"
	fi
}

__upgrade_download_firmware()
{
	local firmware_file="$1"
	local firmware_model="$2"
	local is_router_ap="$3"
	local ap_oemname="$4"
	local firmwarebin="$5"

	echo 2 >/tmp/apupdate/status
	if [ "$OEMNAME" ]; then
		echo "" >/tmp/apupdate/download.model
	else
		echo "$firmware_model" >/tmp/apupdate/download.model
	fi

	local __wget=
	local wget_url=
	local submit_download=$(cat /tmp/iktmp/ik_hosts/submit 2>/dev/null)
	local cloud_node=$(cat /tmp/iktmp/cache/cloud_node 2>/dev/null)
	if [ "$OEM_DL" ];then
		__wget="wget -4 -t 3 -T 20 --connect-timeout=10 --dns-timeout=20"
		wget_url=${OEM_DL%,*}
	elif [ "$submit_download" -a "${cloud_node:-0}" != "0" ]; then
		__wget="wget -4 -t 3 -T 20 --connect-timeout=10 --dns-timeout=20"
		wget_url="$submit_download"
	else
		local cert_path="/etc/ssl/32015"
		__wget="wget -4 -t 3 -T 20 --certificate=$cert_path/ca.crt  --private-key=$cert_path/ca.key --ca-certificate=$cert_path/server.crt --connect-timeout=10 --dns-timeout=20"
		wget_url="download.ikuai8.com:32015"
	fi

	rm -f /tmp/apupdate/IK-*
	if $__wget "https://${wget_url}/apfirmware/$firmware_file?is_router_ap=$is_router_ap&oemname=$ap_oemname&firmwarebin=$firmwarebin" -O /tmp/apupdate/$firmware_file.tmp 2>/tmp/apupdate/download.status ;then
		if [ "$is_router_ap" != "1" ];then
			local check_md5sum=$($__wget -q "https://${wget_url}/apfirmware/md5sum/$firmware_file.md5sum?is_router_ap=$is_router_ap&oemname=$ap_oemname&firmwarebin=$firmwarebin" -O-)
			local src_md5sum=$(md5sum /tmp/apupdate/$firmware_file.tmp)
			local src_md5sum="${src_md5sum:0:32}"
			if [ "$check_md5sum" != "$src_md5sum" ];then
				echo -3 >/tmp/apupdate/status
				rm -f /tmp/apupdate/$firmware_file.tmp
				__ap_upgrade_syslog
				return 1
			fi
			echo "$src_md5sum" > /tmp/apupdate/$firmware_file.md5sum
		fi

		mv /tmp/apupdate/$firmware_file.tmp /tmp/apupdate/$firmware_file
		return 0
	else
		rm -f /tmp/apupdate/$firmware_file.tmp /tmp/apupdate/$firmware_file
		echo -1 >/tmp/apupdate/status
		__ap_upgrade_syslog
		return 1
	fi
}

__upgrade_send_reboot()
{
	echo 3 >/tmp/apupdate/status
	local md5=$(cat /tmp/apupdate/$__firmware_file.md5sum)
	local token=$(date +%s%N|md5sum)
	local $(wum -c wtps -m $mac |awk '{printf "aid=%s ip_addr=%s",$1,$3;exit}') >/dev/null
	if [ "$aid" ];then
		ap_reboot_count+=1
		echo "$mac" >> /tmp/apupdate/reboot_mac
		echo "$mac" >> /tmp/apupdate/update_mac
		ln -sf /tmp/apupdate/$__firmware_file /tmp/iktmp/ac_www/apfirm/${token:0:32}

		wum -c set -w $aid -s "echo -e \"token=${token:0:32}\\nmd5=$md5\" >/etc/.acupgrade ; >/etc/config/wireless; >/sbin/wifi; >/usr/ikuai/script/aptime; reboot"
		sleep 1
		wum -c delete -w $aid >/dev/null 2>&1
		return 0
	fi

	sleep 1
	return 0
}

__upgrade_wait_reboot()
{
	local line
	declare -i wait_count=0
	declare -i wait_timeout=300
	while :;do
		sleep 1
		line=$(wc -l /tmp/apupdate/reboot_mac)
		if [ "${line// *}" = 0 ];then
			return 0
		fi

		wait_count+=1
		if [ "$wait_count" -ge "$wait_timeout" ];then
			echo -2 >/tmp/apupdate/status
			__ap_upgrade_syslog
			return 1
		fi
	done

	return 0
}

__upgrade_direct_update()
{
	local firmware_file="$1"
	local token=$(date +%s%N|md5sum)
	local token=${token:0:32}

	local $(wum -c wtps -m $mac |awk '{printf "aid=%s ip_addr=%s",$1,$3;exit}') >/dev/null
	if [ "$aid" ];then
		ln -sf /tmp/apupdate/$__firmware_file /tmp/iktmp/ac_www/apfirm/$token
		wum -c set -m $mac -s "/usr/ikuai/script/upgrade.sh autoupgrade_apmode $token"
		sleep 1
		wum -c delete -w $aid >/dev/null 2>&1
		return 0
	fi
}

__upgrade_wait_update()
{
	local firmware_file="$1"
	local file_size=$(ls -Ll /tmp/apupdate/$firmware_file | awk '{print $5}')
	#X1 is NAND Flash
	if [ "${firmware_file:0:14}" = "IK-WAAR9344_5G" ];then
		local write_speed=204800
	else
		local write_speed=102400
	fi
	local need_time=$(( file_size / write_speed))

	declare -i wait_count=0
	echo 0 > /tmp/apupdate/wait_update_progress
	echo 4 >/tmp/apupdate/status
	sleep 5
	while [ $wait_count -lt $need_time ];do
		wait_count+=1
		local p=$((wait_count * 100 / need_time))
		echo $p > /tmp/apupdate/wait_update_progress
		sleep 1
	done
}

__upgrade_begin()
{
	version_all_load
	rm -rf /tmp/iktmp/ac_www/apfirm
	mkdir -p /tmp/iktmp/ac_www/apfirm
	echo 1 >/tmp/apupdate/status
	>/tmp/apupdate/reboot_mac
	>/tmp/apupdate/prev_firmware_file
	>/tmp/apupdate/wait_update_progress

	if [ "$id" ] ;then
		local upgrade_where="where connected = 1 and id in ($id)"
	else
		local upgrade_where="where connected = 1"
	fi

	local __sql_implant_code__
	local sql_show="select id,mac,firmware,ap_model,router_ap,oemname,version,on_upgrade,comment,connected(mac) as connected, firmwarebin(firmware, router_ap, oemname) as firmwarebin, new_version(firmware, router_ap, oemname) as new_version from ac_server $upgrade_where order by firmware"
	__sql_implant_code__=$(__implant_code)

	ap_batch_num=10
	declare -i ap_reboot_count=0
	local prev_firmware=""
	local prev_firmware_file=""
	sql_config_get_list $IK_DB_CONFIG "$sql_show"  |\
	while read config ;do
		local $config
		if [ "$prev_router_ap" != "1" ];then
			if [ "$prev_firmware" != "" ] && [ "$prev_firmware" != "${firmware}" -o $ap_reboot_count = $ap_batch_num ];then
				ap_reboot_count=0
				if ! __upgrade_wait_reboot ;then
					> /tmp/apupdate/reboot_mac
					break
				fi

				__upgrade_wait_update "$prev_firmware_file"
				echo 1 >/tmp/apupdate/status
				> /tmp/apupdate/reboot_mac
				> /tmp/apupdate/update_mac
			fi
		fi

		if [ ! "$MAINTEN_FIRMWARE" ];then
			if [ "$new_version" = "" -o "$version" = "" -o "$new_version" = "$version" ];then
				continue
			fi
			if [ "$new_version" -a "$(Version $version)" -ge "$(Version $new_version)" ]; then
				continue
			fi
		fi

		__ap_upgrade_syslog

		if [ "$MAINTEN_FIRMWARE" ];then
			local __firmware_file=$(echo "$MAINTEN_FIRMWARE"|awk -vf=${firmware}_ '$1~"^"f{x=$1} END{print x}')
			if [ ! "$__firmware_file" ];then
				continue
			fi
		else
			local __firmware_file="${firmware}_${new_version}"
			if [ ! -f /tmp/apupdate/$__firmware_file ];then
				#下载固件失败
				if ! __upgrade_download_firmware "$__firmware_file" "$ap_model" "$router_ap" "$oemname" "$firmwarebin" ;then
					break
				fi
			fi
		fi
		echo 1 >/tmp/apupdate/status

		if [ "$router_ap" = "1" ];then
			__upgrade_direct_update "$__firmware_file"
			echo 1 >/tmp/apupdate/status
			> /tmp/apupdate/reboot_mac
			> /tmp/apupdate/update_mac
		else
			__upgrade_send_reboot
		fi

		prev_router_ap="$router_ap"
		prev_firmware="$firmware"
		prev_firmware_file="$__firmware_file"
		echo "$prev_firmware_file" > /tmp/apupdate/prev_firmware_file
	done

	if [ "$(cat /tmp/apupdate/reboot_mac)" != "" ];then
		prev_firmware_file=$(cat /tmp/apupdate/prev_firmware_file)
		if __upgrade_wait_reboot ;then
			__upgrade_wait_update "$prev_firmware_file"
		fi
		> /tmp/apupdate/reboot_mac
		> /tmp/apupdate/update_mac
	fi

	#如果是负数,那么是错误退出,保留错误信息
	#大于0是正在升级的状态,结束时把状态改变为0
	if [ "$(cat /tmp/apupdate/status)" -gt 0 ];then
		echo 0 >/tmp/apupdate/status
	fi

	rm -f /tmp/apupdate/*
	rm -f /tmp/.ac_on_upgrade
	rm -rf /tmp/iktmp/ac_www/apfirm
}

__ap_upgrade_syslog()
{
	I18nload ac_upgrade.json

	local upgrade_status="$(cat /tmp/apupdate/status)"
	local upgrade_status=${upgrade_status:-0}
	local upgrade_status_msg
	local progress=-1

	case $upgrade_status in
	-3)
	    upgrade_status_msg="$(Iecho i18n_ac_upgrade_error_md5sum_fail)"
	    ;;
	-2)
	    local info=$(cat /tmp/apupdate/reboot_mac)
	    local info=${info//$LINE_N/, }
	    if [ "${#info}" -gt 74 ];then
		info="${info:0:76} ......"
	    fi
	    upgrade_status_msg="$(Iecho i18n_ac_upgrade_error_restart_fail '${info[0]}' '${info[1]}')"
	    ;;
	-1) upgrade_status_msg="$(Iecho i18n_ac_upgrade_error_download_fail)" ;;
	 *) upgrade_status_msg="$(Iecho i18n_ac_upgrade_upgrade_msg '$new_version')" ;;
	esac

	local timestamp="$(date +%s)"
	local action="upgrade"
	local comment="$(awk -v mac="$mac" '{if ($1==mac){print $2;exit}}' /tmp/iktmp/apname)"

	logger -t ap_event "$action $timestamp $mac ${comment:---} $upgrade_status_msg"
}

#ap升级
upgrade()
{
	if [ -f /tmp/.ac_on_upgrade ];then
		return
	fi
	touch /tmp/.ac_on_upgrade
	__upgrade_begin >/dev/null 2>&1 &
	fsyslog $(Iecho i18n_fsyslog_upgrade)
}

#filename= origname=
mainten_savefile()
{
	check_varl 'filename != ""' \
		   'origname != ""' || exit 1

	if [ ! -f "$IK_DIR_IMPORT/$filename" ];then
		echo "Not Found file($filename)"
		exit 1
	fi

	mkdir -p /tmp/apupdate/.mainten
	mv $IK_DIR_IMPORT/$filename /tmp/apupdate/.mainten/$origname
}

mainten_upgrade()
{
	local MAINTEN_FIRMWARE=$(ls /tmp/apupdate/.mainten 2>/dev/null)
	if [ ! "$MAINTEN_FIRMWARE" ];then
		echo "Must upload an firmware file"
		return 1
	fi
	if [ -f /tmp/.ac_on_upgrade ];then
		return
	fi
	touch /tmp/.ac_on_upgrade

	ln -sf /tmp/apupdate/.mainten/$MAINTEN_FIRMWARE /tmp/apupdate/
	md5sum=$(md5sum /tmp/apupdate/.mainten/$MAINTEN_FIRMWARE)
	echo "${md5sum:0:32}" > /tmp/apupdate/$MAINTEN_FIRMWARE.md5sum

	__upgrade_begin >/dev/null 2>&1 &
}

mainten_clean()
{
	if [ "$files" ];then
		for f in ${files//,/ } ;do
			rm -f /tmp/apupdate/.mainten/$f
		done
	else
		rm -rf /tmp/apupdate/.mainten
	fi
}

__show_mainten_files()
{
	local mainten=$(ls /tmp/apupdate/.mainten 2>/dev/null)
	mainten="${mainten//$LINE_N/\",\"}"
	mainten_files="[${mainten:+\"$mainten\"}]"
	json_append __json_result__ mainten_files:json
}

show()
{
	local __filter=$(sql_auto_get_filter)
	local __order=$(sql_auto_get_order)
	local __limit=$(sql_auto_get_limit)
	local __where="$__filter $__order $__limit"
	Show __json_result__
}

#嵌入一段sql封装代码
__implant_code()
{
cat -<<EOF
	load_config  = require 'iklua.utils.load_config'
	local version_all = load_config.load_version_ap()
	local online_ap = {}
	local fp = io.popen('wum -c wtps 2>/dev/null')
	if fp then
		for line in fp:lines() do
			aid,mac = line:match('^([^ ]+) ([^ ]+)')
			if aid then
				online_ap[mac] = true
			end
		end
		fp:close()
	end
	ikdb:create_function('connected',1,function (ctx, mac) ctx:result_int(online_ap[mac] and 1 or 0) end)
	ikdb:create_function('firmwarebin',3,
	function (ctx, firm, is_router, oem)
		local _firm
		if is_router == 1 and oem and oem ~= "" and oem ~= "--" then
			_firm = firm .. "_" .. oem .. "_firmware"
		else
			_firm = firm .. "_firmware"
		end

		ctx:result_text(version_all[_firm] or '')
	end)
	ikdb:create_function('new_version',3,
	function (ctx, firm, is_router, oem)
		local _firm
		if is_router == 1 and oem and oem ~= "" and oem ~= "--" then
			_firm = firm .. "_" .. oem
		else
			_firm = firm
		end

		ctx:result_text(version_all[_firm] or '')
	end)

	ikdb:create_function('can_upgrade',5,
	function (ctx, mac, firm, ver, is_router, oem)
		if not online_ap[mac] then
			ctx:result_int(0)
			return
		end
		local _firm
		if is_router == 1 and oem and oem ~= "" and oem ~= "--" then
			_firm = firm .. "_" .. oem
		else
			_firm = firm
		end

		local new_version = version_all[_firm]
		if not new_version or not ver or new_version == '' or ver == '' then
			ctx:result_int(0)
			return
		end

		local new_v1, new_v2, new_v3 = new_version:match('^(%d+).(%d+).(%d+)')
		local v1, v2, v3 = ver:match('^(%d+).(%d+).(%d+)')

		local new_ver = tonumber(string.format('%d%04d%04d',new_v1 or 0,new_v2 or 0,new_v3 or 0))
		local old_ver = tonumber(string.format('%d%04d%04d',v1 or 0,v2 or 0,v3 or 0))

		if new_ver > old_ver then
			ctx:result_int(1)
		else
			ctx:result_int(0)
		end
	end)

	local f = io.open("/usr/ikuai/ik_devcheck/Vendor/iKuai")
	local iKuaiMac  = {}
	local iKuaiExcl = { ["IK-WAQCA9558_5G"] = true, ["IK-MT7628"] = true, ["IK-MT7628w3"] = true, ["IK-MT7620AV1"] = true, ["IK-MT7620AV2"] = true, ["IK-MT7620NV1"] = true, ["IK-MT7620NV2"] = true, ["IK-WAAR9341"] = true, ["IK-WAAR9344_5G"] = true, ["IK-WAQCA9531_H3_5G"] = true }
	if f then
		for line in f:lines() do
			line = line:gsub("%-",":"):lower()
			iKuaiMac[line] = true
		end
		f:close()
	end

	local PirateMac = {}
	local BeyondMac = {}

	local f = io.open("/tmp/iktmp/cache/config/AC/pirated")
	if f then
		for line in f:lines() do
			PirateMac[line] = true
		end
		f:close()
	end
	local f = io.open("/tmp/iktmp/cache/config/AC/black")
	if f then
		for line in f:lines() do
			PirateMac[line] = true
		end
		f:close()
	end
	local f = io.open("/tmp/iktmp/cache/config/AC/beyond")
	if f then
		for line in f:lines() do
			BeyondMac[line] = true
		end
		f:close()
	end

	local f = io.open("/etc/release")
	local Release = {}
	if f then
		for line in f:lines() do
			local key,val = line:match("^([^ ]+) *= *(.+)")
			if key then
				Release[key] = val
			end
		end
		f:close()
	end

	ikdb:create_function('pirated',4,
		function (ctx, mac, firm, oemname, antipiracy)
			local ret = 0
			local __mac = mac:sub(0,8)
			if antipiracy ~= 0 then
				ret = 1
			elseif BeyondMac[mac] then
				ret = 2
			elseif PirateMac[mac] then
				ret = 1
			elseif oemname ~= "oem" then
				if not iKuaiExcl[firm] and not iKuaiMac[__mac] then
					if not Release.OEM_UNCHK_APMAC or Release.OEMNAME ~= oemname then
						ret = 1
					end
				end
			end
			ctx:result_int(ret)
		end
	)
EOF
}


__show_total()
{
	local __sql_implant_code__
	local sql_show="select count() as total,connected(mac) as connected,new_version(firmware, router_ap, oemname) as new_version, can_upgrade(mac, firmware, version, router_ap, oemname) can_upgrade, pirated(mac, firmware, oemname, antipiracy) pirated, comment from ac_server $__filter"
	__sql_implant_code__=$(__implant_code)

	local $(sql_config_get_list $IK_DB_CONFIG "$sql_show")
	json_append __json_result__ total:int
	return 0
}

__show_data()
{
	local __sql_implant_code__
	local sql_show="select id,mac,firmware,ap_model,version,on_upgrade, connected(mac) as connected,new_version(firmware, router_ap, oemname) as new_version, can_upgrade(mac, firmware, version, router_ap, oemname) can_upgrade, pirated(mac, firmware, oemname, antipiracy) pirated, comment from ac_server $__where"
	__sql_implant_code__=$(__implant_code)
	local data=$(sql_config_get_json $IK_DB_CONFIG "$sql_show")
	json_append __json_result__ data:json
	return 0
}

__show_on_upgrade()
{
	if [ -f /tmp/.ac_on_upgrade ];then
		local on_upgrade=1
	else
		local on_upgrade=0
	fi
	json_append __json_result__ on_upgrade:int
}

__show_upgrade_status()
{
	I18nload ac_upgrade.json

	local upgrade_status="$(cat /tmp/apupdate/status)"
	local upgrade_status=${upgrade_status:-0}
	local upgrade_status_msg
	local progress=-1

	case $upgrade_status in
	-3)
	    upgrade_status_msg="$(Iecho i18n_ac_upgrade_error_md5sum_fail)"
	    ;;
	-2)
	    local info=$(cat /tmp/apupdate/reboot_mac)
	    local info=${info//$LINE_N/, }
	    if [ "${#info}" -gt 74 ];then
		info="${info:0:76} ......"
	    fi
	    upgrade_status_msg="$(Iecho i18n_ac_upgrade_error_restart_fail '${info[0]}' '${info[1]}')"
	    ;;
	-1) upgrade_status_msg="$(Iecho i18n_ac_upgrade_error_download_fail)" ;;
	 0) upgrade_status_msg="$(Iecho i18n_ac_upgrade_finish)" ;;
	 1) upgrade_status_msg="$(Iecho i18n_ac_upgrade_begin)" ;;
	 2) 
	    progress=$(__upgrade_download_progress)
	    model=$(cat /tmp/apupdate/download.model)
	    upgrade_status_msg="$(Iecho i18n_ac_upgrade_on_download_firmware '$model' $progress)"
	    ;;
	 3)
	    local info=$(cat /tmp/apupdate/reboot_mac)
	    local info=${info//$LINE_N/, }
	    if [ "${#info}" -gt 74 ];then
		info="${info:0:76} ......"
	    fi
	    upgrade_status_msg="$(Iecho i18n_ac_upgrade_on_restart_ap '$info')"
	     ;;
	 4)
	    local info=$(cat /tmp/apupdate/update_mac)
	    local info=${info//$LINE_N/, }
	    if [ "${#info}" -gt 74 ];then
		info="${info:0:76} ......"
	    fi
	    progress="$(cat /tmp/apupdate/wait_update_progress)"
	    upgrade_status_msg="$(Iecho i18n_ac_upgrade_on_upgrade_ap  '$info')"
	    ;;
	esac

	upgrade_progress=${progress//%}
	if [ "$OEMNAME" ]; then
		upgrade_status_msg="${upgrade_status_msg//\(iKuai-AP\)/}"
		upgrade_status_msg="${upgrade_status_msg//\(\)/}"
	fi
	json_append __json_result__ upgrade_status:int upgrade_progress:int upgrade_status_msg:str
}
