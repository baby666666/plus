#!/bin/bash /etc/ikcommon
Include crond.sh,lock.sh

key=12345

boot() {
	init
}
init()
{
	crond_clean cloud_bak
	local $(sql_config_get_list $IK_DB_CONFIG "select * from cloud_bak where id=1")
	local __rule=""
	__exec_crond_set
	crond_insert cloud_bak "$__rule"
	crond_commit
}
__exec_crond_set()
{
	if [ "$enabled" = "yes" -a "$type" = "2" ];then
		[ "$strategy" = "week" ]&&{
				if [ -n "$cyctime" -a -n "$back_time"  ];then
					H=${back_time%:*}
					M=${back_time#*:}
					cyctime=${cyctime//7/0}
					__rule="${M:-*} ${H:-*} * * $cyctime /usr/ikuai/script/cloud_bak.sh backup 2"
				fi
			}
			#每月
		[ "$strategy" = "month" ]&&{
				if [ -n "$cyctime"  ];then
					H=${back_time%:*}
					M=${back_time#*:}
					__rule="${M:-*} ${H:-*} $cyctime * * /usr/ikuai/script/cloud_bak.sh backup 2"
				fi
			}	
	fi
}

backup()
{
	local type_value="$1"
	local node=$(cat /tmp/iktmp/cache/cloud_node)
	if [ "$node" = "0" ]; then
		local cloud_domain="yun.ikuai8.com"
		if [ "$OEMCLOUD" ]; then
			cloud_domain="$OEMCLOUD"
		fi
	else
		local cloud_domain=$(cat /tmp/iktmp/ik_hosts/register)
	fi
	local filename=$($IK_DIR_SCRIPT/backup.sh create_tmpfile 2>/dev/null)
	if [ -z "$filename" ]; then
		return
	fi

	if [ ! -e "$IK_DIR_EXPORT/$filename" ]; then
		return
	fi
	md5_value=$(echo  -n "key=$key&gwid=${GWID}" | md5sum|awk '{print $1}') 
	wget -4 -O- -q -t 5 -T 30 --connect-timeout=30 --dns-timeout=20 "https://${cloud_domain}/UploadConfig?type=${type_value:-1}&gwid=${GWID}&value=$md5_value" --post-file="$IK_DIR_EXPORT/$filename"
	rm -f $IK_DIR_EXPORT/$filename
}

save()
{
	__check_param || exit 1
	local sql_param="enabled:str type:int strategy:str back_time:str cyctime:str"
	touch /tmp/cloud_lock >/dev/null 2>/dev/null
	flock /tmp/cloud_lock >/dev/null 2>/dev/null
	ps |awk '$1!="'$$'"{if($0~/\/usr\/ikuai\/script\/cloud_bak.sh/)system("kill " $1)}'
	sleep 5
	if SqlMsg=$(sql_config_update $IK_DB_CONFIG cloud_bak "id=1" $sql_param);then
		if [ "$enabled" = "yes" -a "$type" = "1" ];then
			backup ${type:-1}
		fi
		init
		echo "$SqlMsg"
		return 0
	else
		echo "$SqlMsg"
		return 1
	fi
}
__check_param()
{
	check_varl \
		'enabled == "yes" or == "no"'\
		'type == 1 or == 2'\
		'strategy != ""'\
		'back_time time'\
		'cyctime > 0'
}
show()
{
	local __filter=$(sql_auto_get_filter)
	local __order=$(sql_auto_get_order)
	local __limit=$(sql_auto_get_limit)
	local __where="$__filter $__order $__limit"
	Show __json_result__
}
__show_data()
{
	local sql_show="select * from cloud_bak $__where"
	local data=$(sql_config_get_json $IK_DB_CONFIG "$sql_show")
	json_append __json_result__ data:json
	return 0
}
