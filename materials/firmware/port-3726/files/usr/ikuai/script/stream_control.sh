#!/bin/bash /etc/ikcommon

boot()
{
	#open rate statis
	echo 1 > /sys/module/sch_htb/parameters/htb_rate_est
	$IK_DIR_SCRIPT/utils/qos.sh start >/dev/null 2>/dev/null &
}

seting()
{
	local sql_param
	if [ "${CHECK_IS_SETING[stream_ctl_mode]}" ];then
		check_varl 'stream_ctl_mode != "" and >= 0' || exit 1
		sql_param+=" stream_ctl_mode:int"
	fi
	local SqlMsg
	if SqlMsg=$(sql_config_update $IK_DB_CONFIG global_config "id=1" $sql_param) ;then
		__restart_qos
		return 0
	else
		echo  "$SqlMsg"
		return 1
	fi
}

show()
{
	Show __json_result__
}

__show_stream_ctl_mode()
{
	local stream_ctl_mode=$(sqlite3 $IK_DB_CONFIG "select stream_ctl_mode from global_config")
	json_append __json_result__ stream_ctl_mode:int
}

__restart_qos()
{
	killall -q qos.sh
	$IK_DIR_SCRIPT/utils/qos.sh start >/dev/null 2>/dev/null &
}
