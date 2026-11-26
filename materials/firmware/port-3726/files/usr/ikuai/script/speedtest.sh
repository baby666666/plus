#!/bin/bash /etc/ikcommon
Include interface.sh
I18nload speedtest.json

PIDFILE="/var/run/speedtest.pid"
SPEEDTEST="/tmp/iktmp/speedtest"
SPEEDTEST_TASK="/tmp/iktmp/speedtest/task"
SPEEDTEST_TIME="/etc/log/speedtest/timestamp"
SPEEDTEST_RECENT_FILE="/etc/log/speedtest/recent"
SPEEDTEST_LOG="/etc/log/speedtest"
SPEEDTEST_TMP="/tmp/iktmp/speedtest/tmp"

boot() {
	init
}

init() {
	if [ ! -e $SPEEDTEST ];then
		mkdir -p $SPEEDTEST
		mkdir -p $SPEEDTEST_TMP
		mkdir -p $SPEEDTEST_LOG
	fi
	echo -n >$SPEEDTEST_TASK
}

clean() {
	rm -rf $SPEEDTEST
	init
}

__start() {
	[ -e $PIDFILE ]&& return 0
	echo $$ > $PIDFILE
	cd $SPEEDTEST
	
	if [ "$interface" = "all" -o "$interface" = "" ];then
		interface=$(interface_get_ifname wan,sdsaas)
	fi
	start_time=$(date +%s)

	for iface in ${interface//,/ } ;do
		echo "wait" > $iface
	done
	
	for iface in ${interface//,/ } ;do
		echo -n "$iface" >$SPEEDTEST_TASK
		if interface_check_is_wanpppoe $iface;then
			_iface=${iface}_ad
		else
			_iface=${iface}
		fi

		if [ "${_iface:0:6}" != "sdsaas" ] && [ "${_iface:0:2}" != "wg" ]; then
			local link_status=$(awk '{print $8}' /tmp/iktmp/monitor-link/$iface)
			if [ "$link_status" != "success" ];then
				echo "exception" >$iface
				continue
			fi
		fi
		
		__get_test_source || break
		(echo wait ;ikcheck speedtest -I $_iface -T 5 -d 114.114.114.114 -l) > $iface
		cp $iface $SPEEDTEST_LOG/$iface
	done
	stop_time=$(date +%s)
	echo "$stop_time $((stop_time-start_time))" >$SPEEDTEST_TIME

	rm -f $PIDFILE
}

start() {
	clean >/dev/null 2>&1
	__start >/dev/null 2>&1 &
}

stop() {
	ps -w| awk '{if($5 == "{ikcheck}" && $8 == "speedtest") {system("kill "$1)}}'
	rm -f $PIDFILE
	echo -n >$SPEEDTEST_TASK
}

show() {
	Show __json_result__
}

__show_time() {
	local now_time timedesc lastime
	local interval_time=0 
	local speed_time=0
	local now_time=$(date +%s)
	if [ -e "$SPEEDTEST_TIME" ]; then
		timedesc=$(cat $SPEEDTEST_TIME)
		lastime=${timedesc// */}
		interval_time=$((now_time-lastime))
		speed_time=${timedesc//* /}
	fi
	local time
	json_append time speed_time:int interval_time:int

	json_append __json_result__ time:json
}

__show_data()
{
	rm -f $SPEEDTEST_TMP/*
	if [ -e $PIDFILE ];then
		global_status=1
		global_status_msg=$(Iecho i18n_speedtest_global_state_running)
	else
		global_status=0
		global_status_msg=$(Iecho i18n_speedtest_global_state_stop)
	fi
    
	__get_speedtest_data | while read config;do
		if [ -n "$config" ];then
			local $config
			case "$status_msg" in
				wait) status_msg=$(Iecho i18n_speedtest_current_state_wait) ;;
				server_resource_fail) status_msg=$(Iecho i18n_speedtest_current_state_server_resource_fail) ;;
				iface_err) status_msg=$(Iecho i18n_speedtest_current_state_iface_err) ;;
				get_resource) status_msg=$(Iecho i18n_speedtest_current_state_get_resource) ;;
				get_resource_err) status_msg=$(Iecho i18n_speedtest_current_state_get_resource_err) ;;
				get_resource_ok) status_msg=$(Iecho i18n_speedtest_current_state_get_resource_ok) ;;
				preparing) status_msg=$(Iecho i18n_speedtest_current_state_preparing) ;;
				download_running) status_msg=$(Iecho i18n_speedtest_current_state_download_running) ;;
				upload_running) status_msg=$(Iecho i18n_speedtest_current_state_upload_running) ;;
				complete) status_msg=$(Iecho i18n_speedtest_current_state_complete) ;;
				not_speedtest) status_msg=$(Iecho i18n_speedtest_current_state_none) ;;
				exception) status_msg=$(Iecho i18n_speedtest_current_state_exception) ;;
			esac

			echo "interface=$interface status=$status status_msg=$status_msg download=$download upload=$upload down_avg=$down_avg up_avg=$up_avg down_min=$down_min up_min=$up_min down_max=$down_max up_max=$up_max" >>$SPEEDTEST_TMP/$interface
			##状态大于0的表示当前正在测速的状态，小于等于0的表示测速的结果
			if [ "$status" -le "0" ];then
				touch $SPEEDTEST/.finish
			else
				rm $SPEEDTEST/.finish >/dev/null 2>/dev/null
			fi
		fi
    	done
	local data=$(__get_data_sort)
	local task=$(cat $SPEEDTEST_TASK)

    	json_append __json_result__ global_status:int global_status_msg:str task:str data:json
	#将上次成功测速完成的数据记录下来
	if [ -f $SPEEDTEST/.finish ]; then
		echo "$__json_result__" > $SPEEDTEST_RECENT_FILE 
	fi
	return 0
}

__show_recent_data() {
	if [ -f "$SPEEDTEST_RECENT_FILE" ]; then
		local recent_data="$(cat $SPEEDTEST_RECENT_FILE)"
	else
		local recent_data="{}"
	fi
	json_append __json_result__ recent_data:json
}

__show_interface() {
	local interface=$(interface_append_wireguard_json "$(interface_get_ifname_comment_json wan,sdsaas)")
	json_append __json_result__ interface:json
}

__get_data_sort()
{
	local sortdata tmpdata
	for iface in $(ls $SPEEDTEST_TMP/wan* 2>/dev/null; ls $SPEEDTEST_TMP/vwan* 2>/dev/null; ls $SPEEDTEST_TMP/adsl* 2>/dev/null; ls $SPEEDTEST_TMP/sdsaas* 2>/dev/null; ls $SPEEDTEST_TMP/wg* 2>/dev/null); do
		while read config; do
			[ "$config" ] || continue
			local $config
			tmpdata="$(json_output interface:str status:str status_msg:str download:str upload:str down_avg:str up_avg:str down_min:str up_min:str down_max:str up_max:str)"	
			tmpdata="\"$interface\": $tmpdata"
			sortdata+="${sortdata:+,}$tmpdata"
		done <	$iface
	done

	echo "{$sortdata}"
}

__get_test_source() {
	if [ ! -e /tmp/iktmp/speedtest-nearby-src ];then
		echo "get test source" >$iface
		if speedtest-nearby-src >/dev/null 2>/dev/null ;then
			echo "get test source ok" >$iface
			return 0
		else
			echo "get test source fail" >$iface
			return 1
		fi
	else
		return 0
	fi
}

__get_speedtest_data() {
	limit=(${limit//,/ })

	if [ "$interface" = "all" -o "$interface" = "" ];then
		interface=$(interface_get_ifname wan,sdsaas)
        	interface=$(echo "$interface"|sed ':label;N;s/\n/,/;b label')
	fi

	cd $SPEEDTEST

	output='interface=%s status=%s status_msg=%s download=%s upload=%s down_avg=%s up_avg=%s down_min=%s up_min=%s down_max=%s up_max=%s\n'
	output_null='interface=%s status=%s status_msg=%s download=-- upload=-- down_avg=-- up_avg=-- down_min=-- up_min=-- down_max=-- up_max=--\n'

	awk -v Start="${limit[0]:-0}" -v Stop="$((${limit[0]:-0}+${limit[1]:-10000000}))" -v iface="$interface" -v output="$output" -v output_null="$output_null" '
	function init() {
		status_msg="prepare"
		status=1
		down_avg=0
		down_min=0
		down_max=0
		up_avg=0
		up_min=0
		up_max=0
		download=0
		upload=0
		GET_SRC="get test source"
		GET_SRC_OK="get test source ok"
		GET_SRC_FAIL="get test source fail"
		TEST_START_DOWN="Speedtest down start"
		TEST_START_UP="Speedtest up start"
		ERR_INTERFACE="Interface error"
		ERR_NOT_FOUND_SRC="Not found speedtest source"
		TEST_EXCEPTION="exception"
		ST_WAIT="wait"
	}
	function scan(FILENAME) {
		if($0==ST_WAIT){
			status_msg="wait"
			status=1
		}
		else if($0==GET_SRC){
			status_msg="get_resource"
			status=2
		}
		else if($0==GET_SRC_OK){
			status_msg="get_resource_ok"
			status=3
		}
		else if($0==TEST_START_DOWN){
			status_msg="download_running"
			ST=TEST_START_DOWN
			status=4
		}
		else if($0==TEST_START_UP){
			status_msg="upload_running"
			ST=TEST_START_UP
			status=5
		}
		else if($0==ERR_NOT_FOUND_SRC){
			status_msg="server_resource_fail"
			status=-1
		}
		else if($0==ERR_INTERFACE){
			status_msg="iface_err"
			status=-2
		}
		else if($0==GET_SRC_FAIL){
			status_msg="get_resource_err"
			status=-3
		}
		else if($0==TEST_EXCEPTION){
			status_msg="exception"
			status=-4
		}
		else if($1==FILENAME) {
			if(ST==TEST_START_DOWN)download=$4
			else if(ST==TEST_START_UP)upload=$2
		}
		else if($1=="down") {
			down_avg=$4
			down_min=$8
			down_max=$12
		}
		else if($1=="up") {
			up_avg=$4
			up_min=$8
			up_max=$12
			status=0
			status_msg="complete"
		}
	}

	BEGIN {
		split(iface,ifaces,",")
		NR=0
		for(i in ifaces){
			if(ifaces[i]=="")continue
			NR++

			if(NR<Start)continue
			if(NR>=Stop)break
			if(getline<ifaces[i]>0){
				init()
				scan(ifaces[i])
				while(getline<ifaces[i])
					scan(ifaces[i])
				printf output,ifaces[i],status,status_msg, download,upload, down_avg,up_avg, down_min,up_min, down_max,up_max
			} else {
				printf output_null,ifaces[i],0,"not_speedtest"
			}
		}

	}'

}

