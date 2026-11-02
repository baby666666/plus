#!/bin/bash

REST_VER="v2"
AUDIT_HOST="https://audit.ikuai8.com/api"
CONFIG_BASE_URL="$AUDIT_HOST/$REST_VER/audit/get_audit_conf?gwid="
LIBRARY_BASE_URL="$AUDIT_HOST/$REST_VER/audit/get_audit_so?gwid="
TIME_BASE_URL="$AUDIT_HOST/$REST_VER/audit/update_plugin_time?gwid="
WXTID_URL="$AUDIT_HOST/$REST_VER/audit/get_wechat_decode?gwid="

PUBLISHER_BIN_URL="https://routers.ikuai8.com:6444/audit/publisher/"

CONFIG_PATH="/etc/mnt/audit/ikaudit.conf"
SO_PATH="/etc/mnt/audit/"
SO_NAME="libaudit.so"
WORK_PATH="/etc/log"
#1 表示路径可读，0表示路径不可读
WORK_PATH_STATUS=1
#1 表示当前数据发送已经超时，不再上报，0表示正常上报
AUDIT_TIME_SEND_FLAG=0
AUDIT_TIME_FILE="$SO_PATH""last.time"
#临时时间存储，用来检验数据传输时间是否发生变化
tmp_time=`date +%s`
AUDIT_RUN_TIME="/tmp/last.time"

PLUGIN_NORMAL="0"
PLUGIN_TRANS_ERR="1"
PLUGIN_FS_ERR="2"
PLUGIN_PLUG_ERR="3"

__get_gwid()
{
	if [ -f /etc/release ];then
		## 3.0 version
		local $(cat /etc/release | grep GWID=)
		echo ${GWID}
	elif [ -f /etc/mnt/uid ];then
		## old version
		cat /etc/mnt/uid
	fi
}

__md5_str_check() {
	local md5=(`echo -n "$1" | md5sum | awk '{print $1}'`)
	[ $md5 = $2 ]&& return 0 || return 1
}

__md5_file_check() {
	local md5=$(md5sum $1 | awk '{print $1}')
	[ $md5 = $2 ]&& return 0 || return 1
}

__md5_file() {
	if [ -f "$1" ]; then
		local md5=$(md5sum $1 | awk '{print $1}')
	fi
	
	echo "${md5:-null}"
}

conf_update() {
	md5=$(__md5_file "$CONFIG_PATH")
	CONFIG_URL="$CONFIG_BASE_URL"$gwid"&md5=$md5""&arch=$arch"

	echo "request to $CONFIG_URL"

	if ! curl -4 --connect-timeout 10 -m 20 "$CONFIG_URL"   -o  "/tmp/audit_conf_res.tmp"; then
		rm -f /tmp/audit_conf_res.tmp
		echo "***Failed to download config data."
		return
	fi

	err=`cat /tmp/audit_conf_res.tmp | jq --raw-output '.err'`
	if [ "$err" != 1 ]; then
		errmsg=`cat /tmp/audit_conf_res.tmp | jq --raw-output '.errmsg'`
		echo "***"$errmsg
		rm -f /tmp/audit_conf_res.tmp
		return
	fi

	data=`cat /tmp/audit_conf_res.tmp | jq --raw-output '.data'`
	md5value=`cat /tmp/audit_conf_res.tmp | jq --raw-output '.md5'`
	if __md5_str_check "$data" "$md5value"; then
		echo 'download new version config file success'
		echo -n "$data" > $CONFIG_PATH
	else
		echo "***conf md5 not consistency"
	fi

	rm -f /tmp/audit_conf_res.tmp
	## notify audit client to load config
	killall -s SIGUSR1 ik_audit_client
}

# return value
# 0 sucess
# 1 failed

so_update() {
	# idfile to keep plugin version, webside need to check update
	local idfile="$SO_PATH""plugin.id"
	if [ -f "$idfile" ]; then
		id=$(cat "$idfile")
	else
		id="null"
	fi

	SO_URL="$LIBRARY_BASE_URL""$gwid""&id=$id""&arch=$arch"

	echo "request to $SO_URL"

	if ! curl -4 --connect-timeout 10 -m 20 "$SO_URL"   -o  "/tmp/audit_so_res.tmp"; then
		rm -f /tmp/audit_so_res.tmp
		echo "***Failed to download library path data."
		return 1
	fi

	err=`cat /tmp/audit_so_res.tmp | jq --raw-output '.err'`
	if [ "$err" != 1 ]; then

		errmsg=`cat /tmp/audit_so_res.tmp | jq --raw-output '.errmsg'`
		echo "***"$errmsg
		rm -f /tmp/audit_so_res.tmp

		# err = 0 means no new version library to update and others mean internal error
		[ "$err" = 0 ]&& return 0 || return 1
	fi

	# Enter new version library download routine

	so_url=`cat /tmp/audit_so_res.tmp | jq --raw-output '.data'`
	md5value=`cat /tmp/audit_so_res.tmp | jq --raw-output '.md5'`
	idvalue=`cat /tmp/audit_so_res.tmp | jq --raw-output '.id'`
	rm -f /tmp/audit_so_res.tmp

	echo "downloading library from $so_url"

	so_file=new_audit_plugin_$(date +%s).zip
	ab_so_path="/tmp/""$so_file"
	if ! curl -4 --connect-timeout 10 -m 20 "$so_url"   -o  "${ab_so_path}"; then
		echo "***Failed to download library file"
		return 1
	fi

	if ! __md5_file_check "$ab_so_path" "$md5value"; then
		rm -f "$ab_so_file"
		echo "***md5 check error"
		return 1
	fi

	local plugin_so_exist=$( ls ${SO_PATH}libadtp*.so.* 2>/dev/null)
	if [ -z "${plugin_so_exist}" ] && pidof ik_audit_client ;then
		## notify audit client to unload plugin
		killall -s SIGUSR2 ik_audit_client
		## singal is async,so it's better to wait a while
		sleep 5
	fi

	rm -f ${SO_PATH}*.so.*
	rm -rf ${SO_PATH}template
	rm -rf ${SO_PATH}rc
	rm -rf ${SO_PATH}libadtp_*
	rm -rf $AUDIT_RUN_TIME

	echo "extracting library to path $SO_PATH"

	unzip "$ab_so_path" -d "$SO_PATH"
	if [ $? -eq 0 ]; then
		echo -n "$idvalue" > "$SO_PATH""plugin.id"
		find ${SO_PATH} -name 'libadtp_*.so.*' -exec tar -zvxf '{}' -C ${SO_PATH} \;
		echo "download new version success"
		## notify client to load plugin
		killall -s SIGUSR2 ik_audit_client
	else
		echo "unzip file ${ab_so_path} failed"
		rm -f ${idfile}
		return 1
	fi

	rm -f "$ab_so_path"

	return 0
}

plugin_update() {
	if ! so_update; then
		echo "plugin library update failed"
		return
	fi

	conf_update
}

update_status() {
	local data_status=$1
	local var=$2
	local date_var=$3
	local part0=`echo -n "$var" | tail -c 2`
	local part1=`echo -n "$gwid" | tail -c 2`
	local part2=`echo -n "$var" | tail -c 1`
	local key=`echo -n "$part0""$part1""$part2""19" | base64`
	local time_url="$TIME_BASE_URL""$gwid""&var=$var""&date_var=$date_var""&data_status=$data_status""&ak=$key&arch=$arch"
	echo "request to $time_url"

	if ! curl -4 --connect-timeout 10 -m 20 "$time_url"   -o  "/tmp/audit_time_res.tmp"; then
		echo "***Failed to update audit time"
		rm -f /tmp/audit_time_res.tmp
		return
	fi

	err=`cat /tmp/audit_time_res.tmp | jq --raw-output '.err'`

	if [ "$err" != 0 ]; then
		errmsg=`cat /tmp/audit_time_res.tmp | jq --raw-output '.errmsg'`
		echo "***"$errmsg
	fi
	echo "time update success"

	rm -f /tmp/audit_time_res.tmp
}

__check_if_exit()
{
	local proccess_name=$1
	local wait_seconds=$2

	while [ "$((wait_seconds--))" -gt 0 ] && pidof ${proccess_name} >/dev/null;do
		sleep 1
	done

	if pidof ${proccess_name}  >/dev/null;then
		kill -9 `pidof ${proccess_name}`
	fi
}

audit_status_update() {
	local audit_time=`date +%s`
	local data_trans_time=`date +%s`
	if [ ! -w "$WORK_PATH" ]; then
		if [ $WORK_PATH_STATUS -eq 1 ]; then
			echo "***/etc/log read only"
			update_status $PLUGIN_FS_ERR $audit_time $data_trans_time
			WORK_PATH_STATUS=0
		fi
		return
	else
		WORK_PATH_STATUS=1
	fi

	[ -f "$AUDIT_TIME_FILE" ] || return
	local current_time=`date +%s`
	local audit_time=`cat "$AUDIT_TIME_FILE"`
	local ver=`expr $current_time - $audit_time`
	if [ 3600 -ge $ver ]; then
		if [ ! $tmp_time -eq $audit_time ]; then
			update_status $PLUGIN_NORMAL $audit_time $audit_time
			AUDIT_TIME_SEND_FLAG=0
			tmp_time=$audit_time
		fi
	else
		if [ $AUDIT_TIME_SEND_FLAG -eq 0 ]; then
			update_status $PLUGIN_TRANS_ERR $audit_time $audit_time
			AUDIT_TIME_SEND_FLAG=1
		fi
	fi
}

audit_client_stat_check() {
	local time_file=""
	if [ -f "$AUDIT_RUN_TIME" ]; then
		time_file=$AUDIT_RUN_TIME
	elif [ -f "$AUDIT_TIME_FILE" ]; then
		time_file=$AUDIT_TIME_FILE
	else
		return
	fi
	local current_time=`date +%s`
	local audit_time=`cat "$time_file"`
	local ver=`expr $current_time - $audit_time`
	if [ 3600 -le $ver ]; then
		if pidof ik_audit_client >/dev/null; then
			killall -s SIGTERM ik_audit_client 2>/dev/null
			__check_if_exit ik_audit_client 8
			rm -rf $time_file
		fi
	fi
}

__checkout_newpublisher() {
	local latest_bin="$SO_PATH/publisher/$arch/audit_publisher"

	if [ ! -f "$latest_bin" ]; then
		echo "*** current publisher is lastest version"
		return
	fi

	local cur_ver=$(/usr/bin/ik_audit_publisher -v)
	local new_ver=$("$latest_bin" -v)
	local err_str="invalid"

	if [[ "$cur_ver" == *"$err_str"* ]]; then
		cur_ver="1.20170101"
	fi

	if [[ $new_ver > $cur_ver ]]; then
		local working_link="/usr/bin/ik_audit_publisher"
		rm -f "$working_link"
		ln -s "$latest_bin" "$working_link"

		## monitor process will launch it again
		killall ik_audit_publisher

		echo "checkout new publisher finished"
	fi
}

#*
#* ik_audit_publisher version: major.minor like 1.20171103
#*
publisher_update() {
	local cur_ver=$(/usr/bin/ik_audit_publisher -v)
	local err_str="invalid"

	if [[ "$cur_ver" == *"$err_str"* ]]; then
		## consider all the release version which not support -v option as the first version
		##     and will be updated
		cur_ver="1.20170101"
	fi

	if [ -f "$SO_PATH/publisher/$arch/audit_publisher" ]; then
		cur_ver=$("$SO_PATH"/publisher/$arch/audit_publisher -v)
	fi

	local desc_file="/tmp/audit_publisher.desc"
	local url0="$PUBLISHER_BIN_URL""/desc/""$arch""?gwid=$gwid"

	echo "request to $url0"

	if ! curl -4 --connect-timeout 10 -m 20 "$url0"   -o  "$desc_file"; then
		echo "*** publisher update stage 1 failed"
		rm -f $desc_file
		return
	fi

	local latest_ver=$(cat $desc_file | jq --raw-output '.version')
	local md5=$(cat $desc_file | jq --raw-output '.md5')

	local major0=$(echo $cur_ver| cut -d '.' -f1)
	local major1=$(echo $latest_ver| cut -d '.' -f1)
	local minor0=$(echo $cur_ver | cut -d '.' -f2)
	local minor1=$(echo $latest_ver | cut -d '.' -f2)

	local if_restart_now=$(cat $desc_file | jq --raw-output '.restart')


	rm -f $desc_file

	echo "minor0 $minor0"
	echo "minor1 $minor1"

	if [ "$major0" != "$major1" ]; then
		echo "*** publisher major version non-consistent"
		return
	fi

	if [ "$minor0" -ge "$minor1" ]; then
		echo "*** publisher already latest version"
		return
	fi


	local tmp_bin_path="/tmp/audit_publisher"
	local url1="$PUBLISHER_BIN_URL""/dl/""publisher.$arch"

	echo "request to $url1"

	if ! curl -4 --connect-timeout 10 -m 20 "$url1"   -o  "$tmp_bin_path"; then
		echo "*** publisher update stage 2 failed"
		rm -f $tmp_bin_path
		return
	fi


	if ! __md5_file_check "$tmp_bin_path" "$md5"; then
		echo "*** publisher update download file md5 invalid"
		rm -f "$tmp_bin_path"
		return
	fi

	chmod +x "$tmp_bin_path"

	mkdir -p "$SO_PATH/publisher/$arch"
	mv "$tmp_bin_path" "$SO_PATH/publisher/$arch/"

	echo "latest publisher bin file download success"

	if [ "$if_restart_now" = "yes" ]; then
		__checkout_newpublisher
	fi
}

wxtid_keys_update() {
	[ -f /tmp/wx_tid_update ] || return

	local wx_update_cont=$(cat /tmp/wx_tid_update)

	if [ "$wx_update_cont" != "yes" ]; then
		echo "*** weixin tid keys no need to update"
		return
	fi


	local len=${#gwid}
	local substr=${gwid:$len-1:1}${gwid:$len-2:2}"ikuai"
	local sign_str=$(echo -n $substr | md5sum | awk '{print $1}')

	local url="$WXTID_URL$gwid&sign=$sign_str&arch=$arch"
	local tmpfile="/tmp/audit_wxtid_keys.tmp"

	echo "request to $url"

	if ! curl -4 --connect-timeout 10 -m 20 "$url"   -o  "$tmpfile"; then
		rm -f $tmpfile
		echo "*** Failed to get weixin tid keys."
		return
	fi

	err=$(cat $tmpfile | jq --raw-output '.err')
	if [ "$err" != 1 ]; then
		echo "*** weixin tid keys return error, $err"
		return
	fi

	data=$(cat $tmpfile | jq --raw-output '.data')
	echo $data > /etc/mnt/audit/wxtid.keys

	rm -f $tmpfile

	echo "no" > /tmp/wx_tid_update

	echo "*** Signal to publisher sucess"
	killall -s SIGUSR1 ik_audit_publisher
}

sigint()
{
	echo "INTERUPT BY SIGINT, exiting..."
	rm -f /tmp/ikaudit_update.lock
	exit 0
}

main() {
	trap 'sigint' INT

	if [ -e /tmp/ikaudit_update.lock ]; then
		echo "ikaudit_update is already running now !"
		return
	fi

	touch /tmp/ikaudit_update.lock
	mkdir -p "$SO_PATH"/"publisher"

	## publisher use pmd update
	##__checkout_newpublisher

	while true; do
		plugin_update
		audit_status_update
		audit_client_stat_check
		##publisher_update
		wxtid_keys_update

		sleep 60
	done

}

gwid=$(__get_gwid)
arch=$(uname -m)

main

