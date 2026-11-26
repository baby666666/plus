#!/bin/bash /etc/ikcommon

ikmessage_db=/etc/log/message.db

init() {
	res=$(sqlite3 $ikmessage_db "select id from ik_message where read != 1")
	if [ -n "$res" ];then
		touch /tmp/iktmp/new_ikmessages
	else
		rm -f /tmp/iktmp/new_ikmessages
	fi
}

quit() {
	rm -f /tmp/ikmessages.on
	exit
}

__start() {
	quit
	if [ -e /tmp/ikmessages.on ];then
		return 0
	else
		touch /tmp/ikmessages.on
	fi
	local node=$(cat /tmp/iktmp/cache/cloud_node)
	if [ "$node" = "0" ]; then
		local cloud_domain="yun.ikuai8.com"
		if [ "$OEMCLOUD" ]; then
			cloud_domain="$OEMCLOUD"
		fi
	else
		local cloud_domain=$(cat /tmp/iktmp/ik_hosts/register)
	fi

	local ik_message_version json_string msg_length msg_title msg_content msg_timestamp

	ik_message_version=$(sqlite3 $ikmessage_db  "select * from ik_message_version")

	if json_string=$(wget -4 -t 1 -T 30 --connect-timeout=30 --dns-timeout=20 -O- -q "https://${cloud_domain}/RouterMes/getMeg_detail?msgv=${ik_message_version:-0}&gwid=$GWID&sysv=$VERSION&fw=$FIRMWARENAME") ;then
		if [ -n "$json_string" ];then
			json_decode msg json_string
			[ "$msg_1_msg_version" = "" ]&& quit

			sqlite3 $ikmessage_db "update ik_message_version set msg_version=${msg_1_msg_version:-0}"

			for((i=2; ; i++));do
				msg_title=$(eval echo \$msg_${i}_title)
				[ "$msg_title" = "" ] && break
				msg_content=$(eval echo \$msg_${i}_content)
				msg_timestamp=$(eval echo \$msg_${i}_timestamp)
				sqlite3 $ikmessage_db "insert into ik_message(id,title,content,timestamp) values(NULL,'$msg_title','$msg_content',${msg_timestamp:-0})"
			done
			init
		fi
	fi

	quit
}

start() {
	__start >/dev/null 2>&1 &
}

del() {
	if sqlite3 $ikmessage_db "delete from ik_message where id in ($id)" ;then
		init
	fi
}

clean() {
	sqlite3 $ikmessage_db "delete from ik_message"
	rm -f /tmp/iktmp/new_ikmessages
}

reading() {
	if sqlite3 $ikmessage_db "update ik_message set read=1 where id in ($id)" ;then
		init
	fi
}

show() {
	local __filter=$(sql_auto_get_filter)
	local __order=$(sql_auto_get_order)
	local __limit=$(sql_auto_get_limit)
	local __where="$__filter $__order $__limit"
	Show __json_result__
}

__show_data() {
	data=$(sql_config_get_json $ikmessage_db "select * from ik_message $__where")
	json_append __json_result__ data:json
}

__show_total() {
	total=$(sqlite3 $ikmessage_db "select count() from ik_message $__where")
	json_append __json_result__ total:int
}

#检查是否有未读消息
__show_new_messages() {
	local new_messages
	if [ -f "/tmp/iktmp/new_ikmessages" ]; then
		new_messages=1
	else
		new_messages=0
	fi
	json_append __json_result__ new_messages:int
}

