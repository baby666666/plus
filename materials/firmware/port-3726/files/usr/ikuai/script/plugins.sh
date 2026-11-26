#!/bin/bash /etc/ikcommon

boot()
{
    $IK_DIR_SCRIPT/feature_port.sh init || return 1
    $IK_DIR_SCRIPT/init_plugins.sh init
    chrootmgt build_chroot
	return
}

show()
{
	Show __json_result__
}

__show_data()
{
	local data
	local _json
	for f in $(ls /usr/ikuai/www/plugins) ;do
		if _json=$(cat /usr/ikuai/www/plugins/$f/metadata.json) ;then
			data+="${data:+,}$_json"
		fi
	done
	data="[$data]"
	json_append __json_result__ data:json
}
