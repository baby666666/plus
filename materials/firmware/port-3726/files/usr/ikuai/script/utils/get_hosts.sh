#!/bin/bash /etc/ikcommon
GETHOSTS_PATH="/etc/log/get_hosts"
GETHOSTS_VER_PATH=$GETHOSTS_PATH"/ver"
GETHOSTS_LIST_PATH=$GETHOSTS_PATH"/hosts"
GETHOSTS_LIST_PATH_DECRYPT=$GETHOSTS_PATH"/host_decrypt"
GETHOSTS_VER_PATH_NEW=$GETHOSTS_PATH"/ver_new"
GETHOSTS_LIST_PATH_NEW=$GETHOSTS_PATH"/hosts_new"

GETHOSTS_CONF_PATH="/etc/get_hosts/hosts.conf"

RC_CONF="/etc/remote2/ikuai.conf"
PMD_CONF="/etc/pmd.d/pmd_host"
CRE_CONF="/etc/cre.d/cre_host"
RC_CONF_BAK="/etc/remote2/ikuai.conf_bak"
PMD_CONF_BAK="/etc/pmd.d/pmd_host_bak"
CRE_CONF_BAK="/etc/cre.d/cre_host_bak"

if [ -n "$OEMNAME" -a "$OEMNAME" != "oem" ]; then
	exit 0
fi

boot()
{
	#开机判断如果有历史信息，更新下对应服务域名
	process_new_hosts
	start >/dev/null 2>&1 &
}

check_bind_cn()
{
	local node=$(cat /tmp/iktmp/cache/cloud_node)
	if [ -z "$node" -o "$node" = "0" ];then
		return 0
	fi
	return 1
}

check_rc_ok()
{
	#连续20次检查失败,暂定检查间隔5s
	for i in {1..20}
	do
		conn_cn=$(netstat -tnp |grep ik_rc_client|grep ESTABLISHED|wc -l)
		if [ "$conn_cn" -gt 0 ];then
			return 0
		fi
		seep 5
	done
	return 1
}

str2bin() {
    local str="$1" char val bin
    for ((i=0; i<${#str}; i++)); do
        char="${str:$i:1}"
        printf -v val "%d" "'$char"
        for ((j=128; j>0; j/=2)); do
            (( val & j )) && printf "1" || printf "0"
        done
    done
}

get_hosts_from_url()
{
	local url_list=$(cat $GETHOSTS_CONF_PATH | jq -r '.urls[]')
	local old_ver=$(cat $GETHOSTS_VER_PATH)

	local get_url
	local new_ver
	local url_ver
	local url_host

	for get_url in $url_list; do
		url_ver=$get_url"rAVKB3uJo0AGIfm0SOAj?"$url_arg
		url_host=$get_url"Xca758pKhtcwlNwhypx0"
		#echo "ver:curl \"$url_ver\" -f -s  --connect-timeout 10 -m20"
		new_ver=`curl "$url_ver" -f -s  --connect-timeout 10 -m20`
		if [ -n "$new_ver" ]; then
			if [ "$new_ver" == "$old_ver" ];then
				return 0
			fi
			#echo "host:curl \"$url_host\" -f -s  --connect-timeout 10 -m20 -o $GETHOSTS_LIST_PATH_NEW"
			if curl "$url_host" -f -s  --connect-timeout 10 -m20 -o $GETHOSTS_LIST_PATH_NEW; then
				if ik_get_hosts_clt -t -f $GETHOSTS_LIST_PATH_NEW ;then
					echo "$new_ver" > $GETHOSTS_VER_PATH
					mv $GETHOSTS_LIST_PATH_DECRYPT $GETHOSTS_LIST_PATH 
					process_new_hosts
					return 0
				fi
			fi
		fi
	done
	return 1
}
get_hosts_from_svr()
{
	local old_ver=$(cat $GETHOSTS_VER_PATH)
	local servers=$(cat $GETHOSTS_CONF_PATH|jq -r '.servers[]')
	for server_info in $servers; do
		server_host=${server_info%:*}
		server_port=${server_info#*:}
		#echo "ik_get_hosts_clt -s $server_host -p $server_port -r ${old_ver:-0}"
		ik_get_hosts_clt -s $server_host -p $server_port -r ${old_ver:-0}
		ret=$?
		if [ $ret -eq 0 ] ;then
			sleep 2
			if ik_get_hosts_clt -t -f $GETHOSTS_LIST_PATH_NEW ;then
				mv $GETHOSTS_VER_PATH_NEW $GETHOSTS_VER_PATH
				mv $GETHOSTS_LIST_PATH_DECRYPT $GETHOSTS_LIST_PATH 
				process_new_hosts
				return 0
			fi

		elif [ $ret -eq 1 ]; then
			return 0
		fi
	done
	return 1
	
}

process_new_hosts()
{
	if ! [ -f $GETHOSTS_LIST_PATH ];then
		return 0
	fi
	if ! [ -f $GETHOSTS_VER_PATH ];then
		return 0
	fi
	#备份
	#生成新配置文件
	#重新加载配置文件
	new_rc_host=$(cat $GETHOSTS_LIST_PATH |jq -r '.rc[]')
	new_pmd_host=$(cat $GETHOSTS_LIST_PATH |jq -r '.pmd[]')
	new_cre_host=$(cat $GETHOSTS_LIST_PATH |jq -r '.cre[]')
	if [ -n "$new_rc_host" ]; then
		if ! [ -f $RC_CONF_BAK ];then
			cp $RC_CONF $RC_CONF_BAK
		fi
		new_rc_host=$(cat $GETHOSTS_LIST_PATH|jq -r '.rc[]'|awk -F ':' '{printf(",\"as"NR+100".ikuai8.com:"$2"\"")}')
		sed "/host/ s/\]/${new_rc_host}\]/" $RC_CONF_BAK > $RC_CONF
		sed -i '/##ikuai-begin/,/##ikuai-end/d' /etc/hosts 2>/dev/null
		(	echo "##ikuai-begin"
			cat $GETHOSTS_LIST_PATH| jq -r '.rc[]'|awk -F ':' '{print $1,"as"NR+100".ikuai8.com"}'
			echo "##ikuai-end"
		) >> /etc/hosts
		#重启rc
		killall ik_rc_client
	fi
	if [ -n "$new_pmd_host" ]; then
		if ! [ -f $PMD_CONF_BAK ];then
			cp $PMD_CONF $PMD_CONF_BAK
		fi
		cat $PMD_CONF_BAK > $PMD_CONF
		echo "" >> $PMD_CONF
		cat $GETHOSTS_LIST_PATH |jq -r '.pmd[]' >> $PMD_CONF
		killall pmd
	fi
	if [ -n "$new_cre_host" ]; then
		if ! [ -f $CRE_CONF_BAK ];then
			cp $CRE_CONF $CRE_CONF_BAK
		fi
		cat $CRE_CONF_BAK > $CRE_CONF
		cat $GETHOSTS_LIST_PATH |jq -r '.cre[]' >> $CRE_CONF
		killall cre
	fi
	return 0
}

start()
{
	#避免开机网络不通导致的误判
	sleep 300
	mkdir -p $GETHOSTS_PATH
	
	url_arg=$(echo -n $(str2bin $GWID)|base64 |tr -d '\n')
	while :;do
		if ! check_bind_cn ;then
			sleep 300
			continue
		fi
		if check_rc_ok ;then
			#rc ok, 5分钟后再启动检查
			sleep 300
			continue
		fi
		#get host from url
		if get_hosts_from_url ;then
			#获取到host, 继续下次等待检测
			sleep 300
			continue
		fi
		#前面都没有获取到，最后一次获取，无论成功失败都等待5分钟后重新检测
		get_hosts_from_svr
		rm  $GETHOSTS_VER_PATH_NEW
		rm  $GETHOSTS_LIST_PATH_NEW
		sleep 300
	done
}
