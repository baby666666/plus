#!/bin/bash /etc/ikcommon
Include sqlite.sh json.sh timersql.sh

#WEB管理穿透访问
#tunnel_http server_host="1.2.3.4:2222" rsa="base64 code" target_host="127.0.0.1:601"
tunnel_http()
{
	check_varl 'server_host != ""'  'rsa != ""' || exit 1
	if [ "$target_host" -a "${target_port}" ];then
		local __target_host="${target_host}:${target_port}"
	else
		local __target_host="127.0.0.1:601"
	fi
    # Require an independently provisioned host identity; never trust a scan.
    local known_hosts=/etc/mnt/ikuai/ssh-known-hosts
    [[ "$server_host" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ ]] || { echo 'Invalid tunnel host';return 1; }
    [[ "$server_port" =~ ^[0-9]+$ ]] && [ "$server_port" -ge 1 ] && [ "$server_port" -le 65535 ] || { echo 'Invalid tunnel port';return 1; }
    [ -f "$known_hosts" ] && [ ! -L "$known_hosts" ] && [ -s "$known_hosts" ] || { echo 'SSH host key is not provisioned';return 1; }
    chmod 600 "$known_hosts" || return 1
	mkdir -p /root/.ssh/
	if res=$(echo "$rsa" |base64 -d ) ;then
		echo -e "$res" >/root/.ssh/id_rsa
		chmod 600 /root/.ssh/id_rsa 
		ssh -Nf -R "${server_host}:${server_port}:${__target_host}" "${server_host}" -oUserKnownHostsFile="$known_hosts" -oStrictHostKeyChecking=yes -oBatchMode=yes -oConnectTimeout=10 -ltunnel -i /root/.ssh/id_rsa >/dev/null 2>&1 || { echo "SSH tunnel host verification or connection failed";return 1; }
		return 0
	else
		echo "base64 parse faild for param (rsa)"
		return 1
	fi
}

show()
{
	Show __json_result__
}

__show_basic_info()
{
	local enterprise=${ENTERPRISE}
	local router_ver=${VERSION}
	local firmware=${FIRMWARENAME}
	local gwid=${GWID}
	local basic_info=$(json_output firmware:str router_ver:str enterprise:str gwid:str)
	json_append __json_result__ basic_info:json
}

__show_webport()
{
	local webserver_dir="/usr/openresty"
	local webport=$(awk 'NR==2{print $2}' $webserver_dir/conf/webman_temp.conf)

	if [ ! "$webport" ];then
		#随机一个 800-1000 不存在的端口号
		while :;do
			webport=$((RANDOM%200+800))
			if [ "$webport" -lt "989" -a "$webport" != "873" ];then
				if [ "$(netstat -ant |awk '$4=="0.0.0.0:'$webport'"{print}')" = "" ];then
					break
				fi
			fi
		done
		echo -e "server {\n    listen $webport ;\n    set \$temp_webport \"$webport\";\n    include conf/webman.conf ;\n}" > $webserver_dir/conf/webman_temp.conf
		openresty -s reload
		__http_heartbeat >/dev/null 2>&1 &
	else
		touch /tmp/.ikapi_new_webport
	fi

	json_append __json_result__ webport:int
	return 0
}

#检测临时开启的http port,如果在120秒内无任何访问,将会自动关闭
__http_heartbeat()
{
	local timeout=0
	while :;do
		timenow=$(date +%s)
		sleep 120
		if [ -f /tmp/.ikapi_new_webport ];then
			rm -f /tmp/.ikapi_new_webport
			continue
		fi

		if res=$(wget -4 http://127.0.0.1:$webport/check_temp_webport -O- -q) ;then
			if [ "$res" = "nil" ]; then
				res=0
			fi
			if [ "$timenow" -gt "${res:-0}" ];then
				timeout=1
			fi
		else
			timeout=1
		fi

		if [ "$timeout" = "1" ];then
			> $webserver_dir/conf/webman_temp.conf
			openresty -s reload
			break
		fi
	done
}
