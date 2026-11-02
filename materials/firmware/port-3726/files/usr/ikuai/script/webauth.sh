#!/bin/bash /etc/ikcommon
Include convert_ipmask.sh auth/authqos.sh auth/authcntl.sh crond.sh timersql.sh
Include interface.sh sys/cgroup_control.sh auth/webid.sh urlcode.sh check.sh

__is_decimal_uint()
{
	case "${1-}" in
		''|*[!0-9]*) return 1 ;;
		*) return 0 ;;
	esac
}

TRYOUT_EXPR_REC="/etc/mnt/ikuai/tryout_expired_record"
WEBAUTH_TEMP="/etc/mnt/template/webauth.zip"
boot()
{
	init_template
	start
	restore_webauth
	$IK_DIR_SCRIPT/ik_webauth_roaming.sh init >/dev/null 2>&1 &
}

connect_detection()
{
#获取开关,radius开关,radius_ip
	local $(cat /tmp/iktmp/webauth/auth_mode 2>/dev/null)
	if [ "$enabled" != "yes" -o "$api_radius" != "1"];then
		crond_clean webauth_connect
		crond_commit
		return 0
	fi
#循环三次ping如果都ping不通则关闭认证服务
	for i in 1 2 3; do
		if ikcheck ping $radius_ip -i 1 -c 2 -t 1 >/dev/null 2>&1;then
				return 0
		else
				sleep 1
		fi
	done
	stop
	return 0
}


init_template()
{
	if [ -e $WEBAUTH_TEMP ];then
		rm -rf /tmp/iktmp/webauth/custom
		rm -rf /usr/ikuai/webauth/templates/custom
		ln -s /tmp/iktmp/webauth/custom /usr/ikuai/webauth/templates/custom
		mkdir -p /tmp/iktmp/webauth/custom
		unzip -o $WEBAUTH_TEMP -d /tmp/iktmp/webauth/custom >/dev/null
	fi
}

restart_dnsik8() {
	. /etc/release
	rm -f /tmp/iktmp/ikdnsx.status
	kill -9 $(cat /var/run/ikdnsx.hosts.pid)
	iptables -w -t nat -F DNSIKUAI8
	iptables -w -t nat -F DNSIKUAI8_NOAUTH
	hosts="$(cat /tmp/redirect_domain.txt 2>/dev/null)"

	local domains+="1.0.0.0 $PORTAL\n"

	if [ -z "$OEMNAME" ]; then
		domains+="192.0.0.0 local.ikuai8.com\n"
		domains+="1.0.0.0 portal.ikuai8.com\n"
	fi
	domains+="1.0.0.0 ik.auth.graph.qq.com\n"
	domains+="1.0.0.0 ik.auth.api.weibo.com\n"

	> /tmp/hosts_ikuai8
	echo "ipv4 www.google.com 1.0.0.0" >> /tmp/hosts_ikuai8
	echo -e "$domains" |while read ip domain; do
		if [ -n "$domain" ]; then
			echo "ipv4 $domain $ip" >>/tmp/hosts_ikuai8
			iptables -w -t nat -A DNSIKUAI8 -p udp --dport 53 -m string --hex-string "|$(__hexstring $domain)|" --algo bm -j REDIRECT --to-port 54
		fi
	done

	if [ -e /tmp/iktmp/webauth/auth_switch ];then
		local $(cat /tmp/iktmp/webauth/auth_mode 2>/dev/null)
		if [ "$authip_mode" = "1" -o "$1" = "boot" ] ;then
			#authip_mode = 1 表示针对部分IP做认证，反之全部IP认证
			#主要问题针对 clients3.google.com来判断不需要认证的IP 不解析DNS
			webauth_ipset="-m set --match-set Linux_webauth_default src "
		else
			webauth_ipset=""
		fi
		##已认证的mac地址不在进行dns劫持
		local webauth_authlist="-m set ! --match-set Linux_webauth_authed_list src "

		iptables -w -t nat -A DNSIKUAI8 -p udp --dport 53 $webauth_authlist -j DNSIKUAI8_NOAUTH

		for host in $hosts ;do
			host_hex=$(__hexstring $host)
			echo "ipv4 $host 1.0.0.0"  >> /tmp/hosts_ikuai8
			iptables -w -t nat -A DNSIKUAI8_NOAUTH -p udp --dport 53 $webauth_ipset -m string --hex-string "|${host_hex}|" --algo bm -j REDIRECT --to-port 54
		done
	fi

	echo -e "[global]\nhost = 0.0.0.0\nport = 54\ncache_max = 100\ncache_ttl = 300\nnameserver = 114.114.114.114\nnameserver = 223.5.5.5" > /tmp/hosts_conf
	local cmd="ikdnsx -C /tmp/hosts_conf -S /tmp/hosts_ikuai8 -P /var/run/ikdnsx.hosts.pid"
	$cmd
	echo "$cmd" > /tmp/iktmp/ikdnsx.status
}

start() {

	#auth_ver: 0是官方版本，其他都是OEM版本
	local $(sql_config_get_list $IK_DB_CONFIG "select * from webauth")
	local $(cat $IK_DIR_CACHE/config/basic)
	local AUTH_MAX_TIME="${max_time:-0}"
	local AUTH_IDLE_TIME="${idle_time:-0}"
	local AUTH_MAX_TIME_SECONDS
	if ! __is_decimal_uint "$AUTH_MAX_TIME" || ! __is_decimal_uint "$AUTH_IDLE_TIME"; then
		return 1
	fi
	AUTH_MAX_TIME_SECONDS=$(($AUTH_MAX_TIME * 60))

	iptables -w -F WEBAUTH
	ipset -F Linux_webauth_default
	ipset -F Linux_webauth_white
	ik_cntl auth clear white >/dev/null 2>/dev/null

	sql_config_get_json $IK_DB_CONFIG "select * from webauth" > /tmp/iktmp/webauth/auth_mode.json
	sql_config_get_list $IK_DB_CONFIG "select * from webauth" > /tmp/iktmp/webauth/auth_mode

	if [ "$enc_ssid_noauth" = "1" ];then
		touch /tmp/iktmp/webauth/enc_ssid_noauth
	else
		rm -f /tmp/iktmp/webauth/enc_ssid_noauth
	fi

	if [ "$enabled" = "yes" ] ;then
		local ip_conf sip eip
		touch /tmp/iktmp/webauth/auth_switch
		
		#WEB认证同步(不包括webRadius)
		__sync_auth_start
		
		#忽略synproxy对portal ip的处理
		$IPSET_ADD Linux_portalip_default 1.0.0.0

		#WEBredius开启网络监测
		if [ "$api_radius" = "1" -a "$OEMNAME" = "wtyd" ];then
			crond_clean webauth_connect
			crond_insert webauth_connect "* * * * * $IK_DIR_SCRIPT/webauth.sh connect_detection 2>/dev/null"
			crond_commit
		fi

		#WEBredius开启网络监测
		if [ "$ldap_auth" = "1" -a "$ldap_mode" = "1" ];then
			crond_clean webauth_ldap
			crond_insert webauth_ldap "0 */3 * * * $IK_DIR_SCRIPT/webauth.sh update_ldapinfo 2>/dev/null"
			crond_commit
		else
			crond_clean webauth_ldap
			crond_commit
		fi

		#WEB认证IP群组
		if [ "$authip_mode" = "0" ];then
			#开启全部IP认证
			sip=$(conver_ip2int 0.0.0.0)
			eip=$(conver_ip2int 255.255.255.255)
			Append ip_conf "$LINE_N" "ip_range { start_ip: $sip end_ip: $eip }"
			webauth_ipset=""
		else
			for ip in ${ipgroup//,/ };do
				sip=$(conver_ip2int ${ip%-*})
				eip=$(conver_ip2int ${ip#*-})
				Append ip_conf "$LINE_N" "ip_range { start_ip: $sip end_ip: $eip }"
				$IPSET_ADD Linux_webauth_default $ip
			done
			webauth_ipset="-m set --match-set Linux_webauth_default src "
		fi
		echo -e "$ip_conf" >/tmp/webauth_ipset.txt
		
		if [ -n "$(cat /tmp/webauth_ipset.txt)" -o "$authip_mode" = "0" ] ;then

			#加载白名单域名
			load_white_domain

			#start server
			ik_cntl auth on "${PORTAL}/Action/webauth" "gwid=$GWID&router_ver=$VERSION" >/dev/null 2>/dev/null

			#加载认证IP群组
			__load_ipgroup
			
			#WEB Radius
			__load_radius

			#认证超时预设值
			ik_cntl auth tmp_time 120  >/dev/null
			ik_cntl auth max_time "${AUTH_MAX_TIME_SECONDS:-0}" >/dev/null
			ik_cntl auth idle_time "$AUTH_IDLE_TIME" >/dev/null
			
			#免认证的MAC地址
			load_white_mac

			__http_proxy on
			iptables -w -A WEBAUTH $webauth_ipset -j ACCEPT
			rm -f /tmp/webauth_ipset.bin /tmp/webauth_ipset.txt

			#加载AC AP加密上线的client mac 为免认证
			__load_client_enc_mac >/dev/null 2>/dev/null &
			__crond_webauth start
			__load_ldapinfo >/dev/null 2>&1 &
		else
			stop
		fi
        	if [ "$link_mode" = "1" ];then
           		$IK_DIR_SCRIPT/basic.sh __start_bypass_auth $listenport $backport
		fi
	else
		stop
	fi

	openresty -s reload
}


load_white_domain() {
	if [ ! -e /tmp/iktmp/webauth/auth_switch ];then
		return 0
	fi

	[ "$1" = "sync" ]&& local $(sql_config_get_list $IK_DB_CONFIG "select * from webauth")	#如果通过外部调用的，那么读取一下数据库
	WHITE_FILE_CONF="/usr/libproto/white_wifi_filter.txt"
	WHITE_FILE="/tmp/white_wifi.txt"
	WHITE_DATA="/tmp/white_wifi.dat"
	REDIRECT_DOMAIN="/tmp/redirect_domain.txt"
	WHITE_IP_FILE="/tmp/white_wifi.ip.$$"
	rm -f $WHITE_FILE $WHITE_DATA $REDIRECT_DOMAIN
	: > "$WHITE_IP_FILE"
	gawk \
		-v whiteip="$whiteip" \
		-v white_ip_file="$WHITE_IP_FILE" \
		-v redirect_domain="$REDIRECT_DOMAIN" \
		-v api_switch="$api_switch" \
		-v api_radius="$api_radius" \
		-v user_auth="$user_auth" \
		-v coupon_auth="$coupon_auth" \
		-v qq_auth="$qq_auth" \
		-v weibo_auth="$weibo_auth" \
		-v facebook_auth="$facebook_auth" \
		-v twitter_auth="$twitter_auth" \
		-v google_auth="$google_auth" \
		-v phone_auth="$phone_auth" \
		-v static_pwd="$static_pwd" \
		-v nopasswd="$nopasswd" \
		-v weixin="$weixin" \
		-v allow_tryout="$allow_tryout" \
		-v weixin_absorb="$weixin_absorb" \
		-v redpacket_auth="$redpacket_auth" \
		-v weixin_mini="$weixin_mini" \
		-v popups="$popups" \
		-v popups_android="$popups_android" \
		-v popups_ios="$popups_ios" \
		-v weixin2="$weixin2" \
		-v api_url="$api_url" \
		-v whitelist="$whitelist" \
		-v whitelist_https="$whitelist_https" '
	function AddWhiteIp(addr) {
		if(addr!="")print addr >> white_ip_file
	}
	BEGIN{
	INDEX["HTTP_URL"]=0; INDEX["HTTP_HOST"]=1; INDEX["HTTP_USER_AGENT"]=2; INDEX["HTTP_REFERER"]=3; INDEX["HTTP_SEQ"]=4; INDEX["HTTP_PRAGMA"]=5; INDEX["HTTP_ACCEPT"]=6
	INDEX["HTTP_COOKIE"]=7; INDEX["HTTP_KEEP_ALIVE"]=8; INDEX["HTTP_CACHE_CONTROL"]=9; INDEX["HTTP_CONTENT_ENCODING"]=10; INDEX["HTTP_CONTENT_LANGUAGE"]=11; INDEX["HTTP_CONTENT_TYPE"]=12
	INDEX["HTTP_RANGE"]=13; INDEX["HTTP_CONTENT_LENGTH"]=14; INDEX["HTTP_CONNECTION"]=15; INDEX["HTTP_DATE"]=16; INDEX["HTTP_TRANSFER_ENCODING"]=17; INDEX["HTTP_UPGRADE"]=18; INDEX["HTTP_VIA"]=19
	INDEX["HTTP_ACCEPT_CHARSET"]=20; INDEX["HTTP_ACCEPT_ENCODING"]=21; INDEX["HTTP_ACCEPT_LANGUAGE"]=22; INDEX["HTTP_AUTHORIZATION"]=23; INDEX["HTTP_FROM"]=24; INDEX["HTTP_IF_MODIFIED_SINCE"]=25
	INDEX["HTTP_IF_MATCH"]=26; INDEX["HTTP_IF_NONE_MATCH"]=27; INDEX["HTTP_IF_RANGE"]=28; INDEX["HTTP_IF_UNMODIFIED_SINCE"]=29; INDEX["HTTP_MAX_FORWARDS"]=30; INDEX["HTTP_PROXY_AUTHORIZATION"]=31
	INDEX["HTTP_AGE"]=32; INDEX["HTTP_LOCATION"]=33; INDEX["HTTP_PROXY_AUTHENTICATE"]=34; INDEX["HTTP_PUBLIC"]=35; INDEX["HTTP_RETRY_AFTER"]=36; INDEX["HTTP_SERVER"]=37; INDEX["HTTP_VARY"]=38
	INDEX["HTTP_WARNING"]=39; INDEX["HTTP_WWW_AUTHENTICATE"]=40; INDEX["HTTP_ALLOW"]=41; INDEX["HTTP_CONTENT_BASE"]=42; INDEX["HTTP_CONTENT_LOCATION"]=43; INDEX["HTTP_CONTENT_MD5"]=44
	INDEX["HTTP_CONTENT_RANGE"]=45; INDEX["HTTP_ETAG"]=46; INDEX["HTTP_EXPIRES"]=47; INDEX["HTTP_LAST_MODIFIED"]=48; INDEX["HTTP_VERSION"]=49; INDEX["HTTP_STATUS"]=50; INDEX["HTTP_PRIV"]=51
	INDEX["HTTP_EXT"]=52; INDEX["HTTP_BODY"]=53; INDEX["HTTP_MAX"]=54; INDEX["HTTP_PRIV3"]=55; INDEX["HTTP_X_REQUEST_WITH"]=56; INDEX["HTTP_SET_COOKIE"]=57; INDEX["HTTP_MAX"]=58

	FUN["api_switch"]=api_switch
	FUN["api_radius"]=api_radius
	FUN["default"]="1"
	FUN["user_auth"]=user_auth
	FUN["coupon_auth"]=coupon_auth
	FUN["qq_auth"]=qq_auth
	FUN["weibo_auth"]=weibo_auth
	FUN["facebook_auth"]=facebook_auth
	FUN["twitter_auth"]=twitter_auth
	FUN["google_auth"]=google_auth
	FUN["phone_auth"]=phone_auth
	FUN["static_pwd"]=static_pwd
	FUN["nopasswd"]=nopasswd
	FUN["weixin"]=weixin
	FUN["allow_tryout"]=allow_tryout
	FUN["weixin_absorb"]=weixin_absorb
	FUN["redpacket_auth"]=redpacket_auth
	FUN["weixin_mini"]=weixin_mini

	if (popups=="1") {
		if (popups_ios=="1") {
			POP_SW["ios"]="ON"
		} else {
			POP_SW["ios"]="OFF"
		}
		if (popups_android=="1") {
			POP_SW["android"]="ON"
		} else {
			POP_SW["android"]="OFF"
		}
	} else {
		POP_SW["android"]="OFF"
		POP_SW["ios"]="OFF"
	}
	POPUPS_FILTERS=""
	HTTP_FILTERS=""
	PRIOR_HTTP_FILTERS=""
	PAIR=1

	if(FUN["weixin_absorb"]=="1"){
		FUN["weixin2"]="1"
	}else{
		FUN["weixin2"]=weixin2
	}
	if(FUN["redpacket_auth"]=="1"){
		FUN["weixin2"]="1"
	}
	if(FUN["weixin_mini"]=="1"){
		FUN["weixin2"]="1"
	}
	}
	function FormatPopups() {
		HEADERS=""
		FUNCTION=""
		HTTP_ACTION=""
		RULE=""
		delete(INVERT)
		for(i=1;i<=NF;i++){
			if(match($i,"([^=]+) *= *\"(.+)\"",a)==0)return
			
			v=a[1]
			k=a[2]
			if(v=="FUNCTION"){ FUNCTION=k }
			else if((FUNCTION!="") && (v==POP_SW[FUNCTION]"_HTTP_ACTION")){ HTTP_ACTION=k }
			else if(v~/^INVERT/){ gsub("INVERT_","",v);INVERT[v]="\n\t\tinvert: "k }
			else {
				ID=INDEX[v]
				if(ID!=""){
					DATA=k
					HEADERS=sprintf("headers { \n\t\t\tdata: \"%s\" \n\t\t\tindex: %s %s\n\t\t}\n\t\t%s",DATA,ID,INVERT[v],HEADERS)
				}
			}
		} 
		if(HEADERS!="" &&  HTTP_ACTION!=""){
			RULE=sprintf("\tmatch_rules { \n\t\t%s \n\t\taction: %s \n\t}\n",HEADERS,HTTP_ACTION)
			POPUPS_FILTERS=POPUPS_FILTERS""RULE
		}
	}
	function FormatHttp() {
		HEADERS=""
		FUNCTION=""
		HTTP_ACTION=""
		RULE=""
		delete(INVERT)
		for(i=1;i<=NF;i++){
			if(match($i,"([^=]+) *= *\"(.+)\"",a)==0)return
			
			v=a[1]
			k=a[2]
			if(v=="FUNCTION"){ FUNCTION=k }
			else if(v=="HTTP_ACTION"){ HTTP_ACTION=k }
			else if(v~/^INVERT/){ gsub("INVERT_","",v);INVERT[v]="\n\t\tinvert: "k }
			else {
				ID=INDEX[v]
				if(ID!=""){
					DATA=k
					HEADERS=sprintf("headers { \n\t\t\tdata: \"%s\" \n\t\t\tindex: %s %s\n\t\t}\n\t\t%s",DATA,ID,INVERT[v],HEADERS)
				}
			}
		} 
		if(HEADERS!="" && FUNCTION!="" && HTTP_ACTION!="" && FUN[FUNCTION]=="1"){
			RULE=""
			RULE=sprintf("\tmatch_rules { \n\t\t%s \n\t\taction: %s \n\t}\n",HEADERS,HTTP_ACTION)
			HTTP_FILTERS=HTTP_FILTERS""RULE
		}
	}
	function FormatHttps() {
		HEADERS=""
		HEADERS_RED=""
		HEADERS_RED2=""
		FUNCTION=""
		for(i=1;i<=NF;i++){
			if(match($i,"([^=]+) *= *\"(.+)\"",a)==0)return
			v=a[1]
			k=a[2]
			if(v=="FUNCTION"){ FUNCTION=k }
			else if(v=="HTTPS_HOST"){
				
				DATAS=k
				split(DATAS,b,",")
				for(ii in b){ 
					if(b[ii]!="")HEADERS=sprintf("\tauth_domain: \"%s\"\n%s",b[ii],HEADERS)
					if(b[ii]!="")HEADERS_RED=sprintf("\tdomain: \"%s\"\n%s",b[ii],HEADERS_RED)
					if(b[ii]!="")HEADERS_RED2=sprintf("%s\n%s",b[ii],HEADERS_RED2)
				}
				
			}
		} 
		if(FUN[FUNCTION]=="1"){
			printf "%s",HEADERS
			printf "%s",HEADERS_RED2 >"/tmp/iktmp/webauth/white_https.txt"
			printf "%s",HEADERS_RED >"/tmp/white_wifi.https"
		}	
	}
	function FormatIpset() {
		HEADERS=""
		HEADERS_RED=""
		FUNCTION=""
		for(i=1;i<=NF;i++){
			if(match($i,"([^=]+) *= *\"(.+)\"",a)==0)return
			v=a[1]
			k=a[2]
			if(v=="FUNCTION"){ FUNCTION=k }
			else if(v=="IPADDR"){
				
				DATAS=k
				split(DATAS,b,",")
				for(ii in b){
					AddWhiteIp(b[ii])
				}
				
			}
		} 
	}
	function FormatDomain() {
		for(i=1;i<=NF;i++){
			if(match($i,"([^=]+) *= *\"(.+)\"",a)==0)return
			v=a[1]
			k=a[2]
			if(v=="DOMAIN"){
				split(k,b,",")
				for(ii in b){
					if(b[ii]!=""){
					printf "%s ",b[ii] >redirect_domain
					}
				}
			}
		} 
	}
	function FormatPriorHttp() {
		RULE=""
		#自动把API的域名加白名单
		if(FUN["api_switch"]=="1" || FUN["api_radius"]=="1"){
			if(match(api_url,"//([^/:]+)",u)){
				RULE=""
				RULE=sprintf("\tmatch_rules { \n\t\theaders { \n\t\t\tdata: \"%s\" \n\t\t\tindex: 1\n\t\t}\n\t\taction: AUTH_ACCEPT\n\t}\n",u[1])
				PRIOR_HTTP_FILTERS=PRIOR_HTTP_FILTERS""RULE
			}
		}
		#优先处理用户自定义
		split(whitelist,w,",")
		for(ii in w){ 
			if(w[ii]!=""){
				RULE=""
				RULE=sprintf("\tmatch_rules { \n\t\theaders { \n\t\t\tdata: \"%s\" \n\t\t\tindex: 1\n\t\t}\n\t\taction: AUTH_ACCEPT\n\t}\n",w[ii])
				PRIOR_HTTP_FILTERS=PRIOR_HTTP_FILTERS""RULE
			}
		}
	}
	function PrintHttpFilters() {
		print "filter {\n"PRIOR_HTTP_FILTERS""POPUPS_FILTERS""HTTP_FILTERS"}"
	}
	
	{
		if($1=="[HTTP]"){ 
			CONFIG="HTTP"
		}
		else if($1=="[HTTPS]"){
			if (!PAIR) { print "}";PAIR=1 }
			CONFIG="HTTPS"
			print "auth_domains {";PAIR=0 
			print "white_https {" >"/tmp/white_wifi.https"
			#优先处理用户自定义
			split(whitelist_https,w,",")
			for(ii in w){ 
				if(w[ii]!=""){
					printf "\tauth_domain: \"%s\"\n",w[ii]
					printf "%s\n",w[ii] >"/tmp/iktmp/webauth/white_https.txt"
					printf "\tdomain: \"%s\"\n",w[ii] >"/tmp/white_wifi.https"
				}
			}
		}
		else if($1=="[IPGROUP]"){
			CONFIG="IPGROUP"
			#加载用户自定义白名单IP
			split(whiteip,w,",")
			for(ii in w){ 
				if(w[ii]!=""){
					AddWhiteIp(w[ii])
				}
			}
		}
		else if($1=="[POPUPS]"){
			CONFIG="POPUPS"
		}
		else if($1=="[DOMAIN]"){
			CONFIG="DOMAIN"
		}
		else if($1~/^\[.+\]$/){
			CONFIG="UNKNOWN"
		}
		else {
			if(CONFIG=="HTTP"){
				FormatHttp()
			}
			else if(CONFIG=="HTTPS"){
				FormatHttps()
			}
			else if(CONFIG=="IPGROUP"){
				FormatIpset()
			}
			else if(CONFIG=="POPUPS"){
				FormatPopups()
			}
			else if(CONFIG=="DOMAIN"){
				FormatDomain()
			}
		}
		
	}
	END {
		if (!PAIR) { print "}";PAIR=1 }
		FormatPriorHttp()
		PrintHttpFilters()
		printf "\twhite_https_ipset: \x22Linux_webauth_white_https\x22\n\tredirect_port: 700\n}\n" >"/tmp/white_wifi.https"
	}
		' $WHITE_FILE_CONF > $WHITE_FILE
	while IFS= read -r white_ip; do
		check_is_ipall "$white_ip" && $IPSET_ADD Linux_webauth_white "$white_ip"
	done < "$WHITE_IP_FILE"
	rm -f "$WHITE_IP_FILE"

		#超时配置
	local user_type_id=1 coupon_type_id=2 static_type_id=3 phone_type_id=4 qq_type_id=5 weibo_type_id=6 nopasswd_type_id=7 weixin_type_id=8,12 tryout_type_id=11 radius_type_id=13 facebook_type_id=15 redpacket_type_id=16 twitter_type_id=17 google_type_id=18 hotel_type_id=19
	local MAX_TIME IDLE_TIME TYPE_ID ID conf
	for i in user coupon qq weibo phone static nopasswd weixin tryout facebook twitter google redpacket hotel;do
		TIMEOUT_VAR="${i}_timeout"
		MAX_TIME_VAR="${i}_max_time"
		IDLE_TIME_VAR="${i}_idle_time"
		TYPE_ID_VAR="${i}_type_id"
		if [ "${!TIMEOUT_VAR}" = "1" ];then
			MAX_TIME="${!MAX_TIME_VAR}"
			IDLE_TIME="${!IDLE_TIME_VAR}"
			TYPE_ID="${!TYPE_ID_VAR}"
			if ! __is_decimal_uint "$MAX_TIME" || ! __is_decimal_uint "$IDLE_TIME"; then
				continue
			fi
			MAX_TIME_SECONDS=$(($MAX_TIME * 60))
			for ID in ${TYPE_ID//,/ };do
				Append conf "$LINE_N" "auth_method_config {"
				Append conf "$LINE_NT" "auth_method: $ID"
				Append conf "$LINE_NT" "max_auth_time: ${MAX_TIME_SECONDS:-0}"
				Append conf "$LINE_NT" "max_idle_time: ${IDLE_TIME:-0}"
				Append conf "$LINE_N" "}"
			done
		fi
		done

	if [ "$weixin_absorb" = "1" ];then
		Append conf "$LINE_N" "permit_no_http: true"
	else
		Append conf "$LINE_N" "permit_no_http: false"
	fi

	Append conf "$LINE_N" "dummy_dns {"
	Append conf "$LINE_NT" "domain: \"www.google.com\""
	Append conf "$LINE_NT" "port: 54"
	Append conf "$LINE_N" "}"

	[ "$https_redirect" = "1" ]&& Append conf "$LINE_N" "$(cat /tmp/white_wifi.https)" #合并HTTPS 重定向规则

	Append conf "$LINE_N" 'auth_ifs: "lan*"'
	Append conf "$LINE_N" 'auth_ifs: "vlan*"'
	Append conf "$LINE_N" 'white_ip_set: "Linux_webauth_white"'
	echo -e "$conf" >>$WHITE_FILE

	cd /usr/lib
	protoc-c --encode=WhiteUrlList libqqsec_proto.so.2   < $WHITE_FILE  > $WHITE_DATA
	ik_cntl auth white_list $WHITE_DATA >/dev/null
	restart_dnsik8 >/dev/null 2>/dev/null &
}

load_white_mac()
{
	ik_cntl auth clear white >/dev/null 2>/dev/null
	ipset -F Linux_webauth_white_mac
	noauth_mac=${noauth_mac,,}
	for mac in ${noauth_mac//,/ } ;do
		ik_cntl auth add mac ${mac//[:-]/} white >/dev/null 2>/dev/null
		$IPSET_ADD Linux_webauth_white_mac $mac
	done
}

update_white_mac()
{
	declare -A NEW_WHITE_MAC
	declare -A OLD_WHITE_MAC

	for mac_one in ${old_noauth_mac//,/ }; do
		OLD_WHITE_MAC[$mac_one]=1
	done

	##添加新的
	for mac_one in ${noauth_mac//,/ }; do
		NEW_WHITE_MAC[$mac_one]=1
		##如果不在老的mac白名单, 则添加
		if [ "${OLD_WHITE_MAC[$mac_one]}" != "1" ]; then
			ik_cntl auth add mac ${mac_one//[:-]/} white >/dev/null 2>/dev/null
			$IPSET_ADD Linux_webauth_white_mac $mac_one
		fi
	done

	##删掉老的
	for mac_one in ${old_noauth_mac//,/ }; do
		##如果不在新的mac白名单, 则删除
		if [ "${NEW_WHITE_MAC[$mac_one]}" != "1" ]; then
			ik_cntl auth del mac ${mac_one//[:-]/} white >/dev/null 2>/dev/null
			ipset -! -D Linux_webauth_white_mac $mac_one
		fi
	done

	unset NEW_WHITE_MAC
	unset OLD_WHITE_MAC
}

period_start()
{
	sqlite3 $IK_DB_CONFIG "update webauth set enabled='yes'"
	local __is_restart__=true
	stop
	start
}

period_stop()
{
	sqlite3 $IK_DB_CONFIG "update webauth set enabled='no'"
	local __is_restart__=true
	stop
}

restart()
{
	local __is_restart__=true
	stop
	start
}


stop()
{
	crond_clean webauth_connect
	crond_commit
	local $(cat $IK_DIR_CACHE/config/basic)
	__http_proxy off
	killall -q ik_web_radius
	rm -f /tmp/iktmp/ik_sync_server.status
	killall -q ik_sync_server
	ik_cntl auth off >/dev/null 2>/dev/null
	ik_cntl http_app_data id 20 off >/dev/null 2>/dev/null
	iptables -w -F WEBAUTH 
	iptables -w -F WEBAUTH_QOS
	ipset -F Linux_webauth_default
	ipset -F Linux_webauth_white
	ipset -F Linux_webauth_authed
	ipset -F Linux_webauth_white_mac
	ipset -! -D Linux_portalip_default 1.0.0.0

	rm -f /tmp/iktmp/authqos/webauth
	rm -f /tmp/WEBAUTHUSERQOS
	rm -f /tmp/iktmp/webauth/tmp_auth/* 
	rm -f /tmp/iktmp/webauth/auth_switch
	if res=$(iktimerc "select * from authuser where ppptype='web'; delete from authuser where ppptype='web'") ;then
		echo "$res" | authcntl_kick ppp_online_kick >/dev/null 2>&1
	fi
	rm -f /tmp/iktmp/ik_web_radius.status
	rm -f /etc/api/webradius.ini
	rm -f /tmp/iktmp/webauth/imperceptible
	restart_dnsik8 >/dev/null 2>/dev/null &
	__crond_webauth stop
	rm -f $IK_DIR_CONF/backup_webauth.gz
	rm -f $TRYOUT_EXPR_REC
	rm -f /tmp/iktmp/webauth/enc_ssid_noauth
	local auto_auth_switch="/etc/mnt/ikuai/mac_autoauth"
	if [ "$link_mode" = "1" ] && [ ! -f "$auto_auth_switch" ];then
		$IK_DIR_SCRIPT/basic.sh __stop_bypass_auth $listenport
	fi
}

save() {
	if [ "$sync_switch" = "" ];then
		sync_switch=0
	fi
	local sql_param
	local timer_restart_week=${timer_restart_week:-1234567}
	sql_param+=" enabled:str timer_restart:int timer_event:str timer_restart_week:str timer_restart_time:str enc_ssid_noauth:int max_time:int idle_time:int"
	sql_param+=" user_auth:int coupon_auth:int qq_auth:int weibo_auth:int phone_auth:int redpacket_auth:int static_pwd:int nopasswd:int"
	sql_param+=" weixin:int weixin2:int weixin_mini:int facebook_auth:int twitter_auth:int google_auth:int openapi_auth:int custom_auth:int hotel_auth:int authip_mode:int allow_tryout:int tryout_time:int auto_auth:int"
	sql_param+=" popups:int popups_ios:int popups_android:int auto_auth_timeout:int api_switch:int api_url:str passwd:str ipgroup:str custom_appkey:str"
	sql_param+=" noauth_mac:str whitelist:str whitelist_https:str whiteip:str api_radius:int imperceptible:int macbind_server:str nasname:str radius_ip:str radius_key:str radius_authport:int radius_accountport:int radius_interval:int radius_basip:str api_ipchange_url:str"
	sql_param+=" coupon_up:int coupon_down:int weixin_up:int weixin_down:int phone_up:int phone_down:int nopasswd_up:int nopasswd_down:int redpacket_up:int redpacket_down:int static_pwd_up:int static_pwd_down:int weibo_up:int weibo_down:int tryout_up:int tryout_down:int qq_up:int qq_down:int facebook_up:int facebook_down:int google_up:int google_down:int twitter_up:int twitter_down:int hotel_up:int hotel_down:int"
	sql_param+=" weixin_absorb:int https_redirect:int user_timeout:int coupon_timeout:int qq_timeout:int weibo_timeout:int phone_timeout:int static_timeout:int nopasswd_timeout:int weixin_timeout:int redpacket_timeout:int facebook_timeout:int google_timeout:int twitter_timeout:int hotel_timeout:int tryout_timeout:int user_max_time:int user_idle_time:int coupon_max_time:int coupon_idle_time:int hotel_max_time:int hotel_idle_time:int"
	sql_param+=" qq_max_time:int qq_idle_time:int weibo_max_time:int weibo_idle_time:int phone_max_time:int phone_idle_time:int static_max_time:int static_idle_time:int nopasswd_max_time:int nopasswd_idle_time:int weixin_max_time:int weixin_idle_time:int redpacket_max_time:int redpacket_idle_time:int facebook_max_time:int facebook_idle_time:int google_max_time:int google_idle_time:int twitter_max_time:int twitter_idle_time:int tryout_max_time:int tryout_idle_time:int sync_switch:int interface:str group_key:str group_id:int"
	sql_param+=" uri_add_apinfo:int"
	ldap_port=${ldap_port:-389}
	sql_param+=" ldap_auth:int ldap_usergroup:str ldap_url:str ldap_mode:int ldap_cname:str ldap_port:int ldap_base:str ldap_admin_dn:str ldap_admin_passwd:str ldap_share_count:int" ##ldap协议
	sql_param+=" proxy_service:int proxy_ipaddr:str"
    Append conf "$LINE_N" "phone_auth='$phone_auth'"
	__init_int $sql_param
	__check_global_param || exit 1

	if [ "${api_switch:-0}" = "1" -o "${api_radius:-0}" = "1" ]; then
		api_url=$(url_decode $api_url)
		api_ipchange_url=$(url_decode $api_ipchange_url)
	fi

	if [ "${api_radius:-0}" = "1" ];then
		check_radius_param="enabled api_radius imperceptible macbind_server nasname radius_ip radius_key radius_authport radius_accountport radius_interval radius_basip api_ipchange_url api_switch api_url"
		local $(sql_config_get_list $IK_DB_CONFIG "select ${check_radius_param// /,} from webauth where id=1" prefix=old_)
	fi

	if SqlMsg=$(sql_config_update $IK_DB_CONFIG webauth "id=1" $sql_param) ;then
		if [ "$enabled" = "yes" ] ;then
			if [ "${api_radius:-0}" = "1" ];then
				if NewOldVarl $check_radius_param ;then
					radius_norestart=1
				else
					stop
				fi
			fi
			start
		else
			stop
		fi
	else
		echo "$SqlMsg"
		return 1
	fi
}

switch()
{
	check_varl 'enabled == "yes" or == "no"' || exit 1
	local sql_param="enabled:str "
	if SqlMsg=$(sql_config_update $IK_DB_CONFIG webauth "id=1" $sql_param) ;then
		if [ "$enabled" = "yes" ] ;then
			start
		else
			stop
		fi
	else
		echo "$SqlMsg"
		return 1
	fi
}

#清理免费试用的MAC(添加动作 在 auth/authcntl.sh库中 踢用户下线的事件中)
tryout_mac_clean() {
	date_now=$(date +%Y%m%d)
	if [ -f "$TRYOUT_EXPR_REC" ] && ! grep $date_now $TRYOUT_EXPR_REC >/dev/null 2>&1;then
		rm -f $TRYOUT_EXPR_REC
	fi
}


sync_template()
{
	__sync_template >/dev/null 2>&1 &
	return 0
}

#备份web认证列表,在下次开机启动时 自动加载
#主要做web认证持久化功能
backup_webauth()
{
	local old_authuser_last_timeold authuser_last_time

	if [ -f $IK_DIR_CONF/authuser_last_time ];then
		old_authuser_last_timeold=$(cat $IK_DIR_CONF/authuser_last_time)
	fi

	authuser_last_time=$(timersql_exec "select timestamp from authuser_last_time")
	if [ "$old_authuser_last_timeold" != "$authuser_last_time" -a "$authuser_last_time" != "-1" ];then
		timersql_exec "select * from authuser where ppptype='web' and webid != ${WEBID_RADIUS}" |gzip -9 >$IK_DIR_CONF/backup_webauth.tmp
		mv $IK_DIR_CONF/backup_webauth.tmp $IK_DIR_CONF/backup_webauth.gz
	fi
}

#将备份的web认证列表加载到 timersql 和 ik_code
#注意: 加载备份数据 必须将在web认证服务启动以后
#      启动web认证服务 必须 在lan设置之前启动,保证在无终端连接的时候 处理完这些事物
restore_webauth()
{
	if [ -f $IK_DIR_CONF/backup_webauth.gz ];then
		Include auth/authqos.sh
		local now_timestamp=$(date +%s)
		local _timeout=$((now_timestamp+180))
		gunzip < $IK_DIR_CONF/backup_webauth.gz |\
		while read config ;do
			local $config
			if [ "$expires" -le "$_timeout" -a "$expires" != "0" ];then
				pppuser_offtime_update "$username" "$expires"
				continue
			fi

			packages=${packages:-0}
			timersql_insert authuser packages:int packname:str auth_time:int session:str uid:str username:str expires:int ip_addr:str mac:str interface:str ppptype:str pppdev:str upload:int download:int phone:str name:str comment:str webid:int proxy_username:str

			if [ "$proxy_username" ]; then
				if [ "$ppptype" = "web" ];then
					local ip_addr=$mac
				fi
				$IK_DIR_SCRIPT/pppoe_proxy.sh proxy_connect username=$username ip=$ip_addr >/dev/null 2>&1 &
			fi

			ik_cntl auth add mac ${mac//:} $webid >/dev/null 2>&1
			authqos_webauth_add $mac $upload $download >/dev/null 2>&1
			$IPSET_ADD Linux_webauth_authed $mac
			if [ "$webid" = "${WEBID_USER}" ];then
				pppuser_comment_add "$username" "$mac" "$name" "$comment"
			fi
			pppuser_conntime_update "$username" "$now_timestamp"
		done
	fi
}

#单独设置白名单
seting()
{
	local sql_param
	if [ "${CHECK_IS_SETING[noauth_mac]}" ];then
		check_varl 'noauth_mac  macs or == ""' || exit 1
		sql_param+=" noauth_mac:str"
	fi
	if [ "${CHECK_IS_SETING[whiteip]}" ];then
		check_varl 'whiteip ipall_not_ipmasks or == ""' || exit 1
		sql_param+=" whiteip:str"
	fi
	if [ "${CHECK_IS_SETING[whitelist]}" ];then
		sql_param+=" whitelist:str"
	fi
	if [ "${CHECK_IS_SETING[whitelist_https]}" ];then
		sql_param+=" whitelist_https:str"
	fi
	
	if [ ! "$sql_param" ];then
		echo "not found one param"
		return 1
	fi
	local res=$(sql_config_get_list $IK_DB_CONFIG "select noauth_mac,whiteip,whitelist,whitelist_https from webauth" prefix=old_)
	if [ -z "$res" ]; then
		echo "not found webauth config"
		return 1
	fi
	local $res

	local SqlMsg
	if SqlMsg=$(sql_config_update $IK_DB_CONFIG webauth "id=1" $sql_param) ;then
		if [ "${CHECK_IS_SETING[noauth_mac]}" ] && ! NewOldVarl noauth_mac;then
			update_white_mac
		fi
		
		local load_flag=0
		if [ "${CHECK_IS_SETING[whiteip]}" ] && ! NewOldVarl whiteip;then
			load_flag=1
		fi
		if [ "${CHECK_IS_SETING[whitelist]}" ] && ! NewOldVarl whitelist;then
			load_flag=1
		fi
		if [ "${CHECK_IS_SETING[whitelist_https]}" ] && ! NewOldVarl whitelist_https;then
			load_flag=1
		fi

		if [ "$load_flag" = "1" ]; then
			load_white_domain sync
		fi
		return 0
	else
		echo  "$SqlMsg"
		return 1
	fi
}

vrrp_init()
{
	sqlite3 $IK_DB_CONFIG "delete from webauth"
	sqlite3 $IK_DIR_LOG/vrrp/conf/config.db ".dump webauth" |grep "^INSERT"| sqlite3 $IK_DB_CONFIG
	start
}


show()
{
	Show __json_result__
}

__show_data()
{
	local sql_show="select * from webauth"
	local data=$(sql_config_get_json $IK_DB_CONFIG "$sql_show")
	json_append __json_result__ data:json
	return 0
}

__show_template()
{
	local template=0
	if [ -e "$WEBAUTH_TEMP" ]; then
		template=1
	fi
	json_append __json_result__ template:int
}

__show_sync_interface()
{
	local interface=$(interface_get_ifname_json wan,lan)
	json_append __json_result__ interface:json
}

__sync_auth_start() {
	rm -f /tmp/iktmp/ik_sync_server.status
	killall -q ik_sync_server
	if [ "$sync_switch" = "1" ] ;then
		cgroup_exec ik_sync_server -i $interface -k $group_key -n $group_id -a >/dev/null 2>/dev/null &
		echo "ik_sync_server -i $interface -k $group_key -n $group_id -a >/dev/null 2>/dev/null" > /tmp/iktmp/ik_sync_server.status 
	fi
}

#同步云下发的模板,这个接口在云上面调用
#当云设置好模板以后,点保存时下发一个URL给此函数
#该函数会去下载模板到本地
#sync_template url=https://xxxx.ikuai8.com/xxxx.gz
__sync_template()
{
	local temp_file="/tmp/wifi_sync_template_$$"
	if wget -4 -q -t 5 -T 30 --connect-timeout=30 --dns-timeout=20 "$url" -O $temp_file >/dev/null 2>&1 ;then
		mkdir -p /etc/mnt/template
		mv $temp_file $WEBAUTH_TEMP
		init_template
	fi
}


__check_global_param() {
	check_varl \
		'enabled		== "yes" or == "no"' \
		'enc_ssid_noauth        == 0 or == 1'\
		'timer_restart          == 0 or == 1'\
		' [ timer_restart == 1 ] && {
			timer_restart_week     week or == "" ;
			timer_restart_time     time or timerange ;
		}' \
		'max_time		>= 0' \
		'idle_time		>= 0' \
		'authip_mode	== 1 or == 0' \
		'[ authip_mode == 1 ] && {
			ipgroup		ips_mashup ;
		}' \
		'popups		  	== 1 or == 0' \
		'popups_ios	  	== 1 or == 0' \
		'popups_android	== 1 or == 0' \
		'https_redirect == 1 or == 0' \
		'noauth_mac  macs or == ""' \
		'whiteip		ipall_not_ipmasks or == ""'\
		'[ sync_switch == 1 ] && {
			interface	ifname_lan or ifname_wan;
			group_key	!= "" ;
			group_id		>= 0 ;
		}'
}

__init_int() {
	for i in $*;do
		[ "${i#*:}" == "int" ] && eval "[ \"\$${i%:*}\" == \"\" ] && ${i%:*}=0" 
	done
}


radius_macbind_request()
{
	local imperceptible=$(sqlite3 $IK_DB_CONFIG "select imperceptible from webauth where enabled='yes'")
	if [ "$imperceptible" != "1" ]; then
		return
	fi
	#发送macbind消息，查询终端是否已经认证了
	local tmpfile=$(cat /proc/ikuai/stats/host_stats 2>/dev/null)
	while read ip mac other; do
		[ "$ip" -a "$mac" ] || continue
		ik_webradius_ctl -t online -o $mac -i $ip >/dev/null 2>&1
	done <<EOF
	$tmpfile
EOF
}


__load_radius() {

	#判断云上面保存时,radius参数 未发现变化时,不需要重新加载配置
	if [ "$radius_norestart" = "1" ];then
		return 0
	fi

	if [ "$api_radius" = "1" ];then
		if [ -n "$api_ipchange_url" ];then
			echo "${api_ipchange_url}?gwid=$GWID&nasname=$nasname&basip=$radius_basip" >/tmp/iktmp/webauth/api_ipchange_url
		else
			rm -f /tmp/iktmp/webauth/api_ipchange_url
		fi
		if [ -z "$macbind_server" ]; then
			macbind_server="$radius_ip"
		fi
		local rds_conf rds_ini
		Append rds_conf "$LINE_N" "auth_order      radius"
		Append rds_conf "$LINE_N" "imperceptible   ${imperceptible:-0}"
		Append rds_conf "$LINE_N" "macbind_server   $macbind_server"
		Append rds_conf "$LINE_N" "macbind_nas      ${nasname:-iKuai}"
		Append rds_conf "$LINE_N" "radius_basip    $radius_basip"
		Append rds_conf "$LINE_N" "authserver      ${radius_ip}:${radius_authport}"
		Append rds_conf "$LINE_N" "acctserver      ${radius_ip}:${radius_accountport}"
		Append rds_conf "$LINE_N" "servers         /etc/radiusclient/servers"
		Append rds_conf "$LINE_N" "dictionary      /etc/radiusclient/dictionary"
		Append rds_conf "$LINE_N" "seqfile         /var/run/radius.seq"
		Append rds_conf "$LINE_N" "mapfile         /etc/radiusclient/port-id-map"
		Append rds_conf "$LINE_N" "default_realm "
		Append rds_conf "$LINE_N" "radius_timeout  10"
		Append rds_conf "$LINE_N" "radius_retries  3"
		Append rds_conf "$LINE_N" "nas_identifier ${nasname}"
		Append rds_conf "$LINE_N" "interim_interval ${radius_interval:-60}"
		echo -e "$rds_conf" >/etc/radiusclient/radiusclient.conf

		echo "${radius_ip} ${radius_key}" > /etc/radiusclient/servers
		ik_web_radius >/dev/null 2>&1 &
		touch /tmp/iktmp/ik_web_radius.status

		Append rds_ini "$LINE_N" "[radius_client]"
		Append rds_ini "$LINE_N" "port=3799"
		Append rds_ini "$LINE_N" "addr=$radius_ip"
		Append rds_ini "$LINE_N" "auth_code=${radius_key}"
		Append rds_ini "$LINE_N" "enable=1"
		echo -e "$rds_ini" >/etc/api/webradius.ini
		$IK_DIR_SCRIPT/3rd_server.sh restart &
		if [ "$imperceptible" = "1" ]; then
			touch /tmp/iktmp/webauth/imperceptible
			radius_macbind_request
		else
			rm /tmp/iktmp/webauth/imperceptible
		fi
	else
		rm -f /etc/api/webradius.ini
		rm -f /tmp/iktmp/ik_web_radius.status
		rm -f /tmp/iktmp/webradius-status/*
		rm -f /tmp/iktmp/webauth/imperceptible
		killall -q ik_web_radius
		$IK_DIR_SCRIPT/3rd_server.sh restart &

	fi
}

__load_ipgroup() {
	cd /usr/lib
	protoc-c --encode=IPSet libipset.so.2 < /tmp/webauth_ipset.txt > /tmp/webauth_ipset.bin
	ik_cntl auth ipset /tmp/webauth_ipset.bin >/dev/null
}

__hexstring() {
	echo "${1//./$'\x0a'}" |awk -F "" '
	BEGIN {
		for (i=0;i<=255;i++) a[sprintf("%c",i)]=i ;
	} 
	
	{
		printf "%0.2x ",NF
		for(ii=1;ii<=NF;ii++)printf "%0.2x ",a[$ii]
	} END {
		printf "00"
	}'
}


#客户端通过ikuai的AP，并使用加密连接的 直接跳过web认证
__load_client_enc_mac()
{
	[ ! -f /tmp/iktmp/webauth/enc_ssid_noauth ] && return
	[ ! -f /tmp/iktmp/AC.status ] && return

	ipset -L Linux_webauth_wifi_enc |\
	while read mac; do
		check_is_mac "$mac" && \
		  ik_cntl auth add mac ${mac//:/} wifi_enc >/dev/null 2>/dev/null
	done
}

__load_ldapinfo()
{
	#LDAP开启且配置了管理员路径，获取服务器的账号信息
	if [ "$ldap_auth" = "1" -a "$ldap_base" -a "$ldap_admin_dn" -a "$ldap_admin_passwd" -a "$ldap_port" -a "$ldap_mode" = "1" ]; then
		rm /tmp/ldapinfo 2>/dev/null
		ldapsearch -h $ldap_url  -p $ldap_port -D "$ldap_admin_dn" -w "$ldap_admin_passwd" -b "$ldap_base" -LLL -x >/tmp/ldapinfo
		if [ "${ldap_admin_dn:0:3}" = "uid" ]; then
			$IK_DIR_SCRIPT/utils/ldapinfo_load.lua uid
		else
			$IK_DIR_SCRIPT/utils/ldapinfo_load.lua
		fi
	fi
}

timer_ldapload()
{
	if [ "$ldap_url" -a "$ldap_base" -a "$ldap_admin_dn" -a "$ldap_admin_passwd" -a "$ldap_port" -a "$ldap_mode" = "1" ]; then
		ldapsearch -h $ldap_url -p $ldap_port -D "$ldap_admin_dn" -w "$ldap_admin_passwd" -b "$ldap_base" -LLL -x >/tmp/.ldapinfo.$$	
		if [ "$?" = "0" ]; then
			mv /tmp/.ldapinfo.$$ /tmp/ldapinfo
			if [ "${ldap_admin_dn:0:3}" = "uid" ]; then
				$IK_DIR_SCRIPT/utils/ldapinfo_load.lua uid
			else
				$IK_DIR_SCRIPT/utils/ldapinfo_load.lua
			fi
			return 0
		fi
	fi
	return 1
}

update_ldapinfo()
{
	local $(sql_config_get_list $IK_DB_CONFIG "select ldap_auth,ldap_usergroup,ldap_url,ldap_port,ldap_mode,ldap_base,ldap_admin_dn,ldap_admin_passwd from webauth")
	if [ "$ldap_auth" = "1" -a "$ldap_mode" = "1" ]; then
		timer_ldapload >/dev/null 2>&1 &
	fi
	return 0
}

__crond_webauth()
{
	[ "$__is_restart__" = "true" ]&&return

	local period_stop_flag=0
	crond_clean webauth
	crond_insert webauth "*/30 * * * * $IK_DIR_SCRIPT/webauth.sh tryout_mac_clean 2>/dev/null"
	if [ "$1" = "start" ];then
		crond_insert webauth "* * * * * $IK_DIR_SCRIPT/webauth.sh backup_webauth"
		if [ "$timer_restart" = "1" ];then
			##指定时间段开启认证
			local timer_restart_week=${timer_restart_week//7/0}
			if [ "$timer_event" = "period" ]; then
				local timeinfo=(${timer_restart_time//-/ })	
				local timeinfo_left=${timeinfo[0]}
				local timeinfo_right=${timeinfo[1]}

				local H_left=${timeinfo_left%:*}
				local M_left=${timeinfo_left#*:}
				local H_right=${timeinfo_right%:*}
				local M_right=${timeinfo_right#*:}
				if [ "$timer_restart_week" = "1234560" ];then
					crond_insert webauth "$M_left $H_left * * * $IK_DIR_SCRIPT/webauth.sh period_start"
					crond_insert webauth "$M_right $H_right * * * $IK_DIR_SCRIPT/webauth.sh period_stop"
				else
					for((i=0;i<7;i++));do
						k=${timer_restart_week:i:1}
						[ "$k" = "" ]&&break
						crond_insert webauth "$M_left $H_left * * $k $IK_DIR_SCRIPT/webauth.sh period_start"
						crond_insert webauth "$M_right $H_right * * $k $IK_DIR_SCRIPT/webauth.sh period_stop"
					done
				fi
				period_stop_flag=1
			else
				local H=${timer_restart_time%:*}
				local M=${timer_restart_time#*:}
				if [ "$timer_restart_week" = "1234560" ];then
					crond_insert webauth "$M $H * * * $IK_DIR_SCRIPT/webauth.sh restart"
				else
					for((i=0;i<7;i++));do
						k=${timer_restart_week:i:1}
						[ "$k" = "" ]&&break
						crond_insert webauth "$M $H * * $k $IK_DIR_SCRIPT/webauth.sh restart"
					done
				fi
			fi

			
		fi
	fi

	crond_commit

	if [ "$period_stop_flag" = "1" ]; then
		local now_time="$(date +%s)"
		local week_day="$(date +%u)"
		local auth_start="$(date +%s -d $timeinfo_left)"
		local auth_end="$(date +%s -d $timeinfo_right)"
		local weeks=${timer_restart_week//0/7}

		if [[ "$weeks" =~ $week_day ]]; then
			if ! [ "$now_time" -ge "$auth_start" -a "$now_time" -le "$auth_end" ]; then
				period_stop
			fi
		else
			period_stop
		fi
	fi

}

__http_proxy()
{
	iptables -w -t nat -D HTTPPROXY -d 1.0.0.0 -p tcp --dport 80 -j REDIRECT --to-ports 689 >/dev/null 2>&1
	iptables -w -t nat -D HTTPPROXY -d 1.0.0.0 -p tcp --dport 443 -j REDIRECT --to-ports 700 >/dev/null 2>&1
	iptables -w -t nat -F HTTPSPROXY
	iptables -w -t nat -D HTTPPROXY -j HTTPSPROXY >/dev/null 2>&1
	ik_cntl https_redirect on >/dev/null 2>&1
	if [ "$1" = "on" ];then
		iptables -w -t nat -A HTTPPROXY -d 1.0.0.0 -p tcp --dport 80 -j REDIRECT --to-ports 689 >/dev/null 2>&1
		iptables -w -t nat -A HTTPPROXY -d 1.0.0.0 -p tcp --dport 443 -j REDIRECT --to-ports 700 >/dev/null 2>&1
		if [ "$proxy_service" = "1" -a "$proxy_ipaddr" ]; then
			iptables -w -t nat -A  HTTPSPROXY -m addrtype ! --dst-type LOCAL -p tcp --dport 443 -m urlroute  ! --urlroute httpsauth -j DNAT --to-destination $proxy_ipaddr:700 >/dev/null 2>&1
			iptables -w -t nat -A HTTPPROXY -j HTTPSPROXY
			ik_cntl https_redirect off >/dev/null 2>&1
		fi
	fi
}
