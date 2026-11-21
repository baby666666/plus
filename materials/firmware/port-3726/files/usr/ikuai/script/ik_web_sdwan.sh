#!/bin/bash /etc/ikcommon

API_URL="https://yun.ikuai8.com/api/v3"
API_TOKEN_FILE="/tmp/iktmp/ik_web_sdwan.token"

show() {
	touch $API_TOKEN_FILE
	Show __json_result__
}

__gen_sign()
{
	local timestamp="$1"
	local key="3fed9451233658a2f7e7fe948c97230b"
	local sign="$(echo -n "${timestamp}$key" |md5sum)"
	echo "${sign:0:32}"
}

router_bind_sms_easy_bind()
{
	local timestamp="$(date +%s)"
	local sign=$(__gen_sign $timestamp)
	local gwid=$GWID
	local scene="LOCALROUTE"

	local body=$(json_output gwid:str timestamp:str sign:str sms_code:str mobile:str remark:str scene:str)

	local res=$(curl -4 -X POST  -s --connect-timeout 10 "$API_URL/router_bind/sms_easy_bind" -H "Content-Type:application/json" -d "$body")	
	local code="$(echo $res |jq .code)"
	if [ "$res" -a "$code" = "2000" ]; then
		local token=$(echo $res |jq .token)
		[ "$token" ] && echo $token > $API_TOKEN_FILE
	fi
	
	echo "$res"
}

sms_code_login()
{
	local timestamp="$(date +%s)"
	local sign=$(__gen_sign $timestamp)
	local gwid=$GWID
	local scene="LOCALROUTE"

	local body=$(json_output timestamp:str sign:str sms_code:str mobile:str scene:str gwid:str)

	local res=$(curl -4 -X POST   -s --connect-timeout 10 "$API_URL/sms_code/login" -H "Content-Type:application/json" -d "$body")	
	local code="$(echo $res |jq .code)"
	if [ "$res" -a "$code" = "2000" ]; then
		local token=$(echo $res |jq .token)
		[ "$token" ] && echo $token > $API_TOKEN_FILE
	fi
	
	echo "$res"
}

router_bind_get_sms_code()
{
	local timestamp="$(date +%s)"
	local sign=$(__gen_sign $timestamp)

	local body=$(json_output timestamp:str sign:str mobile:str)

	local res=$(curl -4 -X POST   -s --connect-timeout 10 "$API_URL/router_bind/get_sms_code" -H "Content-Type:application/json" -d "$body")	
	echo "$res"
}

local_get_sms_code()
{
	local timestamp="$(date +%s)"
	local sign=$(__gen_sign $timestamp)

	local body=$(json_output timestamp:str sign:str mobile:str)

	local res=$(curl -4 -X POST  -s --connect-timeout 10 "$API_URL/sdwan/local/get_sms_code" -H "Content-Type:application/json" -d "$body")	
	echo "$res"
}

local_list()
{
	local timestamp="$(date +%s)"
	local sign=$(__gen_sign $timestamp)
	local gwid=$GWID

	local res=$(curl -4 -X GET  -s --connect-timeout 10 "$API_URL/sdwan/local/list?timestamp=$timestamp&gwid=$gwid&sign=$sign" -H "Content-Type:application/json")	
	echo "$res"
}

local_members()
{
	local timestamp="$(date +%s)"
	local sign=$(__gen_sign $timestamp)
	local token=$(cat $API_TOKEN_FILE)
	local gwid=$GWID

	local res=$(curl -4 -X GET  -s --connect-timeout 10 "$API_URL/sdwan/local/members?timestamp=$timestamp&sign=$sign" -H "Authorization: $token" -H "Content-Type:application/json")	
	echo "$res"
}

local_create()
{
	local timestamp="$(date +%s)"
	local sign=$(__gen_sign $timestamp)
	local token=$(cat $API_TOKEN_FILE)

	local nodes
	for id in $ids; do
		nodes+="${nodes:+,}$(json_output id:str)"
	done
	
	nodes=$(json_output timestamp:str sign:str nodes:json)	

	local res=$(curl -4 -X POST   -s --connect-timeout 10 "$API_URL/sdwan/local/create?timestamp=$timestamp&sign=$sign" -H "Content-Type:application/json" -H "Authorization: $token" -d "$body")	
	echo "$res"
}

local_update()
{
	local timestamp="$(date +%s)"
	local sign=$(__gen_sign $timestamp)
	local token=$(cat $API_TOKEN_FILE)

	local nodes
	for id in $ids; do
		nodes+="${nodes:+,}$(json_output id:str)"
	done
	
	nodes=$(json_output timestamp:str sign:str nodes:json sdwan_id:str)	

	local res=$(curl -4 -X POST  -s --connect-timeout 10 "$API_URL/sdwan/local/create?timestamp=$timestamp&sign=$sign" -H "Content-Type:application/json" -H "Authorization: $token" -d "$body")	
	echo "$res"
}


local_delete()
{
	local timestamp="$(date +%s)"
	local sign=$(__gen_sign $timestamp)
	local token=$(cat $API_TOKEN_FILE)

	local nodes
	for id in $ids; do
		nodes+="${nodes:+,}\"$id\""
	done
	nodes="[$nodes]"
	
	nodes=$(json_output timestamp:str sign:str nodes:json sdwan_id:str)	

	local res=$(curl -4 -X POST  -s --connect-timeout 10 "$API_URL/sdwan/local/create?timestamp=$timestamp&sign=$sign" -H "Content-Type:application/json" -H "Authorization: $token" -d "$body")	
	echo "$res"
}

local_info()
{
	local timestamp="$(date +%s)"
	local sign=$(__gen_sign $timestamp)
	local gwid=$GWID

	local res=$(curl -4 -X GET  -s --connect-timeout 10 "$API_URL/sdwan/local/info?timestamp=$timestamp&gwid=$gwid&sign=$sign" -H "Content-Type:application/json")	
	echo "$res"
}


__show_data()
{
	local data
	local res=$($method)
	if [ -z "$res" ]; then
		local code=2020
		local message="connect server failed"
		data="$(json_output code:str message:str)"
	else
		data="$res"
	fi
	json_append __json_result__ data:json
	return 0
}

__show_bind_status()
{
	local bind_status=0
	$IK_DIR_SCRIPT/register.sh __check_bind_async >/dev/null 2>&1
	sleep 2
	bind_status=$(cat /tmp/iktmp/register_status)
	local gwid=$GWID
	
	json_append __json_result__ bind_status:int gwid:str
	return 0
}
