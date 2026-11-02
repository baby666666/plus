#!/bin/bash /etc/ikcommon
Include timersql.sh sqlite.sh crond.sh interface.sh iproute.sh

IK_TERM_DB="/tmp/iktmp/hosttype/hosttype.db"

boot()
{
	init
}

init()
{
	return
}

check_param()
{
	check_varl \
		'ip	ip'
}

del_conn()
{
	check_param || exit 1
	conntrack -D -s "$ip" >/dev/null 2>&1 &
	conntrack -D -r "$ip" >/dev/null 2>&1 &
	return 0
}

show()
{
	local __filter=$(sql_auto_get_filter)
	local __order=$(sql_auto_get_order)
	local __limit=$(sql_auto_get_limit)
	local __where="$__filter $__order $__limit"
	local __monitor_rows_ready=0 __monitor_rows_total __monitor_rows_data
	local __monitor_conn_ready=0 __monitor_conn_file='' __monitor_conn_ip='' status=0
	case ",${TYPE:-data}," in
		*,data,*|*,total,*) __monitor_prepare_rows || return 1 ;;
	esac
	case ",${TYPE:-data}," in
		*,conn,*|*,appid_conn,*) __monitor_prepare_conn || return 1 ;;
	esac
	Show __json_result__ || status=$?
	[ -z "$__monitor_conn_file" ] || rm -f "$__monitor_conn_file"
	return "$status"
}

__show_total()
{
	__monitor_prepare_rows || return 1
	local total="$__monitor_rows_total"
	json_append __json_result__ total:int
}

__show_data()
{
	__monitor_prepare_rows || return 1
	local data="$__monitor_rows_data"
	json_append __json_result__ data:json

	return 0;
}

# LAN and WG rows must share one filter/order/page and one total. Keep the
# original JSON payloads while using a private in-memory SQLite index, so
# native/custom fields and number types are not lost in the merged response.
# The fresh sample and filtered results are reused within this request only.
__monitor_prepare_rows()
{
	[ "${__monitor_rows_ready:-0}" = 1 ] && return 0
	local snapshot result status
	snapshot=$(mktemp -d "${IK_DIR_TMP:-/tmp/iktmp}/monitor-hosts.XXXXXX") || return 1
	if ! iktimerc ".load_hosts; .json; select * from online_user" > "$snapshot/lan.json" ||
	   ! __wg_monitor_data > "$snapshot/wg.json"; then
		rm -rf "$snapshot"
		return 1
	fi
	result=$(/usr/bin/lua - "$snapshot" "$__filter" "$__order" "$__limit" <<'LUA'
local json=require('cjson')
local sqlite=require('lsqlite3')
local root,filter,ordering,limit=arg[1],arg[2]or'',arg[3]or'',arg[4]or''
local function read(name)
 local f=assert(io.open(root..'/'..name));local text=f:read('*a');f:close()
 assert(text:match('^%s*%['),'invalid monitor array')
 local value=json.decode(text);assert(type(value)=='table','invalid monitor snapshot');return value
end
local rows={};for _,name in ipairs{'lan.json','wg.json'}do
 for _,row in ipairs(read(name))do assert(type(row)=='table');rows[#rows+1]=row end
end
local numeric={};for name in ('id timestamp webid ip_addr_int connect_num auth_type download upload total_up total_down reject ac_gid client_typeid latest_handshake'):gmatch('%S+')do numeric[name]=true end
local columns={};for name in ('id timestamp hostname username ppptype ssid frequencies webid ip_addr ip_addr_int connect_num auth_type client_type mac download upload total_up total_down link_addr bssid uprate downrate reject comment apmac ac_gid apname signal dtalk_name client_typeid client_model client_device uptime interface endpoint latest_handshake'):gmatch('%S+')do columns[name]=true end
for _,row in ipairs(rows)do for name,value in pairs(row)do
 assert(type(name)=='string'and not name:match('^__monitor_'),'invalid monitor field')
 columns[name]=true;if type(value)=='number'then numeric[name]=true end
end end
local function quote(name)return '"'..name:gsub('"','""')..'"'end
local names={};for name in pairs(columns)do names[#names+1]=name end;table.sort(names)
local schema={'__monitor_seq INTEGER PRIMARY KEY','__monitor_json TEXT NOT NULL'}
local insertnames={'__monitor_json'};local params={'?'}
for _,name in ipairs(names)do
 schema[#schema+1]=quote(name)..(numeric[name]and' NUMERIC DEFAULT 0'or" TEXT DEFAULT ''")
 insertnames[#insertnames+1]=quote(name);params[#params+1]='?'
end
local db=assert(sqlite.open_memory())
assert(db:exec('CREATE TABLE online_user ('..table.concat(schema,',')..')')==sqlite.OK,db:errmsg())
local insert=assert(db:prepare('INSERT INTO online_user ('..table.concat(insertnames,',')..') VALUES ('..table.concat(params,',')..')'))
assert(db:exec('BEGIN')==sqlite.OK)
for _,row in ipairs(rows)do
 assert(insert:bind(1,json.encode(row))==sqlite.OK)
 for i,name in ipairs(names)do
  local value=row[name]
  if value==json.null then value=nil
  elseif value==nil then value=numeric[name]and 0 or ''
  elseif type(value)=='boolean'then value=value and 1 or 0
  elseif type(value)=='table'then value=json.encode(value)end
  assert(insert:bind(i+1,value)==sqlite.OK)
 end
 assert(insert:step()==sqlite.DONE,db:errmsg());insert:reset()
end
insert:finalize();assert(db:exec('COMMIT')==sqlite.OK)
local count=assert(db:prepare('SELECT count(*) FROM online_user '..filter),db:errmsg())
assert(count:step()==sqlite.ROW,db:errmsg());local total=count:get_value(0);count:finalize()
ordering=ordering:match('%S')and(ordering..', __monitor_seq')or'ORDER BY __monitor_seq'
local query=assert(db:prepare('SELECT __monitor_json FROM online_user '..filter..' '..ordering..' '..limit),db:errmsg())
local result={};while true do local code=query:step();if code==sqlite.DONE then break end
 assert(code==sqlite.ROW,db:errmsg());result[#result+1]=query:get_value(0)
end
query:finalize();db:close();io.write(tostring(total),'\n[',table.concat(result,','),']')
LUA
	)
	status=$?
	rm -rf "$snapshot"
	[ "$status" = 0 ] || return "$status"
	__monitor_rows_total="${result%%$'\n'*}"
	__monitor_rows_data="${result#*$'\n'}"
	__monitor_rows_ready=1
}

__wg_bin()
{
	if [ -x /usr/bin/wg ]; then
		echo /usr/bin/wg
	else
		command -v wg 2>/dev/null
	fi
}

__json_array_merge()
{
	local left="${1:-[]}"
	local right="${2:-[]}"
	left="${left#[}"
	left="${left%]}"
	right="${right#[}"
	right="${right%]}"
	if [ "$left" -a "$right" ]; then
		echo "[$left,$right]"
	elif [ "$left" ]; then
		echo "[$left]"
	else
		echo "[$right]"
	fi
}

__wg_monitor_total()
{
	sqlite3 "$IK_DB_CONFIG" "select count() from wireguard_peers where enabled='yes' and ifnull(allowips,'')!=''" 2>/dev/null || echo 0
}

__wg_peer_transfer()
{
	local iface="$1"
	local pubkey="$2"
	local key="$3"
	local wg_bin=$(__wg_bin)
	[ "$wg_bin" -a "$iface" -a "$pubkey" ] || {
		echo 0
		return
	}
	"$wg_bin" show "$iface" transfer 2>/dev/null | awk -v pubkey="$pubkey" -v key="$key" '
		$1 == pubkey {
			if (key == "download") print $3;
			else print $2;
			found=1;
			exit;
		}
		END { if (!found) print 0; }
	'
}

__monitor_conntrack_count()
{
	local host_ip="$1"
	case "$host_ip" in
		''|0.0.0.0|*[!0-9.]*) echo 0; return ;;
	esac
	# Match the two directions and supported protocols used by the native detail list.
	if [ "${__monitor_conn_ready:-0}" = 1 ] && [ "$__monitor_conn_ip" = "$host_ip" ]; then
		awk '$1 ~ /^(tcp|udp|icmp|gre)$/ && /src=[0-9]/ {n++} END {print n+0}' "$__monitor_conn_file"
		return
	fi
	{ conntrack -L -s "$host_ip"; conntrack -L -r "$host_ip"; } 2>/dev/null |
		awk '$1 ~ /^(tcp|udp|icmp|gre)$/ && /src=[0-9]/ {n++} END {print n+0}'
}

# Preserve both native directional queries, including their existing counting
# semantics. Filters/result limits never alter this request's complete sample.
__monitor_prepare_conn()
{
	local host_ip="${1:-${ip:-}}" sample status=0
	case "$host_ip" in *[!0-9.]*) return 1;; esac
	if [ "${__monitor_conn_ready:-0}" = 1 ] && [ "$__monitor_conn_ip" = "$host_ip" ]; then return 0; fi
	sample=$(mktemp "${IK_DIR_TMP:-/tmp/iktmp}/monitor-conn.XXXXXX") || return 1
	if [ -n "$host_ip" ]; then
		conntrack -L -s "$host_ip" > "$sample" 2>/dev/null || status=1
		conntrack -L -r "$host_ip" >> "$sample" 2>/dev/null || status=1
	else
		conntrack -L > "$sample" 2>/dev/null || status=1
	fi
	if [ "$status" != 0 ]; then rm -f "$sample"; return 1; fi
	[ -z "${__monitor_conn_file:-}" ] || rm -f "$__monitor_conn_file"
	__monitor_conn_file="$sample"; __monitor_conn_ip="$host_ip"; __monitor_conn_ready=1
}

# Serialize counter sampling, not the potentially expensive conntrack scan.
# Kernel flock locks disappear when their holders exit; the persistent lock
# file itself is harmless. A contended/missing lock only disables this optional
# rate fallback for the request and never blocks native LAN statistics.
__wg_monitor_sample()
{
	(
		umask 077
		local wg_bin="$1" rows_file="$2" transfer_file="$3" handshake_file="$4" endpoint_file="$5" rate_file="$6"
		local state="/tmp/iktmp/wireguard/monitor" locked=0 attempt=0 uptime unused next_cache transfer_ok=0
		mkdir -p "$state" 2>/dev/null && chmod 700 "$state" 2>/dev/null
		if command -v flock >/dev/null 2>&1 && { exec 9>"$state/lock"; } 2>/dev/null; then
			while [ "$attempt" -lt 20 ]; do
				if flock -x -n 9; then locked=1; break; fi
				attempt=$((attempt + 1))
				sleep .05
			done
		fi
		: > "$rate_file"
		"$wg_bin" show all transfer > "$transfer_file" 2>/dev/null || exit 1
		transfer_ok=1
		read -r uptime unused < /proc/uptime || uptime=""
		"$wg_bin" show all latest-handshakes > "$handshake_file" 2>/dev/null || exit 1
		"$wg_bin" show all endpoints > "$endpoint_file" 2>/dev/null || exit 1
		[ "$locked" = 1 ] && [ "$transfer_ok" = 1 ] || exit 0
		[[ "$uptime" =~ ^[0-9]+([.][0-9]+)?$ ]] || exit 0
		next_cache=$(mktemp "$state/rates.XXXXXX") || exit 0
		trap 'rm -f "$next_cache"' EXIT
		if awk -v rows_file="$rows_file" -v transfer_file="$transfer_file" -v cache="$state/rates.tsv" -v output="$next_cache" -v rate_file="$rate_file" -v now="$uptime" '
		function unsigned(v) { return v~/^[0-9]+$/ }
		BEGIN {
			while ((getline line < rows_file)>0) {
				split(line,f,"|");iface=f[2];pub=f[3];key=iface SUBSEP pub;
				if(iface!~/^[A-Za-z0-9_.:-]+$/ || pub!~/^[A-Za-z0-9+\/=]+$/)continue;
				peer_id[key]=f[1];interfaces[key]=iface;publics[key]=pub;
				if(!(pub in pub_iface))pub_iface[pub]=iface;else if(pub_iface[pub]!=iface)pub_iface[pub]="";
			}
			close(rows_file);
			while ((getline line < cache)>0) {
				n=split(line,f,"\t");key=f[1] SUBSEP f[2];
				if(n!=9 || !unsigned(f[3]) || !unsigned(f[4]) || f[5]!~/^[0-9]+([.][0-9]+)?$/ || !unsigned(f[6]) || !unsigned(f[7]) || !unsigned(f[8]) || !unsigned(f[9]))continue;
				old_index[key]=f[3];old_id[key]=f[4];old_time[key]=f[5]+0;
				old_up[key]=f[6]+0;old_down[key]=f[7]+0;old_rate_up[key]=f[8]+0;old_rate_down[key]=f[9]+0;
			}
			close(cache);
			while ((getline line < transfer_file)>0) {
				n=split(line,f,"\t");
				if(n==4){iface=f[1];pub=f[2];rx=f[3];tx=f[4]}
				else if(n==3 && pub_iface[f[1]]!=""){iface=pub_iface[f[1]];pub=f[1];rx=f[2];tx=f[3]}
				else continue;
				key=iface SUBSEP pub;
				if(key in peer_id && unsigned(rx) && unsigned(tx)){current_up[key]=rx+0;current_down[key]=tx+0}
			}
			close(transfer_file);
			for(key in current_up){
				iface=interfaces[key];pub=publics[key];
				if(!(iface in ifindex)){
					path="/sys/class/net/" iface "/ifindex";current_index="";
					if((getline current_index < path)>0 && unsigned(current_index))ifindex[iface]=current_index;else ifindex[iface]="";
					close(path);
				}
				current_index=ifindex[iface];if(current_index=="")continue;
				timestamp=now+0;rx=current_up[key];tx=current_down[key];ru=0;rd=0;elapsed=now-old_time[key];
				if(key in old_time && old_index[key]==current_index && old_id[key]==peer_id[key] && elapsed>=0 && elapsed<=30 && rx>=old_up[key] && tx>=old_down[key]){
					if(elapsed<1){
						# Concurrent/subsecond pollers reuse a rate without moving its baseline.
						timestamp=old_time[key];rx=old_up[key];tx=old_down[key];ru=old_rate_up[key];rd=old_rate_down[key];
					}else{ru=(rx-old_up[key])/elapsed;rd=(tx-old_down[key])/elapsed}
				}
				# A long idle gap, clock/counter reset or interface/peer replacement
				# establishes a fresh baseline instead of publishing a stale spike.
				printf "%s\t%s\t%s\t%s\t%.2f\t%.0f\t%.0f\t%.0f\t%.0f\n",iface,pub,current_index,peer_id[key],timestamp,rx,tx,ru,rd > output;
				printf "%s\t%s\t%.0f\t%.0f\n",iface,pub,ru,rd > rate_file;
			}
			close(output);close(rate_file);
		}' && mv -f "$next_cache" "$state/rates.tsv"; then
			:
		else
			: > "$rate_file"
		fi
	)
}

__wg_monitor_data()
{
	(
	local now=$(date +%s)
	local rows
	local transfer_file="/tmp/iktmp/wireguard/monitor_transfer.$$"
	local handshake_file="/tmp/iktmp/wireguard/monitor_handshake.$$"
	local endpoint_file="/tmp/iktmp/wireguard/monitor_endpoint.$$"
	local connection_file="/tmp/iktmp/wireguard/monitor_connections.$$"
	local stats_file="/tmp/iktmp/wireguard/monitor_stats.$$"
	local missing_file="/tmp/iktmp/wireguard/monitor_missing.$$"
	local rows_file="/tmp/iktmp/wireguard/monitor_rows.$$"
	local rate_file="/tmp/iktmp/wireguard/monitor_rates.$$"
	local cleanup
	# Capture paths now: exit from a nested function can unwind its locals before
	# Bash runs the inherited EXIT trap.
	printf -v cleanup 'rm -f %q %q %q %q %q %q %q %q %q' "$transfer_file" "$handshake_file" "$endpoint_file" "$connection_file" "$connection_file.raw" "$stats_file" "$missing_file" "$rows_file" "$rate_file"
	trap "$cleanup" EXIT
	rows=$(sqlite3 "$IK_DB_CONFIG" -separator '|' "select id,interface,peer_publickey,allowips,ifnull(comment,'') from wireguard_peers where enabled='yes' and ifnull(allowips,'')!='' order by id" 2>/dev/null) || exit 1
	[ "$rows" ] || {
		echo "[]"
		return
	}
	mkdir -p /tmp/iktmp/wireguard 2>/dev/null || exit 1
	printf '%s\n' "$rows" > "$rows_file"
	cat /proc/ikuai/stats/host_stats > "$stats_file" 2>/dev/null || :
	# Native counters are preferred. All peers needing a fallback share one
	# conntrack dump instead of two full-table queries per peer on every refresh.
	echo "$rows" | awk -F'|' -v stats_file="$stats_file" '
	BEGIN { while ((getline line < stats_file)>0) {split(line,f," ");count[f[1]]=f[3]+0} close(stats_file) }
	{ ip=$4;sub(/,.*/,"",ip);sub(/\/.*/,"",ip);if(ip!=""&&ip!="0.0.0.0"&&ip!~/[^0-9.]/&&count[ip]<=0&&!seen[ip]++)print ip }
	' > "$missing_file"
	: > "$connection_file"
	if [ -s "$missing_file" ]; then
		conntrack -L > "$connection_file.raw" 2>/dev/null || exit 1
		awk -v missing_file="$missing_file" '
		BEGIN { while ((getline ip < missing_file)>0) wanted[ip]=1;close(missing_file) }
		$1~/^(tcp|udp|icmp|gre)$/ {
			n=0;first="";second="";
			for(i=1;i<=NF;i++)if($i~/^src=/){ip=substr($i,5);if(++n==1)first=ip;else if(n==2){second=ip;break}}
			if(first in wanted)count[first]++;
			if(second!=first&&(second in wanted))count[second]++;
		}
		END { for(ip in wanted)print ip,count[ip]+0 }
		' "$connection_file.raw" > "$connection_file" || exit 1
	fi
	local wg_bin=$(__wg_bin)
	: > "$rate_file"
	if [ "$wg_bin" ]; then
		__wg_monitor_sample "$wg_bin" "$rows_file" "$transfer_file" "$handshake_file" "$endpoint_file" "$rate_file" || exit 1
	else exit 1; fi

	echo "$rows" | awk -F'|' -v now="$now" -v rows_file="$rows_file" -v transfer_file="$transfer_file" -v handshake_file="$handshake_file" -v endpoint_file="$endpoint_file" -v connection_file="$connection_file" -v stats_file="$stats_file" -v rate_file="$rate_file" '
	function esc(s, i,c,out) {
		out="";
		for(i=1;i<=length(s);i++){
			c=substr(s,i,1);
			if(c=="\\")out=out "\\\\";
			else if(c=="\"")out=out "\\\"";
			else if(c=="\t")out=out "\\t";
			else if(c=="\r")out=out "\\r";
			else out=out c;
		}
		return out;
	}
	function iponly(s) { sub(/,.*/,"",s); sub(/\/.*/,"",s); return s }
	function ipint(ip, a) { split(ip,a,"."); return a[1]*16777216+a[2]*65536+a[3]*256+a[4] }
	function timefmt(ts, cmd, out) {
		if (!ts || ts <= 0) return "";
		cmd = "date -d @" ts " \"+%Y-%m-%d %H:%M:%S\" 2>/dev/null";
		cmd | getline out;
		close(cmd);
		return out;
	}
	BEGIN {
		while ((getline line < rows_file)>0) {
			split(line,f,"|");if(!(f[3] in pub_iface))pub_iface[f[3]]=f[2];else if(pub_iface[f[3]]!=f[2])pub_iface[f[3]]="";
		}
		close(rows_file);
		while ((getline line < transfer_file) > 0) {
			split(line, f, "\t");
			if (f[4] != "") {
				key=f[1] SUBSEP f[2];up[key]=f[3]+0;down[key]=f[4]+0;
			} else if (f[3] != "" && pub_iface[f[1]]!="") {
				key=pub_iface[f[1]] SUBSEP f[1];up[key]=f[2]+0;down[key]=f[3]+0;
			}
		}
		close(transfer_file);
		while ((getline line < handshake_file) > 0) {
			split(line, f, "\t");
			if (f[3] != "") latest[f[1] SUBSEP f[2]]=f[3]+0;
			else if (f[2] != "" && pub_iface[f[1]]!="") latest[pub_iface[f[1]] SUBSEP f[1]]=f[2]+0;
		}
		close(handshake_file);
		while ((getline line < endpoint_file) > 0) {
			split(line, f, "\t");
			if (f[3] != "") endpoint[f[1] SUBSEP f[2]]=f[3];
			else if (f[2] != "" && pub_iface[f[1]]!="") endpoint[pub_iface[f[1]] SUBSEP f[1]]=f[2];
		}
		close(endpoint_file);
		while ((getline line < stats_file) > 0) {
			split(line, f, " ");
			if (f[1] != "") {
				native_rate[f[1]]=1;
				rate_up[f[1]]=f[4]+0;
				rate_down[f[1]]=f[5]+0;
				conn[f[1]]=f[3]+0;
			}
		}
		close(stats_file);
		while ((getline line < rate_file)>0) {
			split(line,f,"\t");key=f[1] SUBSEP f[2];fallback_up[key]=f[3]+0;fallback_down[key]=f[4]+0;
		}
		close(rate_file);
		while ((getline line < connection_file) > 0) {
			split(line, f, " ");
			tracked_conn[f[1]]=f[2]+0;
		}
		close(connection_file);
		printf "[";
	}
	{
		id=$1; iface=$2; pub=$3; allow=$4; comment=$5;
		ip=iponly(allow);
		key=iface SUBSEP pub;
		rate_upload=(ip in native_rate)?rate_up[ip]:fallback_up[key];
		rate_download=(ip in native_rate)?rate_down[ip]:fallback_down[key];
		peer_conn=conn[ip]+0;
		if (peer_conn == 0) peer_conn=tracked_conn[ip]+0;
		if (n++ > 0) printf ",";
		# Firmware awk formats %d as signed 32-bit; retain high IPv4 values and counters.
		printf "{\"id\":%.0f,\"timestamp\":%.0f,\"hostname\":\"%s\",\"username\":\"%s\",\"ppptype\":\"wireguard\",\"ssid\":\"\",\"frequencies\":\"\",\"webid\":0,\"ip_addr\":\"%s\",\"ip_addr_int\":%.0f,\"connect_num\":%.0f,\"auth_type\":0,\"client_type\":\"WireGuard\",\"mac\":\"00:00:00:00:00:00\",\"download\":%.0f,\"upload\":%.0f,\"total_up\":%.0f,\"total_down\":%.0f,\"link_addr\":\"%s\",\"bssid\":\"\",\"uprate\":\"\",\"downrate\":\"\",\"reject\":0,\"comment\":\"%s\",\"apmac\":\"\",\"ac_gid\":0,\"apname\":\"\",\"signal\":\"\",\"dtalk_name\":\"\",\"client_typeid\":0,\"client_model\":\"\",\"client_device\":\"WireGuard\",\"uptime\":\"%s\",\"interface\":\"%s\",\"endpoint\":\"%s\",\"latest_handshake\":%.0f}", id, now, esc(iface "-" id), esc(iface), ip, ipint(ip), peer_conn, rate_download+0, rate_upload+0, up[key]+0, down[key]+0, esc(endpoint[key]), esc(comment), esc(timefmt(latest[key])), esc(iface), esc(endpoint[key]), latest[key]+0;
	}
	END { printf "]" }
	'
	)
}

__wg_monitor_interface_json()
{
	sqlite3 "$IK_DB_CONFIG" "select name from wireguard where name like 'wg%' union select distinct interface from wireguard_peers where interface like 'wg%' order by 1" 2>/dev/null | \
	awk '
	function esc(s) { gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); return s }
	BEGIN { printf "[" }
	NF {
		if (n++ > 0) printf ",";
		printf "[\"%s\",\"%s\"]", esc($1), esc($1);
	}
	END { printf "]" }
	'
}

__show_acl_mac()
{
	local acl_mac=$(sqlite3 $IK_DB_CONFIG "select acl_mac from global_config;")
	json_append __json_result__ acl_mac:int

}

#查看终端流量详情
#ip=192.168.1.1
__show_terminal_flow()
{
	check_varl 'ip ip' || exit 1
	if [ -e "/tmp/iktmp/LANG/1" ];then
		language="cn"
	elif [ -e "/tmp/iktmp/LANG/3" ];then
		language="tw"
	else
		language="en"
	fi
	terminal_flow=$(echo -n "["
	ik_cntl show host_proto $ip 2>/dev/null |\
	awk -v language=$language '{
		if(language=="cn"){
			gsub(/HTTP/,"HTTP协议");
			gsub(/Download/,"网络下载");
			gsub(/Transport/,"文件传输");
			gsub(/IM/,"网络通讯");
			gsub(/Video/,"网络视频");
			gsub(/Common/,"常用协议");
			gsub(/Game/,"网络游戏");
			gsub(/Others/,"其它应用");
			gsub(/Test/,"测速软件");
			gsub(/Unknown/,"未知应用");
		} else if(language=="tw"){
			gsub(/HTTP/,"未知應用");
			gsub(/Download/,"網路下載");
			gsub(/Transport/,"文件傳輸");
			gsub(/IM/,"網路通訊");
			gsub(/Video/,"網路媒體");
			gsub(/Common/,"常用協定");
			gsub(/Game/,"網路遊戲");
			gsub(/Others/,"其他應用");
			gsub(/Test/,"測速軟體");
			gsub(/Unknown/,"未知應用");
		}else{
			gsub(/HTTP/,"HttpProtocol");
			gsub(/Download/,"NetDownload");
			gsub(/Transport/,"FileTransfer");
			gsub(/IM/,"NetMessage");
			gsub(/Video/,"NetVideo");
			gsub(/Common/,"CommonProtocol");
			gsub(/Game/,"NetGame");
			gsub(/Others/,"OtherSoft");
			gsub(/Test/,"SpeedTool");
		}
		if(NR>1)printf ",";
		printf "{\x22app_name\x22:\x22%s\x22,\x22upload\x22:%s,\x22download\x22:%s,\x22total_up\x22:%s,\x22total_down\x22:%s}\n",$1,$2,$3,$4,$5 
	}'
	echo "]")
	json_append __json_result__ terminal_flow:json
}

#显示终端连接详情
#ip=192.168.1.1
__show_conn() {
	check_varl 'ip ip' || exit 1
	json='{"protocol":"%s","status":"%s","dst_addr":"%s","src_port":%s,"dst_port":%s,"forward_addr":"%s","app_name":"%s","interface":"%s","total_up":%s,"total_down":%s}'
	if [ -e "/tmp/iktmp/LANG/1" ];then
		proto_list="/tmp/iktmp/cache/appid_cn.txt"
		language="cn"
	else
		proto_list="/tmp/iktmp/cache/appid_en.txt"
		language="en"
	fi
	if [ "$interface" = "all" ]; then
		interface=""
	fi
	
	if [ "$maxnum" ]; then
		[[ "$maxnum" =~ ^[0-9]+$ ]] || return 1
	fi
	__monitor_prepare_conn || return 1

	# Native routing marks contain rule/exit IDs, not the legacy WAN mark.
	# Filter on the observed egress below, then cap the matching result count.
	conn=$(echo -n "["
	gawk -v requested_proto="${proto:-all}" -v ip="$ip" -v interface="$interface" -v maxnum="${maxnum:-0}" -v json="$json" -v proto_list="$proto_list" -v language="$language" '
	BEGIN {
		if(language=="cn"){
			status["SYN_SENT"]="请求连接"
			status["FIN_WAIT"]="回复等待"
			status["ESTABLISHED"]="已连接"
			status["TIME_WAIT"]="等待"
			status["CLOSE"]="关闭连接"
			status["CLOSE_WAIT"]="关闭连接"
		}else{
			status["SYN_SENT"]="SYN_SENT"
			status["FIN_WAIT"]="FIN_WAIT"
			status["ESTABLISHED"]="ESTABLISHED"
			status["TIME_WAIT"]="TIME_WAIT"
			status["CLOSE"]="CLOSE"
			status["CLOSE_WAIT"]="CLOSE_WAIT"
		}
		while ((getline < proto_list) > 0) appid_name[$2]=$1
		close(proto_list)
	}
	{
		if(requested_proto!="all" && requested_proto!="" && $1!=requested_proto && $2!=requested_proto)next
		orig_srcip="--"; orig_dstip="--"; orig_sport=0; orig_dport=0; orig_packets="--"; orig_bytes="--"
		reply_srcip="--"; reply_dstip="--"; reply_sport=0; reply_dport=0; reply_packets="--"; reply_bytes="--"
		orig_type="--"; orig_code="--"; orig_id="--"; reply_type="--"; reply_code="--"; reply_id="--"
		orig_srckey="--"; orig_dstkey="--"; reply__srckey="--"; reply__dstkey="--"
		app_name="--"; remote_if="--"

		proto=$1
		timeout=$3
		if(proto=="tcp"){
			stat=status[$4]
		} else {
			stat="--"
		}
		
		if(proto=="tcp" || proto=="udp"){
			match($0,"src=([0-9\\.]+) dst=([0-9\\.]+) sport=([0-9]+) dport=([0-9]+) packets=([0-9]+) bytes=([0-9]+).* src=([0-9\\.]+) dst=([0-9\\.]+) sport=([0-9]+) dport=([0-9]+) packets=([0-9]+) bytes=([0-9]+).* appid=([0-9]+)",conntrack)
			match($0,"remote_if=([^ ]+)",ifname)
			orig_srcip=conntrack[1]
			orig_dstip=conntrack[2]
			orig_sport=conntrack[3]
			orig_dport=conntrack[4]
			orig_packets=conntrack[5]
			orig_bytes=conntrack[6]
			reply_srcip=conntrack[7]
			reply_dstip=conntrack[8]
			reply_sport=conntrack[9]
			reply_dport=conntrack[10]
			reply_packets=conntrack[11]
			reply_bytes=conntrack[12]
			app_name=appid_name[conntrack[13]]
			remote_if=ifname[1]
		}
		else if(proto=="icmp"){
			match($0,"src=([0-9\\.]+) dst=([0-9\\.]+) type=([0-9]+) code=([0-9]+) id=([0-9]+) packets=([0-9]+) bytes=([0-9]+).* src=([0-9\\.]+) dst=([0-9\\.]+) type=([0-9]+) code=([0-9]+) id=([0-9]+) packets=([0-9]+) bytes=([0-9]+).* appid=([0-9]+)",conntrack)
			match($0,"remote_if=([^ ]+)",ifname)
			orig_srcip=conntrack[1]
			orig_dstip=conntrack[2]
			orig_type=conntrack[3]
			orig_code=conntrack[4]
			orig_id=conntrack[5]
			orig_packets=conntrack[6]
			orig_bytes=conntrack[7]
			reply_srcip=conntrack[8]
			reply_dstip=conntrack[9]
			reply_type=conntrack[10]
			reply_code=conntrack[11]
			reply_id=conntrack[12]
			reply_packets=conntrack[13]
			reply_bytes=conntrack[14]
			app_name=appid_name[conntrack[15]]
			remote_if=ifname[1]
		}
		else if(proto=="gre"){
			match($0,"src=([0-9\\.]+) dst=([0-9\\.]+) srckey=(0x[a-z0-9]+) dstkey=(0x[a-z0-9]+) packets=([0-9]+) bytes=([0-9]+).* src=([0-9\\.]+) dst=([0-9\\.]+) srckey=(0x[a-z0-9]+) dstkey=(0x[a-z0-9]+) packets=([0-9]+) bytes=([0-9]+).* appid=([0-9]+)",conntrack)
			match($0,"remote_if=([^ ]+)",ifname)
			orig_srcip=conntrack[1]
			orig_dstip=conntrack[2]
			orig_srckey=conntrack[3]
			orig_dstkey=conntrack[4]
			orig_packets=conntrack[5]
			orig_bytes=conntrack[6]
			reply_srcip=conntrack[7]
			reply_dstip=conntrack[8]
			reply_srckey=conntrack[9]
			reply_dstkey=conntrack[10]
			reply_packets=conntrack[11]
			reply_bytes=conntrack[12]
			app_name=appid_name[conntrack[13]]
			remote_if=ifname[1]
		} else {
			next
		}

		if(!orig_srcip)
			next

		if(match(remote_if, /^wan[0-9]+_ad$/)){
			remote_if=substr(remote_if,0,length(remote_if)-3)
		}
		if(interface && remote_if!=interface)
			next
		if(maxnum>0 && n>=maxnum)
			next

		if(n++>0)printf ","
		if(ip==orig_srcip){
			printf json,proto,stat,orig_dstip,orig_sport,orig_dport,reply_dstip,app_name,remote_if,orig_bytes,reply_bytes
		} else {
			printf json,proto,stat,reply_dstip,reply_sport,reply_dport,orig_dstip,app_name,remote_if,reply_bytes,orig_bytes
		}
		#print proto,timeout,stat,orig_srcip,orig_dstip,orig_sport,orig_dport,orig_packets,orig_bytes,reply_srcip,reply_dstip,reply_sport,reply_dport,reply_packets,reply_bytes,app_name
	}' "$__monitor_conn_file" || exit 1
	echo "]") || return 1
	json_append __json_result__ conn:json
}

__show_conn_num()
{
	local conn_num=$(awk -v ip="$ip" '{if($1==ip){print $3;exit}}' /proc/ikuai/stats/host_stats)
	if [ -z "$conn_num" -o "$conn_num" = "0" ]; then
		__monitor_prepare_conn || return 1
		conn_num=$(__monitor_conntrack_count "$ip") || return 1
	fi
	json_append __json_result__ conn_num:int
}

###每个终端 具体协议的连接数及上下行统计信息
##ip=a.b.c.d
__show_appid_conn() {

	json='{"conn":"%s","app_name":"%s","total_up":%s,"total_down":%s}'
	if [ -e "/tmp/iktmp/LANG/1" ];then
		proto_list="/tmp/iktmp/cache/appid_cn.txt"
		language="cn"
	else
		proto_list="/tmp/iktmp/cache/appid_en.txt"
		language="en"
	fi
	if [ "$ip" ]; then
		case "$ip" in
			*[!0-9.]* ) return 1 ;;
		esac
	fi
	__monitor_prepare_conn || return 1

	appid_conn=$(set -o pipefail; echo -n "["
	sort -k1 "$__monitor_conn_file" |gawk -v ip="$ip" -v json="$json" -v proto_list="$proto_list" -v language="$language" '
	BEGIN {
		while ((getline < proto_list) > 0) {
			appid_name[$2]=$1
		}
		close(proto_list)
	}
	{
		match($0,"src=([0-9\\.]+).* bytes=([0-9]+).* src=([0-9\\.]+).* bytes=([0-9]+).* appid=([0-9]+)",conntrack)
		orig_srcip=conntrack[1]
		orig_bytes=conntrack[2]
		reply_srcip=conntrack[3]
		reply_bytes=conntrack[4]
		app_name=appid_name[conntrack[5]]

		if (appid_conn[app_name]) {
			appid_conn[app_name] = appid_conn[app_name] + 1
		} else {
			appid_conn[app_name] = 1
		}
		if (!appid_upload_bytes[app_name]) {
			appid_upload_bytes[app_name]=0
			appid_download_bytes[app_name]=0
		}
		if (ip==orig_srcip) {
			appid_upload_bytes[app_name] = appid_upload_bytes[app_name] + orig_bytes;
			appid_download_bytes[app_name] = appid_download_bytes[app_name] + reply_bytes;
		} else {
			appid_upload_bytes[app_name] = appid_upload_bytes[app_name] + reply_bytes;
			appid_download_bytes[app_name] = appid_download_bytes[app_name] + orig_bytes;
		}

		if(!orig_srcip)
			next

	}END{
		n=0
		for (name in appid_conn) {
			if (n>0) printf ","
			printf json,appid_conn[name],name,appid_upload_bytes[name],appid_download_bytes[name]
			n++
		}
	}' || exit 1
	echo "]") || return 1
	json_append __json_result__ appid_conn:json
}

__show_reset_total_load()
{
	local reset_total_load=$(sqlite3 $IK_DB_CONFIG "select reset_total_load from global_config;")
	json_append __json_result__ reset_total_load:int
}

__show_interface()
{
	local interface=$(interface_get_ifname_comment_json all all)
	local wg_interface=$(__wg_monitor_interface_json)
	interface=$(__json_array_merge "$interface" "$wg_interface")
	json_append __json_result__ interface:json
}


__show_hosttype_ua_total()
{
        local ua_total=0
        if [ -e "$IK_TERM_DB" ]; then
                ua_total=$(sqlite3 $IK_TERM_DB "select count() from user_agent $__filter")
        fi
        json_append __json_result__ ua_total:int
        return 0
}

__show_hosttype_ua_data()
{
        local ua=""
        local hostname=""
        if [ "$mac" -a -e "$IK_TERM_DB" ]; then
                local ua=$(sqlite3 $IK_TERM_DB "select ua from user_agent where mac='$mac' limit 1")
                local hostname=$(sqlite3 /var/db/leases.db "select hostname from leases where mac='$mac' limit 1")
        fi
        json_append __json_result__ ua:str hostname:str
        return 0
}

__show_hosttype_total()
{
        local hosttype_total=0
        if [ -e "$IK_TERM_DB" ]; then
                hosttype_total=$(sqlite3 $IK_TERM_DB "select count() from host $__filter")
        fi
        json_append __json_result__ hosttype_total:int
        return 0
}

__show_hosttype_data()
{
        local hosttype_data
        if [ -e "$IK_TERM_DB" ]; then
                local sql_show="select * from host $__where"
                hosttype_data=$(sql_config_get_json $IK_TERM_DB "$sql_show")
        else
                hosttype_data="[]"
        fi
        json_append __json_result__ hosttype_data:json

        return 0
}
