#!/bin/bash /etc/ikcommon
Include lock.sh
# On-demand client-export address discovery. No WG peer/runtime or route changes.
# Usage: wg_client_endpoint.sh get wgN [1]   (1 requests a bounded refresh)

__wce_reply()
{
 printf '{"ip":"%s","source":"%s","wan":"%s","message":"%s","listen_port":%s}\n' "$1" "$2" "$3" "$4" "${5:-0}"
}

__wce_ipv4()
{
 local ip="$1" a b c d part
 [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
 IFS=. read -r a b c d <<< "$ip"
 for part in "$a" "$b" "$c" "$d";do
  [ "${#part}" = 1 ] || [ "${part:0:1}" != 0 ] || return 1
  [ "$((10#$part))" -le 255 ] || return 1
 done
 # A usable WAN address may be private/CGNAT, but not unspecified, loopback,
 # link-local, multicast or reserved class E. Read it only from the live device.
 [ "$a" -gt 0 ] && [ "$a" -lt 224 ] && [ "$a" != 127 ] || return 1
 [ "$a.$b" != 169.254 ] || return 1
}

# Local-only FIB lookup used by device imports and subsequent DNS refresh.
# The mark matches the native WG/QUIC transport socket. This never probes a
# network host and does not require a running or reachable peer.
check_outer()
{
 local ip=$1 dev=$2 src=$3 peer=$4 route kind actual
 __wce_ipv4 "$ip" && [[ $dev =~ ^wg[0-9]{1,10}$ ]] && [ "$ip" != "${src%/*}" ] && [ "$ip" != "${peer%/*}" ] || return 1
 route=$(ip -4 route get "$ip" mark 0x56000000 2>/dev/null) || return 1
 read -r kind _ <<< "$route"
 case "$kind" in local|broadcast|unreachable|blackhole|prohibit) return 1;;esac
 [[ $route =~ (^|[[:space:]])dev[[:space:]]+([^[:space:]]+) ]] || return 1
 actual=${BASH_REMATCH[2]}; [ "$actual" != lo ] && [ "$actual" != "$dev" ] && [ "$actual" != "ppp$dev" ]
}

__wce_public_ipv4()
{
 __wce_ipv4 "$1" || return 1
 local a b c d
 IFS=. read -r a b c d <<< "$1"
 [ "$a" != 10 ] || return 1
 [ "$a" != 100 ] || [ "$b" -lt 64 ] || [ "$b" -gt 127 ] || return 1
 [ "$a" != 172 ] || [ "$b" -lt 16 ] || [ "$b" -gt 31 ] || return 1
 case "$a.$b" in 192.168|198.18|198.19) return 1;; esac
 case "$a.$b.$c" in 192.0.0|192.0.2|192.88.99|198.51.100|203.0.113) return 1;; esac
}

__wce_wan_name()
{
 [[ "$1" =~ ^(wan|vwan|adsl)[0-9][A-Za-z0-9_.-]*$ ]] && [ "${#1}" -le 15 ]
}

__wce_inventory()
{
 # Match the native WAN inventory (static=0, DHCP=1, PPPoE=2,
 # MACVLAN=3, VLAN=4), but never refresh its shared cache from this read API.
 # The same read snapshot supplies the PPPoE device mapping, not old cache.
 sqlite3 -cmd '.timeout 1000' -separator '|' "$IK_DB_CONFIG" "select name,case when internet=2 then name||'_ad' else name end from wan_config where bandif!='' and internet in (0,1,2) union select wan_vlan.vlan_name,wan_vlan.vlan_name from wan_config join wan_vlan on wan_config.name=wan_vlan.interface where wan_config.internet in (3,4) and wan_config.bandif!='';" 2>/dev/null
}

__wce_device()
{
 local wanted="$1" inventory="$2" wan dev extra found=""
 __wce_wan_name "$wanted" || return 1
 while IFS='|' read -r wan dev extra;do
  [ "$wan" = "$wanted" ] || continue
  [[ "$dev" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] && [ -z "$extra" ] || return 1
  [ -z "$found" ] || return 1
  found="$dev"
 done <<< "$inventory"
 [ "$found" ] || return 1
 printf '%s\n' "$found"
}

__wce_map_device()
{
 local wanted="$1" inventory="$2" wan dev extra found=""
 [[ "$wanted" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || return 1
 while IFS='|' read -r wan dev extra;do
  __wce_wan_name "$wan" || continue
  [[ "$dev" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] && [ -z "$extra" ] || continue
  [ "$dev" = "$wanted" ] || continue
  [ -z "$found" ] || return 1
  found="$wan"
 done <<< "$inventory"
 [ "$found" ] || return 1
 printf '%s\n' "$found"
}

__wce_default_devices()
{
 # A multi-path/equal-priority default is ambiguous. Lower-priority backup
 # routes do not make an otherwise unique current default ambiguous.
 ip -4 route show table main default 2>/dev/null | awk '
 function add(dev,dead) { if(dev!="" && !dead){ n++; d[n]=dev; m[n]=metric } }
 $1=="default" {
  metric=0;route_dead=0;hop_dead=0;in_hop=0;dev=""
  for(i=1;i<NF;i++)if($i=="metric")metric=$(i+1)+0
  for(i=2;i<=NF;i++) {
   if($i=="nexthop"){add(dev,route_dead||hop_dead);dev="";hop_dead=0;in_hop=1}
   else if($i=="dev")dev=$(i+1)
   else if($i=="linkdown"){if(in_hop)hop_dead=1;else route_dead=1}
  }
  add(dev,route_dead||hop_dead);next
 }
 $1=="nexthop" {
  dev="";hop_dead=0
  for(i=1;i<=NF;i++){if($i=="dev")dev=$(i+1);if($i=="linkdown")hop_dead=1}
  add(dev,route_dead||hop_dead)
 }
 END { min=-1;for(i=1;i<=n;i++)if(min<0||m[i]<min)min=m[i];for(i=1;i<=n;i++)if(m[i]==min&&!seen[d[i]]++)print d[i] }
 ' | sort -u
}

__wce_default_wan()
{
 local inventory="$1" defaults first second dev
 defaults=$(__wce_default_devices)
 [ "$(printf '%s\n' "$defaults" | awk 'NF{n++}END{print n+0}')" -le 1 ] || return 1
 # These are routing lookups only; no packets are sent to either address.
 # Requiring agreement avoids picking one WAN from destination-specific paths.
 first=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++)if($i=="dev"){print $(i+1);exit}}')
 second=$(ip -4 route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<NF;i++)if($i=="dev"){print $(i+1);exit}}')
 [ "$first" -a "$first" = "$second" ] || return 1
 # Two DNS destinations may share a policy route that overrides the default.
 [ -z "$defaults" ] || [ "$first" = "$defaults" ] || return 1
 dev="$first"
 __wce_map_device "$dev" "$inventory"
}

__wce_local_address()
{
 local dev="$1" address
 while read -r address;do
  __wce_ipv4 "$address" || continue
  printf '%s\n' "$address";return 0
 done < <(ip -o -4 addr show dev "$dev" scope global 2>/dev/null | awk '{for(i=1;i<NF;i++)if($i=="inet"){split($(i+1),a,"/");print a[1]}}')
 return 1
}

__wce_now()
{
 local value ignored
 read -r value ignored < /proc/uptime || return 1
 value=${value%%.*}
 [[ "$value" =~ ^[0-9]+$ ]] || return 1
 printf '%s\n' "$value"
}

__wce_cached()
{
 local root="$1" wan="$2" dev="$3" index="$4" address="$5" now="$6" force="$7" port="$8"
 local stamp saved_dev saved_index saved_address saved_ip source extra age ttl
 [ -f "$root/$wan.cache" ] || return 1
 IFS=$'\t' read -r stamp saved_dev saved_index saved_address saved_ip source extra < "$root/$wan.cache" || return 1
 [[ "$stamp" =~ ^[0-9]+$ ]] && [ -z "$extra" ] || return 1
 [ "$saved_dev" = "$dev" -a "$saved_index" = "$index" -a "$saved_address" = "$address" ] || return 1
 [ "$now" -ge "$stamp" ] || return 1
 age=$((now-stamp));ttl=10
 case "$source" in
  public) __wce_public_ipv4 "$saved_ip" || return 1;ttl=60;;
  wan) [ "$saved_ip" = "$address" ] || return 1;;
  *) return 1;;
 esac
 [ "$age" -lt "$ttl" ] || return 1
 # Even a forced refresh may not start a new probe within ten seconds.
 [ "$force" != 1 ] || [ "$age" -lt 10 ] || return 1
 if [ "$source" = public ];then
  __wce_reply "$saved_ip" public "$wan" '已检测到所选 WAN 的公网 IPv4 地址' "$port"
 else
  __wce_reply "$address" wan "$wan" '公网检测未成功，已使用该 WAN 获取的 IPv4 地址' "$port"
 fi
}

__wce_probe()
{
 local root="$1" dev="$2" body status value url
 body=$(umask 077;mktemp "$root/probe.XXXXXX") || return 1
 # Never accept caller URLs, proxies, redirects or insecure TLS. Bind the
 # actual WAN device, including wanN_ad for a physical PPPoE WAN.
 for url in https://api.ipify.org/ https://checkip.amazonaws.com/;do
  : > "$body"
  status=$(/usr/bin/curl -q -4 --silent --fail --proto '=https' --tlsv1.2 --noproxy '*' --proxy '' --interface "if!$dev" --connect-timeout 1 --max-time 2 --max-filesize 64 --max-redirs 0 --output "$body" --write-out '%{http_code}' "$url" 2>/dev/null) || continue
  [ "$status" = 200 ] || continue
  [ "$(wc -c < "$body")" -le 64 ] || continue
  value=$(cat "$body");value=${value%$'\r'}
  __wce_public_ipv4 "$value" || continue
  rm -f "$body"
  printf '%s\n' "$value";return 0
 done
 rm -f "$body"
 return 1
}

get()
{
 local service="$1" force="${2:-0}" row bind port inventory wan dev index address now root key value source after after_port current_wan current_dev current_index current_address
 [[ "$service" =~ ^wg[0-9]+$ ]] && [ "${#service}" -le 10 ] || { __wce_reply '' unavailable '' '请选择有效的 WG 服务接口' 0;return 0; }
 [ "$force" = 1 ] || force=0
 row=$(sqlite3 -cmd '.timeout 1000' "$IK_DB_CONFIG" "select ifnull(interface,'auto'),ifnull(local_listenport,0) from wireguard where name='$service' limit 1;" 2>/dev/null) || { __wce_reply '' unavailable '' '读取服务接口失败，请重试' 0;return 0; }
 [ "$row" ] || { __wce_reply '' unavailable '' 'WG 服务接口不存在，请先保存服务接口' 0;return 0; }
 IFS='|' read -r bind port <<< "$row"
 [[ "$port" =~ ^[0-9]{1,5}$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { __wce_reply '' unavailable '' '服务接口监听端口无效，请先修改服务接口' 0;return 0; }
 port=$((10#$port))
 inventory=$(__wce_inventory) || { __wce_reply '' unavailable '' '读取 WAN 设置失败，请重试或手动填写 IP' "$port";return 0; }
 if [ -z "$bind" -o "$bind" = auto ];then
  wan=$(__wce_default_wan "$inventory") || { __wce_reply '' unavailable '' '无法确定唯一的默认 WAN，请为服务接口选择 WAN 或手动填写 IP' "$port";return 0; }
 else
  __wce_device "$bind" "$inventory" >/dev/null || { __wce_reply '' unavailable '' '服务接口未绑定单一有效 WAN，请选择 WAN 或手动填写 IP' "$port";return 0; }
  wan="$bind"
 fi
 dev=$(__wce_device "$wan" "$inventory") || { __wce_reply '' unavailable "$wan" '所选 WAN 的设备不可用，请手动填写 IP' "$port";return 0; }
 address=$(__wce_local_address "$dev") || { __wce_reply '' unavailable "$wan" '所选 WAN 尚未获取有效 IPv4 地址，请手动填写 IP' "$port";return 0; }
 index=$(cat "/sys/class/net/$dev/ifindex" 2>/dev/null)
 [[ "$index" =~ ^[0-9]+$ ]] || { __wce_reply "$address" wan "$wan" '公网检测暂不可用，已使用该 WAN 获取的 IPv4 地址' "$port";return 0; }
 root="$IK_DIR_TMP/wg-client-endpoint"
 now=$(__wce_now) || now=0
 __wce_cached "$root" "$wan" "$dev" "$index" "$address" "$now" "$force" "$port" && return 0
 if ! (umask 077;mkdir -p "$root" && chmod 700 "$root");then
  __wce_reply "$address" wan "$wan" '公网检测暂不可用，已使用该 WAN 获取的 IPv4 地址' "$port";return 0
 fi
 key="wg_client_endpoint_${wan//[!A-Za-z0-9_]/_}"
 if ! LockNonblock "$key";then
  __wce_cached "$root" "$wan" "$dev" "$index" "$address" "$now" 0 "$port" && return 0
  __wce_reply "$address" wan "$wan" '该 WAN 正在检测公网地址，暂用已获取的 WAN 地址' "$port";return 0
 fi
 # Another request may have finished between the first cache check and lock.
 if __wce_cached "$root" "$wan" "$dev" "$index" "$address" "$now" "$force" "$port";then unLock "$key";return 0;fi
 value=$(__wce_probe "$root" "$dev") && source=public || { value="$address";source=wan; }
 # Re-read the complete selection after slow probes. An unchanged WG name
 # can have a different bind, default WAN, PPPoE device, address or ifindex now.
 after=$(sqlite3 -cmd '.timeout 1000' "$IK_DB_CONFIG" "select ifnull(interface,'auto'),ifnull(local_listenport,0) from wireguard where name='$service' limit 1;" 2>/dev/null)
 IFS='|' read -r after after_port <<< "$after"
 if ! [[ "$after_port" =~ ^[0-9]{1,5}$ ]] || [ "$after_port" -lt 1 ] || [ "$after_port" -gt 65535 ];then
  unLock "$key";__wce_reply '' unavailable '' '服务接口设置已变化，请重新检测或手动填写 IP' 0;return 0
 fi
 port=$((10#$after_port))
 inventory=$(__wce_inventory) || { unLock "$key";__wce_reply '' unavailable '' '重新读取 WAN 设置失败，请重试或手动填写 IP' "$port";return 0; }
 if [ -z "$after" -o "$after" = auto ];then
  current_wan=$(__wce_default_wan "$inventory") || { unLock "$key";__wce_reply '' unavailable '' '默认线路已变化，无法确定唯一 WAN，请手动填写 IP' "$port";return 0; }
 else
  __wce_device "$after" "$inventory" >/dev/null || { unLock "$key";__wce_reply '' unavailable '' '服务接口线路已变化，请选择 WAN 或手动填写 IP' "$port";return 0; }
  current_wan="$after"
 fi
 current_dev=$(__wce_device "$current_wan" "$inventory")
 current_address=$(__wce_local_address "$current_dev")
 current_index=$(cat "/sys/class/net/$current_dev/ifindex" 2>/dev/null)
 if ! __wce_ipv4 "$current_address";then
  unLock "$key";__wce_reply '' unavailable "$current_wan" '检测期间 WAN 已断开，请重连或手动填写 IP' "$port";return 0
 fi
 if [ "$after" != "$bind" -o "$current_wan" != "$wan" -o "$current_dev" != "$dev" -o "$current_index" != "$index" -o "$current_address" != "$address" ];then
  unLock "$key"
  __wce_reply "$current_address" wan "$current_wan" '线路或地址已变化，暂用当前 WAN 地址，请重新检测' "$port"
  return 0
 fi
 port=$((10#$after_port));now=$(__wce_now) || now=0
 (umask 077;printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$now" "$dev" "$index" "$address" "$value" "$source" > "$root/$wan.cache.$$" && mv -f "$root/$wan.cache.$$" "$root/$wan.cache") || true
 unLock "$key"
 if [ "$source" = public ];then __wce_reply "$value" public "$wan" '已检测到所选 WAN 的公网 IPv4 地址' "$port"
 else __wce_reply "$address" wan "$wan" '公网检测未成功，已使用该 WAN 获取的 IPv4 地址' "$port";fi
}

# Only a globally routable literal can be prefilled as the public HY entry.
# On an unreachable WAN leave the caller a manual override; never advertise a
# private fallback or the address of a different uplink.
get_public()
{
 local result address
 result=$(get "$1" 0) && address=$(printf '%s' "$result" | jq -e -r '.ip') &&
  __wce_public_ipv4 "$address" || return 1
 printf '%s\n' "$address"
}
