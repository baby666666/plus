#!/bin/bash
# Verify only native IPv4 management listeners. Never create a listener or alter
# WEBACL, users, sessions, permissions, forwarding, or the public management flag.
set -u
set -o pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mode=${1:-}; gateway=${2:-}; http=${3:-0}; https=${4:-0}
conf=/usr/openresty/conf
root=/tmp/iktmp/wg-pure-admin
case "$mode" in probe|refresh) ;; *) exit 2;;esac
valid_port(){
 [[ $1 =~ ^(0|[1-9][0-9]{0,4})$ ]] && [ "$1" -le 65535 ] || return 1
 # Port 53 is captured and NR_INPUT protects 6153:6232 for native DNS.
 # Reject each conflicting port independently; the other listener can remain.
 [ "$1" != 53 ] && { [ "$1" -lt 6153 ] || [ "$1" -gt 6232 ]; }
}
[[ $gateway =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || exit 1
IFS=. read -r a b c d <<< "$gateway"
for n in "$a" "$b" "$c" "$d";do
 [[ $n = 0 || $n != 0* ]] && [ "$((10#$n))" -le 255 ] || exit 1
done
printf -v local_hex '%02X%02X%02X%02X' "$d" "$c" "$b" "$a"
cache=
if [ -d "$root" ] && [ ! -L "$root" ] && [ "$(stat -c '%u:%a' "$root")" = 0:700 ];then cache=$root/sockets;fi
if [ "$mode" = refresh ] && [ ! -e "$root" ] && [ ! -L "$root" ];then
 mkdir -m 700 "$root" 2>/dev/null || :
 [ -d "$root" ] && [ ! -L "$root" ] && [ "$(stat -c '%u:%a' "$root")" = 0:700 ] && cache=$root/sockets
fi
socket_owner(){
 local inode=$1 pid fd saved rest path candidate
 if [ -n "$cache" ] && [ -f "$cache" ] && [ ! -L "$cache" ];then
  while read -r saved pid fd rest;do
   [[ $saved = "$inode" && $pid =~ ^[1-9][0-9]*$ && $fd =~ ^[0-9]+$ && -z $rest ]] || continue
   if [ "$(readlink "/proc/$pid/exe" 2>/dev/null)" = /usr/sbin/openresty ] &&
      [ "$(readlink "/proc/$pid/fd/$fd" 2>/dev/null)" = "socket:[$inode]" ];then
    owners+="$inode $pid $fd"$'\n';return 0
   fi
  done < "$cache"
 fi
 for path in /proc/[0-9]*/exe;do
  [ "$(readlink "$path" 2>/dev/null)" = /usr/sbin/openresty ] || continue
  pid=${path#/proc/};pid=${pid%/exe}
  for candidate in "/proc/$pid/fd/"*;do
   [ "$(readlink "$candidate" 2>/dev/null)" = "socket:[$inode]" ] || continue
   owners+="$inode $pid ${candidate##*/}"$'\n';return 0
  done
 done
 return 1
}
verify_port(){
 local kind=$1 port=$2 hex inodes inode
 valid_port "$port" && [ "$port" != 0 ] || return 1
 [ "$http" = 0 ] || [ "$https" = 0 ] || [ "$http" != "$https" ] || return 1
 ipset test Linux_webport_default "$port" >/dev/null 2>&1 || return 1
 grep -Ex "[[:space:]]*include conf/webman_$kind[.]conf;[[:space:]]*" "$conf/server.conf" >/dev/null 2>&1 || return 1
 if [ "$kind" = http ];then
  grep -Ex "[[:space:]]*listen $port;[[:space:]]*" "$conf/http_port.conf" >/dev/null 2>&1 || return 1
 else
  grep -Ex "[[:space:]]*listen $port ssl;[[:space:]]*" "$conf/https_port.conf" >/dev/null 2>&1 || return 1
 fi
 # Fail closed for unreadable kernel state, missing listeners and conflicting
 # processes. An unrelated listener with the same port is not management.
 printf -v hex '%04X' "$port"
 inodes=$(awk -v port="$hex" -v local_ip="$local_hex" '
  $4=="0A"{split($2,a,":");if(a[2]==port&&(a[1]=="00000000"||a[1]==local_ip))print $10}' /proc/net/tcp) || return 1
 [ -n "$inodes" ] || return 1
 while read -r inode;do
  [[ $inode =~ ^[1-9][0-9]*$ ]] && socket_owner "$inode" || return 1
 done <<< "$inodes"
}
owners=;verified_http=0;verified_https=0
verify_port http "$http" && verified_http=$http
verify_port https "$https" && verified_https=$https
if [ "$mode" = refresh ] && [ -n "$cache" ];then
 printf '%s' "$owners" > "$cache.$$" && mv -f "$cache.$$" "$cache" || rm -f "$cache.$$"
fi
printf '%s %s\n' "$verified_http" "$verified_https"
