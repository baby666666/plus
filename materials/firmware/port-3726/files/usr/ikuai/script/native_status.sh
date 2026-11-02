#!/bin/bash
# A short read snapshot uses the existing writer lock; a busy writer is reported
# immediately. Never recover/remove someone else's lock or run health probes.
STATE=/tmp/iktmp/strict-routing
# Without the writer's parent directory there is no coherent lockable snapshot.
if [ ! -d "$STATE" ];then exec /usr/bin/lua /usr/ikuai/script/native_status.lua busy;fi
if ! mkdir "$STATE/lock" 2>/dev/null;then
 exec /usr/bin/lua /usr/ikuai/script/native_status.lua busy
fi
cleanup(){
 local owner
 if [ -f "$STATE/lock/pid" ];then
  IFS= read -r owner < "$STATE/lock/pid" || owner=
  # A replaced lock belongs to another operation, even if our sample failed.
  [ "$owner" = "$$" ] || [ ! -s "$STATE/lock/pid" ] || return 0
  rm -f "$STATE/lock/pid"
 fi
 rmdir "$STATE/lock" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if ! printf '%s\n' "$$" > "$STATE/lock/pid";then
 cleanup
 trap - EXIT
 exec /usr/bin/lua /usr/ikuai/script/native_status.lua busy
fi
/usr/bin/lua /usr/ikuai/script/native_status.lua
