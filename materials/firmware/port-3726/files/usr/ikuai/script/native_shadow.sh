#!/bin/bash
# Called with the shared transaction lock held. Only exact routing plans and
# existing all-source selectors qualify; scoped/time/exit edits keep full apply.
nr_shadow_stage(){
 local next="$1" rc group slot source weeks first last loaded expected
 [ ! -f "$NR/native-stage.pending" ] && [ ! -f "$NR/native-dirty" ] || return 1
 expected=$(wc -l < "$NR/native-loaded.map")
 if [ -s "$next/native-count-before" ];then [ "$(cat "$next/native-count-before")" = "$expected" ] || return 1;fi
 /usr/sbin/native-work-run /usr/sbin/native-shadow-plan "$NR" "$next";rc=$?
 [ "$rc" != 3 ] || return 3
 [ "$rc" = 0 ] || return 1
 # Persist intent before the first mutation; interrupted preparation is never
 # silently accepted by the monitor. The next full apply rebuilds from scratch.
 cp "$next/shadow-create" "$NR/native-stage.pending" || return 1
 while read -r group;do
  [ "$group" ] || continue
  ipset test "nr_ng_$group" 0.0.0.0/1 >/dev/null 2>&1 && ipset test "nr_ng_$group" 128.0.0.0/1 >/dev/null 2>&1 || return 1
 done < "$next/shadow-retire"
 while read -r group slot source weeks first last;do
  [ "$group" ] || continue
  ipset create "nr_ng_$group" hash:net || return 1
  ipset create "nr_ns_$group" hash:net || return 1
  ipset add "nr_ns_$group" 0.0.0.0/1 && ipset add "nr_ns_$group" 128.0.0.0/1 || return 1
  ik_cntl url_route group add "$group" "nr_ng_$group" "$first" "$last" "$weeks" "$((11000+slot)):pppnrd$slot" >/dev/null || return 1
 done < "$next/shadow-create"
 : > "$next/shadow-empty.map"
 /usr/sbin/native-url-sync "$next/shadow-empty.map" "$next/shadow-stage.map" || return 1
 loaded=$(/usr/sbin/native-work-run /usr/sbin/native-url-count) || return 1
 [ "$loaded" = "$(cat "$next/shadow-total")" ] || { echo '预加载域名数量校验失败';return 1; }
 cp "$next/shadow-desired.map" "$next/native-desired.map" && cp "$next/shadow-groups" "$next/native-desired.groups" || return 1
 touch "$next/shadow-verified"
}
nr_shadow_commit(){
 local group slot source weeks first last
 [ -f "$NR/native-stage.pending" ] && [ -f "$NR/active/shadow-verified" ] || return 1
 touch "$NR/native-dirty"
 # The existing traffic guard covers this multi-group transition. No domain
 # loading, full kernel enumeration or DNS parsing occurs in this window.
 while read -r group;do
  [ "$group" ] || continue
  ipset flush "nr_ng_$group" || return 1
 done < "$NR/active/shadow-retire"
 while read -r group slot source weeks first last;do
  [ "$group" ] || continue
  ipset swap "nr_ng_$group" "nr_ns_$group" || return 1
 done < "$NR/active/shadow-create"
 cp "$NR/active/native-desired.map" "$NR/native-loaded.map.new" && mv "$NR/native-loaded.map.new" "$NR/native-loaded.map" || return 1
 cp "$NR/active/native-desired.slots" "$NR/native-slots.json.new" && mv "$NR/native-slots.json.new" "$NR/native-slots.json" || return 1
 cp "$NR/active/shadow-bindings" "$NR/native-bindings.new" && mv "$NR/native-bindings.new" "$NR/native-bindings" || return 1
 # stage.pending remains until inactive old groups are retired and checked.
 rm -f "$NR/native-dirty"
}
nr_shadow_retire(){
 [ -f "$NR/active/shadow-verified" ] && [ -f "$NR/native-stage.pending" ] || return 0
 local group slot source weeks first last loaded
 while read -r group;do
  [ "$group" ] || continue
  ik_cntl url_route group del "$group" >/dev/null || return 1
  ipset destroy "nr_ng_$group" || return 1
 done < "$NR/active/shadow-retire"
 while read -r group slot source weeks first last;do
  [ "$group" ] || continue;ipset destroy "nr_ns_$group" || return 1
 done < "$NR/active/shadow-create"
 # The complete active+staged membership was verified before activation.
 # Only inactive old groups were removed here. Destroying each private source
 # set above must succeed: the kernel refuses it while any group holds a
 # reference. This validates retirement without re-enumerating live rules.
 rm -f "$NR/native-stage.pending" "$NR/active/shadow-verified"
}
