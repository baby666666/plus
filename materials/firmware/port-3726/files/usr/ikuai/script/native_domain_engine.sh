#!/bin/bash
# The native learner emits a per-rule mark. An always-up internal selector
# prevents its WAN availability fallback; policy routing and the existing
# fixed-exit guards decide the real output device.
source /usr/ikuai/script/native_shadow.sh
nr_native_begin(){
 [ "${NR_SHADOW:-0}" != 1 ] || return 0
 ik_cntl url_route disable >/dev/null
 # A dirty cache is never trusted after an interrupted update or first boot.
 local expected loaded slot tag pref dev group binding
 declare -gA NR_NATIVE_KEEP=() NR_NATIVE_BINDINGS=() NR_NATIVE_REPLACED=() NR_NATIVE_WANTED=()
 while read -r slot group;do [ -z "$slot" ] || NR_NATIVE_WANTED[$slot]=1;done < "$NR/active/native-desired.groups"
 expected=$(wc -l 2>/dev/null < "$NR/native-loaded.map" || echo -1)
 if [ -s "$NR/active/native-count-before" ];then
  loaded=$(cat "$NR/active/native-count-before")
  rm -f "$NR/active/native-count-before"
 else
  loaded=$(/usr/sbin/native-url-count)
 fi
 local cold=0
 if [ -f "$NR/native-dirty" ] || [ -f "$NR/native-stage.pending" ] || [ ! -f "$NR/native-loaded.map" ] || [ ! -f "$NR/native-bindings" ] || [ "$loaded" != "$expected" ];then
  [ "${NR_NATIVE_DELTA:-0}" != 1 ] || { echo "原生缓存已变化，拒绝增量提交";return 1; }
  cold=1
  ik_cntl url_route group clear >/dev/null
  ik_cntl url_route clear >/dev/null
  local gate
  for gate in $(ipset list -name | grep -E "^nr_n[gs]_[0-9]+$");do ipset destroy "$gate" || return 1;done
  rm -f "$NR/native-stage.pending"
  : > "$NR/native-loaded.map"
 else
  while read -r group binding;do [ -z "$group" ] || NR_NATIVE_BINDINGS[$group]="$binding";done < "$NR/native-bindings"
  while read -r group;do
   [ -n "$group" ] || continue
   ik_cntl url_route group del "$group" >/dev/null
   NR_NATIVE_REPLACED[$group]=1
  done < "$NR/active/native-changed.groups"
 fi
 : > "$NR/native-bindings.next"
 : > "$NR/native-replaced.groups"
 touch "$NR/native-dirty"
 if [ -f "$NR/native-selectors" ];then
  while read -r slot tag dev;do
   if [ "$cold" = 0 ] && [ "${NR_NATIVE_WANTED[$slot]}" = 1 ] && [ -e "/sys/class/net/$dev" ];then
    NR_NATIVE_KEEP[$slot]=1
    continue
   fi
   [ "${NR_NATIVE_DELTA:-0}" != 1 ] || { echo "原生选择器已变化，拒绝增量提交";return 1; }
   pref=$((700+slot*2))
   while ip rule del pref "$pref" 2>/dev/null;do :;done
   ik_cntl iface_band del "$dev" >/dev/null
   ip link del "$dev" 2>/dev/null || true
  done < "$NR/native-selectors"
 fi
 [ "${NR_NATIVE_DELTA:-0}" = 1 ] || : > "$NR/native-selectors"
 NR_NATIVE_GROUP=0
 NR_NATIVE_EXPECTED=0
}
nr_native_selector(){
 local slot="$1" exit="$2" time="$3" rule="$4" dev="pppnrd$1" tag=$((11000+$1)) mark=$((3011000+$1)) pref=$((700+$1*2)) iface real available
 read -r exit iface real available <<< "$(awk -v id="$exit" '$1==id{print;exit}' "$NR/exits")"
 [ "$iface" ] && [ "$slot" -ge 1 ] && [ "$slot" -le 255 ]
 # Never overwrite an unrelated route mark or device.
 [ "${NR_NATIVE_KEEP[$slot]}" = 1 ] || [ ! -e "/sys/class/net/$dev" ]
 ! ip rule show | grep -E "fwmark $(printf '0x%x' "$tag")([ /]|$)" | grep -v "^$pref:" | grep -v "^$((pref+1)):" >/dev/null
 printf '%s %s %s\n' "$slot" "$tag" "$dev" >> "$NR/native-selectors"
 if [ "${NR_NATIVE_KEEP[$slot]}" != 1 ];then
  ip link add "$dev" type ipip local "127.248.0.$slot" remote "127.249.0.$slot" dev lo
  ik_cntl iface_band add "$dev" "$tag" >/dev/null
 fi
 ip link set "$dev" up
 ik_cntl iface_band set "$dev" 1 >/dev/null
 while ip rule del pref "$pref" 2>/dev/null;do :;done
 while ip rule del pref "$((pref+1))" 2>/dev/null;do :;done
 ip rule add pref "$((pref+1))" fwmark "$tag" prohibit
 if [ "$available" = 1 ];then ip rule add pref "$pref" fwmark "$tag" table "$iface";fi
 # Randomize TCP to avoid rapid tuple reuse; this kernel conflicts on random UDP NAT.
 nr_ipt -t nat -A NR_NAT -m connmark --mark "$mark" -o "$real" -p tcp -j MASQUERADE --random-fully
 nr_ipt -t nat -A NR_NAT -m connmark --mark "$mark" -o "$real" -j MASQUERADE
 nr_ipt -t mangle -A NR_FAST -m connmark --mark "$mark" -j ACCEPT
 local table chain window
 for table in filter mangle;do
  chain=NR_FWD;[ "$table" != mangle ] || chain=NR_EGRESS
  while IFS= read -r window;do
   nr_ipt -t "$table" -A "$chain" -m connmark --mark "$mark" $window -m conntrack --ctdir REPLY -j RETURN
   nr_ipt -t "$table" -A "$chain" -m connmark --mark "$mark" $window -m set --match-set "nr_h_$rule" dst,src -o "$real" -j RETURN
  done <<< "$time"
  nr_ipt -t "$table" -A "$chain" -m connmark --mark "$mark" -j DROP
 done
}
nr_native_group(){
 [ "${NR_SHADOW:-0}" != 1 ] || return 0
 local slot="$1" source="$2" weeks="$3" times="$4" file="$5" group binding
 binding="$slot $source $weeks $times"
 [ "$source" != null ] || binding="$binding gate1"
 while read -r group;do
  [ -n "$group" ] || continue
  # Existing groups cannot be rebound by another add. Keep their selector
  # devices alive; replace only changed memberships or binding parameters.
  # Native source sets are flushed/refilled in place, preserving their IDs.
  if [ "${NR_NATIVE_REPLACED[$group]}" = 1 ] || [ "${NR_NATIVE_BINDINGS[$group]}" != "$binding" ];then
   if [ -n "${NR_NATIVE_BINDINGS[$group]}" ] && [ "${NR_NATIVE_REPLACED[$group]}" != 1 ];then
    ik_cntl url_route group del "$group" >/dev/null
   fi
   printf '%s\n' "$group" >> "$NR/native-replaced.groups"
   local bound="$source"
   if [ "$source" = null ];then
    bound="nr_ng_$group"
    ipset create "$bound" hash:net -exist || return 1
    ipset flush "$bound" && ipset add "$bound" 0.0.0.0/1 && ipset add "$bound" 128.0.0.0/1 || return 1
   fi
   ik_cntl url_route group add "$group" "$bound" $times "$weeks" "$((11000+slot)):pppnrd$slot" >/dev/null
  fi
  printf '%s %s\n' "$group" "$binding" >> "$NR/native-bindings.next"
  NR_NATIVE_GROUP=$((NR_NATIVE_GROUP+1))
 done < <(awk -v slot="$slot" '$1==slot{print $2}' "$NR/active/native-desired.groups")
 NR_NATIVE_EXPECTED=$((NR_NATIVE_EXPECTED+$(wc -l < "$file")))
}
nr_native_match(){
 local expression slot="$2" mark="$3" native=$((3011000+$2))
 while IFS= read -r expression;do
  nr_ipt -t mangle -A NR_CLASS $expression -m connmark --mark "$native" -j MARK --set-mark "$mark"
  nr_ipt -t mangle -A NR_CLASS $expression -m connmark --mark "$native" -j CONNMARK --save-mark
  nr_ipt -t mangle -A NR_CLASS $expression -m mark --mark "$mark" -j ACCEPT
 done <<< "$1"
}
nr_native_finish(){
 if [ "${NR_SHADOW:-0}" = 1 ];then nr_shadow_commit;return $?;fi
 # Broad native connmarks must not be sent through an unintended interface if
 # a selector is removed or an incomplete apply leaves a connection behind.
 local loaded group
 /usr/sbin/native-url-sync "$NR/native-loaded.map" "$NR/active/native-desired.map" "$NR/native-replaced.groups" || return 1
 loaded=$(/usr/sbin/native-url-count)
 [ "$loaded" = "$NR_NATIVE_EXPECTED" ] || { echo "原生域名载入校验失败：$loaded/$NR_NATIVE_EXPECTED";return 1; }
 cp "$NR/active/native-desired.map" "$NR/native-loaded.map.new" && mv "$NR/native-loaded.map.new" "$NR/native-loaded.map" || return 1
 cp "$NR/active/native-desired.slots" "$NR/native-slots.json.new" && mv "$NR/native-slots.json.new" "$NR/native-slots.json" || return 1
 mv "$NR/native-bindings.next" "$NR/native-bindings" || return 1
 local gate gid
 for gate in $(ipset list -name | grep -E "^nr_n[gs]_[0-9]+$");do
  gid=${gate##*_}
  if [[ "$gate" == nr_ns_* ]] || ! grep -q "^$gid .* gate1$" "$NR/native-bindings";then ipset destroy "$gate" || return 1;fi
 done
 rm -f "$NR/native-dirty"
 if [ "$NR_NATIVE_GROUP" -gt 0 ];then ik_cntl url_route enable >/dev/null;fi
}
