#!/bin/bash /etc/ikcommon
Include iproute.sh

CONF=/etc/mnt/ikuai/wg_center.conf
WORK=/etc/mnt/ikuai/wg_center
TMP=/tmp/iktmp/wg_center
SET_CHINA=wg_center_china4
TAG="wg-center-policy"

write_default_conf()
{
    [ -f "$CONF" ] && return
    cat > "$CONF" <<'EOF'
# 0=disable, 1=enable
ENABLE=0

# B center node: clients connected to B by WireGuard.
CLIENT_SRC="10.100.10.0/24"

# China mainland exit and overseas exit WireGuard interface names on B.
CHINA_IFACE="wg_to_A"
OVERSEA_IFACE="wg_to_C"

# Optional: traffic not matched by China IP set goes to OVERSEA_IFACE when set to 1.
ROUTE_NON_CHINA=1

# China IPv4 CIDR list is maintained by:
# Network Settings > Terminal Group > IP Group > China IP library auto update.
CHINA_IPLIB="/etc/mnt/ikuai/china_iplib/china_ipv4.txt"

# Optional NAT for exit nodes A/C. Keep disabled on center node B.
NAT_ENABLE=0
NAT_SRC="10.100.10.0/24"
NAT_WAN="wan1"
EOF
}

load_conf()
{
    write_default_conf
    . "$CONF"
}

fetch_file()
{
    local url="$1" out="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -L --connect-timeout 15 --max-time 60 -o "$out" "$url" >/dev/null 2>&1
        return $?
    fi
    if command -v wget >/dev/null 2>&1; then
        wget -T 60 -O "$out" "$url" >/dev/null 2>&1
        return $?
    fi
    return 1
}

valid_cidr_file()
{
    local f="$1"
    [ -s "$f" ] || return 1
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' "$f" >/dev/null 2>&1
}

update_ipset()
{
    load_conf
    local src="${CHINA_IPLIB:-/etc/mnt/ikuai/china_iplib/china_ipv4.txt}"
    local old="$WORK/china_ipv4.txt"

    valid_cidr_file "$src" || {
        echo "china ip library not found, update it in IP Group page first: $src"
        return 1
    }
    cp "$src" "$old"
    echo "$(date '+%F %T') updated $(wc -l < "$old") china ipv4 routes" > "$WORK/last_update.log"
}

load_ipset()
{
    ipset create "$SET_CHINA" hash:net family inet hashsize 4096 maxelem 262144 >/dev/null 2>&1 || true
    ipset flush "$SET_CHINA" >/dev/null 2>&1 || return 1
    local list="${CHINA_IPLIB:-/etc/mnt/ikuai/china_iplib/china_ipv4.txt}"
    valid_cidr_file "$list" || list="$WORK/china_ipv4.txt"
    valid_cidr_file "$list" || return 1
    while read net; do
        [ "$net" ] || continue
        ipset add "$SET_CHINA" "$net" >/dev/null 2>&1 || true
    done < "$list"
}

mark_id()
{
    local iface="$1"
    local mark=$(iproute_get_markid "$iface" 2>/dev/null)
    [ "$mark" ] || mark=$(echo "$iface" | cksum | awk '{print 30000 + ($1 % 20000)}')
    echo "$mark"
}

ensure_rule()
{
    local mark="$1" table="$2" prio="$3"
    ip rule show 2>/dev/null | grep -q "fwmark .*0x$(printf '%x' "$mark").*lookup $table" || \
        ip rule add fwmark "$mark" table "$table" prio "$prio" >/dev/null 2>&1
}

ensure_table_default()
{
    local iface="$1"
    [ "$iface" ] || return
    echo "$iface" | grep -Eq '^(wan|vwan|adsl)' && return
    [ -e "/sys/class/net/$iface" ] || return
    ip route show table "$iface" 2>/dev/null | grep -q '^default ' || \
        ip route replace default dev "$iface" table "$iface" metric 100 >/dev/null 2>&1
}

clean_rule_chain()
(
    set -o pipefail
    local table="$1" chain="$2" first="$3" second="${4:-}"
    local -a rule
    iptables -w 3 -t "$table" -S "$chain" | awk -v a="$first" -v b="$second" '
        {sub(/^\[fastid: [0-9]+\] /,"")}
        $1=="-A" {
            for(i=2;i<NF;i++) if($i=="--comment"){
                tag=$(i+1)
                if(tag==a || tag=="\"" a "\"")tag=a
                else if(b!="" && (tag==b || tag=="\"" b "\""))tag=b
                else break
                $1="-D";$(i+1)=tag;print;break
            }
        }' | while read -r -a rule;do
            iptables -w 3 -t "$table" "${rule[@]}" || return 1
        done
)

clean_rules()
{
    clean_rule_chain mangle PREROUTING "$TAG:china" "$TAG:oversea" &&
        clean_rule_chain nat POSTROUTING "$TAG:nat"
}

install_rules()
{
    iptables -w 3 -t mangle -A PREROUTING -s "$CLIENT_SRC" -m set --match-set "$SET_CHINA" dst \
        -m comment --comment "$TAG:china" -j MARK --set-mark "$1" || return 1
    if [ "$ROUTE_NON_CHINA" = "1" ]; then
        iptables -w 3 -t mangle -A PREROUTING -s "$CLIENT_SRC" -m set ! --match-set "$SET_CHINA" dst \
            -m comment --comment "$TAG:oversea" -j MARK --set-mark "$2" || return 1
    fi
    if [ "$NAT_ENABLE" = "1" -a "$NAT_SRC" -a "$NAT_WAN" ]; then
        iptables -w 3 -t nat -A POSTROUTING -s "$NAT_SRC" -o "$NAT_WAN" \
            -m comment --comment "$TAG:nat" -j MASQUERADE || return 1
    fi
}
apply_policy()
{
    load_conf
    [ "$ENABLE" = "1" ] || {
        clean_rules || { echo "failed to clean WG center rules";return 1; }
        echo "disabled"
        return 0
    }
    [ "$CLIENT_SRC" -a "$CHINA_IFACE" -a "$OVERSEA_IFACE" ] || {
        echo "missing CLIENT_SRC/CHINA_IFACE/OVERSEA_IFACE"
        return 1
    }
    load_ipset || {
        echo "ipset not ready, run: $0 update"
        return 1
    }

    local mark_cn=$(mark_id "$CHINA_IFACE")
    local mark_os=$(mark_id "$OVERSEA_IFACE")

    ensure_table_default "$CHINA_IFACE"
    ensure_table_default "$OVERSEA_IFACE"
    ensure_rule "$mark_cn" "$CHINA_IFACE" 10021
    ensure_rule "$mark_os" "$OVERSEA_IFACE" 10022

    clean_rules || { echo "failed to clean WG center rules";return 1; }
    if ! install_rules "$mark_cn" "$mark_os";then
        clean_rules
        echo "failed to apply WG center rules"
        return 1
    fi
    echo "$(date '+%F %T') applied client=$CLIENT_SRC china=$CHINA_IFACE oversea=$OVERSEA_IFACE" > "$WORK/last_apply.log"
}

install_cron()
{
    if command -v crontab >/dev/null 2>&1; then
        (crontab -l 2>/dev/null | grep -v 'wg_center_route.sh update_apply'; echo '17 4 * * * /usr/ikuai/script/wg_center_route.sh update_apply >/tmp/iktmp/wg_center_cron.log 2>&1') | crontab -
    fi
}

# /etc/ikcommon sources this file with an empty argument before dispatching
# the requested function. Take the lock only inside a mutating entry point.
run_center_action()
(
    mkdir -p "$WORK" "$TMP" || return 1
    exec 8>"$TMP/policy.lock" && flock -x 8 || return 1
    case "$1" in
        boot) install_cron && apply_policy;;
        apply) apply_policy;;
        update) update_ipset;;
        update_apply) update_ipset && apply_policy;;
        clean) clean_rules;;
        *) return 1;;
    esac
)

boot(){ run_center_action boot; }
apply(){ run_center_action apply; }
update(){ run_center_action update; }
update_apply(){ run_center_action update_apply; }
clean(){ run_center_action clean; }

status()
{
    load_conf || return 1
    echo "ENABLE=$ENABLE CLIENT_SRC=$CLIENT_SRC CHINA_IFACE=$CHINA_IFACE OVERSEA_IFACE=$OVERSEA_IFACE ROUTE_NON_CHINA=$ROUTE_NON_CHINA"
    ipset list "$SET_CHINA" 2>/dev/null | head -20
    local log
    for log in "$WORK/last_update.log" "$WORK/last_apply.log";do
        [ ! -f "$log" ] || cat "$log"
    done
}
