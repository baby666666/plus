#!/bin/bash
# Copy this script into a disposable iKuai test VM; it deliberately kills its test listener.
set -euo pipefail
umask 077
engine=/usr/ikuai/script/wg_hy_engine.sh
runtime=/tmp/iktmp/wg-hy-engine/puh-19471
if [ "${1:-}" != --disposable-guest ] || [ ! -x "$engine" ] ||
        ! grep -q 'DEVELOPER=true' /proc/cmdline; then
    echo 'Run only inside the disposable firmware test VM with --disposable-guest [official archive].' >&2
    exit 2
fi
unit_existed=no
[ ! -e "$runtime" ] || unit_existed=yes
if "$engine" puh-19471 status || [ -e "$runtime/live.json" ]; then
    echo 'This guest already has an active or recoverable listener.' >&2
    exit 2
fi
if [ "$unit_existed" = no ]; then
    "$engine" puh-19471 available 19471 || { echo 'Test port 19471 is occupied.' >&2; exit 2; }
    [ ! -e "$runtime" ] || { echo 'A status read created a unit directory.' >&2; exit 1; }
fi
temp=$(mktemp -d /tmp/test-hy-engine.XXXXXX)
blocker=
cleanup() {
    "$engine" puh-19471 stop || :
    [ -z "$blocker" ] || kill "$blocker" 2>/dev/null || :
    rm -rf "$temp"
}
trap cleanup EXIT
reject() {
    if "$@"; then echo "Unexpected success: $1 $2" >&2; exit 1; fi
}

echo invalid > "$temp/invalid"
mkfifo "$temp/pipe"
ln -s "$temp/invalid" "$temp/link"
reject "$engine" install "$temp/invalid"
reject "$engine" install "$temp/pipe"
reject "$engine" install "$temp/link"
if [ "$#" -ge 2 ]; then "$engine" install "$2"; else "$engine" install; fi
"$engine" installed
binary=$("$engine" path)
case $("$engine" storage):$("$engine" location):$binary in
    disk:plain:/etc/*|memory:memory:/tmp/iktmp/wg-hy-engine/sing-box) ;;
    disk:compact:/tmp/iktmp/wg-hy-engine/compact/sing-box)
        awk -v root="${binary%/*}" '$5==root && $6~/(^|,)ro(,|$)/ && $6~/(^|,)nosuid(,|$)/ &&
            $6~/(^|,)nodev(,|$)/ && $6!~/(^|,)noexec(,|$)/ && $(NF-2)=="squashfs" {found=1}
            END{exit !found}' /proc/self/mountinfo
        [ "$(sha256sum "$binary" | cut -d " " -f 1)" = fe23d7000aaaa91f40b63641a65a1a84d96b5f179c65b63f34893e238884cd5c ]
        [ ! -e "${runtime%/*}/sing-box" ];;

    *) echo 'Invalid storage report for the installed core.' >&2; exit 1;;
esac
reject "$engine" hyr-19471 start "$temp/invalid"
"$binary" version | sed -n '1p'

# Generate private loopback listeners, without any real WG credentials.
openssl req -new -newkey rsa:2048 -x509 -nodes -sha256 -days 1 -subj /CN=localhost \
    -keyout "$temp/key.pem" -out "$temp/cert.pem" </dev/null >/dev/null 2>&1
for port in 19471 19472; do
    if netstat -lun | awk -v p="$port" '$4 ~ ":"p"$" {found=1} END{exit !found}'; then
        echo "Test port $port already occupied" >&2; exit 1
    fi
    cat >"$temp/$port" <<JSON
{"inbounds":[{"type":"hysteria2","listen":"127.0.0.1","listen_port":$port,"users":[{"name":"qa","password":"loopback-test"}],"tls":{"enabled":true,"certificate_path":"$temp/cert.pem","key_path":"$temp/key.pem"}}],"outbounds":[{"type":"direct"}]}
JSON
done
"$binary" run -c "$temp/19472" </dev/null >/dev/null 2>&1 &
blocker=$!
for ((i=0; i<100; i++)); do
    netstat -lun | awk '$4 ~ /:19472$/ {found=1} END{exit !found}' && break
    kill -0 "$blocker"
    sleep 0.1
done
"$engine" puh-19471 start "$temp/19471"
"$engine" puh-19471 status
original=$(cat "$runtime/service.pid")
"$engine" puh-19471 start "$temp/19471"
test "$original" = "$(cat "$runtime/service.pid")"
reject "$engine" puh-19471 start "$temp/invalid"
test "$original" = "$(cat "$runtime/service.pid")"
reject "$engine" puh-19471 start "$temp/19472"
"$engine" puh-19471 status
cmp -s "$temp/19471" "$runtime/live.json"

# A fresh start recovers the known listen configuration after a killed process.
read -r pid _ <"$runtime/service.pid"
kill -KILL "$pid"
for ((i=0; i<50; i++)); do "$engine" puh-19471 status || break; sleep 0.1; done
"$engine" puh-19471 start "$temp/19471"
"$engine" puh-19471 status
"$engine" puh-19471 stop
if "$engine" puh-19471 status || [ -e "$runtime/live.json" ]; then exit 1; fi
echo 'PASS: pinned Hysteria core, idempotent start, invalid config, UDP bind rollback and stop.'
