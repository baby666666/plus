#!/bin/bash /etc/ikcommon
# Compatibility entry points cannot start a second DNS engine after upgrade.
retired() {
 /usr/ikuai/script/retire_wg_dns.sh cleanup || return 1
 echo 'WireGuard DNS split retired; use domain routing DNS settings'
 return 1
}
apply() { retired; }
update() { retired; }
update_apply() { retired; }
status() { retired; }
test() { retired; }
stop() { /usr/ikuai/script/retire_wg_dns.sh cleanup; }
clean() { stop; }
