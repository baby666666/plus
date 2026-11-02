#!/usr/bin/ikluajit
-- Retired compatibility stub: the sole DNS routing engine is strict-dnsmasq.
io.stderr:write('WireGuard DNS split retired; use domain routing DNS settings\n')
os.exit(1)
