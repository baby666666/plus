#!/usr/bin/env python3
"""Portable WG pure-unit tests; never contacts a router."""
from pathlib import Path
import argparse,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--lua',default='lua',help='Lua 5.1-compatible interpreter');a=p.parse_args()
for name in ['address-ui-unit.js','import-unit.js','client-config-unit.js','site-config-unit.js','wg-i18n-unit.js','singbox-unit.js','key-generation-unit.js']:
 subprocess.run(['node',str(ROOT/'materials/web-src/tests'/name)],check=True)
subprocess.run([a.lua,str(ROOT/'materials/tests/wg-address-unit.lua'),str(ROOT/'materials/firmware/port-3726/files/usr/ikuai/script/wg_address_plan.lua')],check=True)

subprocess.run([a.lua,str(ROOT/'materials/tests/wg-exit-unit.lua'),str(ROOT/'materials/firmware/port-3726/files/usr/ikuai/script/wg_address_plan.lua')],check=True)

subprocess.run([a.lua,str(ROOT/'materials/tests/wg-site-unit.lua'),str(ROOT/'materials/firmware/port-3726/files/usr/ikuai/script/wg_address_plan.lua')],check=True)
subprocess.run([a.lua,str(ROOT/'materials/tests/wg-interface-dependency-unit.lua'),str(ROOT/'materials/firmware/port-3726/files/usr/ikuai/script/wg_address_plan.lua')],check=True)
subprocess.run([sys.executable,str(ROOT/'materials/tests/wg-endpoint-restore-unit.py'),str(ROOT/'materials/firmware/port-3726/files/usr/ikuai/script/wireguard.sh')],check=True)
subprocess.run([sys.executable,str(ROOT/'materials/tests/native-dns-bind-interface-unit.py'),str(ROOT/'materials/firmware/port-3726/files/usr/ikuai/script/native_dns_bind.sh')],check=True)

subprocess.run([sys.executable,str(ROOT/'materials/tests/wg-resolver-unit.py'),str(ROOT/'materials/firmware/port-3726/files/usr/ikuai/script/wireguard.sh')],check=True)

subprocess.run([sys.executable,str(ROOT/'materials/tests/wg-apply-unit.py'),str(ROOT/'materials/firmware/port-3726/files/usr/ikuai/script/wireguard.sh')],check=True)

subprocess.run([sys.executable,str(ROOT/'materials/tests/wg-api-dispatch-unit.py'),str(ROOT/'materials/firmware/port-3726/files/usr/ikuai/function/func_api.sh')],check=True)

subprocess.run([sys.executable,str(ROOT/'materials/tests/wg-client-endpoint-unit.py'),str(ROOT/'materials/firmware/port-3726/files/usr/ikuai/script/wg_client_endpoint.sh')],check=True)
subprocess.run([sys.executable,str(ROOT/'materials/tests/wg-export-backend-unit.py'),'--lua',a.lua],check=True)
