#!/usr/bin/env python3
"""Run the repository's portable tests; never contact a router or alter host networking.

Use a completed tools/rebuild.py workdir for Lua and the three original vendor
fixtures. Firmware shell functions run only inside their existing mock harnesses.
VM/browser/live traffic checks are separate and are not claimed by this report.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
M = ROOT / 'materials'
PY = sys.executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workdir', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True, help='New file outside the checkout')
    args = parser.parse_args()
    report = args.report.resolve()
    assert report != ROOT and ROOT not in report.parents and not report.exists()
    work = args.workdir.resolve()
    lua = work / 'toolbuild/lua-5.1.5/src/lua'
    base = work / 'decrypted-3.7.26-enterprise/rootfs.img'
    assert lua.is_file() and base.is_file(), 'Complete the independent rebuild first'
    # Resolve fixture paths from the clean base image, never from a previous AI workspace.
    from dissect.extfs import ExtFS
    results = []
    report.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='nr-host-') as directory, base.open('rb') as stream:
        temp = Path(directory)
        fs = ExtFS(stream)
        fixtures = {}
        for name, relative in {
            'validator': 'usr/ikuai/include/check_varl.sh',
            'importer': 'usr/ikuai/include/import_export.sh',
            'vendor': 'usr/ikuai/www/static/js/vendor.9963e3172df892e7087c.js.gz',
        }.items():
            target = temp / Path(relative).name
            target.write_bytes(fs.get('/' + relative).open().read())
            fixtures[name] = target
        commands = [[PY, str(ROOT / 'tools' / (name + '.py'))] for name in
                    ['check_materials', 'sync_wg', 'sync_ctpanel', 'sync_routing', 'sync_router_time', 'prune_web_assets']]
        commands += [[PY, str(ROOT / 'tools/run_wg_tests.py'), '--lua', str(lua)],
                     [PY, str(ROOT / 'tools/tests/test_wg_native_role.py')],
                     [PY, str(ROOT / 'tools/tests/test_wg_iface_change.py')],
                     [PY, str(ROOT / 'tools/tests/test_wg_pure_routing.py')],
                     [PY, str(ROOT / 'tools/tests/test_wg_pure_profiles.py')],
                     [PY, str(ROOT / 'tools/tests/test_wg_management.py')],
                     [PY, str(ROOT / 'tools/tests/test_wg_management_service.py')],
                     [PY, str(ROOT / 'tools/tests/test_wg_pure_admin.py')],
                     [PY, str(ROOT / 'tools/tests/test_wg_pure_management.py')],
                     [PY, str(ROOT / 'tools/tests/test_wg_site_client.py')],
                     [PY, str(ROOT / 'tools/tests/test_wg_hyr_native.py')],
                     [PY, str(ROOT / 'tools/tests/test_wg_hyr_ports.py')],
                     [PY, str(ROOT / 'tools/tests/test_wg_hy_ctl.py')]]
        python_tests = '''encrypted-dns failed-ingress-reconcile health-cycle-inventory
health-probe-routing monitor-lanip monitor-query-reuse monitor-wg-rates
native-dns-mac-scope native-exit-health native-ingress-state protocol-ingress-vendor reconcile-wg-global
routing-guard-dedup routing-order routing-policy-compiler routing-policy-marks
routing-policy-runtime routing-recovery-state routing-schedule routing-worker-restart
wg-probe-reset wg-transport-scan'''.split()
        commands += [[PY, str(M / 'tests' / (name + '-unit.py'))] for name in python_tests]
        commands += [[PY, str(M / 'tests/native-status-unit.py'), '--lua', str(lua)]]
        commands += [[PY, str(M / 'tests/routing-policy-schema-unit.py'),
                      '--native-validator', str(fixtures['validator']), '--lua', str(lua),
                      '--native-import', str(fixtures['importer'])]]
        commands += [[PY, str(M / 'tests/routing-exit-validation-unit.py'),
                      '--native-validator', str(fixtures['validator']), '--lua', str(lua)]]
        commands += [['node', str(M / 'tests' / (name + '-unit.js'))] for name in
                     ['routing-ui', 'routing-status-ui', 'encrypted-dns-ui']]
        commands += [['node', str(M / 'web-src/tests' / (name + '-unit.js'))] for name in
                     ['source-files', 'export', 'router-time', 'management-language']]
        commands += [[PY, str(M / 'web-src/tests/export-backend-unit.py')],
                     ['node', str(M / 'web-src/tests/router-time-vue-unit.js'), str(fixtures['vendor'])],
                     ['node', str(M / 'web-src/tests/wg-native-hy-unit.js'), str(fixtures['vendor'])]]
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        for command in commands:
            name = str(Path(command[1]).relative_to(ROOT))
            print('Running ' + name, flush=True)
            result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            print(result.stdout, end='', flush=True)
            results.append({'command': name, 'returncode': result.returncode, 'output': result.stdout})
            summary = {'passed': len(results) == len(commands) and all(x['returncode'] == 0 for x in results),
                       'completed_commands': len(results), 'planned_commands': len(commands),
                       'material_manifest_sha256': hashlib.sha256((M / 'SHA256SUMS').read_bytes()).hexdigest(),
                       'scope': 'Host tests only; VM boot, browser interaction and real traffic are separate.',
                       'results': results}
            report.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
            if result.returncode:
                raise SystemExit(result.returncode)
        print('PASS: all %d host test commands completed.' % len(commands), flush=True)


if __name__ == '__main__':
    main()
