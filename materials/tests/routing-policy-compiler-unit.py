#!/usr/bin/env python3
"""Compile actual routing snapshots and verify selectable exit-policy semantics."""
from pathlib import Path
import json
import os
import shlex
import shutil
import subprocess
import tempfile
from lupa.lua51 import LuaRuntime, lua_type

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / 'materials/firmware/port-3726/files'
SCRIPTS = FILES / 'usr/ikuai/script'
checks = 0

def check(value, why):
    global checks
    assert value, why
    checks += 1

with tempfile.TemporaryDirectory(prefix='routing-policy-compiler-') as directory:
    temp = Path(directory)
    output = temp / 'out'
    output.mkdir()
    (output / 'settings.json').write_text('{}')
    appids = temp / 'appids.sh'
    appids.write_text("APPIDS['live']='4010374'\n")
    lua = LuaRuntime(unpack_returned_tuples=True)
    def encode(value):
        if lua_type(value) != 'table':
            return value
        items = dict(value.items())
        if items and set(items) == set(range(1, len(items)+1)):
            return [encode(items[i]) for i in range(1, len(items)+1)]
        return {key: encode(item) for key, item in items.items()}
    def decode(value):
        if isinstance(value, dict):
            return lua.table_from({key: decode(item) for key,item in value.items()})
        if isinstance(value, list):
            return lua.table_from([decode(item) for item in value])
        return value
    def popen(command):
        data = subprocess.check_output(command, shell=True, text=True)
        return lua.table_from({'read': lambda _self, mode: data.splitlines()[0] if mode == '*l' else data, 'close': lambda _self: True})
    lua.globals().json_encode = lambda value: json.dumps(encode(value), ensure_ascii=False)
    lua.globals().json_decode = lambda value: decode(json.loads(value))
    lua.globals().host_popen = popen
    lua.globals().script_root = str(SCRIPTS)
    lua.globals().appid_fixture = str(appids)
    lua.globals().arg = decode({0: 'unit-test'})
    lua.execute('''
package.preload.cjson=function() return {encode=json_encode,decode=json_decode} end
local original_dofile=dofile
dofile=function(path) return original_dofile(path:gsub('^/usr/ikuai/script/',script_root..'/')) end
local original_open=io.open
io.popen=host_popen
io.open=function(path,mode)
 if path=='/tmp/iktmp/cache/appid.sh' then path=appid_fixture end
 return original_open(path,mode)
end
os.exit=function(code) error('exit:'..tostring(code)) end
''')
    if not shutil.which('sha256sum'):
        shim = temp / 'sha256sum'
        shim.write_text('#!/bin/sh\nexec shasum -a 256 "$@"\n')
        shim.chmod(0o755)
        os.environ['PATH'] = str(temp) + os.pathsep + os.environ['PATH']
    compiler = lua.eval('dofile')(str(SCRIPTS / 'native_rules.lua'))
    common = {'id': 1, 'enabled': 'yes', 'interface': 'wg2,wan1', 'src_addr': '198.18.1.2/32', 'week': '1234567', 'time': '00:00-23:59'}
    domain = {**common, 'domain': 'policy.example', 'nr_group': 'manual', 'nr_route': 'fixed', 'nr_dns': '192.0.2.53'}
    port = {**common, 'type': 0, 'protocol': 'tcp', 'dst_port': '443'}
    protocol = {**common, 'app_proto': 'live'}
    def compile_rows(**rows):
        (output / 'snapshot.json').write_text(json.dumps({'domain': [], 'port': [], 'protocol': [], 'ipgroup': [], 'macgroup': [], **rows}))
        compiler.compile(decode({'dir': str(output), 'root': str(FILES / 'usr/share/strict-routing')}))
        script = (output / 'apply.sh').read_text()
        subprocess.run(['bash', '-n', str(output / 'apply.sh')], check=True)
        return script, json.loads((output / 'policy-plan.json').read_text())
    for kind, row in [('port', port), ('protocol', protocol)]:
        for mode in (0, 1, 2, 3, 4, 6):
            for band in (0, 1):
                script, plan = compile_rows(**{kind: [{**row, 'mode': mode, 'iface_band': band}]})
                policy = plan[0]
                check(policy['interfaces'] == ['wg2', 'wan1'] and policy['exits'] == [1, 2], kind + ' preserves candidate ordering')
                check(policy['mode'] == mode and policy['iface_band'] == band, kind + ' native mode and binding are compiled')
                check(policy['marks'][:2] == [policy['base']+1, policy['base']+2] and len(policy['marks']) == (3 if band == 0 else 2), 'fallback identity exists only for unbound strategy')
                if kind == 'protocol':
                    check('--appid 4010374' in script and '--ctstate NEW' in script, 'real 4M non-P2P recognition keeps NEW condition')
    for kind, row, default in [('domain', domain, 1), ('port', port, 0), ('protocol', protocol, 0)]:
        _, plan = compile_rows(**{kind: [row]})
        check(plan[0]['iface_band'] == default, kind + ' retains intended missing-field default')
        for invalid in ('garbage', 2, -1):
            try:
                compile_rows(**{kind: [{**row, 'iface_band': invalid}]})
            except Exception as error:
                check('线路绑定值无效' in str(error), 'nonempty invalid binding is rejected')
            else:
                raise AssertionError('invalid binding silently defaulted')
    for invalid in ('wg2,wg2', 'wg2,blackhole', 'pppwg2', 'ppphy2'):
        try:
            compile_rows(port=[{**port, 'interface': invalid}])
        except Exception:
            check(True, 'invalid candidate set is rejected')
        else:
            raise AssertionError('invalid candidate set accepted')
    for mode in (5, 7, 'garbage'):
        try:
            compile_rows(port=[{**port, 'mode': mode}])
        except Exception as error:
            check('出口负载模式无效' in str(error), 'unsupported mode rejected')
        else:
            raise AssertionError('invalid mode accepted')
    # Same resolver/physical candidates must never collapse distinct binding or
    # candidate ordering into a shared DNS owner / worker.
    script, plan = compile_rows(domain=[
        {**domain, 'id': 1, 'iface_band': 1},
        {**domain, 'id': 2, 'domain': 'second.example', 'iface_band': 0},
        {**domain, 'id': 3, 'domain': 'third.example', 'interface': 'wan1,wg2', 'iface_band': 0},
        {**domain, 'id': 4, 'domain': 'fourth.example', 'iface_band': 0},
    ])
    workers = [shlex.split(line) for line in script.splitlines() if line.startswith('nr_worker ')]
    check(len(workers) == 3, 'only identical complete strategy identity can share DNS worker')
    check([int(row[2]) for row in workers] == [1, 2, 3], 'workers reference policy identity instead of physical exit')
    check('nr_native_selector' not in script, 'multi-exit domain uses per-client DNS/history path')
    marks = (output / 'flow-marks').read_text().splitlines()
    check(len([row for row in marks if row.startswith('2 ')]) == 3, 'transition cleanup records all unbound candidates and fallback mark')
    script, _ = compile_rows(domain=[{**domain, 'interface': 'wan1', 'iface_band': 1}])
    check('nr_native_selector' in script, 'single bound domain retains native acceleration')
    for kind,row in [('domain',domain),('port',port),('protocol',protocol)]:
        reference=None
        for ingress in ['wg1','pppwg1','ppphy1']:
            script,_=compile_rows(**{kind:[{**row,'nr_ingress':ingress}]})
            if reference is None:reference=script
            check(script==reference,kind+' aliases compile to the identical ordered policy')
            for actual in ['wg1','pppwg1','ppphy1']:
                check(' -i '+actual in script,kind+' retains '+actual+' match')
            if kind=='domain':
                check('I wg1\n' in (output/'dns.rules').read_text(),'DNS receives logical ingress')
    fallback={**domain,'nr_group':'fallback','nr_ingress':'ppphy2'}
    try:compile_rows(domain=[fallback])
    except Exception as error:check('兜底出口不能与入接口相同' in str(error),'HY2 alias cannot select itself as fallback exit')
    else:raise AssertionError('HY2 alias self fallback accepted')
    try:compile_rows(domain=[{**fallback,'interface':'wan1','id':2,'nr_ingress':'ppphy1'},
                              {**fallback,'interface':'wan1','id':1,'nr_ingress':'pppwg1'}])
    except Exception as error:check('重叠' in str(error),'alias scopes cannot create overlapping fallbacks')
    else:raise AssertionError('overlapping alias fallbacks accepted')

print(json.dumps({'suite': 'routing policy compiler', 'checks': checks, 'status': 'passed'}))
