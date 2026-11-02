#!/usr/bin/env python3
"""Exercise native S0/import parsing and actual routing RPC failure wrappers.

Requires the original check_varl.sh and local Lua 5.1. Its formatter, serialized
request parser and per-file loop are real. Closed-source format predicates use
controlled homogeneous WAN/VPN fixtures; the real firmware predicates still
require final VM acceptance. No router, firewall or host-process operations.
"""
from pathlib import Path
import argparse
import json
import os
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'materials/firmware/port-3726/files/usr/ikuai/script'
parser = argparse.ArgumentParser()
parser.add_argument('--native-validator', type=Path, required=True)
parser.add_argument('--lua', type=Path, required=True)
args = parser.parse_args()
checked = 0


def check(value, message):
    global checked
    assert value, message
    checked += 1


def function(source, name):
    start = re.search(r'^' + name + r'\(\)\s*\{?', source, re.M).start()
    end = start + re.search(r'^\}', source[start:], re.M).end()
    return source[start:end]


with tempfile.TemporaryDirectory(prefix='routing-exit-validation-') as directory:
    temp = Path(directory)
    module = temp / 'lua/iklua/string'
    module.mkdir(parents=True)
    (module / 'check.lua').write_text('''
local function names(v,kind)
 if not v or v=='' or v:match('^,') or v:match(',$') or v:match(',,') then return false end
 for item in v:gmatch('[^,]+') do
  if kind=='wan' then if not item:match('^wan%d+$') then return false end
  elseif not (item:match('^wg%d+$') or item:match('^pptp%d+$')) then return false end
 end
 return true
end
return {
 match=function(v,p) return v ~= nil and v:match(p) ~= nil end,
 ifnames_wan=function(v) return names(v,'wan') end,
 ifnames_vpn=function(v) return names(v,'vpn') end,
 week=function(v) return v=='1234567' end,
 timeranges=function(v) return v=='00:00-23:59' end,
 ports=function(v) return v ~= nil and v:match('^%d+$') ~= nil end,
 ip=function(v) return v=='192.0.2.1' end
}
''')
    native = args.native_validator.read_text()
    # The same two macOS Bash 3.2 portability adaptations as schema tests.
    native = re.sub(r'^\s*IlleStr\s*=.*$',
                    '\tIlleStr = string.char(91,39,34,96,36,59,124,38,92,93)', native, flags=re.M)
    native = native.replace(r'${__LOGIC//!/\~}', '${__LOGIC//!/~}')
    native = ('I18nload(){ :; }; Iecho(){ printf \'"native parameter error"\'; };\n'
              'lua(){ LUA_PATH='+shlex.quote(str(temp / 'lua/?.lua'))+' '+
              shlex.quote(str(args.lua.resolve()))+' "$@"; };\n'+native+'\n')
    interface = (SCRIPTS.parent / 'include/interface.sh').read_text()
    exit_check = '\n'.join(function(interface, name) for name in
                           ['interface_is_wg_ingress_helper', 'interface_check_routing_exit'])
    sources = {kind: (SCRIPTS / ('stream_'+kind+'.sh')).read_text()
               for kind in ['domain', 'ipport', 'layer7']}
    checkers = {}
    for kind, source in sources.items():
        names = ['nr_check_exit_interfaces', '__check_param']
        if kind == 'domain':
            names.insert(0, 'nr_import_exit_policy')
        checkers[kind] = '\n'.join(function(source, name) for name in names)
    common = {'enabled': 'no', 'week': '1234567', 'time': '00:00-23:59', 'iface_band': '0',
              'domain': 'unit.invalid', 'app_proto': 'all', 'type': '0', 'nexthop': '',
              'protocol': 'tcp', 'src_port': '', 'dst_port': '443'}

    def serialized(values):
        return ' '.join(key+'='+value for key, value in values.items())

    def validate(kind, exits, overrides=None, import_rows=None):
        values = {**common, 'interface': exits, **(overrides or {})}
        raw = serialized(values)
        setup = '\n'.join(key+'='+shlex.quote(value)+';' for key, value in values.items())
        setup += '\nnr_action=add; S0='+shlex.quote(raw)+';\n'
        file = None
        if import_rows is not None:
            file = temp / ('import-'+kind+'.txt')
            file.write_text('\n'.join(serialized({**common, **row}) for row in import_rows)+'\n')
            # The importer checks one callback with its own outer parameters;
            # actual row interfaces must come from the file, not this sentinel.
            setup += 'interface=; _______CHECK_VARL_IMPORT_FILE_______='+shlex.quote(str(file))+';\n'
        script = native+exit_check+'\n'+checkers[kind]+'\n'+setup
        script += '__check_param && printf "STATE:%s\\nS0:%s\\n" "$interface" "$S0"\n'
        result = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=15)
        check(not result.stderr, kind+' native validator has no Lua/shell error: '+result.stderr)
        return result, raw, file

    # First prove the original predicate failure is represented by this fixture.
    old = subprocess.run(['bash', '-c', native+'\nS0=interface=wg2,wan1; '
                          'check_varl \'interface ifnames_wan or ifnames_vpn\''],
                         capture_output=True, text=True)
    check(old.returncode != 0 and not old.stderr, 'homogeneous native predicate contract rejects mixed whole list')

    for kind in sources:
        for exits in ['wg2', 'wan1', 'wg2,wan1', 'wan1,wg2', 'wg2,wg3', 'wan1,wan2']:
            result, raw, _ = validate(kind, exits)
            check(result.returncode == 0 and result.stdout == 'STATE:'+exits+'\nS0:'+raw+'\n',
                  kind+' accepts ordered exits without changing interface or original S0: '+exits)
        for invalid in ['', ',wg2', 'wg2,', 'wg2,,wan1', 'lan1', 'notanexit', 'pppwg1',
                        'wg2,pppwg1', 'pppwg1,wan1', 'wg2,lan1', 'wg2,blackhole']:
            result, _, _ = validate(kind, invalid)
            check(result.returncode != 0, kind+' rejects invalid exit list: '+invalid)
        result, _, _ = validate(kind, 'wg2,wan1', {'enabled': 'bad'})
        check(result.returncode != 0, kind+' preserves unrelated native enabled validation')
        result, _, _ = validate(kind, 'wg2,wan1', {'week': 'bad'})
        check(result.returncode != 0, kind+' preserves unrelated native time/week validation')
        imported = [{'interface': 'wg2,wan1'}, {'interface': 'wan1,wg2'}]
        result, raw, file = validate(kind, '', import_rows=imported)
        check(result.returncode == 0 and result.stdout == 'STATE:\nS0:'+raw+'\n',
              kind+' validates mixed imported rows independently of outer interface')
        check([re.search(r'(?:^| )interface=([^ ]*)', line).group(1)
               for line in file.read_text().splitlines()] == ['wg2,wan1', 'wan1,wg2'],
              kind+' import preserves per-row interface order')
        for invalid in ['wan1,pppwg1', 'wg2,lan1', 'wg2,', '']:
            result, _, _ = validate(kind, '', import_rows=[imported[0], {'interface': invalid}])
            check(result.returncode != 0, kind+' rejects invalid interface in a later import row: '+invalid)

    result, _, _ = validate('ipport', 'blackhole')
    check(result.returncode == 0, 'port retains standalone blackhole')
    result, _, _ = validate('ipport', '', {'type': '1', 'nexthop': '192.0.2.1'})
    check(result.returncode == 0, 'port next-hop route does not require an exit')
    result, _, _ = validate('ipport', '', import_rows=[{'interface': 'wg2,wan1'},
                         {'type': '1', 'interface': '', 'nexthop': '192.0.2.1'}])
    check(result.returncode == 0, 'port imports preserve mixed exit and next-hop row semantics')

    # Run each actual RPC mutation wrapper with only DB/firewall/action effects
    # stubbed. Error input and stale successful logs must never enter ErrMsg.
    for kind, source in sources.items():
        for fault in ['validation', 'mutation', 'apply', 'success']:
            state = temp / (kind+'-'+fault)
            state.mkdir()
            (state / 'edit-result.log').write_text('OK compiled\nstale-log\n')
            raw_error = 'interface\nOK compiled\n"bad"\\value\tinput'
            wrapper = function(source, 'nr_native_change')
            wrapper = wrapper.replace('/tmp/iktmp/native-rules', str(state))
            wrapper = wrapper.replace('/usr/ikuai/script/native_rules.sh', 'stub_native')
            stubs = r'''
interface_check_routing_exit(){ return 0; }
sqlite3(){
 case "$2" in
  '.dump '*) echo 'fixture backup';;
  select*) if [ -f "$TEST_STATE/mutated" ];then echo changed;else echo before;fi;;
  *) cat >/dev/null;;
 esac
}
nr_original_add(){
 if [ "$FAULT" = validation ] || [ "$FAULT" = mutation ];then
  [ "$FAULT" != mutation ] || touch "$TEST_STATE/mutated"
  printf '%s\n' "$RAW_ERROR";return 1
 fi
 echo 123
}
nr_original_init(){ :; }
init(){ :; }
stub_native(){
 [ "$1" != apply ] || [ "$FAULT" != apply ] || { printf '%s\n' "$RAW_ERROR";return 1; }
}
'''
            env = dict(os.environ, TEST_STATE=str(state), RAW_ERROR=raw_error, FAULT=fault,
                       IK_DB_CONFIG=str(state / 'db'), interface='wg2,wan1', type='0')
            result = subprocess.run(['bash', '-c', stubs+'\n'+wrapper+'\nnr_native_change add'],
                                    env=env, capture_output=True, text=True, timeout=15)
            check(not result.stderr, kind+'/'+fault+' wrapper has no unexpected shell output: '+result.stderr)
            if fault == 'success':
                check(result.returncode == 0 and result.stdout == '123\n', kind+' keeps native add success response')
            else:
                check(result.returncode != 0, kind+'/'+fault+' still returns failure')
                text = result.stdout.rstrip('\n')
                check('\n' not in text and '\r' not in text and 'OK compiled' not in text
                      and 'interface' not in text and '\t' not in text,
                      kind+'/'+fault+' exposes only one fixed safe message')
                check(json.loads('{"ErrMsg":"'+text+'"}')['ErrMsg'] == text,
                      kind+'/'+fault+' remains valid inside the original unescaped JSON envelope')
                check(raw_error in (state / 'edit-error.log').read_text(),
                      kind+'/'+fault+' keeps diagnostics only in the local error log')

print(f'routing-exit-validation: {checked} checks passed')
