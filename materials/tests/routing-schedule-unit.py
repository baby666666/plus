#!/usr/bin/env python3
"""Exercise the real Lua compiler and shell rule emitters in an isolated fixture.

Requires lupa==2.6 (Lua 5.1). No firewall/router commands are executed: nr_ipt
records its actual argv; ip/ik_cntl are inert stubs for selector guard checks.
Calendar-day/cross-midnight semantics are compared for every minute of a week.
"""
from pathlib import Path
import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from lupa.lua51 import LuaRuntime, lua_type

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / 'materials/firmware/port-3726/files'
SCRIPTS = FILES / 'usr/ikuai/script'
parser = argparse.ArgumentParser()
parser.add_argument('--compiler', type=Path, default=SCRIPTS / 'native_rules.lua')
options = parser.parse_args()
checked = 0


def check(value, message):
    global checked
    assert value, message
    checked += 1


def option(argv, name, default=None):
    return argv[argv.index(name) + 1] if name in argv else default


def active(argv, minute):
    if '--weekdays' not in argv:
        return True
    day, local = divmod(minute, 1440)
    if str(day + 1) not in option(argv, '--weekdays').split(','):
        return False
    def hm(value):
        h, m, _ = map(int, value.split(':'))
        return h * 60 + m
    first, last = hm(option(argv, '--timestart')), hm(option(argv, '--timestop'))
    return first <= local <= last if first <= last else local >= first or local <= last


def expected(week, times):
    result = set()
    for day in map(int, week):
        for window in times.split(','):
            first, last = window.split('-')
            start = int(first[:2]) * 60 + int(first[3:])
            end = int(last[:2]) * 60 + int(last[3:])
            result.update((day - 1) * 1440 + minute for minute in range(1440)
                          if (start <= minute <= end if start <= end else minute >= start or minute <= end))
    return result


with tempfile.TemporaryDirectory(prefix='routing-schedule-') as directory:
    temp = Path(directory)
    output = temp / 'output'
    output.mkdir()
    (output / 'settings.json').write_text('{}')
    appids = temp / 'appid.sh'
    appids.write_text("APPIDS['test-app']='2000001'\nAPPIDS['douyin-live']='4010374'\n")
    lua = LuaRuntime(unpack_returned_tuples=True)

    def to_lua(value):
        if isinstance(value, dict):
            return lua.table_from({key: to_lua(item) for key, item in value.items()})
        if isinstance(value, list):
            return lua.table_from([to_lua(item) for item in value])
        return value

    def from_lua(value):
        if lua_type(value) != 'table':
            return value
        items = dict(value.items())
        if items and set(items) == set(range(1, len(items) + 1)):
            return [from_lua(items[i]) for i in range(1, len(items) + 1)]
        return {key: from_lua(item) for key, item in items.items()}

    def popen(command):
        result = subprocess.check_output(command, shell=True, text=True)
        return lua.table_from({'read': lambda _self, mode: result.splitlines()[0] if mode == '*l' else result,
                               'close': lambda _self: True})

    lua.globals().json_encode = lambda value: json.dumps(from_lua(value), ensure_ascii=False)
    lua.globals().json_decode = lambda value: to_lua(json.loads(value))
    lua.globals().host_popen = popen
    lua.globals().script_root = str(SCRIPTS)
    lua.globals().appid_fixture = str(appids)
    lua.globals().arg = to_lua({0: 'unit-test'})
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
        os.exit=function(code) error('unexpected process exit: '..tostring(code)) end
    ''')
    if not shutil.which('sha256sum'):
        shim = temp / 'sha256sum'
        shim.write_text('#!/bin/sh\nexec shasum -a 256 "$@"\n')
        shim.chmod(0o755)
        os.environ['PATH'] = str(temp) + os.pathsep + os.environ['PATH']
    compiler = lua.eval('dofile')(str(options.compiler))
    common = {'id': 7, 'enabled': 'yes', 'interface': 'wan1', 'src_addr': '198.18.1.2/32',
              'nr_ingress': 'wg1', 'iface_band': 1, 'comment': '', 'week': '15', 'time': '08:00-09:00,18:00-19:00'}
    domain = {**common, 'domain': 'schedule.example', 'nr_group': 'manual', 'nr_dns': '192.0.2.53', 'nr_route': 'fixed'}
    port = {**common, 'type': 0, 'protocol': 'tcp', 'dst_addr': '192.0.2.1', 'dst_port': '443'}
    protocol = {**common, 'app_proto': 'test-app'}

    def compile_rows(**rows):
        snapshot = {'domain': [], 'port': [], 'protocol': [], 'ipgroup': [], 'macgroup': [], **rows}
        (output / 'snapshot.json').write_text(json.dumps(snapshot))
        compiler.compile(to_lua({'dir': str(output), 'root': str(FILES / 'usr/share/strict-routing')}))
        for script in ('apply.sh', 'delta.sh'):
            subprocess.run(['bash', '-n', str(output / script)], check=True)
        return (output / 'apply.sh').read_text()

    # Source all actual definitions; replace only the engine's absolute source.
    engine = temp / 'native_domain_engine.sh'
    engine.write_text((SCRIPTS / 'native_domain_engine.sh').read_text().replace(
        'source /usr/ikuai/script/native_shadow.sh', 'source ' + shlex.quote(str(SCRIPTS / 'native_shadow.sh'))))
    runtime = temp / 'native_runtime.sh'
    runtime.write_text((SCRIPTS / 'native_runtime.sh').read_text().replace('source /usr/ikuai/script/native_exit_health.sh', ':'))
    state = temp / 'state'
    state.mkdir()
    prelude = f'''
set -e -o pipefail
source {shlex.quote(str(runtime))}
source {shlex.quote(str(engine))}
NR={shlex.quote(str(state))}
: > "$NR/exits"
nr_ipt(){{ case " $* " in *" -D "*) return 1;; esac; printf '%s\\t' "$@";printf '\\n'; }}
# Deny unexpected low-level mutation commands instead of using the host tools.
iptables(){{ return 99; }}
ipset(){{ return 99; }}
ip(){{ [ "$1 $2" != 'rule del' ]; }}
ik_cntl(){{ :; }}
nr_begin(){{ : > "$NR/policies"; }}
nr_native_begin(){{ :; }}
nr_exit(){{ printf '%s %s %s 1\\n' "$1" "$2" "$2" >> "$NR/exits"; }}
nr_worker(){{ :; }}
nr_addr(){{ :; }}
nr_domain_set(){{ :; }}
nr_native_group(){{ :; }}
nr_ipv6(){{ :; }}
nr_finish(){{ :; }}
nr_native_finish(){{ :; }}
conntrack(){{ :; }}
'''

    def capture(script):
        # Keep every quoted newline in compiler arguments intact.
        script = re.sub(r'^(?:#!/bin/bash /etc/ikcommon|Include .*|source /usr/ikuai/script/.*)\n', '', script, flags=re.M)
        recorded = subprocess.check_output(['bash'], input=prelude + script, text=True, timeout=30)
        return [line.rstrip('\t').split('\t') for line in recorded.splitlines()]

    def dns_minutes():
        found = set()
        for line in (output / 'dns.rules').read_text().splitlines():
            if line.startswith('T '):
                _, a, b = line.split()
                found.update(range(int(a), int(b) + 1))
        return found

    def guards(commands, mark, schedule):
        for table, chain in (('filter', 'NR_FWD'), ('mangle', 'NR_EGRESS')):
            rows = [a for a in commands if option(a, '-A') == chain and option(a, '--mark') == str(mark)
                    and option(a, '-t', 'filter') == table]
            check(bool(rows) and option(rows[-1], '-j') == 'DROP', chain + ' has terminal guard')
            # Duplicated logical matches may repeat guard blocks, but each block
            # must allow every window before its first unconditional DROP.
            first_drop = next(i for i, a in enumerate(rows) if option(a, '-j') == 'DROP')
            returns = rows[:first_drop]
            for direction in ('ORIGINAL', 'REPLY'):
                allowed = [a for a in returns if (option(a, '--ctdir') == 'REPLY') == (direction == 'REPLY')]
                actual = {minute for minute in range(10080) if any(active(a, minute) for a in allowed)}
                check(actual == schedule, chain + ' allows all and only OR windows for ' + direction)
            check(all(option(a, '-o') == 'wan1' for a in returns if '--ctdir' not in a), chain + ' keeps fixed exit')

    for week, times in [('1234567', '00:00-23:59'), ('15', '08:00-09:00,18:00-19:00'),
                        ('17', '22:00-02:00,12:00-12:00'), ('2', '08:00-10:00,09:00-11:00'),
                        ('7', '23:59-00:00,05:15-05:15'), ('1234567', '00:00-23:59,12:00-13:00')]:
        row = {**domain, 'week': week, 'time': times}
        script = compile_rows(domain=[row])
        commands = capture(script)
        wanted = expected(week, times)
        check(dns_minutes() == wanted, 'DNS union: ' + week + ' ' + times)
        selects = [a for a in commands if option(a, '-A') == 'NR_CLASS' and option(a, '-j') == 'MARK']
        check(all(option(a, '--match-set') == 'nr_ds_7_src' and option(a, '-i') == 'pppwg1' for a in selects), 'source and ingress on every alternative')
        actual = {minute for minute in range(10080) if any(active(a, minute) for a in selects)}
        check(actual == wanted, 'kernel selection equals DNS union')
        scopes = [a for a in commands if option(a, '-A') == 'NR_DNS']
        for transport in ('tcp', 'udp'):
            check({m for m in range(10080) if any(active(a, m) for a in scopes if option(a, '-p') == transport)} == wanted,
                  'DNS admission schedule: ' + transport)
        guards(commands, option(selects[0], '--set-mark'), wanted)

    wanted = expected(common['week'], common['time'])
    for layer, row, extra in [('port', port, '--dports'), ('protocol', protocol, '--appid')]:
        script = compile_rows(**{layer: [row]})
        commands = capture(script)
        selects = [a for a in commands if option(a, '-A') == 'NR_LOWER' and option(a, '-j') == 'MARK']
        check(len(selects) == 2 and all(extra in a and (layer != 'port' or option(a, '-i') == 'pppwg1') and 'nr_' in ' '.join(a) for a in selects), layer + ' repeats full match per time')
        check({m for m in range(10080) if any(active(a, m) for a in selects)} == wanted, layer + ' OR selection')
        guards(commands, option(selects[0], '--set-mark'), wanted)

    for application, appid, state in [('test-app', '2000001', None), ('douyin-live', '4010374', 'NEW'),
                                       ('all', None, 'NEW')]:
        commands = capture(compile_rows(protocol=[{**protocol, 'app_proto': application}]))
        selects = [a for a in commands if option(a, '-A') == 'NR_LOWER' and option(a, '-j') == 'MARK']
        check(len(selects) == 2 and all(option(a, '--appid') == appid and option(a, '--ctstate') == state for a in selects),
              'existing P2P/non-P2P/all state semantics: ' + application)
        check({m for m in range(10080) if any(active(a, m) for a in selects)} == wanted, application + ' both windows')

    script = compile_rows(domain=[{**domain, 'nr_ingress': ''}])
    metadata = json.loads((output / 'native-engine.json').read_text())
    check(metadata['selectors'] == 0 and metadata['rules'][0]['fallback_reason'] == 'multi_time_windows', 'multi-window native ABI is never guessed')
    check('nr_native_group ' not in script, 'multi-window stays on per-client DNS/history evidence')
    compile_rows(domain=[{**domain, 'time': '08:00-09:00', 'nr_ingress': ''}])
    check(json.loads((output / 'native-engine.json').read_text())['selectors'] == 1, 'single-window native acceleration preserved')

    fallback = {**domain, 'nr_group': 'fallback', 'domain': ''}
    script = compile_rows(domain=[{**domain, 'nr_route': 'dns_only'}, {**fallback, 'id': 8, 'src_addr': ''}])
    commands = capture(script)
    skip = [a for a in commands if option(a, '-A') == 'NR_FALLBACK' and option(a, '-j') == 'RETURN']
    check(len(skip) == 4 and all('nr_d_7' in a or 'nr_h_7' in a for a in skip), 'DNS-only current/history bypass covers both windows')
    check({m for m in range(10080) if any(active(a, m) for a in skip)} == wanted, 'DNS-only bypass only during schedule')
    # Non-overlapping fallback windows are accepted; any overlapping OR member is rejected.
    compile_rows(domain=[fallback, {**fallback, 'id': 8, 'time': '10:00-11:00,20:00-21:00'}])
    checked += 1
    try:
        compile_rows(domain=[fallback, {**fallback, 'id': 8, 'time': '10:00-11:00,18:30-20:00'}])
    except Exception as error:
        check('时段重叠' in str(error), 'fallback overlap includes second time window')
    else:
        raise AssertionError('overlapping fallback accepted')

    # Real emitters: native guard, strict admission, conflict, and blackhole.
    windows = '\n'.join(' -m time --kerneltz --weekdays 1,5 --timestart ' + a + ':00 --timestop ' + b + ':59'
                        for a, b in (value.split('-') for value in common['time'].split(',')))
    expressions = '\n'.join(' -s 198.18.1.2/32' + line + ' -d 192.0.2.1' for line in windows.splitlines())
    q = shlex.quote
    commands = capture(f'nr_exit 1 wan1\nNR_NATIVE_KEEP=(0 0)\nnr_native_selector 1 1 {q(windows)} 7\n')
    guards(commands, 3011001, wanted)
    check(all('--match-set' in a for a in commands if option(a, '-j') == 'RETURN' and '--ctdir' not in a), 'native forward guard still requires client DNS evidence')
    commands = capture(f'nr_native_match {q(expressions)} 1 123\n')
    check(len(commands) == 6 and all('-s' in a and '-d' in a and '--timestart' in a for a in commands), 'native mark conversion repeats full predicate')
    commands = capture(f'nr_strict_guard {q(expressions)} 123\nnr_conflict {q(expressions)}\nnr_rule {q(expressions)} 123 0 {q(windows)}\n')
    strict = [a for a in commands if option(a, '-j') == 'NR_STRICT']
    check(len(strict) == 2 and {m for m in range(10080) if any(active(a, m) for a in strict)} == wanted, 'strict fallback admission repeats all OR windows')
    conflicts = [a for a in commands if '-I' in a]
    check(len(conflicts) == 6 and all('--timestart' in a and '-s' in a and '-d' in a for a in conflicts), 'priority conflict protects each complete alternative')
    blackhole = [a for a in commands if option(a, '-A') == 'NR_CLASS']
    check(len(blackhole) == 2 and all(option(a, '-j') == 'DROP' for a in blackhole), 'blackhole emits each window')
    # Compiler-generated cross-rule conflict must prefix and suffix every alternative.
    commands = capture(compile_rows(domain=[domain, {**domain, 'id': 8, 'interface': 'wg2'}]))
    conflicts = [a for a in commands if '-I' in a]
    check(len(conflicts) == 6 and all('--mark' in a and 'nr_h_7' in a and 'nr_ds_7_src' in a for a in conflicts), 'compiled priority conflicts retain full predicate')

    for times in ('', '08:00-09:00,', ',08:00-09:00', '08:00-09:00,,18:00-19:00',
                  '08:00-09:00,24:00-25:00', '08:60-09:00', '8:00-09:00'):
        try:
            compile_rows(port=[{**port, 'time': times}])
        except Exception as error:
            check('时间无效' in str(error), 'malformed schedule rejected: ' + times)
        else:
            raise AssertionError('malformed schedule accepted: ' + times)

print(json.dumps({'suite': 'routing schedules', 'checks': checked, 'status': 'passed'}))
