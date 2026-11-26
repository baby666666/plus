#!/usr/bin/env python3
"""Run the real snapshot SQL and Lua compiler against isolated SQLite fixtures.

Host dependency: lupa==2.6 (Lua 5.1). SQLite/JSON adapters replace only native
bindings, not the snapshot queries, compiler, domain library or runtime rules.
Never connects to a router or executes generated firewall commands.
"""
from pathlib import Path
import argparse
import ipaddress
import json
import os
import re
import shlex
import sqlite3
import subprocess
import tempfile
from lupa.lua51 import LuaRuntime, lua_type

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / 'materials/firmware/port-3726/files'
SCRIPTS = FILES / 'usr/ikuai/script'
parser = argparse.ArgumentParser()
parser.add_argument('--snapshot', type=Path, default=SCRIPTS / 'native_snapshot.lua')
options = parser.parse_args()
checked = 0

def check(value, message):
    global checked
    assert value, message
    checked += 1

with tempfile.TemporaryDirectory(prefix='routing-order-') as directory:
    temp = Path(directory)
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

    lua.globals().json_encode = lambda value: json.dumps(from_lua(value), ensure_ascii=False)
    lua.globals().json_decode = lambda value: to_lua(json.loads(value))
    connections = []

    def popen(command):
        output = subprocess.check_output(command, shell=True, text=True)
        return lua.table_from({'read': lambda _self, mode: output.splitlines()[0] if mode == '*l' else output,
                               'close': lambda _self: True})

    lua.globals().host_popen = popen

    def connect(path):
        db = sqlite3.connect(path, isolation_level=None)
        db.row_factory = sqlite3.Row
        connections.append(db)
        return lua.table_from({
            'busy_timeout': lambda _self, ms: db.execute('PRAGMA busy_timeout=' + str(ms)),
            'exec': lambda _self, query: (db.execute(query), 0)[1],
            'rows': lambda _self, query: to_lua([dict(row) for row in db.execute(query)]),
            'errmsg': lambda _self: 'SQLite operation failed',
            'close': lambda _self: db.close(),
        })

    lua.globals().sqlite_open = connect
    lua.globals().script_root = str(SCRIPTS)
    appids = temp / 'appid.sh'
    appids.write_text("APPIDS['test-app']='2000001'\n")
    lua.globals().appid_fixture = str(appids)
    lua.execute('''
        package.preload.cjson=function() return {encode=json_encode,decode=json_decode} end
        package.preload.lsqlite3=function()
            return {OK=0,open=function(path)
                local db=sqlite_open(path)
                db.nrows=function(self,query)
                    local rows=self:rows(query);local i=0
                    return function() i=i+1;return rows[i] end
                end
                return db
            end}
        end
        local original_dofile=dofile
        dofile=function(path)
            path=path:gsub('^/usr/ikuai/script/',script_root..'/')
            return original_dofile(path)
        end
        local original_open=io.open
        io.popen=host_popen
        io.open=function(path,mode)
            if path=='/tmp/iktmp/cache/appid.sh' then path=appid_fixture end
            return original_open(path,mode)
        end
        os.exit=function(code) error('unexpected process exit: '..tostring(code)) end
    ''')
    # macOS ships shasum rather than sha256sum; preserve the real library checks.
    if not __import__('shutil').which('sha256sum'):
        shim = temp / 'sha256sum'
        shim.write_text('#!/bin/sh\nexec shasum -a 256 "$@"\n')
        shim.chmod(0o755)
        os.environ['PATH'] = str(temp) + os.pathsep + os.environ['PATH']

    database = temp / 'config.db'
    common = {'id': 1, 'enabled': 'yes', 'interface': 'wan1', 'src_addr': '',
              'week': '1234567', 'time': '00:00-23:59', 'comment': ''}
    tables = {
        'stream_domain': {**common, 'domain': 'example.test', 'nr_group': 'manual',
                          'nr_dns': '192.0.2.53', 'nr_route': 'fixed'},
        'stream_ipport': {**common, 'type': 0, 'protocol': 'tcp', 'dst_port': '443'},
        'stream_layer7': {**common, 'app_proto': 'test-app'},
        'ipgroup': {'id': 1, 'group_name': '', 'addr_pool': ''},
        'macgroup': {'id': 1, 'group_name': '', 'addr_pool': ''},
    }
    db = sqlite3.connect(database)
    for table, fields in tables.items():
        db.execute('CREATE TABLE ' + table + '(' + ','.join(
            key + (' INTEGER PRIMARY KEY' if key == 'id' else ' INTEGER' if isinstance(value, int) else ' TEXT')
            for key, value in fields.items()) + ')')
    db.commit()

    def seed(table, specific_first=True, disabled=False):
        db.execute('DELETE FROM ' + table)
        # Insert high ID first deliberately: physical insertion order must not win.
        for priority in (40, 7):
            specific = (priority == 40) == specific_first
            row = {**tables[table], 'id': priority,
                   'interface': 'wan1' if specific else 'wg2',
                   'src_addr': '198.18.0.2/32' if specific else '',
                   'enabled': 'no' if disabled and specific else 'yes'}
            db.execute('INSERT INTO ' + table + '(' + ','.join(row) + ') VALUES(' +
                       ','.join('?' for _ in row) + ')', list(row.values()))
        db.commit()

    out = temp / 'output'
    out.mkdir()
    (out / 'settings.json').write_text('{}')
    snapshot = options.snapshot
    lua.globals().arg = to_lua({0: 'unit-test'})
    compiler = lua.eval('dofile')(str(SCRIPTS / 'native_rules.lua'))

    def compile_rules():
        lua.globals().arg = to_lua({1: str(database), 2: str(out / 'snapshot.json')})
        lua.execute(snapshot.read_text().split('\n', 1)[1])
        data = json.loads((out / 'snapshot.json').read_text())
        lua.globals().arg = to_lua({0: 'unit-test'})
        compiler.compile(to_lua({'dir': str(out), 'root': str(FILES / 'usr/share/strict-routing')}))
        return data, (out / 'apply.sh').read_text(), (out / 'dns.rules').read_text()

    def winner(script, source, layer):
        sets = {}
        exits = {}
        policies = {}
        lower = False
        for line in script.splitlines():
            args = shlex.split(line)
            if not args:
                continue
            if args[0] == 'nr_exit':
                exits[args[1]] = args[2]
            elif args[0] == 'nr_policy':
                policies[args[1]] = args[2]
            elif args[0] == 'nr_addr':
                sets[args[1]] = [ipaddress.ip_network(x) for x in args[2].split(',')]
            elif args[0] == 'nr_lower_begin':
                lower = True
            elif args[0] == 'nr_policy_rule' and lower:
                expr = args[1]
                if layer == 'protocol' and '--appid' not in expr:
                    continue
                if layer == 'port' and '--dports' not in expr:
                    continue
                scope = re.search(r'--match-set (nr_[ap]s_\d+_src) src', expr)
                if scope and not any(ipaddress.ip_address(source) in net for net in sets[scope[1]]):
                    continue
                return exits[policies[args[2]]]

    for table, layer in [('stream_layer7', 'protocol'), ('stream_ipport', 'port')]:
        for specific_first, disabled in [(True, False), (False, False), (True, True)]:
            seed(table, specific_first, disabled)
            data, script, dns = compile_rules()
            check([r['id'] for r in data[layer]] == [40, 7], layer + ' SQL order')
            check(winner(script, '198.18.0.2', layer) == ('wan1' if specific_first and not disabled else 'wg2'),
                  layer + ' first applicable row wins')
            check(winner(script, '198.18.0.3', layer) == 'wg2', layer + ' nonmatching source continues')
        db.execute('DELETE FROM ' + table)
        db.commit()

    seed('stream_domain')
    seed('stream_ipport')
    seed('stream_layer7')
    data, script, dns = compile_rules()
    check([r['id'] for r in data['domain']] == [40, 7], 'domain SQL order')
    check(re.findall(r'^R (\d+) ', dns, re.M) == ['40', '7'], 'DNS priority matches list')
    check(script.index('--match-set nr_d_40') < script.index('--match-set nr_d_7') <
          script.index('nr_lower_begin'), 'domain decisions precede lower layers')
    check(script.index('nr_ps_40_src') < script.index('nr_as_40_src'), 'port precedes protocol')

    # Exercise each actual list handler, including an obsolete descending request.
    for name in ['stream_domain', 'stream_ipport', 'stream_layer7', 'stream_updown']:
        source = (SCRIPTS / (name + '.sh')).read_text()
        function = re.search(r'^show\(\)\s*\n\{.*?^\}', source, re.M | re.S).group()
        harness = '''sql_auto_get_filter(){ echo 'where enabled="yes"'; }
sql_auto_get_order(){ echo 'order by interface desc'; }
sql_auto_get_limit(){ echo 'limit 20 offset 0'; }
Show(){ printf '%s' "$__where"; }
''' + function + '\nORDER_BY=interface ORDER=desc show\n'
        result = subprocess.check_output(['bash', '-c', harness], text=True)
        check(result == 'where enabled="yes" order by id desc limit 20 offset 0', name + ' stable paginated display')

    # The legacy chain writers must agree with the compiled chain after boot,
    # edits and re-enables. Exercise their actual sort operations on mixed IDs.
    queued = temp / 'native-queue'
    queued.write_text('7 older\n40 newer\n12 middle\n')
    for name in ['stream_ipport', 'stream_layer7', 'stream_updown']:
        source = (SCRIPTS / (name + '.sh')).read_text()
        sorts = re.findall(r'sort\s+-n(?:\s+-r)?\s+-k1\b', source)
        check(len(sorts) == (3 if name == 'stream_ipport' else 1), name + ' all native priority queues covered')
        for command in sorts:
            result = subprocess.check_output(shlex.split(command) + [str(queued)], text=True)
            check(result.splitlines() == ['40 newer', '12 middle', '7 older'], name + ' native queue priority')

    new_rule = {**tables['stream_layer7'], 'id': 61, 'interface': 'wg2'}
    db.execute('INSERT INTO stream_layer7(' + ','.join(new_rule) + ') VALUES(' +
               ','.join('?' for _ in new_rule) + ')', list(new_rule.values()))
    db.commit()
    data, script, dns = compile_rules()
    check([r['id'] for r in data['protocol']] == [61, 40, 7], 'newly added rule is first')
    check(winner(script, '198.18.0.2', 'protocol') == 'wg2', 'new rule matches ahead of existing rules')
    db.close()

print('PASS:', checked, 'routing ordering checks; real snapshot SQL, Lua compiler and list handlers')
