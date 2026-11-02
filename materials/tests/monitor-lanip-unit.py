#!/usr/bin/env python3
"""Exercise the real monitor shell functions and inline Lua with isolated data.

Requires lupa==2.6 (Lua 5.1), as routing-order-unit.py does. Only native command
inputs and the cjson/lsqlite3 bindings are adapted. No router, network, service,
firewall, or persistent configuration is touched. The conntrack parser also
runs when GNU awk is available; firmware VM validation covers that native path.
"""
from pathlib import Path
import json
import os
import re
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
from lupa.lua51 import LuaRuntime, lua_type

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'materials/firmware/port-3726/files/usr/ikuai/script/monitor_lanip.sh'
SOURCE = SCRIPT.read_text()


def lua_fixture(arguments, program):
    """Adapter implements the used lsqlite3 API over an actual SQLite database."""
    lua = LuaRuntime(unpack_returned_tuples=True)
    null_marker = object()

    def to_lua(value):
        if value is None:
            return null_marker
        if isinstance(value, dict):
            return lua.table_from({key: to_lua(item) for key, item in value.items()})
        if isinstance(value, list):
            return lua.table_from([to_lua(item) for item in value])
        return value

    def from_lua(value):
        if value is null_marker:
            return None
        if lua_type(value) != 'table':
            return value
        return {key: from_lua(item) for key, item in value.items()}

    def open_memory():
        db = sqlite3.connect(':memory:', isolation_level=None)

        def prepare(_self, query):
            parameters, current, cursor = {}, None, None

            def bind(_self, index, value):
                parameters[index] = value
                return 0

            def step(_self):
                nonlocal cursor, current
                if cursor is None:
                    cursor = db.execute(query, [parameters[i] for i in sorted(parameters)])
                current = cursor.fetchone()
                return 101 if current is None else 100

            def reset(_self):
                nonlocal cursor
                if cursor is not None:
                    cursor.close()
                cursor = None
                return 0

            return lua.table_from({'bind': bind, 'step': step, 'reset': reset,
                                   'finalize': reset, 'get_value': lambda _self, i: current[i]})

        return lua.table_from({'prepare': prepare,
                               'exec': lambda _self, query: (db.execute(query), 0)[1],
                               'errmsg': lambda _self: 'SQLite operation failed',
                               'close': lambda _self: db.close()})

    lua.globals().json_encode = lambda value: json.dumps(from_lua(value), ensure_ascii=False)
    lua.globals().json_decode = lambda value: to_lua(json.loads(value))
    lua.globals().json_null = null_marker
    lua.globals().sqlite_open_memory = open_memory
    lua.globals().arg = to_lua(dict(enumerate(arguments, 1)))
    lua.execute('''
      package.preload.cjson=function() return {encode=json_encode,decode=json_decode,null=json_null} end
      package.preload.lsqlite3=function()
        return {OK=0,ROW=100,DONE=101,open_memory=sqlite_open_memory}
      end
    ''')
    lua.execute(program)


if len(sys.argv) > 1 and sys.argv[1] == '--lua-fixture':
    # The shell invokes this wrapper in place of /usr/bin/lua, preserving stdin
    # and positional arguments, including the interpreter's "-" argument.
    lua_fixture(sys.argv[3:], sys.stdin.read())
    sys.exit(0)


def function(name):
    return re.search(r'^' + re.escape(name) + r'\(\)\s*\{.*?^\}', SOURCE, re.M | re.S).group()


checked = 0


def check(value, message):
    global checked
    assert value, message
    checked += 1


with tempfile.TemporaryDirectory(prefix='monitor-lanip-') as directory:
    temp = Path(directory)
    runtime = temp / 'iktmp'
    runtime.mkdir()
    stats = temp / 'host_stats'
    peers = temp / 'peers'
    conntrack = temp / 'conntrack-data'
    calls = temp / 'calls'
    transfer = temp / 'transfer'
    wg = temp / 'wg'
    wg.write_text('#!/bin/sh\ncase "$3" in transfer) cat ' + shlex.quote(str(transfer)) + ';; esac\n')
    wg.chmod(0o755)

    def shell(program, timeout=8):
        program = program.replace('/tmp/iktmp', str(runtime)).replace('/proc/ikuai/stats/host_stats', str(stats))
        with subprocess.Popen(['bash', '-c', program], text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, start_new_session=True) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                raise
            return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)

    dependencies = f'''
sqlite3(){{ cat {shlex.quote(str(peers))}; }}
__wg_bin(){{ echo {shlex.quote(str(wg))}; }}
conntrack(){{ printf '%s\\n' "$*" >> {shlex.quote(str(calls))}; cat {shlex.quote(str(conntrack))}; }}
'''
    peers.write_text('1|wg1|pub1|198.18.1.2/32|phone\n2|wg1|pub2|198.18.1.3/32|computer\n')
    stats.write_text('198.18.1.2 0 7 10 90\n198.18.1.3 0 4 20 80\n')
    transfer.write_text('wg1\tpub1\t100\t900\nwg1\tpub2\t200\t800\n')
    conntrack.write_text('')

    def wg_rows():
        result = shell(dependencies + function('__wg_monitor_sample') + '\n' + function('__wg_monitor_data') + '\n__wg_monitor_data\n')
        check(result.returncode == 0, result.stderr)
        return json.loads(result.stdout)

    rows = wg_rows()
    check(rows[0]['total_up'] == 100 and rows[0]['total_down'] == 900, 'WG RX is client upload; TX is download')
    check(rows[0]['upload'] == 10 and rows[0]['download'] == 90, 'existing host rate direction is preserved')
    check([r['connect_num'] for r in rows] == [7, 4] and not calls.exists(), 'positive host counters avoid conntrack entirely')
    transfer.write_text('pub1\t101\t901\npub2\t201\t801\n')
    rows = wg_rows()
    check(rows[1]['total_up'] == 201 and rows[1]['total_down'] == 801, 'three-column transfer compatibility')

    # Missing/zero counters share one table scan. The reverse tuple counts
    # inbound sessions too, while a session matching both tuples counts once.
    stats.write_text('198.18.1.2 0 0 10 90\n')
    conntrack.write_text('''tcp 6 100 ESTABLISHED src=198.18.1.2 dst=203.0.113.1 src=203.0.113.1 dst=198.18.1.2
udp 17 100 src=198.18.1.3 dst=203.0.113.1 src=203.0.113.1 dst=198.18.1.3
icmp 1 100 src=203.0.113.1 dst=192.0.2.1 src=198.18.1.2 dst=203.0.113.1
gre 47 100 src=198.18.1.2 dst=192.0.2.1 src=198.18.1.2 dst=192.0.2.1
sctp 132 100 src=198.18.1.3 dst=192.0.2.1 src=192.0.2.1 dst=198.18.1.3
''')
    rows = wg_rows()
    check([r['connect_num'] for r in rows] == [3, 1], 'batch counts supported protocols, both tuple directions, no double count')
    check(calls.read_text().splitlines() == ['-L'], 'all missing peers share exactly one conntrack dump')
    check(not list((runtime / 'wireguard').glob('monitor_*')), 'WG request snapshots are removed')
    calls.unlink()
    stats.write_text('198.18.1.2 0 8 10 90\n')
    rows = wg_rows()
    check([r['connect_num'] for r in rows] == [8, 1], 'native counters take precedence over fallback')
    check(calls.read_text().splitlines() == ['-L'], 'only one fallback scan for partially populated native stats')
    peers.write_text('1|wg1|pub1|198.18.1.2/32|phone "test" \\path\tlabel\n')
    rows = wg_rows()
    check(rows[0]['comment'] == 'phone "test" \\path\tlabel', 'WG JSON preserves quotes, backslashes and tabs')
    peers.write_text('1|wg1|pub1|198.18.1.2/32|large-counter\n')
    transfer.write_text('wg1\tpub1\t8589934593\t17179869186\n')
    stats.write_text('198.18.1.2 0 7 4294967300 4294967400\n')
    rows = wg_rows()
    check(rows[0]['ip_addr_int'] == 3323068674 and rows[0]['total_up'] == 8589934593 and rows[0]['total_down'] == 17179869186
          and rows[0]['upload'] == 4294967300 and rows[0]['download'] == 4294967400,
          'high IPv4 and byte/rate counters survive signed 32-bit formatting boundaries')
    formatter = function('__wg_monitor_data')
    check(not re.search(r'printf "\{.*%d', formatter), 'firmware awk JSON formatter avoids its signed 32-bit %d conversion')
    peers.write_text('')
    check(wg_rows() == [], 'no enabled WG peers yields an empty array')

    lan = temp / 'lan.json'
    wgs = temp / 'wg.json'
    snapshot_calls = temp / 'snapshot-calls'
    wrapper = temp / 'lua'
    wrapper.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' ' + shlex.quote(str(Path(__file__).resolve())) + ' --lua-fixture "$@"\n')
    wrapper.chmod(0o755)
    show_functions = '\n'.join(function(name) for name in ['show', '__show_total', '__show_data', '__monitor_prepare_rows'])
    show_functions = show_functions.replace('/usr/bin/lua', str(wrapper))
    lan_rows = [dict(id=11, ip_addr='192.168.1.10', ip_addr_int=3232235786, upload=30, comment='LAN "quoted" \\path', native_extra='kept'),
                dict(id=12, ip_addr='192.168.1.11', ip_addr_int=3232235787, upload=5, comment='other LAN')]
    wg_list = [dict(id=1, ip_addr='198.18.1.2', ip_addr_int=3323068674, upload=90, comment='phone'),
               dict(id=2, ip_addr='198.18.1.3', ip_addr_int=3323068675, upload=10, comment='computer')]
    lan.write_text(json.dumps(lan_rows))
    wgs.write_text(json.dumps(wg_list))

    def monitor(filter_sql='', order='', limit='', types='data,total'):
        # Every request samples fresh inputs; request-local reuse has a separate suite.
        if snapshot_calls.exists():
            snapshot_calls.unlink()
        harness = f'''
IK_DIR_TMP={shlex.quote(str(runtime))}
sql_auto_get_filter(){{ printf '%s' {shlex.quote(filter_sql)}; }}
sql_auto_get_order(){{ printf '%s' {shlex.quote(order)}; }}
sql_auto_get_limit(){{ printf '%s' {shlex.quote(limit)}; }}
iktimerc(){{ echo LAN >> {shlex.quote(str(snapshot_calls))}; cat {shlex.quote(str(lan))}; }}
__wg_monitor_data(){{ echo WG >> {shlex.quote(str(snapshot_calls))}; cat {shlex.quote(str(wgs))}; }}
json_append(){{ case "$2" in total:int) printf 'TOTAL:%s\\n' "$total";; data:json) printf 'DATA:%s\\n' "$data";; esac; }}
Show(){{ local kind; for kind in ${{TYPE//,/ }}; do "__show_$kind" || return; done; }}
''' + show_functions + '\nTYPE=' + shlex.quote(types) + ' show\n'
        result = shell(harness)
        parsed = {line.split(':', 1)[0]: json.loads(line.split(':', 1)[1]) for line in result.stdout.splitlines() if ':' in line}
        return result, parsed

    result, data = monitor("WHERE ip_addr='192.168.1.10'", limit='LIMIT 1 OFFSET 0')
    check(result.returncode == 0, result.stderr)
    check(data == {'DATA': [lan_rows[0]], 'TOTAL': 1}, 'LAN filter excludes WG and preserves extra native fields')
    check(snapshot_calls.read_text().splitlines() == ['LAN', 'WG'], 'data and total use one snapshot')
    result, data = monitor("WHERE ip_addr='198.18.1.2'", types='total,data')
    check(data == {'TOTAL': 1, 'DATA': [wg_list[0]]}, 'WG search works with total-first calls')
    result, data = monitor(order='ORDER BY upload DESC', limit='LIMIT 2 OFFSET 0')
    check([r['ip_addr'] for r in data['DATA']] == ['198.18.1.2', '192.168.1.10'] and data['TOTAL'] == 4,
          'numeric sort and first page are global across LAN and WG')
    result, data = monitor(order='ORDER BY upload DESC', limit='LIMIT 2 OFFSET 2')
    check([r['ip_addr'] for r in data['DATA']] == ['198.18.1.3', '192.168.1.11'] and data['TOTAL'] == 4,
          'second page neither repeats WG nor exceeds page size')
    result, data = monitor("WHERE comment LIKE '%phone%'", limit='LIMIT 1 OFFSET 1')
    check(data == {'DATA': [], 'TOTAL': 1}, 'total counts filtered rows before pagination')
    result, data = monitor("WHERE ip_addr='192.0.2.99'")
    check(data == {'DATA': [], 'TOTAL': 0}, 'no match has empty data and zero total')
    check(not list(runtime.glob('monitor-hosts.*')), 'merged snapshots are removed')
    lan.write_text('[]'); wgs.write_text('[]')
    result, data = monitor("WHERE ip_addr LIKE '10.%'", order='ORDER BY total_down DESC')
    check(result.returncode == 0 and data == {'DATA': [], 'TOTAL': 0}, 'empty snapshots support standard filters and order')
    null_rows = [dict(id=1, comment=None, auth_type=None), dict(id=2, comment='', auth_type=0), dict(id=3)]
    lan.write_text(json.dumps(null_rows))
    result, data = monitor("WHERE auth_type=0 AND comment=''")
    check(result.returncode == 0 and data == {'DATA': null_rows[1:], 'TOTAL': 2},
          'explicit JSON null stays SQL NULL; missing fields retain compatibility defaults')
    wgs.write_text('invalid json')
    result, data = monitor()
    check(result.returncode != 0 and not data and not list(runtime.glob('monitor-hosts.*')),
          'malformed snapshot fails the request and is cleaned up')

    # The actual shell handler must never invoke legacy -m or prefilter -k.
    # The actual gawk parser is exercised too wherever GNU awk is installed.
    calls.unlink()
    conntrack.write_text('')
    gawk = shutil.which('gawk')
    parser_stub = '' if gawk else 'gawk(){ cat >/dev/null; }\n'
    conn_dependencies = f'''
check_varl(){{ return 0; }}
json_append(){{ printf '%s' "$conn"; }}
iproute_get_markid(){{ echo ERROR >&2; return 1; }}
conntrack(){{ printf '%s\\n' "$*" >> {shlex.quote(str(calls))}; if [ "$2" = -s ];then cat {shlex.quote(str(conntrack))};fi; }}
'''
    conn_function = function('__monitor_prepare_conn') + '\n' + function('__show_conn')
    result = shell(conn_dependencies + parser_stub + conn_function + '\nip=198.18.1.2 interface=wan1 proto=tcp maxnum=1 __show_conn\n')
    check(result.returncode == 0 and calls.read_text().splitlines() == ['-L -s 198.18.1.2', '-L -r 198.18.1.2'],
          'WAN filter does not prefilter native routing marks or truncate before actual egress filter')
    check(json.loads(result.stdout) == [], 'missing application cache permits an empty connection result')
    result = shell(conn_dependencies + parser_stub + conn_function + '\nip=198.18.1.2 interface=wan1 maxnum=bad __show_conn\n')
    check(result.returncode != 0, 'invalid connection limit is rejected')
    if gawk:
        (runtime / 'cache').mkdir()
        (runtime / 'cache/appid_en.txt').write_text('Douyin 123\n')
        lines = []
        for iface, mark, port in [('wg2', 1426063617, 1001), ('wan1_ad', 1426063873, 1002), ('wan1', 1426064129, 1003)]:
            lines.append(f'tcp 6 100 ESTABLISHED src=198.18.1.2 dst=203.0.113.1 sport={port} dport=443 packets=2 bytes=100 src=203.0.113.1 dst=192.0.2.1 sport=443 dport={port} packets=3 bytes=900 mark={mark} appid=123 remote_if={iface}')
        conntrack.write_text('\n'.join(lines) + '\n')
        result = shell(conn_dependencies + conn_function + '\nip=198.18.1.2 interface=wan1 proto=tcp maxnum=1 __show_conn\n')
        detail = json.loads(result.stdout)
        check(len(detail) == 1 and detail[0]['src_port'] == 1002 and detail[0]['interface'] == 'wan1',
              'actual egress filtering and wan_ad normalization precede result cap')

print(f'PASS: {checked} monitor checks; real shell functions and inline Lua/SQLite query')
if not gawk:
    print('NOTE: GNU awk unavailable locally; native connection parser requires firmware VM validation.')
