#!/usr/bin/env python3
"""Test request-local monitor query reuse with real shell and Lua/SQLite.

External inputs are adapted; filtering, paging, snapshot lifecycle and counting
run from the implementation. No cross-request raw cache is expected. GNU awk
parsing assertions are explicitly skipped when unavailable on the host.
"""
from pathlib import Path
import concurrent.futures
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = ROOT / 'materials/firmware/port-3726/files/usr/ikuai/script/monitor_lanip.sh'
LUA_ADAPTER = Path(__file__).with_name('monitor-lanip-unit.py')
SOURCE = SOURCE_PATH.read_text()
checked = 0
skipped = []


def check(value, description):
    global checked
    assert value, description
    checked += 1


with tempfile.TemporaryDirectory(prefix='monitor-query-reuse-') as directory:
    temp = Path(directory)
    runtime, binpath = temp / 'runtime', temp / 'bin'
    runtime.mkdir()
    binpath.mkdir()
    calls, host_stats = [temp / name for name in ('calls', 'host-stats')]
    lan, wg = temp / 'lan.json', temp / 'wg.json'
    calls.write_text('')
    host_stats.write_text('')
    lua = binpath / 'lua'
    lua.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' ' +
                   shlex.quote(str(LUA_ADAPTER)) + ' --lua-fixture "$@"\n')
    lua.chmod(0o755)
    source = temp / 'monitor.sh'
    source.write_text(SOURCE.replace('/proc/ikuai/stats/host_stats', str(host_stats))
                      .replace('/tmp/iktmp', str(runtime))
                      .replace('/usr/bin/lua', str(lua)))
    gawk = shutil.which('gawk')
    env = dict(os.environ, PATH=str(binpath) + os.pathsep + os.environ['PATH'],
               FIXTURE=str(temp), IK_DIR_TMP=str(runtime))
    dependencies = '''
Include(){ :; }
source "$FIXTURE/monitor.sh"
sql_auto_get_filter(){ printf '%s' "$FILTER_SQL"; }
sql_auto_get_order(){ printf '%s' "$ORDER_SQL"; }
sql_auto_get_limit(){ printf '%s' "$LIMIT_SQL"; }
check_varl(){ return 0; }
iktimerc(){
  printf 'LAN\\n' >> "$FIXTURE/calls"
  if [ "$LAN_PARTIAL_FAIL" = 1 ]; then printf '['; return 1; fi
  cat "$FIXTURE/lan.json"
  return 0
}
__wg_monitor_data(){
  printf 'WG\\n' >> "$FIXTURE/calls"
  [ "$WG_FAIL" = 1 ] && { printf '['; return 1; }
  cat "$FIXTURE/wg.json"
}
conntrack(){
  printf 'CT %s\\n' "$*" >> "$FIXTURE/calls"
  [ "$1" = -D ] && return 0
  [ "$CT_FAIL_DIRECTION" = "$2" ] && { printf 'tcp partial'; return 1; }
  local direction="$2" host="$3"
  cat "$FIXTURE/ct.$host.$direction"
}
json_append(){
  case "$2" in
    data:json) printf 'DATA:%s\\n' "$data";;
    total:int) printf 'TOTAL:%s\\n' "$total";;
    conn:json) printf 'CONN:%s\\n' "$conn";;
    conn_num:int) printf 'CONN_NUM:%s\\n' "$conn_num";;
    appid_conn:json) printf 'APPID_CONN:%s\\n' "$appid_conn";;
  esac
}
Show(){ local kind; for kind in ${TYPE//,/ }; do "__show_$kind" || return; done; }
'''
    # This adapter is used only to inspect the real request/counter lifecycle
    # on hosts without GNU awk. No detail-parser assertion uses its output.
    count_only_parser = '' if gawk else 'gawk(){ cat >/dev/null; }\n'

    def shell(program, extra_env=None, timeout=8):
        with subprocess.Popen(['bash', '-c', dependencies + count_only_parser + program],
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env={**env, **(extra_env or {})}, start_new_session=True) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                raise
            return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)

    def request(types='data,total', filter_sql='', order='', limit='', extra_env=None):
        result = shell('show\n', {'TYPE': types, 'FILTER_SQL': filter_sql,
                                 'ORDER_SQL': order, 'LIMIT_SQL': limit, **(extra_env or {})})
        fields = {}
        for line in result.stdout.splitlines():
            key, sep, value = line.partition(':')
            if sep and key in ('DATA', 'TOTAL', 'CONN', 'CONN_NUM', 'APPID_CONN'):
                fields[key] = json.loads(value)
        return result, fields

    def good_request(**kwargs):
        result, data = request(**kwargs)
        check(result.returncode == 0, result.stderr or 'monitor request failed')
        return data

    def collected():
        return [line for line in calls.read_text().splitlines() if line in ('LAN', 'WG')]

    def conn_calls():
        return [line[3:] for line in calls.read_text().splitlines() if line.startswith('CT ')]

    def inputs(tag='one'):
        lrows = [dict(id=1, ip_addr='192.168.1.2', upload=20, comment='LAN-' + tag,
                      native_metadata={'kept': True}),
                 dict(id=2, ip_addr='192.168.1.3', upload=5, comment='LAN-other')]
        wrows = [dict(id=3, ip_addr='198.18.1.2', upload=100, comment='WG-' + tag),
                 dict(id=4, ip_addr='198.18.1.3', upload=10, comment='WG-other')]
        lan.write_text(json.dumps(lrows))
        wg.write_text(json.dumps(wrows))
        return lrows, wrows

    # data/total share one fresh sample, but another HTTP request collects anew.
    lrows, wrows = inputs()
    values = good_request(order='ORDER BY upload DESC', limit='LIMIT 2 OFFSET 0')
    check(values == {'DATA': [wrows[0], lrows[0]], 'TOTAL': 4}, 'global merge/order/page retains the unfiltered total')
    check(collected() == ['LAN', 'WG'], 'data plus total collects LAN and WG once each')
    fresh_lan, fresh_wg = inputs('new')
    values = good_request(types='total,data', order='ORDER BY upload DESC', limit='LIMIT 2 OFFSET 2')
    check(values == {'TOTAL': 4, 'DATA': [fresh_wg[1], fresh_lan[1]]}, 'reversed TYPE shares one fresh page sample')
    check(collected() == ['LAN', 'WG'] * 2, 'the next request resamples immediately without a raw-cache TTL')
    values = good_request(filter_sql="WHERE ip_addr='198.18.1.2'")
    check(values == {'DATA': [fresh_wg[0]], 'TOTAL': 1}, 'a client filter cannot inherit earlier request results')
    values = good_request(filter_sql="WHERE comment LIKE 'LAN-%'", limit='LIMIT 1 OFFSET 1')
    check(values == {'DATA': [fresh_lan[1]], 'TOTAL': 2}, 'filtered total is independent of page limit')
    values = good_request(filter_sql="WHERE ip_addr='198.51.100.99'")
    check(values == {'DATA': [], 'TOTAL': 0}, 'empty filter leaves no stale rows')
    values = good_request()
    check(values == {'DATA': fresh_lan + fresh_wg, 'TOTAL': 4}, 'unfiltered response retains native metadata')
    check(not (runtime/'monitor-cache').exists(), 'monitor requests do not create a cross-request raw cache')

    # Every concurrent request owns its own sample and SQL result.
    calls.write_text('')
    queries=["WHERE ip_addr='198.18.1.2'", "WHERE ip_addr='192.168.1.2'", '', "WHERE id=999"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results=list(pool.map(lambda query:request(filter_sql=query),queries))
    check(all(result.returncode == 0 for result,data in results), 'four concurrent real shell requests succeed')
    check([data['TOTAL'] for result,data in results] == [1,1,4,0], 'concurrent filters/counts stay independent')
    check(collected().count('LAN') == 4 and collected().count('WG') == 4, 'each concurrent request performs one fresh collection')

    for failure, description in [({'LAN_PARTIAL_FAIL':'1'},'LAN collector failure'),({'WG_FAIL':'1'},'WG collector failure')]:
        result, values=request(extra_env=failure)
        check(result.returncode != 0 and not values, description+' returns no partial successful rows')
        check(not list(runtime.glob('monitor-hosts.*')), description+' removes its private snapshot')
    for invalid in ['[{"id":1}', '{"not":"an array"}', '']:
        lan.write_text(invalid)
        result, values=request()
        check(result.returncode != 0 and not values, 'invalid JSON/root cannot masquerade as an empty monitor list')
        check(not list(runtime.glob('monitor-hosts.*')), 'invalid JSON removes request scratch')
    inputs('recovered')
    values=good_request()
    check(values['DATA'][0]['comment']=='LAN-recovered', 'the next valid request recovers immediately after a collection error')

    calls.write_text('')
    result=shell('ip=198.18.1.2\ndel_conn\nwait\n')
    check(result.returncode == 0 and sorted(conn_calls())==['-D -r 198.18.1.2','-D -s 198.18.1.2'],
          'connection deletion keeps both asynchronous native directions')

    # Native conntrack is replaced only at its input boundary. The real
    # prepare/count path must scan each direction once, without protocol caps.
    def connection(proto, port, interface, ip='198.18.1.2', inbound=False):
        source, destination = ('203.0.113.10', ip) if inbound else (ip, '203.0.113.10')
        reply_source, reply_destination = destination, source
        state = 'ESTABLISHED ' if proto == 'tcp' else ''
        return (f'{proto} {6 if proto == "tcp" else 17} 100 {state}'
                f'src={source} dst={destination} sport={port} dport=443 packets=2 bytes=100 '
                f'src={reply_source} dst={reply_destination} sport=443 dport={port} packets=3 bytes=900 '
                f'mark=1426063617 appid=123 remote_if={interface}')

    ct_source = [connection('tcp', 1001, 'wg2'), connection('udp', 1002, 'wan1_ad'),
                 connection('tcp', 1003, 'wan1')]
    ct_reply = [connection('tcp', 1004, 'wg2', inbound=True)]
    (temp / 'ct.198.18.1.2.-s').write_text('\n'.join(ct_source) + '\n')
    (temp / 'ct.198.18.1.2.-r').write_text('\n'.join(ct_reply) + '\n')
    (temp / 'ct.198.18.1.3.-s').write_text(connection('udp', 2001, 'wg3', ip='198.18.1.3') + '\n')
    (temp / 'ct.198.18.1.3.-r').write_text('')
    (runtime / 'cache').mkdir(exist_ok=True)
    (runtime / 'cache/appid_en.txt').write_text('Douyin 123\n')
    for types in ('conn,conn_num', 'conn_num,conn', 'conn,conn_num,appid_conn'):
        calls.write_text('')
        values = good_request(types=types, extra_env={'ip': '198.18.1.2', 'proto': 'tcp',
                                                     'interface': 'wg2', 'maxnum': '1'})
        check(conn_calls() == ['-L -s 198.18.1.2', '-L -r 198.18.1.2'],
              types + ' shares exactly two complete direction scans')
        check(values['CONN_NUM'] == 4, types + ' total ignores protocol, egress and result limit')
    calls.write_text('')
    values = good_request(types='conn_num,conn', extra_env={'ip': '198.18.1.3', 'proto': 'udp',
                                                           'interface': 'all', 'maxnum': '0'})
    check(values['CONN_NUM'] == 1 and conn_calls() == ['-L -s 198.18.1.3', '-L -r 198.18.1.3'],
          'another client cannot inherit a previous request connection sample')
    host_stats.write_text('198.18.1.2 0 23 0 0\n')
    calls.write_text('')
    values = good_request(types='conn_num', extra_env={'ip': '198.18.1.2'})
    check(values['CONN_NUM'] == 23 and not conn_calls(), 'native positive count alone requires no conntrack scan')
    host_stats.write_text('')
    calls.write_text('')
    result, values = request(types='conn,conn_num', extra_env={'ip': '198.18.1.2', 'CT_FAIL_DIRECTION': '-r'})
    check(result.returncode != 0 and not values, 'failed direction scan cannot expose a partial successful detail/count')
    calls.write_text('')
    values = good_request(types='conn_num', extra_env={'ip': '198.18.1.2'})
    check(values['CONN_NUM'] == 4 and len(conn_calls()) == 2, 'request following a failed sample retries both directions')

    if gawk:
        values = good_request(types='conn,conn_num', extra_env={'ip': '198.18.1.2', 'proto': 'tcp',
                                                               'interface': 'wg2', 'maxnum': '1'})
        check(len(values['CONN']) == 1 and values['CONN'][0]['src_port'] == 1001 and values['CONN_NUM'] == 4,
              'real gawk applies protocol plus egress then caps only the matching rows')
        values = good_request(types='conn,conn_num', extra_env={'ip': '198.18.1.2', 'proto': 'udp',
                                                               'interface': 'wan1', 'maxnum': '1'})
        check(len(values['CONN']) == 1 and values['CONN'][0]['src_port'] == 1002 and values['CONN'][0]['interface'] == 'wan1',
              'real gawk retains PPPoE egress normalization with post-snapshot protocol filtering')
        values = good_request(types='conn,conn_num', extra_env={'ip': '198.18.1.2', 'proto': 'all',
                                                               'interface': 'all', 'maxnum': '0'})
        check(len(values['CONN']) == 4 and values['CONN_NUM'] == 4,
              'real gawk unfiltered detail and fallback count agree on the same raw sample')
        values = good_request(types='conn,conn_num', extra_env={'ip': '198.18.1.2', 'proto': 'udp',
                                                               'interface': 'wg2', 'maxnum': '1'})
        check(values['CONN'] == [] and values['CONN_NUM'] == 4,
              'real gawk empty detail filter does not erase an unfiltered connection count')
        appids = runtime / 'cache/appid_en.txt'
        for cache_state in ('missing', 'empty'):
            if cache_state == 'missing':
                appids.unlink()
            else:
                appids.write_text('')
            values = good_request(types='conn,conn_num,appid_conn',
                                  extra_env={'ip': '198.18.1.2', 'proto': 'all',
                                             'interface': 'all', 'maxnum': '0'})
            check(len(values['CONN']) == 4 and values['CONN_NUM'] == 4,
                  cache_state + ' application cache preserves connection rows and totals')
            groups = values['APPID_CONN']
            check(sum(int(row['conn']) for row in groups) == 4
                  and sum(row['total_up'] for row in groups) == 1200
                  and sum(row['total_down'] for row in groups) == 2800,
                  cache_state + ' application cache preserves grouped traffic without hanging')
        appids.write_text('Douyin 123\n')
        values = good_request(types='appid_conn', extra_env={'ip': '198.18.1.2'})
        check(values['APPID_CONN'] == [dict(conn='4', app_name='Douyin', total_up=1200, total_down=2800)],
              'application names return on the next request after the cache is restored')
    else:
        skipped.append('GNU awk detail-parser and application-cache assertions (gawk unavailable; native firmware validation required)')

    check(not list(runtime.glob('monitor-hosts.*')), 'request row-snapshot directories are cleaned after success and failure')
    check(not list(runtime.glob('monitor-conn.*')), 'connection snapshots are cleaned after normal and failed requests')

print(f'PASS: {checked} monitor query-reuse checks; real shell and inline Lua/SQLite')
for message in skipped:
    print('SKIP: ' + message)
