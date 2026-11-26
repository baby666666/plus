#!/usr/bin/env python3
"""Exercise actual client Endpoint helper with isolated network/DB fixtures.

Never contacts a public service, production router, or test VM. Only fixed
environment paths and curl are redirected; WAN selection, parsing, caching,
identity checks and lock control execute the shipped shell functions.
"""
from pathlib import Path
import json
import os
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import time

source = Path(sys.argv[1]).read_text()
assert source.startswith('#!/bin/bash /etc/ikcommon\nInclude lock.sh\n')
assert 'interface_get_name_to_cache_wan' not in source
assert 'interface_check_is_wanpppoe' not in source
source = source.split('\n', 2)[2].replace('/usr/bin/curl', 'mock_curl')
source = source.replace('/sys/class/net/', '$FIXTURE/sys/')
count = 0

MOCKS = r'''
sqlite3() {
 printf '%s\n' "$*" >> "$FIXTURE/sql.log"
 [ ! -e "$FIXTURE/sql.fail" ] || return 1
 if [[ "$*" == *'from wan_config'* ]];then
  [ ! -e "$FIXTURE/inventory.fail" ] || return 1
  local item
  while read -r item;do
   if [ -e "$FIXTURE/pppoe-$item" ];then printf '%s|%s_ad\n' "$item" "$item"
   else printf '%s|%s\n' "$item" "$item";fi
  done < "$FIXTURE/inventory"
  return 0
 fi
 cat "$FIXTURE/service"
}
ip() {
 printf '%s\n' "$*" >> "$FIXTURE/ip.log"
 case "$*" in
  '-4 route show table main default') cat "$FIXTURE/routes";;
  '-4 route get 1.1.1.1') cat "$FIXTURE/route1";;
  '-4 route get 8.8.8.8') cat "$FIXTURE/route2";;
  '-o -4 addr show dev '* ) cat "$FIXTURE/addr-$6" 2>/dev/null;;
  *) return 1;;
 esac
}
__wce_now() { cat "$FIXTURE/clock"; }
LockNonblock() {
 mkdir "$FIXTURE/lock-$1" 2>/dev/null || return 1
 printf 'lock %s\n' "$1" >> "$FIXTURE/locks.log"
}
unLock() {
 rmdir "$FIXTURE/lock-$1" || return 1
 printf 'unlock %s\n' "$1" >> "$FIXTURE/locks.log"
}
mock_curl() {
 local output='' arg value n delay
 printf '%s\n' "$*" >> "$FIXTURE/curl.log"
 n=$(wc -l < "$FIXTURE/curl.log" | tr -d ' ')
 while [ "$#" -gt 0 ];do
  arg="$1";shift
  if [ "$arg" = --output ];then output="$1";shift;fi
 done
 [ "$output" ] || return 97
 if [ -e "$FIXTURE/hook-$n" ];then bash "$FIXTURE/hook-$n" || return 98;fi
 if [ -f "$FIXTURE/delay" ];then delay=$(cat "$FIXTURE/delay");sleep "$delay";fi
 if [ -f "$FIXTURE/body-$n" ];then cat "$FIXTURE/body-$n" > "$output";else printf '%s\n' '8.8.4.4' > "$output";fi
 if [ -f "$FIXTURE/status-$n" ];then cat "$FIXTURE/status-$n";else printf '200';fi
 if [ -f "$FIXTURE/rc-$n" ];then return "$(cat "$FIXTURE/rc-$n")";fi
 return 0
}
'''


class Fixture:
    def __init__(self, root):
        self.root = root
        root.mkdir()
        self.put('service', 'auto|50001\n')
        self.put('inventory', 'wan1\nwan2\n')
        self.put('clock', '100')
        self.route('wan1')
        self.address('wan1', '10.1.0.2', 11)
        self.address('wan2', '192.168.2.2', 12)
        self.address('wan1_ad', '100.64.1.2', 13)
        self.script = root / 'runner.sh'
        self.script.write_text(source + '\n' + MOCKS + '\n"$@"\n')
        self.env = dict(os.environ, FIXTURE=str(root), IK_DIR_TMP=str(root / 'tmp'), IK_DB_CONFIG=str(root / 'db'))

    def put(self, name, text=''):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def address(self, dev, address, index):
        self.put('addr-' + dev, f'2: {dev} inet {address}/24 brd 10.1.0.255 scope global {dev}\n')
        self.put(f'sys/{dev}/ifindex', f'{index}\n')

    def route(self, dev):
        self.put('routes', f'default via 10.1.0.1 dev {dev} metric 10\n')
        self.put('route1', f'1.1.1.1 via 10.1.0.1 dev {dev} src 10.1.0.2\n')
        self.put('route2', f'8.8.8.8 via 10.1.0.1 dev {dev} src 10.1.0.2\n')

    def start(self, *args):
        return subprocess.Popen(['bash', str(self.script), *args], env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def raw(self, *args):
        p = self.start(*args)
        out, err = p.communicate(timeout=5)
        return p.returncode, out, err

    def get(self, name='wg1', force='0'):
        rc, out, err = self.raw('get', name, force)
        assert rc == 0, (rc, out, err)
        assert not err, err
        result = json.loads(out)
        assert set(result) == {'ip', 'source', 'wan', 'message', 'listen_port'}, result
        assert isinstance(result['listen_port'], int), result
        return result

    def calls(self):
        path = self.root / 'curl.log'
        return path.read_text().splitlines() if path.exists() else []

    def hook(self, text):
        self.put('hook-1', text)

    def no_cache(self):
        return not list((self.root / 'tmp').glob('wg-client-endpoint/*.cache'))

    def check_clean(self):
        assert not list(self.root.glob('lock-*')), 'lock leaked'
        assert not list((self.root / 'tmp').glob('wg-client-endpoint/probe.*')), 'response body leaked'


def check(result, ip=None, source=None, wan=None, port=50001):
    if ip is not None:
        assert result['ip'] == ip, result
    if source is not None:
        assert result['source'] == source, result
    if wan is not None:
        assert result['wan'] == wan, result
    assert result['listen_port'] == port, result


with tempfile.TemporaryDirectory(prefix='wg-client-endpoint-') as tmp:
    base = Path(tmp)

    def case(name):
        global count
        count += 1
        return Fixture(base / f'{count:03d}-{name}')

    f = case('public-success')
    check(f.get(), '8.8.4.4', 'public', 'wan1')
    assert len(f.calls()) == 1
    args = shlex.split(f.calls()[0])
    # The mock's human-readable log collapses empty strings; mandatory fixed
    # options are checked textually and executable arguments below remain fixed.
    for option in ['--proto =https', '--interface if!wan1', '--connect-timeout 1',
                   '--max-time 2', '--max-filesize 64', '--max-redirs 0', '--noproxy *', '--proxy ']:
        assert option in f.calls()[0], f.calls()[0]
    assert f.calls()[0].endswith('https://api.ipify.org/')
    assert '-k' not in args and '--location' not in args
    assert (f.root / 'tmp/wg-client-endpoint').stat().st_mode & 0o777 == 0o700
    assert (f.root / 'tmp/wg-client-endpoint/wan1.cache').stat().st_mode & 0o777 == 0o600
    f.check_clean()

    f = case('fixed-wan-not-default')
    f.put('service', 'wan2|55223\n')
    check(f.get(), source='public', wan='wan2', port=55223)
    assert '--interface if!wan2' in f.calls()[0]

    f = case('auto-not-inventory-first')
    f.route('wan2')
    check(f.get(), source='public', wan='wan2')
    assert '--interface if!wan2' in f.calls()[0]

    for bind in ['auto', 'wan1']:
        f = case('pppoe-' + bind)
        f.put('service', bind + '|50001\n')
        f.put('pppoe-wan1')
        f.route('wan1_ad')
        check(f.get(), source='public', wan='wan1')
        assert '--interface if!wan1_ad' in f.calls()[0]

    f = case('virtual-wan')
    f.put('inventory', 'wan1\nvwan1\nadsl1\n')
    f.address('vwan1', '172.16.4.3', 42)
    f.route('vwan1')
    check(f.get(), source='public', wan='vwan1')

    for device in ['wg2', 'pppwg2', 'tun0', 'eth1']:
        f = case('reject-nonwan-default-' + device)
        f.route(device)
        check(f.get(), '', 'unavailable', '')
        assert not f.calls()

    for routes in [
        'default via 10.0.0.1 dev wan1 metric 10\ndefault via 10.0.0.2 dev wan2 metric 10\n',
        'default metric 10\n nexthop via 10.0.0.1 dev wan1 weight 1\n nexthop via 10.0.0.2 dev wan2 weight 1\n',
        'default metric 10 nexthop via 10.0.0.1 dev wan1 weight 1 nexthop via 10.0.0.2 dev wan2 weight 1\n',
        'default metric 10 nexthop dev wan1 weight 1 nexthop dev wan2 weight 1 nexthop dev wan3 linkdown\n',
    ]:
        f = case('ambiguous-default')
        f.put('routes', routes)
        check(f.get(), '', 'unavailable', '')
        assert not f.calls()

    for routes in [
        'default dev wan1 metric 10\ndefault dev wan2 metric 20\n',
        'default dev wan1 metric 10\ndefault dev wan2 metric 5 linkdown\n',
        'default metric 10\n nexthop dev wan1 weight 1\n nexthop dev wan2 weight 1 linkdown\n',
        'default metric 10 nexthop dev wan1 weight 1 nexthop dev wan2 weight 1 linkdown\n',
    ]:
        f = case('backup-default')
        f.put('routes', routes)
        check(f.get(), source='public', wan='wan1')

    f = case('destination-specific-routing')
    f.put('route2', '8.8.8.8 dev wan2\n')
    check(f.get(), '', 'unavailable', '')
    assert not f.calls()

    f = case('both-lookups-overridden-by-policy')
    f.route('wan2')
    f.put('routes', 'default dev wan1 metric 10\n')
    check(f.get(), '', 'unavailable', '')
    assert not f.calls()

    f = case('policy-default-no-main')
    f.put('routes', '')
    check(f.get(), source='public', wan='wan1')

    f = case('no-default-lookup')
    f.put('route1', '')
    check(f.get(), '', 'unavailable', '')
    assert not f.calls()

    for bind in ['wan1,wan2', 'wg2', 'wan99', 'wan1;touch injected', "wan1' OR 1=1--"]:
        f = case('reject-binding')
        f.put('service', bind + '|50001\n')
        check(f.get(), '', 'unavailable', '')
        assert not f.calls()

    for name in ['wg1;touch injected', "wg1' OR 1=1--", 'wan1', 'wg', 'wg123456789']:
        f = case('reject-service-name')
        check(f.get(name), '', 'unavailable', '', port=0)
        assert not (f.root / 'sql.log').exists() and not f.calls()

    for port in ['0', '65536', '-1', 'abc', '1;echo x']:
        f = case('invalid-port')
        f.put('service', 'auto|' + port + '\n')
        check(f.get(), '', 'unavailable', '', port=0)
        assert not f.calls()

    f = case('port-decimal-leading-zero')
    f.put('service', 'auto|00008\n')
    check(f.get(), source='public', port=8)

    for value in ['', '0.0.0.0', '127.0.0.1', '169.254.1.1', '224.0.0.1', '255.255.255.255']:
        f = case('no-valid-live-address')
        f.put('addr-wan1', '' if not value else f'2: wan1 inet {value}/24 scope global wan1\n')
        check(f.get(), '', 'unavailable', 'wan1')
        assert not f.calls()

    f = case('skip-invalid-first-address')
    f.put('addr-wan1', '2: wan1 inet 127.0.0.1/24 scope global wan1\n2: wan1 inet 10.1.0.2/24 scope global wan1\n')
    check(f.get(), source='public', wan='wan1')

    f = case('missing-ifindex')
    (f.root / 'sys/wan1/ifindex').unlink()
    check(f.get(), '10.1.0.2', 'wan', 'wan1')
    assert not f.calls()

    for missing in ['sql-fail', 'service-missing']:
        f = case(missing)
        f.put('sql.fail' if missing == 'sql-fail' else 'service')
        check(f.get(), '', 'unavailable', '', port=0)
        assert not f.calls()

    f = case('inventory-query-failure')
    f.put('inventory.fail')
    check(f.get(), '', 'unavailable', '')
    assert not f.calls() and '读取 WAN 设置失败' in f.get()['message']

    f = case('inventory-real-sql-and-pppoe-mapping')
    db = sqlite3.connect(f.root / 'db')
    db.executescript('''
        create table wan_config(name text, bandif text, internet integer);
        create table wan_vlan(interface text, vlan_name text);
        insert into wan_config values
          ('wan1','eth0',0),('wan2','eth1',1),('wan3','eth2',2),
          ('wan4','',0),('wan5','eth4',10),('wan6','eth5',3),('wan7','eth6',4);
        insert into wan_vlan values ('wan6','vwan1'),('wan7','adsl1');
    ''')
    db.commit();db.close()
    # Run the helper's actual SQL with sqlite3's engine without requiring a
    # host sqlite3 CLI installation. No fabricated inventory result here.
    f.put('dbquery.py', '''import sqlite3,sys
args=sys.argv[1:]
while args and args[0].startswith('-'):args=args[2:]
db=sqlite3.connect(args[0],timeout=1)
for row in db.execute(args[1]):print('|'.join('' if v is None else str(v) for v in row))
''')
    override = '\nsqlite3() { ' + shlex.quote(sys.executable) + ' "$FIXTURE/dbquery.py" "$@"; }\n'
    f.script.write_text(source + '\n' + MOCKS + override + '\n"$@"\n')
    rc, out, err = f.raw('__wce_inventory')
    assert rc == 0 and not err, (rc, out, err)
    assert set(out.splitlines()) == {'wan1|wan1', 'wan2|wan2', 'wan3|wan3_ad', 'vwan1|vwan1', 'adsl1|adsl1'}, out

    f = case('second-public-service')
    f.put('rc-1', '28')
    check(f.get(), source='public', wan='wan1')
    assert len(f.calls()) == 2 and f.calls()[1].endswith('https://checkip.amazonaws.com/')
    f.check_clean()

    for address in ['10.1.0.2', '172.16.0.2', '192.168.1.2', '100.64.1.2', '8.8.4.4']:
        f = case('probe-failure-fallback')
        f.address('wan1', address, 11)
        f.put('rc-1', '28');f.put('rc-2', '28')
        check(f.get(), address, 'wan', 'wan1')
        assert len(f.calls()) == 2
        f.check_clean()

    for body in ['10.0.0.1', '100.64.1.2', '127.0.0.1', '169.254.1.1', '172.31.1.1',
                 '192.168.1.1', '198.18.0.1', '192.0.2.1', '198.51.100.1', '203.0.113.1',
                 '224.0.0.1', '01.2.3.4', '256.1.1.1', '1.2.3.4;echo secret',
                 '<html>8.8.4.4</html>', '8.8.4.4\n8.8.8.8', 'A'*65]:
        f = case('invalid-probe-body')
        f.put('body-1', body);f.put('body-2', body)
        check(f.get(), '10.1.0.2', 'wan', 'wan1')
        assert len(f.calls()) == 2
        f.check_clean()

    f = case('reject-http-redirect')
    f.put('status-1', '302');f.put('status-2', '302')
    check(f.get(), '10.1.0.2', 'wan', 'wan1')
    f = case('accept-crlf-public')
    f.put('body-1', '8.8.4.4\r\n')
    check(f.get(), '8.8.4.4', 'public', 'wan1')

    f = case('public-cache-fresh-port-expiry')
    check(f.get(), source='public')
    f.put('clock', '159');f.put('service', 'auto|54321\n')
    check(f.get(), source='public', port=54321)
    assert len(f.calls()) == 1
    f.put('clock', '160')
    check(f.get(), source='public', port=54321)
    assert len(f.calls()) == 2

    f = case('failed-cache-expiry')
    f.put('rc-1', '28');f.put('rc-2', '28')
    check(f.get(), source='wan')
    f.put('clock', '109');check(f.get(), source='wan')
    assert len(f.calls()) == 2
    f.put('clock', '110');check(f.get(), source='public')
    assert len(f.calls()) == 3

    f = case('force-rate-limit')
    check(f.get(), source='public')
    f.put('clock', '109');check(f.get(force='1'), source='public')
    assert len(f.calls()) == 1
    f.put('clock', '110');check(f.get(force='1'), source='public')
    assert len(f.calls()) == 2

    for what in ['address', 'ifindex', 'pppoe', 'clock-backward']:
        f = case('cache-invalidated-' + what)
        f.get()
        if what == 'address':f.address('wan1', '10.1.0.3', 11)
        if what == 'ifindex':f.put('sys/wan1/ifindex', '19\n')
        if what == 'pppoe':f.put('pppoe-wan1');f.route('wan1_ad')
        if what == 'clock-backward':f.put('clock', '99')
        check(f.get(), source='public')
        assert len(f.calls()) == 2

    for content in ['100\twan1\t11\t10.1.0.2\t10.0.0.1\tpublic\n',
                    '100\twan1\t11\t10.1.0.2\t8.8.8.8\twan\n',
                    '100\twan1\t11\t10.1.0.2\t8.8.8.8\tpublic\textra\n',
                    'NaN\twan1\t11\t10.1.0.2\t8.8.8.8\tpublic\n']:
        f = case('reject-bad-cache')
        f.put('tmp/wg-client-endpoint/wan1.cache', content)
        check(f.get(), '8.8.4.4', 'public')
        assert len(f.calls()) == 1

    race_cases = [
        ('binding', "printf 'wan2|50002\\n' > \"$FIXTURE/service\"", '192.168.2.2', 'wan', 'wan2', 50002),
        ('default-wan', "printf 'default dev wan2 metric 10\\n' > \"$FIXTURE/routes\";printf '1.1.1.1 dev wan2\\n' > \"$FIXTURE/route1\";printf '8.8.8.8 dev wan2\\n' > \"$FIXTURE/route2\"", '192.168.2.2', 'wan', 'wan2', 50001),
        ('address', "printf '2: wan1 inet 10.1.0.3/24 scope global wan1\\n' > \"$FIXTURE/addr-wan1\"", '10.1.0.3', 'wan', 'wan1', 50001),
        ('ifindex', "printf '19\\n' > \"$FIXTURE/sys/wan1/ifindex\"", '10.1.0.2', 'wan', 'wan1', 50001),
        ('port-only', "printf 'auto|55000\\n' > \"$FIXTURE/service\"", '8.8.4.4', 'public', 'wan1', 55000),
        ('disconnect', ": > \"$FIXTURE/addr-wan1\"", '', 'unavailable', 'wan1', 50001),
        ('service-deleted', ": > \"$FIXTURE/service\"", '', 'unavailable', '', 0),
        ('binding-vpn', "printf 'wg2|50001\\n' > \"$FIXTURE/service\"", '', 'unavailable', '', 50001),
        ('sql-unreadable', "touch \"$FIXTURE/sql.fail\"", '', 'unavailable', '', 0),
        ('inventory-unreadable', "touch \"$FIXTURE/inventory.fail\"", '', 'unavailable', '', 50001),
        ('pppoe', "touch \"$FIXTURE/pppoe-wan1\";printf '1.1.1.1 dev wan1_ad\\n' > \"$FIXTURE/route1\";printf '8.8.8.8 dev wan1_ad\\n' > \"$FIXTURE/route2\";printf 'default dev wan1_ad\\n' > \"$FIXTURE/routes\"", '100.64.1.2', 'wan', 'wan1', 50001),
    ]
    for name, hook, address, kind, wan, port in race_cases:
        f = case('during-probe-' + name)
        f.hook(hook)
        check(f.get(), address, kind, wan, port)
        assert len(f.calls()) == 1
        assert name == 'port-only' or f.no_cache(), 'stale identity was cached'
        f.check_clean()

    f = case('concurrent-one-probe')
    f.put('delay', '.25')
    p = f.start('get', 'wg1', '1')
    deadline = time.monotonic() + 2
    while not f.calls() and time.monotonic() < deadline:
        time.sleep(.005)
    assert f.calls(), 'first probe did not start'
    check(f.get(force='1'), '10.1.0.2', 'wan', 'wan1')
    out, err = p.communicate(timeout=3)
    assert p.returncode == 0 and not err, (out, err)
    check(json.loads(out), '8.8.4.4', 'public', 'wan1')
    assert len(f.calls()) == 1
    check(f.get(force='1'), '8.8.4.4', 'public', 'wan1')
    assert len(f.calls()) == 1
    f.check_clean()

    for address, valid in [('1.2.3.4', True), ('10.0.0.1', True), ('100.64.0.1', True),
                           ('172.31.0.1', True), ('192.168.0.1', True), ('0.1.2.3', False),
                           ('127.2.3.4', False), ('169.254.0.1', False), ('224.1.2.3', False),
                           ('240.1.2.3', False), ('1.2.3', False), ('1.2.3.256', False),
                           ('01.2.3.4', False), ('1.2.3.4\n5.6.7.8', False)]:
        f = case('fallback-address-validator')
        rc, out, err = f.raw('__wce_ipv4', address)
        assert (rc == 0) == valid and not out and not err, (address, rc, out, err)

print(f'PASS {count} client Endpoint discovery, WAN identity, bounded cache, concurrency and validation cases')
