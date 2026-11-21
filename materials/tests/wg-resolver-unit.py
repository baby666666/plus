#!/usr/bin/env python3
"""Run real resolver shell functions against disposable SQLite/command mocks.

No real network, WireGuard device, router, or key material is used. The lock
mock uses an atomic directory. DNS must run without that lock; a queued apply
must read the post-mutation database and discard answers for changed peers.
"""
from pathlib import Path
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time


SOURCE = Path(sys.argv[1]).read_text()


def extract(name):
    match = re.search(r"^" + re.escape(name) + r"\(\)\s*\{.*?^\}", SOURCE, re.M | re.S)
    assert match, "missing shell function: " + name
    return match.group()


RESOLVER = "\n".join(extract(name) for name in (
    "__wg_endpoint_identity", "__wg_endpoint_socket",
    "__wg_resolve_flush_locked", "resolve_flush",
))

MOCK_DRIVER = r'''
from pathlib import Path
import json, os, sqlite3, sys, time
root = Path(os.environ['MOCK_DIR'])
mode, args = sys.argv[1], sys.argv[2:]
def event(kind, *values):
    with (root/'events').open('a') as f:
        f.write(json.dumps([kind, *values])+'\n')
if mode == 'lock':
    assert args == ['wireguard_address', 'excl', '20'], args
    if os.environ.get('LOCK_FAIL') == '1':
        event('lock_failed'); sys.exit(1)
    lock = root/'lock-wireguard_address'
    deadline = time.monotonic()+5
    waiting = False
    while True:
        try:
            lock.mkdir(); break
        except FileExistsError:
            if not waiting: event('lock_wait'); waiting = True
            if time.monotonic() > deadline: sys.exit(2)
            time.sleep(.01)
    event('lock_acquired')
elif mode == 'unlock':
    assert args == ['wireguard_address'], args
    (root/'lock-wireguard_address').rmdir()
    event('lock_released')
elif mode in ('sql', 'sqlite'):
    db, query = args[:2]
    phase = 'recheck' if 'where p.id=' in query else 'snapshot'
    event('sql', phase)
    if os.environ.get('SQL_FAIL') == '1': sys.exit(1)
    if phase == 'recheck' and os.environ.get('SQL_RECHECK_FAIL') == '1': sys.exit(1)
    with sqlite3.connect(db) as con:
        cursor = con.execute(query)
        columns = [column[0] for column in cursor.description]
        for row in cursor.fetchall():
            values = ['' if value is None else str(value) for value in row]
            if mode == 'sqlite': print('|'.join(values))
            else: print(' '.join(name+'='+value for name,value in zip(columns,values)))
elif mode == 'dns':
    event('dns', args[0])
    if args[0] == 'a.example.invalid' and (root/'hold-dns').exists():
        event('dns_wait')
        deadline = time.monotonic()+5
        while (root/'hold-dns').exists():
            if time.monotonic() > deadline: sys.exit(2)
            time.sleep(.01)
    result = json.loads((root/'dns.json').read_text()).get(args[0])
    if result is None: sys.exit(1)
    print(result)
elif mode == 'wg':
    event('wg', *args)
    state = json.loads((root/'runtime.json').read_text())
    if args[0] == 'show':
        if os.environ.get('SHOW_FAIL') == '1': sys.exit(1)
        iface = args[1]
        if iface not in state: sys.exit(1)
        if args[2] == 'peers': print('\n'.join(state[iface]))
        elif args[2] == 'endpoints':
            print('\n'.join(k+'\t'+v for k,v in state[iface].items()))
        else: raise AssertionError('unexpected wg show form')
    elif len(args) == 6 and args[0] == 'set' and args[2] == 'peer' and args[4] == 'endpoint':
        if os.environ.get('WRITE_FAIL') == '1': sys.exit(1)
        state.setdefault(args[1], {})[args[3]] = args[5]
        (root/'runtime.json').write_text(json.dumps(state))
    else:
        event('forbidden_wg'); sys.exit(90)
elif mode in ('logger', 'policy'):
    event(mode)
else:
    event('forbidden', mode); sys.exit(91)
'''

MOCK_FUNCTIONS = r'''
Lock(){ "$MOCK_PY" "$MOCK_DRIVER" lock "$@"; }
unLock(){ "$MOCK_PY" "$MOCK_DRIVER" unlock "$@"; }
__wg_bin(){ printf '%s\n' "$MOCK_WG"; }
sql_config_get_list(){ "$MOCK_PY" "$MOCK_DRIVER" sql "$@"; }
sqlite3(){ "$MOCK_PY" "$MOCK_DRIVER" sqlite "$@"; }
__wg_resolve_address(){ "$MOCK_PY" "$MOCK_DRIVER" dns "$@"; }
logger(){ "$MOCK_PY" "$MOCK_DRIVER" logger "$@"; }
__wg_policy_apply(){ "$MOCK_PY" "$MOCK_DRIVER" policy "$@"; }
ip(){ "$MOCK_PY" "$MOCK_DRIVER" forbidden_ip "$@"; }
resolve_flush
'''


class Fixture:
    def __init__(self, root):
        self.root = root
        self.cache = root/'wireguard/config'
        self.cache.mkdir(parents=True)
        self.db = root/'config.db'
        self.driver = root/'driver.py'
        self.driver.write_text(MOCK_DRIVER)
        self.wg = root/'wg'
        self.wg.write_text('#!/bin/sh\nexec "$MOCK_PY" "$MOCK_DRIVER" wg "$@"\n')
        self.wg.chmod(0o700)
        self.env = dict(os.environ, MOCK_DIR=str(root), MOCK_PY=sys.executable,
                        MOCK_DRIVER=str(self.driver), MOCK_WG=str(self.wg),
                        IK_DIR_TMP=str(root), IK_DB_CONFIG=str(self.db))
        with sqlite3.connect(self.db) as con:
            con.executescript('''
                CREATE TABLE wireguard(id INTEGER, name TEXT, enabled TEXT);
                CREATE TABLE wireguard_peers(
                    id INTEGER, enabled TEXT, interface TEXT, peer_publickey TEXT,
                    endpoint TEXT, endpoint_port TEXT, out_mode TEXT,
                    out_wans TEXT, out_balance TEXT);
                INSERT INTO wireguard VALUES(1,'wg1','yes'),(2,'wg2','yes');
                INSERT INTO wireguard_peers VALUES
                    (1,'yes','wg1','FAKE_A','a.example.invalid','51820','auto','','failover'),
                    (2,'yes','wg1','FAKE_B','b.example.invalid','51821','auto','','failover');
            ''')
        self.runtime({'wg1': {'FAKE_A': '192.0.2.10:51820', 'FAKE_B': '192.0.2.20:51821'}})
        self.dns({'a.example.invalid': '192.0.2.11', 'b.example.invalid': '192.0.2.20'})
        self.cache_value(1, 'wg1', 'FAKE_A', 'a.example.invalid', '51820', '192.0.2.10')
        self.cache_value(2, 'wg1', 'FAKE_B', 'b.example.invalid', '51821', '192.0.2.20')
        # Deliberately stale legacy full config: no resolver may replay it.
        self.conf = root/'wireguard/wg1.conf'
        self.conf.write_text('[Peer]\nPublicKey = FAKE_A\n[Peer]\nPublicKey = FAKE_B\n')
        self.original_conf = self.conf.read_bytes()

    def sql(self, query):
        with sqlite3.connect(self.db) as con:
            con.execute(query)

    def runtime(self, value=None):
        path = self.root/'runtime.json'
        if value is not None: path.write_text(json.dumps(value))
        return json.loads(path.read_text())

    def dns(self, value):
        (self.root/'dns.json').write_text(json.dumps(value))

    def cache_value(self, peer_id, *values):
        (self.cache/str(peer_id)).write_text('\t'.join(values)+'\n')

    def events(self):
        path = self.root/'events'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def writes(self):
        return [event[1:] for event in self.events() if event[:2] == ['wg', 'set']]

    def start(self):
        return subprocess.Popen(['bash', '-c', RESOLVER+'\n'+MOCK_FUNCTIONS],
                                env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def finish(self, process, failure=False):
        stdout, stderr = process.communicate(timeout=10)
        assert bool(process.returncode) == failure, (process.returncode, stdout, stderr)
        assert not any(event[0].startswith('forbidden') for event in self.events())
        assert not (self.root/'lock-wireguard_address').exists(), 'mutation lock leaked'
        assert self.conf.read_bytes() == self.original_conf, 'resolver rewrote a legacy full config'
        held = False
        for event in self.events():
            if event[0] == 'lock_acquired':
                assert not held, 'nested resolver mutation lock'
                held = True
            elif event[0] == 'lock_released':
                assert held, 'release without acquired mutation lock'
                held = False
            elif event[0] == 'dns':
                assert not held, 'DNS lookup held the configuration mutation lock'
            elif event[0] == 'wg' or event == ['sql', 'recheck']:
                assert held, 'runtime access or DB recheck without mutation lock'
            elif event == ['sql', 'snapshot']:
                assert not held, 'snapshot unexpectedly held the mutation lock'
        assert not held, 'mutation lock not released after operation'

    def run(self, failure=False):
        self.finish(self.start(), failure)


def check(name, operation):
    with tempfile.TemporaryDirectory(prefix='wg-resolver-unit-') as directory:
        fixture = Fixture(Path(directory))
        try: operation(fixture)
        except Exception as error: raise AssertionError(name) from error


def normal_refresh(f):
    before = f.runtime()['wg1']['FAKE_B']
    f.run()
    assert f.writes() == [['set','wg1','peer','FAKE_A','endpoint','192.0.2.11:51820']]
    assert f.runtime()['wg1']['FAKE_B'] == before
    assert (f.cache/'1').read_text().strip().split('\t') == ['wg1','FAKE_A','a.example.invalid','51820','192.0.2.11']


def inactive_peer(f, query):
    f.sql(query)
    live = f.runtime()
    del live['wg1']['FAKE_A']
    f.runtime(live)
    f.dns({'a.example.invalid':'192.0.2.11', 'b.example.invalid':'192.0.2.21'})
    before = (f.cache/'1').read_bytes()
    f.run()
    assert f.writes() == [['set','wg1','peer','FAKE_B','endpoint','192.0.2.21:51821']]
    assert 'FAKE_A' not in f.runtime()['wg1']
    assert (f.cache/'1').read_bytes() == before


def no_updates(f, query):
    f.sql(query)
    before = f.runtime()
    f.run()
    assert f.writes() == []
    assert f.runtime() == before


def moved_peer(f, present):
    f.sql("UPDATE wireguard_peers SET interface='wg2' WHERE id=1")
    before = f.runtime()
    f.runtime({**before, 'wg2': {'FAKE_A':'192.0.2.10:51820'} if present else {}})
    f.run()
    assert f.runtime()['wg1'] == before['wg1']
    expected = [['set','wg2','peer','FAKE_A','endpoint','192.0.2.11:51820']] if present else []
    assert f.writes() == expected


def wrong_cache(f):
    sentinel = f.root/'cache-was-executed'
    (f.cache/'1').write_text('name=wg99 endpoint=wrong.invalid remote_addr=$(touch '+str(sentinel)+')\n')
    f.run()
    assert not sentinel.exists()
    assert f.writes() == [['set','wg1','peer','FAKE_A','endpoint','192.0.2.11:51820']]


def same_ip_wrong_identity(f, changed):
    f.dns({'a.example.invalid':'192.0.2.10', 'b.example.invalid':'192.0.2.20'})
    values = ['wg1','FAKE_A','a.example.invalid','51820','192.0.2.10']
    values[changed] = ['wg99','FAKE_OLD','old.example.invalid','59999'][changed]
    f.cache_value(1, *values)
    f.run()
    assert f.writes() == [['set','wg1','peer','FAKE_A','endpoint','192.0.2.10:51820']]


def refresh_failure(f, mode):
    before_cache = (f.cache/'1').read_bytes()
    before_runtime = f.runtime()
    if mode == 'dns': f.dns({'b.example.invalid':'192.0.2.20'})
    else: f.env[mode] = '1'
    f.run(failure=True)
    assert (f.cache/'1').read_bytes() == before_cache
    assert f.runtime() == before_runtime


def ipv6_refresh(f):
    f.dns({'a.example.invalid':'2001:db8::11', 'b.example.invalid':'192.0.2.20'})
    f.run()
    assert f.writes() == [['set','wg1','peer','FAKE_A','endpoint','[2001:db8::11]:51820']]


def lock_failure(f):
    f.env['LOCK_FAIL'] = '1'
    f.run(failure=True)
    assert ['lock_failed'] in f.events()
    assert not any(event[0] == 'wg' or event == ['sql', 'recheck'] for event in f.events())


def concurrent_mutation(f, query, phase):
    lock = f.root/'lock-wireguard_address'
    hold_dns = f.root/'hold-dns'
    # Both old and possible new identities exist at runtime: membership checks
    # alone must not let an answer for the old DB identity update either peer.
    state = f.runtime()
    state['wg1']['FAKE_NEW'] = '192.0.2.40:51820'
    state['wg2'] = {'FAKE_A':'192.0.2.30:51820'}
    f.runtime(state)
    before_cache = {p.name:p.read_bytes() for p in f.cache.iterdir()}
    if phase == 'dns': hold_dns.touch()
    else: lock.mkdir()  # A configuration mutation already owns the shared lock.
    process = f.start()
    try:
        deadline = time.monotonic()+5
        expected_event = ['dns_wait'] if phase == 'dns' else ['lock_wait']
        while expected_event not in f.events():
            assert process.poll() is None, 'refresh did not reach the concurrent mutation point'
            assert time.monotonic() < deadline, 'refresh never reached the concurrent mutation point'
            time.sleep(.01)
        assert ['sql', 'snapshot'] in f.events(), 'candidate snapshot was not read before DNS'
        assert not any(event[0] == 'wg' or event == ['sql', 'recheck'] for event in f.events())
        if phase == 'dns': lock.mkdir()  # Must succeed while DNS is still blocked.
        f.sql(query)
        lock.rmdir()
        if phase == 'dns': hold_dns.unlink()
        f.finish(process)
        assert f.writes() == [], 'refresh applied an answer for a stale peer identity'
        assert f.runtime() == state
        assert {p.name:p.read_bytes() for p in f.cache.iterdir()} == before_cache
    finally:
        if process.poll() is None:
            process.kill(); process.communicate()


CASES = [
    ('shared interface updates only the changed peer', normal_refresh),
    ('deleted peer cannot be restored by another peer refresh', lambda f: inactive_peer(f, 'DELETE FROM wireguard_peers WHERE id=1')),
    ('disabled peer cannot be restored by another peer refresh', lambda f: inactive_peer(f, "UPDATE wireguard_peers SET enabled='no' WHERE id=1")),
    ('disabled parent interface is skipped', lambda f: no_updates(f, "UPDATE wireguard SET enabled='no' WHERE name='wg1'")),
    ('cleared endpoint is skipped', lambda f: no_updates(f, "UPDATE wireguard_peers SET endpoint='' WHERE id=1")),
    ('moved peer updates only its current interface', lambda f: moved_peer(f, True)),
    ('missing runtime peer is not recreated', lambda f: moved_peer(f, False)),
    ('old-format or executable cache is treated as literal data', wrong_cache),
    *[('changed cache identity field '+str(i), lambda f, i=i: same_ip_wrong_identity(f, i)) for i in range(4)],
    ('failed DNS preserves last successful cache', lambda f: refresh_failure(f, 'dns')),
    ('failed WG write preserves last successful cache', lambda f: refresh_failure(f, 'WRITE_FAIL')),
    ('failed WG peer lookup preserves state', lambda f: refresh_failure(f, 'SHOW_FAIL')),
    ('failed snapshot does not acquire the mutation lock', lambda f: refresh_failure(f, 'SQL_FAIL')),
    ('failed database recheck releases the lock', lambda f: refresh_failure(f, 'SQL_RECHECK_FAIL')),
    ('IPv6 endpoint is passed as one bracketed argument', ipv6_refresh),
    ('lock failure prevents DB recheck and WG access', lock_failure),
]

MUTATIONS = [
    ('deleted peer', 'DELETE FROM wireguard_peers WHERE id=1'),
    ('disabled peer', "UPDATE wireguard_peers SET enabled='no' WHERE id=1"),
    ('disabled parent', "UPDATE wireguard SET enabled='no' WHERE name='wg1'"),
    ('moved peer', "UPDATE wireguard_peers SET interface='wg2' WHERE id=1"),
    ('changed public identity', "UPDATE wireguard_peers SET peer_publickey='FAKE_NEW' WHERE id=1"),
    ('changed hostname', "UPDATE wireguard_peers SET endpoint='new.example.invalid' WHERE id=1"),
    ('changed port', "UPDATE wireguard_peers SET endpoint_port='52999' WHERE id=1"),
]
for mutation, query in MUTATIONS:
    for phase in ('dns', 'lock'):
        CASES.append((mutation+' during '+phase,
                      lambda f, q=query, p=phase: concurrent_mutation(f, q, p)))

for name, operation in CASES:
    check(name, operation)

IP_CASES = [
    ('192.0.2.1', True), ('0.0.0.0', True), ('255.255.255.255', True),
    ('::', True), ('::1', True), ('2001:db8::1', True), ('fe80::ABCD', True),
    ('2001:db8:0:1:2:3:4:5', True), ('1:2:3:4:5:6:7::', True),
    ('', False), ('unresolved.example.invalid', False), ('999.1.2.3', False),
    ('1.2.3', False), ('1.2.3.4.5', False), ('1.-1.2.3', False),
    ('1.2.3.4/32', False), ('1.2.3.4:51820', False), (' 192.0.2.1', False),
    ('2001:db8:0:1:2:3:4', False), ('1:2:3:4:5:6:7:8:9', False),
    ('1:2:3:4:5:6:7::8', False), ('1:2:3:4:5:6:7:gggg', False),
    ('1:2:3:4:5:6:7:12345', False), ('1::2::3', False), ('1:::2', False),
    (':1::2', False), ('1::2:', False), ('::1:', False),
    ('[2001:db8::1]', False), ('2001:db8::1/64', False),
]
ip_function = extract('__wg_is_endpoint_ip')
for value, valid in IP_CASES:
    result = subprocess.run(['bash','-c',ip_function+'\n__wg_is_endpoint_ip "$1"','test',value],
                            capture_output=True, text=True)
    assert (result.returncode == 0) == valid, ('endpoint IP validation', value, result.returncode)

ADDRESS_CASES = [
    ('IPv4 literal', '192.0.2.1', '', '', '192.0.2.1'),
    ('IPv6 literal', '2001:db8::1', '', '', '2001:db8::1'),
    ('first IPv4 DNS answer', 'a.example.invalid', '192.0.2.1\n192.0.2.2', '', '192.0.2.1'),
    ('IPv6 DNS fallback', 'a.example.invalid', '', '2001:db8::1', '2001:db8::1'),
    ('invalid IPv4 answer falls back', 'a.example.invalid', '999.1.2.3', '2001:db8::1', '2001:db8::1'),
    ('no DNS answer', 'a.example.invalid', '', '', None),
    ('hostname echoed on failure is rejected', 'a.example.invalid', 'a.example.invalid', '', None),
    ('malformed IPv6 answer is rejected', 'a.example.invalid', '', '1::2:', None),
]
address_script = ip_function+'\n'+extract('__wg_resolve_address')+r'''
resolveip(){
 [ "$#" = 4 ] && [ "$2" = -t ] && [ "$3" = 4 ] && [ "$4" = "$EXPECTED_HOST" ] || return 97
 case "$1" in
  -4) [ "$ANSWER4" ] || return 1;printf '%s\n' "$ANSWER4";;
  -6) [ "$ANSWER6" ] || return 1;printf '%s\n' "$ANSWER6";;
  *) return 98;;
 esac
}
EXPECTED_HOST=$1 ANSWER4=$2 ANSWER6=$3
__wg_resolve_address "$1"
'''
for name, host, answer4, answer6, expected in ADDRESS_CASES:
    result = subprocess.run(['bash','-c',address_script,'test',host,answer4,answer6],
                            capture_output=True, text=True)
    assert (result.returncode == 0) == (expected is not None), name
    assert result.stdout.rstrip('\n') == (expected or ''), name

print('PASS '+str(len(CASES)+len(IP_CASES)+len(ADDRESS_CASES))+
      ' WG resolver cases ('+str(len(CASES))+' state/lock, '+str(len(IP_CASES))+
      ' IP validation, '+str(len(ADDRESS_CASES))+' DNS helper)')
