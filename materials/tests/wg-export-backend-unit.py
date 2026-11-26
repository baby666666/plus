#!/usr/bin/env python3
"""Exercise WG key generation, saved export and query snapshots without a router.

The actual firmware functions run against temporary SQLite/command fixtures.
The mock WG derives deterministic test keys; no real credential is read.
"""
from pathlib import Path
import argparse, base64, concurrent.futures, hashlib, json, os, re, sqlite3, subprocess, tempfile, time

parser = argparse.ArgumentParser()
parser.add_argument('--lua', default='lua')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
source = (root / 'firmware/port-3726/files/usr/ikuai/script/wireguard.sh').read_text()
starts = list(re.finditer(r'(?m)^([A-Za-z_]\w*)\(\)\s*\{', source))
functions = {m.group(1): source[m.start():starts[i+1].start() if i+1 < len(starts) else len(source)] for i, m in enumerate(starts)}
names = ['__check_key_valid', '__wg_public_from_private', '__show_gen_privatekey', '__show_gen_publickey', '__show_gen_sharedkey', '__show_client_export', '__wg_saved_client_export', '__wg_export_ipv4', '__implant_code', 'show', '__wg_checked_show']
body = '\n'.join(functions[n] for n in names)
passed = 0
def check(ok, label):
    global passed
    assert ok, label
    passed += 1
    print('PASS', label, flush=True)
def key(text):
    return base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()
def pub(private):
    return key('public:' + private)

with tempfile.TemporaryDirectory(prefix='wg-export-test-') as tmp:
    d = Path(tmp)
    fake = d / 'wg'
    fake.write_text('''#!/usr/bin/env python3
import os,sys,hashlib,base64,time,json
from pathlib import Path
def key(s):return base64.b64encode(hashlib.sha256(s.encode()).digest()).decode()
op=sys.argv[1]
with open(os.environ['FIXTURE']+'/calls','a') as f:f.write(json.dumps(sys.argv[1:])+'\\n')
if os.environ.get('FAIL')==op:
 print('SECRET_ERROR_SENTINEL');print('SECRET_ERROR_SENTINEL',file=sys.stderr);sys.exit(1)
if os.environ.get('EMPTY')==op:sys.exit(0)
if os.environ.get('BAD')==op:print('bad-key');sys.exit(0)
if op=='genkey':time.sleep(.01);print(key('private:'+os.environ['REQUEST']))
elif op=='genpsk':time.sleep(.01);print(key('psk:'+os.environ['REQUEST']))
elif op=='pubkey':
 value=sys.stdin.read().strip()
 if os.environ.get('SLOW_PUB'):
  Path(os.environ['FIXTURE']+'/deriving').touch();time.sleep(.2)
 print(key('public:'+value))
else:sys.exit(2)
''')
    fake.chmod(0o700)
    db = d / 'config.db'
    con = sqlite3.connect(db)
    con.executescript('''
CREATE TABLE wireguard(id INTEGER,name TEXT,enabled TEXT,interface TEXT,local_address TEXT,local_listenport INTEGER,local_publickey TEXT,local_privatekey TEXT,keepalive INTEGER,mtu INTEGER);
CREATE TABLE wireguard_peers(id INTEGER,interface TEXT,enabled TEXT,exit_peer TEXT,allowips TEXT,peer_privatekey TEXT,peer_publickey TEXT,presharedkey TEXT,client_endpoint TEXT,client_dns TEXT,keepalive INTEGER,site_local TEXT,site_remote TEXT,comment TEXT,out_mode TEXT,out_wans TEXT,out_balance TEXT,endpoint TEXT,endpoint_port TEXT,native_role TEXT);
''')
    parent_private, peer_private = key('server-private'), key('phone-private')
    iface = (1, 'wg3', 'yes', 'auto', '10.100.2.1/24', 50003, pub(parent_private), parent_private, 10, 1420)
    peer = (5, 'wg3', 'yes', 'yes', '10.100.2.2/32', peer_private, pub(peer_private), key('psk'), '192.0.2.150', '10.100.2.1', 25, '', '', 'phone " test', 'auto', '', 'failover', '', '', '')
    def reset():
        con.execute('DELETE FROM wireguard'); con.execute('DELETE FROM wireguard_peers')
        con.execute('INSERT INTO wireguard VALUES (' + ','.join('?' * len(iface)) + ')', iface)
        con.execute('INSERT INTO wireguard_peers VALUES (' + ','.join('?' * len(peer)) + ')', peer)
        con.commit()
    reset()
    sql = d / 'sql.py'
    sql.write_text('''import sqlite3,json,sys,os
from pathlib import Path
assert Path(os.environ['FIXTURE']+'/lock').exists(),'snapshot must be locked'
c=sqlite3.connect(sys.argv[1]);c.row_factory=sqlite3.Row
print(json.dumps([dict(r) for r in c.execute(sys.argv[2])]))
''')
    shell = d / 'test.sh'
    shell.write_text(r'''
FIXTURE=$1
IK_DB_CONFIG="$FIXTURE/config.db"
__wg_bin(){ [ "${NO_WG:-0}" != 1 ] && printf '%s\n' "$FIXTURE/wg"; }
Lock(){ [ "${FAIL_LOCK:-0}" != 1 ] && mkdir "$FIXTURE/lock" 2>/dev/null; }
unLock(){ rmdir "$FIXTURE/lock"; }
sql_config_get_json(){ [ "${FAIL_SQL:-0}" != 1 ] && python3 "$FIXTURE/sql.py" "$1" "$2"; }
json_append(){
 case "$2" in
  client_export:json) printf '%s\n' "$client_export";;
  pubkey:str) if [ "$3" = privatekey:str ];then printf '%s\n%s\n' "$pubkey" "$privatekey";else printf '%s\n' "$pubkey";fi;;
  presharedkey:str) printf '%s\n' "$presharedkey";;
  *) return 2;;
 esac
}
''' + body + r'''
peer_id=${PEER_ID:-5}
privatekey=${PRIVATE_KEY:-}
if [ "$2" = show ];then
 sql_auto_get_filter(){ :; };sql_auto_get_order(){ :; };sql_auto_get_limit(){ :; }
 Show(){ printf '{"legacy":true}'; }
 # Mirror native dynamic-scope accumulation; direct helper tests above still
 # print their return value, whereas the real Show path collects one object.
 json_append(){
  local item field value sep
  [ "$__json_result__" ] || __json_result__='{}'
  for item in "${@:2}";do
   field=${item%:*};value=${!field}
   case "$item" in *:str) value="\"$value\"";;esac
   sep='';[ "$__json_result__" = '{}' ] || sep=,
   __json_result__="${__json_result__%\}}$sep\"$field\":$value}"
  done
 }
fi
"$2"
''')
    def run(action, request='one', **env):
        return subprocess.run(['bash', str(shell), str(d), action], capture_output=True, text=True,
                              env={**os.environ, 'FIXTURE': str(d), 'REQUEST': request, **env})
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        generated = list(pool.map(lambda i: run('__show_gen_privatekey', str(i)), range(40)))
    values = [r.stdout.strip().splitlines() for r in generated]
    check(all(r.returncode == 0 for r in generated) and all(len(v) == 2 and v[0] == pub(v[1]) for v in values), 'concurrent private/public responses always match')
    check(len({v[1] for v in values}) == 40, 'concurrent requests retain their own generated keys')
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        shared = list(pool.map(lambda i: run('__show_gen_sharedkey', str(i)), range(40)))
    check(all(r.returncode == 0 for r in shared) and len({r.stdout for r in shared}) == 40, 'concurrent PSK responses remain independent')
    check(run('__show_gen_publickey', PRIVATE_KEY=peer_private).stdout.strip() == pub(peer_private), 'public key derivation reads stdin')
    for action, op in [('__show_gen_privatekey', 'genkey'), ('__show_gen_privatekey', 'pubkey'), ('__show_gen_publickey', 'pubkey'), ('__show_gen_sharedkey', 'genpsk')]:
        for failure in ['FAIL', 'EMPTY', 'BAD']:
            r = run(action, PRIVATE_KEY=peer_private, **{failure: op})
            check(r.returncode != 0 and 'SECRET_ERROR_SENTINEL' not in r.stdout + r.stderr and peer_private not in r.stdout + r.stderr,
                  action + ' safely rejects ' + failure + ' ' + op)
    for action in ['__show_gen_privatekey', '__show_gen_publickey', '__show_gen_sharedkey']:
        check(run(action, NO_WG='1', PRIVATE_KEY=peer_private).returncode != 0, action + ' fails if WG binary is missing')
    for invalid in ['', 'bad', peer_private + '\n' + peer_private]:
        check(run('__show_gen_publickey', PRIVATE_KEY=invalid).returncode != 0, 'invalid private input rejected')
    check(all(len(json.loads(line)) == 1 for line in (d / 'calls').read_text().splitlines()), 'keys never passed as WG command arguments')
    check(not any(n in body for n in ['/wireguard/.privatekey', '/wireguard/.pubkey', '/wireguard/.presharekey']), 'generation does not use shared temporary secret files')
    r = run('__show_client_export')
    check(r.returncode == 0, 'saved export succeeds')
    exported = json.loads(r.stdout)
    check(exported['peer']['peer_privatekey'] == peer_private and exported['iface']['local_publickey'] == pub(parent_private) and exported['keypair_valid'] is True, 'saved export returns matching authorized client material')
    check(parent_private not in r.stdout and 'local_privatekey' not in r.stdout, 'parent interface private key never leaves saved export')
    check(not (d / 'lock').exists(), 'successful export releases edit lock')
    con.execute('UPDATE wireguard_peers SET allowips=?', ('10.100.2.2',)); con.commit()
    r = run('__show_client_export')
    check(r.returncode == 0 and json.loads(r.stdout)['peer']['allowips'] == '10.100.2.2', 'single bare IPv4 retains existing /32 semantics')
    con.execute("UPDATE wireguard_peers SET native_role='access',exit_peer='no'")
    con.execute("INSERT INTO wireguard_peers(id,interface,enabled) VALUES(6,'wg3','yes')")
    con.commit()
    r = run('__show_client_export')
    check(r.returncode==0 and json.loads(r.stdout)['peer']['native_role']=='access', 'explicit native access can export on a shared interface')
    reset()
    for invalid in ['0', '-1', '01', '5;DROP TABLE wireguard', '1.5', '9' * 25]:
        r = run('__show_client_export', PEER_ID=invalid)
        check(r.returncode != 0 and not (d / 'lock').exists(), 'invalid export id rejected before lock: ' + invalid[:12])
    for changes, label in [
        ([('DELETE FROM wireguard_peers', ())], 'missing peer'),
        ([('UPDATE wireguard_peers SET enabled=?', ('no',))], 'disabled peer'),
        ([('UPDATE wireguard SET enabled=?', ('no',))], 'disabled parent'),
        ([('UPDATE wireguard_peers SET exit_peer=?', ('no',))], 'ordinary access peer'),
        ([('UPDATE wireguard_peers SET site_local=?', ('192.168.1.0/24',))], 'site network'),
        ([('UPDATE wireguard_peers SET allowips=?', ('10.100.2.0/24',))], 'non-host address'),
        ([('UPDATE wireguard_peers SET allowips=?', ('10.100.2.999/32',))], 'invalid address octet'),
        ([('UPDATE wireguard_peers SET client_endpoint=?', ('127.0.0.1',))], 'invalid endpoint'),
        ([('UPDATE wireguard SET local_listenport=?', (65536,))], 'invalid saved port'),
        ([('UPDATE wireguard_peers SET keepalive=?', (-1,))], 'invalid keepalive'),
        ([('UPDATE wireguard_peers SET peer_publickey=?', (key('wrong'),))], 'mismatched peer key pair'),
        ([('UPDATE wireguard SET local_publickey=?', (key('wrong'),))], 'mismatched parent key pair'),
        ([('UPDATE wireguard_peers SET presharedkey=?', ('SECRET_INVALID_KEY',))], 'invalid PSK'),
        ([('INSERT INTO wireguard_peers(id,interface,enabled) VALUES(6,\'wg3\',\'no\')', ())], 'disabled sibling still violates dedicated interface'),
    ]:
        reset()
        for query, params in changes: con.execute(query, params)
        con.commit(); r = run('__show_client_export')
        check(r.returncode != 0 and peer_private not in r.stdout + r.stderr and parent_private not in r.stdout + r.stderr and 'SECRET_INVALID_KEY' not in r.stdout + r.stderr and not (d / 'lock').exists(), 'saved export rejects ' + label + ' without secret/lock leak')
    reset()
    for env in [{'FAIL_SQL': '1'}, {'FAIL_LOCK': '1'}, {'FAIL': 'pubkey'}, {'NO_WG': '1'}]:
        r = run('__show_client_export', **env)
        check(r.returncode != 0 and not (d / 'lock').exists() and 'SECRET_ERROR_SENTINEL' not in r.stdout + r.stderr, 'export failure releases lock: ' + str(env))
    r = run('show', TYPE='client_export')
    check(r.returncode == 0 and json.loads(r.stdout)['client_export']['keypair_valid'], 'checked show returns valid saved export JSON')
    for types in ['gen_privatekey', 'gen_sharedkey', 'gen_publickey', 'gen_privatekey,gen_sharedkey', ' gen_sharedkey, gen_publickey']:
        r = run('show', TYPE=types, PRIVATE_KEY=peer_private)
        check(r.returncode == 0 and isinstance(json.loads(r.stdout), dict), 'checked show accumulates valid JSON for ' + types)
    for types, env in [
        ('client_export', {'PEER_ID': '0'}),
        ('gen_privatekey', {'FAIL': 'genkey'}),
        ('gen_sharedkey', {'FAIL': 'genpsk'}),
        ('gen_publickey', {'PRIVATE_KEY': 'bad'}),
        ('gen_privatekey,client_export', {'PEER_ID': '0'}),
        ('client_export,gen_publickey', {'PRIVATE_KEY': 'bad'}),
        ('gen_privatekey,missing', {}),
        ('all', {'PEER_ID': '0'}),
    ]:
        r = run('show', TYPE=types, **env)
        check(r.returncode != 0 and r.stdout.strip() == 'WG 配置读取或密钥生成失败，请检查已保存配置后重试' and
              peer_private not in r.stdout and parent_private not in r.stdout and 'SECRET_ERROR_SENTINEL' not in r.stdout,
              'checked show discards all partial data and propagates failure for ' + types)
    r = run('show', TYPE='data,total')
    check(r.returncode == 0 and json.loads(r.stdout) == {'legacy': True}, 'unaffected listing types retain native Show path')
    # Hold key derivation in progress; a parallel export/edit-lock requester
    # cannot obtain a mixed view while the saved response is being validated.
    p = subprocess.Popen(['bash', str(shell), str(d), '__show_client_export'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         env={**os.environ, 'FIXTURE': str(d), 'REQUEST': 'slow', 'SLOW_PUB': '1'})
    until = time.monotonic() + 5
    while not (d / 'deriving').exists() and time.monotonic() < until: time.sleep(.01)
    blocked = run('__show_client_export')
    out, err = p.communicate(timeout=5)
    check(blocked.returncode != 0 and p.returncode == 0 and json.loads(out)['keypair_valid'] and not (d / 'lock').exists(), 'saved snapshot remains locked through both key-pair checks')
    con.close()

    implant = run('__implant_code')
    check(implant.returncode == 0, 'extract query-local Lua implementation')
    lua = d / 'transfers.lua'
    lua.write_text('''
local funcs, count = {}, {}
ikdb={create_function=function(self,name,n,fn) funcs[name]=fn end}
local fixtures={wg1={"peerA\\t9007199254740993\\t18446744073709551615","peerB\\t0\\t42"},wg2={"peerA\\t11\\t22"}}
io.popen=function(cmd)
 local iface=assert(cmd:match("^wg show (wg%d+) transfer 2>/dev/null$"))
 count[iface]=(count[iface] or 0)+1
 local rows=fixtures[iface] or {};local i=0
 return {lines=function()return function()i=i+1;return rows[i]end end,close=function()return true end}
end
local function invoke(name,iface,peer)
 local out;funcs[name]({result=function(self,v)out=v end},iface,peer);return out
end
local function install()
''' + implant.stdout + '''
end
install()
assert(invoke('upload','wg1','peerA')=='18446744073709551615')
assert(invoke('download','wg1','peerA')=='9007199254740993')
for i=1,32 do invoke('upload','wg1','peerA');invoke('download','wg1','peerB') end
assert(count.wg1==1,'same query must read each interface once')
assert(invoke('upload','wg2','peerA')=='22' and invoke('download','wg2','peerA')=='11')
assert(count.wg2==1,'same key on another interface must not collide')
assert(invoke('download','wg1','peerB')=='0')
assert(invoke('upload','wg1','missing')=='')
assert(invoke('upload','wg9','missing')=='');invoke('download','wg9','missing');assert(count.wg9==1)
assert(invoke('upload','wg1;bad','peerA')=='','invalid interface must not execute a shell command')
fixtures.wg1={"peerA\\t33\\t44"}
assert(invoke('upload','wg1','peerA')=='18446744073709551615','current request sample must remain stable')
install();assert(invoke('upload','wg1','peerA')=='44' and count.wg1==2,'next request must refresh')
io.popen=function()return nil end
install();assert(invoke('upload','wg1','peerA')=='' and invoke('download','wg1','peerA')=='')
print('LUA_TRANSFER_SNAPSHOT_PASS')
''')
    result = subprocess.run([args.lua, str(lua)], capture_output=True, text=True)
    check(result.returncode == 0 and 'LUA_TRANSFER_SNAPSHOT_PASS' in result.stdout, 'actual Lua snapshot preserves counters, directions, interface identity and request freshness: ' + result.stderr)
print('WG_EXPORT_BACKEND_PASS', passed)
