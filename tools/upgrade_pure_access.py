"""Native upgrade checks for supported and retired transport profiles for the disposable native upgrade guest."""
import json
import re
import time


def seed(call, post, *, rc16=False, fixtures=None):
    def wg(action, **fields):
        return call('wireguard', action, fields)
    def show(kind, **fields):
        return wg('show', TYPE=kind, **fields)['Data'][kind]
    cases = {}
    if fixtures is None:
        pure_roles = ('access',) if rc16 else ('access','both','lend')
        fixtures = [('pure_hy2', role) for role in pure_roles] + [('hysteria2','both'), ('native','both')]
    for n, (transport, role) in enumerate(fixtures, 21):
        name = f'wg{n}'
        local = wg('show', TYPE='gen_privatekey')['Data']
        wg('iface_add', enabled='yes', name=name, interface='auto', mtu=1420,
           local_address=f'10.173.{n}.1/24', local_listenport=51840+n,
           local_privatekey=local['privatekey'], local_publickey=local['pubkey'])
        remote = wg('show', TYPE='gen_privatekey')['Data']
        options = dict(hyr_addr_mode='manual', hyr_port_mode='wg', hyr_public_ip='10.0.2.2') if transport != 'native' else {}
        wg('add', enabled='yes', interface=name, comment=f'upgrade-{transport}-{role}',
           peer_privatekey=remote['privatekey'], peer_publickey=remote['pubkey'], presharedkey='',
           allowips=f'10.173.{n}.2/32', endpoint='', endpoint_port='', keepalive=25,
           client_endpoint='10.0.2.2', client_dns='1.1.1.1', exit_peer='no' if role=='access' else 'yes',
           site_local='', site_remote='', wg_transport=transport, wg_role=role, hyr_id='', **options)
        if transport=='native':
            cases['native'] = {'iface':name,'public':remote['pubkey']}
            continue
        reg = next(m for m in show('hyr_settings')['members'] if m['interface']==name)
        params = {'peer_id':reg['peer_id'], 'id':reg['id']}
        profile = show('hyr_profile', expected_role=role, **params)
        case = {'iface':name, 'port':reg['public_port'], 'params':params, 'role':role, 'profile':profile}
        case['stun_port'] = reg.get('stun_port')
        bundle = show('hyr_site_profile', expected_role=role, **params)
        case['bundle'] = bundle
        # The remote address is SLIRP's gateway. RC15 may persist a reverse
        # import before a peer is available. Require its exact durable row.
        if transport=='hysteria2':
            # A hub cannot import its own keys. Model another hub with a fresh
            # WG identity and independent subnet on this same disposable guest.
            bundle=json.loads(json.dumps(bundle))
            keys=wg('show',TYPE='gen_privatekey')['Data']
            bundle['wireguard'].update(public_key=keys['pubkey'],
                private_key=wg('show',TYPE='gen_privatekey')['Data']['privatekey'],
                address='10.176.42.2/32',peer_address='10.176.42.1/32')
            case['bundle']=bundle
        old = {m['id'] for m in show('site_client_status')['members']}
        response = post('/Action/call', {'func_name':'wireguard', 'action':'site_client_import',
            'param':{'config_hex':json.dumps(bundle,separators=(',',':')).encode().hex()}})
        if response['Result']!=30000:
            assert '已保存' in str(response.get('ErrMsg') or ''), ('baseline rejected import', transport, role, response.get('Result'), response.get('ErrMsg'))
        rows = [m for m in show('site_client_status')['members'] if m['id'] not in old]
        assert len(rows)==1 and rows[0]['transport']==transport and rows[0]['purpose']==role
        case['import'] = rows[0]
        cases['wrapped' if transport=='hysteria2' else role] = case
    return cases


def verify_api(call, post, cases):
    def busy(code, message):
        return code==30006 and ('正在保存' in (message or '') or '正在恢复' in (message or ''))
    def show(kind, **fields):
        # Native startup can hold wireguard_address after the management API
        # is available. Wait only for a read that explicitly reports this lock.
        end=time.monotonic()+240
        while True:
            try:
                return call('wireguard','show',{'TYPE':kind,**fields})['Data'][kind]
            except AssertionError as error:
                record=error.args[0] if error.args else None
                if not isinstance(record,tuple) or len(record)!=5 or not busy(record[3],record[4]) or time.monotonic()>=end:
                    raise
                time.sleep(3)
    def denied(action, fields):
        end=time.monotonic()+180
        while True:
            result = post('/Action/call',{'func_name':'wireguard','action':action,'param':fields})
            if not busy(result.get('Result'),result.get('ErrMsg')):break
            assert time.monotonic()<end, 'native controller did not complete startup'
            time.sleep(3)
        assert result.get('Result') not in (10014,30000), f'retired {action} unexpectedly succeeded'
    deadline=time.monotonic()+240
    while True:
        state=show('hyr_status')
        active={m['interface'] for m in state['members'] if m.get('running')}
        if {cases[k]['iface'] for k in ('access','both') if k in cases} <= active:
            break
        if time.monotonic()>=deadline:
            raise AssertionError('expected forward listeners to start automatically after upgrade')
        time.sleep(3)
    members = {m['interface']:m for m in state['members']}
    imports = {m['interface']:m for m in show('site_client_status')['members']}
    for role in (k for k in ('access','both','lend') if k in cases):
        case=cases[role]
        m=members[case['iface']]
        assert m['id']==case['params']['id'] and not m.get('stun_port') and not m.get('realm_port')
        other=imports[case['import']['interface']]
        if role=='lend':
            assert m.get('retired') and not m.get('running')
            assert other.get('retired') and not other.get('enabled')
            denied('show',{'TYPE':'hyr_profile',**case['params']})
            denied('up',{'id':str(other['id'])})
        else:
            assert m['mode']=='access' and m['running'] and other['purpose']=='access'
            assert other['id']==case['import']['id'] and other.get('enabled')==case['import'].get('enabled')
            profile=show('hyr_profile',expected_role='access',**case['params'])
            bundle=show('hyr_site_profile',expected_role='access',**case['params'])
            assert bundle['purpose']=='access' and 'reverse' not in bundle and bundle['transport']==case['bundle']['transport']
            def forward(profile):
                return [out for out in profile['outbounds'] if out['type']=='hysteria2']
            assert len(forward(profile))==1 and forward(profile)==forward(case['profile'])
            assert {i['type'] for i in profile['inbounds']}=={'tun'} and 'services' not in profile
        if role!='access':
            denied('site_client_import',{'config_hex':json.dumps(case['bundle'],separators=(',',':')).encode().hex()})
    wrapped=cases['wrapped']
    old=members[wrapped['iface']]
    receiver=imports[wrapped['import']['interface']]
    assert old.get('retired') and not old.get('running') and not old.get('active')
    assert old['id']==wrapped['params']['id']
    assert receiver.get('retired') and not receiver.get('running') and not receiver.get('enabled')
    assert receiver['id']==wrapped['import']['id']
    denied('show',{'TYPE':'hyr_profile',**wrapped['params']})
    denied('show',{'TYPE':'hyr_site_profile',**wrapped['params']})
    denied('up',{'id':str(receiver['id'])})
    denied('up',{'id':str(wrapped['params']['peer_id'])})
    denied('site_client_import',{'config_hex':json.dumps(wrapped['bundle'],separators=(',',':')).encode().hex()})


def verify_kernel(shell,cases):
    native=cases['native']
    names=[case['iface'] for case in cases.values()]
    assert all(re.fullmatch('wg[0-9]+',name) for name in names)
    # The second boot deliberately uses a diagnostic bootloader. Management
    # readiness can precede WG and the dynamically cached core by several minutes.
    # Wait for live positive controls before interpreting absent listeners.
    units=[int(cases[role]['params']['peer_id']) for role in ('access','both') if role in cases]
    deadline=time.monotonic()+300
    while True:
        links=set(shell('/usr/bin/wg show interfaces').split())
        probes=' && '.join(f'/usr/ikuai/script/wg_hy_engine.sh puh-{row} status >/dev/null 2>&1' for row in units)
        ready=shell(f'if {probes};then echo yes;else echo no;fi')
        if ready=='yes' and native['iface'] in links and shell('/usr/bin/wg show '+native['iface']+' peers')==native['public']:
            break
        assert time.monotonic()<deadline, ('services not ready on diagnostic boot', sorted(links), ready)
        time.sleep(3)
    for role in (k for k in ('access','both','lend') if k in cases):
        case=cases[role]
        iface=case['iface']; port=int(case['port']); peer=int(case['params']['peer_id'])
        assert re.fullmatch('wg[0-9]+',iface)
        if iface in links:
            assert not shell('/usr/bin/wg show '+iface+' peers'), (role,'unexpected native WG peer')
        shell(f"test ! -e /sys/class/net/nph{peer}")
        if case.get('stun_port'):
            udp=int(case['stun_port'])
            shell(f"""listeners=$(netstat -lntu) && printf '%s\\n' "$listeners" | awk '$1~/^tcp/ && $4~/[:.]{port}$/ || $1~/^udp/ && $4~/[:.]{udp}$/ {{seen=1}} END {{exit seen+0}}'""")
        record_ok=shell(f"""jq -M -e --arg id '{peer}' '.members[$id] | type=="object" and .realm_token == null and .reverse_key == null and .stun_port == null' /etc/mnt/ikuai/wg-hyr/state.json""")
        assert record_ok=='true', (role,'missing or unmigrated registry entry')
        imported=int(case['import']['id'])
        if role=='lend':
            shell(f"test ! -e /tmp/iktmp/wg-hy-engine/puh-{peer}/service.pid")
            shell(f'''test "$(sqlite3 /etc/mnt/ikuai/config.db 'select pure_bundle is null from wg_site_clients where peer_id={imported}')" = 1''')
        if role=='both':
            bundle_ok=shell(f'''set -o pipefail; sqlite3 /etc/mnt/ikuai/config.db 'select pure_bundle from wg_site_clients where peer_id={imported}' | jq -M -e '.purpose=="access" and .reverse==null' ''')
            assert bundle_ok=='true', 'missing or unmigrated imported access bundle'
    native=cases['native']
    assert shell('wg show '+native['iface']+' peers')==native['public']

    old=cases['wrapped']
    for iface in (old['iface'],old['import']['interface']):
        assert re.fullmatch('wg[0-9]+',iface)
        assert iface not in links or not shell('wg show '+iface+' peers'), 'retired peer active in kernel'
    # Positive control above established the engine is ready on this boot.
    receiver_id=int(old['import']['id'])
    relay=int(shell(f"sqlite3 /etc/mnt/ikuai/config.db 'select relay_port from wg_site_clients where peer_id={receiver_id}'"))
    assert 0 < relay < 65536
    assert shell(f"sqlite3 /etc/mnt/ikuai/config.db 'select length(password)+length(pin) from wg_site_clients where peer_id={receiver_id}'")=='0'
    center_id=int(old['params']['peer_id'])
    registry=f'.members["{center_id}"] | type=="object" and .password==null'
    assert shell(f"jq -M -e '{registry}' /etc/mnt/ikuai/wg-hyr/state.json")=='true'
    for suffix in ('hyr-'+str(int(old['port'])), 'hyc-'+str(relay)):
        shell(f'test ! -s /tmp/iktmp/wg-hy-engine/{suffix}/service.pid')
