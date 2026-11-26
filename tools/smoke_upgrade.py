#!/usr/bin/env python3
"""Native upgrade/configuration/runtime checks in a newly launched localhost VM only.

The test shell is added to a disposable configuration partition. It is never
written to the release image or firmware. No destination URL can be supplied.
Requires Python 3.12 (telnetlib), QEMU and a completed tools/rebuild.py workdir.
"""
from pathlib import Path
import argparse, base64, hashlib, http.cookiejar, json, re, secrets, shutil, socket
import subprocess, telnetlib, time, urllib.request, tempfile, shlex, io
from dissect.extfs import ExtFS
from native_upload import upload_and_install

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline-image', type=Path, required=True, help='Uncompressed .img; copied, never booted directly')
    p.add_argument('--workdir', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True, help='New private directory outside checkout')
    p.add_argument('--qemu', default='qemu-system-x86_64')
    p.add_argument('--firmware-dir', type=Path)
    p.add_argument('--test-public-https', action='store_true', help='Allow guest outbound networking and verify HTTPS against example.com')
    p.add_argument('--check-retired-hy', action='store_true', help='Enable the standalone Hysteria service on the baseline and verify that the new firmware retires its listener and API')
    p.add_argument('--check-rc4-tunnel', action='store_true', help='Verify an existing RC4 dual-use enrollment and its QR contents after upgrade')
    p.add_argument('--retired-tcp-core', type=Path, help='On RC7, seed a VLESS lend peer and verify retirement and direction migration after upgrading')
    p.add_argument('--rc8-core', type=Path, help='Verify a native lend peer and a same-port Hysteria peer from an RC8/RC9 baseline')
    p.add_argument('--paused-carriers', action='store_true', help='Disable the RC8/RC9 WG carrier before upgrade, then explicitly resume just one peer')
    p.add_argument('--device-editor', action='store_true', help='Seed active carriers using only per-device add/edit on RC10 and newer baselines')
    p.add_argument('--check-imported-site', action='store_true', help='Preserve an RC12 receiver and test its first directional import after upgrade')
    p.add_argument('--check-rc13-devices', action='store_true', help='Preserve existing v2 native/HY device imports across an RC13 upgrade')
    p.add_argument('--check-rc15-pure', action='store_true', help='Verify RC15 pure device modes, existing imports and compatible forward credentials after upgrade')
    p.add_argument('--check-rc16-transports', action='store_true', help='Verify pure HY2 and native WG survive and wrapped hub/receiver profiles retire')
    p.add_argument('--small-disk-core', type=Path, help='On RC17, seed a memory-backed HY2 worker with only small system partitions, then verify disk-backed recovery after upgrade')
    a = p.parse_args()
    if a.small_disk_core and (a.rc8_core or a.retired_tcp_core or a.check_rc16_transports or a.check_rc15_pure):
        p.error('--small-disk-core runs against a dedicated RC17 baseline')
    if a.check_rc16_transports and (not a.rc8_core or a.check_rc15_pure or a.check_rc4_tunnel):
        p.error('--check-rc16-transports requires the RC16 baseline and --rc8-core')
    if a.check_rc15_pure and not a.rc8_core:
        p.error('--check-rc15-pure requires the RC15 baseline and --rc8-core')
    if a.check_rc13_devices and not a.check_imported_site:
        p.error('--check-rc13-devices requires --check-imported-site')
    if a.check_imported_site and not a.device_editor:
        p.error('--check-imported-site requires --device-editor and a baseline supporting site imports')
    if a.device_editor and (not a.rc8_core or a.paused_carriers or a.check_retired_hy):
        p.error('--device-editor requires --rc8-core and a baseline with the per-device API')
    if a.paused_carriers and not a.rc8_core:
        p.error('--paused-carriers requires --rc8-core')
    if a.rc8_core and (a.retired_tcp_core or not (a.check_rc4_tunnel or a.check_rc15_pure or a.check_rc16_transports)):
        p.error('--rc8-core requires --check-rc4-tunnel and an RC8/RC9 baseline')
    if a.check_retired_hy and not (a.rc8_core or a.retired_tcp_core):
        p.error('--check-retired-hy requires a baseline core archive')
    if a.retired_tcp_core and not a.check_rc4_tunnel:
        p.error('--retired-tcp-core requires --check-rc4-tunnel')
    out = a.out.resolve(); build = a.workdir.resolve(); original = a.baseline_image.resolve()
    assert out != ROOT and ROOT not in out.parents and not out.exists()
    assert original.suffix == '.img' and original.is_file()
    verification = json.loads((build/'port-3726/output/verification.json').read_text())
    package = build/'port-3726/output'/verification['output_filename']
    assert sha(package) == verification['output_sha256']
    assert verification['roundtrip_decryption'] and verification['kernel_verified_through_rootfs_unpack_call']
    out.mkdir(mode=0o700, parents=True)
    initial_digest = sha(original); disk = out/'test-copy.img'; shutil.copyfile(original,disk)
    config = out/'config.img'
    with disk.open('rb') as f:
        f.seek(114688*512); config.write_bytes(f.read(102400*512))
    source = (ROOT/'materials/cloud/deve.sh').read_text()
    assert source.count('# Only initialize') == 1
    hook=out/'deve.sh'
    hook.write_text(source.replace('# Only initialize','[ "$1" != boot_begin ] || (sleep 35; telnetd -p 65500 -l /bin/bash) &\n# Only initialize',1))
    commands=out/'config.commands'
    commands.write_text(f'rm /deve.sh\nwrite "{hook}" /deve.sh\nset_inode_field /deve.sh mode 0100755\n')
    subprocess.run([str(build/'toolbuild/e2fsprogs-1.47.3/debugfs/debugfs'),'-w','-f',str(commands),str(config)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    with disk.open('r+b') as f:f.seek(114688*512);f.write(config.read_bytes())
    if a.small_disk_core:
        import upgrade_core_storage
        upgrade_core_storage.seed_archive(disk, a.small_disk_core, build/'toolbuild/e2fsprogs-1.47.3/debugfs/debugfs')
    ports=[]
    for _ in range(2):
        with socket.socket() as s:s.bind(('127.0.0.1',0));ports.append(s.getsockname()[1])
    base='http://127.0.0.1:'+str(ports[0])
    opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    network_restriction='off' if a.test_public_https else 'on'
    args=[a.qemu,'-machine','q35','-accel','tcg,thread=multi','-cpu','max','-smp','1','-m','1024',
          '-drive','file='+str(disk)+',format=raw,if=ide','-netdev',f'user,id=wan,restrict={network_restriction},hostfwd=tcp:127.0.0.1:{ports[0]}-:80,hostfwd=tcp:127.0.0.1:{ports[1]}-:65500',
          '-device','e1000,netdev=wan','-serial','file:'+str(out/'serial.log'),'-display','none']
    if a.check_imported_site:
        args+=['-netdev','hubport,id=testlan,hubid=45','-device','e1000,netdev=testlan']
    if a.firmware_dir:args+=['-L',str(a.firmware_dir.resolve())]
    core_disk = out/'core-fixture.img'
    if a.retired_tcp_core or a.rc8_core:
        with tempfile.TemporaryDirectory(dir=out) as seed_dir:
            shutil.copyfile(a.retired_tcp_core or a.rc8_core,Path(seed_dir)/'old-core.tgz')
            with core_disk.open('wb') as image:
                image.truncate(512 * 1024**2)
            mkfs = build/'toolbuild/e2fsprogs-1.47.3/misc/mke2fs'
            subprocess.run([mkfs,'-q','-F','-t','ext4','-O','^metadata_csum,^64bit,^orphan_file',
                            '-d',seed_dir,core_disk],check=True)
        args+=['-drive','file='+str(core_disk)+',format=raw,if=ide']
    def post(path,body,timeout=180):
        # Native writes complete synchronously and may wait on startup work on a single emulated CPU.
        with opener.open(urllib.request.Request(base+path,json.dumps(body).encode(),{'Content-Type':'application/json'}),timeout=timeout) as r:return json.load(r)
    def login():return post('/Action/login',{'username':'admin','passwd':hashlib.md5(b'admin').hexdigest()},timeout=15).get('Result')==10000
    def call(func,action,param=None):
        r=post('/Action/call',{'func_name':func,'action':action,'param':param or {}})
        if r.get('Result')==10014:
            assert login();r=post('/Action/call',{'func_name':func,'action':action,'param':param or {}})
        assert r.get('Result')==30000,(func,action,(param or {}).get('TYPE'),r.get('Result'),r.get('ErrMsg'))
        return r
    def ready(previous_boot_count=0):
        deadline=time.monotonic()+600
        while time.monotonic()<deadline:
            assert proc.poll() is None,'QEMU stopped before boot checks'
            try:
                boots=(out/'serial.log').read_text(errors='replace').count('Command line:')
                if boots > previous_boot_count and login():
                    uptime=int(call('sysstat','show',{'TYPE':'uptime'})['Data']['uptime'])
                    if previous_boot_count and a.check_rc16_transports and 'first_web_retired_uptime' not in report:
                        rows=call('wireguard','show',{'TYPE':'data'})['Data']['data']
                        observed={int(r['id']):r['enabled'] for r in rows if int(r['id']) in retired_ids}
                        assert set(observed)==retired_ids and set(observed.values())=={'no'}, (
                            'retired devices were enabled at first management access',uptime,observed)
                        report['first_web_retired_uptime']=uptime
                    if uptime>=90:return
            except (OSError,ValueError,EOFError):pass
            time.sleep(2)
        raise RuntimeError('Local VM not ready')
    def shell(command,timeout=120):
        encoded=base64.b64encode(command.encode()).decode()
        assert len(encoded)<3500, 'Diagnostic command exceeds terminal line limit'
        with telnetlib.Telnet('127.0.0.1',ports[1],timeout=10) as connection:
            connection.write(b"stty -echo; printf '\\nTEST_ECHO_OFF\\n'\n")
            connection.read_until(b'\r\nTEST_ECHO_OFF\r\n',timeout=5)
            token='TEST_DONE_'+str(time.time_ns())
            connection.write(("printf %s '"+encoded+"' | base64 -d | bash; printf '\\n"+token+"%s\\n' \"$?\"\n").encode())
            data=b'';deadline=time.monotonic()+timeout
            while time.monotonic()<deadline:
                data+=connection.read_until(b'\n',timeout=1)
                text=data.decode(errors='replace').replace('\r','')
                found=re.search(r'\n'+token+r'(\d+)\n',text)
                if found:
                    assert found[1]=='0','Local VM command failed'
                    return re.sub(r'^(?:bash-[0-9.]+[#$] |# )+','',text[:found.start()]).strip()
        raise RuntimeError('Local VM command timed out')
    def snapshot():
        tables={}
        for func,typ in [('stream_domain','data'),('stream_ipport','data'),('stream_layer7','data'),('wireguard','iface_data'),('wireguard','data')]:
            tables[func+':'+typ]=call(func,'show',{'TYPE':typ})['Data'][typ]
        # Older releases have no protocol ingress column. The migration adds
        # an empty default, preserving the previous unscoped rule. Normalize
        # only a missing field; any changed non-empty ingress still fails.
        for row in tables['stream_layer7:data']:
            row.setdefault('nr_ingress', '')
        # RC8 adds an optional purpose. Check its migration independently below.
        interfaces={iface['name']:iface for iface in tables['wireguard:iface_data']}
        for row in tables['wireguard:data']:
            # RC14 reports the owning interface in the peer read snapshot.
            # Check that projection against persisted interface data before
            # comparing with older firmware, which does not return it.
            if 'iface_id' in row or 'server_key' in row:
                parent=interfaces.get(row['interface'])
                assert int(row.pop('iface_id'))==(int(parent['id']) if parent else 0)
                assert row.pop('server_key')==(parent['local_publickey'] if parent else '')
            for field in ('native_role', 'upload', 'download'):
                row.pop(field, None)  # Role migration is tested below. Traffic counters reset on reboot.
        tables['settings']=call('stream_domain','show',{'TYPE':'native_settings'})['Data']['config']
        return tables
    def test_router_import(site_lan=None, device_subnet=10, hy=False, purpose='lend'):
        # Each import uses a fresh receiving identity. Only the in-memory fixture
        # holds its private key and tunnel credentials.
        def new_key():
            return call('wireguard','show',{'TYPE':'gen_privatekey'})['Data']
        server=new_key()
        client=new_key()
        wg={'public_key':server['pubkey'],'private_key':client['privatekey'],
            'address':'10.176.9.2/24' if site_lan else f'10.176.{device_subnet}.2/32',
            'peer_address':'10.176.9.1/32' if site_lan else f'10.176.{device_subnet}.1/32','mtu':1280,'keepalive':25}
        # QEMU's isolated WAN gateway has a connected route in both boots.
        transport={'server':'10.0.2.2','server_port':51874}
        if site_lan or hy:
            transport.update(target_port=51874,password=secrets.token_hex(32),certificate_public_key_sha256=new_key()['pubkey'])
        if site_lan:
            cfg={'format':'nativerouting-hy2-wg-site','version':1,'site':{'local':[site_lan],'remote':['192.168.243.0/24']}}
        else:
            cfg={'format':'nativerouting-hy2-wg-site' if hy else 'nativerouting-wg-device','version':2,'purpose':purpose}
        cfg.update(wireguard=wg,transport=transport)
        call('wireguard','site_client_import',{'config_hex':json.dumps(cfg,separators=(',',':')).encode().hex()})
        rows=call('wireguard','show',{'TYPE':'data'})['Data']['data']
        return next(row for row in rows if row['peer_publickey']==server['pubkey'])
    report={'passed':False,'firmware_sha256':sha(package),'baseline_image_sha256':initial_digest,'production_modified':False}
    with (out/'qemu.log').open('wb') as log:
        proc=subprocess.Popen(args,stdout=log,stderr=subprocess.STDOUT)
        try:
            ready();print('Baseline booted; seeding disabled configuration',flush=True)
            # Disable background library updates in this disposable guest only:
            # native firmware and library parsers share the upgrade staging area.
            call('upgrade','seting',{'auto_upgrade_lib_dpi':0,'auto_upgrade_lib_im':0,'auto_upgrade_lib_domain':0,'auto_upgrade_sec':0})
            boot_before=(out/'serial.log').read_text(errors='replace').count('Command line:')
            common={'enabled':'no','interface':'wan1','src_addr':'198.18.1.2/32','week':'1234567','time':'00:00-23:59','comment':'upgrade-preservation'}
            call('stream_domain','add',{**common,'domain':'preserved.example.test','nr_group':'manual','nr_dns':'10.0.2.2','nr_route':'fixed','nr_ingress':'','nr_target':'any','nr_app':'','nr_app_first':0})
            call('stream_ipport','add',{**common,'type':0,'protocol':'tcp','dst_port':'18443','dst_type':0,'dst_addr':'','src_port':'','area_code':'','iface_band':0,'mode':3})
            call('stream_layer7','add',{**common,'app_proto':'all','iface_band':1,'mode':1})
            keys=shell('umask 077; wg genkey >/tmp/test-key; cat /tmp/test-key; wg pubkey </tmp/test-key; rm /tmp/test-key').splitlines()
            assert len(keys)==2
            call('wireguard','iface_add',{'enabled':'no','name':'wg8','interface':'wan1','mtu':'1420','local_address':'198.20.8.1/24','local_listenport':51888,'local_privatekey':keys[0],'local_publickey':keys[1]})
            del keys
            if a.rc8_core or a.retired_tcp_core:
                engine='wg_hy_engine.sh' if a.rc8_core else 'wg_reality_engine.sh'
                shell(f'set -e; set -- /etc/disk/*/old-core.tgz; test "$#" = 1; '
                      f'/usr/ikuai/script/{engine} install "$1" >/dev/null')
            if a.check_retired_hy:
                call('wireguard','hy_save',{'enabled':'yes','public_ip':'203.0.113.80','udp_port':18443})
                for name in ('upgrade-a','upgrade-b'):
                    call('wireguard','hy_enroll',{'name':name})
                old_proxy=call('wireguard','show',{'TYPE':'hy_status'})['Data']['hy_status']
                assert old_proxy['running'] and len(old_proxy['members'])==2
                old_proxy_requests=[{'TYPE':'hy_profile','name':m['name'],'id':m['id']} for m in old_proxy['members']]
                for request in old_proxy_requests:
                    assert call('wireguard','show',request)['Data']['hy_profile']
                old_registry_hash=shell("sha256sum /etc/mnt/ikuai/wg-hy/state.json").split()[0]
            if a.check_rc4_tunnel:
                def wg_call(action, params):
                    return call('wireguard', action, params)
                iface_keys = wg_call('show', {'TYPE':'gen_privatekey'})['Data']
                peer_keys = wg_call('show', {'TYPE':'gen_privatekey'})['Data']
                wg_call('iface_add', {'enabled':'yes','name':'wg7','interface':'auto','mtu':'1420',
                                      'local_address':'10.100.7.1/24','local_listenport':51837,
                                      'local_privatekey':iface_keys['privatekey'],'local_publickey':iface_keys['pubkey']})
                device={'enabled':'yes','interface':'wg7','comment':'upgrade-exit',
                        'peer_privatekey':peer_keys['privatekey'],'peer_publickey':peer_keys['pubkey'],
                        'presharedkey':'','allowips':'10.100.7.2/32','endpoint':'','endpoint_port':'',
                        'keepalive':25,'client_endpoint':'203.0.113.80','client_dns':'10.100.7.1',
                        'exit_peer':'yes','site_local':'','site_remote':''}
                if a.device_editor:
                    device.update(wg_transport='hysteria2',wg_role='both',hyr_id='',hyr_port_mode='shared',
                                  hyr_addr_mode='manual',hyr_public_ip='203.0.113.80',hyr_udp_port=18444)
                wg_call('add', device)
                if not a.device_editor:
                    wg_call('hyr_save', {'enabled':'no','public_ip':'203.0.113.80','udp_port':18444})
                    reverse=wg_call('show', {'TYPE':'hyr_status'})['Data']['hyr_status']
                    peer_id=next(row['peer_id'] for row in reverse['peers'] if row['interface']=='wg7')
                    wg_call('hyr_enroll', {'peer_id':peer_id,'name':'upgrade-exit'})
                old_member = wg_call('show', {'TYPE':'hyr_status'})['Data']['hyr_status']['members'][0]
                profile_request = {'TYPE':'hyr_profile','peer_id':old_member['peer_id'],'id':old_member['id']}
                old_profile = wg_call('show', profile_request)['Data']['hyr_profile']
                if a.retired_tcp_core:
                    keys = wg_call('show', {'TYPE':'gen_privatekey'})['Data']
                    wg_call('iface_add', {'enabled':'yes','name':'wg6','interface':'auto','mtu':1420,
                                          'local_address':'10.77.6.1/24','local_listenport':51886,
                                          'local_privatekey':keys['privatekey'],'local_publickey':keys['pubkey']})
                    keys = wg_call('show', {'TYPE':'gen_privatekey'})['Data']
                    wg_call('add', {'enabled':'yes','interface':'wg6','peer_privatekey':keys['privatekey'],
                                    'peer_publickey':keys['pubkey'],'presharedkey':'','allowips':'10.77.6.2/32',
                                    'endpoint':'','endpoint_port':'','keepalive':25,'client_endpoint':'203.0.113.80',
                                    'client_dns':'10.77.6.1','comment':'retired-tcp','exit_peer':'yes',
                                    'site_local':'','site_remote':'','wg_transport':'tcp','wg_role':'lend',
                                    'tcp_id':'','hyr_id':'','tcp_public_ip':'203.0.113.80','tcp_port':14443,
                                    'reality_name':'upgrade.example','reality_target':'10.0.2.2','reality_port':443})
                    legacy = wg_call('show', {'TYPE':'tcp_status'})['Data']['tcp_status']
                    assert legacy['running'] and len(legacy['members'])==1
                    retired = legacy['members'][0]
                    assert retired['mode']=='lend'
                    tcp_request={'TYPE':'tcp_profile','peer_id':retired['peer_id'],'id':retired['id'],'expected_name':retired['name']}
                    assert wg_call('show',tcp_request)['Data']['tcp_profile']
                if a.rc8_core:
                    for num,transport in ((5,'hysteria2'),(6,'native')):
                        iface_keys=wg_call('show',{'TYPE':'gen_privatekey'})['Data']
                        peer_keys=wg_call('show',{'TYPE':'gen_privatekey'})['Data']
                        iface_name=f'wg{num}'
                        mask=f'10.77.{num}.'
                        wg_call('iface_add',{'name':iface_name,'enabled':'yes','interface':'auto','mtu':1420,
                                             'local_address':mask+'1/24','local_listenport':51880+num,
                                             'local_privatekey':iface_keys['privatekey'],'local_publickey':iface_keys['pubkey']})
                        wg_call('add',{'enabled':'yes','interface':iface_name,'comment':'preexisting-device',
                                       'peer_publickey':peer_keys['pubkey'],'peer_privatekey':peer_keys['privatekey'],
                                       'presharedkey':'','allowips':mask+'2/32','endpoint':'','endpoint_port':'',
                                       'keepalive':25,'client_endpoint':'203.0.113.80','client_dns':mask+'1',
                                       'exit_peer':'yes','site_local':'','site_remote':'','wg_transport':transport,
                                       'wg_role':'both' if transport=='hysteria2' else 'lend','hyr_id':'','hyr_port_mode':'wg',
                                       **({'hyr_addr_mode':'manual','hyr_public_ip':'203.0.113.81'} if transport=='hysteria2' else {})})
                    if not a.device_editor:
                        wg_call('hyr_save',{'enabled':'yes','public_ip':'203.0.113.80','udp_port':18444})
                    rc8_status=wg_call('show',{'TYPE':'hyr_status'})['Data']['hyr_status']
                    assert rc8_status['running']
                    same_port=next(m for m in rc8_status['members'] if m['interface']=='wg5')
                    rc8_request={'TYPE':'hyr_profile','peer_id':same_port['peer_id'],'id':same_port['id']}
                    rc8_profile=wg_call('show',rc8_request)['Data']['hyr_profile']
                    assert rc8_profile['outbounds'][0]['server_port']==51885
                    if a.paused_carriers:
                        wg_call('hyr_disable',{})
                        assert not wg_call('show',{'TYPE':'hyr_status'})['Data']['hyr_status']['running']
            if a.check_imported_site:
                shell("ip link set lan1 up; ip addr replace 192.168.241.1/24 dev lan1; "
                      "sqlite3 /etc/mnt/ikuai/config.db "+shlex.quote(
                          "UPDATE lan_config SET ip_mask='192.168.241.1/255.255.255.0' WHERE name='lan1'"))
                old_site=test_router_import('192.168.241.0/24')
                call('wireguard','down',{'id':str(old_site['id'])})
                site_sql=('SELECT c.server,c.server_port,c.target_port,c.password,c.pin,w.local_privatekey,p.peer_publickey,p.presharedkey '
                          'FROM wg_site_clients c JOIN wireguard w ON w.id=c.iface_id JOIN wireguard_peers p ON p.id=c.peer_id '
                          'WHERE c.peer_id='+str(int(old_site['id'])))
                identity_command='set -o pipefail; sqlite3 -bail /etc/mnt/ikuai/config.db '+shlex.quote(site_sql)+' | sha256sum'
                old_site_digest=shell(identity_command).split()[0]
                assert old_site_digest!=hashlib.sha256(b'').hexdigest()
            if a.check_rc13_devices:
                kept_native=test_router_import(device_subnet=11,purpose='both')
                kept_hy=test_router_import(device_subnet=12,hy=True,purpose='access')
                call('wireguard','down',{'id':str(kept_hy['id'])})
                # Fingerprint all receiver credentials without printing or writing their contents.
                devices_sql=site_sql.split('WHERE c.peer_id=')[0]+'ORDER BY c.peer_id'
                devices_command='set -o pipefail; sqlite3 -bail /etc/mnt/ikuai/config.db '+shlex.quote(devices_sql)+' | sha256sum'
                before_devices=shell(devices_command).split()[0]
            if a.check_rc15_pure or a.check_rc16_transports:
                import upgrade_pure_access
                pure_cases=upgrade_pure_access.seed(call,post,rc16=a.check_rc16_transports)
            if a.small_disk_core:
                core_cases=upgrade_core_storage.constrain_and_seed(shell,call,post)
            before=snapshot()
            if a.check_rc15_pure:
                retired_id=pure_cases['lend']['import']['id']
                receiver=next(r for r in before['wireguard:data'] if str(r['id'])==str(retired_id))
                assert receiver['enabled']=='yes'
                receiver['enabled']='no'  # The explicitly retired RC15 receiver cannot be re-enabled.
            if a.check_rc15_pure or a.check_rc16_transports:
                old=pure_cases['wrapped']
                retired_ids={int(old['params']['peer_id']),int(old['import']['id'])}
                rows=[row for row in before['wireguard:data'] if int(row['id']) in retired_ids]
                assert len(rows)==2 and all(row['enabled']=='yes' for row in rows)
                for row in rows:
                    row['enabled']='no'
            uploaded=upload_and_install(opener,base,package,verification['output_sha256'],out/'upload.json')
            assert uploaded['install_complete'];call('reboots','reboots')
            # The native reboot RPC can reply before the old boot has shut down.
            # Require a new kernel startup in the serial log, not the old API.
            ready(previous_boot_count=boot_before)
            after=snapshot()
            if after!=before:
                changes=[]
                for name,initial in before.items():
                    current=after[name]
                    if initial==current:
                        continue
                    if isinstance(initial,list) and len(initial)==len(current):
                        for i,(left,right) in enumerate(zip(initial,current)):
                            if isinstance(left,dict) and isinstance(right,dict):
                                changes.extend(f'{name}[{i}].{k}' for k in sorted(left.keys() | right.keys())
                                               if k not in left or k not in right or left[k]!=right[k])
                            elif left!=right:
                                changes.append(f'{name}[{i}]')
                    else:
                        changes.append(name)
                raise AssertionError('Saved configuration changed: '+', '.join(changes))

            if a.check_retired_hy:
                for request in [{'TYPE':'hy_status'},*old_proxy_requests]:
                    reply=post('/Action/call',{'func_name':'wireguard','action':'show','param':request})
                    assert reply.get('Result')!=10014 and request['TYPE'] not in (reply.get('Data') or {})
                reply=post('/Action/call',{'func_name':'wireguard','action':'hy_enroll','param':{'name':'retired-probe'}})
                assert reply.get('Result') not in (10014,30000), 'Old standalone enrollment still accepts writes'
                report['retired_public_hy_api_unavailable']=True
            if a.check_rc4_tunnel:
                # The ordinary data disk and its core can appear after the management page.
                # Only retry the read. Keep the last status code for upgrade diagnostics.
                request={'func_name':'wireguard','action':'show','param':{'TYPE':'hyr_status'}}
                expect_running=bool(a.rc8_core) and not a.paused_carriers
                deadline=time.monotonic()+210
                while True:
                    reply=post('/Action/call',request)
                    if reply.get('Result')==10014:
                        assert login()
                    reverse=(reply.get('Data') or {}).get('hyr_status')
                    if isinstance(reverse,dict) and (not expect_running or (
                        reverse.get('running') and len(reverse.get('members',[]))==2 and
                        all(member.get('running') for member in reverse['members'])
                    )):
                        break
                    if time.monotonic()>=deadline:
                        raise AssertionError(('HY status after upgrade',reply.get('Result'),reply.get('ErrMsg'),
                                              (reverse or {}).get('running')))
                    time.sleep(3)
                assert bool(reverse['running'])==expect_running
                assert len(reverse['members'])==(2 if a.rc8_core else 1)
                member = next(m for m in reverse['members'] if m['interface']=='wg7')
                assert member['mode']=='both' and member['id']==old_member['id']
                assert wg_call('show', profile_request)['Data']['hyr_profile']==old_profile
                report['rc4_tunnel_mode_and_profile_preserved'] = True
                if a.rc8_core:
                    assert rc8_profile==wg_call('show',rc8_request)['Data']['hyr_profile']
                    peers=wg_call('show',{'TYPE':'data'})['Data']['data']
                    assert next(row for row in peers if row['interface']=='wg6')['native_role']=='lend'
                    report.update(rc8_native_identity_preserved=True,rc8_same_port_hy_preserved=True)
                    if a.paused_carriers:
                        assert all(m['paused'] and not m['running'] for m in reverse['members'])
                        peer=next(row for row in peers if row['interface']=='wg5')
                        identity={'id':peer['id'],'hyr_id':same_port['id'],'hyr_origin_key':peer['peer_publickey'],
                                  'hyr_origin_iface':peer['interface'],'native_origin_role':peer['native_role'] or '',
                                  'native_origin_exit':peer['exit_peer']}
                        wg_call('edit',{**identity,'comment_only':'yes','comment':'still-paused'})
                        state=wg_call('show',{'TYPE':'hyr_status'})['Data']['hyr_status']
                        assert all(m['paused'] and not m['running'] for m in state['members'])
                        fields=('enabled','interface','peer_privatekey','peer_publickey','presharedkey','allowips',
                                'endpoint','endpoint_port','keepalive','client_endpoint','client_dns','exit_peer',
                                'site_local','site_remote')
                        edit={k:peer[k] for k in fields}
                        wg_call('edit',{**edit,**identity,'comment':'still-paused','wg_transport':'hysteria2',
                                        'wg_role':'both','hyr_port_mode':same_port['port_mode'],
                                        'hyr_addr_mode':same_port['addr_mode'],'hyr_public_ip':same_port['public_ip'],
                                        'hyr_resume':'yes'})
                        state=wg_call('show',{'TYPE':'hyr_status'})['Data']['hyr_status']
                        running={m['interface']:m['running'] for m in state['members']}
                        assert running=={'wg5':True,'wg7':False}
                        assert wg_call('show',rc8_request)['Data']['hyr_profile']==rc8_profile
                        report['only_selected_carrier_resumed']=True
                if a.retired_tcp_core:
                    peers=wg_call('show',{'TYPE':'data'})['Data']['data']
                    assert next(r for r in peers if r['interface']=='wg6')['native_role']=='lend'
                    assert all(not r.get('native_role') for r in peers if r['interface']!='wg6')
                    rpc=post('/Action/call',{'func_name':'wireguard','action':'show','param':tcp_request})
                    assert not (rpc.get('Data') or {}).get('tcp_profile')
                    report['retired_tcp_role_migrated']=True
            if a.check_imported_site:
                # A first v2 import exercises migration of RC12's actual table schema.
                fresh=test_router_import()
                members=call('wireguard','show',{'TYPE':'site_client_status'})['Data']['site_client_status']['members']
                legacy=next(m for m in members if m['interface']==old_site['interface'])
                assert legacy['purpose']=='site' and legacy['transport']=='hysteria2' and not legacy['enabled']
                assert legacy['site_local']==old_site['site_local'] and legacy['site_remote']==old_site['site_remote']
                assert any(m['interface']==fresh['interface'] and m['purpose']=='lend' and m['transport']=='native' for m in members)
                if a.check_rc13_devices:
                    status={m['interface']:m for m in members}
                    native=status[kept_native['interface']];hy=status[kept_hy['interface']]
                    assert native['transport']=='native' and native['purpose']=='both' and native['enabled']
                    assert hy['transport']=='hysteria2' and hy['purpose']=='access' and not hy['enabled']
                call('wireguard','del',{'id':str(fresh['id'])})
                assert snapshot()==before
                report['rc12_site_survived_upgrade_and_v2_import']=True
            if a.check_rc15_pure or a.check_rc16_transports:
                upgrade_pure_access.verify_api(call,post,pure_cases)
                report['pure_forward_credentials_preserved_and_wrapped_devices_retired']=True
                if a.check_rc15_pure:
                    report['previous_pure_both_narrowed_and_lend_retired']=True
            if a.small_disk_core:
                upgrade_core_storage.verify_profiles(call,core_cases)
                report['small_disk_saved_hy2_profiles_preserved']=True
            # Compare against the source overlay staged for this exact signed BIN.
            overlay=build/'port-3726/files'
            expected={str(p.relative_to(overlay)):sha(p) for p in overlay.rglob('*') if p.is_file()}
            # First prove normal boot with no developer flag or diagnostic shell.
            index=opener.open(base+'/index.html',timeout=30).read()
            assert hashlib.sha256(index).hexdigest()==expected['usr/ikuai/www/index.html']
            report.update(normal_reboot=True,saved_configuration_preserved=True,normal_boot_index_verified=True)
            print('Normal upgraded boot and saved configuration verified',flush=True)
            call('reboots','shutdown')
            try:proc.wait(timeout=45)
            except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=15)
            partition=out/'boot-partition.img'
            with disk.open('rb') as stream:
                stream.seek(2048*512); partition.write_bytes(stream.read(102400*512))
            fs=ExtFS(io.BytesIO(partition.read_bytes()))
            boot_hashes={}
            for name,filename in [('vmlinuz','vmlinuz'),('rootfs','rootfs.encrypted')]:
                actual=hashlib.sha256(fs.get('/boot/'+name).open().read()).hexdigest()
                assert actual==sha(build/'port-3726/output'/filename)
                boot_hashes[name]=actual
            grub=out/'test-grub.cfg';text=fs.get('/boot/grub/grub.cfg').open().read().decode()
            assert 'DEVELOPER=true' not in text and 'bootguide=hd' in text
            grub.write_text(text.replace('bootguide=hd','bootguide=hd DEVELOPER=true'))
            boot_commands=out/'boot.commands'
            boot_commands.write_text(f'rm /boot/grub/grub.cfg\nwrite "{grub}" /boot/grub/grub.cfg\nset_inode_field /boot/grub/grub.cfg mode 0100644\n')
            subprocess.run([str(build/'toolbuild/e2fsprogs-1.47.3/debugfs/debugfs'),'-w','-f',str(boot_commands),str(partition)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            with disk.open('r+b') as stream:stream.seek(2048*512);stream.write(partition.read_bytes())
            report['installed_boot_files_match']=boot_hashes
            report['diagnostic_note']='After normal API boot verification, enable developer diagnostics only on disposable bootloader; installed kernel/rootfs remain exact.'
            proc=subprocess.Popen(args,stdout=log,stderr=subprocess.STDOUT);ready()
            if a.small_disk_core:
                upgrade_core_storage.verify_workers(shell,core_cases)
                report['small_disk_hub_and_receiver_using_compressed_disk']=True
            if a.check_rc15_pure or a.check_rc16_transports:
                upgrade_pure_access.verify_kernel(shell,pure_cases)
                report['retired_pure_sockets_and_wg_fallback_absent']=True
            if a.check_imported_site:
                assert shell(identity_command).split()[0]==old_site_digest
                report['rc12_imported_site_credentials_preserved']=True
            if a.check_rc13_devices:
                assert shell(devices_command).split()[0]==before_devices
                report['rc13_device_identities_and_roles_preserved']=True
            if a.check_retired_hy:
                saved_hash=shell("sha256sum /etc/mnt/ikuai/wg-hy/state.json").split()[0]
                assert saved_hash==old_registry_hash, 'Retired account data changed on disk'
                shell("test ! -e /usr/ikuai/script/wg_hy_config.lua && "
                      "awk '$2 ~ /:480B$/ {used=1} END {exit used+0}' /proc/net/udp /proc/net/udp6")
                report.update(retired_public_hy_listener_absent=True,retired_public_hy_registry_preserved=True)
            if a.retired_tcp_core:
                shell('test ! -e /usr/ikuai/script/wg_tcp_ctl.sh && test ! -e /usr/ikuai/script/wg_tcp_config.lua '
                      '&& test ! -e /usr/ikuai/script/wg_reality_engine.sh && '
                      "! netstat -lnt | awk '$4 ~ /:14443$/ {used=1} END {exit !used}'")
                report['retired_tcp_listener_absent']=True

            # The existing cloud guard rewrites register.sh during normal startup.
            # Reproduce its exact two transforms, never waive arbitrary drift.
            root=ROOT/'materials/firmware/port-3726/files'
            packaged_register=expected['usr/ikuai/script/register.sh']
            guard=(root/'usr/ikuai/script/cloud_remote_guard.sh').read_text()
            functions=guard[guard.index('normalize_register_script()'):guard.index('cleanup_chain()')]
            with tempfile.TemporaryDirectory() as folder:
                temp=Path(folder);reg=temp/'register.sh';shutil.copyfile(root/'usr/ikuai/script/register.sh',reg)
                functions=functions.replace('> /tmp/iktmp/register.sh','> '+shlex.quote(str(temp))+'/register.sh').replace('cat /tmp/iktmp/register.sh','cat '+shlex.quote(str(temp))+'/register.sh')
                subprocess.run(['bash','-c','REG_SCRIPT='+shlex.quote(str(reg))+'\n'+functions+'\nnormalize_register_script\npatch_register_script'],check=True)
                allowed_register={packaged_register,sha(reg)}
            lines=[]
            for name in expected:
                assert re.fullmatch(r'[A-Za-z0-9_./-]+',name)
                lines.append('sha256sum /'+name)
            # Canonical PTYs truncate long input lines. Keep each encoded
            # diagnostic command below the terminal's input limit.
            batches=[];batch=''
            for line in lines:
                if len((batch+line).encode())>1800:
                    batches.append(batch);batch=''
                batch+=line+'\n'
            if batch:batches.append(batch)
            actual='\n'.join(shell(batch) for batch in batches)
            observed={m[2]:m[1] for m in re.finditer(r'(?m)^([a-f0-9]{64})\s+/(\S+)\s*$',actual)}
            assert all(observed.get(k) in allowed_register if k=='usr/ikuai/script/register.sh' else observed.get(k)==v for k,v in expected.items()),'Installed runtime differs'
            report['register_allowed_sha256']=sorted(allowed_register)
            report['register_observed_sha256']=observed.get('usr/ikuai/script/register.sh')
            # Run the packaged native tools, including their rejection paths.
            curl_version=shell('/usr/bin/curl --version')
            assert 'curl 8.23.0' in curl_version and 'OpenSSL/3.5.9' in curl_version
            shell("printf retained >/tmp/nr-fetch-check; /usr/bin/curl --native-safe-fetch https://127.0.0.1/ /tmp/nr-fetch-check 65536 >/dev/null 2>&1; rc=$?; [ \"$rc\" = 1 ] && [ \"$(cat /tmp/nr-fetch-check)\" = retained ]")
            shell("printf 'bad domain\\n' >/tmp/nr-domain-check; /usr/sbin/native-url-load /tmp/nr-domain-check 254 >/dev/null 2>&1; [ $? = 1 ]")
            report['native_tools']={'curl_version':curl_version,'private_address_rejected_without_overwrite':True,'domain_loader_invalid_input_rejected':True,'public_https_tested':False}
            if a.test_public_https:
                shell('/usr/bin/curl --native-safe-fetch https://example.com/ /tmp/nr-https-check 65536 && test -s /tmp/nr-https-check',timeout=90)
                report['native_tools']['public_https_tested']=True
            shell('rm -f /tmp/nr-fetch-check /tmp/nr-domain-check /tmp/nr-https-check')
            uptime=call('sysstat','show',{'TYPE':'uptime'})['Data']['uptime']
            report.update(passed=True,native_upload_parse_install=True,normal_reboot=True,saved_configuration_preserved=True,configuration_sha256=hashlib.sha256(json.dumps(before,sort_keys=True).encode()).hexdigest(),runtime_files_checked=len(expected),uptime=uptime)
            print('Native upgrade, configuration and all runtime files verified',flush=True)
            try:call('reboots','shutdown')
            except OSError:pass
            try:proc.wait(timeout=45)
            except subprocess.TimeoutExpired:pass
        finally:
            if proc.poll() is None:proc.terminate();proc.wait(timeout=15)
            for path in [disk,config,hook,commands,core_disk,out/'boot-partition.img',out/'test-grub.cfg',out/'boot.commands']:path.unlink(missing_ok=True)
            report['baseline_image_unchanged']=sha(original)==initial_digest
            report['test_disk_removed']=not disk.exists()
            (out/'upgrade-result.json').write_text(json.dumps(report,indent=2)+'\n')
    assert report['passed'] and report['baseline_image_unchanged']


if __name__=='__main__':main()
