#!/usr/bin/env python3
"""Native upgrade/configuration/runtime checks in a newly launched localhost VM only.

The test shell is added to a disposable configuration partition. It is never
written to the release image or firmware. No destination URL can be supplied.
Requires Python 3.12 (telnetlib), QEMU and a completed tools/rebuild.py workdir.
"""
from pathlib import Path
import argparse, base64, hashlib, http.cookiejar, json, re, shutil, socket
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
    a = p.parse_args()
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
    ports=[]
    for _ in range(2):
        with socket.socket() as s:s.bind(('127.0.0.1',0));ports.append(s.getsockname()[1])
    base='http://127.0.0.1:'+str(ports[0])
    opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    network_restriction='off' if a.test_public_https else 'on'
    args=[a.qemu,'-machine','q35','-accel','tcg,thread=multi','-cpu','max','-smp','1','-m','1024',
          '-drive','file='+str(disk)+',format=raw,if=ide','-netdev',f'user,id=wan,restrict={network_restriction},hostfwd=tcp:127.0.0.1:{ports[0]}-:80,hostfwd=tcp:127.0.0.1:{ports[1]}-:65500',
          '-device','e1000,netdev=wan','-serial','file:'+str(out/'serial.log'),'-display','none']
    if a.firmware_dir:args+=['-L',str(a.firmware_dir.resolve())]
    def post(path,body):
        with opener.open(urllib.request.Request(base+path,json.dumps(body).encode(),{'Content-Type':'application/json'}),timeout=45) as r:return json.load(r)
    def login():return post('/Action/login',{'username':'admin','passwd':hashlib.md5(b'admin').hexdigest()}).get('Result')==10000
    def call(func,action,param=None):
        r=post('/Action/call',{'func_name':func,'action':action,'param':param or {}})
        if r.get('Result')==10014:
            assert login();r=post('/Action/call',{'func_name':func,'action':action,'param':param or {}})
        assert r.get('Result')==30000,(func,action,r.get('Result'))
        return r
    def ready(previous_boot_count=0):
        deadline=time.monotonic()+600
        while time.monotonic()<deadline:
            assert proc.poll() is None,'QEMU stopped before boot checks'
            try:
                if login() and int(call('sysstat','show',{'TYPE':'uptime'})['Data']['uptime'])>=90:
                    if (out/'serial.log').read_text(errors='replace').count('Command line:') > previous_boot_count:return
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
        tables['settings']=call('stream_domain','show',{'TYPE':'native_settings'})['Data']['config']
        return hashlib.sha256(json.dumps(tables,sort_keys=True).encode()).hexdigest()
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
            before=snapshot()
            uploaded=upload_and_install(opener,base,package,verification['output_sha256'],out/'upload.json')
            assert uploaded['install_complete'];call('reboots','reboots')
            # The native reboot RPC can reply before the old boot has shut down.
            # Require a new kernel startup in the serial log, not the old API.
            ready(previous_boot_count=boot_before)
            assert snapshot()==before,'Saved configuration changed'
            expected={str(p.relative_to(ROOT/'materials/firmware/port-3726/files')):sha(p) for p in (ROOT/'materials/firmware/port-3726/files').rglob('*') if p.is_file()}
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
            report.update(passed=True,native_upload_parse_install=True,normal_reboot=True,saved_configuration_preserved=True,configuration_sha256=before,runtime_files_checked=len(expected),uptime=uptime)
            print('Native upgrade, configuration and all runtime files verified',flush=True)
            try:call('reboots','shutdown')
            except OSError:pass
            try:proc.wait(timeout=45)
            except subprocess.TimeoutExpired:pass
        finally:
            if proc.poll() is None:proc.terminate();proc.wait(timeout=15)
            for path in [disk,config,hook,commands,out/'boot-partition.img',out/'test-grub.cfg',out/'boot.commands']:path.unlink(missing_ok=True)
            report['baseline_image_unchanged']=sha(original)==initial_digest
            report['test_disk_removed']=not disk.exists()
            (out/'upgrade-result.json').write_text(json.dumps(report,indent=2)+'\n')
    assert report['passed'] and report['baseline_image_unchanged']


if __name__=='__main__':main()
