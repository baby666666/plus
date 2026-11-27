#!/usr/bin/env python3
"""Exercise native HY2 reverse forwarding between two disposable firmware VMs.

Only copies of --image are booted. The diagnostic shell and echo target are
installed into those copies, never the original image or release payload. All
host listeners bind 127.0.0.1; guest traffic uses only the local QEMU gateways.
Requires Python 3.12, QEMU, a real Go compiler, and a completed rebuild workdir.
The image must contain the pinned offline HY2 core (cloud --hy2-core-archive).
Exit 3 means functional checks completed but the UI gate remains unverified or
blocked. Only an actual successful native browser check makes overall passed
true; an independently observed IPC denial is retained as a failed gate.
"""
from pathlib import Path
import argparse
import base64
import concurrent.futures
import hashlib
import http.cookiejar
import http.server
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import telnetlib
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MAPPING_PORTS = {'management': 18080, 'tcp': 18081, 'udp': 18082,
                 'denied': 18083, 'unreachable': 18084, 'conflict': 18085}
TARGET_TCP = 19092
TARGET_UDP = 19091
TARGET_CLOSED = 19093
FIXTURE_GO = r'''package main
import ("fmt"; "io"; "net"; "os"; "time")
func main() {
 if len(os.Args)<3 { panic("fixture arguments") }
 if os.Args[1]=="busy" {
  l,e:=net.Listen("tcp4","0.0.0.0:"+os.Args[2]);if e!=nil {panic(e)}
  fmt.Println("READY")
  for {c,e:=l.Accept();if e!=nil{return};c.Close()}
 }
 if os.Args[1]!="serve" || len(os.Args)!=4 {panic("fixture arguments")}
 l,e:=net.Listen("tcp4","127.0.0.1:"+os.Args[2]);if e!=nil {panic(e)}
 u,e:=net.ListenPacket("udp4","127.0.0.1:"+os.Args[3]);if e!=nil {panic(e)}
 go func(){b:=make([]byte,65535);for {n,a,e:=u.ReadFrom(b);if e!=nil{return};u.WriteTo(b[:n],a)}}()
 fmt.Println("READY")
 slots:=make(chan struct{},8)
 for {c,e:=l.Accept();if e!=nil{return};select {case slots<-struct{}{}:go func(){defer func(){<-slots;c.Close()}();c.SetDeadline(time.Now().Add(90*time.Second));b,e:=io.ReadAll(io.LimitReader(c,2<<20));if e==nil {c.Write(append(b,[]byte("\nHALF_CLOSE_OK\n")...))}}();default:c.Close()}}
}
'''


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def reserve_port(protocol='tcp'):
    kind = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, kind) as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def hex_json(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode().hex()


def wait_for(label, check, timeout=100, interval=2):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = check()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f'{label}: timed out')


class LocalFixture:
    def __init__(self, binary):
        self.prefix = '/reverse-test-' + secrets.token_hex(12)
        self.body = ('ordinary-hy2-' + secrets.token_hex(24)).encode()
        contents = {self.prefix + '/fixture': binary.read_bytes(),
                    self.prefix + '/ordinary': self.body}
        self.hits = []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = contents.get(self.path)
                if body is None:
                    self.send_error(404)
                    return
                owner.hits.append(self.path)
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def gateway(self):
        return f'http://10.0.2.2:{self.server.server_address[1]}{self.prefix}'

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class VM:
    def __init__(self, name, args, extra_forwards):
        self.name = name
        # Separate gateways keep the external fixture distinct from the
        # advertised HY2 entrance, which correctly rejects forwarding loops.
        self.gateway_ip = '10.0.3.2' if name == 'center' else '10.0.2.2'
        self.directory = args.out / name
        self.directory.mkdir(mode=0o700)
        self.disk = self.directory / 'test-copy.img'
        self.process = None
        self.log = None
        self.http_port = reserve_port()
        self.shell_port = reserve_port()
        self.base = f'http://127.0.0.1:{self.http_port}'
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        subprocess.run(['cp', '--reflink=auto', '--sparse=always', str(args.image), str(self.disk)], check=True)
        config = self.directory / 'config.img'
        with self.disk.open('rb') as stream:
            stream.seek(114688 * 512)
            data = stream.read(102400 * 512)
        assert len(data) == 102400 * 512, 'Configuration partition missing'
        config.write_bytes(data)
        source = (ROOT / 'materials/cloud/deve.sh').read_text()
        assert source.count('# Only initialize') == 1
        hook = self.directory / 'deve.sh'
        hook.write_text(source.replace('# Only initialize',
            '[ "$1" != boot_begin ] || (sleep 35; telnetd -p 65500 -l /bin/bash) &\n# Only initialize', 1))
        commands = self.directory / 'config.commands'
        commands.write_text(f'rm /deve.sh\nwrite "{hook}" /deve.sh\nset_inode_field /deve.sh mode 0100755\n')
        debugfs = args.workdir / 'toolbuild/e2fsprogs-1.47.3/debugfs/debugfs'
        subprocess.run([str(debugfs), '-w', '-f', str(commands), str(config)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with self.disk.open('r+b') as stream:
            stream.seek(114688 * 512)
            stream.write(config.read_bytes())
        config.unlink()
        commands.unlink()
        hook.unlink()
        forwards = [('tcp', self.http_port, 80), ('tcp', self.shell_port, 65500)] + extra_forwards
        network = ('user,id=wan,restrict=off,net=10.0.' + ('3' if name == 'center' else '2') + '.0/24') + ''.join(
            f',hostfwd={protocol}:127.0.0.1:{host}-:{guest}' for protocol, host, guest in forwards)
        command = [args.qemu, '-machine', 'q35', '-accel', 'tcg,thread=multi', '-cpu', 'max',
                   '-smp', '1', '-m', str(args.memory), '-drive', f'file={self.disk},format=raw,if=ide',
                   '-netdev', network, '-device', 'e1000,netdev=wan', '-serial',
                   f'file:{self.directory / "serial.log"}', '-display', 'none']
        if args.firmware_dir:
            command += ['-L', str(args.firmware_dir)]
        self.command = command

    def start(self):
        self.log = (self.directory / 'qemu.log').open('wb')
        self.process = subprocess.Popen(self.command, stdout=self.log, stderr=subprocess.STDOUT)

    def post(self, path, body, timeout=180):
        request = urllib.request.Request(self.base + path, json.dumps(body).encode(),
                                         {'Content-Type': 'application/json'})
        with self.opener.open(request, timeout=timeout) as response:
            return json.load(response)

    def login(self):
        return self.post('/Action/login', {'username': 'admin',
             'passwd': hashlib.md5(b'admin').hexdigest()}, timeout=15).get('Result') == 10000

    def request(self, function, action, parameters=None):
        request = {'func_name': function, 'action': action, 'param': parameters or {}}
        deadline = time.monotonic() + 180
        while True:
            response = self.post('/Action/call', request)
            if response.get('Result') == 10014:
                assert self.login(), f'{self.name}: local login failed'
                response = self.post('/Action/call', request)
            message = str(response.get('ErrMsg') or '')
            if response.get('Result') == 30006 and ('正在保存' in message or '正在恢复' in message):
                assert time.monotonic() < deadline, f'{self.name}: native controller remained busy'
                time.sleep(3)
                continue
            return response

    def call(self, function, action, parameters=None):
        start = time.monotonic()
        if action != 'show':
            print(f'{self.name}: applying native {function}.{action}', flush=True)
        response = self.request(function, action, parameters)
        assert response.get('Result') == 30000, (self.name, function, action,
            (parameters or {}).get('TYPE'), response.get('Result'), response.get('ErrMsg'))
        if action != 'show':
            print(f'{self.name}: native {function}.{action} completed in {time.monotonic() - start:.1f}s', flush=True)
        return response

    def wg(self, action, **fields):
        return self.call('wireguard', action, fields)

    def show(self, kind, **fields):
        return self.wg('show', TYPE=kind, **fields)['Data'][kind]

    def ready(self):
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            assert self.process.poll() is None, f'{self.name}: QEMU exited during boot'
            try:
                if self.login():
                    uptime = int(self.call('sysstat', 'show', {'TYPE': 'uptime'})['Data']['uptime'])
                    if uptime >= 90:
                        self.call('upgrade', 'seting', {'auto_upgrade_lib_dpi': 0,
                            'auto_upgrade_lib_im': 0, 'auto_upgrade_lib_domain': 0, 'auto_upgrade_sec': 0})
                        self.shell('test -x /usr/sbin/nr-hy2-reverse && '
                                   '/usr/ikuai/script/wg_hy_engine.sh installed')
                        identity = self.shell('/usr/sbin/nr-hy2-reverse version; '
                            'sha256sum /usr/sbin/nr-hy2-reverse; uname -r').splitlines()
                        assert len(identity) == 3, f'{self.name}: worker identity unavailable'
                        return {'worker_version': identity[0], 'worker_sha256': identity[1].split()[0],
                                'kernel': identity[2]}
            except (OSError, ValueError, EOFError, urllib.error.URLError):
                pass
            time.sleep(2)
        raise RuntimeError(f'{self.name}: VM did not become ready')

    def shell(self, command, timeout=120):
        encoded = base64.b64encode(command.encode()).decode()
        assert len(encoded) < 3500, 'Diagnostic command exceeds terminal line limit'
        with telnetlib.Telnet('127.0.0.1', self.shell_port, timeout=10) as connection:
            connection.write(b"stty -echo; printf '\\nTEST_ECHO_OFF\\n'\n")
            connection.read_until(b'\r\nTEST_ECHO_OFF\r\n', timeout=5)
            token = 'TEST_DONE_' + str(time.time_ns())
            connection.write(("printf %s '" + encoded + "' | base64 -d | bash; printf '\\n" +
                              token + "%s\\n' \"$?\"\n").encode())
            data = b''
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                data += connection.read_until(b'\n', timeout=1)
                text = data.decode(errors='replace').replace('\r', '')
                found = re.search(r'\n' + token + r'(\d+)\n', text)
                if found:
                    assert found[1] == '0', f'{self.name}: local diagnostic command failed (exit {found[1]})'
                    return re.sub(r'^(?:bash-[0-9.]+[#$] |# )+', '', text[:found.start()]).strip()
        raise RuntimeError(f'{self.name}: local diagnostic command timed out')

    def install_fixture(self, fixture, binary):
        destination = '/tmp/nr-reverse-test-fixture'
        self.shell('set -e; umask 077; /usr/bin/curl -q -4 -fsS --noproxy "*" --max-time 60 ' +
                   shlex.quote(fixture.gateway.replace('10.0.2.2', self.gateway_ip) + '/fixture') + ' -o ' + destination + '; chmod 700 ' +
                   destination + '; test "$(sha256sum ' + destination + ' | cut -d\' \' -f1)" = ' + sha(binary))

    def start_fixture(self, mode):
        arguments = f'serve {TARGET_TCP} {TARGET_UDP}' if mode == 'serve' else f'busy {MAPPING_PORTS["conflict"]}'
        self.shell(f'set -e; /tmp/nr-reverse-test-fixture {arguments} </dev/null '
                   '>/tmp/nr-reverse-test-fixture.log 2>&1 & echo $! >/tmp/nr-reverse-test-fixture.pid; '
                   'for n in $(seq 1 50); do grep -q READY /tmp/nr-reverse-test-fixture.log && exit 0; sleep .2; done; exit 1')

    def diagnostics(self):
        # Never read raw configuration, environment, argv, cookies or bundles.
        status = {}
        for kind in ('hyr_status', 'site_client_status'):
            try:
                members = self.show(kind).get('members', [])
                status[kind] = [{key: member[key] for key in
                    ('peer_id', 'interface', 'enabled', 'running', 'paused', 'transport', 'purpose', 'reverse_status')
                    if key in member} for member in members]
            except Exception:
                status[kind] = 'unavailable'
        try:
            status['network'] = self.shell('ip -4 addr show; ip -4 rule; '
                'ss -lnut 2>/dev/null || netstat -lnut; '
                'for f in /tmp/iktmp/wg-hy-reverse/*/status.json; do '
                '[ ! -f "$f" ] || jq -c \'{mode,state,connected,error,mappings}\' "$f"; done', timeout=20)
        except Exception:
            status['network'] = 'unavailable'
        (self.directory / 'diagnostics.json').write_text(json.dumps(status, ensure_ascii=False, indent=2))

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        if self.log:
            self.log.close()
        self.disk.unlink(missing_ok=True)


def get_url(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=30) as response:
        return response.read()


def authenticated_management_probe(base, client):
    # Use a fresh cookie jar: the mapped service must perform its own native
    # login, with no cookie inherited from direct VM setup or the other router.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def post(path, body):
        request = urllib.request.Request(base + path, json.dumps(body).encode(),
            {'Content-Type': 'application/json'})
        with opener.open(request, timeout=60) as response:
            return json.load(response)

    login = post('/Action/login', {'username': 'admin', 'passwd': hashlib.md5(b'admin').hexdigest()})
    assert login.get('Result') == 10000, 'Mapped router native login failed'

    def read(function, kind):
        result = post('/Action/call', {'func_name': function, 'action': 'show', 'param': {'TYPE': kind}})
        assert result.get('Result') == 30000, f'Mapped authenticated {function} read failed'
        return result['Data'][kind]

    assert int(read('sysstat', 'uptime')) > 0
    # Keep raw rows, keys and cookies in memory only. The interface identities
    # distinguish the actual receiving router from the center's WG interface.
    def identity(rows):
        return sorted((str(row['id']), row['name'], row['local_address'], row['local_publickey']) for row in rows)

    mapped = identity(read('wireguard', 'iface_data'))
    direct = identity(client.show('iface_data'))
    assert mapped and mapped == direct, 'Authenticated mapped API did not identify the receiving router'
    return {'authenticated': True, 'uptime_read': True, 'matching_client_interfaces': len(mapped)}


def no_response(port, timeout=5):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            connection.sendall(b'GET / HTTP/1.0\r\nHost: reverse-test.invalid\r\n\r\n')
            return connection.recv(64) == b''
    except (ConnectionError, TimeoutError, OSError):
        return True


def tcp_roundtrip(port):
    payload = (bytes(range(256)) * 4096) + b'client-half-close'
    with socket.create_connection(('127.0.0.1', port), timeout=30) as connection:
        connection.settimeout(60)
        connection.sendall(payload)
        connection.shutdown(socket.SHUT_WR)
        received = bytearray()
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            received.extend(chunk)
    expected = payload + b'\nHALF_CLOSE_OK\n'
    assert bytes(received) == expected, f'TCP reverse stream was truncated ({len(received)}/{len(expected)} response bytes)'
    return len(payload)


def udp_roundtrip(port):
    sizes = (1, 1024, 8192, 32768, 0)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(30)
        for size in sizes:
            body = bytes((n * 17 + 23) % 256 for n in range(size))
            connection.sendto(body, ('127.0.0.1', port))
            received, _ = connection.recvfrom(65535)
            assert received == body, f'UDP datagram changed ({size} bytes)'
    return list(sizes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--workdir', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True, help='New private directory outside checkout')
    parser.add_argument('--qemu', default='qemu-system-x86_64')
    parser.add_argument('--firmware-dir', type=Path)
    parser.add_argument('--go', required=True, help='Absolute path to the genuine Go compiler')
    parser.add_argument('--memory', type=int, default=1024, help='MiB per guest')
    parser.add_argument('--hold-after-checks', action='store_true', help='Wait for OUT/release-ui before final cleanup')
    parser.add_argument('--hold-seconds', type=int, default=1800, help='Maximum read-only UI review hold')
    parser.add_argument('--browser-check', action='store_true', help='Run the native desktop/mobile Playwright check in the same network namespace')
    parser.add_argument('--browser-python', default=os.environ.get('CODEX_PRIMARY_RUNTIME_PYTHON'),
                        help='Python with Playwright (defaults to the primary runtime)')
    parser.add_argument('--chromium', type=Path, help='Optional isolated Chromium executable or wrapper for the UI check')
    parser.add_argument('--browser-retry-wait', type=int, default=0,
                        help='On UI-check failure, wait this many seconds for OUT/retry-browser before cleanup')
    parser.add_argument('--browser-blocked-reason', choices=('environment_denied_browser_ipc',),
                        help='Record an independently observed browser environment block; never marks the UI gate passed')
    args = parser.parse_args()
    args.image = args.image.resolve()
    args.workdir = args.workdir.resolve()
    args.out = args.out.resolve()
    if args.firmware_dir:
        args.firmware_dir = args.firmware_dir.resolve()
    assert args.image.is_file() and args.image.suffix == '.img'
    assert args.out != ROOT and ROOT not in args.out.parents and not args.out.exists()
    assert 768 <= args.memory <= 4096 and 1 <= args.hold_seconds <= 3600
    assert 0 <= args.browser_retry_wait <= 600
    assert not args.browser_check or args.browser_python, '--browser-check needs --browser-python or the primary runtime'
    assert '\n' not in str(args.out) and '"' not in str(args.out)
    os.umask(0o077)
    args.out.mkdir(mode=0o700, parents=True)
    original_digest = sha(args.image)
    verification_path = args.workdir / 'port-3726/output/verification.json'
    verification = json.loads(verification_path.read_text())
    package = verification_path.parent / verification['output_filename']
    assert sha(package) == verification['output_sha256']
    assert verification['roundtrip_decryption'] and verification['kernel_verified_through_rootfs_unpack_call']
    report = {'passed': False, 'functional_passed': False, 'ui_status': 'not_run',
              'ui_screenshots_completed': False, 'image_sha256': original_digest,
              'firmware_sha256': verification['output_sha256'], 'production_modified': False,
              'scope': 'Two copied firmware guests, native API and real sing-box/HY2; loopback client targets and local host fixture only.',
              'steps': {}}
    report_path = args.out / 'report.json'
    started = time.monotonic()
    vms = []
    fixture = None

    def record(name, value=True):
        report['steps'][name] = value
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        print('Passed:', name, flush=True)

    try:
        source = args.out / 'fixture.go'
        binary = args.out / 'fixture'
        source.write_text(FIXTURE_GO)
        environment = dict(os.environ, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0', GOTOOLCHAIN='local')
        subprocess.run([args.go, 'build', '-trimpath', '-buildvcs=false', '-ldflags=-s -w -buildid=',
                        '-o', str(binary), str(source)], env=environment, check=True)
        fixture = LocalFixture(binary)
        hy2_port = reserve_port('udp')
        mapped_host = {name: reserve_port('udp' if name == 'udp' else 'tcp')
                       for name in MAPPING_PORTS if name != 'conflict'}
        extra = [('udp', hy2_port, hy2_port)] + [
            ('udp' if name == 'udp' else 'tcp', host, MAPPING_PORTS[name]) for name, host in mapped_host.items()]
        center = VM('center', args, extra)
        vms.append(center)
        client = VM('client', args, [])
        vms.append(client)
        for vm in vms:
            vm.start()
        print('Booting two image copies; all management/fixture ports are localhost only.', flush=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            identities = dict(zip((vm.name for vm in vms), executor.map(lambda vm: vm.ready(), vms)))
        expected_worker = sha(ROOT / 'materials/firmware/port-3726/files/usr/sbin/nr-hy2-reverse')
        assert all(identity['worker_sha256'] == expected_worker for identity in identities.values()), 'Image worker differs from this checkout'
        record('both_native_guests_booted_with_offline_hy2_core', identities)
        for vm in vms:
            vm.install_fixture(fixture, binary)
        client.start_fixture('serve')
        marker_path = '/static/reverse-test-' + secrets.token_hex(12) + '.js'
        marker = '/* client-router-' + secrets.token_hex(24) + ' */'
        client.shell('printf %s ' + shlex.quote(marker) + ' > ' + shlex.quote('/usr/ikuai/www' + marker_path))
        marker_response = get_url(client.base + marker_path)
        assert marker_response == marker.encode(), f'Client static probe was not served ({len(marker_response)} bytes)'
        local = center.wg('show', TYPE='gen_privatekey')['Data']
        remote = center.wg('show', TYPE='gen_privatekey')['Data']
        center.wg('iface_add', enabled='yes', name='wg21', interface='auto', mtu=1420,
                  local_address='10.173.21.1/24', local_listenport=hy2_port,
                  local_privatekey=local['privatekey'], local_publickey=local['pubkey'])
        reverse = {'enabled': True, 'mappings': [
            {'id': str(index), 'protocol': 'udp' if name == 'udp' else 'tcp',
             'listen_port': MAPPING_PORTS[name], 'target_ip': '127.0.0.1', 'target_port': target,
             'sources': [{'denied': '192.0.2.0/24', 'tcp': center.gateway_ip + '/32'}.get(name, '0.0.0.0/0')]}
            for index, (name, target) in enumerate((('management', 80), ('tcp', TARGET_TCP),
                ('udp', TARGET_UDP), ('denied', 80), ('unreachable', TARGET_CLOSED)), 1)]}
        fields = dict(enabled='yes', interface='wg21', comment='reverse-native-vm-test',
            peer_privatekey=remote['privatekey'], peer_publickey=remote['pubkey'], presharedkey='',
            allowips='10.173.21.2/32', endpoint='', endpoint_port='', keepalive=25,
            client_endpoint='10.0.2.2', client_dns='10.173.21.1', exit_peer='no', site_local='', site_remote='',
            wg_transport='pure_hy2', wg_role='access', hyr_id='', hyr_addr_mode='manual',
            hyr_port_mode='wg', hyr_public_ip='10.0.2.2', hyr_reverse_hex=hex_json(reverse))
        center.wg('add', **fields)

        def server_member(live=False):
            return next(member for member in center.show('hyr_status' if live else 'hyr_settings')['members']
                        if member['interface'] == 'wg21')

        def export_bundle():
            member = server_member()
            return center.show('hyr_site_profile', peer_id=member['peer_id'], id=member['id'], expected_role='access')

        bundle = export_bundle()
        assert bundle['format'] == 'nativerouting-pure-hy2-device' and bundle['version'] == 2
        assert bundle['transport']['server'] == '10.0.2.2' and bundle['transport']['server_port'] == hy2_port
        assert bundle['reverse']['server'] == '10.173.21.1' and bundle['reverse']['server_port'] == 49871
        assert bundle['reverse']['mappings'] == reverse['mappings']
        record('native_v2_export_retains_transport_and_exact_reverse_mappings')
        assert no_response(mapped_host['management']), 'Server listener opened before receiver authentication'
        record('unauthenticated_receiver_has_no_public_mapping')

        def import_bundle(value):
            old = {str(row['id']) for row in client.show('site_client_status')['members']}
            client.wg('site_client_import', config_hex=hex_json(value))
            new = [row for row in client.show('site_client_status')['members'] if str(row['id']) not in old]
            assert len(new) == 1 and new[0]['transport'] == 'pure_hy2'
            return str(new[0]['id'])

        client_id = import_bundle(bundle)

        def receiver_member():
            return next(member for member in client.show('site_client_status')['members'] if str(member['id']) == client_id)

        def connected():
            server = server_member(True).get('reverse_status', {})
            receiver = receiver_member().get('reverse_status', {})
            if not all(value.get('connected') and value.get('state') == 'online' for value in (server, receiver)):
                return False
            assert len(server.get('mappings', [])) == len(reverse['mappings'])
            assert all(mapping['listening'] for mapping in server['mappings'])
            return {'server': server, 'client': receiver}

        live = wait_for('native reverse handshake', connected, timeout=150)
        record('manual_native_status_reports_authenticated_online', live)
        assert get_url(f'http://127.0.0.1:{mapped_host["management"]}/') == get_url(client.base + '/')
        assert get_url(f'http://127.0.0.1:{mapped_host["management"]}{marker_path}') == marker.encode()
        record('server_public_port_fetches_actual_second_router_management_page')
        record('mapped_management_login_and_native_read_matches_client',
               authenticated_management_probe(f'http://127.0.0.1:{mapped_host["management"]}', client))
        record('tcp_full_upload_and_response_after_half_close_bytes', tcp_roundtrip(mapped_host['tcp']))
        record('explicit_source_cidr_allows_the_matching_source')
        record('udp_preserves_datagram_sizes_including_empty', udp_roundtrip(mapped_host['udp']))
        assert no_response(mapped_host['denied'])
        denied = next(mapping for mapping in server_member(True)['reverse_status']['mappings'] if mapping['id'] == '4')
        assert denied['active'] == 0 and denied['rx_bytes'] == 0 and denied['tx_bytes'] == 0
        record('native_source_cidr_rejects_unlisted_source_without_forwarding')
        assert no_response(mapped_host['unreachable'], timeout=20)

        def target_failure():
            state = server_member(True)['reverse_status']
            row = next(mapping for mapping in state['mappings'] if mapping['id'] == '5')
            return state['connected'] and row.get('last_error') == 'target_unreachable'

        wait_for('target failure status', target_failure, timeout=30)
        record('target_unreachable_is_distinct_from_live_tunnel')

        def ordinary_hy2():
            number = int(client_id)
            socks = f'127.77.{1 + (number - 1) // 254}.{1 + (number - 1) % 254}:1080'
            body = client.shell('/usr/bin/curl -q -4 -fsS --max-time 30 --noproxy "" --socks5-hostname ' +
                socks + ' ' + shlex.quote(fixture.gateway.replace('10.0.2.2', center.gateway_ip) + '/ordinary'))
            assert body.encode() == fixture.body, 'Ordinary HY2 forwarding did not reach local external fixture'
            assert fixture.prefix + '/ordinary' in fixture.hits

        ordinary_hy2()
        record('ordinary_hy2_socks_outbound_reaches_host_local_external_fixture')
        time.sleep(2)
        transferred = connected()
        assert transferred
        for identifier in ('1', '2', '3'):
            row = next(mapping for mapping in transferred['server']['mappings'] if mapping['id'] == identifier)
            assert row['rx_bytes'] > 0 and row['tx_bytes'] > 0 and row['last_success'] > 0
        record('manual_status_counts_actual_target_traffic', transferred)

        def offline():
            value = server_member(True).get('reverse_status', {})
            return not value.get('connected') and not any(row.get('listening') for row in value.get('mappings', []))

        # Stop only the actual client transport. The reverse worker must lose its
        # HY2 carrier and revoke listeners even though the native row is enabled.
        client.shell(f'/usr/ikuai/script/wg_hy_engine.sh puc-{client_id} stop')
        wait_for('carrier loss revokes server listeners', offline, timeout=100)
        assert no_response(mapped_host['management'])
        record('actual_sing_box_carrier_loss_revokes_reverse_listener')
        client.wg('up', id=client_id)
        wait_for('carrier recovery reconnects', connected, timeout=150)
        assert get_url(f'http://127.0.0.1:{mapped_host["management"]}{marker_path}') == marker.encode()
        ordinary_hy2()
        record('native_reapply_restores_real_hy2_and_reverse_traffic')
        client.wg('down', id=client_id)
        wait_for('disabled receiver revokes listener', offline, timeout=100)
        assert no_response(mapped_host['management'])
        assert not receiver_member().get('reverse_status', {}).get('connected')
        client.wg('up', id=client_id)
        wait_for('native receiver enable reconnects', connected, timeout=150)
        record('native_receiver_disable_revoke_and_enable_reconnect')

        def edit_reverse(value, success=True):
            saved = server_member()
            parameters = dict(fields, id=str(saved['peer_id']), hyr_id=saved['id'],
                hyr_origin_key=remote['pubkey'], hyr_origin_iface='wg21',
                native_origin_role='', native_origin_exit='no', hyr_reverse_hex=hex_json(value))
            result = center.request('wireguard', 'edit', parameters)
            if success:
                assert result.get('Result') == 30000, ('center', 'edit', result.get('Result'), result.get('ErrMsg'))
            else:
                assert result.get('Result') not in (10014, 30000), 'Occupied listener save unexpectedly succeeded'
            return result

        center.start_fixture('busy')
        before = export_bundle()
        before_id = server_member()['id']
        conflict = json.loads(json.dumps(reverse))
        conflict['mappings'].append({'id': '6', 'protocol': 'tcp', 'listen_port': MAPPING_PORTS['conflict'],
            'target_ip': '127.0.0.1', 'target_port': 80, 'sources': ['0.0.0.0/0']})
        # A rejected save must leave an already established application stream
        # alive, not merely recreate an equivalent configuration afterwards.
        with socket.create_connection(('127.0.0.1', mapped_host['tcp']), timeout=30) as held:
            held.settimeout(60)
            held.sendall(b'before-rejected-save/')
            wait_for('existing stream before port-conflict save', lambda: any(
                row['id'] == '2' and row['active'] > 0
                for row in server_member(True)['reverse_status']['mappings']), timeout=30)
            rejected = edit_reverse(conflict, success=False)
            held.sendall(b'after-rejected-save')
            held.shutdown(socket.SHUT_WR)
            received = bytearray()
            while True:
                chunk = held.recv(65536)
                if not chunk:
                    break
                received.extend(chunk)
            assert bytes(received) == b'before-rejected-save/after-rejected-save\nHALF_CLOSE_OK\n', 'Rejected save disrupted an existing stream'
        assert export_bundle() == before and server_member()['id'] == before_id
        wait_for('rejected save preserves online mapping', connected, timeout=30)
        assert get_url(f'http://127.0.0.1:{mapped_host["management"]}{marker_path}') == marker.encode()
        record('native_save_rejects_occupied_port_without_mutating_bundle',
               {'result': rejected['Result'], 'existing_stream_preserved': True})
        edit_reverse({'enabled': False})
        wait_for('feature disable revokes mappings', offline, timeout=60)
        assert no_response(mapped_host['management'])
        disabled = export_bundle()
        assert disabled['version'] == 1 and 'reverse' not in disabled
        record('feature_disable_revokes_listeners_and_exports_legacy_v1')
        edit_reverse(reverse)
        refreshed = export_bundle()
        assert refreshed['version'] == 2 and refreshed['reverse']['token'] != bundle['reverse']['token']
        time.sleep(3)
        assert not server_member(True).get('reverse_status', {}).get('connected')
        assert no_response(mapped_host['management'])
        record('reenabled_mapping_rejects_old_receiver_bundle')
        client.wg('del', id=client_id)
        client_id = import_bundle(refreshed)
        wait_for('new versioned import reconnects', connected, timeout=150)
        assert get_url(f'http://127.0.0.1:{mapped_host["management"]}{marker_path}') == marker.encode()
        udp_roundtrip(mapped_host['udp'])
        ordinary_hy2()
        record('fresh_native_v2_import_restores_revoked_mapping')
        report['functional_passed'] = True
        if args.browser_blocked_reason:
            report['ui_status'] = 'blocked'
            report['ui_reason'] = args.browser_blocked_reason
            report['steps']['real_native_desktop_and_mobile_browser_check'] = {
                'status': 'blocked', 'reason': args.browser_blocked_reason, 'screenshots_completed': False}
            print('UI gate blocked:', args.browser_blocked_reason, '(screenshots not completed)', flush=True)
        elif args.browser_check:
            browser = ROOT / 'tools/tests/check_wg_reverse_browser.py'
            assert browser.is_file(), 'Native browser check is missing'
            for attempt in range(3):
                browser_out = args.out / ('browser' if attempt == 0 else f'browser-retry-{attempt}')
                browser_command = [args.browser_python, str(browser), '--center-url', center.base,
                    '--client-url', client.base, '--center-peer-id', str(server_member()['peer_id']),
                    '--client-peer-id', client_id, '--out', str(browser_out)]
                if args.chromium:
                    browser_command += ['--chromium', str(args.chromium.resolve())]
                completed = subprocess.run(browser_command, cwd=ROOT, timeout=300)
                if completed.returncode == 0:
                    break
                retry = args.out / 'retry-browser'
                print(f'Native UI check failed; screenshots/DOM: {browser_out}. '
                      f'Create {retry} within {args.browser_retry_wait}s to retry the read-only check.', flush=True)
                deadline = time.monotonic() + args.browser_retry_wait
                while not retry.exists() and time.monotonic() < deadline:
                    time.sleep(2)
                if attempt == 2 or not retry.exists():
                    raise AssertionError('Real native browser check failed; see browser report')
                retry.unlink()
            record('real_native_desktop_and_mobile_browser_check')
            report['ui_status'] = 'passed'
            report['ui_screenshots_completed'] = True
        report['passed'] = report['functional_passed'] and report['ui_status'] == 'passed'
        report['seconds'] = round(time.monotonic() - started, 1)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        if args.hold_after_checks:
            review = {'center_url': center.base, 'client_url': client.base,
                      'reverse_management_url': f'http://127.0.0.1:{mapped_host["management"]}',
                      'center_peer_id': str(server_member()['peer_id']), 'client_peer_id': client_id,
                      'release_file': str(args.out / 'release-ui'),
                      'note': 'Disposable guests; read-only UI review, then create release_file to clean up.'}
            (args.out / 'review.json').write_text(json.dumps(review, indent=2) + '\n')
            print('Checks passed; waiting for read-only UI review:', args.out / 'review.json', flush=True)
            deadline = time.monotonic() + args.hold_seconds
            while not (args.out / 'release-ui').exists() and time.monotonic() < deadline:
                assert all(vm.process.poll() is None for vm in vms), 'Review guest exited'
                time.sleep(2)
            report['ui_review_released'] = (args.out / 'release-ui').exists()
        print('Two-VM native reverse functional checks passed. UI gate: ' + report['ui_status'], flush=True)
    except BaseException as error:
        report['passed'] = False
        if report['functional_passed'] and report['ui_status'] != 'passed':
            report['ui_status'] = 'failed'
        # Exception strings contain only labels/API Result and ErrMsg, never payloads.
        report['failure'] = str(error)
        for vm in vms:
            if vm.process is not None and vm.process.poll() is None:
                vm.diagnostics()
        raise
    finally:
        for vm in reversed(vms):
            vm.close()
        if fixture:
            fixture.close()
        report['original_image_unchanged'] = sha(args.image) == original_digest
        report['booted_disks_removed'] = all(not vm.disk.exists() for vm in vms)
        report['seconds'] = round(time.monotonic() - started, 1)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        for filename in ('fixture', 'fixture.go'):
            (args.out / filename).unlink(missing_ok=True)
        assert report['original_image_unchanged'], 'Original image changed'
    return 0 if report['passed'] else 3


if __name__ == '__main__':
    raise SystemExit(main())
