#!/usr/bin/env python3
"""Unprivileged, real HY2 transport test; all sockets are random loopback ports.

The two sing-box processes use their actual Hysteria 2 transport with an exact
public-key pin. Both reverse daemons use the production binary and timings.
No TUN, network namespace, routing table, firewall or external service is used.
Private configurations, certificates and process logs are removed on every exit;
the requested report contains binary hashes and sanitized test evidence only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[2]
LOOPBACK = '127.0.0.1'


class CheckFailure(Exception):
    """Only fixed, non-secret check identifiers enter the saved report."""


def require(condition, code):
    if not condition:
        raise CheckFailure(code)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def receive_exact(connection, length):
    data = bytearray()
    while len(data) < length:
        part = connection.recv(length - len(data))
        if not part:
            raise EOFError()
        data.extend(part)
    return bytes(data)


def exchange(connection, payload):
    connection.sendall(struct.pack('!I', len(payload)) + payload)
    size = struct.unpack('!I', receive_exact(connection, 4))[0]
    require(size <= 2 * 1024 * 1024, 'unexpected_target_response_size')
    reply = receive_exact(connection, size)
    require(reply == b'TARGET:' + payload[::-1], 'target_response_mismatch')
    return len(reply)


def socks_connect(port, destination):
    connection = socket.create_connection((LOOPBACK, port), timeout=10)
    try:
        connection.sendall(b'\x05\x01\x00')
        require(receive_exact(connection, 2) == b'\x05\x00', 'socks_method_rejected')
        connection.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(LOOPBACK) + struct.pack('!H', destination))
        reply = receive_exact(connection, 4)
        require(reply[0] == 5 and reply[1] == 0, 'socks_connection_rejected')
        if reply[3] == 1:
            receive_exact(connection, 6)
        elif reply[3] == 4:
            receive_exact(connection, 18)
        elif reply[3] == 3:
            receive_exact(connection, receive_exact(connection, 1)[0] + 2)
        else:
            raise CheckFailure('socks_reply_invalid')
        return connection
    except BaseException:
        connection.close()
        raise


class TCPResponder:
    def __init__(self, port=0):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((LOOPBACK, port))
        self.port = self.listener.getsockname()[1]
        self.listener.listen()
        self.listener.settimeout(0.2)
        self.closed = threading.Event()
        self.connections = set()
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.closed.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                self.connections.add(connection)
            threading.Thread(target=self.respond, args=(connection,), daemon=True).start()

    def respond(self, connection):
        try:
            while not self.closed.is_set():
                size = struct.unpack('!I', receive_exact(connection, 4))[0]
                if size > 1024 * 1024:
                    return
                payload = receive_exact(connection, size)
                reply = b'TARGET:' + payload[::-1]
                connection.sendall(struct.pack('!I', len(reply)) + reply)
        except (EOFError, OSError):
            pass
        finally:
            connection.close()
            with self.lock:
                self.connections.discard(connection)

    def close(self):
        if self.closed.is_set():
            return
        self.closed.set()
        self.listener.close()
        with self.lock:
            for connection in self.connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
        self.thread.join(timeout=2)


class UDPResponder:
    def __init__(self):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.connection.bind((LOOPBACK, 0))
        self.port = self.connection.getsockname()[1]
        self.connection.settimeout(0.2)
        self.closed = threading.Event()
        self.respond = True
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.closed.is_set():
            try:
                payload, source = self.connection.recvfrom(65535)
                if self.respond:
                    self.connection.sendto(bytes(byte ^ 0x5a for byte in payload), source)
            except socket.timeout:
                continue
            except OSError:
                return

    def close(self):
        self.closed.set()
        self.connection.close()
        self.thread.join(timeout=2)


class Fixture:
    def __init__(self, directory, sing_box, binary, report):
        self.directory, self.sing_box, self.binary = directory, sing_box, binary
        self.report = report
        self.processes, self.logs, self.targets, self.connections = {}, {}, [], []
        self.ports = set()
        self.phase = 'prepare'

    def free_port(self, kind=socket.SOCK_STREAM):
        while True:
            with socket.socket(socket.AF_INET, kind) as connection:
                connection.bind((LOOPBACK, 0))
                port = connection.getsockname()[1]
            if port not in self.ports:
                self.ports.add(port)
                return port

    def private_json(self, name, value):
        path = self.directory / (name + '.json')
        path.write_text(json.dumps(value, separators=(',', ':')) + '\n')
        path.chmod(0o600)
        return path

    def command(self, args, code, *, input=None):
        result = subprocess.run(args, input=input, capture_output=True, timeout=20)
        require(result.returncode == 0, code)
        return result.stdout

    def launch(self, name, executable, config):
        stream = (self.directory / (name + '.log')).open('ab', buffering=0)
        self.logs[name] = stream
        args = [str(executable), 'run', '-c' if executable == self.sing_box else '-config', str(config)]
        self.processes[name] = subprocess.Popen(args, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)

    def stop(self, name):
        process = self.processes.get(name)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if name in self.logs:
            self.logs.pop(name).close()

    def healthy(self):
        for name in ('hy-server', 'reverse-server', 'reverse-client'):
            process = self.processes.get(name)
            if process is not None and process.poll() is not None:
                log = (self.directory / (name + '.log')).read_text(errors='replace')
                if 'create netlink socket: operation not permitted' in log:
                    raise CheckFailure('environment_denied_netlink_socket')
            require(process is None or process.poll() is None, name + '_exited')

    def wait(self, code, condition, timeout=15):
        self.phase = code
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.healthy()
            if condition():
                return
            time.sleep(0.1)
        raise CheckFailure(code)

    def status(self, mode):
        path = self.directory / (mode + '-status.json')
        try:
            value = json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
        require(value.get('pid') == self.processes['reverse-' + mode].pid, 'status_pid_mismatch')
        require(value.get('config_sha256') == digest(self.directory / ('reverse-' + mode + '.json')), 'status_config_mismatch')
        require(abs(time.time() - value.get('updated_at', 0)) < 10, 'status_not_fresh')
        return value

    def mapping(self, mode, identifier):
        return next((row for row in self.status(mode).get('mappings', []) if row['id'] == identifier), {})

    def online(self):
        return all(self.status(mode).get('connected') is True for mode in ('server', 'client'))

    def offline(self):
        return all(self.status(mode).get('connected') is False for mode in ('server', 'client'))

    def route_count(self, name, control):
        log = (self.directory / (name + '.log')).read_text(errors='replace')
        tag = 'inbound/socks[socks-in]' if name == 'hy-client' else 'inbound/hysteria2[hy-in]'
        destination = 'inbound connection to ' + LOOPBACK + ':' + str(control)
        return sum(tag in line and destination in line for line in log.splitlines())

    def routed_work(self, control, before):
        self.wait('work_connections_cross_socks_and_hy2', lambda: all(
            self.route_count(name, control) > before[name] for name in before))

    def passed(self, name, **evidence):
        self.report['checks'].append({'name': name, 'passed': True, 'evidence': evidence})
        print('PASS ' + name, flush=True)

    def cleanup(self):
        for connection in self.connections:
            connection.close()
        for name in reversed(list(self.processes)):
            self.stop(name)
        for target in self.targets:
            target.close()
        return all(process.poll() is not None for process in self.processes.values())

    def run(self):
        tcp_target, udp_target = TCPResponder(), UDPResponder()
        self.targets.extend((tcp_target, udp_target))
        self.ports.update((tcp_target.port, udp_target.port))
        control, socks, bad_socks = self.free_port(), self.free_port(), self.free_port()
        tcp_public, udp_public, hy_port = self.free_port(), self.free_port(socket.SOCK_DGRAM), self.free_port(socket.SOCK_DGRAM)
        key_path, cert_path = self.directory / 'tls.key', self.directory / 'tls.crt'
        self.command(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                      '-sha256', '-days', '1', '-nodes', '-keyout', str(key_path), '-out', str(cert_path),
                      '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'], 'tls_certificate_creation_failed')
        public = self.command(['openssl', 'x509', '-in', str(cert_path), '-pubkey', '-noout'], 'tls_public_key_failed')
        der = self.command(['openssl', 'pkey', '-pubin', '-outform', 'DER'], 'tls_pin_failed', input=public)
        pin = base64.b64encode(hashlib.sha256(der).digest()).decode()
        password, token = secrets.token_hex(32), secrets.token_hex(32)
        server_config = self.private_json('hy-server', {
            'log': {'level': 'info', 'timestamp': False},
            'inbounds': [{'type': 'hysteria2', 'tag': 'hy-in', 'listen': LOOPBACK, 'listen_port': hy_port,
                          'users': [{'name': 'fixture', 'password': password}],
                          'tls': {'enabled': True, 'certificate_path': str(cert_path), 'key_path': str(key_path)}}],
            'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}})

        def client_config(port, fingerprint):
            return {'log': {'level': 'info', 'timestamp': False},
                    'inbounds': [{'type': 'socks', 'tag': 'socks-in', 'listen': LOOPBACK, 'listen_port': port}],
                    'outbounds': [{'type': 'hysteria2', 'tag': 'hy-out', 'server': LOOPBACK, 'server_port': hy_port,
                                   'password': password, 'tls': {'enabled': True, 'server_name': LOOPBACK,
                                                               'certificate_public_key_sha256': [fingerprint]}}],
                    'route': {'final': 'hy-out'}}

        client_path = self.private_json('hy-client', client_config(socks, pin))
        bad_path = self.private_json('hy-bad-pin', client_config(bad_socks, base64.b64encode(secrets.token_bytes(32)).decode()))
        for path in (server_config, client_path, bad_path):
            self.command([str(self.sing_box), 'check', '-c', str(path)], 'sing_box_config_invalid')
        self.launch('hy-server', self.sing_box, server_config)
        self.launch('hy-client', self.sing_box, client_path)
        self.launch('hy-bad-pin', self.sing_box, bad_path)

        def direct_roundtrip():
            try:
                with socks_connect(socks, tcp_target.port) as connection:
                    exchange(connection, b'ordinary HY2 access')
                return True
            except (OSError, EOFError, CheckFailure):
                return False

        self.wait('correct_tls_pin_allows_real_hy2', direct_roundtrip, 30)
        require(self.processes['hy-bad-pin'].poll() is None, 'bad_pin_proxy_exited')
        try:
            with socks_connect(bad_socks, tcp_target.port) as connection:
                exchange(connection, b'must not arrive through a wrong pin')
        except (OSError, EOFError, CheckFailure):
            pass
        else:
            raise CheckFailure('wrong_tls_pin_was_accepted')
        self.stop('hy-bad-pin')
        self.passed('strict_tls_pin', correct_pin_works=True, wrong_pin_rejected=True)

        mappings = [
            {'id': '1', 'protocol': 'tcp', 'listen': f'{LOOPBACK}:{tcp_public}',
             'target': f'{LOOPBACK}:{tcp_target.port}', 'allow': [LOOPBACK + '/32']},
            {'id': '2', 'protocol': 'udp', 'listen': f'{LOOPBACK}:{udp_public}',
             'target': f'{LOOPBACK}:{udp_target.port}', 'allow': [LOOPBACK + '/32']}]
        for mode in ('server', 'client'):
            config = {'mode': mode, 'token': token, 'control': f'{LOOPBACK}:{control}',
                      'status_file': str(self.directory / (mode + '-status.json')), 'mappings': mappings}
            if mode == 'client':
                config['socks'] = f'{LOOPBACK}:{socks}'
            config_path = self.private_json('reverse-' + mode, config)
            self.command([str(self.binary), 'check', '-config', str(config_path)], 'reverse_config_invalid')
            self.launch('reverse-' + mode, self.binary, config_path)
        self.wait('reverse_authenticated_over_hy2', self.online, 40)
        self.wait('authenticated_session_binds_both_listeners', lambda:
                  len(self.status('server').get('mappings', [])) == 2 and all(
                      row.get('listening') is True for row in self.status('server')['mappings']))
        self.wait('authenticated_control_crosses_socks_and_hy2', lambda: all(
            self.route_count(name, control) >= 1 for name in ('hy-client', 'hy-server')))
        self.passed('authenticated_control_uses_hy2', authenticated=True, public_listeners=True)

        payload = bytes(range(256)) * 1024 + b'tcp-tail'
        before = {name: self.route_count(name, control) for name in ('hy-client', 'hy-server')}
        with socket.create_connection((LOOPBACK, tcp_public), timeout=10) as connection:
            response_bytes = exchange(connection, payload)
        self.routed_work(control, before)
        self.wait('tcp_bidirectional_counters', lambda: all(
            self.mapping(mode, '1').get('rx_bytes', 0) >= len(payload) and
            self.mapping(mode, '1').get('tx_bytes', 0) >= response_bytes and
            self.mapping(mode, '1').get('last_success', 0) > 0 for mode in ('server', 'client')))
        self.passed('tcp_response_through_hy2_work_connection', request_bytes=len(payload), response_bytes=response_bytes)

        def udp_roundtrip(sizes):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                connection.settimeout(10)
                connection.bind((LOOPBACK, 0))
                for size in sizes:
                    request = bytes((number * 17 + 3) % 256 for number in range(size))
                    connection.sendto(request, (LOOPBACK, udp_public))
                    response, source = connection.recvfrom(65535)
                    require(source == (LOOPBACK, udp_public), 'udp_response_source_mismatch')
                    require(response == bytes(byte ^ 0x5a for byte in request), 'udp_response_mismatch')

        before = {name: self.route_count(name, control) for name in ('hy-client', 'hy-server')}
        sizes = [0, 17, 1450, 65507]
        udp_roundtrip(sizes)
        self.routed_work(control, before)
        self.wait('udp_bidirectional_counters', lambda: all(
            self.mapping(mode, '2').get('rx_bytes', 0) >= sum(sizes) and
            self.mapping(mode, '2').get('tx_bytes', 0) >= sum(sizes) and
            self.mapping(mode, '2').get('last_success', 0) > 0 for mode in ('server', 'client')))
        self.passed('udp_datagram_boundaries_and_large_payload', sizes=sizes, request_bytes=sum(sizes), response_bytes=sum(sizes))
        require(direct_roundtrip(), 'ordinary_hy2_access_broken_by_reverse')
        self.passed('ordinary_hy2_access_coexists', separate_proxy_roundtrip=True)

        held = socket.create_connection((LOOPBACK, tcp_public), timeout=10)
        self.connections.append(held)
        exchange(held, b'connection held across transport loss')
        self.stop('hy-client')
        self.wait('transport_loss_revokes_authenticated_session', self.offline, 45)
        self.wait('transport_loss_revokes_public_listeners', lambda:
                  len(self.status('server').get('mappings', [])) == 2 and all(
                      row.get('listening') is False for row in self.status('server')['mappings']))
        with socket.create_connection((LOOPBACK, control), timeout=2):
            pass  # Direct control reachability remains available to catch fallback.
        try:
            with socket.create_connection((LOOPBACK, tcp_public), timeout=1):
                raise CheckFailure('tcp_listener_remained_after_transport_loss')
        except OSError:
            pass
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.bind((LOOPBACK, udp_public))  # Exclusive bind proves the UDP listener was removed.
        try:
            held.settimeout(2)
            require(held.recv(1) == b'', 'old_work_connection_survived_transport_loss')
        except (ConnectionResetError, BrokenPipeError):
            pass
        for _ in range(30):
            require(self.offline(), 'direct_fallback_after_socks_loss')
            time.sleep(0.1)
        self.passed('socks_loss_has_no_direct_fallback', direct_control_still_reachable=True,
                    tcp_listener_removed=True, udp_listener_removed=True, old_work_connection_closed=True)

        self.launch('hy-client', self.sing_box, client_path)
        self.wait('reverse_automatically_reconnects', self.online, 45)
        with socket.create_connection((LOOPBACK, tcp_public), timeout=10) as connection:
            exchange(connection, b'TCP after automatic reconnection')
        udp_roundtrip([65507])
        self.passed('automatic_reconnect_restores_tcp_and_udp', tcp_response=True, udp_response_bytes=65507)

        self.wait('reconnected_tcp_success_snapshot', lambda: all(
            self.mapping(mode, '1').get('last_success', 0) > 0 and
            self.mapping(mode, '1').get('last_error') == '' for mode in ('server', 'client')))
        previous = {mode: self.mapping(mode, '1').get('last_success') for mode in ('server', 'client')}
        target_port = tcp_target.port
        tcp_target.close()
        try:
            with socket.create_connection((LOOPBACK, tcp_public), timeout=10) as connection:
                exchange(connection, b'unreachable target must not succeed')
        except (EOFError, OSError):
            pass
        else:
            raise CheckFailure('closed_target_unexpectedly_succeeded')
        self.wait('target_failure_recorded_separately', lambda: all(
            self.mapping(mode, '1').get('last_error') in ('target_unreachable', 'target_timeout') for mode in ('server', 'client')))
        require(self.online(), 'target_failure_closed_authenticated_channel')
        require(all(self.mapping(mode, '1').get('last_success') == previous[mode] for mode in previous), 'target_failure_changed_success_timestamp')
        udp_roundtrip([1450])
        self.passed('target_failure_is_not_channel_failure', connected=True, other_mapping_works=True, historical_success_preserved=True)
        tcp_target = TCPResponder(target_port)
        self.targets.append(tcp_target)
        with socket.create_connection((LOOPBACK, tcp_public), timeout=10) as connection:
            exchange(connection, b'restarted target without daemon restart')
        self.wait('target_recovery_clears_error', lambda: all(
            self.mapping(mode, '1').get('last_error') == '' for mode in ('server', 'client')))
        self.passed('target_recovery_without_daemon_restart', tcp_response=True)

        previous_tx = {mode: self.mapping(mode, '2').get('tx_bytes', 0) for mode in ('server', 'client')}
        udp_roundtrip([17])
        self.wait('udp_success_snapshot_before_silence', lambda: all(
            self.mapping(mode, '2').get('tx_bytes', 0) >= previous_tx[mode] + 17 for mode in previous_tx))
        previous = {mode: self.mapping(mode, '2').get('last_success') for mode in ('server', 'client')}
        # Cross a whole timestamp tick before dialing a fresh silent association.
        # A faulty UDP dial-as-success implementation must not pass by coincidence.
        time.sleep(1.1)
        udp_target.respond = False
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(2)
            connection.bind((LOOPBACK, 0))
            connection.sendto(b'no target response', (LOOPBACK, udp_public))
            try:
                connection.recvfrom(65535)
            except socket.timeout:
                pass
            else:
                raise CheckFailure('silent_udp_target_fabricated_response')
        require(self.online(), 'silent_udp_target_closed_channel')
        require(all(self.mapping(mode, '2').get('last_success') == previous[mode] for mode in previous), 'udp_dial_alone_claimed_target_success')
        udp_target.respond = True
        udp_roundtrip([17])
        self.passed('udp_listener_does_not_prove_target_response', connected=True, no_false_success=True, recovery_response=True)

        for path, key in ((self.sing_box, 'sing_box_sha256'), (self.binary, 'reverse_sha256')):
            require(digest(path) == self.report['artifacts'][key], 'binary_changed_during_test')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sing-box', required=True, type=Path)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    sing_box, binary, report_path = args.sing_box.resolve(), args.binary.resolve(), args.report.resolve()
    for executable in (sing_box, binary):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            parser.error('Both executable arguments must name existing executable files')
    if report_path.exists() or not report_path.parent.is_dir() or ROOT in report_path.parents:
        parser.error('--report must be a new file in an existing directory outside the checkout')
    version = subprocess.run([str(sing_box), 'version'], capture_output=True, text=True, timeout=10)
    if version.returncode or version.stdout.splitlines()[0] != 'sing-box version 1.14.4':
        parser.error('This test requires the pinned sing-box 1.14.4 executable')
    report = {'test': 'real_hy2_reverse_transport', 'passed': False,
              'artifacts': {'sing_box_sha256': digest(sing_box), 'reverse_sha256': digest(binary)},
              'scope': {'loopback_only': True, 'host_network_changes': False, 'unprivileged': os.geteuid() != 0,
                        'real_hysteria2': True, 'tls_public_key_pin': True}, 'checks': []}
    started, fixture, stopped = time.monotonic(), None, False
    old_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix='nr-reverse-hy2-') as directory:
            fixture = Fixture(Path(directory), sing_box, binary, report)
            try:
                fixture.run()
                report['passed'] = True
            except CheckFailure as error:
                report['failure'] = str(error)
                report['phase'] = fixture.phase
                if str(error) == 'environment_denied_netlink_socket':
                    report['failure_detail'] = ('The execution environment denied sing-box its network-monitor netlink socket; '
                                                'no HY2 connection or reverse forwarding was exercised.')
            except Exception as error:
                report['failure'] = type(error).__name__
                report['phase'] = fixture.phase
            finally:
                stopped = fixture.cleanup()
        report['cleanup'] = {'processes_stopped': stopped, 'temporary_files_removed': not Path(directory).exists()}
    finally:
        os.umask(old_umask)
    report['duration_seconds'] = round(time.monotonic() - started, 3)
    report['passed'] = report['passed'] and stopped and report['cleanup']['temporary_files_removed']
    with report_path.open('x') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    print(json.dumps({'passed': report['passed'], 'checks': len(report['checks']),
                      'failure': report.get('failure'), 'cleanup': report['cleanup']}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
