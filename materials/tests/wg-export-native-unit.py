#!/usr/bin/env python3
"""Read-only WG export checks on an explicitly supplied local development VM.

The helper supplies authenticated localhost HTTP and a local shell channel.
No configuration is changed, and keys stay in process memory, never in reports.
"""
from pathlib import Path
import argparse
import base64
import importlib.util
from urllib.parse import urlparse

parser = argparse.ArgumentParser()
parser.add_argument('--helper', required=True)
parser.add_argument('--peer-id', type=int, required=True)
args = parser.parse_args()
assert args.peer_id > 0
spec = importlib.util.spec_from_file_location('wg_export_test_vm', Path(args.helper).resolve())
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)
assert urlparse(vm.base).hostname in ('127.0.0.1', '::1', 'localhost'), 'only an isolated local VM is supported'
passed = 0


def check(ok, label):
    global passed
    assert ok, label
    passed += 1
    print('PASS', label, flush=True)


def call(types, **params):
    return vm.post('/Action/call', {'func_name': 'wireguard', 'action': 'show', 'param': {'TYPE': types, **params}})


def valid_key(value):
    try:
        decoded = base64.b64decode(value, validate=True)
        return len(decoded) == 32 and base64.b64encode(decoded).decode() == value
    except (ValueError, TypeError):
        return False


vm.login()
check(vm.shell('jq --version').strip() == 'jq-1.4', 'actual firmware jq 1.4 runtime')
response = call('client_export', peer_id=args.peer_id)
check(response.get('Result') == 30000, 'native export succeeds through original API wrapper')
exported = response['Data']['client_export']
check(exported['keypair_valid'] is True and exported['peer']['id'] == args.peer_id and
      exported['peer']['enabled'] == 'yes' and exported['iface']['enabled'] == 'yes', 'saved enabled client and parent are returned')
check(set(exported) == {'peer', 'iface', 'keypair_valid'} and 'local_privatekey' not in exported['iface'], 'export allowlist never includes server private key')
derived = call('gen_publickey', privatekey=exported['peer']['peer_privatekey'])
check(derived.get('Result') == 30000 and derived['Data']['pubkey'] == exported['peer']['peer_publickey'], 'saved client key pair matches native WG derivation')
generated = call('gen_privatekey,gen_sharedkey')
check(generated.get('Result') == 30000 and all(valid_key(generated['Data'].get(k)) for k in ('privatekey', 'pubkey', 'presharedkey')), 'mixed native generation types produce one valid JSON response')
derived = call('gen_publickey', privatekey=generated['Data']['privatekey'])
check(derived.get('Result') == 30000 and derived['Data']['pubkey'] == generated['Data']['pubkey'], 'fresh native private/public pair matches')
for types, params in [
    ('client_export', {'peer_id': 0}),
    ('client_export', {'peer_id': -1}),
    ('client_export', {'peer_id': 99999999}),
    ('gen_publickey', {'privatekey': 'INVALID_TEST_KEY'}),
    ('gen_privatekey,client_export', {'peer_id': 0}),
    ('client_export,gen_publickey', {'peer_id': args.peer_id, 'privatekey': 'INVALID_TEST_KEY'}),
    ('gen_privatekey,missing', {}),
]:
    response = call(types, **params)
    check(response.get('Result') == 30006 and 'Data' not in response and
          response.get('ErrMsg') == 'WG 配置读取或密钥生成失败，请检查已保存配置后重试',
          'native failure is valid JSON with no partial data: ' + types + ' ' + str(len(params)))
response = call('client_export', peer_id='1;bad')
check(response.get('Result') == 10013 and 'Data' not in response, 'native parameter filter rejects shell metacharacters before show')
response = call('data,total')
check(response.get('Result') == 30000 and isinstance(response['Data']['data'], list), 'ordinary native listing remains compatible')
response = call('data,client_export', peer_id=args.peer_id)
check(response.get('Result') == 30000 and isinstance(response['Data']['data'], list) and
      response['Data']['client_export']['keypair_valid'] is True, 'mixed listing and saved export remain compatible')
print('WG_EXPORT_NATIVE_PASS', passed)
