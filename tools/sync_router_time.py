#!/usr/bin/env python3
"""Publish/check router-time sources, hashed chunks, active manifest and gzip."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'materials/web-src'
WEB = ROOT / 'materials/firmware/port-3726/files/usr/ikuai/www'
parser = argparse.ArgumentParser()
parser.add_argument('--write', action='store_true')
args = parser.parse_args()
assets = json.loads((SOURCE / 'time-assets.json').read_text())
wg = json.loads((SOURCE / 'wg-assets.json').read_text())
old_manifest = wg['manifest']
manifest = (WEB / 'static/js' / old_manifest).read_text()
index = (WEB / 'index.html').read_text()


def publish(path, data):
    compressed = Path(str(path) + '.gz')
    if args.write:
        path.write_bytes(data)
        compressed.write_bytes(gzip.compress(data, mtime=0))
    else:
        assert path.read_bytes() == data, path
        assert gzip.decompress(compressed.read_bytes()) == data, compressed


def resource(data, prefix):
    filename = prefix + hashlib.sha256(data).hexdigest()[:20] + '.js'
    publish(WEB / 'static/js' / filename, data)
    return filename


for chunk, asset in assets['chunks'].items():
    data = (SOURCE / 'time' / asset['source']).read_bytes()
    text = data.decode()
    assert 'window.RouterTime.' in text, asset['source']
    assert 'el-date-picker' not in text, asset['source']
    filename = resource(data, chunk + '.')
    digest = filename.split('.')[1]
    manifest, count = re.subn(r'(?<=[{,])' + chunk + r':"[a-f0-9]+"',
                             chunk + ':"' + digest + '"', manifest)
    assert count == 1, chunk
    if not args.write:
        assert asset['runtime'] == filename, chunk
    asset['runtime'] = filename

app_data = (SOURCE / 'time/app.js').read_bytes()
assert b'window.RouterTime.beginRequest(t);' in app_data
assert b'window.RouterTime.captureResponse(t);' in app_data
new_app = resource(app_data, 'app.featureport.')
# The entry chunk map must point to the same current app as the loader.
manifest = manifest.replace('"static/js/"+e+"."+{', '"static/js/"+({167:"vendor",168:"app.featureport"}[e]||e)+"."+{')
manifest, app_count = re.subn(r'(?<=[{,])168:"[a-f0-9]+"', '168:"' + new_app.split('.')[-2] + '"', manifest)
assert app_count == 1 and '168:"app.featureport"' in manifest
helper_data = (SOURCE / 'src/router-time.js').read_bytes()
new_helper = resource(helper_data, 'router-time.')
assert index.count(assets['app']) == 1
index = index.replace(assets['app'], new_app)
if assets['helper']:
    assert index.count(assets['helper']) == 1
    index = index.replace(assets['helper'], new_helper)
else:
    assert args.write, 'Initial router-time helper sync required'
    assert index.count('var files = [') == 1
    index = index.replace('var files = [', 'var files = ["/static/js/' + new_helper + '?v=2.0", ')
# The native sequential loader appends &entry_attempt on its initial request
# and retries. Every entry, including this new helper, needs a query string.
index = index.replace('/static/js/' + new_helper + '"', '/static/js/' + new_helper + '?v=2.0"')
assert '/static/js/' + new_helper + '?v=2.0"' in index
assert index.index(new_helper) < index.index(new_app)
if not args.write:
    assert assets['app'] == new_app and assets['helper'] == new_helper
assets['app'], assets['helper'] = new_app, new_helper

wg['manifest'] = resource(manifest.encode(), 'manifest.featureport.')
assert index.count(old_manifest) == 1
index = index.replace(old_manifest, wg['manifest'])
publish(WEB / 'index.html', index.encode())
if args.write:
    (SOURCE / 'time-assets.json').write_text(json.dumps(assets, indent=2) + '\n')
    (SOURCE / 'wg-assets.json').write_text(json.dumps(wg, indent=2) + '\n')
else:
    assert wg['manifest'] == old_manifest
print('Router-time source, active app/log/basic chunks, manifest, index and gzip match')
