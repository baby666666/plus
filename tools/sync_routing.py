#!/usr/bin/env python3
"""Synchronize routing pages, content hashes, entry manifest and gzip copies."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / 'materials/firmware/port-3726/files/usr/ikuai/www'
SOURCE = ROOT / 'materials/web-src'
parser = argparse.ArgumentParser()
parser.add_argument('--write', action='store_true')
args = parser.parse_args()
assets = json.loads((SOURCE / 'routing-assets.json').read_text())
wg = json.loads((SOURCE / 'wg-assets.json').read_text())
old_manifest = wg['manifest']
manifest = (WEB / 'static/js' / old_manifest).read_text()

def publish(path, data):
    compressed = Path(str(path) + '.gz')
    if args.write:
        path.write_bytes(data)
        compressed.write_bytes(gzip.compress(data, mtime=0))
    else:
        assert path.read_bytes() == data, path
        assert gzip.decompress(compressed.read_bytes()) == data, compressed

translations = json.loads((SOURCE / 'routing/status-translations.json').read_text())
for locale in ['zh-CN', 'zh-TW', 'en-US']:
    path = WEB / 'static/i18n' / (locale + '.json')
    data = json.loads(path.read_text())
    if args.write:
        data['routing_runtime'] = translations[locale]
        publish(path, json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode())
    else:
        assert data['routing_runtime'] == translations[locale], locale + ' routing status translations'
        assert gzip.decompress(Path(str(path) + '.gz').read_bytes()) == path.read_bytes()

for chunk, asset in assets.items():
    data = (SOURCE / 'routing' / asset['source']).read_bytes()
    text = data.decode()
    assert 'orderable:!0' not in text, asset['source']
    assert 'ORDER_BY:"id",ORDER:"desc"' in text, asset['source']
    digest = hashlib.sha256(data).hexdigest()[:20]
    filename = chunk + '.' + digest + '.js'
    manifest, count = re.subn(r'(?<=[{,])' + chunk + r':"[a-f0-9]+"',
                             chunk + ':"' + digest + '"', manifest)
    assert count == 1, chunk
    if not args.write:
        assert asset['runtime'] == filename, chunk
    asset['runtime'] = filename
    publish(WEB / 'static/js' / filename, data)

wg['manifest'] = 'manifest.featureport.' + hashlib.sha256(manifest.encode()).hexdigest()[:20] + '.js'
publish(WEB / 'static/js' / wg['manifest'], manifest.encode())
index = (WEB / 'index.html').read_text()
assert index.count(old_manifest) == 1
index = index.replace(old_manifest, wg['manifest'])
publish(WEB / 'index.html', index.encode())
if args.write:
    (SOURCE / 'wg-assets.json').write_text(json.dumps(wg, indent=2) + '\n')
    (SOURCE / 'routing-assets.json').write_text(json.dumps(assets, indent=2) + '\n')
else:
    assert wg['manifest'] == old_manifest
print('Routing source, newest-first list order, active chunks, manifest and gzip match')
