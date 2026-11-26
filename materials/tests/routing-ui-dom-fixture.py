#!/usr/bin/env python3
"""Serve isolated real-Vue routing component checks; no router or login required.

Pass the built rootfs.tar.gz for its unchanged vendor bundle. Open the printed
loopback URL with the approved browser UI tool and press Run checks. All API
responses are local in-memory fixtures; this server never proxies requests.
"""
from pathlib import Path
import argparse
import gzip
import http.server
import json
import re
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument('--rootfs', type=Path, required=True)
p.add_argument('--port', type=int, default=0)
a = p.parse_args()
web = ROOT / 'materials/firmware/port-3726/files/usr/ikuai/www'
wg = json.loads((ROOT / 'materials/web-src/wg-assets.json').read_text())
time_assets = json.loads((ROOT / 'materials/web-src/time-assets.json').read_text())
with tempfile.TemporaryDirectory(prefix='routing-ui-dom-') as folder:
    out = Path(folder)
    with tarfile.open(a.rootfs) as archive:
        members = {m.name.lstrip('./'): m for m in archive.getmembers()}
        for name, target in [('usr/ikuai/www/static/js/vendor.9963e3172df892e7087c.js', 'vendor.js')]:
            member = members.get(name) or members[name + '.gz']
            content = archive.extractfile(member).read()
            (out / target).write_bytes(gzip.decompress(content) if member.name.endswith('.gz') else content)
    (out / 'manifest.js').write_bytes((web / 'static/js' / wg['manifest']).read_bytes())
    (out / 'app.js').write_bytes((web / 'static/js' / time_assets['app']).read_bytes())
    (out / 'i18n.json').write_bytes((web / 'static/i18n/zh-CN.json').read_bytes())
    for locale in ['zh-TW', 'en-US']:
        (out / (locale + '.json')).write_bytes((web / 'static/i18n' / (locale + '.json')).read_bytes())
    for name in ['domain', 'port', 'protocol', 'updown']:
        (out / (name + '.js')).write_bytes((ROOT / 'materials/web-src/routing' / (name + '.js')).read_bytes())
    (out / 'checks.js').write_bytes((ROOT / 'materials/tests/routing-ui-dom.js').read_bytes())
    (out / 'index.html').write_text('''<!doctype html><meta charset="utf-8"><title>Offline routing component checks</title>
<style>body{font:14px sans-serif;margin:20px;color:#222}button{margin:5px;padding:6px 12px}table{border-collapse:collapse}td,th{padding:3px 8px;border:1px solid #ddd}.passed{color:#06752b}.failed{color:#a11}pre{white-space:pre-wrap}#mount{max-height:450px;overflow:auto;border:1px solid #aaa;padding:12px}.line_edit{margin:6px 0}.input_tit{display:inline-block;min-width:140px}</style>
<h1>Offline routing component checks</h1><p>Real firmware Vue, page render, DTable and pagination. In-memory fixture data only; no router requests.</p>
<button id="run" disabled>Run checks</button><button id="preview-domain" disabled>预览域名编辑</button><button id="preview-port" disabled>预览端口编辑</button><button id="preview-protocol" disabled>预览协议编辑</button><p id="preview-status"></p><div id="mount"></div><details id="results" open><summary>回归结果</summary><pre id="result">Loading local components...</pre></details>
<script src="manifest.js"></script><script>window.registerFixtureModules=window.webpackJsonp;window.webpackJsonp=function(chunks,modules){return window.registerFixtureModules(chunks,modules);};</script>
<script src="vendor.js"></script><script src="app.js"></script><script src="domain.js"></script><script src="port.js"></script><script src="protocol.js"></script><script src="updown.js"></script><script src="checks.js"></script>''')
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=folder, **kwargs)
        def log_message(self, *_):
            pass
    with http.server.ThreadingHTTPServer(('127.0.0.1', a.port), Handler) as server:
        print(f'Offline fixture: http://127.0.0.1:{server.server_port}/', flush=True)
        server.serve_forever()
