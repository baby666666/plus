#!/usr/bin/env python3
"""Verify/update WG source, hashed runtime resources and references; no build."""
from pathlib import Path
import argparse,gzip,hashlib,json,re
ROOT=Path(__file__).resolve().parents[1];M=ROOT/'materials';S=M/'web-src';W=M/'firmware/port-3726/files/usr/ikuai/www'
p=argparse.ArgumentParser();p.add_argument('--write',action='store_true');a=p.parse_args()
old=json.loads((S/'wg-assets.json').read_text());new=dict(old)
spec={'chunk':('wg-page.js','34.','.js'),'helper':('wg-paste-import.js','wg-import.','.js'),'planner':('wg-address-plan.js','wg-address.','.js'),'client':('wg-client-config.js','wg-client.','.js'),'singbox':('wg-singbox.js','wg-singbox.','.js'),'i18n':('wg-i18n.js','wg-i18n.','.js'),'css':('wg-actions.css','wg-actions.','.css')}
for kind,(source,prefix,suffix)in spec.items():
 data=(S/'src'/source).read_bytes();name=prefix+hashlib.sha256(data).hexdigest()[:20]+suffix
 path=W/('static/css'if kind=='css'else'static/js')/name;new[kind]=name
 if a.write:path.write_bytes(data);Path(str(path)+'.gz').write_bytes(gzip.compress(data,mtime=0))
 else:
  assert name==old[kind] and path.read_bytes()==data,'WG source differs: '+source
  assert gzip.decompress(Path(str(path)+'.gz').read_bytes())==data,'WG gzip differs: '+name
manifest=(W/'static/js'/old['manifest']).read_text();needle='34:"'+old['chunk'].split('.')[1]+'"';assert needle in manifest
manifest=manifest.replace(needle,'34:"'+new['chunk'].split('.')[1]+'"')
new['manifest']='manifest.featureport.'+hashlib.sha256(manifest.encode()).hexdigest()[:20]+'.js'
index=(W/'index.html').read_text()
for kind in ['helper','planner','client','singbox','i18n','css','manifest']:
 assert old[kind]in index,'Missing index reference: '+kind
 index=index.replace(old[kind],new[kind])
# All helpers use the same sequential loader and retry behavior as the native app.
assert re.search(r'var files = \[.*?'+re.escape(new['client']),index),'Missing client helper in sequential loader'
assert index.index(new['i18n'])<index.index(new['client']),'WG translations must load before client helpers'
assert index.index(new['singbox'])<index.index(new['client']),'sing-box export must load before client helpers'
translations=json.loads((S/'wg-translations.json').read_text())
for locale in ['zh-CN','en-US','zh-TW']:
 path=W/'static/i18n'/(locale+'.json');data=path.read_bytes()
 assert json.loads(data)['wire_guard']['ext']=={r['key']:r[locale] for r in translations},locale
 assert gzip.decompress(Path(str(path)+'.gz').read_bytes())==data,locale+' gzip'
if a.write:
 path=W/'static/js'/new['manifest'];path.write_text(manifest);Path(str(path)+'.gz').write_bytes(gzip.compress(manifest.encode(),mtime=0))
 (W/'index.html').write_text(index);(W/'index.html.gz').write_bytes(gzip.compress(index.encode(),mtime=0));(S/'wg-assets.json').write_text(json.dumps(new,indent=2)+'\n')
else:
 assert new==old,'Manifest/content hash mismatch'
 assert gzip.decompress((W/'static/js'/(old['manifest']+'.gz')).read_bytes()).decode()==manifest
 assert gzip.decompress((W/'index.html.gz').read_bytes()).decode()==index
print('WG source, runtime, manifest, index and gzip match')
