import hashlib,io,json,shutil,subprocess,sys
from pathlib import Path
from dissect.extfs import ExtFS
from web_assets import obsolete_assets, asset_inventory
R=Path(__file__).resolve().parent.parent;P=R/'port-3726';O=P/'output';O.mkdir(exist_ok=True)
F=P/'files';BASE=R/'custom-3.7.26-enterprise';dbg=R/'toolbuild/e2fsprogs-1.47.3/debugfs/debugfs';check=R/'toolbuild/e2fsprogs-1.47.3/e2fsck/e2fsck'
menu=json.loads((F/'usr/ikuai/www/json/menu.json').read_text());assert sum(x.get('func_name')=='plugins' for x in menu)==1
manifest={x['path']:x for x in json.loads((BASE/'manifest.json').read_text())}
shutil.copy2(BASE/'rootfs.img',O/'rootfs.img')
# Kernel CONFIG_BLK_DEV_RAM_SIZE=204800 KiB; leave runtime room below this cap.
resize=R/'toolbuild/e2fsprogs-1.47.3/resize/resize2fs'
r=subprocess.run([str(resize),str(O/'rootfs.img'),'160M'],capture_output=True)
(O/'resize.log').write_bytes(r.stdout+r.stderr);assert r.returncode==0,r.stderr
assert (O/'rootfs.img').stat().st_size<=200*1024**2
commands=[];changes={};newdirs=set()
for f in sorted(F.rglob('*')):
 if not f.is_file():continue
 rel=str(f.relative_to(F));data=f.read_bytes();old=manifest.get(rel);h=hashlib.sha256(data).hexdigest()
 if old and old.get('sha256')==h:continue
 for parent in reversed(Path(rel).parents):
  name=str(parent)
  if name!='.' and name not in manifest and name not in newdirs:
   commands+=['mkdir /'+name,'set_inode_field /'+name+' mode 040755'];newdirs.add(name)
 if old:commands+=['rm /'+rel]
 mode=int(old['mode'],8) if old else (0o100755 if data.startswith(b'#!') or f.stat().st_mode & 0o111 else 0o100644)
 commands+=['write "'+str(f)+'" /'+rel,'set_inode_field /'+rel+' mode '+('0%o'%mode),'set_inode_field /'+rel+' uid 0','set_inode_field /'+rel+' gid 0']
 changes[rel]={'sha256':h,'size':len(data),'mode':oct(mode)}
# Keep only resources reachable from the current entry pages and manifest.
# This also removes superseded stock chunks when an overlay replaces a page.
web_prefix='usr/ikuai/www/'
with (BASE/'rootfs.img').open('rb') as stream:
 basefs=ExtFS(stream)
 webfiles={rel[len(web_prefix):]:basefs.get('/'+rel).open().read()
           for rel,entry in manifest.items() if rel.startswith(web_prefix) and 'sha256' in entry}
for f in (F/web_prefix).rglob('*'):
 if f.is_file():webfiles[str(f.relative_to(F/web_prefix))]=f.read_bytes()
needed,generated=asset_inventory(webfiles)
available={Path(name).name.removesuffix('.gz') for name in webfiles}
assert needed <= available, 'Missing active web resource: '+str(sorted(needed-available))
removed=[web_prefix+name for name in obsolete_assets(webfiles)]
for rel in removed:
 assert rel not in changes, 'Prune unused source assets before building: '+rel
 commands.append('rm /'+rel)
(O/'removed-web-assets.json').write_text(json.dumps(removed,indent=2)+'\n')
for name in ['init_plugins','plugin_ctpanel','plugin_pgstore','ikmessages','feature_port']:
 rel='usr/ikuai/function/'+name
 if rel in manifest:commands+=['rm /'+rel]
 commands+=['symlink /'+rel+' ../script/'+name+'.sh']
(O/'debugfs.commands').write_text('\n'.join(commands)+'\n')
r=subprocess.run([str(dbg),'-w','-f',str(O/'debugfs.commands'),str(O/'rootfs.img')],capture_output=True);(O/'debugfs.log').write_bytes(r.stdout+r.stderr);assert r.returncode==0
fs=ExtFS(io.BytesIO((O/'rootfs.img').read_bytes()))
for rel,x in changes.items():
 node=fs.get('/'+rel)
 assert hashlib.sha256(node.open().read()).hexdigest()==x['sha256'],rel
 assert node.inode.i_mode==int(x['mode'],8),(rel,oct(node.inode.i_mode),x['mode'])
for rel in removed:
 try:fs.get('/'+rel)
 except FileNotFoundError:pass
 else:raise AssertionError('Unused web asset remains: '+rel)
for name in ['init_plugins','plugin_ctpanel','plugin_pgstore','ikmessages','feature_port']:assert fs.get('/usr/ikuai/function/'+name).link=='../script/'+name+'.sh'
r=subprocess.run([str(check),'-f','-n',str(O/'rootfs.img')],capture_output=True);(O/'filesystem-check.log').write_bytes(r.stdout+r.stderr);assert r.returncode==0,r.stdout+r.stderr
(O/'changes.json').write_text(json.dumps(changes,indent=2));print('Rootfs ready:',len(changes),'modified/added files; filesystem check passed')
for name in ['local-signing-key.pem','local-public-key.der','vmlinuz','vmlinux','vmlinux.symbols']:shutil.copy2(BASE/name,O/name)
