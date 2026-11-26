#!/usr/bin/env python3
"""Build an unbooted cloud disk from the verified BIN and pinned EFI boot template."""
import argparse, gzip, hashlib, io, json, os, shutil, struct, subprocess
from pathlib import Path
from dissect.extfs import ExtFS
SHA=None
NAME=None
def sha(b): return hashlib.sha256(b).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--firmware',type=Path,required=True);p.add_argument('--template',type=Path,required=True);p.add_argument('--tools',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--hy2-core-archive',type=Path,required=True);a=p.parse_args()
 core_meta=json.loads(Path(__file__).resolve().parents[1].joinpath('base/hy2-core.json').read_text())
 core=a.hy2_core_archive.resolve();core_data=core.read_bytes()
 assert len(core_data)==core_meta['bytes'] and sha(core_data)==core_meta['sha256'],'HY2 archive differs from pinned input'
 assert not any(c in str(core) for c in '\\"\n\r\x00'),'Unsafe archive path'
 a.output.mkdir(parents=True,exist_ok=True);w=a.output/'build';w.mkdir(exist_ok=True)
 data=a.firmware.read_bytes();assert SHA is not None and sha(data)==SHA,'Use tools/cloud_from_rebuild.py with a verified build'
 n=struct.unpack('>I',data[:4])[0];h=json.loads(gzip.decompress(bytes.fromhex('1f8b08006f9b4b590203')+data[4:4+n]));body=data[4+n:]
 assert len(body)==int(h['length']) and hashlib.md5(body).hexdigest()==h['md5'] and sha(body).startswith(h['sha256'])
 fs=ExtFS(io.BytesIO(gzip.decompress(body)))
 for name in ['vmlinuz','rootfs']:(w/name).write_bytes(fs.get('/boot/'+name).open().read())
 template=a.template.read_bytes();assert sha(template)=='00dba53173528f00efc3a4858a95225908d65a4807e6376b8884d41416e70cbf','Wrong EFI template';disk=bytearray(gzip.decompress(template));assert len(disk)==262144000
 parts={1:(2048,102400),2:(104448,10240),3:(114688,102400),5:(219136,286720)}
 assert disk[510:512]==b'\x55\xaa' and disk[466]==0xef,'Need EFI template with ESP'
 # p2 is reserved for iKuai device identity; it MUST NOT be the ESP.
 # Relocate the template ESP into a new logical p6, keeping p1/p3/p5 numbers.
 esp=bytearray(disk[104448*512:114688*512]);struct.pack_into('<I',esp,28,514048)
 disk.extend(bytes(256*1024**2-len(disk)))
 disk[466]=0x83
 struct.pack_into('<I',disk,446+3*16+12,524288-217088)
 def entry(kind,start,length):return bytes([0,254,255,255,kind,254,255,255])+struct.pack('<II',start,length)
 disk[217088*512+462:217088*512+478]=entry(0x05,512000-217088,12288)
 ebr=bytearray(512);ebr[446:462]=entry(0xef,2048,10240);ebr[510:512]=b'\x55\xaa'
 disk[512000*512:512001*512]=ebr
 disk[104448*512:114688*512]=bytes(10240*512)
 disk[514048*512:524288*512]=esp
 parts[6]=(514048,10240)
 for i,(s,c) in parts.items():(w/f'p{i}.img').write_bytes(disk[s*512:(s+c)*512])
 old=ExtFS(open(w/'p1.img','rb'));cfg=old.get('/boot/grub/grub.cfg').open().read().decode()
 assert '3.7.26' in cfg
 assert 'DEVELOPER=true' in cfg and 'set default=1' in cfg
 (w/'grub.cfg').write_text(cfg)
 def run(args,log):
  r=subprocess.run([str(x) for x in args],stdout=subprocess.PIPE,stderr=subprocess.STDOUT);(w/log).write_bytes(r.stdout);assert r.returncode==0,r.stdout.decode(errors='replace')
 dbg=a.tools/'debugfs/debugfs';check=a.tools/'e2fsck/e2fsck';mk=a.tools/'misc/mke2fs'
 commands=''
 for name,dest in [('vmlinuz','/boot/vmlinuz'),('rootfs','/boot/rootfs'),('grub.cfg','/boot/grub/grub.cfg')]:
  try:old.get(dest)
  except FileNotFoundError:pass
  else:commands+=f'rm {dest}\n'
  commands+=f'write "{(w/name).resolve()}" {dest}\nset_inode_field {dest} mode 0100644\n'
 (w/'boot.commands').write_text(commands);run([dbg,'-w','-f',w/'boot.commands',w/'p1.img'],'boot-edit.log')
 # Brand-new config and log filesystems: no imported router state or deleted old scripts.
 os.environ['MKE2FS_CONFIG']=str((a.tools/'misc/mke2fs.conf').resolve())
 for i in [3,5]:
  (w/f'p{i}.img').write_bytes(bytes(parts[i][1]*512))
  run([mk,'-F','-t','ext4','-b','4096','-I','256','-m','0','-O','^64bit,^metadata_csum,^orphan_file','-E','lazy_itable_init=0,lazy_journal_init=0',w/f'p{i}.img'],f'p{i}-format.log')
 hook=Path(__file__).with_name('deve.sh');shutil.copyfile(hook,w/'deve.sh')
 (w/'config.commands').write_text(f'write "{(w/"deve.sh").resolve()}" /deve.sh\nset_inode_field /deve.sh mode 0100755\n')
 run([dbg,'-w','-f',w/'config.commands',w/'p3.img'],'config-edit.log')
 core_dest='/.nr-wg-reality/'+core_meta['name']
 commands=f'mkdir /.nr-wg-reality\nset_inode_field /.nr-wg-reality mode 040700\nwrite "{core}" {core_dest}\nset_inode_field {core_dest} mode 0100600\n'
 (w/'core.commands').write_text(commands);run([dbg,'-w','-f',w/'core.commands',w/'p5.img'],'core-edit.log')
 with (w/'p5.img').open('rb') as stream:
  logs=ExtFS(stream);entry=logs.get(core_dest)
  assert entry.open().read()==core_data and entry.inode.i_uid==0 and entry.inode.i_gid==0 and entry.inode.i_mode==0o100600
  assert logs.get('/.nr-wg-reality').inode.i_mode==0o40700
 for i in [1,3,5]:run([check,'-f','-n',w/f'p{i}.img'],f'p{i}-check.log')
 for i,(s,c) in parts.items():
  b=(w/f'p{i}.img').read_bytes();assert len(b)==c*512;disk[s*512:(s+c)*512]=b
 new=ExtFS(open(w/'p1.img','rb'))
 for name in ['vmlinuz','rootfs']:assert new.get('/boot/'+name).open().read()==(w/name).read_bytes()
 out=a.output/NAME;out.write_bytes(disk)
 with open(str(out)+'.gz','wb') as f:
  with gzip.GzipFile(filename='',fileobj=f,mode='wb',compresslevel=9,mtime=0) as g:g.write(disk)
 report={'firmware_sha256':SHA,'template_sha256':sha(template),'raw_sha256':sha(disk),'gzip_sha256':sha(Path(str(out)+'.gz').read_bytes()),'raw_bytes':len(disk),'kernel_sha256':sha((w/'vmlinuz').read_bytes()),'encrypted_rootfs_sha256':sha((w/'rootfs').read_bytes()),'boot_mode':'x86_64 UEFI fallback + legacy BIOS; serial console default','defaults':'eth0 -> wan1, DHCP, WAN Web enabled; one-time initialization','partitions':parts,'boot_tested':False,'image_core_archive':core_meta['name'],'image_core_sha256':core_meta['sha256'],'offline_core_verified':True}
 (a.output/'build-report.json').write_text(json.dumps(report,indent=2)+'\n');(a.output/'SHA256SUMS').write_text(report['gzip_sha256']+'  '+NAME+'.gz\n'+report['raw_sha256']+'  '+NAME+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
