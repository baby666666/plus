#!/usr/bin/env python3
"""Rebuild a derivative from pinned clean inputs, using a newly generated key.

Run with the venv containing materials/base/requirements-analysis.txt.
Never installs firmware, boots guest code, or writes a block device.
"""
from pathlib import Path
import argparse, gzip, hashlib, io, json, os, re, shutil, subprocess, sys, tarfile

ROOT=Path(__file__).resolve().parents[1]
M=ROOT/'materials'
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def run(args,cwd):
    print('Running:', ' '.join(map(str,args)),flush=True)
    subprocess.run([str(x)for x in args],cwd=cwd,check=True)
def main():
    p=argparse.ArgumentParser()
    p.add_argument('--inputs-archive',type=Path,required=True)
    p.add_argument('--workdir',type=Path,required=True,help='New directory outside the checkout; contains private signing keys')
    p.add_argument('--label',default='V2_0-REBUILD',help='Safe unique output label; never overwrite the published release')
    a=p.parse_args();W=a.workdir.resolve()
    assert re.fullmatch(r'[A-Za-z0-9_-]{1,48}',a.label),'Unsafe output label'
    assert W!=ROOT and ROOT not in W.parents,'Keep private build output outside the checkout'
    assert not W.exists(),'Work directory already exists; preserve it and choose a new one'
    for tool in ['cc','make','tar','openssl','node']:
        assert shutil.which(tool),'Missing system tool: '+tool
    converter=Path(sys.executable).with_name('vmlinux-to-elf')
    assert converter.is_file(),'Install requirements-analysis.txt in this venv first'
    run([sys.executable,ROOT/'tools/check_materials.py'],ROOT)
    bundle=json.loads((M/'base/input-bundle.json').read_text())
    archive=a.inputs_archive.resolve()
    assert archive.stat().st_size==bundle['bytes'] and sha(archive)==bundle['sha256'],'Input archive differs from pinned release'
    W.mkdir(parents=True,mode=0o700)
    with tarfile.open(archive,'r:gz')as t:
        members=t.getmembers()
        assert {x.name for x in members}=={'inputs/'+n for n in bundle['files']}
        for member in members:
            assert member.isfile() and member.name.startswith('inputs/') and '..'not in Path(member.name).parts
            data=t.extractfile(member).read();name=Path(member.name).name;entry=bundle['files'][name]
            assert len(data)==entry['bytes'] and hashlib.sha256(data).hexdigest()==entry['sha256']
            dest=W/member.name;dest.parent.mkdir(exist_ok=True);dest.write_bytes(data)
    tools=W/'toolbuild';tools.mkdir()
    for name in ['e2fsprogs-1.47.3','lua-5.1.5']:
        run(['tar','-xzf',M/'base/vendor'/(name+'.tar.gz'),'-C',tools],W)
    E=tools/'e2fsprogs-1.47.3'
    run(['./configure','--disable-nls','--disable-fuse2fs','--disable-uuidd'],E)
    run(['make','-j2'],E)
    run(['make','generic'],tools/'lua-5.1.5')
    for n in ['unpack_ikuai.py','recover_3726.py','build_3726_custom.py']:
        shutil.copy2(M/'base'/n,W/n)
    shutil.copytree(M/'base/analysis',W/'analysis')
    official='iKuai8_x64_3.7.26_Enterprise_Build202609111742.bin'
    shutil.copy2(W/'inputs/official-enterprise.bin',W/official)
    run([sys.executable,'unpack_ikuai.py',official,'decrypted-3.7.26-enterprise'],W)
    run([converter,'decrypted-3.7.26-enterprise/vmlinux','decrypted-3.7.26-enterprise/vmlinux.symbols'],W)
    run([sys.executable,'-u','recover_3726.py','decrypted-3.7.26-enterprise',official],W)
    run([sys.executable,'-u','build_3726_custom.py'],W)
    shutil.copytree(M/'firmware/port-3726',W/'port-3726',ignore=shutil.ignore_patterns('output','__pycache__'))
    pack=W/'port-3726/pack.py';content=pack.read_text();old="filename='iKuai8_x64_3.7.26_Enterprise_NativeRouting_V2_0.bin'"
    assert content.count(old)==1
    filename='iKuai8_x64_3.7.26_Enterprise_NativeRouting_'+a.label+'.bin'
    pack.write_text(content.replace(old,'filename='+repr(filename)))
    run([sys.executable,'-u',W/'port-3726/assemble.py'],W)
    run([sys.executable,'-u',pack],W)
    O=W/'port-3726/output';verification=json.loads((O/'verification.json').read_text())
    assert sha(O/filename)==verification['output_sha256'] and verification['roundtrip_decryption']
    # Each derivative has a new matching kernel key, not the private release key.
    key=W/'custom-3.7.26-enterprise/local-signing-key.pem';assert key.is_file()
    for private_key in [key,O/'local-signing-key.pem']:private_key.chmod(0o600)
    shipped=json.loads((ROOT/'release.json').read_text())
    assert verification['local_key_fingerprint']!=shipped['signing_public_key_sha256'],'Fresh build unexpectedly reused release key'
    summary={'rebuilt_from_official':True,'source_release':shipped['release'],'base_firmware':official,'output_filename':filename,
      'output_sha256':verification['output_sha256'],'new_signing_key_generated':True,
      'public_key_sha256':verification['local_key_fingerprint'],'boot_tested':False,
      'status':'OFFLINE REBUILD PASSED; MUST BOOT AND TEST THIS NEW BINARY BEFORE USE'}
    (W/'rebuild-result.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2),flush=True)
    print('Private key remains only in workdir. Do not publish this directory.',flush=True)
if __name__=='__main__':main()
