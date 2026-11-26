#!/usr/bin/env python3
"""Build a SHA-pinned, explicitly experimental local 3.7.26 firmware derivative.
Never boots guest code or writes a device. Preserves ext allocations and inode sizes.
"""
import base64, gzip, hashlib, io, json, lzma, os, runpy, struct, subprocess, tarfile, zlib
from pathlib import Path
from elftools.elf.elffile import ELFFile
from dissect.extfs import ExtFS
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import *
from unpack_ikuai import write_tar

SRC=Path('decrypted-3.7.26-enterprise')
OUT=Path('custom-3.7.26-enterprise'); OUT.mkdir(exist_ok=True)
sha=lambda b:hashlib.sha256(b).hexdigest()
ORIGINAL=Path('iKuai8_x64_3.7.26_Enterprise_Build202609111742.bin').read_bytes()
assert sha(ORIGINAL)=='79345ed39e9d12bfa99e3c1fa4d4f671da7efd2914bd328fc74d5b122fe6d2ab'

def emit(s): print(s,flush=True)
def savejson(p,x): p.write_text(json.dumps(x,indent=2,ensure_ascii=False)+'\n')
def replace_ext(image,changes):
    out=bytearray(image); fs=ExtFS(io.BytesIO(image))
    assert not fs.sb.s_feature_ro_compat & 0x400, 'metadata checksums require additional support'
    for path,data in changes.items():
        node=fs.get('/'+path); assert len(data)==node.size,(path,len(data),node.size)
        cursor=0
        for block,count in node.dataruns():
            assert block is not None,'Sparse file unsupported'
            length=min(count*fs.block_size,len(data)-cursor)
            if length<=0: break
            out[block*fs.block_size:block*fs.block_size+length]=data[cursor:cursor+length]; cursor+=length
        assert cursor==len(data)
    check=ExtFS(io.BytesIO(out))
    for path,data in changes.items(): assert check.get('/'+path).open().read()==data
    return bytes(out)

def pad_text(text,old):
    data=text.encode();assert len(data)<=len(old),(len(data),len(old))
    return data+b'\n'*(len(old)-len(data))

def patch_core(data):
    out=bytearray(data); e=ELFFile(io.BytesIO(data));syms=e.get_section_by_name('.symtab')
    fake=syms.get_symbol_by_name('g_ik_is_fake')[0]
    assert e.get_section(fake['st_shndx'])['sh_type']=='SHT_NOBITS' and fake['st_size']==1
    patches=[];refs=0
    for section in e.iter_sections():
        if section['sh_type']!='SHT_RELA':continue
        target=e.get_section(section['sh_info']); code=target.data()
        for i,r in enumerate(section.iter_relocations()):
            s=syms.get_symbol(r['r_info_sym'])
            if s.name!='g_ik_is_fake':
                assert not(s['st_info']['type']=='STT_SECTION' and s['st_shndx']==fake['st_shndx'] and abs(r['r_addend']-fake['st_value'])<8),'Unexpected alias reference'
                continue
            refs+=1;assert r['r_info_type']==2
            p=r['r_offset']; offset=target['sh_offset']+p
            if code[p-2:p]==b'\xc6\x05':
                assert code[p+4] in (0,1)
                if code[p+4]==1:
                    out[offset+4]=0; patches.append({'section':target.name,'offset':p-2,'kind':'nonzero immediate store becomes zero'})
            elif code[p-2:p]==b'\x88\x05':
                out[offset-2:offset+4]=b'\x90'*6
                struct.pack_into('<Q',out,section['sh_offset']+i*section['sh_entsize']+8,r['r_info_sym']<<32)
                patches.append({'section':target.name,'offset':p-2,'kind':'dynamic store removed; relocation changed to NONE'})
            else:
                assert code[p-2:p]==b'\x80\x3d' or code[p-3:p] in (b'\x0f\xb6\x15',b'\x0f\xb6\x35'),(target.name,hex(p),code[p-4:p].hex())
    assert refs==16,(refs,patches)
    assert len(patches)>=5
    savejson(OUT/'module-patches.json',{'original_sha256':sha(data),'modified_sha256':sha(out),'variable':'g_ik_is_fake','references_inspected':refs,'patches':patches})
    return bytes(out)

root=(SRC/'rootfs.img').read_bytes();fs=ExtFS(io.BytesIO(root));read=lambda p:fs.get('/'+p).open().read()
changes={}
old=read('etc/release');changes['etc/release']=pad_text(old.decode().replace('FIRMWAREID=10002','FIRMWAREID=10001').replace('MODELTYPE=X86ENT','MODELTYPE=X86'),old)
old=read('sbin/sysinit');text=old.decode();guard='if [ "$SUPPORT_APT" = "" -a "$specialized" = "1" ];then';assert text.count(guard)==1;text=text.replace(guard,'if true;then')
anchor='\t\t$IK_DIR_SCRIPT/rc boot >/dev/null 2>&1 &';assert text.count(anchor)==4;text=text.replace(anchor,anchor+'\n\t\t(sleep 5; $IK_DIR_SCRIPT/auth_code.sh save) >/dev/null 2>&1 &',1)
# Remove comment-only lines to make room without changing filesystem allocations.
text='\n'.join(line for line in text.split('\n') if not(line.lstrip().startswith('#') and not line.startswith('#!')))
changes['sbin/sysinit']=pad_text(text,old)
old=read('usr/ikuai/script/auth_code.sh');gwid=old.decode().split('__show_gwid()\n',1)[1].split('__check_param()',1)[0]
text='''#!/bin/bash /etc/ikcommon
Include sys/sysstat.sh
# Local custom build: status paired with the patched 3.7.26 core module.
save()
{
    mkdir -p /tmp/iktmp
    printf 'status=1\\nauth_info="Enterprise local custom"\\n' >/tmp/iktmp/auth_info
    Autoiecho auth_code activate_success
}
show()
{
    Show __json_result__
}
__show_data()
{
    local status=1 auth_info="Enterprise local custom"
    local data=$(json_output status:int auth_info:str)
    json_append __json_result__ data:json
}
__show_gwid()
'''+gwid
changes['usr/ikuai/script/auth_code.sh']=pad_text(text,old)
changes['lib/modules/5.10.194/ik_core.ko']=patch_core(read('lib/modules/5.10.194/ik_core.ko'))
root=replace_ext(root,changes);(OUT/'rootfs.img').write_bytes(root)
for p,data in changes.items():
    dest=OUT/'changed-files'/p;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
    if p.endswith('.sh') or p=='sbin/sysinit':subprocess.run(['/bin/bash','-n',str(dest)],check=True)
cache_ok=False
if (OUT/'rootfs.tar.gz').exists():
    with tarfile.open(OUT/'rootfs.tar.gz','r:gz') as archive:
        cache_ok=all(archive.extractfile(p).read()==v for p,v in changes.items())
if cache_ok and (OUT/'manifest.json').exists():entries=json.loads((OUT/'manifest.json').read_text())
else:
    entries=write_tar(ExtFS(io.BytesIO(root)),OUT/'rootfs.tar.gz');savejson(OUT/'manifest.json',entries)
oldentries={x['path']:x for x in json.loads((SRC/'manifest.json').read_text())}
actual=[x['path'] for x in entries if x!=oldentries.get(x['path'])]
assert set(actual)==set(changes),actual
emit('Rootfs modified: exactly four files, inode sizes and allocations preserved')

# Dedicated local signing key; never printed or placed in the firmware.
keyfile=OUT/'local-signing-key.pem'
if not keyfile.exists():
    pem=subprocess.run(['openssl','genrsa','2048'],check=True,capture_output=True).stdout
    if b'BEGIN PRIVATE KEY' in pem:
        pem=subprocess.run(['openssl','rsa','-traditional'],input=pem,check=True,capture_output=True).stdout
    assert b'BEGIN RSA PRIVATE KEY' in pem, 'Expected PKCS1 RSA key'
    fd=os.open(keyfile,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(pem)
pem=keyfile.read_bytes();der=base64.b64decode(b''.join(x for x in pem.splitlines() if not x.startswith(b'---')))
def tlv(data,pos=0):
    tag=data[pos];n=data[pos+1];p=pos+2
    if n&128:
        k=n&127;n=int.from_bytes(data[p:p+k],'big');p+=k
    return tag,data[p:p+n],p+n
_,seq,_=tlv(der);ints=[];p=0
while p<len(seq):
    tag,val,p=tlv(seq,p);assert tag==2,'Expected PKCS1 private key';ints.append(int.from_bytes(val,'big'))
_,modulus,exponent,private,*_=ints;assert exponent==65537
pub=b'\x30\x82\x01\x0a\x02\x82\x01\x01\x00'+modulus.to_bytes(256,'big')+bytes.fromhex('0203010001')
(OUT/'local-public-key.der').write_bytes(pub)
def sign(data):
    tail=bytes.fromhex('3031300d060960864801650304020105000420')+hashlib.sha256(data).digest()
    em=b'\x00\x01'+b'\xff'*(256-len(tail)-3)+b'\x00'+tail
    return pow(int.from_bytes(em,'big'),private,modulus).to_bytes(256,'big')

oldpub=(SRC/'kernel-public-key.der').read_bytes();original_kernel=(SRC/'vmlinux').read_bytes();assert original_kernel.count(oldpub)==1
kernel=original_kernel.replace(oldpub,pub);(OUT/'vmlinux').write_bytes(kernel)
symbol_kernel=(SRC/'vmlinux.symbols').read_bytes().replace(oldpub,pub)
(OUT/'vmlinux.symbols').write_bytes(symbol_kernel)
helper=runpy.run_path('analysis/patch_vmlinuz_reference.py');bz=(SRC/'vmlinuz').read_bytes();start,psz=helper['find_payload'](bz);raw,used=helper['xz_decompress'](bz[start:]);assert raw==original_kernel
params=helper['parse_xz_params'](bz,start);params['filters'][-1]['preset']=9|lzma.PRESET_EXTREME
emit('Recompressing kernel with the local verification key')
if (OUT/'vmlinuz').exists() and helper['xz_decompress']((OUT/'vmlinuz').read_bytes()[start:])[0]==kernel:
    cached=(OUT/'vmlinuz').read_bytes();_,cache_used=helper['xz_decompress'](cached[start:]);compressed=cached[start:start+cache_used]
    emit('Reusing verified compressed kernel')
else:
    for preset,pb,lc in [(9|lzma.PRESET_EXTREME,2,3),(9,2,3),(9|lzma.PRESET_EXTREME,0,3),(9|lzma.PRESET_EXTREME,0,4),(9|lzma.PRESET_EXTREME,1,3)]:
        params['filters'][-1].update(preset=preset,pb=pb,lc=lc)
        compressed=lzma.compress(kernel,check=params['check'],filters=params['filters'])
        emit('Kernel compression preset=%s pb=%s lc=%s: %s / %s'%(preset,pb,lc,len(compressed),used))
        if len(compressed)<=used:break
    else:raise ValueError('Compressed kernel does not fit original allocation')
newbz=bytearray(bz);newbz[start:start+used]=compressed+b'\0'*(used-len(compressed))
assert struct.unpack('<I',bz[-4:])[0]==(zlib.crc32(bz[:-4])^0xffffffff)
struct.pack_into('<I',newbz,len(newbz)-4,zlib.crc32(newbz[:-4])^0xffffffff)
assert helper['xz_decompress'](newbz[start:])[0]==kernel
(OUT/'vmlinuz').write_bytes(newbz)

enc=(SRC/'rootfs.encrypted').read_bytes();n=len(enc)-660;meta=bytearray(enc[n+20:n+148]);assert meta[:4]==b'IKMF'
# Keep original payload size using valid XZ stream padding, preserving ext allocation.
emit('Compressing modified rootfs')
xz=lzma.compress(root,check=lzma.CHECK_CRC32,preset=9|lzma.PRESET_EXTREME);assert len(xz)<=n,(len(xz),n)
plain=xz+b'\0'*(n-len(xz));assert (n-len(xz))%4==0
decoder=lzma.LZMADecompressor();assert decoder.decompress(plain)==root and decoder.eof;assert not any(decoder.unused_data) and len(decoder.unused_data)%4==0;(OUT/'rootfs.xz').write_bytes(plain)
meta[32:64]=hashlib.sha256(plain).digest();meta=bytes(meta);msig=sign(meta)
e=ELFFile(io.BytesIO(symbol_kernel))
def virtual_bytes(addr,size):
    for segment in e.iter_segments():
        if segment['p_type']=='PT_LOAD' and segment['p_vaddr']<=addr<segment['p_vaddr']+segment['p_filesz']:
            o=addr-segment['p_vaddr'];return segment.data()[o:o+size]
    raise ValueError(hex(addr))
words=struct.unpack('<16I',virtual_bytes(0xffffffff82200400,64))
def raw_hash(buf):
    h=0xffffffff
    for c in buf:
        t=words[(c^h)&15]^(h>>4);h=words[(t^(c>>4))&15]^(t>>4)
    return (~h)&0xffffffff
checksum=raw_hash(raw_hash(plain).to_bytes(4,'big')).to_bytes(4,'big')
# The core module rechecks a legacy MD5-derived tag after boot. Keep it valid.
plain_md5=hashlib.md5(plain).digest()
legacy_tag=hashlib.md5(hashlib.md5(plain_md5[8:]+plain_md5[:8]+checksum).digest()).digest()
trailer=legacy_tag+checksum+meta+msig

def transform(data,ctx,decode=False):
    width,rounds=struct.unpack_from('<HH',ctx,0xa00);assert width==2048 and rounds==3
    out=bytearray(data);perm=ctx[0x800:0x900];inverse=ctx[0x900:0xa00]
    assert bytes(inverse[v] for v in perm)==bytes(range(256))
    for r in (range(rounds-1,-1,-1) if decode else range(rounds)):
        for i in range(width):
            mix=ctx[(17*r+i)%width]+len(data)+r;carry=(mix>>8)&255;s=(mix&7)+1;lut=[]
            for c in range(256):
                if decode:
                    v=((c-r-carry)&255)^carry;v=((v>>s)|(v<<(8-s)))&255;v=inverse[(v-mix-r)&255]
                else:
                    v=(perm[c]+mix+r)&255;v=((v<<s)|(v>>(8-s)))&255;v=((v^carry)+r+carry)&255
                lut.append(v)
            out[i::width]=out[i::width].translate(bytes(lut))
    return bytes(out)

def simulate(data,verify=False):
    u=Uc(UC_ARCH_X86,UC_MODE_64);physical=lambda a:a&((1<<52)-1)
    u.mem_map(0xfffff81000000,0x4000000);u.mem_map(0,0x40000);u.mem_map(0x10000000,0x200000);u.mem_map(0x20000000,0x4000000);u.mem_map(0x30000000,0x4000000)
    write=lambda a,v:u.mem_write(physical(a),bytes(v));read=lambda a,n:bytes(u.mem_read(physical(a),n))
    for s in e.iter_segments():
        if s['p_type']=='PT_LOAD' and s['p_filesz']:write(s['p_vaddr'],s.data())
    write(0x20000000,data);write(0xffffffff82c84078,struct.pack('<Q',0x20000000));write(0xffffffff82c84070,struct.pack('<Q',0x20000000+len(data)));write(0xffffffff828b7d50,b'\xff'*8)
    u.reg_write(UC_X86_REG_RSP,0x101fff00);u.reg_write(UC_X86_REG_GS_BASE,0)
    context={};checks=[]
    def ret(v=0):
        sp=u.reg_read(UC_X86_REG_RSP);dest=int.from_bytes(read(sp,8),'little');u.reg_write(UC_X86_REG_RAX,v&0xffffffffffffffff);u.reg_write(UC_X86_REG_RSP,sp+8);u.reg_write(UC_X86_REG_RIP,dest)
    def hook(uc,pc,size,unused):
        a,b,c,d=[u.reg_read(r) for r in (UC_X86_REG_RDI,UC_X86_REG_RSI,UC_X86_REG_RDX,UC_X86_REG_RCX)]
        if pc==0xffffffff82bddfb0:write(c,hashlib.sha256(read(a,b)).digest());ret()
        elif pc==0xffffffff82bdf640:
            digest=read(a,32);sig=read(b,c);tail=bytes.fromhex('3031300d060960864801650304020105000420')+digest;expected=b'\0\1'+b'\xff'*(256-len(tail)-3)+b'\0'+tail
            assert c==256 and pow(int.from_bytes(sig,'big'),65537,modulus).to_bytes(256,'big')==expected,'RSA check failed'
            checks.append(digest.hex());ret()
        elif pc==0xffffffff81c64170:write(a,read(b,c));ret(a)
        elif pc==0xffffffff8124f340:assert a<0x4000000;ret(0x30000000)
        elif pc in (0xffffffff81bc0c22,0xffffffff81c63cc0):raise RuntimeError('Kernel verification failure '+hex(pc)+' '+repr(read(a,80)))
        elif pc==0xffffffff82bdfbc0:ret(raw_hash(read(a,b)))
        elif pc==0xffffffff82bdfde0:
            context['bytes']=read(a,0xa10)
            if not verify:u.emu_stop();return
            decoded=transform(read(c,d),context['bytes'],True);assert decoded==plain,'Roundtrip mismatch';write(c,decoded);ret()
        elif pc==0xffffffff82b8eb73:
            if a==0x20000000:
                assert b==n and read(a,b)==plain;context['verified_to_unpack']=True;u.emu_stop()
            else:ret()
    for address in [0xffffffff82bddfb0,0xffffffff82bdf640,0xffffffff81c64170,0xffffffff8124f340,0xffffffff81bc0c22,0xffffffff81c63cc0,0xffffffff82bdfbc0,0xffffffff82bdfde0,0xffffffff82b8eb73]:u.hook_add(UC_HOOK_CODE,hook,begin=address,end=address)
    u.emu_start(0xffffffff82b8ee93,0xffffffff82b8f278,timeout=180000000,count=10000000)
    assert len(checks)==2 and 'bytes' in context,(checks,hex(u.reg_read(UC_X86_REG_RIP)))
    if verify:assert context.get('verified_to_unpack'),hex(u.reg_read(UC_X86_REG_RIP))
    context['rsa_checks']=checks;return context

emit('Deriving cipher context using the unchanged kernel verification routines')
dummy=bytes(n)+trailer;dummy+=sign(dummy)
ctx=simulate(dummy)['bytes'];cipher=transform(plain,ctx);payload=cipher+trailer;payload+=sign(payload)
assert len(payload)==len(enc);(OUT/'rootfs.encrypted').write_bytes(payload)
emit('Verifying both signatures, decryption, checksum, plaintext hash and kernel acceptance path')
verified=simulate(payload,True);assert verified['bytes']==ctx
boot=replace_ext((SRC/'boot.img').read_bytes(),{'boot/rootfs':payload,'boot/vmlinuz':bytes(newbz)})
(OUT/'boot.img').write_bytes(boot)
filename='iKuai8_x64_3.7.26_Enterprise_CustomAuth_Build202609111742_EXPERIMENTAL.bin'
body=gzip.compress(boot,compresslevel=9,mtime=0);header=json.loads((SRC/'header.json').read_text());header.update(filename=filename,firmwareid='10001',length=str(len(body)),md5=hashlib.md5(body).hexdigest(),sha256=sha(body)[:32]);head=gzip.compress(json.dumps(header,separators=(',',':')).encode(),mtime=0)[10:];result=struct.pack('>I',len(head))+head+body
(OUT/filename).write_bytes(result);savejson(OUT/'header.json',header)
# Re-read the final container and both filesystem payloads, not just intermediates.
final=(OUT/filename).read_bytes();hn=struct.unpack('>I',final[:4])[0];hd=json.loads(gzip.decompress(bytes.fromhex('1f8b08006f9b4b590003')+final[4:4+hn]));bb=final[4+hn:]
assert len(bb)==int(hd['length']) and hashlib.md5(bb).hexdigest()==hd['md5'] and sha(bb).startswith(hd['sha256'])
bf=ExtFS(io.BytesIO(gzip.decompress(bb)));assert bf.get('/boot/rootfs').open().read()==payload and bf.get('/boot/vmlinuz').open().read()==bytes(newbz)
report={'base_firmware_sha256':sha(ORIGINAL),'output_filename':filename,'output_sha256':sha(result),'output_md5':hashlib.md5(result).hexdigest(),'changed_rootfs_files':actual,'kernel_change':'only embedded RSA public key; recompression and bzImage CRC updated','signature_checks':verified['rsa_checks'],'roundtrip_decryption':True,'kernel_verified_through_rootfs_unpack_call':True,'filesystem_allocations_and_sizes_preserved':True,'final_container_checks':True,'boot_tested':False,'status':'EXPERIMENTAL - NOT BOOT TESTED','local_key_fingerprint':sha(pub)}
savejson(OUT/'verification.json',report)
(OUT/'SHA256SUMS').write_text(sha(result)+'  '+filename+'\n')
emit(json.dumps(report,ensure_ascii=False,indent=2))
