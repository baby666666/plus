import base64,gzip,hashlib,io,json,lzma,os,struct,subprocess,shutil
from pathlib import Path
from elftools.elf.elffile import ELFFile
from dissect.extfs import ExtFS
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
ROOT=Path(__file__).resolve().parent.parent
SRC=ROOT/'decrypted-3.7.26-enterprise';BASE=ROOT/'custom-3.7.26-enterprise';OUT=ROOT/'port-3726/output'
DBG=ROOT/'toolbuild/e2fsprogs-1.47.3/debugfs/debugfs';CHECK=ROOT/'toolbuild/e2fsprogs-1.47.3/e2fsck/e2fsck'
BASE_SHA=json.loads((BASE/'verification.json').read_text())['output_sha256']
sha=lambda b:hashlib.sha256(b).hexdigest()
def emit(s):print(s,flush=True)
def savejson(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
root=(OUT/'rootfs.img').read_bytes();actual=list(json.loads((OUT/'changes.json').read_text()))
# Dedicated local signing key; never printed or placed in the firmware.
keyfile=OUT/'local-signing-key.pem'
assert keyfile.exists(), 'Matching local signing key required; never silently generate a mismatched key'
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

symbol_kernel=(OUT/'vmlinux.symbols').read_bytes();newbz=(OUT/'vmlinuz').read_bytes()
enc=(SRC/'rootfs.encrypted').read_bytes();n=len(enc)-660;meta=bytearray(enc[n+20:n+148]);assert meta[:4]==b'IKMF'
# Permit a bounded growth of the rootfs file; retain filesystem and signature validation.
# IKMF3 stores compressed and encrypted payload lengths as little-endian uint64s.
original_n=n
emit('Compressing modified rootfs')
filters=[{"id":lzma.FILTER_X86},{"id":lzma.FILTER_LZMA2,"preset":9|lzma.PRESET_EXTREME,"dict_size":128*1024**2,"pb":1}]
cached=OUT/'rootfs.xz'
xz=cached.read_bytes() if cached.exists() and lzma.decompress(cached.read_bytes())==root else lzma.compress(root,check=lzma.CHECK_CRC32,filters=filters)
emit('Compressed rootfs: '+str(len(xz))+'; original payload: '+str(original_n))
# New TLS executable needs a bounded additional 4 MiB; boot filesystem capacity
# and exact payload recovery are independently verified below.
n=max(original_n,len(xz));assert n%4==0 and n<=original_n+4*1048576,'rootfs growth exceeds build limit'
assert struct.unpack_from('<QQ',meta,16)==(original_n,original_n)
struct.pack_into('<QQ',meta,16,n,n)
emit('XZ bytes: '+str(len(xz))+'; payload bytes: '+str(n)+'; growth: '+str(n-original_n))
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
assert len(payload)==n+660;(OUT/'rootfs.encrypted').write_bytes(payload)
emit('Verifying both signatures, decryption, checksum, plaintext hash and kernel acceptance path')
verified=simulate(payload,True);assert verified['bytes']==ctx
shutil.copy2(BASE/'boot.img',OUT/'boot.img')
cmds='rm /boot/rootfs\nwrite "'+str(OUT/'rootfs.encrypted')+'" /boot/rootfs\nset_inode_field /boot/rootfs mode 0100644\n'
(OUT/'boot.commands').write_text(cmds)
r=subprocess.run([str(DBG),'-w','-f',str(OUT/'boot.commands'),str(OUT/'boot.img')],capture_output=True);(OUT/'boot-edit.log').write_bytes(r.stdout+r.stderr);assert r.returncode==0
r=subprocess.run([str(CHECK),'-f','-n',str(OUT/'boot.img')],capture_output=True);(OUT/'boot-check.log').write_bytes(r.stdout+r.stderr);assert r.returncode==0,r.stdout+r.stderr
boot=(OUT/'boot.img').read_bytes()
(OUT/'boot.img').write_bytes(boot)
filename='iKuai8_x64_3.7.26_Enterprise_NativeRouting_V1_0.bin'
body=gzip.compress(boot,compresslevel=9,mtime=0);header=json.loads((SRC/'header.json').read_text());header.update(filename=filename,firmwareid='10001',length=str(len(body)),md5=hashlib.md5(body).hexdigest(),sha256=sha(body)[:32]);head=gzip.compress(json.dumps(header,separators=(',',':')).encode(),mtime=0)[10:];result=struct.pack('>I',len(head))+head+body
(OUT/filename).write_bytes(result);savejson(OUT/'header.json',header)
# Re-read the final container and both filesystem payloads, not just intermediates.
final=(OUT/filename).read_bytes();hn=struct.unpack('>I',final[:4])[0];hd=json.loads(gzip.decompress(bytes.fromhex('1f8b08006f9b4b590003')+final[4:4+hn]));bb=final[4+hn:]
assert len(bb)==int(hd['length']) and hashlib.md5(bb).hexdigest()==hd['md5'] and sha(bb).startswith(hd['sha256'])
bf=ExtFS(io.BytesIO(gzip.decompress(bb)));assert bf.get('/boot/rootfs').open().read()==payload and bf.get('/boot/vmlinuz').open().read()==bytes(newbz)
report={'base_firmware_sha256':BASE_SHA,'output_filename':filename,'output_sha256':sha(result),'output_md5':hashlib.md5(result).hexdigest(),'changed_rootfs_files':actual,'kernel_change':'Same locally rebuilt 3.7.26 baseline kernel; new build not boot tested','signature_checks':verified['rsa_checks'],'roundtrip_decryption':True,'kernel_verified_through_rootfs_unpack_call':True,'filesystem_checked':True,'final_container_checks':True,'boot_tested':False,'status':'EXPERIMENTAL - NOT BOOT TESTED','local_key_fingerprint':sha(pub)}
savejson(OUT/'verification.json',report)
(OUT/'SHA256SUMS').write_text(sha(result)+'  '+filename+'\n')
emit(json.dumps(report,ensure_ascii=False,indent=2))
