#!/usr/bin/env python3
"""Recover the 3.7.26 IKMF3 cipher context in an isolated Unicorn CPU.

This is specific to the SHA-256-pinned official x64 free and enterprise
Build202609111743 / Build202609111742 images, which share the same kernel.
No kernel is booted, no host system calls are exposed, and RSA verification
is performed against the public key embedded in this same kernel.
"""
from pathlib import Path
import hashlib
import io
import json
import lzma
import struct
import argparse

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn.x86_const import *
from dissect.extfs import ExtFS
from unpack_ikuai import write_tar

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('output', nargs='?', type=Path, default=Path('decrypted-3.7.26'))
ap.add_argument('firmware', nargs='?', type=Path, default=Path('iKuai8_x64_3.7.26_Build202609111743.bin'))
opts = ap.parse_args()
OUT = opts.output
firmware = opts.firmware.read_bytes()
SUPPORTED_FIRMWARE = {
    'cbc654b18600ddf1b0f51ed99d8012772faeac6853d63dc3dfa6662d228baf85': 'free',
    '79345ed39e9d12bfa99e3c1fa4d4f671da7efd2914bd328fc74d5b122fe6d2ab': 'enterprise',
}
firmware_hash = hashlib.sha256(firmware).hexdigest()
assert firmware_hash in SUPPORTED_FIRMWARE, 'Unsupported firmware build'
assert hashlib.sha256((OUT / 'vmlinux').read_bytes()).hexdigest() == '5a840d4aa7ff9317f4669e06270d7133ab39d3bf3eac4a22be9cf156e29e07f7', 'Unexpected kernel'
assert hashlib.sha256((OUT / 'vmlinux.symbols').read_bytes()).hexdigest() == '607762068d2b4c5d15d1a11dbed68e3d13b3410b4e832afbfd0f9704d2461ebf', 'Unexpected symbol recovery output' 
data = (OUT / 'rootfs.encrypted').read_bytes()
kernel = (OUT / 'vmlinux.symbols').read_bytes()
e = ELFFile(io.BytesIO(kernel))
u = Uc(UC_ARCH_X86, UC_MODE_64)
physical = lambda address: address & ((1 << 52) - 1)
write = lambda address, value: u.mem_write(physical(address), value)
u.mem_map(0xfffff81000000, 0x4000000)
u.mem_map(0, 0x40000)
u.mem_map(0x10000000, 0x200000)
u.mem_map(0x20000000, 0x4000000)
for p in e.iter_segments():
    if p['p_type'] == 'PT_LOAD' and p['p_filesz']:
        write(p['p_vaddr'], p.data())
write(0x20000000, data)
write(0xffffffff82c84078, struct.pack('<Q', 0x20000000))
write(0xffffffff82c84070, struct.pack('<Q', 0x20000000 + len(data)))
write(0xffffffff828b7d50, b'\xff' * 8)
u.reg_write(UC_X86_REG_RSP, 0x101fff00)
u.reg_write(UC_X86_REG_GS_BASE, 0)
read = lambda p, n: bytes(u.mem_read(physical(p), n))
reg = u.reg_read
args = lambda: [reg(x) for x in (UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9)]
signature_checks = []
context = {}


def ret(value):
    sp = reg(UC_X86_REG_RSP)
    dest = int.from_bytes(read(sp, 8), 'little')
    u.reg_write(UC_X86_REG_RAX, value & 0xffffffffffffffff)
    u.reg_write(UC_X86_REG_RSP, sp + 8)
    u.reg_write(UC_X86_REG_RIP, dest)


pub = read(0xffffffff82200200, 270)
assert pub[:9] == bytes.fromhex('3082010a0282010100')
modulus = int.from_bytes(pub[9:265], 'big')
assert pub[265:] == bytes.fromhex('0203010001')
(OUT / 'kernel-public-key.der').write_bytes(pub)


def hook(uc, address, size, unused):
    a, b, c, d, e_, f = args()
    if address == 0xffffffff82bddfb0:
        write(c, hashlib.sha256(read(a, b)).digest())
        ret(0)
    elif address == 0xffffffff82bdf640:
        assert c == 256
        digest = read(a, 32)
        signature = read(b, c)
        encoded = pow(int.from_bytes(signature, 'big'), 65537, modulus).to_bytes(256, 'big')
        tail = bytes.fromhex('3031300d060960864801650304020105000420') + digest
        expected = b'\x00\x01' + b'\xff' * (256 - len(tail) - 3) + b'\x00' + tail
        assert encoded == expected, 'RSA signature mismatch'
        signature_checks.append({'sha256': digest.hex(), 'result': 'passed'})
        print('RSA signature verified', len(signature_checks), flush=True)
        ret(0)
    elif address == 0xffffffff81c64170:
        write(a, read(b, c))
        ret(a)
    elif address == 0xffffffff82b8eb73:
        ret(0)  # Empty built-in initramfs; stop before real unpacking.
    elif address in (0xffffffff81bc0c22, 0xffffffff81c63cc0):
        raise RuntimeError(f'Kernel verification failure at {address:x}; {read(a, 80)!r}')
    elif address == 0xffffffff82be0042:
        context['derived_key'] = read(c, d).hex()
    elif address == 0xffffffff82bdfde0:
        context.update({'context': read(a, 0xa10).hex(), 'size_argument': b,
                        'payload_address': c, 'payload_size': d})
        uc.emu_stop()


for address in (0xffffffff82bddfb0, 0xffffffff82bdf640, 0xffffffff81c64170,
                0xffffffff82b8eb73, 0xffffffff81bc0c22, 0xffffffff81c63cc0,
                0xffffffff82be0042, 0xffffffff82bdfde0):
    u.hook_add(UC_HOOK_CODE, hook, begin=address, end=address)
def memory_error(uc, access, address, size, value, unused):
    print('Unmapped', access, hex(address), 'RIP', hex(reg(UC_X86_REG_RIP)), flush=True)
    return False
u.hook_add(UC_HOOK_MEM_INVALID, memory_error)
u.emu_start(0xffffffff82b8ee93, 0xffffffff82b8f278, timeout=30000000, count=2000000)
assert 'context' in context, f"Did not reach cipher: RIP={reg(UC_X86_REG_RIP):x}"
assert len(signature_checks) == 2
(OUT / 'cipher-context.json').write_text(json.dumps(context, indent=2) + '\n')
ctx = bytes.fromhex(context['context'])
width, rounds = struct.unpack_from('<HH', ctx, 0xa00)
position = struct.unpack_from('<I', ctx, 0xa0c)[0]
assert width == 2048 and rounds == 3 and ctx[0xa08] & 7 == 7 and position == 0
size = context['payload_size']
assert size == len(data) - 660
plain = bytearray(data[:size])
inverse = ctx[0x900:0xa00]
for round_ in range(rounds - 1, -1, -1):
    for i in range(width):
        mix = ctx[(17*round_ + i) % width] + context['size_argument'] + round_
        carry = (mix >> 8) & 255
        shift = (mix & 7) + 1
        lut = []
        for x in range(256):
            v = ((x - round_ - carry) & 255) ^ carry
            v = ((v >> shift) | (v << (8-shift))) & 255
            lut.append(inverse[(v - mix - round_) & 255])
        plain[i::width] = plain[i::width].translate(bytes(lut))
assert plain[:6] == b'\xfd7zXZ\x00', plain[:16].hex()
print('XZ header recovered; checking hashes', flush=True)
manifest = data[size+20:size+148]
assert manifest[:4] == b'IKMF'
assert hashlib.sha256(plain).digest() == manifest[32:64], 'Signed plaintext SHA256 mismatch'
words = struct.unpack('<16I', read(0xffffffff82200400, 64))
def raw_hash(buf):
    h = 0xffffffff
    for b in buf:
        t = words[(b ^ h) & 15] ^ (h >> 4)
        h = words[(t ^ (b >> 4)) & 15] ^ (t >> 4)
    return (~h) & 0xffffffff
h = int.from_bytes(raw_hash(raw_hash(plain).to_bytes(4, 'big')).to_bytes(4, 'big'), 'little')
assert h == int.from_bytes(data[size+16:size+20], 'little'), 'Rootfs checksum mismatch'
(OUT / 'rootfs.xz').write_bytes(plain)
image = lzma.decompress(plain)
(OUT / 'rootfs.img').write_bytes(image)
fs = ExtFS(io.BytesIO(image))
release = fs.get('/etc/release').open().read().decode()
(OUT / 'release.txt').write_text(release)
entries = write_tar(fs, OUT / 'rootfs.tar.gz')
(OUT / 'manifest.json').write_text(json.dumps(entries, indent=2) + '\n')
report = {'format': 'IKMF version 3; 660-byte trailer', 'edition': SUPPORTED_FIRMWARE[firmware_hash],
          'rsa_signatures': signature_checks,
          'signed_plaintext_sha256': hashlib.sha256(plain).hexdigest(),
          'rootfs_checksum': f'{h:08x}', 'xz_integrity': 'passed',
          'rootfs_image_sha256': hashlib.sha256(image).hexdigest(),
          'firmware_md5': hashlib.md5(firmware).hexdigest(),
          'firmware_sha256': hashlib.sha256(firmware).hexdigest(),
          'entries': len(entries), 'release': release}
(OUT / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
