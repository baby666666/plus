#!/usr/bin/env python3
"""Read-only iKuai BIN container extractor and ext filesystem archive helper.

Requires dissect.extfs. For the 3.7.26 cipher use recover_3726.py.
No firmware binaries or scripts are executed.
"""
import argparse
import gzip
import hashlib
import io
import json
import lzma
from pathlib import Path
import stat
import struct
import tarfile

from dissect.extfs import ExtFS

def write_tar(fs, destination):
    entries = []
    with tarfile.open(destination, 'w:gz') as archive:
        def walk(node, prefix=''):
            for item in node.iterdir():
                name = item.filename
                if name in ('.', '..'):
                    continue
                if '/' in name or '\x00' in name:
                    raise ValueError('Unsafe directory entry')
                path = prefix + name
                info = tarfile.TarInfo(path)
                info.mode = item.inode.i_mode & 0o7777
                info.uid = item.inode.i_uid
                info.gid = item.inode.i_gid
                info.mtime = int(item.mtime.timestamp())
                entry = {'path': path, 'mode': oct(item.inode.i_mode), 'size': item.size}
                if item.filetype == stat.S_IFDIR:
                    info.type = tarfile.DIRTYPE
                    archive.addfile(info)
                    walk(item, path + '/')
                elif item.filetype == stat.S_IFREG:
                    info.size = item.size
                    content = item.open().read()
                    entry['sha256'] = hashlib.sha256(content).hexdigest()
                    archive.addfile(info, io.BytesIO(content))
                elif item.filetype == stat.S_IFLNK:
                    info.type = tarfile.SYMTYPE
                    info.linkname = item.link
                    entry['link'] = item.link
                    archive.addfile(info)
                else:
                    entry['archive_note'] = 'Special inode retained only in rootfs.img'
                entries.append(entry)
        walk(fs.get('/'))
    return entries


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('firmware', type=Path)
    ap.add_argument('output', type=Path)
    args = ap.parse_args()
    args.output.mkdir(exist_ok=False, parents=True)
    data = args.firmware.read_bytes()
    n = struct.unpack('>I', data[:4])[0]
    header = json.loads(gzip.decompress(bytes.fromhex('1f8b08006f9b4b590003') + data[4:4+n]))
    body = data[4+n:]
    checks = {
        'length': len(body) == int(header['length']),
        'md5': hashlib.md5(body).hexdigest() == header['md5'],
        'sha256_prefix': hashlib.sha256(body).hexdigest().startswith(header['sha256']),
    }
    if not all(checks.values()):
        raise ValueError(f'BIN header validation failed: {checks}')
    (args.output / 'header.json').write_text(json.dumps(header, indent=2) + '\n')
    disk = gzip.decompress(body)
    (args.output / 'boot.img').write_bytes(disk)
    bootfs = ExtFS(io.BytesIO(disk))
    encrypted = bootfs.get('/boot/rootfs').open().read()
    (args.output / 'rootfs.encrypted').write_bytes(encrypted)
    (args.output / 'vmlinuz').write_bytes(bootfs.get('/boot/vmlinuz').open().read())
    kernel = (args.output / 'vmlinuz').read_bytes()
    offset = kernel.find(b'\xfd7zXZ\x00')
    if offset < 0:
        raise ValueError('No XZ kernel payload found')
    elf = lzma.LZMADecompressor().decompress(kernel[offset:])
    if elf[:4] != b'\x7fELF':
        raise ValueError('Kernel payload is not ELF')
    (args.output / 'vmlinux').write_bytes(elf)
    (args.output / 'container-verification.json').write_text(json.dumps(checks, indent=2) + '\n')
    print('BIN checks passed; boot/rootfs, vmlinuz and vmlinux extracted')


if __name__ == '__main__':
    main()
