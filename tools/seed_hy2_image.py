#!/usr/bin/env python3
"""Add the pinned HY2 archive to a fresh NativeRouting image's log partition."""
import argparse
import gzip
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from dissect.extfs import ExtFS
from dissect.util.stream import RangeStream

ARCHIVE = 'sing-box-1.14.4-linux-amd64-musl.tar.gz'
ARCHIVE_BYTES = 32555215
ARCHIVE_SHA = '8f7c5f0651238850d96a0e488e5473cd77ec1a0098f63942e943f475a12057ca'
CACHE = '/.nr-wg-reality'
LOG_PARTITION = [219136, 286720]  # Sectors in the 256 MiB clean installation template.


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_archive(fs):
    directory = fs.get(CACHE).inode
    member = fs.get(CACHE + '/' + ARCHIVE)
    inode = member.inode
    require((directory.i_mode, directory.i_uid, directory.i_gid) == (0o40700, 0, 0),
            'Incorrect cache directory permissions')
    require((inode.i_mode, inode.i_uid, inode.i_gid, inode.i_links_count, member.size) ==
            (0o100600, 0, 0, 1, ARCHIVE_BYTES), 'Incorrect archive metadata')
    with member.open() as stream:
        require(hashlib.file_digest(stream, 'sha256').hexdigest() == ARCHIVE_SHA,
                'Archive read from image failed the pinned checksum')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True, help='Unbooted raw .img next to build-report.json')
    parser.add_argument('--archive', type=Path, required=True, help='Pinned upstream Linux AMD64 musl archive')
    parser.add_argument('--e2fsprogs', type=Path, required=True, help='Built e2fsprogs-1.47.3 directory')
    parser.add_argument('--output', type=Path, required=True, help='New output directory outside the image directory')
    args = parser.parse_args()
    image, archive, tools, out = (p.resolve() for p in (args.image, args.archive, args.e2fsprogs, args.output))
    require(image.suffix == '.img' and image.is_file(), 'Expected a raw installation image')
    require(not out.exists() and not out.is_relative_to(image.parent), 'Choose a new directory outside the image directory')
    report = json.loads(image.with_name('build-report.json').read_text())
    require(report['partitions']['5'] == LOG_PARTITION and image.stat().st_size == report['raw_bytes'] == 256 * 1024**2,
            'Unsupported installation image layout')
    require(digest(image) == report['raw_sha256'], 'Source image differs from build report')
    require(archive.stat().st_size == ARCHIVE_BYTES and digest(archive) == ARCHIVE_SHA, 'Wrong HY2 archive')
    offset, length = (value * 512 for value in LOG_PARTITION)
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=out.parent) as temporary:
        stage = Path(temporary)
        result = stage / 'result'
        result.mkdir()
        raw = result / (image.stem + '-HY2-offline.img')
        shutil.copyfile(image, raw)
        require(digest(raw) == report['raw_sha256'], 'Source image changed during copy')
        partition = stage / 'log.ext4'
        with raw.open('rb') as stream, partition.open('wb') as disk_slice:
            shutil.copyfileobj(RangeStream(stream, offset, length), disk_slice)
        with partition.open('rb') as stream:
            fs = ExtFS(stream)
            require(set(fs.get('/').listdir()) <= {'.', '..', 'lost+found'},
                    'Expected a fresh, empty log partition')
        copy = stage / ARCHIVE
        shutil.copyfile(archive, copy)
        require(digest(copy) == ARCHIVE_SHA, 'Source archive changed during copy')
        target = CACHE + '/' + ARCHIVE
        commands = (f'mkdir {CACHE}\nset_inode_field {CACHE} mode 040700\n'
                    f'write {ARCHIVE} {target}\nset_inode_field {target} mode 0100600\n')
        subprocess.run([tools / 'debugfs/debugfs', '-w', '-f', '-', partition], cwd=stage,
                       check=True, text=True, input=commands)
        subprocess.run([tools / 'e2fsck/e2fsck', '-fn', partition], check=True)
        require(partition.stat().st_size == length, 'Unexpected partition size')
        with raw.open('r+b') as stream, partition.open('rb') as verified:
            stream.seek(offset)
            shutil.copyfileobj(verified, stream)
        with raw.open('rb') as stream:
            verify_archive(ExtFS(RangeStream(stream, offset, length)))
        packed = raw.with_suffix('.img.gz')
        with raw.open('rb') as stream, packed.open('wb') as target:
            with gzip.GzipFile(filename='', fileobj=target, mode='wb', compresslevel=9, mtime=0) as encoded:
                shutil.copyfileobj(stream, encoded)
        raw_sha = digest(raw)
        with gzip.open(packed, 'rb') as stream:
            require(hashlib.file_digest(stream, 'sha256').hexdigest() == raw_sha, 'Compressed image verification failed')
        report.update(raw_sha256=raw_sha, gzip_sha256=digest(packed), source_image_sha256=report['raw_sha256'],
                      image_core_archive=ARCHIVE, image_core_sha256=ARCHIVE_SHA, boot_tested=False)
        (result / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
        (result / 'SHA256SUMS').write_text(f"{report['gzip_sha256']}  {packed.name}\n{raw_sha}  {raw.name}\n")
        result.rename(out)


if __name__ == '__main__':
    main()
