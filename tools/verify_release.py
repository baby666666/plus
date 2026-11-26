#!/usr/bin/env python3
"""Verify downloaded assets against this checkout, without executing firmware."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(stream):
    result = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        result.update(block)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    release = json.loads((ROOT / 'release.json').read_text())
    bundle = json.loads((ROOT / 'materials/base/input-bundle.json').read_text())
    assert release['rebuild_inputs'] == bundle, 'Release and fixed input metadata disagree'
    expected = {
        release['firmware_filename']: release['firmware_sha256'],
        release['image_filename']: release['image_sha256'],
        bundle['name']: bundle['sha256'],
    }
    core = json.loads((ROOT / 'materials/base/hy2-core.json').read_text())
    assert release['offline_image_core'] == core, 'Offline core metadata differs'
    expected[core['name']] = core['sha256']
    assert (args.directory / core['name']).stat().st_size == core['bytes']
    manifest = (ROOT / 'SHA256SUMS').read_bytes()
    parsed = dict((name, value) for value, name in
                  (line.split('  ', 1) for line in manifest.decode().splitlines()))
    assert parsed == expected, 'Root SHA256SUMS disagrees with release.json'
    assert (args.directory / 'SHA256SUMS').read_bytes() == manifest, 'Downloaded checksum file differs'
    for name, value in expected.items():
        assert Path(name).name == name
        path = args.directory / name
        assert path.is_file() and not path.is_symlink(), 'Missing/non-regular asset: ' + name
        with path.open('rb') as stream:
            assert digest(stream) == value, 'Checksum mismatch: ' + name
        print('PASS ' + name, flush=True)
    assert (args.directory / bundle['name']).stat().st_size == bundle['bytes']
    with gzip.open(args.directory / release['image_filename'], 'rb') as stream:
        assert digest(stream) == release['image_raw_sha256'], 'Decompressed image differs'
    print('PASS: release assets and decompressed installation image verified.')


if __name__ == '__main__':
    main()
