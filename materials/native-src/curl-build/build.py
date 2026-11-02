#!/usr/bin/env python3
"""Build the current static curl/native-safe-fetch executable in a fresh directory."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import tarfile
import time

SOURCES = {
    'curl': ('curl-8.23.0', '8dadd7d2536a314f982ad05a651b713f426bf7d02cc2c76cffb9796f2218e6c5'),
    'openssl': ('openssl-3.5.9', '603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a'),
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def elf_info(path):
    data = path.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01':
        raise RuntimeError('Expected little-endian ELF64')
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    if header[2] != 62:
        raise RuntimeError('Expected x86_64 ELF')
    programs = [struct.unpack_from('<IIQQQQQQ', data, header[5] + i * header[9])
                for i in range(header[10])]
    if any(p[0] == 3 for p in programs):
        raise RuntimeError('Executable unexpectedly requires a dynamic interpreter')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, header[6] + i * header[11])
                for i in range(header[12])]
    names_section = sections[header[13]]
    names = data[names_section[4]:names_section[4] + names_section[5]]
    allocated = {}
    for section in sections:
        if section[2] & 2:
            name = names[section[0]:].split(b'\0', 1)[0].decode('ascii')
            content = b'' if section[1] == 8 else data[section[4]:section[4] + section[5]]
            allocated[name] = (section[1:4], section[5:10], hashlib.sha256(content).hexdigest())
    return {'entry': header[4], 'program_headers': programs, 'allocated_sections': allocated}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--curl-source', type=Path, required=True)
    parser.add_argument('--openssl-source', type=Path, required=True)
    parser.add_argument('--zig', type=Path, required=True, help='Zig 0.14.1 executable')
    parser.add_argument('--work', type=Path, required=True, help='New, nonexistent output directory outside the source checkout')
    parser.add_argument('--build-triplet', help='Host triplet; otherwise use curl config.guess')
    parser.add_argument('--objcopy', type=Path, help='Optional existing ELF-capable objcopy executable')
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    source_root = Path(__file__).resolve().parent.parent
    work = args.work.resolve()
    checkout = source_root.parents[1]
    if work.is_relative_to(checkout) or work.exists():
        parser.error('--work must not exist and must be outside this source checkout')
    zig = args.zig.resolve()
    if subprocess.check_output([str(zig), 'version'], text=True).strip() != '0.14.1':
        parser.error('This recipe requires Zig 0.14.1')
    archives = {'curl': args.curl_source.resolve(), 'openssl': args.openssl_source.resolve()}
    for name, archive in archives.items():
        if sha(archive) != SOURCES[name][1]:
            parser.error(name + ' archive SHA256 mismatch')
    work.mkdir(parents=True)
    sources, wrappers, logs = (work / name for name in ('sources', 'bin', 'logs'))
    for directory in (sources, wrappers, logs):
        directory.mkdir()
    for archive in archives.values():
        with tarfile.open(archive) as tf:
            tf.extractall(sources, filter='data')
    openssl = sources / SOURCES['openssl'][0]
    curl = sources / SOURCES['curl'][0]
    ssl_stage = work / 'ssl-stage'
    shutil.copyfile(source_root / 'native_safe_fetch.c', work / 'native_safe_fetch.c')
    shutil.copyfile(source_root / 'curl-build/tool_main.c.modified', curl / 'src/tool_main.c')
    for name, command in {'zigcc': 'cc -target x86_64-linux-musl', 'zigar': 'ar', 'zigranlib': 'ranlib'}.items():
        script = '#!/bin/sh\nexec ' + shlex.quote(str(zig)) + ' ' + command
        if name == 'zigcc':
            # Keep host paths out of OpenSSL's recorded compiler command.
            for origin, target in ((work, '/usr/src/nativerouting'), (zig.parent, '/usr/src/zig')):
                for option in ('-ffile-prefix-map=', '-fdebug-prefix-map='):
                    script += ' ' + shlex.quote(option + str(origin) + '=' + target)
        wrapper = wrappers / name
        wrapper.write_text(script + ' "$@"\n')
        wrapper.chmod(0o755)
    env = dict(os.environ, PATH=str(wrappers) + os.pathsep + os.environ['PATH'],
               CC='zigcc', AR='zigar', RANLIB='zigranlib', PKG_CONFIG='/usr/bin/false',
               ZIG_GLOBAL_CACHE_DIR=str(work / 'zig-global'), ZIG_LOCAL_CACHE_DIR=str(work / 'zig-local'))
    records = []

    def run(name, command, cwd, extra=None, allow_failure=False):
        started = time.monotonic()
        print('START ' + name, flush=True)
        with (logs / (name + '.log')).open('wb') as log:
            result = subprocess.run(command, cwd=cwd, env=env | dict(extra or {}), stdout=log, stderr=subprocess.STDOUT)
        records.append({'step': name, 'returncode': result.returncode,
                        'seconds': round(time.monotonic() - started, 2)})
        (work / 'progress.json').write_text(json.dumps(records, indent=2) + '\n')
        if result.returncode and not allow_failure:
            raise RuntimeError(name + ' failed; see ' + str(logs / (name + '.log')))
        print(('PASS ' if not result.returncode else 'FALLBACK ') + name, flush=True)
        return result.returncode

    openssl_flags = ['linux-x86_64', 'no-shared', 'no-tests', 'no-apps', 'no-module', 'no-asm',
                     'no-legacy', 'no-weak-ssl-ciphers', 'no-docs', '--prefix=/usr',
                     '--libdir=lib64', '--openssldir=/etc/ssl', '-Os']
    run('openssl-configure', ['perl', 'Configure'] + openssl_flags, openssl)
    run('openssl-build', ['make', '-j' + str(args.jobs), 'build_libs'], openssl)
    run('openssl-install', ['make', 'DESTDIR=' + str(ssl_stage), 'install_dev'], openssl)
    build_triplet = args.build_triplet or subprocess.check_output(['sh', str(curl / 'config.guess')], text=True).strip()
    flags = dict(CFLAGS='-Os', CPPFLAGS='-I' + str(ssl_stage / 'usr/include'),
                 LDFLAGS='-static -L' + str(ssl_stage / 'usr/lib64'))
    curl_flags = ['--host=x86_64-linux-musl', '--build=' + build_triplet, '--prefix=/usr',
                  '--with-openssl=' + str(ssl_stage / 'usr'),
                  '--with-ca-bundle=/etc/ssl/certs/ca-certificates.crt', '--without-ca-path',
                  '--disable-shared', '--enable-static', '--disable-threaded-resolver',
                  '--disable-docs', '--disable-manual', '--without-zlib', '--without-brotli',
                  '--without-zstd', '--without-libidn2', '--without-libpsl', '--without-nghttp2',
                  '--without-nghttp3', '--without-libssh2', '--disable-ldap', '--disable-ldaps',
                  '--disable-rtsp', '--disable-dict', '--disable-telnet', '--disable-tftp',
                  '--disable-pop3', '--disable-imap', '--disable-smtp', '--disable-smb',
                  '--disable-gopher', '--disable-mqtt']
    run('curl-configure', ['./configure'] + curl_flags, curl, flags)
    obj = work / 'native_safe_fetch.o'
    run('native-fetch-build', ['zigcc', '-Os', '-I' + str(curl / 'include'),
                              '-Dmain=native_safe_fetch_main', '-c', str(work / 'native_safe_fetch.c'), '-o', str(obj)], work)
    makefile = curl / 'src/Makefile'
    content = makefile.read_text()
    matches = list(re.finditer(r'(?m)^curl_LDADD\s*=.*$', content))
    if len(matches) != 1:
        raise RuntimeError('Unexpected curl_LDADD declaration')
    match = matches[0]
    makefile.write_text(content[:match.start()] + match.group().replace('=', '= ' + str(obj), 1) + content[match.end():])
    run('curl-build', ['make', '-j' + str(args.jobs)], curl, flags)
    raw, output = work / 'curl.unstripped', work / 'curl'
    shutil.copyfile(curl / 'src/curl', raw)
    if args.objcopy:
        run('curl-strip', [str(args.objcopy.resolve()), '--strip-all', str(raw), str(output)], work)
    elif run('curl-strip', [str(zig), 'objcopy', '--strip-all', str(raw), str(output)], work, allow_failure=True):
        # Some macOS SDK/Zig combinations cannot link Zig's host helper. Build
        # its own objcopy implementation and let the system compiler link it.
        helper = work / 'elf-objcopy'
        status = run('objcopy-build', [str(zig), 'build-exe', str(zig.parent / 'lib/compiler/objcopy.zig'),
                                     '-lc', '-O', 'ReleaseFast', '-femit-bin=' + str(helper)], work, allow_failure=True)
        if status:
            objcopy_object = Path(str(helper) + '.o')
            if not objcopy_object.is_file() or not objcopy_object.stat().st_size:
                raise RuntimeError('Provide a working ELF objcopy using --objcopy')
            run('objcopy-link', ['cc', str(objcopy_object), '-o', str(helper)], work)
        run('objcopy-help', [str(helper), '--help'], work)
        run('curl-strip-fallback', [str(helper), '--strip-all', str(raw), str(output)], work)
    output.chmod(0o755)
    before, after = elf_info(raw), elf_info(output)
    if before != after:
        raise RuntimeError('Stripping altered allocated sections or program mappings')
    data = output.read_bytes()
    for forbidden in (b'/Users/', b'/home/', str(work).encode(), str(zig.parent).encode()):
        if forbidden in data:
            raise RuntimeError('Build directory or outdated version leaked into output')
    for required in (b'iKuai-NativeLibrary/1.0', b'--native-safe-fetch', b'/etc/ssl/certs/ca-certificates.crt'):
        if required not in data:
            raise RuntimeError('Missing expected runtime marker: ' + required.decode())
    report = {'passed': True, 'source_archives': {k: v[1] for k, v in SOURCES.items()},
              'native_source_sha256': sha(source_root / 'native_safe_fetch.c'),
              'dispatch_source_sha256': sha(source_root / 'curl-build/tool_main.c.modified'),
              'output_sha256': sha(output), 'output_bytes': output.stat().st_size,
              'compiler': 'Zig 0.14.1 x86_64-linux-musl', 'curl_version': '8.23.0', 'openssl_version': '3.5.9',
              'openssl_flags': openssl_flags, 'curl_flags': curl_flags,
              'allocated_sections_and_program_mappings_unchanged_by_strip': True,
              'runtime_tested': False, 'steps': records}
    (work / 'build-report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('OUTPUT ' + str(output) + '\nSHA256 ' + sha(output), flush=True)


if __name__ == '__main__':
    main()
