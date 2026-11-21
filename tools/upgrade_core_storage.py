"""Test a constrained RC17 to current upgrade on a disposable disk without a data volume."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

ARCHIVE = 'sing-box-1.14.4-linux-amd64-musl.tar.gz'
ARCHIVE_SHA = '8f7c5f0651238850d96a0e488e5473cd77ec1a0098f63942e943f475a12057ca'
ELF_SHA = 'fe23d7000aaaa91f40b63641a65a1a84d96b5f179c65b63f34893e238884cd5c'
ENGINE = '/usr/ikuai/script/wg_hy_engine.sh'
RUNTIME = '/tmp/iktmp/wg-hy-engine'


def seed_archive(disk, archive, debugfs):
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == ARCHIVE_SHA
    # Partition 5 is the template's ext log volume. Seed only our private copy.
    with tempfile.TemporaryDirectory(dir=disk.parent) as folder:
        root = Path(folder)
        part = root / 'log.img'
        with disk.open('rb') as stream:
            stream.seek(219136 * 512)
            part.write_bytes(stream.read(286720 * 512))
        shutil.copyfile(archive, root / ARCHIVE)
        target = '/.nr-wg-reality/' + ARCHIVE
        commands = root / 'seed.commands'
        commands.write_text('mkdir /.nr-wg-reality\nset_inode_field /.nr-wg-reality mode 040700\n'
                            f'write {ARCHIVE} {target}\nset_inode_field {target} mode 0100600\n')
        subprocess.run([debugfs, '-w', '-f', commands, part], cwd=root, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with disk.open('r+b') as stream, part.open('rb') as payload:
            stream.seek(219136 * 512)
            shutil.copyfileobj(payload, stream)


def constrain_and_seed(shell, call, post):
    from upgrade_pure_access import seed
    # Bound each freshly booted test volume with a disposable, allocated file.
    # Measure after placing the official archive, not on an empty partition.
    for volume, target_kib in [('/etc/log', 74 * 1024), ('/etc/mnt', 20 * 1024)]:
        available = int(shell(f"df -Pk {volume} | awk 'END {{print $4}}'"))
        assert available >= target_kib, 'template smaller than fixture'
        shell(f'dd if=/dev/zero of={volume}/nr-fixture-space bs=1024 count={available-target_kib} 2>/dev/null && sync')
        after = int(shell(f"df -Pk {volume} | awk 'END {{print $4}}'"))
        assert abs(after - target_kib) < 256
    shell(f'test "$(sha256sum /etc/log/.nr-wg-reality/{ARCHIVE} | cut -d\' \' -f1)" = {ARCHIVE_SHA}')
    cases = seed(call, post, fixtures=[('pure_hy2', 'access'), ('native', 'both')])
    shell(f'test "$({ENGINE} storage)" = memory && test -s {RUNTIME}/sing-box')
    return cases


def verify_profiles(call, cases):
    case = cases['access']
    ident = case['params']
    deadline = time.monotonic() + 360
    while time.monotonic() < deadline:
        try:
            status = call('wireguard', 'show', {'TYPE': 'hyr_status'})['Data']['hyr_status']
            if status.get('core_storage') == 'disk' and status.get('core_format') == 'squashfs' and any(
                    row['id'] == ident['id'] and row.get('running') for row in status['members']):
                break
        except AssertionError as error:
            details = error.args[0]
            if not isinstance(details, tuple) or len(details) < 4 or details[3] != 30006:
                raise
        time.sleep(3)
    else:
        raise AssertionError('existing pure HY2 listener did not recover using disk')
    for kind, field in [('hyr_profile', 'profile'), ('hyr_site_profile', 'bundle')]:
        cfg = call('wireguard', 'show', {'TYPE': kind, 'expected_role': 'access', **ident})['Data'][kind]
        assert cfg == case[field], 'saved mobile or router credentials changed'
    rows = call('wireguard', 'show', {'TYPE': 'site_client_status'})['Data']['site_client_status']['members']
    receiver = next(row for row in rows if row['id'] == case['import']['id'])
    assert receiver['enabled'] and receiver['purpose'] == 'access'


def verify_workers(shell, cases):
    case = cases['access']
    ids = [('puh', int(case['params']['peer_id'])), ('puc', int(case['import']['id']))]
    deadline = time.monotonic() + 360
    for unit, row in ids:
        pidfile = f'{RUNTIME}/{unit}-{row}/service.pid'
        while time.monotonic() < deadline:
            ready = shell(f'if {ENGINE} {unit}-{row} status >/dev/null 2>&1; then echo yes; else echo no; fi')
            if ready == 'yes':
                break
            time.sleep(3)
        else:
            raise AssertionError(f'{unit} worker did not recover on cold boot')
        shell(f"""set -e
read pid _ < {pidfile}
test ! -f {RUNTIME}/sing-box
test "$(sha256sum /proc/$pid/exe | cut -d' ' -f1)" = {ELF_SHA}
exe=$(readlink /proc/$pid/exe)
mountdir=${{exe%/*}}
awk -v d="$mountdir" '$2==d && $3=="squashfs" && $4~/(^|,)ro(,|$)/ {{found=1}} END {{exit !found}}' /proc/mounts""")
    native = cases['native']
    assert shell('wg show ' + native['iface'] + ' peers') == native['public']
