"""Exercise the logical-exit fence with the real shell and a small kernel fixture."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[2] / 'materials/firmware/port-3726/files/usr/ikuai/script'


class PureEgressTest(unittest.TestCase):
    def test_tun_ownership_and_withdrawal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ['wg-hyr', 'iproute2', 'wg-hy-engine/puc-7', 'net/nph7', 'proc/100/fdinfo', 'tools']:
                (root / name).mkdir(parents=True)
            (root / 'wg-hyr/state.json').touch()
            (root / 'iproute2/rt_tables').write_text('100 wg3\n')
            (root / 'net/nph7/tun_flags').touch()
            (root / 'wg-hy-engine/puc-7/service.pid').write_text('100 654321\n')
            (root / 'proc/100/stat').write_text(' '.join(['0'] * 21 + ['654321'])+'\n')
            owner = root / 'proc/100/fdinfo/4'
            owner.write_text('iff:\tnph7\n')
            inventory = root / 'inventory'
            inventory.write_text('wg3 nph7 puc-7 yes\n')
            for name, body in {
                'ip': 'echo "$*" >> "$LOG"',
                'lua': 'cat "$INVENTORY"',
                'flock': 'exit 0'
            }.items():
                tool = root / 'tools' / name
                tool.write_text('#!/bin/sh\n' + body + '\n')
                tool.chmod(0o700)
            env = dict(os.environ, PATH=str(root/'tools')+':'+os.environ['PATH'],
                       LOG=str(root/'log'), INVENTORY=str(inventory))
            script = (SCRIPTS/'wg_pure_routing.sh').read_text()
            for source, target in [('/tmp/iktmp/', root), ('/etc/mnt/ikuai/', root),
                                   ('/etc/iproute2/', root/'iproute2'), ('/sys/class/net/', root/'net'),
                                   ('/proc/', root/'proc'), ('/usr/bin/lua ', root/'tools/lua')]:
                script=script.replace(source, str(target)+(' ' if source.endswith(' ') else '/'))
            def sync():
                (root/'log').write_text('')
                subprocess.run(['bash','-c',script,'fixture','sync','db'],env=env,check=True)
                return (root/'log').read_text().splitlines()
            fence = '-4 route replace prohibit default table wg3 metric 42'
            route = 'default dev nph7 table wg3 metric 41'
            self.assertEqual(sync(), [fence, '-4 route replace '+route])
            owner.write_text('iff:\tnph8\n')
            self.assertEqual(sync(), [fence, '-4 route del '+route])
            owner.write_text('iff:\tnph7\n')
            (root/'wg-hy-engine/puc-7/service.pid').write_text('100 10000\n')
            self.assertEqual(sync(), [fence, '-4 route del '+route])
            (root/'wg-hy-engine/puc-7/service.pid').write_text('100 654321\n')
            inventory.write_text('wg3 nph7 puc-7 no\n')
            self.assertEqual(sync(), [fence, '-4 route del '+route])
            inventory.write_text('')
            self.assertEqual(sync(), ['-4 route del '+route, '-4 route del prohibit default table wg3 metric 42'])
            self.assertFalse((root/'wg-pure-routing/map').exists())


if __name__ == '__main__':
    unittest.main()
