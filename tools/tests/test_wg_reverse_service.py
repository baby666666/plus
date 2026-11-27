"""Lifecycle and firewall boundaries; no host networking is modified."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'materials/firmware/port-3726/files/usr/ikuai/script'


class ReverseServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = self.root / 'runtime'
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.log = self.root / 'calls'
        self.env = dict(os.environ, CALLS=str(self.log))
        self.script = self.root / 'service'
        text = (SCRIPTS / 'wg_hy_reverse.sh').read_text()
        text = text.replace('/tmp/iktmp/wg-hy-reverse', str(self.runtime))
        text = text.replace('export PATH=/usr/sbin:/usr/bin:/sbin:/bin',
                            'export PATH="' + str(self.bin) + ':$PATH"')
        text = text.replace('0:700', f'{os.getuid()}:700').replace('0:600', f'{os.getuid()}:600')
        self.script.write_text(text)
        fake = self.bin / 'iptables'
        fake.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >>"$CALLS"\nexit 1\n')
        fake.chmod(0o700)

    def run_service(self, *args):
        return subprocess.run(['bash', str(self.script), *args], env=self.env,
                              text=True, capture_output=True)

    def test_status_and_stop_absent_do_not_create_runtime(self):
        result = self.run_service('status', 'puh-12')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)['connected'])
        self.assertFalse(self.runtime.exists())
        self.assertEqual(self.run_service('stop', 'puh-12').returncode, 0)
        self.assertFalse(self.runtime.exists())
        self.assertFalse(self.log.exists())

    def test_invalid_identity_is_rejected_before_any_io(self):
        for value in ('puh-0', 'puh-1/../../x', 'puc-1;touch x', 'wg1', 'puh-01'):
            with self.subTest(value=value):
                self.assertNotEqual(self.run_service('stop', value).returncode, 0)
        self.assertFalse(self.runtime.exists())
        self.assertFalse(self.log.exists())

    def test_stale_status_cannot_report_connected(self):
        self.runtime.mkdir(mode=0o700)
        unit = self.runtime / 'puh-12'
        unit.mkdir(mode=0o700)
        status = unit / 'status.json'
        status.write_text(json.dumps({'connected': True, 'state': 'online', 'pid': 1,
                                      'updated_at': 9999999999, 'token': 'must-not-leak'}))
        status.chmod(0o600)
        result = self.run_service('status', 'puh-12')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)['connected'])
        self.assertNotIn('must-not-leak', result.stdout)

    def test_symlink_runtime_is_not_followed(self):
        other = self.root / 'other'
        other.mkdir(mode=0o700)
        self.runtime.symlink_to(other, target_is_directory=True)
        self.assertNotEqual(self.run_service('stop', 'puh-12').returncode, 0)
        self.assertEqual(list(other.iterdir()), [])


class ReverseIngressTests(unittest.TestCase):
    def render(self, port):
        source = (SCRIPTS / 'wg_pure_ingress.sh').read_text().split('\nidentity ||', 1)[0]
        result = subprocess.run(['bash', '-c', source + '\nidentity;input_guards emit\n',
                                 'fixture', 'ready', 'wg7', '7', '10.177.7.2',
                                 '10.177.7.1', '0', '0', '0', '', str(port)],
                                text=True, capture_output=True)
        return result

    def test_control_grant_is_exact_and_only_when_enabled(self):
        off = self.render(0)
        on = self.render(49871)
        self.assertEqual(on.returncode, 0, on.stderr)
        self.assertNotIn('--dport 49871', off.stdout)
        grants = [line for line in on.stdout.splitlines() if '--dport 49871' in line]
        self.assertEqual(len(grants), 1)
        grant = grants[0]
        self.assertIn('-s 10.177.7.2/32 -d 10.177.7.1/32 -p tcp', grant)
        self.assertIn('--ctorigdst 10.177.7.1 --ctorigdstport 49871', grant)
        self.assertTrue(grant.endswith('-j ACCEPT'))
        self.assertTrue(on.stdout.rstrip().endswith('-A NHI7 -j DROP'))


if __name__ == '__main__':
    unittest.main()
