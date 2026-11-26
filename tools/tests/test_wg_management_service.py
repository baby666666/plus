"""Exercise management namespace lifecycle without changing the 2.0 data path."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPTS=Path(__file__).resolve().parents[2]/'materials/firmware/port-3726/files/usr/ikuai/script'


class ManagementLifecycle(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.tools=self.root/'bin';self.tools.mkdir()
        self.stage=self.root/'stage';self.stage.mkdir()
        self.units=self.root/'units';self.network=self.root/'network';self.log=self.root/'calls'
        self.env={**os.environ,'UNITS':str(self.units),'NETWORK':str(self.network),
                  'CALLS':str(self.log),'FW':str(self.root/'firewall')}
        self.tool('engine', '''echo engine:$2 >> "$CALLS"
case $2 in
start) cp "$3" "$UNITS/$1/live.json";;
stop) rm -f "$UNITS/$1/live.json";;
status) test -f "$UNITS/$1/live.json";;
available) exit 0;;
*) [ "$1" = check ];;
esac''')
        self.tool('management', '''echo management:$1 >> "$CALLS"
case $1 in
check) [ "${FAIL:-}" != check ];;
up) mkdir -p "$NETWORK";touch "$NETWORK/$2";[ "${FAIL:-}" != up ];;
down) rm -f "$NETWORK/$2";;
manage|ready) test -f "$NETWORK/$2" && [ "${FAIL:-}" != ready ];;
*) exit 1;;
esac''')
        self.tool('iptables', '''case $3 in
-C) test -f "$FW";;
-A) touch "$FW";;
-D) rm -f "$FW";;
*) exit 1;;
esac''')
        self.tool('ip','test "$1" = link')
        self.tool('dns','echo dns:$1 >> "$CALLS"; test "${FAIL:-}" != dns')
        source=(SCRIPTS/'wg_pure_service.sh').read_text().replace('/usr/ikuai/script/native_dns_bind.sh',str(self.tools/'dns'))
        source=source.replace('export PATH=/usr/sbin:/usr/bin:/sbin:/bin',
                              'export PATH="'+str(self.tools)+':$PATH"')
        source=source.replace('/usr/ikuai/script/wg_hy_engine.sh',str(self.tools/'engine'))
        source=source.replace('/usr/ikuai/script/wg_pure_ingress.sh',str(self.tools/'management'))
        source=source.replace('/tmp/iktmp/wg-pure-ingress',str(self.network))
        source=source.replace('/tmp/iktmp/wg-hy-engine',str(self.units))
        if os.uname().sysname=='Darwin':source=source.replace("stat -c '%u:%a'","stat -f '%u:%Lp'")
        source=source.replace('0:700',str(os.getuid())+':700')
        self.script=self.root/'service';self.script.write_text(source)
        self.configure(False)

    def tool(self,name,body):
        target=self.tools/name;target.write_text('#!/bin/bash\n'+body+'\n');target.chmod(0o700)

    def configure(self,allowed):
        (self.stage/'pure-bindings').write_text('wg7 7 51707 21707\n')
        (self.stage/'pure.7').write_text('{"management":true}\n' if allowed else '{}\n')
        admin=self.stage/'admin.7'
        if allowed:admin.write_text('wg7 7 10.177.7.2 10.177.7.1 80 443\n')
        else:admin.unlink(missing_ok=True)

    def run_service(self,op='sync',failure=''):
        self.log.unlink(missing_ok=True)
        result=subprocess.run(['bash',str(self.script),op,str(self.stage)],
                              env={**self.env,'FAIL':failure},text=True,capture_output=True)
        self.calls=self.log.read_text().splitlines() if self.log.exists() else []
        return result

    def passed(self,op='sync'):
        result=self.run_service(op);self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_missing_binding_prevents_direct_exit(self):
        self.configure(False);result=self.run_service()
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('engine:start',self.calls)

    def test_cold_grant_creates_restricted_network_before_start(self):
        self.configure(True);self.passed()
        self.assertLess(self.calls.index('management:up'),self.calls.index('engine:start'))
        self.assertEqual((self.units/'puh-7/admin-binding').read_bytes(),(self.stage/'admin.7').read_bytes())
        self.passed('status');self.assertTrue((self.stage/'ready.7').exists())
        self.assertNotIn('management:up',self.calls);self.assertNotIn('engine:start',self.calls)

    def test_read_only_preflight_does_not_create_or_stop(self):
        self.configure(True);self.passed('check')
        self.assertIn('management:check',self.calls)
        self.assertNotIn('management:up',self.calls);self.assertNotIn('engine:stop',self.calls)
        self.assertFalse(self.network.exists());self.assertFalse(self.units.exists())

    def test_healthy_sync_only_refreshes_listener_grants(self):
        self.configure(True);self.passed();self.passed()
        self.assertIn('management:manage',self.calls);self.assertIn('management:ready',self.calls)
        for call in ('engine:stop','engine:start','management:down','management:up'):
            self.assertNotIn(call,self.calls)

    def test_removing_binding_stops_worker_instead_of_reverting_to_host(self):
        self.configure(True);self.passed();self.configure(False)
        self.assertNotEqual(self.run_service().returncode,0)
        self.assertIn('engine:stop',self.calls);self.assertIn('management:down',self.calls)
        self.assertNotIn('engine:start',self.calls)

    def test_address_change_rebuilds_even_if_profile_does_not_change(self):
        self.configure(True);self.passed()
        binding=self.stage/'admin.7';binding.write_text(binding.read_text().replace('10.177.7.2','10.177.7.3'))
        self.passed()
        self.assertLess(self.calls.index('engine:stop'),self.calls.index('management:down'))
        self.assertLess(self.calls.index('management:down'),self.calls.index('management:up'))
        self.assertLess(self.calls.index('management:up'),self.calls.index('engine:start'))

    def test_failed_setup_cleans_owned_path_and_never_starts_worker(self):
        self.configure(True);result=self.run_service(failure='up')
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('engine:start',self.calls);self.assertIn('management:down',self.calls)
        self.assertFalse((self.network/'wg7').exists())
        self.assertFalse((self.units/'puh-7/admin-binding').exists())

    def test_unavailable_policy_dns_never_starts_an_unclassified_worker(self):
        self.configure(True)
        result=self.run_service(failure='dns')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('dns:ensure',self.calls)
        self.assertNotIn('engine:start',self.calls)
        self.passed();self.assertIn('engine:start',self.calls)

    def test_delete_or_shutdown_removes_network_and_listener(self):
        for operation in ('sync','stop'):
            with self.subTest(operation=operation):
                self.configure(True);self.passed()
                (self.stage/'pure-bindings').write_text('');(self.stage/'pure.7').unlink()
                self.passed(operation)
                self.assertIn('management:down',self.calls);self.assertNotIn('engine:start',self.calls)
                self.assertFalse((self.network/'wg7').exists())
                self.assertFalse((self.units/'puh-7/live.json').exists())


if __name__=='__main__':unittest.main()
