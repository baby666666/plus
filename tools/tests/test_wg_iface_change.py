#!/usr/bin/env python3
"""Exercise the writer with SQLite and disposable link fixtures; never touch host networking."""
from pathlib import Path
import os, re, sqlite3, subprocess, tempfile, unittest

ROOT = Path(__file__).resolve().parents[2]
src = (ROOT / 'materials/firmware/port-3726/files/usr/ikuai/script/wireguard.sh').read_text()
starts = list(re.finditer(r'(?m)^([A-Za-z_]\w*)\(\)\s*[({]', src))
functions = {m[1]: src[m.start():starts[i+1].start() if i+1<len(starts) else None]
             for i,m in enumerate(starts)}
SHELL = '\n'.join(functions[n] for n in ('__wg_locked_iface_add', '__wg_locked_iface_edit',
    '__wg_check_iface_keys', '__wg_iface_name_free', '__wg_write_config', '__check_key_valid',
    '__check_param_iface_add'))
SHELL += r"""
IK_DB_CONFIG="$PWD/db";IK_DIR_TMP="$PWD"; name=wg1; enabled=yes; interface=auto; id=2
mtu=${TEST_MTU-1420};local_privatekey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
local_publickey=${TEST_PUBLIC-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=}
__wg_check_iface_address(){ :; };__wg_fill_local_keys(){ :; }
__wg_check_route_iface(){ :; };interface_check_routing_exit(){ :; };check_varl(){ :; }
__wg_bin(){ echo test_wg; }
test_wg(){ [ "$1" = pubkey ] && read -r key && [ "$key" = "$local_privatekey" ] && echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=; }
ip(){ [ "$1 $2 $3" = "link show dev" ] && [ -e "net/$4" ]; }
sql_config_insert(){ sqlite3 "$1" "insert into wireguard(name,enabled) values('$name','$enabled');select last_insert_rowid();"; }
sql_config_update(){ sqlite3 "$1" "update wireguard set enabled='$enabled',name='$name' where $3;"; }
sql_config_get_list(){ sqlite3 "$1" "select 'old_name='||name||' old_enabled='||enabled from ($2)"; }
__exec_rule_restart_one(){ touch "net/$1"; if [ -f fail ];then echo "$1 运行配置应用失败（创建内核接口）";return 1;fi;echo ok > "wireguard/$1.conf"; }
__wg_apply_iface(){ __exec_rule_restart_one "$@"; }
__exec_rule_iface_del(){ [ ! -f failclean ] && rm -f "net/$1" "wireguard/$1.conf"; }
__wg_iface_cache_update(){ :; }
NewOldVarl(){ for x in "$@";do case "$x" in enabled) [ "$enabled" = "$old_enabled" ] || return 1;;name) [ "$name" = "$old_name" ] || return 1;;esac;done;return 0; }
"""
class Writer(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.d=Path(tmp.name)
        (self.d/'net').mkdir();(self.d/'wireguard').mkdir()
        self.db=sqlite3.connect(self.d/'db');self.addCleanup(self.db.close)
        self.db.executescript("create table wireguard(id integer primary key,name text unique,enabled text);insert into wireguard values(1,'wg10','yes');")
        (self.d/'net/wg10').touch()
    def invoke(self, cmd='__wg_locked_iface_add', **kw):
        return subprocess.run(['bash','-c',SHELL+'\n'+cmd], cwd=self.d,text=True,
            env={**os.environ,**kw},capture_output=True)
    def count(self):return self.db.execute('select count(*) from wireguard').fetchone()[0]
    def test_revert_and_retry(self):
        flag=self.d/'fail';flag.touch()
        r=self.invoke();self.assertNotEqual(r.returncode,0);self.assertIn('已撤销',r.stdout);self.assertIn('创建内核接口',r.stdout)
        self.assertEqual(self.count(),1);self.assertFalse((self.d/'net/wg1').exists());self.assertTrue((self.d/'net/wg10').exists())
        flag.unlink();r=self.invoke();self.assertEqual((r.returncode,r.stdout.strip()),(0,'2'));self.assertEqual(self.count(),2)
    def test_cleanup_failure_visible(self):
        (self.d/'fail').touch();(self.d/'failclean').touch()
        r=self.invoke();self.assertNotEqual(r.returncode,0);self.assertIn('清理失败',r.stdout);self.assertEqual(self.count(),2)
    def test_validation(self):
        for env in ({'TEST_MTU':'bad-mtu'}, {'TEST_MTU':'575'}, {'TEST_MTU':'9001'}, {'TEST_PUBLIC':'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI='}):
            r=self.invoke(**env);self.assertNotEqual(r.returncode,0);self.assertEqual(self.count(),1)
            self.assertNotIn('AAAAAAAA',r.stdout+r.stderr)
        (self.d/'net/wg1').write_text('original')
        r=self.invoke();self.assertNotEqual(r.returncode,0);self.assertEqual(self.count(),1)
        self.assertEqual((self.d/'net/wg1').read_text(),'original')
    def test_enable_disable_and_repair(self):
        self.assertNotEqual(self.invoke('__wg_locked_iface_edit').returncode,0)
        self.assertEqual(self.invoke('enabled=no;__wg_locked_iface_add', TEST_MTU='').returncode,0)
        self.assertFalse((self.d/'net/wg1').exists())
        self.assertEqual(self.invoke('__wg_locked_iface_edit').returncode,0)
        self.assertTrue((self.d/'net/wg1').exists());(self.d/'wireguard/wg1.conf').unlink()
        self.assertEqual(self.invoke('__wg_locked_iface_edit').returncode,0);self.assertTrue((self.d/'wireguard/wg1.conf').exists())
        self.assertEqual(self.invoke('enabled=no;__wg_locked_iface_edit').returncode,0);self.assertFalse((self.d/'net/wg1').exists())
class CenterSave(unittest.TestCase):
    def run_writer(self, folder, fail=False):
        fn=functions['center_save'].replace('/etc/mnt/ikuai', '"$PWD"').replace('/usr/ikuai/script/wg_center_route.sh', 'apply_center').replace('/tmp/iktmp/wg_center_web_apply.log', '"$PWD/apply.log"')
        stub='__wg_center_conf(){ echo "$PWD/center.conf"; };__wg_center_quote(){ printf %s "$1"; };apply_center(){ [ "$FAIL" = no ]; };'
        return subprocess.run(['bash','-c',fn+'\n'+stub+' enable=1;center_save'],cwd=folder,text=True,capture_output=True,env={**os.environ,'FAIL':'yes' if fail else 'no'})
    def test_saved_and_applied_are_distinct(self):
        with tempfile.TemporaryDirectory() as d:
            for fail in (True,False):
                r=self.run_writer(d,fail)
                self.assertEqual(r.returncode!=0,fail)
                self.assertEqual('已保存' in r.stdout,fail)
                self.assertIn("ENABLE='1'",(Path(d)/'center.conf').read_text())
                self.assertFalse(list(Path(d).glob('center.conf.*')))
                self.assertEqual((Path(d)/'center.conf').stat().st_mode & 0o777,0o600)
if __name__=='__main__': unittest.main()
