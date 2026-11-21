"""Exercise the actual retired-carrier permission migration against SQLite."""
import json
import os
import sqlite3
import subprocess
import unittest

from lupa.lua51 import LuaRuntime, LuaError
from wg_model_fixture import WireGuardModelFixture, SCRIPTS


class FirmwareShellEntrypoints(unittest.TestCase):
    def test_boot_shutdown_monitor_and_tunnel_scripts_parse(self):
        for path in [SCRIPTS/'rc', SCRIPTS/'utils/monitor_process.sh', SCRIPTS/'wireguard.sh',
                     *sorted(SCRIPTS.glob('wg_*.sh'))]:
            with self.subTest(entrypoint=path.name):
                subprocess.run(['bash','-n',path], check=True)


class NativeRoleUpgrade(WireGuardModelFixture):
    def setUp(self):
        super().setUp()
        self.sql("ALTER TABLE wireguard_peers ADD COLUMN native_role TEXT DEFAULT ''")
        self.sql('UPDATE wireguard_peers SET keepalive=25 WHERE id=3')
        iface,server=self.sql('SELECT id,local_publickey FROM wireguard WHERE id=2')[0]
        public,addr=self.sql('SELECT peer_publickey,allowips FROM wireguard_peers WHERE id=3')[0]
        self.registered=dict(managed=True,mode='lend',interface='wg2',iface_id=iface,
                             peer_key=public,server_key=server,address=addr,port=51822,exit=True)
        self.legacy=dict(self.registered)
        for k in ['managed','mode','port','address']: del self.legacy[k]

    def migrate(self,retired,hy=None):
        lua=LuaRuntime(unpack_returned_tuples=True)
        db=sqlite3.connect(self.db,isolation_level=None)
        db.row_factory=sqlite3.Row
        def exec_sql(stmt):
            db.execute(stmt)
            return 0
        def query(stmt,*args):
            rows=db.execute(stmt,args)
            return lua.table_from([dict(r) for r in rows],recursive=True)
        g=lua.globals()
        g.exec_sql=exec_sql;g.query=query
        g.load_json=lambda txt:lua.table_from(json.loads(txt),recursive=True)
        g.peerlib=str(SCRIPTS/'wg_mobile_peer.lua')
        lua.execute("""
          package.preload.cjson=function() return {decode=load_json} end
          package.preload.lsqlite3=function()
            return {OK=0,ROW=100,DONE=101,open=function()
              return {close=function() end,busy_timeout=function() end,exec=function(_,sql) return exec_sql(sql) end,
                      prepare=function(_,sql)
                        local rows,idx
                        return {bind_values=function(_,... ) rows=query(sql,...);idx=0 end,
                                step=function() idx=idx+1;return rows[idx] and 100 or 101 end,
                                get_named_values=function() return rows[idx] end,finalize=function() end}
                      end} end}
          end
          local load=dofile;dofile=function(p) assert(p=='/usr/ikuai/script/wg_mobile_peer.lua');return load(peerlib) end
          print=function() end;os.exit=function(n) error('exit '..n) end
        """)
        def write(name,members):
            if members is None: return '-'
            path=self.folder/name;path.write_text(json.dumps(dict(version=1,enabled=True,members=members)))
            return str(path)
        g.arg=lua.table_from([str(self.db),write('retired',retired),write('hy',hy)])
        try:
            lua.execute((SCRIPTS/'wg_role_migrate.lua').read_text())
        finally:
            db.close()

    def roles(self):
        return self.sql('SELECT enabled,native_role FROM wireguard_peers ORDER BY id')

    def test_edit_compares_native_purpose_and_legacy_exit_state_before_note_write(self):
        self.sql("ALTER TABLE wireguard_peers ADD COLUMN comment TEXT DEFAULT ''")
        # SQL storage historically accepted both '' and 'no' for ordinary peers.
        current=self.sql('SELECT peer_publickey FROM wireguard_peers WHERE id=3')[0][0]
        source=(SCRIPTS/'wireguard.sh').read_text().replace('/etc/mnt/ikuai/wg-',str(self.folder/'wg-'))
        entry=self.folder/'wireguard.sh'
        entry.write_text(source)
        cmd="""
          Include(){ :; }; source "$1"
          Lock(){ :; }; unLock(){ :; }
          sql_config_update(){
            [[ "$2|$3|$4" = "wireguard_peers|id=3|comment:str" ]] || return 1
            sqlite3 "$1" "update wireguard_peers set comment='saved' where id=3"
          }
          id=3; comment=saved; comment_only=yes; hyr_id=
          hyr_origin_iface=wg2
          __wg_address_change edit
        """
        for role,exit_peer,origin,origin_exit,succeeds in [
                ('lend','yes','both','yes',False), ('access','no','access','yes',False),
                ('','no','','yes',False), ('lend','yes','lend','yes',True),
                ('','','','no',True), ('',None,'','no',True)]:
            with self.subTest(role=role,exit_peer=exit_peer,origin=origin,origin_exit=origin_exit):
                self.sql("UPDATE wireguard_peers SET native_role=?,exit_peer=?,comment='' WHERE id=3",(role,exit_peer))
                env={**os.environ,'IK_DB_CONFIG':str(self.db),'hyr_origin_key':current,
                     'native_origin_role':origin,'native_origin_exit':origin_exit}
                result=subprocess.run(['bash','-c',cmd,'native-edit',entry],env=env,text=True,capture_output=True)
                self.assertEqual(result.returncode==0,succeeds,result.stdout+result.stderr)
                self.assertEqual(self.sql('SELECT native_role,exit_peer,comment FROM wireguard_peers WHERE id=3'),
                                 [(role,exit_peer,'saved' if succeeds else '')])

    def test_legacy_edit_cannot_widen_a_managed_native_role(self):
        cmd='Include(){ :; }; source "$1"; id=3; __wg_native_origin_ok'
        for saved,requested,succeeds in [('both','access',True),('lend','lend',True),('access','lend',False),
                                          ('lend','both',False),('','both',True)]:
            self.sql('UPDATE wireguard_peers SET native_role=? WHERE id=3',(saved,))
            for field in ('wg_role','hyr_mode'):
                with self.subTest(saved=saved,requested=requested,field=field):
                    result=subprocess.run(['bash','-c',cmd,'legacy-role',SCRIPTS/'wireguard.sh'],
                        env={**os.environ,'IK_DB_CONFIG':str(self.db),field:requested},capture_output=True)
                    self.assertEqual(result.returncode==0,succeeds,result.stderr)

    def test_active_native_monitor_rechecks_policy_without_removing_edit_fence(self):
        runtime=self.folder/'runtime';output=self.folder/'events'
        direction=self.folder/'direction'
        direction.write_text('#!/bin/bash\necho "$2" >> "$EVENTS"\ncat "$1" >> "$EVENTS"\n')
        direction.chmod(0o700)
        source=(SCRIPTS/'wg_native_role.sh').read_text()
        source=source.replace('/tmp/iktmp/wg-native-role',str(runtime)).replace('/usr/ikuai/script/wg_hyr_direction.sh',str(direction))
        if os.uname().sysname=='Darwin': source=source.replace("stat -c '%u:%a'","stat -f '%u:%Lp'")
        source=source.replace('0:700',str(os.getuid())+':700')
        ctl=self.folder/'ctl';ctl.write_text(source)
        def run(*args):
            subprocess.run(['bash',ctl,self.db,*args],env={**os.environ,'EVENTS':str(output)},check=True)
        run('after')
        self.assertFalse(runtime.exists())
        self.sql("UPDATE wireguard_peers SET native_role='lend' WHERE id=3")
        run('after')
        self.assertTrue((runtime/'active').is_file())
        output.unlink()
        run('refresh')
        self.assertEqual(output.read_text().splitlines(),['native','wg2 lend 10.44.2.5/32'])
        self.sql("UPDATE wireguard_peers SET enabled='no' WHERE id=3")
        run('after')
        self.assertFalse((runtime/'active').exists())

    def test_only_managed_matching_devices_inherit_direction(self):
        self.migrate({'3':self.registered})
        self.assertEqual(self.roles(),[('yes',''),('yes',''),('yes','lend')])
        self.migrate({'3':self.registered})  # interrupted after DB commit
        self.assertEqual(self.roles()[-1],('yes','lend'))

    def test_legacy_raw_wg_and_active_hy_keep_existing_authority(self):
        self.migrate({'3':self.legacy})
        self.assertTrue(all(row==('yes','') for row in self.roles()))
        self.migrate({'3':self.registered},{'3':dict(self.registered,mode='both')})
        self.assertTrue(all(row==('yes','') for row in self.roles()))
        # A stale HY entry cannot shadow the valid, restricted native record.
        self.migrate({'3':self.registered},{'3':dict(self.registered,port=50000)})
        self.assertEqual(self.roles()[-1],('yes','lend'))

    def test_unresolvable_same_key_is_disabled_but_unrelated_peer_is_untouched(self):
        self.migrate({'3':dict(self.registered,port=50000)})
        self.assertEqual(self.roles(),[('yes',''),('yes',''),('no','')])

    def test_corrupt_registration_is_never_silently_treated_as_unmanaged(self):
        for broken in [dict(self.registered,mode='???'),dict(self.registered,managed=False),{}]:
            with self.assertRaisesRegex(LuaError,'exit 1'):
                self.migrate({'3':broken})
            self.assertTrue(all(row==('yes','') for row in self.roles()))


if __name__ == '__main__':
    unittest.main()
