"""Run the router's Lua WG model against a temporary SQLite peer database."""
import base64
import json
import os
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path

from lupa.lua51 import LuaError, LuaRuntime, lua_type

SCRIPTS = Path(__file__).resolve().parents[2] / 'materials/firmware/port-3726/files/usr/ikuai/script'

ADAPTERS = """
package.preload.cjson = function() return {decode=decode,encode=encode} end
package.preload.lsqlite3 = function()
    return {ROW=100,DONE=101,OK=0,open=function(path)
        return {busy_timeout=function() end, close=function() end, exec=function(_,sql) query(path,sql);return 0 end,
            prepare=function(_,sql)
                if not preparable(path,sql) then return nil end
                local rows,idx
                return {bind_values=function(_,...) rows=query(path,sql,...);idx=0 end,
                    step=function() idx=idx+1;return rows[idx] and 100 or 101 end,
                    get_named_values=function() return rows[idx] end, finalize=function() end}
            end}
    end}
end
local fopen=io.open
io.open=function(path,mode)
    if path=='/proc/sys/kernel/random/uuid' then
        return {read=function(_,kind) assert(kind=='*l');return new_uuid() end,close=function() end}
    end
    return fopen(path,mode)
end
io.popen=function(cmd)
    local host=discovered(cmd)
    return {read=function() return host end,close=function() end}
end
os.execute=derive
io.write=output
print=output
os.exit=function(code) error('model exited '..code) end
"""


def python_value(table):
    if lua_type(table) != 'table':
        return table
    keys = list(table)
    if keys and set(keys) == set(range(1, len(keys) + 1)):
        return [python_value(table[i]) for i in range(1, len(keys) + 1)]
    return {k: python_value(v) for k, v in table.items()}


class WireGuardModelFixture(unittest.TestCase):
    model = SCRIPTS / 'wg_hyr_config.lua'

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.db = self.folder / 'wg.sqlite'
        self.state = self.folder / 'state'
        self.keys = {}
        self.sql('CREATE TABLE wireguard (id INTEGER PRIMARY KEY, name, enabled, local_privatekey, local_publickey, local_listenport, local_address)')
        self.sql('CREATE TABLE wireguard_peers (id INTEGER PRIMARY KEY,interface,allowips,enabled,exit_peer,keepalive,peer_publickey,client_dns,site_local,site_remote,peer_privatekey,presharedkey)')
        self.interface(1)
        self.interface(2)
        self.peer(1, 1)
        self.peer(2, 1)
        self.peer(3, 2, reverse=True)

    def keypair(self):
        private, public = [base64.b64encode(os.urandom(32)).decode() for _ in range(2)]
        self.keys[private] = public
        return private, public

    def sql(self, sql, params=()):
        with sqlite3.connect(self.db) as db:
            return db.execute(sql, params).fetchall()

    def interface(self, n):
        private, public = self.keypair()
        self.sql('INSERT INTO wireguard VALUES(?,?,?,?,?,?,?)',
                 (n, f'wg{n}', 'yes', private, public, 51820+n, f'10.44.{n}.1/24'))

    def peer(self, n, interface, reverse=False):
        private, public = self.keypair()
        self.sql('INSERT INTO wireguard_peers VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                 (n, f'wg{interface}', f'10.44.{interface}.{n+2}/32', 'yes', 'yes' if reverse else 'no',
                  0, public, '', '', '', private, ''))

    def discovered(self, command):
        self.assertRegex(command, r'^/usr/ikuai/script/wg_client_endpoint\.sh get_public wg\d+ 2>/dev/null$')
        return getattr(self, 'public_endpoint', None)

    def call(self, action, *args, fails=None):
        stage = self.folder / 'stage'
        stage.mkdir(exist_ok=True)
        for name in ('next', 'relay', 'ports', 'bindings', 'directions', 'aliases', 'placements', 'pure-bindings'):
            (stage / name).unlink(missing_ok=True)
        for profile in stage.glob('pure.*'):
            profile.unlink()
        for profile in stage.glob('admin.*'):
            profile.unlink()
        for profile in stage.glob('pure-web.*'):
            profile.unlink()
        lua = LuaRuntime(unpack_returned_tuples=True)
        g = lua.globals()
        logs = []
        g.output = logs.append
        g.new_uuid = lambda: str(uuid.uuid4())
        g.encode = lambda v: json.dumps(python_value(v), separators=(',', ':'))
        g.decode = lambda s: lua.table_from(json.loads(s), recursive=True)

        db = sqlite3.connect(self.db, isolation_level=None)
        self.addCleanup(db.close)
        db.row_factory = sqlite3.Row
        def query(path, sql, *values):
            self.assertEqual(Path(path), self.db)
            rows = db.execute(sql, values)
            return lua.table_from([dict(r) for r in rows], recursive=True)

        def preparable(path, sql):
            self.assertEqual(Path(path), self.db)
            try:
                db.execute('EXPLAIN '+sql)
                return True
            except sqlite3.ProgrammingError:
                return True  # preparation reached parameter binding
            except sqlite3.OperationalError:
                return False

        g.preparable=preparable
        def derive(command):
            self.assertEqual(command, f"/usr/bin/wg pubkey < '{stage}/key' > '{stage}/pub' 2>/dev/null")
            public = self.keys.get((stage/'key').read_text().strip())
            if public:
                (stage/'pub').write_text(public+'\n')
            return 0 if public else 1

        g.query, g.derive, g.discovered = query, derive, self.discovered
        g.arg = lua.table_from([action, str(self.db), str(self.state) if self.state.exists() else '-',
                                str(stage), *map(str, args)])
        lua.execute(ADAPTERS)
        g.script_folder = str(SCRIPTS)
        lua.execute("""local load = dofile; dofile = function(p)
            local name=p:match('^/usr/ikuai/script/(.+)$')
            if name=='wg_pure_client.lua' then return {local_addresses=function() return {'192.0.2.1/32'} end} end
            assert(name=='wg_mobile_peer.lua' or name=='wg_address_plan.lua' or name=='wg_pure_profile.lua' or name=='wg_pure_lan.lua'); return load(script_folder..'/'..name) end""")
        if fails:
            with self.assertRaisesRegex(LuaError, 'model exited 1'):
                lua.execute(self.model.read_text())
            self.assertIn(fails, logs)
            self.assertFalse((stage/'next').exists())
            return
        lua.execute(self.model.read_text())
        if (stage/'next').exists():
            (stage/'next').replace(self.state)
        return json.loads(logs[0]) if logs else None

    @property
    def relay(self):
        return json.loads((self.folder/'stage/relay').read_text())
