#!/usr/bin/env python3
"""Run the real schema migration and domain parameter checker in a local DB.

No router, network or firewall access. Paths and native validation helpers alone
are substituted; migration SQL and backward-compatible policy handling are real.
"""
from pathlib import Path
import argparse
import json
import os
import re
import shlex
import sqlite3
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / 'materials/firmware/port-3726/files/usr/ikuai/script'
parser = argparse.ArgumentParser()
parser.add_argument('--native-import', type=Path,
                    help='Pinned official import_export.sh; exercises the material importer with real SQLite metadata')
parser.add_argument('--native-validator', type=Path,
                    help='Optional original check_varl.sh; runs its real S0/import-file validation path')
parser.add_argument('--lua', type=Path, help='Local Lua 5.1 executable used with --native-validator')
args = parser.parse_args()
if bool(args.native_validator) != bool(args.lua):
    parser.error('--native-validator and --lua must be supplied together')
checked = 0


def check(condition, description):
    global checked
    assert condition, description
    checked += 1


def function(source, name):
    start = re.search(r'^' + name + r'\(\)\s*\{?', source, re.M).start()
    end = re.search(r'^\}', source[start:], re.M).end() + start
    return source[start:end]


with tempfile.TemporaryDirectory(prefix='routing-policy-schema-') as directory:
    temp = Path(directory)
    database = temp / 'config.db'
    db = sqlite3.connect(database)
    db.executescript('''
        CREATE TABLE stream_domain(
          id INTEGER PRIMARY KEY,
          interface TEXT,
          nr_group TEXT,
          nr_app TEXT,
          nr_app_first INTEGER
        );
        INSERT INTO stream_domain VALUES(1,'wg2','manual','',0);
        INSERT INTO stream_domain VALUES(2,'wg2,wan1','manual','',0);
        INSERT INTO stream_domain VALUES(3,'wg2','app','old-app',1);
        CREATE TABLE stream_ipport(id INTEGER PRIMARY KEY, interface TEXT,
          mode INTEGER, iface_band INTEGER);
        INSERT INTO stream_ipport VALUES(1,'wg2,wan1',6,0);
        INSERT INTO stream_ipport VALUES(2,'wg2',3,1);
        CREATE TABLE stream_layer7(id INTEGER PRIMARY KEY, interface TEXT,
          mode INTEGER, iface_band INTEGER);
        INSERT INTO stream_layer7 VALUES(1,'wan1,wg2',1,0);
    ''')
    db.commit()
    unchanged = {table: db.execute('SELECT * FROM '+table).fetchall()
                 for table in ['stream_ipport', 'stream_layer7']}
    source = (SCRIPTS / 'native_rules.sh').read_text()
    migration = '\n'.join(function(source, name) for name in ['ensure_conf', 'retire_app_rules'])
    migration = migration.replace('/etc/mnt/ikuai', str(temp / 'mnt'))
    env = dict(os.environ, IK_DB_CONFIG=str(database), NR=str(temp / 'nr'),
               STATE=str(temp / 'state'), CONF=str(temp / 'mnt/config.json'))
    result = subprocess.run(['bash', '-c', migration+'\nensure_conf'], env=env,
                            text=True, capture_output=True)
    check(result.returncode == 0, 'old schema migration: '+result.stderr)
    check(db.execute('SELECT id,interface,iface_band FROM stream_domain ORDER BY id').fetchall()
          == [(1, 'wg2', 1), (2, 'wg2,wan1', 1)], 'existing domain rules remain bound and ordered')
    check(db.execute('SELECT id,iface_band FROM nr_retired_app_rules').fetchall()
          == [(3, 1)], 'archived app row remains retired with compatible policy column')
    # Keep an actual pre-policy backup with the older extension columns/archive.
    # Restoring it later must not rely on /tmp migration markers being removed.
    old_database = temp / 'pre-policy.db'
    old_db = sqlite3.connect(old_database)
    db.backup(old_db)
    old_db.execute('ALTER TABLE stream_domain DROP COLUMN iface_band')
    old_db.execute('ALTER TABLE nr_retired_app_rules DROP COLUMN iface_band')
    old_db.commit()
    for table, rows in unchanged.items():
        names = 'id,interface,mode,iface_band'
        check(db.execute('SELECT '+names+' FROM '+table).fetchall() == rows,
              table+' original policy values preserved')
    db.execute("INSERT INTO stream_domain(id,interface,nr_group) VALUES(4,'wg2','manual')")
    db.execute('UPDATE stream_domain SET iface_band=0 WHERE id=1')
    db.commit()
    check(db.execute('SELECT iface_band FROM stream_domain WHERE id=4').fetchone()[0] == 0,
          'new rows default to native unbound policy')
    # Simulate both same-process calls and a reboot that removes /tmp markers.
    for reboot in [False, True]:
        if reboot:
            for marker in (temp / 'nr').glob('schema*'):
                marker.unlink()
        result = subprocess.run(['bash', '-c', migration+'\nensure_conf'], env=env,
                                text=True, capture_output=True)
        check(result.returncode == 0, 'idempotent schema migration: '+result.stderr)
        check(db.execute('SELECT iface_band FROM stream_domain ORDER BY id').fetchall()
              == [(0,), (1,), (0,)], 'explicit saved zero is never overwritten')
    domain_source = (SCRIPTS / 'stream_domain.sh').read_text()
    checker = '\n'.join(function(domain_source, name)
                        for name in ['nr_import_exit_policy', 'nr_check_exit_interfaces', '__check_param'])
    preamble = 'interface_check_routing_exit(){ return 0; }; check_varl(){ return 0; };\n'

    def validate(action, value=None, rid='1', import_file=None, serialized=None,
                 preamble_override=None):
        setup = 'nr_action='+shlex.quote(action)+'; id='+shlex.quote(rid)+'; interface=wg2;\n'
        if value is not None:
            setup += 'iface_band='+shlex.quote(value)+';\n'
        if import_file is not None:
            setup += '_______CHECK_VARL_IMPORT_FILE_______='+shlex.quote(str(import_file))+';\n'
        if serialized is not None:
            setup += 'S0='+shlex.quote(serialized)+';\n'
        return subprocess.run(['bash', '-c', (preamble if preamble_override is None
                                             else preamble_override)+checker+'\n'+setup+
                               '__check_param && printf "%s" "$iface_band"'],
                              env=env, text=True, capture_output=True)

    for action, value, rid, expected in [
        ('add', None, '1', '0'), ('edit', None, '1', '0'),
        ('edit', None, '2', '1'), ('edit', '0', '2', '0'),
        ('edit', '1', '1', '1'), ('IMPORT', None, '1', '1'),
        ('IMPORT', '0', '1', '0'),
    ]:
        result = validate(action, value, rid)
        check(result.returncode == 0 and result.stdout == expected,
              f'policy compatibility {action}/{value}/{rid}: {result.stdout!r} {result.stderr!r}')
    for invalid in ['2', '-1', 'false', '0,1', '1;echo bad']:
        check(validate('edit', invalid).returncode != 0, 'reject invalid policy '+invalid)
    check(validate('edit', None, '1 OR 1=1').returncode != 0, 'reject malformed legacy edit id')

    import_file = temp / 'mixed.txt'
    import_file.write_text('interface=wg2 iface_band=0 nr_group=foreign nr_dns=192.0.2.53 nr_route=dns_only nr_target=any\n'
                           'interface=wan1 nr_group=fallback nr_dns=198.51.100.53 nr_route=fixed nr_target=cn\n'
                           'interface=wg3 iface_band=\ninterface=wan2 iface_band=1\n'
                           'interface=wg4\n\n')
    result = validate('IMPORT', import_file=import_file)
    check(result.returncode == 0, 'real multi-line import normalization: '+result.stderr)
    normalized = import_file.read_text()
    values = [re.search(r'(?:^| )iface_band=([01])(?: |$)', line).group(1)
              for line in normalized.splitlines() if line.strip()]
    check(values == ['0', '1', '1', '1', '1'],
          'missing/empty imported policy is independently bound; explicit zero stays zero')
    check(not list(temp.glob('mixed.txt.nr-policy.*')), 'successful normalization leaves no staging file')
    for invalid in ['2', '-1', 'false', '00', '01', '1.0', '+1', '0,1',
                    '0 iface_band=1', '1 iface_band=1']:
        original = 'interface=wg2 iface_band=0\ninterface=wan1 iface_band='+invalid+'\n'
        import_file.write_text(original)
        result = validate('IMPORT', import_file=import_file)
        check(result.returncode != 0, 'reject invalid/duplicate imported policy '+invalid)
        check(import_file.read_text() == original,
              'invalid input does not partially rewrite original import '+invalid)
        check(not list(temp.glob('mixed.txt.nr-policy.*')), 'failed normalization removes staging file')
    import_file.write_text(normalized)

    if args.native_validator:
        # Keep the original shell formatter, generated Lua condition, Check
        # parser, S0 argument and import-file loop unchanged. Only unrelated
        # native format helpers and localization are substituted. In particular,
        # check_varl must inspect S0, not the shell default filled by __check_param.
        module_dir = temp / 'lua/iklua/string'
        module_dir.mkdir(parents=True)
        (module_dir / 'check.lua').write_text('''return {
          match=function(value,pattern) return value ~= nil and value:match(pattern) ~= nil end,
          ifnames_wan=function() return true end, ifnames_vpn=function() return true end,
          week=function() return true end, timeranges=function() return true end
        }''')
        native_validator = args.native_validator.read_text()
        # macOS Bash 3.2 misparses the native nested heredoc's escaped quote in
        # IlleStr. Spell the identical Lua character class as bytes; no request,
        # field parser, condition formatter or validation branch is changed.
        native_validator = re.sub(r'^\s*IlleStr\s*=.*$',
                                  '\tIlleStr = string.char(91,39,34,96,36,59,124,38,92,93)',
                                  native_validator, flags=re.M)
        # Bash 3.2 also preserves the escaped tilde in parameter replacement,
        # unlike firmware Bash. Emit the same intended Lua ~= operator.
        native_validator = native_validator.replace(r'${__LOGIC//!/\~}', '${__LOGIC//!/~}')
        native_preamble = ('interface_check_routing_exit(){ return 0; }; I18nload(){ :; };\n'
                           'Iecho(){ printf \'"native validation error"\'; };\n'
                           'lua(){ LUA_PATH='+shlex.quote(str(temp / 'lua/?.lua'))+' '+
                           shlex.quote(str(args.lua.resolve()))+' "$@"; };\n'+
                           native_validator+'\n')
        valid_s0 = 'interface=wg2 enabled=no domain=unit.invalid week=1234567 time=00:00-23:59'
        for action, value, rid, suffix, expected in [
            ('add', None, '1', '', '0'),
            ('edit', None, '1', '', '0'),
            ('edit', None, '2', '', '1'),
            ('edit', '', '2', ' iface_band=', '1'),
            ('edit', '0', '2', ' iface_band=0', '0'),
            ('edit', '1', '1', ' iface_band=1', '1'),
        ]:
            result = validate(action, value, rid, serialized=valid_s0+suffix,
                              preamble_override=native_preamble)
            check(result.returncode == 0 and result.stdout == expected and not result.stderr,
                  f'real native S0 compatibility {action}/{value}/{rid}: '
                  f'{result.stdout!r} {result.stderr!r}')
        # Deliberately contradict the shell variable: this fails only if the
        # native validator really reads the original request serialized in S0.
        result = validate('edit', '0', serialized=valid_s0+' iface_band=2',
                          preamble_override=native_preamble)
        check(result.returncode != 0 and not result.stderr,
              'native validator rejects invalid S0 despite valid shell default: '+
              repr((result.stdout, result.stderr)))
        native_import_file = temp / 'native-validation.txt'
        native_import_file.write_text('\n'.join(valid_s0+suffix for suffix in
                                                [' iface_band=0', '', ' iface_band=', ' iface_band=1'])+'\n')
        result = validate('IMPORT', import_file=native_import_file,
                          serialized=valid_s0+' iface_band=2', preamble_override=native_preamble)
        check(result.returncode == 0 and not result.stderr,
              'native check_varl reads normalized import file instead of S0: '+result.stdout+result.stderr)
        check([re.search(r'iface_band=([01])', row).group(1)
               for row in native_import_file.read_text().splitlines()] == ['0', '1', '1', '1'],
              'real native import validation keeps independent row policies')

    if args.native_import:
        from lupa.lua51 import LuaRuntime
        original_importer = args.native_import.read_text()
        material_importer = (SCRIPTS.parent / 'include/import_export.sh').read_text()
        migrated_schema = db.execute("SELECT sql FROM sqlite_master WHERE name='stream_domain'").fetchone()[0]
        old_start = original_importer.index('--获得表结构的字段和类型')
        old_end = original_importer.index('--解析导入文件', old_start)
        old_lua = LuaRuntime()
        old_lua.globals().tbl_struct = migrated_schema
        old_types = old_lua.execute(original_importer[old_start:old_end]+'\nreturn types')
        check(old_types['interface'] == 'text' and old_types['iface_band'] is None,
              'original regexp recognizes native columns but misses ALTER-added policy; keep regression reproducer')

        def insert_native_rows(file, expected_metadata=None):
            # Run native schema discovery as well as its per-line parser/INSERT
            # loop. In particular, never inject types: ALTER ADD COLUMN can put
            # new fields on one line that the native schema regexp may not read.
            start = material_importer.index('--获得表结构的字段和类型')
            end = material_importer.index('tmpdb:close()', start)
            program = material_importer[start:end].replace('$tablename', 'stream_domain')
            program = re.sub(r'\$\(Iecho [^)]*\)', '"native import error"', program)
            native_db = sqlite3.connect(':memory:')
            native_db.execute(migrated_schema)
            lua = LuaRuntime(unpack_returned_tuples=True)
            schema_queries = []
            def execute(_self, sql):
                native_db.execute(sql)
                return 0
            def nrows(_self, sql):
                # The actual material Lua issues PRAGMA; return actual SQLite
                # cursor metadata/rows, never a hand-written field/type table.
                schema_queries.append(sql)
                cursor = native_db.execute(sql)
                names = [column[0] for column in cursor.description]
                def next_row(*_):
                    row = cursor.fetchone()
                    return lua.table_from(dict(zip(names, row))) if row is not None else None
                return next_row
            lua.globals().tmpdb = lua.table_from({'exec': execute, 'nrows': nrows})
            lua.globals().tbl_struct = migrated_schema
            lua.globals().file = str(file)
            lua.globals().ikdebug = ''
            lua.execute('import={}')
            native_types = lua.execute(program+'\nreturn types')
            check(native_types['iface_band'] == 'integer',
                  'native importer discovers iface_band from the real migrated sqlite_master SQL: '+
                  migrated_schema+'; discovered='+repr(dict(native_types.items())))
            check(schema_queries == ['PRAGMA table_info(stream_domain)'],
                  'material importer obtains column types from the actual SQLite schema')
            if expected_metadata:
                actual = native_db.execute('SELECT nr_group,nr_dns,nr_route,nr_target FROM stream_domain ORDER BY rowid LIMIT 2').fetchall()
                check(actual == expected_metadata, 'other ALTER-added domain metadata survives the real import: '+repr(actual))
            rows = native_db.execute('SELECT interface,iface_band FROM stream_domain ORDER BY rowid').fetchall()
            native_db.close()
            return rows

        check(insert_native_rows(import_file, [('foreign', '192.0.2.53', 'dns_only', 'any'),
                                               ('fallback', '198.51.100.53', 'fixed', 'cn')]) ==
              [('wg2', 0), ('wan1', 1), ('wg3', 1), ('wan2', 1), ('wg4', 1)],
              'real native TXT INSERTs store normalized values instead of column default zero')
        csv_file = temp / 'mixed.csv'
        csv_file.write_text('interface,iface_band,comment\nwg2,0,explicit-zero\n'
                            'wan1,,old-empty\nwg3,1,explicit-one\nwg4,,old-after-one\n')
        csv_program = re.search(r'local file="\$file".*?os.rename\(file_tmp, file\)',
                                material_importer, re.S).group()
        csv_program = csv_program.replace('"$file.tmp"', json.dumps(str(csv_file)+'.tmp'))
        csv_program = csv_program.replace('"$file"', json.dumps(str(csv_file)))
        LuaRuntime().execute(csv_program)
        result = validate('IMPORT', import_file=csv_file)
        check(result.returncode == 0, 'real native CSV conversion reaches policy normalizer')
        check(insert_native_rows(csv_file) == [('wg2', 0), ('wan1', 1), ('wg3', 1), ('wg4', 1)],
              'real native CSV-to-TXT-to-SQL preserves explicit policy without inheriting previous row')

    check((temp / 'nr/schema').exists() and (temp / 'nr/schema-exit-policy').exists(),
          'restore fixture deliberately retains both schema markers')
    old_db.backup(db)
    result = subprocess.run(['bash', '-c', migration+'\nensure_conf'], env=env,
                            text=True, capture_output=True)
    check(result.returncode == 0, 'restored old database is migrated despite live markers: '+result.stderr)
    check(db.execute('SELECT iface_band FROM stream_domain ORDER BY id').fetchall() == [(1,), (1,)],
          'restored pre-policy rows regain the column and keep their bound behavior')
    check(db.execute('SELECT iface_band FROM nr_retired_app_rules').fetchall() == [(1,)],
          'restored archive schema regains the compatible policy column')
    old_db.close()
    db.close()

print(f'routing-policy-schema: {checked} checks passed')
