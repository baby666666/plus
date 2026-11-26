#!/usr/bin/env python3
"""Exercise real native protocol generators and add/init/up/edit call paths.

Only vendor commands and database reads are mocked. Generated compatibility
rules are inspected; this does not replace VM tests of DPI or packet routing.
"""
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'materials/firmware/port-3726/files/usr/ikuai/script/stream_layer7.sh'
source = SOURCE.read_text()
checked = 0


def check(value, message):
    global checked
    assert value, message
    checked += 1


def function(name):
    start = re.search(r'^' + re.escape(name) + r'\(\)\s*\{?', source, re.M).start()
    end = start + re.search(r'^\}', source[start:], re.M).end()
    return source[start:end]


with tempfile.TemporaryDirectory(prefix='protocol-ingress-vendor-') as directory:
    temp = Path(directory)
    paths = temp / 'rules'
    paths.mkdir()
    scripts = temp / 'scripts'
    scripts.mkdir()
    (scripts / 'stream_domain.sh').write_text('#!/bin/sh\nexit 0\n')
    (scripts / 'stream_domain.sh').chmod(0o700)
    selected = ['init', '__exec_rule_clean', '__exec_rule_commit', '__exec_rule_add',
                '__exec_rule_del', '__format_ipset', 'nr_original_add',
                'nr_original_up', 'nr_original_edit']
    functions = '\n'.join(function(name) for name in selected)
    functions = functions.replace('/tmp/iktmp/ipt_rule_id', str(paths))
    # A one-entry appid array works with macOS Bash 3.2 and the vendor Bash.
    # This replaces the fixture database only, not its rule generation.
    common = r'''
set -o pipefail
Lock(){ :; }; unLock(){ :; }
iptables(){ :; }
ik_cntl(){ printf '%s\n' "$*" >> "$trace"; }
iproute_get_markid(){ echo 10003; }
ipt_format_time(){ echo '-m time --timestart 09:00 --timestop 17:00'; }
ipset_rule_add(){ :; }
__check_param(){ :; }
__check_interface_nums(){ :; }
sqlite3(){ echo 0; }
sql_config_insert(){ echo 7; }
sql_config_update(){ :; }
sql_config_get_list(){ case "$*" in *prefix=old_*) cat "$old";; *) cat "$rows";; esac; }
NewOldVarl(){ return 1; }
iptables-restore(){ cat "${@: -1}" > "$applied"; }
# Equivalent GNU sed -i -r execution using the host's extended-regexp sed.
sed(){
 if [ "$1" = -i ] && [ "$2" = -r ];then
  command sed -E "$3" "$4" > "$4.new" && mv "$4.new" "$4"
 else command sed "$@";fi
}
LOCKUP='Lock stream_layer7';UNLOCK='unLock stream_layer7'
IK_DB_CONFIG=mock;IPT_CONNMARK_STREAM_LAYER7=4000000
LINE_N=$'\n';APPIDS=(1000000:1999999)
id=7;enabled=yes;interface=wan3;src_addr=198.18.1.2/32;src='-m set --match-set slayer7_src_7 src'
week=1234567;time=09:00-17:00;mode=6;iface_band=1;app_proto=all;nr_ingress=
'''
    settings = '\n'.join(name + '=' + shlex.quote(str(path)) for name, path in {
        'trace': temp / 'trace', 'rows': temp / 'rows', 'old': temp / 'old',
        'applied': temp / 'applied', 'INIT_CONFIG': temp / 'iptables',
        'IK_DIR_SCRIPT': scripts,
    }.items())

    def run(actions, rows='', old='old_id=7 old_nr_ingress='):
        for p in [paths / 'stream_layer7_id', paths / 'stream_layer7_id_rule',
                  temp / 'trace', temp / 'applied']:
            p.write_text('')
        (temp / 'rows').write_text(rows)
        (temp / 'old').write_text(old + '\n')
        result = subprocess.run(['bash'], input=settings + '\n' + common + '\n' +
                                functions + '\n' + actions, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        check(result.returncode == 0, 'native generator execution: ' + result.stderr)
        return ((paths / 'stream_layer7_id_rule').read_text(),
                (temp / 'applied').read_text(), (temp / 'trace').read_text())

    for app in ['all', 'HttpProtocol', 'CustomP2P']:
        fixture = "APPIDS=(2000001)\n" if app == 'CustomP2P' else ''
        for ingress in ['wg1', 'pppwg1', 'ppphy1', 'lan1']:
            rules, _, trace = run(fixture + 'app_proto=' + app + ';nr_ingress=' + ingress + ';nr_original_add\n')
            check(not rules and 'mark_rule add' not in trace,
                  app + '/' + ingress + ' has no broad compatibility duplicate')
        rules, _, _ = run(fixture + 'app_proto=' + app + ';nr_ingress=;nr_original_add\n')
        check('STREAM_LAYER7_NEW' in rules and '--set-ifname wan3' in rules,
              app + ' unrestricted native rule is retained')
        check('--set-mode 6' in rules and '--set-band-flag 1' in rules and
              '--match-set slayer7_src_7 src' in rules and '--timestart 09:00' in rules,
              app + ' source, time, ordered exit mode and binding are unchanged')
        if app != 'all':
            check('--appid ' + ('2000001' if app == 'CustomP2P' else '1000000:1999999') in rules,
                  app + ' retains native protocol match')

    rows = ('id=7 enabled=yes interface=wan3 app_proto=all nr_ingress=wg1 src_addr=198.18.1.7/32\n'
            'id=8 enabled=yes interface=wan2 app_proto=all src_addr=198.18.1.8/32\n'
            'id=9 enabled=yes interface=wan3 app_proto=all nr_ingress= src_addr=198.18.1.9/32\n')
    for action in ['init', 'nr_original_up']:
        rules, applied, _ = run(action + '\n', rows=rows)
        check(not re.search(r'^7 ', rules, re.M), action + ' skips scoped row')
        check(bool(re.search(r'^8 ', rules, re.M)), action + ' missing ingress does not inherit prior scope')
        check(bool(re.search(r'^9 ', rules, re.M)), action + ' explicit empty ingress restores unrestricted row')
        check('--match-set slayer7_src_8 src' in applied and '--match-set slayer7_src_9 src' in applied,
              action + ' retains each unrestricted row source')

    rules, applied, _ = run('nr_original_add >/dev/null;nr_ingress=wg1;nr_original_edit\n')
    check(not rules and 'STREAM_LAYER7_NEW' not in applied,
          'editing unrestricted to scoped removes existing broad rule')
    rules, applied, _ = run('nr_ingress=wg1;nr_original_add >/dev/null;nr_ingress=;nr_original_edit\n',
                            old='old_id=7 old_nr_ingress=wg1')
    check(len(rules.splitlines()) == 1 and 'STREAM_LAYER7_NEW' in applied,
          'clearing ingress recreates exactly one unrestricted rule')

print('PASS: %d native protocol ingress compatibility checks' % checked)
