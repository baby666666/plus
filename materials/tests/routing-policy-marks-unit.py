#!/usr/bin/env python3
"""Check the real C and shell mark-admission boundaries without netlink access."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / 'materials/native-src/native_conntrack_prune.c').read_text()
function = re.search(r'^static int is_managed\(.*?\n', source, re.M).group()
shell = (ROOT / 'materials/firmware/port-3726/files/usr/ikuai/script/native_rules.sh').read_text()
start = shell.index('guard(){')
guard = shell[start:start+re.search(r'^\}', shell[start:], re.M).end()]
accepted = [0x55000001, 0x55FFFFFF, 0x58000100, 0x58000101, 0x58FFFFFF,
            0x53000001, 0x2DF001, 3011001]
rejected = [0, 1, 0x54000001, 0x56000000, 0x57000001, 0x59000001,
            0x2DEFFF, 0x2E0000, 0xFFFFFFFF]
checked = 0
with tempfile.TemporaryDirectory(prefix='routing-policy-marks-') as directory:
    temp = Path(directory)
    c = temp / 'check.c'
    c.write_text('#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n'+function+
                 'int main(int argc,char **argv){for(int i=1;i<argc;i++)'
                 'printf("%d\\n",is_managed((uint32_t)strtoull(argv[i],0,0)));return 0;}\n')
    subprocess.run(['cc', '-Wall', '-Werror', str(c), '-o', str(temp / 'check')], check=True)
    marks = accepted+rejected
    actual = subprocess.check_output([str(temp / 'check')]+[str(value) for value in marks], text=True)
    assert actual.splitlines() == ['1']*len(accepted)+['0']*len(rejected)
    checked += len(marks)
    stubs = 'nr_ipv6(){ :; }; nr_ipt(){ :; }; nr_hook(){ :; }; iptables-restore(){ cat; };\n'
    env = dict(os.environ, NR=str(temp / 'nr'), NR_IFACES='lan1 wg1')
    for value in marks:
        path = temp / 'marks'
        path.write_text(str(value)+'\n')
        result = subprocess.run(['bash', '-c', stubs+guard+'\nguard 1 "$1"', 'check', str(path)],
                                env=env, text=True, capture_output=True)
        assert (result.returncode == 0) == (value in accepted), (value, result.stdout, result.stderr)
        if value in accepted:
            assert '--mark '+str(value)+'/0xffffffff -j RETURN' in result.stdout
        checked += 1
    for bad in ['4294967296', '0x58000100', '1476395264 extra', '-1', '1; echo bad']:
        path.write_text(bad+'\n')
        result = subprocess.run(['bash', '-c', stubs+guard+'\nguard 1 "$1"', 'check', str(path)],
                                env=env, text=True, capture_output=True)
        assert result.returncode != 0 and '-A NR_FORWARD_GUARD' not in result.stdout, bad
        checked += 1
print(f'routing-policy-marks: {checked} checks passed')
