from pathlib import Path
import json, os, subprocess, tempfile

ROOT=Path(__file__).resolve().parents[2]
script=(ROOT/'firmware/port-3726/files/usr/ikuai/script/plugin_ctpanel.sh').read_text()
export=script[script.index('\nEXPORT()'):]
fixtures=[{'name':'中文源, "引号"','url':'https://example.test/repo?a=1&b=%2F','enabled':'no'},
          {'name':'plain','url':'https://example.org/path','enabled':'yes'}]
cases=[]
with tempfile.TemporaryDirectory(prefix='native-export-') as tmp:
    d=Path(tmp); repos=d/'repos'; repos.mkdir(); out=d/'out'; out.mkdir()
    source=repos/'repos.json'; source.write_text(json.dumps(fixtures))
    runner=d/'export.sh'; runner.write_text('__ensure_repos() { :; }\n'+export+'\nEXPORT\n')
    def run(fmt):
        return subprocess.run(['bash',str(runner)],capture_output=True,env={**os.environ,
          'format':fmt,'RMT_PLUGIN_REPOS_DIR':str(repos),'IK_DIR_EXPORT':str(out)})
    helper=str(ROOT/'web-src/src/ctpanel-source-files.js')
    js="const h=require(process.argv[1]); let s=''; process.stdin.on('data',x=>s+=x).on('end',()=>process.stdout.write(h.serialize(JSON.parse(s),process.argv[2])));"
    for fmt in ['csv','txt']:
        r=run(fmt); assert r.returncode==0,r.stderr
        name='software_sources.'+fmt; assert r.stdout.decode().strip()==name
        expected=subprocess.check_output(['node','-e',js,helper,fmt],input=json.dumps(fixtures).encode())
        assert (out/name).read_bytes()==expected+(b'\r\n' if fmt=='csv' else b'\n')
        assert (out/name).stat().st_mode & 0o777 == 0o600
        cases.append(fmt+'_UTF8_exact_bytes_and_private_permissions')
    for fmt in ['po','../x','csv;touch BAD']:
        assert run(fmt).returncode!=0
        cases.append('reject_format_'+fmt)
    before=(out/'software_sources.csv').read_bytes()
    source.write_text('{broken')
    assert run('csv').returncode!=0
    assert (out/'software_sources.csv').read_bytes()==before
    assert not list(out.glob('.software-sources.*'))
    cases.append('invalid_JSON_preserves_previous_export_and_removes_temporary_file')
(Path(tempfile.gettempdir())/'export-backend-unit.json').write_text(json.dumps({'passed':len(cases),'cases':cases},indent=2)+'\n')
print('PASS',len(cases),'backend export cases')
