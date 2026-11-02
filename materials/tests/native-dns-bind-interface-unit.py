from pathlib import Path
import subprocess,tempfile,sys

s=Path(sys.argv[1]).read_text();body=s[s.index('interfaces(){'):s.index('prepare(){')]
cases=[
 ('live WG and helper both bound',[('wg1',True,True),('pppwg1',True,True)],['pppwg1','wg1']),
 ('empty WG and live-looking helper skipped',[('wg8',False,True),('pppwg8',True,True)],[]),
 ('orphan helper skipped',[('pppwg9',True,True)],[]),
 ('non-WG legacy binding preserved',[('lan1',False,True),('vlan1',True,True),('ppp1',True,True)],['lan1','ppp1','vlan1']),
 ('WAN and internal dispatcher ignored',[('wan1',True,True),('pppnrd1',True,True)],[]),
 ('IPv4 address still required',[('wg1',True,False),('lan1',True,False)],[]),
 ('mixed interfaces isolate empty changes',[('wg1',True,True),('pppwg1',True,True),('wg8',False,True),('pppwg8',True,True),('lan1',True,True)],['lan1','pppwg1','wg1']),
 ('active WG UNKNOWN state accepted',[('wg123',True,True)],['wg123'])
]
with tempfile.TemporaryDirectory()as d:
 d=Path(d)
 script='''set -e -o pipefail
ip(){
 if [ "$*" = '-o link show' ]; then cat "$FIXTURE/links"; return; fi
 if [ "$1 $2 $3 $4" = '-o link show dev' ]; then cat "$FIXTURE/link-$5" 2>/dev/null; return; fi
 if [ "$1 $2 $3 $4 $5" = '-o -4 addr show dev' ]; then cat "$FIXTURE/addr-$6" 2>/dev/null; return; fi
 return 2
}
FIXTURE=$1
'''+body+'\ninterfaces\n'
 for name,rows,expected in cases:
  for p in d.iterdir():p.unlink()
  lines=[]
  for i,(dev,up,addr)in enumerate(rows,1):
   line=f'{i}: {dev}: <POINTOPOINT,NOARP'+(',UP,LOWER_UP'if up else '')+'> mtu 1420 state UNKNOWN\n'
   lines.append(line);(d/('link-'+dev)).write_text(line)
   (d/('addr-'+dev)).write_text(f'{i}: {dev} inet 10.100.{i}.1/24 scope global {dev}\n'if addr else '')
  (d/'links').write_text(''.join(lines))
  r=subprocess.run(['bash','-c',script,'test',str(d)],capture_output=True,text=True)
  assert r.returncode==0 and r.stdout.splitlines()==expected,(name,r.returncode,r.stdout,r.stderr)
print('PASS 8 DNS ingress binding cases')
