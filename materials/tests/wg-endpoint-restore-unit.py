from pathlib import Path
import sys,subprocess,tempfile

s=Path(sys.argv[1]).read_text()
body=s[s.index('__wg_restore_learned_endpoints()'):s.index('#interface=wg11')]
cases=[
 ('learned endpoint restored','A\t1.2.3.4:1234','A\t(none)',0,0,['set wg2 peer A endpoint 1.2.3.4:1234']),
 ('explicit endpoint unchanged','A\t1.2.3.4:1234','A\t5.6.7.8:9876',0,0,[]),
 ('removed peer not recreated','A\t1.2.3.4:1234','B\t(none)',0,0,[]),
 ('unlearned old endpoint skipped','A\t(none)','A\t(none)',0,0,[]),
 ('multiple peers isolated','A\t1.2.3.4:1234\nB\t5.6.7.8:9876\nC\t9.8.7.6:1111','A\t(none)\nB\t2.2.2.2:2222',0,0,['set wg2 peer A endpoint 1.2.3.4:1234']),
 ('empty snapshot is no-op','','A\t(none)',0,0,[]),
 ('read error propagated','A\t1.2.3.4:1234','A\t(none)',1,0,[]),
 ('write error propagated','A\t1.2.3.4:1234','A\t(none)',0,1,['set wg2 peer A endpoint 1.2.3.4:1234']),
 ('IPv6 endpoint retained as one argument','A\t[2001:db8::1]:1234','A\t(none)',0,0,['set wg2 peer A endpoint [2001:db8::1]:1234'])
]
with tempfile.TemporaryDirectory()as d:
 log=Path(d)/'calls'
 script=body+'''
__wg_bin(){ echo mock_wg; }
mock_wg(){
 if [ "$1" = show ]; then printf '%s\n' "$CURRENT"; return "$READ_ERROR"; fi
 [ "$#" = 6 ] || return 7
 printf '%s\n' "$*" >> "$CALLS"
 return "$WRITE_ERROR"
}
PREVIOUS=$1 CURRENT=$2 READ_ERROR=$3 WRITE_ERROR=$4 CALLS=$5
__wg_restore_learned_endpoints wg2 "$PREVIOUS"
'''
 for name,old,current,readerr,writeerr,expected in cases:
  log.write_text('')
  r=subprocess.run(['bash','-c',script,'test',old,current,str(readerr),str(writeerr),str(log)],capture_output=True,text=True)
  assert bool(r.returncode)==bool(readerr or writeerr),(name,r.returncode,r.stderr)
  assert log.read_text().splitlines()==expected,(name,log.read_text())
print('PASS 9 learned-endpoint restoration cases')
