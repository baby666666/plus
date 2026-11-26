#!/usr/bin/env python3
"""Run extracted firmware apply functions against isolated command fixtures.

No router, network, real database, or real WG key is accessed. Absolute firmware
helpers and /sys reads are redirected to fixtures; function logic is unchanged.
"""
from pathlib import Path
import base64,os,re,subprocess,sys,tempfile

source=Path(sys.argv[1]).read_text()
starts=list(re.finditer(r'(?m)^([A-Za-z_]\w*)\(\)\s*[({]',source))
functions={m.group(1):source[m.start():starts[i+1].start() if i+1<len(starts) else len(source)] for i,m in enumerate(starts)}
names=['__exec_rule_restart_one','__init_iface_config','__wg_valid_ids','__wg_write_config','__check_key_valid','__wg_endpoint_identity','__wg_endpoint_socket','__wg_build_iface_config','__wg_apply_iface','__wg_apply_failed','__wg_apply_interfaces','__wg_locked_del','__wg_locked_down','__wg_locked_up','__exec_rule_iface_del','__wg_locked_iface_del','__wg_locked_iface_down','__wg_locked_iface_up','__wg_revoke_peer_sessions','__wg_peer_write','__wg_save_peer','__wg_locked_edit']
body='\n'.join(functions[n] for n in names)
body=body.replace('/usr/bin/lua /usr/ikuai/script/wg_peer_options.lua','mock_lua').replace('/usr/ikuai/script/native_ingress.sh','mock_ingress').replace('/usr/bin/lua /usr/ikuai/script/wg_address_config.lua','mock_lua').replace('/sys/class/net/','$FIXTURE/sys/')
mocks=r'''
FIXTURE=$1
IK_DB_CONFIG=fixture.db
IK_DIR_TMP="$FIXTURE/tmp"
log(){ printf '%s\n' "$*" >> "$FIXTURE/log"; }
fail(){ [ -f "$FIXTURE/fail-$1" ]; }
sqlite3(){
 log "SQLITE $*"
 fail sql && return 1
 case "$*" in
  *"update wireguard"*|*"delete from wireguard"*)
   log DB_WRITE
   fail dbwrite && return 1
   : > "$FIXTURE/db-written";;
  *"select count(*)"*) cat "$FIXTURE/enabled";;
  *) return 2;;
 esac
}
sql_config_get_list(){
 log "SQL $2"
 fail rows && return 1
 case "$2" in *"; update "*|*"; delete "*) return 2;;esac
 case "$2" in
  *"from wireguard where id in"*) printf '%s' "$2" > "$FIXTURE/selection";cat "$FIXTURE/ifaces";;
  *"from wireguard where"*) cat "$FIXTURE/iface";;
  *"where id in"*) printf '%s' "$2" > "$FIXTURE/selection";cat "$FIXTURE/peers";;
  *"from wireguard_peers where interface="*) cat "$FIXTURE/peers";;
  *) return 2;;
 esac
}
__wg_bin(){ echo mock_wg; }
mock_wg(){
 if [ "$1" = show ];then cat "$FIXTURE/endpoints";return;fi
 log "WG $1 $2"
 cp "$3" "$FIXTURE/submitted"
 if fail wgsecret;then
  printf '%s\n' 'WG_PARSE_SECRET_SENTINEL_DO_NOT_EXPOSE'
  printf '%s\n' 'WG_PARSE_SECRET_SENTINEL_DO_NOT_EXPOSE' >&2
  return 1
 fi
 fail wg && return 1
 log APPLY_OK
}
interface_check_routing_exit(){ ! fail routeiface; }
iproute_get_markid(){ echo 53; }
__format_ipmask(){ printf '%s\n' "$1"; }
__wg_resolve_address(){ log "RESOLVE $1";fail resolve && return 1;echo 192.0.2.20; }
mock_lua(){ log VALIDATE;! fail validate; }
mock_ingress(){ log "INGRESS $*";[ "$1" != up ] || ! fail ingress; }
__wg_inbound_policy_apply(){ log IFACE_POLICY;! fail inbound; }
__wg_restore_learned_endpoints(){ ! fail restore; }
__wg_site_client_table(){ return 1; }
__wg_inbound_policy_del(){ log "IFACE_POLICY_DEL $1"; }
__wg_policy_apply(){ log "POLICY $id";! fail policy; }
__wg_policy_del(){ log "POLICY_DEL $1"; }
__del_config_cache(){ rm -f "$IK_DIR_TMP/wireguard/config/$id"; }
__wg_iface_cache_update(){ log IFACE_CACHE; }
logger(){ log LOGGER; }
mktemp(){ fail mktemp && return 1;command mktemp "$@"; }
chmod(){ fail chmod && return 1;command chmod "$@"; }
mv(){
 case "$1 $2 $3" in *iface.conf*) fail publish && return 1;; *cache-*) fail cachepublish && return 1;; esac
 log "PUBLISH ${2##*/}"
 command mv "$@"
}
ip(){
 log "IP $*"
 case "$*" in
  'link show dev '* ) ! fail new;;
  'link add dev '* ) ! fail linkadd;;
  'address add dev '* ) ! fail address;;
  'link set mtu '* ) ! fail mtu;;
  'link set down dev '* ) : > "$FIXTURE/blocked";printf '0x0\n' > "$FIXTURE/sys/wg1/flags";;
  'route show table main dev '* ) cat "$FIXTURE/routes";;
  'route del '* ) ! fail routedel;;
  'route flush '* ) :;;
  'link del dev '* ) ! fail ifacedel;;
  'route replace default '* )
   if fail routewhendown && [ "$(( $(cat "$FIXTURE/sys/wg1/flags") & 1 ))" = 0 ];then return 1;fi
   ! fail default;;
  'route replace '* )
   if fail routewhendown && [ "$(( $(cat "$FIXTURE/sys/wg1/flags") & 1 ))" = 0 ];then return 1;fi
   ! fail route;;
  'link set up dev '* )
   fail linkup && return 1
   printf '0x1\n' > "$FIXTURE/sys/wg1/flags";;
  * ) return 2;;
 esac
}
'''

def fixture(d,peers=2,endpoints=False):
 (d/'tmp/wireguard/config').mkdir(parents=True)
 (d/'sys/wg1').mkdir(parents=True);(d/'sys/wg1/flags').write_text('0x1\n')
 (d/'enabled').write_text('1\n')
 (d/'iface').write_text('id=100 name=wg1 enabled=yes interface=auto local_listenport=50001 local_privatekey=FAKE_INTERFACE_KEY local_address=10.100.1.1/24\n')
 rows=[]
 for i in range(1,peers+1):
  rows.append(f'id={i} interface=wg1 enabled=yes peer_publickey=FAKE_PEER_{i} allowips=10.100.1.{i+1}/32 site_remote= exit_peer=no endpoint='+('endpoint.example endpoint_port=50002' if endpoints else ' endpoint_port=')+' keepalive=0 presharedkey= out_mode=auto\n')
 (d/'peers').write_text(''.join(rows));(d/'endpoints').write_text('')
 (d/'routes').write_text('10.100.1.2 dev wg1 metric 100\n')
 (d/'log').write_text('')
 (d/'tmp/wireguard/wg1.conf').write_text('OLD_CONFIG')

def run(d,action='__wg_apply_iface wg1',extra=''):
 return subprocess.run(['bash','-c',mocks+'\n'+body+'\n'+extra+'\n'+action,'test',str(d)],capture_output=True,text=True)

def lines(d):return (d/'log').read_text().splitlines()
def check(b,name,detail=''):assert b,(name,detail)
def blocked_failure(d,r,name):
 check(r.returncode!=0,name+' status',r.stderr)
 check((d/'blocked').exists(),name+' fail closed')
 check(not (d/'tmp/wireguard/wg1.conf').exists(),name+' stale config invalidated')

count=0
with tempfile.TemporaryDirectory(prefix='wg-apply-unit-') as tmp:
 def fresh(name,**kw):
  global count
  count+=1;d=Path(tmp)/name;d.mkdir();fixture(d,**kw);return d
 d=fresh('full-apply',peers=3,endpoints=True);r=run(d);log=lines(d)
 check(r.returncode==0,'complete apply',r.stderr)
 check([x for x in log if x.startswith('WG ')]==['WG syncconf wg1'],'single syncconf')
 cfg=(d/'submitted').read_text()
 check(cfg.count('[Peer]')==3,'all peers before apply')
 check(cfg.count('PersistentKeepalive = 0')==3 and cfg.count('PresharedKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')==3,'explicit field clear')
 check(all(log.index(x)>log.index('APPLY_OK') for x in log if x.startswith('PUBLISH ')),'publish after apply')
 check(all((d/f'tmp/wireguard/config/{i}').exists() for i in (1,2,3)),'cache committed')
 check(not any(x.startswith('IP link del') or x.startswith('IP route flush') or x.startswith('INGRESS ') for x in log),'live interface preserved')
 check('IP route replace 10.100.1.2 dev wg1 metric 100' not in log,'unchanged route retained')
 check('IP route replace 10.100.1.3 dev wg1 metric 100' in log,'new route added')
 check((d/'tmp/wireguard/wg1.conf').stat().st_mode&0o777==0o600,'private config permissions')

 d=fresh('new-interface');(d/'fail-new').touch();(d/'sys/wg1/flags').write_text('0x0\n');r=run(d)
 check(r.returncode==0,'new iface',r.stderr)
 check([x for x in lines(d) if x.startswith('WG ')]==['WG setconf wg1'],'new iface one setconf')
 check('INGRESS up wg1' in lines(d),'new interface ingress setup')

 d=fresh('route-requires-up');(d/'fail-new').touch();(d/'fail-routewhendown').touch();(d/'sys/wg1/flags').write_text('0x0\n');r=run(d)
 check(r.returncode==0,'new interface kernel routes require UP',r.stderr)
 log=lines(d)
 first_route=min(i for i,line in enumerate(log) if line.startswith('IP route replace '))
 check(log.index('IP link set up dev wg1') < first_route,'new interface UP before route install')

 d=fresh('empty-new',peers=0);(d/'fail-new').touch();(d/'sys/wg1/flags').write_text('0x0\n');r=run(d)
 check(r.returncode==0,'empty iface',r.stderr)
 check(not any(x.startswith('IP link set up') for x in lines(d)),'empty iface remains down')

 for fault,step in [('linkadd','创建内核接口'),('address','设置接口地址'),('mtu','设置接口 MTU'),
                    ('ingress','配置接入接口'),('inbound','应用回包策略'),('wgsecret','载入 WireGuard 配置')]:
  d=fresh('restart-'+fault,peers=0)
  (d/'fail-new').touch()
  (d/('fail-'+fault)).touch()
  r=run(d,'__exec_rule_restart_one wg1')
  blocked_failure(d,r,'restart '+fault)
  check(r.stdout.strip()=='wg1 运行配置应用失败（'+step+'）','restart identifies safe stage '+fault,r.stdout)
  check('WG_PARSE_SECRET_SENTINEL' not in r.stdout+r.stderr,'restart suppresses sensitive diagnostics')
  (d/('fail-'+fault)).unlink()
  r=run(d,'__exec_rule_restart_one wg1')
  check(r.returncode==0 and not r.stdout,'same saved configuration recovered '+fault,r.stderr)
  check((d/'tmp/wireguard/wg1.conf').is_file(),'only successful configuration published '+fault)

 d=fresh('remove-obsolete');(d/'routes').write_text('10.100.1.2 dev wg1 metric 100\n10.100.1.90 dev wg1 metric 100\n');r=run(d)
 check(r.returncode==0,'obsolete route removal',r.stderr)
 check('IP route del 10.100.1.90 dev wg1 metric 100' in lines(d),'only obsolete route removed')
 check('IP route del 10.100.1.2 dev wg1 metric 100' not in lines(d),'shared live route untouched')

 d=fresh('cached-roaming',peers=1,endpoints=True)
 (d/'endpoints').write_text('FAKE_PEER_1\t192.0.2.80:60000\n')
 (d/'tmp/wireguard/config/1').write_text('wg1\tFAKE_PEER_1\tendpoint.example\t50002\t192.0.2.20\n')
 r=run(d);check(r.returncode==0,'roaming cached endpoint',r.stderr)
 check('Endpoint = 192.0.2.80:60000' in (d/'submitted').read_text(),'learned endpoint retained')
 check(not any(x.startswith('RESOLVE ') for x in lines(d)),'unchanged endpoint no DNS')

 for failure in ['sql','validate','mktemp','chmod','resolve','wg','route','default','policy','publish','cachepublish']:
  d=fresh('failure-'+failure,endpoints=True);(d/('fail-'+failure)).touch();r=run(d)
  blocked_failure(d,r,failure)
  if failure in ['sql','validate','mktemp','chmod','resolve']:
   check(not any(x.startswith('WG ') for x in lines(d)),failure+' before WG apply')
  check(not (d/'tmp/wireguard/config/1').exists(),failure+' no false cache')

 d=fresh('failure-routedel');(d/'routes').write_text('10.100.1.90 dev wg1 metric 100\n');(d/'fail-routedel').touch();r=run(d)
 blocked_failure(d,r,'routedel')

 for action in ['del','down','up']:
  d=fresh('batch-'+action,peers=3)
  (d/'peers').write_text('id=1 interface=wg1 enabled=yes\nid=2 interface=wg1 enabled=yes\nid=3 interface=wg2 enabled=yes\n')
  r=run(d,'id=1,2,3;__wg_locked_'+action, '__wg_apply_iface(){ log "APPLY $1"; }')
  check(r.returncode==0,'batch '+action,r.stderr)
  check('id in (1,2,3)' in (d/'selection').read_text(),'batch selection preserved '+action)
  check([x for x in lines(d) if x.startswith('APPLY ')]==['APPLY wg1','APPLY wg2'],'batch dedup '+action)
  check((d/'db-written').exists(),'explicit SQLite batch write '+action)
  check(lines(d).index('DB_WRITE') < lines(d).index('APPLY wg1'),'DB write precedes runtime batch '+action)
  check(';' not in (d/'selection').read_text(),'list helper is read-only '+action)

 d=fresh('aggregate-fail')
 r=run(d,'__wg_apply_interfaces "wg1 wg2 wg1 wg3"','__wg_apply_iface(){ log "APPLY $1";[ "$1" != wg2 ]; }')
 check(r.returncode!=0,'batch failure propagated')
 check([x for x in lines(d) if x.startswith('APPLY ')]==['APPLY wg1','APPLY wg2','APPLY wg3'],'other affected interfaces still reconciled')

 d=fresh('iface-delete-ok');r=run(d,'__exec_rule_iface_del wg1')
 check(r.returncode==0,'interface teardown succeeds',r.stderr)
 check('IP link del dev wg1' in lines(d),'live interface removed')
 check(not (d/'tmp/wireguard/wg1.conf').exists(),'teardown invalidates config')

 d=fresh('iface-delete-missing');(d/'fail-new').touch();r=run(d,'__exec_rule_iface_del wg1')
 check(r.returncode==0,'missing interface delete idempotent',r.stderr)
 check('IP link del dev wg1' not in lines(d),'missing interface not deleted again')
 check(not (d/'tmp/wireguard/wg1.conf').exists(),'missing interface cache invalidated')

 d=fresh('iface-delete-failure');(d/'fail-ifacedel').touch();r=run(d,'__exec_rule_iface_del wg1')
 blocked_failure(d,r,'interface deletion')

 d=fresh('disabled-apply-failure');(d/'enabled').write_text('0\n');(d/'fail-ifacedel').touch();r=run(d)
 blocked_failure(d,r,'disabled interface apply')
 check(not any(x.startswith('WG ') for x in lines(d)),'disabled interface never reapplied')

 d=fresh('iface-batch-failure')
 (d/'ifaces').write_text('id=1 name=wg1 enabled=yes\nid=2 name=wg2 enabled=yes\nid=3 name=wg3 enabled=yes\n')
 for action in ['del','down']:
  (d/'log').write_text('')
  r=run(d,'id=1,2,3;__wg_locked_iface_'+action,'__exec_rule_iface_del(){ log "DELETE $1";[ "$1" != wg2 ]; }')
  check(r.returncode!=0,'interface batch failure returned '+action)
  check('id in (1,2,3)' in (d/'selection').read_text(),'interface selection retained '+action)
  check([x for x in lines(d) if x.startswith('DELETE ')]==['DELETE wg1','DELETE wg2','DELETE wg3'],'remaining interfaces processed '+action)

 d=fresh('wg-error-secret');(d/'fail-wgsecret').touch();r=run(d)
 blocked_failure(d,r,'secret-bearing WG parser error')
 check('WG_PARSE_SECRET_SENTINEL_DO_NOT_EXPOSE' not in r.stdout+r.stderr,'WG error hides sensitive parser output')
 check('载入 WireGuard 配置' in r.stdout,'WG parser error identifies the stage')

 # Use iptables -S output in both native forms. Quoted comments must become
 # actual argv values when deleting the rule, with no prefix collisions.
 policy_functions='\n'.join(functions[n] for n in (
  '__wg_policy_comment','__wg_inbound_comment','__wg_iface_comment','__wg_delete_policy_rules',
  '__wg_policy_del','__wg_disable_peer_wan_policy','__wg_inbound_policy_del'))
 policy_mocks=r"""
sqlite3(){ :; }
iptables(){
 [ "$1 $2 $3 $4" = '-w 3 -t mangle' ] || return 4
 shift 4
 case "$1" in
  -S) fail snapshot && return 1; cat "$FIXTURE/$2";;
  -D) fail delete && return 1;log "DELETE_RULE $*";;
  *) return 2;;
 esac
}
"""
 d=fresh('policy-identity')
 markers=['wg-inbound-policy:wg1','wg-inbound-policy:wg10','wg-iface-policy:wg1','wg-iface-policy:wg10',
          'wg-wan-policy:1','wg-wan-policy:10','external wg-inbound-policy:wg1','wg-inbound-policy:wg1 external','wg-wan-policy:old']
 for chain in ('PREROUTING','OUTPUT'):
  rows=[f'[fastid: {100+i}] -A {chain} -m comment --comment "{m}" -j ACCEPT' for i,m in enumerate(markers)]
  rows.append(f'-A {chain} -m comment --comment wg-iface-policy:wg1 -j RETURN')
  (d/chain).write_text('\n'.join(rows)+'\n')
 def clean(action):
  (d/'log').write_text('')
  return run(d,action,policy_functions+'\n'+policy_mocks)
 r=clean('__wg_inbound_policy_del wg1')
 expected=[]
 for chain in ('PREROUTING','OUTPUT'):
  for tag,target in [('wg-inbound-policy:wg1','ACCEPT'),('wg-iface-policy:wg1','ACCEPT'),('wg-iface-policy:wg1','RETURN')]:
   expected.append(f'DELETE_RULE -D {chain} -m comment --comment {tag} -j {target}')
 check(r.returncode==0 and lines(d)==expected,'interface cleanup retains wg10 and external comments',lines(d))
 r=clean('__wg_policy_del 1')
 check(r.returncode==0 and lines(d)==['DELETE_RULE -D OUTPUT -m comment --comment wg-wan-policy:1 -j ACCEPT'],
       'peer cleanup retains peer 10',lines(d))
 r=clean('__wg_disable_peer_wan_policy')
 check(r.returncode==0 and lines(d)==[f'DELETE_RULE -D OUTPUT -m comment --comment wg-wan-policy:{i} -j ACCEPT' for i in (1,10)],
       'startup cleanup removes only numeric per-peer marks',lines(d))
 for failure in ('snapshot','delete'):
  (d/('fail-'+failure)).touch()
  check(clean('__wg_inbound_policy_del wg1').returncode!=0,'iptables '+failure+' failure propagated')
  (d/('fail-'+failure)).unlink()

 # The center policy also owns rules in nat. Exercise repeated activation
 # and failures using the deployed script and the vendor's displayed form.
 center=Path(sys.argv[1]).with_name('wg_center_route.sh').read_text()
 center_body=center[center.index('clean_rule_chain()'):center.index('install_cron()')]
 center_mocks=r"""
TAG=wg-center-policy
WORK="$FIXTURE"
load_conf(){ :; }
load_ipset(){ :; }
ensure_table_default(){ :; }
ensure_rule(){ :; }
mark_id(){ echo 53; }
iptables(){
 [ "$1 $2 $3" = '-w 3 -t' ] || return 4
 local file="$FIXTURE/rules.$4.$6" spec
 case "$5" in
  -S) fail snapshot && return 1;cat "$file";;
  -A|-D)
   local op=$5
   shift 5
   spec="[fastid: 0] -A $*"
   spec=$(printf '%s\n' "$spec" | sed 's/--comment \([^ ]*\)/--comment "\1"/')
   if [ "$op" = -A ];then
    fail insertion && [[ $spec = *':oversea"'* ]] && return 1
    printf '%s\n' "$spec" >> "$file"
   else
    fail removal && return 1
    awk -v rule="$spec" '$0==rule&&!removed{removed=1;next}{print}END{if(!removed)exit 1}' "$file" > "$file.new" && mv "$file.new" "$file"
   fi;;
  *) return 2;;
 esac
}
ENABLE=1 CLIENT_SRC=192.0.2.0/24 CHINA_IFACE=wg1 OVERSEA_IFACE=wg10
SET_CHINA=testset ROUTE_NON_CHINA=1 NAT_ENABLE=1 NAT_SRC=192.0.2.0/24 NAT_WAN=wan1
"""
 d=fresh('center-ownership')
 mangle=d/'rules.mangle.PREROUTING';nat=d/'rules.nat.POSTROUTING'
 unrelated='[fastid: 0] -A PREROUTING -m comment --comment "wg-center-policy:china external" -j RETURN\n'
 mangle.write_text(unrelated);nat.write_text('')
 def center_run(action):
  return run(d,action,center_mocks+'\n'+center_body)
 for repeat in range(2):
  r=center_run('apply_policy')
  check(r.returncode==0 and len(mangle.read_text().splitlines())==3 and len(nat.read_text().splitlines())==1,
        'center reapply retains one of each rule',r.stderr)
 for fault in ('removal','snapshot'):
  previous=(mangle.read_text(),nat.read_text());(d/('fail-'+fault)).touch()
  for command in ('apply_policy','ENABLE=0;apply_policy'):
   r=center_run(command)
   check(r.returncode!=0 and (mangle.read_text(),nat.read_text())==previous and 'disabled' not in r.stdout,
         'center cleanup failures stop activation and disabling '+fault)
  (d/('fail-'+fault)).unlink()
 (d/'fail-insertion').touch();r=center_run('apply_policy')
 check(r.returncode!=0 and mangle.read_text()==unrelated and not nat.read_text(),
       'center partial insertion cleaned without removing another comment',r.stderr)
 (d/'fail-insertion').unlink();r=center_run('apply_policy;ENABLE=0;apply_policy')
 check(r.returncode==0 and r.stdout=='disabled\n' and mangle.read_text()==unrelated and not nat.read_text(),
       'center disable removes its mangle and nat rules',r.stderr)

 d=fresh('center-native-entry')
 saved_script=d/'wg_center_route.sh'
 saved_script.write_text(center.replace('WORK=/etc/mnt/ikuai/wg_center','WORK="$FIXTURE/center-data"')
                               .replace('TMP=/tmp/iktmp/wg_center','TMP="$FIXTURE/center-run"'))
 entry=r"""
Include(){ :; }
. "$FIXTURE/wg_center_route.sh" ""
[ ! -e "$FIXTURE/center-run" ] && [ ! -e "$FIXTURE/center-data" ] || exit 1
flock(){ [ "$*" = '-x 8' ] && log LOCK; }
install_cron(){ log CRON; }
update_ipset(){ log UPDATE;! fail input; }
apply_policy(){ log APPLY; }
clean_rules(){ log CLEAN; }
load_conf(){ ENABLE=0;log READ; }
ipset(){ :; }
"""
 for action,expected in [('boot',['LOCK','CRON','APPLY']),('update',['LOCK','UPDATE']),
                         ('update_apply',['LOCK','UPDATE','APPLY']),('apply',['LOCK','APPLY']),
                         ('clean',['LOCK','CLEAN']),('status',['READ'])]:
  (d/'log').write_text('')
  for folder in ('center-run','center-data'):
   for f in (d/folder).glob('*'):f.unlink()
   if (d/folder).is_dir():(d/folder).rmdir()
  r=run(d,'declare -F '+action+' >/dev/null && '+action,entry)
  check(r.returncode==0 and lines(d)==expected,'native center entry '+action,lines(d))
 check(not (d/'center-run').exists(),'status does not allocate a writer lock')
 (d/'fail-input').touch();(d/'log').write_text('')
 r=run(d,'update_apply',entry)
 check(r.returncode!=0 and lines(d)==['LOCK','UPDATE'],'failed IP library update never applies')
 feature_port=Path(sys.argv[1]).with_name('feature_port.sh').read_text()
 check('/usr/ikuai/script/wg_center_route.sh boot' in feature_port,'boot installs cron through native action')

 key_cases=[
  ('optional empty','',True),
  ('canonical 32 bytes',base64.b64encode(bytes(range(32))).decode(),True),
  ('canonical zero 32 bytes',base64.b64encode(bytes(32)).decode(),True),
  ('short 31 bytes',base64.b64encode(bytes(31)).decode(),False),
  ('long 33 bytes',base64.b64encode(bytes(33)).decode(),False),
  ('invalid character','KEY_SECRET_SENTINEL$'+'A'*24+'=',False),
  ('embedded newline','A'*21+'\n'+'A'*22+'=',False),
  ('noncanonical padding','A'*42+'B=',False),
  ('missing padding','A'*43,False),
  ('extra padding','A'*43+'==',False),
  ('trailing whitespace','A'*43+'= ',False),
 ]
 for name,key,valid in key_cases:
  count+=1
  r=subprocess.run(['bash','-c',functions['__check_key_valid']+'\n__check_key_valid "$1"','key-test',key],capture_output=True,text=True)
  check((r.returncode==0)==valid,'key validation '+name)
  if valid:
   check(not r.stdout and not r.stderr,'valid key produces no output '+name)
  else:
   check('WG 密钥格式错误' in r.stdout,'invalid key generic error '+name)
   check(key not in r.stdout+r.stderr,'invalid secret never echoed '+name)

 revoke_mocks=r"""
__wg_bin(){ fail nobin && return 1;echo revoke_wg; }
revoke_wg(){
 if [ "$1" = show ];then
  log READ_ENDPOINTS
  fail endpointread && return 1
  cat "$FIXTURE/endpoints";return
 fi
 if [ "$1 $3 $5" = 'set peer remove' ];then
  log "REMOVE $4"
  ! fail peerremove;return
 fi
 return 2
}
"""
 revoke_cases=[
  ('select-one',None,'FAKE_PEER_1\t192.0.2.30:45000\nFAKE_PEER_2\t192.0.2.40:46000\n',0,'FAKE_PEER_1\t192.0.2.30:45000\n',True),
  ('unlearned',None,'FAKE_PEER_1\t(none)\n',0,'FAKE_PEER_1\t(none)\n',True),
  ('absent-peer',None,'FAKE_PEER_2\t192.0.2.40:46000\n',0,'',True),
  ('read-fails','endpointread','',1,'',False),
  ('remove-fails','peerremove','FAKE_PEER_1\t192.0.2.30:45000\n',1,'',True),
  ('absent-interface','new','',0,'',False),
  ('missing-tool','nobin','',1,'',False),
 ]
 for name,failure,endpoints,code,expected,removed in revoke_cases:
  d=fresh('revoke-'+name);(d/'endpoints').write_text(endpoints)
  if failure:(d/('fail-'+failure)).touch()
  r=run(d,'__wg_revoke_peer_sessions wg1 FAKE_PEER_1',revoke_mocks)
  check((r.returncode==0)==(code==0),'peer revocation status '+name,r.stderr)
  check(r.stdout==expected,'peer revocation snapshot '+name)
  check([x for x in lines(d) if x.startswith('REMOVE ')]==(['REMOVE FAKE_PEER_1'] if removed else []),'only selected peer revoked '+name)

 edit_mocks=revoke_mocks+r"""
__check_param_add(){ :; }
__check_allowip_conflict(){ :; }
__check_key_valid(){ :; }
__wg_client_dns_for_iface(){ echo 10.100.1.1; }
sql_config_get_list(){ cat "$FIXTURE/old-peer"; }
sql_config_update(){ log SQL_UPDATE; }
NewOldVarl(){
 local field
 for field in "$@";do eval '[ "${'"$field"'-}" = "${old_'"$field"'-}" ]' || return 1;done
 return 0
}
__wg_apply_iface(){ log "APPLY $1"; }
__wg_restore_learned_endpoints(){ log "RESTORE $1 $2"; }
"""
 for name,old_psk,new_psk,revokes in [('metadata','old','old',False),('psk-set','','new',True),('psk-clear','old','',True)]:
  d=fresh('edit-'+name)
  (d/'endpoints').write_text('FAKE_PEER_1\t192.0.2.30:45000\nFAKE_PEER_2\t192.0.2.40:46000\n')
  fields={'enabled':'yes','interface':'wg1','peer_publickey':'FAKE_PEER_1','presharedkey':old_psk,'allowips':'10.100.1.2/32','endpoint':'','endpoint_port':'','keepalive':'0','out_mode':'auto','out_wans':'','out_balance':'failover','exit_peer':'no','site_local':'','site_remote':''}
  (d/'old-peer').write_text(' '.join('old_'+k+'='+v for k,v in fields.items()))
  fields.update(presharedkey=new_psk,client_dns='10.100.1.99',peer_privatekey='CLIENT_EXPORT_METADATA')
  assignments=';'.join(k+'='+v for k,v in fields.items())
  r=run(d,assignments+';id=1;__wg_locked_edit',edit_mocks)
  check(r.returncode==0,'edit rekey '+name,r.stderr)
  log=lines(d);removed=[x for x in log if x.startswith('REMOVE ')]
  if revokes:
   check(removed==['REMOVE FAKE_PEER_1'],'PSK edit revokes selected peer '+name)
   check(log.index('SQL_UPDATE')<log.index('REMOVE FAKE_PEER_1')<log.index('APPLY wg1'),'PSK edit revoke before reapply '+name)
   restores=[x for x in log if x.startswith('RESTORE ')]
   check(len(restores)==1 and 'FAKE_PEER_1' in restores[0] and 'FAKE_PEER_2' not in restores[0],'only changed peer endpoint restored '+name)
   check(log.index(restores[0])>log.index('APPLY wg1'),'endpoint restored after apply '+name)
  else:
   check(not removed and not any(x.startswith(('APPLY ','RESTORE ')) for x in log),'metadata edit does not revoke or apply')

 batch_actions=['del','down','up','iface_del','iface_down','iface_up']
 for action in batch_actions:
  d=fresh('batch-write-fails-'+action)
  (d/'ifaces').write_text('id=1 name=wg1 enabled=yes\n')
  (d/'tmp/wireguard/config/1').write_text('EXISTING_CACHE')
  (d/'fail-dbwrite').touch()
  r=run(d,'id=1;__wg_locked_'+action,'__wg_apply_iface(){ log "UNEXPECTED_APPLY"; };__exec_rule_restart_one(){ log "UNEXPECTED_RESTART"; }')
  check(r.returncode!=0,'DB write failure returned '+action)
  check('DB_WRITE' in lines(d) and not (d/'db-written').exists(),'failed DB mutation attempted '+action)
  check(not any(x.startswith(('UNEXPECTED_','IP ','POLICY_DEL ','IFACE_CACHE')) for x in lines(d)),'no runtime mutation after failed DB write '+action)
  check((d/'tmp/wireguard/config/1').read_text()=='EXISTING_CACHE','DNS cache retained on DB failure '+action)

 invalid_ids=['','1,,2','1);delete from wireguard;--',' 1','1\n2','-1']
 for action,invalid in zip(batch_actions,invalid_ids):
  d=fresh('batch-bad-id-'+action);(d/'requested-id').write_text(invalid)
  r=run(d,'id="$(cat "$FIXTURE/requested-id")";__wg_locked_'+action)
  check(r.returncode!=0,'invalid batch ID rejected '+action)
  check(not lines(d),'invalid ID no database or kernel access '+action)

 d=fresh('iface-up-explicit-write')
 (d/'ifaces').write_text('id=1 name=wg1 enabled=no\nid=2 name=wg2 enabled=no\n')
 r=run(d,'id=1,2;__wg_locked_iface_up','__exec_rule_restart_one(){ log "RESTART $1"; }')
 check(r.returncode==0,'interface up explicit write',r.stderr)
 check([x for x in lines(d) if x.startswith('RESTART ')]==['RESTART wg1','RESTART wg2'],'interface up applies all selected interfaces')
 check(lines(d).index('DB_WRITE')<lines(d).index('RESTART wg1'),'interface up writes before runtime')
 check(';' not in (d/'selection').read_text(),'interface up list helper read-only')

print(f'PASS {count} WG apply, cache, deduplication and fail-closed cases')
