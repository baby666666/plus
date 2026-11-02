#!/usr/bin/env python3
"""Probe binding and fail-closed eligibility; command fixtures only, no network."""
from pathlib import Path
import argparse
import os
import shlex
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parents[1] / 'firmware/port-3726/files/usr/ikuai/script/native_exit_health.sh'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path, default=SOURCE)
parser.add_argument('--document-pre-fix', action='store_true')
args = parser.parse_args()
checks = 0

def check(value, why):
    global checks
    assert value, why
    checks += 1

with tempfile.TemporaryDirectory(prefix='health-probe-routing-') as td:
    d = Path(td)
    source = d / 'health.sh'
    fake = d / 'strict-probe'
    fake.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$STATE/probes"\nexit 0\n')
    fake.chmod(0o755)
    source.write_text(args.source.read_text().replace('/etc/iproute2/rt_tables', str(d/'tables')).replace('/usr/sbin/strict-probe', str(fake)))
    (d/'tables').write_text('254 main\n29991 wg1\n29932 wg32\n10001 wan1\n')
    (d/'exits').write_text('1 wg1 wg1 1\n32 wg32 wg32 1\n')
    rules = ['0: from all lookup local', '141: from all uidrange 48101-48101 lookup wg1',
             '172: from all uidrange 48132-48132 lookup wg32', '180: from all uidrange 48101-48232 prohibit',
             '32766: from all lookup main']
    output = ['-P OUTPUT ACCEPT', '-A OUTPUT -j NR_OUTPUT']
    chain = ['-N NR_OUTPUT', '-A NR_OUTPUT -o lo -j RETURN',
             '-A NR_OUTPUT -m mark --mark 0x56000000 -j RETURN',
             '-A NR_OUTPUT -p udp -m udp --sport 51820 -m mark --mark 0x2711 -m owner --uid-owner 48101-48232 -m comment --comment "nr-wg-transport" -j RETURN',
             '-A NR_OUTPUT -m owner --uid-owner 48101 ! -o wg1 -j DROP',
             '-A NR_OUTPUT -m owner --uid-owner 48101 -j RETURN',
             '-A NR_OUTPUT -m owner --uid-owner 48132 ! -o wg32 -j DROP',
             '-A NR_OUTPUT -m owner --uid-owner 48132 -j RETURN',
             '-A NR_OUTPUT -m owner --uid-owner 48201 -g NR_D1',
             '-A NR_OUTPUT -m owner --uid-owner 48201-48232 -j DROP']
    def reset_guard(dev, address):
        return f'-A NR_OUTPUT -s {address}/32 ! -o {dev} -p tcp -m tcp --dport 53 --tcp-flags RST RST -m conntrack --ctstate INVALID -m comment --comment nr-wg-probe-reset -j DROP'
    resets=[reset_guard('wg1','198.19.1.1'),reset_guard('wg32','198.19.32.1')]
    chain=chain[:2]+resets+chain[2:]
    prelude = r'''
set -e -o pipefail
source "$SOURCE"
NR="$STATE"
NR_HEALTH_SNAPSHOT="$STATE"
ip(){ printf 'ip %s\n' "$*" >> "$STATE/commands";[ "$*" = 'rule show' ] || return 98;cat "$STATE/rules";[ ! -f "$STATE/fail.rules" ]; }
iptables(){
 printf 'iptables %s\n' "$*" >> "$STATE/commands"
 case "$*" in '-w -S OUTPUT') cat "$STATE/output";[ ! -f "$STATE/fail.output" ];;
 '-w -S NR_OUTPUT') cat "$STATE/chain";[ ! -f "$STATE/fail.chain" ];;
 '-w -S NR_OUT_GUARD') cat "$STATE/prefix";[ ! -f "$STATE/fail.prefix" ];;
 '-w -C NR_OUTPUT '*) grep -Fx -- "-A ${*:3}" "$STATE/chain" >/dev/null;;*) return 98;;esac
}
'''
    env = dict(os.environ, SOURCE=str(source), STATE=str(d))
    def reset(rr=None, oo=None, cc=None):
        for name, rows in [('rules', rules if rr is None else rr), ('output', output if oo is None else oo), ('chain', chain if cc is None else cc)]:
            (d/name).write_text('\n'.join(rows)+'\n')
        for path in d.glob('guard.*'): path.unlink()
        for path in d.glob('fail.*'): path.unlink()
        (d/'commands').write_text('')
        (d/'prefix').write_text('-N NR_OUT_GUARD\n')
        (d/'addresses').write_text('1: lo inet 127.0.0.1/8\n7: wg1 inet 198.19.1.1/24\n8: wg32 inet 198.19.32.1/24\n')
    def run(body):
        return subprocess.run(['bash', '-c', prelude+body], env=env, capture_output=True, text=True, timeout=5)
    def guarded(expected, label, eid=1, dev='wg1'):
        result = run(f'nr_health_guarded {eid} {dev}')
        check((result.returncode == 0) == expected, label + ': ' + result.stderr)
    reset()
    if args.document_pre_fix:
        reset(rr=[r for r in rules if not r.startswith('141:')])
        guarded(True, 'pre-fix guard accepts a probe with no positive UID route')
        result=run('nr_health_probe_one 1 wg1 203.0.113.57 tcpping '+shlex.quote(str(d/'ok')))
        check(result.returncode==0, 'pre-fix probe runs through the same helper fixture')
        check((d/'probes').read_text().strip()=='1 ikcheck tcpping 203.0.113.57 -I wg1 -c 1 -p 53 -t 1',
              'pre-fix dedicated-UID TCP probe forces socket interface binding')
        print(f'health-probe-routing pre-fix gaps: {checks} checks passed')
        raise SystemExit(0)
    guarded(True, 'complete exact route and reachable output guard permit WG probe')
    guarded(True, 'UID 48132 at pref 172 uses its own table', 32, 'wg32')
    check((d/'commands').read_text().splitlines() == ['ip rule show', 'iptables -w -S OUTPUT', 'iptables -w -S NR_OUTPUT'], 'all exits share one read-only guard inventory')
    reset(cc=[r.replace('-m owner --uid-owner 48101 ! -o wg1', '! -o wg1 -m owner --uid-owner 48101') for r in chain])
    guarded(True, 'native iptables canonical output-device-first guard is accepted')
    reset(oo=[('[fastid: 0] '+r) if r.startswith('-A ') else r for r in output],
          cc=[('[fastid: 0] '+r.replace('-m owner --uid-owner 48101 ! -o wg1', '! -o wg1 -m owner --uid-owner 48101')) if r.startswith('-A ') else r for r in chain])
    guarded(True, 'native fastid rule prefixes and canonical guard order are accepted')
    reset(cc=['[fastid: broken] '+r if r.startswith('-A ') else r for r in chain])
    guarded(False, 'malformed fastid prefix is not ignored')
    reset(rr=[r.replace('lookup wg1', 'lookup 29991') for r in rules])
    guarded(True, 'numeric table identity is equivalent')
    for label, rr in [
        ('missing positive owner route', [r for r in rules if not r.startswith('141:')]),
        ('wrong owner table', [r.replace('lookup wg1', 'lookup wan1') for r in rules]),
        ('duplicate owner routes', rules+[rules[1]]),
        ('conditional owner route', [r.replace('141: from all ', '141: from 192.0.2.0/24 ') for r in rules]),
        ('missing terminal prohibition', [r for r in rules if not r.startswith('180:')]),
        ('conditional terminal prohibition', [r.replace('180: from all ', '180: from 192.0.2.0/24 ') for r in rules]),
    ]:
        reset(rr=rr);guarded(False, label+' refuses probe')
    for label, oo in [
        ('missing OUTPUT hook', output[:1]),
        ('late OUTPUT hook', [output[0], '-A OUTPUT -j ACCEPT', output[1]]),
        ('conditional OUTPUT hook', [output[0], '-A OUTPUT -p tcp -j NR_OUTPUT']),
        ('malformed fastid OUTPUT prefix', [output[0], '[fastid: broken] -A OUTPUT -j ACCEPT', output[1]]),
        ('unrecognized OUTPUT row prefix', [output[0], 'garbage -A OUTPUT -j ACCEPT', output[1]]),
    ]:
        reset(oo=oo);guarded(False, label+' refuses probe')
    guarded_output = [output[0], '-A OUTPUT -j NR_OUT_GUARD', output[1]]
    for prefix in ['', '-A NR_OUT_GUARD ! -o lo -m owner --uid-owner 48201-48232 -j DROP\n', '-A NR_OUT_GUARD -j RETURN\n']:
        reset(oo=guarded_output);(d/'prefix').write_text('-N NR_OUT_GUARD\n'+prefix)
        guarded(True, 'empty/drop-only/return protection prefix permits later NR_OUTPUT')
        check((d/'commands').read_text().splitlines()[-1]=='iptables -w -S NR_OUT_GUARD', 'preceding guard chain receives its own actual-state read')
    for prefix in ['-A NR_OUT_GUARD -j ACCEPT\n', '-A NR_OUT_GUARD -j another_chain\n', 'malformed\n']:
        reset(oo=guarded_output);(d/'prefix').write_text('-N NR_OUT_GUARD\n'+prefix)
        guarded(False, 'unsafe or unreadable protection prefix refuses probe')
    reset(oo=[('[fastid: 0] '+r) if r.startswith('-A ') else r for r in guarded_output],
          cc=[('[fastid: 0] '+r) if r.startswith('-A ') else r for r in chain])
    (d/'prefix').write_text('-N NR_OUT_GUARD\n[fastid: 0] -A NR_OUT_GUARD -m owner --uid-owner 48201-48232 -j DROP\n')
    guarded(True, 'native prefixed transient protection is read and accepted before output guard')
    reset(oo=guarded_output);(d/'fail.prefix').touch()
    guarded(False, 'preceding guard chain read failure refuses probe')
    for label, cc in [
        ('missing output guard', [r for r in chain if not ('48101 !' in r)]),
        ('wrong output device', [r.replace('! -o wg1 ', '! -o wan1 ') for r in chain]),
        ('owner RETURN before DROP', chain[:6]+[chain[7],chain[6]]+chain[8:]),
        ('unconditional early RETURN', chain[:1]+['-A NR_OUTPUT -j RETURN']+chain[1:]),
        ('broad owner ACCEPT before guard', chain[:1]+['-A NR_OUTPUT -m owner --uid-owner 48101-48232 -j ACCEPT']+chain[1:]),
        ('negated owner bypass', chain[:1]+['-A NR_OUTPUT -m owner ! --uid-owner 0 -j RETURN']+chain[1:]),
        ('negated UDP bypass', chain[:1]+['-A NR_OUTPUT ! -p udp -j RETURN']+chain[1:]),
        ('mark mask may include probe', chain[:1]+['-A NR_OUTPUT -m mark --mark 0x55000000/0xff000000 -j RETURN']+chain[1:]),
        ('malformed chain', ['unparseable']+chain),
    ]:
        reset(cc=cc);guarded(False, label+' refuses probe')
    for label, cc in [
        ('missing reset guard', [r for r in chain if r != resets[0]]),
        ('late reset guard', [r for r in chain if r != resets[0]]+[resets[0]]),
        ('wrong reset port', [r.replace('--dport 53', '--dport 54') if r==resets[0] else r for r in chain]),
        ('wrong reset state', [r.replace('--ctstate INVALID', '--ctstate ESTABLISHED') if r==resets[0] else r for r in chain]),
        ('wrong reset device', [r.replace('! -o wg1 ', '! -o wg2 ') if r==resets[0] else r for r in chain]),
        ('wrong reset source', [r.replace('198.19.1.1/32', '198.19.1.2/32') if r==resets[0] else r for r in chain]),
        ('widened reset subnet', [r.replace('198.19.1.1/32', '198.19.1.0/24') if r==resets[0] else r for r in chain]),
    ]:
        reset(cc=cc);guarded(False,label+' refuses probe')
    reset();(d/'addresses').unlink();guarded(False,'missing address inventory refuses probe')
    reset();(d/'addresses').write_text('7: wg1 inet malformed/24\n');guarded(False,'malformed current WG address refuses probe')
    reset();(d/'addresses').write_text('7: wg1 inet 198.19.1.1/24\n7: wg1 inet 198.19.1.2/24\n')
    guarded(False,'all current WG IPv4 addresses require reset guards')
    reset(cc=chain[:2]+[reset_guard('wg1','198.19.1.2')]+chain[2:])
    (d/'addresses').write_text('7: wg1 inet 198.19.1.1/24\n7: wg1 inet 198.19.1.2/24\n')
    guarded(True,'multiple protected IPv4 addresses permit probe')
    for part in ['rules', 'output', 'chain']:
        reset();(d/('fail.'+part)).touch()
        guarded(False, part+' read failure refuses probe despite partial stdout')
        count=len((d/'commands').read_text().splitlines())
        guarded(False, part+' read failure is retained for current cycle', 32, 'wg32')
        check(len((d/'commands').read_text().splitlines())==count, part+' failure is not re-read per exit')
    reset();guarded(True, 'fresh invocation does not retain prior read failure')
    guarded(False, 'mismatched caller device rejected', 1, 'wg32')
    guarded(False, 'out-of-range probe UID rejected', 101, 'wg1')
    for dev in ['wg1', 'wan1']:
        for kind in ['ping', 'tcpping']:
            result=run('nr_health_probe_one 1 '+shlex.quote(dev)+' 203.0.113.57 '+kind+' '+shlex.quote(str(d/'ok')))
            check(result.returncode==0, f'{dev} {kind} probe runs')
            command=(d/'probes').read_text().splitlines()[-1]
            check(command.startswith('1 ikcheck '+kind+' 203.0.113.57 '), 'dedicated UID helper and target preserved')
            check(('-I '+dev in command) == (dev=='wan1'), f'{dev} binding treatment for {kind}')
    check(not any('-I wg' in row for row in (d/'probes').read_text().splitlines()), 'no WG probe uses forced socket interface binding')

    # Exercise the actual sampler with actual guards. Network results are the
    # only probe fixture; all eligibility, batching, cache and publication logic
    # remains real. No guard or route command may mutate kernel state.
    (d/'tables').write_text('254 main\n'+''.join(f'{29900+i} wg{i}\n' for i in range(1,33)))
    (d/'exits').write_text(''.join(f'{i} wg{i} wg{i} 1\n' for i in range(1,33)))
    (d/'policies').write_text('1 '+','.join(map(str,range(1,33)))+' 6 0\n')
    (d/'policy-workers').write_text('1 1 203.0.113.57\n')
    many_rules=['0: from all lookup local']+[f'{140+i}: from all uidrange {48100+i}-{48100+i} lookup wg{i}' for i in range(1,33)]+[rules[3],'32766: from all lookup main']
    many_chain=chain[:2]+[reset_guard(f'wg{i}',f'198.19.{i}.1') for i in range(1,33)]+chain[4:6]+[row for i in range(1,33) for row in [f'-A NR_OUTPUT ! -o wg{i} -m owner --uid-owner {48100+i} -j DROP',f'-A NR_OUTPUT -m owner --uid-owner {48100+i} -j RETURN']]
    reset(rr=many_rules,cc=many_chain)
    sampler=r'''
nr_health_now(){ cat "$STATE/now"; }
nr_health_inventory(){ local i;printf '1: lo inet 127.0.0.1/8\n' > "$1/addresses";for ((i=1;i<=32;i++));do printf '%s: wg%s inet 198.19.%s.1/24\n' "$((i+1))" "$i" "$i" >> "$1/addresses";done; }
nr_health_signature(){ printf 'identity-%s\n' "$1"; }
nr_health_device(){ return 0; }
nr_health_probe(){ printf '%s\n' "$1" >> "$STATE/sampled";echo 1 > "$4"; }
ik_cntl(){ return 0; }
nr_exit_health_sync
'''
    for cycle in range(8):
        (d/'now').write_text(str(100+cycle*3))
        result=run(sampler)
        check(result.returncode==0, 'actual guarded sampler cycle succeeds: '+result.stderr)
        check(len((d/'sampled').read_text().splitlines())==4*(cycle+1), 'actual guarded sampler retains four-exit bound')
    samples=(d/'sampled').read_text().splitlines()
    check(len(set(samples))==32, 'actual guards do not starve any of 32 exits')
    check(all(row.split()[1:]==['1','1'] for row in (d/'exit-health').read_text().splitlines()), 'all 32 guarded successful probes publish known healthy')
    check((d/'commands').read_text().splitlines()==['ip rule show','iptables -w -S OUTPUT','iptables -w -S NR_OUTPUT']*8,
          'eight actual sampler cycles use exactly eight guard inventories, all read-only')
    check(not list(d.glob('.health.*')), 'guard snapshots are removed with each sampler invocation')
    (d/'policies').write_text('1 32 6 0\n');(d/'now').write_text('122');(d/'commands').write_text('')
    check(run(sampler).returncode==0 and not (d/'commands').read_text(), 'fresh cached single-exit cycle performs no guard inventory or network probe')
    (d/'policies').write_text('1 '+','.join(map(str,range(1,33)))+' 6 0\n')
    (d/'now').write_text('200');(d/'sampled').write_text('')
    reset(rr=[r for r in many_rules if 'uidrange' not in r or r.startswith('172:') or r.startswith('180:')],cc=many_chain)
    check(run(sampler).returncode==0, 'missing owner routes complete without launching unsafe probes')
    check((d/'sampled').read_text().splitlines()==['32'], '31 rejected guards do not consume the last valid exit probe slot')
    check(all(row.split()[1:]==(['1','1'] if row.split()[0]=='32' else ['0','0']) for row in (d/'exit-health').read_text().splitlines()),
          'missing guard invalidates expired healthy cache to unknown without false healthy publication')
    (d/'now').write_text('220');(d/'sampled').write_text('');reset(rr=many_rules,cc=many_chain);(d/'fail.chain').touch()
    check(run(sampler).returncode==0 and not (d/'sampled').read_text(), 'partial firewall read failure sends no probes')
    check(all(row.split()[1:]==['0','0'] for row in (d/'exit-health').read_text().splitlines()), 'failed guard inventory publishes every due WG as unknown')
    check((d/'commands').read_text().splitlines()==['ip rule show','iptables -w -S OUTPUT','iptables -w -S NR_OUTPUT'],
          'failed inventory is not retried 32 times in the same health call')
print(f'health-probe-routing: {checks} checks passed')
