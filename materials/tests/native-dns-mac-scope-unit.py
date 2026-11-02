#!/usr/bin/env python3
"""Compile the real DNS category/choose functions with deterministic ARP/time.

Only OS evidence is stubbed. No router, network or live ARP table is accessed.
The full dispatcher binary and kernel integration require separate VM tests.
"""
from pathlib import Path
import argparse
import json
import os
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--source', type=Path, default=ROOT / 'materials/native-src/nr_dns.c')
args = parser.parse_args()
source = args.source.read_text()
policy = (ROOT / 'materials/native-src/dns_policy.h').read_text()
structs = source[source.index('struct range {'):source.index('#include "dns_policy.h"')]
structs += policy[policy.index('struct global_index {'):policy.index('static struct policy *live;')]
cmp = re.search(r'static int cmp\([^\n]+', policy).group(0)
functions = source[source.index('static int category('):source.index('static size_t attr(')]
harness = r'''
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#define MAXRULE 256
''' + structs + '\n' + cmp + r'''
static const char *arp_text;
static int arp_reads, checked;
static FILE *mock_fopen(const char *path,const char *mode){
 (void)mode;if(strcmp(path,"/proc/net/arp")){fprintf(stderr,"unexpected file\n");exit(2);}
 arp_reads++;if(!arp_text)return NULL;
 FILE *f=tmpfile();if(!f)abort();fputs(arp_text,f);rewind(f);return f;
}
static time_t mock_time(time_t *p){if(p)*p=0;return 0;}
static struct tm *mock_localtime(const time_t *p,struct tm *t){
 (void)p;memset(t,0,sizeof(*t));t->tm_wday=1;t->tm_hour=10;return t;
}
#define fopen mock_fopen
#define time mock_time
#define localtime_r mock_localtime
''' + functions + r'''
#undef fopen
#undef time
#undef localtime_r
static struct policy p;
static struct global_index g;
static struct range all={0,UINT32_MAX},phone={0xc6120102,0xc6120102};
static char *manual[]={"lan.example"},*exact[]={"exact.example"},*exclude[]={"skip.lan.example"};
static char *mac[]={"aa:bb:cc:dd:ee:ff"},*cn[]={"cn.example"},*foreign[]={"foreign.example"};
static char *cn_exact[]={"only-cn.example"},*foreign_exact[]={"only-foreign.example"};
static struct word overrides[]={{"override.example",2}};
static void reset(void){
 memset(&p,0,sizeof(p));memset(&g,0,sizeof(g));p.nr=2;p.global=&g;
 g.cn=cn;g.ncn=1;g.foreign=foreign;g.nforeign=1;g.cn_exact=cn_exact;g.ncn_exact=1;
 g.foreign_exact=foreign_exact;g.nforeign_exact=1;g.words=overrides;g.nw=1;
 p.rules[0].domains=manual;p.rules[0].nd=1;p.rules[0].macs=mac;p.rules[0].nm=1;
 p.rules[1].group=4;p.rules[1].ranges=&all;p.rules[1].nr=1;
 for(int i=0;i<2;i++)memset(p.rules[i].active,1,sizeof(p.rules[i].active));
 arp_text=NULL;arp_reads=0;
}
static void check(const char *label,const char *name,const char *ingress,int expected,int reads){
 int got=choose(&p,name,phone.a,ingress);
 if(got!=expected||arp_reads!=reads){fprintf(stderr,"%s: choose=%d expected=%d arp=%d expected=%d\n",label,got,expected,arp_reads,reads);exit(1);}checked++;
}
int main(void){
 reset();check("unrelated MAC manual rule", "other.example","wg1",1,0);
 reset();check("applicable unknown MAC fails closed","cdn.lan.example","wg1",-2,1);
 reset();p.rules[0].exclude=exclude;p.rules[0].nx=1;
 check("suffix exclusion skips MAC","cdn.skip.lan.example","wg1",1,0);
 reset();p.rules[0].exclude_exact=manual;p.rules[0].ny=1;
 check("exact exclusion skips MAC","lan.example","wg1",1,0);
 reset();p.rules[0].domains=NULL;p.rules[0].nd=0;p.rules[0].exact=exact;p.rules[0].ne=1;
 check("exact does not widen to subdomain","sub.exact.example","wg1",1,0);
 reset();p.rules[0].exact=exact;p.rules[0].ne=1;
 check("applicable exact unknown MAC fails closed","exact.example","wg1",-2,1);
 reset();p.rules[0].group=3;check("group 3 unrelated skips MAC","other.example","wg1",1,0);
 reset();p.rules[0].group=1;check("regional mismatch skips MAC","cdn.foreign.example","wg1",1,0);
 reset();p.rules[0].group=2;check("regional exact mismatch skips MAC","only-cn.example","wg1",1,0);
 reset();p.rules[0].group=1;check("uncategorized skips MAC","unknown.example","wg1",1,0);
 reset();p.rules[0].group=1;check("regional applicable unknown MAC fails closed","cdn.cn.example","wg1",-2,1);
 reset();p.rules[0].group=1;check("regional manual override mismatch skips MAC","override.example","wg1",1,0);
 reset();p.rules[0].group=2;check("regional manual override requires MAC","override.example","wg1",-2,1);
 reset();p.rules[0].ranges=&phone;p.rules[0].nr=1;
 check("IP OR MAC match needs no ARP","lan.example","wg1",0,0);
 reset();arp_text="198.18.1.2 0x1 0x2 aa:bb:cc:dd:ee:ff * lan1\n";
 check("learned matching MAC selects rule","lan.example","lan1",0,1);
 reset();arp_text="198.18.1.2 0x1 0x2 00:11:22:33:44:55 * lan1\n";
 check("learned nonmatching MAC falls through","lan.example","lan1",1,1);
 reset();strcpy(p.rules[0].ingress,"lan1");check("irrelevant ingress skips MAC","lan.example","wg1",1,0);
 reset();strcpy(p.rules[0].ingress,"wg1");p.rules[0].ranges=&phone;p.rules[0].nr=1;
 check("pppwg normalization preserved","lan.example","pppwg1",0,0);
 reset();memset(p.rules[0].active,0,sizeof(p.rules[0].active));
 check("inactive rule skips MAC","lan.example","wg1",1,0);
 reset();p.rules[0].group=4;check("applicable fallback unknown MAC fails closed","other.example","wg1",-2,1);
 reset();p.rules[0].group=4;p.rules[1].group=0;p.rules[1].domains=manual;p.rules[1].nd=1;
 check("explicit rule still precedes fallback","lan.example","wg1",1,0);
 reset();p.nr=1;check("no applicable rule returns default","other.example","wg1",-1,0);
 /* Incomplete ARP rows are not evidence of a different MAC. Only a
  * complete unicast neighbour on the actual ingress permits fall-through. */
 reset();arp_text="198.18.1.2 0x1 0x0 00:00:00:00:00:00 * lan1\n";
 check("incomplete zero ARP fails closed","lan.example","lan1",-2,1);
 reset();arp_text="198.18.1.2 0x1 0x0 aa:bb:cc:dd:ee:ff * lan1\n";
 check("incomplete cached MAC fails closed","lan.example","lan1",-2,1);
 reset();arp_text="198.18.1.2 0x1 0x4 aa:bb:cc:dd:ee:ff * lan1\n";
 check("permanent flag without complete is unknown","lan.example","lan1",-2,1);
 reset();arp_text="198.18.1.2 0x1 0x6 aa:bb:cc:dd:ee:ff * lan1\n";
 check("complete permanent neighbour accepted","lan.example","lan1",0,1);
 reset();arp_text="198.18.1.2 0x1 0x2 00:00:00:00:00:00 * lan1\n";
 check("complete zero MAC remains unknown","lan.example","lan1",-2,1);
 reset();arp_text="198.18.1.2 0x1 0x2 ff:ff:ff:ff:ff:ff * lan1\n";
 check("broadcast MAC is not source evidence","lan.example","lan1",-2,1);
 reset();arp_text="198.18.1.2 0x1 0x2 01:00:5e:00:00:01 * lan1\n";
 check("multicast MAC is not source evidence","lan.example","lan1",-2,1);
 reset();arp_text="198.18.1.2 0x1 0x2 aa:bb:cc:dd:ee * lan1\n";
 check("short MAC is not source evidence","lan.example","lan1",-2,1);
 reset();arp_text="198.18.1.2 0x1 0x2 gg:bb:cc:dd:ee:ff * lan1\n";
 check("nonhex MAC is not source evidence","lan.example","lan1",-2,1);
 reset();arp_text="198.18.1.2 0x1 invalid aa:bb:cc:dd:ee:ff * lan1\n";
 check("invalid ARP flags fail closed","lan.example","lan1",-2,1);
 reset();arp_text="198.18.1.2 0x1 0x2 AA:BB:CC:DD:EE:FF * lan1\n";
 check("complete uppercase MAC accepted","lan.example","lan1",0,1);
 reset();arp_text="198.18.1.2 0x1 0x2 aa:bb:cc:dd:ee:ff * lan2\n";
 check("other ingress MAC is not source evidence","lan.example","lan1",-2,1);
 reset();arp_text="198.18.1.3 0x1 0x2 aa:bb:cc:dd:ee:ff * lan1\n";
 check("other client MAC is not source evidence","lan.example","lan1",-2,1);
 reset();arp_text="198.18.1.2 0x1 0x2 aa:bb:cc:dd:ee:ff * lan2\n198.18.1.2 0x1 0x2 aa:bb:cc:dd:ee:ff * lan1\n";
 check("skip wrong ingress before usable neighbour","lan.example","lan1",0,1);
 reset();arp_text="198.18.1.2 0x1 0x0 00:00:00:00:00:00 * lan1\n198.18.1.2 0x1 0x2 aa:bb:cc:dd:ee:ff * lan1\n";
 check("skip incomplete row before usable neighbour","lan.example","lan1",0,1);
 reset();arp_text="IP address HW type Flags HW address Mask Device\n";
 check("header without neighbour fails closed","lan.example","lan1",-2,1);
 reset();p.rules[0].ranges=&phone;p.rules[0].nr=1;arp_text="198.18.1.2 0x1 0x0 00:00:00:00:00:00 * lan1\n";
 check("matching IP bypasses unusable ARP","lan.example","lan1",0,0);
 reset();arp_text="198.18.1.2 0x1 0x0 00:00:00:00:00:00 * lan1\n";
 check("unrelated domain still skips incomplete ARP","other.example","lan1",1,0);
 reset();struct range other={phone.a+1,phone.a+1};p.rules[0].ranges=&other;p.rules[0].nr=1;
 arp_text="198.18.1.2 0x1 0x2 aa:bb:cc:dd:ee:ff * lan1\n";
 check("nonmatching IP permits matching MAC OR branch","lan.example","lan1",0,1);
 reset();arp_text="198.18.1.2 0x1 0x2 aa:bb:cc:dd:ee:ff * lan2\n198.18.1.2 0x1 0x2 00:11:22:33:44:55 * lan1\n";
 check("known nonmatching ingress MAC still falls through","lan.example","lan1",1,1);
 reset();arp_text="198.18.1.2 malformed\n";
 check("truncated matching neighbour fails closed","lan.example","lan1",-2,1);
 printf("{\"checks\":%d,\"status\":\"passed\"}\n",checked);return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='dns-mac-scope-') as directory:
    path = Path(directory)
    (path / 'scope.c').write_text(harness)
    subprocess.run([*shlex.split(os.environ.get('CC', 'cc')), '-std=c11', '-O2', '-Wall', '-Wextra',
                    str(path / 'scope.c'), '-o', str(path / 'scope')], check=True)
    result = subprocess.check_output([str(path / 'scope')], text=True)
    print(json.dumps({'suite': 'native DNS MAC scope', **json.loads(result)}))
