/* Native rule DNS dispatcher: source/time aware; one asynchronous event loop.
 * Replies are released only after tuple ipset updates are acknowledged. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <sys/un.h>
#include <sys/stat.h>
#define MAXRULE 256
#define MAXQ 512
#define MAXBIND 129
#define SZ 65536
struct range {uint32_t a,b;};
struct rule {char ingress[IFNAMSIZ];int id,port,group,nr,nd,nm,ne,nx,ny;char **macs; unsigned char active[10080];struct range *ranges;char **domains,**exact,**exclude,**exclude_exact;};

struct word {char *s;int group;};
#include "dns_policy.h"
struct dns_client_budget;
struct query {struct dns_client_budget *budget;char name[254];char ingress[IFNAMSIZ];int in,out,state,rule,replyfd;uint32_t src;struct sockaddr_in peer;socklen_t plen;size_t have,want,sent;time_t start;unsigned char *buf,*request;size_t request_size;uint16_t txid;};
struct query qs[MAXQ];int nl;unsigned seq;
static unsigned long long admission_drops;
static time_t monotime(void);
#include "dns_limits.h"
struct binding {int udp,tcp;char ingress[IFNAMSIZ];};
static struct binding bindings[MAXBIND];static int nb;
static void fatal(const char *s){perror(s);exit(1);}
static int category(const struct policy *policy,const char *q){const char *manual=q;while(manual){int lo=0,hi=policy->global->nw;while(lo<hi){int mid=lo+(hi-lo)/2,c=strcmp(manual,policy->global->words[mid].s);if(!c)return policy->global->words[mid].group;if(c<0)hi=mid;else lo=mid+1;}manual=strchr(manual,'.');if(manual)manual++;}if(bsearch(&q,policy->global->cn_exact,policy->global->ncn_exact,sizeof(char*),cmp))return 1;if(bsearch(&q,policy->global->foreign_exact,policy->global->nforeign_exact,sizeof(char*),cmp))return 2;const char *p=q;while(p){if(bsearch(&p,policy->global->foreign,policy->global->nforeign,sizeof(char*),cmp))return 2;if(bsearch(&p,policy->global->cn,policy->global->ncn,sizeof(char*),cmp))return 1;p=strchr(p,'.');if(p)p++;}return 0;}
/* A neighbour row is usable source evidence only after address resolution.
 * Reject zero/group addresses even if a damaged row carries ATF_COM. */
static int source_mac_valid(const char *mac){
 unsigned byte[6];char tail;
 if(strlen(mac)!=17||strspn(mac,"0123456789abcdefABCDEF:")!=17||
    sscanf(mac,"%2x:%2x:%2x:%2x:%2x:%2x%c",byte,byte+1,byte+2,byte+3,byte+4,byte+5,&tail)!=6)return 0;
 return !(byte[0]&1)&&(byte[0]|byte[1]|byte[2]|byte[3]|byte[4]|byte[5]);
}
static int choose(const struct policy *policy,const char *name,uint32_t src,const char *ingress){
 char logical[IFNAMSIZ];const char *number=NULL;
 if(!strncmp(ingress,"pppwg",5))number=ingress+5;
 else if(!strncmp(ingress,"ppphy",5))number=ingress+5;
 if(number&&*number&&strspn(number,"0123456789")==strlen(number)){
  snprintf(logical,sizeof(logical),"wg%s",number);ingress=logical;
 }
 time_t now=time(NULL);struct tm t;localtime_r(&now,&t);
 int m=((t.tm_wday+6)%7)*1440+t.tm_hour*60+t.tm_min,g=-1;
 for(int pass=0;pass<2;pass++)for(int i=0;i<policy->nr;i++){
  const struct rule *r=&policy->rules[i];
  if((r->group==4?1:0)!=pass||!r->active[m]||(r->ingress[0]&&strcmp(r->ingress,ingress)))continue;
  /* Only an applicable domain rule may require source-MAC evidence. Routed
   * clients (including WG) have no ARP entry; an unrelated LAN MAC rule must
   * not turn their other DNS queries into SERVFAIL. Applicable unknown MACs
   * still fail closed rather than silently selecting a lower-priority exit. */
  if(r->group==0||r->group==3){
   const char *p=name;int found=0,blocked=0;
   if(bsearch(&p,r->exact,r->ne,sizeof(char*),cmp))found=1;
   if(bsearch(&p,r->exclude_exact,r->ny,sizeof(char*),cmp))blocked=1;
   while(p){if(bsearch(&p,r->domains,r->nd,sizeof(char*),cmp))found=1;if(bsearch(&p,r->exclude,r->nx,sizeof(char*),cmp))blocked=1;p=strchr(p,'.');if(p)p++;}
   if(!found||blocked)continue;
  }else if(r->group!=4){if(g<0)g=category(policy,name);if(g!=r->group)continue;}
  int yes=0;
  for(int j=0;j<r->nr;j++)if(src>=r->ranges[j].a&&src<=r->ranges[j].b){yes=1;break;}
  if(!yes&&r->nm){
   int learned=0;unsigned flags;char ip[32],mac[32],dev[32],wanted[32],line[256];uint32_t n=htonl(src);
   inet_ntop(AF_INET,&n,wanted,sizeof(wanted));FILE *arp=fopen("/proc/net/arp","r");
   if(arp){while(fgets(line,sizeof(line),arp)){
    if(sscanf(line,"%31s %*s %x %31s %*s %31s",ip,&flags,mac,dev)==4&&!strcmp(ip,wanted)&&(!ingress[0]||!strcmp(dev,ingress))){
     if(!(flags&ATF_COM)||!source_mac_valid(mac))continue;
     learned=1;for(int k=0;k<r->nm;k++)if(!strcasecmp(mac,r->macs[k]))yes=1;break;
    }
   }fclose(arp);}
   if(!learned)return -2;
  }
  if(yes)return i;
 }
 return -1;
}
static size_t attr(unsigned char *b,size_t pos,int type,const void *v,size_t n){struct nlattr *a=(void*)(b+pos);a->nla_type=type;a->nla_len=sizeof(*a)+n;if(n)memcpy(a+1,v,n);return pos+NLA_ALIGN(a->nla_len);}
static int addset(const char *prefix,int id,uint32_t dst,uint32_t src,unsigned seconds){unsigned char b[512]={0},reply[512];struct nlmsghdr *h=(void*)b;h->nlmsg_type=(NFNL_SUBSYS_IPSET<<8)|IPSET_CMD_ADD;h->nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK;h->nlmsg_seq=++seq;struct nfgenmsg *g=NLMSG_DATA(h);g->nfgen_family=AF_INET;size_t p=NLMSG_LENGTH(sizeof(*g));unsigned char ver=IPSET_PROTOCOL;char name[32];snprintf(name,sizeof(name),"%s%d",prefix,id);p=attr(b,p,IPSET_ATTR_PROTOCOL,&ver,1);p=attr(b,p,IPSET_ATTR_SETNAME,name,strlen(name)+1);size_t nest=p;p=attr(b,p,IPSET_ATTR_DATA|NLA_F_NESTED,NULL,0);size_t a=p;p=attr(b,p,IPSET_ATTR_IP|NLA_F_NESTED,NULL,0);p=attr(b,p,IPSET_ATTR_IPADDR_IPV4|NLA_F_NET_BYTEORDER,&dst,4);((struct nlattr*)(b+a))->nla_len=p-a;a=p;p=attr(b,p,IPSET_ATTR_IP2|NLA_F_NESTED,NULL,0);src=htonl(src);p=attr(b,p,IPSET_ATTR_IPADDR_IPV4|NLA_F_NET_BYTEORDER,&src,4);((struct nlattr*)(b+a))->nla_len=p-a;unsigned char cidr=32;p=attr(b,p,IPSET_ATTR_CIDR,&cidr,1);p=attr(b,p,IPSET_ATTR_CIDR2,&cidr,1);uint32_t timeout=htonl(seconds);p=attr(b,p,IPSET_ATTR_TIMEOUT|NLA_F_NET_BYTEORDER,&timeout,4);((struct nlattr*)(b+nest))->nla_len=p-nest;h->nlmsg_len=p;struct sockaddr_nl sa={.nl_family=AF_NETLINK};if(sendto(nl,b,p,0,(void*)&sa,sizeof(sa))<0)return -1;for(int i=0;i<4;i++){ssize_t n=recv(nl,reply,sizeof(reply),0);if(n<(ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr)))return -1;struct nlmsghdr *x=(void*)reply;if(x->nlmsg_seq!=seq)continue;struct nlmsgerr *e=NLMSG_DATA(x);return e->error==0||e->error==-IPSET_ERR_EXIST?0:-1;}return -1;}
static uint16_t u16(const unsigned char *p){return ((unsigned)p[0]<<8)|p[1];}
static int skip(const unsigned char *b,size_t n,size_t *p){int labels=0;while(*p<n&&labels++<128){unsigned v=b[(*p)++];if(!v)return 0;if((v&192)==192){if(*p>=n)return -1;(*p)++;return 0;}if(v>63||*p+v>n)return -1;*p+=v;}return -1;}
static int question(const unsigned char *b,size_t n,char *name){if(n<17||u16(b+4)!=1||(b[2]&0xf8))return -1;size_t p=12,o=0;while(p<n){unsigned v=b[p++];if(!v){if(p+4>n)return -1;name[o?o-1:0]=0;return o?0:-1;}if(v>63||p+v>n||o+v+1>253)return -1;for(unsigned i=0;i<v;i++){unsigned c=b[p++];if(c>='A'&&c<='Z')c+=32;if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_'))return -1;name[o++]=c;}name[o++]='.';}return -1;}

/* Bounded, RAM-only history of names which may have installed address evidence.
 * No client addresses or payloads are retained. Overflow/missing history makes
 * reuse conservative for a full evidence lifetime, never silently incomplete. */
#define HISTORY_SIZE 65536
struct seen { char name[254]; int id; time_t until; };
static struct seen history[HISTORY_SIZE];
static time_t history_incomplete;
static volatile sig_atomic_t terminate;
static const char *history_path;
static time_t monotime(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec;}
static void ending(int sig){(void)sig;terminate=1;}
static unsigned namehash(int id,const char *name){unsigned h=2166136261u^(unsigned)id;for(;*name;name++)h=(h^(unsigned char)*name)*16777619u;return h;}
static void remember_until(int id,const char *name,time_t until){
 time_t now=monotime();unsigned start=namehash(id,name)%HISTORY_SIZE;int vacant=-1;
 for(unsigned k=0;k<HISTORY_SIZE;k++){
  unsigned i=(start+k)%HISTORY_SIZE;struct seen *e=&history[i];
  if(e->id==id&&!strcmp(e->name,name)){if(until>e->until)e->until=until;return;}
  if(e->until<=now&&vacant<0)vacant=i;
  if(!e->id)break;
 }
 if(vacant<0){if(until>history_incomplete)history_incomplete=until;return;}
 struct seen *e=&history[vacant];e->id=id;e->until=until;snprintf(e->name,sizeof(e->name),"%s",name);
}
static void history_load(void){
 time_t now=monotime();history_incomplete=now+721;
 if(getenv("NR_EVIDENCE_EMPTY")){history_incomplete=0;unlink(history_path);return;}
 FILE *f=fopen(history_path,"r");if(!f)return;
 char line[320],name[254],tail;long incomplete;int ok=fgets(line,sizeof(line),f)&&sscanf(line,"V1 %ld %c",&incomplete,&tail)==1;
 if(ok){history_incomplete=incomplete;while(fgets(line,sizeof(line),f)){
  int id;long until;if(sscanf(line,"%d %ld %253s %c",&id,&until,name,&tail)!=3||id<1||id>999999||until>now+721){ok=0;break;}
  if(until>now)remember_until(id,name,until);
 }}
 if(ferror(f))ok=0;fclose(f);unlink(history_path);
 if(!ok)history_incomplete=now+721;
}
static void history_save(void){
 char temp[512];snprintf(temp,sizeof(temp),"%s.new",history_path);FILE *f=fopen(temp,"w");if(!f)return;
 int bad=fprintf(f,"V1 %ld\n",(long)history_incomplete)<0;time_t now=monotime();
 for(int i=0;i<HISTORY_SIZE;i++)if(history[i].until>now&&fprintf(f,"%d %ld %s\n",history[i].id,(long)history[i].until,history[i].name)<0)bad=1;
 if(fclose(f))bad=1;if(!bad)rename(temp,history_path);else unlink(temp);
}
#include "dns_evidence.h"
static int answer(struct query *q,unsigned char *b,size_t n){if(n<12||u16(b)!=q->txid||!(b[2]&128))return -1;if(q->rule<0)return 0;remember_until(live->rules[q->rule].id,q->name,monotime()+721);size_t p=12;unsigned counts=u16(b+6)+u16(b+8)+u16(b+10);for(int i=0;i<u16(b+4);i++){if(skip(b,n,&p)||p+4>n)return -1;p+=4;}for(unsigned i=0;i<counts;i++){if(skip(b,n,&p)||p+10>n)return -1;unsigned type=u16(b+p),cl=u16(b+p+2),len=u16(b+p+8);if(p+10+len>n)return -1;/* advertise at most sixty seconds; never extend a shorter TTL */
if(type!=41){uint32_t ttl;memcpy(&ttl,b+p+4,4);if(ntohl(ttl)>60){ttl=htonl(60);memcpy(b+p+4,&ttl,4);}}if(type==1&&cl==1&&len==4){uint32_t ip;memcpy(&ip,b+p+10,4);/* Native address cache retains advertised TTL + 600 s. Keep conflict
 * evidence longer than its maximum (60 + 600), scoped to this client. */
if(install_evidence(live->rules[q->rule].id,ip,q->src))return -1;}p+=10+len;}return 0;}
static void closeq(struct query *q){if(q->budget&&q->budget->active)q->budget->active--;if(q->in>=0)close(q->in);if(q->out>=0)close(q->out);free(q->buf);free(q->request);memset(q,0,sizeof(*q));q->in=q->out=-1;}
static struct query *newq(uint32_t src){
 struct query *slot=NULL;
 for(int i=0;i<MAXQ;i++)if(!qs[i].state){slot=&qs[i];break;}
 if(!slot)dns_global_drops++;
 struct dns_client_budget *budget=slot?dns_admit(src,monotime()):NULL;
 if(!budget){admission_drops++;return NULL;}
 slot->buf=malloc(SZ+2);if(!slot->buf)return NULL;
 slot->budget=budget;budget->active++;
 slot->src=src;slot->in=slot->out=-1;slot->start=monotime();return slot;
}
static void failed(struct query *q){
 /* A failed write cannot be repaired by writing another error forever.
  * Only a complete, validated original question can be reflected back. */
 if(q->state==5||!q->request){closeq(q);return;}
 size_t off=q->in>=0?2:0;
 if(q->request_size<off+12){closeq(q);return;}
 size_t n=q->request_size-off;unsigned char *b=q->buf+off;
 memcpy(q->buf,q->request,q->request_size);
 b[2]=(b[2]&1)|0x80;b[3]=0x82;memset(b+6,0,6);
 size_t p=12;if(skip(b,n,&p)||p+4>n){closeq(q);return;}n=p+4;
 if(q->in<0){sendto(q->replyfd,b,n,0,(void*)&q->peer,q->plen);closeq(q);}
 else{q->buf[0]=n>>8;q->buf[1]=n;q->have=q->want=n+2;q->sent=0;q->state=5;}
}
static int paused;
static void dispatch(struct query *q){if(paused){q->state=6;return;}unsigned char *b=q->buf+(q->in>=0?2:0);size_t n=q->have-(q->in>=0?2:0);char name[254];if(question(b,n,name)){failed(q);return;}snprintf(q->name,sizeof(q->name),"%s",name);q->txid=u16(b);q->rule=choose(live,name,q->src,q->ingress);if(!q->request){q->request=malloc(q->have);if(!q->request){failed(q);return;}memcpy(q->request,q->buf,q->have);q->request_size=q->have;}if(getenv("NR_DEBUG"))fprintf(stderr,"query %s src=%u rule=%d\n",name,q->src,q->rule);int port=q->rule==-1?6199:q->rule==-2?0:live->rules[q->rule].port;if(!port){failed(q);return;}q->out=socket(AF_INET,(q->in<0?SOCK_DGRAM:SOCK_STREAM)|SOCK_NONBLOCK,0);if(q->out<0){failed(q);return;}struct sockaddr_in sa={.sin_family=AF_INET,.sin_port=htons(port),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};if(connect(q->out,(void*)&sa,sizeof(sa))<0&&errno!=EINPROGRESS){failed(q);return;}q->sent=0;q->want=q->have;q->state=2;}
static int bound(int type,int port,uint32_t address){int fd=socket(AF_INET,type|SOCK_NONBLOCK,0);if(fd<0)fatal("socket");int on=1;setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on));struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(port),.sin_addr.s_addr=address};if(bind(fd,(void*)&a,sizeof(a)))fatal("bind");return fd;}
static void add_binding(uint32_t address,int port,const char *ingress){
 if(nb>=MAXBIND){errno=E2BIG;fatal("DNS binding limit");}
 struct binding *b=&bindings[nb++];b->udp=bound(SOCK_DGRAM,port,address);b->tcp=bound(SOCK_STREAM,port,address);
 snprintf(b->ingress,sizeof(b->ingress),"%s",ingress);int on=1;setsockopt(b->udp,IPPROTO_IP,IP_PKTINFO,&on,sizeof(on));if(listen(b->tcp,128))fatal("listen");
}
static void load_bindings(const char *path){
 const char *portenv=getenv("NR_DNS_PORT");int port=portenv?atoi(portenv):6153;if(port<1||port>65535){errno=EINVAL;fatal("DNS port");}add_binding(INADDR_ANY,port,"");if(!path)return;FILE *f=fopen(path,"r");if(!f)fatal("DNS bindings");
 char line[128],ip[32],iface[IFNAMSIZ],extra;while(fgets(line,sizeof(line),f)){
  struct in_addr a;if(sscanf(line,"%31s %15s %c",ip,iface,&extra)!=2||inet_pton(AF_INET,ip,&a)!=1||strspn(iface,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")!=strlen(iface)){errno=EINVAL;fatal("DNS binding syntax");}
  add_binding(a.s_addr,53,iface);
 }if(ferror(f))fatal("DNS bindings read");fclose(f);
}
static void receive_udp(struct binding *binding){
 unsigned char packet[SZ];struct sockaddr_in peer;char name[254];
 char control[CMSG_SPACE(sizeof(struct in_pktinfo))];struct iovec io={packet,sizeof(packet)};
 struct msghdr msg={.msg_name=&peer,.msg_namelen=sizeof(peer),.msg_iov=&io,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
 ssize_t n=recvmsg(binding->udp,&msg,0);
 if(n<0||(msg.msg_flags&MSG_TRUNC)||question(packet,n,name))return;
 struct query *q=newq(ntohl(peer.sin_addr.s_addr));if(!q)return;
 memcpy(q->buf,packet,n);q->replyfd=binding->udp;q->peer=peer;q->plen=msg.msg_namelen;
 for(struct cmsghdr *cm=CMSG_FIRSTHDR(&msg);cm;cm=CMSG_NXTHDR(&msg,cm))if(cm->cmsg_level==IPPROTO_IP&&cm->cmsg_type==IP_PKTINFO)if_indextoname(((struct in_pktinfo*)CMSG_DATA(cm))->ipi_ifindex,q->ingress);
 if(binding->ingress[0])snprintf(q->ingress,sizeof(q->ingress),"%s",binding->ingress);
 q->have=n;q->state=1;dispatch(q);
}
static void receive_tcp(struct binding *binding){
 struct sockaddr_in peer;socklen_t len=sizeof(peer);int fd=accept4(binding->tcp,(void*)&peer,&len,SOCK_NONBLOCK|SOCK_CLOEXEC);if(fd<0)return;
 struct query *q=newq(ntohl(peer.sin_addr.s_addr));if(!q){close(fd);return;}q->in=fd;
 if(binding->ingress[0])snprintf(q->ingress,sizeof(q->ingress),"%s",binding->ingress);
 else{struct sockaddr_in local;socklen_t z=sizeof(local);if(!getsockname(fd,(void*)&local,&z)){struct ifaddrs *ifs=NULL;if(!getifaddrs(&ifs)){for(struct ifaddrs *a=ifs;a;a=a->ifa_next)if(a->ifa_addr&&a->ifa_addr->sa_family==AF_INET&&((struct sockaddr_in*)a->ifa_addr)->sin_addr.s_addr==local.sin_addr.s_addr){snprintf(q->ingress,sizeof(q->ingress),"%s",a->ifa_name);break;}freeifaddrs(ifs);}}}
 q->want=2;q->state=1;
}
static void deliver(struct query *q){
 if(paused){q->state=7;return;}
 unsigned char *b=q->buf+(q->in>=0?2:0);size_t len=q->have-(q->in>=0?2:0);
 if(answer(q,b,len)){failed(q);return;}
 if(q->in<0){sendto(q->replyfd,b,len,0,(void*)&q->peer,q->plen);closeq(q);}
 else {q->state=5;q->want=q->have;q->sent=0;}
}
#include "dns_control.h"
int main(int argc,char **argv){if(argc>1&&!strcmp(argv[1],"--control"))return control_client(argc,argv);if(argc<2)return 2;signal(SIGPIPE,SIG_IGN);signal(SIGTERM,ending);signal(SIGINT,ending);if(argc>5)setpriority(PRIO_PROCESS,0,10);live=policy_load(argv[1],getenv("NR_DNS_GLOBAL"),NULL);if(!live)fatal("DNS policy");if(argc>5)setpriority(PRIO_PROCESS,0,0);
 char evidence[512];snprintf(evidence,sizeof(evidence),"%s.evidence",argc>2?argv[2]:"/tmp/native-dns");history_path=evidence;
 if(argc>5){FILE *f=fopen(argv[5],"w");if(!f)fatal("prepared");fputs("prepared\n",f);fclose(f);
  /* A staged process has no sockets and cannot affect the live generation. */
  while(!terminate&&access(argv[4],F_OK)){usleep(20000);}if(terminate)return 0;
 }
 if(dns_limits_read(dns_limits_path(),&dns_limits,1))fatal("DNS source limits");
 control_open();history_load();nl=socket(AF_NETLINK,SOCK_RAW,NETLINK_NETFILTER);if(nl<0)fatal("netlink");struct timeval tv={.tv_sec=1};setsockopt(nl,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));load_bindings(argc>3?argv[3]:NULL);if(argc>2){FILE *ready=fopen(argv[2],"w");if(!ready)fatal("ready");fputs("ready\n",ready);fclose(ready);}for(int i=0;i<MAXQ;i++)qs[i].in=qs[i].out=-1;
for(;;){if(terminate){history_save();control_close();return 0;}struct pollfd pf[MAXQ+2*MAXBIND+1];int ix[MAXQ+2*MAXBIND+1];int count=0;
for(int k=0;k<nb;k++){pf[count++]=(struct pollfd){bindings[k].udp,POLLIN,0};pf[count++]=(struct pollfd){bindings[k].tcp,POLLIN,0};}
int control_index=count;pf[count++]=(struct pollfd){control_poll_fd(),POLLIN,0};int first_query=count;time_t now=monotime();for(int i=0;i<MAXQ;i++){struct query *q=&qs[i];if(!q->state)continue;if(!paused&&now-q->start>8){closeq(q);continue;}if(q->state==6||q->state==7||(paused&&q->state==5))continue;int fd=q->state==1||q->state==5?q->in:q->out;pf[count]=(struct pollfd){fd,(q->state==2||q->state==5)?POLLOUT:POLLIN,0};ix[count++]=i;}if(poll(pf,count,250)<0){if(errno==EINTR)continue;fatal("poll");}
if(pf[control_index].revents&POLLIN){control_receive();continue;}
for(int k=0;k<nb;k++){if(pf[2*k].revents&POLLIN)receive_udp(&bindings[k]);if(pf[2*k+1].revents&POLLIN)receive_tcp(&bindings[k]);}
for(int j=first_query;j<count;j++){struct query *q=&qs[ix[j]];if(!q->state||!pf[j].revents)continue;if(pf[j].revents&(POLLERR|POLLNVAL)){failed(q);continue;}if(q->state==2||q->state==5){int fd=q->state==2?q->out:q->in;ssize_t n=send(fd,q->buf+q->sent,q->want-q->sent,MSG_NOSIGNAL);if(n<0){if(errno!=EAGAIN&&errno!=EINTR)failed(q);continue;}if(getenv("NR_DEBUG"))fprintf(stderr,"sent state=%d n=%zd fd=%d\n",q->state,n,fd);q->sent+=n;if(q->sent==q->want){if(q->state==5){closeq(q);continue;}q->state=3;q->have=0;q->want=q->in>=0?2:SZ;}continue;}
int fd=q->state==1?q->in:q->out;ssize_t n=recv(fd,q->buf+q->have,q->want-q->have,0);if(n<=0){if(n==0||(errno!=EAGAIN&&errno!=EINTR))closeq(q);continue;}q->have+=n;if(q->in>=0){if(q->have<q->want)continue;if(q->want==2){q->want=u16(q->buf)+2;if(q->want<14){closeq(q);continue;}continue;}}
if(q->state==1){dispatch(q);continue;}deliver(q);}
}}
