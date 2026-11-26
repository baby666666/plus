/* Delete affected IPv4 connections only, under the caller's traffic guard.
 * A complete validated dump precedes any deletion. Every delete carries the
 * original tuple, zone and opaque CTA_ID; it can never become a table flush.
 * Kernel ABI reference: Linux v5.10 net/netfilter/nf_conntrack_netlink.c,
 * ctnetlink_del_conntrack (tuple + zone + CTA_ID comparison).
 * Unchanged higher-priority domain marks are supplied by the conservative
 * transition compiler, never inferred from incomplete DNS query history. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define LIMIT 262144
#define ATTR_TYPE(a) ((a)->nla_type & 0x3fff)
struct range {uint32_t low,high;};
static struct range *ranges;static size_t range_count;
static uint32_t preserved[1024],locals[1024];static size_t preserved_count,local_count;
struct deletion {unsigned char attrs[320];size_t length;};
static struct deletion *deletions;static size_t deletion_count,deletion_cap;
static size_t scanned,kept_scope,kept_mark,kept_local;
static int fail(const char *s){fprintf(stderr,"conntrack prune: %s (%s)\n",s,strerror(errno));return 1;}
static struct nlattr *nextattr(struct nlattr *a,size_t *remaining){
 if(*remaining<sizeof(*a)||a->nla_len<sizeof(*a)||a->nla_len>*remaining)return NULL;
 size_t size=NLA_ALIGN(a->nla_len);if(size>*remaining)return NULL;
 *remaining-=size;return (void*)((char*)a+size);
}
static int ip_attr(struct nlattr *tuple,uint32_t *source,uint32_t *destination){
 size_t n=tuple->nla_len-sizeof(*tuple);struct nlattr *a=(void*)(tuple+1);int found=0;
 while(n){struct nlattr *next=nextattr(a,&n);if(!next)return -1;
  if(ATTR_TYPE(a)==CTA_TUPLE_IP){
   size_t m=a->nla_len-sizeof(*a);struct nlattr *ip=(void*)(a+1);
   while(m){struct nlattr *after=nextattr(ip,&m);if(!after)return -1;
    int type=ATTR_TYPE(ip);if(type==CTA_IP_V4_SRC||type==CTA_IP_V4_DST){
     if(ip->nla_len!=sizeof(*ip)+4)return -1;uint32_t value;memcpy(&value,ip+1,4);value=ntohl(value);
     if(type==CTA_IP_V4_SRC){if(found&1)return -1;*source=value;found|=1;}
     else {if(found&2)return -1;*destination=value;found|=2;}
    }ip=after;
   }
  }a=next;
 }
 return found==3?0:-1;
}
static int is_local(uint32_t address){for(size_t i=0;i<local_count;i++)if(locals[i]==address)return 1;return 0;}
static int is_managed(uint32_t mark){return (mark&0xff000000)==0x55000000||(mark&0xff000000)==0x58000000||(mark&0xfffff000)==0x2df000||(mark&0xff000000)==0x53000000;}
static int collect(struct nlmsghdr *h){
 if(h->nlmsg_len<NLMSG_LENGTH(sizeof(struct nfgenmsg)))return -1;
 struct nfgenmsg *nf=NLMSG_DATA(h);if(nf->nfgen_family!=AF_INET)return -1;
 size_t size=h->nlmsg_len-NLMSG_LENGTH(sizeof(*nf));struct nlattr *a=(void*)((char*)nf+NLMSG_ALIGN(sizeof(*nf)));
 struct nlattr *tuple=NULL,*id=NULL,*zone=NULL;uint32_t mark=0;int has_mark=0;
 while(size){struct nlattr *next=nextattr(a,&size);if(!next)return -1;
  switch(ATTR_TYPE(a)){
  case CTA_TUPLE_ORIG:if(tuple)return -1;tuple=a;break;
  case CTA_ID:if(id||a->nla_len!=sizeof(*a)+4)return -1;id=a;break;
  case CTA_ZONE:if(zone||a->nla_len!=sizeof(*a)+2)return -1;zone=a;break;
  case CTA_MARK:if(has_mark||a->nla_len!=sizeof(*a)+4)return -1;memcpy(&mark,a+1,4);mark=ntohl(mark);has_mark=1;break;
  }a=next;
 }
 uint32_t source,destination;
 if(!tuple||!id||tuple->nla_len>256||ip_attr(tuple,&source,&destination))return -1;
 scanned++;int scope=0;
 for(size_t i=0;i<range_count;i++)if(source>=ranges[i].low&&source<=ranges[i].high){scope=1;break;}
 if(!scope){kept_scope++;return 0;}
 for(size_t i=0;i<preserved_count;i++)if(mark==preserved[i]){kept_mark++;return 0;}
 /* Membership-only edits leave router-originated DNS/WG transport policies
  * unchanged. Do not kill their sockets or incoming management connections.
  * Managed hairpin/DNAT flows are still eligible for removal. */
 if(is_local(source)||(is_local(destination)&&!is_managed(mark))){kept_local++;return 0;}
 if(deletion_count==LIMIT)return -1;
 if(deletion_count==deletion_cap){size_t capacity=deletion_cap?deletion_cap*2:1024;void *p=realloc(deletions,capacity*sizeof(*deletions));if(!p)return -1;deletions=p;deletion_cap=capacity;}
 struct deletion *d=&deletions[deletion_count++];memset(d,0,sizeof(*d));
 struct nlattr *items[]={tuple,id,zone};
 for(size_t i=0;i<3;i++)if(items[i]){size_t length=NLA_ALIGN(items[i]->nla_len);if(d->length+length>sizeof(d->attrs))return -1;memcpy(d->attrs+d->length,items[i],items[i]->nla_len);d->length+=length;}
 return 0;
}
static int load_inputs(const char *source_file,const char *mark_file){
 FILE *f=fopen(source_file,"r");if(!f)return -1;char line[128];
 while(fgets(line,sizeof(line),f)){
  char address[32],bittext[4],extra;unsigned bits;struct in_addr ip;
  if(sscanf(line,"%31[^/]/%3[0-9] %c",address,bittext,&extra)!=2||(bits=(unsigned)atoi(bittext))>32||inet_pton(AF_INET,address,&ip)!=1||range_count>=65536){fclose(f);return -1;}
  void *p=realloc(ranges,(range_count+1)*sizeof(*ranges));if(!p){fclose(f);return -1;}ranges=p;
  uint32_t mask=bits?UINT32_MAX<<(32-bits):0,lo=ntohl(ip.s_addr)&mask;
  ranges[range_count++]=(struct range){lo,lo|~mask};
 }int bad=ferror(f);fclose(f);if(bad||!range_count)return -1;
 f=fopen(mark_file,"r");if(!f)return -1;
 while(fgets(line,sizeof(line),f)){
  unsigned long long value;char extra;
  if(sscanf(line,"%llu %c",&value,&extra)!=1||value>UINT32_MAX||!is_managed(value)||preserved_count>=1024){fclose(f);return -1;}
  preserved[preserved_count++]=value;
 }bad=ferror(f);fclose(f);if(bad)return -1;
 struct ifaddrs *addresses;if(getifaddrs(&addresses))return -1;
 for(struct ifaddrs *a=addresses;a;a=a->ifa_next)if(a->ifa_addr&&a->ifa_addr->sa_family==AF_INET){
  if(local_count>=1024){freeifaddrs(addresses);return -1;}
  locals[local_count++]=ntohl(((struct sockaddr_in*)a->ifa_addr)->sin_addr.s_addr);
 }freeifaddrs(addresses);return local_count?0:-1;
}
static int netlink_socket(void){
 int fd=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC,NETLINK_NETFILTER);if(fd<0)return -1;
 struct sockaddr_nl a={.nl_family=AF_NETLINK};struct timeval timeout={.tv_sec=5};int buffer=1024*1024;
 if(bind(fd,(void*)&a,sizeof(a))||setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))||setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))){close(fd);return -1;}
 setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&buffer,sizeof(buffer));return fd;
}
static ssize_t receive(int fd,unsigned char *buffer,size_t size){
 struct sockaddr_nl sender;struct iovec io={buffer,size};struct msghdr m={.msg_name=&sender,.msg_namelen=sizeof(sender),.msg_iov=&io,.msg_iovlen=1};
 ssize_t n;do n=recvmsg(fd,&m,0);while(n<0&&errno==EINTR);
 if(n<0||m.msg_flags&MSG_TRUNC||m.msg_namelen!=sizeof(sender)||sender.nl_pid!=0)return -1;return n;
}
static int send_request(int fd,const void *buffer,size_t size){struct sockaddr_nl a={.nl_family=AF_NETLINK};return sendto(fd,buffer,size,0,(void*)&a,sizeof(a))==(ssize_t)size?0:-1;}
int main(int argc,char **argv){
 if(argc!=3||geteuid()!=0)return 2;if(load_inputs(argv[1],argv[2]))return fail("invalid inputs");
 int dump=netlink_socket();if(dump<0)return fail("dump socket");
 _Alignas(struct nlmsghdr) unsigned char request[512]={0},buffer[65536];struct nlmsghdr *h=(void*)request;
 h->nlmsg_len=NLMSG_LENGTH(sizeof(struct nfgenmsg));h->nlmsg_type=(NFNL_SUBSYS_CTNETLINK<<8)|IPCTNL_MSG_CT_GET;h->nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP;h->nlmsg_seq=1;
 struct nfgenmsg *nf=NLMSG_DATA(h);nf->nfgen_family=AF_INET;
 if(send_request(dump,request,h->nlmsg_len))return fail("dump request");
 int done=0;
 while(!done){ssize_t n=receive(dump,buffer,sizeof(buffer));if(n<1)return fail("incomplete dump");
  for(struct nlmsghdr *m=(void*)buffer;NLMSG_OK(m,n);m=NLMSG_NEXT(m,n)){
   if(m->nlmsg_seq!=1||(m->nlmsg_flags&NLM_F_DUMP_INTR))return fail("interrupted dump");
   if(m->nlmsg_type==NLMSG_DONE){if(m->nlmsg_len>=NLMSG_LENGTH(4)&&*(int*)NLMSG_DATA(m))return fail("dump error");done=1;}
   else if(m->nlmsg_type==NLMSG_ERROR)return fail("dump rejected");
   else if(m->nlmsg_type!=((NFNL_SUBSYS_CTNETLINK<<8)|IPCTNL_MSG_CT_NEW)||collect(m))return fail("invalid dump record");
  }if(n)return fail("truncated netlink record");
 }
 close(dump);int fd=netlink_socket();if(fd<0)return fail("delete socket");size_t deleted=0,expired=0;
 for(size_t i=0;i<deletion_count;i++){
  memset(request,0,sizeof(request));h=(void*)request;h->nlmsg_len=NLMSG_LENGTH(sizeof(*nf))+deletions[i].length;
  h->nlmsg_type=(NFNL_SUBSYS_CTNETLINK<<8)|IPCTNL_MSG_CT_DELETE;h->nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK;h->nlmsg_seq=i+2;
  nf=NLMSG_DATA(h);nf->nfgen_family=AF_INET;memcpy(request+NLMSG_LENGTH(sizeof(*nf)),deletions[i].attrs,deletions[i].length);
  if(send_request(fd,request,h->nlmsg_len))return fail("delete request");
  ssize_t n=receive(fd,buffer,sizeof(buffer));struct nlmsghdr *ack=(void*)buffer;
  if(n<(ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr))||ack->nlmsg_len<NLMSG_LENGTH(sizeof(struct nlmsgerr))||ack->nlmsg_len>(unsigned)n||ack->nlmsg_type!=NLMSG_ERROR||ack->nlmsg_seq!=i+2)return fail("delete acknowledgement");
  int error=((struct nlmsgerr*)NLMSG_DATA(ack))->error;
  if(!error)deleted++;else if(error==-ENOENT)expired++;else {errno=-error;return fail("delete rejected");}
 }
 close(fd);printf("scanned=%zu deleted=%zu expired=%zu preserved_marks=%zu preserved_local=%zu outside_scope=%zu\n",scanned,deleted,expired,kept_mark,kept_local,kept_scope);
 free(deletions);free(ranges);return 0;
}
