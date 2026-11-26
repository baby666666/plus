/* Source limits are opt-in. CIDRs select per-address quotas, not shared subnet
 * quotas. Longest prefix wins, including explicit disabled exceptions. */
#define DNS_CLIENT_SLOTS 4096
#define DNS_LIMIT_RULES 64
struct dns_limit_rule {uint32_t network,mask;unsigned prefix,enabled,concurrency,rate,burst;};
struct dns_limit_config {unsigned count;struct dns_limit_rule rules[DNS_LIMIT_RULES];};
struct dns_client_budget {uint32_t source;time_t at;unsigned tokens,active;int used;};
static struct dns_limit_config dns_limits;
static struct dns_client_budget dns_clients[DNS_CLIENT_SLOTS],dns_unlimited,dns_overflow;
static unsigned long long dns_source_drops,dns_rate_drops,dns_table_drops,dns_global_drops;
static const char *dns_limits_path(void){const char *p=getenv("NR_DNS_LIMITS_FILE");return p?p:"/etc/mnt/ikuai/dns-limits.conf";}
static int dns_limits_read(const char *path,struct dns_limit_config *out,int missing_ok){
 int fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
 if(fd<0){if(errno==ENOENT&&missing_ok){memset(out,0,sizeof(*out));return 0;}return -1;}
 struct stat st;char data[8193];
 if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size>8192||st.st_uid!=geteuid()||(st.st_mode&0022)){close(fd);return -1;}
 ssize_t n=read(fd,data,sizeof(data)-1);close(fd);
 if(n<1||n!=st.st_size||memchr(data,0,n))return -1;data[n]=0;
 struct dns_limit_config cfg={0};char *save=NULL,*line=strtok_r(data,"\n",&save);
 if(!line||strcmp(line,"v1"))return -1;
 while((line=strtok_r(NULL,"\n",&save))){
  if(cfg.count==DNS_LIMIT_RULES)return -1;
  char cidr[64],ip[32],extra;unsigned en,cap,rate,burst,prefix;struct in_addr addr;
  if(sscanf(line,"%63s %u %u %u %u %c",cidr,&en,&cap,&rate,&burst,&extra)!=5||en>1||cap<1||cap>384||rate<1||rate>4096||burst<rate||burst>8192)return -1;
  if(sscanf(cidr,"%31[^/]/%u%c",ip,&prefix,&extra)!=2||prefix>32||inet_pton(AF_INET,ip,&addr)!=1)return -1;
  uint32_t mask=prefix?UINT32_MAX<<(32-prefix):0,network=ntohl(addr.s_addr);
  if((network&mask)!=network)return -1;
  for(unsigned i=0;i<cfg.count;i++)if(cfg.rules[i].network==network&&cfg.rules[i].prefix==prefix)return -1;
  cfg.rules[cfg.count++]=(struct dns_limit_rule){network,mask,prefix,en,cap,rate,burst};
 }
 *out=cfg;return 0;
}
static const struct dns_limit_rule *dns_limit_for(uint32_t source){
 const struct dns_limit_rule *best=NULL;
 for(unsigned i=0;i<dns_limits.count;i++){const struct dns_limit_rule *r=&dns_limits.rules[i];if((source&r->mask)==r->network&&(!best||r->prefix>best->prefix))best=r;}
 return best&&best->enabled?best:NULL;
}
static struct dns_client_budget *dns_budget(uint32_t source,time_t now,const struct dns_limit_rule *rule){
 unsigned start=(source*2654435761u)&(DNS_CLIENT_SLOTS-1);struct dns_client_budget *free_slot=NULL;
 for(unsigned i=0;i<16;i++){
  struct dns_client_budget *b=&dns_clients[(start+i)&(DNS_CLIENT_SLOTS-1)];
  if(b->used&&b->source==source){
   time_t elapsed=now-b->at;
   if(elapsed>0){unsigned long long credit=(unsigned long long)elapsed*rule->rate,total=b->tokens+credit;b->tokens=total>rule->burst?rule->burst:(unsigned)total;b->at=now;}
   if(b->tokens>rule->burst)b->tokens=rule->burst;return b;
  }
  if(!free_slot&&(!b->used||(!b->active&&now-b->at>60)))free_slot=b;
 }
 if(!free_slot)return NULL;
 *free_slot=(struct dns_client_budget){source,now,rule->burst,0,1};return free_slot;
}
static struct dns_client_budget *dns_admit(uint32_t source,time_t now){
 const struct dns_limit_rule *rule=dns_limit_for(source);
 if(!rule)return &dns_unlimited;
 struct dns_client_budget *b=dns_budget(source,now,rule);
 if(!b){dns_table_drops++;return NULL;}
 if(b->active>=rule->concurrency){dns_source_drops++;return NULL;}
 if(!b->tokens){dns_rate_drops++;return NULL;}b->tokens--;return b;
}
/* Called by the event-loop thread only. Existing sockets retain their lifetime
 * and count toward a newly enabled/reduced cap; none are disconnected. */
static void dns_limits_apply(const struct dns_limit_config *cfg,time_t now){
 dns_limits=*cfg;dns_unlimited.active=dns_overflow.active=0;
 for(unsigned i=0;i<DNS_CLIENT_SLOTS;i++)dns_clients[i].active=0;
 /* Prevent reassignment of a slot referenced by any active query. */
 for(int i=0;i<MAXQ;i++)if(qs[i].state&&qs[i].budget&&qs[i].budget!=&dns_unlimited&&qs[i].budget!=&dns_overflow)qs[i].budget->at=now;
 for(int i=0;i<MAXQ;i++)if(qs[i].state){
  const struct dns_limit_rule *r=dns_limit_for(qs[i].src);struct dns_client_budget *b=r?dns_budget(qs[i].src,now,r):&dns_unlimited;
  if(!b)b=&dns_overflow;qs[i].budget=b;b->active++;
 }
}
static int dns_limits_commit(void){
 char pending[600];if(snprintf(pending,sizeof(pending),"%s.pending",dns_limits_path())>=(int)sizeof(pending))return -1;
 struct dns_limit_config cfg;if(dns_limits_read(pending,&cfg,0))return -1;
 if(rename(pending,dns_limits_path()))return -1;
 dns_limits_apply(&cfg,monotime());return 0;
}
