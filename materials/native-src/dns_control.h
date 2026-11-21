/* Root-only, bounded control protocol. PREPARE never publishes a policy.
 * PAUSE acknowledges a reply barrier; COMMIT requires that barrier and the
 * same ticket. The kernel transaction stays responsible for its traffic guard. */
static int control_fd=-1,control_peer=-1,restart_pending;
static time_t control_peer_at,pause_at;
static char control_path[108],ticket[65],committed[65];
static pthread_mutex_t preparation_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_t preparation_thread;
static int preparation_running,preparation_done;
static struct policy *prepared;
static int retained_ids[MAXRULE];static size_t retained_count;
static int retain_confirmed;
static int retain_kernel_sets(const char *path){
 if(strcmp(path,"/tmp/iktmp/native-rules/active/dns-preserve.ids"))return -1;
 FILE *f=fopen(path,"r");if(!f)return -1;
 int ids[MAXRULE];size_t count=0;char line[32];int invalid=0;
 while(fgets(line,sizeof(line),f)){
  char *end;errno=0;long id=strtol(line,&end,10);
  if(errno||end==line||id<1||id>999999||strcmp(end,"\n")||count==MAXRULE){invalid=1;break;}
  for(size_t j=0;j<count;j++)if(ids[j]==id)invalid=1;
  const struct rule *a=NULL,*b=NULL;
  for(int j=0;j<live->nr;j++)if(live->rules[j].id==id)a=&live->rules[j];
  for(int j=0;j<prepared->nr;j++)if(prepared->rules[j].id==id)b=&prepared->rules[j];
  // The caller proves unchanged kernel sets. Independently reject changes to
  // the resolver, source, schedule or ingress metadata, even on a bad request.
  if(!a||!b||a->port!=b->port||a->group!=b->group||a->nr!=b->nr||a->nm!=b->nm||strcmp(a->ingress,b->ingress)||memcmp(a->active,b->active,sizeof(a->active))){invalid=1;break;}
  if(a->nr&&memcmp(a->ranges,b->ranges,a->nr*sizeof(*a->ranges))){invalid=1;break;}
  for(int j=0;j<a->nm;j++)if(strcmp(a->macs[j],b->macs[j]))invalid=1;
  if(invalid)break;ids[count++]=(int)id;
 }
 if(ferror(f))invalid=1;fclose(f);if(invalid)return -1;
 memcpy(retained_ids,ids,count*sizeof(*ids));retained_count=count;retain_confirmed=1;return 0;
}
struct preparation {char rules[512],globals[512];struct global_index *base;};
static void *prepare_thread(void *arg){
 struct preparation *a=arg;
 struct policy *p=policy_load(a->rules,a->globals,a->base);
 global_release(a->base);free(a);
 pthread_mutex_lock(&preparation_lock);prepared=p;preparation_done=1;pthread_mutex_unlock(&preparation_lock);
 return NULL;
}
static int preparation_ready(void){
 pthread_mutex_lock(&preparation_lock);int ready=preparation_done;pthread_mutex_unlock(&preparation_lock);
 if(ready&&preparation_running){pthread_join(preparation_thread,NULL);preparation_running=0;}
 return ready;
}
static int valid_ticket(const char *s){return *s&&strlen(s)<sizeof(ticket)&&strspn(s,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")==strlen(s);}
static int control_client(int argc,char **argv){
 if(argc<5||strlen(argv[2])>=108)return 2;
 char msg[1200]={0};size_t used=0;
 for(int i=3;i<argc;i++){
  if(strpbrk(argv[i],"\n\r\t ")||used+strlen(argv[i])+2>=sizeof(msg))return 2;
  if(i>3)msg[used++]=' ';strcpy(msg+used,argv[i]);used+=strlen(argv[i]);
 }
 int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);if(fd<0)return 1;
 const char *limit=getenv("NR_CONTROL_TIMEOUT");long seconds=limit?strtol(limit,NULL,10):10;if(seconds<1||seconds>300)return 2;
 struct timeval timeout={.tv_sec=seconds};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
 struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,argv[2]);
 if(connect(fd,(void*)&a,sizeof(a))||send(fd,msg,used,MSG_NOSIGNAL)!=(ssize_t)used){close(fd);return 1;}
 char response[256];ssize_t n=recv(fd,response,sizeof(response)-1,0);close(fd);
 if(n<1)return 1;response[n]=0;fputs(response,stdout);
 return !strncmp(response,"OK ",3)?0:1;
}
static void control_open(void){
 const char *path=getenv("NR_DNS_CONTROL");if(!path)path="/tmp/iktmp/native-rules/dns.control";
 if(strlen(path)>=sizeof(control_path)){errno=EINVAL;fatal("control path");}
 strcpy(control_path,path);
 struct stat st;
 if(!lstat(path,&st)){
  if(!S_ISSOCK(st.st_mode)||st.st_uid!=geteuid()){errno=EPERM;fatal("control owner");}
  int test=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,path);
  if(test<0)fatal("control probe");int rc=connect(test,(void*)&a,sizeof(a)),e=errno;close(test);
  if(rc==0||e!=ECONNREFUSED){errno=EADDRINUSE;fatal("control active");}
  if(unlink(path))fatal("control stale");
 }
 control_fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0);if(control_fd<0)fatal("control socket");
 struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,path);
 mode_t mask=umask(0077);int rc=bind(control_fd,(void*)&a,sizeof(a));umask(mask);
 if(rc||listen(control_fd,8))fatal("control bind");
}
static int control_poll_fd(void){
 if(control_peer>=0&&monotime()-control_peer_at>5){close(control_peer);control_peer=-1;}
 return control_peer>=0?control_peer:control_fd;
}
static int same_decision(const struct policy *a,int ai,const struct policy *b,int bi){
 if(ai<0||bi<0)return ai==bi;
 const struct rule *x=&a->rules[ai],*y=&b->rules[bi];
 return x->id==y->id&&x->port==y->port&&x->group==y->group;
}
static void resume_queries(struct policy *old){
 time_t held=monotime()-pause_at;paused=0;
 for(int i=0;i<MAXQ;i++){
  struct query *q=&qs[i];if(!q->state)continue;q->start+=held;
  if(q->state==1)continue; /* TCP query not yet complete. */
  if(q->state==6){dispatch(q);continue;}
  int selected=choose(live,q->name,q->src,q->ingress);
  if(restart_pending||!same_decision(old,q->rule,live,selected)){
   /* Never mix a partly transmitted TCP response with another generation. */
   if(q->state==5&&q->sent){closeq(q);continue;}
   if(q->out>=0){close(q->out);q->out=-1;}
   if(!q->request){closeq(q);continue;}
   memcpy(q->buf,q->request,q->request_size);q->have=q->request_size;q->start=monotime();dispatch(q);continue;
  }
  q->rule=selected;
  if(q->state==7)deliver(q);
  else if(q->state==5){ /* Reinstall evidence cleared by the guarded commit. */
   if(answer(q,q->buf+2,q->have-2))closeq(q);
  }
 }
}
static void control_reply(const char *s){send(control_peer,s,strlen(s),MSG_NOSIGNAL|MSG_DONTWAIT);close(control_peer);control_peer=-1;}
static void control_receive(void){
 if(control_peer<0){
  control_peer=accept4(control_fd,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);if(control_peer<0)return;
  struct ucred cred;socklen_t n=sizeof(cred);
  if(getsockopt(control_peer,SOL_SOCKET,SO_PEERCRED,&cred,&n)||cred.uid!=0){close(control_peer);control_peer=-1;return;}
  control_peer_at=monotime();return;
 }
 char msg[1200],cmd[16],id[65],a[512],b[512],extra;
 ssize_t n=recv(control_peer,msg,sizeof(msg)-1,MSG_DONTWAIT|MSG_TRUNC);
 if(n<0&&(errno==EAGAIN||errno==EINTR))return;
 if(n<1||n>=(ssize_t)sizeof(msg)||memchr(msg,0,n)){control_reply("ERR request\n");return;}msg[n]=0;
 int fields=sscanf(msg,"%15s %64s %511s %511s %c",cmd,id,a,b,&extra);
 if(fields<2||!valid_ticket(id)){control_reply("ERR request\n");return;}
 if(!strcmp(cmd,"PREPARE")&&fields==4){
  preparation_ready();
  if(paused||preparation_running||prepared||ticket[0]){control_reply("ERR busy\n");return;}
  if(a[0]!='/'||b[0]!='/'){control_reply("ERR path\n");return;}
  struct preparation *job=calloc(1,sizeof(*job));if(!job){control_reply("ERR memory\n");return;}
  strcpy(job->rules,a);strcpy(job->globals,b);job->base=live->global;atomic_fetch_add(&job->base->refs,1);
  strcpy(ticket,id);preparation_done=0;preparation_running=1;retain_confirmed=0;retained_count=0;
  if(pthread_create(&preparation_thread,NULL,prepare_thread,job)){
   global_release(job->base);free(job);ticket[0]=0;preparation_running=0;control_reply("ERR thread\n");return;
  }
  control_reply("OK preparing\n");return;
 }
 if(!strcmp(cmd,"RETAIN")&&fields==3){
  if(strcmp(id,ticket)||!paused||!prepared||restart_pending){control_reply("ERR not-paused\n");return;}
  if(retain_kernel_sets(a)){retain_confirmed=0;retained_count=0;control_reply("ERR retain\n");return;}
  control_reply("OK retained\n");return;
 }
 if(fields!=2){control_reply("ERR request\n");return;}
 if(!strcmp(cmd,"LIMITS")){control_reply(dns_limits_commit()?"ERR invalid-limits\n":"OK limits-applied\n");return;}
 if(!strcmp(cmd,"LIMITSTATS")){
  char result[256];unsigned active=0;for(int i=0;i<MAXQ;i++)if(qs[i].state)active++;
  snprintf(result,sizeof(result),"OK active=%u global_max=512 source_drops=%llu rate_drops=%llu table_drops=%llu global_drops=%llu\n",active,dns_source_drops,dns_rate_drops,dns_table_drops,dns_global_drops);control_reply(result);return;
 }
 if(!strcmp(cmd,"PING")){control_reply("OK hot-v2\n");return;}
 if(!strcmp(cmd,"METRICS")){char result[128];snprintf(result,sizeof(result),"OK tuple_hits=%llu tuple_updates=%llu admission_drops=%llu\n",tuple_hits,tuple_updates,admission_drops);control_reply(result);return;}
 if(!strcmp(cmd,"STATUS")){
  if(!strcmp(id,committed)&&!ticket[0]){control_reply("OK committed\n");return;}
  if(strcmp(id,ticket)){control_reply("ERR ticket\n");return;}
  if(!preparation_ready()){control_reply("OK preparing\n");return;}
  control_reply(prepared?(paused?"OK paused\n":"OK ready\n"):"ERR invalid-policy\n");return;
 }
 if(strcmp(id,ticket)){control_reply("ERR ticket\n");return;}
 if(!strcmp(cmd,"ABORT")){
  if(paused||!preparation_ready()){control_reply("ERR busy\n");return;}
  policy_free(prepared);prepared=NULL;ticket[0]=0;preparation_done=0;control_reply("OK aborted\n");return;
 }
 if(!strcmp(cmd,"PAUSE")){
  if(!preparation_ready()||!prepared){control_reply("ERR not-ready\n");return;}
  if(!paused){paused=1;pause_at=monotime();unlink(history_path);history_save();}
  control_reply("OK paused\n");return;
 }
 if(!strcmp(cmd,"RESTART")){
  if(!paused||!prepared){control_reply("ERR not-paused\n");return;}
  restart_pending=1;retain_confirmed=0;retained_count=0;control_reply("OK restart\n");return;
 }
 if(!strcmp(cmd,"RESET")){
  if(!paused||!prepared){control_reply("ERR not-paused\n");return;}
  memset(history,0,sizeof(history));history_incomplete=0;evidence_clear();retain_confirmed=0;retained_count=0;control_reply("OK reset\n");return;
 }
 if(!strcmp(cmd,"COMMIT")){
  if(!paused||!prepared){control_reply("ERR not-paused\n");return;}
  struct policy *old=live;live=prepared;prepared=NULL;strcpy(committed,ticket);ticket[0]=0;preparation_done=0;
  if(retain_confirmed&&!restart_pending)evidence_retain(retained_ids,retained_count);else evidence_clear();
  retain_confirmed=0;retained_count=0;resume_queries(old);restart_pending=0;policy_free(old);control_reply("OK committed\n");return;
 }
 control_reply("ERR command\n");
}
static void control_close(void){
 if(control_peer>=0)close(control_peer);if(control_fd>=0)close(control_fd);unlink(control_path);
 /* Exit may happen during preparation; join before freeing its shared base. */
 if(preparation_running)pthread_join(preparation_thread,NULL);
 policy_free(prepared);policy_free(live);
}
