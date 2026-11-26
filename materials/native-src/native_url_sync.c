#define _GNU_SOURCE
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
/* Verified iKuai 3.7.26 add ABI. native_plan.lua identifies changed groups;
 * native_domain_engine.sh deletes/rebinds those groups before this loader.
 * Reinsert only their desired memberships; unchanged groups stay in kernel. */
typedef struct {char *name;int group,slot;} Row;
typedef struct {Row *rows;size_t n;} Map;
static int valid(const char *s){size_t n=strlen(s),label=0;if(!n||n>253||s[n-1]=='.')return 0;for(size_t i=0;i<n;i++){char c=s[i];if(c=='.'){if(!label||label>63||s[i-1]=='-')return 0;label=0;}else{if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-')||(!label&&c=='-'))return 0;label++;}}return label&&label<=63&&s[n-1]!='-';}
static int cmp(const void *a,const void *b){const Row *x=a,*y=b;int v=strcmp(x->name,y->name);return v?v:x->group-y->group;}
static Map load(const char *path){Map m={0};FILE *f=fopen(path,"r");if(!f){perror(path);exit(2);}char *line=NULL;size_t cap=0,allocated=0;ssize_t len;unsigned counts[256]={0};int owner[256]={0};
 while((len=getline(&line,&cap,f))>=0){char name[254],tail;int g,s;if(sscanf(line,"%253s %d %d %c",name,&g,&s,&tail)!=3||!valid(name)||g<1||g>255||s<1||s>255||++counts[g]>1000||(owner[g]&&owner[g]!=s)){fprintf(stderr,"invalid native map\n");exit(2);}owner[g]=s;
  if(m.n==allocated){allocated+=4096;m.rows=realloc(m.rows,allocated*sizeof(Row));if(!m.rows)exit(2);}m.rows[m.n++]=(Row){strdup(name),g,s};if(m.n>255000)exit(2);
 }if(ferror(f))exit(2);free(line);fclose(f);qsort(m.rows,m.n,sizeof(Row),cmp);for(size_t i=1;i<m.n;i++)if(!cmp(&m.rows[i-1],&m.rows[i])){fprintf(stderr,"duplicate native membership\n");exit(2);}return m;}
static double seconds(clockid_t c){struct timespec t;clock_gettime(c,&t);return t.tv_sec+t.tv_nsec/1e9;}
static double wall,cpu;
static void pace(void){double delay=(seconds(CLOCK_PROCESS_CPUTIME_ID)-cpu)/0.45-(seconds(CLOCK_MONOTONIC)-wall);if(delay>0){struct timespec t={(time_t)delay,(long)((delay-(time_t)delay)*1e9)};while(nanosleep(&t,&t)&&errno==EINTR){}}}
static void word(unsigned char *p,size_t off,uint32_t n){memcpy(p+off,&n,4);}
static void sendrow(int fd,int operation,const char *name,int group){unsigned char msg[32816]={0};struct nlmsghdr *h=(void*)msg;h->nlmsg_len=sizeof(msg);h->nlmsg_pid=getpid();word(msg,16,10);word(msg,24,operation);word(msg,28,4);word(msg,32,group);memcpy(msg+48,name,strlen(name));struct sockaddr_nl kernel={.nl_family=AF_NETLINK};struct iovec io={msg,sizeof(msg)};struct msghdr m={.msg_name=&kernel,.msg_namelen=sizeof(kernel),.msg_iov=&io,.msg_iovlen=1};ssize_t n;do{n=sendmsg(fd,&m,0);}while(n<0&&errno==EINTR);if(n!=sizeof(msg)){perror("native delta");exit(3);}}
static size_t end(Map m,size_t i){size_t n=i+1;while(n<m.n&&!strcmp(m.rows[i].name,m.rows[n].name))n++;return n;}
int main(int argc,char **argv){if(argc!=3&&argc!=4)return 2;wall=seconds(CLOCK_MONOTONIC);cpu=seconds(CLOCK_PROCESS_CPUTIME_ID);Map old=load(argv[1]),next=load(argv[2]);int fd=socket(AF_NETLINK,SOCK_RAW,53);if(fd<0){perror("native socket");return 3;}struct sockaddr_nl local={.nl_family=AF_NETLINK,.nl_pid=getpid()};if(bind(fd,(void*)&local,sizeof(local)))return 3;
 size_t i=0,j=0,added=0,kept=0,groups=0;unsigned char changed[256]={0};
 while(i<old.n||j<next.n){int c=i==old.n?1:j==next.n?-1:cmp(&old.rows[i],&next.rows[j]);if(!c){i++;j++;}else if(c<0){changed[old.rows[i++].group]=1;}else{changed[next.rows[j++].group]=1;}}
 if(argc==4){FILE *f=fopen(argv[3],"r");if(!f)return 2;char line[32],tail;int g;while(fgets(line,sizeof(line),f)){if(sscanf(line,"%d %c",&g,&tail)!=1||g<1||g>255){fclose(f);return 2;}changed[g]=1;}if(ferror(f)){fclose(f);return 2;}fclose(f);}
 for(int g=1;g<=255;g++)if(changed[g])groups++;
 for(j=0;j<next.n;j++){if(!changed[next.rows[j].group]){kept++;continue;}sendrow(fd,2,next.rows[j].name,next.rows[j].group);added++;if(added%64==0)pace();}
 pace();close(fd);printf("Native delta: kept=%zu added=%zu replaced_groups=%zu cpu_seconds=%.3f wall_seconds=%.3f\n",kept,added,groups,seconds(CLOCK_PROCESS_CPUTIME_ID)-cpu,seconds(CLOCK_MONOTONIC)-wall);return 0;
}
