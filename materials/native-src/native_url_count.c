#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#define ROOT "/tmp/iktmp/native-rules"
#define SOCK ROOT "/counter.sock"
static double seconds(clockid_t id){struct timespec t;clock_gettime(id,&t);return t.tv_sec+t.tv_nsec/1e9;}
/* Rewind the retained seq_file on EVERY request: preserve buffer allocation,
 * never a result or file position. No cached count may authorize a commit. */
static int count_fd(int fd,uint64_t *result,int paced){
 if(lseek(fd,0,SEEK_SET)<0)return -1;
 char buf[65536];const char prefix[]="URL: ";unsigned pos=0;int match=1;uint64_t count=0;ssize_t n;
 double start=seconds(CLOCK_MONOTONIC),cpu=seconds(CLOCK_PROCESS_CPUTIME_ID);
 while((n=read(fd,buf,sizeof(buf)))!=0){
  if(n<0){if(errno==EINTR)continue;return -1;}
  for(ssize_t i=0;i<n;i++){char c=buf[i];if(c=='\n'){pos=0;match=1;continue;}if(pos<5){if(c!=prefix[pos])match=0;if(++pos==5&&match)count++;}}
  if(paced){double delay=(seconds(CLOCK_PROCESS_CPUTIME_ID)-cpu)/0.35-(seconds(CLOCK_MONOTONIC)-start);if(delay>0){struct timespec t={(time_t)delay,(long)((delay-(time_t)delay)*1e9)};while(nanosleep(&t,&t)&&errno==EINTR){}}}
 }
 *result=count;return 0;
}
static void timeout(int fd,int sec){struct timeval t={sec,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&t,sizeof(t));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&t,sizeof(t));}
static int connect_counter(void){int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(fd<0)return -1;struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,SOCK);if(connect(fd,(void*)&a,sizeof(a))){int e=errno;close(fd);errno=e;return -1;}timeout(fd,120);return fd;}
static void serve(void){
 prctl(PR_SET_PDEATHSIG,0);setsid();signal(SIGPIPE,SIG_IGN);signal(SIGHUP,SIG_IGN);setpriority(PRIO_PROCESS,0,0);
 long max=sysconf(_SC_OPEN_MAX);if(max<0||max>65536)max=65536;for(int i=0;i<max;i++)close(i);
 int null=open("/dev/null",O_RDWR);if(null!=0)_exit(1);dup2(null,1);dup2(null,2);
 int lock=open(ROOT "/counter.lock",O_CREAT|O_RDWR|O_CLOEXEC,0600);if(lock<0||flock(lock,LOCK_EX|LOCK_NB))_exit(0);
 int listenfd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(listenfd<0)_exit(1);
 struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,SOCK);unlink(SOCK);umask(077);
 if(bind(listenfd,(void*)&a,sizeof(a))||listen(listenfd,16))_exit(1);
 FILE *pf=fopen(ROOT "/counter.pid","w");if(pf){fprintf(pf,"%ld\n",(long)getpid());fclose(pf);}
 int proc=-1;
 for(;;){
  int client=accept4(listenfd,0,0,SOCK_CLOEXEC);if(client<0){if(errno==EINTR)continue;_exit(1);}timeout(client,5);
  char request;ssize_t n;do{n=read(client,&request,1);}while(n<0&&errno==EINTR);
  if(n==1&&request=='C'){
   if(proc<0)proc=open("/proc/ikuai/stats/ik_summary",O_RDONLY|O_CLOEXEC);
   uint64_t count=0;char reply[64];int len;
   if(proc<0||count_fd(proc,&count,1)){if(proc>=0)close(proc);proc=-1;len=snprintf(reply,sizeof(reply),"ERR\n");}
   else len=snprintf(reply,sizeof(reply),"OK %llu\n",(unsigned long long)count);
   /* A closed client must not terminate the service or publish stale data. */
   send(client,reply,(size_t)len,MSG_NOSIGNAL);
  }
  close(client);
 }
}
int main(int argc,char **argv){
 if(argc==2){int fd=open(argv[1],O_RDONLY);uint64_t n;int rc=fd<0?-1:count_fd(fd,&n,0);if(fd>=0)close(fd);if(rc)return 1;printf("%llu\n",(unsigned long long)n);return ferror(stdout)?1:0;}
 if(argc!=1)return 2;
 struct stat st;if(lstat(ROOT,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=geteuid()){fprintf(stderr,"counter runtime unavailable\n");return 1;}
 int fd=connect_counter();
 if(fd<0){
  if(errno!=ENOENT&&errno!=ECONNREFUSED)return 1;
  pid_t p=fork();if(p<0)return 1;if(!p){serve();_exit(1);}
  for(int i=0;i<100&&fd<0;i++){struct timespec t={0,50000000};nanosleep(&t,0);fd=connect_counter();}
 }
 if(fd<0)return 1;
 if(send(fd,"C",1,MSG_NOSIGNAL)!=1){close(fd);return 1;}
 char reply[64];size_t used=0;
 while(used<sizeof(reply)-1){ssize_t n=read(fd,reply+used,sizeof(reply)-1-used);if(n<0&&errno==EINTR)continue;if(n<=0)break;used+=(size_t)n;if(memchr(reply,'\n',used))break;}
 close(fd);reply[used]=0;if(!used||reply[used-1]!='\n')return 1;unsigned long long count;char extra;
 if(sscanf(reply,"OK %llu %c",&count,&extra)!=1){fprintf(stderr,"native counter failed\n");return 1;}
 printf("%llu\n",count);return ferror(stdout)?1:0;
}
