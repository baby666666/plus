#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
/* Fair scheduling plus a 35% worker CPU budget: lowering nice as well made
 * edits starve behind sustained traffic. This is not a total-router CPU cap.
 * Pace only this compiler child; never stop the router's packet forwarding,
 * DNS or monitor processes. This is a worker budget, not a router CPU cap. */
static volatile sig_atomic_t interrupted;
static void signal_handler(int sig){interrupted=sig;}
static double seconds(clockid_t id){struct timespec t;if(clock_gettime(id,&t))return -1;return t.tv_sec+t.tv_nsec/1e9;}
int main(int argc,char **argv){
 if(argc<2)return 2;
 double budget=0.35;const char *setting=getenv("NR_WORK_CPU_PERCENT");
 if(setting){char *end;long percent=strtol(setting,&end,10);if(!*setting||*end||percent<5||percent>35){fprintf(stderr,"invalid worker CPU budget\n");return 2;}budget=percent/100.0;}
 struct sigaction sa={.sa_handler=signal_handler};sigemptyset(&sa.sa_mask);sigaction(SIGTERM,&sa,0);sigaction(SIGINT,&sa,0);sigaction(SIGHUP,&sa,0);
 pid_t child=fork();if(child<0)return 2;
 if(!child){if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()==1)_exit(2);sa.sa_handler=SIG_DFL;sigaction(SIGTERM,&sa,0);sigaction(SIGINT,&sa,0);sigaction(SIGHUP,&sa,0);setpriority(PRIO_PROCESS,0,0);execv(argv[1],argv+1);perror("native worker exec");_exit(127);}
 clockid_t cpu;int clock_ok=clock_getcpuclockid(child,&cpu)==0,status=0,stopped=0;double last_wall=seconds(CLOCK_MONOTONIC),last_cpu=0,credit=0.015;
 for(;;){
  pid_t r=waitpid(child,&status,WNOHANG);if(r==child)break;if(r<0&&errno!=EINTR)return 2;
  if(interrupted){kill(child,SIGCONT);kill(child,interrupted);while(waitpid(child,&status,0)<0&&errno==EINTR){}break;}
  double used=clock_ok?seconds(cpu):-1,wall=seconds(CLOCK_MONOTONIC);
  if(used>=0){credit+=(wall-last_wall)*budget-(used-last_cpu);if(credit>0.015)credit=0.015;last_cpu=used;}
  last_wall=wall;int pause=used>=0&&credit<0;
  if(pause&&!stopped){kill(child,SIGSTOP);stopped=1;}
  if(!pause&&stopped){kill(child,SIGCONT);stopped=0;}
  struct timespec tick={0,20000000};nanosleep(&tick,0);
 }
 if(WIFEXITED(status))return WEXITSTATUS(status);if(WIFSIGNALED(status))return 128+WTERMSIG(status);return 2;
}
