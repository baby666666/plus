/* Batch the exact url_route-add ABI used by iKuai 3.7.26 ik_cntl.
 * No kernel patch or protocol recognition code is changed. */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#define NATIVE_NETLINK 53
#define MESSAGE_SIZE 32816
static int valid(const char *s){size_t n=strlen(s);if(!n||n>253||s[n-1]=='.')return 0;size_t label=0;for(size_t i=0;i<n;i++){unsigned char c=s[i];if(c=='.'){if(!label||label>63||s[i-1]=='-')return 0;label=0;}else{if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-')||(!label&&c=='-'))return 0;label++;}}return label&&label<=63&&s[n-1]!='-';}
static int parse(const char *s){char *end;errno=0;long n=strtol(s,&end,10);return errno||*end||n<1||n>255?-1:(int)n;}
static void word(unsigned char *p,size_t offset,uint32_t n){memcpy(p+offset,&n,4);}
int main(int argc,char **argv){
 if(argc!=3){fprintf(stderr,"usage: native-url-load FILE FIRST_GROUP\n");return 2;}
 int group=parse(argv[2]);if(group<0)return 2;FILE *f=fopen(argv[1],"r");if(!f){perror("domains");return 1;}
 /* Validate the entire file before sending any mutations. */
 char *line=NULL;size_t size=0,count=0;ssize_t len;
 while((len=getline(&line,&size,f))>=0){if(len&&line[len-1]=='\n')line[--len]=0;if((size_t)len!=strlen(line)||!valid(line)||group+(int)(count/1000)>255){fprintf(stderr,"invalid native domain at line %zu\n",count+1);free(line);fclose(f);return 1;}count++;}
 if(ferror(f)||!count){fprintf(stderr,"empty/unreadable native domains\n");free(line);fclose(f);return 1;}rewind(f);
 int fd=socket(AF_NETLINK,SOCK_RAW,NATIVE_NETLINK);if(fd<0){perror("native netlink");return 1;}
 struct sockaddr_nl local={.nl_family=AF_NETLINK,.nl_pid=(uint32_t)getpid()},kernel={.nl_family=AF_NETLINK};
 if(bind(fd,(void*)&local,sizeof(local))){perror("native bind");return 1;}
 unsigned char message[MESSAGE_SIZE]={0};struct nlmsghdr *h=(void*)message;h->nlmsg_len=MESSAGE_SIZE;h->nlmsg_pid=getpid();
 word(message,16,10);word(message,24,2);word(message,28,4);
 struct iovec iov={message,sizeof(message)};struct msghdr msg={.msg_name=&kernel,.msg_namelen=sizeof(kernel),.msg_iov=&iov,.msg_iovlen=1};
 size_t sent=0;while((len=getline(&line,&size,f))>=0){if(len&&line[len-1]=='\n')line[--len]=0;if((size_t)len!=strlen(line)||!valid(line)||sent>=count){fprintf(stderr,"native domain file changed during load\n");close(fd);free(line);fclose(f);return 1;}word(message,32,group+(uint32_t)(sent/1000));memset(message+48,0,254);memcpy(message+48,line,(size_t)len);
  ssize_t n;do{n=sendmsg(fd,&msg,0);}while(n<0&&errno==EINTR);if(n!=MESSAGE_SIZE){perror("native domain send");close(fd);free(line);fclose(f);return 1;}sent++;
 }
 int failed=ferror(f)||sent!=count;close(fd);free(line);fclose(f);if(failed)return 1;printf("Native domain entries submitted: %zu\n",sent);return 0;
}
