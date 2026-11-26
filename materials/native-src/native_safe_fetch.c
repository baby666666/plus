#define _GNU_SOURCE
#include <curl/curl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
/* IPv4-only source downloads. Routing/DNS for user traffic is independent. */
static int public4(uint32_t x){
 unsigned a=x>>24,b=(x>>16)&255,c=(x>>8)&255;
 if(a==0||a==10||a==127||a>=224)return 0;
 if(a==100&&b>=64&&b<=127)return 0;
 if(a==169&&b==254)return 0;
 if(a==172&&b>=16&&b<=31)return 0;
 if(a==192&&(b==168||(b==0&&(c==0||c==2))||(b==88&&c==99)))return 0;
 if(a==198&&(b==18||b==19||(b==51&&c==100)))return 0;
 if(a==203&&b==0&&c==113)return 0;
 return 1;
}
struct sink {FILE *f;size_t n,max;};
static size_t write_body(char *data,size_t sz,size_t count,void *v){
 struct sink *s=v;if(sz&&count>SIZE_MAX/sz)return 0;size_t n=sz*count;
 if(n>s->max-s->n)return 0;size_t done=fwrite(data,1,n,s->f);s->n+=done;return done;
}
static int resolve_public(const char *host,char out[INET_ADDRSTRLEN]){
 struct addrinfo h={0},*list=NULL;h.ai_family=AF_INET;h.ai_socktype=SOCK_STREAM;
 if(getaddrinfo(host,"443",&h,&list))return -1;int have=0,bad=0;
 for(struct addrinfo *a=list;a;a=a->ai_next){struct in_addr ip=((struct sockaddr_in*)a->ai_addr)->sin_addr;if(!public4(ntohl(ip.s_addr)))bad=1;else if(!have){inet_ntop(AF_INET,&ip,out,INET_ADDRSTRLEN);have=1;}}
 freeaddrinfo(list);return have&&!bad?0:-1;
}
static int validate_url(const char *text,char **host,char **canonical){
 if(strlen(text)>4096)return -1;
 CURLU *u=curl_url();char *scheme=NULL,*port=NULL,*user=NULL,*pass=NULL;int ok=0;
 if(!u)return -1;
 if(curl_url_set(u,CURLUPART_URL,text,0))goto done;
 if(curl_url_get(u,CURLUPART_SCHEME,&scheme,0)||strcmp(scheme,"https"))goto done;
 if(!curl_url_get(u,CURLUPART_USER,&user,0)||!curl_url_get(u,CURLUPART_PASSWORD,&pass,0))goto done;
 if(!curl_url_get(u,CURLUPART_PORT,&port,0)&&strcmp(port,"443"))goto done;
 if(curl_url_get(u,CURLUPART_HOST,host,0)||strlen(*host)>253)goto done;
 for(char *p=*host;*p;p++)if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='.'||*p=='-'))goto done;
 if(curl_url_get(u,CURLUPART_URL,canonical,0))goto done;ok=1;
 done:curl_free(scheme);curl_free(port);curl_free(user);curl_free(pass);curl_url_cleanup(u);return ok?0:-1;
}
#ifndef FETCH_UNIT
int main(int argc,char **argv){
 if(argc!=4){fprintf(stderr,"usage: native-safe-fetch HTTPS_URL OUTPUT MAX_BYTES\n");return 2;}
 char *end;errno=0;unsigned long max=strtoul(argv[3],&end,10);if(errno||*end||max<1||max>16777216)return 2;
 if(curl_global_init(CURL_GLOBAL_DEFAULT))return 1;
 char tmp[4096];if(snprintf(tmp,sizeof(tmp),"%s.part.%ld",argv[2],(long)getpid())>=(int)sizeof(tmp))return 2;
 int fd=open(tmp,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC|O_NOFOLLOW,0600);if(fd<0)return 1;
 FILE *f=fdopen(fd,"wb");if(!f){close(fd);unlink(tmp);return 1;}
 char *url=strdup(argv[1]);int result=1;alarm(180);
 for(int hop=0;url&&hop<6;hop++){
  char *host=NULL,*canonical=NULL,*next=NULL,ip[INET_ADDRSTRLEN],pin[512];
  CURL *c=NULL;struct curl_slist *pins=NULL;long code=0;CURLcode status=CURLE_FAILED_INIT;
  if(validate_url(url,&host,&canonical)||resolve_public(host,ip)){fprintf(stderr,"source URL or address is not permitted\n");goto step_done;}
  snprintf(pin,sizeof(pin),"%s:443:%s",host,ip);pins=curl_slist_append(NULL,pin);c=curl_easy_init();if(!c||!pins)goto step_done;
  if(fflush(f)||ftruncate(fd,0)||fseek(f,0,SEEK_SET))goto step_done;
  struct sink sink={f,0,max};
  #define OPT(k,v) if(curl_easy_setopt(c,k,v)!=CURLE_OK)goto step_done
  OPT(CURLOPT_URL,canonical);OPT(CURLOPT_RESOLVE,pins);OPT(CURLOPT_PROXY,"");OPT(CURLOPT_IPRESOLVE,CURL_IPRESOLVE_V4);
  OPT(CURLOPT_PROTOCOLS_STR,"https");OPT(CURLOPT_REDIR_PROTOCOLS_STR,"https");OPT(CURLOPT_FOLLOWLOCATION,0L);
  OPT(CURLOPT_SSL_VERIFYPEER,1L);OPT(CURLOPT_SSL_VERIFYHOST,2L);OPT(CURLOPT_CAINFO,"/etc/ssl/certs/ca-certificates.crt");
  OPT(CURLOPT_SSLVERSION,CURL_SSLVERSION_TLSv1_2);OPT(CURLOPT_CONNECTTIMEOUT,15L);OPT(CURLOPT_TIMEOUT,60L);
  OPT(CURLOPT_MAXFILESIZE_LARGE,(curl_off_t)max);OPT(CURLOPT_WRITEFUNCTION,write_body);OPT(CURLOPT_WRITEDATA,&sink);
  OPT(CURLOPT_USERAGENT,"iKuai-NativeLibrary/1.0");OPT(CURLOPT_NOSIGNAL,1L);
  status=curl_easy_perform(c);curl_easy_getinfo(c,CURLINFO_RESPONSE_CODE,&code);
  if(status==CURLE_OK&&code>=200&&code<300){if(!fflush(f)&&!fsync(fd)&&!rename(tmp,argv[2]))result=0;}
  else if(status==CURLE_OK&&(code==301||code==302||code==303||code==307||code==308)){
   char *redirect=NULL;curl_easy_getinfo(c,CURLINFO_REDIRECT_URL,&redirect);if(redirect)next=strdup(redirect);
  }else fprintf(stderr,"source download failed: curl=%d http=%ld\n",(int)status,code);
  step_done: if(c)curl_easy_cleanup(c);curl_slist_free_all(pins);curl_free(host);curl_free(canonical);free(url);url=next;
  if(!result)break;
 }
 free(url);fclose(f);unlink(tmp);curl_global_cleanup();return result;
}
#else
#include <assert.h>
int main(void){
 assert(curl_global_init(CURL_GLOBAL_DEFAULT)==0);
 const char *bad[]={"127.0.0.1","10.0.0.1","169.254.169.254","172.16.0.1","192.168.1.1","100.64.0.1","198.18.0.1","224.0.0.1","0.0.0.0","255.255.255.255"};
 for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++){struct in_addr a;assert(inet_pton(AF_INET,bad[i],&a)==1);assert(!public4(ntohl(a.s_addr)));}
 const char *invalid[]={"http://example.com/a","https://a:b@example.com/a","https://example.com:8080/a","https://[::1]/a","file:///tmp/a"};
 for(unsigned i=0;i<sizeof(invalid)/sizeof(*invalid);i++){char *h=NULL,*u=NULL;assert(validate_url(invalid[i],&h,&u));curl_free(h);curl_free(u);}
 char *h=NULL,*u=NULL;assert(!validate_url("https://raw.githubusercontent.com/a/b/c",&h,&u));curl_free(h);curl_free(u);
 assert(public4(0x08080808));puts("FETCH_UNIT_PASS");curl_global_cleanup();return 0;
}
#endif
