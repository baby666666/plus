#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
/* Semantic equivalent of native_shadow.lua; private candidate output only. */
typedef struct {char *name;int group,slot;} Row;
typedef struct {Row *rows;size_t n;} Map;
static int valid(const char *s){size_t n=strlen(s),label=0;if(!n||n>253||s[n-1]=='.')return 0;for(size_t i=0;i<n;i++){char c=s[i];if(c=='.'){if(!label||label>63||s[i-1]=='-')return 0;label=0;}else{if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-')||(!label&&c=='-'))return 0;label++;}}return label&&label<=63&&s[n-1]!='-';}
static int cmp(const void *a,const void *b){const Row *x=a,*y=b;int v=strcmp(x->name,y->name);return v?v:x->group-y->group;}
static Map load(const char *path){Map m={0};FILE *f=fopen(path,"r");if(!f){perror(path);exit(2);}char *line=NULL;size_t cap=0,allocated=0;ssize_t len;unsigned counts[256]={0};int owner[256]={0};
 while((len=getline(&line,&cap,f))>=0){char name[254],tail;int g,s;if(sscanf(line,"%253s %d %d %c",name,&g,&s,&tail)!=3||!valid(name)||g<1||g>255||s<1||s>255||++counts[g]>1000||(owner[g]&&owner[g]!=s)){fprintf(stderr,"invalid native map\n");exit(2);}owner[g]=s;
  if(m.n==allocated){allocated+=4096;m.rows=realloc(m.rows,allocated*sizeof(Row));if(!m.rows)exit(2);}char *copy=strdup(name);if(!copy)exit(2);m.rows[m.n++]=(Row){copy,g,s};if(m.n>255000)exit(2);if(m.n>1&&cmp(&m.rows[m.n-2],&m.rows[m.n-1])>=0){fprintf(stderr,"unsorted map\n");exit(2);}
 }if(ferror(f))exit(2);free(line);fclose(f);for(size_t i=1;i<m.n;i++)if(!cmp(&m.rows[i-1],&m.rows[i])){fprintf(stderr,"duplicate native membership\n");exit(2);}return m;}

static char path[4096];
static const char *join(const char *dir,const char *name){if(snprintf(path,sizeof(path),"%s/%s",dir,name)>=(int)sizeof(path))exit(2);return path;}
static FILE *output(const char *dir,const char *name){FILE *f=fopen(join(dir,name),"w");if(!f){perror(path);exit(2);}return f;}
static void finish(FILE *f){if(ferror(f)||fclose(f)){perror("write candidate");exit(2);}}
int main(int argc,char **argv){
 if(argc!=3)return 2;const char *root=argv[1],*dir=argv[2];
 Map old=load(join(root,"native-loaded.map")),next=load(join(dir,"native-desired.map"));
 int own[256]={0},want[256]={0},changed[256]={0},remap[256]={0},allocated[256]={0},outowner[256]={0};
 char bindings[256][256]={{0}},by_slot[256][256]={{0}};int gated[256]={0};
 for(size_t i=0;i<old.n;i++)own[old.rows[i].group]=old.rows[i].slot;
 for(size_t i=0;i<next.n;i++)want[next.rows[i].group]=next.rows[i].slot;
 FILE *f=fopen(join(root,"native-bindings"),"r");if(!f)return 2;char line[512],source[64],week[32],gate[16],tail;int g,s,first,last;
 while(fgets(line,sizeof(line),f)){
  if(!strchr(line,'\n'))return 2;
  int n=sscanf(line,"%d %d %63s %31s %d %d %15s %c",&g,&s,source,week,&first,&last,gate,&tail);
  if(n<6||n>7||g<1||g>255||s<1||s>255||own[g]!=s||bindings[g][0]||first<0||first>=86400||last<0||last>86400)return 2;
  if(strspn(week,"1234567,")!=strlen(week))return 2;
  char *b=strchr(line,' ');if(!b||strlen(++b)>=sizeof(bindings[g]))return 2;b[strcspn(b,"\r\n")]=0;strcpy(bindings[g],b);
  if(by_slot[s][0]&&strcmp(by_slot[s],b))return 2;strcpy(by_slot[s],b);
  if(n==7&&!strcmp(source,"null")&&!strcmp(gate,"gate1"))gated[g]=1;
 }
 if(ferror(f)||fclose(f))return 2;
 size_t i=0,j=0;
 while(i<old.n||j<next.n){
  int c=i==old.n?1:j==next.n?-1:cmp(&old.rows[i],&next.rows[j]);
  if(!c){if(old.rows[i].slot!=next.rows[j].slot)changed[old.rows[i].group]=1;i++;j++;}
  else if(c<0)changed[old.rows[i++].group]=1;else changed[next.rows[j++].group]=1;
 }
 for(g=1;g<=255;g++)if(changed[g]){
  if(own[g]&&!gated[g])return 3;
  if(want[g]){
   int ok=0;for(int k=1;k<=255;k++)if(own[k]==want[g]&&gated[k])ok=1;
   if(!ok)return 3;
   int k;for(k=1;k<=255;k++)if(!own[k]&&!allocated[k])break;if(k==256)return 3;
   remap[g]=k;allocated[k]=1;
  }
 }
 for(g=1;g<=255;g++)if(own[g]&&!bindings[g][0])return 2;
 for(i=0;i<next.n;i++){Row *r=&next.rows[i];if(remap[r->group])r->group=remap[r->group];outowner[r->group]=r->slot;}
 /* Remapping changes order only among equal-domain memberships. */
 for(i=0;i<next.n;){j=i+1;while(j<next.n&&!strcmp(next.rows[i].name,next.rows[j].name))j++;if(j>i+1)qsort(next.rows+i,j-i,sizeof(Row),cmp);i=j;}
 FILE *full=output(dir,"shadow-desired.map"),*stage=output(dir,"shadow-stage.map");size_t added=0;
 for(i=0;i<next.n;i++){Row *r=&next.rows[i];fprintf(full,"%s %d %d\n",r->name,r->group,r->slot);if(allocated[r->group]){fprintf(stage,"%s %d %d\n",r->name,r->group,r->slot);added++;}}
 finish(full);finish(stage);
 FILE *gs=output(dir,"shadow-groups"),*bs=output(dir,"shadow-bindings"),*create=output(dir,"shadow-create"),*retire=output(dir,"shadow-retire");
 for(g=1;g<=255;g++){
  if(own[g]&&changed[g])fprintf(retire,"%d\n",g);
  if(outowner[g]){
   s=outowner[g];if(!by_slot[s][0])return 2;fprintf(gs,"%d %d\n",s,g);fprintf(bs,"%d %s\n",g,by_slot[s]);
   if(allocated[g]){char b[256];strcpy(b,by_slot[s]);char *p=strstr(b," gate1");if(!p||p[6])return 2;*p=0;fprintf(create,"%d %s\n",g,b);}
  }
 }
 finish(gs);finish(bs);finish(create);finish(retire);f=output(dir,"shadow-total");fprintf(f,"%zu\n",old.n+added);finish(f);
 return 0;
}
