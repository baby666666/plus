/* Immutable DNS generations. Only the event-loop thread publishes a policy;
 * a single preparer builds candidates without touching serving state. */
#include <stdatomic.h>
#define POLICY_MAX_BYTES (32u * 1024u * 1024u)
#define POLICY_MAX_NAMES 1000000
struct global_index {
 atomic_uint refs;
 struct word *words; int nw;
 char **cn, **foreign, **cn_exact, **foreign_exact;
 int ncn, nforeign, ncn_exact, nforeign_exact;
 char *text; size_t length;
};
struct policy { struct rule rules[MAXRULE]; int nr; struct global_index *global; };
static struct policy *live;
static void names_free(char **a,int n){for(int i=0;i<n;i++)free(a[i]);free(a);}
static void global_release(struct global_index *g){
 if(!g||atomic_fetch_sub(&g->refs,1)!=1)return;
 names_free(g->cn,g->ncn);names_free(g->foreign,g->nforeign);
 names_free(g->cn_exact,g->ncn_exact);names_free(g->foreign_exact,g->nforeign_exact);
 for(int i=0;i<g->nw;i++)free(g->words[i].s);
 free(g->words);free(g->text);free(g);
}
static void policy_free(struct policy *p){
 if(!p)return;
 for(int i=0;i<p->nr;i++){
  struct rule *r=&p->rules[i];free(r->ranges);names_free(r->macs,r->nm);
  names_free(r->domains,r->nd);names_free(r->exact,r->ne);
  names_free(r->exclude,r->nx);names_free(r->exclude_exact,r->ny);
 }
 global_release(p->global);free(p);
}
static char *policy_read(const char *path,size_t *length){
 FILE *f=fopen(path,"r");if(!f)return NULL;
 if(fseek(f,0,SEEK_END)){fclose(f);return NULL;}
 long size=ftell(f);
 if(size<0||size>POLICY_MAX_BYTES||fseek(f,0,SEEK_SET)){fclose(f);return NULL;}
 char *s=malloc((size_t)size+1);
 if(!s){fclose(f);return NULL;}
 size_t n=fread(s,1,(size_t)size,f);int bad=ferror(f)||n!=(size_t)size;
 fclose(f);if(bad||memchr(s,0,n)){free(s);return NULL;}
 s[n]=0;*length=n;return s;
}
static int valid_name(const char *s){
 size_t n=strlen(s);if(!n||n>253||s[n-1]=='.')return 0;
 unsigned label=0;
 for(;*s;s++){unsigned char c=*s;
  if(c=='.'){if(!label)return 0;label=0;}
  else {if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'||c=='-')||++label>63)return 0;}
 }
 return label>0;
}
static int name_add(char ***list,int *count,const char *value){
 if(*count>=POLICY_MAX_NAMES)return -1;
 /* Geometric allocation: one realloc per entry made large libraries costly. */
 if(!*count||((*count&(*count-1))==0)){
  size_t cap=*count?(size_t)*count*2:1;
  char **a=realloc(*list,cap*sizeof(*a));if(!a)return -1;*list=a;
 }
 char *s=strdup(value);if(!s)return -1;(*list)[(*count)++]=s;return 0;
}
static int cmp(const void *a,const void *b){return strcmp(*(char *const*)a,*(char *const*)b);}
static void name_sort(char **a,int *n){
 if(*n<2)return;qsort(a,*n,sizeof(*a),cmp);int out=1;
 for(int i=1;i<*n;i++){if(!strcmp(a[out-1],a[i]))free(a[i]);else a[out++]=a[i];}*n=out;
}
static int global_line(struct global_index *g,const char *line){
 if(line[1]!=' ')return -1;
 if(line[0]=='M'){
  int group;char name[254],tail;
  if(sscanf(line,"M %d %253s %c",&group,name,&tail)!=2||(group!=1&&group!=2)||!valid_name(name)||g->nw>=POLICY_MAX_NAMES)return -1;
  struct word *w=realloc(g->words,(g->nw+1)*sizeof(*w));if(!w)return -1;g->words=w;
  char *s=strdup(name);if(!s)return -1;g->words[g->nw++]=(struct word){s,group};return 0;
 }
 if(!valid_name(line+2))return -1;
 switch(line[0]){
 case 'C':return name_add(&g->cn,&g->ncn,line+2);
 case 'F':return name_add(&g->foreign,&g->nforeign,line+2);
 case 'H':return name_add(&g->cn_exact,&g->ncn_exact,line+2);
 case 'G':return name_add(&g->foreign_exact,&g->nforeign_exact,line+2);
 default:return -1;
 }
}
static int word_compare(const void *a,const void *b){return strcmp(((const struct word*)a)->s,((const struct word*)b)->s);}
static void global_sort(struct global_index *g){
 if(g->nw>1)qsort(g->words,g->nw,sizeof(*g->words),word_compare);
 name_sort(g->cn,&g->ncn);name_sort(g->foreign,&g->nforeign);
 name_sort(g->cn_exact,&g->ncn_exact);name_sort(g->foreign_exact,&g->nforeign_exact);
}
static struct global_index *global_load(const char *path,struct global_index *previous){
 size_t n;char *text=policy_read(path,&n);if(!text)return NULL;
 if(previous&&previous->text&&n==previous->length&&!memcmp(text,previous->text,n)){
  free(text);atomic_fetch_add(&previous->refs,1);return previous;
 }
 struct global_index *g=calloc(1,sizeof(*g));if(!g){free(text);return NULL;}
 atomic_init(&g->refs,1);g->text=text;g->length=n;
 char *copy=strdup(text);if(!copy){global_release(g);return NULL;}
 char *state,*line=strtok_r(copy,"\n",&state);int bad=0;
 for(;line;line=strtok_r(NULL,"\n",&state)){line[strcspn(line,"\r")]=0;if(*line&&global_line(g,line)){bad=1;break;}}
 free(copy);if(bad){global_release(g);return NULL;}global_sort(g);return g;
}
static struct policy *policy_load(const char *path,const char *globals,struct global_index *previous){
 size_t length;char *text=policy_read(path,&length);if(!text)return NULL;
 struct policy *p=calloc(1,sizeof(*p));if(!p){free(text);return NULL;}
 p->global=globals?global_load(globals,previous):calloc(1,sizeof(*p->global));
 if(!p->global)goto bad;if(!globals)atomic_init(&p->global->refs,1);
 struct rule *r=NULL;char *state,*line=strtok_r(text,"\n",&state);
 for(;line;line=strtok_r(NULL,"\n",&state)){
  line[strcspn(line,"\r")]=0;if(!*line)continue;
  if(line[1]!=' ')goto bad;
  if(strchr("CFHGM",line[0])){if(globals||global_line(p->global,line))goto bad;continue;}
  if(line[0]=='R'){
   int id,port,group;char tail;
   if(p->nr==MAXRULE||sscanf(line,"R %d %d %d %c",&id,&port,&group,&tail)!=3||id<1||id>999999||port<1||port>65535||group<0||group>4)goto bad;
   for(int i=0;i<p->nr;i++)if(p->rules[i].id==id)goto bad;
   r=&p->rules[p->nr++];r->id=id;r->port=port;r->group=group;continue;
  }
  if(!r)goto bad;
  switch(line[0]){
   case 'I':if(!line[2]||strlen(line+2)>=IFNAMSIZ||strspn(line+2,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")!=strlen(line+2))goto bad;strcpy(r->ingress,line+2);break;
   case 'S':{
    unsigned long long a,b;char tail;
    if(sscanf(line,"S %llu %llu %c",&a,&b,&tail)!=2||a>b||b>UINT32_MAX||r->nr>=65536)goto bad;
    struct range *v=realloc(r->ranges,(r->nr+1)*sizeof(*v));if(!v)goto bad;r->ranges=v;r->ranges[r->nr++]=(struct range){a,b};break;
   }
   case 'T':{int a,b;char tail;if(sscanf(line,"T %d %d %c",&a,&b,&tail)!=2||a<0||b>=10080||a>b)goto bad;memset(r->active+a,1,b-a+1);break;}
   case 'A':{
    unsigned a[6];char tail;
    if(strlen(line+2)!=17||sscanf(line+2,"%2x:%2x:%2x:%2x:%2x:%2x%c",a,a+1,a+2,a+3,a+4,a+5,&tail)!=6||name_add(&r->macs,&r->nm,line+2))goto bad;break;
   }
   case 'D':case 'E':case 'X':case 'Y':{
    if(!valid_name(line+2))goto bad;
    char ***v=line[0]=='D'?&r->domains:line[0]=='E'?&r->exact:line[0]=='X'?&r->exclude:&r->exclude_exact;
    int *n=line[0]=='D'?&r->nd:line[0]=='E'?&r->ne:line[0]=='X'?&r->nx:&r->ny;
    if(name_add(v,n,line+2))goto bad;break;
   }
   default:goto bad;
  }
 }
 for(int i=0;i<p->nr;i++){
  r=&p->rules[i];if(!r->nr&&!r->nm)goto bad;
  name_sort(r->domains,&r->nd);name_sort(r->exact,&r->ne);name_sort(r->exclude,&r->nx);name_sort(r->exclude_exact,&r->ny);
 }
 if(!globals)global_sort(p->global);free(text);return p;
 bad:free(text);policy_free(p);errno=EINVAL;return NULL;
}
