/* Prepare native URL memberships without launching a second Lua compiler.
 * Input is a private, validated compiler generation. No kernel mutations.
 * Preserve the Lua reference's group allocation/order exactly. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#define LIMIT 255000
struct entry { char *name; unsigned slot, group; };
struct vector { struct entry *v; size_t n, cap; };
static unsigned ids[256], owner[256], counts[256];
static const char *dir;
static void fail(const char *s) { fprintf(stderr,"native-group-plan: %s\n",s);exit(1); }
static void append(struct vector *v, const char *name,unsigned slot,unsigned group) {
 if(v->n>=LIMIT)fail("native group capacity exceeded");
 if(v->n==v->cap){size_t cap=v->cap?v->cap*2:1024;if(cap>LIMIT)cap=LIMIT;
  void *p=realloc(v->v,cap*sizeof(*v->v));if(!p)fail("allocation failed");v->v=p;v->cap=cap;}
 char *p=strdup(name);if(!p)fail("allocation failed");v->v[v->n++]=(struct entry){p,slot,group};
}
static FILE *openpath(const char *name,const char *mode) {
 char path[PATH_MAX];if(snprintf(path,sizeof(path),"%s/%s",dir,name)>=(int)sizeof(path))fail("path too long");
 FILE *f=fopen(path,mode);if(!f)fail("cannot open generation file");return f;
}
static void closefile(FILE *f) { if(ferror(f)||fclose(f))fail("file I/O failed"); }
static int line(FILE *f,char *s,size_t cap) {
 if(!fgets(s,cap,f)){if(ferror(f))fail("read failed");return 0;}
 size_t n=strlen(s);if(n&&s[n-1]=='\n')s[--n]=0;else if(!feof(f))fail("line too long");
 return 1;
}
static int validname(const char *s){size_t n=strlen(s);if(!n||n>253)return 0;for(size_t i=0;i<n;i++)if((unsigned char)s[i]<=32||(unsigned char)s[i]>=127)return 0;return 1;}
static unsigned number(char **p) {
 if(!isdigit((unsigned char)**p))fail("invalid number");
 errno=0;char *end;unsigned long v=strtoul(*p,&end,10);if(errno||v>UINT_MAX)fail("number overflow");*p=end;return (unsigned)v;
}
static void space(char **p){if(**p!=' ')fail("invalid delimiter");++*p;}
static int byslot(const void *a,const void *b){const struct entry *x=a,*y=b;return x->slot!=y->slot?(x->slot<y->slot?-1:1):strcmp(x->name,y->name);}
static int bymap(const void *a,const void *b){const struct entry *x=a,*y=b;int n=strcmp(x->name,y->name);return n?n:(x->group<y->group?-1:x->group>y->group);}
/* A bounded accelerator for the validated, sorted desired set. The sorted
 * array remains authoritative: collisions or allocation failure fall back to
 * bsearch, so adversarial names cannot turn lookup into an unbounded scan. */
struct lookup { uint32_t *buckets; size_t mask; };
static size_t namehash(const struct entry *e) {
#ifdef NR_TEST_COLLISION
 return 0;
#else
 const unsigned char *p=(const unsigned char *)e->name;size_t n=strlen(e->name);
 uint64_t h=UINT64_C(0x9e3779b97f4a7c15)^n^((uint64_t)e->slot<<32),w;
 /* memcpy keeps unaligned chunks well-defined on every compiler target.
  * The index is process-local; no hash value is stored in a routing file. */
 while(n>=8){memcpy(&w,p,8);h=(h^w)*UINT64_C(0xbf58476d1ce4e5b9);h^=h>>31;p+=8;n-=8;}
 w=0;memcpy(&w,p,n);h^=w;h^=h>>30;h*=UINT64_C(0xbf58476d1ce4e5b9);h^=h>>27;
 return (size_t)h;
#endif
}
static struct lookup index_desired(struct vector *v) {
 struct lookup x={0};if(v->n<64)return x;
 size_t cap=128;while(cap<v->n*2)cap*=2;
#ifndef NR_TEST_NO_INDEX
 x.buckets=calloc(cap,sizeof(*x.buckets));
#endif
 if(!x.buckets)return x;x.mask=cap-1;
 for(size_t i=0;i<v->n;i++){
  size_t h=namehash(&v->v[i]);
  for(size_t j=0;j<16;j++){
   size_t k=(h+j)&x.mask;
   if(!x.buckets[k]){x.buckets[k]=(uint32_t)i+1;break;}
  }
 }
 return x;
}
static struct entry *find_desired(struct lookup *x,struct vector *v,struct entry *key) {
 if(x->buckets){
  size_t h=namehash(key);
  for(size_t j=0;j<16;j++){
   uint32_t id=x->buckets[(h+j)&x->mask];if(!id)break;
   struct entry *e=&v->v[id-1];
   if(e->slot==key->slot&&!strcmp(e->name,key->name))return e;
  }
 }
 return v->n?bsearch(key,v->v,v->n,sizeof(*v->v),byslot):NULL;
}
int main(int argc,char **argv){
 if(argc!=2&&argc!=3)fail("usage: native-group-plan generation [loaded-map]");dir=argv[1];
 struct vector desired={0},old={0};char buf[512],file[64];FILE *f=openpath("native-inputs","r");
 while(line(f,buf,sizeof(buf))){char *p=buf;unsigned id=number(&p);space(&p);unsigned s=number(&p);
  if(*p||!id||s<1||s>255||ids[s])fail("invalid selector input");
  for(unsigned k=1;k<=255;k++)if(ids[k]==id)fail("duplicate rule id");ids[s]=id;
 }closefile(f);
 for(unsigned s=1;s<=255;s++)if(ids[s]){
  snprintf(file,sizeof(file),"native-domains-%u.txt",s);f=openpath(file,"r");
  while(line(f,buf,sizeof(buf))){if(!validname(buf))fail("invalid domain");append(&desired,buf,s,0);}closefile(f);
 }
 if(desired.n)qsort(desired.v,desired.n,sizeof(*desired.v),byslot);
 /* The compiler emits unique names, but retain reference set semantics. */
 size_t unique=0;for(size_t i=0;i<desired.n;i++){
  if(unique&&byslot(&desired.v[unique-1],&desired.v[i])==0){free(desired.v[i].name);continue;}
  desired.v[unique++]=desired.v[i];
 }desired.n=unique;
 struct lookup lookup={0};
 f=argc==3?fopen(argv[2],"r"):NULL;if(argc==3&&!f&&errno!=ENOENT)fail("cannot read loaded map");
 if(f){lookup=index_desired(&desired);while(line(f,buf,sizeof(buf))){char *p=strchr(buf,' ');if(!p)fail("invalid loaded map");*p++=0;if(!validname(buf))fail("invalid cached domain");
   unsigned g=number(&p);space(&p);unsigned s=number(&p);if(*p||g<1||g>255||s<1||s>255)fail("invalid cache range");
   struct entry key={buf,s,g};if(old.n&&bymap(&old.v[old.n-1],&key)>=0)fail("unsorted native cache");
   append(&old,buf,s,g);
   struct entry *match=find_desired(&lookup,&desired,&key);
   if(match&&!match->group){if(owner[g]&&owner[g]!=s)fail("group ownership conflict");owner[g]=s;if(++counts[g]>1000)fail("group capacity exceeded");match->group=g;}
  }closefile(f);}
 free(lookup.buckets);
 for(size_t i=0;i<desired.n;i++){struct entry *e=&desired.v[i];if(e->group)continue;unsigned g;
  for(g=1;g<=255;g++)if(owner[g]==e->slot&&counts[g]<1000)break;
  if(g>255){for(g=1;g<=255;g++)if(!owner[g])break;if(g>255)fail("native group capacity exceeded");owner[g]=e->slot;}
  counts[g]++;e->group=g;
 }
 if(desired.n)qsort(desired.v,desired.n,sizeof(*desired.v),bymap);
 unsigned changed[256]={0};size_t a=0,b=0;
 while(a<old.n||b<desired.n){int n=a==old.n?1:b==desired.n?-1:bymap(&old.v[a],&desired.v[b]);
  if(n<0)changed[old.v[a++].group]=1;else if(n>0)changed[desired.v[b++].group]=1;else {a++;b++;}}
 f=openpath("native-desired.map","w");for(size_t i=0;i<desired.n;i++)fprintf(f,"%s %u %u\n",desired.v[i].name,desired.v[i].group,desired.v[i].slot);closefile(f);
 f=openpath("native-desired.groups","w");for(unsigned g=1;g<=255;g++)if(owner[g])fprintf(f,"%u %u\n",owner[g],g);closefile(f);
 f=openpath("native-desired.slots","w");fputc('{',f);int comma=0;for(unsigned s=1;s<=255;s++)if(ids[s]){fprintf(f,"%s\"%u\":%u",comma?",":"",ids[s],s);comma=1;}fputs("}\n",f);closefile(f);
 f=openpath("native-changed.groups","w");for(unsigned g=1;g<=255;g++)if(changed[g])fprintf(f,"%u\n",g);closefile(f);
 for(size_t i=0;i<old.n;i++)free(old.v[i].name);free(old.v);for(size_t i=0;i<desired.n;i++)free(desired.v[i].name);free(desired.v);return 0;
}
