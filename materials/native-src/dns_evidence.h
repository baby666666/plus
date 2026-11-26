/* Cache only successfully acknowledged tuples owned by this dispatcher.
 * At 45 seconds the 120-second route set still has >=75 seconds left, and
 * the 720-second conflict set has >=675 seconds left: both exceed the maximum
 * advertised TTL (60) and the native address-cache lifetime (60+600).
 * Guarded commits invalidate every entry unless the transaction explicitly
 * confirms that both corresponding kernel sets were preserved unchanged.
 * A full cache/collision merely uses the original acknowledged update path. */
#define TUPLE_CACHE_SIZE 32768
struct installed_tuple {int id;uint32_t destination,source;time_t installed;};
static struct installed_tuple tuple_cache[TUPLE_CACHE_SIZE];
static unsigned long long tuple_hits,tuple_updates;
static void evidence_clear(void){memset(tuple_cache,0,sizeof(tuple_cache));}
static void evidence_retain(const int *ids,size_t count){
 for(unsigned i=0;i<TUPLE_CACHE_SIZE;i++){
  struct installed_tuple *e=&tuple_cache[i];if(!e->id)continue;
  size_t j;for(j=0;j<count;j++)if(e->id==ids[j])break;
  if(j==count)memset(e,0,sizeof(*e));
 }
}
static int install_evidence(int id,uint32_t destination,uint32_t source){
 unsigned hash=((unsigned)id*2654435761u)^destination^(source*2246822519u);
 time_t now=monotime();struct installed_tuple *slot=NULL;
 for(unsigned j=0;j<16;j++){
  struct installed_tuple *e=&tuple_cache[(hash+j)&(TUPLE_CACHE_SIZE-1)];
  if(e->id==id&&e->destination==destination&&e->source==source){
   if(now>=e->installed&&now-e->installed<45){tuple_hits++;return 0;}
   slot=e;break;
  }
  if(!slot&&(!e->id||now-e->installed>=45))slot=e;
  if(!e->id)break;
 }
 if(addset("nr_h_",id,destination,source,720)||addset("nr_d_",id,destination,source,120))return -1;
 tuple_updates++;
 if(slot)*slot=(struct installed_tuple){id,destination,source,now};
 return 0;
}
