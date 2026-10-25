#include "shim/mdns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned live,fail_after,queries; static bool ready,fail_search,wrong_iface;
static void* zero(size_t n,size_t s) { if(fail_after && !--fail_after) return NULL; void* p=calloc(n,s); if(p) ++live; return p; }
static void release(void* p) { if(p) { assert(live); --live; free(p); } }
#define calloc zero
#define free release
#include "../matter_idf_resolver.c"
#undef calloc
#undef free
static esp_netif_t iface={1},other={2};
static uint8_t address[16]={0xfe,0x80,0,0,0,0,0,0,1};
static mdns_txt_item_t text[]={{"SII","800"},{"SAI","250"},{"SAT","1000"}};
static uint8_t text_size[]={3,3,4};
typedef struct { mdns_result_t result; mdns_ip_addr_t ip; } Answer;
mdns_search_once_t* mdns_query_async_new(const char* name,const char* service,const char* protocol,uint16_t type,uint32_t timeout,size_t max,void* notifier) {
    assert(name && timeout==3000 && max==1 && !notifier); ++queries;
    if(service) {
        /* Regression: an ANY result may legally contain only TXT. It cannot
         * establish the service's target/port or resolve its additional AAAA. */
        assert((type==MDNS_TYPE_SRV || type==MDNS_TYPE_TXT) && !strcmp(service,"_matter") && !strcmp(protocol,"_tcp"));
        assert(!strcmp(name,"0123456789ABCDEF-000000000000007B"));
    } else assert(type==MDNS_TYPE_AAAA && !protocol && !strcmp(name,"peer"));
    if(fail_search) return NULL;
    mdns_search_once_t* s=zero(1,sizeof(*s)); if(s) s->type=type; return s;
}
bool mdns_query_async_get_results(mdns_search_once_t* search,uint32_t timeout,mdns_result_t** results,uint8_t* count) {
    assert(!timeout && !count); if(!ready) return false;
    Answer* a=zero(1,sizeof(*a)); assert(a); a->result.esp_netif=wrong_iface?&other:&iface;
    if(search->type==MDNS_TYPE_SRV) { a->result.port=5541; a->result.hostname="peer"; }
    else if(search->type==MDNS_TYPE_TXT) { a->result.txt=text; a->result.txt_value_len=text_size; a->result.txt_count=3; }
    else { a->result.addr=&a->ip; a->ip.addr.type=ESP_IPADDR_TYPE_V6; memcpy(a->ip.addr.u_addr.ip6.addr,address,16); }
    *results=&a->result; return true;
}
esp_err_t mdns_query_async_delete(mdns_search_once_t* s) { release(s); return 0; }
void mdns_query_results_free(mdns_result_t* r) { release(r); }
int main(void) {
    Matter_Resolver_Query_T q={.compressed_fabric={1,0x23,0x45,0x67,0x89,0xab,0xcd,0xef},.node_id=123,.interface_id=1};
    fail_after=1; assert(!matter_idf_resolver_new(&iface)); fail_after=0;
    Matter_Idf_Resolver_T r=matter_idf_resolver_new(&iface); assert(r); Matter_Resolver_Port_T p=matter_idf_resolver_port(r);
    uint64_t id=99; Matter_Resolver_Answer_T a; memset(&a,0xcc,sizeof(a)); Matter_Operation_Result_T outcome=MATTER_OPERATION_SUCCEEDED;
    fail_after=1; assert(p.start(r,&q,&id)==MATTER_LIMIT_REACHED && id==99); fail_after=0;
    fail_search=true; assert(p.start(r,&q,&id)==MATTER_PORT_ERROR && id==99); fail_search=false;
    assert(p.start(r,&q,&id)==MATTER_PENDING && id==1); assert(matter_idf_resolver_delete(r)==MATTER_BUSY);
    assert(p.take(r,id,&outcome,&a)==MATTER_PENDING && a.peer.port==0xcccc);
    ready=true; assert(p.take(r,id,&outcome,&a)==MATTER_PENDING); /* SRV -> target AAAA. */
    assert(p.take(r,id,&outcome,&a)==MATTER_PENDING); /* Valid route -> optional MRP TXT. */
    assert(p.take(r,id,&outcome,&a)==MATTER_OK && outcome==MATTER_OPERATION_SUCCEEDED);
    assert(a.peer.port==5541 && !memcmp(a.peer.address,address,16) && a.idle_ms==800 && a.active_ms==250 && a.active_threshold_ms==1000);
    assert(p.take(r,id,&outcome,&a)==MATTER_INVALID_STATE);
    assert(p.start(r,&q,&id)==MATTER_PENDING && id==2); p.cancel(r,id); ready=false;
    assert(p.take(r,id,&outcome,&a)==MATTER_PENDING); ready=true;
    assert(p.take(r,id,&outcome,&a)==MATTER_OK && outcome==MATTER_OPERATION_CANCELLED);
    wrong_iface=true; assert(p.start(r,&q,&id)==MATTER_PENDING);
    assert(p.take(r,id,&outcome,&a)==MATTER_OK && outcome==MATTER_OPERATION_FAILED); wrong_iface=false;
    uint64_t ids[8]; for(unsigned i=0;i<8;++i) assert(p.start(r,&q,&ids[i])==MATTER_PENDING);
    id=99; assert(p.start(r,&q,&id)==MATTER_BUSY && id==99);
    for(unsigned i=0;i<8;++i) { p.cancel(r,ids[i]); assert(p.take(r,ids[i],&outcome,&a)==MATTER_OK && outcome==MATTER_OPERATION_CANCELLED); }
    assert(matter_idf_resolver_delete(r)==MATTER_OK && !live);
    puts("PASS ESP resolver boundary: SRV before AAAA, TXT, OOM, limits, cancel/drain, stale IDs, interface and ownership");
    return 0;
}
