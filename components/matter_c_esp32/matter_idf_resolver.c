#include "matter_idf_resolver.h"
#include "mdns.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef struct Job {
    struct Job* next; mdns_search_once_t* search; uint64_t id;
    Matter_Resolver_Answer_T answer; char instance[34];
    bool cancel,address_ready; unsigned phase;
} Job;
enum { SERVICE,HOST,TXT };
#if CONFIG_MATTER_C_RUNTIME_USERCASE
#define RESOLVER_TRACE(...) printf(__VA_ARGS__)
#else
#define RESOLVER_TRACE(...) ((void)0)
#endif
struct Matter_Idf_Resolver { esp_netif_t* iface; Job* jobs; uint64_t serial; unsigned count; uint32_t interface_id; };
static Matter_Result_T start(void* u,const Matter_Resolver_Query_T* q,uint64_t* id) {
    Matter_Idf_Resolver_T r=u;
    if(!r || !q || !id || !q->node_id || (q->interface_id && q->interface_id!=r->interface_id)) return MATTER_INVALID_ARGUMENT;
    if(r->count==8 || r->serial==UINT64_MAX) return MATTER_BUSY;
    Job* j=calloc(1,sizeof(*j)); if(!j) return MATTER_LIMIT_REACHED;
    for(unsigned i=0;i<8;++i) snprintf(j->instance+2*i,3,"%02X",q->compressed_fabric[i]);
    snprintf(j->instance+16,18,"-%016llX",(unsigned long long)q->node_id);
    /* ANY may satisfy max_results with TXT alone (no SRV host/port), and this
     * SDK explicitly excludes additional AAAA from ANY service searches. Ask
     * for SRV; resolve its target's AAAA separately when not included. */
    j->search=mdns_query_async_new(j->instance,"_matter","_tcp",MDNS_TYPE_SRV,3000,1,NULL);
    if(!j->search) { free(j); return MATTER_PORT_ERROR; }
    j->answer.idle_ms=500; j->answer.active_ms=300; j->answer.active_threshold_ms=4000;
    j->id=++r->serial; j->next=r->jobs; r->jobs=j; ++r->count; *id=j->id;
    RESOLVER_TRACE("RESOLVER_START id=%llu instance=%s\n",(unsigned long long)j->id,j->instance);
    return MATTER_PENDING;
}
static void txt(Job* j,const mdns_result_t* p) {
    for(size_t i=0;i<p->txt_count;++i) {
        const mdns_txt_item_t* t=&p->txt[i]; if(!t->key || !t->value || !p->txt_value_len) continue;
        size_t n=p->txt_value_len[i]; if(!n || n>7) continue;
        uint32_t v=0; bool valid=true;
        for(size_t k=0;k<n;++k) {
            if(t->value[k]<'0' || t->value[k]>'9') { valid=false; break; }
            v=v*10+(unsigned)(t->value[k]-'0');
        }
        if(!valid || v>3600000) continue;
        if(!strcmp(t->key,"SII")) j->answer.idle_ms=v;
        else if(!strcmp(t->key,"SAI")) j->answer.active_ms=v;
        else if(!strcmp(t->key,"SAT") && v<=UINT16_MAX) j->answer.active_threshold_ms=v;
    }
}
static Matter_Result_T take(void* u,uint64_t id,Matter_Operation_Result_T* result,Matter_Resolver_Answer_T* out) {
    Matter_Idf_Resolver_T r=u;
    if(!r || !result || !out) return MATTER_INVALID_ARGUMENT;
    Job** link=&r->jobs; while(*link && (*link)->id!=id) link=&(*link)->next;
    Job* j=*link; if(!j) return MATTER_INVALID_STATE;
    mdns_result_t* results=NULL;
    if(!mdns_query_async_get_results(j->search,0,&results,NULL)) return MATTER_PENDING;
    /* SDK contract permits delete only after get_results reports completion. */
    ESP_ERROR_CHECK(mdns_query_async_delete(j->search)); j->search=NULL;
    bool found=j->phase==TXT && j->address_ready; char hostname[64]={0};
    for(mdns_result_t* p=results;p;p=p->next) {
        if(p->esp_netif!=r->iface) continue;
        if(j->phase==TXT) { txt(j,p); continue; }
        if(j->phase==SERVICE) {
            j->answer.peer.port=p->port;
            if(p->hostname && strlen(p->hostname)<sizeof(hostname)) memcpy(hostname,p->hostname,strlen(p->hostname)+1);
        }
        for(mdns_ip_addr_t* ip=p->addr;ip;ip=ip->next) {
            if(ip->addr.type!=ESP_IPADDR_TYPE_V6 || !j->answer.peer.port) continue;
            memcpy(j->answer.peer.address,ip->addr.u_addr.ip6.addr,16); found=true; break;
        }
        if(found) break;
    }
    mdns_query_results_free(results);
    RESOLVER_TRACE("RESOLVER_STEP id=%llu phase=%u address=%u port=%u\n",(unsigned long long)j->id,j->phase,found?1u:0u,(unsigned)j->answer.peer.port);
    if(!found && !j->cancel && j->phase==SERVICE && hostname[0] && j->answer.peer.port) {
        j->phase=HOST; j->search=mdns_query_async_new(hostname,NULL,NULL,MDNS_TYPE_AAAA,3000,1,NULL);
        if(j->search) return MATTER_PENDING;
    }
    if(found && !j->cancel && j->phase!=TXT) {
        j->phase=TXT; j->address_ready=true;
        j->search=mdns_query_async_new(j->instance,"_matter","_tcp",MDNS_TYPE_TXT,3000,1,NULL);
        if(j->search) return MATTER_PENDING;
        /* TXT is optional; a search allocation failure retains the validated
         * route and standard MRP defaults. It cannot create an identity grant. */
    }
    *result=j->cancel?MATTER_OPERATION_CANCELLED:found?MATTER_OPERATION_SUCCEEDED:MATTER_OPERATION_FAILED;
    RESOLVER_TRACE("RESOLVER_DONE id=%llu result=%u\n",(unsigned long long)j->id,(unsigned)*result);
    if(*result==MATTER_OPERATION_SUCCEEDED) *out=j->answer;
    *link=j->next; --r->count; free(j); return MATTER_OK;
}
static void cancel(void* u,uint64_t id) {
    Matter_Idf_Resolver_T r=u; if(!r) return;
    for(Job* j=r->jobs;j;j=j->next) if(j->id==id) { j->cancel=true; break; }
}
Matter_Idf_Resolver_T matter_idf_resolver_new(esp_netif_t* iface) {
    if(!iface) return NULL;
    int index=esp_netif_get_netif_impl_index(iface); if(index<=0) return NULL;
    Matter_Idf_Resolver_T r=calloc(1,sizeof(*r)); if(r) { r->iface=iface; r->interface_id=(uint32_t)index; } return r;
}
Matter_Resolver_Port_T matter_idf_resolver_port(Matter_Idf_Resolver_T r) { return (Matter_Resolver_Port_T){r,start,take,cancel}; }
Matter_Result_T matter_idf_resolver_delete(Matter_Idf_Resolver_T r) {
    if(!r) return MATTER_INVALID_ARGUMENT;
    if(r->jobs) return MATTER_BUSY;
    free(r); return MATTER_OK;
}
