/* Public-engine memory envelope, not a network/crypto emulator. Real dispatcher
 * quota/MRP/UDP leases are covered by test_dispatch and the two-host scenario.
 * Each explicit TX lease reserves the unchanged maximum packet capacity. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "model/matter_im_subscribe.h"
#include "runtime/matter_host_limits.h"
#include "test_alloc_bytes.h"
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"node-memory:%d: %s\n",__LINE__,#x); abort(); } } while(0)
enum { BUCKETS=MATTER_FABRIC_CAPACITY+1, SUBS=BUCKETS*(MATTER_HOST_SUBS_PER_FABRIC+1),
    READS=BUCKETS, TAILS=BUCKETS+MATTER_HOST_DELIVERY_BURST, ENGINES=SUBS+READS+TAILS };
typedef struct Node Node;
typedef struct {
    Node* node; unsigned slot,attributes,events,reads; bool sub,more;
    uint8_t fabric; Matter_Im_Read_T read; Matter_Im_Subscribe_T subscription;
    Matter_Tlv_Writer_T writer; Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T token;
    uint8_t request[128]; size_t size,packet_size; uint32_t digest;
} Engine;
struct Node {
    Matter_Events_T log; uint64_t high; uint32_t next_id;
    Engine engines[ENGINES]; uint8_t* packets[MATTER_HOST_TRANSACTIONS];
};
static Matter_Result_T load(void* u,uint64_t* n) { *n=((Node*)u)->high; return MATTER_OK; }
static Matter_Result_T store(void* u,uint64_t n) { ((Node*)u)->high=n; return MATTER_OK; }
static Matter_Result_T fabric(void* u,Matter_Exchange_Session_T session,uint8_t* f) {
    Engine* e=u; CHECK(session==e->slot+1); *f=e->fabric; return MATTER_OK;
}
static Matter_Im_Status_T allow(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    Engine* e=u; CHECK(session==e->slot+1 && p->endpoint==1 && p->cluster==0x91 && privilege==MATTER_IM_VIEW); return 0;
}
static Matter_Im_Status_T describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* a) {
    (void)u; (void)p; *a=(Matter_Im_Attribute_T){MATTER_IM_VIEW,false}; return 0;
}
static Matter_Im_Status_T describe_event(void* u,const Matter_Event_Path_T* p,Matter_Im_Attribute_T* a) {
    CHECK(p->event==1); return describe(u,NULL,a);
}
static Matter_Im_Status_T read_value(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    Engine* e=u; CHECK(filtered); ++e->reads;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=p->attribute,.data_version=7}; return 0;
}
static Matter_Result_T enumerate(void* u,const Matter_Im_Selector_T* q,const Matter_Im_Path_T* after,Matter_Im_Path_T* next,bool* found) {
    (void)u; CHECK(q->present==(MATTER_IM_ENDPOINT|MATTER_IM_CLUSTER));
    uint32_t attribute=after?after->attribute+1:1; *found=attribute<=MATTER_IM_READ_MAX_RESULTS;
    *next=(Matter_Im_Path_T){1,0x91,attribute}; return MATTER_OK;
}
static uint8_t reserve(void* u,Matter_Exchange_Session_T session,bool keep,uint32_t* id) {
    Engine* e=u; CHECK(session==e->slot+1); (void)keep; *id=++e->node->next_id; return 0;
}
static void release(void* u,uint32_t id) { (void)u; CHECK(id); }
static void put(Engine* e,Matter_Tlv_Type_T type,int tag,uint64_t n) {
    e->token=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=n};
    CHECK(!matter_tlv_write(&e->writer,&e->token,0));
}
static Matter_Rx_Decision_T decision(Engine* e,bool initial) {
    static const uint8_t ok[]={0x15,0x24,0,0,0x24,255,13,0x18};
    return (Matter_Rx_Decision_T){.action=MATTER_RX_EXISTING,.session=e->slot+1,
        .header={.protocol_id=1,.exchange_id=12,.exchange_flags=MATTER_PROTOCOL_INITIATOR,.opcode=initial?(e->sub?3:2):1},
        .payload=initial?e->request:ok,.payload_size=initial?e->size:sizeof(ok)};
}
static void process(Engine* e) {
    CHECK((e->sub?matter_im_subscribe_process(e->subscription,0):matter_im_read_process(e->read,0))==MATTER_PENDING);
}
static void receive(Engine* e,bool initial) {
    Matter_Rx_Decision_T d=decision(e,initial);
    CHECK((e->sub?matter_im_subscribe_receive(e->subscription,&d):matter_im_read_receive(e->read,&d))==MATTER_OK);
}
static Matter_Im_Read_Message_T output(Engine* e) {
    Matter_Im_Read_Message_T out;
    CHECK((e->sub?matter_im_subscribe_output(e->subscription,&out):matter_im_read_output(e->read,&out))==MATTER_OK); return out;
}
static uint32_t digest(const uint8_t* data,size_t n) { uint32_t sum=2166136261u; for(size_t i=0;i<n;++i) sum=(sum^data[i])*16777619u; return sum; }
static void packet(Engine* e,Matter_Im_Read_Message_T out) {
    CHECK(out.size+30<=MATTER_SECURE_MAX_PACKET);
    uint8_t* p=e->node->packets[e->slot]; memcpy(p+30,out.data,out.size);
    e->packet_size=out.size+30; e->digest=digest(p,e->packet_size);
}
static void emit(Engine* e) {
    Matter_Im_Read_Message_T out=output(e); CHECK(out.opcode==5); packet(e,out);
    CHECK(!matter_tlv_init(&e->reader,out.data,out.size,8)); unsigned depth=0,array=0; e->more=false;
    Matter_Tlv_Result_T result;
    while((result=matter_tlv_next(&e->reader,&e->token))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* v=&e->token;
        if(v->type==MATTER_TLV_END) { CHECK(depth); --depth; continue; }
        if(depth==1 && v->type==MATTER_TLV_ARRAY) array=v->tag.number;
        if(depth==1 && v->tag.number==3) e->more=v->unsigned_value!=0;
        if(array==1 && depth==4 && v->tag.number==2 && v->type==MATTER_TLV_UNSIGNED) CHECK(v->unsigned_value==++e->attributes);
        if(array==2 && depth==4 && v->tag.number==1 && v->type==MATTER_TLV_UNSIGNED) CHECK(v->unsigned_value==e->events++);
        if(array==2 && depth==5 && v->tag.number==0 && v->type==MATTER_TLV_UNSIGNED) CHECK(v->unsigned_value==(uint8_t)(e->events-1));
        if(v->type==MATTER_TLV_STRUCTURE || v->type==MATTER_TLV_LIST || v->type==MATTER_TLV_ARRAY) ++depth;
    }
    CHECK(result==MATTER_TLV_DONE && !depth);
    CHECK((e->sub?matter_im_subscribe_sent_at(e->subscription,0):matter_im_read_sent(e->read))==MATTER_OK);
}
static void confirm(Engine* e) { CHECK((e->sub?matter_im_subscribe_confirm(e->subscription,0):matter_im_read_confirm(e->read,0))==MATTER_OK); }
static void complete_chunk(Engine* e,bool status_first) {
    CHECK(digest(e->node->packets[e->slot],e->packet_size)==e->digest);
    if(!e->sub && !e->more) { confirm(e); return; }
    if(status_first) { receive(e,false); process(e); confirm(e); process(e); }
    else { confirm(e); receive(e,false); process(e); }
}
static void create(Engine* e,Node* node,unsigned slot,bool sub) {
    e->node=node; e->slot=slot; e->sub=sub; e->fabric=(uint8_t)(slot%BUCKETS);
    Matter_Im_Read_Port_T port={e,allow,describe,read_value,enumerate,NULL};
    Matter_Im_Read_Fabric_Port_T resolver={fabric};
    Matter_Im_Read_Config_T cfg={{slot+1,12,false},30000,MATTER_IM_READ_MAX_OUTPUT,!e->fabric};
    Matter_Im_Read_Events_Port_T events={e,node->log,describe_event};
    if(sub) {
        Matter_Im_Subscribe_Port_T sp={port,reserve,release};
        e->subscription=e->fabric?matter_im_subscribe_new_case(&sp,&resolver,&cfg,0):matter_im_subscribe_new(&sp,&cfg,0);
        CHECK(e->subscription && !matter_im_subscribe_bind_events(e->subscription,&events));
    } else {
        e->read=e->fabric?matter_im_read_new_case(&port,&resolver,&cfg,0):matter_im_read_new(&port,&cfg,0);
        CHECK(e->read && !matter_im_read_bind_events(e->read,&events));
    }
    CHECK(!matter_tlv_writer_init(&e->writer,e->request,sizeof(e->request),8)); put(e,MATTER_TLV_STRUCTURE,-1,0);
    if(sub) { put(e,MATTER_TLV_BOOL,0,1); put(e,MATTER_TLV_UNSIGNED,1,1); put(e,MATTER_TLV_UNSIGNED,2,30); }
    else {
        put(e,MATTER_TLV_ARRAY,0,0); put(e,MATTER_TLV_LIST,-1,0);
        put(e,MATTER_TLV_UNSIGNED,2,1); put(e,MATTER_TLV_UNSIGNED,3,0x91); put(e,MATTER_TLV_END,-1,0); put(e,MATTER_TLV_END,-1,0);
    }
    put(e,MATTER_TLV_ARRAY,sub?4:1,0); put(e,MATTER_TLV_LIST,-1,0); put(e,MATTER_TLV_UNSIGNED,1,1);
    put(e,MATTER_TLV_UNSIGNED,2,0x91); put(e,MATTER_TLV_UNSIGNED,3,1); put(e,MATTER_TLV_END,-1,0); put(e,MATTER_TLV_END,-1,0);
    put(e,MATTER_TLV_BOOL,sub?7:3,1); put(e,MATTER_TLV_UNSIGNED,255,13); put(e,MATTER_TLV_END,-1,0);
    CHECK(!matter_tlv_writer_finish(&e->writer,&e->size)); receive(e,true);
    for(unsigned i=0;i<256;++i) {
        process(e); Matter_Im_Read_Message_T out;
        if((sub?matter_im_subscribe_output(e->subscription,&out):matter_im_read_output(e->read,&out))==MATTER_OK) { emit(e); return; }
    }
    CHECK(false);
}
static void append(Node* n,unsigned value) {
    const uint8_t data[]={0x15,0x24,0,(uint8_t)value,0x18}; Matter_Event_Path_T path={1,0x91,1};
    CHECK(!matter_events_append(n->log,&path,1,value,false,data,sizeof(data)));
}
static void drain(Engine* e) {
    for(unsigned i=0;;++i) {
        CHECK(i<2*MATTER_EVENTS_CAPACITY+MATTER_IM_READ_MAX_RESULTS);
        bool more=e->more; complete_chunk(e,(i+e->slot)%2!=0);
        if(!more) break;
        emit(e);
    }
    CHECK(e->events==MATTER_EVENTS_CAPACITY && e->reads==(e->sub?0u:MATTER_IM_READ_MAX_RESULTS));
    CHECK(e->attributes==(e->sub?0u:MATTER_IM_READ_MAX_RESULTS));
    if(e->sub) {
        Matter_Im_Read_Message_T out=output(e); CHECK(out.opcode==4); packet(e,out);
        CHECK(!matter_im_subscribe_sent_at(e->subscription,0)); confirm(e);
        CHECK(matter_im_subscribe_state(e->subscription)==MATTER_IM_SUB_IDLE);
    } else CHECK(matter_im_read_state(e->read)==MATTER_IM_READ_COMPLETE);
}
static void cancelled_tails(void) {
    for(unsigned mode=0;mode<2;++mode) {
        Node* n=calloc(1,sizeof(*n)); CHECK(n); Matter_Events_Port_T p={n,load,store};
        n->log=matter_events_new(&p); CHECK(n->log);
        for(unsigned i=0;i<MATTER_EVENTS_CAPACITY;++i) append(n,i);
        n->packets[0]=matter_test_calloc(1,MATTER_SECURE_MAX_PACKET); CHECK(n->packets[0]);
        Engine* e=&n->engines[0]; create(e,n,0,false);
        while(e->more) { complete_chunk(e,mode!=0); emit(e); }
        CHECK(matter_im_read_awaiting_delivery(e->read));
        for(unsigned i=0;i<MATTER_EVENTS_CAPACITY;++i) append(n,i);
        size_t held=live_bytes,called=calls; fail_at=calls+1;
        if(mode) CHECK(matter_im_read_process(e->read,30000)==MATTER_PORT_ERROR);
        else CHECK(!matter_im_read_cancel(e->read));
        fail_at=0; CHECK(calls==called && live_bytes==held && matter_im_read_state(e->read)==MATTER_IM_READ_FAILED);
        CHECK(digest(n->packets[0],e->packet_size)==e->digest);
        CHECK(matter_im_read_confirm(e->read,30000)==MATTER_INVALID_STATE);
        matter_test_free(n->packets[0]); /* Explicit modelled transport completion. */
        CHECK(!matter_im_read_delete(e->read) && !matter_events_delete(n->log)); free(n); CHECK(!live && !live_bytes);
    }
    puts("PASS final Read cancellation/timeout: snapshots retained through drain, independent packet unchanged, no allocation, cleanup after lease completion");
}
int main(void) {
    Node* n=calloc(1,sizeof(*n)); CHECK(n && !live); peak_bytes=max_request=0;
    Matter_Events_Port_T p={n,load,store}; n->log=matter_events_new(&p); CHECK(n->log);
    for(unsigned i=0;i<MATTER_EVENTS_CAPACITY;++i) append(n,i);
    size_t log_bytes=live_bytes;
    for(unsigned i=0;i<MATTER_HOST_TRANSACTIONS;++i) { n->packets[i]=matter_test_calloc(1,MATTER_SECURE_MAX_PACKET); CHECK(n->packets[i]); }
    for(unsigned i=0;i<SUBS+READS;++i) create(&n->engines[i],n,i,i<SUBS);
    size_t active_bytes=live_bytes;
    for(unsigned i=SUBS+READS;i<ENGINES;++i) {
        Engine* e=&n->engines[i]; create(e,n,i,false);
        while(e->more) { complete_chunk(e,i%2!=0); emit(e); }
        CHECK(matter_im_read_awaiting_delivery(e->read));
    }
    size_t held_bytes=live_bytes;
    for(unsigned i=0;i<MATTER_EVENTS_CAPACITY;++i) append(n,i);
    size_t evicted_bytes=live_bytes;
    /* Node publication OOM while all reporting/TX leases are occupied. */
    uint64_t before,after; CHECK(!matter_events_position(n->log,&before));
    const uint8_t data[]={0x15,0x18}; Matter_Event_Path_T path={1,0x91,1}; fail_at=calls+1;
    CHECK(matter_events_append(n->log,&path,1,0,false,data,sizeof(data))==MATTER_LIMIT_REACHED); fail_at=0;
    CHECK(!matter_events_position(n->log,&after) && before==after && live_bytes==evicted_bytes);
    for(unsigned i=0;i<SUBS+READS;++i) drain(&n->engines[i]);
    for(unsigned i=SUBS+READS;i<ENGINES;++i) drain(&n->engines[i]);
    size_t drained_bytes=live_bytes;
    printf("NODE_MEMORY buckets=%u subs_and_replacements=%u active_reads=%u read_tails=%u tx_leases=%u log=%zu active=%zu held=%zu evicted=%zu drained=%zu peak=%zu largest=%zu\n",
        BUCKETS,SUBS,READS,TAILS,MATTER_HOST_TRANSACTIONS,log_bytes,active_bytes,held_bytes,evicted_bytes,drained_bytes,peak_bytes,max_request);
    for(unsigned i=0;i<ENGINES;++i) {
        Engine* e=&n->engines[i];
        CHECK(digest(n->packets[i],e->packet_size)==e->digest);
        if(e->sub) CHECK(!matter_im_subscribe_delete(e->subscription)); else CHECK(!matter_im_read_delete(e->read));
    }
    for(unsigned i=0;i<MATTER_HOST_TRANSACTIONS;++i) matter_test_free(n->packets[i]);
    CHECK(!matter_events_delete(n->log)); free(n); CHECK(!live && !live_bytes);
    puts("PASS node component envelope: shared/evicted events, 512-path reads, delayed tails, immutable independent TX leases, both status/ACK orders and publication OOM");
    cancelled_tails();
    return 0;
}
