/* Shared public-API contract tests for Read and Subscribe, heap-owned fixtures. */
#include "codec/matter_tlv_writer.h"
#ifdef TEST_MULTI_SUB
#define MultiEngine Matter_Im_Subscribe_T
#else
#define MultiEngine Matter_Im_Read_T
#endif
typedef struct {
    MultiEngine engine; Matter_Events_T log; uint64_t high; uint8_t fabric;
    uint32_t denied; unsigned reads,releases; bool sub_update,bad_metadata;
    bool wild_model,wild_request,manage,deny_view; uint8_t masks[9];
    uint16_t query_endpoint; uint32_t query_cluster;
    unsigned model_endpoints,model_clusters,model_events,enum_mode,enums,views,describes,processes;
    Matter_Event_Record_T pending,records[MATTER_EVENTS_CAPACITY];
    Matter_Event_Filter_T filters[MATTER_IM_READ_MAX_PATHS];
    Matter_Tlv_Writer_T writer; uint8_t request[1024]; size_t size;
    const uint8_t* out; size_t out_size; uint8_t opcode;
    unsigned attributes,events,statuses; uint64_t numbers[32]; uint32_t ids[32],clusters[32]; uint16_t endpoints[32];
    uint8_t codes[32]; bool more; uint64_t now;
} MultiEvents;
static Matter_Result_T multi_load(void* u,uint64_t* n) { *n=((MultiEvents*)u)->high; return MATTER_OK; }
static Matter_Result_T multi_store(void* u,uint64_t n) { ((MultiEvents*)u)->high=n; return MATTER_OK; }
static Matter_Result_T multi_fabric(void* u,Matter_Exchange_Session_T session,uint8_t* f) {
    CHECK(session==1); *f=((MultiEvents*)u)->fabric; return MATTER_OK;
}
static Matter_Im_Status_T multi_auth(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* p,Matter_Im_Privilege_T v) {
    MultiEvents* m=u; CHECK(session==1 && (v==MATTER_IM_VIEW || v==MATTER_IM_MANAGE));
    if(v==MATTER_IM_VIEW) ++m->views;
    return (p->attribute==m->denied || (m->deny_view && v==MATTER_IM_VIEW))?MATTER_IM_UNSUPPORTED_ACCESS:0;
}
static Matter_Im_Status_T multi_describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* a) {
    (void)u; CHECK(p->endpoint==0 && p->cluster==0x28); *a=(Matter_Im_Attribute_T){MATTER_IM_VIEW,false}; return 0;
}
static Matter_Im_Status_T multi_event(void* u,const Matter_Event_Path_T* p,Matter_Im_Attribute_T* a) {
    MultiEvents* m=u; ++m->describes;
    if(!m->wild_model) CHECK(p->endpoint==0 && p->cluster==0x28);
    *a=(Matter_Im_Attribute_T){m->manage?MATTER_IM_MANAGE:MATTER_IM_VIEW,p->event==2};
    if(m->bad_metadata && p->event==3) return (Matter_Im_Status_T)256;
    if(m->wild_model) return p->endpoint>=m->model_endpoints?MATTER_IM_UNSUPPORTED_ENDPOINT:
        p->cluster<0x28 || p->cluster>=0x28+m->model_clusters?MATTER_IM_UNSUPPORTED_CLUSTER:
        !p->event || p->event>m->model_events?MATTER_IM_UNSUPPORTED_EVENT:0;
    return p->event==99?MATTER_IM_UNSUPPORTED_EVENT:0;
}
static Matter_Im_Status_T multi_read(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    (void)p; (void)filtered; ++((MultiEvents*)u)->reads;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=123,.data_version=5}; return 0;
}
#ifdef TEST_MULTI_SUB
static uint8_t multi_reserve(void* u,Matter_Exchange_Session_T session,bool keep,uint32_t* id) {
    (void)u; (void)keep; CHECK(session==1); *id=7; return 0;
}
static void multi_release(void* u,uint32_t id) { CHECK(id==7); ++((MultiEvents*)u)->releases; }
#endif
static MultiEvents* multi_new(void) {
    MultiEvents* m=calloc(1,sizeof(*m)); CHECK(m); m->fabric=1; m->denied=UINT32_MAX; m->query_cluster=0x28;
    Matter_Events_Port_T lp={m,multi_load,multi_store}; m->log=matter_events_new(&lp); CHECK(m->log);
    Matter_Im_Read_Port_T p={m,multi_auth,multi_describe,multi_read,NULL,NULL}; Matter_Im_Read_Fabric_Port_T f={multi_fabric};
    Matter_Im_Read_Events_Port_T ep={m,m->log,multi_event};
#ifdef TEST_MULTI_SUB
    Matter_Im_Subscribe_Port_T sp={p,multi_reserve,multi_release};
    Matter_Im_Subscribe_Config_T c={{1,12,false},10000,128,false};
    m->engine=matter_im_subscribe_new_case(&sp,&f,&c,0); CHECK(m->engine);
    CHECK(matter_im_subscribe_bind_events(m->engine,&ep)==MATTER_OK);
#else
    Matter_Im_Read_Config_T c={{1,12,false},10000,128,false};
    m->engine=matter_im_read_new_case(&p,&f,&c,0); CHECK(m->engine);
    CHECK(matter_im_read_bind_events(m->engine,&ep)==MATTER_OK);
#endif
    return m;
}
static void multi_free(MultiEvents* m) {
#ifdef TEST_MULTI_SUB
    CHECK(matter_im_subscribe_delete(m->engine)==MATTER_OK);
#else
    CHECK(matter_im_read_delete(m->engine)==MATTER_OK);
#endif
    CHECK(matter_events_delete(m->log)==MATTER_OK); free(m);
}
static void multi_append(MultiEvents* m,uint32_t event,uint8_t fabric) {
    static const uint8_t data[]={0x15,0x24,0,7,0x18};
    m->pending=(Matter_Event_Record_T){.path={0,0x28,event},.priority=1,.fabric=fabric,.timestamp_ms=25,.size=sizeof(data)};
    memcpy(m->pending.data,data,sizeof(data));
    CHECK(matter_events_prepare(m->log,&m->pending,1)==MATTER_OK); matter_events_finish(m->log,true);
}
static void multi_put(MultiEvents* m,Matter_Tlv_Type_T type,int tag,uint64_t n) {
    Matter_Tlv_Element_T e={.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=n};
    CHECK(matter_tlv_write(&m->writer,&e,0)==MATTER_TLV_OK);
}
static void multi_request(MultiEvents* m,unsigned attrs,const uint32_t* ids,unsigned count,uint32_t urgent,uint64_t minimum) {
    CHECK(matter_tlv_writer_init(&m->writer,m->request,sizeof(m->request),8)==MATTER_TLV_OK);
    multi_put(m,MATTER_TLV_STRUCTURE,-1,0);
#ifdef TEST_MULTI_SUB
    multi_put(m,MATTER_TLV_BOOL,0,0); multi_put(m,MATTER_TLV_UNSIGNED,1,1); multi_put(m,MATTER_TLV_UNSIGNED,2,5);
    unsigned a=3,e=4,f=5,b=7;
#else
    unsigned a=0,e=1,f=2,b=3;
#endif
    if(attrs) {
        multi_put(m,MATTER_TLV_ARRAY,a,0);
        for(unsigned i=0;i<attrs;++i) {
            multi_put(m,MATTER_TLV_LIST,-1,0); multi_put(m,MATTER_TLV_UNSIGNED,2,0);
            multi_put(m,MATTER_TLV_UNSIGNED,3,0x28); multi_put(m,MATTER_TLV_UNSIGNED,4,10+i); multi_put(m,MATTER_TLV_END,-1,0);
        }
        multi_put(m,MATTER_TLV_END,-1,0);
    }
    multi_put(m,MATTER_TLV_ARRAY,e,0);
    for(unsigned i=0;i<count;++i) {
        uint8_t mask=m->wild_request?m->masks[i]:7;
        multi_put(m,MATTER_TLV_LIST,-1,0);
        if(mask&1) multi_put(m,MATTER_TLV_UNSIGNED,1,m->query_endpoint);
        if(mask&2) multi_put(m,MATTER_TLV_UNSIGNED,2,m->query_cluster);
        if(mask&4) multi_put(m,MATTER_TLV_UNSIGNED,3,ids[i]);
        multi_put(m,MATTER_TLV_BOOL,4,!!(urgent&(1u<<i))); multi_put(m,MATTER_TLV_END,-1,0);
    }
    multi_put(m,MATTER_TLV_END,-1,0);
    if(minimum) {
        multi_put(m,MATTER_TLV_ARRAY,f,0); multi_put(m,MATTER_TLV_STRUCTURE,-1,0);
        multi_put(m,MATTER_TLV_UNSIGNED,1,minimum); multi_put(m,MATTER_TLV_END,-1,0); multi_put(m,MATTER_TLV_END,-1,0);
    }
    multi_put(m,MATTER_TLV_BOOL,b,0); multi_put(m,MATTER_TLV_UNSIGNED,255,13); multi_put(m,MATTER_TLV_END,-1,0);
    CHECK(matter_tlv_writer_finish(&m->writer,&m->size)==MATTER_TLV_OK);
}
static void multi_process(MultiEvents* m) {
    for(unsigned step=0;step<100;++step) {
        unsigned before=m->enums; ++m->processes;
#ifdef TEST_MULTI_SUB
        CHECK(matter_im_subscribe_process(m->engine,m->now)==MATTER_PENDING);
        CHECK(m->enums-before<=8);
        if(m->wild_model && matter_im_subscribe_state(m->engine)==MATTER_IM_SUB_COLLECTING) continue;
        Matter_Im_Subscribe_Message_T out; CHECK(matter_im_subscribe_output(m->engine,&out)==MATTER_OK);
#else
        CHECK(matter_im_read_process(m->engine,m->now)==MATTER_PENDING);
        CHECK(m->enums-before<=8);
        if(m->wild_model && matter_im_read_state(m->engine)==MATTER_IM_READ_COLLECTING) continue;
        Matter_Im_Read_Message_T out; CHECK(matter_im_read_output(m->engine,&out)==MATTER_OK);
#endif
        m->out=out.data; m->out_size=out.size; m->opcode=out.opcode; return;
    }
    CHECK(false);
}
static void multi_receive(MultiEvents* m,bool initial) {
    static const uint8_t ok[]={0x15,0x24,0,0,0x24,255,13,0x18};
    Matter_Rx_Decision_T d={.action=MATTER_RX_EXISTING,.session=1,
        .header={.protocol_id=1,.exchange_id=m->sub_update?13:12,.exchange_flags=m->sub_update?0:1},
        .payload=initial?m->request:ok,.payload_size=initial?m->size:sizeof(ok)};
#ifdef TEST_MULTI_SUB
    d.header.opcode=initial?3:1; CHECK(matter_im_subscribe_receive(m->engine,&d)==MATTER_OK);
#else
    d.header.opcode=initial?2:1; CHECK(matter_im_read_receive(m->engine,&d)==MATTER_OK);
#endif
}
static void multi_start(MultiEvents* m) { multi_receive(m,true); multi_process(m); }
static void multi_confirm(MultiEvents* m) {
#ifdef TEST_MULTI_SUB
    CHECK(matter_im_subscribe_sent_at(m->engine,m->now)==MATTER_OK && matter_im_subscribe_confirm(m->engine,m->now)==MATTER_OK);
#else
    CHECK(matter_im_read_sent(m->engine)==MATTER_OK && matter_im_read_confirm(m->engine,m->now)==MATTER_OK);
#endif
}
/* Independent public TLV traversal, no engine fields or expected output encoder. */
static void multi_report(MultiEvents* m) {
    CHECK(m->opcode==5); Matter_Tlv_Reader_T r; Matter_Tlv_Element_T e; unsigned depth=0,array=0; bool data=false;
    CHECK(matter_tlv_init(&r,m->out,m->out_size,8)==MATTER_TLV_OK); m->more=false;
    Matter_Tlv_Result_T result;
    while((result=matter_tlv_next(&r,&e))==MATTER_TLV_OK) {
        if(e.type==MATTER_TLV_END) { CHECK(depth); --depth; continue; }
        if(depth==1 && e.type==MATTER_TLV_ARRAY) array=e.tag.number;
        if(depth==1 && e.type==MATTER_TLV_BOOL && e.tag.number==3) m->more=e.unsigned_value!=0;
        if(depth==3 && e.type==MATTER_TLV_STRUCTURE) {
            data=e.tag.number==1;
            if(array==1) ++m->attributes;
            if(array==2) { if(data) { CHECK(m->events<32); ++m->events; } else { CHECK(m->statuses<32); ++m->statuses; } }
        }
        if(array==2 && data && depth==4 && e.type==MATTER_TLV_UNSIGNED && e.tag.number==1) m->numbers[m->events-1]=e.unsigned_value;
        if(array==2 && data && depth==5 && e.type==MATTER_TLV_UNSIGNED && e.tag.number==1) m->endpoints[m->events-1]=(uint16_t)e.unsigned_value;
        if(array==2 && data && depth==5 && e.type==MATTER_TLV_UNSIGNED && e.tag.number==2) m->clusters[m->events-1]=(uint32_t)e.unsigned_value;
        if(array==2 && data && depth==5 && e.type==MATTER_TLV_UNSIGNED && e.tag.number==3) m->ids[m->events-1]=(uint32_t)e.unsigned_value;
        if(array==2 && !data && depth==5 && e.type==MATTER_TLV_UNSIGNED && e.tag.number==0) m->codes[m->statuses-1]=(uint8_t)e.unsigned_value;
        if(e.type==MATTER_TLV_STRUCTURE || e.type==MATTER_TLV_LIST || e.type==MATTER_TLV_ARRAY) ++depth;
    }
    CHECK(result==MATTER_TLV_DONE && !depth);
}
static void multi_drain(MultiEvents* m) {
    unsigned chunks=0;
    do {
        CHECK(++chunks<32); multi_report(m); multi_confirm(m);
        if(m->more) { multi_receive(m,false); multi_process(m); }
    } while(m->more);
#ifdef TEST_MULTI_SUB
    multi_receive(m,false);
    CHECK(matter_im_subscribe_process(m->engine,m->now)==MATTER_PENDING);
    if(!m->sub_update) {
        multi_process(m); CHECK(m->opcode==4); multi_confirm(m);
    }
    CHECK(matter_im_subscribe_state(m->engine)==MATTER_IM_SUB_IDLE);
#else
    CHECK(matter_im_read_state(m->engine)==MATTER_IM_READ_COMPLETE);
#endif
}
static void multi_tests(void) {
    static const uint32_t ids[]={2,1,3,1,4,5,6,7,8,9};
    MultiEvents* m=multi_new();
    multi_append(m,1,0); multi_append(m,2,2); multi_append(m,3,0); multi_append(m,2,1); multi_append(m,1,0);
    /* Union ordering and per-path fabric scope; overlapping filters do not duplicate. */
    m->filters[0]=(Matter_Event_Filter_T){{0,0x28,2},true};
    m->filters[1]=(Matter_Event_Filter_T){{0,0x28,1},false}; m->filters[2]=m->filters[1]; size_t n=0;
    CHECK(matter_events_copy_selected(m->log,m->filters,3,0,1,m->records,&n)==MATTER_OK && n==3);
    CHECK(m->records[0].number==0 && m->records[1].number==3 && m->records[2].number==4);
    CHECK(matter_events_copy_selected(m->log,m->filters,3,3,1,NULL,&n)==MATTER_OK && n==2);
    CHECK(matter_events_copy_selected(m->log,m->filters,3,0,0,NULL,&n)==MATTER_INVALID_ARGUMENT);
    multi_request(m,1,ids,4,0,0); multi_start(m);
    /* All event snapshots already taken before the attribute chunk leaves. */
    for(unsigned i=0;i<20;++i) multi_append(m,1,0);
    multi_drain(m); CHECK(m->attributes==1 && m->reads==1 && m->events==4 && !m->statuses);
    CHECK(m->numbers[0]==0 && m->numbers[1]==2 && m->numbers[2]==3 && m->numbers[3]==4);
    CHECK(m->ids[0]==1 && m->ids[1]==3 && m->ids[2]==2 && m->ids[3]==1); multi_free(m);
    /* Inclusive filter across all selected paths. */
    m=multi_new(); for(unsigned i=0;i<5;++i) multi_append(m,i%2?3:1,0);
    multi_request(m,0,ids,3,0,3); multi_start(m); multi_drain(m);
    CHECK(m->events==2 && m->numbers[0]==3 && m->numbers[1]==4); multi_free(m);
    static const uint32_t distinct[]={9,8,7,6,5,4,3,2,1};
    m=multi_new(); for(unsigned i=1;i<=9;++i) multi_append(m,i,i==2?1:0);
    multi_request(m,0,distinct,9,0,0); multi_start(m); multi_drain(m);
    CHECK(m->events==9 && !m->statuses);
    for(unsigned i=0;i<9;++i) CHECK(m->ids[i]==i+1 && m->numbers[i]==i);
    multi_free(m);
    /* Both normative mixed budgets and this implementation's 9-path limit. */
    for(unsigned attrs=0;attrs<=8;++attrs) {
        m=multi_new(); for(unsigned i=1;i<=8;++i) multi_append(m,i,i==2?1:0);
        multi_request(m,attrs,ids,9-attrs,0,0); multi_start(m); multi_drain(m);
        CHECK(m->attributes==attrs && m->events==(attrs<=5?8-attrs:9-attrs)); multi_free(m);
    }
    for(unsigned attrs=0;attrs<=9;++attrs) {
        m=multi_new(); multi_request(m,attrs,ids,10-attrs,0,0); multi_start(m);
        CHECK(m->opcode==1 && m->out[3]==MATTER_IM_PATHS_EXHAUSTED && !m->reads); multi_free(m);
    }
    /* One bad path neither hides good paths nor produces duplicate errors. */
    static const uint32_t bad[]={99,1,99,2};
    m=multi_new(); multi_append(m,1,0); m->denied=2;
    multi_request(m,1,bad,4,0,0); multi_start(m); multi_drain(m);
    CHECK(m->events==1 && m->statuses==2 && m->codes[0]==MATTER_IM_UNSUPPORTED_EVENT && m->codes[1]==MATTER_IM_UNSUPPORTED_ACCESS); multi_free(m);
    m=multi_new(); m->bad_metadata=true; multi_append(m,3,0);
    multi_request(m,1,ids,3,0,0); multi_start(m); multi_drain(m);
    CHECK(!m->events && m->statuses==1 && m->codes[0]==MATTER_IM_FAILURE); multi_free(m);
    /* Revoke one cached path after the first event chunk, retain the other. */
    m=multi_new(); multi_append(m,1,0); multi_append(m,2,1); multi_append(m,3,0);
    multi_request(m,0,ids,3,0,0); multi_start(m); multi_report(m); CHECK(m->events==1 && m->more);
    m->denied=2; multi_confirm(m); multi_receive(m,false); multi_process(m);
#ifdef TEST_MULTI_SUB
    multi_report(m); CHECK(m->statuses==1 && m->more); multi_confirm(m); multi_receive(m,false); multi_process(m);
    multi_report(m); CHECK(m->events==2 && m->ids[1]==3 && !m->more);
    multi_confirm(m); multi_receive(m,false); CHECK(matter_im_subscribe_process(m->engine,0)==MATTER_PORT_ERROR && m->releases==1);
#else
    multi_drain(m); CHECK(m->events==2 && m->ids[1]==3 && m->statuses==1);
#endif
    multi_free(m);
    puts("PASS multiple events: mixed 9 paths, union/order/dedup, fabric isolation, EventMin, immutable chunks, limits, per-path errors and ACL revocation");
}
#ifdef TEST_MULTI_SUB
static void multi_update(MultiEvents* m,uint64_t now) {
    m->now=now; CHECK(matter_im_subscribe_process(m->engine,now)==MATTER_PENDING && matter_im_subscribe_state(m->engine)==MATTER_IM_SUB_NEED_EXCHANGE);
    Matter_Exchange_Info_T e={1,13,true}; CHECK(matter_im_subscribe_bind_report(m->engine,&e,now)==MATTER_OK); m->sub_update=true;
    m->events=m->statuses=m->attributes=0; multi_process(m);
}
static void multi_sub_tests(void) {
    static const uint32_t ids[]={1,2,3,1}; MultiEvents* m=multi_new();
    /* Duplicate path ORs IsUrgent, while other paths remain non-urgent. */
    multi_request(m,0,ids,4,8,0); multi_start(m); multi_drain(m); CHECK(!m->events);
    multi_append(m,3,0); multi_append(m,2,2); CHECK(matter_im_subscribe_events_changed(m->engine)==MATTER_OK);
    m->now=1000; CHECK(matter_im_subscribe_process(m->engine,1000)==MATTER_PENDING && matter_im_subscribe_state(m->engine)==MATTER_IM_SUB_IDLE);
    uint64_t deadline=0; CHECK(matter_im_subscribe_deadline(m->engine,&deadline)==MATTER_OK && deadline==5000);
    multi_append(m,1,0); CHECK(matter_im_subscribe_events_changed(m->engine)==MATTER_OK); multi_update(m,1000);
    /* Snapshot at start of report; append during flight stays for the next one. */
    multi_report(m); CHECK(m->events==1 && m->numbers[0]==0 && m->more);
    multi_append(m,1,0); CHECK(matter_im_subscribe_events_changed(m->engine)==MATTER_OK);
    multi_confirm(m); multi_receive(m,false); multi_process(m); multi_drain(m);
    CHECK(m->events==2 && m->numbers[1]==2);
    CHECK(matter_im_subscribe_deadline(m->engine,&deadline)==MATTER_OK && deadline==2000);
    m->now=2000; CHECK(matter_im_subscribe_process(m->engine,2000)==MATTER_PENDING && matter_im_subscribe_state(m->engine)==MATTER_IM_SUB_NEED_EXCHANGE);
    Matter_Exchange_Info_T e={1,14,true}; CHECK(matter_im_subscribe_bind_report(m->engine,&e,2000)==MATTER_OK); multi_process(m);
    m->events=0; multi_report(m); CHECK(m->events==1 && m->numbers[0]==3 && !m->more); multi_free(m);
    static const uint32_t invalid[]={99,99}; m=multi_new(); multi_request(m,0,invalid,2,0,0); multi_start(m);
    CHECK(m->opcode==1 && m->out[3]==MATTER_IM_INVALID_ACTION); multi_free(m);
    static const uint32_t partial[]={99,1}; m=multi_new(); multi_request(m,1,partial,2,2,0); multi_start(m); multi_drain(m);
    CHECK(m->statuses==1 && m->attributes==1);
    multi_append(m,1,0); CHECK(matter_im_subscribe_events_changed(m->engine)==MATTER_OK); multi_update(m,1000); multi_drain(m);
    CHECK(m->events==1 && !m->statuses && !m->attributes); multi_free(m);
    puts("PASS multi-event Subscribe: per-path urgency, watermark after whole report, in-flight append and all-invalid prime");
    /* Reboot barrier: IM Success alone cannot confirm a reliable event report. */
    Matter_Event_Path_T path={0,0x28,1},other={0,0x28,9};
    CHECK(!matter_im_subscribe_event_pending(NULL,&path,0));
    m=multi_new(); multi_request(m,0,ids,1,1,0); multi_start(m); multi_drain(m);
    CHECK(!matter_im_subscribe_event_pending(m->engine,NULL,0));
    uint64_t number=0; CHECK(matter_events_position(m->log,&number)==MATTER_OK);
    multi_append(m,1,0); CHECK(matter_im_subscribe_events_changed(m->engine)==MATTER_OK);
    CHECK(matter_im_subscribe_event_pending(m->engine,&path,number));
    CHECK(!matter_im_subscribe_event_pending(m->engine,&other,number));
    CHECK(matter_im_subscribe_process(m->engine,999)==MATTER_PENDING && matter_im_subscribe_state(m->engine)==MATTER_IM_SUB_IDLE);
    CHECK(matter_im_subscribe_event_pending(m->engine,&path,number));
    multi_update(m,1000); multi_report(m); CHECK(m->events==1 && !m->more);
    CHECK(matter_im_subscribe_sent_at(m->engine,1000)==MATTER_OK);
    multi_receive(m,false); CHECK(matter_im_subscribe_process(m->engine,1000)==MATTER_PENDING);
    CHECK(matter_im_subscribe_event_pending(m->engine,&path,number));
    CHECK(matter_im_subscribe_confirm(m->engine,1000)==MATTER_OK);
    CHECK(matter_im_subscribe_process(m->engine,1000)==MATTER_PENDING);
    CHECK(!matter_im_subscribe_event_pending(m->engine,&path,number));
    multi_append(m,1,0); CHECK(matter_im_subscribe_event_pending(m->engine,&path,number+1));
    CHECK(matter_im_subscribe_cancel(m->engine)==MATTER_OK);
    CHECK(!matter_im_subscribe_event_pending(m->engine,&path,number+1)); multi_free(m);
    m=multi_new(); multi_append(m,1,0); multi_request(m,0,ids,1,1,100); multi_start(m); multi_drain(m);
    CHECK(!matter_im_subscribe_event_pending(m->engine,&path,0)); multi_free(m);
    puts("PASS event delivery barrier: min interval, unrelated path, EventMin, IM-before-MRP, confirmed cursor and cancel");
}
#endif
#undef MultiEngine
