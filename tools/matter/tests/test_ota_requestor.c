#include "clusters/matter_ota_requestor.h"
#include "model/matter_im_subscribe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"OTA line %d: %s\n",__LINE__,#x); exit(1); } } while(0)
#ifdef MATTER_TEST_ALLOC
#include "test_alloc_bytes.h"
#endif
typedef struct {
    Matter_Ota_Provider_T defaults[5]; uint64_t generations[6],high; bool fail,accept,event_fail,reenter,load_fail;
    Matter_Ota_Offer_T last; unsigned selected,stored,deny_after; Matter_Cluster_T cluster;
    Matter_Tlv_Writer_T writer; Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T element;
    Matter_Im_Read_T read; Matter_Im_Subscribe_T sub; uint64_t clock;
    uint8_t expected[256],held[112]; size_t starts[5],sizes[5];
    unsigned seen[2],replaces[2],adds[2],reads,releases; uint32_t report_version;
    uint8_t bytes[1024],metadata[513]; size_t size; Matter_Event_Record_T records[16];
} Test;
static void provider_reentry(Test* t) {
    if(!t->reenter || !t->cluster) return;
    Matter_Ota_Provider_T out; const Matter_Cluster_Request_T q={.is_case=true,.fabric=1}; Matter_Im_Value_T value;
    CHECK(matter_ota_requestor_selected(t->cluster,&out)==MATTER_BUSY);
    CHECK(matter_ota_requestor_state(t->cluster,true,4,1,0,1,0)==MATTER_BUSY);
    CHECK(matter_ota_requestor_applied(t->cluster,1,1,0)==MATTER_BUSY);
    CHECK(matter_ota_requestor_error(t->cluster,1,1,1,NULL,0)==MATTER_BUSY);
    CHECK(matter_cluster_read(t->cluster,0,&q,&value)==MATTER_IM_FAILURE);
    CHECK(matter_cluster_delete(t->cluster)==MATTER_BUSY);
}
static Matter_Result_T load(void* u,Matter_Ota_Provider_T out[5]) { Test* t=u; provider_reentry(t); if(t->load_fail) return MATTER_PORT_ERROR; memcpy(out,t->defaults,sizeof(t->defaults)); return MATTER_OK; }
static Matter_Result_T store(void* u,uint8_t fabric,const Matter_Ota_Provider_T* p) {
    Test* t=u; provider_reentry(t); if(t->fail) return MATTER_PORT_ERROR; ++t->stored;
    t->defaults[fabric-1]=p?*p:(Matter_Ota_Provider_T){0}; return MATTER_OK;
}
static uint64_t generation(void* u,uint8_t fabric) { return fabric<6?((Test*)u)->generations[fabric]:0; }
static bool select_provider(void* u,const Matter_Ota_Offer_T* offer) {
    Test* t=u; provider_reentry(t); ++t->selected; t->last=*offer; Matter_Ota_Provider_T p;
    CHECK(matter_ota_requestor_selected(t->cluster,&p)==MATTER_BUSY); return t->accept;
}
static Matter_Result_T event_load(void* u,uint64_t* v) { *v=((Test*)u)->high; return MATTER_OK; }
static Matter_Result_T event_store(void* u,uint64_t v) { Test* t=u; provider_reentry(t); if(t->event_fail) return MATTER_PORT_ERROR; t->high=v; return MATTER_OK; }
static void put(Test* t,Matter_Tlv_Type_T type,int tag,uint64_t v,const void* data,size_t size) {
    t->element=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(unsigned)tag},.unsigned_value=v,.data=data,.size=size};
    CHECK(matter_tlv_write(&t->writer,&t->element,0)==MATTER_TLV_OK);
}
static void begin(Test* t,Matter_Tlv_Type_T type) { CHECK(matter_tlv_writer_init(&t->writer,t->bytes,sizeof(t->bytes),4)==MATTER_TLV_OK); put(t,type,-1,0,NULL,0); }
static void end(Test* t) { put(t,MATTER_TLV_END,-1,0,NULL,0); CHECK(matter_tlv_writer_finish(&t->writer,&t->size)==MATTER_TLV_OK); }
static void provider(Test* t,uint64_t node,uint16_t ep) {
    put(t,MATTER_TLV_STRUCTURE,-1,0,NULL,0); put(t,MATTER_TLV_UNSIGNED,1,node,NULL,0); put(t,MATTER_TLV_UNSIGNED,2,ep,NULL,0);
    put(t,MATTER_TLV_UNSIGNED,254,5,NULL,0); put(t,MATTER_TLV_END,-1,0,NULL,0);
}
static uint8_t write_list(Test* t,Matter_Cluster_Request_T* q,unsigned count,uint64_t node) {
    begin(t,MATTER_TLV_ARRAY); for(unsigned i=0;i<count;++i) provider(t,node,0); end(t);
    return matter_cluster_write_list(t->cluster,0,q,MATTER_IM_LIST_REPLACE,t->bytes,t->size).status;
}
static uint8_t announce(Test* t,Matter_Cluster_Request_T* q,uint64_t node,uint8_t reason,size_t metadata_size) {
    begin(t,MATTER_TLV_STRUCTURE); put(t,MATTER_TLV_UNSIGNED,0,node,NULL,0); put(t,MATTER_TLV_UNSIGNED,1,0x1234,NULL,0);
    put(t,MATTER_TLV_UNSIGNED,2,reason,NULL,0); if(metadata_size) put(t,MATTER_TLV_BYTES,3,0,t->metadata,metadata_size);
    put(t,MATTER_TLV_UNSIGNED,4,1,NULL,0); end(t);
    Matter_Im_Command_Result_T out; uint64_t token;
    CHECK(matter_cluster_start(t->cluster,0,q,t->bytes,t->size,&t->writer,&out,&token)==MATTER_OK && !token); return out.status;
}
static size_t providers(Test* t,Matter_Cluster_Request_T* q) {
    Matter_Im_Value_T v; CHECK(!matter_cluster_read(t->cluster,0,q,&v));
    CHECK(matter_tlv_init(&t->reader,v.data,v.size,4)==MATTER_TLV_OK); size_t count=0;
    while(matter_tlv_next(&t->reader,&t->element)==MATTER_TLV_OK) if(t->element.type==MATTER_TLV_STRUCTURE) {
        ++count; CHECK(matter_tlv_skip_container(&t->reader)==MATTER_TLV_OK);
    }
    return count;
}
static uint8_t im_auth(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* path,Matter_Im_Privilege_T privilege) {
    (void)session; (void)path; (void)privilege; Test* t=u;
    return t->deny_after && t->stored>=t->deny_after?MATTER_IM_UNSUPPORTED_ACCESS:0;
}
static Matter_Result_T im_fabric(void* u,Matter_Exchange_Session_T session,uint8_t* out) { (void)u; (void)session; *out=1; return MATTER_OK; }
static uint8_t im_describe(void* u,const Matter_Im_Path_T* path,Matter_Im_Write_Attribute_T* out) { return matter_cluster_describe_write(((Test*)u)->cluster,path->attribute,out); }
static Matter_Result_T im_version(void* u,const Matter_Im_Path_T* path,uint32_t* out) { (void)path; return matter_cluster_version(((Test*)u)->cluster,out); }
static uint8_t im_validate(void* u,const Matter_Im_Path_T* path,const uint8_t* d,size_t n) { (void)u; (void)path; (void)d; (void)n; return MATTER_IM_UNSUPPORTED_WRITE; }
static Matter_Im_Write_Result_T im_write(void* u,const Matter_Im_Path_T* path,const uint8_t* d,size_t n) {
    return (Matter_Im_Write_Result_T){.status=im_validate(u,path,d,n)};
}
static uint8_t im_validate_list(void* u,const Matter_Im_Path_T* path,Matter_Im_List_Change_T op,const uint8_t* d,size_t n) {
    Matter_Cluster_Request_T q={.is_case=true,.fabric=1}; return matter_cluster_validate_list(((Test*)u)->cluster,path->attribute,&q,op,d,n);
}
static Matter_Im_Write_Result_T im_write_list(void* u,const Matter_Im_Path_T* path,Matter_Im_List_Change_T op,const uint8_t* d,size_t n) {
    Matter_Cluster_Request_T q={.is_case=true,.fabric=1}; return matter_cluster_write_list(((Test*)u)->cluster,path->attribute,&q,op,d,n);
}
static void multi_tests(Test* t) {
    for(unsigned mode=0;mode<12;++mode) {
        Matter_Cluster_Request_T q={.is_case=true,.fabric=1}; CHECK(!write_list(t,&q,1,100));
        unsigned stored=t->stored; uint32_t dv; CHECK(matter_cluster_version(t->cluster,&dv)==MATTER_OK);
        unsigned blocks=mode==8?5:mode==5?3:2;
        begin(t,MATTER_TLV_STRUCTURE);
        if(mode==9) put(t,MATTER_TLV_BOOL,0,1,NULL,0);
        put(t,MATTER_TLV_BOOL,1,0,NULL,0); put(t,MATTER_TLV_ARRAY,2,0,NULL,0);
        for(unsigned i=0;i<blocks;++i) {
            put(t,MATTER_TLV_STRUCTURE,-1,0,NULL,0);
            if(mode==4) put(t,MATTER_TLV_UNSIGNED,0,dv,NULL,0);
            put(t,MATTER_TLV_LIST,1,0,NULL,0); put(t,MATTER_TLV_UNSIGNED,2,i && mode==2?1:0,NULL,0);
            put(t,MATTER_TLV_UNSIGNED,3,mode==7?0x1234:0x2a,NULL,0); put(t,MATTER_TLV_UNSIGNED,4,0,NULL,0);
            if(i) put(t,mode==6?MATTER_TLV_UNSIGNED:MATTER_TLV_NULL,5,0,NULL,0);
            put(t,MATTER_TLV_END,-1,0,NULL,0);
            put(t,i?MATTER_TLV_STRUCTURE:MATTER_TLV_ARRAY,2,0,NULL,0);
            if(i) { put(t,MATTER_TLV_UNSIGNED,1,mode==10?0:112233,NULL,0); put(t,MATTER_TLV_UNSIGNED,2,0,NULL,0); }
            put(t,MATTER_TLV_END,-1,0,NULL,0); put(t,MATTER_TLV_END,-1,0,NULL,0);
        }
        put(t,MATTER_TLV_END,-1,0,NULL,0);
        if(mode==11) put(t,MATTER_TLV_BOOL,3,1,NULL,0);
        put(t,MATTER_TLV_UNSIGNED,255,13,NULL,0); end(t);
        Matter_Im_Write_Port_T p={t,im_auth,im_describe,im_version,im_validate,im_write,im_validate_list,im_write_list};
        Matter_Im_Read_Fabric_Port_T fabric={im_fabric};
        Matter_Im_Write_Config_T cfg={{1,123,false},1000,mode==1?8:256,false};
        Matter_Im_Write_T im=matter_im_write_new_case(&p,&fabric,&cfg,0); CHECK(im);
        if(mode==3) t->deny_after=stored+1;
        Matter_Rx_Decision_T rx={.action=MATTER_RX_NEW_RESPONDER,.session=1,.header={.protocol_id=1,.opcode=6,.exchange_id=123,.exchange_flags=5},.payload=t->bytes,.payload_size=t->size};
        CHECK(matter_im_write_receive_at(im,&rx,0)==MATTER_OK);
        CHECK(matter_im_write_process(im,0)==(mode==9?MATTER_OK:MATTER_PENDING));
        bool shape_error=mode==1 || mode==2 || mode==6 || mode==8;
        CHECK(t->stored==stored+(shape_error || mode==7?0:mode==3 || mode==4 || mode==10?1:2)); t->deny_after=0;
        if(mode!=9) {
            Matter_Im_Write_Message_T out; CHECK(matter_im_write_output(im,&out)==MATTER_OK && out.opcode==(shape_error?1:7));
            CHECK(matter_tlv_init(&t->reader,out.data,out.size,8)==MATTER_TLV_OK); unsigned statuses=0;
            while(matter_tlv_next(&t->reader,&t->element)==MATTER_TLV_OK) {
                if(t->element.type!=MATTER_TLV_UNSIGNED || t->element.tag.control!=1 || t->element.tag.number!=0) continue;
                uint64_t expected=mode==7?MATTER_IM_INVALID_ACTION:shape_error?(mode==1 || mode==8?MATTER_IM_RESOURCE_EXHAUSTED:MATTER_IM_INVALID_ACTION):
                    statuses==1 && mode==3?MATTER_IM_UNSUPPORTED_ACCESS:statuses==1 && mode==4?MATTER_IM_DATA_VERSION_MISMATCH:
                    (statuses==2 && mode==5) || (statuses==1 && mode==10)?MATTER_IM_CONSTRAINT_ERROR:0;
                CHECK(t->element.unsigned_value==expected); ++statuses;
            }
            CHECK(statuses==(shape_error?1:blocks));
            unsigned effects=t->stored; CHECK(matter_im_write_process(im,1)==MATTER_PENDING && t->stored==effects);
            CHECK(matter_im_write_sent_at(im,1)==MATTER_OK && matter_im_write_confirm(im,2)==MATTER_OK);
            CHECK(matter_im_write_state(im)==(mode==11?MATTER_IM_WRITE_WAIT_CHUNK:MATTER_IM_WRITE_COMPLETE));
        }
        CHECK(matter_im_write_delete(im)==MATTER_OK);
    }
    puts("PASS OTA multi-IB Write: 12 scenarios, per-IB status/version/access, partial failure, all-shape/capacity preflight, bounds, suppression and chunk lifecycle");
}
static const uint8_t report_read[]={0x15,0x36,0,0x17,0x24,2,0,0x24,3,0x2a,0x24,4,0,0x18,0x18,0x28,3,0x24,255,13,0x18};
static const uint8_t report_sub[]={0x15,0x29,0,0x24,1,2,0x24,2,5,0x36,3,0x17,0x24,2,0,0x24,3,0x2a,0x24,4,0,0x18,0x18,0x28,7,0x24,255,13,0x18};
static const uint8_t report_ok[]={0x15,0x24,0,0,0x24,255,13,0x18};
static Matter_Im_Status_T report_allow(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* path,Matter_Im_Privilege_T privilege) {
    (void)u; CHECK(session==1 && !path->endpoint && path->cluster==0x2a && !path->attribute && privilege==MATTER_IM_VIEW); return 0;
}
static Matter_Im_Status_T report_describe(void* u,const Matter_Im_Path_T* path,Matter_Im_Attribute_T* access) {
    (void)u; CHECK(!path->attribute); *access=(Matter_Im_Attribute_T){MATTER_IM_VIEW,false}; return 0;
}
static Matter_Im_Status_T report_read_value(void* u,const Matter_Im_Path_T* path,bool filtered,Matter_Im_Value_T* out) {
    Test* t=u; CHECK(!filtered && !path->attribute); ++t->reads;
    const Matter_Cluster_Request_T q={.is_case=true,.fabric=1,.filtered=false};
    return matter_cluster_read(t->cluster,0,&q,out);
}
static uint8_t report_reserve(void* u,Matter_Exchange_Session_T session,bool keep,uint32_t* id) {
    (void)u; CHECK(session==1 && keep); *id=42; return 0;
}
static void report_release(void* u,uint32_t id) { Test* t=u; CHECK(id==42 && !t->releases++); }
static void report_receive(Test* t,unsigned which,uint8_t opcode,const uint8_t* data,size_t size) {
    Matter_Rx_Decision_T rx={.action=MATTER_RX_EXISTING,.session=1,
        .header={.protocol_id=1,.opcode=opcode,.exchange_id=(uint16_t)(12+which),.exchange_flags=1},.payload=data,.payload_size=size};
    CHECK(!(which?matter_im_subscribe_receive(t->sub,&rx):matter_im_read_receive(t->read,&rx)));
}
static void report_process(Test* t,unsigned which) {
    CHECK((which?matter_im_subscribe_process(t->sub,++t->clock):matter_im_read_process(t->read,++t->clock))==MATTER_PENDING);
}
static Matter_Im_Read_Message_T report_output(Test* t,unsigned which) {
    Matter_Im_Read_Message_T out; report_process(t,which);
    CHECK(!(which?matter_im_subscribe_output(t->sub,&out):matter_im_read_output(t->read,&out))); return out;
}
static void report_mutate(Test* t) {
    for(unsigned i=0;i<5;++i) ++t->defaults[i].node;
    CHECK(matter_cluster_process(t->cluster,t->clock)==MATTER_OK);
    const Matter_Cluster_Request_T q={.is_case=true,.fabric=1}; Matter_Im_Value_T value;
    CHECK(!matter_cluster_read(t->cluster,0,&q,&value));
    CHECK(!matter_cluster_read(t->cluster,2,&q,&value)); /* Release provider encoding. */
}
static bool report_check(Test* t,unsigned which,Matter_Im_Read_Message_T out) {
    CHECK(out.opcode==5 && out.size<=sizeof(t->held)); memcpy(t->held,out.data,out.size);
    report_mutate(t); CHECK(!memcmp(t->held,out.data,out.size));
    CHECK(!matter_tlv_init(&t->reader,out.data,out.size,8)); unsigned depth=0; bool more=false,append=false; Matter_Tlv_Result_T r;
    while((r=matter_tlv_next(&t->reader,&t->element))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&t->element;
        if(e->type==MATTER_TLV_END) { CHECK(depth); --depth; continue; }
        if(depth==1 && e->tag.number==3) more=e->unsigned_value!=0;
        if(depth==4 && e->tag.number==0) CHECK(e->type==MATTER_TLV_UNSIGNED && e->unsigned_value==t->report_version);
        if(depth==4 && e->tag.number==1) append=false;
        if(depth==5 && e->tag.number==5) { CHECK(e->type==MATTER_TLV_NULL); append=true; }
        if(depth==4 && e->tag.number==2 && e->type==MATTER_TLV_ARRAY) CHECK(!append && !t->replaces[which]++);
        if(e->type==MATTER_TLV_STRUCTURE && ((depth==5 && !e->tag.control) || (depth==4 && e->tag.control==1 && e->tag.number==2))) {
            unsigned n=t->seen[which]++; CHECK(n<5 && t->replaces[which]==1); size_t start=e->offset,header=depth==4?2:1;
            if(depth==4) { CHECK(append); ++t->adds[which]; }
            CHECK(!matter_tlv_skip_container(&t->reader) && t->reader.offset-start==t->sizes[n]+header-1);
            CHECK(!memcmp(out.data+start+header,t->expected+t->starts[n]+1,t->sizes[n]-1)); continue;
        }
        if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) ++depth;
    }
    CHECK(r==MATTER_TLV_DONE && !depth); return more;
}
static void report_ack(Test* t,unsigned which,bool more,bool im_first) {
    CHECK(!(which?matter_im_subscribe_sent_at(t->sub,t->clock):matter_im_read_sent(t->read)));
    if((which || more) && im_first) { report_receive(t,which,1,report_ok,sizeof(report_ok)); report_process(t,which); }
    CHECK(!(which?matter_im_subscribe_confirm(t->sub,t->clock):matter_im_read_confirm(t->read,t->clock)));
    if((which || more) && !im_first) report_receive(t,which,1,report_ok,sizeof(report_ok));
}
static void report_tests(unsigned order) {
    Test* t=calloc(1,sizeof(*t)); CHECK(t); t->accept=true;
    for(unsigned i=0;i<5;++i) { t->generations[i+1]=i+1; t->defaults[i]=(Matter_Ota_Provider_T){UINT64_C(0xffffff0000000000)+i,65534,(uint8_t)(i+1)}; }
    Matter_Events_Port_T ep={t,event_load,event_store}; Matter_Events_T events=matter_events_new(&ep); CHECK(events);
    Matter_Ota_Requestor_Port_T port={t,load,store,generation,select_provider}; t->cluster=matter_ota_requestor_new(&port,events,7,false); CHECK(t->cluster);
    Matter_Cluster_Request_T q={.is_case=true,.fabric=1}; Matter_Im_Value_T value;
    CHECK(!matter_cluster_read(t->cluster,0,&q,&value) && value.size<=sizeof(t->expected)); t->report_version=value.data_version;
    memcpy(t->expected,value.data,value.size); CHECK(!matter_tlv_init(&t->reader,t->expected,value.size,4)); CHECK(!matter_tlv_next(&t->reader,&t->element));
    for(unsigned i=0;i<5;++i) {
        CHECK(!matter_tlv_next(&t->reader,&t->element) && t->element.type==MATTER_TLV_STRUCTURE); t->starts[i]=t->element.offset;
        CHECK(!matter_tlv_skip_container(&t->reader)); t->sizes[i]=t->reader.offset-t->starts[i];
    }
    Matter_Im_Read_Port_T p={t,report_allow,report_describe,report_read_value,NULL,NULL}; Matter_Im_Read_Config_T cfg={{1,12,false},30000,sizeof(t->held),true};
    t->read=matter_im_read_new(&p,&cfg,0); CHECK(t->read); cfg.exchange.exchange_id=13;
    Matter_Im_Subscribe_Port_T sp={p,report_reserve,report_release}; t->sub=matter_im_subscribe_new(&sp,&cfg,0); CHECK(t->sub);
    report_receive(t,0,2,report_read,sizeof(report_read)); report_receive(t,1,3,report_sub,sizeof(report_sub));
    Matter_Im_Read_Message_T first=report_output(t,0),second=report_output(t,1); CHECK(t->reads==2);
    for(unsigned which=0;which<2;++which) {
        Matter_Im_Read_Message_T out=which?second:first; unsigned chunks=0; bool more;
        do { more=report_check(t,which,out); report_ack(t,which,more,(++chunks+order)%2!=0); if(more) out=report_output(t,which); } while(more);
        CHECK(chunks>1 && t->seen[which]==5 && t->replaces[which]==1 && t->adds[which] && t->reads==2);
    }
    CHECK(matter_im_read_state(t->read)==MATTER_IM_READ_COMPLETE); CHECK(report_output(t,1).opcode==4);
    CHECK(!matter_im_subscribe_sent_at(t->sub,t->clock) && !matter_im_subscribe_confirm(t->sub,t->clock));
    CHECK(matter_im_subscribe_state(t->sub)==MATTER_IM_SUB_IDLE);
    CHECK(!matter_im_read_delete(t->read) && !matter_im_subscribe_delete(t->sub) && !matter_cluster_delete(t->cluster) && !matter_events_delete(events)); free(t);
#ifdef MATTER_TEST_ALLOC
    CHECK(!live && !live_bytes);
#endif
    puts("PASS OTA reports: concurrent multipart Read/Subscribe, five fabrics, provider mutation/free, immutable values/version and both ACK orders");
}
#ifdef MATTER_TEST_ALLOC
static void memory_tests(void) {
    Test* t=calloc(1,sizeof(*t)); CHECK(t); t->accept=true;
    for(unsigned i=1;i<=5;++i) t->generations[i]=i;
    Matter_Events_Port_T ep={t,event_load,event_store}; Matter_Events_T events=matter_events_new(&ep); CHECK(events);
    Matter_Ota_Requestor_Port_T port={t,load,store,generation,select_provider};
    t->cluster=matter_ota_requestor_new(&port,events,1,false); CHECK(t->cluster);
    Matter_Cluster_Request_T q={.is_case=true,.fabric=1}; Matter_Im_Value_T v;
    t->reenter=true; size_t idle=live_bytes,base_calls=calls; uint32_t dv;
    for(unsigned i=0;i<20;++i) CHECK(matter_cluster_process(t->cluster,i)==MATTER_OK);
    CHECK(calls==base_calls && live_bytes==idle);
    for(unsigned i=1;i<=3;++i) {
        fail_at=calls+i; CHECK(announce(t,&q,100,0,0)==MATTER_IM_RESOURCE_EXHAUSTED); fail_at=0;
        CHECK(live_bytes==idle && matter_cluster_process(t->cluster,20)==MATTER_OK && !t->selected);
    }
    for(unsigned i=1;i<=2;++i) {
        CHECK(matter_cluster_version(t->cluster,&dv)==MATTER_OK);
        fail_at=calls+i; CHECK(write_list(t,&q,1,100)==MATTER_IM_RESOURCE_EXHAUSTED); fail_at=0;
        uint32_t after; CHECK(matter_cluster_version(t->cluster,&after)==MATTER_OK && after==dv && !t->stored && live_bytes==idle);
    }
    CHECK(!write_list(t,&q,1,100));
    fail_at=calls+1; CHECK(matter_cluster_process(t->cluster,21)==MATTER_OK); fail_at=0;
    CHECK(!t->selected && live_bytes==idle);
    CHECK(matter_cluster_process(t->cluster,22)==MATTER_OK && t->selected==1 && live_bytes==idle);
    size_t before=calls; CHECK(matter_cluster_process(t->cluster,23)==MATTER_OK && calls==before);
    const uint32_t arrays[]={0,0xfff8,0xfff9,0xfffb};
    for(unsigned i=0;i<4;++i) {
        fail_at=calls+1; CHECK(matter_cluster_read(t->cluster,arrays[i],&q,&v)==MATTER_IM_RESOURCE_EXHAUSTED); fail_at=0;
        CHECK(live_bytes==idle && !matter_cluster_read(t->cluster,arrays[i],&q,&v) && v.size<=256);
        CHECK(!matter_cluster_read(t->cluster,2,&q,&v) && live_bytes==idle);
    }
    /* Five independent pending offers, latest wins, immutable metadata copy. */
    t->metadata[0]=0x17; t->metadata[1]=0x18;
    for(unsigned i=1;i<=5;++i) { q.fabric=(uint8_t)i; CHECK(!announce(t,&q,200+i,2,2)); }
    size_t queued=live_bytes; CHECK(queued==idle+5*sizeof(Matter_Ota_Offer_T));
    unsigned before_selection=t->selected; t->load_fail=true;
    CHECK(matter_cluster_process(t->cluster,24)==MATTER_PORT_ERROR && t->selected==before_selection && live_bytes==queued);
    t->load_fail=false;
    q.fabric=5; CHECK(!announce(t,&q,300,1,2) && live_bytes==queued);
    memset(t->bytes,0,sizeof(t->bytes)); t->metadata[0]=0;
    unsigned selected=t->selected; CHECK(matter_cluster_process(t->cluster,24)==MATTER_OK && t->selected==selected+5);
    CHECK(t->last.provider.node==300 && t->last.metadata[0]==0x17 && live_bytes==idle);
    CHECK(!announce(t,&q,400,0,0));
    for(unsigned i=1;i<=2;++i) {
        fail_at=calls+i; CHECK(announce(t,&q,401,0,0)==MATTER_IM_RESOURCE_EXHAUSTED); fail_at=0;
        CHECK(live_bytes==idle+sizeof(Matter_Ota_Offer_T));
    }
    selected=t->selected; CHECK(matter_cluster_process(t->cluster,25)==MATTER_OK && t->selected==selected+1 && t->last.provider.node==400);
    CHECK(!announce(t,&q,402,0,0)); t->generations[5]=0; selected=t->selected;
    CHECK(matter_cluster_process(t->cluster,25)==MATTER_OK && t->selected==selected && live_bytes==idle);
    /* Encoding and log-node failures must leave state/version/events untouched. */
    for(unsigned i=1;i<=2;++i) {
        CHECK(matter_cluster_version(t->cluster,&dv)==MATTER_OK); fail_at=calls+i;
        CHECK(matter_ota_requestor_state(t->cluster,true,4,20,1,9,26)==MATTER_LIMIT_REACHED); fail_at=0;
        uint32_t after; CHECK(matter_cluster_version(t->cluster,&after)==MATTER_OK && after==dv);
        CHECK(!matter_cluster_read(t->cluster,2,&q,&v) && v.unsigned_value==1 && live_bytes==idle);
        Matter_Event_Path_T path={0,MATTER_OTA_REQUESTOR_CLUSTER,0}; size_t n;
        CHECK(matter_events_copy(events,&path,0,t->records,&n)==MATTER_OK && !n);
        fail_at=calls+i; CHECK(matter_ota_requestor_applied(t->cluster,9,1,27)==MATTER_LIMIT_REACHED); fail_at=0;
        int64_t code=-9; fail_at=calls+i;
        CHECK(matter_ota_requestor_error(t->cluster,9,UINT64_MAX,-1,&code,28)==MATTER_LIMIT_REACHED); fail_at=0;
        CHECK(live_bytes==idle);
    }
    CHECK(matter_ota_requestor_state(t->cluster,true,4,20,1,9,29)==MATTER_OK);
    before=calls; CHECK(matter_ota_requestor_state(t->cluster,true,4,21,1,9,30)==MATTER_OK && calls==before);
    CHECK(matter_cluster_delete(t->cluster)==MATTER_OK && matter_events_delete(events)==MATTER_OK && !live && !live_bytes);
    printf("PASS OTA demand memory: idle=%zu queued5=%zu peak=%zu largest=%zu; parse/queue/read/event OOM, retry and atomicity\n",idle,queued,peak_bytes,max_request); free(t);
}
#endif
int main(void) {
    Test* t=calloc(1,sizeof(*t)); CHECK(t); t->accept=true;
    for(unsigned i=1;i<6;++i) t->generations[i]=i;
    Matter_Events_Port_T ep={t,event_load,event_store}; Matter_Events_T events=matter_events_new(&ep); CHECK(events);
    Matter_Ota_Requestor_Port_T p={t,load,store,generation,select_provider};
#ifdef MATTER_TEST_ALLOC
    size_t baseline=live;
    for(unsigned i=1;i<=2;++i) { fail_at=calls+i; CHECK(!matter_ota_requestor_new(&p,events,7,false)); fail_at=0; CHECK(live==baseline); }
#endif
    t->cluster=matter_ota_requestor_new(&p,events,7,false); CHECK(t->cluster);
    Matter_Cluster_Request_T q={.is_case=true,.fabric=1,.filtered=true}; Matter_Im_Value_T v;
    Matter_Im_Write_Attribute_T wa; CHECK(!matter_cluster_describe_write(t->cluster,0,&wa) && wa.privilege==MATTER_IM_ADMINISTER && wa.fabric_scoped && wa.list);
    Matter_Im_Command_T ca; CHECK(!matter_cluster_command(t->cluster,0,&ca) && ca.privilege==MATTER_IM_ADMINISTER && !ca.timed);
    CHECK(matter_cluster_attribute_count(t->cluster)==9 && matter_cluster_event_count(t->cluster)==3);
    CHECK(!matter_cluster_read(t->cluster,1,&q,&v) && v.type==MATTER_TLV_BOOL && !v.unsigned_value);
    CHECK(!matter_cluster_read(t->cluster,2,&q,&v) && v.unsigned_value==1);
    CHECK(!matter_cluster_read(t->cluster,3,&q,&v) && v.type==MATTER_TLV_NULL);
    CHECK(!providers(t,&q)); q.is_case=false;
    CHECK(write_list(t,&q,1,100)==MATTER_IM_UNSUPPORTED_ACCESS && announce(t,&q,100,0,0)==MATTER_IM_UNSUPPORTED_ACCESS);
    q.is_case=true; q.fabric=0; CHECK(announce(t,&q,100,0,0)==MATTER_IM_UNSUPPORTED_ACCESS); q.fabric=1;
    uint32_t dv; CHECK(matter_cluster_version(t->cluster,&dv)==MATTER_OK && dv==7);
    t->fail=true; CHECK(write_list(t,&q,1,100)==MATTER_IM_FAILURE); t->fail=false;
    CHECK(matter_cluster_version(t->cluster,&dv)==MATTER_OK && dv==7 && !t->stored);
    CHECK(write_list(t,&q,2,100)==MATTER_IM_CONSTRAINT_ERROR && write_list(t,&q,1,0)==MATTER_IM_CONSTRAINT_ERROR);
    CHECK(!write_list(t,&q,1,100) && t->defaults[0].fabric==1 && !t->selected);
    CHECK(matter_cluster_process(t->cluster,0)==MATTER_OK && t->selected==1 && !t->last.announced);
    CHECK(matter_cluster_process(t->cluster,1)==MATTER_OK && t->selected==1);
    CHECK(matter_cluster_version(t->cluster,&dv)==MATTER_OK && dv==8);
    CHECK(!write_list(t,&q,1,100)); CHECK(matter_cluster_version(t->cluster,&dv)==MATTER_OK && dv==8);
    for(unsigned i=2;i<=5;++i) { q.fabric=(uint8_t)i; CHECK(!write_list(t,&q,1,100+i)); }
    CHECK(providers(t,&q)==1); q.filtered=false; CHECK(providers(t,&q)==5); q.filtered=true; q.fabric=1;
    /* ADD cannot create a second default for a fabric. */
    CHECK(matter_tlv_writer_init(&t->writer,t->bytes,sizeof(t->bytes),4)==MATTER_TLV_OK); provider(t,999,0);
    CHECK(matter_tlv_writer_finish(&t->writer,&t->size)==MATTER_TLV_OK);
    CHECK(matter_cluster_write_list(t->cluster,0,&q,MATTER_IM_LIST_ADD,t->bytes,t->size).status==MATTER_IM_CONSTRAINT_ERROR);
    CHECK(announce(t,&q,0,0,0)==MATTER_IM_INVALID_COMMAND && announce(t,&q,200,3,0)==MATTER_IM_INVALID_COMMAND);
    /* Exactly 512 bytes, a qualified vendor field; the outer command copies it. */
    CHECK(matter_tlv_writer_init(&t->writer,t->metadata,sizeof(t->metadata),4)==MATTER_TLV_OK);
    put(t,MATTER_TLV_LIST,-1,0,NULL,0);
    t->element=(Matter_Tlv_Element_T){.type=MATTER_TLV_BYTES,.tag={.control=6,.vendor=0x1234,.profile=1,.number=1},.data=t->bytes,.size=501};
    CHECK(matter_tlv_write(&t->writer,&t->element,0)==MATTER_TLV_OK); end(t); CHECK(t->size==512);
    CHECK(!announce(t,&q,200,1,512));
    CHECK(announce(t,&q,200,1,513)==MATTER_IM_INVALID_COMMAND);
    t->metadata[0]=0x15; t->metadata[1]=0x18; CHECK(announce(t,&q,200,1,2)==MATTER_IM_INVALID_COMMAND); /* Structure is not list. */
    t->metadata[0]=0x17; CHECK(!announce(t,&q,200,2,2)); memset(t->bytes,0,sizeof(t->bytes));
    CHECK(matter_cluster_process(t->cluster,2)==MATTER_OK && t->defaults[0].node==100);
    Matter_Ota_Provider_T selected; CHECK(matter_ota_requestor_selected(t->cluster,&selected)==MATTER_OK);
    /* Other fabric defaults may be offered later; require announcement was copied by isolating next process. */
    CHECK(!announce(t,&q,201,1,2)); t->metadata[0]=0;
    CHECK(matter_cluster_process(t->cluster,3)==MATTER_OK && t->last.announced && t->last.provider.node==201 && t->last.metadata[0]==0x17);
    CHECK(!announce(t,&q,202,0,0)); unsigned count=t->selected;
    t->generations[1]=0; t->defaults[0]=(Matter_Ota_Provider_T){0};
    CHECK(matter_cluster_process(t->cluster,4)==MATTER_OK && t->selected==count && matter_ota_requestor_selected(t->cluster,&selected)==MATTER_INVALID_STATE);
    t->generations[1]=6; CHECK(matter_cluster_process(t->cluster,5)==MATTER_OK && t->selected==count);
    t->accept=false; CHECK(!announce(t,&q,203,0,0)); CHECK(matter_cluster_process(t->cluster,6)==MATTER_OK);
    CHECK(matter_ota_requestor_selected(t->cluster,&selected)==MATTER_INVALID_STATE);
    /* Independent factory and private state. */
    Matter_Cluster_T other=matter_ota_requestor_new(&p,events,1,true); CHECK(other);
    CHECK(!matter_cluster_read(other,1,&q,&v) && v.unsigned_value==1); CHECK(matter_cluster_delete(other)==MATTER_OK);
    t->event_fail=true; CHECK(matter_ota_requestor_state(t->cluster,true,4,20,1,10,7)==MATTER_PORT_ERROR);
    CHECK(!matter_cluster_read(t->cluster,2,&q,&v) && v.unsigned_value==1); t->event_fail=false;
    CHECK(matter_ota_requestor_state(t->cluster,true,4,20,1,10,8)==MATTER_OK);
    CHECK(matter_ota_requestor_state(t->cluster,true,4,101,1,10,9)==MATTER_INVALID_ARGUMENT);
    CHECK(matter_ota_requestor_applied(t->cluster,10,2,10)==MATTER_OK);
    int64_t code=-123; CHECK(matter_ota_requestor_error(t->cluster,11,UINT64_MAX,-1,&code,11)==MATTER_OK);
    for(unsigned i=0;i<3;++i) {
        Matter_Event_Path_T path={0,MATTER_OTA_REQUESTOR_CLUSTER,i}; size_t n;
        CHECK(matter_events_copy(events,&path,0,t->records,&n)==MATTER_OK && n==1 && t->records[0].priority==(i==1?2:1));
        CHECK(matter_tlv_init(&t->reader,t->records[0].data,t->records[0].size,4)==MATTER_TLV_OK);
        CHECK(matter_tlv_next(&t->reader,&t->element)==MATTER_TLV_OK && t->element.type==MATTER_TLV_STRUCTURE);
        unsigned fields=0;
        while(matter_tlv_next(&t->reader,&t->element)==MATTER_TLV_OK && t->element.type!=MATTER_TLV_END) {
            unsigned tag=t->element.tag.number; CHECK(t->element.tag.control==1 && tag==fields++);
            if(i==0) CHECK(t->element.type==MATTER_TLV_UNSIGNED && t->element.unsigned_value==(tag==0?1:tag==1?4:tag==2?1:10));
            if(i==1) CHECK(t->element.type==MATTER_TLV_UNSIGNED && t->element.unsigned_value==(tag==0?10:2));
            if(i==2 && tag<2) CHECK(t->element.type==MATTER_TLV_UNSIGNED && t->element.unsigned_value==(tag==0?11:UINT64_MAX));
            if(i==2 && tag==2) CHECK(t->element.type==MATTER_TLV_NULL);
            if(i==2 && tag==3) CHECK(t->element.type==MATTER_TLV_SIGNED && t->element.signed_value==code);
        }
        CHECK(fields==(i==1?2u:4u));
    }
    multi_tests(t);
    CHECK(matter_cluster_delete(t->cluster)==MATTER_OK && matter_events_delete(events)==MATTER_OK); free(t);
#ifdef MATTER_TEST_ALLOC
    CHECK(!live);
#endif
#ifdef MATTER_TEST_ALLOC
    memory_tests();
#endif
    report_tests(0); report_tests(1);
    puts("PASS OTA Requestor: metadata, fabric-scoped defaults, atomic failure, deferred/copied selection, removal/reuse, instance isolation, state/event failure");
    return 0;
}
