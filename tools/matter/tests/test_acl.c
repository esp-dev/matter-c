#include <stdio.h>
#include "matter_compat.h"
#include <stdlib.h>
#include <string.h>
#include "clusters/matter_acl.h"
#include "test_acl_wire.h"
#define A(c) do { if(!(c)) { fprintf(stderr,"ACL:%d: %s\n",__LINE__,#c); abort(); } } while(0)
#ifdef MATTER_TEST_ALLOC
static void encoded_reentry(void*,size_t);
#define MATTER_TEST_ALLOC_AFTER_ALLOC encoded_reentry
#include "test_alloc_bytes.h"
#undef MATTER_TEST_ALLOC_AFTER_ALLOC
static Matter_Acl_T reentry_model;
static unsigned reentry_calls;
static void encoded_reentry(void* data,size_t size) {
    (void)data; (void)size; if(!reentry_model) return;
    ++reentry_calls; Matter_Im_Value_T v; static const uint8_t empty[]={0x16,0x18};
    Matter_Cluster_Request_T q={.fabric=1,.is_case=true,.peer_node=101}; Matter_Acl_Entry_T entry={0};
    A(matter_acl_read(reentry_model,0,1,true,&v)==MATTER_IM_FAILURE);
    A(matter_acl_read(reentry_model,2,1,true,&v)==MATTER_IM_FAILURE);
    A(matter_acl_read(reentry_model,0xfffb,1,true,&v)==MATTER_IM_FAILURE);
    A(matter_acl_validate(reentry_model,1,MATTER_IM_LIST_REPLACE,empty,sizeof(empty))==MATTER_IM_FAILURE);
    A(matter_acl_write(reentry_model,1,MATTER_IM_LIST_REPLACE,empty,sizeof(empty))==MATTER_IM_FAILURE);
    A(!matter_acl_authorize(reentry_model,1,101,NULL,0,NULL,MATTER_IM_ADMINISTER,NULL));
    A(matter_acl_prepare_added(reentry_model,&q,&entry)==MATTER_BUSY);
    A(matter_acl_delete(reentry_model)==MATTER_BUSY);
    A(matter_acl_version(reentry_model)); /* Existing nonmutating direct query. */
}
#endif
typedef struct {
    Matter_Acl_View_T view; Matter_Acl_T acl; AclWire wire; bool fail; unsigned stores; uint8_t index;
    Matter_Events_T log; uint64_t high; bool fail_reserve;
    Matter_Event_Record_T records[MATTER_EVENTS_CAPACITY];
} Fixture;
static const Matter_Acl_View_T* view(void* u) { return &((Fixture*)u)->view; }
static uint8_t store(void* u,uint8_t index,const Matter_Acl_Entry_T* entries,size_t count) {
    Fixture* f=u; A(matter_acl_delete(f->acl)==MATTER_BUSY); ++f->stores;
    if(f->fail) return MATTER_IM_FAILURE;
    Matter_Acl_Fabric_T* a=&f->view.fabrics[index-1]; A(a->index==index);
    memset(a->entries,0,sizeof(a->entries)); memcpy(a->entries,entries,count*sizeof(*entries)); a->count=(uint8_t)count; ++f->view.version; return 0;
}
static bool types(void* u,uint16_t ep,uint32_t type) { (void)u; return ep==0 && type==0x16; }
static Matter_Result_T write_index(void* u,Matter_Exchange_Session_T session,uint8_t* index) { (void)session; *index=((Fixture*)u)->index; return MATTER_OK; }
static uint8_t wa(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* p,Matter_Im_Privilege_T v) { (void)u; (void)session; (void)p; (void)v; return 0; }
static uint8_t wd(void* u,const Matter_Im_Path_T* p,Matter_Im_Write_Attribute_T* a) { (void)u; (void)p; *a=(Matter_Im_Write_Attribute_T){.privilege=MATTER_IM_ADMINISTER,.fabric_scoped=true,.list=true}; return 0; }
static Matter_Result_T wv(void* u,const Matter_Im_Path_T* p,uint32_t* v) { (void)p; *v=matter_acl_version(((Fixture*)u)->acl); return MATTER_OK; }
static uint8_t wl(void* u,const Matter_Im_Path_T* p,Matter_Im_List_Change_T c,const uint8_t* d,size_t n) { (void)p; Fixture* f=u; return matter_acl_validate(f->acl,f->index,c,d,n); }
static Matter_Im_Write_Result_T ww(void* u,const Matter_Im_Path_T* p,Matter_Im_List_Change_T c,const uint8_t* d,size_t n) { (void)p; Fixture* f=u; return (Matter_Im_Write_Result_T){.status=matter_acl_write(f->acl,f->index,c,d,n)}; }
static uint8_t ws(void* u,const Matter_Im_Path_T* p,const uint8_t* d,size_t n) { (void)u; (void)p; (void)d; (void)n; abort(); return 1; }
static Matter_Im_Write_Result_T wx(void* u,const Matter_Im_Path_T* p,const uint8_t* d,size_t n) { (void)u; (void)p; (void)d; (void)n; abort(); return (Matter_Im_Write_Result_T){.status=1}; }
static uint8_t real_access(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* p,Matter_Im_Privilege_T v) {
    (void)session; Fixture* f=u;
    return matter_acl_authorize(f->acl,f->index,101,NULL,0,p,v,NULL)?0:MATTER_IM_UNSUPPORTED_ACCESS;
}
static void legacy_acl(void) {
    Fixture* f=calloc(1,sizeof(*f)); A(f); f->index=1; f->view.fabrics[0].index=1;
    Matter_Acl_Port_T ap={f,view,store}; f->acl=matter_acl_new(&ap); A(f->acl);
    Matter_Im_Write_Port_T p={f,real_access,wd,wv,ws,wx,wl,ww}; Matter_Im_Read_Fabric_Port_T resolver={write_index};
    for(unsigned mode=0;mode<3;++mode) {
        AclWire* w=&f->wire; aw_list(w,false); A(!matter_acl_write(f->acl,1,MATTER_IM_LIST_REPLACE,w->data,w->size));
        Matter_Im_Write_Config_T config={{42,10,false},1000,256,false};
        Matter_Im_Write_T h=matter_im_write_new_case(&p,&resolver,&config,0); A(h);
        /* One request with an empty replacement and one append, literal TLV. */
        w->size=0; aw_entry(w,mode==2?102:101,5,0); aw_request(w,true,false,-1);
        static const uint8_t clear[]={0x15,0x37,1,0x24,2,0,0x24,3,0x1f,0x24,4,0,0x18,0x36,2,0x18,0x18};
        memmove(w->request+5+sizeof(clear),w->request+5,w->request_size-5);
        memcpy(w->request+5,clear,sizeof(clear)); w->request_size+=sizeof(clear);
        unsigned before=f->stores; f->fail=mode==1;
        Matter_Rx_Decision_T d={.session=42,.action=MATTER_RX_NEW_RESPONDER,.header={.exchange_id=10,.protocol_id=1,.opcode=6,.exchange_flags=MATTER_PROTOCOL_INITIATOR},.payload=w->request,.payload_size=w->request_size};
        A(matter_im_write_receive_at(h,&d,0)==MATTER_OK && matter_im_write_process(h,0)==MATTER_PENDING);
        Matter_Im_Write_Message_T out; A(matter_im_write_output(h,&out)==MATTER_OK && out.opcode==7);
        A(out.data[20]==(mode==1?MATTER_IM_FAILURE:0));
        A(f->stores==before+2 && f->view.fabrics[0].count==1);
        A(f->view.fabrics[0].entries[0].subjects[0]==(mode==2?102u:101u));
        A(matter_im_write_delete(h)==MATTER_OK); f->fail=false;
        /* No grant may leak to the next request after replacement removes us. */
        if(mode==2) {
            h=matter_im_write_new_case(&p,&resolver,&config,1); A(h); before=f->stores;
            A(matter_im_write_receive_at(h,&d,1)==MATTER_OK && matter_im_write_process(h,1)==MATTER_PENDING);
            A(matter_im_write_output(h,&out)==MATTER_OK && out.opcode==7 && out.data[20]==MATTER_IM_UNSUPPORTED_ACCESS && f->stores==before);
            A(matter_im_write_delete(h)==MATTER_OK);
        }
    }
    A(matter_acl_delete(f->acl)==MATTER_OK); free(f);
}
static void write_identity(Fixture* f) {
    Matter_Im_Write_Port_T p={f,wa,wd,wv,ws,wx,wl,ww}; Matter_Im_Read_Fabric_Port_T r={write_index};
    Matter_Im_Write_Config_T config={{42,10,false},1000,128,false};
    for(unsigned mode=0;mode<3;++mode) {
        f->index=mode==0?0:1;
        Matter_Im_Write_T h=matter_im_write_new_case(&p,&r,&config,0); A(h);
        aw_list(&f->wire,false); aw_request(&f->wire,false,mode==1,-1);
        Matter_Rx_Decision_T d={.session=42,.action=MATTER_RX_NEW_RESPONDER,.header={.exchange_id=10,.protocol_id=1,.opcode=6,.exchange_flags=MATTER_PROTOCOL_INITIATOR},.payload=f->wire.request,.payload_size=f->wire.request_size};
        unsigned writes=f->stores; A(matter_im_write_receive_at(h,&d,0)==MATTER_OK);
        if(mode==2) { A(matter_im_write_cancel(h)==MATTER_OK && f->stores==writes); }
        else {
            A(matter_im_write_process(h,0)==MATTER_PENDING); Matter_Im_Write_Message_T out; A(matter_im_write_output(h,&out)==MATTER_OK && out.opcode==7);
            A(out.data[20]==(mode==0?MATTER_IM_UNSUPPORTED_ACCESS:0));
            if(mode==1) {
                A(matter_im_write_sent_at(h,0)==MATTER_OK && matter_im_write_confirm(h,0)==MATTER_OK);
                f->index=2; writes=f->stores; aw_list(&f->wire,true); aw_request(&f->wire,false,false,-1); d.action=MATTER_RX_EXISTING; d.payload_size=f->wire.request_size;
                A(matter_im_write_receive_at(h,&d,1)==MATTER_OK && matter_im_write_process(h,1)==MATTER_PENDING);
                A(matter_im_write_output(h,&out)==MATTER_OK && out.data[20]==MATTER_IM_UNSUPPORTED_ACCESS && f->stores==writes);
            }
        }
        A(matter_im_write_delete(h)==MATTER_OK);
    }
}
static Matter_Result_T event_load(void* u,uint64_t* n) { *n=((Fixture*)u)->high; return MATTER_OK; }
static Matter_Result_T event_store(void* u,uint64_t n) { Fixture* f=u; if(f->fail_reserve) return MATTER_PORT_ERROR; f->high=n; return MATTER_OK; }
static uint64_t event_now(void* u) { (void)u; return 123; }
#ifdef MATTER_TEST_ALLOC
static void encoding_storage(void) {
    Fixture* f=calloc(1,sizeof(*f)); Fixture* other=calloc(1,sizeof(*other)); A(f && other);
    Matter_Acl_View_T* saved=calloc(1,sizeof(*saved)); A(saved);
    for(unsigned i=0;i<5;++i) f->view.fabrics[i].index=(uint8_t)(i+1);
    f->view.version=17; other->view=f->view;
    Matter_Acl_Port_T p={f,view,store},op={other,view,store};
    f->acl=matter_acl_new(&p); other->acl=matter_acl_new(&op); A(f->acl && other->acl);
    for(unsigned i=1;i<=5;++i) {
        AclWire* w=&f->wire; w->size=0; aw_open(w,0x16,-1);
        for(unsigned j=0;j<4;++j) aw_entry_ex(w,UINT64_C(0xffffffef00000001)+j*4,5,2,4,3,1);
        aw_byte(w,0x18); A(!matter_acl_write(f->acl,(uint8_t)i,MATTER_IM_LIST_REPLACE,w->data,w->size));
    }
    size_t baseline=live_bytes,blocks=live,started=calls; Matter_Im_Value_T v;
    for(unsigned n=0;n<20;++n) {
        for(unsigned i=2;i<=4;++i) A(!matter_acl_read(f->acl,i,0,true,&v));
        A(!matter_acl_read(f->acl,0xfffc,0,true,&v) && !matter_acl_read(f->acl,0xfffd,0,true,&v));
        (void)matter_acl_version(f->acl);
    }
    A(calls==started && live==blocks && live_bytes==baseline);
    /* Each fabric/filter combination, plus all three encoded global lists. */
    for(unsigned n=0;n<13;++n) {
        uint32_t attr=n<10?0:n==10?0xfff8:n==11?0xfff9:0xfffb;
        uint8_t index=(uint8_t)(n<10?n/2+1:0); bool filtered=(n%2)==0;
        size_t before=calls; unsigned probes=reentry_calls; reentry_model=f->acl;
        A(!matter_acl_read(f->acl,attr,index,filtered,&v)); reentry_model=NULL;
        A(calls==before+1 && reentry_calls==probes+1 && live==blocks+1);
        A(v.size && v.size<=sizeof(f->wire.request) && matter_test_allocation_size(v.data)==v.size && live_bytes==baseline+v.size);
        memcpy(f->wire.request,v.data,v.size); const uint8_t* held=v.data; size_t size=v.size; uint32_t version=v.data_version;
        Matter_Im_Attribute_T access; A(!matter_cluster_describe(f->acl,attr,&access));
        A(matter_acl_version(f->acl)==version && !matter_acl_read(other->acl,2,0,true,&v));
        A(matter_acl_read(f->acl,0,255,true,&v)==MATTER_IM_UNSUPPORTED_ACCESS);
        A(live==blocks+1 && live_bytes==baseline+size && !memcmp(held,f->wire.request,size));
        *saved=f->view; unsigned stores=f->stores;
        fail_at=calls+1; A(matter_acl_read(f->acl,attr,index,filtered,&v)==MATTER_IM_RESOURCE_EXHAUSTED); fail_at=0;
        A(live==blocks && live_bytes==baseline && f->stores==stores && !memcmp(saved,&f->view,sizeof(*saved)));
        A(!matter_acl_read(f->acl,attr,index,filtered,&v) && v.size==size && v.data_version==version && !memcmp(v.data,f->wire.request,size));
        A(!matter_acl_read(f->acl,2,0,true,&v) && live==blocks && live_bytes==baseline);
    }
    /* Validation/write can consume the borrowed read itself, without another
     * encoding allocation. Both successful and failed store retain that span. */
    A(!matter_acl_read(f->acl,0,1,true,&v)); size_t size=v.size; const uint8_t* data=v.data;
    memcpy(f->wire.request,data,size); *saved=f->view; size_t before=calls;
    fail_at=calls+1;
    A(!matter_acl_validate(f->acl,1,MATTER_IM_LIST_REPLACE,data,size));
    f->fail=true; A(matter_acl_write(f->acl,1,MATTER_IM_LIST_REPLACE,data,size)==MATTER_IM_FAILURE); f->fail=false;
    A(!memcmp(saved,&f->view,sizeof(*saved)) && !memcmp(data,f->wire.request,size));
    A(!matter_acl_write(f->acl,2,MATTER_IM_LIST_REPLACE,data,size)); fail_at=0;
    A(calls==before && live==blocks+1 && !memcmp(data,f->wire.request,size));
    A(f->view.version==saved->version+1 && !memcmp(&f->view.fabrics[0],&saved->fabrics[0],sizeof(saved->fabrics[0])));
    A(!matter_acl_delete(f->acl) && !matter_acl_delete(other->acl)); free(saved); free(other); free(f);
    A(!live && !live_bytes);
    puts("PASS ACL encoding: scalar/query no allocations, exact-size spans, all13 fabric/filter/global OOM retries, immutable view, reentry, read-to-write alias/store failure and zero-live cleanup");
}
#endif
static Matter_Im_Write_Result_T event_write(void* u,const Matter_Im_Path_T* p,Matter_Im_List_Change_T c,const uint8_t* d,size_t n) {
    Fixture* f=u; A(p->endpoint==0 && p->cluster==0x1f && p->attribute==0);
    Matter_Cluster_Request_T q={.fabric=f->index,.is_case=true,.peer_node=101};
    return matter_cluster_write_list(f->acl,0,&q,c,d,n);
}
static void invalid_entries(void) {
    Fixture* f=calloc(1,sizeof(*f)); A(f); f->index=1;
    f->view.fabrics[0].index=1; f->view.fabrics[1].index=2;
    Matter_Acl_Port_T ap={f,view,store}; f->acl=matter_acl_new(&ap); A(f->acl);
    Matter_Events_Port_T lp={f,event_load,event_store}; f->log=matter_events_new(&lp); A(f->log);
    Matter_Acl_Events_Port_T ep={f->log,f,event_now}; A(!matter_acl_bind_events(f->acl,&ep));
    Matter_Cluster_Request_T q={.fabric=1,.is_case=true,.peer_node=101};
    AclWire* w=&f->wire; aw_list(w,false);
    A(!matter_acl_write(f->acl,1,MATTER_IM_LIST_REPLACE,w->data,w->size));
    A(!matter_acl_write(f->acl,2,MATTER_IM_LIST_REPLACE,w->data,w->size));
    /* Core 9.10.5.2/7.3.8: Proxy View is D, not an assignable privilege.
     * Core 9.10.5.7: PASE entries, Group Administer, zero/oversized subjects
     * and malformed CASE/CAT subjects must not mutate storage or emit events. */
    static const struct { uint64_t subject; unsigned privilege,mode; } bad[]={
        {101,0,2},{101,2,2},{101,6,2},{101,255,2},{101,256,2},
        {1,1,0},{1,1,1},{1,1,4},{1,5,3},{0,3,3},{0x10000,3,3},
        {UINT64_C(0x100000001),3,3},{0,1,2},{UINT64_C(0xfffffff000000000),1,2},
        {UINT64_C(0xfffffffd00010000),1,2},{UINT64_C(0xfffffffd00000001),1,2}
    };
    unsigned stores=f->stores; uint32_t version=f->view.version;
    for(size_t i=0;i<sizeof(bad)/sizeof(*bad);++i) for(unsigned replace=0;replace<2;++replace) {
        if(MATTER_CSA_COMPAT_PROXY_VIEW && bad[i].privilege==2) continue;
        w->size=0;
        if(replace) { aw_open(w,0x16,-1); aw_entry(w,101,5,0); }
        aw_entry_ex(w,bad[i].subject,bad[i].privilege,bad[i].mode,1,0,0);
        if(replace) aw_byte(w,0x18);
        Matter_Im_List_Change_T change=replace?MATTER_IM_LIST_REPLACE:MATTER_IM_LIST_ADD;
        A(matter_acl_validate(f->acl,1,change,w->data,w->size)==MATTER_IM_CONSTRAINT_ERROR);
        A(matter_cluster_write_list(f->acl,0,&q,change,w->data,w->size).status==MATTER_IM_CONSTRAINT_ERROR);
        uint64_t position; A(!matter_events_position(f->log,&position) && !position);
        A(f->stores==stores && f->view.version==version && f->view.fabrics[0].count==1);
        A(f->view.fabrics[1].count==1 && f->view.fabrics[1].entries[0].subjects[0]==101);
        A(matter_acl_authorize(f->acl,1,101,NULL,0,NULL,MATTER_IM_ADMINISTER,NULL));
    }
    A(matter_acl_delete(f->acl)==MATTER_OK && matter_events_delete(f->log)==MATTER_OK); free(f);
}
static void invalid_group_write(void) {
    for(unsigned legacy=0;legacy<2;++legacy) {
        Fixture* f=calloc(1,sizeof(*f)); A(f); f->index=1;
        f->view.fabrics[0].index=1; f->view.fabrics[1].index=2;
        Matter_Acl_Port_T ap={f,view,store}; f->acl=matter_acl_new(&ap); A(f->acl);
        Matter_Events_Port_T lp={f,event_load,event_store}; f->log=matter_events_new(&lp); A(f->log);
        Matter_Acl_Events_Port_T ep={f->log,f,event_now}; A(!matter_acl_bind_events(f->acl,&ep));
        AclWire* w=&f->wire; aw_list(w,false);
        A(!matter_acl_write(f->acl,1,MATTER_IM_LIST_REPLACE,w->data,w->size));
        A(!matter_acl_write(f->acl,2,MATTER_IM_LIST_REPLACE,w->data,w->size));
        AclWire* request=calloc(1,sizeof(*request)); A(request);
        /* Literal WriteRequests: REPLACE(admin, invalid), or legacy
         * REPLACE([]), ADD(admin), ADD(group 0). All IBs share one message. */
        static const uint8_t head[]={0x15,0x28,1,0x36,2},tail[]={0x18,0x24,255,13,0x18};
        memcpy(request->request,head,sizeof(head)); size_t n=sizeof(head);
        unsigned blocks=legacy?3:1;
        for(unsigned i=0;i<blocks;++i) {
            w->size=0;
            if(!legacy) { aw_open(w,0x16,-1); aw_entry(w,101,5,0); aw_entry_ex(w,0,3,3,1,0,0); aw_byte(w,0x18); }
            else if(!i) { aw_open(w,0x16,-1); aw_byte(w,0x18); }
            else if(i==1) aw_entry(w,101,5,0);
            else aw_entry_ex(w,0,3,3,1,0,0);
            aw_request(w,legacy && i,false,-1);
            size_t ib=w->request_size-sizeof(head)-sizeof(tail);
            A(n+ib+sizeof(tail)<=sizeof(request->request));
            memcpy(request->request+n,w->request+sizeof(head),ib); n+=ib;
        }
        memcpy(request->request+n,tail,sizeof(tail)); n+=sizeof(tail);
        Matter_Im_Write_Port_T p={f,real_access,wd,wv,ws,wx,wl,event_write};
        Matter_Im_Read_Fabric_Port_T resolver={write_index}; Matter_Im_Write_Config_T config={{42,10,false},1000,256,false};
        Matter_Im_Write_T h=matter_im_write_new_case(&p,&resolver,&config,0); A(h);
        Matter_Rx_Decision_T d={.session=42,.action=MATTER_RX_NEW_RESPONDER,
            .header={.exchange_id=10,.protocol_id=1,.opcode=6,.exchange_flags=MATTER_PROTOCOL_INITIATOR},.payload=request->request,.payload_size=n};
        unsigned before=f->stores; uint32_t version=f->view.version;
        A(!matter_im_write_receive_at(h,&d,0) && matter_im_write_process(h,0)==MATTER_PENDING);
        Matter_Im_Write_Message_T out; A(!matter_im_write_output(h,&out) && out.opcode==7);
        Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T token; A(!matter_tlv_init(&reader,out.data,out.size,8));
        unsigned depth=0,statuses=0; Matter_Tlv_Result_T r;
        while((r=matter_tlv_next(&reader,&token))==MATTER_TLV_OK) {
            if(token.type==MATTER_TLV_END) { A(depth); --depth; continue; }
            if(depth==4 && token.type==MATTER_TLV_UNSIGNED && token.tag.control==1 && !token.tag.number) {
                A(statuses<blocks && token.unsigned_value==(statuses==blocks-1?MATTER_IM_CONSTRAINT_ERROR:0)); ++statuses;
            }
            if(token.type==MATTER_TLV_ARRAY || token.type==MATTER_TLV_STRUCTURE || token.type==MATTER_TLV_LIST) ++depth;
        }
        A(r==MATTER_TLV_DONE && !depth && statuses==blocks);
        A(f->stores==before+(legacy?2u:0u) && f->view.version==version+(legacy?2u:0u));
        A(f->view.fabrics[0].count==1 && f->view.fabrics[0].entries[0].subjects[0]==101);
        A(f->view.fabrics[1].count==1 && f->view.fabrics[1].entries[0].subjects[0]==101);
        Matter_Event_Path_T path={0,0x1f,0}; size_t count;
        A(!matter_events_copy_fabric(f->log,&path,0,1,true,f->records,&count) && count==(legacy?2u:0u));
        if(legacy) A(f->records[0].data[8]==2 && f->records[1].data[8]==1); /* Only admin Removed/Added. */
        A(matter_acl_authorize(f->acl,1,101,NULL,0,NULL,MATTER_IM_ADMINISTER,NULL));
        A(!matter_im_write_delete(h) && !matter_acl_delete(f->acl) && !matter_events_delete(f->log));
        free(request); free(f);
    }
    puts("PASS ACL invalid writes: modern [ConstraintError], legacy [Success, Success, ConstraintError], no invalid state/events, fabric isolation");
}
static void target_ids(void) {
    Fixture* f=calloc(1,sizeof(*f)); A(f); f->view.fabrics[0].index=1;
    Matter_Acl_Port_T p={f,view,store}; f->acl=matter_acl_new(&p); A(f->acl);
    static const struct { unsigned tag; uint64_t id; bool valid; } cases[]={
        {0,0,true},{0,0x7fff,true},{0,0x8000,false},{0,0xfc00,false},
        {0,0x0001fbff,false},{0,0x0001fc00,true},{0,0xfff4fffe,true},
        {0,0xfff4ffff,false},{0,0xfff5fc00,false},{0,UINT32_MAX,false},
        {1,0,true},{1,0xfffe,true},{1,0xffff,false},{1,0x10000,false},
        {2,0,true},{2,0xbfff,true},{2,0xc000,false},{2,0xfff4bfff,true},
        {2,0xfff50000,false},{2,UINT32_MAX,false},{2,UINT64_C(0x100000000),false}
    };
    for(size_t i=0;i<sizeof(cases)/sizeof(*cases);++i) for(unsigned replace=0;replace<2;++replace) {
        AclWire* w=&f->wire; w->size=0;
        if(replace) aw_open(w,0x16,-1);
        aw_open(w,0x15,-1); aw_uint(w,1,1); aw_uint(w,2,2); aw_open(w,0x14,3);
        aw_open(w,0x16,4); aw_open(w,0x15,-1);
        for(unsigned tag=0;tag<3;++tag) {
            if(tag==cases[i].tag) aw_uint(w,(int)tag,cases[i].id); else aw_open(w,0x14,(int)tag);
        }
        aw_byte(w,0x18); aw_byte(w,0x18); aw_byte(w,0x18);
        if(replace) aw_byte(w,0x18);
        unsigned stores=f->stores; uint32_t version=f->view.version;
        uint8_t status=matter_acl_write(f->acl,1,replace?MATTER_IM_LIST_REPLACE:MATTER_IM_LIST_ADD,w->data,w->size);
        A(status==(cases[i].valid?0:MATTER_IM_CONSTRAINT_ERROR));
        if(!cases[i].valid) A(f->stores==stores && f->view.version==version);
        f->view.fabrics[0].count=0;
    }
    A(matter_acl_delete(f->acl)==MATTER_OK); free(f);
}
static void acl_events(void) {
    Fixture* f=calloc(1,sizeof(*f)); A(f); f->view.fabrics[0].index=1;
    Matter_Acl_Port_T p={f,view,store}; f->acl=matter_acl_new(&p); A(f->acl);
    Matter_Events_Port_T lp={f,event_load,event_store}; f->log=matter_events_new(&lp); A(f->log);
    Matter_Acl_Events_Port_T ep={f->log,f,event_now}; A(matter_acl_bind_events(f->acl,&ep)==MATTER_OK);
    const Matter_Event_Def_T* meta=matter_cluster_event(f->acl,0); A(meta && meta->fabric_scoped && meta->priority==1 && meta->privilege==MATTER_IM_ADMINISTER);
    Matter_Cluster_Request_T q={.fabric=1,.is_case=true,.peer_node=100};
    AclWire* w=&f->wire; aw_list(w,false); uint64_t next; size_t count;
    f->fail_reserve=true;
    A(matter_cluster_write_list(f->acl,0,&q,MATTER_IM_LIST_REPLACE,w->data,w->size).status==MATTER_IM_FAILURE && !f->stores);
    f->fail_reserve=false; f->fail=true;
    A(matter_cluster_write_list(f->acl,0,&q,MATTER_IM_LIST_REPLACE,w->data,w->size).status==MATTER_IM_FAILURE);
    A(matter_events_position(f->log,&next)==MATTER_OK && !next); f->fail=false;
    A(!matter_cluster_write_list(f->acl,0,&q,MATTER_IM_LIST_REPLACE,w->data,w->size).status);
    Matter_Event_Path_T path={0,0x1f,0};
    A(matter_events_copy_fabric(f->log,&path,0,1,true,f->records,&count)==MATTER_OK && count==1);
    static const uint8_t added[]={0x15,0x24,1,100,0x34,2,0x24,3,1,0x35,4,0x24,1,5,0x24,2,2,0x36,3,4,101,0x18,0x34,4,0x24,254,1,0x18,0x24,254,1,0x18};
    A(f->records[0].size==sizeof(added) && !memcmp(f->records[0].data,added,sizeof(added)) && f->records[0].timestamp_ms==123);
    A(matter_events_copy_fabric(f->log,&path,0,2,true,f->records,&count)==MATTER_OK && !count);
    /* Event encoding shares the writer, not the provider's retained bytes.
     * A failed staged publication must preserve both ACL/version and borrow. */
    Matter_Im_Value_T held; A(!matter_acl_read(f->acl,0,1,true,&held));
    memcpy(w->request,held.data,held.size); uint32_t held_version=matter_acl_version(f->acl);
    f->fail=true;
    A(matter_cluster_write_list(f->acl,0,&q,MATTER_IM_LIST_REPLACE,w->data,w->size).status==MATTER_IM_FAILURE);
    f->fail=false;
    A(matter_acl_version(f->acl)==held_version && !memcmp(held.data,w->request,held.size));
    A(!matter_events_position(f->log,&next) && next==1);
    A(!matter_cluster_write_list(f->acl,0,&q,MATTER_IM_LIST_REPLACE,w->data,w->size).status);
    A(!memcmp(held.data,w->request,held.size));
    A(matter_events_position(f->log,&next)==MATTER_OK && next==2); /* Equal REPLACE still rewrites the entry. */
    aw_list(w,true); A(!matter_cluster_write_list(f->acl,0,&q,MATTER_IM_LIST_REPLACE,w->data,w->size).status);
    w->size=0; aw_open(w,0x16,-1); aw_entry(w,101,3,0); aw_byte(w,0x18);
    A(!matter_cluster_write_list(f->acl,0,&q,MATTER_IM_LIST_REPLACE,w->data,w->size).status);
    A(matter_events_copy(f->log,&path,0,f->records,&count)==MATTER_OK && count==6);
    A(f->records[1].data[8]==0 && f->records[4].data[8]==0 && f->records[5].data[8]==2); /* Changed and Removed, old entry available. */
    unsigned stores=f->stores; --w->size;
    A(matter_cluster_write_list(f->acl,0,&q,MATTER_IM_LIST_REPLACE,w->data,w->size).status && f->stores==stores);
    A(matter_events_position(f->log,&next)==MATTER_OK && next==6);
    /* Largest supported entry, full 64-bit subjects and three targets. */
    w->size=0; aw_entry_ex(w,UINT64_C(0xffffffef00000001),5,2,4,3,1);
    A(!matter_cluster_write_list(f->acl,0,&q,MATTER_IM_LIST_ADD,w->data,w->size).status);
    /* AddNOC PASE bootstrap stages an event but failed install leaves no trace. */
    q.is_case=false; q.peer_node=0; q.fabric=2;
    A(matter_acl_prepare_added(f->acl,&q,&f->view.fabrics[0].entries[0])==MATTER_OK);
    A(matter_events_position(f->log,&next)==MATTER_BUSY && matter_acl_delete(f->acl)==MATTER_BUSY);
    matter_acl_finish_added(f->acl,false); A(matter_events_position(f->log,&next)==MATTER_OK && next==7);
    A(matter_acl_prepare_added(f->acl,&q,&f->view.fabrics[0].entries[0])==MATTER_OK); matter_acl_finish_added(f->acl,true);
    A(matter_events_copy_fabric(f->log,&path,0,2,true,f->records,&count)==MATTER_OK && count==1);
    A(f->records[0].data[1]==0x34 && f->records[0].data[3]==0x24 && f->records[0].data[4]==2 && f->records[0].data[5]==0);
    A(matter_events_forget_fabric(f->log,2)==MATTER_OK && matter_events_copy_fabric(f->log,&path,0,2,true,f->records,&count)==MATTER_OK && !count);
    /* Critical log saturation fails BEFORE the ACL mutation. */
    static const uint8_t data[]={0x15,0x24,0,1,0x18};
    for(unsigned i=0;i<MATTER_EVENTS_CAPACITY;++i) A(matter_events_append(f->log,&path,2,200,false,data,sizeof(data))==MATTER_OK);
    q.is_case=true; q.peer_node=100; q.fabric=1; aw_list(w,false); stores=f->stores;
    A(matter_cluster_write_list(f->acl,0,&q,MATTER_IM_LIST_REPLACE,w->data,w->size).status==MATTER_IM_RESOURCE_EXHAUSTED && f->stores==stores);
    A(matter_acl_delete(f->acl)==MATTER_OK && matter_events_delete(f->log)==MATTER_OK); free(f);
    puts("PASS ACL events: literal payload, CASE/PASE subjects, Added/Changed/Removed/equal-REPLACE, fabric isolation/purge, atomic store/reservation/capacity errors");
}
static void proxy_view_compatibility(void) {
    Fixture* f=calloc(1,sizeof(*f)); A(f);
    f->view.fabrics[0].index=1; f->view.fabrics[1].index=2;
    Matter_Acl_Port_T ap={f,view,store}; f->acl=matter_acl_new(&ap); A(f->acl);
    AclWire* w=&f->wire; aw_list(w,false);
    A(!matter_acl_write(f->acl,1,MATTER_IM_LIST_REPLACE,w->data,w->size));
    w->size=0; aw_entry_ex(w,102,2,2,1,1,1);
    unsigned before=f->stores;
    A(matter_acl_write(f->acl,1,MATTER_IM_LIST_ADD,w->data,w->size)==
        (MATTER_CSA_COMPAT_PROXY_VIEW?MATTER_IM_SUCCESS:MATTER_IM_CONSTRAINT_ERROR));
    A(f->stores==before+(MATTER_CSA_COMPAT_PROXY_VIEW?1u:0u));
    /* Also model a persisted legacy ACL loaded by a strict image. Only the
     * compatibility image may grant View; both must deny higher privileges. */
    f->view.fabrics[0].count=2;
    f->view.fabrics[0].entries[1]=(Matter_Acl_Entry_T){.privilege=2,.auth_mode=2,
        .subjects={102},.subject_count=1,.targets={{.present=3,.endpoint=0,.cluster=0x28}},.target_count=1};
    Matter_Im_Path_T basic={0,0x28,2},other={1,0x28,2},acl={0,0x1f,0};
    A(matter_acl_authorize(f->acl,1,102,NULL,0,&basic,MATTER_IM_VIEW,NULL)==!!MATTER_CSA_COMPAT_PROXY_VIEW);
    A(!matter_acl_authorize(f->acl,1,102,NULL,0,&basic,MATTER_IM_OPERATE,NULL));
    A(!matter_acl_authorize(f->acl,1,102,NULL,0,&basic,MATTER_IM_MANAGE,NULL));
    A(!matter_acl_authorize(f->acl,1,102,NULL,0,&basic,MATTER_IM_ADMINISTER,NULL));
    A(!matter_acl_authorize(f->acl,1,102,NULL,0,&other,MATTER_IM_VIEW,NULL));
    A(!matter_acl_authorize(f->acl,1,102,NULL,0,&acl,MATTER_IM_VIEW,NULL));
    A(!matter_acl_authorize(f->acl,2,102,NULL,0,&basic,MATTER_IM_VIEW,NULL));
    A(!matter_acl_authorize(f->acl,1,103,NULL,0,&basic,MATTER_IM_VIEW,NULL));
    A(matter_acl_authorize(f->acl,1,101,NULL,0,&acl,MATTER_IM_ADMINISTER,NULL));
    A(matter_acl_delete(f->acl)==MATTER_OK); free(f);
}
int main(void) {
    Fixture* f=calloc(1,sizeof(*f)); A(f); f->view.version=17;
    for(unsigned i=0;i<5;++i) f->view.fabrics[i].index=(uint8_t)(i+1);
    Matter_Acl_Port_T p={f,view,store};
#ifdef MATTER_TEST_ALLOC
    for(unsigned i=1;i<=2;++i) { size_t before=live; fail_at=calls+i; A(!matter_acl_new(&p) && live==before); fail_at=0; }
#endif
    f->acl=matter_acl_new(&p); A(f->acl); AclWire* w=&f->wire; Matter_Im_Value_T v;
    for(unsigned i=2;i<=4;++i) A(!matter_acl_read(f->acl,i,0,true,&v) && v.unsigned_value==(i==3?3u:4u));
    A(!matter_acl_read(f->acl,0xfffd,0,true,&v) && v.unsigned_value==3);
    A(!matter_acl_read(f->acl,0xfffc,0,true,&v) && !v.unsigned_value);
    A(matter_acl_read(f->acl,0,0,true,&v)==MATTER_IM_UNSUPPORTED_ACCESS);
    aw_list(w,false); A(!matter_acl_write(f->acl,1,MATTER_IM_LIST_REPLACE,w->data,w->size));
    A(!matter_acl_read(f->acl,0,1,true,&v));
    static const uint8_t expected[]={0x16,0x15,0x24,1,5,0x24,2,2,0x36,3,4,101,0x18,0x34,4,0x24,254,1,0x18,0x18};
    A(v.size==sizeof(expected) && !memcmp(v.data,expected,sizeof(expected)));
    /* Unfiltered foreign entries expose only FabricIndex; no sensitive fields
     * may be present even with null/zero values (Core 8.4.3.3). */
    f->view.fabrics[1].count=1; f->view.fabrics[1].entries[0]=f->view.fabrics[0].entries[0];
    A(!matter_acl_read(f->acl,0,1,false,&v));
    static const uint8_t foreign[]={0x15,0x24,254,2,0x18,0x18};
    A(v.size==sizeof(expected)-1+sizeof(foreign) && !memcmp(v.data,expected,sizeof(expected)-1) &&
        !memcmp(v.data+sizeof(expected)-1,foreign,sizeof(foreign)));
    A(!matter_acl_read(f->acl,0,2,false,&v));
    static const uint8_t first_foreign[]={0x16,0x15,0x24,254,1,0x18};
    A(v.size==sizeof(expected)-1+sizeof(foreign) && !memcmp(v.data,first_foreign,sizeof(first_foreign)));
    A(!matter_acl_read(f->acl,0,1,true,&v) && v.size==sizeof(expected) && !memcmp(v.data,expected,sizeof(expected)));
    f->view.fabrics[1].count=0;
    Matter_Im_Path_T basic={0,0x28,2},other={1,0x28,2},acl={0,0x1f,0};
    A(matter_acl_authorize(f->acl,1,101,NULL,0,&acl,MATTER_IM_ADMINISTER,NULL));
    A(!matter_acl_authorize(f->acl,2,101,NULL,0,&acl,MATTER_IM_VIEW,NULL));
    aw_list(w,true); A(!matter_acl_write(f->acl,1,MATTER_IM_LIST_REPLACE,w->data,w->size));
    A(matter_acl_authorize(f->acl,1,102,NULL,0,&basic,MATTER_IM_VIEW,NULL));
    A(!matter_acl_authorize(f->acl,1,102,NULL,0,&basic,MATTER_IM_OPERATE,NULL));
    A(!matter_acl_authorize(f->acl,1,102,NULL,0,&other,MATTER_IM_VIEW,NULL));
    A(!matter_acl_authorize(f->acl,1,102,NULL,0,&acl,MATTER_IM_VIEW,NULL));
    w->size=0; aw_entry(w,UINT64_C(0xfffffffd00010002),3,2);
    A(!matter_acl_write(f->acl,1,MATTER_IM_LIST_ADD,w->data,w->size));
    uint32_t cat=0x10003; Matter_Acl_Device_Port_T d={NULL,types};
    A(matter_acl_authorize(f->acl,1,103,&cat,1,&basic,MATTER_IM_OPERATE,&d));
    A(!matter_acl_authorize(f->acl,1,103,&cat,1,&basic,MATTER_IM_OPERATE,NULL));
    cat=0x10001; A(!matter_acl_authorize(f->acl,1,103,&cat,1,&basic,MATTER_IM_OPERATE,&d));
    /* Error paths leave count, version and all grants unchanged. */
    unsigned before=f->stores; uint32_t version=f->view.version;
    for(unsigned bad=0;bad<9;++bad) {
        if(MATTER_CSA_COMPAT_PROXY_VIEW && bad==0) continue;
        w->size=0; aw_entry_ex(w,bad==3?0:bad==4?UINT64_C(0xfffffffd00010000):105,
            bad==0?2:bad==2?5:1,bad==1?1:bad==2?3:2,bad==5?5:1,bad==6?4:bad>=7?1:0,bad==7?3:bad==8?4:1);
        uint8_t status=matter_acl_write(f->acl,1,MATTER_IM_LIST_ADD,w->data,w->size);
        A(status==(bad==5 || bad==6?MATTER_IM_RESOURCE_EXHAUSTED:MATTER_IM_CONSTRAINT_ERROR));
        A(f->view.version==version && f->stores==before);
    }
    aw_list(w,false); f->fail=true; A(matter_acl_write(f->acl,1,MATTER_IM_LIST_REPLACE,w->data,w->size)==MATTER_IM_FAILURE); f->fail=false;
    A(f->view.version==version && f->view.fabrics[0].count==3);
    A(matter_acl_write(f->acl,0,MATTER_IM_LIST_REPLACE,w->data,w->size)==MATTER_IM_UNSUPPORTED_ACCESS);
    /* All declared minima, five independent fabrics, unfiltered read/chunk source. */
    for(unsigned i=1;i<=5;++i) {
        w->size=0; aw_open(w,0x16,-1);
        for(unsigned j=0;j<4;++j) aw_entry_ex(w,100+j*4,5,2,4,3,1);
        aw_byte(w,0x18); A(!matter_acl_write(f->acl,(uint8_t)i,MATTER_IM_LIST_REPLACE,w->data,w->size));
    }
    A(!matter_acl_read(f->acl,0,1,true,&v) && v.size<1024); size_t own_size=v.size;
    A(!matter_acl_read(f->acl,0,1,false,&v) && v.size==own_size+16*5);
    w->size=0; aw_entry(w,999,1,0); A(matter_acl_write(f->acl,1,MATTER_IM_LIST_ADD,w->data,w->size)==MATTER_IM_RESOURCE_EXHAUSTED);
    /* Empty/null Subjects/Targets wildcards; Group entries do not grant CASE. */
    w->size=0; aw_open(w,0x16,-1); aw_entry_ex(w,0,1,2,0,0,0); aw_byte(w,0x18);
    A(!matter_acl_write(f->acl,1,MATTER_IM_LIST_REPLACE,w->data,w->size));
    A(matter_acl_authorize(f->acl,1,999,NULL,0,&other,MATTER_IM_VIEW,NULL));
    w->data[7]=3; A(!matter_acl_write(f->acl,1,MATTER_IM_LIST_REPLACE,w->data,w->size));
    A(!matter_acl_authorize(f->acl,1,999,NULL,0,&other,MATTER_IM_VIEW,NULL));
    /* Self-lockout is allowed by the model; no privileged entry silently retained. */
    w->size=0; aw_open(w,0x16,-1); aw_byte(w,0x18); A(!matter_acl_write(f->acl,1,MATTER_IM_LIST_REPLACE,w->data,w->size));
    A(!matter_acl_authorize(f->acl,1,101,NULL,0,&acl,MATTER_IM_ADMINISTER,NULL));
    A(f->view.fabrics[1].count==4);
    write_identity(f);
    A(matter_acl_delete(f->acl)==MATTER_OK); free(f);
    acl_events(); target_ids(); legacy_acl(); invalid_entries(); invalid_group_write(); proxy_view_compatibility();
#ifdef MATTER_TEST_ALLOC
    A(!live && !live_bytes); encoding_storage();
#endif
    puts("PASS ACL: literal TLV, fabric isolation, Node/CAT/targets/privileges, minima, schema/errors, atomic store, self-revocation and OOM"); return 0;
}
