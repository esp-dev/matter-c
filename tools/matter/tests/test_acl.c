#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "clusters/matter_acl.h"
#include "test_acl_wire.h"
#define A(c) do { if(!(c)) { fprintf(stderr,"ACL:%d: %s\n",__LINE__,#c); abort(); } } while(0)
#ifdef MATTER_TEST_ALLOC
static size_t live,calls,fail_at;
void* matter_test_calloc(size_t n,size_t z) { if(++calls==fail_at) return NULL; void* p=calloc(n,z); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { A(live); --live; } free(p); }
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
    A(!matter_cluster_write_list(f->acl,0,&q,MATTER_IM_LIST_REPLACE,w->data,w->size).status);
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
    acl_events(); target_ids(); legacy_acl();
#ifdef MATTER_TEST_ALLOC
    A(!live);
#endif
    puts("PASS ACL: literal TLV, fabric isolation, Node/CAT/targets/privileges, minima, schema/errors, atomic store, self-revocation and OOM"); return 0;
}
