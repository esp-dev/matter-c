#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_root_fixture.h"
#include "model/matter_cluster.h"
#include "clusters/matter_root_internal.h"
#ifdef MATTER_TEST_ALLOC
static size_t live,calls,fail_at;
void* matter_test_calloc(size_t n,size_t z) { if(++calls==fail_at) return NULL; void* p=calloc(n,z); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { ROOT_CHECK(live); --live; } free(p); }
#endif
typedef struct { Matter_Cluster_T cluster; Matter_Cluster_Request_T last; uint32_t version; uint64_t value; unsigned starts,polls,cancels,destroys; bool ready,drain,fail; } State;
static Matter_Result_T version(void* u,uint32_t* v) { State* s=u; *v=s->version; return s->fail?MATTER_PORT_ERROR:MATTER_OK; }
static Matter_Result_T destroy(void* u) { State* s=u; if(s->drain) return MATTER_BUSY; ++s->destroys; return MATTER_OK; }
static uint8_t read_value(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    State* s=u; s->last=*q;
    ROOT_CHECK(matter_cluster_delete(s->cluster)==MATTER_BUSY);
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=s->value+*(const unsigned*)ref,.data_version=s->version}; return 0;
}
static uint8_t validate(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    (void)u; (void)ref; (void)q; return n==2 && d[0]==4?0:MATTER_IM_INVALID_DATA_TYPE;
}
static Matter_Im_Write_Result_T write_value(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    (void)ref; (void)q; (void)n; State* s=u;
    if(s->value!=d[1]) { s->value=d[1]; ++s->version; } return (Matter_Im_Write_Result_T){0};
}
static uint8_t read_list(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; State* s=u; static const uint8_t empty[]={0x16,0x18};
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_ARRAY,.data=empty,.size=sizeof(empty),.data_version=s->version}; return 0;
}
static uint8_t validate_list(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_List_Change_T c,const uint8_t* d,size_t n) {
    (void)u; (void)ref; return q->is_case && q->fabric==7 && c==MATTER_IM_LIST_REPLACE && n==2 && d[0]==0x16 && d[1]==0x18?0:MATTER_IM_CONSTRAINT_ERROR;
}
static Matter_Im_Write_Result_T write_list(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_List_Change_T c,const uint8_t* d,size_t n) {
    (void)u; (void)ref; (void)q; (void)c; (void)d; (void)n;
    return (Matter_Im_Write_Result_T){.status=MATTER_IM_FAILURE,.has_cluster_status=true,.cluster_status=0x37};
}
static uint8_t validate_command(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    (void)u; (void)ref; (void)q; return n==2 && d[0]==0x15 && d[1]==0x18?0:MATTER_IM_INVALID_COMMAND;
}
static Matter_Result_T start(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* r,uint64_t* token) {
    (void)ref; (void)q; (void)d; (void)n; (void)w; (void)r; State* s=u; ++s->starts; *token=77; return MATTER_PENDING;
}
static Matter_Result_T poll(void* u,const void* ref,uint64_t token,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out) {
    (void)w; State* s=u; ROOT_CHECK(token==77); ++s->polls;
    if(!s->ready) return MATTER_PENDING;
    *out=(Matter_Im_Command_Result_T){.status=(uint8_t)*(const unsigned*)ref}; return MATTER_OK;
}
static void cancel(void* u,const void* ref,uint64_t token) { (void)ref; ROOT_CHECK(token==77); ++((State*)u)->cancels; }
static Matter_Cluster_T make(State* s,uint32_t id) {
    Matter_Cluster_Config_T c={.id=id,.attributes=3,.commands=2,.events=1,.pending=2,
        .callbacks={.ctx=s,.version=version,.destroy=destroy}};
    Matter_Cluster_T m=matter_cluster_new(&c); if(!m) return NULL; s->cluster=m;
    static const unsigned refs[]={0,6};
    Matter_Attribute_Def_T a={.id=6,.read_access={MATTER_IM_VIEW,false},.write_access={.privilege=MATTER_IM_MANAGE},
        .ref=&refs[0],.read=read_value,.validate=validate,.write=write_value};
    ROOT_CHECK(matter_cluster_add_attribute(m,&a)==MATTER_OK && matter_cluster_add_attribute(m,&a)==MATTER_INVALID_ARGUMENT);
    a.id=2; a.ref=&refs[1]; ROOT_CHECK(matter_cluster_add_attribute(m,&a)==MATTER_OK);
    Matter_Attribute_Def_T list={.id=4,.read_access={MATTER_IM_VIEW,true},.write_access={.privilege=MATTER_IM_MANAGE,.list=true,.fabric_scoped=true},.read=read_list,.validate_list=validate_list,.write_list=write_list};
    ROOT_CHECK(matter_cluster_add_attribute(m,&list)==MATTER_OK);
    a.id=7; ROOT_CHECK(matter_cluster_add_attribute(m,&a)==MATTER_LIMIT_REACHED);
    for(unsigned i=0;i<2;++i) {
        Matter_Command_Def_T command={.id=i+3,.access={.privilege=MATTER_IM_OPERATE},.ref=&refs[i],.validate=validate_command,.start=start,.poll=poll,.cancel=cancel};
        ROOT_CHECK(matter_cluster_add_command(m,&command)==MATTER_OK && matter_cluster_add_command(m,&command)==MATTER_INVALID_ARGUMENT);
    }
    Matter_Event_Def_T event={.id=8,.privilege=MATTER_IM_VIEW,.priority=1};
    ROOT_CHECK(matter_cluster_add_event(m,&event)==MATTER_OK && matter_cluster_add_event(m,&event)==MATTER_INVALID_ARGUMENT);
    ROOT_CHECK(matter_cluster_event(m,8)->priority==1 && !matter_cluster_event(m,9));
    return m;
}
static void endpoint_routing(void) {
    State* root=calloc(1,sizeof(*root)); State* leaf=calloc(1,sizeof(*leaf)); ROOT_CHECK(root && leaf);
    Matter_Cluster_T a=make(root,0xfff10001),b=make(leaf,0xfff10001); ROOT_CHECK(a && b);
    RootFixture* f=root_fixture(); root_open(f);
    Matter_Root_Endpoint_Config_T ep={1,1,0x0510,11};
    ROOT_CHECK(matter_root_add_endpoint(f->root,&ep)==MATTER_OK && matter_root_attach_cluster(f->root,a)==MATTER_OK && matter_root_attach_cluster_at(f->root,1,b)==MATTER_OK);
    Matter_Im_Path_T path={1,0xfff10001,6}; const uint8_t data[]={4,73}; Matter_Im_Value_T value;
    ROOT_CHECK(!f->write.write(f->write.user,&path,data,sizeof(data)).status && leaf->value==73 && !root->value);
    ROOT_CHECK(!f->read.read(f->read.user,&path,true,&value) && value.unsigned_value==73);
    Matter_Cluster_Request_T q={.is_case=true,.fabric=7}; path.attribute=4;
    Matter_Im_Write_Result_T list=matter_root_cluster_list(f->root,&path,&q,MATTER_IM_LIST_REPLACE,(const uint8_t[]){0x16,0x18},2,true);
    ROOT_CHECK(list.status==MATTER_IM_FAILURE && list.has_cluster_status && list.cluster_status==0x37);
    Matter_Root_Async_Invoke_Binding_T binding; Matter_Im_Invoke_Port_T ip; Matter_Im_Invoke_Async_Port_T ap;
    ROOT_CHECK(matter_root_async_invoke_port(f->root,f->session,&binding,&ip,&ap)==MATTER_OK);
    const uint8_t args[]={0x15,0x18}; Matter_Im_Command_Result_T result; uint64_t token;
    Matter_Im_Command_Path_T command={1,0xfff10001,3};
    ROOT_CHECK(ap.start(ip.user,&command,args,2,NULL,&result,&token)==MATTER_PENDING && binding.pending_endpoint==1);
    ROOT_CHECK(leaf->starts==1 && !root->starts && matter_root_delete(f->root)==MATTER_BUSY);
    ROOT_CHECK(ap.poll(ip.user,token,NULL,&result)==MATTER_PENDING && leaf->polls==1 && !root->polls);
    ap.cancel(ip.user,token); ROOT_CHECK(leaf->cancels==1 && !root->cancels);
    leaf->ready=true; command.command=4;
    ROOT_CHECK(ap.start(ip.user,&command,args,2,NULL,&result,&token)==MATTER_PENDING && ap.poll(ip.user,token,NULL,&result)==MATTER_OK && result.status==6);
    ROOT_CHECK(matter_cluster_delete(a)==MATTER_BUSY && matter_cluster_delete(b)==MATTER_BUSY);
    root_release(f); ROOT_CHECK(matter_cluster_delete(a)==MATTER_OK && matter_cluster_delete(b)==MATTER_OK);
    free(root); free(leaf);
}
static void event_enumeration(void) {
    State* state=calloc(1,sizeof(*state)); ROOT_CHECK(state);
    Matter_Cluster_Config_T config={.id=0xfff10003,.events=3,.callbacks={.ctx=state,.version=version}};
    Matter_Cluster_T c=matter_cluster_new(&config); ROOT_CHECK(c);
    const uint32_t inserted[]={9,3,6};
    for(unsigned i=0;i<3;++i) {
        Matter_Event_Def_T e={.id=inserted[i],.privilege=MATTER_IM_VIEW,.priority=1};
        ROOT_CHECK(matter_cluster_add_event(c,&e)==MATTER_OK);
    }
    ROOT_CHECK(!matter_cluster_event_count(NULL) && matter_cluster_event_count(c)==3);
    uint32_t id=99;
    ROOT_CHECK(!matter_cluster_event_at(NULL,0,&id) && !matter_cluster_event_at(c,0,NULL) && !matter_cluster_event_at(c,3,&id) && id==99);
    for(unsigned i=0;i<3;++i) ROOT_CHECK(matter_cluster_event_at(c,i,&id) && id==3*(i+1));
    RootFixture* f=root_fixture(); root_open(f);
    ROOT_CHECK(matter_root_attach_cluster(f->root,c)==MATTER_OK);
    Matter_Root_Endpoint_Config_T ep={9,1,0x0510,11};
    ROOT_CHECK(matter_root_add_endpoint(f->root,&ep)==MATTER_OK && matter_root_attach_cluster_at(f->root,9,c)==MATTER_OK);
    ep.endpoint=2; ROOT_CHECK(matter_root_add_endpoint(f->root,&ep)==MATTER_OK && matter_root_attach_cluster_at(f->root,2,c)==MATTER_OK);
    const uint8_t masks[]={0,1,2,3,6,7}; const unsigned counts[]={10,3,9,3,3,1};
    for(unsigned t=0;t<6;++t) {
        Matter_Im_Event_Selector_T q={{2,0xfff10003,6},masks[t]};
        Matter_Event_Path_T path={0}; bool found=false; unsigned count=0;
        do {
            /* Alias after/out deliberately: the Root callback copies its cursor. */
            ROOT_CHECK(matter_root_event_enumerate(f->root,&q,count?&path:NULL,&path,&found)==MATTER_OK);
            if(found) {
                ROOT_CHECK(++count<=10);
                if(t==2) ROOT_CHECK(path.endpoint==(count<=3?0:count<=6?2:9) && path.event==3*((count-1)%3+1));
            }
        } while(found);
        ROOT_CHECK(count==counts[t]);
    }
    Matter_Im_Event_Selector_T bad={{0,0,1},4}; Matter_Event_Path_T next; bool found;
    ROOT_CHECK(matter_root_event_enumerate(f->root,&bad,NULL,&next,&found)==MATTER_INVALID_ARGUMENT);
    bad.present=128; ROOT_CHECK(matter_root_event_enumerate(f->root,&bad,NULL,&next,&found)==MATTER_INVALID_ARGUMENT);
    root_release(f); ROOT_CHECK(matter_cluster_delete(c)==MATTER_OK); free(state);
    puts("PASS event metadata enumeration: sorted IDs/endpoints, six selectors, no log dependency, aliased cursor, invalid arguments and shared cluster lifetime");
}
int main(void) {
    event_enumeration();
    endpoint_routing();
    (void)root_read_request; (void)root_write_request; (void)root_report;
    State* s=calloc(1,sizeof(*s)); State* other=calloc(1,sizeof(*other)); ROOT_CHECK(s && other);
#ifdef MATTER_TEST_ALLOC
    fail_at=calls+1; ROOT_CHECK(!make(s,0xfff10001) && !s->destroys); fail_at=0;
#endif
    Matter_Cluster_T c=make(s,0xfff10001),second=make(other,0xfff10002); ROOT_CHECK(c && second);
    /* The common type still rejects use with a different private implementation. */
    ROOT_CHECK(!matter_acl_version(c) && !matter_wifi_version(c) && !matter_opcreds_version(c));
    ROOT_CHECK(matter_wifi_write(c,NULL,0)==MATTER_IM_FAILURE && matter_wifi_validate(c,0,NULL,0)==MATTER_IM_FAILURE);
    ROOT_CHECK(matter_wifi_commit(c)==MATTER_INVALID_ARGUMENT && matter_opcreds_commit(c)==MATTER_INVALID_ARGUMENT);
    ROOT_CHECK(matter_opcreds_validate(c,0,NULL,0)==MATTER_IM_FAILURE && matter_diagnostics_validate(c,0x33,0,NULL,0)==MATTER_IM_FAILURE);
    ROOT_CHECK(matter_diagnostics_invoke(c,0x33,0,NULL,0,NULL).status==MATTER_IM_FAILURE);
    Matter_Cluster_Request_T q={0}; Matter_Im_Value_T value;
    ROOT_CHECK(matter_cluster_read(c,6,&q,&value)==0 && !value.unsigned_value);
    ROOT_CHECK(matter_cluster_read(c,1,&q,&value)==MATTER_IM_UNSUPPORTED_ATTRIBUTE);
    ROOT_CHECK(matter_cluster_write(c,6,&q,(const uint8_t[]){8},1).status==MATTER_IM_INVALID_DATA_TYPE && !s->version);
    ROOT_CHECK(!matter_cluster_write(c,6,&q,(const uint8_t[]){4,42},2).status && s->version==1);
    ROOT_CHECK(!matter_cluster_read(second,6,&q,&value) && !value.unsigned_value);
    RootFixture* f=root_fixture(); root_open(f);
    ROOT_CHECK(matter_root_attach_cluster(f->root,c)==MATTER_OK && matter_root_attach_cluster(f->root,c)==MATTER_INVALID_STATE);
    ROOT_CHECK(matter_cluster_delete(c)==MATTER_BUSY && matter_root_attach_cluster(f->root,second)==MATTER_OK);
    Matter_Im_Selector_T selector={0}; Matter_Im_Path_T path={0}; bool found; unsigned count=0;
    /* Aliased after/next is explicitly supported by the existing IM contract. */
    while(f->read.enumerate(f->read.user,&selector,count?&path:NULL,&path,&found)==MATTER_OK && found) ++count;
    ROOT_CHECK(count==36 && path.cluster==0xfff10002 && path.attribute==6);
    path=(Matter_Im_Path_T){0,0xfff10001,6};
    ROOT_CHECK(!f->read.read(f->read.user,&path,false,&value) && value.unsigned_value==42);
    Matter_Root_Invoke_Binding_T read_binding; Matter_Im_Read_Port_T bound; Matter_Im_Read_Fabric_Port_T fabric;
    ROOT_CHECK(matter_root_fabric_read_port(f->root,f->session,&read_binding,&bound,&fabric)==MATTER_OK);
    ROOT_CHECK(!bound.read(bound.user,&path,true,&value) && s->last.session==f->session && !s->last.is_case && !s->last.fabric && s->last.filtered);

    uint32_t v; s->fail=true; ROOT_CHECK(f->read.version(f->read.user,&path,&v)==MATTER_PORT_ERROR); s->fail=false;
    ROOT_CHECK(!f->write.write(f->write.user,&path,(const uint8_t[]){4,43},2).status && s->value==43);
    Matter_Im_Path_T list_path={0,0xfff10001,4}; Matter_Cluster_Request_T list_request={.fabric=7,.is_case=true};
    Matter_Im_Write_Result_T list_result=matter_root_cluster_list(f->root,&list_path,&list_request,MATTER_IM_LIST_REPLACE,(const uint8_t[]){0x16,0x18},2,true);
    ROOT_CHECK(list_result.status==MATTER_IM_FAILURE && list_result.has_cluster_status && list_result.cluster_status==0x37);

    /* Generic IM Invoke: application authorizer still gates effects. */
    Matter_Root_Async_Invoke_Binding_T binding; Matter_Im_Invoke_Port_T ip; Matter_Im_Invoke_Async_Port_T ap;
    ROOT_CHECK(matter_root_async_invoke_port(f->root,f->session,&binding,&ip,&ap)==MATTER_OK);
    Matter_Im_Command_Path_T command={0,0xfff10001,3}; Matter_Im_Command_T metadata; Matter_Im_Command_Result_T result; uint64_t token,token2;
    ROOT_CHECK(ip.describe(ip.user,&command,&metadata)==0 && metadata.privilege==MATTER_IM_OPERATE);
    f->denied=MATTER_IM_UNSUPPORTED_ACCESS; ROOT_CHECK(ip.authorize(ip.user,f->session,&command,MATTER_IM_OPERATE)==MATTER_IM_UNSUPPORTED_ACCESS && !s->starts); f->denied=0;
    static const uint8_t args[]={0x15,0x18};
    ROOT_CHECK(ip.invoke(ip.user,&command,args,sizeof(args),NULL).status==MATTER_IM_INVALID_ACTION && !s->starts);
    ROOT_CHECK(ap.start(ip.user,&command,args,sizeof(args),NULL,&result,&token)==MATTER_PENDING);
    ROOT_CHECK(matter_root_delete(f->root)==MATTER_BUSY && matter_cluster_delete(c)==MATTER_BUSY);
    ROOT_CHECK(matter_cluster_start(c,4,&q,args,sizeof(args),NULL,&result,&token2)==MATTER_PENDING && token2!=token);
    uint64_t none; ROOT_CHECK(matter_cluster_start(c,3,&q,args,sizeof(args),NULL,&result,&none)==MATTER_OK && result.status==MATTER_IM_RESOURCE_EXHAUSTED && !none && s->starts==2);
    ROOT_CHECK(ap.poll(ip.user,token,NULL,&result)==MATTER_PENDING);
    s->ready=true; ROOT_CHECK(matter_cluster_poll(c,token2,NULL,&result)==MATTER_OK && result.status==6);
    ap.cancel(ip.user,token); ROOT_CHECK(s->cancels==1 && matter_cluster_poll(c,token,NULL,&result)==MATTER_INVALID_STATE);
    ROOT_CHECK(matter_cluster_start(c,3,&q,args,sizeof(args),NULL,&result,&token2)==MATTER_PENDING && token2>token);
    ROOT_CHECK(matter_cluster_cancel(c,token2)==MATTER_OK);
    static const uint8_t invoke[]={0x15,0x28,0,0x28,1,0x36,2,0x15,0x37,0,0x24,0,0,0x26,1,1,0,0xf1,0xff,0x24,2,3,0x18,0x35,1,0x18,0x18,0x18,0x24,0xff,13,0x18};
    for(unsigned denied=0;denied<2;++denied) {
        Matter_Im_Invoke_Config_T config={{f->session,0x4321,false},1000,256,true};
        Matter_Im_Invoke_T handler=matter_im_invoke_new_async(&ip,&ap,&config,0); ROOT_CHECK(handler);
        Matter_Rx_Decision_T rx={.action=MATTER_RX_NEW_RESPONDER,.session=f->session,
            .header={.protocol_id=1,.opcode=8,.exchange_id=0x4321,.exchange_flags=5},.payload=invoke,.payload_size=sizeof(invoke)};
        unsigned starts=s->starts; f->denied=denied?MATTER_IM_UNSUPPORTED_ACCESS:0;
        ROOT_CHECK(matter_im_invoke_receive_at(handler,&rx,0)==MATTER_OK);
        for(unsigned i=0;i<4 && matter_im_invoke_state(handler)!=MATTER_IM_INVOKE_OUTPUT;++i) ROOT_CHECK(matter_im_invoke_process(handler,i)==MATTER_PENDING);
        Matter_Im_Invoke_Message_T output; ROOT_CHECK(matter_im_invoke_output(handler,&output)==MATTER_OK && output.opcode==9);
        ROOT_CHECK(s->starts==starts+(denied?0:1));
        const uint8_t reply[]={0x15,0x29,0,0x36,1,0x15,0x35,1,0x37,0,0x24,0,0,0x26,1,1,0,0xf1,0xff,0x24,2,3,0x18,0x35,1,0x24,0,denied?MATTER_IM_UNSUPPORTED_ACCESS:0,0x18,0x18,0x18,0x18,0x24,255,13,0x18};
        ROOT_CHECK(output.size==sizeof(reply) && !memcmp(output.data,reply,sizeof(reply)));
        ROOT_CHECK(matter_im_invoke_delete(handler)==MATTER_OK);
    }
    ROOT_CHECK(matter_root_delete(f->root)==MATTER_OK); f->root=NULL; root_release(f);
    s->drain=true; ROOT_CHECK(matter_cluster_delete(c)==MATTER_BUSY && !s->destroys); s->drain=false;
    ROOT_CHECK(matter_cluster_delete(c)==MATTER_OK && s->destroys==1 && matter_cluster_delete(second)==MATTER_OK);
    free(s); free(other);
#ifdef MATTER_TEST_ALLOC
    ROOT_CHECK(!live);
#endif
    puts("PASS generic clusters: dynamic descriptors, duplicate/capacity, isolated state, Root enumeration/read/write/command routing, auth, async pins/tokens/cancel/drain and OOM"); return 0;
}
