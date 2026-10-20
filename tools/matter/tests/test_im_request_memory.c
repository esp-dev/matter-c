#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "model/matter_im_write.h"
#include "model/matter_im_client.h"
#include "test_alloc_bytes.h"
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"request memory:%d: %s\n",__LINE__,#c); abort(); } } while(0)
#include "test_invoke_model.h"
#include "test_write_model.h"

static Matter_Rx_Decision_T rx(uint8_t opcode,const uint8_t* data,size_t size) {
    return (Matter_Rx_Decision_T){.action=MATTER_RX_NEW_RESPONDER,.session=1,
        .header={.protocol_id=1,.opcode=opcode,.exchange_id=0x1234,.exchange_flags=5},.payload=data,.payload_size=size};
}
static void clean(void) { CHECK(!live && !live_bytes && !allocations); fail_at=0; }
static size_t invoke_scratch,write_scratch;
static Matter_Im_Command_Result_T invoke_noalloc(void* u,const Matter_Im_Command_Path_T* p,const uint8_t* d,size_t n,Matter_Tlv_Writer_T* w) {
    Matter_Im_Command_Result_T result=invoke_execute(u,p,d,n,w); fail_at=calls+1; return result;
}
static void invoke_oom(void) {
    InvokeModel* m=calloc(1,sizeof(*m)); CHECK(m);
    const Matter_Im_Invoke_Config_T config={{1,0x1234,false},1000,1024,true};
    size_t sites=0,owner=0;
    for(size_t failure=0;!failure || failure<=sites;++failure) {
        memset(m,0,sizeof(*m)); Matter_Im_Invoke_Port_T port=invoke_port(m);
        port.invoke=invoke_noalloc;
        size_t first=calls; fail_at=failure ? first+failure : 0;
        m->active=matter_im_invoke_new(&port,&config,0);
        if(m->active) {
            if(!failure) { CHECK(live==1); owner=live_bytes; }
            Matter_Rx_Decision_T d=rx(8,invoke_request,sizeof(invoke_request));
            Matter_Result_T r=matter_im_invoke_receive(m->active,&d);
            if(r==MATTER_OK) {
                if(!failure) { CHECK(live==3); invoke_scratch=live_bytes-owner-sizeof(invoke_request); CHECK(invoke_scratch>1024); }
                r=matter_im_invoke_process(m->active,0);
                if(!failure) {
                    sites=calls-first; CHECK(m->executions==1 && r==MATTER_PENDING);
                    /* Only the owner and response remain after provider input/body consumption. */
                    CHECK(live==2 && live_bytes==owner+80);
                    Matter_Im_Invoke_Message_T out; CHECK(matter_im_invoke_output(m->active,&out)==MATTER_OK);
                    CHECK(out.size==sizeof(invoke_response) && !memcmp(out.data,invoke_response,out.size));
                    size_t sent_calls=calls; fail_at=calls+1;
                    CHECK(matter_im_invoke_sent_at(m->active,1)==MATTER_OK && live==2);
                    CHECK(matter_im_invoke_process(m->active,2)==MATTER_PENDING && calls==sent_calls);
                    CHECK(matter_im_invoke_confirm(m->active,3)==MATTER_OK && live_bytes==owner);
                } else CHECK(!m->executions);
            } else {
                CHECK(r==MATTER_LIMIT_REACHED && !m->executions);
                /* Failed receive does not publish a queued request or advance time. */
                fail_at=0; CHECK(matter_im_invoke_receive_at(m->active,&d,0)==MATTER_OK);
            }
            CHECK(matter_im_invoke_delete(m->active)==MATTER_OK);
        } else CHECK(failure==1);
        clean();
    }
    CHECK(sites==7);
    printf("Invoke owner=%zu, scratch=%zu, response=80, injected sites=%zu\n",owner,invoke_scratch,sites);
    free(m);
}
typedef struct { InvokeModel model; unsigned cancels; } Pending;
static Matter_Result_T pending_start(void* u,const Matter_Im_Command_Path_T* p,const uint8_t* d,size_t n,
    Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* result,uint64_t* token) {
    *result=invoke_noalloc(u,p,d,n,w); *token=42; return MATTER_PENDING;
}
static Matter_Result_T pending_poll(void* u,uint64_t token,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* result) {
    (void)u; (void)w; (void)result; CHECK(token==42); return MATTER_PENDING;
}
static void pending_cancel(void* u,uint64_t token) { Pending* p=u; CHECK(token==42); ++p->cancels; }
static void pending(void) {
    for(unsigned mode=0;mode<3;++mode) {
        Pending* p=calloc(1,sizeof(*p)); CHECK(p);
        Matter_Im_Invoke_Port_T port=invoke_port(&p->model);
        const Matter_Im_Invoke_Async_Port_T async={pending_start,pending_poll,pending_cancel};
        const Matter_Im_Invoke_Config_T config={{1,0x1234,false},1000,1024,true};
        p->model.active=matter_im_invoke_new_async(&port,&async,&config,0); CHECK(p->model.active);
        size_t owner=live_bytes; Matter_Rx_Decision_T d=rx(8,invoke_request,sizeof(invoke_request));
        CHECK(matter_im_invoke_receive(p->model.active,&d)==MATTER_OK);
        CHECK(matter_im_invoke_process(p->model.active,0)==MATTER_PENDING);
        CHECK(live==4 && live_bytes==owner+80+16+invoke_scratch); /* async writer retained, input/args consumed */
        size_t before=calls;
        CHECK(matter_im_invoke_process(p->model.active,1)==MATTER_PENDING && calls==before);
        if(mode==1) CHECK(matter_im_invoke_cancel(p->model.active)==MATTER_OK);
        if(mode==2) CHECK(matter_im_invoke_process(p->model.active,1000)==MATTER_PORT_ERROR);
        CHECK(matter_im_invoke_delete(p->model.active)==MATTER_OK && p->cancels==1);
        free(p); clean();
    }
}

/* A CASE fabric-list model exercises all four same-path IBs. Allocations are
 * made to fail starting at the first mutation; subsequent IBs must still run. */
typedef struct { unsigned writes; bool poison; } ListModel;
static Matter_Result_T fabric(void* u,Matter_Exchange_Session_T s,uint8_t* f) { (void)u; (void)s; *f=1; return MATTER_OK; }
static uint8_t allow(void* u,Matter_Exchange_Session_T s,const Matter_Im_Path_T* p,Matter_Im_Privilege_T v) {
    (void)u; (void)s; (void)p; (void)v; return 0;
}
static uint8_t describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Write_Attribute_T* a) {
    (void)u; CHECK(!p->endpoint && p->cluster==0x1f && !p->attribute);
    *a=(Matter_Im_Write_Attribute_T){.privilege=MATTER_IM_ADMINISTER,.fabric_scoped=true,.list=true}; return 0;
}
static Matter_Result_T version(void* u,const Matter_Im_Path_T* p,uint32_t* v) { (void)u; (void)p; *v=1; return MATTER_OK; }
static uint8_t validate(void* u,const Matter_Im_Path_T* p,const uint8_t* d,size_t n) { (void)u; (void)p; (void)d; (void)n; return 0; }
static Matter_Im_Write_Result_T write_scalar(void* u,const Matter_Im_Path_T* p,const uint8_t* d,size_t n) {
    (void)u; (void)p; (void)d; (void)n; CHECK(false); return (Matter_Im_Write_Result_T){0};
}
static uint8_t validate_list(void* u,const Matter_Im_Path_T* p,Matter_Im_List_Change_T c,const uint8_t* d,size_t n) {
    (void)u; (void)p; (void)c; CHECK(n==2 && d[0]==0x16 && d[1]==0x18); return 0;
}
static Matter_Im_Write_Result_T write_list(void* u,const Matter_Im_Path_T* p,Matter_Im_List_Change_T c,const uint8_t* d,size_t n) {
    ListModel* m=u; (void)p; (void)c; (void)d; (void)n;
    ++m->writes; if(m->poison) fail_at=calls+1; return (Matter_Im_Write_Result_T){0};
}
static void write_oom(void) {
    /* Four empty replacements; same concrete ACL path. */
    const uint8_t ib[]={0x15,0x37,1,0x24,2,0,0x24,3,0x1f,0x24,4,0,0x18,0x36,2,0x18,0x18};
    uint8_t request[80]={0x15,0x28,1,0x36,2}; size_t n=5;
    for(unsigned i=0;i<4;++i) { memcpy(request+n,ib,sizeof(ib)); n+=sizeof(ib); }
    const uint8_t tail[]={0x18,0x24,255,13,0x18}; memcpy(request+n,tail,sizeof(tail)); n+=sizeof(tail);
    size_t sites=0,owner=0;
    for(size_t failure=0;!failure || failure<=sites;++failure) {
        ListModel model={0};
        Matter_Im_Write_Port_T p={&model,allow,describe,version,validate,write_scalar,validate_list,write_list};
        const Matter_Im_Read_Fabric_Port_T f={fabric};
        const Matter_Im_Write_Config_T config={{1,0x1234,false},1000,1024,false};
        size_t first=calls; fail_at=failure ? first+failure : 0;
        Matter_Im_Write_T s=matter_im_write_new_case(&p,&f,&config,0);
        if(s) {
            if(!failure) { CHECK(live==1); owner=live_bytes; model.poison=true; }
            Matter_Rx_Decision_T d=rx(6,request,n);
            Matter_Result_T r=matter_im_write_receive_at(s,&d,0);
            if(r==MATTER_OK) {
                if(!failure) { CHECK(live==3); write_scratch=live_bytes-owner-n; CHECK(write_scratch>1024); }
                r=matter_im_write_process(s,0);
                if(!failure) {
                    sites=calls-first; CHECK(r==MATTER_PENDING && model.writes==4);
                    CHECK(live==2 && live_bytes==owner+200);
                    CHECK(matter_im_write_sent_at(s,1)==MATTER_OK && live==2);
                    size_t sent_calls=calls;
                    CHECK(matter_im_write_confirm(s,2)==MATTER_OK && calls==sent_calls && live_bytes==owner);
                } else CHECK(!model.writes);
            } else {
                CHECK(r==MATTER_LIMIT_REACHED && !model.writes); fail_at=0;
                CHECK(matter_im_write_receive_at(s,&d,0)==MATTER_OK);
            }
            CHECK(matter_im_write_delete(s)==MATTER_OK);
        } else CHECK(failure==1);
        clean();
    }
    CHECK(sites==7);
    printf("Write owner=%zu, scratch=%zu, four-IB response=200, injected sites=%zu\n",owner,write_scratch,sites);
}
static void queued(void) {
    WriteModel* m=calloc(1,sizeof(*m)); CHECK(m);
    Matter_Im_Write_Port_T p=write_port(m); const Matter_Im_Write_Config_T config={{1,0x1234,false},1000,1024,true};
    m->active=matter_im_write_new(&p,&config,0); CHECK(m->active);
    Matter_Rx_Decision_T d=rx(10,write_timed,sizeof(write_timed));
    CHECK(matter_im_write_receive_at(m->active,&d,0)==MATTER_OK && matter_im_write_process(m->active,0)==MATTER_PENDING);
    Matter_Im_Write_Message_T out; CHECK(matter_im_write_output(m->active,&out)==MATTER_OK);
    uint8_t saved[8]; CHECK(out.size==sizeof(saved)); memcpy(saved,out.data,sizeof(saved));
    CHECK(matter_im_write_sent_at(m->active,1)==MATTER_OK);
    uint8_t request[sizeof(write_request)]; memcpy(request,write_request,sizeof(request)); request[1]=0x29;
    d=rx(6,request,sizeof(request)); size_t before=live_bytes;
    fail_at=calls+1; CHECK(matter_im_write_receive_at(m->active,&d,2)==MATTER_LIMIT_REACHED && live_bytes==before);
    CHECK(!memcmp(saved,out.data,sizeof(saved)) && !m->writes);
    fail_at=0; CHECK(matter_im_write_receive_at(m->active,&d,2)==MATTER_OK); memset(request,0,sizeof(request));
    CHECK(matter_im_write_process(m->active,2)==MATTER_PENDING && !m->writes && !memcmp(saved,out.data,sizeof(saved)));
    CHECK(matter_im_write_confirm(m->active,3)==MATTER_OK);
    CHECK(matter_im_write_process(m->active,3)==MATTER_PENDING && m->writes==1);
    CHECK(matter_im_write_delete(m->active)==MATTER_OK); free(m); clean();
}
static void client_oom(void) {
    const uint8_t fields[]={0x15,0x24,0,2,0x18};
    const uint8_t reply[]={0x15,0x28,0,0x36,1,0x15,0x35,0,0x37,0,0x24,0,1,0x24,1,0x29,0x24,2,1,0x18,
        0x35,1,0x24,0,2,0x18,0x18,0x18,0x18,0x24,255,13,0x18};
    Matter_Im_Command_Path_T path={1,0x29,0}; size_t owner=0;
    for(size_t failure=0;failure<=6;++failure) {
        fail_at=failure ? calls+failure : 0;
        Matter_Im_Client_T c=matter_im_client_new(&path,1,fields,sizeof(fields));
        if(c) {
            CHECK(failure==0 || failure>=4);
            if(!failure) { CHECK(live==2); owner=live_bytes-(sizeof(fields)+48); }
            CHECK(matter_im_client_sent(c)==MATTER_OK && live_bytes==owner);
            Matter_Result_T r=matter_im_client_receive(c,9,reply,sizeof(reply));
            if(failure) {
                CHECK(r==MATTER_LIMIT_REACHED); uint8_t code; const uint8_t* body; size_t n;
                CHECK(matter_im_client_result(c,&code,&body,&n)==MATTER_PENDING);
                fail_at=0; CHECK(matter_im_client_receive(c,9,reply,sizeof(reply))==MATTER_OK);
            } else CHECK(r==MATTER_OK);
            Matter_Im_Read_Message_T out; CHECK(matter_im_client_output(c,&out)==MATTER_OK && out.size==8);
            CHECK(live_bytes==owner+6+8); size_t before=calls; fail_at=calls+1;
            uint8_t code; const uint8_t* body; size_t n;
            CHECK(matter_im_client_result(c,&code,&body,&n)==MATTER_PENDING);
            CHECK(matter_im_client_sent(c)==MATTER_OK && calls==before && live_bytes==owner+6);
            CHECK(matter_im_client_result(c,&code,&body,&n)==MATTER_OK && !code && n==sizeof(fields) && !memcmp(body,fields,n));
            matter_im_client_delete(c);
        } else CHECK(failure>=1 && failure<=3);
        clean();
    }
    printf("Client owner=%zu, request=%zu, result=6, status=8, injected sites=6\n",owner,sizeof(fields)+48);
}
int main(void) {
    invoke_oom(); pending(); write_oom(); queued(); client_oom();
    puts("PASS demand request/reply/result memory: every allocation OOM, no model effects, four IBs, queued RX and delivery lifetimes"); return 0;
}
