#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "model/matter_im_invoke.h"
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"Invoke test:%d: %s\n",__LINE__,#c); abort(); } } while (0)
#ifdef MATTER_TEST_ALLOC
static size_t live,calls,fail_at;
void* matter_test_calloc(size_t n,size_t z) { if(++calls==fail_at) return NULL; void* p=calloc(n,z); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { CHECK(live); --live; } free(p); }
#endif
#include "test_invoke_model.h"
static InvokeModel* create(size_t capacity) {
    InvokeModel* m=calloc(1,sizeof(*m)); CHECK(m);
    Matter_Im_Invoke_Port_T p=invoke_port(m); Matter_Im_Invoke_Config_T c={{1,0x1234,false},1000,capacity,true};
    m->active=matter_im_invoke_new(&p,&c,0); CHECK(m->active); return m;
}
static void release(InvokeModel* m) { CHECK(matter_im_invoke_delete(m->active)==MATTER_OK); free(m); }
static Matter_Rx_Decision_T decision(const uint8_t* data,size_t size) {
    return (Matter_Rx_Decision_T){.action=MATTER_RX_NEW_RESPONDER,.session=1,
        .header={.protocol_id=1,.opcode=8,.exchange_id=0x1234,.exchange_flags=5},.payload=data,.payload_size=size};
}
static Matter_Im_Invoke_Message_T start(InvokeModel* m,const uint8_t* data,size_t size) {
    Matter_Rx_Decision_T d=decision(data,size); CHECK(matter_im_invoke_receive(m->active,&d)==MATTER_OK);
    CHECK(matter_im_invoke_receive(m->active,&d)==MATTER_WOULD_BLOCK && !m->auths);
    CHECK(matter_im_invoke_process(m->active,0)==MATTER_PENDING);
    Matter_Im_Invoke_Message_T out; CHECK(matter_im_invoke_output(m->active,&out)==MATTER_OK); return out;
}
static void expect_status(Matter_Im_Invoke_Message_T out,uint8_t code,bool root) {
    if(root) { const uint8_t expected[]={0x15,0x24,0,code,0x24,0xff,13,0x18}; CHECK(out.opcode==1 && out.size==8 && !memcmp(out.data,expected,8)); }
    else {
        const uint8_t expected[]={0x15,0x29,0,0x36,1,0x15,0x35,1,0x37,0,0x24,0,0,0x24,1,0x30,0x24,2,0,0x18,
            0x35,1,0x24,0,code,0x18,0x24,2,42,0x18,0x18,0x18,0x24,0xff,13,0x18};
        CHECK(out.opcode==9 && out.size==sizeof(expected) && !memcmp(out.data,expected,sizeof(expected)));
    }
}
#include "test_invoke_timed.h"
#include "test_invoke_async.h"
int main(void) {
    InvokeModel* m=create(1024); memcpy(m->input,invoke_request,sizeof(invoke_request));
    Matter_Rx_Decision_T d=decision(m->input,sizeof(invoke_request));
    CHECK(matter_im_invoke_receive(m->active,&d)==MATTER_OK);
    d.header.opcode=7; CHECK(matter_im_invoke_receive(m->active,&d)==MATTER_WOULD_BLOCK); d.header.opcode=8;
    memset(m->input,0,sizeof(m->input));
    CHECK(matter_im_invoke_process(m->active,0)==MATTER_PENDING);
    Matter_Im_Invoke_Message_T out; CHECK(matter_im_invoke_output(m->active,&out)==MATTER_OK);
    CHECK(out.opcode==9 && out.size==sizeof(invoke_response) && !memcmp(out.data,invoke_response,out.size));
    CHECK(m->executions==1 && m->value==7 && matter_im_invoke_process(m->active,1)==MATTER_PENDING);
    CHECK(matter_im_invoke_receive(m->active,&d)==MATTER_INVALID_STATE && m->executions==1);
    d.header.opcode=7; CHECK(matter_im_invoke_receive(m->active,&d)==MATTER_INVALID_STATE); d.header.opcode=8;
    CHECK(matter_im_invoke_confirm(m->active,1)==MATTER_INVALID_STATE);
    CHECK(!matter_im_invoke_awaiting_delivery(m->active) && !matter_im_invoke_awaiting_delivery(NULL));
    CHECK(matter_im_invoke_sent(m->active)==MATTER_OK && matter_im_invoke_awaiting_delivery(m->active));
    CHECK(matter_im_invoke_confirm(m->active,2)==MATTER_OK && !matter_im_invoke_awaiting_delivery(m->active));
    CHECK(matter_im_invoke_state(m->active)==MATTER_IM_INVOKE_COMPLETE && m->executions==1); release(m);
    for(unsigned mode=0;mode<13;++mode) {
        m=create(mode==9 ? 8 : mode==10 ? 40 : 1024); uint8_t code=MATTER_IM_FAILURE; bool root=false;
        if(mode<2) { m->deny=code=mode ? MATTER_IM_ACCESS_RESTRICTED : MATTER_IM_UNSUPPORTED_ACCESS; m->second_deny=mode!=0; }
        if(mode==2) m->describe_error=code=MATTER_IM_UNSUPPORTED_COMMAND;
        if(mode==3) { m->metadata.fabric_scoped=true; code=MATTER_IM_UNSUPPORTED_ACCESS; }
        if(mode==4) { m->metadata.timed=true; code=MATTER_IM_NEEDS_TIMED_INTERACTION; }
        if(mode==5) { m->metadata.large_message=true; code=MATTER_IM_INVALID_TRANSPORT_TYPE; }
        if(mode==6) m->validation_error=code=MATTER_IM_INVALID_COMMAND;
        if(mode==7) m->validation_error=code=MATTER_IM_CONSTRAINT_ERROR;
        if(mode==8) m->metadata.privilege=MATTER_IM_VIEW;
        if(mode==9 || mode==10) { code=MATTER_IM_RESOURCE_EXHAUSTED; root=mode==9; }
        if(mode==11) m->metadata.response_capacity=0;
        if(mode==12) m->metadata.response_capacity=1025;
        if(mode>=11) code=MATTER_IM_RESOURCE_EXHAUSTED;
        out=start(m,invoke_request,sizeof(invoke_request)); expect_status(out,code,root); CHECK(!m->executions); release(m);
    }
    for(unsigned mode=0;mode<4;++mode) {
        m=create(1024); m->metadata.response=mode==3;
        memcpy(m->input,invoke_request,sizeof(invoke_request)); if(mode) m->input[1]=0x29;
        if(mode==2) m->result.status=MATTER_IM_FAILURE;
        d=decision(m->input,sizeof(invoke_request)); CHECK(matter_im_invoke_receive(m->active,&d)==MATTER_OK);
        CHECK(matter_im_invoke_process(m->active,0)==(mode==1 || mode==2 ? MATTER_OK : MATTER_PENDING));
        if(mode==1 || mode==2) CHECK(matter_im_invoke_state(m->active)==MATTER_IM_INVOKE_COMPLETE && matter_im_invoke_output(m->active,&out)==MATTER_INVALID_STATE);
        else { CHECK(matter_im_invoke_output(m->active,&out)==MATTER_OK); if(!mode) expect_status(out,0,false); else CHECK(out.size==sizeof(invoke_response)); }
        CHECK(m->executions==1); release(m);
    }
    for(unsigned mode=0;mode<4;++mode) {
        m=create(1024); m->malformed=mode; if(!mode) { m->result.status=1; m->result.has_cluster_status=true; m->result.cluster_status=99; }
        out=start(m,invoke_request,sizeof(invoke_request)); CHECK(m->executions==1);
        if(mode) expect_status(out,MATTER_IM_FAILURE,false);
        else CHECK(out.size==39 && out.data[25]==0x24 && out.data[26]==1 && out.data[27]==99);
        CHECK(matter_im_invoke_process(m->active,1)==MATTER_PENDING && m->executions==1); release(m);
    }
    for(size_t n=0;n<sizeof(invoke_request);++n) {
        m=create(1024); expect_status(start(m,invoke_request,n),MATTER_IM_INVALID_ACTION,true); CHECK(!m->auths); release(m);
    }
    for(unsigned mode=0;mode<9;++mode) {
        m=create(1024); memcpy(m->input,invoke_request,sizeof(invoke_request)); size_t size=sizeof(invoke_request);
        uint8_t code=MATTER_IM_INVALID_ACTION; bool root=true;
        if(mode==0) { m->input[3]=0x29; code=MATTER_IM_TIMED_REQUEST_MISMATCH; }
        if(mode==1) m->input[14]=0; /* duplicate path endpoint */
        if(mode==2) m->input[11]=4; /* missing endpoint/wildcard */
        if(mode==3) { m->input[20]=0x37; code=MATTER_IM_INVALID_COMMAND; root=false; }
        if(mode==4) { m->input[24]=101; code=MATTER_IM_CONSTRAINT_ERROR; root=false; }
        if(mode==5) { memmove(m->input+20,m->input+26,size-26); size-=6; code=MATTER_IM_INVALID_COMMAND; root=false; }
        if(mode==6) { memmove(m->input+7,m->input+30,size-30); size-=23; } /* empty requests */
        if(mode==7) { memmove(m->input+53,m->input+30,size-30); memcpy(m->input+30,invoke_request+7,23); size+=23; } /* two commands */
        if(mode==8) { memmove(m->input+26,m->input+29,size-29); size-=3; } /* optional ref absent */
        out=start(m,m->input,size);
        if(mode==8) { CHECK(m->executions==1 && out.size==sizeof(invoke_response)-3); }
        else { expect_status(out,code,root); CHECK(!m->executions); if(root) CHECK(!m->auths); }
        release(m);
    }
    for(unsigned mode=0;mode<4;++mode) {
        m=create(1024); d=decision(invoke_request,sizeof(invoke_request));
        CHECK(matter_im_invoke_receive(m->active,&d)==MATTER_OK);
        if(mode) { CHECK(matter_im_invoke_process(m->active,0)==MATTER_PENDING); if(mode>1) CHECK(matter_im_invoke_sent(m->active)==MATTER_OK); }
        if(mode==3) CHECK(matter_im_invoke_cancel(m->active)==MATTER_OK);
        else CHECK(matter_im_invoke_process(m->active,1000)==MATTER_PORT_ERROR);
        CHECK(matter_im_invoke_state(m->active)==MATTER_IM_INVOKE_FAILED && m->executions==(mode ? 1u : 0u));
        CHECK(matter_im_invoke_confirm(m->active,1001)==MATTER_INVALID_STATE); release(m);
    }
    m=create(1024); d=decision(invoke_request,sizeof(invoke_request));
    ++d.session; CHECK(matter_im_invoke_receive(m->active,&d)==MATTER_INVALID_ARGUMENT); --d.session;
    d.header.opcode=10; CHECK(matter_im_invoke_receive(m->active,&d)==MATTER_INVALID_ARGUMENT); d.header.opcode=8;
    d.payload=m->input; d.payload_size=1025; CHECK(matter_im_invoke_receive(m->active,&d)==MATTER_LIMIT_REACHED); release(m);
    test_invoke_timed();
    test_invoke_async();
#ifdef MATTER_TEST_ALLOC
    m=create(1024); Matter_Im_Invoke_Port_T p=invoke_port(m); Matter_Im_Invoke_Config_T c={{1,1,false},1,1024,true};
    fail_at=calls+1; CHECK(!matter_im_invoke_new(&p,&c,0)); fail_at=0; release(m); CHECK(!live);
#endif
    puts("PASS Invoke: literal wire, access/schema/preflight, exactly-once effects, refs/suppression, malformed provider, bounds/OOM and abort");
    return 0;
}
