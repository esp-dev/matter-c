#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "model/matter_im_subscribe.h"
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"Subscribe:%d: %s\n",__LINE__,#c); abort(); } } while(0)
#ifdef MATTER_TEST_ALLOC
#include "test_alloc_bytes.h"
#endif
#include "test_subscribe_model.h"
static SubModel* create(size_t cap) {
    SubModel* m=calloc(1,sizeof(*m)); CHECK(m); Matter_Im_Subscribe_Port_T p=sub_port(m);
    Matter_Im_Subscribe_Config_T c={{1,12,false},10000,cap,true}; m->active=matter_im_subscribe_new(&p,&c,0); CHECK(m->active); return m;
}
static void release(SubModel* m) { CHECK(matter_im_subscribe_delete(m->active)==MATTER_OK); free(m); }
static Matter_Rx_Decision_T decision(const uint8_t* data,size_t size,uint8_t opcode,uint16_t exchange,bool initiator) {
    return (Matter_Rx_Decision_T){.action=MATTER_RX_EXISTING,.session=1,.header={.protocol_id=1,.opcode=opcode,.exchange_id=exchange,.exchange_flags=initiator ? 1 : 0},.payload=data,.payload_size=size};
}
static void receive(SubModel* m,const uint8_t* data,size_t n,uint8_t opcode,uint16_t exchange,bool initiator) {
    Matter_Rx_Decision_T d=decision(data,n,opcode,exchange,initiator); CHECK(matter_im_subscribe_receive(m->active,&d)==MATTER_OK);
    CHECK(matter_im_subscribe_receive(m->active,&d)==MATTER_WOULD_BLOCK);
}
static Matter_Im_Subscribe_Message_T output(SubModel* m,uint64_t now) {
    CHECK(matter_im_subscribe_process(m->active,now)==MATTER_PENDING);
    Matter_Im_Subscribe_Message_T out; CHECK(matter_im_subscribe_output(m->active,&out)==MATTER_OK); return out;
}
static void literal(Matter_Im_Subscribe_Message_T out,uint8_t opcode,const uint8_t* data,size_t n) { CHECK(out.opcode==opcode && out.size==n && !memcmp(out.data,data,n)); }
static void prime(SubModel* m,bool ack_first) {
    receive(m,sub_request,sizeof(sub_request),3,12,true); literal(output(m,0),5,sub_report,sizeof(sub_report));
    CHECK(m->reads==1 && m->reserves==1 && m->keep && matter_im_subscribe_sent_at(m->active,100)==MATTER_OK);
    if(ack_first) CHECK(matter_im_subscribe_confirm(m->active,101)==MATTER_OK);
    receive(m,sub_success,sizeof(sub_success),1,12,true);
    if(!ack_first) {
        CHECK(matter_im_subscribe_process(m->active,101)==MATTER_PENDING && matter_im_subscribe_state(m->active)==MATTER_IM_SUB_IN_FLIGHT);
        CHECK(matter_im_subscribe_confirm(m->active,102)==MATTER_OK);
    }
    literal(output(m,103),4,sub_response,sizeof(sub_response));
    CHECK(matter_im_subscribe_sent_at(m->active,104)==MATTER_OK && matter_im_subscribe_confirm(m->active,105)==MATTER_OK);
    CHECK(matter_im_subscribe_state(m->active)==MATTER_IM_SUB_IDLE);
}
typedef struct { SubModel model; uint8_t fabric; bool revoked; } SubCase;
static Matter_Result_T sub_case_index(void* u,Matter_Exchange_Session_T session,uint8_t* index) {
    SubCase* c=u; CHECK(session==1); sub_guard(&c->model); *index=c->fabric; return c->revoked?MATTER_INVALID_STATE:MATTER_OK;
}
static void case_tests(void) {
    for(unsigned mode=0;mode<7;++mode) {
        SubCase* c=calloc(1,sizeof(*c)); CHECK(c); SubModel* m=&c->model; c->fabric=1;
        Matter_Im_Subscribe_Port_T p=sub_port(m); Matter_Im_Read_Fabric_Port_T resolver={sub_case_index};
        Matter_Im_Subscribe_Config_T config={{1,12,false},10000,128,false};
        CHECK(!matter_im_subscribe_new(&p,&config,0) && !matter_im_subscribe_new_case(&p,NULL,&config,0));
        config.pase_commissionee=true; CHECK(!matter_im_subscribe_new_case(&p,&resolver,&config,0)); config.pase_commissionee=false;
#ifdef MATTER_TEST_ALLOC
        fail_at=calls+1; CHECK(!matter_im_subscribe_new_case(&p,&resolver,&config,0)); fail_at=0;
#endif
        m->active=matter_im_subscribe_new_case(&p,&resolver,&config,0); CHECK(m->active); m->fabric=true;
        if(mode<3) {
            c->fabric=mode==0?0:mode==1?255:1; c->revoked=mode==2;
            receive(m,sub_request,sizeof(sub_request),3,12,true); Matter_Im_Subscribe_Message_T out=output(m,0);
            CHECK(out.opcode==1 && out.data[3]==MATTER_IM_INVALID_ACTION && !m->reserves && !m->reads);
        } else {
            prime(m,true); /* A scalar fabric-scoped attribute is allowed only on CASE. */
            if(mode==3) c->fabric=2;
            if(mode==4) c->revoked=true;
            if(mode==5) c->fabric=0;
            CHECK(matter_im_subscribe_process(m->active,5100)==MATTER_PENDING);
            Matter_Exchange_Info_T e={1,13,true}; CHECK(matter_im_subscribe_bind_report(m->active,&e,5100)==MATTER_OK);
            Matter_Im_Subscribe_Message_T out=output(m,5100);
            if(mode==6) literal(out,5,sub_empty,sizeof(sub_empty));
            else {
                static const uint8_t denied[]={0x15,0x24,0,42,0x36,1,0x15,0x35,0,0x37,0,0x24,2,0,0x24,3,0x28,0x24,4,2,
                    0x18,0x35,1,0x24,0,0x7e,0x18,0x18,0x18,0x18,0x28,4,0x24,255,13,0x18};
                literal(out,5,denied,sizeof(denied)); CHECK(m->reads==1);
            }
        }
        CHECK(matter_im_subscribe_cancel(m->active)==MATTER_OK && m->releases==(mode<3?0u:1u));
        CHECK(matter_im_subscribe_delete(m->active)==MATTER_OK); free(c);
    }
    puts("PASS CASE Subscribe: trusted constructor, live fabric before reserve/report/heartbeat, zero/revoked/changed identity, scoped scalar, release and OOM");
}
#include "test_subscribe_complex.h"
#include "test_subscribe_lists.h"
#include "test_subscribe_selectors.h"
#include "test_subscribe_memory.h"
#define TEST_MULTI_SUB
#include "test_im_multi_events.h"
#include "test_im_event_wildcards.h"
#define TEST_PATH_SUB
#include "test_im_path_grammar.h"
int main(int argc,char** argv) {
    if(argc==2 && (!strcmp(argv[1],"--memory-only") || !strcmp(argv[1],"--memory-profile"))) {
        subscription_memory_profile();
#ifdef MATTER_TEST_ALLOC
        if(!strcmp(argv[1],"--memory-only")) subscription_memory_oom();
#endif
        return 0;
    }
#ifdef MATTER_TEST_ALLOC
    subscription_memory_oom();
#endif
    path_grammar_tests();
    /* MP04 countdown quality: unrelated dirty notifications and heartbeat must
     * not report a new IdentifyTime until an explicitly reportable version. */
    {
        SubModel* m=create(128); m->report_on_version=true; prime(m,true);
        const uint64_t times[]={2100,3100,4100,9100,11100};
        for(unsigned step=0;step<5;++step) {
            uint64_t now=times[step];
            m->value=10+step; if(step==2) ++m->version;
            if(step==4) m->deny=true;
            CHECK(matter_im_subscribe_changed(m->active)==MATTER_OK);
            CHECK(matter_im_subscribe_process(m->active,now)==MATTER_PENDING);
            Matter_Exchange_Info_T e={1,(uint16_t)(13+step),true};
            CHECK(matter_im_subscribe_bind_report(m->active,&e,now)==MATTER_OK);
            if(step<2) {
                CHECK(matter_im_subscribe_process(m->active,now)==MATTER_PENDING);
                Matter_Im_Subscribe_Message_T out; uint64_t deadline;
                CHECK(matter_im_subscribe_state(m->active)==MATTER_IM_SUB_IDLE && matter_im_subscribe_output(m->active,&out)==MATTER_INVALID_STATE);
                CHECK(matter_im_subscribe_deadline(m->active,&deadline)==MATTER_OK && deadline==5100);
                continue;
            }
            Matter_Im_Subscribe_Message_T out=output(m,now);
            if(step==2) CHECK(out.size==sizeof(sub_report) && out.data[26]==12);
            else if(step==3) literal(out,5,sub_empty,sizeof(sub_empty));
            else CHECK(out.size>sizeof(sub_empty)); /* Authorization is rechecked, not suppressed. */
            CHECK(matter_im_subscribe_sent_at(m->active,now)==MATTER_OK && matter_im_subscribe_confirm(m->active,now+1)==MATTER_OK);
            if(step<4) { receive(m,sub_success,sizeof(sub_success),1,e.exchange_id,false); CHECK(matter_im_subscribe_process(m->active,now+2)==MATTER_PENDING); }
        }
        release(m);
    }
    multi_tests();
    event_wild_tests();
    event_wild_sub_tests();
    multi_sub_tests();
    complex_tests();
    list_tests();
    selector_tests();
    case_tests();
    for(unsigned order=0;order<2;++order) {
        SubModel* m=create(128); prime(m,order!=0); uint64_t deadline;
        CHECK(matter_im_subscribe_deadline(m->active,&deadline)==MATTER_OK && deadline==5100);
        m->value=10; ++m->version; CHECK(matter_im_subscribe_changed(m->active)==MATTER_OK);
        CHECK(matter_im_subscribe_deadline(m->active,&deadline)==MATTER_OK && deadline==2100);
        CHECK(matter_im_subscribe_process(m->active,2099)==MATTER_PENDING && matter_im_subscribe_state(m->active)==MATTER_IM_SUB_IDLE);
        CHECK(matter_im_subscribe_process(m->active,2100)==MATTER_PENDING && matter_im_subscribe_state(m->active)==MATTER_IM_SUB_NEED_EXCHANGE);
        Matter_Exchange_Info_T e={1,13,true}; CHECK(matter_im_subscribe_bind_report(m->active,&e,2100)==MATTER_OK);
        Matter_Rx_Decision_T wrong=decision(sub_request,sizeof(sub_request),3,13,false);
        CHECK(matter_im_subscribe_receive(m->active,&wrong)==MATTER_INVALID_STATE);
        Matter_Im_Subscribe_Message_T out=output(m,2100); CHECK(out.opcode==5 && out.data[11]==8 && out.data[26]==10 && m->reads==2);
        m->value=11; CHECK(matter_im_subscribe_changed(m->active)==MATTER_OK);
        CHECK(matter_im_subscribe_sent_at(m->active,2100)==MATTER_OK);
        wrong=decision(sub_success,sizeof(sub_success),1,13,true); CHECK(matter_im_subscribe_receive(m->active,&wrong)==MATTER_INVALID_ARGUMENT);
        receive(m,sub_success,sizeof(sub_success),1,13,false);
        CHECK(matter_im_subscribe_confirm(m->active,2101)==MATTER_OK && matter_im_subscribe_process(m->active,2102)==MATTER_PENDING);
        CHECK(matter_im_subscribe_deadline(m->active,&deadline)==MATTER_OK && deadline==4100);
        CHECK(matter_im_subscribe_process(m->active,4100)==MATTER_PENDING); e.exchange_id=14;
        CHECK(matter_im_subscribe_bind_report(m->active,&e,4100)==MATTER_OK); out=output(m,4100); CHECK(out.data[26]==11 && m->reads==3);
        CHECK(matter_im_subscribe_sent_at(m->active,4100)==MATTER_OK && matter_im_subscribe_confirm(m->active,4101)==MATTER_OK);
        receive(m,sub_success,sizeof(sub_success),1,14,false); CHECK(matter_im_subscribe_process(m->active,4102)==MATTER_PENDING);
        CHECK(matter_im_subscribe_process(m->active,9100)==MATTER_PENDING); e.exchange_id=15;
        CHECK(matter_im_subscribe_bind_report(m->active,&e,9100)==MATTER_OK); literal(output(m,9100),5,sub_empty,sizeof(sub_empty)); CHECK(m->reads==3);
        CHECK(matter_im_subscribe_cancel(m->active)==MATTER_OK && m->releases==1 && matter_im_subscribe_confirm(m->active,9101)==MATTER_INVALID_STATE); release(m);
    }
    for(size_t n=0;n<sizeof(sub_request);++n) {
        SubModel* m=create(128); receive(m,sub_request,n,3,12,true); Matter_Im_Subscribe_Message_T out=output(m,0);
        CHECK(out.opcode==1 && out.data[3]==MATTER_IM_INVALID_ACTION && !m->reads && !m->reserves); release(m);
    }
    for(unsigned mode=0;mode<9;++mode) {
        SubModel* m=create(mode==4 ? 8 : 128); memcpy(m->input,sub_request,sizeof(sub_request));
        if(mode==0) m->deny=true;
        if(mode==1) m->fabric=true;
        if(mode==2) m->read_error=true;
        if(mode==3) m->reserve_error=true;
        if(mode==5) m->input[5]=6;
        if(mode==6) m->input[10]=4; /* Unsupported events instead of attributes. */
        if(mode==7) m->input[13]=4; /* Duplicate path field / missing endpoint. */
        if(mode==8) m->type=MATTER_TLV_ARRAY;
        receive(m,m->input,sizeof(sub_request),3,12,true); Matter_Im_Subscribe_Message_T out=output(m,0);
        CHECK(out.opcode==1 && out.data[3]==(mode==3 || mode==4 ? MATTER_IM_RESOURCE_EXHAUSTED : MATTER_IM_INVALID_ACTION));
        CHECK(matter_im_subscribe_sent_at(m->active,1)==MATTER_OK && matter_im_subscribe_confirm(m->active,2)==MATTER_PORT_ERROR);
        CHECK(m->releases==(mode==3 || mode==5 || mode==6 || mode==7 ? 0u : 1u)); release(m);
    }
    for(unsigned mode=0;mode<5;++mode) {
        SubModel* m=create(128); prime(m,false);
        if(mode==0) {
            CHECK(matter_im_subscribe_process(m->active,5101)==MATTER_PENDING && matter_im_subscribe_state(m->active)==MATTER_IM_SUB_NEED_EXCHANGE);
            CHECK(matter_im_subscribe_process(m->active,15100)==MATTER_PENDING);
            CHECK(matter_im_subscribe_process(m->active,15101)==MATTER_PORT_ERROR); /* No exchange admitted. */
        }
        else {
            CHECK(matter_im_subscribe_process(m->active,5100)==MATTER_PENDING); Matter_Exchange_Info_T e={1,13,true};
            CHECK(matter_im_subscribe_bind_report(m->active,&e,5100)==MATTER_OK);
            if(mode==4) m->deny=true;
            Matter_Im_Subscribe_Message_T out=output(m,5100); CHECK(out.opcode==5);
            CHECK(matter_im_subscribe_sent_at(m->active,5100)==MATTER_OK);
            if(mode==1) CHECK(matter_im_subscribe_process(m->active,15100)==MATTER_PORT_ERROR);
            else if(mode==2) CHECK(matter_im_subscribe_cancel(m->active)==MATTER_OK);
            else { memcpy(m->input,sub_success,sizeof(sub_success)); if(mode==3) m->input[3]=0x7d;
                receive(m,m->input,sizeof(sub_success),1,13,false);
                CHECK(matter_im_subscribe_confirm(m->active,5101)==MATTER_OK && matter_im_subscribe_process(m->active,5102)==MATTER_PORT_ERROR); }
        }
        CHECK(m->releases==1 && matter_im_subscribe_changed(m->active)==MATTER_INVALID_STATE); release(m);
    }
    /* Real owner loops do not land exactly on MaxInterval. An overdue heartbeat
     * still sends, accepts the peer's status, and schedules from actual TX time. */
    {
        SubModel* s=create(128); prime(s,false);
        CHECK(matter_im_subscribe_process(s->active,5107)==MATTER_PENDING);
        Matter_Exchange_Info_T e={1,13,true}; CHECK(matter_im_subscribe_bind_report(s->active,&e,5111)==MATTER_OK);
        literal(output(s,5112),5,sub_empty,sizeof(sub_empty));
        CHECK(matter_im_subscribe_sent_at(s->active,5120)==MATTER_OK && matter_im_subscribe_confirm(s->active,5121)==MATTER_OK);
        receive(s,sub_success,sizeof(sub_success),1,13,false);
        CHECK(matter_im_subscribe_process(s->active,5122)==MATTER_PENDING);
        uint64_t due; CHECK(matter_im_subscribe_deadline(s->active,&due)==MATTER_OK && due==10120);
        CHECK(matter_im_subscribe_process(s->active,10127)==MATTER_PENDING);
        e.exchange_id=14; CHECK(matter_im_subscribe_bind_report(s->active,&e,10127)==MATTER_OK);
        literal(output(s,10128),5,sub_empty,sizeof(sub_empty));
        CHECK(matter_im_subscribe_sent_at(s->active,10129)==MATTER_OK);
        CHECK(matter_im_subscribe_process(s->active,20127)==MATTER_PORT_ERROR && s->releases==1);
        release(s);
    }
    for(unsigned keep=0;keep<2;++keep) {
        SubModel* a=create(128); prime(a,true);
        SubModel* b=create(128); b->other=a; b->id=43;
        memcpy(b->input,sub_request,sizeof(sub_request)); b->input[1]=keep ? 0x29 : 0x28;
        receive(b,b->input,sizeof(sub_request),3,12,true); Matter_Im_Subscribe_Message_T out=output(b,0);
        CHECK(out.data[3]==43 && b->reserves==1 && a->releases==(keep ? 0u : 1u));
        CHECK(matter_im_subscribe_state(a->active)==(keep ? MATTER_IM_SUB_IDLE : MATTER_IM_SUB_FAILED));
        release(b); release(a);
    }
    for(size_t n=0;n<sizeof(sub_success);++n) {
        SubModel* s=create(128); receive(s,sub_request,sizeof(sub_request),3,12,true); (void)output(s,0);
        CHECK(matter_im_subscribe_sent_at(s->active,1)==MATTER_OK);
        receive(s,sub_success,n,1,12,true);
        CHECK(matter_im_subscribe_process(s->active,2)==MATTER_PORT_ERROR && s->releases==1); release(s);
    }
    /* Zero interval ceiling negotiates a nonzero heartbeat; null remains scalar data. */
    SubModel* m=create(128); memcpy(m->input,sub_request,sizeof(sub_request)); m->input[5]=m->input[8]=0; m->type=MATTER_TLV_NULL;
    receive(m,m->input,sizeof(sub_request),3,12,true); Matter_Im_Subscribe_Message_T out=output(m,0);
    CHECK(out.opcode==5 && out.data[24]==0x34);
    CHECK(matter_im_subscribe_sent_at(m->active,1)==MATTER_OK && matter_im_subscribe_confirm(m->active,2)==MATTER_OK);
    receive(m,sub_success,sizeof(sub_success),1,12,true); out=output(m,3); CHECK(out.opcode==4 && out.data[6]==1); release(m);
    m=create(128); memcpy(m->input,sub_request,sizeof(sub_request)); m->input[1]=0x28;
    receive(m,m->input,sizeof(sub_request),3,12,true); (void)output(m,0); CHECK(!m->keep); release(m);
    for(size_t size=1025;size<=1202;size=size==1025?1198:1202) {
        m=create(1198); size_t padding=size-sizeof(sub_request)-4,at=sizeof(sub_request)-1;
        memcpy(m->input,sub_request,at); m->input[at++]=0x31; m->input[at++]=9;
        m->input[at++]=(uint8_t)padding; m->input[at++]=(uint8_t)(padding>>8);
        memset(m->input+at,0,padding); m->input[size-1]=0x18;
        receive(m,m->input,size,3,12,true); literal(output(m,0),5,sub_report,sizeof(sub_report)); release(m);
        if(size==1202) break;
    }
    m=create(1198); Matter_Rx_Decision_T oversized=decision(m->input,sizeof(m->input),3,12,true);
    CHECK(matter_im_subscribe_receive(m->active,&oversized)==MATTER_LIMIT_REACHED); release(m);
#ifdef MATTER_TEST_ALLOC
    m=create(128); Matter_Im_Subscribe_Port_T p=sub_port(m); Matter_Im_Subscribe_Config_T c={{1,1,false},100,128,true};
    size_t base=live;
    for(size_t allocation=1;allocation<=2;++allocation) {
        fail_at=calls+allocation; CHECK(!matter_im_subscribe_new(&p,&c,0)); fail_at=0; CHECK(live==base);
    }
    Matter_Rx_Decision_T d=decision(sub_request,sizeof(sub_request),3,12,true);
    for(size_t site=1;site<=2;++site) {
        fail_at=calls+site; CHECK(matter_im_subscribe_receive(m->active,&d)==MATTER_LIMIT_REACHED); fail_at=0;
        CHECK(live==base && matter_im_subscribe_state(m->active)==MATTER_IM_SUB_WAITING);
    }
    prime(m,false); release(m); CHECK(!live);
#endif
    puts("PASS Subscribe: literal prime/status/response, IM and MRP ordering, min/max, dirty during TX, new exchanges, heartbeat, access/schema, timeout/cancel and OOM");
    return 0;
}
