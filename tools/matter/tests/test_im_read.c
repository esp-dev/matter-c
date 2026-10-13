#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "model/matter_im_read.h"
#include "test_im_vectors.h"
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"IM:%d: %s\n",__LINE__,#c); abort(); } } while (0)
#ifdef MATTER_TEST_ALLOC
static size_t live,calls,fail_at;
void* matter_test_calloc(size_t n,size_t z) { if (++calls==fail_at) return NULL; void* p=calloc(n,z); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { CHECK(live); --live; } free(p); }
#endif
typedef struct {
    Matter_Im_Read_T s;
    unsigned auths,describes,reads;
    Matter_Im_Status_T auth,description,read_status;
    bool fabric,second_deny;
    Matter_Tlv_Type_T type;
    uint64_t value;
    Matter_Im_Read_Message_T out;
    uint8_t input[1025];
} Fixture;
static void guard(Fixture* f) {
    CHECK(matter_im_read_cancel(f->s)==MATTER_BUSY && matter_im_read_delete(f->s)==MATTER_BUSY);
    CHECK(matter_im_read_process(f->s,0)==MATTER_BUSY && matter_im_read_sent(f->s)==MATTER_BUSY);
    CHECK(matter_im_read_output(f->s,&f->out)==MATTER_BUSY);
}
static Matter_Im_Status_T allow(void* u,Matter_Exchange_Session_T s,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    Fixture* f=u; guard(f); ++f->auths;
    CHECK(s==1 && p->endpoint==0 && p->cluster==0x28 && p->attribute==2);
    CHECK(privilege==(f->auths%2 ? MATTER_IM_VIEW : MATTER_IM_MANAGE));
    return f->second_deny && f->auths==2 ? MATTER_IM_UNSUPPORTED_ACCESS : f->auth;
}
static Matter_Im_Status_T describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* out) {
    Fixture* f=u; guard(f); CHECK(p->attribute==2 && f->auths%2==1); ++f->describes;
    *out=(Matter_Im_Attribute_T){MATTER_IM_MANAGE,f->fabric}; return f->description;
}
static Matter_Im_Status_T read_value(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* out) {
    Fixture* f=u; guard(f); CHECK(p->attribute==2 && filtered && f->auths%2==0); ++f->reads;
    *out=(Matter_Im_Value_T){.type=f->type,.unsigned_value=f->value,.signed_value=INT64_MIN,.data_version=7}; return f->read_status;
}
static Fixture* create(size_t capacity) {
    Fixture* f=calloc(1,sizeof(*f)); CHECK(f);
    f->type=MATTER_TLV_UNSIGNED; f->value=0xfff1;
    Matter_Im_Read_Port_T p={f,allow,describe,read_value,NULL,NULL};
    Matter_Im_Read_Config_T c={{1,0x1234,false},1000,capacity,true};
    f->s=matter_im_read_new(&p,&c,10); CHECK(f->s); return f;
}
static Matter_Rx_Decision_T decision(const uint8_t* data,size_t size) {
    return (Matter_Rx_Decision_T){.action=MATTER_RX_NEW_RESPONDER,.session=1,.exchange=1,
        .header={.protocol_id=1,.opcode=2,.exchange_id=0x1234,.exchange_flags=5},.payload=data,.payload_size=size};
}
static void execute(Fixture* f,const uint8_t* data,size_t n) {
    Matter_Rx_Decision_T d=decision(data,n);
    CHECK(matter_im_read_receive(f->s,&d)==MATTER_OK);
    CHECK(matter_im_read_receive(f->s,&d)==MATTER_WOULD_BLOCK);
    CHECK(matter_im_read_process(f->s,10)==MATTER_PENDING);
    CHECK(matter_im_read_output(f->s,&f->out)==MATTER_OK);
}
static void release(Fixture* f) { CHECK(matter_im_read_delete(f->s)==MATTER_OK); free(f); }
static void status_response(Fixture* f,uint8_t status) {
    const uint8_t expected[]={0x15,0x24,0,status,0x24,0xff,13,0x18};
    CHECK(f->out.opcode==1 && f->out.size==sizeof(expected) && !memcmp(f->out.data,expected,sizeof(expected)));
}
#include "test_im_chunks.h"
#include "test_im_wildcard.h"
#include "test_im_complex.h"
#include "test_im_events.h"
#include "test_im_multi_events.h"
#include "test_im_event_wildcards.h"
#include "test_im_path_grammar.h"
int main(void) {
    path_grammar_tests();
    multi_tests();
    event_wild_tests();
    Fixture* f=create(1024);
    memcpy(f->input,im_request,sizeof(im_request));
    Matter_Rx_Decision_T d=decision(f->input,sizeof(im_request));
    ++d.session; CHECK(matter_im_read_receive(f->s,&d)==MATTER_INVALID_ARGUMENT); --d.session;
    d.header.opcode=1; CHECK(matter_im_read_receive(f->s,&d)==MATTER_INVALID_ARGUMENT); d.header.opcode=2;
    d.action=MATTER_RX_DROP; CHECK(matter_im_read_receive(f->s,&d)==MATTER_INVALID_ARGUMENT); d.action=MATTER_RX_NEW_RESPONDER;
    CHECK(matter_im_read_receive(f->s,&d)==MATTER_OK); memset(f->input,0,sizeof(f->input));
    CHECK(matter_im_read_process(f->s,10)==MATTER_PENDING && matter_im_read_output(f->s,&f->out)==MATTER_OK);
    CHECK(f->auths==2 && f->reads==1 && f->describes==1 && f->out.opcode==5 && f->out.size==sizeof(im_report));
    CHECK(!memcmp(f->out.data,im_report,sizeof(im_report)));
    CHECK(matter_im_read_process(f->s,11)==MATTER_PENDING && f->reads==1);
    CHECK(matter_im_read_confirm(f->s,11)==MATTER_INVALID_STATE);
    CHECK(!matter_im_read_awaiting_delivery(f->s) && !matter_im_read_awaiting_delivery(NULL));
    CHECK(matter_im_read_sent(f->s)==MATTER_OK && matter_im_read_awaiting_delivery(f->s));
    CHECK(matter_im_read_confirm(f->s,12)==MATTER_OK && !matter_im_read_awaiting_delivery(f->s));
    CHECK(matter_im_read_confirm(f->s,12)==MATTER_INVALID_STATE && matter_im_read_state(f->s)==MATTER_IM_READ_COMPLETE);
    release(f);
    for(unsigned mode=0;mode<8;++mode) {
        f=create(1024);
        uint8_t code=MATTER_IM_UNSUPPORTED_ACCESS;
        if(mode==0) f->auth=MATTER_IM_UNSUPPORTED_ACCESS;
        if(mode==1) f->second_deny=true;
        if(mode==2) f->fabric=true;
        if(mode==3) { f->description=MATTER_IM_UNSUPPORTED_ATTRIBUTE; code=MATTER_IM_UNSUPPORTED_ATTRIBUTE; }
        if(mode==4) { f->auth=MATTER_IM_ACCESS_RESTRICTED; code=MATTER_IM_ACCESS_RESTRICTED; }
        if(mode==5) { f->read_status=MATTER_IM_FAILURE; code=MATTER_IM_FAILURE; }
        if(mode==6) f->read_status=MATTER_IM_UNSUPPORTED_ACCESS;
        if(mode==7) { f->read_status=MATTER_IM_ACCESS_RESTRICTED; code=MATTER_IM_ACCESS_RESTRICTED; }
        execute(f,im_request,sizeof(im_request));
        const uint8_t expected[]={0x15,0x36,1,0x15,0x35,0,0x37,0,0x24,2,0,0x24,3,0x28,0x24,4,2,0x18,
            0x35,1,0x24,0,code,0x18,0x18,0x18,0x18,0x29,4,0x24,0xff,13,0x18};
        CHECK(f->out.opcode==5 && f->out.size==sizeof(expected) && !memcmp(f->out.data,expected,sizeof(expected)));
        CHECK(f->reads==(mode>=5 ? 1u : 0u));
        if(mode==0 || mode==4) CHECK(!f->describes);
        release(f);
    }
    for(size_t n=0;n<sizeof(im_request);++n) { f=create(1024); execute(f,im_request,n); status_response(f,0x80); CHECK(!f->auths); release(f); }
    for(unsigned mode=0;mode<5;++mode) {
        f=create(1024); memcpy(f->input,im_request,sizeof(im_request)); size_t n=sizeof(im_request);
        if(mode==0) f->input[3]=0x15; /* Path structure is not a path LIST. */
        if(mode==1) f->input[8]=2; /* Duplicate context tag in list. */
        if(mode==2) f->input[17]=0x28; /* revision is no longer an unsigned int */
        if(mode==3) { memcpy(f->input+n-1,"\x29\x03\x18",3); n+=2; } /* duplicate FabricFiltered */
        if(mode==4) f->input[10]=0x28; /* attribute has the wrong type */
        execute(f,f->input,n); status_response(f,0x80); CHECK(!f->auths); release(f);
    }
    f=create(1024); memcpy(f->input,im_request,sizeof(im_request)-1);
    memcpy(f->input+sizeof(im_request)-1,"\x35\x06\x24\x00\x01\x18\x18",7); /* unknown nested context tag */
    execute(f,f->input,sizeof(im_request)+6); CHECK(f->reads==1 && !memcmp(f->out.data,im_report,sizeof(im_report))); release(f);
    f=create(8); execute(f,im_request,sizeof(im_request)); status_response(f,0x89); CHECK(f->reads==1); release(f);
    for(unsigned mode=0;mode<4;++mode) {
        f=create(1024); f->type=mode==0 ? MATTER_TLV_UNSIGNED : mode==1 ? MATTER_TLV_SIGNED : mode==2 ? MATTER_TLV_BOOL : MATTER_TLV_NULL;
        f->value=mode<2 ? UINT64_MAX : 1;
        execute(f,im_request,sizeof(im_request));
        Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T e; bool found=false;
        CHECK(matter_tlv_init(&reader,f->out.data,f->out.size,8)==MATTER_TLV_OK);
        Matter_Tlv_Result_T r;
        while((r=matter_tlv_next(&reader,&e))==MATTER_TLV_OK) {
            if(e.offset==21) { found=true; CHECK(e.tag.control==1 && e.tag.number==2 && e.type==f->type);
                if(mode==0) CHECK(e.unsigned_value==UINT64_MAX);
                if(mode==1) CHECK(e.signed_value==INT64_MIN);
                if(mode==2) CHECK(e.unsigned_value==1);
            }
        }
        CHECK(found && r==MATTER_TLV_DONE); release(f);
    }
    f=create(1024);
    const uint8_t empty_request[]={0x15,0x29,3,0x24,0xff,13,0x18};
    const uint8_t empty_report[]={0x15,0x36,1,0x18,0x29,4,0x24,0xff,13,0x18};
    execute(f,empty_request,sizeof(empty_request));
    CHECK(!f->auths && f->out.size==sizeof(empty_report) && !memcmp(f->out.data,empty_report,sizeof(empty_report))); release(f);
    f=create(1024); memcpy(f->input,im_request,14); memcpy(f->input+14,im_request+3,11); memcpy(f->input+25,im_request+14,7);
    execute(f,f->input,32); CHECK(f->reads==2 && f->out.opcode==5 && f->out.size==58); release(f);
    f=create(1024); d=decision(f->input,sizeof(f->input));
    CHECK(matter_im_read_receive(f->s,&d)==MATTER_LIMIT_REACHED && matter_im_read_state(f->s)==MATTER_IM_READ_WAITING);
    release(f);
    for(unsigned mode=0;mode<3;++mode) {
        f=create(1024); execute(f,im_request,sizeof(im_request));
        if(mode) CHECK(matter_im_read_sent(f->s)==MATTER_OK);
        if(mode==2) CHECK(matter_im_read_cancel(f->s)==MATTER_OK);
        else CHECK(matter_im_read_process(f->s,1010)==MATTER_PORT_ERROR);
        CHECK(matter_im_read_state(f->s)==MATTER_IM_READ_FAILED && matter_im_read_output(f->s,&f->out)==MATTER_INVALID_STATE);
        release(f);
    }
    test_im_chunks();
    test_im_fabric_scope();
    test_im_wildcard();
    test_im_complex();
    test_im_events();
#ifdef MATTER_TEST_ALLOC
    Matter_Im_Read_Port_T p={NULL,allow,describe,read_value,NULL,NULL}; Matter_Im_Read_Config_T c={{1,1,false},10,1024,true};
    fail_at=calls+1; CHECK(!matter_im_read_new(&p,&c,0)); fail_at=0; CHECK(!live);
#endif
    puts("PASS IM read: literal request/report/status, access order, malformed TLV, bounds, timeout/cancel and OOM");
    return 0;
}
