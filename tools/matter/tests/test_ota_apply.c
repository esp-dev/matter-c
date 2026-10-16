#include "clusters/matter_ota_apply.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"apply:%d %s\n",__LINE__,#x); exit(1); } } while(0)
#ifdef MATTER_TEST_ALLOC
static bool allocation_fail; static size_t live;
void* matter_test_calloc(size_t n,size_t s) { if(allocation_fail) return NULL; void* p=calloc(n,s); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { CHECK(live); --live; } free(p); }
#endif
typedef struct {
    Matter_Ota_Apply_T apply; Matter_Ota_Apply_Context_T context;
    uint64_t generation,job,now; unsigned starts,cancels,grants,done;
    bool reply,fail_state,change_on_take; uint8_t state,im,response[64]; size_t size;
    Matter_Result_T start_result,take_result,ready_result; Matter_Ota_Apply_Result_T result;
} Test;
static uint64_t generation(void* u,uint8_t fabric) { CHECK(fabric==1); return ((Test*)u)->generation; }
static Matter_Result_T start(void* u,const Matter_Ota_Provider_T* p,const uint8_t* d,size_t n,uint64_t* id) {
    Test* t=u; CHECK(p->fabric==1 && p->node==42 && p->endpoint==1 && !t->job);
    /* Independently inspect exact anonymous fields, including copied token. */
    CHECK(n==43 && d[0]==0x15 && d[1]==0x30 && d[2]==0 && d[3]==32);
    for(unsigned i=0;i<32;++i) CHECK(d[4+i]==i);
    CHECK(!memcmp(d+36,"\x26\x01\x78\x56\x34\x12\x18",7));
    if(t->start_result!=MATTER_PENDING) return t->start_result;
    *id=t->job=++t->starts; return MATTER_PENDING;
}
static Matter_Result_T take(void* u,uint64_t id,uint8_t* im,const uint8_t** d,size_t* n) {
    Test* t=u; CHECK(id==t->job); if(!t->reply) return MATTER_PENDING;
    t->reply=false; t->job=0; *im=t->im; *d=t->response; *n=t->size;
    if(t->change_on_take) ++t->generation;
    return t->take_result;
}
static void cancel(void* u,uint64_t id) { Test* t=u; CHECK(id==t->job); ++t->cancels; }
static Matter_Result_T state(void* u,uint8_t state,uint8_t reason,uint32_t version,uint64_t now) {
    Test* t=u; CHECK(reason<=4 && version==0x12345678 && now>=t->now);
    if(t->fail_state) return MATTER_PORT_ERROR;
    t->state=state; return MATTER_OK;
}
static Matter_Result_T ready(void* u,const Matter_Ota_Apply_Context_T* c) {
    Test* t=u; CHECK(c->artifact==7 && c->version==0x12345678 && c->generation==t->generation);
    CHECK(c->token_size==32 && c->token[31]==31); ++t->grants; return t->ready_result;
}
static void done(void* u,const Matter_Ota_Apply_Context_T* c,Matter_Ota_Apply_Result_T result) {
    Test* t=u; CHECK(c->artifact==7); ++t->done; t->result=result;
}
static Test* setup(uint64_t now) {
    Test* t=calloc(1,sizeof(*t)); CHECK(t); t->generation=1; t->start_result=MATTER_PENDING;
    t->context=(Matter_Ota_Apply_Context_T){.provider={42,1,1},.generation=1,.artifact=7,.version=0x12345678,.token_size=32};
    for(unsigned i=0;i<32;++i) t->context.token[i]=(uint8_t)i;
    Matter_Ota_Apply_Port_T p={t,generation,start,take,cancel,state,ready,done};
#ifdef MATTER_TEST_ALLOC
    allocation_fail=true; CHECK(!matter_ota_apply_new(&p,now)); allocation_fail=false;
#endif
    t->apply=matter_ota_apply_new(&p,now); CHECK(t->apply); t->now=now; return t;
}
static void begin(Test* t) { CHECK(matter_ota_apply_begin(t->apply,&t->context,t->now)==MATTER_OK); }
static void pump(Test* t,uint64_t now) {
    for(unsigned i=0;i<3;++i) { Matter_Result_T r=matter_ota_apply_process(t->apply,now); CHECK(r==MATTER_OK || r==MATTER_PENDING); }
    t->now=now;
}
static void reply(Test* t,uint8_t action,uint32_t delay) {
    const uint8_t data[]={0x15,0x24,0,action,0x26,1,0,0,0,0,0x18};
    memcpy(t->response,data,sizeof(data));
    for(unsigned i=0;i<4;++i) t->response[6+i]=(uint8_t)(delay>>(8*i));
    t->size=sizeof(data); t->reply=true;
}
static void destroy(Test* t) {
    matter_ota_apply_cancel(t->apply); t->reply=true; pump(t,t->now);
    CHECK(matter_ota_apply_delete(t->apply)==MATTER_OK); free(t);
}
static void policy(void) {
    for(unsigned mode=0;mode<5;++mode) {
        Test* t=setup(0); begin(t); memset(t->context.token,255,32); t->context.version=0; pump(t,0); CHECK(t->starts==1 && t->state==5);
        uint32_t delay=mode==0?0:mode==1?3:mode==2?86400:UINT32_MAX;
        reply(t,mode==4?2:0,delay); pump(t,10);
        if(mode<4 && delay) {
            uint64_t due=10+(uint64_t)(delay>86400?86400:delay)*1000;
            pump(t,due-1); CHECK(!t->grants && !t->done && t->starts==1); pump(t,due);
        }
        CHECK(t->done==1 && t->grants==(mode==4?0u:1u));
        CHECK(t->result==(mode==4?MATTER_OTA_APPLY_DISCONTINUED:MATTER_OTA_APPLY_ACCEPTED));
        CHECK(t->state==(mode==4?1:5));
        pump(t,UINT64_MAX); CHECK(t->done==1 && t->starts==1); destroy(t);
    }
    for(unsigned mode=0;mode<4;++mode) {
        Test* t=setup(0); begin(t); pump(t,0); uint32_t delay=mode==0?0:mode==1?119:mode==2?121:UINT32_MAX;
        reply(t,1,delay); pump(t,1); CHECK(t->state==6);
        uint64_t due=1+(uint64_t)(delay<120?120:delay>86400?86400:delay)*1000;
        pump(t,due-1); CHECK(t->starts==1 && !t->grants); pump(t,due); CHECK(t->starts==2 && t->state==5);
        reply(t,0,0); pump(t,due+1); CHECK(t->grants==1 && t->done==1); destroy(t);
    }
    Test* t=setup(UINT64_MAX-10); begin(t); pump(t,t->now); reply(t,0,1); pump(t,t->now);
    pump(t,UINT64_MAX-1); CHECK(!t->grants); pump(t,UINT64_MAX); CHECK(t->grants==1); destroy(t);
    puts("PASS Apply policy: Proceed once, Await120s floor/24h cap, Discontinue, copied token, saturated clock");
}
static void errors(void) {
    for(unsigned mode=0;mode<10;++mode) {
        Test* t=setup(0); begin(t); pump(t,0); reply(t,0,0);
        if(mode==0) --t->size;
        if(mode==1) t->response[3]=3;
        if(mode==2) t->response[1]=0x20; /* signed action */
        if(mode==3) t->response[5]=0; /* duplicate action */
        if(mode==4) t->response[5]=2; /* missing delay */
        if(mode==5) { t->response[4]=0x27; memset(t->response+6,255,8); t->response[14]=0x18; t->size=15; }
        if(mode==6) t->im=1;
        if(mode==7) t->take_result=MATTER_PORT_ERROR;
        if(mode==8) t->response[0]=0x17;
        if(mode==9) t->size=0;
        pump(t,1); CHECK(t->done==1 && !t->grants && t->result==MATTER_OTA_APPLY_ERROR); destroy(t);
    }
    Test* t=setup(0); begin(t); t->start_result=MATTER_BUSY; pump(t,0); CHECK(!t->starts);
    t->start_result=MATTER_PORT_ERROR; pump(t,1); CHECK(t->result==MATTER_OTA_APPLY_ERROR && t->done==1); destroy(t);
    t=setup(0); begin(t); pump(t,0); pump(t,64999); CHECK(!t->cancels);
    pump(t,65000); pump(t,65001); CHECK(t->cancels==1 && matter_ota_apply_delete(t->apply)==MATTER_BUSY);
    reply(t,0,0); pump(t,65002); CHECK(!t->grants && t->result==MATTER_OTA_APPLY_ERROR); destroy(t);
    t=setup(0); begin(t); t->fail_state=true; CHECK(matter_ota_apply_process(t->apply,0)==MATTER_PORT_ERROR && !t->starts);
    t->fail_state=false; pump(t,0); reply(t,0,0); t->ready_result=MATTER_INVALID_STATE;
    CHECK(matter_ota_apply_process(t->apply,1)==MATTER_PENDING && t->grants==1);
    t->fail_state=true; CHECK(matter_ota_apply_process(t->apply,2)==MATTER_PORT_ERROR && t->grants==1 && !t->done);
    t->fail_state=false; pump(t,3); CHECK(t->done==1 && t->grants==1 && t->result==MATTER_OTA_APPLY_REJECTED); destroy(t);
    puts("PASS Apply errors: TLV/types/duplicates/overflow/status/I/O, busy, timeout+drain, failed state publication, application rejection once");
}
static void lifecycle(void) {
    for(unsigned mode=0;mode<6;++mode) {
        Test* t=setup(0); begin(t); pump(t,0);
        if(mode<3) { reply(t,mode==1?1:0,120); pump(t,1); }
        if(mode==0 || mode==3) matter_ota_apply_cancel(t->apply);
        else if(mode==5) t->change_on_take=true;
        else t->generation=mode==1?0:2;
        pump(t,2); if(t->job) { reply(t,0,0); pump(t,3); }
        CHECK(t->done==1 && !t->grants);
        CHECK(t->result==(mode==0 || mode==3?MATTER_OTA_APPLY_CANCELLED:MATTER_OTA_APPLY_INVALIDATED)); destroy(t);
    }
    Test* a=setup(0); Test* b=setup(0); begin(a); begin(b); pump(a,0); pump(b,0);
    CHECK(matter_ota_apply_begin(a->apply,&a->context,0)==MATTER_BUSY);
    CHECK(matter_ota_apply_process(a->apply,1)==MATTER_PENDING);
    CHECK(matter_ota_apply_process(a->apply,0)==MATTER_INVALID_ARGUMENT);
    a->now=1;
    reply(b,0,0); pump(b,2); CHECK(b->grants==1 && !a->grants); destroy(a); destroy(b);
    a=setup(0); begin(a); pump(a,0); reply(a,0,100); pump(a,1); destroy(a);
    a=setup(0); pump(a,100001); CHECK(!a->starts && !a->grants); /* No grant on restart. */
    a->context.generation=2; CHECK(matter_ota_apply_begin(a->apply,&a->context,a->now)==MATTER_INVALID_STATE);
    a->context.generation=1; a->context.token_size=33; CHECK(matter_ota_apply_begin(a->apply,&a->context,a->now)==MATTER_INVALID_ARGUMENT); destroy(a);
    puts("PASS Apply lifetime: two instances, rotation/removal during request/delay, late reply, cancel/drain, restart without grant");
}
int main(void) { policy(); errors(); lifecycle();
#ifdef MATTER_TEST_ALLOC
    CHECK(!live); puts("PASS Apply allocation failure/ownership");
#endif
    return 0;
}
