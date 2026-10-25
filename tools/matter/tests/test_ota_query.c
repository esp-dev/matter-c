#include "clusters/matter_ota_query.h"
#include "model/matter_im_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"query:%d %s\n",__LINE__,#x); exit(1); } } while(0)
#ifdef MATTER_TEST_ALLOC
static bool allocation_fail; static size_t live;
void* matter_test_calloc(size_t n,size_t size) { if(allocation_fail) return NULL; void* p=calloc(n,size); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { CHECK(live); --live; } free(p); }
#endif
typedef struct {
    uint64_t generation,job,now; uint32_t random;
    unsigned starts,cancels,available,expected_token; uint8_t state,reason,im,available_state; bool ready,fail_state;
    Matter_Result_T take_result;
    uint8_t response[1024]; size_t size; Matter_Tlv_Writer_T writer;
    uint8_t extra[513]; char uri[258],version[66];
    Matter_Ota_Offer_T offer; Matter_Ota_Query_T query;
} Test;
static uint64_t generation(void* u,uint8_t fabric) { return fabric?((Test*)u)->generation:0; }
static Matter_Result_T random32(void* u,uint32_t* out) { *out=((Test*)u)->random; return MATTER_OK; }
static Matter_Result_T start(void* u,const Matter_Ota_Provider_T* p,const uint8_t* d,size_t n,uint64_t* id) {
    Test* t=u; CHECK(p->node==42 || p->node==43); CHECK(d[0]==0x15 && n>15); CHECK(!t->job);
    *id=t->job=++t->starts; return MATTER_PENDING;
}
static Matter_Result_T take(void* u,uint64_t id,uint8_t* im,const uint8_t** d,size_t* n) {
    Test* t=u; CHECK(id==t->job); if(!t->ready) return MATTER_PENDING;
    t->ready=false; t->job=0; *im=t->im; *d=t->response; *n=t->size; return t->take_result;
}
static void cancel(void* u,uint64_t id) { Test* t=u; CHECK(id==t->job); ++t->cancels; }
static Matter_Result_T state(void* u,uint8_t s,uint8_t reason,uint64_t now) {
    Test* t=u; CHECK(reason<=4); CHECK(now>=t->now); if(t->fail_state) return MATTER_PORT_ERROR;
    t->state=s; t->reason=reason; return MATTER_OK;
}
static void available(void* u,const Matter_Ota_Provider_T* p,const Matter_Ota_Image_T* i) {
    Test* t=u; CHECK(p->node==42); CHECK(i->version==2 && i->token_size==(t->expected_token?t->expected_token:8));
    t->available_state=t->state; t->state=4; ++t->available;
}
static void put(Test* t,Matter_Tlv_Type_T type,int tag,uint64_t value,const char* data,size_t n) {
    Matter_Tlv_Element_T e={.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=value,.data=(const uint8_t*)data,.size=n};
    CHECK(matter_tlv_write(&t->writer,&e,0)==MATTER_TLV_OK);
}
static void response(Test* t,uint8_t status,int64_t delay,bool image) {
    CHECK(matter_tlv_writer_init(&t->writer,t->response,sizeof(t->response),4)==MATTER_TLV_OK);
    put(t,MATTER_TLV_STRUCTURE,-1,0,NULL,0); put(t,MATTER_TLV_UNSIGNED,0,status,NULL,0);
    if(delay>=0) put(t,MATTER_TLV_UNSIGNED,1,(uint64_t)delay,NULL,0);
    if(image) {
        const char* uri="bdx://000000000000002A/image%20v2";
        put(t,MATTER_TLV_UTF8,2,0,uri,strlen(uri)); put(t,MATTER_TLV_UNSIGNED,3,2,NULL,0);
        put(t,MATTER_TLV_UTF8,4,0,"v2",2); put(t,MATTER_TLV_BYTES,5,0,"12345678",8);
    }
    put(t,MATTER_TLV_END,-1,0,NULL,0); CHECK(matter_tlv_writer_finish(&t->writer,&t->size)==MATTER_TLV_OK); t->ready=true;
}
static Test* setup(bool bdx) {
    Test* t=calloc(1,sizeof(*t)); CHECK(t); t->generation=1; t->state=1;
    Matter_Ota_Query_Config_T c={.vendor=0xfff1,.product=0x8001,.version=1,.protocol_count=bdx?1:0};
    Matter_Ota_Query_Port_T p={t,generation,random32,start,take,cancel,state,available};
#ifdef MATTER_TEST_ALLOC
    allocation_fail=true; CHECK(!matter_ota_query_new(&c,&p,0)); allocation_fail=false;
#endif
    t->query=matter_ota_query_new(&c,&p,0); CHECK(t->query);
    t->offer.provider=(Matter_Ota_Provider_T){42,1,1}; return t;
}
static void pump(Test* t,uint64_t now) {
    for(unsigned i=0;i<3;++i) { Matter_Result_T r=matter_ota_query_process(t->query,now); CHECK(r==MATTER_OK || r==MATTER_PENDING); }
    t->now=now;
}
static void destroy(Test* t) {
    (void)matter_ota_query_stop(t->query); if(t->job) t->ready=true;
    pump(t,t->now); CHECK(matter_ota_query_delete(t->query)==MATTER_OK); free(t);
}
static void policy(void) {
    Test* t=setup(false); CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,0); CHECK(t->starts==1 && t->state==2);
    response(t,1,300,false); pump(t,1000); CHECK(t->state==3);
    CHECK(matter_ota_query_offer(t->query,&t->offer,2000)); pump(t,300999); CHECK(t->starts==1);
    pump(t,301000); CHECK(t->starts==2); response(t,2,0,false); pump(t,301001); CHECK(t->state==1);
    pump(t,301001+86400000-1); CHECK(t->starts==2); pump(t,301001+86400000); CHECK(t->starts==3); destroy(t);
    /* UpdateAvailable uses the next scheduled query. After
     * handing off an image, a provider restart does not itself cancel that
     * schedule. A laboratory recovery trigger must choose its reason explicitly,
     * and even SimpleAnnouncement must retain the 120-second query floor. */
    for(unsigned simple=0;simple<2;++simple) {
        t=setup(true); CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,0);
        response(t,0,0,true); pump(t,1); CHECK(t->available==1 && t->starts==1);
        t->offer.announced=true; t->offer.reason=simple?0:1;
        CHECK(matter_ota_query_offer(t->query,&t->offer,1000));
        pump(t,120000); CHECK(t->starts==1);
        if(simple) { pump(t,120001); CHECK(t->starts==2); }
        else {
            pump(t,541001); CHECK(t->starts==1); /* Five-minute stall + 240s wait. */
            pump(t,86400000); CHECK(t->starts==1);
            pump(t,86400001); CHECK(t->starts==2);
        }
        destroy(t);
    }
    for(unsigned edge=0;edge<2;++edge) {
        t=setup(false); t->offer.announced=true; t->offer.reason=2; t->random=edge?599:0;
        CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,edge?599999:999); CHECK(!t->starts);
        pump(t,edge?600000:1000); CHECK(t->starts==1); destroy(t);
    }
    /* CASE can delay the actual QueryImage beyond start(). A repeated
     * announcement must not reset the Busy retry to that earlier floor. */
    t=setup(false); CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,0);
    response(t,1,60,false); pump(t,500); CHECK(t->state==3);
    t->offer.announced=true; t->offer.reason=0;
    CHECK(matter_ota_query_offer(t->query,&t->offer,1000));
    pump(t,120000); CHECK(t->starts==1); pump(t,120499); CHECK(t->starts==1);
    pump(t,120500); CHECK(t->starts==2); destroy(t);
    t=setup(false); CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,0);
    response(t,2,0,false); pump(t,1); t->offer.provider.node=43;
    CHECK(matter_ota_query_offer(t->query,&t->offer,2)); pump(t,120000); CHECK(t->starts==1); pump(t,120001); CHECK(t->starts==2); destroy(t);
    t=setup(false); CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,0);
    t->generation=2; pump(t,1); CHECK(t->cancels==1); pump(t,2); CHECK(t->cancels==1);
    CHECK(matter_ota_query_delete(t->query)==MATTER_BUSY); response(t,0,0,true); pump(t,3); CHECK(!t->available && t->state==1); destroy(t);
    t=setup(false); CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,0); pump(t,65000); CHECK(t->cancels==1);
    response(t,2,0,false); pump(t,65001); CHECK(t->state==1); destroy(t);
    t=setup(false); CHECK(matter_ota_query_offer(t->query,&t->offer,0));
    t->fail_state=true; CHECK(matter_ota_query_process(t->query,0)==MATTER_PENDING);
    CHECK(matter_ota_query_process(t->query,0)==MATTER_PORT_ERROR && !t->starts); t->fail_state=false; pump(t,1); CHECK(t->starts==1); destroy(t);
    /* Busy without its required delay is malformed, not a valid Busy reply. */
    t=setup(false); CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,0); response(t,1,-1,false); pump(t,1); CHECK(t->state==1);
    pump(t,120000); CHECK(t->starts==1); pump(t,120001); CHECK(t->starts==2); destroy(t);
    for(unsigned bdx=0;bdx<2;++bdx) {
        t=setup(bdx!=0); CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,0);
        response(t,0,10,true); pump(t,1); CHECK(t->state==1);
        pump(t,10000); CHECK(!t->available); pump(t,10001); CHECK(t->available==bdx); destroy(t);
    }
    t=setup(true); CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,0); response(t,0,UINT32_MAX,true);
    pump(t,1); pump(t,UINT64_C(4294967295000)); CHECK(!t->available); pump(t,UINT64_C(4294967295001)); CHECK(t->available==1); destroy(t);
    for(unsigned mode=0;mode<7;++mode) {
        t=setup(true); CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,0); response(t,0,0,true);
        char* uri=(char*)memchr(t->response,'b',t->size); CHECK(uri);
        if(mode==0) uri[21]='B'; /* BDX identity differs from provider. */
        if(mode==1) uri[0]='h'; /* Protocol not advertised. */
        if(mode==2) uri[23]='?'; /* No query or fragment permitted. */
        if(mode==3) uri[29]='Z'; /* Malformed percent escape. */
        if(mode==4) t->size--; /* Truncated document. */
        if(mode==5) { t->response[3]=4; } /* Unknown OTA Status. */
        if(mode==6) { uri[strlen("bdx://000000000000002A/image%20v2")+2]=1; } /* Same version. */
        pump(t,1); CHECK(!t->available); destroy(t);
    }
    puts("PASS OTA policy: normal/Busy/delay/urgent/global floor/generation/cancel/timeout/state failure/available");
}
static void retry_states(void) {
    /* Core 11.20.7.4 UpdateStateEnum: DelayedOnQuery denotes a Busy response,
     * not a transport/IM/decoding error. Backoff still applies while Idle. */
    for(unsigned mode=0;mode<6;++mode) {
        Test* t=setup(false); CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,0);
        response(t,mode==0?1:2,mode==0?180:0,false);
        if(mode==1) t->im=0x9c;
        if(mode==2) t->take_result=MATTER_PORT_ERROR;
        if(mode==3) t->im=MATTER_IM_FAILURE;
        if(mode==4) t->size=1;
        if(mode==5) { t->ready=false; pump(t,65000); CHECK(t->cancels==1); t->ready=true; }
        uint64_t now=mode==5?65001:1;
        pump(t,now);
        CHECK(t->state==(mode<2?3:1) && t->reason==(mode<2?4:2));
        uint64_t due=now+(mode==0?180000:120000);
        pump(t,due-1); CHECK(t->starts==1 && t->state==(mode<2?3:1));
        pump(t,due); CHECK(t->starts==2 && t->state==2); destroy(t);
    }
    puts("PASS OTA retry state: Busy remains DelayedOnQuery; transport/IM/TLV/timeout errors remain Idle during unchanged backoff");
}
static void handoff(void) {
    for(unsigned delayed=0;delayed<2;++delayed) {
        Test* t=setup(true); CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,0);
        response(t,0,delayed?10:0,true); pump(t,1);
        if(delayed) { CHECK(!t->available && t->state==1); pump(t,10001); }
        CHECK(t->available==1 && t->available_state==(delayed?1:2) && t->state==4);
        pump(t,10002); CHECK(t->available==1 && t->state==4); destroy(t);
    }
    puts("PASS OTA handoff: immediate Querying -> Downloading, delayed Idle -> Downloading, no spurious Idle or repeated callback");
}
static void client(void) {
    const uint8_t fields[]={0x15,0x24,0,2,0x18};
    const uint8_t reply[]={0x15,0x29,0,0x36,1,0x15,0x35,0,0x37,0,0x24,0,1,0x24,1,0x29,0x24,2,1,0x18,
        0x35,1,0x24,0,2,0x18,0x18,0x18,0x18,0x24,255,13,0x18};
    for(unsigned mode=0;mode<8;++mode) {
        Matter_Im_Command_Path_T path={1,0x29,0};
#ifdef MATTER_TEST_ALLOC
        allocation_fail=true; CHECK(!matter_im_client_new(&path,1,fields,sizeof(fields))); allocation_fail=false;
#endif
        Matter_Im_Client_T c=matter_im_client_new(&path,1,fields,sizeof(fields)); CHECK(c);
        Matter_Im_Read_Message_T out; CHECK(matter_im_client_output(c,&out)==MATTER_OK && out.opcode==8);
        CHECK(matter_im_client_sent(c)==MATTER_OK); uint8_t b[sizeof(reply)]; memcpy(b,reply,sizeof(b));
        if(mode==1) b[1]=0x28; /* suppress=false: status reply is required */
        if(mode==2) b[12]=2; /* wrong endpoint */
        if(mode==3) b[18]=0; /* wrong command */
        if(mode==4) b[31]=0; /* wrong revision */
        if(mode==7) b[31]=12; /* Previous IM revision remains interoperable. */
        Matter_Result_T r=matter_im_client_receive(c,mode==5?8:9,b,sizeof(b)-(mode==6?1:0));
        if(mode>=2 && mode!=7) CHECK(r==MATTER_INVALID_ARGUMENT);
        else {
            CHECK(r==MATTER_OK);
            if(mode==1) { CHECK(matter_im_client_output(c,&out)==MATTER_OK && out.opcode==1); CHECK(matter_im_client_sent(c)==MATTER_OK); }
            uint8_t status; const uint8_t* body; size_t size;
            CHECK(matter_im_client_result(c,&status,&body,&size)==MATTER_OK && !status && size==sizeof(fields) && !memcmp(body,fields,size));
            CHECK(matter_im_client_receive(c,9,b,sizeof(b))==MATTER_INVALID_STATE);
        }
        matter_im_client_delete(c);
    }
    puts("PASS Invoke client: encoded request/response identity/status reply/revision/truncation/duplicate");
    for(unsigned mode=0;mode<5;++mode) {
        const Matter_Im_Command_Path_T path={1,0x29,4};
        Matter_Im_Client_T c=matter_im_client_new(&path,mode==4?3:MATTER_IM_CLIENT_STATUS_ONLY,fields,sizeof(fields)); CHECK(c);
        CHECK(matter_im_client_sent(c)==MATTER_OK);
        uint8_t status_reply[]={0x15,0x29,0,0x36,1,0x15,0x35,1,0x37,0,0x24,0,1,0x24,1,0x29,0x24,2,4,0x18,
            0x35,1,0x24,0,0,0x18,0x18,0x18,0x18,0x24,255,13,0x18};
        if(mode==1) status_reply[24]=1;
        if(mode==2) status_reply[18]=3;
        if(mode==3) status_reply[7]=0;
        Matter_Result_T r=matter_im_client_receive(c,9,status_reply,sizeof(status_reply));
        if(mode>=2) CHECK(r==MATTER_INVALID_ARGUMENT);
        else {
            uint8_t status; const uint8_t* body; size_t n;
            CHECK(r==MATTER_OK && matter_im_client_result(c,&status,&body,&n)==MATTER_OK && status==mode && !n);
        }
        matter_im_client_delete(c);
    }
    puts("PASS Notify status-only Invoke: success/error, path binding, unexpected data and ordinary command unchanged");
}
static void boundaries(void) {
    for(unsigned mode=0;mode<5;++mode) {
        Test* t=setup(true); t->expected_token=32;
        CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,0);
        memset(t->extra,7,sizeof(t->extra));
        const uint8_t header[]={0x17,0xd1,1,0,0,0,1,0,0xf5,1};
        memcpy(t->extra,header,sizeof(header)); t->extra[511]=0x18;
        memset(t->uri,'a',257); memcpy(t->uri,"bdx://000000000000002A/",23); memset(t->version,'v',65);
        CHECK(matter_tlv_writer_init(&t->writer,t->response,sizeof(t->response),4)==MATTER_TLV_OK);
        put(t,MATTER_TLV_STRUCTURE,-1,0,NULL,0); put(t,MATTER_TLV_UNSIGNED,0,0,NULL,0);
        put(t,MATTER_TLV_UTF8,2,0,t->uri,mode==1?257:256); put(t,MATTER_TLV_UNSIGNED,3,2,NULL,0);
        put(t,MATTER_TLV_UTF8,4,0,t->version,mode==2?65:64);
        put(t,MATTER_TLV_BYTES,5,0,(char*)t->extra,mode==3?33:32);
        put(t,MATTER_TLV_BYTES,7,0,(char*)t->extra,mode==4?513:512);
        put(t,MATTER_TLV_END,-1,0,NULL,0); CHECK(matter_tlv_writer_finish(&t->writer,&t->size)==MATTER_TLV_OK);
        t->ready=true; pump(t,1); CHECK(t->available==(mode==0?1u:0u)); destroy(t);
    }
    puts("PASS QueryImageResponse URI256/version64/token32/metadata512 and each over-limit rejection");
}
static void metadata_shape(void) {
    /* Core 11.20: presence requires an anonymous TLV list, even when there
     * are no vendor elements. CHIP's example provider sends zero bytes for
     * even requestor node IDs; that is distinct from a valid empty list. */
    for(unsigned mode=0;mode<3;++mode) {
        Test* t=setup(true); CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,0);
        response(t,0,0,true); size_t prefix=t->size-1;
        const uint8_t zero[]={0x30,7,0,0x18},list[]={0x30,7,2,0x17,0x18,0x18},structure[]={0x30,7,2,0x15,0x18,0x18};
        const uint8_t* bytes=mode==0?zero:mode==1?list:structure; size_t size=mode?sizeof(list):sizeof(zero);
        memcpy(t->response+prefix,bytes,size);t->size=prefix+size;
        pump(t,1); CHECK(t->available==(mode==1?1u:0u)); destroy(t);
    }
    puts("PASS OTA metadata: empty anonymous list accepted; zero bytes and wrong container rejected");
}
static void manual_requests(void) {
    CHECK(matter_ota_query_request(NULL,0)==MATTER_INVALID_ARGUMENT);
    Test* t=setup(false);
    CHECK(matter_ota_query_request(t->query,0)==MATTER_INVALID_STATE);
    t->offer.announced=true; t->offer.reason=1;
    CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,10); CHECK(!t->starts);
    CHECK(matter_ota_query_request(t->query,9)==MATTER_INVALID_ARGUMENT);
    CHECK(matter_ota_query_request(t->query,10)==MATTER_OK); pump(t,10); CHECK(t->starts==1);
    CHECK(matter_ota_query_request(t->query,10)==MATTER_BUSY);
    response(t,1,180,false); pump(t,20);
    CHECK(matter_ota_query_request(t->query,30)==MATTER_OK);
    pump(t,180019); CHECK(t->starts==1); pump(t,180020); CHECK(t->starts==2);
    response(t,2,0,false); pump(t,180021);
    CHECK(matter_ota_query_request(t->query,180022)==MATTER_OK);
    CHECK(matter_ota_query_request(t->query,180023)==MATTER_OK);
    pump(t,300020); CHECK(t->starts==2); pump(t,300021); CHECK(t->starts==3);
    response(t,2,0,false); pump(t,300022);
    ++t->generation; CHECK(matter_ota_query_request(t->query,300023)==MATTER_INVALID_STATE);
    CHECK(matter_ota_query_stop(t->query)==MATTER_OK);
    CHECK(matter_ota_query_request(t->query,300023)==MATTER_INVALID_STATE); destroy(t);
    t=setup(false); t->offer.announced=true; t->offer.reason=2; t->random=599;
    CHECK(matter_ota_query_offer(t->query,&t->offer,0));
    CHECK(matter_ota_query_request(t->query,10)==MATTER_OK);
    pump(t,599999); CHECK(!t->starts); pump(t,600000); CHECK(t->starts==1); destroy(t);
    t=setup(true); CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,0);
    response(t,0,60,true); pump(t,1);
    CHECK(matter_ota_query_request(t->query,2)==MATTER_BUSY); destroy(t);
    t=setup(false); CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,0);
    response(t,1,0,false); pump(t,1);
    CHECK(matter_ota_query_request(t->query,2)==MATTER_OK);
    pump(t,120001); CHECK(t->starts==2);
    response(t,1,0,false); pump(t,120002);
    CHECK(matter_ota_query_request(t->query,120003)==MATTER_OK);
    pump(t,240002); CHECK(t->starts==2); /* Global floor alone has elapsed. */
    pump(t,360001); CHECK(t->starts==2); pump(t,360002); CHECK(t->starts==3); destroy(t);
    puts("PASS explicit OTA query: selected/live provider, daily override, clocks, Busy/image ownership, 120s/provider/urgent floors and stop");
}
static void restart_retry_chain(void) {
    Test* t=setup(false); CHECK(matter_ota_query_offer(t->query,&t->offer,0)); pump(t,0);
    response(t,1,60,false); pump(t,1); CHECK(t->state==3 && t->reason==4);
    pump(t,120001); CHECK(t->starts==2);
    t->take_result=MATTER_PORT_ERROR; t->ready=true; t->im=0; t->size=0;
    pump(t,120010); CHECK(t->state==1 && t->reason==2 && !t->available);
    CHECK(matter_ota_query_request(t->query,120011)==MATTER_OK);
    pump(t,240010); CHECK(t->starts==2); /* Global floor expired, second-failure backoff did not. */
    pump(t,360009); CHECK(t->starts==2); pump(t,360010); CHECK(t->starts==3);
    t->take_result=MATTER_OK; response(t,2,-1,false); pump(t,360011);
    CHECK(t->state==1 && t->reason==1 && !t->available); /* An actual NotAvailable, not a transport failure. */
    CHECK(matter_ota_query_request(t->query,360012)==MATTER_OK);
    pump(t,480010); CHECK(t->starts==3); pump(t,480011); CHECK(t->starts==4);
    response(t,1,60,false); pump(t,480012);
    CHECK(t->state==3 && t->reason==4);
    pump(t,600011); CHECK(t->starts==4); pump(t,600012); CHECK(t->starts==5); destroy(t);
    puts("PASS query restart chain: Busy60, transport failure/Idle, 240s backoff, actual NotAvailable resets failures and next Busy uses120s");
}
int main(void) { client(); policy(); retry_states(); handoff(); boundaries(); metadata_shape(); manual_requests(); restart_retry_chain();
#ifdef MATTER_TEST_ALLOC
    CHECK(!live); puts("PASS Query/Invoke constructor OOM and allocation ownership");
#endif
    return 0;
}
