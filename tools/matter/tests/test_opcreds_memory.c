#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "clusters/matter_opcreds.h"
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"Opcreds memory:%d: %s\n",__LINE__,#c); abort(); } } while(0)
#ifdef MATTER_TEST_ALLOC
static void allocation(void*,size_t);
static void releasing(void*,size_t);
#define MATTER_TEST_ALLOC_AFTER_ALLOC allocation
#define MATTER_TEST_ALLOC_BEFORE_FREE releasing
#include "test_alloc_bytes.h"
#endif
typedef struct {
    Matter_Opcreds_T model; Matter_Fabric_T fabrics; Matter_Fabric_View_T view;
    Matter_Tlv_Writer_T writer; Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T e;
    uint8_t public_blob[900],request[1024],reply[1024],held[1024],challenge[16];
    size_t request_size,reply_size,base_bytes,sign_size; uint64_t token,serial,staged,current;
    unsigned prepares,signs,publishes,discards,timestamps,roots,reentries;
    bool fail_prepare,fail_sign,fail_publish,hold_discard,fail_discard,revoked,fail_time;
    unsigned bad_csr; void* context;
    Matter_Im_Command_Result_T result;
} Fixture;
static Fixture* active;
#ifdef MATTER_TEST_ALLOC
static unsigned wipes;
#endif
static void reentry(Fixture* f) {
    if(!f || !f->model) return;
    ++f->reentries; Matter_Im_Command_Result_T out; Matter_Im_Value_T value; uint64_t token=0;
    CHECK(matter_opcreds_process(f->model)==MATTER_BUSY && matter_opcreds_delete(f->model)==MATTER_BUSY);
    CHECK(matter_opcreds_poll(f->model,f->token,NULL,&out)==MATTER_BUSY);
    CHECK(matter_opcreds_rollback(f->model)==MATTER_BUSY && matter_opcreds_commit_ready(f->model)==MATTER_BUSY);
    CHECK(matter_opcreds_read(f->model,0xfffd,&value)==MATTER_IM_FAILURE);
    CHECK(!matter_opcreds_start(f->model,1,0,true,NULL,0,NULL,&out,&token) && out.status==MATTER_IM_FAILURE && !token);
    matter_opcreds_cancel(f->model,f->token);
}
#ifdef MATTER_TEST_ALLOC
static void allocation(void* p,size_t n) { (void)p; (void)n; reentry(active); }
static void releasing(void* p,size_t n) {
    for(size_t i=0;i<n;++i) CHECK(!((uint8_t*)p)[i]);
    ++wipes;
    if(active && p!=active->context) reentry(active);
}
#endif
static Matter_Result_T challenge(void* u,Matter_Exchange_Session_T session,uint8_t out[16]) {
    Fixture* f=u; CHECK(session==1); reentry(f);
    memcpy(out,f->challenge,16); return f->revoked?MATTER_INVALID_STATE:MATTER_OK;
}
static Matter_Result_T timestamp(void* u,uint32_t* out) {
    Fixture* f=u; reentry(f); ++f->timestamps; *out=0x89abcdef; return f->fail_time?MATTER_PORT_ERROR:MATTER_OK;
}
static Matter_Result_T sign(void* u,const uint8_t* data,size_t n,uint8_t out[64]) {
    Fixture* f=u; reentry(f); ++f->signs; f->sign_size=n;
    CHECK(n<=916 && n>16 && !memcmp(data+n-16,f->challenge,16));
#ifdef MATTER_TEST_ALLOC
    CHECK(matter_test_allocation_size(data)==n && live==2 && live_bytes==f->base_bytes+n);
#endif
    memcpy(f->held,data,n-16); f->reply_size=n-16; memset(out,0x77,64);
    return f->fail_sign?MATTER_PORT_ERROR:MATTER_OK;
}
static Matter_Result_T prepare(void* u,uint64_t* key,uint8_t* csr,size_t capacity,size_t* size) {
    Fixture* f=u; reentry(f); ++f->prepares; CHECK(capacity==512);
#ifdef MATTER_TEST_ALLOC
    CHECK(matter_test_allocation_size(csr)==512 && live==2 && live_bytes==f->base_bytes+512);
#endif
    memset(csr,0x66,capacity);
    if(f->fail_prepare) { *key=0; *size=0; return MATTER_PORT_ERROR; }
    *key=f->staged=++f->serial; *size=f->bad_csr==1?0:f->bad_csr==2?513:512; return MATTER_OK;
}
static Matter_Result_T publish(void* u,uint64_t key) {
    Fixture* f=u; reentry(f); ++f->publishes; CHECK(key && key==f->staged);
#ifdef MATTER_TEST_ALLOC
    CHECK(live==2); /* TBS, not CSR, survives this phase. */
#endif
    if(f->fail_publish) return MATTER_PORT_ERROR;
    f->current=key; f->staged=0; return MATTER_OK;
}
static Matter_Result_T discard(void* u,uint64_t key) {
    Fixture* f=u; reentry(f); ++f->discards;
#ifdef MATTER_TEST_ALLOC
    CHECK(live==1 && live_bytes==f->base_bytes); /* No DER/TBS through retry. */
#endif
    if(f->hold_discard) return MATTER_PENDING;
    if(f->fail_discard) return MATTER_PORT_ERROR;
    if(f->staged==key) f->staged=0;
    if(f->current==key) f->current=0;
    return MATTER_OK;
}
static const Matter_Fabric_View_T* view(void* u) { return &((Fixture*)u)->view; }
static uint8_t root(void* u,Matter_Cert_Tlv_T cert) {
    Fixture* f=u; ++f->roots; CHECK(cert.size==400);
    for(size_t i=0;i<cert.size;++i) CHECK(cert.data[i]==0x66);
    return 0;
}
static Matter_Result_T install(void* u,Matter_Exchange_Session_T s,uint64_t key,const Matter_Fabric_Add_T* a,uint8_t* st,uint8_t* index) {
    (void)u; (void)s; (void)key; (void)a; (void)st; (void)index; abort(); return MATTER_PORT_ERROR;
}
static Matter_Result_T rollback(void* u) { (void)u; return MATTER_OK; }
static void put(Fixture* f,Matter_Tlv_Type_T type,int tag,uint64_t value,const uint8_t* p,size_t n) {
    f->e=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=value,.data=p,.size=n};
    CHECK(!matter_tlv_write(&f->writer,&f->e,0));
}
static void request(Fixture* f,uint32_t command) {
    CHECK(!matter_tlv_writer_init(&f->writer,f->request,sizeof(f->request),3)); put(f,MATTER_TLV_STRUCTURE,-1,0,NULL,0);
    if(command==11) {
        memset(f->public_blob,0x66,900); put(f,MATTER_TLV_BYTES,0,0,f->public_blob,400);
        put(f,MATTER_TLV_BYTES,8,0,f->public_blob,614); /* Exactly1024 bytes, unknown field retained. */
    } else if(command==2) put(f,MATTER_TLV_UNSIGNED,0,1,NULL,0);
    else { put(f,MATTER_TLV_BYTES,0,0,f->public_blob,32); if(command==4) put(f,MATTER_TLV_BOOL,1,0,NULL,0); }
    put(f,MATTER_TLV_END,-1,0,NULL,0); CHECK(!matter_tlv_writer_finish(&f->writer,&f->request_size));
}
static Matter_Result_T start(Fixture* f,uint32_t command) {
    CHECK(!matter_tlv_writer_init(&f->writer,f->reply,sizeof(f->reply),3));
    return matter_opcreds_start(f->model,1,command,true,f->request,f->request_size,&f->writer,&f->result,&f->token);
}
static void idle(Fixture* f) {
#ifdef MATTER_TEST_ALLOC
    CHECK(live==1 && live_bytes==f->base_bytes);
#endif
    CHECK(!matter_opcreds_commit_ready(f->model));
}
static void finish(Fixture* f,uint8_t status) {
    Matter_Result_T r=MATTER_PENDING;
    for(unsigned i=0;i<8 && r==MATTER_PENDING;++i) {
        Matter_Result_T p=matter_opcreds_process(f->model); CHECK(p==MATTER_OK || p==MATTER_PENDING);
        r=matter_opcreds_poll(f->model,f->token,&f->writer,&f->result);
    }
    CHECK(!r && f->result.status==status);
}
static Fixture* create(size_t cd_size) {
    Fixture* f=calloc(1,sizeof(*f)); CHECK(f); memset(f->public_blob,0x5a,900); memset(f->challenge,0xa5,16);
    Matter_Opcreds_Config_T config={.dac={f->public_blob,1},.pai={f->public_blob,1},.certification_declaration={f->public_blob,cd_size}};
    Matter_Opcreds_Port_T port={f,challenge,timestamp,sign,prepare,publish,discard};
    f->model=matter_opcreds_new(&config,&port); CHECK(f->model);
#ifdef MATTER_TEST_ALLOC
    CHECK(live==1 && live_bytes<1040); f->base_bytes=live_bytes; f->context=allocations->pointer;
#endif
    active=f; return f;
}
static void destroy(Fixture* f) {
    CHECK(!matter_opcreds_rollback(f->model) && !f->staged && !f->current);
    active=NULL; CHECK(!matter_opcreds_delete(f->model)); if(f->fabrics) CHECK(!matter_fabric_delete(f->fabrics)); free(f);
#ifdef MATTER_TEST_ALLOC
    CHECK(!live && !live_bytes);
#endif
}
static void successful(void) {
    Fixture* f=create(853); request(f,0); CHECK(start(f,0)==MATTER_PENDING);
#ifdef MATTER_TEST_ALLOC
    CHECK(live==1); /* No workspace at admission for nonce-only commands. */
#endif
    CHECK(matter_opcreds_process(f->model)==MATTER_PENDING && f->timestamps==1);
    CHECK(!matter_opcreds_process(f->model) && f->sign_size==916);
    CHECK(matter_opcreds_delete(f->model)==MATTER_INVALID_STATE);
    CHECK(!matter_opcreds_poll(f->model,f->token,&f->writer,&f->result) && !f->result.status);
    size_t size; CHECK(!matter_tlv_writer_finish(&f->writer,&size) && size==973); idle(f);
    uint8_t* saved=malloc(size); CHECK(saved); memcpy(saved,f->reply,size);
    request(f,0); CHECK(start(f,0)==MATTER_PENDING);
    CHECK(matter_opcreds_process(f->model)==MATTER_PENDING && !matter_opcreds_process(f->model));
    CHECK(!memcmp(saved,f->reply,size)); /* Caller output survives new phase workspace. */
    CHECK(!matter_opcreds_poll(f->model,f->token,&f->writer,&f->result)); free(saved);
    request(f,2); CHECK(!start(f,2) && !f->result.status); idle(f);
    request(f,4); CHECK(start(f,4)==MATTER_PENDING && matter_opcreds_process(f->model)==MATTER_PENDING);
    CHECK(matter_opcreds_process(f->model)==MATTER_PENDING && f->sign_size==569);
    CHECK(!matter_opcreds_process(f->model) && f->current && !f->staged);
    uint64_t candidate=f->current; CHECK(!matter_opcreds_poll(f->model,f->token,&f->writer,&f->result) && !f->result.status);
    CHECK(f->current==candidate); /* Published key outlives freed response workspace. */
    request(f,0); CHECK(start(f,0)==MATTER_PENDING); finish(f,0); CHECK(f->current==candidate);
    CHECK(f->reentries && f->timestamps==3); destroy(f);
}
static void cancellations(void) {
    for(unsigned phase=0;phase<=3;++phase) {
        Fixture* f=create(200); request(f,4); CHECK(start(f,4)==MATTER_PENDING);
        for(unsigned i=0;i<phase;++i) { Matter_Result_T r=matter_opcreds_process(f->model); CHECK(r==MATTER_PENDING || !r); }
        uint64_t candidate=f->current; f->hold_discard=true; matter_opcreds_cancel(f->model,f->token);
#ifdef MATTER_TEST_ALLOC
        CHECK(live==1 && live_bytes==f->base_bytes);
#endif
        if(f->staged) {
            CHECK(matter_opcreds_process(f->model)==MATTER_PENDING);
            f->hold_discard=false; f->fail_discard=true; CHECK(matter_opcreds_process(f->model)==MATTER_PENDING);
            CHECK(matter_opcreds_delete(f->model)==MATTER_INVALID_STATE); f->fail_discard=false;
            CHECK(!matter_opcreds_process(f->model));
        }
        CHECK(f->current==candidate); f->hold_discard=false; destroy(f);
    }
}
static void failures(void) {
    for(unsigned mode=0;mode<7;++mode) {
        Fixture* f=create(200); request(f,4); CHECK(start(f,4)==MATTER_PENDING); finish(f,0); uint64_t previous=f->current;
        f->fail_prepare=mode==0; f->fail_sign=mode==1; f->fail_publish=mode==2; f->bad_csr=mode==3?1:mode==4?2:0;
        request(f,4); CHECK(start(f,4)==MATTER_PENDING);
        if(mode>=5) { CHECK(matter_opcreds_process(f->model)==MATTER_PENDING); if(mode==5) f->revoked=true; else ++f->challenge[0]; }
        finish(f,mode>=5?MATTER_IM_UNSUPPORTED_ACCESS:MATTER_IM_FAILURE);
        CHECK(f->current==previous && !f->staged);
        f->revoked=false; f->fail_discard=false; destroy(f);
    }
    Fixture* f=create(200); f->fail_time=true; request(f,0); CHECK(start(f,0)==MATTER_PENDING); finish(f,MATTER_IM_FAILURE); destroy(f);
}
static void request_copy(void) {
    Fixture* f=create(200); f->view.root_ready=true; f->view.root_size=400; memset(f->view.root,0x66,400);
    Matter_Fabric_Port_T p={.user=f,.view=view,.root=root,.install=install,.rollback=rollback};
    f->fabrics=matter_fabric_new(&p); CHECK(f->fabrics && !matter_opcreds_attach_fabrics(f->model,f->fabrics));
    request(f,11); CHECK(f->request_size==1024);
#ifdef MATTER_TEST_ALLOC
    fail_at=calls+1; CHECK(!start(f,11) && f->result.status==MATTER_IM_RESOURCE_EXHAUSTED && !f->token && !f->roots); fail_at=0; idle(f);
#endif
    CHECK(start(f,11)==MATTER_PENDING); memset(f->request,0,f->request_size);
    CHECK(!matter_opcreds_process(f->model) && f->roots==1);
#ifdef MATTER_TEST_ALLOC
    CHECK(live==1);
#endif
    CHECK(!matter_opcreds_poll(f->model,f->token,NULL,&f->result) && !f->result.status); idle(f);
    request(f,11); CHECK(start(f,11)==MATTER_PENDING); f->revoked=true; finish(f,MATTER_IM_UNSUPPORTED_ACCESS); CHECK(f->roots==1);
    f->revoked=false; request(f,11); CHECK(start(f,11)==MATTER_PENDING); matter_opcreds_cancel(f->model,f->token); idle(f); destroy(f);
}
#ifdef MATTER_TEST_ALLOC
static void oom(void) {
    for(unsigned mode=0;mode<3;++mode) {
        Fixture* f=create(200); request(f,4); CHECK(start(f,4)==MATTER_PENDING); finish(f,0); uint64_t previous=f->current;
        unsigned prepares=f->prepares,signs=f->signs,publishes=f->publishes;
        request(f,mode?4:0); CHECK(start(f,mode?4:0)==MATTER_PENDING); fail_at=calls+(mode==2?2:1);
        CHECK(matter_opcreds_process(f->model)==MATTER_PENDING); fail_at=0;
        CHECK(live==1 && f->current==previous && f->signs==signs && f->publishes==publishes);
        CHECK(f->prepares==prepares+(mode==2)); /* CSR OOM precedes key generation. */
        if(mode==2) { f->hold_discard=true; CHECK(matter_opcreds_process(f->model)==MATTER_PENDING); f->hold_discard=false; }
        finish(f,MATTER_IM_RESOURCE_EXHAUSTED); CHECK(f->current==previous && !f->staged);
        request(f,4); CHECK(start(f,4)==MATTER_PENDING); finish(f,0); CHECK(f->current!=previous); destroy(f);
    }
}
#endif
int main(void) {
    successful(); cancellations(); failures(); request_copy();
#ifdef MATTER_TEST_ALLOC
    oom(); CHECK(wipes && !live); printf("PASS phase workspaces/OOM/secure wipe: peak=%zu max=%zu wipes=%u\n",peak_bytes,max_request,wipes);
#endif
    puts("PASS Opcreds limits, phase lifetimes, challenge/key binding, cancellation/discard retries and owned responses"); return 0;
}
