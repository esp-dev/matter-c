/* Shared host identity fixture, public test DAC private scalar=3 only. */
#include "matter_opcreds_host.h"
#include "test_opcreds_vectors.h"
#define OC_CHECK(c) do { if(!(c)) { fprintf(stderr,"Opcreds:%d: %s\n",__LINE__,#c); abort(); } } while(0)
#define OC_DER(a) (Matter_Der_T){a,sizeof(a)}
typedef struct {
    Matter_Crypto_Port_T crypto; Matter_Credentials_Port_T credentials;
    Matter_Opcreds_Host_Config_T config; Matter_Opcreds_Host_T host;
    Matter_Opcreds_Port_T backend, port; Matter_Opcreds_T core;
    Matter_Tlv_Writer_T writer; Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T e;
    Matter_Im_Command_Result_T result;
    uint64_t token; size_t request_size, reply_size, tbs_size, csr_size;
    uint8_t key[32], nonce[32], challenge[16], request[128], reply[1024], tbs[916], signature[64], csr[512];
    uint8_t candidate[65], previous[65], parsed[65];
    unsigned signs, prepares, publishes, discards;
    bool revoked, fail_sign, fail_prepare, fail_publish, hold_discard, fail_time, reenter;
    void* session_user;
    Matter_Result_T (*session_challenge)(void*,Matter_Exchange_Session_T,uint8_t[16]);
} OcFixture;
static Matter_Result_T oc_challenge(void* u,Matter_Exchange_Session_T session,uint8_t out[16]) {
    OcFixture* f=u;
    if(f->revoked) return MATTER_INVALID_STATE;
    if(f->session_challenge) return f->session_challenge(f->session_user,session,out);
    if(session!=1) return MATTER_INVALID_STATE;
    memcpy(out,f->challenge,16); return MATTER_OK;
}
static Matter_Result_T oc_time(void* u,uint32_t* out) {
    OcFixture* f=u; *out=677103357; return f->fail_time?MATTER_PORT_ERROR:MATTER_OK;
}
static Matter_Result_T oc_sign(void* u,const uint8_t* p,size_t n,uint8_t out[64]) {
    OcFixture* f=u; ++f->signs;
    if(f->reenter) OC_CHECK(matter_opcreds_process(f->core)==MATTER_BUSY && matter_opcreds_delete(f->core)==MATTER_BUSY);
    return f->fail_sign?MATTER_PORT_ERROR:f->backend.sign(f->host,p,n,out);
}
static Matter_Result_T oc_prepare(void* u,uint64_t* h,uint8_t* csr,size_t n,size_t* size) {
    OcFixture* f=u; ++f->prepares;
    return f->fail_prepare?MATTER_PORT_ERROR:f->backend.csr_prepare(f->host,h,csr,n,size);
}
static Matter_Result_T oc_publish(void* u,uint64_t h) {
    OcFixture* f=u; ++f->publishes;
    return f->fail_publish?MATTER_PORT_ERROR:f->backend.csr_publish(f->host,h);
}
static Matter_Result_T oc_discard(void* u,uint64_t h) {
    OcFixture* f=u; ++f->discards;
    return f->hold_discard?MATTER_PENDING:f->backend.csr_discard(f->host,h);
}
static OcFixture* oc_new(const Matter_Crypto_Port_T* crypto,const Matter_Credentials_Port_T* cp) {
    OcFixture* f=calloc(1,sizeof(*f)); OC_CHECK(f); f->crypto=*crypto; f->credentials=*cp;
    f->key[31]=3; for(unsigned i=0;i<32;++i) f->nonce[i]=(uint8_t)(i+1);
    for(unsigned i=0;i<16;++i) f->challenge[i]=(uint8_t)(0xa0+i);
    f->config.identity=(Matter_Opcreds_Config_T){.dac=OC_DER(oc_dac),.pai=OC_DER(oc_pai),.certification_declaration=OC_DER(oc_cd),.data_version=17};
    f->config.trusted_paa=OC_DER(oc_paa); f->config.dac_private=f->key; f->config.vendor_id=0xfff1; f->config.product_id=0x8000;
    f->config.user=f; f->config.challenge=oc_challenge; f->config.timestamp=oc_time;
    f->host=matter_opcreds_host_new(&f->config,crypto,cp); OC_CHECK(f->host);
    f->backend=matter_opcreds_host_port(f->host);
    f->port=(Matter_Opcreds_Port_T){f,oc_challenge,oc_time,oc_sign,oc_prepare,oc_publish,oc_discard};
    f->core=matter_opcreds_new(&f->config.identity,&f->port); OC_CHECK(f->core); return f;
}
static inline void oc_free(OcFixture* f) {
    f->hold_discard=false;
    OC_CHECK(matter_opcreds_rollback(f->core)==MATTER_OK && matter_opcreds_delete(f->core)==MATTER_OK);
    OC_CHECK(matter_opcreds_host_delete(f->host)==MATTER_OK); memset(f,0,sizeof(*f)); free(f);
}
static void oc_put(OcFixture* f,Matter_Tlv_Type_T type,int tag,uint64_t value,const uint8_t* p,size_t n) {
    f->e=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=value,.data=p,.size=n};
    OC_CHECK(matter_tlv_write(&f->writer,&f->e,0)==MATTER_TLV_OK);
}
static void oc_request(OcFixture* f,uint32_t command,unsigned cert,size_t nonce_size,bool update) {
    OC_CHECK(matter_tlv_writer_init(&f->writer,f->request,sizeof(f->request),2)==MATTER_TLV_OK);
    oc_put(f,MATTER_TLV_STRUCTURE,-1,0,NULL,0);
    if(command==2) oc_put(f,MATTER_TLV_UNSIGNED,0,cert,NULL,0);
    else oc_put(f,MATTER_TLV_BYTES,0,0,f->nonce,nonce_size);
    if(command==4) oc_put(f,MATTER_TLV_BOOL,1,update,NULL,0);
    oc_put(f,MATTER_TLV_END,-1,0,NULL,0);
    OC_CHECK(matter_tlv_writer_finish(&f->writer,&f->request_size)==MATTER_TLV_OK);
}
static inline Matter_Result_T oc_start(OcFixture* f,uint32_t cmd,bool armed) {
    OC_CHECK(matter_tlv_writer_init(&f->writer,f->reply,sizeof(f->reply),4)==MATTER_TLV_OK);
    return matter_opcreds_start(f->core,1,cmd,armed,f->request,f->request_size,&f->writer,&f->result,&f->token);
}
static inline void oc_finish(OcFixture* f) {
    Matter_Result_T r=MATTER_PENDING;
    for(unsigned i=0;i<8 && r==MATTER_PENDING;++i) {
        Matter_Result_T step=matter_opcreds_process(f->core); OC_CHECK(step==MATTER_OK || step==MATTER_PENDING);
        r=matter_opcreds_poll(f->core,f->token,&f->writer,&f->result);
    }
    OC_CHECK(r==MATTER_OK);
    if(!f->result.status) OC_CHECK(matter_tlv_writer_finish(&f->writer,&f->reply_size)==MATTER_TLV_OK);
}
/* Works on a bare command body OR a full IM response, independently locates the
 * two signed octet fields and validates their exact serialized transcript. */
static void oc_verify(OcFixture* f,uint32_t cmd,const uint8_t* data,size_t n) {
    OC_CHECK(matter_tlv_init(&f->reader,data,n,8)==MATTER_TLV_OK);
    unsigned fields=0; Matter_Tlv_Result_T tr;
    while((tr=matter_tlv_next(&f->reader,&f->e))==MATTER_TLV_OK) {
        if(f->e.type!=MATTER_TLV_BYTES) continue;
        if(f->e.tag.number==0) { OC_CHECK(!fields && f->e.size<=900); memcpy(f->tbs,f->e.data,f->e.size); f->tbs_size=f->e.size; fields|=1; }
        else if(f->e.tag.number==1) { OC_CHECK(fields==1 && f->e.size==64); memcpy(f->signature,f->e.data,64); fields|=2; }
    }
    OC_CHECK(tr==MATTER_TLV_DONE && fields==3);
    memcpy(f->tbs+f->tbs_size,f->challenge,16);
    OC_CHECK(f->crypto.ecdsa_verify(f->crypto.user,oc_public,f->tbs,f->tbs_size+16,f->signature)==MATTER_OK);
    f->tbs[f->tbs_size]^=1;
    OC_CHECK(f->crypto.ecdsa_verify(f->crypto.user,oc_public,f->tbs,f->tbs_size+16,f->signature)!=MATTER_OK);
    f->tbs[f->tbs_size]^=1;
    OC_CHECK(matter_tlv_init(&f->reader,f->tbs,f->tbs_size,2)==MATTER_TLV_OK);
    OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.type==MATTER_TLV_STRUCTURE && !f->e.tag.control);
    OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.type==MATTER_TLV_BYTES && f->e.tag.number==1);
    if(cmd==4) {
        OC_CHECK(f->e.size<=512); memcpy(f->csr,f->e.data,f->e.size); f->csr_size=f->e.size;
        OC_CHECK(f->credentials.csr_verify(f->credentials.user,(Matter_Der_T){f->csr,f->csr_size},f->parsed)==MATTER_OK);
        OC_CHECK(matter_opcreds_host_candidate(f->host,f->candidate)==MATTER_OK && !memcmp(f->candidate,f->parsed,65));
    } else OC_CHECK(f->e.size==sizeof(oc_cd) && !memcmp(f->e.data,oc_cd,sizeof(oc_cd)));
    OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.tag.number==2 && f->e.type==MATTER_TLV_BYTES && f->e.size==32 && !memcmp(f->e.data,f->nonce,32));
    if(!cmd) OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.tag.number==3 && f->e.unsigned_value==677103357);
    OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.type==MATTER_TLV_END && matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_DONE);
}
