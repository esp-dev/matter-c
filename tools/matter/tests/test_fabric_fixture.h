#include "matter_fabric_host.h"
#include "test_fabric_vectors.h"
/* Test-only deterministic operational keys, independently certified by OpenSSL.
 * PASE and ECDSA nonce generation still use the real backend RNG. */
static uint8_t fab_scalar_value=10;
static Matter_Result_T fab_scalar(void* u,uint8_t out[32]) { (void)u; memset(out,0,32); out[31]=fab_scalar_value; return MATTER_OK; }
typedef struct {
    OcFixture* o; Matter_Fabric_Host_Image_T image; Matter_Fabric_Host_T host;
    Matter_Fabric_T model; Matter_Fabric_Port_T port; Matter_Cert_Time_Policy_T time;
    Matter_Fabric_Host_Control_T control;
    Matter_Tlv_Writer_T writer; Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T e;
    uint8_t args[1024], response[1024], wire[1024], ipk[16], signature[64], changed[400];
    size_t args_size,response_size,wire_size; uint64_t token;
    Matter_Im_Command_Result_T result;
} FabFixture;
static void fab_attach(FabFixture* f) {
    f->host=matter_fabric_host_new(f->image,f->o->host,&f->o->crypto,&f->o->credentials,&f->time); OC_CHECK(f->host);
    f->port=matter_fabric_host_port(f->host); f->model=matter_fabric_new(&f->port); OC_CHECK(f->model);
    OC_CHECK(matter_opcreds_attach_fabrics(f->o->core,f->model)==MATTER_OK);
}
static FabFixture* fab_new(const Matter_Crypto_Port_T* p,const Matter_Credentials_Port_T* cp) {
    FabFixture* f=calloc(1,sizeof(*f)); OC_CHECK(f); Matter_Crypto_Port_T crypto=*p; crypto.p256_scalar=fab_scalar;
    f->o=oc_new(&crypto,cp); f->time=(Matter_Cert_Time_Policy_T){MATTER_CERT_TIME_SUPPLIED,{2026,10,8,0,0,0}};
    f->image=matter_fabric_host_image_new(); OC_CHECK(f->image); fab_attach(f); return f;
}
static void fab_free(FabFixture* f) {
    f->control=(Matter_Fabric_Host_Control_T){0}; matter_fabric_host_control(f->host,&f->control);
    OC_CHECK(matter_opcreds_rollback(f->o->core)==MATTER_OK && matter_opcreds_delete(f->o->core)==MATTER_OK);
    OC_CHECK(matter_fabric_delete(f->model)==MATTER_OK && matter_fabric_host_delete(f->host)==MATTER_OK);
    OC_CHECK(matter_opcreds_host_delete(f->o->host)==MATTER_OK && matter_fabric_host_image_delete(f->image)==MATTER_OK);
    memset(f->o,0,sizeof(*f->o)); free(f->o); memset(f,0,sizeof(*f)); free(f);
}
static inline void fab_restart(FabFixture* f) {
    /* Simulated process loss AFTER installation consumed CSR: image retains its
     * journal, old runtime is discarded without executing rollback. */
    OC_CHECK(matter_opcreds_delete(f->o->core)==MATTER_OK && matter_fabric_delete(f->model)==MATTER_OK);
    OC_CHECK(matter_fabric_host_delete(f->host)==MATTER_OK);
    f->o->core=matter_opcreds_new(&f->o->config.identity,&f->o->port); OC_CHECK(f->o->core); fab_attach(f);
}
static void fab_put(FabFixture* f,Matter_Tlv_Type_T t,int tag,uint64_t v,const uint8_t* p,size_t n) {
    f->e=(Matter_Tlv_Element_T){.type=t,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=v,.data=p,.size=n};
    OC_CHECK(matter_tlv_write(&f->writer,&f->e,0)==MATTER_TLV_OK);
}
static void fab_request(FabFixture* f,uint32_t cmd,Matter_Cert_Tlv_T cert,Matter_Cert_Tlv_T icac,uint64_t admin) {
    OC_CHECK(matter_tlv_writer_init(&f->writer,f->args,sizeof(f->args),2)==MATTER_TLV_OK);
    fab_put(f,MATTER_TLV_STRUCTURE,-1,0,NULL,0); fab_put(f,MATTER_TLV_BYTES,0,0,cert.data,cert.size);
    if(cmd==6) {
        if(icac.size) fab_put(f,MATTER_TLV_BYTES,1,0,icac.data,icac.size);
        memset(f->ipk,0x42,16); fab_put(f,MATTER_TLV_BYTES,2,0,f->ipk,16);
        fab_put(f,MATTER_TLV_UNSIGNED,3,admin,NULL,0); fab_put(f,MATTER_TLV_UNSIGNED,4,0xfff1,NULL,0);
    }
    fab_put(f,MATTER_TLV_END,-1,0,NULL,0); OC_CHECK(matter_tlv_writer_finish(&f->writer,&f->args_size)==MATTER_TLV_OK);
}
static inline void fab_call(FabFixture* f,Matter_Exchange_Session_T session,uint32_t cmd,bool armed,uint8_t im_status,uint8_t noc_status) {
    OC_CHECK(matter_tlv_writer_init(&f->writer,f->response,sizeof(f->response),3)==MATTER_TLV_OK);
    Matter_Result_T r=matter_opcreds_start(f->o->core,session,cmd,armed,f->args,f->args_size,cmd==11?NULL:&f->writer,&f->result,&f->token);
    for(unsigned i=0;i<8 && r==MATTER_PENDING;++i) {
        Matter_Result_T step=matter_opcreds_process(f->o->core); OC_CHECK(step==MATTER_OK || step==MATTER_PENDING);
        r=matter_opcreds_poll(f->o->core,f->token,cmd==11?NULL:&f->writer,&f->result);
    }
    if(r!=MATTER_OK || f->result.status!=im_status) fprintf(stderr,"fabric cmd=%u result=%d IM=%u expected=%u NOC=%u\n",(unsigned)cmd,r,f->result.status,im_status,noc_status);
    OC_CHECK(r==MATTER_OK && f->result.status==im_status);
    if(!im_status && cmd==6) {
        OC_CHECK(matter_tlv_writer_finish(&f->writer,&f->response_size)==MATTER_TLV_OK);
        OC_CHECK(matter_tlv_init(&f->reader,f->response,f->response_size,2)==MATTER_TLV_OK);
        OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.unsigned_value==noc_status);
        OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK);
        if(!noc_status) { OC_CHECK(f->e.tag.number==1 && f->e.unsigned_value>=1 && f->e.unsigned_value<=254); OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK); }
        OC_CHECK(f->e.type==MATTER_TLV_END);
    }
}
static inline void fab_csr(FabFixture* f,unsigned key) {
    fab_scalar_value=(uint8_t)key; oc_request(f->o,4,0,32,false); OC_CHECK(oc_start(f->o,4,true)==MATTER_PENDING);
    oc_finish(f->o); OC_CHECK(!f->o->result.status); oc_verify(f->o,4,f->o->reply,f->o->reply_size);
}
#define FAB_CERT(a) (Matter_Cert_Tlv_T){a,sizeof(a)}
