#include "session/matter_case.h"
#ifndef MATTER_TEST_PASE
#include "test_opcreds_fixture.h"
#include "test_fabric_fixture.h"
#endif
typedef struct {
    FabFixture* fabrics[2]; Matter_Case_T session[2]; Matter_Case_Config_T config[2]; Matter_Case_Port_T ports[2];
    Matter_Case_Keys_T keys[2]; Matter_Secure_T secure[2]; Matter_Crypto_Port_T crypto;
    uint8_t bytes[1200],packet[1232]; size_t size; unsigned admitted;
} CaseFixture;
static CaseFixture* case_fixture(const Matter_Crypto_Port_T* crypto,const Matter_Credentials_Port_T* cp) {
    CaseFixture* f=calloc(1,sizeof(*f)); OC_CHECK(f); f->crypto=*crypto;
    for(unsigned i=0;i<2;++i) {
        FabFixture* m=f->fabrics[i]=fab_new(crypto,cp);
        fab_csr(m,i?10:11); fab_request(m,11,FAB_CERT(fab_root),(Matter_Cert_Tlv_T){0},0); fab_call(m,1,11,true,0,0);
        fab_request(m,6,i?FAB_CERT(fab_noc0):FAB_CERT(fab_conflict),(Matter_Cert_Tlv_T){0},i?101:100); fab_call(m,1,6,true,0,0);
        f->ports[i]=matter_fabric_host_case_port(m->host);
        f->config[i]=(Matter_Case_Config_T){.responder=i!=0,.local_session_id=(uint16_t)(41+i),.timeout_ms=30000,.fabric_index=1,.peer_node_id=100,
            .time={MATTER_CERT_TIME_SUPPLIED,{2026,10,9,0,0,0}}};
        f->session[i]=matter_case_new(crypto,cp,&f->ports[i],&f->config[i],0); OC_CHECK(f->session[i]);
    }
    return f;
}
static void case_free(CaseFixture* f) {
    for(unsigned i=0;i<2;++i) {
        if(f->secure[i]) OC_CHECK(matter_secure_close(f->secure[i])==MATTER_OK && matter_secure_delete(f->secure[i])==MATTER_OK);
        OC_CHECK(matter_case_delete(f->session[i])==MATTER_OK); fab_free(f->fabrics[i]);
    }
    memset(f,0,sizeof(*f)); free(f);
}
static inline void case_step(CaseFixture* f,unsigned from,uint64_t now) {
    Matter_Pase_Message_T message,again; OC_CHECK(matter_case_output(f->session[from],&message)==MATTER_OK);
    OC_CHECK(matter_case_output(f->session[from],&again)==MATTER_OK && message.data==again.data && message.size==again.size);
    memcpy(f->bytes,message.data,message.size); f->size=message.size;
    OC_CHECK(matter_case_receive(f->session[1-from],message.opcode,f->bytes,f->size)==MATTER_OK && matter_case_sent(f->session[from])==MATTER_OK);
    memset(f->bytes,0,f->size); /* Receiver owns the payload. */
    Matter_Result_T r=matter_case_process(f->session[1-from],now); OC_CHECK(r==MATTER_PENDING || r==MATTER_OK);
}
static inline void case_establish(CaseFixture* f) {
    OC_CHECK(matter_case_process(f->session[0],0)==MATTER_PENDING);
    for(unsigned i=0;i<3;++i) { OC_CHECK(matter_case_take_keys(f->session[i%2],&f->keys[i%2])==MATTER_INVALID_STATE); case_step(f,i%2,i+1); }
    case_step(f,1,4); OC_CHECK(matter_case_state(f->session[0])==MATTER_CASE_COMPLETE);
    OC_CHECK(matter_case_state(f->session[1])==MATTER_CASE_COMPLETE);
    OC_CHECK(matter_case_confirm_delivery(f->session[1],5)==MATTER_OK);
}
