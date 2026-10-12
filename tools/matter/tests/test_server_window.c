/* Host composition regression: rollback must not destroy window credentials.
 * No socket/state files: real root/admin/crypto, empty dispatcher sessions. */
#include "runtime/matter_runtime.c"
#include "crypto/matter_crypto_mbedtls.h"
#include "session/matter_secure_internal.h"
#include "clusters/matter_root_internal.h"
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"Window:%d: %s\n",__LINE__,#c); abort(); } } while(0)
static Matter_Result_T vendor(void* u,uint8_t i,uint16_t* v) { (void)u; (void)i; *v=0xfff1; return MATTER_OK; }
static Matter_Result_T unblocked(void* u,bool* b) { (void)u; *b=false; return MATTER_OK; }
static Matter_Result_T idle(void* u) { (void)u; return MATTER_OK; }
static Matter_Result_T pending_cleanup(void* u) { return *(bool*)u?MATTER_PENDING:MATTER_OK; }
static uint8_t grant;
static Matter_Result_T radio_regulatory(void* u,const Matter_Root_Settings_T* v,uint8_t c,bool* ok) { (void)u; (void)v; (void)c; *ok=true; return MATTER_OK; }
static uint8_t live_access(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* p,Matter_Im_Privilege_T v) {
    (void)u; (void)p; CHECK(session==1 && v==MATTER_IM_ADMINISTER); return grant;
}
static Matter_Result_T case_keys(void* u,Matter_Pase_Keys_T* keys,Matter_Secure_Identity_T* id) {
    (void)u; memset(keys,0,sizeof(*keys)); keys->local_session_id=1; keys->peer_session_id=2;
    *id=(Matter_Secure_Identity_T){.fabric_index=1,.local_node_id=1,.peer_node_id=2}; return MATTER_OK;
}
static void attempt(Matter_Runtime_T s,uint64_t now,bool allowed) {
    Matter_Pase_T p=pase(s,123,now); CHECK((p!=NULL)==allowed);
    if(p) CHECK(matter_pase_delete(p)==MATTER_OK);
}
static void open_window(Matter_Runtime_T s,uint8_t* args) {
    /* Valid verifier w0=1, L=G; cryptographic handshake tested by SDK scenario. */
    const uint8_t head[]={0x15,0x25,0,180,0,0x30,1,97};
    const uint8_t tail[]={0x25,2,0x23,1,0x25,3,0xe8,3,0x30,4,16};
    memcpy(args,head,sizeof(head)); memcpy(args+8,s->pase.w0,32); memcpy(args+40,s->pase.L,65);
    memcpy(args+105,tail,sizeof(tail)); memcpy(args+116,s->pase.salt,16); args[132]=0x18;
    Matter_Cluster_Request_T q={.session=1,.fabric=1,.is_case=true};
    Matter_Im_Command_Result_T r; uint64_t token;
    CHECK(matter_cluster_start(s->admin,0,&q,args,133,NULL,&r,&token)==MATTER_OK && !r.status && !token);
}
int main(void) {
    Matter_Runtime_T s=calloc(1,sizeof(*s)); uint8_t* args=calloc(1,133); CHECK(s && args); s->platform.regulatory=radio_regulatory;
    Matter_Crypto_Mbedtls_T backend=matter_crypto_mbedtls_new(NULL); CHECK(backend);
    CHECK(matter_crypto_mbedtls_port(backend,&s->crypto)==MATTER_OK);
    s->identity.vendor_name=(Matter_Root_Text_T){1,{'v'}}; s->identity.product_name=(Matter_Root_Text_T){1,{'p'}};
    s->identity.hardware_string=(Matter_Root_Text_T){1,{'h'}}; s->identity.software_string=(Matter_Root_Text_T){1,{'s'}};
    s->identity.unique_id=(Matter_Root_Text_T){1,{'u'}}; s->identity.vendor_id=0xfff1; s->identity.product_id=0x8001;
    s->identity.configuration_version=1; s->identity.capabilities=(Matter_Root_Capabilities_T){3,3,1,1,9,3};
    s->identity.settings.location[0]=s->identity.settings.location[1]='X';
    bool pending=true;
    Matter_Root_Port_T rp={s,load,authorize,store};
    Matter_Root_Commissioning_Config_T config={60,900,0,2,true,true,0};
    Matter_Root_Commissioning_Port_T cp={&pending,idle,pending_cleanup,regulatory,NULL};
    s->root=matter_root_new_commissioning(&rp,&config,&cp,0); CHECK(s->root);
    s->pase=(Matter_Pase_Config_T){.responder=true,.iterations=1000,.salt_size=16,.timeout_ms=30000};
    s->pase.w0[31]=1;
    CHECK(s->crypto.p256_base(s->crypto.user,s->pase.w0,32,s->pase.L)==MATTER_OK);
    s->window=true; s->deadline=900000;
    CHECK(retire(s,false)==MATTER_OK && s->window && s->deadline==900000);
    attempt(s,0,false); /* Async recovery gates admission, not advertising. */
    CHECK(matter_root_process(s->root,0)==MATTER_PENDING && matter_runtime_commissioning_mode(s,NULL)==1);
    pending=false; CHECK(matter_root_process(s->root,1)==MATTER_OK); attempt(s,1,true);
    CHECK(retire(s,false)==MATTER_OK); attempt(s,899999,true); attempt(s,900000,false);
    CHECK(retire(s,true)==MATTER_OK && !matter_runtime_commissionable(s));
    Matter_Admin_Commissioning_Port_T ap={s,vendor,unblocked,admin_advertise,admin_revoke};
    s->admin=matter_admin_commissioning_new(&ap,&s->crypto,0,0); CHECK(s->admin);
    open_window(s,args); uint64_t deadline; uint16_t discriminator=0;
    CHECK(matter_cluster_deadline(s->admin,&deadline)==MATTER_OK && deadline==180000);
    for(unsigned i=0;i<3;++i) {
        CHECK(retire(s,false)==MATTER_OK);
        CHECK(matter_runtime_commissioning_mode(s,&discriminator)==2 && discriminator==0x123);
        CHECK(matter_cluster_deadline(s->admin,&deadline)==MATTER_OK && deadline==180000);
        attempt(s,i+1,true);
    }
    CHECK(matter_cluster_process(s->admin,180000)==MATTER_OK);
    CHECK(retire(s,false)==MATTER_OK && !matter_runtime_commissionable(s)); attempt(s,180000,false);
    open_window(s,args); CHECK(retire(s,true)==MATTER_OK);
    CHECK(matter_cluster_process(s->admin,180001)==MATTER_OK && !matter_runtime_commissionable(s)); attempt(s,180001,false);
    open_window(s,args);
    const uint8_t empty[]={0x15,0x18}; Matter_Cluster_Request_T q={.session=1,.fabric=1,.is_case=true};
    Matter_Im_Command_Result_T r; uint64_t token;
    CHECK(matter_cluster_start(s->admin,2,&q,empty,sizeof(empty),NULL,&r,&token)==MATTER_PENDING);
    CHECK(matter_cluster_process(s->admin,180002)==MATTER_OK);
    CHECK(matter_cluster_poll(s->admin,token,NULL,&r)==MATTER_OK && !r.status);
    CHECK(retire(s,false)==MATTER_OK && !matter_runtime_commissionable(s)); attempt(s,180002,false);
    open_window(s,args); s->stopping=true; attempt(s,180003,false);
    CHECK(matter_admin_commissioning_close(s->admin)==MATTER_PENDING);
    CHECK(matter_cluster_process(s->admin,180003)==MATTER_OK);
    CHECK(matter_root_delete(s->root)==MATTER_OK);
    /* Slow cleanup used to revoke the already accepted CASE Revoke response.
     * Keep live access checks; no permission for new commands or PASE. */
    pending=true; rp.authorize=live_access; s->stopping=false; config.recover_pending=false;
    s->root=matter_root_new_commissioning(&rp,&config,&cp,0); CHECK(s->root);
    CHECK(matter_root_attach_cluster(s->root,s->admin)==MATTER_OK);
    Matter_Secure_T secure=matter_secure_from_case(&s->crypto,NULL,case_keys,0); CHECK(secure);
    Matter_Root_Case_Invoke_Binding_T binding; Matter_Im_Invoke_Port_T invoke;
    Matter_Im_Invoke_Async_Port_T async; Matter_Im_Read_Fabric_Port_T resolver;
    CHECK(matter_root_case_invoke_port(s->root,1,secure,&binding,&invoke,&async,&resolver)==MATTER_OK);
    const Matter_Im_Command_Path_T revoke_path={0,0x3c,2},open_path={0,0x3c,0};
    open_window(s,args);
    const uint8_t arm[]={0x15,0x24,0,60,0x24,1,0,0x18};
    const Matter_Im_Command_Path_T arm_path={0,0x30,0}; Matter_Tlv_Writer_T writer;
    CHECK(matter_tlv_writer_init(&writer,args,133,4)==MATTER_TLV_OK);
    CHECK(matter_root_cluster_start(s->root,&arm_path,&q,arm,sizeof(arm),&writer,&r,&token)==MATTER_OK && !r.status);
    CHECK(async.start(invoke.user,&revoke_path,empty,sizeof(empty),NULL,&r,&token)==MATTER_PENDING && binding.pending==s->admin);
    CHECK(matter_cluster_process(s->admin,180004)==MATTER_PENDING);
    CHECK(invoke.authorize(invoke.user,1,&revoke_path,MATTER_IM_ADMINISTER)==MATTER_IM_SUCCESS);
    CHECK(invoke.authorize(invoke.user,2,&revoke_path,MATTER_IM_ADMINISTER)==MATTER_IM_UNSUPPORTED_ACCESS);
    CHECK(invoke.authorize(invoke.user,1,&open_path,MATTER_IM_ADMINISTER)==MATTER_IM_UNSUPPORTED_ACCESS);
    grant=MATTER_IM_UNSUPPORTED_ACCESS;
    CHECK(invoke.authorize(invoke.user,1,&revoke_path,MATTER_IM_ADMINISTER)==grant);
    grant=MATTER_IM_ACCESS_RESTRICTED;
    CHECK(invoke.authorize(invoke.user,1,&revoke_path,MATTER_IM_ADMINISTER)==grant); grant=0;
    Matter_Root_Invoke_Binding_T pase_binding; Matter_Im_Invoke_Port_T pase_port;
    CHECK(matter_root_invoke_port(s->root,1,&pase_binding,&pase_port)==MATTER_OK);
    CHECK(pase_port.authorize(pase_port.user,1,&revoke_path,MATTER_IM_ADMINISTER)==MATTER_IM_UNSUPPORTED_ACCESS);
    CHECK(async.poll(invoke.user,token,NULL,&r)==MATTER_PENDING && binding.pending==s->admin);
    CHECK(matter_cluster_process(s->admin,180004)==MATTER_PENDING);
    pending=false; CHECK(matter_root_process(s->root,1)==MATTER_OK);
    CHECK(matter_cluster_process(s->admin,180005)==MATTER_OK);
    CHECK(async.poll(invoke.user,token,NULL,&r)==MATTER_OK && !r.status && !binding.pending);
    CHECK(matter_secure_close(secure)==MATTER_OK);
    CHECK(matter_secure_delete(secure)==MATTER_OK && matter_root_delete(s->root)==MATTER_OK);
    CHECK(matter_cluster_delete(s->admin)==MATTER_OK);
    CHECK(matter_crypto_mbedtls_delete(backend)==MATTER_OK); free(args); free(s);
    puts("PASS host rollback: basic/enhanced admission, unchanged deadline/discriminator, cleanup gate, expiry, Complete, Revoke, stop");
    puts("PASS pending CASE Revoke waits for cleanup, checks live ACL/session, rejects new commands and PASE");
    return 0;
}
