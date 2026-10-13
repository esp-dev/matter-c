#include "matter_runtime.h"
#include "../storage/matter_store_tlv.h"
#include "matter_store_host.h"
#include "clusters/matter_admin_commissioning.h"
#include "clusters/matter_ota_query.h"
#include "clusters/matter_ota_apply.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
typedef struct { Matter_Credentials_Port_T base; void* user; Matter_Result_T (*utc)(void*,Matter_Cert_Time_T*); bool chip_validity; } Host_Credentials_T;
struct Matter_Runtime {
    Matter_Root_Config_T identity; Matter_Root_T root; Matter_Dispatch_T dispatch;
    Matter_Runtime_Config_T platform; Matter_Crypto_Port_T crypto; Matter_Credentials_Port_T credentials;
    Host_Credentials_T credential_adapter;
    Matter_Pase_Config_T pase; Matter_Cert_Time_Policy_T time;
    Matter_Opcreds_Host_Config_T attestation;
    Matter_Opcreds_Host_T keys; Matter_Opcreds_T opcreds;
    Matter_Fabric_Host_Image_T fabric_image; Matter_Fabric_Host_T fabric_host;
    Matter_Fabric_Port_T fabric_port; Matter_Fabric_T fabrics;
    Matter_Commissioning_Host_Image_T commission_image; Matter_Commissioning_Host_T commission;
    Matter_Wifi_T wifi; Matter_Acl_T acl; Matter_Groupkey_T groupkey;
    Matter_Diagnostics_Host_Image_T diagnostics_image; Matter_Diagnostics_Host_T diagnostics_host; Matter_Diagnostics_T diagnostics;
    Matter_Store_Host_T store;
    Matter_Cluster_T admin,ota; uint16_t enhanced_discriminator;
    Matter_Resolver_Port_T resolver; Matter_Case_Resumption_Profile_T resumption_profile;
    Matter_Udp_Path_T outbound; Matter_Ota_Query_T query; uint64_t now;
    Matter_Runtime_Ota_Port_T ota_port; bool has_ota; uint64_t download; uint32_t download_version;
    Matter_Ota_Apply_T apply; Matter_Ota_Apply_Context_T candidate;
    Matter_Ota_Update_T update; Matter_Ota_Signed_T proof;
    uint64_t notify; uint8_t notify_args[48]; bool ota_reboot,applied_event;
    uint64_t deadline; bool window,enhanced,stopping,stopped,reset,recovering;
    char log_buffer[384];
};
static void runtime_log(Matter_Runtime_T s,const char* format,...) {
    if(!s->platform.log) return;
    va_list args; va_start(args,format);
    (void)vsnprintf(s->log_buffer,sizeof(s->log_buffer),format,args); va_end(args);
    s->platform.log(s->platform.user,s->log_buffer);
}
static void erase(void* data,size_t size) { volatile uint8_t* p=data; while(size--) *p++=0; }
static Matter_Result_T host_csr_create(void* user,const uint8_t* key,uint8_t* der,size_t capacity,size_t* size) {
    Host_Credentials_T* h=user;
    return h->base.csr_create(h->base.user,key,der,capacity,size);
}
static Matter_Result_T host_csr_verify(void* user,Matter_Der_T csr,uint8_t* key) {
    Host_Credentials_T* h=user;
    return h->base.csr_verify(h->base.user,csr,key);
}
/* Strict mode uses application UTC at verification, not construction. Explicit CHIP
 * mode waives only operational validity periods; attestation stays unchanged. */
static Matter_Result_T live_chain_verify(void* user,Matter_Der_T leaf,Matter_Der_T intermediate,
    Matter_Der_T root,const Matter_Cert_Time_Policy_T* policy,uint8_t* public_key,bool operational) {
    if(!user || !policy || !public_key) return MATTER_INVALID_ARGUMENT;
    Host_Credentials_T* h=user;
    Matter_Cert_Time_Policy_T current=*policy;
    if(current.mode==MATTER_CERT_TIME_SUPPLIED && h->chip_validity) {
        current.mode=MATTER_CERT_TIME_IGNORE_VALIDITY;
    } else if(current.mode==MATTER_CERT_TIME_SUPPLIED) {
        if(h->utc(h->user,&current.now)!=MATTER_OK) { erase(public_key,65); return MATTER_OFFLINE; }
    }
    return (operational && h->base.operational_verify_chain ? h->base.operational_verify_chain : h->base.cert_verify_chain)
        (h->base.user,leaf,intermediate,root,&current,public_key);
}
static Matter_Result_T live_cert_verify(void* user,Matter_Der_T leaf,Matter_Der_T intermediate,
    Matter_Der_T root,const Matter_Cert_Time_Policy_T* policy,uint8_t* public_key) {
    return live_chain_verify(user,leaf,intermediate,root,policy,public_key,false);
}
static Matter_Result_T live_operational_verify(void* user,Matter_Der_T leaf,Matter_Der_T intermediate,
    Matter_Der_T root,const Matter_Cert_Time_Policy_T* policy,uint8_t* public_key) {
    return live_chain_verify(user,leaf,intermediate,root,policy,public_key,true);
}
static Matter_Result_T load(void* u,Matter_Root_Config_T* c) { *c=((Matter_Runtime_T)u)->identity; return MATTER_OK; }
static Matter_Result_T store(void* u,const Matter_Root_Settings_T* settings) { return matter_store_host_root(((Matter_Runtime_T)u)->store,settings); }
static bool contains(void* u,uint16_t ep,uint32_t type) {
    return matter_root_has_device_type(((Matter_Runtime_T)u)->root,ep,type);
}
static uint8_t authorize(void* u,Matter_Exchange_Session_T token,const Matter_Im_Path_T* path,Matter_Im_Privilege_T privilege) {
    Matter_Runtime_T s=u; Matter_Secure_T secure=matter_dispatch_session(s->dispatch,token); if(!secure) return MATTER_IM_UNSUPPORTED_ACCESS;
    Matter_Secure_Identity_T id;
    /* A completed PASE was admitted by the window. Expiry prevents NEW attempts;
     * explicit revoke/Complete/rollback gates its incarnation in the dispatcher. */
    if(matter_secure_identity(secure,&id)!=MATTER_OK) return MATTER_IM_SUCCESS;
    Matter_Acl_Device_Port_T devices={s,contains};
    return matter_acl_authorize(s->acl,id.fabric_index,id.peer_node_id,id.cats,id.cat_count,path,privilege,&devices)?MATTER_IM_SUCCESS:MATTER_IM_UNSUPPORTED_ACCESS;
}
static Matter_Result_T challenge(void* u,Matter_Exchange_Session_T token,uint8_t out[16]) {
    Matter_Runtime_T s=u; Matter_Secure_T secure=matter_dispatch_session(s->dispatch,token);
    return secure?matter_secure_challenge(secure,out):MATTER_INVALID_STATE;
}
static Matter_Result_T timestamp(void* u,uint32_t* out) {
    Matter_Runtime_T s=u; return s->platform.timestamp(s->platform.user,out);
}
static Matter_Result_T retire(void* u,bool success) {
    Matter_Runtime_T s=u;
    /* Core 11.10.7.2.2 retires sessions on rollback, not the independent
     * commissioning window. Keep its original deadline and PAKE credentials;
     * explicit Revoke, expiry and shutdown already close their own window. */
    if(success) {
        s->window=false; s->enhanced=false;
        if(s->admin) (void)matter_admin_commissioning_close(s->admin);
    }
    Matter_Result_T r=matter_dispatch_retire(s->dispatch,false);
    if(!success && matter_dispatch_retire_fabric(s->dispatch,matter_opcreds_pending_fabric(s->opcreds))!=MATTER_OK) r=MATTER_PENDING;
    return r;
}
static Matter_Result_T begin(void* u) { return matter_commissioning_host_begin(((Matter_Runtime_T)u)->commission); }
static Matter_Result_T cleanup(void* u) { return matter_commissioning_host_cleanup(((Matter_Runtime_T)u)->commission); }
static Matter_Result_T window_open(void* u,bool* open) {
    Matter_Runtime_T s=u; *open=(s->window || s->enhanced) && !s->stopping; return MATTER_OK;
}
static Matter_Result_T complete(void* u,uint8_t fabric) { return matter_commissioning_host_complete(((Matter_Runtime_T)u)->commission,fabric); }
static Matter_Result_T regulatory(void* u,const Matter_Root_Settings_T* settings,uint8_t candidate,bool* supported) {
    Matter_Runtime_T s=u; *supported=false;
    Matter_Result_T r=s->platform.regulatory(s->platform.user,settings,candidate,supported);
    if(r==MATTER_OK && *supported) r=store(u,settings);
    return r;
}
static Matter_Pase_T pase(void* u,uint16_t id,uint64_t now) {
    Matter_Runtime_T s=u; if(s->stopping || s->recovering) return NULL;
    Matter_Root_Fail_Safe_State_T state;
    if(matter_root_fail_safe_state(s->root,&state)!=MATTER_OK || state==MATTER_ROOT_FAIL_SAFE_CLEANUP) return NULL;
    if(s->enhanced) return matter_admin_commissioning_pase_new(s->admin,id,30000,now);
    if(!s->window || now>=s->deadline) return NULL;
    s->pase.local_session_id=id; return matter_pase_new(&s->crypto,&s->pase,now);
}
static Matter_Result_T admin_vendor(void* u,uint8_t index,uint16_t* vendor) {
    const Matter_Fabric_View_T* view=matter_runtime_fabrics(u);
    for(unsigned i=0;i<5;++i) if(view->records[i].index==index) { *vendor=view->records[i].vendor; return MATTER_OK; }
    return MATTER_INVALID_STATE;
}
static Matter_Result_T admin_blocked(void* u,bool* blocked) {
    Matter_Runtime_T s=u; Matter_Root_Fail_Safe_State_T state;
    Matter_Result_T r=matter_root_fail_safe_state(s->root,&state);
    if(r==MATTER_OK) *blocked=s->window || s->stopping || state!=MATTER_ROOT_FAIL_SAFE_IDLE;
    return r;
}
static Matter_Result_T admin_advertise(void* u,bool open,uint16_t discriminator) {
    Matter_Runtime_T s=u; s->enhanced=open; s->enhanced_discriminator=discriminator; return MATTER_OK;
}
static Matter_Result_T admin_revoke(void* u) {
    Matter_Runtime_T s=u; s->enhanced=false;
    Matter_Result_T r=matter_dispatch_retire(s->dispatch,false);
    Matter_Root_Fail_Safe_State_T state; (void)matter_root_fail_safe_state(s->root,&state);
    if(state!=MATTER_ROOT_FAIL_SAFE_IDLE) { (void)matter_root_expire(s->root); return MATTER_PENDING; }
    return r;
}
static void fabric_removed(void* u,uint8_t index) {
    Matter_Runtime_T s=u;
    /* Core 11.19.7.2/3: retain window, PAKE credentials and opening VendorID;
     * only the reference to the removed fabric becomes null. */
    (void)matter_admin_commissioning_fabric_removed(s->admin,index);
    matter_dispatch_changed(s->dispatch);
}
Matter_Root_T matter_runtime_root(Matter_Runtime_T s) { return s?s->root:NULL; }
bool matter_runtime_commissionable(Matter_Runtime_T s) { return s && (s->window || s->enhanced) && !s->stopping; }
uint8_t matter_runtime_commissioning_mode(Matter_Runtime_T s,uint16_t* discriminator) {
    if(!matter_runtime_commissionable(s)) return 0;
    if(s->enhanced) { if(discriminator) *discriminator=s->enhanced_discriminator; return 2; }
    return 1;
}
const Matter_Fabric_View_T* matter_runtime_fabrics(Matter_Runtime_T s) { return s && s->fabric_host?s->fabric_port.view(s->fabric_port.user):NULL; }
bool matter_runtime_reset_requested(Matter_Runtime_T s) { return s && s->reset; }
bool matter_runtime_reset_ready(Matter_Runtime_T s) { return s && s->reset && !matter_dispatch_removal_pending(s->dispatch); }
static uint64_t credential_revision(void* u,uint8_t index,Matter_Exchange_Session_T* session) {
    return matter_fabric_host_credential_revision(((Matter_Runtime_T)u)->fabric_host,index,session);
}
static bool fabric_live(void* u,uint8_t index) {
    if(!index) return !matter_fabric_host_reset_requested(((Matter_Runtime_T)u)->fabric_host);
    const Matter_Fabric_View_T* v=matter_runtime_fabrics(u);
    for(unsigned i=0;i<5;++i) if(v->records[i].index==index) return true;
    return false;
}
Matter_Runtime_T matter_runtime_new(const Matter_Runtime_Config_T* c,uint32_t pin,uint64_t now) {
    if(!c || !c->identity || !pin || pin>99999998 || pin==12345678 || pin==87654321 || pin%11111111==0 ||
        !c->utc || !c->timestamp || !c->regulatory || !c->storage.read || !c->storage.replace ||
        !c->wifi.initialize || !c->wifi.process || !c->wifi.observe || !c->wifi.control.load ||
        !c->wifi.control.configure || !c->wifi.control.start || !c->wifi.control.cancel || !c->wifi.control.restore ||
        !c->crypto.random || !c->crypto.sha256 || !c->crypto.hmac_sha256 || !c->crypto.hkdf_sha256 ||
        !c->crypto.pbkdf2_sha256 || !c->crypto.p256_reduce || !c->crypto.p256_base || !c->crypto.p256_scalar ||
        !c->crypto.spake_share || !c->crypto.spake_secrets || !c->crypto.equal || !c->crypto.clear ||
        !c->crypto.ccm_encrypt || !c->crypto.ccm_decrypt || !c->crypto.ecdsa_sign || !c->crypto.ecdsa_verify ||
        !c->crypto.ecdh || !c->crypto.pake_verifier || !c->credentials.csr_create || !c->credentials.csr_verify ||
        !c->credentials.cert_verify_chain) return NULL;
    Matter_Runtime_T s=calloc(1,sizeof(*s)); if(!s) return NULL;
    s->platform=*c; s->platform.identity=NULL; s->platform.attestation.dac_private=NULL;
    const Matter_Root_Config_T* identity=c->identity;
    s->identity=*identity; s->now=now; s->crypto=c->crypto; s->update=c->update;
    s->credential_adapter=(Host_Credentials_T){.base=c->credentials,.user=c->user,.utc=c->utc};
    s->credentials=(Matter_Credentials_Port_T){.user=&s->credential_adapter,.csr_create=host_csr_create,
        .csr_verify=host_csr_verify,.cert_verify_chain=live_cert_verify,.operational_verify_chain=live_operational_verify};
    s->attestation=c->attestation; s->attestation.user=s; s->attestation.challenge=challenge; s->attestation.timestamp=timestamp;
    s->attestation.vendor_id=identity->vendor_id; s->attestation.product_id=identity->product_id;
    s->attestation.identity.data_version=identity->basic_version;
    s->keys=matter_opcreds_host_new(&s->attestation,&s->crypto,&s->credentials); s->attestation.dac_private=NULL;
    if(!s->keys) goto fail;
    Matter_Opcreds_Port_T op=matter_opcreds_host_port(s->keys); s->opcreds=matter_opcreds_new(&s->attestation.identity,&op); if(!s->opcreds) goto fail;
    /* Snapshot is too large for embedded task stacks. No retained temporary spans. */
    Matter_Store_Wifi_T* initial=calloc(1,sizeof(*initial)); if(!initial) goto fail;
    Matter_Result_T r=c->wifi.control.load(c->wifi.control.user,&initial->settings,&initial->connected);
    if(r==MATTER_OK) s->commission_image=matter_commissioning_host_image_new(&initial->settings,&initial->connected);
    erase(initial,sizeof(*initial)); free(initial);
    s->fabric_image=matter_fabric_host_image_new();
    if(!s->fabric_image || !s->commission_image) goto fail;
    s->store=matter_store_host_new(&c->storage,s->fabric_image,s->commission_image,&s->identity.settings,&s->diagnostics_image,true);
    if(!s->store) goto fail;
    if(c->wifi.initialize(c->wifi.control.user,matter_commissioning_host_settings(s->commission_image),
        matter_commissioning_host_connected(s->commission_image))!=MATTER_OK) goto fail;
    s->wifi=matter_wifi_new(&c->wifi_config,&c->wifi.control,now); if(!s->wifi) goto fail;
    s->time.mode=MATTER_CERT_TIME_SUPPLIED;
    if(c->utc(c->user,&s->time.now)!=MATTER_OK) goto fail;
    s->fabric_host=matter_fabric_host_new(s->fabric_image,s->keys,&s->crypto,&s->credentials,&s->time); if(!s->fabric_host) goto fail;
    s->fabric_port=matter_fabric_host_port(s->fabric_host); s->fabrics=matter_fabric_new(&s->fabric_port);
    if(!s->fabrics || matter_opcreds_attach_fabrics(s->opcreds,s->fabrics)!=MATTER_OK) goto fail;
    Matter_Acl_Port_T ap=matter_fabric_host_acl_port(s->fabric_host); s->acl=matter_acl_new(&ap);
    Matter_Groupkey_Port_T gp=matter_fabric_host_groupkey_port(s->fabric_host); s->groupkey=matter_groupkey_new(&gp);
    Matter_Diagnostics_Radio_Port_T radio={c->wifi.control.user,c->wifi.observe};
    s->diagnostics_host=matter_diagnostics_host_new_port(&s->diagnostics_image,&radio,&c->iface,c->boot_reason,c->reboot,now);
    if(!s->diagnostics_host) goto fail;
    Matter_Diagnostics_Port_T dp=matter_diagnostics_host_port(s->diagnostics_host); s->diagnostics=matter_diagnostics_new(&dp,identity->basic_version,identity->descriptor_version);
    Matter_Commissioning_Host_Port_T cp={s,retire};
    s->commission=matter_commissioning_host_new_port(s->commission_image,s->wifi,&c->wifi.control,s->opcreds,s->fabric_host,&cp); if(!s->commission) goto fail;
    s->recovering=matter_commissioning_host_pending(s->commission_image);
    Matter_Root_Port_T rp={s,load,authorize,store}; Matter_Root_Commissioning_Port_T gc={s,begin,cleanup,regulatory,window_open};
    Matter_Root_Commissioning_Config_T rc={60,900,0,2,true,false,identity->descriptor_version};
    s->root=matter_root_new_commissioning(&rp,&rc,&gc,now);
    Matter_Root_Complete_Port_T done={s,complete};
    if(!s->root || !s->acl || !s->groupkey || !s->diagnostics || matter_root_attach_wifi(s->root,s->wifi)!=MATTER_OK ||
        matter_root_attach_opcreds(s->root,s->opcreds)!=MATTER_OK || matter_root_attach_acl(s->root,s->acl)!=MATTER_OK ||
        matter_root_attach_groupkey(s->root,s->groupkey)!=MATTER_OK || matter_root_attach_diagnostics(s->root,s->diagnostics)!=MATTER_OK || matter_root_attach_complete(s->root,&done)!=MATTER_OK) goto fail;
    Matter_Admin_Commissioning_Port_T admin={s,admin_vendor,admin_blocked,admin_advertise,admin_revoke};
    s->admin=matter_admin_commissioning_new(&admin,&s->crypto,identity->basic_version,now);
    if(!s->admin || matter_root_attach_cluster(s->root,s->admin)!=MATTER_OK) goto fail;
    s->pase=(Matter_Pase_Config_T){.responder=true,.iterations=1000,.salt_size=16,.timeout_ms=30000};
    /* Secret temporary derivation workspace is heap-owned and erased on all paths. */
    uint8_t* tmp=calloc(1,116); if(!tmp) goto fail;
    for(unsigned i=0;i<4;++i) tmp[i]=(uint8_t)(pin>>(i*8));
    bool valid=s->crypto.random(s->crypto.user,s->pase.salt,16)==MATTER_OK &&
        s->crypto.pbkdf2_sha256(s->crypto.user,tmp,4,s->pase.salt,16,1000,tmp+4,80)==MATTER_OK &&
        s->crypto.p256_reduce(s->crypto.user,tmp+4,40,s->pase.w0)==MATTER_OK &&
        s->crypto.p256_reduce(s->crypto.user,tmp+44,40,tmp+84)==MATTER_OK && s->crypto.p256_base(s->crypto.user,tmp+84,32,s->pase.L)==MATTER_OK;
    erase(tmp,116); free(tmp); if(!valid) goto fail;
    s->window=s->fabric_port.view(s->fabric_port.user)->count==0; s->deadline=UINT64_MAX-now<900000?UINT64_MAX:now+900000;
    return s;
fail:
    /* No asynchronous work was submitted by new; preserve a recovery marker. */
    s->recovering=false;
    (void)matter_runtime_stop(s,now); (void)matter_runtime_delete(s); return NULL;
}
Matter_Result_T matter_runtime_set_resumption(Matter_Runtime_T s,Matter_Case_Resumption_Profile_T profile) {
    if(!s || (profile!=MATTER_CASE_RESUMPTION_SPEC && profile!=MATTER_CASE_RESUMPTION_CHIP)) return MATTER_INVALID_ARGUMENT;
    if(s->dispatch || s->stopping) return MATTER_INVALID_STATE;
    s->resumption_profile=profile; return MATTER_OK;
}
Matter_Result_T matter_runtime_set_certificate_validity(Matter_Runtime_T s,bool chip) {
    if(!s) return MATTER_INVALID_ARGUMENT;
    if(s->dispatch || s->stopping) return MATTER_INVALID_STATE;
    s->credential_adapter.chip_validity=chip; return MATTER_OK;
}
Matter_Result_T matter_runtime_set_test_trigger(Matter_Runtime_T s,const Matter_Diagnostics_Test_Trigger_T* p) {
    if(!s) return MATTER_INVALID_ARGUMENT;
    if(s->dispatch || s->stopping) return MATTER_INVALID_STATE;
    return matter_diagnostics_set_test_trigger(s->diagnostics,p);
}
Matter_Result_T matter_runtime_set_resolver(Matter_Runtime_T s,const Matter_Resolver_Port_T* p) {
    if(!s || !p || !p->start || !p->take || !p->cancel) return MATTER_INVALID_ARGUMENT;
    if(s->dispatch || s->stopping) return MATTER_INVALID_STATE;
    s->resolver=*p; return MATTER_OK;
}
static Matter_Result_T compressed_fabric(void* u,uint8_t index,uint8_t out[8]) {
    Matter_Runtime_T s=u; const Matter_Fabric_View_T* v=s->fabric_port.view(s->fabric_port.user);
    if(index) for(unsigned i=0;i<MATTER_FABRIC_CAPACITY;++i) if(v->records[i].index==index) {
        memcpy(out,v->records[i].compressed_id,8); return MATTER_OK;
    }
    return MATTER_INVALID_STATE;
}
static uint64_t event_clock(void* u) { return ((Matter_Runtime_T)u)->now; }
static Matter_Result_T event_admin(void* u,Matter_Exchange_Session_T token,Matter_Cluster_Request_T* q) {
    Matter_Runtime_T s=u; Matter_Secure_T secure=matter_dispatch_session(s->dispatch,token);
    if(!secure) return MATTER_INVALID_STATE;
    Matter_Secure_Identity_T id; *q=(Matter_Cluster_Request_T){.session=token};
    if(matter_secure_identity(secure,&id)==MATTER_OK) { q->is_case=true; q->peer_node=id.peer_node_id; }
    return MATTER_OK;
}
static Matter_Result_T ota_load(void* u,Matter_Ota_Provider_T out[MATTER_OTA_PROVIDERS]) { return matter_store_host_ota_load(((Matter_Runtime_T)u)->store,out); }
static Matter_Result_T ota_store(void* u,uint8_t fabric,const Matter_Ota_Provider_T* p) { return matter_store_host_ota_store(((Matter_Runtime_T)u)->store,fabric,p); }
static uint64_t ota_generation(void* u,uint8_t fabric) {
    if(!fabric || !fabric_live(u,fabric)) return 0;
    Matter_Exchange_Session_T ignored; uint64_t revision=credential_revision(u,fabric,&ignored);
    /* A restored live fabric starts at revision zero. OTA reserves zero for
     * absence; offset without wrap, fail closed at exhausted revision space. */
    return revision==UINT64_MAX?0:revision+1;
}
static bool ota_select(void* u,const Matter_Ota_Offer_T* offer) {
    Matter_Runtime_T s=u; if(s->stopping || s->reset || s->ota_reboot || s->notify || matter_ota_update_pending(s->update) || s->download || matter_ota_apply_busy(s->apply)) return false;
    runtime_log(s,"OTA_SELECTED fabric=%u node=%llu endpoint=%u source=%s reason=%u\n",(unsigned)offer->provider.fabric,
        (unsigned long long)offer->provider.node,(unsigned)offer->provider.endpoint,offer->announced?"announcement":"default",(unsigned)offer->reason);
     return s->query && matter_ota_query_offer(s->query,offer,s->now);
}
static Matter_Result_T query_random(void* u,uint32_t* out) {
    Matter_Runtime_T s=u; return s->crypto.random(s->crypto.user,(uint8_t*)out,sizeof(*out));
}
static Matter_Result_T query_start(void* u,const Matter_Ota_Provider_T* p,const uint8_t* d,size_t n,uint64_t* id) {
    Matter_Runtime_T s=u; Matter_Im_Command_Path_T path={p->endpoint,0x29,0};
    Matter_Result_T r=matter_dispatch_invoke(s->dispatch,p->fabric,p->node,&path,1,d,n,id);
    if(r==MATTER_PENDING) { runtime_log(s,"OTA_QUERY fabric=%u node=%llu endpoint=%u\n",p->fabric,(unsigned long long)p->node,p->endpoint);  }
    return r;
}
static Matter_Result_T query_take(void* u,uint64_t id,uint8_t* status,const uint8_t** d,size_t* n) {
    return matter_dispatch_invoke_take(((Matter_Runtime_T)u)->dispatch,id,status,d,n);
}
static void query_cancel(void* u,uint64_t id) { matter_dispatch_invoke_cancel(((Matter_Runtime_T)u)->dispatch,id); }
static Matter_Result_T query_state(void* u,uint8_t state,uint8_t reason,uint64_t now) {
    Matter_Runtime_T s=u; Matter_Result_T r=matter_ota_requestor_state(s->ota,s->update!=NULL,state,-1,reason,0,now);
    if(r==MATTER_OK) { matter_dispatch_changed(s->dispatch); runtime_log(s,"OTA_STATE state=%u reason=%u\n",state,reason);  }
    return r;
}
static Matter_Result_T apply_start(void* u,const Matter_Ota_Provider_T* p,const uint8_t* d,size_t n,uint64_t* id) {
    Matter_Runtime_T s=u; Matter_Im_Command_Path_T path={p->endpoint,0x29,2};
    Matter_Result_T r=matter_dispatch_invoke(s->dispatch,p->fabric,p->node,&path,3,d,n,id);
    if(r==MATTER_PENDING) { runtime_log(s,"OTA_APPLY_REQUEST\n");  } return r;
}
static Matter_Result_T apply_state(void* u,uint8_t state,uint8_t reason,uint32_t version,uint64_t now) {
    Matter_Runtime_T s=u; Matter_Result_T r=matter_ota_requestor_state(s->ota,s->update!=NULL,state,-1,reason,version,now);
    if(r==MATTER_OK) { matter_dispatch_changed(s->dispatch); runtime_log(s,"OTA_APPLY_STATE state=%u reason=%u\n",state,reason);  } return r;
}
static bool ota_fingerprint(Matter_Runtime_T s,uint8_t fabric,uint8_t out[32]) {
    const Matter_Fabric_View_T* view=matter_runtime_fabrics(s);
    if(view) for(unsigned i=0;i<5;++i) if(view->records[i].index==fabric)
        return s->crypto.sha256(s->crypto.user,view->records[i].noc,view->records[i].noc_size,out)==MATTER_OK;
    return false;
}
static Matter_Result_T apply_ready(void* u,const Matter_Ota_Apply_Context_T* c) {
    Matter_Runtime_T s=u;
    if(s->update) {
        uint8_t fingerprint[32];
        Matter_Result_T r=s->ota_port.signed_image(s->ota_port.user,c->artifact,&s->proof);
        bool integrity=r==MATTER_OK;
        if(r==MATTER_OK) r=matter_ota_update_verify(s->update,c->version,&s->proof);
        bool authenticated=r==MATTER_OK;
        if(r==MATTER_OK && !ota_fingerprint(s,c->provider.fabric,fingerprint)) r=MATTER_INVALID_STATE;
        if(r==MATTER_OK) r=matter_ota_update_accept(s->update,c,fingerprint,&s->proof);
        if(r==MATTER_OK) s->ota_reboot=true;
        runtime_log(s,"OTA_APPLY_GATE provider=1 integrity=%u authenticated=%u installed=%u version=%lu simulation=1\n",
            integrity?1u:0u,authenticated?1u:0u,r==MATTER_OK?1u:0u,(unsigned long)c->version);
         return r;
    }
    Matter_Result_T r=s->ota_port.check(s->ota_port.user,c->artifact);
    /* This host port deliberately has no signature verifier/installer. A real
     * application must authenticate and consume the SAME artifact itself. */
    runtime_log(s,"OTA_APPLY_GATE provider=1 integrity=%u authenticated=0 installed=0 version=%lu\n",r==MATTER_OK?1u:0u,(unsigned long)c->version);
     return MATTER_INVALID_STATE;
}
static void apply_done(void* u,const Matter_Ota_Apply_Context_T* c,Matter_Ota_Apply_Result_T result) {
    Matter_Runtime_T s=u; s->ota_port.invalidate(s->ota_port.user);
    runtime_log(s,"OTA_APPLY_DONE result=%u\n",(unsigned)result);
    /* Error recovery returns to QueryImage, preserving its global rate floor.
     * Rejected unsigned host fixtures/discontinued images use normal polling. */
    if(result==MATTER_OTA_APPLY_ERROR && !s->stopping && !s->reset) {
        Matter_Ota_Offer_T offer={.provider=c->provider}; (void)matter_ota_query_offer(s->query,&offer,s->now);
    }
}
static void query_available(void* u,const Matter_Ota_Provider_T* p,const Matter_Ota_Image_T* image) {
    Matter_Runtime_T s=u;
    if(!s->has_ota || s->download || matter_ota_apply_busy(s->apply) || image->consent_needed || s->stopping || s->reset) return;
    s->download_version=image->version;
    s->candidate=(Matter_Ota_Apply_Context_T){.provider=*p,.generation=ota_generation(s,p->fabric),.version=image->version,.token_size=image->token_size};
    memcpy(s->candidate.token,image->token,image->token_size);
    Matter_Bdx_Sink_T sink=s->ota_port.sink;
    const uint8_t* fd=(const uint8_t*)image->uri+23; /* Validated bdx URI; no unescaping/path processing. */
    Matter_Result_T r=s->ota_port.prepare(s->ota_port.user,image->version);
    if(r==MATTER_OK) r=matter_dispatch_bdx(s->dispatch,p->fabric,p->node,fd,strlen((const char*)fd),&sink,s->ota_port.limit,&s->download);
    if(r==MATTER_PENDING) {
        (void)matter_ota_requestor_state(s->ota,s->update!=NULL,4,0,1,image->version,s->now); matter_dispatch_changed(s->dispatch);
        runtime_log(s,"OTA_DOWNLOAD version=%lu\n",(unsigned long)image->version);
    } else { s->download=0; erase(&s->candidate,sizeof(s->candidate)); s->ota_port.cancel(s->ota_port.user); runtime_log(s,"OTA_DOWNLOAD_FAILED start=%d\n",r); }
}
static void download_process(Matter_Runtime_T s) {
    if(!s->download) return;
    if(s->stopping || s->reset) matter_dispatch_invoke_cancel(s->dispatch,s->download);
    uint64_t bytes=0; Matter_Result_T r=matter_dispatch_bdx_take(s->dispatch,s->download,&bytes);
    if(r==MATTER_PENDING) return;
    s->download=0;
    if(r==MATTER_OK && !s->stopping && !s->reset && s->candidate.generation &&
        ota_generation(s,s->candidate.provider.fabric)==s->candidate.generation) r=s->ota_port.commit(s->ota_port.user);
    else r=MATTER_PORT_ERROR;
    if(r==MATTER_OK && s->update) {
        r=s->ota_port.signed_image(s->ota_port.user,s->ota_port.artifact(s->ota_port.user),&s->proof);
        if(r==MATTER_OK) r=matter_ota_update_verify(s->update,s->candidate.version,&s->proof);
        runtime_log(s,"OTA_AUTH accepted=%u\n",r==MATTER_OK?1u:0u);
    }
    if(r!=MATTER_OK) {
        s->ota_port.cancel(s->ota_port.user);
        (void)matter_ota_requestor_error(s->ota,s->download_version,bytes,-1,NULL,s->now);
    }
    (void)matter_ota_requestor_state(s->ota,s->update!=NULL,1,-1,r==MATTER_OK?1:2,0,s->now);
    matter_dispatch_changed(s->dispatch);
    runtime_log(s,"OTA_DOWNLOAD_%s bytes=%llu version=%lu\n",r==MATTER_OK?"SAVED":"FAILED",(unsigned long long)bytes,(unsigned long)s->download_version);
    if(r==MATTER_OK) {
        s->candidate.artifact=s->ota_port.artifact(s->ota_port.user);
        if(matter_ota_apply_begin(s->apply,&s->candidate,s->now)!=MATTER_OK) s->ota_port.invalidate(s->ota_port.user);
    }
    erase(&s->candidate,sizeof(s->candidate));
}
Matter_Result_T matter_runtime_set_ota(Matter_Runtime_T s,const Matter_Runtime_Ota_Port_T* p) {
    if(!s || !p || !p->limit || !p->sink.open || !p->sink.write || !p->sink.finish || !p->sink.cancel ||
        !p->prepare || !p->commit || !p->artifact || !p->check || !p->invalidate || !p->cancel ||
        (s->update && !p->signed_image)) return MATTER_INVALID_ARGUMENT;
    if(s->dispatch || s->stopping || s->has_ota) return MATTER_INVALID_STATE;
    s->ota_port=*p; s->has_ota=true; return MATTER_OK;
}
bool matter_runtime_ota_reboot_requested(Matter_Runtime_T s) { return s && s->ota_reboot; }
bool matter_runtime_ota_trial(Matter_Runtime_T s) { return s && matter_ota_update_trial(s->update); }
Matter_Result_T matter_runtime_ota_boot_ready(Matter_Runtime_T s) {
    if(!s || !s->update) return MATTER_OK;
    if(!s->dispatch || !s->ota) return MATTER_INVALID_STATE;
    bool trial=matter_ota_update_trial(s->update);
    /* A confirmed journal may survive a crash before event publication/Notify.
     * Re-emit on that boot until the durable notification claim clears it. */
    if((trial || matter_ota_update_booted(s->update) || matter_ota_update_pending(s->update)) && !s->applied_event) {
        Matter_Result_T r=matter_ota_requestor_applied(s->ota,s->identity.software_version,s->identity.product_id,event_clock(s));
        if(r!=MATTER_OK) return r;
        s->applied_event=true;
    }
    if(trial) {
        Matter_Result_T r=matter_ota_update_confirm(s->update); if(r!=MATTER_OK) return r;
        runtime_log(s,"OTA_SIM_CONFIRMED\n");
    }
    return MATTER_OK;
}
static void notify_process(Matter_Runtime_T s) {
    if(s->notify) {
        if(s->stopping || s->reset) matter_dispatch_invoke_cancel(s->dispatch,s->notify);
        uint8_t status=0; const uint8_t* body=NULL; size_t size=0;
        Matter_Result_T r=matter_dispatch_invoke_take(s->dispatch,s->notify,&status,&body,&size);
        if(r==MATTER_PENDING) return;
        s->notify=0; erase(s->notify_args,sizeof(s->notify_args));
        runtime_log(s,"OTA_NOTIFY_DONE success=%u\n",r==MATTER_OK && !status && !size?1u:0u);
    }
    const Matter_Ota_Apply_Context_T* pending=matter_ota_update_pending(s->update);
    if(!pending || s->stopping || s->reset || s->ota_reboot) return;
    uint8_t fingerprint[32]={0}; bool live=ota_fingerprint(s,pending->provider.fabric,fingerprint);
    Matter_Ota_Apply_Context_T context;
    Matter_Result_T r=matter_ota_update_claim(s->update,fingerprint,live,&context);
    if(r!=MATTER_OK) { if(r==MATTER_OFFLINE) runtime_log(s,"OTA_NOTIFY_ORPHAN\n"); return; }
    /* At-most-once application attempt, persisted before dispatch; MRP retries
     * belong to this exchange only. Crash before start may lose notification. */
    uint8_t* p=s->notify_args; *p++=0x15; *p++=0x30; *p++=0; *p++=(uint8_t)context.token_size;
    memcpy(p,context.token,context.token_size); p+=context.token_size; *p++=0x26; *p++=1;
    for(unsigned i=0;i<4;++i) *p++=(uint8_t)(context.version>>(8*i));
    *p++=0x18;
    Matter_Im_Command_Path_T path={context.provider.endpoint,0x29,4};
    r=matter_dispatch_invoke(s->dispatch,context.provider.fabric,context.provider.node,&path,MATTER_IM_CLIENT_STATUS_ONLY,
        s->notify_args,(size_t)(p-s->notify_args),&s->notify);
    if(r!=MATTER_PENDING) { s->notify=0; erase(s->notify_args,sizeof(s->notify_args)); }
    erase(&context,sizeof(context)); runtime_log(s,"OTA_NOTIFY_ATTEMPT started=%u\n",r==MATTER_PENDING?1u:0u);
}
Matter_Result_T matter_runtime_set_outbound(Matter_Runtime_T s,const Matter_Udp_Path_T* path) {
    if(!s || !path || s->dispatch || !path->local.port || !path->interface_id) return MATTER_INVALID_ARGUMENT;
    s->outbound=*path; return MATTER_OK;
}
Matter_Result_T matter_runtime_start(Matter_Runtime_T s,Matter_T owner,Matter_Udp_T udp,Matter_Events_T events) {
    if(!s || s->stopping || s->dispatch || s->ota) return MATTER_INVALID_STATE;
    Matter_Ota_Requestor_Port_T ota={s,ota_load,ota_store,ota_generation,ota_select};
    s->ota=matter_ota_requestor_new(&ota,events,s->identity.basic_version,s->update!=NULL);
    if(!s->ota || matter_root_attach_cluster(s->root,s->ota)!=MATTER_OK) return MATTER_PORT_ERROR;
    Matter_Acl_Events_Port_T ep={events,s,event_clock};
    Matter_Fabric_Host_Events_T fp={s->acl,events,s,event_admin,fabric_removed};
    if(matter_root_startup(s->root,events,event_clock(s))!=MATTER_OK ||
        matter_diagnostics_boot(s->diagnostics,events,event_clock(s))!=MATTER_OK ||
        matter_acl_bind_events(s->acl,&ep)!=MATTER_OK || matter_fabric_host_bind_events(s->fabric_host,&fp)!=MATTER_OK) return MATTER_PORT_ERROR;
    if(matter_ota_update_rolled_back(s->update)) {
        if(matter_ota_requestor_state(s->ota,true,7,-1,2,s->identity.software_version,event_clock(s))!=MATTER_OK ||
            matter_ota_requestor_state(s->ota,true,1,-1,1,0,event_clock(s))!=MATTER_OK) return MATTER_PORT_ERROR;
    }
    Matter_Dispatch_Config_T cfg={.root=s->root,.events=events,.crypto=s->crypto,.credentials=s->credentials,
        .fabrics=matter_fabric_host_case_port(s->fabric_host),.time=s->time,.user=s,.pase=pase,.fabric_live=fabric_live,.credential_revision=credential_revision,
        .resolver=s->resolver,.compressed_fabric=compressed_fabric,.resumption_profile=s->resumption_profile,.outbound=s->outbound};
    s->dispatch=matter_dispatch_new(owner,udp,&cfg); if(!s->dispatch) return MATTER_PORT_ERROR;
    /* Advertise BDX only when an explicit file sink was configured. */
    Matter_Ota_Query_Config_T qc={.vendor=s->identity.vendor_id,.product=s->identity.product_id,
        .hardware=s->identity.hardware_version,.version=s->identity.software_version,.protocols={0},.protocol_count=s->has_ota?1:0};
    Matter_Ota_Query_Port_T qp={s,ota_generation,query_random,query_start,query_take,query_cancel,query_state,query_available};
    s->query=matter_ota_query_new(&qc,&qp,s->now);
    Matter_Ota_Apply_Port_T ap={s,ota_generation,apply_start,query_take,query_cancel,apply_state,apply_ready,apply_done};
    if(s->has_ota) s->apply=matter_ota_apply_new(&ap,s->now);
    if(!s->query || (s->has_ota && !s->apply) || matter_root_add_client(s->root,0,0x29)!=MATTER_OK) return MATTER_PORT_ERROR;
    /* Device Library 2.3: the exposed Requestor server and Provider client
     * belong to OTA Requestor even when updates are currently unavailable. */
    return matter_root_add_device_type(s->root,0x12,1);
}
void matter_runtime_received(Matter_Runtime_T s,const Matter_Udp_Datagram_T* d) { if(s) matter_dispatch_received(s->dispatch,d); }
void matter_runtime_sent(Matter_Runtime_T s,uint64_t id,Matter_Operation_Result_T result) { if(s) matter_dispatch_sent(s->dispatch,id,result); }
void matter_runtime_changed(Matter_Runtime_T s) { if(s) matter_dispatch_changed(s->dispatch); }
Matter_Result_T matter_runtime_process(Matter_Runtime_T s,uint64_t now) {
    if(!s) return MATTER_OK;
    if(now<s->now || s->stopped) return MATTER_INVALID_STATE;
    s->now=now;
    if(s->recovering) {
        Matter_Result_T recovery=matter_commissioning_host_cleanup(s->commission);
        if(recovery!=MATTER_OK) return recovery;
        s->recovering=false;
    }
    if(s->reset || s->stopping) (void)matter_ota_query_stop(s->query);
    download_process(s);
    if(s->reset || s->stopping) matter_ota_apply_cancel(s->apply);
    if(s->apply) (void)matter_ota_apply_process(s->apply,now);
    if(s->query && !s->ota_reboot && !s->notify && !matter_ota_update_pending(s->update) && !s->download && !matter_ota_apply_busy(s->apply)) (void)matter_ota_query_process(s->query,now);
    if(s->reset) {
        /* A real radio can need deferred cancellation completion after reset.
         * Keep its port alive while draining; do not republish old settings. */
        if(s->wifi) (void)s->platform.wifi.process(s->platform.wifi.control.user,s->wifi,now);
        notify_process(s); return matter_dispatch_process(s->dispatch,now);
    }
    if(s->window && now>=s->deadline) s->window=false;
    if(s->admin) (void)matter_cluster_process(s->admin,now);
    (void)matter_root_process(s->root,now);
    /* Keep the initial default-provider offer until boot notification finishes.
     * The cluster's false selection means ignore, not retry-later. */
    if(s->ota && !matter_ota_update_trial(s->update) && !s->notify && !matter_ota_update_pending(s->update)) {
        uint32_t before,after; (void)matter_cluster_version(s->ota,&before);
        Matter_Result_T ota=matter_cluster_process(s->ota,now); if(ota!=MATTER_OK) return ota;
        (void)matter_cluster_version(s->ota,&after); if(before!=after) matter_dispatch_changed(s->dispatch);
    }
    if(s->wifi) {
        Matter_Result_T radio=s->platform.wifi.process(s->platform.wifi.control.user,s->wifi,now);
        if(radio!=MATTER_OK && radio!=MATTER_PENDING) return radio;
    }
    (void)matter_diagnostics_host_process(s->diagnostics_host,now); (void)matter_diagnostics_refresh(s->diagnostics);
    Matter_Result_T r=matter_dispatch_process(s->dispatch,now);
    if(matter_fabric_host_reset_requested(s->fabric_host)) { s->reset=true; s->window=s->enhanced=false; s->stopping=true; }
    /* The first restored Notify also needs the dispatcher's current clock. */
    if(r==MATTER_OK || r==MATTER_PENDING) notify_process(s);
    return r;
}
Matter_Result_T matter_runtime_stop(Matter_Runtime_T s,uint64_t now) {
    if(!s) return MATTER_OK;
    if(now<s->now) return MATTER_INVALID_ARGUMENT;
    if(s->stopped) return MATTER_OK;
    if(s->recovering) {
        Matter_Result_T recovery=matter_commissioning_host_cleanup(s->commission);
        if(recovery!=MATTER_OK) return MATTER_PENDING;
        s->recovering=false;
    }
    s->stopping=true; s->window=false; s->enhanced=false; s->now=now;
    (void)matter_ota_query_stop(s->query);
    download_process(s);
    notify_process(s);
    matter_ota_apply_cancel(s->apply);
    if(s->apply) (void)matter_ota_apply_process(s->apply,now);
    if(s->query && !s->download && !matter_ota_apply_busy(s->apply)) (void)matter_ota_query_process(s->query,now);
    if(s->admin) { (void)matter_admin_commissioning_close(s->admin); (void)matter_cluster_process(s->admin,now); }
    if(s->root) { (void)matter_root_expire(s->root); (void)matter_root_process(s->root,now); }
    if(s->wifi && matter_wifi_stop(s->wifi)!=MATTER_OK) return MATTER_PENDING;
    if(s->dispatch && matter_dispatch_stop(s->dispatch)!=MATTER_OK) return MATTER_PENDING;
    if(s->download || s->notify || matter_ota_apply_busy(s->apply) || matter_ota_query_stop(s->query)!=MATTER_OK) return MATTER_PENDING;
    if(s->root) { Matter_Root_Fail_Safe_State_T state; if(matter_root_fail_safe_state(s->root,&state)==MATTER_OK && state!=MATTER_ROOT_FAIL_SAFE_IDLE) return MATTER_PENDING; }
    s->stopped=true; return MATTER_OK;
}
Matter_Result_T matter_runtime_delete(Matter_Runtime_T s) {
    if(!s) return MATTER_OK;
    if(!s->stopped || s->download || s->notify || matter_ota_apply_busy(s->apply) || matter_ota_query_stop(s->query)!=MATTER_OK || matter_dispatch_delete(s->dispatch)!=MATTER_OK) return MATTER_BUSY;
    s->dispatch=NULL;
    if(matter_ota_query_delete(s->query)!=MATTER_OK) return MATTER_BUSY;
    (void)matter_ota_apply_delete(s->apply); s->apply=NULL;
    s->query=NULL;
    if(s->root && matter_root_delete(s->root)!=MATTER_OK) return MATTER_BUSY;
    s->root=NULL;
    if(s->ota && matter_cluster_delete(s->ota)!=MATTER_OK) return MATTER_BUSY;
    s->ota=NULL;
    if(s->admin && matter_cluster_delete(s->admin)!=MATTER_OK) return MATTER_BUSY;
    if(s->commission) (void)matter_commissioning_host_delete(s->commission);
    (void)matter_cluster_delete(s->acl); (void)matter_cluster_delete(s->groupkey); (void)matter_diagnostics_delete(s->diagnostics);
    if(s->diagnostics_host) (void)matter_diagnostics_host_delete(s->diagnostics_host);
    if(s->wifi) { (void)matter_wifi_stop(s->wifi); (void)matter_wifi_delete(s->wifi); }
    if(s->opcreds) { (void)matter_opcreds_rollback(s->opcreds); (void)matter_opcreds_delete(s->opcreds); }
    if(s->fabrics) (void)matter_fabric_delete(s->fabrics);
    if(s->fabric_host) (void)matter_fabric_host_delete(s->fabric_host);
    if(s->keys) (void)matter_opcreds_host_delete(s->keys);
    if(s->store) (void)matter_store_host_delete(s->store);
    if(s->fabric_image) (void)matter_fabric_host_image_delete(s->fabric_image);
    if(s->commission_image) (void)matter_commissioning_host_image_delete(s->commission_image);
    erase(s,sizeof(*s)); free(s); return MATTER_OK;
}

Matter_Store_Host_T matter_runtime_store(Matter_Runtime_T s) { return s?s->store:NULL; }
