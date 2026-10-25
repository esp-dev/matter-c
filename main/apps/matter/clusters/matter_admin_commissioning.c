#include "matter_admin_commissioning.h"
#include "../matter_compat.h"
#include "../model/matter_cluster_internal.h"
#include "../codec/matter_tlv_validate.h"
#include <stdlib.h>
#include <string.h>
typedef struct {
    Matter_Admin_Commissioning_Port_T port; Matter_Crypto_Port_T crypto;
    Matter_Pase_Config_T credentials,candidate;
    uint8_t verifier[97]; uint16_t timeout,discriminator,vendor; uint8_t fabric;
    uint32_t version; uint64_t now,expiry;
    bool open,unpublish,revoking,busy; unsigned waiters;
    Matter_Result_T revoke_error;
    Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T e;
    Matter_Tlv_Validation_Workspace_T validation; Matter_Tlv_Tag_T tags[64];
    Matter_Tlv_Writer_T writer; uint8_t encoded[64];
} Admin;
enum { REVOKE_OPEN=1, REVOKE_CLOSED=2, REVOKE_WINDOW_MASK=3, REVOKE_PASE=4 };
static void erase(void* p,size_t n) { volatile uint8_t* b=p; while(n--) *b++=0; }
static void clear_window(Admin* m) {
    if(m->open) { m->open=false; m->unpublish=true; m->fabric=0; m->vendor=0; ++m->version; }
    m->expiry=0; m->timeout=m->discriminator=0;
    erase(&m->credentials,sizeof(m->credentials)); erase(m->verifier,sizeof(m->verifier));
}
static Matter_Result_T destroy(void* u) {
    Admin* m=u;
    if(m->busy || m->open || m->unpublish || m->revoking || m->waiters) return MATTER_BUSY;
    erase(m,sizeof(*m)); free(m); return MATTER_OK;
}
static Matter_Result_T version(void* u,uint32_t* out) { *out=((Admin*)u)->version; return MATTER_OK; }
static Matter_Result_T process(void* u,uint64_t now) {
    Admin* m=u; if(m->busy) return MATTER_BUSY;
    if(now<m->now) return MATTER_INVALID_ARGUMENT;
    m->busy=true; m->now=now;
    if(m->open && now>=m->expiry) clear_window(m);
    Matter_Result_T r=MATTER_OK;
    if(m->unpublish) {
        r=m->port.advertise(m->port.user,false,0);
        if(r==MATTER_OK) m->unpublish=false;
        else if(r!=MATTER_PENDING) r=MATTER_PORT_ERROR;
    }
    /* A discovery error must never delay PASE revocation/rollback. */
    m->revoke_error=MATTER_OK;
    if(m->revoking) {
        Matter_Result_T rr=m->port.revoke(m->port.user);
        if(rr==MATTER_OK) m->revoking=false;
        else if(rr!=MATTER_PENDING) rr=MATTER_PORT_ERROR;
        if(rr==MATTER_PORT_ERROR || r==MATTER_OK) r=rr;
    }
    if(m->waiters && r==MATTER_PORT_ERROR) m->revoke_error=r;
    m->busy=false; return r;
}
static Matter_Result_T deadline(void* u,uint64_t* out) {
    Admin* m=u;
    if(m->unpublish || m->revoking) *out=m->now;
    else if(m->open) *out=m->expiry;
    else return MATTER_INVALID_STATE;
    return MATTER_OK;
}
Matter_Result_T matter_admin_commissioning_close(Matter_Cluster_T c) {
    Admin* m=matter_cluster_context(c,destroy); if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    clear_window(m); return m->unpublish || m->revoking?MATTER_PENDING:MATTER_OK;
}
Matter_Result_T matter_admin_commissioning_fabric_removed(Matter_Cluster_T c,uint8_t index) {
    Admin* m=matter_cluster_context(c,destroy); if(!m || !index || index==255) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->open && m->fabric==index) { m->fabric=0; ++m->version; }
    return MATTER_OK;
}
Matter_Pase_T matter_admin_commissioning_pase_new(Matter_Cluster_T c,uint16_t id,uint32_t timeout,uint64_t now) {
    Admin* m=matter_cluster_context(c,destroy);
    if(!m || m->busy || !id || !timeout || now<m->now) return NULL;
    m->now=now; if(m->open && now>=m->expiry) clear_window(m);
    if(!m->open || m->unpublish || m->revoking) return NULL;
    m->busy=true; m->credentials.local_session_id=id; m->credentials.timeout_ms=timeout;
    Matter_Pase_T p=matter_pase_new(&m->crypto,&m->credentials,now); m->busy=false; return p;
}
static bool next(Admin* m) { return matter_tlv_next(&m->reader,&m->e)==MATTER_TLV_OK; }
static bool skip(Admin* m) {
    return (m->e.type!=MATTER_TLV_STRUCTURE && m->e.type!=MATTER_TLV_ARRAY && m->e.type!=MATTER_TLV_LIST) ||
        matter_tlv_skip_container(&m->reader)==MATTER_TLV_OK;
}
static uint8_t validate(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    (void)ref; (void)q; Admin* m=u;
    const Matter_Tlv_Validation_Options_T opt={1024,256,2048,4,false,0,0}; Matter_Tlv_Validation_Report_T report;
    return matter_tlv_validate(d,n,&opt,&m->validation,m->tags,64,&report)==MATTER_TLV_OK &&
        matter_tlv_init(&m->reader,d,n,4)==MATTER_TLV_OK && next(m) && m->e.type==MATTER_TLV_STRUCTURE && !m->e.tag.control ? 0:MATTER_IM_INVALID_COMMAND;
}
static Matter_Im_Command_Result_T status(uint8_t code) { return (Matter_Im_Command_Result_T){.status=code}; }
static Matter_Im_Command_Result_T specific(uint8_t code) {
    return (Matter_Im_Command_Result_T){.status=MATTER_IM_FAILURE,.has_cluster_status=true,.cluster_status=code};
}
/* Parse into ephemeral scratch, not the live credential. PAKE argument errors
 * must be cluster statuses; IM validate cannot express those, hence start. */
static Matter_Im_Command_Result_T parse(Admin* m,uint32_t cmd,const uint8_t* d,size_t n,Matter_Pase_Config_T* candidate) {
    if(validate(m,NULL,NULL,d,n)) return status(MATTER_IM_INVALID_COMMAND);
    unsigned seen=0;
    while(next(m)) {
        if(m->e.type==MATTER_TLV_END) return seen==(cmd==0?31u:0u) &&
            matter_tlv_next(&m->reader,&m->e)==MATTER_TLV_DONE?status(0):status(MATTER_IM_INVALID_COMMAND);
        if(m->e.tag.control!=1) return status(MATTER_IM_INVALID_COMMAND);
        unsigned tag=m->e.tag.number;
        if(cmd!=0 || tag>4) { if(!skip(m)) return status(MATTER_IM_INVALID_COMMAND); continue; }
        if(seen&(1u<<tag)) return status(MATTER_IM_INVALID_COMMAND);
        seen|=1u<<tag;
        if(tag==1 || tag==4) {
            if(m->e.type!=MATTER_TLV_BYTES || (tag==1?m->e.size!=97:m->e.size<16 || m->e.size>32)) return specific(3);
            if(tag==1) memcpy(m->verifier,m->e.data,97);
            else { memcpy(candidate->salt,m->e.data,m->e.size); candidate->salt_size=(uint8_t)m->e.size; }
        } else {
            if(m->e.type!=MATTER_TLV_UNSIGNED) return tag==3?specific(3):status(MATTER_IM_INVALID_COMMAND);
            uint64_t v=m->e.unsigned_value;
            if(tag==0) { if(v<180 || v>900) return status(MATTER_IM_INVALID_COMMAND); m->timeout=(uint16_t)v; }
            if(tag==2) { if(v>4095) return status(MATTER_IM_INVALID_COMMAND); m->discriminator=(uint16_t)v; }
            if(tag==3) { if(v<1000 || v>100000) return specific(3); candidate->iterations=(uint32_t)v; }
        }
    }
    return status(MATTER_IM_INVALID_COMMAND);
}
static Matter_Result_T start(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n,
    Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out,uint64_t* token) {
    (void)w; Admin* m=u; uint32_t cmd=*(const uint32_t*)ref; *token=0;
    Matter_Pase_Config_T* candidate=&m->candidate;
    *candidate=(Matter_Pase_Config_T){.responder=true};
    m->busy=true; *out=parse(m,cmd,d,n,candidate);
    if(out->status) goto done;
    if(cmd==2) {
        *token=m->open?REVOKE_OPEN:REVOKE_CLOSED; clear_window(m); m->revoking=true; m->revoke_error=MATTER_OK; ++m->waiters;
        /* Bit 2 identifies only this PASE caller. CASE callers still wait for
         * full revocation/rollback; the owner keeps driving cleanup either way. */
        if(MATTER_CSA_COMPAT_REVOKE_REPLY && !q->is_case) *token|=REVOKE_PASE;
        erase(candidate,sizeof(*candidate)); m->busy=false; return MATTER_PENDING;
    }
    if(!q->is_case || !q->fabric || q->fabric==255) { *out=status(MATTER_IM_UNSUPPORTED_ACCESS); goto done; }
    bool blocked=false;
    if(m->open || m->unpublish || m->revoking || m->waiters || q->armed) { *out=specific(2); goto done; }
    if(m->port.blocked(m->port.user,&blocked)!=MATTER_OK) { *out=status(MATTER_IM_FAILURE); goto done; }
    if(blocked) { *out=specific(2); goto done; }
    uint16_t vendor=0;
    if(m->port.vendor(m->port.user,q->fabric,&vendor)!=MATTER_OK || !vendor || vendor==65535) { *out=status(MATTER_IM_FAILURE); goto done; }
    Matter_Result_T r=m->crypto.pake_verifier(m->crypto.user,m->verifier,97);
    if(r!=MATTER_OK) { *out=r==MATTER_INVALID_ARGUMENT?specific(3):status(MATTER_IM_FAILURE); goto done; }
    uint64_t duration=(uint64_t)m->timeout*1000;
    if(UINT64_MAX-m->now<duration) { *out=status(MATTER_IM_FAILURE); goto done; }
    if(m->port.advertise(m->port.user,true,m->discriminator)!=MATTER_OK) { *out=status(MATTER_IM_FAILURE); goto done; }
    memcpy(candidate->w0,m->verifier,32); memcpy(candidate->L,m->verifier+32,65);
    m->credentials=*candidate; m->expiry=m->now+duration; m->fabric=q->fabric; m->vendor=vendor; m->open=true; ++m->version;
done:
    erase(m->verifier,sizeof(m->verifier)); erase(candidate,sizeof(*candidate)); m->busy=false; return MATTER_OK;
}
static Matter_Result_T poll(void* u,const void* ref,uint64_t token,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out) {
    (void)ref; (void)w; Admin* m=u;
    bool wait=m->revoking && !(MATTER_CSA_COMPAT_REVOKE_REPLY && (token&REVOKE_PASE));
    if(m->revoke_error==MATTER_OK && (wait || m->unpublish)) return MATTER_PENDING;
    *out=m->revoke_error!=MATTER_OK?status(MATTER_IM_FAILURE):(token&REVOKE_WINDOW_MASK)==REVOKE_OPEN?status(0):specific(4);
    --m->waiters; return MATTER_OK;
}
static void cancel(void* u,const void* ref,uint64_t token) { (void)ref; (void)token; --((Admin*)u)->waiters; }
static uint8_t read_window(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* out) {
    (void)q; Admin* m=u; uint32_t id=*(const uint32_t*)ref;
    *out=(Matter_Im_Value_T){.type=(id==1?!m->fabric:id==2?!m->open:false)?MATTER_TLV_NULL:MATTER_TLV_UNSIGNED,
        .unsigned_value=id==0?m->open:id==1?m->fabric:m->vendor,.data_version=m->version}; return 0;
}
static uint8_t read_constant(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* out) {
    (void)q; *out=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=*(const uint32_t*)ref,.data_version=((Admin*)u)->version}; return 0;
}
typedef struct { const uint32_t* ids; size_t n; } List;
static uint8_t read_list(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* out) {
    (void)q; Admin* m=u; const List* list=ref;
    if(matter_tlv_writer_init(&m->writer,m->encoded,sizeof(m->encoded),1)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    m->e=(Matter_Tlv_Element_T){.type=MATTER_TLV_ARRAY};
    if(matter_tlv_write(&m->writer,&m->e,0)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    for(size_t i=0;i<list->n;++i) {
        m->e=(Matter_Tlv_Element_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=list->ids[i]};
        if(matter_tlv_write(&m->writer,&m->e,0)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    }
    m->e=(Matter_Tlv_Element_T){.type=MATTER_TLV_END};
    *out=(Matter_Im_Value_T){.type=MATTER_TLV_ARRAY,.data=m->encoded,.data_version=m->version};
    return matter_tlv_write(&m->writer,&m->e,0)==MATTER_TLV_OK && matter_tlv_writer_finish(&m->writer,&out->size)==MATTER_TLV_OK?0:MATTER_IM_FAILURE;
}
Matter_Cluster_T matter_admin_commissioning_new(const Matter_Admin_Commissioning_Port_T* p,const Matter_Crypto_Port_T* crypto,uint32_t dv,uint64_t now) {
    if(!p || !p->vendor || !p->blocked || !p->advertise || !p->revoke || !crypto || !crypto->pake_verifier ||
        !crypto->random || !crypto->sha256 || !crypto->hmac_sha256 || !crypto->hkdf_sha256 || !crypto->pbkdf2_sha256 ||
        !crypto->p256_reduce || !crypto->p256_scalar || !crypto->spake_share || !crypto->spake_secrets || !crypto->clear || !crypto->equal) return NULL;
    Admin* m=calloc(1,sizeof(*m)); if(!m) return NULL;
    m->port=*p; m->crypto=*crypto; m->version=dv; m->now=now;
    Matter_Cluster_Config_T config={.id=MATTER_ADMIN_COMMISSIONING_CLUSTER,.attributes=8,.commands=2,.pending=2,
        .callbacks={m,version,process,deadline,destroy}};
    Matter_Cluster_T c=matter_cluster_new(&config); if(!c) { free(m); return NULL; }
    static const uint32_t attrs[]={0,1,2,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd},commands[]={0,2},zero=0,revision=1;
    static const List lists[]={{NULL,0},{commands,2},{attrs,8}};
    static const Matter_Attribute_Def_T defs[]={
        {.id=0,.read_access={MATTER_IM_VIEW,false},.ref=&attrs[0],.read=read_window},
        {.id=1,.read_access={MATTER_IM_VIEW,false},.ref=&attrs[1],.read=read_window},
        {.id=2,.read_access={MATTER_IM_VIEW,false},.ref=&attrs[2],.read=read_window},
        {.id=0xfff8,.read_access={MATTER_IM_VIEW,false},.ref=&lists[0],.read=read_list},
        {.id=0xfff9,.read_access={MATTER_IM_VIEW,false},.ref=&lists[1],.read=read_list},
        {.id=0xfffb,.read_access={MATTER_IM_VIEW,false},.ref=&lists[2],.read=read_list},
        {.id=0xfffc,.read_access={MATTER_IM_VIEW,false},.ref=&zero,.read=read_constant},
        {.id=0xfffd,.read_access={MATTER_IM_VIEW,false},.ref=&revision,.read=read_constant}
    };
    for(unsigned i=0;i<8;++i) if(matter_cluster_add_attribute(c,&defs[i])!=MATTER_OK) goto fail;
    for(unsigned i=0;i<2;++i) {
        Matter_Command_Def_T def={.id=commands[i],.ref=&commands[i],.access={.privilege=MATTER_IM_ADMINISTER,.timed=true},
            .validate=validate,.start=start,.poll=i?poll:NULL,.cancel=i?cancel:NULL};
        if(matter_cluster_add_command(c,&def)!=MATTER_OK) goto fail;
    }
    (void)matter_cluster_seal(c); return c;
fail:
    matter_cluster_abandon(c); erase(m,sizeof(*m)); free(m); return NULL;
}
