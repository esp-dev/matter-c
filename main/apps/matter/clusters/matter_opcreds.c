#include "matter_opcreds.h"
#include "../model/matter_cluster_internal.h"
#include <stdlib.h>
#include <string.h>
const uint32_t matter_opcreds_attributes[MATTER_OPCREDS_ATTRIBUTES]={0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
static const uint32_t fabric_attributes[]={0,1,2,3,4,5,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};

enum { IDLE, PREPARE, SIGN, PUBLISH, READY, DISCARD };
typedef struct Matter_Opcreds* Opcreds;
static Matter_Result_T destroy(void*);
static Matter_Cluster_T interface_new(Opcreds);
static Matter_Result_T register_fabrics(Opcreds);
struct Matter_Opcreds {
    Matter_Cluster_T interface;
    Matter_Opcreds_Config_T config; Matter_Opcreds_Port_T port;
    Matter_Tlv_Writer_T writer; Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T e;
    Matter_Fabric_T fabrics;
    Matter_Exchange_Session_T session, candidate_session;
    uint64_t serial, token, staged, candidate;
    size_t elements_size, csr_size;
    uint32_t command;
    unsigned phase;
    bool busy, detached, update, candidate_update;
    uint8_t accessing;
    uint8_t candidate_challenge[16], noc_status, fabric_index;
    uint8_t status, cert_type, nonce[32], challenge[16], checked[16], signature[64];
    uint8_t tbs[1024+16], csr[MATTER_CREDENTIALS_MAX_CSR], metadata[48];
};
static void erase(void* p,size_t n) { volatile uint8_t* b=p; while(n--) *b++=0; }
static bool span(Matter_Der_T d,size_t min,size_t max) { return d.size>=min && d.size<=max && (d.data || !d.size); }
static size_t octets(size_t n) { return n+(n<=255?3:4); }
Matter_Cluster_T matter_opcreds_new(const Matter_Opcreds_Config_T* c,const Matter_Opcreds_Port_T* p) {
    if(!c || !p || !p->challenge || !p->timestamp || !p->sign || !p->csr_prepare || !p->csr_publish || !p->csr_discard ||
        !span(c->dac,1,600) || !span(c->pai,1,600) || !span(c->certification_declaration,1,900) || !span(c->firmware_information,0,900) ||
        2+octets(c->certification_declaration.size)+35+6+(c->firmware_information.size?octets(c->firmware_information.size):0)>900) return NULL;
    Opcreds m=calloc(1,sizeof(*m)); if(!m) return NULL; m->config=*c; m->port=*p;
    m->interface=interface_new(m); if(!m->interface) { erase(m,sizeof(*m)); free(m); return NULL; } return m->interface;
}
static Matter_Result_T destroy(void* ctx) {
    Opcreds m=ctx;
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->token || m->staged || m->candidate || m->phase!=IDLE) return MATTER_INVALID_STATE;
    erase(m,sizeof(*m)); free(m); return MATTER_OK;
}
static bool put(Opcreds m,Matter_Tlv_Writer_T* w,Matter_Tlv_Type_T t,int tag,uint64_t v,const uint8_t* p,size_t n) {
    m->e=(Matter_Tlv_Element_T){.type=t,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=v,.data=p,.size=n};
    return matter_tlv_write(w,&m->e,0)==MATTER_TLV_OK;
}
#define PUT(t,tag,v) put(m,w,t,tag,v,NULL,0)
#define BYTES(tag,p,n) put(m,w,MATTER_TLV_BYTES,tag,0,p,n)
uint32_t matter_opcreds_version(Matter_Opcreds_T handle) {
    Opcreds m=matter_cluster_context(handle,destroy); return m?m->config.data_version+(m->fabrics?matter_fabric_revision(m->fabrics):0):0; }
uint8_t matter_opcreds_read(Matter_Opcreds_T m,uint32_t a,Matter_Im_Value_T* v) {
    if(!matter_cluster_context(m,destroy)) return MATTER_IM_FAILURE;
    Matter_Cluster_Request_T q={.filtered=true}; return matter_cluster_read(m,a,&q,v);
}
uint8_t matter_opcreds_command(Matter_Opcreds_T handle,uint32_t command,Matter_Im_Command_T* c) {
    Opcreds m=matter_cluster_context(handle,destroy); if(!m || m->busy) return MATTER_IM_FAILURE;
    return matter_cluster_command_metadata(handle,command,c);
}
uint8_t matter_opcreds_validate(Matter_Opcreds_T handle,uint32_t command,const uint8_t* data,size_t size) {
    Opcreds m=matter_cluster_context(handle,destroy);
    if(!m) return MATTER_IM_FAILURE;
    Matter_Im_Command_T c; uint8_t status=matter_opcreds_command(m->interface,command,&c); if(status) return status;
    if(command>=6) return matter_fabric_validate(command,data,size);
    if(size>1024 || matter_tlv_init(&m->reader,data,size,4)!=MATTER_TLV_OK || matter_tlv_next(&m->reader,&m->e)!=MATTER_TLV_OK ||
        m->e.type!=MATTER_TLV_STRUCTURE || m->e.tag.control) return MATTER_IM_INVALID_COMMAND;
    unsigned seen=0;
    while(matter_tlv_next(&m->reader,&m->e)==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&m->e;
        if(e->type==MATTER_TLV_END) return (seen&1) && matter_tlv_next(&m->reader,e)==MATTER_TLV_DONE?0:MATTER_IM_INVALID_COMMAND;
        if(e->tag.control!=1 || e->tag.number>(command==4?1u:0u)) {
            if((e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) &&
                matter_tlv_skip_container(&m->reader)!=MATTER_TLV_OK) return MATTER_IM_INVALID_COMMAND;
            continue;
        }
        unsigned id=e->tag.number; if(seen&(1u<<id)) return MATTER_IM_INVALID_COMMAND; seen|=1u<<id;
        if(id==1) { if(e->type!=MATTER_TLV_BOOL) return MATTER_IM_INVALID_COMMAND; }
        else if(command==2) { if(e->type!=MATTER_TLV_UNSIGNED || e->unsigned_value<1 || e->unsigned_value>2) return MATTER_IM_INVALID_COMMAND; }
        else if(e->type!=MATTER_TLV_BYTES || e->size!=32) return MATTER_IM_INVALID_COMMAND;
    }
    return MATTER_IM_INVALID_COMMAND;
}
static void clear_operation(Opcreds m) {
    erase(m->tbs,sizeof(m->tbs)); erase(m->csr,sizeof(m->csr)); erase(m->nonce,32);
    erase(m->challenge,16); erase(m->checked,16); erase(m->signature,64);
    m->elements_size=m->csr_size=0; m->token=0; m->session=0; m->phase=IDLE; m->detached=false;
}
static bool current_session(Opcreds m) {
    Matter_Result_T r=m->port.challenge(m->port.user,m->session,m->checked);
    uint8_t different=0; for(unsigned i=0;i<16;++i) different|=m->checked[i]^m->challenge[i];
    erase(m->checked,16); return r==MATTER_OK && !different;
}
static Matter_Result_T start(Matter_Opcreds_T handle,Matter_Exchange_Session_T session,uint8_t accessing,bool is_case,uint32_t command,bool armed,
    const uint8_t* data,size_t size,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* result,uint64_t* token) {
    Opcreds m=matter_cluster_context(handle,destroy);
    if(!m || !session || !result || !token) return MATTER_INVALID_ARGUMENT;
    if(command==9 || command==10 || (command==7 && (!is_case || !accessing))) { *token=0; *result=(Matter_Im_Command_Result_T){.status=MATTER_IM_UNSUPPORTED_COMMAND}; return MATTER_OK; } /* Generic interface supplies accessing fabric. */
    if(command==12 && (!accessing || (!is_case && accessing!=matter_opcreds_fabric_index(handle,session)))) {
        *token=0; *result=(Matter_Im_Command_Result_T){.status=MATTER_IM_UNSUPPORTED_ACCESS}; return MATTER_OK;
    }
    *token=0; *result=(Matter_Im_Command_Result_T){.status=matter_opcreds_validate(m->interface,command,data,size)};
    if(result->status) return MATTER_OK;
    bool update=false;
    if(command==4) {
        matter_tlv_init(&m->reader,data,size,4); matter_tlv_next(&m->reader,&m->e);
        while(matter_tlv_next(&m->reader,&m->e)==MATTER_TLV_OK && m->e.type!=MATTER_TLV_END) {
            if(m->e.tag.control==1 && m->e.tag.number==1) update=m->e.unsigned_value!=0;
            if(m->e.type==MATTER_TLV_STRUCTURE || m->e.type==MATTER_TLV_ARRAY || m->e.type==MATTER_TLV_LIST) matter_tlv_skip_container(&m->reader);
        }
        if(update && !is_case) { result->status=MATTER_IM_INVALID_COMMAND; return MATTER_OK; }
    }
    if((command==4 || command==6 || command==7 || command==11) && !armed) { result->status=0xca; return MATTER_OK; }
    if(m->fabrics && (command==4 || command==6 || command==7 || command==11) && matter_fabric_added(m->fabrics)) { result->status=MATTER_IM_CONSTRAINT_ERROR; return MATTER_OK; }
    if(m->token || m->phase!=IDLE) { result->status=0x9c; return MATTER_OK; }
    if(command!=11 && command!=12 && (!w || w->size || w->capacity<(command==13?75u:(command==6 || command==7)?8u:command==2?606u:976u))) { result->status=MATTER_IM_RESOURCE_EXHAUSTED; return MATTER_OK; }
    m->update=update; m->accessing=accessing;
    if(command==6 || command==7 || command>=11) { memcpy(m->tbs,data,size); m->elements_size=size; }
    else {
    matter_tlv_init(&m->reader,data,size,4); matter_tlv_next(&m->reader,&m->e);
    while(matter_tlv_next(&m->reader,&m->e)==MATTER_TLV_OK && m->e.type!=MATTER_TLV_END) {
        if(m->e.tag.control==1 && m->e.tag.number==0) {
            if(command==2) m->cert_type=(uint8_t)m->e.unsigned_value;
            else memcpy(m->nonce,m->e.data,32);
        }
        if(m->e.type==MATTER_TLV_STRUCTURE || m->e.type==MATTER_TLV_ARRAY || m->e.type==MATTER_TLV_LIST) matter_tlv_skip_container(&m->reader);
    }
    }
    if((command==6 || command==7) && m->candidate && m->candidate_update!=(command==7)) {
        result->status=MATTER_IM_CONSTRAINT_ERROR; clear_operation(m); return MATTER_OK;
    }
    if(command==2) {
        Matter_Der_T cert=m->cert_type==1?m->config.dac:m->config.pai;
        if(!PUT(MATTER_TLV_STRUCTURE,-1,0) || !BYTES(0,cert.data,cert.size) || !PUT(MATTER_TLV_END,-1,0)) result->status=MATTER_IM_FAILURE;
        return MATTER_OK;
    }
    if(m->serial==UINT64_MAX) { result->status=MATTER_IM_RESOURCE_EXHAUSTED; clear_operation(m); return MATTER_OK; }
    m->busy=true; Matter_Result_T r=m->port.challenge(m->port.user,session,m->challenge); m->busy=false;
    if(r!=MATTER_OK) { result->status=MATTER_IM_UNSUPPORTED_ACCESS; clear_operation(m); return MATTER_OK; }
    m->session=session; m->command=command; m->token=++m->serial; m->phase=PREPARE; m->status=0; *token=m->token; return MATTER_PENDING;
}
Matter_Result_T matter_opcreds_start(Matter_Opcreds_T handle,Matter_Exchange_Session_T session,uint32_t command,bool armed,
    const uint8_t* data,size_t size,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* result,uint64_t* token) {
    return start(handle,session,0,false,command,armed,data,size,w,result,token);
}
static bool elements(Opcreds m) {
    uint32_t timestamp=0;
    if(!m->command && m->port.timestamp(m->port.user,&timestamp)!=MATTER_OK) return false;
    Matter_Tlv_Writer_T* w=&m->writer;
    if(matter_tlv_writer_init(w,m->tbs,MATTER_OPCREDS_RESP_MAX,1)!=MATTER_TLV_OK || !PUT(MATTER_TLV_STRUCTURE,-1,0)) return false;
    if(m->command==4) { if(!BYTES(1,m->csr,m->csr_size)) return false; }
    else if(!BYTES(1,m->config.certification_declaration.data,m->config.certification_declaration.size)) return false;
    if(!BYTES(2,m->nonce,32)) return false;
    if(!m->command && (!PUT(MATTER_TLV_UNSIGNED,3,timestamp) ||
        (m->config.firmware_information.size && !BYTES(4,m->config.firmware_information.data,m->config.firmware_information.size)))) return false;
    if(!PUT(MATTER_TLV_END,-1,0) || matter_tlv_writer_finish(w,&m->elements_size)!=MATTER_TLV_OK) return false;
    memcpy(m->tbs+m->elements_size,m->challenge,16); return true;
}
static Matter_Result_T discard_staged(Opcreds m) {
    if(m->staged) {
        Matter_Result_T r=m->port.csr_discard(m->port.user,m->staged); if(r!=MATTER_OK) return r==MATTER_PENDING?MATTER_PENDING:MATTER_PORT_ERROR;
        m->staged=0;
    }
    if(m->detached) clear_operation(m); else m->phase=READY;
    return MATTER_OK;
}
Matter_Result_T matter_opcreds_process(Matter_Opcreds_T handle) {
    Opcreds m=matter_cluster_context(handle,destroy);
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->phase==IDLE || m->phase==READY) return MATTER_OK;
    m->busy=true; Matter_Result_T r=MATTER_OK;
    if(m->phase==DISCARD) r=discard_staged(m);
    else if(!current_session(m)) { m->status=MATTER_IM_UNSUPPORTED_ACCESS; m->phase=DISCARD; }
    else if(m->phase==PREPARE && (m->command==12 || m->command==13)) {
        m->status=matter_fabric_vid(m->fabrics,m->accessing,m->command,m->tbs,m->elements_size,m->challenge,&m->fabric_index,m->signature);
        erase(m->tbs,sizeof(m->tbs)); m->phase=READY;
    } else if(m->phase==PREPARE && (m->command==6 || m->command==7 || m->command==11)) {
        uint8_t different=0; for(unsigned i=0;i<16;++i) different|=m->candidate_challenge[i]^m->challenge[i];
        uint64_t key=m->session==m->candidate_session && !different?m->candidate:0;
        Matter_Im_Command_Result_T result=m->command==7?
            matter_fabric_update(m->fabrics,m->session,m->accessing,key,m->tbs,m->elements_size,&m->noc_status,&m->fabric_index):matter_fabric_execute(m->fabrics,m->session,m->command,key,m->tbs,m->elements_size,&m->noc_status,&m->fabric_index);
        m->status=result.status; erase(m->tbs,sizeof(m->tbs));
        if((m->command==6 || m->command==7) && !m->status && !m->noc_status) { m->candidate=0; m->candidate_session=0; erase(m->candidate_challenge,16); }
        m->phase=READY;
    } else if(m->phase==PREPARE) {
        if(m->command==4) r=m->port.csr_prepare(m->port.user,&m->staged,m->csr,sizeof(m->csr),&m->csr_size);
        if(r!=MATTER_OK || (m->command==4 && (!m->staged || !m->csr_size || m->csr_size>sizeof(m->csr))) || !elements(m)) {
            m->status=MATTER_IM_FAILURE; m->phase=DISCARD;
        } else m->phase=SIGN;
    } else if(m->phase==SIGN) {
        r=m->port.sign(m->port.user,m->tbs,m->elements_size+16,m->signature);
        erase(m->tbs+m->elements_size,16); /* Challenge is never included in the response. */
        if(r!=MATTER_OK) { erase(m->signature,64); m->status=MATTER_IM_FAILURE; m->phase=DISCARD; }
        else m->phase=m->command==4?PUBLISH:READY;
    } else if(m->phase==PUBLISH) {
        r=m->port.csr_publish(m->port.user,m->staged);
        if(r!=MATTER_OK) { m->status=MATTER_IM_FAILURE; m->phase=DISCARD; }
        else { m->candidate_update=m->update; m->candidate=m->staged; m->candidate_session=m->session; memcpy(m->candidate_challenge,m->challenge,16); m->staged=0; m->phase=READY; }
    }
    m->busy=false;
    if(m->phase==DISCARD) return MATTER_PENDING; /* Error response waits for release. */
    return r==MATTER_PORT_ERROR?r:m->phase==READY || m->phase==IDLE?MATTER_OK:MATTER_PENDING;
}
Matter_Result_T matter_opcreds_poll(Matter_Opcreds_T handle,uint64_t token,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* result) {
    Opcreds m=matter_cluster_context(handle,destroy);
    if(!m || !result) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(!token || token!=m->token || m->detached) return MATTER_INVALID_STATE;
    if(m->phase!=READY) return MATTER_PENDING;
    *result=(Matter_Im_Command_Result_T){.status=m->status};
    if(!result->status && m->command==13) {
        m->busy=true; bool live=current_session(m); m->busy=false;
        if(!live) result->status=MATTER_IM_UNSUPPORTED_ACCESS;
    }
    if(!result->status && (m->command==6 || m->command==7)) {
        if(!w || !PUT(MATTER_TLV_STRUCTURE,-1,0) || !PUT(MATTER_TLV_UNSIGNED,0,m->noc_status) ||
            (!m->noc_status && !PUT(MATTER_TLV_UNSIGNED,1,m->fabric_index)) || !PUT(MATTER_TLV_END,-1,0)) result->status=MATTER_IM_FAILURE;
    } else if(!result->status && m->command==13) {
        if(!w || !PUT(MATTER_TLV_STRUCTURE,-1,0) || !PUT(MATTER_TLV_UNSIGNED,0,m->fabric_index) ||
            !PUT(MATTER_TLV_UNSIGNED,1,1) || !BYTES(2,m->signature,64) || !PUT(MATTER_TLV_END,-1,0)) result->status=MATTER_IM_FAILURE;
    } else if(!result->status && m->command!=11 && m->command!=12 && (!w || !PUT(MATTER_TLV_STRUCTURE,-1,0) || !BYTES(0,m->tbs,m->elements_size) ||
        !BYTES(1,m->signature,64) || !PUT(MATTER_TLV_END,-1,0))) result->status=MATTER_IM_FAILURE;
    clear_operation(m); return MATTER_OK;
}
void matter_opcreds_cancel(Matter_Opcreds_T handle,uint64_t token) {
    Opcreds m=matter_cluster_context(handle,destroy);
    if(!m || m->busy || !token || m->token!=token) return;
    m->detached=true;
    if(m->staged) m->phase=DISCARD; else clear_operation(m);
}
Matter_Result_T matter_opcreds_rollback(Matter_Opcreds_T handle) {
    Opcreds m=matter_cluster_context(handle,destroy);
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    matter_opcreds_cancel(m->interface,m->token); m->busy=true;
    Matter_Result_T r=m->fabrics?matter_fabric_rollback(m->fabrics):MATTER_OK;
    if(r==MATTER_OK) r=discard_staged(m);
    if(r==MATTER_OK && m->candidate) {
        r=m->port.csr_discard(m->port.user,m->candidate); if(r==MATTER_OK) m->candidate=0;
    }
    if(r==MATTER_OK) { clear_operation(m); m->candidate_session=0; erase(m->candidate_challenge,16); }
    m->busy=false; return r==MATTER_OK || r==MATTER_PENDING?r:MATTER_PORT_ERROR;
}

Matter_Result_T matter_opcreds_attach_fabrics(Matter_Opcreds_T handle,Matter_Fabric_T f) {
    Opcreds m=matter_cluster_context(handle,destroy);
    if(!m || !f) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->fabrics || m->phase!=IDLE || m->candidate || !matter_cluster_mutable(handle)) return MATTER_INVALID_STATE;
    Matter_Result_T r=register_fabrics(m); if(r!=MATTER_OK) return r;
    m->fabrics=f; ++m->config.data_version; return MATTER_OK;
}
const uint32_t* matter_opcreds_attribute_ids(Matter_Opcreds_T handle,size_t* count) {
    Opcreds m=matter_cluster_context(handle,destroy);
    *count=m && m->fabrics?11:MATTER_OPCREDS_ATTRIBUTES;
    return m && m->fabrics?fabric_attributes:matter_opcreds_attributes;
}
uint8_t matter_opcreds_fabric_index(Matter_Opcreds_T handle,Matter_Exchange_Session_T session) {
    Opcreds m=matter_cluster_context(handle,destroy);
    return m && m->fabrics?matter_fabric_index(m->fabrics,session):0;
}
uint8_t matter_opcreds_pending_fabric(Matter_Opcreds_T handle) {
    Opcreds m=matter_cluster_context(handle,destroy); return m && m->fabrics?matter_fabric_pending_index(m->fabrics):0; }
uint8_t matter_opcreds_read_session(Matter_Opcreds_T m,uint32_t a,Matter_Exchange_Session_T session,bool filtered,Matter_Im_Value_T* v) {
    if(!matter_cluster_context(m,destroy)) return MATTER_IM_FAILURE;
    Matter_Cluster_Request_T q={.session=session,.fabric=matter_opcreds_fabric_index(m,session),.filtered=filtered}; return matter_cluster_read(m,a,&q,v);
}

uint8_t matter_opcreds_read_fabric(Matter_Opcreds_T m,uint32_t a,uint8_t index,bool filtered,Matter_Im_Value_T* v) {
    if(!matter_cluster_context(m,destroy)) return MATTER_IM_FAILURE;
    Matter_Cluster_Request_T q={.fabric=index,.filtered=filtered}; return matter_cluster_read(m,a,&q,v);
}

Matter_Result_T matter_opcreds_commit_ready(Matter_Opcreds_T handle) {
    Opcreds m=matter_cluster_context(handle,destroy);
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    return m->phase==IDLE && !m->token && !m->staged && !m->candidate?MATTER_OK:MATTER_INVALID_STATE;
}
Matter_Result_T matter_opcreds_commit(Matter_Opcreds_T handle) {
    Opcreds m=matter_cluster_context(handle,destroy);
    if(!m) return MATTER_INVALID_ARGUMENT;
    Matter_Result_T r=matter_opcreds_commit_ready(m->interface); if(r!=MATTER_OK) return r;
    m->candidate_session=0; erase(m->candidate_challenge,16); return MATTER_OK;
}

Matter_Result_T matter_opcreds_delete(Matter_Opcreds_T m) {
    if(!matter_cluster_context(m,destroy)) return MATTER_INVALID_ARGUMENT;
    return matter_cluster_delete(m);
}

static Matter_Result_T cluster_version(void* u,uint32_t* v) { Opcreds m=u; *v=matter_opcreds_version(m->interface); return MATTER_OK; }
static Matter_Result_T cluster_process(void* u,uint64_t now) { (void)now; Opcreds m=u; return matter_opcreds_process(m->interface); }
static uint8_t read_scalar(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)q; Opcreds m=u; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=*(const uint32_t*)ref,.data_version=matter_opcreds_version(m->interface),.report_on_version_change=true}; return 0;
}
typedef struct { const uint32_t* ids; size_t base,full; } IdList;
static uint8_t read_ids(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)q; Opcreds m=u; const IdList* list=ref; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_ARRAY,.data_version=matter_opcreds_version(m->interface),.report_on_version_change=true};
    Matter_Tlv_Writer_T* w=&m->writer; size_t n=m->fabrics?list->full:list->base;
    const uint32_t* ids=list->ids;
    if(!ids) ids=matter_opcreds_attribute_ids(m->interface,&n);
    if(matter_tlv_writer_init(w,m->metadata,sizeof(m->metadata),1)!=MATTER_TLV_OK || !PUT(MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
    for(size_t i=0;i<n;++i) if(!PUT(MATTER_TLV_UNSIGNED,-1,ids[i])) return MATTER_IM_FAILURE;
    if(!PUT(MATTER_TLV_END,-1,0) || matter_tlv_writer_finish(w,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->data=m->metadata; return 0;
}
static uint8_t read_fabric(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    Opcreds m=u; if(m->busy) return MATTER_IM_FAILURE;
    uint8_t r=matter_fabric_read_index(m->fabrics,*(const uint32_t*)ref,q->fabric,q->filtered,v);
    /* The fabric revision covers label/credential/VID changes and rollback.
     * Unrelated application notifications must not resend the whole NOC table. */
    if(!r) { v->data_version=matter_opcreds_version(m->interface); v->report_on_version_change=true; }
    return r;
}
static uint8_t cluster_validate(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    Opcreds m=u; uint32_t cmd=*(const uint32_t*)ref;
    if(cmd==9 || cmd==10 || cmd==12) {
        if(!q->fabric || (!q->is_case && q->fabric!=matter_fabric_index(m->fabrics,q->session))) return MATTER_IM_INVALID_COMMAND;
    } else if(cmd==7 && (!q->is_case || !q->fabric)) return MATTER_IM_UNSUPPORTED_COMMAND;
    /* AddRoot/AddNOC also commission a new fabric over an administrator's CASE
     * session (Core 11.18.6.8). ACL, fail-safe ownership and CSR binding are
     * enforced by the existing root/start paths, not by a PASE-only restriction. */
    return matter_opcreds_validate(m->interface,cmd,d,n);
}
static Matter_Result_T cluster_start(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out,uint64_t* token) {
    Opcreds m=u; uint32_t cmd=*(const uint32_t*)ref;
    if(cmd==9 || cmd==10) {
        *token=0; *out=(Matter_Im_Command_Result_T){.status=cluster_validate(u,ref,q,d,n)};
        if(out->status) return MATTER_OK;
        if(m->busy || m->phase!=IDLE) { out->status=0x9c; return MATTER_OK; }
        if(!w || w->size || w->capacity<8) { out->status=MATTER_IM_RESOURCE_EXHAUSTED; return MATTER_OK; }
        uint8_t status,index; m->busy=true;
        *out=matter_fabric_manage(m->fabrics,q->fabric,cmd,d,n,&status,&index);
        if(!out->status && (!PUT(MATTER_TLV_STRUCTURE,-1,0) || !PUT(MATTER_TLV_UNSIGNED,0,status) ||
            (!status && !PUT(MATTER_TLV_UNSIGNED,1,index)) || !PUT(MATTER_TLV_END,-1,0))) out->status=MATTER_IM_FAILURE;
        m->busy=false; return MATTER_OK;
    }
    return start(m->interface,q->session,q->fabric,q->is_case,cmd,q->armed,d,n,w,out,token);
}
static Matter_Result_T cluster_poll(void* u,const void* ref,uint64_t token,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out) {
    (void)ref; Opcreds m=u; return matter_opcreds_poll(m->interface,token,w,out);
}
static void cluster_cancel(void* u,const void* ref,uint64_t token) { (void)ref; Opcreds m=u; matter_opcreds_cancel(m->interface,token); }
static const uint32_t command_ids[]={0,2,4,6,11,9,10,7,12,13};
static Matter_Result_T register_commands(Matter_Cluster_T c,unsigned first,unsigned end) {
    for(unsigned i=first;i<end;++i) {
        uint32_t id=command_ids[i]; Matter_Command_Def_T d={.id=id,.ref=&command_ids[i],.validate=cluster_validate,.start=cluster_start,
            .poll=id==2?NULL:cluster_poll,.cancel=id==2?NULL:cluster_cancel,
            .access={.privilege=MATTER_IM_ADMINISTER,.response=id!=11,.response_command=id==6?8:id+1,.response_capacity=id>=6?8:id==2?606:976}};
        Matter_Result_T r=matter_cluster_add_command(c,&d); if(r!=MATTER_OK) return r;
    }
    return MATTER_OK;
}
static Matter_Result_T register_fabrics(Opcreds m) {
    static const Matter_Attribute_Def_T attrs[]={
        {.id=0,.read_access={MATTER_IM_ADMINISTER,true},.read=read_fabric,.ref=&fabric_attributes[0]},
        {.id=1,.read_access={MATTER_IM_VIEW,true},.read=read_fabric,.ref=&fabric_attributes[1]},
        {.id=2,.read_access={MATTER_IM_VIEW,false},.read=read_fabric,.ref=&fabric_attributes[2]},
        {.id=3,.read_access={MATTER_IM_VIEW,false},.read=read_fabric,.ref=&fabric_attributes[3]},
        {.id=4,.read_access={MATTER_IM_VIEW,false},.read=read_fabric,.ref=&fabric_attributes[4]},
        {.id=5,.read_access={MATTER_IM_VIEW,false},.read=read_fabric,.ref=&fabric_attributes[5]},
    };
    static const Matter_Command_Def_T commands[]={
        {.id=6,.ref=&command_ids[3],.validate=cluster_validate,.start=cluster_start,.poll=cluster_poll,.cancel=cluster_cancel,
            .access={.privilege=MATTER_IM_ADMINISTER,.response=true,.response_command=8,.response_capacity=8}},
        {.id=11,.ref=&command_ids[4],.validate=cluster_validate,.start=cluster_start,.poll=cluster_poll,.cancel=cluster_cancel,
            .access={.privilege=MATTER_IM_ADMINISTER,.response=false,.response_command=8,.response_capacity=8}},
        {.id=9,.ref=&command_ids[5],.validate=cluster_validate,.start=cluster_start,
            .access={.privilege=MATTER_IM_ADMINISTER,.fabric_scoped=true,.response=true,.response_command=8,.response_capacity=8}},
        {.id=7,.ref=&command_ids[7],.validate=cluster_validate,.start=cluster_start,.poll=cluster_poll,.cancel=cluster_cancel,
            .access={.privilege=MATTER_IM_ADMINISTER,.fabric_scoped=true,.response=true,.response_command=8,.response_capacity=8}},
        {.id=10,.ref=&command_ids[6],.validate=cluster_validate,.start=cluster_start,
            .access={.privilege=MATTER_IM_ADMINISTER,.response=true,.response_command=8,.response_capacity=8}},
        {.id=12,.ref=&command_ids[8],.validate=cluster_validate,.start=cluster_start,.poll=cluster_poll,.cancel=cluster_cancel,
            .access={.privilege=MATTER_IM_ADMINISTER,.fabric_scoped=true}},
        {.id=13,.ref=&command_ids[9],.validate=cluster_validate,.start=cluster_start,.poll=cluster_poll,.cancel=cluster_cancel,
            .access={.privilege=MATTER_IM_ADMINISTER,.response=true,.response_command=14,.response_capacity=75}}
    };
    return matter_cluster_extend(m->interface,attrs,6,commands,7);
}
static Matter_Cluster_T interface_new(Opcreds m) {
    Matter_Cluster_Config_T cfg={.id=MATTER_OPCREDS_CLUSTER,.attributes=11,.commands=10,.pending=2,
        .callbacks={.ctx=m,.version=cluster_version,.process=cluster_process,.destroy=destroy}};
    Matter_Cluster_T c=matter_cluster_new(&cfg); if(!c) return NULL;
    static const uint32_t accepted[]={0,2,4,6,7,9,10,11,12,13},generated[]={1,3,5,8,14},zero=0,revision=2;
    static const IdList lists[]={{generated,3,5},{accepted,3,10},{NULL,0,0}};
    static const Matter_Attribute_Def_T attrs[]={
        {.id=0xfff8,.read_access={MATTER_IM_VIEW,false},.read=read_ids,.ref=&lists[0]},
        {.id=0xfff9,.read_access={MATTER_IM_VIEW,false},.read=read_ids,.ref=&lists[1]},
        {.id=0xfffb,.read_access={MATTER_IM_VIEW,false},.read=read_ids,.ref=&lists[2]},
        {.id=0xfffc,.read_access={MATTER_IM_VIEW,false},.read=read_scalar,.ref=&zero},
        {.id=0xfffd,.read_access={MATTER_IM_VIEW,false},.read=read_scalar,.ref=&revision}
    };
    for(size_t i=0;i<sizeof(attrs)/sizeof(*attrs);++i) if(matter_cluster_add_attribute(c,&attrs[i])!=MATTER_OK) { matter_cluster_abandon(c); return NULL; }
    if(register_commands(c,0,3)!=MATTER_OK) { matter_cluster_abandon(c); return NULL; }
    return c; /* attach_fabrics may extend until seal/Root attachment. */
}
