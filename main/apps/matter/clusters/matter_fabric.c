#include "matter_fabric.h"
#include "../codec/matter_tlv_internal.h"
#include <stdlib.h>
#include <string.h>
struct Matter_Fabric {
    Matter_Fabric_Port_T port; bool busy;
    Matter_Tlv_Writer_T writer; Matter_Tlv_Element_T e;
    uint8_t encoded[MATTER_IM_READ_MAX_VALUE];
};
static void erase(void* p,size_t n) { volatile uint8_t* b=p; while(n--) *b++=0; }
Matter_Fabric_T matter_fabric_new(const Matter_Fabric_Port_T* p) {
    if(!p || !p->view || !p->root || !p->install || !p->rollback || !p->view(p->user)) return NULL;
    Matter_Fabric_T m=calloc(1,sizeof(*m)); if(m) m->port=*p; return m;
}
Matter_Result_T matter_fabric_delete(Matter_Fabric_T m) {
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    /* Durable journal belongs to backend; owner must rollback or recover it. */
    erase(m,sizeof(*m)); free(m); return MATTER_OK;
}
uint32_t matter_fabric_revision(Matter_Fabric_T m) { return m->port.view(m->port.user)->revision; }
bool matter_fabric_added(Matter_Fabric_T m) { return m->port.view(m->port.user)->added; }
uint8_t matter_fabric_pending_index(Matter_Fabric_T m) { return m->port.view(m->port.user)->pending_index; }
uint8_t matter_fabric_index(Matter_Fabric_T m,Matter_Exchange_Session_T session) {
    const Matter_Fabric_View_T* v=m->port.view(m->port.user);
    return session && session==v->pase_session?v->pase_index:0;
}
static uint8_t parse(uint32_t cmd,const uint8_t* data,size_t size,Matter_Fabric_Add_T* a,Matter_Cert_Tlv_T* root) {
    Matter_Tlv_Reader_T r; Matter_Tlv_Element_T e; unsigned seen=0;
    if((cmd!=6 && cmd!=7 && cmd!=11) || size>1024 || matter_tlv_init(&r,data,size,4)!=MATTER_TLV_OK ||
        matter_tlv_next(&r,&e)!=MATTER_TLV_OK || e.type!=MATTER_TLV_STRUCTURE || e.tag.control) return MATTER_IM_INVALID_COMMAND;
    while(matter_tlv_next(&r,&e)==MATTER_TLV_OK) {
        if(e.type==MATTER_TLV_END) return (seen&(cmd==6?29u:1u))==(cmd==6?29u:1u) && matter_tlv_next(&r,&e)==MATTER_TLV_DONE?0:MATTER_IM_INVALID_COMMAND;
        if(e.tag.control!=1 || e.tag.number>(cmd==11?0u:cmd==7?1u:4u)) {
            if((e.type==MATTER_TLV_STRUCTURE || e.type==MATTER_TLV_ARRAY || e.type==MATTER_TLV_LIST) && matter_tlv_skip_container(&r)!=MATTER_TLV_OK) return MATTER_IM_INVALID_COMMAND;
            continue;
        }
        unsigned id=e.tag.number; if(seen&(1u<<id)) return MATTER_IM_INVALID_COMMAND; seen|=1u<<id;
        if(id<=2) {
            if(e.type!=MATTER_TLV_BYTES || (id==2?e.size!=16:e.size>400) || (!id && !e.size)) return MATTER_IM_INVALID_COMMAND;
            if(a) {
                if(id==0) a->noc=(Matter_Cert_Tlv_T){e.data,e.size};
                if(id==1) a->icac=(Matter_Cert_Tlv_T){e.size?e.data:NULL,e.size};
                if(id==2) memcpy(a->ipk,e.data,16);
            }
            if(root) *root=(Matter_Cert_Tlv_T){e.data,e.size};
        } else {
            if(e.type!=MATTER_TLV_UNSIGNED) return MATTER_IM_INVALID_COMMAND;
            if(id==4 && (!e.unsigned_value || e.unsigned_value>0xfff4)) return MATTER_IM_CONSTRAINT_ERROR;
            if(a) { if(id==3) a->admin_subject=e.unsigned_value; else a->vendor=(uint16_t)e.unsigned_value; }
        }
    }
    return MATTER_IM_INVALID_COMMAND;
}
static uint8_t management_args(uint32_t cmd,const uint8_t* p,size_t n,const uint8_t** label,size_t* length,uint8_t* index) {
    Matter_Tlv_Reader_T r; Matter_Tlv_Element_T e; bool seen=false;
    if(n>1024 || matter_tlv_init(&r,p,n,4)!=MATTER_TLV_OK || matter_tlv_next(&r,&e)!=MATTER_TLV_OK ||
        e.type!=MATTER_TLV_STRUCTURE || e.tag.control) return MATTER_IM_INVALID_COMMAND;
    while(matter_tlv_next(&r,&e)==MATTER_TLV_OK) {
        if(e.type==MATTER_TLV_END) return seen && matter_tlv_next(&r,&e)==MATTER_TLV_DONE?0:MATTER_IM_INVALID_COMMAND;
        if(e.tag.control==1 && !e.tag.number) {
            if(seen) return MATTER_IM_INVALID_COMMAND;
            seen=true;
            if(cmd==9) {
                if(e.type!=MATTER_TLV_UTF8) return MATTER_IM_INVALID_COMMAND;
                if(e.size>32 || !valid_utf8(e.data,e.size)) return MATTER_IM_CONSTRAINT_ERROR;
                if(label) { *label=e.data; *length=e.size; }
            } else {
                if(e.type!=MATTER_TLV_UNSIGNED) return MATTER_IM_INVALID_COMMAND;
                if(!e.unsigned_value || e.unsigned_value>254) return MATTER_IM_CONSTRAINT_ERROR;
                if(index) *index=(uint8_t)e.unsigned_value;
            }
        } else if((e.type==MATTER_TLV_STRUCTURE || e.type==MATTER_TLV_ARRAY || e.type==MATTER_TLV_LIST) && matter_tlv_skip_container(&r)!=MATTER_TLV_OK) return MATTER_IM_INVALID_COMMAND;
    }
    return MATTER_IM_INVALID_COMMAND;
}
static uint8_t vid_args(uint32_t cmd,const uint8_t* p,size_t n,Matter_Fabric_Vid_T* a,uint8_t* index,const uint8_t** nonce) {
    Matter_Tlv_Reader_T r; Matter_Tlv_Element_T e; unsigned seen=0;
    if(n>1024 || matter_tlv_init(&r,p,n,4)!=MATTER_TLV_OK || matter_tlv_next(&r,&e)!=MATTER_TLV_OK ||
        e.type!=MATTER_TLV_STRUCTURE || e.tag.control) return MATTER_IM_INVALID_COMMAND;
    while(matter_tlv_next(&r,&e)==MATTER_TLV_OK) {
        if(e.type==MATTER_TLV_END) return (cmd==12?seen!=0:seen==3) && matter_tlv_next(&r,&e)==MATTER_TLV_DONE?0:MATTER_IM_INVALID_COMMAND;
        if(e.tag.control!=1 || e.tag.number>(cmd==12?2u:1u)) {
            if((e.type==MATTER_TLV_STRUCTURE || e.type==MATTER_TLV_ARRAY || e.type==MATTER_TLV_LIST) && matter_tlv_skip_container(&r)!=MATTER_TLV_OK) return MATTER_IM_INVALID_COMMAND;
            continue;
        }
        unsigned id=e.tag.number; if(seen&(1u<<id)) return MATTER_IM_INVALID_COMMAND; seen|=1u<<id;
        if(!id) {
            if(e.type!=MATTER_TLV_UNSIGNED) return MATTER_IM_INVALID_COMMAND;
            if(!e.unsigned_value || e.unsigned_value>(cmd==12?0xfff4u:254u)) return MATTER_IM_CONSTRAINT_ERROR;
            if(a) { a->vendor_present=true; a->vendor=(uint16_t)e.unsigned_value; }
            if(index) *index=(uint8_t)e.unsigned_value;
        } else {
            if(e.type!=MATTER_TLV_BYTES) return MATTER_IM_INVALID_COMMAND;
            if(cmd==13?e.size!=32:id==1?(e.size!=0 && e.size!=85):e.size>400) return MATTER_IM_CONSTRAINT_ERROR;
            if(a) {
                if(id==1) { a->vvs_present=true; a->vvs=(Matter_Cert_Tlv_T){e.data,e.size}; }
                else { a->vvsc_present=true; a->vvsc=(Matter_Cert_Tlv_T){e.data,e.size}; }
            }
            if(nonce) *nonce=e.data;
        }
    }
    return MATTER_IM_INVALID_COMMAND;
}
uint8_t matter_fabric_vid(Matter_Fabric_T m,uint8_t accessing,uint32_t cmd,const uint8_t* p,size_t n,
    const uint8_t challenge[16],uint8_t* target,uint8_t signature[64]) {
    if(!m || m->busy || (cmd!=12 && cmd!=13) || !challenge || !target || !signature) return MATTER_IM_FAILURE;
    Matter_Fabric_Vid_T a={0}; const uint8_t* nonce=NULL; *target=accessing;
    uint8_t status=vid_args(cmd,p,n,&a,cmd==13?target:NULL,&nonce); if(status) return status;
    const Matter_Fabric_View_T* v=m->port.view(m->port.user); const Matter_Fabric_Record_T* f=NULL;
    for(unsigned i=0;i<MATTER_FABRIC_CAPACITY;++i) if(*target && v->records[i].index==*target) f=&v->records[i];
    if(!f) return MATTER_IM_CONSTRAINT_ERROR;
    if(cmd==12 && a.vvsc_present && f->icac_size) return MATTER_IM_INVALID_COMMAND;
    m->busy=true; Matter_Result_T r=MATTER_INVALID_STATE;
    if(cmd==12) { if(m->port.vid) r=m->port.vid(m->port.user,accessing,&a); }
    else if(m->port.sign && (!f->vvs_size || f->vvs_size==85)) {
        /* Core 6.4.10.1 / 11.18.6.16. Heap-owned scratch; both integers BE.
         * Read and sign are one owner phase: no stale metadata/key snapshot. */
        uint8_t* b=m->encoded; b[0]=1; memcpy(b+1,nonce,32); memcpy(b+33,challenge,16);
        b[49]=*target; b[50]=1; memcpy(b+51,f->root_public,65);
        for(unsigned i=0;i<8;++i) b[116+i]=(uint8_t)(f->fabric_id>>(56-8*i));
        b[124]=(uint8_t)(f->vendor>>8); b[125]=(uint8_t)f->vendor;
        memcpy(b+126,f->vvs,f->vvs_size);
        r=m->port.sign(m->port.user,*target,b,126+f->vvs_size,signature);
        erase(b,211);
    }
    m->busy=false; if(r!=MATTER_OK) { erase(signature,64); return MATTER_IM_FAILURE; } return 0;
}
uint8_t matter_fabric_validate(uint32_t cmd,const uint8_t* p,size_t n) {
    if(cmd==12 || cmd==13) return vid_args(cmd,p,n,NULL,NULL,NULL);
    return cmd==9 || cmd==10?management_args(cmd,p,n,NULL,NULL,NULL):parse(cmd,p,n,NULL,NULL);
}
Matter_Im_Command_Result_T matter_fabric_manage(Matter_Fabric_T m,uint8_t accessing,uint32_t cmd,
    const uint8_t* data,size_t n,uint8_t* status,uint8_t* index) {
    Matter_Im_Command_Result_T result={0}; const uint8_t* label=NULL; size_t length=0;
    *status=0; *index=accessing;
    if(!m || m->busy || (cmd!=9 && cmd!=10)) { result.status=MATTER_IM_FAILURE; return result; }
    result.status=management_args(cmd,data,n,&label,&length,index); if(result.status) return result;
    const Matter_Fabric_View_T* v=m->port.view(m->port.user); bool found=false;
    for(unsigned i=0;i<MATTER_FABRIC_CAPACITY;++i) {
        const Matter_Fabric_Record_T* f=&v->records[i]; if(!f->index) continue;
        found|=f->index==*index;
        if(cmd==9 && f->index!=accessing && f->label_size==length && (!length || !memcmp(f->label,label,length))) *status=10;
    }
    if(!found) *status=11;
    if(*status) return result;
    m->busy=true;
    Matter_Result_T r=cmd==9?(m->port.label?m->port.label(m->port.user,*index,label,length):MATTER_INVALID_STATE):
        (m->port.remove?m->port.remove(m->port.user,*index):MATTER_INVALID_STATE);
    m->busy=false; if(r!=MATTER_OK) result.status=MATTER_IM_FAILURE; return result;
}
Matter_Im_Command_Result_T matter_fabric_execute(Matter_Fabric_T m,Matter_Exchange_Session_T session,
    uint32_t cmd,uint64_t candidate,const uint8_t* data,size_t n,uint8_t* status,uint8_t* index) {
    Matter_Im_Command_Result_T result={0}; *status=0; *index=0;
    if(!m || m->busy || !session) { result.status=MATTER_IM_FAILURE; return result; }
    Matter_Fabric_Add_T a={0}; Matter_Cert_Tlv_T root={0};
    result.status=parse(cmd,data,n,&a,&root); if(result.status) { erase(&a,sizeof(a)); return result; }
    m->busy=true;
    const Matter_Fabric_View_T* v=m->port.view(m->port.user);
    if(v->added) result.status=MATTER_IM_CONSTRAINT_ERROR;
    else if(cmd==11) {
        if(v->root_ready && (v->root_size!=root.size || memcmp(v->root,root.data,root.size))) result.status=MATTER_IM_CONSTRAINT_ERROR;
        else result.status=m->port.root(m->port.user,root);
    } else if(v->count==MATTER_FABRIC_CAPACITY) *status=5;
    else if(!candidate) *status=4;
    else if(!v->root_ready) *status=3;
    else if(!(a.admin_subject && a.admin_subject<=UINT64_C(0xffffffefffffffff)) &&
        !((a.admin_subject>>32)==UINT64_C(0xfffffffd) && (a.admin_subject&0xffff))) *status=6;
    else if(m->port.install(m->port.user,session,candidate,&a,status,index)!=MATTER_OK) result.status=MATTER_IM_FAILURE;
    erase(&a,sizeof(a)); m->busy=false; return result;
}
Matter_Im_Command_Result_T matter_fabric_update(Matter_Fabric_T m,Matter_Exchange_Session_T session,
    uint8_t accessing,uint64_t candidate,const uint8_t* data,size_t n,uint8_t* status,uint8_t* index) {
    Matter_Im_Command_Result_T result={0}; *status=0; *index=accessing;
    if(!m || m->busy || !session || !accessing || !m->port.update) { result.status=MATTER_IM_FAILURE; return result; }
    Matter_Fabric_Add_T a={0}; result.status=parse(7,data,n,&a,NULL); if(result.status) return result;
    const Matter_Fabric_View_T* v=m->port.view(m->port.user);
    if(v->added || v->root_ready) result.status=MATTER_IM_CONSTRAINT_ERROR;
    else if(!candidate) *status=4;
    else {
        m->busy=true;
        if(m->port.update(m->port.user,session,accessing,candidate,a.noc,a.icac,status)!=MATTER_OK) result.status=MATTER_IM_FAILURE;
        m->busy=false;
    }
    return result;
}
Matter_Result_T matter_fabric_rollback(Matter_Fabric_T m) {
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    m->busy=true; Matter_Result_T r=m->port.rollback(m->port.user); m->busy=false; return r;
}
static bool put(Matter_Fabric_T m,Matter_Tlv_Type_T t,int tag,uint64_t val,const uint8_t* p,size_t n) {
    m->e=(Matter_Tlv_Element_T){.type=t,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=val,.data=p,.size=n};
    return matter_tlv_write(&m->writer,&m->e,0)==MATTER_TLV_OK;
}
#define P(t,tag,v) put(m,t,tag,v,NULL,0)
#define B(tag,p,n) put(m,MATTER_TLV_BYTES,tag,0,p,n)
uint8_t matter_fabric_read_index(Matter_Fabric_T m,uint32_t attr,uint8_t accessing,bool filtered,Matter_Im_Value_T* out) {
    if(!m || !out || m->busy) return MATTER_IM_FAILURE;
    if(attr>5) return MATTER_IM_UNSUPPORTED_ATTRIBUTE;
    const Matter_Fabric_View_T* v=m->port.view(m->port.user);
    *out=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED};
    if(attr==2) { out->unsigned_value=MATTER_FABRIC_CAPACITY; return 0; }
    if(attr==3) { out->unsigned_value=v->count; return 0; }
    if(attr==5) { out->unsigned_value=accessing; return 0; }
    /* NOCs/Fabrics are fabric-scoped, not fabric-sensitive. Before AddNOC,
     * index 0 matches no entry when filtered, and unfiltered reads show all. */
    if(matter_tlv_writer_init(&m->writer,m->encoded,sizeof(m->encoded),3)!=MATTER_TLV_OK || !P(MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
    bool root_seen=false;
    for(unsigned i=0;i<MATTER_FABRIC_CAPACITY;++i) {
        const Matter_Fabric_Record_T* f=&v->records[i]; if(!f->index) continue;
        if(attr==4) { if(!B(-1,f->root,f->root_size)) return MATTER_IM_FAILURE;
            if(f->root_size==v->root_size && !memcmp(f->root,v->root,v->root_size)) root_seen=true;
            continue;
        }
        if(filtered && f->index!=accessing) continue;
        if(!P(MATTER_TLV_STRUCTURE,-1,0)) return MATTER_IM_FAILURE;
        if(!attr) {
            if(!B(1,f->noc,f->noc_size) || (f->icac_size?!B(2,f->icac,f->icac_size):!P(MATTER_TLV_NULL,2,0))) return MATTER_IM_FAILURE;
            if(f->vvsc_size && !B(3,f->vvsc,f->vvsc_size)) return MATTER_IM_FAILURE;
        } else if(!B(1,f->root_public,65) || !P(MATTER_TLV_UNSIGNED,2,f->vendor) ||
            !P(MATTER_TLV_UNSIGNED,3,f->fabric_id) || !P(MATTER_TLV_UNSIGNED,4,f->node_id) ||
            !put(m,MATTER_TLV_UTF8,5,0,f->label,f->label_size)) return MATTER_IM_FAILURE;
        if(attr==1 && f->vvs_size && !B(6,f->vvs,f->vvs_size)) return MATTER_IM_FAILURE;
        if(!P(MATTER_TLV_UNSIGNED,254,f->index) || !P(MATTER_TLV_END,-1,0)) return MATTER_IM_FAILURE;
    }
    if(attr==4 && v->root_ready && !root_seen && !B(-1,v->root,v->root_size)) return MATTER_IM_FAILURE;
    if(!P(MATTER_TLV_END,-1,0) || matter_tlv_writer_finish(&m->writer,&out->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    out->type=MATTER_TLV_ARRAY; out->data=m->encoded; return 0;
}

uint8_t matter_fabric_read(Matter_Fabric_T m,uint32_t attr,Matter_Exchange_Session_T session,bool filtered,Matter_Im_Value_T* out) {
    if(!m || !out || m->busy) return MATTER_IM_FAILURE;
    if(attr>5) return MATTER_IM_UNSUPPORTED_ATTRIBUTE;
    return matter_fabric_read_index(m,attr,matter_fabric_index(m,session),filtered,out);
}
