#include "matter_acl.h"
#include "../codec/matter_tlv_validate.h"
#include "../codec/matter_tlv_internal.h"
#include "../model/matter_cluster_internal.h"
#include <stdlib.h>
#include <string.h>
const uint32_t matter_acl_attributes[MATTER_ACL_ATTRIBUTES]={0,2,3,4,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
typedef struct Matter_Acl* Acl;
static Matter_Result_T destroy(void*);
static Matter_Cluster_T interface_new(Acl);
static uint8_t prepare_events(Acl,const Matter_Cluster_Request_T*,Matter_Im_List_Change_T,size_t*);
struct Matter_Acl {
    Matter_Cluster_T interface;
    Matter_Acl_Port_T port; bool busy,added_prepared;
    Matter_Acl_Events_Port_T events;
    Matter_Event_Record_T changes[MATTER_ACL_ENTRIES];
    Matter_Acl_Entry_T pending[MATTER_ACL_ENTRIES]; size_t count;
    Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T token;
    Matter_Tlv_Validation_Workspace_T validation; Matter_Tlv_Tag_T tags[64];
    Matter_Tlv_Writer_T writer; uint8_t* encoded;
};
/* IM copies provider bytes synchronously. Keep the last borrow through
 * validation/store (including read-then-write aliasing), until another read. */
static void clear_encoded(Acl m) { free(m->encoded); m->encoded=NULL; }
Matter_Result_T matter_acl_bind_events(Matter_Acl_T handle,const Matter_Acl_Events_Port_T* p) {
    Acl m=matter_cluster_context(handle,destroy);
    if(!m || !p || !p->log || !p->now) return MATTER_INVALID_ARGUMENT;
    if(m->busy || matter_cluster_in_use(handle)) return MATTER_BUSY;
    if(m->events.log) return MATTER_INVALID_STATE;
    m->events=*p; return MATTER_OK;
}
static const Matter_Acl_Fabric_T* fabric(const Matter_Acl_View_T* v,uint8_t index) {
    if(!v || !index || index==255) return NULL;
    for(unsigned i=0;i<MATTER_ACL_FABRICS;++i) if(v->fabrics[i].index==index) return &v->fabrics[i];
    return NULL;
}
static bool privilege(uint64_t v) { return v==1 || v==3 || v==4 || v==5; }
static bool subject(uint64_t v,uint8_t mode) {
    if(mode==3) return v && v<=UINT16_MAX;
    return (v && v<=UINT64_C(0xffffffefffffffff)) ||
        ((v>>32)==UINT64_C(0xfffffffd) && ((v>>16)&0xffff) && (v&0xffff));
}
Matter_Cluster_T matter_acl_new(const Matter_Acl_Port_T* p) {
    if(!p || !p->view || !p->store || !p->view(p->user)) return NULL;
    Acl m=calloc(1,sizeof(*m)); if(!m) return NULL; m->port=*p;
    m->interface=interface_new(m); if(!m->interface) { free(m); return NULL; } return m->interface;
}
static Matter_Result_T destroy(void* ctx) {
    Acl m=ctx;
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    clear_encoded(m);
    memset(m,0,sizeof(*m)); free(m); return MATTER_OK;
}
uint32_t matter_acl_version(Matter_Acl_T handle) {
    Acl m=matter_cluster_context(handle,destroy); return m?m->port.view(m->port.user)->version:0; }
static bool next(Acl m) { return matter_tlv_next(&m->reader,&m->token)==MATTER_TLV_OK; }
static bool skip(Acl m) {
    Matter_Tlv_Type_T t=m->token.type;
    return (t!=MATTER_TLV_STRUCTURE && t!=MATTER_TLV_ARRAY && t!=MATTER_TLV_LIST) || matter_tlv_skip_container(&m->reader)==MATTER_TLV_OK;
}
/* Core 1.6.1 7.19.2.27 and 7.21.2: validate identifiers, not whether a
 * currently installed endpoint/cluster/device type matches the target. */
static bool target_id(unsigned tag,uint64_t value) {
    if(tag==1) return value<UINT16_MAX;
    if(value>UINT32_MAX) return false;
    uint32_t vendor=(uint32_t)(value>>16),id=(uint32_t)value&0xffff;
    if(vendor>0xfff4) return false;
    return tag==2?id<=0xbfff:vendor?(id>=0xfc00 && id<=0xfffe):id<=0x7fff;
}
static uint8_t target(Acl m,Matter_Acl_Target_T* t) {
    if(m->token.type!=MATTER_TLV_STRUCTURE || m->token.tag.control) return MATTER_IM_INVALID_DATA_TYPE;
    unsigned seen=0;
    while(next(m)) {
        if(m->token.type==MATTER_TLV_END) return seen==7 && t->present && (t->present&6)!=6?0:MATTER_IM_CONSTRAINT_ERROR;
        if(m->token.tag.control!=1) return MATTER_IM_CONSTRAINT_ERROR;
        unsigned tag=m->token.tag.number;
        if(tag>2) { if(!skip(m)) return MATTER_IM_CONSTRAINT_ERROR; continue; }
        if(seen&(1u<<tag)) return MATTER_IM_CONSTRAINT_ERROR;
        seen|=1u<<tag;
        if(m->token.type==MATTER_TLV_NULL) continue;
        if(m->token.type!=MATTER_TLV_UNSIGNED) return MATTER_IM_INVALID_DATA_TYPE;
        if(!target_id(tag,m->token.unsigned_value)) return MATTER_IM_CONSTRAINT_ERROR;
        t->present|=(uint8_t)(1u<<tag);
        if(tag==0) t->cluster=(uint32_t)m->token.unsigned_value;
        if(tag==1) t->endpoint=(uint16_t)m->token.unsigned_value;
        if(tag==2) t->device_type=(uint32_t)m->token.unsigned_value;
    }
    return MATTER_IM_CONSTRAINT_ERROR;
}
static uint8_t entry(Acl m,Matter_Acl_Entry_T* a) {
    if(m->token.type!=MATTER_TLV_STRUCTURE || m->token.tag.control) return MATTER_IM_INVALID_DATA_TYPE;
    unsigned seen=0;
    while(next(m)) {
        if(m->token.type==MATTER_TLV_END) {
            if(seen!=30 || !privilege(a->privilege) || (a->auth_mode!=2 && a->auth_mode!=3) ||
                (a->auth_mode==3 && a->privilege==5)) return MATTER_IM_CONSTRAINT_ERROR;
            for(unsigned i=0;i<a->subject_count;++i) if(!subject(a->subjects[i],a->auth_mode)) return MATTER_IM_CONSTRAINT_ERROR;
            return 0;
        }
        if(m->token.tag.control!=1) return MATTER_IM_CONSTRAINT_ERROR;
        unsigned tag=m->token.tag.number;
        if(tag==5) return MATTER_IM_CONSTRAINT_ERROR; /* AuxiliaryType forbidden in ACL. */
        if(tag<1 || tag>4) { if(!skip(m)) return MATTER_IM_CONSTRAINT_ERROR; continue; } /* Includes FabricIndex. */
        if(seen&(1u<<tag)) return MATTER_IM_CONSTRAINT_ERROR;
        seen|=1u<<tag;
        if(tag<3) {
            if(m->token.type!=MATTER_TLV_UNSIGNED) return MATTER_IM_INVALID_DATA_TYPE;
            if(m->token.unsigned_value>255) return MATTER_IM_CONSTRAINT_ERROR;
            if(tag==1) a->privilege=(uint8_t)m->token.unsigned_value; else a->auth_mode=(uint8_t)m->token.unsigned_value;
            continue;
        }
        if(m->token.type==MATTER_TLV_NULL) { if(tag==3) a->subjects_null=true; else a->targets_null=true; continue; }
        if(m->token.type!=MATTER_TLV_ARRAY) return MATTER_IM_INVALID_DATA_TYPE;
        while(next(m) && m->token.type!=MATTER_TLV_END) {
            if(tag==3) {
                if(a->subject_count==MATTER_ACL_SUBJECTS) return MATTER_IM_RESOURCE_EXHAUSTED;
                if(m->token.type!=MATTER_TLV_UNSIGNED || m->token.tag.control) return MATTER_IM_INVALID_DATA_TYPE;
                a->subjects[a->subject_count++]=m->token.unsigned_value;
            } else {
                if(a->target_count==MATTER_ACL_TARGETS) return MATTER_IM_RESOURCE_EXHAUSTED;
                uint8_t r=target(m,&a->targets[a->target_count++]); if(r) return r;
            }
        }
        if(m->token.type!=MATTER_TLV_END) return MATTER_IM_CONSTRAINT_ERROR;
    }
    return MATTER_IM_CONSTRAINT_ERROR;
}
static uint8_t parse(Acl m,uint8_t index,Matter_Im_List_Change_T change,const uint8_t* data,size_t size) {
    const Matter_Acl_Fabric_T* f=fabric(m->port.view(m->port.user),index);
    if(!f) return MATTER_IM_UNSUPPORTED_ACCESS;
    if(change!=MATTER_IM_LIST_REPLACE && change!=MATTER_IM_LIST_ADD) return MATTER_IM_INVALID_ACTION;
    const Matter_Tlv_Validation_Options_T opt={1024,256,2048,4,false,0,0}; Matter_Tlv_Validation_Report_T report;
    Matter_Tlv_Result_T vr=matter_tlv_validate(data,size,&opt,&m->validation,m->tags,64,&report);
    if(vr!=MATTER_TLV_OK) return vr==MATTER_TLV_LIMIT_REACHED || vr==MATTER_TLV_DEPTH_LIMIT?MATTER_IM_RESOURCE_EXHAUSTED:MATTER_IM_CONSTRAINT_ERROR;
    memset(m->pending,0,sizeof(m->pending)); m->count=0;
    if(matter_tlv_init(&m->reader,data,size,4)!=MATTER_TLV_OK || !next(m) || m->token.tag.control) return MATTER_IM_INVALID_DATA_TYPE;
    if(change==MATTER_IM_LIST_ADD) {
        if(f->count>=MATTER_ACL_ENTRIES) return MATTER_IM_RESOURCE_EXHAUSTED;
        memcpy(m->pending,f->entries,f->count*sizeof(*m->pending)); m->count=f->count;
        uint8_t r=entry(m,&m->pending[m->count++]); if(r) return r;
    } else {
        if(m->token.type!=MATTER_TLV_ARRAY) return MATTER_IM_INVALID_DATA_TYPE;
        while(next(m) && m->token.type!=MATTER_TLV_END) {
            if(m->count==MATTER_ACL_ENTRIES) return MATTER_IM_RESOURCE_EXHAUSTED;
            uint8_t r=entry(m,&m->pending[m->count++]); if(r) return r;
        }
        if(m->token.type!=MATTER_TLV_END) return MATTER_IM_CONSTRAINT_ERROR;
    }
    return matter_tlv_next(&m->reader,&m->token)==MATTER_TLV_DONE?0:MATTER_IM_CONSTRAINT_ERROR;
}
uint8_t matter_acl_validate(Matter_Acl_T handle,uint8_t index,Matter_Im_List_Change_T c,const uint8_t* p,size_t n) {
    Acl m=matter_cluster_context(handle,destroy);
    if(!m || m->busy) return MATTER_IM_FAILURE;
    m->busy=true; uint8_t r=parse(m,index,c,p,n); m->busy=false; return r;
}
static uint8_t write_entries(Matter_Acl_T handle,uint8_t index,Matter_Im_List_Change_T c,const uint8_t* p,size_t n,const Matter_Cluster_Request_T* q) {
    Acl m=matter_cluster_context(handle,destroy);
    if(!m || m->busy) return MATTER_IM_FAILURE;
    m->busy=true; uint8_t r=parse(m,index,c,p,n);
    size_t events=0;
    if(!r && q && m->events.log) r=prepare_events(m,q,c,&events);
    if(!r) r=m->port.store(m->port.user,index,m->pending,m->count);
    if(events) matter_events_finish(m->events.log,!r);
    m->busy=false; return r;
}
uint8_t matter_acl_write(Matter_Acl_T h,uint8_t i,Matter_Im_List_Change_T c,const uint8_t* p,size_t n) {
    return write_entries(h,i,c,p,n,NULL);
}
static bool put(Acl m,Matter_Tlv_Type_T t,int tag,uint64_t v) {
    m->token=(Matter_Tlv_Element_T){.type=t,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=v};
    return matter_tlv_write(&m->writer,&m->token,0)==MATTER_TLV_OK;
}
#define P(t,tag,v) put(m,t,tag,v)
#define U(tag,v) P(MATTER_TLV_UNSIGNED,tag,v)
#define END() P(MATTER_TLV_END,-1,0)
static bool encode_entry(Acl m,const Matter_Acl_Entry_T* a,uint8_t index,int tag) {
    if(!P(MATTER_TLV_STRUCTURE,tag,0) || !U(1,a->privilege) || !U(2,a->auth_mode)) return false;
    if(!P(a->subjects_null?MATTER_TLV_NULL:MATTER_TLV_ARRAY,3,0)) return false;
    if(!a->subjects_null) {
        for(unsigned i=0;i<a->subject_count;++i) if(!U(-1,a->subjects[i])) return false;
        if(!END()) return false;
    }
    if(!P(a->targets_null?MATTER_TLV_NULL:MATTER_TLV_ARRAY,4,0)) return false;
    if(!a->targets_null) {
        for(unsigned i=0;i<a->target_count;++i) {
            const Matter_Acl_Target_T* t=&a->targets[i];
            if(!P(MATTER_TLV_STRUCTURE,-1,0) || !P(t->present&1?MATTER_TLV_UNSIGNED:MATTER_TLV_NULL,0,t->cluster) ||
                !P(t->present&2?MATTER_TLV_UNSIGNED:MATTER_TLV_NULL,1,t->endpoint) ||
                !P(t->present&4?MATTER_TLV_UNSIGNED:MATTER_TLV_NULL,2,t->device_type) || !END()) return false;
        }
        if(!END()) return false;
    }
    return U(254,index) && END();
}
static bool encode_change(Acl m,Matter_Event_Record_T* e,const Matter_Cluster_Request_T* q,const Matter_Acl_Entry_T* entry,uint8_t change,uint64_t now) {
    memset(e,0,sizeof(*e)); e->path=(Matter_Event_Path_T){0,MATTER_ACL_CLUSTER,0};
    e->priority=1; e->fabric=q->fabric; e->timestamp_ms=now;
    return matter_tlv_writer_init(&m->writer,e->data,sizeof(e->data),4)==MATTER_TLV_OK &&
        P(MATTER_TLV_STRUCTURE,-1,0) && P(q->is_case?MATTER_TLV_UNSIGNED:MATTER_TLV_NULL,1,q->peer_node) &&
        P(q->is_case?MATTER_TLV_NULL:MATTER_TLV_UNSIGNED,2,0) && U(3,change) &&
        encode_entry(m,entry,q->fabric,4) && U(254,q->fabric) && END() && matter_tlv_writer_finish(&m->writer,&e->size)==MATTER_TLV_OK;
}
Matter_Result_T matter_acl_prepare_added(Matter_Acl_T handle,const Matter_Cluster_Request_T* q,const Matter_Acl_Entry_T* entry) {
    Acl m=matter_cluster_context(handle,destroy);
    if(!m || !q || !entry || !q->fabric || q->fabric==255 || (q->is_case && (!q->peer_node || q->peer_node>UINT64_C(0xffffffefffffffff)))) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(!m->events.log) return MATTER_INVALID_STATE;
    m->busy=true;
    Matter_Result_T r=encode_change(m,&m->changes[0],q,entry,1,m->events.now(m->events.user))?
        matter_events_prepare(m->events.log,m->changes,1):MATTER_LIMIT_REACHED;
    m->added_prepared=r==MATTER_OK; m->busy=m->added_prepared; return r;
}
void matter_acl_finish_added(Matter_Acl_T handle,bool commit) {
    Acl m=matter_cluster_context(handle,destroy); if(!m || !m->added_prepared) return;
    matter_events_finish(m->events.log,commit); m->added_prepared=m->busy=false;
}
static uint8_t prepare_events(Acl m,const Matter_Cluster_Request_T* q,Matter_Im_List_Change_T change,size_t* count) {
    if(!q->is_case || !q->peer_node || q->peer_node>UINT64_C(0xffffffefffffffff)) return MATTER_IM_UNSUPPORTED_ACCESS;
    const Matter_Acl_Fabric_T* old=fabric(m->port.view(m->port.user),q->fabric);
    uint64_t now=m->events.now(m->events.user); size_t n=0;
    for(size_t i=0;i<old->count || i<m->count;++i) {
        bool added=i>=old->count,removed=i>=m->count;
        /* REPLACE rewrites each retained entry (Changed), including equal
         * values; ADD touches only the appended entry. Core 9.10.9.1 and
         * the operation-based expectations of CSA TC_ACL_2_6. */
        if(change==MATTER_IM_LIST_ADD && !added) continue;
        if(!encode_change(m,&m->changes[n++],q,removed?&old->entries[i]:&m->pending[i],added?1:removed?2:0,now)) return MATTER_IM_RESOURCE_EXHAUSTED;
    }
    if(n) {
        Matter_Result_T r=matter_events_prepare(m->events.log,m->changes,n);
        if(r!=MATTER_OK) return r==MATTER_LIMIT_REACHED?MATTER_IM_RESOURCE_EXHAUSTED:MATTER_IM_FAILURE;
        *count=n;
    }
    return 0;
}
uint8_t matter_acl_read(Matter_Acl_T m,uint32_t attr,uint8_t index,bool filtered,Matter_Im_Value_T* out) {
    if(!matter_cluster_context(m,destroy)) return MATTER_IM_FAILURE;
    Matter_Cluster_Request_T q={.fabric=index,.filtered=filtered}; return matter_cluster_read(m,attr,&q,out);
}
bool matter_acl_grants(const Matter_Acl_View_T* v,uint8_t index,uint64_t node,const uint32_t* cats,size_t count,
    const Matter_Im_Path_T* p,Matter_Im_Privilege_T required,const Matter_Acl_Device_Port_T* devices) {
    const Matter_Acl_Fabric_T* f=fabric(v,index);
    if(!f || !node || node>UINT64_C(0xffffffefffffffff) || count>3 || (count && !cats) || !privilege(required)) return false;
    for(unsigned i=0;i<f->count;++i) {
        const Matter_Acl_Entry_T* a=&f->entries[i]; if(a->auth_mode!=2 || a->privilege<required) continue;
        bool matches=!a->subject_count;
        for(unsigned j=0;j<a->subject_count;++j) {
            uint64_t s=a->subjects[j]; if(s==node) matches=true;
            if((s>>32)==UINT64_C(0xfffffffd)) for(size_t k=0;k<count;++k)
                if((cats[k]>>16)==((uint32_t)s>>16) && (cats[k]&0xffff)>=(s&0xffff)) matches=true;
        }
        if(!matches) continue;
        if(!a->target_count) return true;
        if(!p) continue;
        for(unsigned j=0;j<a->target_count;++j) {
            const Matter_Acl_Target_T* t=&a->targets[j];
            if((t->present&1) && t->cluster!=p->cluster) continue;
            if((t->present&2) && t->endpoint!=p->endpoint) continue;
            if((t->present&4) && (!devices || !devices->contains || !devices->contains(devices->user,p->endpoint,t->device_type))) continue;
            return true;
        }
    }
    return false;
}
bool matter_acl_authorize(Matter_Acl_T handle,uint8_t i,uint64_t n,const uint32_t* c,size_t count,
    const Matter_Im_Path_T* p,Matter_Im_Privilege_T v,const Matter_Acl_Device_Port_T* d) {
    Acl m=matter_cluster_context(handle,destroy);
    if(!m || m->busy) return false;
    m->busy=true; bool allowed=matter_acl_grants(m->port.view(m->port.user),i,n,c,count,p,v,d); m->busy=false; return allowed;
}

Matter_Result_T matter_acl_delete(Matter_Acl_T m) {
    if(!matter_cluster_context(m,destroy)) return MATTER_INVALID_ARGUMENT;
    return matter_cluster_delete(m);
}

static Matter_Result_T cluster_version(void* u,uint32_t* out) { Acl m=u; *out=m->port.view(m->port.user)->version; return MATTER_OK; }
static uint8_t read_scalar(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* out) {
    (void)q; Acl m=u; if(m->busy) return MATTER_IM_FAILURE;
    m->busy=true; clear_encoded(m);
    *out=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=*(const uint32_t*)ref,.data_version=m->port.view(m->port.user)->version};
    m->busy=false; return 0;
}
static bool encode_entries(Acl m,const Matter_Acl_View_T* v,const void* ref,const Matter_Cluster_Request_T* q) {
    (void)ref;
    if(!P(MATTER_TLV_ARRAY,-1,0)) return false;
    for(unsigned i=0;i<MATTER_ACL_FABRICS;++i) {
        const Matter_Acl_Fabric_T* f=&v->fabrics[i]; if(!f->index || (q->filtered && f->index!=q->fabric)) continue;
        for(unsigned j=0;j<f->count;++j) {
            /* All ACL entry fields except FabricIndex are fabric-sensitive.
             * Core 8.4.3.3 requires omission, not null/zero substitutes. */
            bool ok=f->index==q->fabric?encode_entry(m,&f->entries[j],f->index,-1):
                P(MATTER_TLV_STRUCTURE,-1,0) && U(254,f->index) && END();
            if(!ok) return false;
        }
    }
    return END();
}
static bool encode_ids(Acl m,const Matter_Acl_View_T* v,const void* ref,const Matter_Cluster_Request_T* q) {
    (void)v; (void)q;
    if(!P(MATTER_TLV_ARRAY,-1,0)) return false;
    if(ref) for(unsigned i=0;i<MATTER_ACL_ATTRIBUTES;++i) if(!U(-1,matter_acl_attributes[i])) return false;
    return END();
}
typedef bool (*Encode_Value)(Acl,const Matter_Acl_View_T*,const void*,const Matter_Cluster_Request_T*);
static uint8_t read_encoded(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* out,
    bool scoped,uint8_t depth,Encode_Value encode) {
    Acl m=u; if(m->busy) return MATTER_IM_FAILURE;
    m->busy=true;
    const Matter_Acl_View_T* v=m->port.view(m->port.user);
    uint8_t result=MATTER_IM_UNSUPPORTED_ACCESS; size_t size=0,written=0;
    if(scoped && !fabric(v,q->fabric)) goto done;
    clear_encoded(m);
    *out=(Matter_Im_Value_T){.type=MATTER_TLV_ARRAY,.data_version=v->version}; result=MATTER_IM_FAILURE;
    /* The owner serializes the stable validated view. Both pure passes keep
     * the original TLV budget/depth, without another view/store callback. */
    if(matter_tlv_measure_init(&m->writer,4096,depth)!=MATTER_TLV_OK || !encode(m,v,ref,q) ||
        matter_tlv_writer_finish(&m->writer,&size)!=MATTER_TLV_OK) goto failed;
    m->encoded=calloc(1,size);
    if(!m->encoded) { result=MATTER_IM_RESOURCE_EXHAUSTED; goto failed; }
    if(matter_tlv_writer_init(&m->writer,m->encoded,size,depth)!=MATTER_TLV_OK || !encode(m,v,ref,q) ||
        matter_tlv_writer_finish(&m->writer,&written)!=MATTER_TLV_OK || written!=size) goto failed;
    out->data=m->encoded; out->size=size; result=0; goto done;
failed:
    clear_encoded(m);
done:
    m->busy=false; return result;
}
static uint8_t read_entries(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* out) {
    return read_encoded(u,ref,q,out,true,4,encode_entries);
}
static uint8_t read_ids(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* out) {
    return read_encoded(u,ref,q,out,false,1,encode_ids);
}
static uint8_t cluster_validate(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_List_Change_T c,const uint8_t* d,size_t n) {
    (void)ref; Acl m=u; return q->is_case?matter_acl_validate(m->interface,q->fabric,c,d,n):MATTER_IM_UNSUPPORTED_ACCESS;
}
static Matter_Im_Write_Result_T cluster_write(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_List_Change_T c,const uint8_t* d,size_t n) {
    (void)ref; Acl m=u; return (Matter_Im_Write_Result_T){.status=q->is_case?write_entries(m->interface,q->fabric,c,d,n,q):MATTER_IM_UNSUPPORTED_ACCESS};
}
static Matter_Cluster_T interface_new(Acl m) {
    Matter_Cluster_Config_T cfg={.id=MATTER_ACL_CLUSTER,.attributes=MATTER_ACL_ATTRIBUTES,.events=1,.callbacks={.ctx=m,.version=cluster_version,.destroy=destroy}};
    Matter_Cluster_T c=matter_cluster_new(&cfg); if(!c) return NULL;
    static const uint32_t subjects=MATTER_ACL_SUBJECTS,targets=MATTER_ACL_TARGETS,entries=MATTER_ACL_ENTRIES,zero=0,revision=3;
    static const Matter_Attribute_Def_T attrs[]={
        {.id=0,.read_access={MATTER_IM_ADMINISTER,true},.read=read_entries,
            .write_access={.privilege=MATTER_IM_ADMINISTER,.fabric_scoped=true,.list=true},.validate_list=cluster_validate,.write_list=cluster_write},
        {.id=2,.read_access={MATTER_IM_VIEW,false},.read=read_scalar,.ref=&subjects},
        {.id=3,.read_access={MATTER_IM_VIEW,false},.read=read_scalar,.ref=&targets},
        {.id=4,.read_access={MATTER_IM_VIEW,false},.read=read_scalar,.ref=&entries},
        {.id=0xfff8,.read_access={MATTER_IM_VIEW,false},.read=read_ids},
        {.id=0xfff9,.read_access={MATTER_IM_VIEW,false},.read=read_ids},
        {.id=0xfffb,.read_access={MATTER_IM_VIEW,false},.read=read_ids,.ref=matter_acl_attributes},
        {.id=0xfffc,.read_access={MATTER_IM_VIEW,false},.read=read_scalar,.ref=&zero},
        {.id=0xfffd,.read_access={MATTER_IM_VIEW,false},.read=read_scalar,.ref=&revision}
    };
    for(size_t i=0;i<sizeof(attrs)/sizeof(*attrs);++i) if(matter_cluster_add_attribute(c,&attrs[i])!=MATTER_OK) { matter_cluster_abandon(c); return NULL; }
    const Matter_Event_Def_T event={0,MATTER_IM_ADMINISTER,1,true};
    if(matter_cluster_add_event(c,&event)!=MATTER_OK) { matter_cluster_abandon(c); return NULL; }
    (void)matter_cluster_seal(c); return c;
}
