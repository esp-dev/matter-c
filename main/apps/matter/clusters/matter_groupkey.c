#include "matter_groupkey.h"
#include "../model/matter_cluster_internal.h"
#include "../codec/matter_tlv_validate.h"
#include <stdlib.h>
#include <string.h>
const uint32_t matter_groupkey_attributes[MATTER_GROUPKEY_ATTRIBUTES]={0,1,2,3,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
typedef struct Matter_Groupkey* Groupkey;
static Matter_Result_T destroy(void*);
static Matter_Cluster_T interface_new(Groupkey);
struct Matter_Groupkey {
    Matter_Cluster_T interface;
    Matter_Groupkey_Port_T port; bool busy;
    Matter_Groupkey_Set_T pending; uint8_t keys[3][16];
    Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T e;
    Matter_Tlv_Validation_Workspace_T validation; Matter_Tlv_Tag_T tags[64];
    Matter_Tlv_Writer_T writer; uint8_t encoded[64];
};
static void erase(void* p,size_t n) { volatile uint8_t* b=p; while(n--) *b++=0; }
static const Matter_Groupkey_Fabric_T* fabric(Groupkey m,uint8_t index) {
    if(!index || index==255) return NULL;
    const Matter_Groupkey_View_T* v=m->port.view(m->port.user);
    for(unsigned i=0;i<MATTER_GROUPKEY_FABRICS;++i) if(v->fabrics[i].index==index) return &v->fabrics[i];
    return NULL;
}
Matter_Cluster_T matter_groupkey_new(const Matter_Groupkey_Port_T* p) {
    if(!p || !p->view || !p->store || !p->remove || !p->view(p->user)) return NULL;
    Groupkey m=calloc(1,sizeof(*m)); if(!m) return NULL; m->port=*p;
    m->interface=interface_new(m); if(!m->interface) { erase(m,sizeof(*m)); free(m); return NULL; }
    return m->interface;
}
static Matter_Result_T destroy(void* ctx) {
    Groupkey m=ctx; if(m->busy) return MATTER_BUSY;
    erase(m,sizeof(*m)); free(m); return MATTER_OK;
}
Matter_Result_T matter_groupkey_delete(Matter_Groupkey_T m) {
    if(!matter_cluster_context(m,destroy)) return MATTER_INVALID_ARGUMENT;
    return matter_cluster_delete(m);
}
uint32_t matter_groupkey_version(Matter_Groupkey_T handle) {
    Groupkey m=matter_cluster_context(handle,destroy); return m?m->port.view(m->port.user)->version:0;
}
static bool next(Groupkey m) { return matter_tlv_next(&m->reader,&m->e)==MATTER_TLV_OK; }
static bool skip(Groupkey m) {
    return (m->e.type!=MATTER_TLV_STRUCTURE && m->e.type!=MATTER_TLV_ARRAY && m->e.type!=MATTER_TLV_LIST) ||
        matter_tlv_skip_container(&m->reader)==MATTER_TLV_OK;
}
static uint8_t parse_set(Groupkey m) {
    if(m->e.type!=MATTER_TLV_STRUCTURE) return MATTER_IM_INVALID_COMMAND;
    unsigned seen=0,keys=0,times=0;
    while(next(m)) {
        if(m->e.type==MATTER_TLV_END) {
            if(seen!=255 || keys!=times || !(keys&1) || (keys!=1 && keys!=3 && keys!=7) || !m->pending.times[0]) return MATTER_IM_INVALID_COMMAND;
            m->pending.count=keys==7?3:keys==3?2:1;
            for(unsigned i=1;i<m->pending.count;++i) if(m->pending.times[i]<=m->pending.times[i-1]) return MATTER_IM_INVALID_COMMAND;
            return 0;
        }
        if(m->e.tag.control!=1) return MATTER_IM_INVALID_COMMAND;
        unsigned tag=m->e.tag.number;
        /* Deprecated tag8 and wire FabricIndex are ignored, never generated. */
        if(tag>7) { if(!skip(m)) return MATTER_IM_INVALID_COMMAND; continue; }
        if(seen&(1u<<tag)) return MATTER_IM_INVALID_COMMAND;
        seen|=1u<<tag;
        if(tag<2) {
            if(m->e.type!=MATTER_TLV_UNSIGNED || m->e.unsigned_value>(tag?255:65535)) return MATTER_IM_INVALID_COMMAND;
            if(tag==0) m->pending.id=(uint16_t)m->e.unsigned_value;
            else if(m->e.unsigned_value) return MATTER_IM_INVALID_COMMAND; /* CS not selected. */
        } else if(m->e.type!=MATTER_TLV_NULL) {
            unsigned slot=(tag-2)/2;
            if(tag&1) {
                if(m->e.type!=MATTER_TLV_UNSIGNED) return MATTER_IM_INVALID_COMMAND;
                times|=1u<<slot; m->pending.times[slot]=m->e.unsigned_value;
            } else {
                if(m->e.type!=MATTER_TLV_BYTES) return MATTER_IM_INVALID_COMMAND;
                if(m->e.size!=16) return MATTER_IM_CONSTRAINT_ERROR;
                keys|=1u<<slot; memcpy(m->keys[slot],m->e.data,16);
            }
        }
    }
    return MATTER_IM_INVALID_COMMAND;
}
uint8_t matter_groupkey_command(Matter_Groupkey_T m,uint32_t cmd,Matter_Im_Command_T* out) {
    return matter_cluster_context(m,destroy)?matter_cluster_command(m,cmd,out):MATTER_IM_FAILURE;
}
static uint8_t parse(Groupkey m,uint32_t cmd,const uint8_t* data,size_t size) {
    const Matter_Tlv_Validation_Options_T opt={1024,256,2048,4,false,0,0}; Matter_Tlv_Validation_Report_T report;
    if(cmd!=0 && cmd!=1 && cmd!=3 && cmd!=4) return MATTER_IM_UNSUPPORTED_COMMAND;
    erase(&m->pending,sizeof(m->pending)); erase(m->keys,sizeof(m->keys));
    if(matter_tlv_validate(data,size,&opt,&m->validation,m->tags,64,&report)!=MATTER_TLV_OK ||
        matter_tlv_init(&m->reader,data,size,4)!=MATTER_TLV_OK || !next(m) || m->e.type!=MATTER_TLV_STRUCTURE || m->e.tag.control) return MATTER_IM_INVALID_COMMAND;
    bool seen=false;
    while(next(m)) {
        if(m->e.type==MATTER_TLV_END) return (seen || cmd==4) && matter_tlv_next(&m->reader,&m->e)==MATTER_TLV_DONE?0:MATTER_IM_INVALID_COMMAND;
        if(m->e.tag.control!=1) return MATTER_IM_INVALID_COMMAND;
        if(m->e.tag.number || cmd==4) { if(!skip(m)) return MATTER_IM_INVALID_COMMAND; continue; }
        if(seen) return MATTER_IM_INVALID_COMMAND;
        seen=true;
        if(cmd==0) { uint8_t r=parse_set(m); if(r) return r; }
        else {
            if(m->e.type!=MATTER_TLV_UNSIGNED || m->e.unsigned_value>65535) return MATTER_IM_INVALID_COMMAND;
            m->pending.id=(uint16_t)m->e.unsigned_value;
            if(cmd==3 && !m->pending.id) return MATTER_IM_INVALID_COMMAND;
        }
    }
    return MATTER_IM_INVALID_COMMAND;
}
uint8_t matter_groupkey_validate(Matter_Groupkey_T handle,uint32_t cmd,const uint8_t* data,size_t n) {
    Groupkey m=matter_cluster_context(handle,destroy);
    if(!m || m->busy) return MATTER_IM_FAILURE;
    m->busy=true; uint8_t r=parse(m,cmd,data,n); erase(m->keys,sizeof(m->keys)); m->busy=false; return r;
}
static bool put(Groupkey m,Matter_Tlv_Writer_T* w,Matter_Tlv_Type_T t,int tag,uint64_t value) {
    m->e=(Matter_Tlv_Element_T){.type=t,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=value};
    return matter_tlv_write(w,&m->e,0)==MATTER_TLV_OK;
}
#define P(t,tag,v) put(m,w,t,tag,v)
#define U(tag,v) P(MATTER_TLV_UNSIGNED,tag,v)
#define END() P(MATTER_TLV_END,-1,0)
static uint8_t response(Groupkey m,const Matter_Groupkey_Fabric_T* f,uint32_t cmd,Matter_Tlv_Writer_T* w) {
    const Matter_Groupkey_Set_T* s=NULL;
    if(cmd==1) {
        for(unsigned i=0;i<MATTER_GROUPKEY_SETS;++i) if(f->sets[i].count && f->sets[i].id==m->pending.id) s=&f->sets[i];
        if(!s) return MATTER_GROUPKEY_NOT_FOUND;
    }
    if(!w || w->size || w->capacity<(cmd==1?64u:20u)) return MATTER_IM_RESOURCE_EXHAUSTED;
    if(!P(MATTER_TLV_STRUCTURE,-1,0) || !P(cmd==1?MATTER_TLV_STRUCTURE:MATTER_TLV_ARRAY,0,0)) return MATTER_IM_FAILURE;
    if(s) {
        if(!U(0,s->id) || !U(1,0)) return MATTER_IM_FAILURE;
        for(unsigned i=0;i<3;++i) if(!P(MATTER_TLV_NULL,2+2*i,0) || !P(i<s->count?MATTER_TLV_UNSIGNED:MATTER_TLV_NULL,3+2*i,s->times[i])) return MATTER_IM_FAILURE;
        if(!U(254,f->index)) return MATTER_IM_FAILURE;
    } else for(unsigned i=0;i<MATTER_GROUPKEY_SETS;++i) if(f->sets[i].count && !U(-1,f->sets[i].id)) return MATTER_IM_FAILURE;
    return END() && END()?0:MATTER_IM_FAILURE;
}
Matter_Im_Command_Result_T matter_groupkey_invoke(Matter_Groupkey_T handle,uint8_t index,uint32_t cmd,const uint8_t* data,size_t n,Matter_Tlv_Writer_T* w) {
    Groupkey m=matter_cluster_context(handle,destroy);
    if(!m || m->busy) return (Matter_Im_Command_Result_T){.status=MATTER_IM_FAILURE};
    m->busy=true; uint8_t r=parse(m,cmd,data,n); const Matter_Groupkey_Fabric_T* f=fabric(m,index);
    if(!r && !f) r=MATTER_IM_UNSUPPORTED_ACCESS;
    if(!r) {
        if(cmd==0) r=m->port.store(m->port.user,index,&m->pending,(const uint8_t (*)[16])m->keys);
        else if(cmd==3) r=m->port.remove(m->port.user,index,m->pending.id);
        else r=response(m,f,cmd,w);
    }
    erase(m->keys,sizeof(m->keys)); m->busy=false; return (Matter_Im_Command_Result_T){.status=r};
}
uint8_t matter_groupkey_read(Matter_Groupkey_T m,uint32_t attr,uint8_t index,Matter_Im_Value_T* out) {
    if(!matter_cluster_context(m,destroy)) return MATTER_IM_FAILURE;
    Matter_Cluster_Request_T q={.fabric=index}; return matter_cluster_read(m,attr,&q,out);
}
uint8_t matter_groupkey_map(Matter_Groupkey_T handle,uint8_t index,Matter_Im_List_Change_T change,const uint8_t* d,size_t n) {
    Groupkey m=matter_cluster_context(handle,destroy);
    if(!m || m->busy) return MATTER_IM_FAILURE;
    if(!fabric(m,index)) return MATTER_IM_UNSUPPORTED_ACCESS;
    if(change!=MATTER_IM_LIST_REPLACE && change!=MATTER_IM_LIST_ADD) return MATTER_IM_INVALID_ACTION;
    const Matter_Tlv_Validation_Options_T opt={1024,256,2048,4,false,0,0}; Matter_Tlv_Validation_Report_T report;
    if(matter_tlv_validate(d,n,&opt,&m->validation,m->tags,64,&report)!=MATTER_TLV_OK ||
        matter_tlv_init(&m->reader,d,n,4)!=MATTER_TLV_OK || !next(m) || m->e.tag.control) return MATTER_IM_INVALID_DATA_TYPE;
    bool list=change==MATTER_IM_LIST_REPLACE,any=false;
    if(list && (m->e.type!=MATTER_TLV_ARRAY || !next(m))) return MATTER_IM_INVALID_DATA_TYPE;
    while(m->e.type!=MATTER_TLV_END) {
        if(m->e.type!=MATTER_TLV_STRUCTURE || m->e.tag.control) return MATTER_IM_INVALID_DATA_TYPE;
        unsigned seen=0; any=true;
        while(next(m) && m->e.type!=MATTER_TLV_END) {
            if(m->e.tag.control!=1) return MATTER_IM_INVALID_DATA_TYPE;
            unsigned tag=m->e.tag.number;
            if(tag!=1 && tag!=2) { if(!skip(m)) return MATTER_IM_INVALID_DATA_TYPE; continue; }
            if((seen&(1u<<tag)) || m->e.type!=MATTER_TLV_UNSIGNED) return MATTER_IM_INVALID_DATA_TYPE;
            seen|=1u<<tag;
            if(!m->e.unsigned_value || m->e.unsigned_value>65535) return MATTER_IM_CONSTRAINT_ERROR;
        }
        if(seen!=6 || m->e.type!=MATTER_TLV_END) return MATTER_IM_CONSTRAINT_ERROR;
        if(!list) break;
        if(!next(m)) return MATTER_IM_INVALID_DATA_TYPE;
    }
    if((!list && !any) || matter_tlv_next(&m->reader,&m->e)!=MATTER_TLV_DONE) return MATTER_IM_INVALID_DATA_TYPE;
    return any?MATTER_IM_RESOURCE_EXHAUSTED:0; /* MaxGroupsPerFabric=0. */
}

/* Descriptor callbacks select the operation; ref supplies its immutable ID.
 * These wrappers keep the older typed helper names source-compatible. */
static Matter_Result_T cluster_version(void* u,uint32_t* out) { Groupkey m=u; *out=m->port.view(m->port.user)->version; return MATTER_OK; }
typedef struct { const uint32_t* ids; size_t count; bool fabric; } ReadList;
static uint8_t read_scalar(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* out) {
    (void)q; Groupkey m=u; if(m->busy) return MATTER_IM_FAILURE;
    *out=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=*(const uint32_t*)ref,.data_version=m->port.view(m->port.user)->version}; return 0;
}
static uint8_t read_list(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* out) {
    Groupkey m=u; const ReadList* list=ref; if(m->busy) return MATTER_IM_FAILURE;
    if(list->fabric && !fabric(m,q->fabric)) return MATTER_IM_UNSUPPORTED_ACCESS;
    *out=(Matter_Im_Value_T){.type=MATTER_TLV_ARRAY,.data_version=m->port.view(m->port.user)->version};
    Matter_Tlv_Writer_T* w=&m->writer;
    if(matter_tlv_writer_init(w,m->encoded,sizeof(m->encoded),2)!=MATTER_TLV_OK || !P(MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
    for(size_t i=0;i<list->count;++i) if(!U(-1,list->ids[i])) return MATTER_IM_FAILURE;
    if(!END() || matter_tlv_writer_finish(w,&out->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    out->data=m->encoded; return 0;
}
static uint8_t cluster_validate(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    (void)q; Groupkey m=u; return matter_groupkey_validate(m->interface,*(const uint32_t*)ref,d,n);
}
static Matter_Result_T cluster_start(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n,
    Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out,uint64_t* token) {
    Groupkey m=u; *token=0;
    *out=q->is_case?matter_groupkey_invoke(m->interface,q->fabric,*(const uint32_t*)ref,d,n,w):
        (Matter_Im_Command_Result_T){.status=MATTER_IM_UNSUPPORTED_ACCESS}; return MATTER_OK;
}
static uint8_t cluster_map(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_List_Change_T change,const uint8_t* d,size_t n) {
    (void)ref; Groupkey m=u; return q->is_case?matter_groupkey_map(m->interface,q->fabric,change,d,n):MATTER_IM_UNSUPPORTED_ACCESS;
}
static Matter_Im_Write_Result_T cluster_map_write(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_List_Change_T change,const uint8_t* d,size_t n) {
    return (Matter_Im_Write_Result_T){.status=cluster_map(u,ref,q,change,d,n)};
}
static Matter_Cluster_T interface_new(Groupkey m) {
    Matter_Cluster_Config_T config={.id=MATTER_GROUPKEY_CLUSTER,.attributes=MATTER_GROUPKEY_ATTRIBUTES,.commands=4,
        .callbacks={.ctx=m,.version=cluster_version,.destroy=destroy}};
    Matter_Cluster_T c=matter_cluster_new(&config); if(!c) return NULL;
    static const uint32_t generated[]={2,5},accepted[]={0,1,3,4},zero=0,sets=MATTER_GROUPKEY_SETS,revision=4;
    static const ReadList lists[]={ {NULL,0,true},{generated,2,false},{accepted,4,false},{matter_groupkey_attributes,MATTER_GROUPKEY_ATTRIBUTES,false} };
    static const Matter_Attribute_Def_T definitions[]={
        {.id=0,.read_access={MATTER_IM_VIEW,true},.ref=&lists[0],.read=read_list,
            .write_access={.privilege=MATTER_IM_MANAGE,.fabric_scoped=true,.list=true},.validate_list=cluster_map,.write_list=cluster_map_write},
        {.id=1,.read_access={MATTER_IM_VIEW,true},.ref=&lists[0],.read=read_list},
        {.id=2,.read_access={MATTER_IM_VIEW,false},.ref=&zero,.read=read_scalar},
        {.id=3,.read_access={MATTER_IM_VIEW,false},.ref=&sets,.read=read_scalar},
        {.id=0xfff8,.read_access={MATTER_IM_VIEW,false},.ref=&lists[1],.read=read_list},
        {.id=0xfff9,.read_access={MATTER_IM_VIEW,false},.ref=&lists[2],.read=read_list},
        {.id=0xfffb,.read_access={MATTER_IM_VIEW,false},.ref=&lists[3],.read=read_list},
        {.id=0xfffc,.read_access={MATTER_IM_VIEW,false},.ref=&zero,.read=read_scalar},
        {.id=0xfffd,.read_access={MATTER_IM_VIEW,false},.ref=&revision,.read=read_scalar}
    };
    for(size_t i=0;i<sizeof(definitions)/sizeof(*definitions);++i)
        if(matter_cluster_add_attribute(c,&definitions[i])!=MATTER_OK) { matter_cluster_abandon(c); return NULL; }
    static const uint32_t ids[]={0,1,3,4};
    for(unsigned i=0;i<4;++i) {
        uint32_t id=ids[i]; Matter_Command_Def_T command={.id=id,.ref=&ids[i],.validate=cluster_validate,.start=cluster_start,
            .access={.privilege=MATTER_IM_ADMINISTER,.fabric_scoped=true,.response=id==1 || id==4,.response_command=id+1,.response_capacity=id==1?64:20}};
        if(matter_cluster_add_command(c,&command)!=MATTER_OK) { matter_cluster_abandon(c); return NULL; }
    }
    (void)matter_cluster_seal(c); return c;
}
