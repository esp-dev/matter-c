#include "matter_identify.h"
#include "matter_utility_internal.h"
#include <stdlib.h>
#define IDENTIFY_SECOND_MS UINT64_C(1000)
#define IDENTIFY_MAX_TYPE 5
#define IDENTIFY_ATTRIBUTE_COUNT 2
typedef struct { Matter_Utility_T common; Matter_Identify_Port_T port; uint64_t now,next; uint16_t remaining; uint8_t type; } Identify;
static Matter_Result_T destroy(void* u) { Identify* m=u; if(m->remaining) m->port.present(m->port.user,0); free(m); return MATTER_OK; }
static Matter_Result_T process(void* u,uint64_t now) {
    Identify* m=u; if(now<m->now) return MATTER_INVALID_ARGUMENT; m->now=now;
    if(m->remaining && now>=m->next) {
        uint64_t elapsed=(now-m->next)/IDENTIFY_SECOND_MS+1;
        if(elapsed>=m->remaining) { m->remaining=0; ++m->common.version; m->port.present(m->port.user,0); }
        else { m->remaining-=(uint16_t)elapsed; m->next+=elapsed*IDENTIFY_SECOND_MS; }
    }
    return MATTER_OK;
}
static Matter_Result_T deadline(void* u,uint64_t* out) { Identify* m=u; if(!m->remaining) return MATTER_INVALID_STATE; *out=m->next; return MATTER_OK; }
static uint8_t read_value(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    Identify* m=u; (void)q;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=*(const uint32_t*)ref==MATTER_IDENTIFY_TIME?m->remaining:m->type,
        .data_version=m->common.version,.report_on_version_change=*(const uint32_t*)ref==MATTER_IDENTIFY_TIME}; return MATTER_IM_SUCCESS;
}
static uint8_t scalar(Identify* m,const uint8_t* d,size_t n,uint16_t* value) {
    Matter_Utility_T* s=&m->common;
    if(matter_tlv_init(&s->reader,d,n,1)!=MATTER_TLV_OK || matter_tlv_next(&s->reader,&s->element)!=MATTER_TLV_OK ||
        s->element.tag.control || s->element.type!=MATTER_TLV_UNSIGNED) return MATTER_IM_INVALID_DATA_TYPE;
    if(s->element.unsigned_value>UINT16_MAX) return MATTER_IM_CONSTRAINT_ERROR;
    *value=(uint16_t)s->element.unsigned_value;
    return matter_tlv_next(&s->reader,&s->element)==MATTER_TLV_DONE?MATTER_IM_SUCCESS:MATTER_IM_INVALID_DATA_TYPE;
}
static uint8_t set(Identify* m,uint16_t seconds) {
    if(seconds && m->now>UINT64_MAX-(uint64_t)seconds*IDENTIFY_SECOND_MS) return MATTER_IM_CONSTRAINT_ERROR;
    m->remaining=seconds; m->next=seconds?m->now+IDENTIFY_SECOND_MS:0;
    ++m->common.version; m->port.present(m->port.user,seconds); return MATTER_IM_SUCCESS;
}
static uint8_t validate_write(void* u,const void* r,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    (void)r; (void)q; uint16_t value; return scalar(u,d,n,&value);
}
static Matter_Im_Write_Result_T write_value(void* u,const void* r,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    (void)r; (void)q; uint16_t value; uint8_t status=scalar(u,d,n,&value); if(!status) status=set(u,value);
    return (Matter_Im_Write_Result_T){.status=status};
}
static uint8_t validate_command(void* u,const void* r,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    (void)r; (void)q; uint64_t values[1]; unsigned seen;
    if(!utility_command(&((Identify*)u)->common,d,n,values,1,1,&seen)) return MATTER_IM_INVALID_COMMAND;
    return values[0]<=UINT16_MAX?MATTER_IM_SUCCESS:MATTER_IM_CONSTRAINT_ERROR;
}
static Matter_Result_T start(void* u,const void* r,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* result,uint64_t* token) {
    (void)r; (void)q; (void)w; (void)token; Identify* m=u; uint64_t values[1]; unsigned seen;
    *result=(Matter_Im_Command_Result_T){.status=MATTER_IM_INVALID_COMMAND};
    if(utility_command(&m->common,d,n,values,1,1,&seen) && values[0]<=UINT16_MAX) result->status=set(m,(uint16_t)values[0]);
    return MATTER_OK;
}
Matter_Cluster_T matter_identify_new(const Matter_Identify_Port_T* p,const Matter_Identify_Config_T* c,uint64_t now) {
    if(!p || !p->present || !c || c->identify_type>IDENTIFY_MAX_TYPE) return NULL;
    Identify* m=calloc(1,sizeof(*m)); if(!m) return NULL;
    m->port=*p; m->now=now; m->type=c->identify_type; m->common.version=c->data_version; m->common.revision=MATTER_IDENTIFY_REVISION; m->common.command=true;
    Matter_Cluster_Config_T config={.id=MATTER_IDENTIFY_CLUSTER,.attributes=IDENTIFY_ATTRIBUTE_COUNT+UTILITY_GLOBAL_COUNT,.commands=1,
        .callbacks={.ctx=m,.version=utility_version,.process=process,.deadline=deadline,.destroy=destroy}};
    Matter_Cluster_T h=matter_cluster_new(&config); if(!h) { free(m); return NULL; }
    static const uint32_t ids[]={MATTER_IDENTIFY_TIME,MATTER_IDENTIFY_TYPE};
    for(unsigned i=0;i<IDENTIFY_ATTRIBUTE_COUNT;++i) {
        Matter_Attribute_Def_T a={.id=ids[i],.ref=&ids[i],.read_access={MATTER_IM_VIEW,false},.read=read_value};
        if(ids[i]==MATTER_IDENTIFY_TIME) { a.write_access.privilege=MATTER_IM_OPERATE; a.validate=validate_write; a.write=write_value; }
        if(matter_cluster_add_attribute(h,&a)!=MATTER_OK) goto fail;
    }
    Matter_Command_Def_T cmd={.id=MATTER_IDENTIFY_COMMAND,.access={.privilege=MATTER_IM_MANAGE},.validate=validate_command,.start=start};
    if(!utility_globals(h,&m->common,ids,IDENTIFY_ATTRIBUTE_COUNT) || matter_cluster_add_command(h,&cmd)!=MATTER_OK || matter_cluster_seal(h)!=MATTER_OK) goto fail;
    return h;
fail: matter_cluster_abandon(h); free(m); return NULL;
}
