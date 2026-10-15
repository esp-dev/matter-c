#include "matter_meter_identification.h"
#include "matter_utility_internal.h"
#include <stdlib.h>
#include <string.h>
#define METER_ID_ATTRIBUTE_COUNT 4
#define METER_ID_GENERIC 2
#define METER_ID_UTF8_BYTES (MATTER_METER_ID_TEXT_MAX+3)
typedef struct { Matter_Utility_T common; Matter_Meter_Id_Port_T port; Matter_Meter_Id_Snapshot_T saved,pending; uint8_t scratch[METER_ID_UTF8_BYTES]; bool busy; } MeterId;
static Matter_Result_T destroy(void* u) { MeterId* m=u; if(m->busy) return MATTER_BUSY; free(m); return MATTER_OK; }
static bool valid_text(MeterId* m,const Matter_Meter_Id_Text_T* t) {
    if(!t->known) return true;
    if(t->size>MATTER_METER_ID_TEXT_MAX) return false;
    m->scratch[0]=0x0c; m->scratch[1]=t->size; memcpy(m->scratch+2,t->data,t->size);
    return matter_tlv_init(&m->common.reader,m->scratch,t->size+2,1)==MATTER_TLV_OK &&
        matter_tlv_next(&m->common.reader,&m->common.element)==MATTER_TLV_OK && matter_tlv_next(&m->common.reader,&m->common.element)==MATTER_TLV_DONE;
}
static bool same_text(const Matter_Meter_Id_Text_T* a,const Matter_Meter_Id_Text_T* b) {
    return a->known==b->known && (!a->known || (a->size==b->size && !memcmp(a->data,b->data,a->size)));
}
Matter_Result_T matter_meter_identification_refresh(Matter_Cluster_T h) {
    MeterId* m=matter_cluster_context(h,destroy); if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy || matter_cluster_in_use(h)) return MATTER_BUSY;
    m->busy=true; memset(&m->pending,0,sizeof(m->pending));
    Matter_Result_T r=m->port.snapshot(m->port.user,&m->pending);
    if(r!=MATTER_OK || (m->pending.type_known && m->pending.meter_type>METER_ID_GENERIC) ||
        !valid_text(m,&m->pending.delivery) || !valid_text(m,&m->pending.serial) || !valid_text(m,&m->pending.protocol)) {
        memset(&m->pending,0,sizeof(m->pending)); r=MATTER_PORT_ERROR;
    }
    if(m->saved.type_known!=m->pending.type_known || (m->pending.type_known && m->saved.meter_type!=m->pending.meter_type) ||
        !same_text(&m->saved.delivery,&m->pending.delivery) || !same_text(&m->saved.serial,&m->pending.serial) || !same_text(&m->saved.protocol,&m->pending.protocol)) ++m->common.version;
    m->saved=m->pending; m->busy=false; return r;
}
static uint8_t read_value(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    MeterId* m=u; uint32_t id=*(const uint32_t*)ref; (void)q;
    if(m->busy) return MATTER_IM_FAILURE;
    /* Coarse owner notifications also cover energy samples. Identity changes
     * only when refresh accepts a different snapshot (including unavailable). */
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_NULL,.data_version=m->common.version,.report_on_version_change=true};
    if(id==MATTER_METER_ID_TYPE) { if(m->saved.type_known) { v->type=MATTER_TLV_UNSIGNED; v->unsigned_value=m->saved.meter_type; } }
    else {
        const Matter_Meter_Id_Text_T* t=id==MATTER_METER_ID_DELIVERY?&m->saved.delivery:id==MATTER_METER_ID_SERIAL?&m->saved.serial:&m->saved.protocol;
        if(t->known) { v->type=MATTER_TLV_UTF8; v->data=t->data; v->size=t->size; }
    }
    return MATTER_IM_SUCCESS;
}
Matter_Cluster_T matter_meter_identification_new(const Matter_Meter_Id_Port_T* p,uint32_t version) {
    if(!p || !p->snapshot) return NULL;
    MeterId* m=calloc(1,sizeof(*m)); if(!m) return NULL; m->port=*p; m->common.version=version; m->common.revision=MATTER_METER_IDENTIFICATION_REVISION;
    Matter_Cluster_Config_T config={.id=MATTER_METER_IDENTIFICATION_CLUSTER,.attributes=METER_ID_ATTRIBUTE_COUNT+UTILITY_GLOBAL_COUNT,
        .callbacks={.ctx=m,.version=utility_version,.destroy=destroy}};
    Matter_Cluster_T h=matter_cluster_new(&config); if(!h) { free(m); return NULL; }
    static const uint32_t ids[]={MATTER_METER_ID_TYPE,MATTER_METER_ID_DELIVERY,MATTER_METER_ID_SERIAL,MATTER_METER_ID_PROTOCOL};
    for(unsigned i=0;i<METER_ID_ATTRIBUTE_COUNT;++i) {
        Matter_Attribute_Def_T a={.id=ids[i],.ref=&ids[i],.read_access={MATTER_IM_VIEW,false},.read=read_value};
        if(matter_cluster_add_attribute(h,&a)!=MATTER_OK) goto fail;
    }
    if(!utility_globals(h,&m->common,ids,METER_ID_ATTRIBUTE_COUNT) || matter_cluster_seal(h)!=MATTER_OK) goto fail;
    return h;
fail: matter_cluster_abandon(h); free(m); return NULL;
}
