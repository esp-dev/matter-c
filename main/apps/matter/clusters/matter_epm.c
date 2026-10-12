#include "matter_epm.h"
#include "../model/matter_cluster_internal.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
typedef struct {
    Matter_Epm_Port_T port; Matter_Epm_Config_T config; Matter_Epm_Sample_T pending;
    uint64_t now,last_ready; int64_t power; uint32_t version;
    bool available,dirty,busy;
    Matter_Tlv_Writer_T writer; Matter_Tlv_Element_T token;
    uint8_t accuracy[256]; size_t accuracy_size;
} Epm;
static Matter_Result_T destroy(void* u) { Epm* m=u; if(m->busy) return MATTER_BUSY; free(m); return MATTER_OK; }
static Matter_Result_T version(void* u,uint32_t* v) { Epm* m=u; if(m->busy) return MATTER_BUSY; *v=m->version; return MATTER_OK; }
Matter_Result_T matter_epm_from_watts(double watts,int64_t* out) {
    if(!out || !isfinite(watts) || watts < -(double)MATTER_EPM_LIMIT/1000.0 || watts > (double)MATTER_EPM_LIMIT/1000.0) return MATTER_INVALID_ARGUMENT;
    double scaled=watts*1000.0;
    if(scaled < -(double)MATTER_EPM_LIMIT || scaled > (double)MATTER_EPM_LIMIT) return MATTER_INVALID_ARGUMENT;
    /* Range was checked BEFORE the float-to-integer cast. No libm rounding call. */
    int64_t value=(int64_t)scaled; double fraction=scaled-(double)value;
    if(fraction>=0.5) ++value;
    else if(fraction<=-0.5) --value;
    *out=value; return MATTER_OK;
}
static bool config_valid(const Matter_Epm_Config_T* c) {
    if(!c || !c->max_age_ms || !c->range_count || c->range_count>MATTER_EPM_MAX_RANGES) return false;
    for(unsigned i=0;i<c->range_count;++i) {
        const Matter_Epm_Accuracy_Range_T* r=&c->ranges[i];
        if(r->min_mw < -MATTER_EPM_LIMIT || r->max_mw>MATTER_EPM_LIMIT || r->min_mw>=r->max_mw ||
            !r->fields || (r->fields&~3) || ((r->fields&MATTER_EPM_PERCENT_MAX) && r->percent_max>10000) ||
            ((r->fields&MATTER_EPM_FIXED_MAX) && r->fixed_max_mw> (uint64_t)MATTER_EPM_LIMIT-1) ||
            (i && r->min_mw!=c->ranges[i-1].max_mw+1)) return false;
    }
    return true;
}
static bool put(Epm* m,Matter_Tlv_Type_T type,int tag,uint64_t n,int64_t signed_n) {
    m->token=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=n,.signed_value=signed_n};
    return matter_tlv_write(&m->writer,&m->token,0)==MATTER_TLV_OK;
}
#define P(type,tag,n) put(m,type,tag,n,0)
#define S(tag,n) put(m,MATTER_TLV_SIGNED,tag,0,n)
#define END() P(MATTER_TLV_END,-1,0)
static bool accuracy(Epm* m) {
    const Matter_Epm_Config_T* c=&m->config;
    if(matter_tlv_writer_init(&m->writer,m->accuracy,sizeof(m->accuracy),4)!=MATTER_TLV_OK ||
        !P(MATTER_TLV_ARRAY,-1,0) || !P(MATTER_TLV_STRUCTURE,-1,0) || !P(MATTER_TLV_UNSIGNED,0,5) ||
        !P(MATTER_TLV_BOOL,1,c->measured) || !S(2,c->ranges[0].min_mw) || !S(3,c->ranges[c->range_count-1].max_mw) ||
        !P(MATTER_TLV_ARRAY,4,0)) return false;
    for(unsigned i=0;i<c->range_count;++i) {
        const Matter_Epm_Accuracy_Range_T* r=&c->ranges[i];
        if(!P(MATTER_TLV_STRUCTURE,-1,0) || !S(0,r->min_mw) || !S(1,r->max_mw) ||
            ((r->fields&MATTER_EPM_PERCENT_MAX) && !P(MATTER_TLV_UNSIGNED,2,r->percent_max)) ||
            ((r->fields&MATTER_EPM_FIXED_MAX) && !P(MATTER_TLV_UNSIGNED,5,r->fixed_max_mw)) || !END()) return false;
    }
    return END() && END() && END() && matter_tlv_writer_finish(&m->writer,&m->accuracy_size)==MATTER_TLV_OK;
}
#undef P
#undef S
#undef END
static uint8_t read_power(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    Epm* m=u; (void)ref; (void)q; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=m->available?MATTER_TLV_SIGNED:MATTER_TLV_NULL,.signed_value=m->power,.data_version=m->version}; return 0;
}
static uint8_t read_accuracy(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    Epm* m=u; (void)ref; (void)q; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_ARRAY,.data=m->accuracy,.size=m->accuracy_size,.data_version=m->version}; return 0;
}
static uint8_t read_feature(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    Epm* m=u; (void)ref; (void)q; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=m->config.polyphase?6:2,.data_version=m->version}; return 0;
}
static uint8_t read_constant(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    Epm* m=u; (void)q; if(m->busy) return MATTER_IM_FAILURE;
    *v=*(const Matter_Im_Value_T*)ref; v->data_version=m->version; return 0;
}
Matter_Cluster_T matter_epm_new(const Matter_Epm_Port_T* p,const Matter_Epm_Config_T* c,uint64_t now) {
    if(!p || !p->snapshot || !config_valid(c)) return NULL;
    Epm* m=calloc(1,sizeof(*m)); if(!m) return NULL;
    m->port=*p; m->config=*c; m->version=c->data_version; m->now=m->last_ready=now;
    if(!accuracy(m)) { free(m); return NULL; }
    Matter_Cluster_Config_T config={.id=MATTER_EPM_CLUSTER,.attributes=9,.callbacks={.ctx=m,.version=version,.destroy=destroy}};
    Matter_Cluster_T handle=matter_cluster_new(&config); if(!handle) { free(m); return NULL; }
    static const uint8_t empty[]={0x16,0x18},ids[]={0x16,4,0,4,1,4,2,4,8,5,0xf8,0xff,5,0xf9,0xff,5,0xfb,0xff,5,0xfc,0xff,5,0xfd,0xff,0x18};
    static const Matter_Im_Value_T constants[]={
        {.type=MATTER_TLV_UNSIGNED,.unsigned_value=2},{.type=MATTER_TLV_UNSIGNED,.unsigned_value=1},
        {.type=MATTER_TLV_UNSIGNED,.unsigned_value=3},
        {.type=MATTER_TLV_ARRAY,.data=empty,.size=sizeof(empty)},{.type=MATTER_TLV_ARRAY,.data=ids,.size=sizeof(ids)}
    };
    static const Matter_Attribute_Def_T attrs[]={
        {.id=0,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&constants[0]},
        {.id=1,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&constants[1]},
        {.id=2,.read_access={MATTER_IM_VIEW,false},.read=read_accuracy},
        {.id=8,.read_access={MATTER_IM_VIEW,false},.read=read_power},
        {.id=0xfff8,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&constants[3]},
        {.id=0xfff9,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&constants[3]},
        {.id=0xfffb,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&constants[4]},
        {.id=0xfffc,.read_access={MATTER_IM_VIEW,false},.read=read_feature},
        {.id=0xfffd,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&constants[2]}
    };
    for(unsigned i=0;i<9;++i) if(matter_cluster_add_attribute(handle,&attrs[i])!=MATTER_OK) { matter_cluster_abandon(handle); free(m); return NULL; }
    (void)matter_cluster_seal(handle); return handle;
}
Matter_Result_T matter_epm_refresh(Matter_Cluster_T handle,uint64_t now,bool* ready) {
    Epm* m=matter_cluster_context(handle,destroy);
    if(!m || !ready) return MATTER_INVALID_ARGUMENT;
    if(m->busy || matter_cluster_in_use(handle)) return MATTER_BUSY;
    if(now<m->now) return MATTER_INVALID_ARGUMENT;
    m->busy=true; m->now=now; memset(&m->pending,0,sizeof(m->pending));
    Matter_Result_T r=m->port.snapshot(m->port.user,&m->pending); bool available=false;
    if(r==MATTER_OK && m->pending.available) {
        if(m->pending.sampled_ms>now || m->pending.active_mw<m->config.ranges[0].min_mw ||
            m->pending.active_mw>m->config.ranges[m->config.range_count-1].max_mw) r=MATTER_PORT_ERROR;
        else available=now-m->pending.sampled_ms<m->config.max_age_ms;
    }
    if(m->available!=available || (available && m->power!=m->pending.active_mw)) { ++m->version; m->dirty=true; }
    m->available=available; m->power=available?m->pending.active_mw:0;
    *ready=m->dirty && now-m->last_ready>=1000;
    if(*ready) { m->dirty=false; m->last_ready=now; }
    m->busy=false; return r==MATTER_OK?MATTER_OK:MATTER_PORT_ERROR;
}
