#include "matter_eem.h"
#include "../model/matter_cluster_internal.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
typedef struct {
    Matter_Eem_Port_T port; Matter_Eem_Config_T config;
    Matter_Eem_Checkpoint_T saved,candidate; Matter_Eem_Sample_T sample,published;
    uint64_t now,last_capture,last_ready; uint32_t version;
    bool busy,available,captured,notified,dirty;
    Matter_Tlv_Writer_T writer; Matter_Tlv_Element_T token;
    uint8_t accuracy[96],energy[2][40],event[96]; size_t accuracy_size,energy_size[2],event_size;
} Eem;
static Matter_Result_T destroy(void* u) { Eem* m=u; if(m->busy) return MATTER_BUSY; free(m); return MATTER_OK; }
static Matter_Result_T version(void* u,uint32_t* v) { Eem* m=u; if(m->busy) return MATTER_BUSY; *v=m->version; return MATTER_OK; }
Matter_Result_T matter_eem_from_kwh(double kwh,int64_t* out) {
    if(!out || !isfinite(kwh) || kwh<0 || kwh>(double)MATTER_EEM_LIMIT/1000000.0) return MATTER_INVALID_ARGUMENT;
    double scaled=kwh*1000000.0;
    if(scaled>(double)MATTER_EEM_LIMIT) return MATTER_INVALID_ARGUMENT;
    int64_t value=(int64_t)scaled; if(scaled-(double)value>=0.5) ++value;
    *out=value; return MATTER_OK;
}
static bool checkpoint_valid(const Matter_Eem_Checkpoint_T* c) {
    if(!c->initialized && (c->generation || c->raw_mwh[0] || c->raw_mwh[1] || c->total_mwh[0] || c->total_mwh[1])) return false;
    for(unsigned i=0;i<2;++i) if(c->raw_mwh[i]<0 || c->raw_mwh[i]>MATTER_EEM_LIMIT || c->total_mwh[i]<0 || c->total_mwh[i]>MATTER_EEM_LIMIT) return false;
    return true;
}
static bool put(Eem* m,Matter_Tlv_Type_T type,int tag,uint64_t n) {
    m->token=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=n,.signed_value=(int64_t)n};
    return matter_tlv_write(&m->writer,&m->token,0)==MATTER_TLV_OK;
}
#define P(type,tag,n) put(m,type,tag,n)
#define END() P(MATTER_TLV_END,-1,0)
static bool accuracy(Eem* m) {
    return matter_tlv_writer_init(&m->writer,m->accuracy,sizeof(m->accuracy),4)==MATTER_TLV_OK &&
        P(MATTER_TLV_STRUCTURE,-1,0) && P(MATTER_TLV_UNSIGNED,0,14) && P(MATTER_TLV_BOOL,1,m->config.measured) &&
        P(MATTER_TLV_SIGNED,2,0) && P(MATTER_TLV_SIGNED,3,MATTER_EEM_LIMIT) && P(MATTER_TLV_ARRAY,4,0) &&
        P(MATTER_TLV_STRUCTURE,-1,0) && P(MATTER_TLV_SIGNED,0,0) && P(MATTER_TLV_SIGNED,1,MATTER_EEM_LIMIT) &&
        P(MATTER_TLV_UNSIGNED,2,m->config.percent_max) && P(MATTER_TLV_UNSIGNED,5,m->config.fixed_max_mwh) && END() && END() && END() &&
        matter_tlv_writer_finish(&m->writer,&m->accuracy_size)==MATTER_TLV_OK;
}
static bool measurement(Eem* m,int tag,unsigned direction) {
    return P(MATTER_TLV_STRUCTURE,tag,0) && P(MATTER_TLV_SIGNED,0,m->saved.total_mwh[direction]) &&
        (!m->sample.utc_known || P(MATTER_TLV_UNSIGNED,2,m->sample.epoch_s)) && P(MATTER_TLV_UNSIGNED,4,m->sample.sampled_ms) && END();
}
static bool encode(Eem* m) {
    for(unsigned i=0;i<2;++i) if(matter_tlv_writer_init(&m->writer,m->energy[i],sizeof(m->energy[i]),2)!=MATTER_TLV_OK ||
        !measurement(m,-1,i) || matter_tlv_writer_finish(&m->writer,&m->energy_size[i])!=MATTER_TLV_OK) return false;
    return matter_tlv_writer_init(&m->writer,m->event,sizeof(m->event),3)==MATTER_TLV_OK && P(MATTER_TLV_STRUCTURE,-1,0) &&
        measurement(m,0,0) && measurement(m,1,1) && END() && matter_tlv_writer_finish(&m->writer,&m->event_size)==MATTER_TLV_OK;
}
#undef P
#undef END
static uint8_t read_energy(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    Eem* m=u; (void)q; if(m->busy) return MATTER_IM_FAILURE;
    unsigned i=*(const unsigned*)ref;
    *v=(Matter_Im_Value_T){.type=m->available?MATTER_TLV_STRUCTURE:MATTER_TLV_NULL,.data=m->energy[i],.size=m->available?m->energy_size[i]:0,.data_version=m->version}; return 0;
}
static uint8_t read_accuracy(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    Eem* m=u; (void)ref; (void)q; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_STRUCTURE,.data=m->accuracy,.size=m->accuracy_size,.data_version=m->version}; return 0;
}
static uint8_t read_constant(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    Eem* m=u; (void)q; if(m->busy) return MATTER_IM_FAILURE;
    *v=*(const Matter_Im_Value_T*)ref; v->data_version=m->version; return 0;
}
Matter_Cluster_T matter_eem_new(const Matter_Eem_Port_T* p,const Matter_Eem_Config_T* c,uint64_t now) {
    if(!p || !p->snapshot || !p->load || !p->store || !c || !c->events || !c->max_age_ms || c->percent_max>10000 || c->fixed_max_mwh>MATTER_EEM_LIMIT-1) return NULL;
    Eem* m=calloc(1,sizeof(*m)); if(!m) return NULL;
    m->port=*p; m->config=*c; m->version=c->data_version; m->now=now; m->busy=true;
    if(p->load(p->user,&m->saved)!=MATTER_OK || !checkpoint_valid(&m->saved) || !accuracy(m)) { free(m); return NULL; }
    m->busy=false;
    Matter_Cluster_Config_T config={.id=MATTER_EEM_CLUSTER,.attributes=8,.events=1,.callbacks={.ctx=m,.version=version,.destroy=destroy}};
    Matter_Cluster_T h=matter_cluster_new(&config); if(!h) { free(m); return NULL; }
    static const unsigned directions[]={0,1};
    static const uint8_t empty[]={0x16,0x18},ids[]={0x16,4,0,4,1,4,2,5,0xf8,0xff,5,0xf9,0xff,5,0xfb,0xff,5,0xfc,0xff,5,0xfd,0xff,0x18};
    static const Matter_Im_Value_T constants[]={
        {.type=MATTER_TLV_ARRAY,.data=empty,.size=sizeof(empty)},{.type=MATTER_TLV_ARRAY,.data=ids,.size=sizeof(ids)},
        {.type=MATTER_TLV_UNSIGNED,.unsigned_value=7},{.type=MATTER_TLV_UNSIGNED,.unsigned_value=2}
    };
    static const Matter_Attribute_Def_T attrs[]={
        {.id=0,.read_access={MATTER_IM_VIEW,false},.read=read_accuracy},
        {.id=1,.read_access={MATTER_IM_VIEW,false},.read=read_energy,.ref=&directions[0]},
        {.id=2,.read_access={MATTER_IM_VIEW,false},.read=read_energy,.ref=&directions[1]},
        {.id=0xfff8,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&constants[0]},
        {.id=0xfff9,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&constants[0]},
        {.id=0xfffb,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&constants[1]},
        {.id=0xfffc,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&constants[2]},
        {.id=0xfffd,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&constants[3]}
    };
    static const Matter_Event_Def_T event={0,MATTER_IM_VIEW,1,false};
    for(unsigned i=0;i<8;++i) if(matter_cluster_add_attribute(h,&attrs[i])!=MATTER_OK) goto fail;
    if(matter_cluster_add_event(h,&event)!=MATTER_OK) goto fail;
    (void)matter_cluster_seal(h); return h;
fail: matter_cluster_abandon(h); free(m); return NULL;
}
static bool sample_valid(const Eem* m) {
    if(m->saved.initialized && m->sample.generation<m->saved.generation) return false;
    for(unsigned i=0;i<2;++i) {
        int64_t raw=m->sample.raw_mwh[i];
        if(raw<0 || raw>MATTER_EEM_LIMIT) return false;
        if(m->saved.initialized && m->sample.generation==m->saved.generation &&
            (raw<m->saved.raw_mwh[i] || raw-m->saved.raw_mwh[i]>MATTER_EEM_LIMIT-m->saved.total_mwh[i])) return false;
    }
    return true;
}
static Matter_Result_T capture(Eem* m,uint64_t now) {
    m->candidate=m->saved;
    for(unsigned i=0;i<2;++i) {
        int64_t raw=m->sample.raw_mwh[i];
        if(m->saved.initialized && m->sample.generation==m->saved.generation) {
            m->candidate.total_mwh[i]+=raw-m->saved.raw_mwh[i];
        }
        m->candidate.raw_mwh[i]=raw;
    }
    m->candidate.initialized=true; m->candidate.generation=m->sample.generation;
    bool changed=!m->saved.initialized || m->candidate.generation!=m->saved.generation;
    for(unsigned i=0;i<2;++i) changed=changed || m->candidate.raw_mwh[i]!=m->saved.raw_mwh[i];
    if(changed && m->port.store(m->port.user,&m->candidate)!=MATTER_OK) return MATTER_PORT_ERROR;
    m->saved=m->candidate;
    if(!encode(m)) return MATTER_PORT_ERROR;
    Matter_Event_Path_T path={m->config.endpoint,MATTER_EEM_CLUSTER,0};
    if(matter_events_append(m->config.events,&path,1,now,false,m->event,m->event_size)!=MATTER_OK) return MATTER_PORT_ERROR;
    m->published=m->sample; m->last_capture=now; m->captured=true; return MATTER_OK;
}
Matter_Result_T matter_eem_refresh(Matter_Cluster_T handle,uint64_t now,bool* ready) {
    Eem* m=matter_cluster_context(handle,destroy);
    if(!m || !ready) return MATTER_INVALID_ARGUMENT;
    if(m->busy || matter_cluster_in_use(handle)) return MATTER_BUSY;
    if(now<m->now) return MATTER_INVALID_ARGUMENT;
    m->busy=true; m->now=now; memset(&m->sample,0,sizeof(m->sample));
    Matter_Result_T r=m->port.snapshot(m->port.user,&m->sample); bool available=false,updated=false;
    if(r==MATTER_OK && m->sample.available) {
        if(!sample_valid(m) || m->sample.sampled_ms>now || (m->captured && m->sample.sampled_ms<m->published.sampled_ms)) r=MATTER_PORT_ERROR;
        else if(now-m->sample.sampled_ms<m->config.max_age_ms) {
            bool fresh=!m->captured || m->sample.sampled_ms!=m->published.sampled_ms || m->sample.generation!=m->published.generation ||
                m->sample.utc_known!=m->published.utc_known || (m->sample.utc_known && m->sample.epoch_s!=m->published.epoch_s) ||
                m->sample.raw_mwh[0]!=m->published.raw_mwh[0] || m->sample.raw_mwh[1]!=m->published.raw_mwh[1];
            if(fresh && (!m->captured || now-m->last_capture>=1000)) { r=capture(m,now); updated=r==MATTER_OK; }
            available=r==MATTER_OK && m->captured && now-m->published.sampled_ms<m->config.max_age_ms;
        }
    }
    if(m->available!=available || updated) { ++m->version; m->dirty=true; }
    m->available=available;
    *ready=m->dirty && (!m->notified || now-m->last_ready>=1000);
    if(*ready) { m->dirty=false; m->notified=true; m->last_ready=now; }
    m->busy=false; return r==MATTER_OK?MATTER_OK:MATTER_PORT_ERROR;
}
