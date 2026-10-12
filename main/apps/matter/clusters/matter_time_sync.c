#include "matter_time_sync.h"
#include "matter_utility_internal.h"
#include <stdlib.h>
#include <string.h>
#define TIME_ATTRIBUTE_COUNT 3
#define TIME_COMMAND_REQUIRED 3
typedef struct {
    Matter_Utility_T common; Matter_Time_Sync_Port_T port; Matter_Events_T events;
    Matter_Time_Sync_Sample_T sample; uint64_t now,last_attempt,last_failure;
    bool attempted,failed;
} TimeSync;
static Matter_Result_T destroy(void* u) { free(u); return MATTER_OK; }
static bool valid(const Matter_Time_Sync_Sample_T* s) {
    return s->granularity<=MATTER_TIME_MICROSECONDS && s->source<=MATTER_TIME_SOURCE_MAX && (!!s->granularity==!!s->source);
}
static void publish(TimeSync* m,const Matter_Time_Sync_Sample_T* s,bool explicit_set) {
    if(explicit_set || m->sample.granularity!=s->granularity || m->sample.source!=s->source) ++m->common.version;
    m->sample=*s;
}
static Matter_Result_T process(void* u,uint64_t now) {
    TimeSync* m=u; if(now<m->now) return MATTER_INVALID_ARGUMENT; m->now=now;
    if(!m->attempted || (!m->sample.granularity && now-m->last_attempt>=MATTER_TIME_HOUR_MS)) {
        m->attempted=true; m->last_attempt=now; m->port.synchronize(m->port.user);
    }
    Matter_Time_Sync_Sample_T sample={0}; Matter_Result_T r=m->port.sample(m->port.user,now,&sample);
    if(r!=MATTER_OK || !valid(&sample)) { memset(&sample,0,sizeof(sample)); r=MATTER_PORT_ERROR; }
    publish(m,&sample,false);
    if(!sample.granularity && (!m->failed || now-m->last_failure>=MATTER_TIME_HOUR_MS)) {
        static const uint8_t empty[]={0x15,0x18};
        const Matter_Event_Path_T path={0,MATTER_TIME_SYNC_CLUSTER,MATTER_TIME_FAILURE};
        Matter_Result_T event=matter_events_append(m->events,&path,1,now,false,empty,sizeof(empty));
        if(event!=MATTER_OK) return event;
        m->failed=true; m->last_failure=now;
    }
    return r;
}
static Matter_Result_T deadline(void* u,uint64_t* out) {
    TimeSync* m=u;
    if(!m->attempted) { *out=m->now; return MATTER_OK; }
    if(m->sample.granularity) return MATTER_INVALID_STATE;
    uint64_t base=m->last_attempt;
    if(!m->failed) { *out=m->now; return MATTER_OK; }
    if(m->last_failure<base) base=m->last_failure;
    *out=base>UINT64_MAX-MATTER_TIME_HOUR_MS?UINT64_MAX:base+MATTER_TIME_HOUR_MS; return MATTER_OK;
}
static uint8_t read_value(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    TimeSync* m=u; uint32_t id=*(const uint32_t*)ref; (void)q;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->common.version,.report_on_version_change=id==MATTER_TIME_UTC};
    if(id==MATTER_TIME_UTC) { if(!m->sample.granularity) v->type=MATTER_TLV_NULL; else v->unsigned_value=m->sample.utc_us; }
    else v->unsigned_value=id==MATTER_TIME_GRANULARITY?m->sample.granularity:m->sample.source;
    return MATTER_IM_SUCCESS;
}
static uint8_t parse(TimeSync* m,const uint8_t* d,size_t n,uint64_t* values) {
    unsigned seen; values[2]=0;
    if(!utility_command(&m->common,d,n,values,TIME_ATTRIBUTE_COUNT,TIME_COMMAND_REQUIRED,&seen)) return MATTER_IM_INVALID_COMMAND;
    if(values[1]>MATTER_TIME_MICROSECONDS || values[2]>MATTER_TIME_SOURCE_MAX) return MATTER_IM_CONSTRAINT_ERROR;
    return MATTER_IM_SUCCESS;
}
static uint8_t validate(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    (void)ref; (void)q; uint64_t values[TIME_ATTRIBUTE_COUNT]; return parse(u,d,n,values);
}
static Matter_Result_T start(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* result,uint64_t* token) {
    (void)ref; (void)q; (void)w; (void)token; TimeSync* m=u; uint64_t values[TIME_ATTRIBUTE_COUNT];
    *result=(Matter_Im_Command_Result_T){.status=parse(m,d,n,values)}; if(result->status) return MATTER_OK;
    uint8_t granularity=(uint8_t)values[1]; if(granularity>MATTER_TIME_MINUTES) --granularity;
    Matter_Result_T r=m->port.set(m->port.user,values[0],granularity,m->now);
    if(r!=MATTER_OK) {
        result->status=MATTER_IM_FAILURE;
        if(r==MATTER_INVALID_STATE) { result->has_cluster_status=true; result->cluster_status=MATTER_TIME_NOT_ACCEPTED; }
        return MATTER_OK;
    }
    const Matter_Time_Sync_Sample_T sample={values[0],granularity,granularity?MATTER_TIME_SOURCE_ADMIN:MATTER_TIME_NONE};
    publish(m,&sample,true); return MATTER_OK;
}
Matter_Cluster_T matter_time_sync_new(const Matter_Time_Sync_Port_T* p,Matter_Events_T events,uint32_t version,uint64_t now) {
    if(!p || !p->sample || !p->set || !p->synchronize || !events) return NULL;
    TimeSync* m=calloc(1,sizeof(*m)); if(!m) return NULL;
    m->port=*p; m->events=events; m->now=now; m->common.version=version; m->common.revision=MATTER_TIME_SYNC_REVISION; m->common.command=true;
    Matter_Cluster_Config_T config={.id=MATTER_TIME_SYNC_CLUSTER,.attributes=TIME_ATTRIBUTE_COUNT+UTILITY_GLOBAL_COUNT,.commands=1,.events=1,
        .callbacks={.ctx=m,.version=utility_version,.process=process,.deadline=deadline,.destroy=destroy}};
    Matter_Cluster_T h=matter_cluster_new(&config); if(!h) { free(m); return NULL; }
    static const uint32_t ids[]={MATTER_TIME_UTC,MATTER_TIME_GRANULARITY,MATTER_TIME_SOURCE};
    for(unsigned i=0;i<TIME_ATTRIBUTE_COUNT;++i) {
        Matter_Attribute_Def_T a={.id=ids[i],.ref=&ids[i],.read_access={MATTER_IM_VIEW,false},.read=read_value};
        if(matter_cluster_add_attribute(h,&a)!=MATTER_OK) goto fail;
    }
    const Matter_Event_Def_T event={MATTER_TIME_FAILURE,MATTER_IM_VIEW,1,false};
    Matter_Command_Def_T command={.id=MATTER_TIME_SET_UTC,.access={.privilege=MATTER_IM_ADMINISTER},.validate=validate,.start=start};
    if(!utility_globals(h,&m->common,ids,TIME_ATTRIBUTE_COUNT) || matter_cluster_add_event(h,&event)!=MATTER_OK ||
        matter_cluster_add_command(h,&command)!=MATTER_OK || matter_cluster_seal(h)!=MATTER_OK) goto fail;
    return h;
fail: matter_cluster_abandon(h); free(m); return NULL;
}
