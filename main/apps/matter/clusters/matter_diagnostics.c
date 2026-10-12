#include "matter_diagnostics.h"
#include "../codec/matter_tlv_validate.h"
#include "../codec/matter_tlv_internal.h"
#include "../model/matter_cluster_internal.h"
#include <stdlib.h>
#include <string.h>
static const uint32_t general_attrs[]={0,1,2,3,4,5,6,7,8,10,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
static const uint32_t wifi_attrs[]={0,1,2,3,4,5,6,7,8,9,10,11,12,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
typedef struct Matter_Diagnostics* Diagnostics;
static Matter_Result_T destroy(void*);
static Matter_Cluster_T interface_new(Diagnostics,bool);
struct Matter_Diagnostics {
    Matter_Cluster_T interface,wifi;
    Matter_Diagnostics_Port_T port; Matter_Diagnostics_Snapshot_T current,pending;
    Matter_Diagnostics_Test_Trigger_T test;
    const uint8_t* request_key; uint64_t request_event; /* Borrowed during invoke only. */
    bool busy,valid,initialized,boot_emitted; uint32_t general_version,wifi_version;
    Matter_Tlv_Writer_T writer; Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T e;
    Matter_Tlv_Validation_Workspace_T validation; Matter_Tlv_Tag_T tags[64];
    uint8_t encoded[4096];
};
Matter_Result_T matter_diagnostics_set_test_trigger(Matter_Diagnostics_T h,const Matter_Diagnostics_Test_Trigger_T* config) {
    Diagnostics m=matter_cluster_context(h,destroy); if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy || matter_cluster_in_use(h)) return MATTER_BUSY;
    if(config) {
        uint8_t any=0; for(unsigned i=0;i<16;++i) any|=config->enable_key[i];
        if(!any || !config->trigger) return MATTER_INVALID_ARGUMENT;
        m->test=*config;
    } else memset(&m->test,0,sizeof(m->test));
    ++m->general_version; return MATTER_OK;
}
Matter_Result_T matter_diagnostics_boot(Matter_Diagnostics_T h,Matter_Events_T log,uint64_t now) {
    Diagnostics m=matter_cluster_context(h,destroy);
    if(!m || !log) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->boot_emitted) return MATTER_OK;
    if(!m->valid) return MATTER_PORT_ERROR;
    const uint8_t data[]={0x15,0x24,0,m->current.general.boot_reason,0x18};
    const Matter_Event_Path_T path={0,MATTER_DIAGNOSTICS_GENERAL,3};
    m->busy=true; Matter_Result_T r=matter_events_append(log,&path,2,now,false,data,sizeof(data));
    m->boot_emitted=r==MATTER_OK; m->busy=false; return r;
}
bool matter_diagnostics_cluster(uint32_t c) { return c==MATTER_DIAGNOSTICS_GENERAL || c==MATTER_DIAGNOSTICS_WIFI; }
const uint32_t* matter_diagnostics_attributes(uint32_t c,size_t* n) {
    *n=c==MATTER_DIAGNOSTICS_GENERAL?MATTER_DIAGNOSTICS_GENERAL_ATTRS:c==MATTER_DIAGNOSTICS_WIFI?MATTER_DIAGNOSTICS_WIFI_ATTRS:0;
    return c==MATTER_DIAGNOSTICS_GENERAL?general_attrs:c==MATTER_DIAGNOSTICS_WIFI?wifi_attrs:NULL;
}
static bool valid(const Matter_Diagnostics_Snapshot_T* s) {
    const Matter_Diagnostics_General_T* g=&s->general;
    if(g->interface_count>8 || g->boot_reason>6 || g->hardware_faults>0x7ff || g->radio_faults>0x7f || g->network_faults>15) return false;
    for(unsigned i=0;i<g->interface_count;++i) {
        const Matter_Diagnostics_Interface_T* a=&g->interfaces[i];
        if(a->name_size>32 || !valid_utf8(a->name,a->name_size) || a->ipv4_count>4 || a->ipv6_count>8 || a->type>4 ||
            a->reachable4 < -1 || a->reachable4>1 || a->reachable6 < -1 || a->reachable6>1) return false;
        if((a->type==1 || a->type==2) && (a->hardware[0] || a->hardware[1])) return false;
        for(unsigned j=0;j<i;++j) if(a->name_size==g->interfaces[j].name_size && !memcmp(a->name,g->interfaces[j].name,a->name_size)) return false;
        for(unsigned j=0;j<a->ipv6_count;++j) if(a->ipv6[j][0]==255) return false;
    }
    for(unsigned i=0;i<5;++i) {
        if(g->subscriptions[i].index==255 || (!g->subscriptions[i].index && g->subscriptions[i].current)) return false;
        for(unsigned j=0;j<i;++j) if(g->subscriptions[i].index && g->subscriptions[i].index==g->subscriptions[j].index) return false;
    }
    return !s->wifi.online || (s->wifi.security<=5 && s->wifi.version<=6 && s->wifi.rssi>=-120 && s->wifi.rssi<=0);
}
Matter_Result_T matter_diagnostics_refresh(Matter_Diagnostics_T handle) {
    Diagnostics m=matter_cluster_context(handle,destroy);
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    m->busy=true; memset(&m->pending,0,sizeof(m->pending));
    Matter_Result_T r=m->port.snapshot(m->port.user,&m->pending);
    if(r==MATTER_OK && !valid(&m->pending)) r=MATTER_PORT_ERROR;
    if(r==MATTER_OK && m->initialized && m->pending.general.system_ms<m->current.general.system_ms) r=MATTER_PORT_ERROR;
    if(r==MATTER_OK) {
        if(!m->valid || memcmp(&m->current.general,&m->pending.general,sizeof(m->current.general))) ++m->general_version;
        if(!m->valid || memcmp(&m->current.wifi,&m->pending.wifi,sizeof(m->current.wifi))) ++m->wifi_version;
        m->current=m->pending; m->initialized=true;
    }
    m->valid=r==MATTER_OK; m->busy=false; return r;
}
Matter_Cluster_T matter_diagnostics_new(const Matter_Diagnostics_Port_T* p,uint32_t gv,uint32_t wv) {
    if(!p || !p->snapshot || !p->reset_counts) return NULL;
    Diagnostics m=calloc(1,sizeof(*m)); if(!m) return NULL;
    m->port=*p; m->general_version=gv-1; m->wifi_version=wv-1;
    m->interface=interface_new(m,false); if(!m->interface) { free(m); return NULL; }
    m->wifi=interface_new(m,true);
    if(!m->wifi) { matter_cluster_abandon(m->interface); free(m); return NULL; }
    if(matter_diagnostics_refresh(m->interface)!=MATTER_OK) { matter_cluster_abandon(m->wifi); matter_cluster_abandon(m->interface); free(m); return NULL; }
    (void)matter_cluster_retain(m->wifi); (void)matter_cluster_seal(m->interface); return m->interface;
}
static Matter_Result_T destroy(void* ctx) {
    Diagnostics m=ctx;
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(matter_cluster_in_use(m->wifi) || matter_cluster_pins(m->wifi)!=1) return MATTER_BUSY;
    (void)matter_cluster_release(m->wifi); (void)matter_cluster_delete(m->wifi);
    memset(m,0,sizeof(*m)); free(m); return MATTER_OK;
}
Matter_Result_T matter_diagnostics_version(Matter_Diagnostics_T handle,uint32_t c,uint32_t* v) {
    Diagnostics m=matter_cluster_context(handle,destroy);
    if(!m || !v || !matter_diagnostics_cluster(c)) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(!m->valid) return MATTER_PORT_ERROR; /* Filters must not hide a backend error. */
    *v=c==MATTER_DIAGNOSTICS_GENERAL?m->general_version:m->wifi_version; return MATTER_OK;
}
static bool put(Diagnostics m,Matter_Tlv_Writer_T* w,Matter_Tlv_Type_T t,int tag,uint64_t v,const uint8_t* d,size_t n) {
    m->e=(Matter_Tlv_Element_T){.type=t,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=v,.data=d,.size=n};
    return matter_tlv_write(w,&m->e,0)==MATTER_TLV_OK;
}
#define P(t,tag,v) put(m,w,t,tag,v,NULL,0)
#define U(tag,v) P(MATTER_TLV_UNSIGNED,tag,v)
#define END() P(MATTER_TLV_END,-1,0)
static bool interfaces(Diagnostics m,Matter_Tlv_Writer_T* w) {
    for(unsigned i=0;i<m->current.general.interface_count;++i) {
        const Matter_Diagnostics_Interface_T* a=&m->current.general.interfaces[i];
        if(!P(MATTER_TLV_STRUCTURE,-1,0) || !put(m,w,MATTER_TLV_UTF8,0,0,a->name,a->name_size) || !P(MATTER_TLV_BOOL,1,a->operational) ||
            !P(a->reachable4<0?MATTER_TLV_NULL:MATTER_TLV_BOOL,2,a->reachable4==1) ||
            !P(a->reachable6<0?MATTER_TLV_NULL:MATTER_TLV_BOOL,3,a->reachable6==1) ||
            !put(m,w,MATTER_TLV_BYTES,4,0,a->hardware,8) || !P(MATTER_TLV_ARRAY,5,0)) return false;
        for(unsigned j=0;j<a->ipv4_count;++j) if(!put(m,w,MATTER_TLV_BYTES,-1,0,a->ipv4[j],4)) return false;
        if(!END() || !P(MATTER_TLV_ARRAY,6,0)) return false;
        for(unsigned j=0;j<a->ipv6_count;++j) if(!put(m,w,MATTER_TLV_BYTES,-1,0,a->ipv6[j],16)) return false;
        if(!END() || !U(7,a->type) || !END()) return false;
    }
    return true;
}

uint8_t matter_diagnostics_read(Matter_Diagnostics_T handle,uint32_t c,uint32_t a,uint8_t index,Matter_Im_Value_T* out) {
    Diagnostics m=matter_cluster_context(handle,destroy); if(!m) return MATTER_IM_FAILURE;
    if(!matter_diagnostics_cluster(c)) return MATTER_IM_UNSUPPORTED_CLUSTER;
    Matter_Cluster_Request_T q={.fabric=index}; return matter_cluster_read(c==MATTER_DIAGNOSTICS_GENERAL?handle:m->wifi,a,&q,out);
}
uint8_t matter_diagnostics_command(Matter_Diagnostics_T handle,uint32_t c,uint32_t cmd,Matter_Im_Command_T* out) {
    Diagnostics m=matter_cluster_context(handle,destroy); if(!m || m->busy) return MATTER_IM_FAILURE;
    if(!matter_diagnostics_cluster(c)) return MATTER_IM_UNSUPPORTED_CLUSTER;
    return matter_cluster_command_metadata(c==MATTER_DIAGNOSTICS_GENERAL?handle:m->wifi,cmd,out);
}
uint8_t matter_diagnostics_validate(Matter_Diagnostics_T handle,uint32_t c,uint32_t cmd,const uint8_t* data,size_t n) {
    Diagnostics m=matter_cluster_context(handle,destroy);
    if(!m) return MATTER_IM_FAILURE;
    Matter_Im_Command_T metadata; uint8_t r=matter_diagnostics_command(m->interface,c,cmd,&metadata); if(r) return r;
    const Matter_Tlv_Validation_Options_T opt={1024,256,2048,4,false,0,0}; Matter_Tlv_Validation_Report_T report;
    if(matter_tlv_validate(data,n,&opt,&m->validation,m->tags,64,&report)!=MATTER_TLV_OK ||
        matter_tlv_init(&m->reader,data,n,4)!=MATTER_TLV_OK || matter_tlv_next(&m->reader,&m->e)!=MATTER_TLV_OK ||
        m->e.type!=MATTER_TLV_STRUCTURE || m->e.tag.control) return MATTER_IM_INVALID_COMMAND;
    unsigned seen=0; bool trigger=c==MATTER_DIAGNOSTICS_GENERAL && !cmd;
    m->request_key=NULL; m->request_event=0;
    while(matter_tlv_next(&m->reader,&m->e)==MATTER_TLV_OK) {
        if(m->e.type==MATTER_TLV_END) return (!trigger || seen==3) && matter_tlv_next(&m->reader,&m->e)==MATTER_TLV_DONE?0:MATTER_IM_INVALID_COMMAND;
        if(m->e.tag.control!=1) return MATTER_IM_INVALID_COMMAND;
        unsigned tag=m->e.tag.number;
        if(trigger && tag<2) {
            if(seen&(1u<<tag)) return MATTER_IM_INVALID_COMMAND;
            seen|=1u<<tag;
            if((tag==0 && m->e.type!=MATTER_TLV_BYTES) || (tag==1 && m->e.type!=MATTER_TLV_UNSIGNED)) return MATTER_IM_INVALID_COMMAND;
            if(tag==0 && m->e.size!=16) return MATTER_IM_CONSTRAINT_ERROR;
            if(tag==0) m->request_key=m->e.data;
            else m->request_event=m->e.unsigned_value;
        } else if((m->e.type==MATTER_TLV_STRUCTURE || m->e.type==MATTER_TLV_ARRAY || m->e.type==MATTER_TLV_LIST) && matter_tlv_skip_container(&m->reader)!=MATTER_TLV_OK) return MATTER_IM_INVALID_COMMAND;
    }
    return MATTER_IM_INVALID_COMMAND;
}
Matter_Im_Command_Result_T matter_diagnostics_invoke(Matter_Diagnostics_T handle,uint32_t c,uint32_t cmd,const uint8_t* d,size_t n,Matter_Tlv_Writer_T* w) {
    Diagnostics m=matter_cluster_context(handle,destroy);
    if(!m) return (Matter_Im_Command_Result_T){.status=MATTER_IM_FAILURE};
    uint8_t r=matter_diagnostics_validate(m->interface,c,cmd,d,n); if(r) return (Matter_Im_Command_Result_T){.status=r};
    if(c==MATTER_DIAGNOSTICS_GENERAL && !cmd) {
        uint8_t any=0,diff=0;
        for(unsigned i=0;i<16;++i) { any|=m->request_key[i]; diff|=m->request_key[i]^m->test.enable_key[i]; }
        m->request_key=NULL;
        if(!any || diff || !m->test.trigger) return (Matter_Im_Command_Result_T){.status=MATTER_IM_CONSTRAINT_ERROR};
        m->busy=true; r=m->test.trigger(m->test.user,m->request_event); m->busy=false;
        return (Matter_Im_Command_Result_T){.status=r};
    }
    if(c==MATTER_DIAGNOSTICS_GENERAL) {
        if(!w || w->size || w->capacity<22) return (Matter_Im_Command_Result_T){.status=MATTER_IM_RESOURCE_EXHAUSTED};
        if(matter_diagnostics_refresh(m->interface)!=MATTER_OK) return (Matter_Im_Command_Result_T){.status=MATTER_IM_FAILURE};
        const Matter_Diagnostics_General_T* g=&m->current.general;
        if(!P(MATTER_TLV_STRUCTURE,-1,0) || !U(0,g->system_ms) || !P(g->posix_valid?MATTER_TLV_UNSIGNED:MATTER_TLV_NULL,1,g->posix_ms) || !END()) r=MATTER_IM_FAILURE;
    } else {
        m->busy=true; Matter_Result_T result=m->port.reset_counts(m->port.user); m->busy=false;
        if(result!=MATTER_OK) r=MATTER_IM_FAILURE;
        else {
            memset(m->current.wifi.counts,0,sizeof(m->current.wifi.counts)); ++m->wifi_version;
            /* No second fallible callback after effects. Next owner refresh
             * acquires all telemetry; ResetCounts does not reset OverrunCount. */
        }
    }
    return (Matter_Im_Command_Result_T){.status=r};
}

Matter_Result_T matter_diagnostics_delete(Matter_Diagnostics_T m) {
    return matter_cluster_context(m,destroy)?matter_cluster_delete(m):MATTER_INVALID_ARGUMENT;
}
Matter_Cluster_T matter_diagnostics_wifi(Matter_Diagnostics_T handle) {
    Diagnostics m=matter_cluster_context(handle,destroy); return m?m->wifi:NULL;
}
static Matter_Result_T general_version(void* u,uint32_t* v) { Diagnostics m=u; return matter_diagnostics_version(m->interface,MATTER_DIAGNOSTICS_GENERAL,v); }
static Matter_Result_T wifi_version(void* u,uint32_t* v) { Diagnostics m=u; return matter_diagnostics_version(m->interface,MATTER_DIAGNOSTICS_WIFI,v); }
typedef struct { const uint32_t* ids; size_t count; uint32_t value; bool wifi; } Metadata;
static uint8_t read_metadata(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)q; Diagnostics m=u; const Metadata* d=ref; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=d->value,.data_version=d->wifi?m->wifi_version:m->general_version};
    return 0;
}
static uint8_t read_ids(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    uint8_t r=read_metadata(u,ref,q,v); if(r) return r;
    Diagnostics m=u; const Metadata* d=ref; Matter_Tlv_Writer_T* w=&m->writer;
    if(matter_tlv_writer_init(w,m->encoded,sizeof(m->encoded),1)!=MATTER_TLV_OK || !P(MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
    for(size_t i=0;i<d->count;++i) if(!U(-1,d->ids[i])) return MATTER_IM_FAILURE;
    if(!END() || matter_tlv_writer_finish(w,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->type=MATTER_TLV_ARRAY; v->data=m->encoded; return 0;
}
static uint8_t general_0(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_General_T* g=&m->current.general; (void)g;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->general_version};
    Matter_Tlv_Writer_T* w=&m->writer;
    if(matter_tlv_writer_init(w,m->encoded,sizeof(m->encoded),4)!=MATTER_TLV_OK || !P(MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
    if(!interfaces(m,w)) return MATTER_IM_FAILURE;
    if(!END() || matter_tlv_writer_finish(w,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->type=MATTER_TLV_ARRAY; v->data=m->encoded; return 0;
}
static uint8_t general_1(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_General_T* g=&m->current.general; (void)g;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->general_version};
    v->unsigned_value=g->reboots; return 0;
}
static uint8_t general_2(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_General_T* g=&m->current.general; (void)g;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->general_version};
    v->unsigned_value=g->system_ms/1000; return 0;
}
static uint8_t general_3(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_General_T* g=&m->current.general; (void)g;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->general_version};
    v->unsigned_value=g->operational_hours; return 0;
}
static uint8_t general_4(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_General_T* g=&m->current.general; (void)g;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->general_version};
    v->unsigned_value=g->boot_reason; return 0;
}
static uint8_t general_5(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_General_T* g=&m->current.general; (void)g;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->general_version};
    Matter_Tlv_Writer_T* w=&m->writer;
    if(matter_tlv_writer_init(w,m->encoded,sizeof(m->encoded),4)!=MATTER_TLV_OK || !P(MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
    unsigned bits=g->hardware_faults;
    for(unsigned i=0;i<11;++i) if((bits&(1u<<i)) && !U(-1,i)) return MATTER_IM_FAILURE;
    if(!END() || matter_tlv_writer_finish(w,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->type=MATTER_TLV_ARRAY; v->data=m->encoded; return 0;
}
static uint8_t general_6(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_General_T* g=&m->current.general; (void)g;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->general_version};
    Matter_Tlv_Writer_T* w=&m->writer;
    if(matter_tlv_writer_init(w,m->encoded,sizeof(m->encoded),4)!=MATTER_TLV_OK || !P(MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
    unsigned bits=g->radio_faults;
    for(unsigned i=0;i<11;++i) if((bits&(1u<<i)) && !U(-1,i)) return MATTER_IM_FAILURE;
    if(!END() || matter_tlv_writer_finish(w,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->type=MATTER_TLV_ARRAY; v->data=m->encoded; return 0;
}
static uint8_t general_7(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_General_T* g=&m->current.general; (void)g;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->general_version};
    Matter_Tlv_Writer_T* w=&m->writer;
    if(matter_tlv_writer_init(w,m->encoded,sizeof(m->encoded),4)!=MATTER_TLV_OK || !P(MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
    unsigned bits=g->network_faults;
    for(unsigned i=0;i<11;++i) if((bits&(1u<<i)) && !U(-1,i)) return MATTER_IM_FAILURE;
    if(!END() || matter_tlv_writer_finish(w,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->type=MATTER_TLV_ARRAY; v->data=m->encoded; return 0;
}
static uint8_t general_8(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_General_T* g=&m->current.general; (void)g;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->general_version};
    (void)g; v->type=MATTER_TLV_BOOL; v->unsigned_value=m->test.trigger!=NULL; return 0;
}
static uint8_t general_10(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_General_T* g=&m->current.general; (void)g;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->general_version};
    Matter_Tlv_Writer_T* w=&m->writer;
    if(matter_tlv_writer_init(w,m->encoded,sizeof(m->encoded),4)!=MATTER_TLV_OK || !P(MATTER_TLV_STRUCTURE,-1,0)) return MATTER_IM_FAILURE;
    uint32_t all=0,own=0;
    for(unsigned i=0;i<5;++i) { all+=g->subscriptions[i].current; if(q->fabric && g->subscriptions[i].index==q->fabric) own=g->subscriptions[i].current; }
    if(!U(0,all>65535?65535:all) || !U(1,own) || !U(2,g->total_subscriptions) || !U(3,g->im_sent) || !U(4,g->im_received)) return MATTER_IM_FAILURE;
    if(!END() || matter_tlv_writer_finish(w,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->type=MATTER_TLV_STRUCTURE; v->data=m->encoded; return 0;
}
static uint8_t wifi_0(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_Wifi_T* w=&m->current.wifi;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->wifi_version};
    if(!w->online) { v->type=MATTER_TLV_NULL; return 0; }
    v->type=MATTER_TLV_BYTES; v->data=w->bssid; v->size=6; return 0;
}
static uint8_t wifi_1(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_Wifi_T* w=&m->current.wifi;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->wifi_version};
    if(!w->online) { v->type=MATTER_TLV_NULL; return 0; }
    v->unsigned_value=w->security; return 0;
}
static uint8_t wifi_2(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_Wifi_T* w=&m->current.wifi;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->wifi_version};
    if(!w->online) { v->type=MATTER_TLV_NULL; return 0; }
    v->unsigned_value=w->version; return 0;
}
static uint8_t wifi_3(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_Wifi_T* w=&m->current.wifi;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->wifi_version};
    if(!w->online) { v->type=MATTER_TLV_NULL; return 0; }
    v->unsigned_value=w->channel; return 0;
}
static uint8_t wifi_4(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_Wifi_T* w=&m->current.wifi;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->wifi_version};
    if(!w->online) { v->type=MATTER_TLV_NULL; return 0; }
    v->type=MATTER_TLV_SIGNED; v->signed_value=w->rssi; return 0;
}
static uint8_t wifi_5(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_Wifi_T* w=&m->current.wifi;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->wifi_version};
    if(!w->online) { v->type=MATTER_TLV_NULL; return 0; }
    v->unsigned_value=w->counts[0]; return 0;
}
static uint8_t wifi_6(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_Wifi_T* w=&m->current.wifi;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->wifi_version};
    if(!w->online) { v->type=MATTER_TLV_NULL; return 0; }
    v->unsigned_value=w->counts[1]; return 0;
}
static uint8_t wifi_7(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_Wifi_T* w=&m->current.wifi;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->wifi_version};
    if(!w->online) { v->type=MATTER_TLV_NULL; return 0; }
    v->unsigned_value=w->counts[2]; return 0;
}
static uint8_t wifi_8(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_Wifi_T* w=&m->current.wifi;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->wifi_version};
    if(!w->online) { v->type=MATTER_TLV_NULL; return 0; }
    v->unsigned_value=w->counts[3]; return 0;
}
static uint8_t wifi_9(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_Wifi_T* w=&m->current.wifi;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->wifi_version};
    if(!w->online) { v->type=MATTER_TLV_NULL; return 0; }
    v->unsigned_value=w->counts[4]; return 0;
}
static uint8_t wifi_10(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_Wifi_T* w=&m->current.wifi;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->wifi_version};
    if(!w->online) { v->type=MATTER_TLV_NULL; return 0; }
    v->unsigned_value=w->counts[5]; return 0;
}
static uint8_t wifi_11(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_Wifi_T* w=&m->current.wifi;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->wifi_version};
    if(!w->online) { v->type=MATTER_TLV_NULL; return 0; }
    v->unsigned_value=w->max_rate; return 0;
}
static uint8_t wifi_12(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Diagnostics m=u; if(m->busy || !m->valid) return MATTER_IM_FAILURE;
    const Matter_Diagnostics_Wifi_T* w=&m->current.wifi;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->wifi_version};
    if(!w->online) { v->type=MATTER_TLV_NULL; return 0; }
    v->unsigned_value=w->overruns; return 0;
}

typedef struct { uint32_t cluster,command; } Command;
static uint8_t cluster_validate(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    (void)q; Diagnostics m=u; const Command* c=ref;
    return matter_diagnostics_validate(m->interface,c->cluster,c->command,d,n);
}
static Matter_Result_T cluster_start(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out,uint64_t* token) {
    Diagnostics m=u; const Command* c=ref; *token=0;
    *out=q->is_case?matter_diagnostics_invoke(m->interface,c->cluster,c->command,d,n,w):
        (Matter_Im_Command_Result_T){.status=MATTER_IM_INVALID_ACTION}; return MATTER_OK;
}
static Matter_Cluster_T interface_new(Diagnostics m,bool wifi) {
    Matter_Cluster_Config_T cfg={.id=wifi?MATTER_DIAGNOSTICS_WIFI:MATTER_DIAGNOSTICS_GENERAL,
        .attributes=wifi?MATTER_DIAGNOSTICS_WIFI_ATTRS:MATTER_DIAGNOSTICS_GENERAL_ATTRS,.commands=wifi?1:2,.events=wifi?0:1,
        .callbacks={.ctx=m,.version=wifi?wifi_version:general_version,.destroy=wifi?NULL:destroy}};
    Matter_Cluster_T c=matter_cluster_new(&cfg); if(!c) return NULL;
    if(!wifi) {
        const Matter_Event_Def_T event={3,MATTER_IM_VIEW,2,false};
        if(matter_cluster_add_event(c,&event)!=MATTER_OK) { matter_cluster_abandon(c); return NULL; }
    }
    static const uint32_t generated[]={2},accepted[]={0,1};
    static const Metadata gm[]={{generated,1,0,false},{accepted,2,0,false},{general_attrs,MATTER_DIAGNOSTICS_GENERAL_ATTRS,0,false},{NULL,0,0,false},{NULL,0,3,false}};
    static const Metadata wm[]={{NULL,0,0,true},{accepted,1,0,true},{wifi_attrs,MATTER_DIAGNOSTICS_WIFI_ATTRS,0,true},{NULL,0,3,true},{NULL,0,1,true}};
    static const Matter_Attribute_Def_T general_defs[]={
        {.id=0,.read_access={MATTER_IM_VIEW,false},.read=general_0},
        {.id=1,.read_access={MATTER_IM_VIEW,false},.read=general_1},
        {.id=2,.read_access={MATTER_IM_VIEW,false},.read=general_2},
        {.id=3,.read_access={MATTER_IM_VIEW,false},.read=general_3},
        {.id=4,.read_access={MATTER_IM_VIEW,false},.read=general_4},
        {.id=5,.read_access={MATTER_IM_VIEW,false},.read=general_5},
        {.id=6,.read_access={MATTER_IM_VIEW,false},.read=general_6},
        {.id=7,.read_access={MATTER_IM_VIEW,false},.read=general_7},
        {.id=8,.read_access={MATTER_IM_VIEW,false},.read=general_8},
        {.id=10,.read_access={MATTER_IM_VIEW,false},.read=general_10},
        {.id=0xfff8,.read_access={MATTER_IM_VIEW,false},.read=read_ids,.ref=&gm[0]},
        {.id=0xfff9,.read_access={MATTER_IM_VIEW,false},.read=read_ids,.ref=&gm[1]},
        {.id=0xfffb,.read_access={MATTER_IM_VIEW,false},.read=read_ids,.ref=&gm[2]},
        {.id=0xfffc,.read_access={MATTER_IM_VIEW,false},.read=read_metadata,.ref=&gm[3]},
        {.id=0xfffd,.read_access={MATTER_IM_VIEW,false},.read=read_metadata,.ref=&gm[4]},
    };
    static const Matter_Attribute_Def_T wifi_defs[]={
        {.id=0,.read_access={MATTER_IM_VIEW,false},.read=wifi_0},
        {.id=1,.read_access={MATTER_IM_VIEW,false},.read=wifi_1},
        {.id=2,.read_access={MATTER_IM_VIEW,false},.read=wifi_2},
        {.id=3,.read_access={MATTER_IM_VIEW,false},.read=wifi_3},
        {.id=4,.read_access={MATTER_IM_VIEW,false},.read=wifi_4},
        {.id=5,.read_access={MATTER_IM_VIEW,false},.read=wifi_5},
        {.id=6,.read_access={MATTER_IM_VIEW,false},.read=wifi_6},
        {.id=7,.read_access={MATTER_IM_VIEW,false},.read=wifi_7},
        {.id=8,.read_access={MATTER_IM_VIEW,false},.read=wifi_8},
        {.id=9,.read_access={MATTER_IM_VIEW,false},.read=wifi_9},
        {.id=10,.read_access={MATTER_IM_VIEW,false},.read=wifi_10},
        {.id=11,.read_access={MATTER_IM_VIEW,false},.read=wifi_11},
        {.id=12,.read_access={MATTER_IM_VIEW,false},.read=wifi_12},
        {.id=0xfff8,.read_access={MATTER_IM_VIEW,false},.read=read_ids,.ref=&wm[0]},
        {.id=0xfff9,.read_access={MATTER_IM_VIEW,false},.read=read_ids,.ref=&wm[1]},
        {.id=0xfffb,.read_access={MATTER_IM_VIEW,false},.read=read_ids,.ref=&wm[2]},
        {.id=0xfffc,.read_access={MATTER_IM_VIEW,false},.read=read_metadata,.ref=&wm[3]},
        {.id=0xfffd,.read_access={MATTER_IM_VIEW,false},.read=read_metadata,.ref=&wm[4]},
    };
    const Matter_Attribute_Def_T* attrs=wifi?wifi_defs:general_defs;
    for(size_t i=0;i<cfg.attributes;++i) if(matter_cluster_add_attribute(c,&attrs[i])!=MATTER_OK) { matter_cluster_abandon(c); return NULL; }
    static const Command refs[]={{MATTER_DIAGNOSTICS_GENERAL,0},{MATTER_DIAGNOSTICS_GENERAL,1},{MATTER_DIAGNOSTICS_WIFI,0}};
    for(unsigned i=0;i<cfg.commands;++i) {
        const Command* ref=&refs[wifi?2:i];
        Matter_Command_Def_T cmd={.id=ref->command,.ref=ref,.validate=cluster_validate,.start=cluster_start,
            .access={.privilege=!wifi && !i?MATTER_IM_MANAGE:MATTER_IM_OPERATE,.response=!wifi && i==1,.response_command=2,.response_capacity=22}};
        if(matter_cluster_add_command(c,&cmd)!=MATTER_OK) { matter_cluster_abandon(c); return NULL; }
    }
    return c;
}
