#include "matter_wifi.h"
#include "../model/matter_cluster_internal.h"
#include <stdlib.h>
#include <string.h>
const uint32_t matter_wifi_attributes[MATTER_WIFI_ATTRIBUTE_COUNT]={0,1,2,3,4,5,6,7,8,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
typedef struct Matter_Wifi* Wifi;
static Matter_Result_T destroy(void*);
static Matter_Cluster_T interface_new(Wifi);
struct Matter_Wifi {
    Matter_Cluster_T interface;
    Matter_Wifi_Config_T config; Matter_Wifi_Port_T port;
    Matter_Wifi_Settings_T settings, snapshot, candidate;
    Matter_Wifi_Id_T connected, saved_connected, last_id;
    Matter_Wifi_Network_T request, moving;
    Matter_Wifi_Completion_T completion;
    Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T e; Matter_Tlv_Writer_T writer;
    uint8_t encoded[256];
    uint64_t now, deadline, serial, token, crumb;
    uint32_t command;
    uint8_t last_status, index;
    int32_t last_error;
    bool busy, checkpoint, active, draining, ready, detached, crumb_present;
    bool status_present, error_present, breadcrumb_ready;
};
static void erase(void* data,size_t n) { volatile uint8_t* p=data; while(n--) *p++=0; }
static bool id_equal(const Matter_Wifi_Id_T* a,const Matter_Wifi_Id_T* b) {
    return a->size==b->size && !memcmp(a->bytes,b->bytes,a->size);
}
static int find(Wifi m,const Matter_Wifi_Id_T* id) {
    for(unsigned i=0;i<m->settings.count;++i) if(id_equal(id,&m->settings.networks[i].id)) return (int)i;
    return -1;
}
static bool credentials_valid(const Matter_Wifi_Network_T* n) {
    unsigned size=n->credential_size;
    if(size==0 || size==5 || (size>=8 && size<=63)) return true;
    if(size!=64) return false;
    for(unsigned i=0;i<64;++i) {
        uint8_t c=n->credentials[i];
        if(!((c>='0' && c<='9') || (c>='a' && c<='f') || (c>='A' && c<='F'))) return false;
    }
    return true;
}
static bool valid_settings(Wifi m) {
    if(m->settings.count>m->config.max_networks || m->connected.size>32) return false;
    for(unsigned i=0;i<m->settings.count;++i) {
        Matter_Wifi_Network_T* n=&m->settings.networks[i];
        if(!n->id.size || n->id.size>32 || !credentials_valid(n)) return false;
        for(unsigned j=0;j<i;++j) if(id_equal(&n->id,&m->settings.networks[j].id)) return false;
    }
    return true;
}
Matter_Cluster_T matter_wifi_new(const Matter_Wifi_Config_T* c,const Matter_Wifi_Port_T* p,uint64_t now) {
    if(!c || !p || !p->load || !p->configure || !p->start || !p->cancel || !p->restore ||
        !c->max_networks || c->max_networks>MATTER_WIFI_NETWORKS || !c->scan_seconds || !c->connect_seconds ||
        !c->bands || (c->bands&~63u) || c->token_seed==UINT64_MAX) return NULL;
    Wifi m=calloc(1,sizeof(*m)); if(!m) return NULL;
    m->config=*c; m->port=*p; m->now=now; m->serial=c->token_seed; m->busy=true;
    Matter_Result_T r=p->load(p->user,&m->settings,&m->connected); m->busy=false;
    if(r!=MATTER_OK || !valid_settings(m)) { erase(m,sizeof(*m)); free(m); return NULL; }
    if(m->connected.size) { m->status_present=true; m->last_id=m->connected; }
    m->interface=interface_new(m); if(!m->interface) { erase(m,sizeof(*m)); free(m); return NULL; }
    return m->interface;
}
static Matter_Result_T destroy(void* ctx) {
    Wifi m=ctx;
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->active || m->draining || m->token || m->checkpoint) return MATTER_INVALID_STATE;
    erase(m,sizeof(*m)); free(m); return MATTER_OK;
}
static bool put(Wifi m,Matter_Tlv_Writer_T* w,Matter_Tlv_Type_T t,int tag,uint64_t value,const uint8_t* data,size_t size) {
    m->e=(Matter_Tlv_Element_T){.type=t,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},
        .unsigned_value=value,.signed_value=(int64_t)value,.data=data,.size=size};
    return matter_tlv_write(w,&m->e,0)==MATTER_TLV_OK;
}
#define PUT(t,tag,v) put(m,w,t,tag,v,NULL,0)
#define BYTES(tag,p,n) put(m,w,MATTER_TLV_BYTES,tag,0,p,n)
uint32_t matter_wifi_version(Matter_Wifi_T handle) {
    Wifi m=matter_cluster_context(handle,destroy); return m?m->config.data_version:0; }
uint8_t matter_wifi_describe(Matter_Wifi_T m,uint32_t a,Matter_Im_Attribute_T* out) {
    return matter_cluster_context(m,destroy)?matter_cluster_describe(m,a,out):MATTER_IM_FAILURE;
}
uint8_t matter_wifi_read(Matter_Wifi_T m,uint32_t a,Matter_Im_Value_T* v) {
    if(!matter_cluster_context(m,destroy)) return MATTER_IM_FAILURE;
    Matter_Cluster_Request_T q={0}; return matter_cluster_read(m,a,&q,v);
}
uint8_t matter_wifi_write_validate(Matter_Wifi_T handle,const uint8_t* data,size_t size) {
    Wifi m=matter_cluster_context(handle,destroy);
    if(!m || m->busy) return MATTER_IM_FAILURE;
    if(matter_tlv_init(&m->reader,data,size,1)!=MATTER_TLV_OK || matter_tlv_next(&m->reader,&m->e)!=MATTER_TLV_OK ||
        m->e.tag.control || m->e.type!=MATTER_TLV_BOOL) return MATTER_IM_INVALID_DATA_TYPE;
    m->candidate=m->settings; m->candidate.enabled=m->e.unsigned_value!=0;
    return matter_tlv_next(&m->reader,&m->e)==MATTER_TLV_DONE?0:MATTER_IM_INVALID_DATA_TYPE;
}
uint8_t matter_wifi_write(Matter_Wifi_T handle,const uint8_t* data,size_t size) {
    Wifi m=matter_cluster_context(handle,destroy);
    if(!m) return MATTER_IM_FAILURE;
    uint8_t code=matter_wifi_write_validate(m->interface,data,size); if(code) return code;
    if(m->active || m->draining || m->token) return MATTER_WIFI_BUSY;
    if(m->candidate.enabled==m->settings.enabled) return 0;
    m->busy=true; Matter_Result_T r=m->port.configure(m->port.user,&m->candidate); m->busy=false;
    if(r!=MATTER_OK) return MATTER_IM_FAILURE;
    m->settings=m->candidate; if(!m->settings.enabled) m->connected.size=0; ++m->config.data_version; return 0;
}
uint8_t matter_wifi_command(Matter_Wifi_T handle,uint32_t c,Matter_Im_Command_T* out) {
    Wifi m=matter_cluster_context(handle,destroy); if(!m || m->busy) return MATTER_IM_FAILURE;
    return matter_cluster_command_metadata(handle,c,out);
}
uint8_t matter_wifi_validate(Matter_Wifi_T handle,uint32_t c,const uint8_t* data,size_t size) {
    Wifi m=matter_cluster_context(handle,destroy);
    if(!m) return MATTER_IM_FAILURE;
    Matter_Im_Command_T meta; uint8_t code=matter_wifi_command(m->interface,c,&meta); if(code) return code;
    if(matter_tlv_init(&m->reader,data,size,4)!=MATTER_TLV_OK || matter_tlv_next(&m->reader,&m->e)!=MATTER_TLV_OK ||
        m->e.type!=MATTER_TLV_STRUCTURE || m->e.tag.control) return MATTER_IM_INVALID_COMMAND;
    /* Validation scratch must not overwrite a pending operation's copied request. */
    unsigned seen=0;
    while(matter_tlv_next(&m->reader,&m->e)==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&m->e;
        if(e->type==MATTER_TLV_END) {
            unsigned required=c==0?0:c==2 || c==8?3:1;
            return (seen&required)==required && matter_tlv_next(&m->reader,e)==MATTER_TLV_DONE?0:MATTER_IM_INVALID_COMMAND;
        }
        unsigned n=e->tag.number, crumb=c==2 || c==8?2:1;
        if(e->tag.control!=1 || n>crumb) {
            if((e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) &&
                matter_tlv_skip_container(&m->reader)!=MATTER_TLV_OK) return MATTER_IM_INVALID_COMMAND;
            continue;
        }
        if(seen&(1u<<n)) return MATTER_IM_INVALID_COMMAND;
        seen|=1u<<n;
        if(n==crumb || (c==8 && n==1)) {
            if(e->type!=MATTER_TLV_UNSIGNED) return MATTER_IM_INVALID_COMMAND;
            if(c==8 && n==1 && e->unsigned_value>255) return MATTER_IM_CONSTRAINT_ERROR;
        } else {
            if(c==0 && n==0 && e->type==MATTER_TLV_NULL) continue;
            if(e->type!=MATTER_TLV_BYTES) return MATTER_IM_INVALID_COMMAND;
            if(e->size>(n==1?64u:32u) || (n==0 && c!=2 && !e->size)) return MATTER_IM_CONSTRAINT_ERROR;
        }
    }
    return MATTER_IM_INVALID_COMMAND;
}
static void parse(Wifi m,uint32_t c,const uint8_t* data,size_t size) {
    erase(&m->request,sizeof(m->request)); m->crumb_present=false; m->index=0;
    matter_tlv_init(&m->reader,data,size,4); matter_tlv_next(&m->reader,&m->e);
    while(matter_tlv_next(&m->reader,&m->e)==MATTER_TLV_OK && m->e.type!=MATTER_TLV_END) {
        Matter_Tlv_Element_T* e=&m->e; unsigned n=e->tag.number;
        if(e->tag.control==1 && n==0 && e->type==MATTER_TLV_BYTES) { m->request.id.size=(uint8_t)e->size; memcpy(m->request.id.bytes,e->data,e->size); }
        if(e->tag.control==1 && n==1 && c==2) { m->request.credential_size=(uint8_t)e->size; memcpy(m->request.credentials,e->data,e->size); }
        if(e->tag.control==1 && n==1 && c==8) m->index=(uint8_t)e->unsigned_value;
        if(e->tag.control==1 && n==(c==2 || c==8?2u:1u)) { m->crumb=e->unsigned_value; m->crumb_present=true; }
        if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) matter_tlv_skip_container(&m->reader);
    }
}
static void record(Wifi m,uint8_t code) {
    m->last_status=code; m->status_present=true;
    if(m->command!=0) m->last_id=m->request.id;
    if(m->command==6) { m->error_present=m->completion.has_error && code; m->last_error=m->completion.error; }
    if(!code) { m->error_present=false; m->breadcrumb_ready=m->crumb_present; }
    ++m->config.data_version;
}
static bool encode(Wifi m,Matter_Tlv_Writer_T* w,Matter_Wifi_Reply_T* reply) {
    uint8_t code=m->completion.status;
    *reply=(Matter_Wifi_Reply_T){.breadcrumb=!code && m->crumb_present,.value=m->crumb};
    if(!w || !PUT(MATTER_TLV_STRUCTURE,-1,0) || !PUT(MATTER_TLV_UNSIGNED,0,code)) return false;
    if(m->command==6) {
        if(!PUT(m->completion.has_error && code?MATTER_TLV_SIGNED:MATTER_TLV_NULL,2,(uint64_t)(int64_t)m->completion.error)) return false;
    } else if(m->command==0) {
        if(!PUT(MATTER_TLV_ARRAY,2,0)) return false;
        if(!code) for(unsigned i=0;i<m->completion.count;++i) {
            Matter_Wifi_Ap_T* a=&m->completion.aps[i];
            if(!PUT(MATTER_TLV_STRUCTURE,-1,0) || !PUT(MATTER_TLV_UNSIGNED,0,a->security) || !BYTES(1,a->ssid.bytes,a->ssid.size) ||
                !BYTES(2,a->bssid,6) || !PUT(MATTER_TLV_UNSIGNED,3,a->channel) || !PUT(MATTER_TLV_UNSIGNED,4,a->band) ||
                !PUT(MATTER_TLV_SIGNED,5,(uint64_t)(int64_t)a->rssi) || !PUT(MATTER_TLV_END,-1,0)) return false;
        }
        if(!PUT(MATTER_TLV_END,-1,0)) return false;
    } else if(!code && !PUT(MATTER_TLV_UNSIGNED,2,m->index)) return false;
    return PUT(MATTER_TLV_END,-1,0);
}
static void clear_operation(Wifi m) {
    m->token=0; m->ready=m->detached=false; erase(&m->request,sizeof(m->request));
}
Matter_Result_T matter_wifi_invoke(Matter_Wifi_T handle,uint32_t c,bool armed,const uint8_t* data,size_t size,
    Matter_Tlv_Writer_T* out,Matter_Wifi_Reply_T* reply,uint64_t* token) {
    Wifi m=matter_cluster_context(handle,destroy);
    if(!m || !reply || !token) return MATTER_INVALID_ARGUMENT;
    *token=0; *reply=(Matter_Wifi_Reply_T){0};
    uint8_t code=matter_wifi_validate(m->interface,c,data,size);
    if(!code && c!=8 && !armed) code=MATTER_WIFI_FAILSAFE_REQUIRED;
    if(!code && (m->active || m->draining || m->token)) code=MATTER_WIFI_BUSY;
    if(!code && (!out || out->size || out->capacity<(c==0?600u:16u))) code=MATTER_IM_RESOURCE_EXHAUSTED;
    if(code) { reply->result.status=code; return MATTER_OK; }
    parse(m,c,data,size); m->command=c; memset(&m->completion,0,sizeof(m->completion));
    int at=find(m,&m->request.id); m->candidate=m->settings;
    if(c!=0 && !m->request.id.size) code=1;
    else if(c==2 && !credentials_valid(&m->request)) code=1;
    else if(c==2) {
        if(at<0 && m->settings.count==m->config.max_networks) code=2;
        else { if(at<0) at=m->candidate.count++; m->candidate.networks[at]=m->request; m->index=(uint8_t)at; }
    } else if(c==4 || c==6 || c==8) {
        if(at<0) code=3;
        else if(c==8 && m->index>=m->settings.count) code=1;
        else if(c==4) {
            m->index=(uint8_t)at; --m->candidate.count;
            memmove(&m->candidate.networks[at],&m->candidate.networks[at+1],(m->candidate.count-(unsigned)at)*sizeof(m->request));
            erase(&m->candidate.networks[m->candidate.count],sizeof(m->request));
        } else if(c==8) {
            m->moving=m->candidate.networks[at];
            if((unsigned)at<m->index) memmove(&m->candidate.networks[at],&m->candidate.networks[at+1],(m->index-(unsigned)at)*sizeof(m->request));
            if((unsigned)at>m->index) memmove(&m->candidate.networks[m->index+1],&m->candidate.networks[m->index],((unsigned)at-m->index)*sizeof(m->request));
            m->candidate.networks[m->index]=m->moving; erase(&m->moving,sizeof(m->moving));
        }
    }
    if(!code && (c==0 || c==6)) {
        if(!m->settings.enabled) { reply->result.status=MATTER_WIFI_BUSY; clear_operation(m); return MATTER_OK; }
        if(m->serial==UINT64_MAX) { reply->result.status=MATTER_IM_RESOURCE_EXHAUSTED; clear_operation(m); return MATTER_OK; }
        if(c==6) m->request=m->settings.networks[at];
        m->token=++m->serial;
        m->busy=true; Matter_Result_T r=m->port.start(m->port.user,m->token,c==0,&m->request); m->busy=false;
        if(r==MATTER_PENDING) {
            m->active=true; uint64_t ms=(uint64_t)(c==0?m->config.scan_seconds:m->config.connect_seconds)*1000;
            m->deadline=UINT64_MAX-m->now<ms?UINT64_MAX:m->now+ms; *token=m->token; return MATTER_PENDING;
        }
        clear_operation(m); reply->result.status=r==MATTER_BUSY || r==MATTER_WOULD_BLOCK?MATTER_WIFI_BUSY:MATTER_IM_FAILURE; return MATTER_OK;
    }
    if(!code) {
        m->busy=true; Matter_Result_T r=m->port.configure(m->port.user,&m->candidate); m->busy=false;
        if(r!=MATTER_OK) code=12; else m->settings=m->candidate;
    }
    erase(&m->candidate,sizeof(m->candidate)); m->completion.status=code; record(m,code);
    if(!encode(m,out,reply)) reply->result.status=MATTER_IM_FAILURE;
    clear_operation(m); return MATTER_OK;
}
Matter_Result_T matter_wifi_complete(Matter_Wifi_T handle,uint64_t token,const Matter_Wifi_Completion_T* result) {
    Wifi m=matter_cluster_context(handle,destroy);
    if(!m || !result) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(!token || token!=m->token || !m->active || m->draining) return MATTER_INVALID_STATE;
    if(result->status>12 || result->count>MATTER_WIFI_SCAN_RESULTS) return MATTER_INVALID_ARGUMENT;
    if(m->command==0 && result->status!=0 && result->status!=1 && result->status!=5 && result->status!=6 && result->status!=12) return MATTER_INVALID_ARGUMENT;
    if(m->command==0 && result->status==5 && !m->request.id.size) return MATTER_INVALID_ARGUMENT;
    for(unsigned i=0;i<result->count;++i) {
        const Matter_Wifi_Ap_T* a=&result->aps[i];
        if(a->ssid.size>32 || a->band>5 || !(m->config.bands&(1u<<a->band)) || (a->security&~31u) ||
            (m->request.id.size && m->command==0 && !id_equal(&a->ssid,&m->request.id))) return MATTER_INVALID_ARGUMENT;
    }
    m->completion=*result; m->active=false; m->ready=true;
    if(m->command==6) { if(!result->status) m->connected=m->request.id; else if(id_equal(&m->connected,&m->request.id)) m->connected.size=0; }
    record(m,result->status); return MATTER_OK;
}
Matter_Result_T matter_wifi_poll(Matter_Wifi_T handle,uint64_t token,Matter_Tlv_Writer_T* out,Matter_Wifi_Reply_T* reply) {
    Wifi m=matter_cluster_context(handle,destroy);
    if(!m || !reply) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(!token || m->token!=token || m->detached) return MATTER_INVALID_STATE;
    if(!m->ready) return MATTER_PENDING;
    if(!encode(m,out,reply)) reply->result.status=MATTER_IM_FAILURE;
    clear_operation(m); return MATTER_OK;
}
void matter_wifi_cancel(Matter_Wifi_T handle,uint64_t token) {
    Wifi m=matter_cluster_context(handle,destroy);
    if(!m || m->busy || !token || token!=m->token) return;
    m->detached=true;
    if(m->active) { m->active=false; m->draining=true; }
    if(!m->draining) clear_operation(m);
}
Matter_Result_T matter_wifi_process(Matter_Wifi_T handle,uint64_t now) {
    Wifi m=matter_cluster_context(handle,destroy);
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(now<m->now) return MATTER_INVALID_ARGUMENT;
    m->now=now;
    if(m->active && now>=m->deadline) { m->active=false; m->draining=true; memset(&m->completion,0,sizeof(m->completion)); m->completion.status=12; }
    if(m->draining) {
        m->busy=true; Matter_Result_T r=m->port.cancel(m->port.user,m->token); m->busy=false;
        if(r!=MATTER_OK) return r==MATTER_PENDING?MATTER_PENDING:MATTER_PORT_ERROR;
        m->draining=false;
        if(m->detached) clear_operation(m);
        else { m->ready=true; if(m->command==6 && id_equal(&m->connected,&m->request.id)) m->connected.size=0; record(m,12); }
    }
    return m->active || m->draining?MATTER_PENDING:MATTER_OK;
}
Matter_Result_T matter_wifi_deadline(Matter_Wifi_T handle,uint64_t* out) {
    Wifi m=matter_cluster_context(handle,destroy);
    if(!m || !out) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(!m->active && !m->draining) return MATTER_INVALID_STATE;
    *out=m->draining?m->now:m->deadline; return MATTER_OK;
}
Matter_Result_T matter_wifi_stop(Matter_Wifi_T handle) {
    Wifi m=matter_cluster_context(handle,destroy);
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    matter_wifi_cancel(m->interface,m->token); return matter_wifi_process(m->interface,m->now);
}
Matter_Result_T matter_wifi_checkpoint(Matter_Wifi_T handle) {
    Wifi m=matter_cluster_context(handle,destroy);
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->checkpoint || m->token) return MATTER_INVALID_STATE;
    m->snapshot=m->settings; m->saved_connected=m->connected; m->checkpoint=true; return MATTER_OK;
}
Matter_Result_T matter_wifi_rollback(Matter_Wifi_T handle) {
    Wifi m=matter_cluster_context(handle,destroy);
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    Matter_Result_T r=matter_wifi_stop(m->interface); if(r!=MATTER_OK) return r;
    if(!m->checkpoint) return MATTER_OK;
    m->busy=true; r=m->port.restore(m->port.user,&m->snapshot,&m->saved_connected); m->busy=false;
    if(r!=MATTER_OK) return r==MATTER_PENDING?MATTER_PENDING:MATTER_PORT_ERROR;
    m->settings=m->snapshot; m->connected=m->saved_connected; m->checkpoint=false;
    /* Successful restore includes reconnection. Report that outcome, not the
     * abandoned candidate's LastNetworkID/error (Core 11.9.6.6-8). */
    m->status_present=m->connected.size!=0; m->last_status=0;
    m->last_id=m->connected; m->error_present=false; m->last_error=0;
    m->breadcrumb_ready=false; erase(&m->snapshot,sizeof(m->snapshot)); ++m->config.data_version; return MATTER_OK;
}

bool matter_wifi_take_breadcrumb(Matter_Wifi_T handle,uint64_t* value) {
    Wifi m=matter_cluster_context(handle,destroy);
    if(!m || !value || m->busy || !m->breadcrumb_ready) return false;
    *value=m->crumb; m->breadcrumb_ready=false; return true;
}

Matter_Result_T matter_wifi_commit_ready(Matter_Wifi_T handle) {
    Wifi m=matter_cluster_context(handle,destroy);
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    return m->checkpoint && !m->active && !m->draining && !m->token?MATTER_OK:MATTER_INVALID_STATE;
}
Matter_Result_T matter_wifi_commit(Matter_Wifi_T handle) {
    Wifi m=matter_cluster_context(handle,destroy);
    if(!m) return MATTER_INVALID_ARGUMENT;
    Matter_Result_T r=matter_wifi_commit_ready(m->interface); if(r!=MATTER_OK) return r;
    m->checkpoint=false; erase(&m->snapshot,sizeof(m->snapshot)); erase(&m->saved_connected,sizeof(m->saved_connected)); return MATTER_OK;
}

Matter_Result_T matter_wifi_delete(Matter_Wifi_T m) {
    Wifi state=matter_cluster_context(m,destroy); if(!state) return MATTER_INVALID_ARGUMENT;
    if(state->busy) return MATTER_BUSY;
    if(state->active || state->draining || state->token || state->checkpoint) return MATTER_INVALID_STATE;
    return matter_cluster_delete(m);
}

static uint8_t read_0(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Wifi m=u; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->config.data_version};
    v->unsigned_value=m->config.max_networks; return 0;
}
static uint8_t read_2(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Wifi m=u; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->config.data_version};
    v->unsigned_value=m->config.scan_seconds; return 0;
}
static uint8_t read_3(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Wifi m=u; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->config.data_version};
    v->unsigned_value=m->config.connect_seconds; return 0;
}
static uint8_t read_4(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Wifi m=u; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->config.data_version};
    v->type=MATTER_TLV_BOOL; v->unsigned_value=m->settings.enabled; return 0;
}
static uint8_t read_5(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Wifi m=u; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->config.data_version};
    v->type=m->status_present && m->settings.count?MATTER_TLV_UNSIGNED:MATTER_TLV_NULL; v->unsigned_value=m->last_status; return 0;
}
static uint8_t read_6(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Wifi m=u; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->config.data_version};
    v->type=m->last_id.size && m->settings.count?MATTER_TLV_BYTES:MATTER_TLV_NULL; v->data=m->last_id.bytes; v->size=m->last_id.size; return 0;
}
static uint8_t read_7(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Wifi m=u; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->config.data_version};
    v->type=m->error_present && m->settings.count?MATTER_TLV_SIGNED:MATTER_TLV_NULL; v->signed_value=m->last_error; return 0;
}
static uint8_t read_0xfffc(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Wifi m=u; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->config.data_version};
    v->unsigned_value=1; return 0;
}
static uint8_t read_0xfffd(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Wifi m=u; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->config.data_version};
    v->unsigned_value=2; return 0;
}
static uint8_t read_1(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Wifi m=u; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_ARRAY,.data_version=m->config.data_version};
    Matter_Tlv_Writer_T* w=&m->writer;
    if(matter_tlv_writer_init(w,m->encoded,sizeof(m->encoded),3)!=MATTER_TLV_OK || !PUT(MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
    for(unsigned i=0;i<m->settings.count;++i) {
        Matter_Wifi_Id_T* id=&m->settings.networks[i].id;
        if(!PUT(MATTER_TLV_STRUCTURE,-1,0) || !BYTES(0,id->bytes,id->size) ||
            !PUT(MATTER_TLV_BOOL,1,m->settings.enabled && id_equal(id,&m->connected)) || !PUT(MATTER_TLV_END,-1,0)) return MATTER_IM_FAILURE;
    }
    if(!PUT(MATTER_TLV_END,-1,0) || matter_tlv_writer_finish(w,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->data=m->encoded; return 0;
}
static uint8_t read_8(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Wifi m=u; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_ARRAY,.data_version=m->config.data_version};
    Matter_Tlv_Writer_T* w=&m->writer;
    if(matter_tlv_writer_init(w,m->encoded,sizeof(m->encoded),3)!=MATTER_TLV_OK || !PUT(MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
    for(unsigned i=0;i<6;++i) if((m->config.bands&(1u<<i)) && !PUT(MATTER_TLV_UNSIGNED,-1,i)) return MATTER_IM_FAILURE;
    if(!PUT(MATTER_TLV_END,-1,0) || matter_tlv_writer_finish(w,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->data=m->encoded; return 0;
}
static uint8_t read_0xfffb(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Wifi m=u; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_ARRAY,.data_version=m->config.data_version};
    Matter_Tlv_Writer_T* w=&m->writer;
    if(matter_tlv_writer_init(w,m->encoded,sizeof(m->encoded),3)!=MATTER_TLV_OK || !PUT(MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
    for(unsigned i=0;i<MATTER_WIFI_ATTRIBUTE_COUNT;++i) if(!PUT(MATTER_TLV_UNSIGNED,-1,matter_wifi_attributes[i])) return MATTER_IM_FAILURE;
    if(!PUT(MATTER_TLV_END,-1,0) || matter_tlv_writer_finish(w,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->data=m->encoded; return 0;
}
static uint8_t read_0xfff9(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Wifi m=u; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_ARRAY,.data_version=m->config.data_version};
    Matter_Tlv_Writer_T* w=&m->writer;
    if(matter_tlv_writer_init(w,m->encoded,sizeof(m->encoded),3)!=MATTER_TLV_OK || !PUT(MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
    for(unsigned i=0;i<=8;i+=2) if(!PUT(MATTER_TLV_UNSIGNED,-1,i)) return MATTER_IM_FAILURE;
    if(!PUT(MATTER_TLV_END,-1,0) || matter_tlv_writer_finish(w,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->data=m->encoded; return 0;
}
static uint8_t read_0xfff8(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; (void)q; Wifi m=u; if(m->busy) return MATTER_IM_FAILURE;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_ARRAY,.data_version=m->config.data_version};
    Matter_Tlv_Writer_T* w=&m->writer;
    if(matter_tlv_writer_init(w,m->encoded,sizeof(m->encoded),3)!=MATTER_TLV_OK || !PUT(MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
    static const uint8_t commands[]={1,5,7}; for(unsigned i=0;i<3;++i) if(!PUT(MATTER_TLV_UNSIGNED,-1,commands[i])) return MATTER_IM_FAILURE;
    if(!PUT(MATTER_TLV_END,-1,0) || matter_tlv_writer_finish(w,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->data=m->encoded; return 0;
}

static Matter_Result_T cluster_version(void* u,uint32_t* v) { Wifi m=u; *v=m->config.data_version; return MATTER_OK; }
static Matter_Result_T cluster_process(void* u,uint64_t now) { Wifi m=u; return matter_wifi_process(m->interface,now); }
static Matter_Result_T cluster_deadline(void* u,uint64_t* d) { Wifi m=u; return matter_wifi_deadline(m->interface,d); }
static uint8_t cluster_validate_write(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    (void)ref; (void)q; Wifi m=u; return matter_wifi_write_validate(m->interface,d,n);
}
static Matter_Im_Write_Result_T cluster_write(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    (void)ref; (void)q; Wifi m=u; return (Matter_Im_Write_Result_T){.status=matter_wifi_write(m->interface,d,n)};
}
static uint8_t cluster_validate_command(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    (void)q; Wifi m=u; /* CASE administrators use the same commands and fail-safe gate. */
    return matter_wifi_validate(m->interface,*(const uint32_t*)ref,d,n);
}
static Matter_Result_T cluster_start(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out,uint64_t* token) {
    Wifi m=u; Matter_Wifi_Reply_T reply;
    Matter_Result_T r=matter_wifi_invoke(m->interface,*(const uint32_t*)ref,q->armed,d,n,w,&reply,token); *out=reply.result; return r;
}
static Matter_Result_T cluster_poll(void* u,const void* ref,uint64_t token,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out) {
    (void)ref; Wifi m=u; Matter_Wifi_Reply_T reply={0};
    Matter_Result_T r=matter_wifi_poll(m->interface,token,w,&reply); *out=reply.result; return r;
}
static void cluster_cancel(void* u,const void* ref,uint64_t token) { (void)ref; Wifi m=u; matter_wifi_cancel(m->interface,token); }
static Matter_Cluster_T interface_new(Wifi m) {
    Matter_Cluster_Config_T cfg={.id=MATTER_WIFI_CLUSTER,.attributes=MATTER_WIFI_ATTRIBUTE_COUNT,.commands=5,.pending=2,
        .callbacks={.ctx=m,.version=cluster_version,.process=cluster_process,.deadline=cluster_deadline,.destroy=destroy}};
    Matter_Cluster_T c=matter_cluster_new(&cfg); if(!c) return NULL;
    static const Matter_Attribute_Def_T attrs[]={
        {.id=0,.read_access={MATTER_IM_ADMINISTER,false},.read=read_0},
        {.id=1,.read_access={MATTER_IM_ADMINISTER,false},.read=read_1},
        {.id=2,.read_access={MATTER_IM_VIEW,false},.read=read_2},
        {.id=3,.read_access={MATTER_IM_VIEW,false},.read=read_3},
        {.id=4,.read_access={MATTER_IM_VIEW,false},.read=read_4,.write_access={.privilege=MATTER_IM_ADMINISTER},.validate=cluster_validate_write,.write=cluster_write},
        {.id=5,.read_access={MATTER_IM_ADMINISTER,false},.read=read_5},
        {.id=6,.read_access={MATTER_IM_ADMINISTER,false},.read=read_6},
        {.id=7,.read_access={MATTER_IM_ADMINISTER,false},.read=read_7},
        {.id=8,.read_access={MATTER_IM_VIEW,false},.read=read_8},
        {.id=0xfff8,.read_access={MATTER_IM_VIEW,false},.read=read_0xfff8},
        {.id=0xfff9,.read_access={MATTER_IM_VIEW,false},.read=read_0xfff9},
        {.id=0xfffb,.read_access={MATTER_IM_VIEW,false},.read=read_0xfffb},
        {.id=0xfffc,.read_access={MATTER_IM_VIEW,false},.read=read_0xfffc},
        {.id=0xfffd,.read_access={MATTER_IM_VIEW,false},.read=read_0xfffd},
    };
    for(size_t i=0;i<sizeof(attrs)/sizeof(*attrs);++i) if(matter_cluster_add_attribute(c,&attrs[i])!=MATTER_OK) { matter_cluster_abandon(c); return NULL; }
    static const uint32_t ids[]={0,2,4,6,8};
    for(unsigned i=0;i<5;++i) {
        uint32_t id=ids[i]; Matter_Command_Def_T cmd={.id=id,.ref=&ids[i],.validate=cluster_validate_command,.start=cluster_start,
            .poll=(id==0 || id==6)?cluster_poll:NULL,.cancel=(id==0 || id==6)?cluster_cancel:NULL,
            .access={.privilege=MATTER_IM_ADMINISTER,.response=true,.response_command=id==0?1:id==6?7:5,.response_capacity=id==0?600:16}};
        if(matter_cluster_add_command(c,&cmd)!=MATTER_OK) { matter_cluster_abandon(c); return NULL; }
    }
    (void)matter_cluster_seal(c); return c;
}
