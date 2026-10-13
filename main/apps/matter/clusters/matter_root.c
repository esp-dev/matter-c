#include "matter_root_internal.h"
#include "../codec/matter_tlv_writer.h"
#include "../codec/matter_tlv_internal.h"
#include "../model/matter_cluster_internal.h"
#include <stdlib.h>
#include <string.h>

enum { DESCRIPTOR=0x1d, BASIC=0x28, COMMISSIONING=0x30 };
static const uint32_t descriptor_attrs[]={0,1,2,3,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
static const uint32_t basic_attrs[]={0,1,2,3,4,5,6,7,8,9,10,18,19,21,22,24,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
static const uint32_t commissioning_attrs[]={0,1,2,3,4,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
typedef struct RootEndpoint RootEndpoint;
typedef struct { Matter_Root_T root; Matter_Cluster_T interface; uint32_t* version; RootEndpoint* endpoint; } RootCluster;
struct RootEndpoint {
    Matter_Root_Endpoint_Config_T config; RootCluster descriptor;
    Matter_Cluster_T clusters[16]; size_t count;
    uint32_t clients[8]; size_t client_count;
    uint16_t parent; Matter_Root_Tag_T tags[6]; size_t tag_count;
    struct { uint32_t type; uint16_t revision; } types[4]; size_t type_count;
};
static Matter_Cluster_T builtin_new(RootCluster*,uint32_t);
static Matter_Im_Command_Result_T gc_invoke(Matter_Root_T,uint32_t,const Matter_Cluster_Request_T*,const uint8_t*,size_t,Matter_Tlv_Writer_T*);
struct Matter_Root {
    RootCluster builtin[3];
    Matter_Root_Port_T port;
    Matter_Cluster_T clusters[25],dispatch; size_t cluster_count; unsigned custom_count;
    uint32_t clients[8]; size_t client_count;
    RootEndpoint* endpoints[8]; size_t endpoint_count;
    struct { uint32_t type; uint16_t revision; } types[4]; size_t type_count;
    Matter_Wifi_T wifi;
    Matter_Opcreds_T opcreds;
    Matter_Acl_T acl;
    Matter_Groupkey_T groupkey;
    Matter_Diagnostics_T diagnostics;
    Matter_Root_Config_T config;
    Matter_Root_Settings_T pending;
    Matter_Tlv_Writer_T writer;
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Element_T token;
    uint8_t encoded[128]; /* ServerList <=127 B; six standard semantic tags <=68 B. */
    bool busy,startup_emitted;
    bool commissioning;
    Matter_Root_Commissioning_Config_T gc;
    Matter_Root_Commissioning_Port_T gc_port;
    Matter_Root_Fail_Safe_State_T fail_safe;
    uint8_t armed_fabric;
    Matter_Root_Complete_Port_T complete_port;
    uint64_t complete_serial,complete_token; Matter_Exchange_Session_T complete_session;
    uint8_t complete_index,complete_status;
    bool complete_ready;
    uint64_t now, expiry, cumulative, breadcrumb;
    struct { uint64_t breadcrumb; uint16_t seconds; uint8_t regulatory,country[2]; } args;
};
Matter_Result_T matter_root_startup(Matter_Root_T m,Matter_Events_T events,uint64_t now) {
    if(!m || !events) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->startup_emitted) return MATTER_OK;
    m->busy=true;
    /* Anonymous structure, context SoftwareVersion uint32 (Core 11.1.6.1). */
    uint32_t v=m->config.software_version;
    const uint8_t data[]={0x15,0x26,0,(uint8_t)v,(uint8_t)(v>>8),(uint8_t)(v>>16),(uint8_t)(v>>24),0x18};
    const Matter_Event_Path_T path={0,BASIC,0};
    Matter_Result_T r=matter_events_append(events,&path,2,now,false,data,sizeof(data));
    m->startup_emitted=r==MATTER_OK; m->busy=false; return r;
}
Matter_Cluster_T matter_root_cluster(Matter_Root_T m,uint32_t id) {
    if(m) for(size_t i=0;i<m->cluster_count;++i) if(matter_cluster_id(m->clusters[i])==id) return m->clusters[i];
    return NULL;
}
static RootEndpoint* endpoint(Matter_Root_T m,uint16_t id) {
    if(m) for(size_t i=0;i<m->endpoint_count;++i) if(m->endpoints[i]->config.endpoint==id) return m->endpoints[i];
    return NULL;
}
Matter_Result_T matter_root_add_client(Matter_Root_T m,uint16_t ep,uint32_t cluster) {
    if(!m || cluster==UINT32_MAX) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    RootEndpoint* e=ep?endpoint(m,ep):NULL; if(ep && !e) return MATTER_INVALID_ARGUMENT;
    uint32_t* ids=e?e->clients:m->clients; size_t* count=e?&e->client_count:&m->client_count;
    for(size_t i=0;i<*count;++i) if(ids[i]==cluster) return MATTER_OK;
    if(*count==8) return MATTER_LIMIT_REACHED;
    ids[(*count)++]=cluster; if(e) ++e->config.data_version; else ++m->config.descriptor_version;
    return MATTER_OK;
}
Matter_Result_T matter_root_add_device_type(Matter_Root_T m,uint32_t type,uint16_t revision) {
    if(!m || !revision || type==UINT32_MAX) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(type==0x16) return revision==5?MATTER_OK:MATTER_INVALID_ARGUMENT;
    for(size_t i=0;i<m->type_count;++i) if(m->types[i].type==type) return m->types[i].revision==revision?MATTER_OK:MATTER_INVALID_ARGUMENT;
    if(m->type_count==4) return MATTER_LIMIT_REACHED;
    m->types[m->type_count].type=type; m->types[m->type_count++].revision=revision;
    ++m->config.descriptor_version; return MATTER_OK;
}
bool matter_root_has_device_type(Matter_Root_T m,uint16_t ep,uint32_t type) {
    if(!m) return false;
    if(ep) {
        RootEndpoint* e=endpoint(m,ep); if(!e) return false;
        if(e->config.device_type==type) return true;
        for(size_t i=0;i<e->type_count;++i) if(e->types[i].type==type) return true;
        return false;
    }
    if(type==0x16) return true;
    for(size_t i=0;i<m->type_count;++i) if(m->types[i].type==type) return true;
    return false;
}
Matter_Cluster_T matter_root_cluster_at(Matter_Root_T m,uint16_t ep,uint32_t id) {
    if(!ep) return matter_root_cluster(m,id);
    RootEndpoint* e=endpoint(m,ep);
    if(e) for(size_t i=0;i<e->count;++i) if(matter_cluster_id(e->clusters[i])==id) return e->clusters[i];
    return NULL;
}
static bool contains(Matter_Root_T m,Matter_Cluster_T c) {
    if(!m || !c) return false;
    if(matter_root_cluster(m,matter_cluster_id(c))==c) return true;
    for(size_t i=0;i<m->endpoint_count;++i) for(size_t j=0;j<m->endpoints[i]->count;++j) if(m->endpoints[i]->clusters[j]==c) return true;
    return false;
}
Matter_Result_T matter_root_add_endpoint(Matter_Root_T m,const Matter_Root_Endpoint_Config_T* config) {
    return matter_root_add_tagged_endpoint(m,config,NULL,0);
}
Matter_Result_T matter_root_add_tagged_endpoint(Matter_Root_T m,const Matter_Root_Endpoint_Config_T* config,const Matter_Root_Tag_T* tags,size_t count) {
    if(count>6 || (count && !tags)) return MATTER_INVALID_ARGUMENT;
    for(size_t i=0;i<count;++i) {
        if(tags[i].namespace_id==255 || tags[i].tag==255) return MATTER_INVALID_ARGUMENT;
        for(size_t j=0;j<i;++j) if(tags[i].namespace_id==tags[j].namespace_id && tags[i].tag==tags[j].tag) return MATTER_INVALID_ARGUMENT;
    }
    if(!m || !config || !config->endpoint || config->endpoint==65535 || !config->revision || config->device_type==UINT32_MAX) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->fail_safe!=MATTER_ROOT_FAIL_SAFE_IDLE || endpoint(m,config->endpoint)) return MATTER_INVALID_STATE;
    if(m->endpoint_count==8) return MATTER_LIMIT_REACHED;
    RootEndpoint* e=calloc(1,sizeof(*e)); if(!e) return MATTER_LIMIT_REACHED;
    e->config=*config; e->tag_count=count; if(count) memcpy(e->tags,tags,count*sizeof(*tags)); e->descriptor=(RootCluster){m,NULL,&e->config.data_version,e};
    e->descriptor.interface=builtin_new(&e->descriptor,DESCRIPTOR);
    if(!e->descriptor.interface) { free(e); return MATTER_LIMIT_REACHED; }
    Matter_Result_T r=matter_cluster_retain(e->descriptor.interface);
    if(r!=MATTER_OK) { (void)matter_cluster_delete(e->descriptor.interface); free(e); return r; }
    e->clusters[e->count++]=e->descriptor.interface; m->endpoints[m->endpoint_count++]=e;
    ++m->config.descriptor_version; return MATTER_OK;
}
Matter_Result_T matter_root_set_parent(Matter_Root_T m,uint16_t ep,uint16_t parent) {
    RootEndpoint* e=endpoint(m,ep); if(!e || ep==parent || (parent && !endpoint(m,parent))) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->fail_safe!=MATTER_ROOT_FAIL_SAFE_IDLE) return MATTER_INVALID_STATE;
    for(uint16_t id=parent;id;) {
        if(id==ep) return MATTER_INVALID_ARGUMENT;
        id=endpoint(m,id)->parent;
    }
    if(e->parent==parent) return MATTER_OK;
    if(e->parent) ++endpoint(m,e->parent)->config.data_version;
    e->parent=parent; if(parent) ++endpoint(m,parent)->config.data_version;
    return MATTER_OK;
}
Matter_Result_T matter_root_add_device_type_at(Matter_Root_T m,uint16_t ep,uint32_t type,uint16_t revision) {
    if(!ep) return matter_root_add_device_type(m,type,revision);
    RootEndpoint* e=endpoint(m,ep); if(!e || !revision || type==UINT32_MAX) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->fail_safe!=MATTER_ROOT_FAIL_SAFE_IDLE) return MATTER_INVALID_STATE;
    if(type==e->config.device_type) return revision==e->config.revision?MATTER_OK:MATTER_INVALID_ARGUMENT;
    for(size_t i=0;i<e->type_count;++i) if(e->types[i].type==type) return e->types[i].revision==revision?MATTER_OK:MATTER_INVALID_ARGUMENT;
    if(e->type_count==4) return MATTER_LIMIT_REACHED;
    e->types[e->type_count].type=type; e->types[e->type_count++].revision=revision;
    ++e->config.data_version; return MATTER_OK;
}
Matter_Result_T matter_root_attach_cluster_at(Matter_Root_T m,uint16_t ep,Matter_Cluster_T c) {
    if(!ep) return matter_root_attach_cluster(m,c);
    if(!m || !c) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    RootEndpoint* e=endpoint(m,ep); if(!e) return MATTER_INVALID_ARGUMENT;
    if(m->fail_safe!=MATTER_ROOT_FAIL_SAFE_IDLE || matter_root_cluster_at(m,ep,matter_cluster_id(c))) return MATTER_INVALID_STATE;
    if(e->count==16) return MATTER_LIMIT_REACHED;
    Matter_Result_T r=matter_cluster_retain(c); if(r!=MATTER_OK) return r;
    e->clusters[e->count++]=c; ++e->config.data_version; return MATTER_OK;
}
static Matter_Result_T attach_cluster(Matter_Root_T m,Matter_Cluster_T c) {
    if(m->busy) return MATTER_BUSY;
    if(m->fail_safe!=MATTER_ROOT_FAIL_SAFE_IDLE || matter_root_cluster(m,matter_cluster_id(c))) return MATTER_INVALID_STATE;
    if(m->cluster_count==25) return MATTER_LIMIT_REACHED;
    Matter_Result_T r=matter_cluster_retain(c); if(r!=MATTER_OK) return r;
    m->clusters[m->cluster_count++]=c; ++m->config.descriptor_version; return MATTER_OK;
}
Matter_Result_T matter_root_attach_cluster(Matter_Root_T m,Matter_Cluster_T c) {
    if(!m || !c) return MATTER_INVALID_ARGUMENT;
    uint32_t id=matter_cluster_id(c);
    const uint32_t reserved[]={DESCRIPTOR,BASIC,COMMISSIONING,MATTER_WIFI_CLUSTER,MATTER_OPCREDS_CLUSTER,MATTER_ACL_CLUSTER,MATTER_GROUPKEY_CLUSTER,MATTER_DIAGNOSTICS_GENERAL,MATTER_DIAGNOSTICS_WIFI};
    for(unsigned i=0;i<sizeof(reserved)/sizeof(*reserved);++i) if(id==reserved[i]) return MATTER_INVALID_ARGUMENT;
    if(m->custom_count==16) return MATTER_LIMIT_REACHED;
    Matter_Result_T r=attach_cluster(m,c); if(r==MATTER_OK) ++m->custom_count; return r;
}
static void sync_wifi_breadcrumb(Matter_Root_T m) {
    uint64_t value;
    if(m->wifi && matter_wifi_take_breadcrumb(m->wifi,&value) && m->breadcrumb!=value) { m->breadcrumb=value; ++m->gc.data_version; }
}

static uint8_t exists(Matter_Root_T m,const Matter_Im_Path_T* p) {
    if(!p) return MATTER_IM_FAILURE;
    if(p->endpoint && !endpoint(m,p->endpoint)) return MATTER_IM_UNSUPPORTED_ENDPOINT;
    Matter_Cluster_T c=matter_root_cluster_at(m,p->endpoint,p->cluster); Matter_Im_Attribute_T a;
    return c?matter_cluster_describe(c,p->attribute,&a):MATTER_IM_UNSUPPORTED_CLUSTER;
}
static bool text_valid(const Matter_Root_Text_T* t,size_t min,size_t max) {
    return t->size>=min && t->size<=max && valid_utf8(t->data,t->size);
}
static bool location(uint8_t* code) {
    for(unsigned i=0;i<2;++i) {
        if(code[i]>='a' && code[i]<='z') code[i]-='a'-'A';
        if(code[i]<'A' || code[i]>'Z') return false;
    }
    return true;
}
static bool config_valid(Matter_Root_Config_T* c) {
    const Matter_Root_Capabilities_T* b=&c->capabilities;
    const uint16_t values[]={b->case_sessions,b->subscriptions,b->invokes,b->writes,b->read_paths,b->subscribe_paths};
    const uint16_t minimum[]={3,3,1,1,9,3};
    for(unsigned i=0;i<6;++i) if(values[i]<minimum[i] || values[i]>10000) return false;
    return c->vendor_id && c->product_id && c->configuration_version &&
        text_valid(&c->vendor_name,0,32) && text_valid(&c->product_name,0,32) &&
        text_valid(&c->hardware_string,1,64) && text_valid(&c->software_string,1,64) &&
        text_valid(&c->unique_id,1,32) && c->settings.node_label_size<=32 &&
        valid_utf8(c->settings.node_label,c->settings.node_label_size) && location(c->settings.location);
}
static uint8_t authorize_live(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    Matter_Root_T m=u;
    if(!m || m->busy || !p) return MATTER_IM_UNSUPPORTED_ACCESS;
    m->busy=true; uint8_t status=m->port.authorize(m->port.user,session,p,privilege); m->busy=false;
    return status==MATTER_IM_SUCCESS || status==MATTER_IM_ACCESS_RESTRICTED ? status : MATTER_IM_UNSUPPORTED_ACCESS;
}
static uint8_t authorize(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    Matter_Root_T m=u;
    if(!m || m->fail_safe==MATTER_ROOT_FAIL_SAFE_CLEANUP) return MATTER_IM_UNSUPPORTED_ACCESS;
    return authorize_live(m,session,p,privilege);
}
uint8_t matter_root_authorize_pending_revoke(Matter_Root_T m,Matter_Exchange_Session_T session,
    const Matter_Im_Command_Path_T* p,Matter_Im_Privilege_T privilege) {
    if(!p || p->endpoint || p->cluster!=0x3c || p->command!=2) return MATTER_IM_UNSUPPORTED_ACCESS;
    const Matter_Im_Path_T path={p->endpoint,p->cluster,p->command};
    return authorize_live(m,session,&path,privilege);
}
static Matter_Im_Status_T read_authorize(void* u,Matter_Exchange_Session_T s,const Matter_Im_Path_T* p,Matter_Im_Privilege_T v) {
    return (Matter_Im_Status_T)authorize(u,s,p,v);
}
static Matter_Im_Status_T describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* a) {
    Matter_Root_T m=u; if(!m || m->busy || !a) return MATTER_IM_FAILURE;
    uint8_t r=exists(m,p); if(r) return (Matter_Im_Status_T)r;
    return (Matter_Im_Status_T)matter_cluster_describe(matter_root_cluster_at(m,p->endpoint,p->cluster),p->attribute,a);
}
Matter_Im_Status_T matter_root_event_describe(void* u,const Matter_Event_Path_T* p,Matter_Im_Attribute_T* a) {
    Matter_Root_T m=u; if(!m || !p || !a || m->busy) return MATTER_IM_FAILURE;
    if(p->endpoint && !endpoint(m,p->endpoint)) return MATTER_IM_UNSUPPORTED_ENDPOINT;
    Matter_Cluster_T cluster=matter_root_cluster_at(m,p->endpoint,p->cluster);
    if(!cluster) return MATTER_IM_UNSUPPORTED_CLUSTER;
    const Matter_Event_Def_T* e=matter_cluster_event(cluster,p->event);
    if(!e) return MATTER_IM_UNSUPPORTED_EVENT;
    *a=(Matter_Im_Attribute_T){e->privilege,e->fabric_scoped}; return MATTER_IM_SUCCESS;
}
static Matter_Result_T version(void* u,const Matter_Im_Path_T* p,uint32_t* out) {
    Matter_Root_T m=u; if(!m || !out || exists(m,p)) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    return matter_cluster_version(matter_root_cluster_at(m,p->endpoint,p->cluster),out);
}
static bool put(Matter_Root_T m,Matter_Tlv_Type_T type,int tag,uint64_t value) {
    m->token=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=value};
    return matter_tlv_write(&m->writer,&m->token,0)==MATTER_TLV_OK;
}

static Matter_Im_Status_T read_value(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    Matter_Cluster_Request_T q={.filtered=filtered}; return (Matter_Im_Status_T)matter_root_cluster_read(u,p,&q,v);
}
static bool path_before(const Matter_Im_Path_T* a,const Matter_Im_Path_T* b) {
    return a->endpoint<b->endpoint || (a->endpoint==b->endpoint &&
        (a->cluster<b->cluster || (a->cluster==b->cluster && a->attribute<b->attribute)));
}
static Matter_Result_T enumerate(void* u,const Matter_Im_Selector_T* q,const Matter_Im_Path_T* after,Matter_Im_Path_T* next,bool* found) {
    Matter_Root_T m=u;
    if(!m || !q || !next || !found || (q->present&~MATTER_IM_CONCRETE)) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    Matter_Im_Path_T previous; if(after) { previous=*after; after=&previous; }
    *found=false;
    for(size_t e=0;e<=m->endpoint_count;++e) {
        RootEndpoint* leaf=e?m->endpoints[e-1]:NULL;
        uint16_t ep=leaf?leaf->config.endpoint:0;
        if((q->present&MATTER_IM_ENDPOINT) && q->path.endpoint!=ep) continue;
        size_t count=leaf?leaf->count:m->cluster_count;
        Matter_Cluster_T* clusters=leaf?leaf->clusters:m->clusters;
        for(size_t k=0;k<count;++k) {
            Matter_Cluster_T c=clusters[k]; uint32_t id=matter_cluster_id(c);
            if((q->present&MATTER_IM_CLUSTER) && q->path.cluster!=id) continue;
            for(size_t i=0;i<matter_cluster_attribute_count(c);++i) {
                Matter_Im_Path_T candidate={ep,id,0};
                if(!matter_cluster_attribute_at(c,i,&candidate.attribute)) return MATTER_INVALID_STATE;
                if((q->present&MATTER_IM_ATTRIBUTE) && q->path.attribute!=candidate.attribute) continue;
                if(after && !path_before(after,&candidate)) continue;
                if(!*found || path_before(&candidate,next)) { *next=candidate; *found=true; }
            }
        }
    }
    return MATTER_OK;
}
static bool event_before(const Matter_Event_Path_T* a,const Matter_Event_Path_T* b) {
    return a->endpoint<b->endpoint || (a->endpoint==b->endpoint &&
        (a->cluster<b->cluster || (a->cluster==b->cluster && a->event<b->event)));
}
Matter_Result_T matter_root_event_enumerate(void* u,const Matter_Im_Event_Selector_T* q,const Matter_Event_Path_T* after,Matter_Event_Path_T* next,bool* found) {
    Matter_Root_T m=u;
    if(!m || !q || !next || !found || (q->present&~MATTER_IM_CONCRETE)) return MATTER_INVALID_ARGUMENT;
    if((q->present&MATTER_IM_EVENT) && !(q->present&MATTER_IM_CLUSTER)) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    Matter_Event_Path_T previous; if(after) { previous=*after; after=&previous; }
    *found=false;
    for(size_t e=0;e<=m->endpoint_count;++e) {
        RootEndpoint* leaf=e?m->endpoints[e-1]:NULL;
        uint16_t ep=leaf?leaf->config.endpoint:0;
        if((q->present&MATTER_IM_ENDPOINT) && q->path.endpoint!=ep) continue;
        size_t count=leaf?leaf->count:m->cluster_count;
        Matter_Cluster_T* clusters=leaf?leaf->clusters:m->clusters;
        for(size_t k=0;k<count;++k) {
            Matter_Cluster_T c=clusters[k]; uint32_t id=matter_cluster_id(c);
            if((q->present&MATTER_IM_CLUSTER) && q->path.cluster!=id) continue;
            for(size_t i=0;i<matter_cluster_event_count(c);++i) {
                Matter_Event_Path_T candidate={ep,id,0};
                if(!matter_cluster_event_at(c,i,&candidate.event)) return MATTER_INVALID_STATE;
                if((q->present&MATTER_IM_EVENT) && q->path.event!=candidate.event) continue;
                if(after && !event_before(after,&candidate)) continue;
                if(!*found || event_before(&candidate,next)) { *next=candidate; *found=true; }
            }
        }
    }
    return MATTER_OK;
}
static uint8_t write_describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Write_Attribute_T* a) {
    Matter_Root_T m=u; if(!m || m->busy || !a) return MATTER_IM_FAILURE;
    uint8_t r=exists(m,p); return r?r:matter_cluster_describe_write(matter_root_cluster_at(m,p->endpoint,p->cluster),p->attribute,a);
}
static uint8_t validate(void* u,const Matter_Im_Path_T* p,const uint8_t* data,size_t size) {
    Matter_Cluster_Request_T q={0}; return matter_root_cluster_validate(u,p,&q,data,size);
}
static Matter_Im_Write_Result_T write_value(void* u,const Matter_Im_Path_T* p,const uint8_t* data,size_t size) {
    Matter_Cluster_Request_T q={0}; return matter_root_cluster_write(u,p,&q,data,size);
}
Matter_Root_T matter_root_new(const Matter_Root_Port_T* port) {
    if(!port || !port->load || !port->authorize || !port->store) return NULL;
    Matter_Root_T m=calloc(1,sizeof(*m)); if(!m) return NULL;
    m->port=*port; m->busy=true;
    Matter_Result_T r=port->load(port->user,&m->config); m->busy=false;
    if(r!=MATTER_OK || !config_valid(&m->config)) { free(m); return NULL; }
    m->builtin[0]=(RootCluster){m,NULL,&m->config.descriptor_version,NULL};
    m->builtin[1]=(RootCluster){m,NULL,&m->config.basic_version,NULL};
    m->builtin[0].interface=builtin_new(&m->builtin[0],DESCRIPTOR);
    m->builtin[1].interface=builtin_new(&m->builtin[1],BASIC);
    if(!m->builtin[0].interface || !m->builtin[1].interface) {
        for(unsigned i=0;i<2;++i) if(m->builtin[i].interface) (void)matter_cluster_delete(m->builtin[i].interface);
        free(m); return NULL;
    }
    for(unsigned i=0;i<2;++i) { (void)matter_cluster_retain(m->builtin[i].interface); m->clusters[m->cluster_count++]=m->builtin[i].interface; }
    return m;
}
Matter_Result_T matter_root_ports(Matter_Root_T m,Matter_Im_Read_Port_T* read,Matter_Im_Write_Port_T* write) {
    if(!m || !read || !write) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    *read=(Matter_Im_Read_Port_T){m,read_authorize,describe,read_value,enumerate,version};
    *write=(Matter_Im_Write_Port_T){m,authorize,write_describe,version,validate,write_value,NULL,NULL}; return MATTER_OK;
}
Matter_Result_T matter_root_delete(Matter_Root_T m) {
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->fail_safe!=MATTER_ROOT_FAIL_SAFE_IDLE || m->complete_token) return MATTER_INVALID_STATE;
    for(size_t i=0;i<m->cluster_count;++i) if(matter_cluster_in_use(m->clusters[i])) return MATTER_BUSY;
    for(unsigned i=0;i<3;++i) if(m->builtin[i].interface && matter_cluster_pins(m->builtin[i].interface)!=1) return MATTER_BUSY;
    for(size_t i=0;i<m->endpoint_count;++i) {
        RootEndpoint* e=m->endpoints[i];
        if(matter_cluster_pins(e->descriptor.interface)!=1) return MATTER_BUSY;
        for(size_t j=0;j<e->count;++j) if(matter_cluster_in_use(e->clusters[j])) return MATTER_BUSY;
    }
    for(size_t i=0;i<m->cluster_count;++i) { Matter_Result_T r=matter_cluster_release(m->clusters[i]); if(r!=MATTER_OK) return r; }
    for(unsigned i=0;i<3;++i) if(m->builtin[i].interface) (void)matter_cluster_delete(m->builtin[i].interface);
    for(size_t i=0;i<m->endpoint_count;++i) {
        RootEndpoint* e=m->endpoints[i];
        for(size_t j=0;j<e->count;++j) (void)matter_cluster_release(e->clusters[j]);
        (void)matter_cluster_delete(e->descriptor.interface); free(e);
    }
    free(m); return MATTER_OK;
}

Matter_Root_T matter_root_new_commissioning(const Matter_Root_Port_T* port,
    const Matter_Root_Commissioning_Config_T* c,const Matter_Root_Commissioning_Port_T* p,uint64_t now) {
    if(!c || !p || !p->begin || !p->cleanup || !p->regulatory ||
        c->cumulative_seconds<c->recommended_seconds || c->location_capability>2 || c->regulatory_config>2 ||
        (c->location_capability!=2 && c->regulatory_config!=c->location_capability)) return NULL;
    Matter_Root_T m=matter_root_new(port); if(!m) return NULL;
    m->commissioning=true; m->gc=*c; m->gc_port=*p; m->now=now;
    m->builtin[2]=(RootCluster){m,NULL,&m->gc.data_version,NULL};
    m->builtin[2].interface=builtin_new(&m->builtin[2],COMMISSIONING);
    if(!m->builtin[2].interface) { (void)matter_root_delete(m); return NULL; }
    (void)matter_cluster_retain(m->builtin[2].interface); m->clusters[m->cluster_count++]=m->builtin[2].interface;
    if(c->recover_pending) m->fail_safe=MATTER_ROOT_FAIL_SAFE_CLEANUP;
    return m;
}
static uint64_t deadline_after(uint64_t now,uint16_t seconds) {
    uint64_t duration=(uint64_t)seconds*1000;
    return UINT64_MAX-now<duration ? UINT64_MAX : now+duration;
}
Matter_Result_T matter_root_fail_safe_state(Matter_Root_T m,Matter_Root_Fail_Safe_State_T* state) {
    if(!m || !state || !m->commissioning) return MATTER_INVALID_ARGUMENT;
    *state=m->fail_safe; return MATTER_OK;
}
Matter_Result_T matter_root_expire(Matter_Root_T m) {
    if(!m || !m->commissioning) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->fail_safe==MATTER_ROOT_FAIL_SAFE_ARMED) m->fail_safe=MATTER_ROOT_FAIL_SAFE_CLEANUP;
    return m->fail_safe==MATTER_ROOT_FAIL_SAFE_IDLE ? MATTER_OK : MATTER_PENDING;
}
Matter_Result_T matter_root_deadline(Matter_Root_T m,uint64_t* deadline) {
    if(!m || !deadline || !m->commissioning) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->fail_safe==MATTER_ROOT_FAIL_SAFE_IDLE) return MATTER_INVALID_STATE;
    *deadline=m->fail_safe==MATTER_ROOT_FAIL_SAFE_CLEANUP ? m->now : m->expiry<m->cumulative ? m->expiry : m->cumulative;
    if(m->wifi) { uint64_t wd; if(matter_wifi_deadline(m->wifi,&wd)==MATTER_OK && wd<*deadline) *deadline=wd; }
    return MATTER_OK;
}
Matter_Result_T matter_root_process(Matter_Root_T m,uint64_t now) {
    if(!m || !m->commissioning) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(now<m->now) return MATTER_INVALID_ARGUMENT;
    m->now=now;
    if(m->fail_safe==MATTER_ROOT_FAIL_SAFE_ARMED && (now>=m->expiry || now>=m->cumulative)) m->fail_safe=MATTER_ROOT_FAIL_SAFE_CLEANUP;
    if(m->opcreds && m->fail_safe!=MATTER_ROOT_FAIL_SAFE_CLEANUP) {
        m->busy=true; Matter_Result_T r=matter_opcreds_process(m->opcreds); m->busy=false;
        if(r!=MATTER_OK && r!=MATTER_PENDING) return r;
    }
    if(m->wifi && m->fail_safe!=MATTER_ROOT_FAIL_SAFE_CLEANUP) {
        m->busy=true; Matter_Result_T r=matter_wifi_process(m->wifi,now); m->busy=false;
        if(r!=MATTER_OK && r!=MATTER_PENDING) return r;
        sync_wifi_breadcrumb(m);
    }
    if(m->complete_token && !m->complete_ready && m->fail_safe==MATTER_ROOT_FAIL_SAFE_ARMED) {
        const Matter_Im_Path_T path={0,COMMISSIONING,4}; m->busy=true;
        uint8_t access=m->port.authorize(m->port.user,m->complete_session,&path,MATTER_IM_ADMINISTER);
        Matter_Result_T r=access?MATTER_INVALID_STATE:m->complete_port.complete(m->complete_port.user,m->complete_index); m->busy=false;
        if(r!=MATTER_PENDING) {
            m->complete_ready=true; m->complete_status=r==MATTER_OK?0:access?MATTER_IM_UNSUPPORTED_ACCESS:MATTER_IM_FAILURE;
            if(r==MATTER_OK) {
                if(m->breadcrumb) { m->breadcrumb=0; ++m->gc.data_version; }
                m->expiry=m->cumulative=0; m->armed_fabric=0; m->fail_safe=MATTER_ROOT_FAIL_SAFE_IDLE;
            }
        }
    }
    if(m->fail_safe==MATTER_ROOT_FAIL_SAFE_CLEANUP) {
        m->complete_token=0; m->complete_ready=false;
        m->busy=true; Matter_Result_T r=m->gc_port.cleanup(m->gc_port.user); m->busy=false;
        if(r!=MATTER_OK) return r==MATTER_PENDING ? MATTER_PENDING : MATTER_PORT_ERROR;
        if(m->breadcrumb) { m->breadcrumb=0; ++m->gc.data_version; }
        m->expiry=m->cumulative=0; m->armed_fabric=0; m->fail_safe=MATTER_ROOT_FAIL_SAFE_IDLE;
    }
    return m->fail_safe==MATTER_ROOT_FAIL_SAFE_IDLE ? MATTER_OK : MATTER_PENDING;
}
static uint8_t command_exists(Matter_Root_T m,const Matter_Im_Command_Path_T* p) {
    if(!p) return MATTER_IM_FAILURE;
    if(p->endpoint && !endpoint(m,p->endpoint)) return MATTER_IM_UNSUPPORTED_ENDPOINT;
    Matter_Cluster_T c=matter_root_cluster_at(m,p->endpoint,p->cluster); Matter_Im_Command_T meta;
    return c?matter_cluster_command(c,p->command,&meta):MATTER_IM_UNSUPPORTED_CLUSTER;
}
static uint8_t command_authorize(void* u,Matter_Exchange_Session_T session,const Matter_Im_Command_Path_T* p,Matter_Im_Privilege_T privilege) {
    Matter_Root_Invoke_Binding_T* b=u;
    if(!b || !b->root || !p || session!=b->session) return MATTER_IM_UNSUPPORTED_ACCESS;
    const Matter_Im_Path_T path={p->endpoint,p->cluster,p->command};
    return authorize(b->root,session,&path,privilege);
}
static uint8_t command_describe(void* u,const Matter_Im_Command_Path_T* p,Matter_Im_Command_T* c) {
    Matter_Root_Invoke_Binding_T* b=u; if(!b || !b->root || !c || b->root->busy) return MATTER_IM_FAILURE;
    uint8_t r=command_exists(b->root,p); return r?r:matter_cluster_command(matter_root_cluster_at(b->root,p->endpoint,p->cluster),p->command,c);
}
static uint8_t command_validate(void* u,const Matter_Im_Command_Path_T* p,const uint8_t* data,size_t size) {
    Matter_Root_Invoke_Binding_T* b=u; if(!b || !b->root) return MATTER_IM_FAILURE;
    Matter_Cluster_Request_T q={.session=b->session,.fabric=matter_opcreds_fabric_index(b->root->opcreds,b->session)};
    return matter_root_cluster_validate_command(b->root,p,&q,data,size);
}
static Matter_Im_Command_Result_T gc_response(Matter_Root_T m,Matter_Tlv_Writer_T* out,uint8_t code) {
    if(!out || out->size || out->capacity<8) return (Matter_Im_Command_Result_T){.status=MATTER_IM_RESOURCE_EXHAUSTED};
    m->token=(Matter_Tlv_Element_T){.type=MATTER_TLV_STRUCTURE};
    if(matter_tlv_write(out,&m->token,0)!=MATTER_TLV_OK) return (Matter_Im_Command_Result_T){.status=MATTER_IM_FAILURE};
    m->token=(Matter_Tlv_Element_T){.type=MATTER_TLV_UNSIGNED,.tag={.control=1,.number=0},.unsigned_value=code};
    if(matter_tlv_write(out,&m->token,0)!=MATTER_TLV_OK) return (Matter_Im_Command_Result_T){.status=MATTER_IM_FAILURE};
    m->token=(Matter_Tlv_Element_T){.type=MATTER_TLV_UTF8,.tag={.control=1,.number=1}};
    if(matter_tlv_write(out,&m->token,0)!=MATTER_TLV_OK) return (Matter_Im_Command_Result_T){.status=MATTER_IM_FAILURE};
    m->token=(Matter_Tlv_Element_T){.type=MATTER_TLV_END};
    return (Matter_Im_Command_Result_T){.status=matter_tlv_write(out,&m->token,0)==MATTER_TLV_OK?MATTER_IM_SUCCESS:MATTER_IM_FAILURE};
}
static Matter_Im_Command_Result_T command_invoke(void* u,const Matter_Im_Command_Path_T* p,const uint8_t* data,size_t size,Matter_Tlv_Writer_T* out) {
    Matter_Root_Invoke_Binding_T* b=u; uint8_t status=command_validate(u,p,data,size);
    if(status) return (Matter_Im_Command_Result_T){.status=status};
    Matter_Cluster_T c=matter_root_cluster_at(b->root,p->endpoint,p->cluster);
    Matter_Cluster_Request_T q={.session=b->session,.fabric=matter_opcreds_fabric_index(b->root->opcreds,b->session)};
    /* Legacy synchronous PASE binding: Complete can only return a refusal.
     * CASE completion uses the registered async operation, never this path. */
    if(c==b->root->builtin[2].interface && p->command==4) return gc_invoke(b->root,4,&q,data,size,out);
    if(matter_cluster_command_async(c,p->command)) return (Matter_Im_Command_Result_T){.status=MATTER_IM_INVALID_ACTION};
    Matter_Im_Command_Result_T result; uint64_t token;
    Matter_Result_T r=matter_root_cluster_start(b->root,p,&q,data,size,out,&result,&token);
    return r==MATTER_OK?result:(Matter_Im_Command_Result_T){.status=MATTER_IM_FAILURE};
}
Matter_Result_T matter_root_invoke_port(Matter_Root_T m,Matter_Exchange_Session_T session,
    Matter_Root_Invoke_Binding_T* binding,Matter_Im_Invoke_Port_T* port) {
    if(!m || (!m->commissioning && !m->groupkey && !m->diagnostics && !m->cluster_count) || !session || !binding || !port) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    *binding=(Matter_Root_Invoke_Binding_T){m,session};
    *port=(Matter_Im_Invoke_Port_T){binding,command_authorize,command_describe,command_validate,command_invoke}; return MATTER_OK;
}

Matter_Result_T matter_root_attach_wifi(Matter_Root_T m,Matter_Wifi_T wifi) {
    if(!m || !wifi || !m->commissioning || !m->gc.concurrent_connection) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->wifi || m->fail_safe!=MATTER_ROOT_FAIL_SAFE_IDLE) return MATTER_INVALID_STATE;
    if(matter_cluster_id(wifi)!=MATTER_WIFI_CLUSTER) return MATTER_INVALID_ARGUMENT;
    Matter_Result_T r=attach_cluster(m,wifi); if(r==MATTER_OK) m->wifi=wifi; return r;
}

static Matter_Result_T wifi_start(void* u,const Matter_Im_Command_Path_T* p,const uint8_t* data,size_t size,
    Matter_Tlv_Writer_T* out,Matter_Im_Command_Result_T* result,uint64_t* token) {
    Matter_Root_Invoke_Binding_T* b=u;
    if(p->endpoint || p->cluster!=MATTER_WIFI_CLUSTER) { *token=0; *result=command_invoke(u,p,data,size,out); return MATTER_OK; }
    Matter_Cluster_Request_T q={.session=b->session,.fabric=matter_opcreds_fabric_index(b->root->opcreds,b->session)};
    return matter_root_cluster_start(b->root,p,&q,data,size,out,result,token);
}
static Matter_Result_T wifi_poll(void* u,uint64_t token,Matter_Tlv_Writer_T* out,Matter_Im_Command_Result_T* result) {
    Matter_Root_Invoke_Binding_T* b=u; return matter_root_cluster_poll(b->root,b->root->wifi,token,out,result);
}
static void wifi_cancel(void* u,uint64_t token) {
    Matter_Root_Invoke_Binding_T* b=u; matter_root_cluster_cancel(b->root,b->root->wifi,token);
}
Matter_Result_T matter_root_wifi_invoke_port(Matter_Root_T m,Matter_Exchange_Session_T session,
    Matter_Root_Invoke_Binding_T* binding,Matter_Im_Invoke_Port_T* port,Matter_Im_Invoke_Async_Port_T* async) {
    if(!m || !m->wifi || !async) return MATTER_INVALID_ARGUMENT;
    Matter_Result_T r=matter_root_invoke_port(m,session,binding,port); if(r!=MATTER_OK) return r;
    *async=(Matter_Im_Invoke_Async_Port_T){wifi_start,wifi_poll,wifi_cancel}; return MATTER_OK;
}

Matter_Result_T matter_root_attach_opcreds(Matter_Root_T m,Matter_Opcreds_T opcreds) {
    if(!m || !opcreds || !m->commissioning) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->opcreds || m->fail_safe!=MATTER_ROOT_FAIL_SAFE_IDLE) return MATTER_INVALID_STATE;
    if(matter_cluster_id(opcreds)!=MATTER_OPCREDS_CLUSTER) return MATTER_INVALID_ARGUMENT;
    Matter_Result_T r=attach_cluster(m,opcreds); if(r==MATTER_OK) m->opcreds=opcreds; return r;
}
static Matter_Result_T async_start(void* u,const Matter_Im_Command_Path_T* p,const uint8_t* data,size_t size,
    Matter_Tlv_Writer_T* out,Matter_Im_Command_Result_T* result,uint64_t* token) {
    Matter_Root_Async_Invoke_Binding_T* b=u;
    Matter_Cluster_Request_T q={.session=b->base.session,.fabric=matter_opcreds_fabric_index(b->base.root->opcreds,b->base.session)};
    Matter_Result_T r=matter_root_cluster_start(b->base.root,p,&q,data,size,out,result,token);
    if(r==MATTER_PENDING) { b->pending_cluster=p->cluster; b->pending_endpoint=p->endpoint; }
    return r;
}
static Matter_Result_T async_poll(void* u,uint64_t token,Matter_Tlv_Writer_T* out,Matter_Im_Command_Result_T* result) {
    Matter_Root_Async_Invoke_Binding_T* b=u; Matter_Cluster_T c=matter_root_cluster_at(b->base.root,b->pending_endpoint,b->pending_cluster);
    return matter_root_cluster_poll(b->base.root,c,token,out,result);
}
static void async_cancel(void* u,uint64_t token) {
    Matter_Root_Async_Invoke_Binding_T* b=u;
    matter_root_cluster_cancel(b->base.root,matter_root_cluster_at(b->base.root,b->pending_endpoint,b->pending_cluster),token);
}
Matter_Result_T matter_root_async_invoke_port(Matter_Root_T m,Matter_Exchange_Session_T session,
    Matter_Root_Async_Invoke_Binding_T* b,Matter_Im_Invoke_Port_T* port,Matter_Im_Invoke_Async_Port_T* async) {
    if(!m || (!m->wifi && !m->opcreds && !m->cluster_count) || !b || !async) return MATTER_INVALID_ARGUMENT;
    Matter_Result_T r=matter_root_invoke_port(m,session,&b->base,port); if(r!=MATTER_OK) return r;
    b->pending_cluster=0; b->pending_endpoint=0; port->user=b;
    *async=(Matter_Im_Invoke_Async_Port_T){async_start,async_poll,async_cancel}; return MATTER_OK;
}

static Matter_Im_Status_T bound_read_authorize(void* u,Matter_Exchange_Session_T s,const Matter_Im_Path_T* p,Matter_Im_Privilege_T v) {
    Matter_Root_Invoke_Binding_T* b=u;
    if(s!=b->session) return MATTER_IM_UNSUPPORTED_ACCESS;
    return read_authorize(b->root,s,p,v);
}
static Matter_Im_Status_T bound_describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* a) {
    return describe(((Matter_Root_Invoke_Binding_T*)u)->root,p,a);
}
static Matter_Im_Status_T bound_read(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    Matter_Root_Invoke_Binding_T* b=u;
    Matter_Cluster_Request_T q={.session=b->session,.fabric=matter_opcreds_fabric_index(b->root->opcreds,b->session),.filtered=filtered};
    return (Matter_Im_Status_T)matter_root_cluster_read(b->root,p,&q,v);
}
static Matter_Result_T bound_enumerate(void* u,const Matter_Im_Selector_T* q,const Matter_Im_Path_T* p,Matter_Im_Path_T* n,bool* found) {
    return enumerate(((Matter_Root_Invoke_Binding_T*)u)->root,q,p,n,found);
}
static Matter_Result_T bound_version(void* u,const Matter_Im_Path_T* p,uint32_t* v) { return version(((Matter_Root_Invoke_Binding_T*)u)->root,p,v); }
static Matter_Result_T bound_index(void* u,Matter_Exchange_Session_T session,uint8_t* index) {
    Matter_Root_Invoke_Binding_T* b=u;
    if(!b || !index || b->session!=session || b->root->busy || b->root->fail_safe==MATTER_ROOT_FAIL_SAFE_CLEANUP) return MATTER_INVALID_STATE;
    *index=matter_opcreds_fabric_index(b->root->opcreds,session); return MATTER_OK;
}
Matter_Result_T matter_root_fabric_read_port(Matter_Root_T m,Matter_Exchange_Session_T session,
    Matter_Root_Invoke_Binding_T* b,Matter_Im_Read_Port_T* port,Matter_Im_Read_Fabric_Port_T* fabric) {
    if(!m || (!m->opcreds && !m->cluster_count) || !session || !b || !port || !fabric) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    *b=(Matter_Root_Invoke_Binding_T){m,session};
    *port=(Matter_Im_Read_Port_T){b,bound_read_authorize,bound_describe,bound_read,bound_enumerate,bound_version};
    *fabric=(Matter_Im_Read_Fabric_Port_T){bound_index}; return MATTER_OK;
}
Matter_Result_T matter_root_fail_safe_fabric(Matter_Root_T m,uint8_t* index) {
    if(!m || !index || !m->commissioning) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    uint8_t pending=matter_opcreds_pending_fabric(m->opcreds);
    *index=m->fail_safe==MATTER_ROOT_FAIL_SAFE_IDLE?0:pending?pending:m->armed_fabric; return MATTER_OK;
}

uint8_t matter_root_read_fabric(Matter_Root_T m,const Matter_Im_Path_T* p,uint8_t index,bool filtered,Matter_Im_Value_T* v) {
    Matter_Cluster_Request_T q={.fabric=index,.filtered=filtered}; return matter_root_cluster_read(m,p,&q,v);
}

Matter_Result_T matter_root_attach_complete(Matter_Root_T m,const Matter_Root_Complete_Port_T* p) {
    if(!m || !p || !p->complete || !m->commissioning) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->complete_port.complete || m->fail_safe!=MATTER_ROOT_FAIL_SAFE_IDLE) return MATTER_INVALID_STATE;
    m->complete_port=*p; return MATTER_OK;
}
static Matter_Result_T complete_start_impl(Matter_Root_T m,Matter_Exchange_Session_T session,uint8_t index,bool is_case,Matter_Tlv_Writer_T* out,
    Matter_Im_Command_Result_T* result,uint64_t* token) {
    if(!m || !m->commissioning || !session || !result || !token || !index || index==255) return MATTER_INVALID_ARGUMENT;
    *token=0;
    if(!out || out->size || out->capacity<8) { *result=(Matter_Im_Command_Result_T){.status=MATTER_IM_RESOURCE_EXHAUSTED}; return MATTER_OK; }
    uint8_t pending=matter_opcreds_pending_fabric(m->opcreds);
    uint8_t code=m->fail_safe!=MATTER_ROOT_FAIL_SAFE_ARMED?3:
        !is_case || index!=(pending?pending:m->armed_fabric)?2:0;
    if(code) { *result=gc_response(m,out,code); return MATTER_OK; }
    if(!m->complete_port.complete) { *result=(Matter_Im_Command_Result_T){.status=MATTER_IM_FAILURE}; return MATTER_OK; }
    if(m->complete_token || m->complete_serial==UINT64_MAX) { *result=(Matter_Im_Command_Result_T){.status=MATTER_WIFI_BUSY}; return MATTER_OK; }
    m->complete_session=session; m->complete_index=index; m->complete_ready=false; m->complete_token=++m->complete_serial; *token=m->complete_token;
    return MATTER_PENDING;
}
Matter_Result_T matter_root_complete_start(Matter_Root_T m,Matter_Exchange_Session_T session,uint8_t index,bool is_case,Matter_Tlv_Writer_T* out,
    Matter_Im_Command_Result_T* result,uint64_t* token) {
    if(m && m->busy) return MATTER_BUSY;
    return complete_start_impl(m,session,index,is_case,out,result,token);
}
static Matter_Result_T complete_poll_impl(Matter_Root_T m,uint64_t token,Matter_Tlv_Writer_T* out,Matter_Im_Command_Result_T* result) {
    if(!m || !result) return MATTER_INVALID_ARGUMENT;
    if(!token || token!=m->complete_token) return MATTER_INVALID_STATE;
    if(!m->complete_ready) return MATTER_PENDING;
    *result=m->complete_status?(Matter_Im_Command_Result_T){.status=m->complete_status}:gc_response(m,out,0);
    m->complete_token=0; m->complete_ready=false; return MATTER_OK;
}
Matter_Result_T matter_root_complete_poll(Matter_Root_T m,uint64_t token,Matter_Tlv_Writer_T* out,Matter_Im_Command_Result_T* result) {
    if(m && m->busy) return MATTER_BUSY;
    return complete_poll_impl(m,token,out,result);
}
static void complete_cancel_impl(Matter_Root_T m,uint64_t token) {
    if(m && token && token==m->complete_token) { m->complete_token=0; m->complete_ready=false; }
}
void matter_root_complete_cancel(Matter_Root_T m,uint64_t token) {
    if(m && !m->busy) complete_cancel_impl(m,token);
}
Matter_Result_T matter_root_invoke_fabric(void* u,Matter_Exchange_Session_T session,uint8_t* index) { return bound_index(u,session,index); }

Matter_Result_T matter_root_attach_acl(Matter_Root_T m,Matter_Acl_T acl) {
    if(!m || !acl) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->acl || m->fail_safe!=MATTER_ROOT_FAIL_SAFE_IDLE) return MATTER_INVALID_STATE;
    if(matter_cluster_id(acl)!=MATTER_ACL_CLUSTER) return MATTER_INVALID_ARGUMENT;
    Matter_Result_T r=attach_cluster(m,acl); if(r==MATTER_OK) m->acl=acl; return r;
}
uint8_t matter_root_acl_list(Matter_Root_T m,const Matter_Im_Path_T* p,uint8_t index,Matter_Im_List_Change_T c,const uint8_t* d,size_t n,bool apply) {
    if(!m || m->busy) return MATTER_IM_FAILURE;
    uint8_t status=exists(m,p); if(status) return status;
    if(p->cluster!=MATTER_ACL_CLUSTER || p->attribute) return MATTER_IM_UNSUPPORTED_WRITE;
    m->busy=true;
    status=apply?matter_acl_write(m->acl,index,c,d,n):matter_acl_validate(m->acl,index,c,d,n);
    m->busy=false; return status;
}

Matter_Result_T matter_root_attach_groupkey(Matter_Root_T m,Matter_Groupkey_T g) {
    if(!m || !g) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->groupkey || m->fail_safe!=MATTER_ROOT_FAIL_SAFE_IDLE) return MATTER_INVALID_STATE;
    if(matter_cluster_id(g)!=MATTER_GROUPKEY_CLUSTER) return MATTER_INVALID_ARGUMENT;
    Matter_Result_T r=attach_cluster(m,g); if(r==MATTER_OK) m->groupkey=g; return r;
}
Matter_Im_Command_Result_T matter_root_groupkey_invoke(Matter_Root_T m,uint8_t index,uint32_t cmd,const uint8_t* d,size_t n,Matter_Tlv_Writer_T* w) {
    if(!m || m->busy || !m->groupkey) return (Matter_Im_Command_Result_T){.status=MATTER_IM_FAILURE};
    m->busy=true; Matter_Im_Command_Result_T r=matter_groupkey_invoke(m->groupkey,index,cmd,d,n,w); m->busy=false; return r;
}
uint8_t matter_root_groupkey_map(Matter_Root_T m,const Matter_Im_Path_T* p,uint8_t index,Matter_Im_List_Change_T c,const uint8_t* d,size_t n) {
    if(!m || m->busy) return MATTER_IM_FAILURE;
    uint8_t status=exists(m,p); if(status) return status;
    if(p->cluster!=MATTER_GROUPKEY_CLUSTER || p->attribute) return MATTER_IM_UNSUPPORTED_WRITE;
    return matter_groupkey_map(m->groupkey,index,c,d,n);
}

Matter_Result_T matter_root_attach_diagnostics(Matter_Root_T m,Matter_Diagnostics_T d) {
    if(!m || !d) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->diagnostics || m->fail_safe!=MATTER_ROOT_FAIL_SAFE_IDLE) return MATTER_INVALID_STATE;
    Matter_Cluster_T wifi=matter_diagnostics_wifi(d);
    if(!wifi) return MATTER_INVALID_ARGUMENT;
    if(m->cluster_count>23) return MATTER_LIMIT_REACHED;
    if(matter_root_cluster(m,MATTER_DIAGNOSTICS_GENERAL) || matter_root_cluster(m,MATTER_DIAGNOSTICS_WIFI)) return MATTER_INVALID_STATE;
    if(matter_cluster_in_use(d) || matter_cluster_in_use(wifi)) return MATTER_BUSY;
    Matter_Result_T r=attach_cluster(m,d); if(r!=MATTER_OK) return r;
    r=attach_cluster(m,wifi);
    if(r!=MATTER_OK) { --m->cluster_count; --m->config.descriptor_version; (void)matter_cluster_release(d); return r; }
    --m->config.descriptor_version; m->diagnostics=d; return MATTER_OK;
}
Matter_Im_Command_Result_T matter_root_diagnostics_invoke(Matter_Root_T m,uint32_t cluster,uint32_t cmd,const uint8_t* d,size_t n,Matter_Tlv_Writer_T* w) {
    if(!m || m->busy || !m->diagnostics) return (Matter_Im_Command_Result_T){.status=MATTER_IM_FAILURE};
    m->busy=true; Matter_Im_Command_Result_T r=matter_diagnostics_invoke(m->diagnostics,cluster,cmd,d,n,w); m->busy=false; return r;
}

Matter_Im_Write_Result_T matter_root_cluster_write(Matter_Root_T m,const Matter_Im_Path_T* p,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    if(!m || m->busy || !p) return (Matter_Im_Write_Result_T){.status=MATTER_IM_FAILURE};
    if(p->endpoint && !endpoint(m,p->endpoint)) return (Matter_Im_Write_Result_T){.status=MATTER_IM_UNSUPPORTED_ENDPOINT};
    Matter_Cluster_T c=matter_root_cluster_at(m,p->endpoint,p->cluster); if(!c) return (Matter_Im_Write_Result_T){.status=MATTER_IM_UNSUPPORTED_CLUSTER};
    m->dispatch=c; m->busy=true; Matter_Im_Write_Result_T r=matter_cluster_write(c,p->attribute,q,d,n); m->busy=false; m->dispatch=NULL; return r;
}
Matter_Im_Write_Result_T matter_root_cluster_list(Matter_Root_T m,const Matter_Im_Path_T* p,const Matter_Cluster_Request_T* q,Matter_Im_List_Change_T change,const uint8_t* d,size_t n,bool apply) {
    if(!m || m->busy || !p) return (Matter_Im_Write_Result_T){.status=MATTER_IM_FAILURE};
    if(p->endpoint && !endpoint(m,p->endpoint)) return (Matter_Im_Write_Result_T){.status=MATTER_IM_UNSUPPORTED_ENDPOINT};
    Matter_Cluster_T c=matter_root_cluster_at(m,p->endpoint,p->cluster); if(!c) return (Matter_Im_Write_Result_T){.status=MATTER_IM_UNSUPPORTED_CLUSTER};
    m->dispatch=c; m->busy=true;
    Matter_Im_Write_Result_T r=apply?matter_cluster_write_list(c,p->attribute,q,change,d,n):
        (Matter_Im_Write_Result_T){.status=matter_cluster_validate_list(c,p->attribute,q,change,d,n)};
    m->busy=false; m->dispatch=NULL; return r;
}

Matter_Result_T matter_root_cluster_start(Matter_Root_T m,const Matter_Im_Command_Path_T* p,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out,uint64_t* token) {
    if(!m || !p || !q) return MATTER_INVALID_ARGUMENT;
    if(m->busy || m->fail_safe==MATTER_ROOT_FAIL_SAFE_CLEANUP) return MATTER_BUSY;
    Matter_Cluster_T c=matter_root_cluster_at(m,p->endpoint,p->cluster); if(!c) return MATTER_INVALID_ARGUMENT;
    Matter_Cluster_Request_T request=*q; request.armed=m->fail_safe==MATTER_ROOT_FAIL_SAFE_ARMED && (!m->armed_fabric || (q->is_case && q->fabric==m->armed_fabric));
    m->dispatch=c; m->busy=true; Matter_Result_T r=matter_cluster_start(c,p->command,&request,d,n,w,out,token); m->busy=false; m->dispatch=NULL; if(r==MATTER_OK) sync_wifi_breadcrumb(m); return r;
}
Matter_Result_T matter_root_cluster_poll(Matter_Root_T m,Matter_Cluster_T c,uint64_t token,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out) {
    if(!m || !c || !contains(m,c)) return MATTER_INVALID_ARGUMENT;
    if(m->busy || m->fail_safe==MATTER_ROOT_FAIL_SAFE_CLEANUP) return MATTER_BUSY;
    m->dispatch=c; m->busy=true; Matter_Result_T r=matter_cluster_poll(c,token,w,out); m->busy=false; m->dispatch=NULL; if(r==MATTER_OK) sync_wifi_breadcrumb(m); return r;
}
void matter_root_cluster_cancel(Matter_Root_T m,Matter_Cluster_T c,uint64_t token) {
    if(m && !m->busy && c && contains(m,c)) { m->dispatch=c; m->busy=true; (void)matter_cluster_cancel(c,token); m->busy=false; m->dispatch=NULL; }
}

uint8_t matter_root_cluster_validate(Matter_Root_T m,const Matter_Im_Path_T* p,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    if(!m || m->busy || !p) return MATTER_IM_FAILURE;
    if(p->endpoint && !endpoint(m,p->endpoint)) return MATTER_IM_UNSUPPORTED_ENDPOINT;
    Matter_Cluster_T c=matter_root_cluster_at(m,p->endpoint,p->cluster); if(!c) return MATTER_IM_UNSUPPORTED_CLUSTER;
    m->dispatch=c; m->busy=true; uint8_t r=matter_cluster_validate(c,p->attribute,q,d,n); m->busy=false; m->dispatch=NULL; return r;
}

uint8_t matter_root_cluster_read(Matter_Root_T m,const Matter_Im_Path_T* p,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!m || m->busy || !p) return MATTER_IM_FAILURE;
    if(p->endpoint && !endpoint(m,p->endpoint)) return MATTER_IM_UNSUPPORTED_ENDPOINT;
    Matter_Cluster_T c=matter_root_cluster_at(m,p->endpoint,p->cluster); if(!c) return MATTER_IM_UNSUPPORTED_CLUSTER;
    m->dispatch=c; m->busy=true; uint8_t r=matter_cluster_read(c,p->attribute,q,v); m->busy=false; m->dispatch=NULL; return r;
}
uint8_t matter_root_cluster_validate_command(Matter_Root_T m,const Matter_Im_Command_Path_T* p,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    if(!m || m->busy || !p || !q) return MATTER_IM_FAILURE;
    if(p->endpoint && !endpoint(m,p->endpoint)) return MATTER_IM_UNSUPPORTED_ENDPOINT;
    Matter_Cluster_T c=matter_root_cluster_at(m,p->endpoint,p->cluster); if(!c) return MATTER_IM_UNSUPPORTED_CLUSTER;
    Matter_Cluster_Request_T request=*q; request.armed=m->fail_safe==MATTER_ROOT_FAIL_SAFE_ARMED && (!m->armed_fabric || (q->is_case && q->fabric==m->armed_fabric));
    m->dispatch=c; m->busy=true; uint8_t r=matter_cluster_validate_command(c,p->command,&request,d,n); m->busy=false; m->dispatch=NULL; return r;
}

static uint8_t validate_setting(Matter_Root_T m,bool breadcrumb,bool label,const uint8_t* data,size_t size) {
    if(size>1024 || matter_tlv_init(&m->reader,data,size,1)!=MATTER_TLV_OK ||
        matter_tlv_next(&m->reader,&m->token)!=MATTER_TLV_OK) return MATTER_IM_INVALID_DATA_TYPE;
    if(m->token.tag.control) return MATTER_IM_INVALID_DATA_TYPE;
    if(breadcrumb) {
        if(m->token.type!=MATTER_TLV_UNSIGNED) return MATTER_IM_INVALID_DATA_TYPE;
        m->args.breadcrumb=m->token.unsigned_value;
        return matter_tlv_next(&m->reader,&m->token)==MATTER_TLV_DONE ? MATTER_IM_SUCCESS : MATTER_IM_INVALID_DATA_TYPE;
    }
    if(m->token.type!=MATTER_TLV_UTF8) return MATTER_IM_INVALID_DATA_TYPE;
    size_t n=m->token.size; const uint8_t* value=m->token.data;
    if(matter_tlv_next(&m->reader,&m->token)!=MATTER_TLV_DONE) return MATTER_IM_INVALID_DATA_TYPE;
    m->pending=m->config.settings;
    if(label) {
        if(n>32) return MATTER_IM_CONSTRAINT_ERROR;
        memset(m->pending.node_label,0,32); if(n) memcpy(m->pending.node_label,value,n); m->pending.node_label_size=n;
    } else {
        if(n!=2) return MATTER_IM_CONSTRAINT_ERROR;
        memcpy(m->pending.location,value,2); if(!location(m->pending.location)) return MATTER_IM_CONSTRAINT_ERROR;
    }
    return MATTER_IM_SUCCESS;
}
static Matter_Im_Write_Result_T write_setting(Matter_Root_T m,bool breadcrumb,bool label,const uint8_t* data,size_t size) {
    uint8_t status=validate_setting(m,breadcrumb,label,data,size); if(status) return (Matter_Im_Write_Result_T){.status=status};
    if(breadcrumb) {
        if(m->breadcrumb!=m->args.breadcrumb) { m->breadcrumb=m->args.breadcrumb; ++m->gc.data_version; }
        return (Matter_Im_Write_Result_T){.status=MATTER_IM_SUCCESS};
    }
    Matter_Root_Settings_T* old=&m->config.settings;
    bool changed=old->node_label_size!=m->pending.node_label_size ||
        memcmp(old->node_label,m->pending.node_label,old->node_label_size) || memcmp(old->location,m->pending.location,2);
    if(changed) {
        m->busy=true; Matter_Result_T r=m->port.store(m->port.user,&m->pending); m->busy=false;
        if(r!=MATTER_OK) return (Matter_Im_Write_Result_T){.status=MATTER_IM_FAILURE};
        *old=m->pending; ++m->config.basic_version;
    }
    return (Matter_Im_Write_Result_T){.status=MATTER_IM_SUCCESS};
}
static uint8_t gc_validate(Matter_Root_T m,uint32_t command,const uint8_t* data,size_t size) {
    if(size>1024 || matter_tlv_init(&m->reader,data,size,4)!=MATTER_TLV_OK ||
        matter_tlv_next(&m->reader,&m->token)!=MATTER_TLV_OK || m->token.type!=MATTER_TLV_STRUCTURE || m->token.tag.control) return MATTER_IM_INVALID_COMMAND;
    unsigned seen=0; memset(&m->args,0,sizeof(m->args));
    while(matter_tlv_next(&m->reader,&m->token)==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&m->token;
        if(e->type==MATTER_TLV_END) {
            unsigned required=command==0?3:command==2?7:0;
            return seen==required && matter_tlv_next(&m->reader,e)==MATTER_TLV_DONE ? MATTER_IM_SUCCESS : MATTER_IM_INVALID_COMMAND;
        }
        bool known=e->tag.control==1 && ((command==0 && e->tag.number<2) || (command==2 && e->tag.number<3));
        if(!known) {
            if((e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) &&
                matter_tlv_skip_container(&m->reader)!=MATTER_TLV_OK) return MATTER_IM_INVALID_COMMAND;
            continue;
        }
        unsigned id=e->tag.number; if(seen&(1u<<id)) return MATTER_IM_INVALID_COMMAND; seen|=1u<<id;
        if(command==2 && id==1) {
            if(e->type!=MATTER_TLV_UTF8) return MATTER_IM_INVALID_COMMAND;
            if(e->size!=2) return MATTER_IM_CONSTRAINT_ERROR;
            memcpy(m->args.country,e->data,2); if(!location(m->args.country)) return MATTER_IM_CONSTRAINT_ERROR;
        } else {
            if(e->type!=MATTER_TLV_UNSIGNED) return MATTER_IM_INVALID_COMMAND;
            if(id==0) {
                if(e->unsigned_value>(command==0?UINT16_MAX:UINT8_MAX)) return MATTER_IM_CONSTRAINT_ERROR;
                if(command==0) m->args.seconds=(uint16_t)e->unsigned_value;
                else m->args.regulatory=(uint8_t)e->unsigned_value;
            } else m->args.breadcrumb=e->unsigned_value;
        }
    }
    return MATTER_IM_INVALID_COMMAND;
}
static Matter_Im_Command_Result_T gc_invoke(Matter_Root_T m,uint32_t command,const Matter_Cluster_Request_T* q,const uint8_t* data,size_t size,Matter_Tlv_Writer_T* out) {
    uint8_t status=gc_validate(m,command,data,size); if(status) return (Matter_Im_Command_Result_T){.status=status};
    if(command==4) {
        if(!matter_opcreds_fabric_index(m->opcreds,q->session)) return (Matter_Im_Command_Result_T){.status=MATTER_IM_UNSUPPORTED_ACCESS};
        return gc_response(m,out,m->fail_safe==MATTER_ROOT_FAIL_SAFE_ARMED?2:3);
    }
    if(m->fail_safe==MATTER_ROOT_FAIL_SAFE_CLEANUP) return (Matter_Im_Command_Result_T){.status=MATTER_IM_UNSUPPORTED_ACCESS};
    if(!out || out->size || out->capacity<8) return (Matter_Im_Command_Result_T){.status=MATTER_IM_RESOURCE_EXHAUSTED};
    uint8_t code=0; uint64_t old_breadcrumb=m->breadcrumb; uint8_t old_regulatory=m->gc.regulatory_config;
    if(command==0 && q->is_case && m->fail_safe==MATTER_ROOT_FAIL_SAFE_IDLE && m->gc_port.window_open) {
        bool open=false; m->busy=true;
        Matter_Result_T r=m->gc_port.window_open(m->gc_port.user,&open); m->busy=false;
        if(r!=MATTER_OK) return (Matter_Im_Command_Result_T){.status=MATTER_IM_FAILURE};
        if(open) return gc_response(m,out,4); /* No deadline/Breadcrumb/store effects. */
    }
    if(command==0 && m->fail_safe==MATTER_ROOT_FAIL_SAFE_ARMED &&
        (matter_opcreds_pending_fabric(m->opcreds)?matter_opcreds_pending_fabric(m->opcreds):m->armed_fabric)!=
            (q->is_case?q->fabric:matter_opcreds_fabric_index(m->opcreds,q->session))) {
        code=4; /* BusyWithOtherAdmin: no deadline or Breadcrumb side effects. */
    } else if(command==0) {
        if(!m->args.seconds) { if(m->fail_safe==MATTER_ROOT_FAIL_SAFE_ARMED) m->fail_safe=MATTER_ROOT_FAIL_SAFE_CLEANUP; }
        else {
            if(m->fail_safe==MATTER_ROOT_FAIL_SAFE_IDLE) {
                m->busy=true; Matter_Result_T r=m->gc_port.begin(m->gc_port.user); m->busy=false;
                if(r!=MATTER_OK) return (Matter_Im_Command_Result_T){.status=MATTER_IM_FAILURE};
                m->cumulative=deadline_after(m->now,m->gc.cumulative_seconds); m->armed_fabric=q->is_case?q->fabric:0;
            }
            m->expiry=deadline_after(m->now,m->args.seconds); m->fail_safe=MATTER_ROOT_FAIL_SAFE_ARMED;
        }
        m->breadcrumb=m->args.breadcrumb;
    } else {
        if(m->args.regulatory>2) return gc_response(m,out,1);
        bool permitted=m->gc.location_capability==2 || m->args.regulatory==m->gc.location_capability;
        uint8_t candidate=permitted?m->args.regulatory:old_regulatory; bool country_supported=false;
        m->pending=m->config.settings; memcpy(m->pending.location,m->args.country,2);
        m->busy=true; Matter_Result_T r=m->gc_port.regulatory(m->gc_port.user,&m->pending,candidate,&country_supported); m->busy=false;
        if(r!=MATTER_OK) return (Matter_Im_Command_Result_T){.status=MATTER_IM_FAILURE};
        if(memcmp(m->config.settings.location,m->pending.location,2)) { m->config.settings=m->pending; ++m->config.basic_version; }
        m->gc.regulatory_config=candidate;
        code=permitted && country_supported ? 0 : 1;
        if(!code) m->breadcrumb=m->args.breadcrumb;
    }
    if(old_breadcrumb!=m->breadcrumb || old_regulatory!=m->gc.regulatory_config) ++m->gc.data_version;
    /* Fixed response body and preflighted capacity; no allocation after effects. */
    return gc_response(m,out,code);
}

static bool builtin_ready(void* u) {
    RootCluster* c=u; return !c->root->busy || c->root->dispatch==c->interface;
}
static Matter_Result_T builtin_version(void* u,uint32_t* v) { RootCluster* c=u; *v=*c->version; return MATTER_OK; }
static Matter_Root_T builtin_value(void* u,Matter_Im_Value_T* v) {
    RootCluster* c=u; *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=*c->version,.report_on_version_change=true}; return c->root;
}
static uint8_t read_constant(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)q; (void)builtin_value(u,v); v->unsigned_value=*(const uint32_t*)ref; return 0;
}
typedef struct { const uint32_t* ids; size_t count; } RootIds;
static uint8_t read_ids(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)q; Matter_Root_T m=builtin_value(u,v); const RootIds* ids=ref;
    if(matter_tlv_writer_init(&m->writer,m->encoded,sizeof(m->encoded),1)!=MATTER_TLV_OK || !put(m,MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
    for(size_t i=0;i<ids->count;++i) if(!put(m,MATTER_TLV_UNSIGNED,-1,ids->ids[i])) return MATTER_IM_FAILURE;
    if(!put(m,MATTER_TLV_END,-1,0) || matter_tlv_writer_finish(&m->writer,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->type=MATTER_TLV_ARRAY; v->data=m->encoded; return 0;
}
static uint8_t read_servers(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v);
    if(matter_tlv_writer_init(&m->writer,m->encoded,sizeof(m->encoded),1)!=MATTER_TLV_OK || !put(m,MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
    RootEndpoint* e=((RootCluster*)u)->endpoint;
    size_t count=e?e->count:m->cluster_count; Matter_Cluster_T* clusters=e?e->clusters:m->clusters;
    for(size_t i=0;i<count;++i) if(!put(m,MATTER_TLV_UNSIGNED,-1,matter_cluster_id(clusters[i]))) return MATTER_IM_FAILURE;
    if(!put(m,MATTER_TLV_END,-1,0) || matter_tlv_writer_finish(&m->writer,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->type=MATTER_TLV_ARRAY; v->data=m->encoded; return 0;
}
static uint8_t read_clients(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)ref; RootCluster* c=u; RootEndpoint* e=c->endpoint;
    RootIds ids={e?e->clients:c->root->clients,e?e->client_count:c->root->client_count};
    return read_ids(u,&ids,q,v);
}
static uint8_t read_parts(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v);
    if(matter_tlv_writer_init(&m->writer,m->encoded,sizeof(m->encoded),1)!=MATTER_TLV_OK || !put(m,MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
    RootEndpoint* e=((RootCluster*)u)->endpoint;
    for(size_t i=0;i<m->endpoint_count;++i) if(!e || m->endpoints[i]->parent==e->config.endpoint)
        if(!put(m,MATTER_TLV_UNSIGNED,-1,m->endpoints[i]->config.endpoint)) return MATTER_IM_FAILURE;
    if(!put(m,MATTER_TLV_END,-1,0) || matter_tlv_writer_finish(&m->writer,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->type=MATTER_TLV_ARRAY; v->data=m->encoded; return 0;
}
static uint8_t read_vendor(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v); v->unsigned_value=m->config.vendor_id; return 0;
}
static uint8_t read_product(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v); v->unsigned_value=m->config.product_id; return 0;
}
static uint8_t read_hardware(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v); v->unsigned_value=m->config.hardware_version; return 0;
}
static uint8_t read_software(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v); v->unsigned_value=m->config.software_version; return 0;
}
static uint8_t read_configuration(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v); v->unsigned_value=m->config.configuration_version; return 0;
}
static uint8_t read_label(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v); v->type=MATTER_TLV_UTF8; v->data=m->config.settings.node_label; v->size=m->config.settings.node_label_size; return 0;
}
static uint8_t read_location(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v); v->type=MATTER_TLV_UTF8; v->data=m->config.settings.location; v->size=2; return 0;
}
static uint8_t read_breadcrumb(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v); v->unsigned_value=m->breadcrumb; return 0;
}
static uint8_t read_regulatory(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v); v->unsigned_value=m->gc.regulatory_config; return 0;
}
static uint8_t read_capability(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v); v->unsigned_value=m->gc.location_capability; return 0;
}
static uint8_t read_concurrent(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v); v->type=MATTER_TLV_BOOL; v->unsigned_value=m->gc.concurrent_connection; return 0;
}
static uint8_t read_vendor_name(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v); v->type=MATTER_TLV_UTF8; v->data=m->config.vendor_name.data; v->size=m->config.vendor_name.size; return 0;
}
static uint8_t read_product_name(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v); v->type=MATTER_TLV_UTF8; v->data=m->config.product_name.data; v->size=m->config.product_name.size; return 0;
}
static uint8_t read_hardware_string(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v); v->type=MATTER_TLV_UTF8; v->data=m->config.hardware_string.data; v->size=m->config.hardware_string.size; return 0;
}
static uint8_t read_software_string(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v); v->type=MATTER_TLV_UTF8; v->data=m->config.software_string.data; v->size=m->config.software_string.size; return 0;
}
static uint8_t read_unique_id(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v); v->type=MATTER_TLV_UTF8; v->data=m->config.unique_id.data; v->size=m->config.unique_id.size; return 0;
}
static uint8_t read_device(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v);
    if(matter_tlv_writer_init(&m->writer,m->encoded,sizeof(m->encoded),3)!=MATTER_TLV_OK || !put(m,MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
    RootEndpoint* e=((RootCluster*)u)->endpoint;
    if(!put(m,MATTER_TLV_STRUCTURE,-1,0) || !put(m,MATTER_TLV_UNSIGNED,0,e?e->config.device_type:0x16) || !put(m,MATTER_TLV_UNSIGNED,1,e?e->config.revision:5) || !put(m,MATTER_TLV_END,-1,0)) return MATTER_IM_FAILURE;
    for(size_t i=0;i<(e?e->type_count:m->type_count);++i)
        if(!put(m,MATTER_TLV_STRUCTURE,-1,0) || !put(m,MATTER_TLV_UNSIGNED,0,e?e->types[i].type:m->types[i].type) ||
            !put(m,MATTER_TLV_UNSIGNED,1,e?e->types[i].revision:m->types[i].revision) || !put(m,MATTER_TLV_END,-1,0)) return MATTER_IM_FAILURE;
    if(!put(m,MATTER_TLV_END,-1,0) || matter_tlv_writer_finish(&m->writer,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->type=MATTER_TLV_ARRAY; v->data=m->encoded; return 0;
}
static uint8_t read_capabilities(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v);
    if(matter_tlv_writer_init(&m->writer,m->encoded,sizeof(m->encoded),3)!=MATTER_TLV_OK || !put(m,MATTER_TLV_STRUCTURE,-1,0)) return MATTER_IM_FAILURE;
    const Matter_Root_Capabilities_T* c=&m->config.capabilities;
    const uint16_t values[]={c->case_sessions,c->subscriptions,c->invokes,c->writes,c->read_paths,c->subscribe_paths};
    for(unsigned i=0;i<6;++i) if(!put(m,MATTER_TLV_UNSIGNED,(int)i,values[i])) return MATTER_IM_FAILURE;
    if(!put(m,MATTER_TLV_END,-1,0) || matter_tlv_writer_finish(&m->writer,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->type=MATTER_TLV_STRUCTURE; v->data=m->encoded; return 0;
}
static uint8_t read_info(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v);
    if(matter_tlv_writer_init(&m->writer,m->encoded,sizeof(m->encoded),3)!=MATTER_TLV_OK || !put(m,MATTER_TLV_STRUCTURE,-1,0)) return MATTER_IM_FAILURE;
    if(!put(m,MATTER_TLV_UNSIGNED,0,m->gc.recommended_seconds) || !put(m,MATTER_TLV_UNSIGNED,1,m->gc.cumulative_seconds)) return MATTER_IM_FAILURE;
    if(!put(m,MATTER_TLV_END,-1,0) || matter_tlv_writer_finish(&m->writer,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->type=MATTER_TLV_STRUCTURE; v->data=m->encoded; return 0;
}
static uint8_t validate_label(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; RootCluster* c=u; return validate_setting(c->root,false,true,d,n);
}
static Matter_Im_Write_Result_T write_label(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    if(!builtin_ready(u)) return (Matter_Im_Write_Result_T){.status=MATTER_IM_FAILURE};
    (void)ref; (void)q; RootCluster* c=u; return write_setting(c->root,false,true,d,n);
}
static uint8_t validate_location(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; RootCluster* c=u; return validate_setting(c->root,false,false,d,n);
}
static Matter_Im_Write_Result_T write_location(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    if(!builtin_ready(u)) return (Matter_Im_Write_Result_T){.status=MATTER_IM_FAILURE};
    (void)ref; (void)q; RootCluster* c=u; return write_setting(c->root,false,false,d,n);
}
static uint8_t validate_breadcrumb(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; RootCluster* c=u; return validate_setting(c->root,true,false,d,n);
}
static Matter_Im_Write_Result_T write_breadcrumb(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    if(!builtin_ready(u)) return (Matter_Im_Write_Result_T){.status=MATTER_IM_FAILURE};
    (void)ref; (void)q; RootCluster* c=u; return write_setting(c->root,true,false,d,n);
}
static uint8_t builtin_validate_command(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    RootCluster* c=u; uint32_t id=*(const uint32_t*)ref;
    (void)q; /* SetRegulatoryConfig is also available to CASE administrators. */
    return gc_validate(c->root,id,d,n);
}
static Matter_Result_T builtin_start(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out,uint64_t* token) {
    if(!builtin_ready(u)) return MATTER_BUSY;
    RootCluster* c=u; uint32_t id=*(const uint32_t*)ref; *token=0;
    if(id==4 && q->is_case) return complete_start_impl(c->root,q->session,q->fabric,true,w,out,token);
    *out=gc_invoke(c->root,id,q,d,n,w); return MATTER_OK;
}
static Matter_Result_T builtin_poll(void* u,const void* ref,uint64_t token,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out) {
    (void)ref; RootCluster* c=u; return complete_poll_impl(c->root,token,w,out);
}
static void builtin_cancel(void* u,const void* ref,uint64_t token) { (void)ref; RootCluster* c=u; complete_cancel_impl(c->root,token); }
static uint8_t read_tags(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; Matter_Root_T m=builtin_value(u,v); RootEndpoint* e=((RootCluster*)u)->endpoint;
    if(!e || matter_tlv_writer_init(&m->writer,m->encoded,sizeof(m->encoded),2)!=MATTER_TLV_OK || !put(m,MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
    for(size_t i=0;i<e->tag_count;++i) if(!put(m,MATTER_TLV_STRUCTURE,-1,0) || !put(m,MATTER_TLV_NULL,0,0) ||
        !put(m,MATTER_TLV_UNSIGNED,1,e->tags[i].namespace_id) || !put(m,MATTER_TLV_UNSIGNED,2,e->tags[i].tag) || !put(m,MATTER_TLV_END,-1,0)) return MATTER_IM_FAILURE;
    if(!put(m,MATTER_TLV_END,-1,0) || matter_tlv_writer_finish(&m->writer,&v->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    v->type=MATTER_TLV_ARRAY; v->data=m->encoded; return 0;
}
static uint8_t read_descriptor_feature(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!builtin_ready(u)) return MATTER_IM_FAILURE;
    (void)ref; (void)q; (void)builtin_value(u,v); RootEndpoint* e=((RootCluster*)u)->endpoint;
    v->unsigned_value=e && e->tag_count?1:0; return 0;
}
static uint8_t read_descriptor_ids(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    static const uint32_t tagged[]={0,1,2,3,4,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
    (void)ref; RootEndpoint* e=((RootCluster*)u)->endpoint;
    RootIds ids={e && e->tag_count?tagged:descriptor_attrs,e && e->tag_count?10:9};
    return read_ids(u,&ids,q,v);
}
static Matter_Cluster_T builtin_new(RootCluster* m,uint32_t id) {
    static const uint32_t zero=0,one=1,dm=21,spec=UINT32_C(0x01060100),dr=3,br=6,gr=2,accepted[]={0,2,4},generated[]={1,3,5};
    static const RootIds empty={NULL,0},bl={basic_attrs,21},gl={commissioning_attrs,10},ga={accepted,3},gg={generated,3};
    static const Matter_Attribute_Def_T descriptor[]={
        {.id=0,.read_access={MATTER_IM_VIEW,false},.read=read_device},
        {.id=1,.read_access={MATTER_IM_VIEW,false},.read=read_servers},
        {.id=2,.read_access={MATTER_IM_VIEW,false},.read=read_clients},
        {.id=3,.read_access={MATTER_IM_VIEW,false},.read=read_parts},
        {.id=0xfff8,.read_access={MATTER_IM_VIEW,false},.read=read_ids,.ref=&empty},
        {.id=0xfff9,.read_access={MATTER_IM_VIEW,false},.read=read_ids,.ref=&empty},
        {.id=0xfffb,.read_access={MATTER_IM_VIEW,false},.read=read_descriptor_ids},
        {.id=0xfffc,.read_access={MATTER_IM_VIEW,false},.read=read_descriptor_feature},
        {.id=0xfffd,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&dr},
    };
    static const Matter_Attribute_Def_T basic[]={
        {.id=0,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&dm},
        {.id=1,.read_access={MATTER_IM_VIEW,false},.read=read_vendor_name},
        {.id=2,.read_access={MATTER_IM_VIEW,false},.read=read_vendor},
        {.id=3,.read_access={MATTER_IM_VIEW,false},.read=read_product_name},
        {.id=4,.read_access={MATTER_IM_VIEW,false},.read=read_product},
        {.id=5,.read_access={MATTER_IM_VIEW,false},.read=read_label,.write_access={.privilege=MATTER_IM_MANAGE},.validate=validate_label,.write=write_label},
        {.id=6,.read_access={MATTER_IM_VIEW,false},.read=read_location,.write_access={.privilege=MATTER_IM_ADMINISTER},.validate=validate_location,.write=write_location},
        {.id=7,.read_access={MATTER_IM_VIEW,false},.read=read_hardware},
        {.id=8,.read_access={MATTER_IM_VIEW,false},.read=read_hardware_string},
        {.id=9,.read_access={MATTER_IM_VIEW,false},.read=read_software},
        {.id=10,.read_access={MATTER_IM_VIEW,false},.read=read_software_string},
        {.id=18,.read_access={MATTER_IM_VIEW,false},.read=read_unique_id},
        {.id=19,.read_access={MATTER_IM_VIEW,false},.read=read_capabilities},
        {.id=21,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&spec},
        {.id=22,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&one},
        {.id=24,.read_access={MATTER_IM_VIEW,false},.read=read_configuration},
        {.id=0xfff8,.read_access={MATTER_IM_VIEW,false},.read=read_ids,.ref=&empty},
        {.id=0xfff9,.read_access={MATTER_IM_VIEW,false},.read=read_ids,.ref=&empty},
        {.id=0xfffb,.read_access={MATTER_IM_VIEW,false},.read=read_ids,.ref=&bl},
        {.id=0xfffc,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&zero},
        {.id=0xfffd,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&br},
    };
    static const Matter_Attribute_Def_T gc[]={
        {.id=0,.read_access={MATTER_IM_VIEW,false},.read=read_breadcrumb,.write_access={.privilege=MATTER_IM_ADMINISTER},.validate=validate_breadcrumb,.write=write_breadcrumb},
        {.id=1,.read_access={MATTER_IM_VIEW,false},.read=read_info},
        {.id=2,.read_access={MATTER_IM_VIEW,false},.read=read_regulatory},
        {.id=3,.read_access={MATTER_IM_VIEW,false},.read=read_capability},
        {.id=4,.read_access={MATTER_IM_VIEW,false},.read=read_concurrent},
        {.id=0xfff8,.read_access={MATTER_IM_VIEW,false},.read=read_ids,.ref=&gg},
        {.id=0xfff9,.read_access={MATTER_IM_VIEW,false},.read=read_ids,.ref=&ga},
        {.id=0xfffb,.read_access={MATTER_IM_VIEW,false},.read=read_ids,.ref=&gl},
        {.id=0xfffc,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&zero},
        {.id=0xfffd,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&gr},
    };
    const Matter_Attribute_Def_T* attrs=id==DESCRIPTOR?descriptor:id==BASIC?basic:gc;
    bool tagged=id==DESCRIPTOR && m->endpoint && m->endpoint->tag_count;
    Matter_Cluster_Config_T cfg={.id=id,.attributes=id==DESCRIPTOR?(tagged?10:9):id==BASIC?21:10,.commands=id==COMMISSIONING?3:0,.pending=id==COMMISSIONING?2:0,
        .events=id==BASIC?1:0,.callbacks={.ctx=m,.version=builtin_version}};
    Matter_Cluster_T c=matter_cluster_new(&cfg); if(!c) return NULL;
    if(id==BASIC) {
        const Matter_Event_Def_T event={0,MATTER_IM_VIEW,2,false};
        if(matter_cluster_add_event(c,&event)!=MATTER_OK) { matter_cluster_abandon(c); return NULL; }
    }
    for(size_t i=0;i<(size_t)cfg.attributes-(tagged?1u:0u);++i) if(matter_cluster_add_attribute(c,&attrs[i])!=MATTER_OK) { matter_cluster_abandon(c); return NULL; }
    if(tagged) {
        const Matter_Attribute_Def_T tag={.id=4,.read_access={MATTER_IM_VIEW,false},.read=read_tags};
        if(matter_cluster_add_attribute(c,&tag)!=MATTER_OK) { matter_cluster_abandon(c); return NULL; }
    }
    for(unsigned i=0;i<cfg.commands;++i) {
        Matter_Command_Def_T cmd={.id=accepted[i],.ref=&accepted[i],.validate=builtin_validate_command,.start=builtin_start,
            .poll=i==2?builtin_poll:NULL,.cancel=i==2?builtin_cancel:NULL,
            .access={.privilege=MATTER_IM_ADMINISTER,.fabric_scoped=i==2,.response=true,.response_command=generated[i],.response_capacity=8}};
        if(matter_cluster_add_command(c,&cmd)!=MATTER_OK) { matter_cluster_abandon(c); return NULL; }
    }
    return c;
}
