#include "matter_cluster_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
typedef struct { uint64_t handle,backend; size_t command; } Pending;
struct Matter_Cluster {
    Matter_Cluster_Config_T config; size_t attributes,commands,events,pins;
    Matter_Attribute_Def_T* attribute; Matter_Command_Def_T* command;
    Matter_Event_Def_T* event; Pending* pending;
    uint64_t serial; bool busy,sealed;
};
/* Separate typed tails retain natural alignment, including 32-bit targets. */
#define ALIGN_SIZE(n,T) (((n)+offsetof(struct { char c; T v; },v)-1)/offsetof(struct { char c; T v; },v)*offsetof(struct { char c; T v; },v))
Matter_Cluster_T matter_cluster_new(const Matter_Cluster_Config_T* c) {
    if(!c || !c->callbacks.version || c->attributes>256 || c->commands>64 || c->events>64 || c->pending>16) return NULL;
    size_t a=ALIGN_SIZE(sizeof(struct Matter_Cluster),Matter_Attribute_Def_T);
    size_t b=ALIGN_SIZE(a+c->attributes*sizeof(Matter_Attribute_Def_T),Matter_Command_Def_T);
    size_t e=ALIGN_SIZE(b+c->commands*sizeof(Matter_Command_Def_T),Matter_Event_Def_T);
    size_t p=ALIGN_SIZE(e+c->events*sizeof(Matter_Event_Def_T),Pending);
    Matter_Cluster_T m=calloc(1,p+c->pending*sizeof(Pending)); if(!m) return NULL;
    m->config=*c; m->attribute=(void*)((unsigned char*)m+a); m->command=(void*)((unsigned char*)m+b);
    m->event=(void*)((unsigned char*)m+e); m->pending=(void*)((unsigned char*)m+p); return m;
}
static bool privilege(Matter_Im_Privilege_T p) { return p==MATTER_IM_VIEW || p==MATTER_IM_OPERATE || p==MATTER_IM_MANAGE || p==MATTER_IM_ADMINISTER; }
static const Matter_Attribute_Def_T* attribute(Matter_Cluster_T m,uint32_t id) {
    if(m) for(size_t i=0;i<m->attributes;++i) if(m->attribute[i].id==id) return &m->attribute[i];
    return NULL;
}
static const Matter_Command_Def_T* command(Matter_Cluster_T m,uint32_t id) {
    if(m) for(size_t i=0;i<m->commands;++i) if(m->command[i].id==id) return &m->command[i];
    return NULL;
}
static bool valid_attribute(const Matter_Attribute_Def_T* a) {
    return a && a->read && privilege(a->read_access.privilege) && (!!a->validate==!!a->write) &&
        (!!a->validate_list==!!a->write_list) && (!(a->write || a->write_list) || privilege(a->write_access.privilege)) &&
        (a->write_access.list?(!a->write && a->write_list):a->write_list==NULL);
}
static bool valid_command(Matter_Cluster_T m,const Matter_Command_Def_T* c) {
    return c && c->validate && c->start && privilege(c->access.privilege) && (!!c->poll==!!c->cancel) &&
        (!c->poll || m->config.pending) && (!c->access.response || (c->access.response_capacity>=2 && c->access.response_capacity<=1024));
}
Matter_Result_T matter_cluster_add_attribute(Matter_Cluster_T m,const Matter_Attribute_Def_T* a) {
    if(!m || !valid_attribute(a)) return MATTER_INVALID_ARGUMENT;
    if(m->busy || m->sealed) return MATTER_INVALID_STATE;
    if(attribute(m,a->id)) return MATTER_INVALID_ARGUMENT;
    if(m->attributes==m->config.attributes) return MATTER_LIMIT_REACHED;
    size_t i=m->attributes++; while(i && m->attribute[i-1].id>a->id) { m->attribute[i]=m->attribute[i-1]; --i; }
    m->attribute[i]=*a; return MATTER_OK;
}
Matter_Result_T matter_cluster_add_command(Matter_Cluster_T m,const Matter_Command_Def_T* c) {
    if(!m || !valid_command(m,c)) return MATTER_INVALID_ARGUMENT;
    if(m->busy || m->sealed) return MATTER_INVALID_STATE;
    if(command(m,c->id)) return MATTER_INVALID_ARGUMENT;
    if(m->commands==m->config.commands) return MATTER_LIMIT_REACHED;
    size_t i=m->commands++; while(i && m->command[i-1].id>c->id) { m->command[i]=m->command[i-1]; --i; }
    m->command[i]=*c; return MATTER_OK;
}
const Matter_Event_Def_T* matter_cluster_event(Matter_Cluster_T m,uint32_t id) {
    if(m) for(size_t i=0;i<m->events;++i) if(m->event[i].id==id) return &m->event[i];
    return NULL;
}
Matter_Result_T matter_cluster_add_event(Matter_Cluster_T m,const Matter_Event_Def_T* e) {
    if(!m || !e || !privilege(e->privilege) || e->priority>2) return MATTER_INVALID_ARGUMENT;
    if(m->busy || m->sealed) return MATTER_INVALID_STATE;
    if(matter_cluster_event(m,e->id)) return MATTER_INVALID_ARGUMENT;
    if(m->events==m->config.events) return MATTER_LIMIT_REACHED;
    size_t i=m->events++; while(i && m->event[i-1].id>e->id) { m->event[i]=m->event[i-1]; --i; }
    m->event[i]=*e; return MATTER_OK;
}
Matter_Result_T matter_cluster_seal(Matter_Cluster_T m) { if(!m) return MATTER_INVALID_ARGUMENT; if(m->busy) return MATTER_BUSY; m->sealed=true; return MATTER_OK; }
uint32_t matter_cluster_id(Matter_Cluster_T m) { return m?m->config.id:0; }
size_t matter_cluster_attribute_count(Matter_Cluster_T m) { return m?m->attributes:0; }
size_t matter_cluster_event_count(Matter_Cluster_T m) { return m?m->events:0; }
bool matter_cluster_event_at(Matter_Cluster_T m,size_t i,uint32_t* id) { if(!m || !id || i>=m->events) return false; *id=m->event[i].id; return true; }
bool matter_cluster_attribute_at(Matter_Cluster_T m,size_t i,uint32_t* id) { if(!m || !id || i>=m->attributes) return false; *id=m->attribute[i].id; return true; }
Matter_Result_T matter_cluster_retain(Matter_Cluster_T m) {
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy || m->pins==SIZE_MAX) return MATTER_BUSY;
    m->sealed=true; ++m->pins; return MATTER_OK;
}
Matter_Result_T matter_cluster_release(Matter_Cluster_T m) {
    if(!m || !m->pins) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    --m->pins; return MATTER_OK;
}
Matter_Result_T matter_cluster_delete(Matter_Cluster_T m) {
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy || m->pins) return MATTER_BUSY;
    for(unsigned i=0;i<m->config.pending;++i) if(m->pending[i].handle) return MATTER_BUSY;
    m->busy=true; Matter_Result_T r=m->config.callbacks.destroy?m->config.callbacks.destroy(m->config.callbacks.ctx):MATTER_OK;
    if(r!=MATTER_OK) { m->busy=false; return r; }
    free(m); return MATTER_OK;
}
Matter_Result_T matter_cluster_version(Matter_Cluster_T m,uint32_t* v) {
    if(!m || !v) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    m->busy=true; Matter_Result_T r=m->config.callbacks.version(m->config.callbacks.ctx,v); m->busy=false; return r;
}
Matter_Result_T matter_cluster_process(Matter_Cluster_T m,uint64_t now) {
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    m->busy=true; Matter_Result_T r=m->config.callbacks.process?m->config.callbacks.process(m->config.callbacks.ctx,now):MATTER_OK; m->busy=false; return r;
}
Matter_Result_T matter_cluster_deadline(Matter_Cluster_T m,uint64_t* t) {
    if(!m || !t) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    m->busy=true; Matter_Result_T r=m->config.callbacks.deadline?m->config.callbacks.deadline(m->config.callbacks.ctx,t):MATTER_INVALID_STATE; m->busy=false; return r;
}
uint8_t matter_cluster_describe(Matter_Cluster_T m,uint32_t id,Matter_Im_Attribute_T* out) {
    if(!m || !out || m->busy) return MATTER_IM_FAILURE;
    const Matter_Attribute_Def_T* a=attribute(m,id); if(!a) return MATTER_IM_UNSUPPORTED_ATTRIBUTE;
    *out=a->read_access; return 0;
}
uint8_t matter_cluster_describe_write(Matter_Cluster_T m,uint32_t id,Matter_Im_Write_Attribute_T* out) {
    if(!m || !out || m->busy) return MATTER_IM_FAILURE;
    const Matter_Attribute_Def_T* a=attribute(m,id); if(!a) return MATTER_IM_UNSUPPORTED_ATTRIBUTE;
    if(!a->write && !a->write_list) return MATTER_IM_UNSUPPORTED_WRITE;
    *out=a->write_access; return 0;
}
uint8_t matter_cluster_read(Matter_Cluster_T m,uint32_t id,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    if(!m || !q || !v || m->busy) return MATTER_IM_FAILURE;
    const Matter_Attribute_Def_T* a=attribute(m,id); if(!a) return MATTER_IM_UNSUPPORTED_ATTRIBUTE;
    m->busy=true; uint8_t r=a->read(m->config.callbacks.ctx,a->ref,q,v); m->busy=false; return r;
}
#define ATTRIBUTE_ARGS Matter_Cluster_T m,uint32_t id,const Matter_Cluster_Request_T* q
#define CHECK_ATTRIBUTE(member) \
    if(!m || !q || m->busy || (!d && n)) return MATTER_IM_FAILURE; \
    const Matter_Attribute_Def_T* a=attribute(m,id); if(!a) return MATTER_IM_UNSUPPORTED_ATTRIBUTE; \
    if(!a->member) return MATTER_IM_UNSUPPORTED_WRITE
uint8_t matter_cluster_validate(ATTRIBUTE_ARGS,const uint8_t* d,size_t n) {
    CHECK_ATTRIBUTE(validate); m->busy=true; uint8_t r=a->validate(m->config.callbacks.ctx,a->ref,q,d,n); m->busy=false; return r;
}
Matter_Im_Write_Result_T matter_cluster_write(ATTRIBUTE_ARGS,const uint8_t* d,size_t n) {
    uint8_t r=matter_cluster_validate(m,id,q,d,n); if(r) return (Matter_Im_Write_Result_T){.status=r};
    const Matter_Attribute_Def_T* a=attribute(m,id); m->busy=true;
    Matter_Im_Write_Result_T out=a->write(m->config.callbacks.ctx,a->ref,q,d,n); m->busy=false; return out;
}
uint8_t matter_cluster_validate_list(ATTRIBUTE_ARGS,Matter_Im_List_Change_T change,const uint8_t* d,size_t n) {
    CHECK_ATTRIBUTE(validate_list); m->busy=true; uint8_t r=a->validate_list(m->config.callbacks.ctx,a->ref,q,change,d,n); m->busy=false; return r;
}
Matter_Im_Write_Result_T matter_cluster_write_list(ATTRIBUTE_ARGS,Matter_Im_List_Change_T change,const uint8_t* d,size_t n) {
    uint8_t r=matter_cluster_validate_list(m,id,q,change,d,n); if(r) return (Matter_Im_Write_Result_T){.status=r};
    const Matter_Attribute_Def_T* a=attribute(m,id); m->busy=true;
    Matter_Im_Write_Result_T out=a->write_list(m->config.callbacks.ctx,a->ref,q,change,d,n); m->busy=false; return out;
}
uint8_t matter_cluster_command(Matter_Cluster_T m,uint32_t id,Matter_Im_Command_T* out) {
    if(!m || !out || m->busy) return MATTER_IM_FAILURE;
    const Matter_Command_Def_T* c=command(m,id); if(!c) return MATTER_IM_UNSUPPORTED_COMMAND;
    *out=c->access; return 0;
}
uint8_t matter_cluster_validate_command(Matter_Cluster_T m,uint32_t id,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    if(!m || !q || m->busy || (!d && n)) return MATTER_IM_FAILURE;
    const Matter_Command_Def_T* c=command(m,id); if(!c) return MATTER_IM_UNSUPPORTED_COMMAND;
    m->busy=true; uint8_t r=c->validate(m->config.callbacks.ctx,c->ref,q,d,n); m->busy=false; return r;
}
Matter_Result_T matter_cluster_start(Matter_Cluster_T m,uint32_t id,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n,
    Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out,uint64_t* token) {
    if(!out || !token) return MATTER_INVALID_ARGUMENT;
    *token=0; uint8_t r=matter_cluster_validate_command(m,id,q,d,n);
    if(r) { *out=(Matter_Im_Command_Result_T){.status=r}; return MATTER_OK; }
    const Matter_Command_Def_T* c=command(m,id); Pending* p=NULL;
    if(c->access.response && (!w || w->size || w->capacity<c->access.response_capacity)) {
        *out=(Matter_Im_Command_Result_T){.status=MATTER_IM_RESOURCE_EXHAUSTED}; return MATTER_OK;
    }
    if(c->poll) {
        for(unsigned i=0;i<m->config.pending;++i) if(!m->pending[i].handle) { p=&m->pending[i]; break; }
        if(!p || m->serial==UINT64_MAX) { *out=(Matter_Im_Command_Result_T){.status=MATTER_IM_RESOURCE_EXHAUSTED}; return MATTER_OK; }
    }
    m->sealed=true; m->busy=true; uint64_t backend=0;
    Matter_Result_T result=c->start(m->config.callbacks.ctx,c->ref,q,d,n,w,out,&backend);
    if(result==MATTER_PENDING) {
        if(!p || !backend) { if(backend && c->cancel) c->cancel(m->config.callbacks.ctx,c->ref,backend); result=MATTER_PORT_ERROR; }
        else { *p=(Pending){++m->serial,backend,(size_t)(c-m->command)}; *token=p->handle; }
    } else if(backend) { if(c->cancel) c->cancel(m->config.callbacks.ctx,c->ref,backend); result=MATTER_PORT_ERROR; }
    m->busy=false; return result;
}
static Pending* pending(Matter_Cluster_T m,uint64_t token) {
    if(token) for(unsigned i=0;i<m->config.pending;++i) if(m->pending[i].handle==token) return &m->pending[i];
    return NULL;
}
Matter_Result_T matter_cluster_poll(Matter_Cluster_T m,uint64_t token,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out) {
    if(!m || !out) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    Pending* p=pending(m,token); if(!p) return MATTER_INVALID_STATE;
    const Matter_Command_Def_T* c=&m->command[p->command];
    if(c->access.response && (!w || w->size || w->capacity<c->access.response_capacity)) return MATTER_LIMIT_REACHED;
    m->busy=true; Matter_Result_T r=c->poll(m->config.callbacks.ctx,c->ref,p->backend,w,out);
    if(r!=MATTER_PENDING) { if(r!=MATTER_OK) c->cancel(m->config.callbacks.ctx,c->ref,p->backend); memset(p,0,sizeof(*p)); }
    m->busy=false; return r;
}
Matter_Result_T matter_cluster_cancel(Matter_Cluster_T m,uint64_t token) {
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    Pending* p=pending(m,token); if(!p) return MATTER_INVALID_STATE;
    const Matter_Command_Def_T* c=&m->command[p->command]; m->busy=true;
    c->cancel(m->config.callbacks.ctx,c->ref,p->backend); memset(p,0,sizeof(*p)); m->busy=false; return MATTER_OK;
}

void* matter_cluster_context(Matter_Cluster_T m,Matter_Result_T (*destroy)(void*)) {
    return m && m->config.callbacks.destroy==destroy?m->config.callbacks.ctx:NULL;
}

void matter_cluster_abandon(Matter_Cluster_T m) { if(m && !m->pins && !m->sealed && !m->busy) free(m); }

bool matter_cluster_in_use(Matter_Cluster_T m) {
    if(!m) return false;
    if(m->busy) return true;
    for(unsigned i=0;i<m->config.pending;++i) if(m->pending[i].handle) return true;
    return false;
}

bool matter_cluster_command_async(Matter_Cluster_T m,uint32_t id) {
    const Matter_Command_Def_T* c=command(m,id); return c && c->poll;
}

bool matter_cluster_mutable(Matter_Cluster_T m) { return m && !m->busy && !m->sealed; }
size_t matter_cluster_pins(Matter_Cluster_T m) { return m?m->pins:0; }
uint8_t matter_cluster_command_metadata(Matter_Cluster_T m,uint32_t id,Matter_Im_Command_T* out) {
    if(!m || !out) return MATTER_IM_FAILURE;
    const Matter_Command_Def_T* c=command(m,id); if(!c) return MATTER_IM_UNSUPPORTED_COMMAND;
    *out=c->access; return 0;
}

Matter_Result_T matter_cluster_extend(Matter_Cluster_T m,const Matter_Attribute_Def_T* a,size_t na,const Matter_Command_Def_T* c,size_t nc) {
    if(!m || (!a && na) || (!c && nc)) return MATTER_INVALID_ARGUMENT;
    if(!matter_cluster_mutable(m)) return MATTER_INVALID_STATE;
    if(na>m->config.attributes-m->attributes || nc>m->config.commands-m->commands) return MATTER_LIMIT_REACHED;
    for(size_t i=0;i<na;++i) {
        if(!valid_attribute(&a[i]) || attribute(m,a[i].id)) return MATTER_INVALID_ARGUMENT;
        for(size_t j=0;j<i;++j) if(a[i].id==a[j].id) return MATTER_INVALID_ARGUMENT;
    }
    for(size_t i=0;i<nc;++i) {
        if(!valid_command(m,&c[i]) || command(m,c[i].id)) return MATTER_INVALID_ARGUMENT;
        for(size_t j=0;j<i;++j) if(c[i].id==c[j].id) return MATTER_INVALID_ARGUMENT;
    }
    /* All failures checked before mutation. Owner-thread, no callbacks/allocation. */
    for(size_t i=0;i<na;++i) (void)matter_cluster_add_attribute(m,&a[i]);
    for(size_t i=0;i<nc;++i) (void)matter_cluster_add_command(m,&c[i]);
    return MATTER_OK;
}
