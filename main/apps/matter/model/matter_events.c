#include "matter_events.h"
#include "../codec/matter_tlv_validate.h"
#include <stdlib.h>
#include <string.h>
struct Matter_Events {
    Matter_Events_Port_T port; uint64_t next,limit,pending_next; size_t count,pending_count; bool busy,prepared;
    Matter_Event_Record_T records[MATTER_EVENTS_CAPACITY];
    Matter_Event_Record_T pending[MATTER_EVENTS_CAPACITY],single;
    Matter_Tlv_Validation_Workspace_T validation; Matter_Tlv_Tag_T tags[32];
};
Matter_Events_T matter_events_new(const Matter_Events_Port_T* p) {
    if(!p || !p->load || !p->store) return NULL;
    Matter_Events_T m=calloc(1,sizeof(*m)); if(!m) return NULL;
    m->port=*p; m->busy=true;
    if(p->load(p->user,&m->next)!=MATTER_OK) { free(m); return NULL; }
    m->limit=m->next; m->busy=false; return m;
}
Matter_Result_T matter_events_append(Matter_Events_T m,const Matter_Event_Path_T* path,uint8_t priority,
    uint64_t timestamp,bool epoch,const uint8_t* data,size_t size) {
    if(!m || !path || priority>2 || !data || size<2 || size>MATTER_EVENT_DATA_MAX || data[0]!=0x15) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    m->single=(Matter_Event_Record_T){.path=*path,.timestamp_ms=timestamp,.priority=priority,.epoch=epoch,.size=size};
    memcpy(m->single.data,data,size);
    Matter_Result_T r=matter_events_prepare(m,&m->single,1);
    if(r==MATTER_OK) matter_events_finish(m,true);
    return r;
}
Matter_Result_T matter_events_prepare(Matter_Events_T m,const Matter_Event_Record_T* records,size_t count) {
    if(!m || !records || !count || count>MATTER_EVENTS_CAPACITY) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    const Matter_Tlv_Validation_Options_T opt={MATTER_EVENT_DATA_MAX,64,256,4,false,0,0};
    Matter_Tlv_Validation_Report_T report;
    for(size_t j=0;j<count;++j) {
        const Matter_Event_Record_T* r=&records[j];
        if(r->priority>2 || r->fabric==255 || r->size<2 || r->size>MATTER_EVENT_DATA_MAX || r->data[0]!=0x15 ||
            matter_tlv_validate(r->data,r->size,&opt,&m->validation,m->tags,32,&report)!=MATTER_TLV_OK) return MATTER_INVALID_ARGUMENT;
    }
    if(count>UINT64_MAX-m->next) return MATTER_LIMIT_REACHED;
    memcpy(m->pending,m->records,m->count*sizeof(*m->records)); m->pending_count=m->count;
    for(size_t j=0;j<count;++j) {
        const Matter_Event_Record_T* r=&records[j];
        if(m->pending_count==MATTER_EVENTS_CAPACITY) {
            size_t victim=0;
            for(size_t i=1;i<m->pending_count;++i) if(m->pending[i].priority<m->pending[victim].priority) victim=i;
            if(m->pending[victim].priority>r->priority || m->pending[victim].number>=m->next) return MATTER_LIMIT_REACHED;
            memmove(&m->pending[victim],&m->pending[victim+1],(m->pending_count-victim-1)*sizeof(*m->pending)); --m->pending_count;
        }
        m->pending[m->pending_count]=*r; m->pending[m->pending_count++].number=m->next+j;
    }
    m->pending_next=m->next+count; m->busy=true;
    if(m->pending_next>m->limit) {
        uint64_t reserve=count>32?count:32;
        uint64_t limit=UINT64_MAX-m->next<reserve?UINT64_MAX:m->next+reserve;
        if(m->port.store(m->port.user,limit)!=MATTER_OK) { m->busy=false; return MATTER_PORT_ERROR; }
        m->limit=limit;
    }
    m->prepared=true; return MATTER_OK;
}
void matter_events_finish(Matter_Events_T m,bool commit) {
    if(!m || !m->prepared) return;
    if(commit) { memcpy(m->records,m->pending,m->pending_count*sizeof(*m->records)); m->count=m->pending_count; m->next=m->pending_next; }
    m->prepared=m->busy=false;
}
Matter_Result_T matter_events_forget_fabric(Matter_Events_T m,uint8_t fabric) {
    if(!m || !fabric || fabric==255) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    size_t n=0;
    for(size_t i=0;i<m->count;++i) if(m->records[i].fabric!=fabric) m->records[n++]=m->records[i];
    m->count=n; return MATTER_OK;
}
Matter_Result_T matter_events_copy(Matter_Events_T m,const Matter_Event_Path_T* p,uint64_t minimum,Matter_Event_Record_T* out,size_t* count) {
    if(!m || !p || !out || !count) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    *count=0;
    for(size_t i=0;i<m->count;++i) {
        const Matter_Event_Record_T* r=&m->records[i];
        if(r->number>=minimum && r->path.endpoint==p->endpoint && r->path.cluster==p->cluster && r->path.event==p->event) out[(*count)++]=*r;
    }
    return MATTER_OK;
}
Matter_Result_T matter_events_copy_fabric(Matter_Events_T m,const Matter_Event_Path_T* p,uint64_t minimum,
    uint8_t fabric,bool scoped,Matter_Event_Record_T* out,size_t* count) {
    if(fabric==255 || (scoped && !fabric)) return MATTER_INVALID_ARGUMENT;
    Matter_Result_T r=matter_events_copy(m,p,minimum,out,count); if(r!=MATTER_OK) return r;
    size_t n=0;
    for(size_t i=0;i<*count;++i) if(scoped?out[i].fabric==fabric:!out[i].fabric) out[n++]=out[i];
    *count=n; return MATTER_OK;
}
Matter_Result_T matter_events_copy_selected(Matter_Events_T m,const Matter_Event_Filter_T* filters,size_t paths,
    uint64_t minimum,uint8_t fabric,Matter_Event_Record_T* out,size_t* count) {
    if(!m || (!filters && paths) || paths>MATTER_EVENT_PATH_CAPACITY || fabric==255 || !count) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    for(size_t j=0;j<paths;++j) if(filters[j].scoped && !fabric) return MATTER_INVALID_ARGUMENT;
    *count=0;
    for(size_t i=0;i<m->count;++i) {
        const Matter_Event_Record_T* r=&m->records[i]; if(r->number<minimum) continue;
        for(size_t j=0;j<paths;++j) {
            const Matter_Event_Filter_T* f=&filters[j];
            if(r->path.endpoint!=f->path.endpoint || r->path.cluster!=f->path.cluster || r->path.event!=f->path.event ||
                (f->scoped?r->fabric!=fabric:r->fabric!=0)) continue;
            if(out) out[*count]=*r;
            ++*count; break;
        }
    }
    return MATTER_OK;
}
Matter_Result_T matter_events_position(Matter_Events_T m,uint64_t* next) {
    if(!m || !next) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    *next=m->next; return MATTER_OK;
}
Matter_Result_T matter_events_delete(Matter_Events_T m) {
    if(!m) return MATTER_OK;
    if(m->busy) return MATTER_BUSY;
    free(m); return MATTER_OK;
}
