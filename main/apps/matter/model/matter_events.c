#include "matter_events_internal.h"
#include "../codec/matter_tlv_validate.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
typedef struct EventNode {
    Matter_Event_Record_T record;
    struct EventNode* next;
    size_t references; /* One log/prepared owner plus immutable snapshots. */
    bool evicted; /* Prepared removal only; the published list is untouched. */
} EventNode;
typedef char EventRecordMustBeFirst[(offsetof(EventNode,record)==0)?1:-1];
struct Matter_Events {
    Matter_Events_Port_T port; uint64_t next,limit,pending_next; size_t count,pending_count; bool busy,prepared;
    EventNode *records,*last,*pending,*pending_last;
    Matter_Event_Record_T single;
    Matter_Tlv_Validation_Workspace_T validation; Matter_Tlv_Tag_T tags[32];
};
static void drop_node(EventNode* node) { if(!--node->references) free(node); }
static void free_nodes(EventNode* node) {
    while(node) { EventNode* next=node->next; drop_node(node); node=next; }
}
static void discard_pending(Matter_Events_T m) {
    for(EventNode* node=m->records;node;node=node->next) node->evicted=false;
    free_nodes(m->pending); m->pending=m->pending_last=NULL;
    m->pending_count=0; m->pending_next=0;
}
/* Oldest lowest priority in the simulated post-batch order. New records must
 * participate too: the original policy rejects a batch which would evict any
 * of its own records, even if an older higher-priority record still exists. */
static EventNode* victim(Matter_Events_T m) {
    EventNode* lowest=NULL;
    for(EventNode* node=m->records;node;node=node->next)
        if(!node->evicted && (!lowest || node->record.priority<lowest->record.priority)) lowest=node;
    for(EventNode* node=m->pending;node;node=node->next)
        if(!lowest || node->record.priority<lowest->record.priority) lowest=node;
    return lowest;
}
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
    size_t retained=m->count;
    for(size_t j=0;j<count;++j) {
        const Matter_Event_Record_T* r=&records[j];
        EventNode* old=retained==MATTER_EVENTS_CAPACITY?victim(m):NULL;
        if(old && (old->record.priority>r->priority || old->record.number>=m->next)) {
            discard_pending(m); return MATTER_LIMIT_REACHED;
        }
        EventNode* node=calloc(1,sizeof(*node));
        if(!node) { discard_pending(m); return MATTER_LIMIT_REACHED; }
        node->record=*r; node->record.number=m->next+j; node->references=1;
        if(old) old->evicted=true; else ++retained;
        if(m->pending_last) m->pending_last->next=node; else m->pending=node;
        m->pending_last=node; ++m->pending_count;
    }
    m->pending_next=m->next+count; m->busy=true;
    if(m->pending_next>m->limit) {
        uint64_t reserve=count>32?count:32;
        uint64_t limit=UINT64_MAX-m->next<reserve?UINT64_MAX:m->next+reserve;
        if(m->port.store(m->port.user,limit)!=MATTER_OK) { discard_pending(m); m->busy=false; return MATTER_PORT_ERROR; }
        m->limit=limit;
    }
    m->prepared=true; return MATTER_OK;
}
void matter_events_finish(Matter_Events_T m,bool commit) {
    if(!m || !m->prepared) return;
    if(commit) {
        EventNode** link=&m->records; m->last=NULL;
        while(*link) {
            EventNode* node=*link;
            if(node->evicted) { *link=node->next; drop_node(node); --m->count; }
            else { m->last=node; link=&node->next; }
        }
        if(m->last) m->last->next=m->pending; else m->records=m->pending;
        m->last=m->pending_last; m->count+=m->pending_count; m->next=m->pending_next;
        m->pending=m->pending_last=NULL; m->pending_count=0; m->pending_next=0;
    } else discard_pending(m);
    m->prepared=m->busy=false;
}
Matter_Result_T matter_events_forget_fabric(Matter_Events_T m,uint8_t fabric) {
    if(!m || !fabric || fabric==255) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    EventNode** link=&m->records; m->last=NULL;
    while(*link) {
        EventNode* node=*link;
        if(node->record.fabric==fabric) { *link=node->next; drop_node(node); --m->count; }
        else { m->last=node; link=&node->next; }
    }
    return MATTER_OK;
}
Matter_Result_T matter_events_copy(Matter_Events_T m,const Matter_Event_Path_T* p,uint64_t minimum,Matter_Event_Record_T* out,size_t* count) {
    if(!m || !p || !out || !count) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    *count=0;
    for(EventNode* node=m->records;node;node=node->next) {
        const Matter_Event_Record_T* r=&node->record;
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
static bool selected(const Matter_Event_Record_T* r,const Matter_Event_Filter_T* filters,size_t paths,uint64_t minimum,uint8_t fabric) {
    if(r->number<minimum) return false;
    for(size_t j=0;j<paths;++j) {
        const Matter_Event_Filter_T* f=&filters[j];
        if(r->path.endpoint==f->path.endpoint && r->path.cluster==f->path.cluster && r->path.event==f->path.event &&
            (f->scoped?r->fabric==fabric:r->fabric==0)) return true;
    }
    return false;
}
Matter_Result_T matter_events_copy_selected(Matter_Events_T m,const Matter_Event_Filter_T* filters,size_t paths,
    uint64_t minimum,uint8_t fabric,Matter_Event_Record_T* out,size_t* count) {
    if(!m || (!filters && paths) || paths>MATTER_EVENT_PATH_CAPACITY || fabric==255 || !count) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    for(size_t j=0;j<paths;++j) if(filters[j].scoped && !fabric) return MATTER_INVALID_ARGUMENT;
    *count=0;
    for(EventNode* node=m->records;node;node=node->next) {
        const Matter_Event_Record_T* r=&node->record;
        if(selected(r,filters,paths,minimum,fabric)) {
            if(out) out[*count]=*r;
            ++*count;
        }
    }
    return MATTER_OK;
}
void matter_events_snapshot_release_before(Matter_Events_Snapshot* snapshot,size_t end) {
    if(end>snapshot->count) end=snapshot->count;
    while(snapshot->released<end) {
        size_t i=snapshot->released++;
        /* C permits conversion from a struct's initial member to its owner.
         * Only acquire() produces these immutable record references. */
        drop_node((EventNode*)(void*)snapshot->records[i]); snapshot->records[i]=NULL;
    }
}
void matter_events_snapshot_clear(Matter_Events_Snapshot* snapshot) {
    matter_events_snapshot_release_before(snapshot,snapshot->count);
    free(snapshot->records); memset(snapshot,0,sizeof(*snapshot));
}
Matter_Result_T matter_events_snapshot_acquire(Matter_Events_T m,const Matter_Event_Filter_T* filters,size_t paths,
    uint64_t minimum,uint8_t fabric,Matter_Events_Snapshot* snapshot) {
    if(!snapshot) return MATTER_INVALID_ARGUMENT;
    size_t count=0;
    Matter_Result_T result=matter_events_copy_selected(m,filters,paths,minimum,fabric,NULL,&count);
    if(result!=MATTER_OK) return result;
    if(count>MATTER_EVENTS_CAPACITY || count>SIZE_MAX/sizeof(*snapshot->records)) return MATTER_LIMIT_REACHED;
    const Matter_Event_Record_T** records=count?calloc(count,sizeof(*records)):NULL;
    if(count && !records) return MATTER_LIMIT_REACHED;
    size_t i=0;
    for(EventNode* node=m->records;node;node=node->next) if(selected(&node->record,filters,paths,minimum,fabric)) {
        if(node->references==SIZE_MAX) { free(records); return MATTER_LIMIT_REACHED; }
        records[i++]=&node->record;
    }
    /* No application callbacks or log mutation between count, checked capture
     * and publication. OOM/overflow leave every old snapshot/reference intact. */
    for(i=0;i<count;++i) ++((EventNode*)(void*)records[i])->references;
    matter_events_snapshot_clear(snapshot);
    *snapshot=(Matter_Events_Snapshot){records,count,0}; return MATTER_OK;
}
Matter_Result_T matter_events_position(Matter_Events_T m,uint64_t* next) {
    if(!m || !next) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    *next=m->next; return MATTER_OK;
}
Matter_Result_T matter_events_delete(Matter_Events_T m) {
    if(!m) return MATTER_OK;
    if(m->busy) return MATTER_BUSY;
    free_nodes(m->records); free(m); return MATTER_OK;
}
