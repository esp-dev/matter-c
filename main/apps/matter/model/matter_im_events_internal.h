#ifndef MATTER_IM_EVENTS_INTERNAL_H
#define MATTER_IM_EVENTS_INTERNAL_H 1
#include "matter_im_read.h"
#include "matter_events_internal.h"
#include "matter_im_blocks_internal.h"
#include <stdlib.h>
/* The owner thread cannot mutate the log between count and copy: neither call
 * invokes an application callback. Publish the new immutable snapshot atomically. */
static inline Matter_Result_T matter_im_event_snapshot(Matter_Events_T log,const Matter_Event_Filter_T* filters,
    size_t paths,uint64_t minimum,uint8_t fabric,Matter_Events_Snapshot* records,size_t* count) {
    Matter_Result_T r=matter_events_snapshot_acquire(log,filters,paths,minimum,fabric,records);
    if(r==MATTER_OK) *count=records->count;
    return r;
}
/* Small per-path metadata; the handlers retain ONE node-log snapshot. */
typedef struct {
    Matter_Event_Path_T path;
    Matter_Im_Attribute_T access;
    uint8_t status;
    bool reported,active,urgent,wildcard,omit;
} Matter_Im_Event_Request_T;
MATTER_IM_BLOCK_TABLE(matter_im_event_paths,Matter_Im_Event_Request_T)
typedef struct Matter_Im_Event_Selector_Node {
    struct Matter_Im_Event_Selector_Node* next;
    Matter_Im_Event_Selector_T selector;
    bool urgent;
} Matter_Im_Event_Selector_Node;
typedef struct {
    Matter_Im_Event_Selector_Node *requests,*last,*current;
    Matter_Im_Event_Enumerate_T enumerate;
    size_t cursor,candidates;
    Matter_Event_Path_T after;
    bool after_valid,wildcard;
} Matter_Im_Event_Expansion_T;
static inline void matter_im_event_selectors_clear(Matter_Im_Event_Expansion_T* x) {
    while(x->requests) {
        Matter_Im_Event_Selector_Node* next=x->requests->next;
        free(x->requests); x->requests=next;
    }
    x->last=x->current=NULL;
}
static inline void matter_im_event_metadata_clear(Matter_Im_Event_Expansion_T* x,Matter_Im_Blocks* paths,Matter_Event_Filter_T** filters) {
    matter_im_event_selectors_clear(x); matter_im_blocks_clear(paths);
    free(*filters); *filters=NULL;
}
static inline bool matter_im_event_filters_reserve(Matter_Event_Filter_T** filters,size_t count) {
    if(!count || *filters) return true;
    if(count>MATTER_EVENT_PATH_CAPACITY || count>SIZE_MAX/sizeof(**filters)) return false;
    *filters=calloc(count,sizeof(**filters)); return *filters!=NULL;
}
static inline bool matter_im_event_same(const Matter_Event_Path_T* a,const Matter_Event_Path_T* b) {
    return a->endpoint==b->endpoint && a->cluster==b->cluster && a->event==b->event;
}
static inline size_t matter_im_event_index(Matter_Im_Blocks* paths,size_t count,const Matter_Event_Path_T* path) {
    for(size_t i=0;i<count;++i) {
        const Matter_Im_Event_Request_T* q=matter_im_event_paths_at(paths,i);
        if(matter_im_event_same(&q->path,path)) return i;
    }
    return count;
}
static inline bool matter_im_event_path_add(Matter_Im_Blocks* paths,size_t* count,
    const Matter_Event_Path_T* path,bool wildcard,bool urgent) {
    size_t i=matter_im_event_index(paths,*count,path);
    if(i==*count) {
        if(!matter_im_event_paths_reserve(paths,*count+1,MATTER_EVENT_PATH_CAPACITY)) return false;
        *matter_im_event_paths_at(paths,(*count)++)=(Matter_Im_Event_Request_T){.path=*path,.wildcard=wildcard};
    }
    matter_im_event_paths_at(paths,i)->urgent|=urgent; return true;
}
static inline uint8_t matter_im_event_selector_add(Matter_Im_Event_Expansion_T* x,Matter_Im_Blocks* paths,size_t* count,
    const Matter_Im_Event_Selector_T* selector,bool urgent) {
    bool wildcard=selector->present!=MATTER_IM_CONCRETE;
    if(wildcard && !x->enumerate) return MATTER_IM_INVALID_ACTION;
    Matter_Im_Event_Selector_Node* node=calloc(1,sizeof(*node));
    if(!node) return MATTER_IM_RESOURCE_EXHAUSTED;
    node->selector=*selector; node->urgent=urgent;
    if(!wildcard && !matter_im_event_path_add(paths,count,&selector->path,false,urgent)) { free(node); return MATTER_IM_RESOURCE_EXHAUSTED; }
    if(x->last) x->last->next=node; else x->requests=x->current=node;
    x->last=node; x->wildcard|=wildcard; return 0;
}
static inline bool matter_im_event_matches(const Matter_Im_Event_Selector_T* q,const Matter_Event_Path_T* p) {
    return (!(q->present&MATTER_IM_ENDPOINT) || q->path.endpoint==p->endpoint) &&
        (!(q->present&MATTER_IM_CLUSTER) || q->path.cluster==p->cluster) &&
        (!(q->present&MATTER_IM_EVENT) || q->path.event==p->event);
}
static inline bool matter_im_event_before(const Matter_Event_Path_T* a,const Matter_Event_Path_T* b) {
    return a->endpoint<b->endpoint || (a->endpoint==b->endpoint &&
        (a->cluster<b->cluster || (a->cluster==b->cluster && a->event<b->event)));
}
static inline bool matter_im_event_omitted(bool wildcard,uint8_t status) {
    return wildcard && (status==MATTER_IM_UNSUPPORTED_ACCESS || status==MATTER_IM_ACCESS_RESTRICTED ||
        status==MATTER_IM_UNSUPPORTED_ENDPOINT || status==MATTER_IM_UNSUPPORTED_CLUSTER || status==MATTER_IM_UNSUPPORTED_EVENT);
}
/* Concrete selectors are inserted while decoding, so they retain explicit
 * status semantics even when overlapping a wildcard earlier in the request. */
static inline uint8_t matter_im_event_expand(Matter_Im_Event_Expansion_T* x,void* user,size_t raw_count,
    Matter_Im_Blocks* paths,size_t* count) {
    for(unsigned step=0;step<MATTER_IM_READ_WORK_BATCH && x->cursor<raw_count;++step) {
        Matter_Im_Event_Selector_Node* node=x->current;
        const Matter_Im_Event_Selector_T* q=&node->selector;
        if(q->present==MATTER_IM_CONCRETE) {
            if(x->candidates++==MATTER_EVENT_PATH_CAPACITY) return MATTER_IM_RESOURCE_EXHAUSTED;
            ++x->cursor; x->current=node->next; continue;
        }
        Matter_Event_Path_T path={0}; bool found=false;
        if(!x->enumerate || x->enumerate(user,q,x->after_valid?&x->after:NULL,&path,&found)!=MATTER_OK) return MATTER_IM_FAILURE;
        if(!found) { ++x->cursor; x->current=node->next; x->after_valid=false; continue; }
        if(!matter_im_event_matches(q,&path) || (x->after_valid && !matter_im_event_before(&x->after,&path))) return MATTER_IM_FAILURE;
        if(x->candidates++==MATTER_EVENT_PATH_CAPACITY) return MATTER_IM_RESOURCE_EXHAUSTED;
        x->after=path; x->after_valid=true;
        if(!matter_im_event_path_add(paths,count,&path,true,node->urgent)) return MATTER_IM_RESOURCE_EXHAUSTED;
    }
    return 0;
}
/* Status blocks precede remaining data. Denied paths cannot emit their cached
 * payload after ACL revocation. Caller rechecks permissions before using this. */
static inline bool matter_im_event_more(Matter_Im_Blocks* paths,size_t count,
    const Matter_Events_Snapshot* records,size_t cursor,size_t end) {
    for(size_t i=0;i<count;++i) {
        const Matter_Im_Event_Request_T* q=matter_im_event_paths_at(paths,i);
        if(q->status && !q->reported && !q->omit) return true;
    }
    for(size_t i=cursor;i<end;++i) {
        size_t j=matter_im_event_index(paths,count,&records->records[i]->path);
        if(j<count && !matter_im_event_paths_at(paths,j)->status && !matter_im_event_paths_at(paths,j)->omit) return true;
    }
    return false;
}
/* Consume one status or record; skipped/revoked records never become output. */
static inline size_t matter_im_event_take(Matter_Im_Blocks* paths,size_t count,
    const Matter_Events_Snapshot* records,size_t* cursor,size_t end,const Matter_Event_Record_T** record) {
    *record=NULL;
    for(size_t i=0;i<count;++i) {
        Matter_Im_Event_Request_T* q=matter_im_event_paths_at(paths,i);
        if(q->status && !q->reported && !q->omit) { q->reported=true; return i; }
    }
    while(*cursor<end) {
        const Matter_Event_Record_T* r=records->records[(*cursor)++];
        size_t i=matter_im_event_index(paths,count,&r->path);
        if(i<count && !matter_im_event_paths_at(paths,i)->status && !matter_im_event_paths_at(paths,i)->omit) { *record=r; return i; }
    }
    return count;
}
#endif
