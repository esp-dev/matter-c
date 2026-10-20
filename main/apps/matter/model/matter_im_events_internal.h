#ifndef MATTER_IM_EVENTS_INTERNAL_H
#define MATTER_IM_EVENTS_INTERNAL_H 1
#include "matter_im_read.h"
#include <stdlib.h>
/* The owner thread cannot mutate the log between count and copy: neither call
 * invokes an application callback. Publish the new immutable snapshot atomically. */
static inline Matter_Result_T matter_im_event_snapshot(Matter_Events_T log,const Matter_Event_Filter_T* filters,
    size_t paths,uint64_t minimum,uint8_t fabric,Matter_Event_Record_T** records,size_t* count) {
    size_t n=0;
    Matter_Result_T r=matter_events_copy_selected(log,filters,paths,minimum,fabric,NULL,&n);
    if(r!=MATTER_OK) return r;
    if(n>MATTER_EVENTS_CAPACITY || n>SIZE_MAX/sizeof(**records)) return MATTER_LIMIT_REACHED;
    Matter_Event_Record_T* next=n?calloc(n,sizeof(*next)):NULL;
    if(n && !next) return MATTER_LIMIT_REACHED;
    if(n) r=matter_events_copy_selected(log,filters,paths,minimum,fabric,next,&n);
    if(r!=MATTER_OK) { free(next); return r; }
    free(*records); *records=next; *count=n; return MATTER_OK;
}
/* Small per-path metadata; the handlers retain ONE node-log snapshot. */
typedef struct {
    Matter_Event_Path_T path;
    Matter_Im_Attribute_T access;
    uint8_t status;
    bool reported,active,urgent,wildcard,omit;
} Matter_Im_Event_Request_T;
typedef struct {
    struct { Matter_Im_Event_Selector_T selector; bool urgent; } requests[MATTER_IM_READ_MAX_PATHS];
    Matter_Im_Event_Enumerate_T enumerate;
    size_t cursor,candidates;
    Matter_Event_Path_T after;
    bool after_valid,wildcard;
} Matter_Im_Event_Expansion_T;
static inline bool matter_im_event_same(const Matter_Event_Path_T* a,const Matter_Event_Path_T* b) {
    return a->endpoint==b->endpoint && a->cluster==b->cluster && a->event==b->event;
}
static inline size_t matter_im_event_index(const Matter_Im_Event_Request_T* paths,size_t count,const Matter_Event_Path_T* path) {
    for(size_t i=0;i<count;++i) if(matter_im_event_same(&paths[i].path,path)) return i;
    return count;
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
    Matter_Im_Event_Request_T* paths,size_t* count) {
    for(unsigned step=0;step<MATTER_IM_READ_WORK_BATCH && x->cursor<raw_count;++step) {
        const Matter_Im_Event_Selector_T* q=&x->requests[x->cursor].selector;
        if(q->present==MATTER_IM_CONCRETE) {
            if(x->candidates++==MATTER_EVENT_PATH_CAPACITY) return MATTER_IM_RESOURCE_EXHAUSTED;
            ++x->cursor; continue;
        }
        Matter_Event_Path_T path={0}; bool found=false;
        if(!x->enumerate || x->enumerate(user,q,x->after_valid?&x->after:NULL,&path,&found)!=MATTER_OK) return MATTER_IM_FAILURE;
        if(!found) { ++x->cursor; x->after_valid=false; continue; }
        if(!matter_im_event_matches(q,&path) || (x->after_valid && !matter_im_event_before(&x->after,&path))) return MATTER_IM_FAILURE;
        if(x->candidates++==MATTER_EVENT_PATH_CAPACITY) return MATTER_IM_RESOURCE_EXHAUSTED;
        x->after=path; x->after_valid=true;
        size_t i=matter_im_event_index(paths,*count,&path);
        if(i==*count) {
            if(*count==MATTER_EVENT_PATH_CAPACITY) return MATTER_IM_RESOURCE_EXHAUSTED;
            paths[(*count)++]=(Matter_Im_Event_Request_T){.path=path,.wildcard=true};
        }
        paths[i].urgent|=x->requests[x->cursor].urgent;
    }
    return 0;
}
/* Status blocks precede remaining data. Denied paths cannot emit their cached
 * payload after ACL revocation. Caller rechecks permissions before using this. */
static inline bool matter_im_event_more(const Matter_Im_Event_Request_T* paths,size_t count,
    const Matter_Event_Record_T* records,size_t cursor,size_t end) {
    for(size_t i=0;i<count;++i) if(paths[i].status && !paths[i].reported && !paths[i].omit) return true;
    for(size_t i=cursor;i<end;++i) {
        size_t j=matter_im_event_index(paths,count,&records[i].path);
        if(j<count && !paths[j].status && !paths[j].omit) return true;
    }
    return false;
}
/* Consume one status or record; skipped/revoked records never become output. */
static inline size_t matter_im_event_take(Matter_Im_Event_Request_T* paths,size_t count,
    const Matter_Event_Record_T* records,size_t* cursor,size_t end,const Matter_Event_Record_T** record) {
    *record=NULL;
    for(size_t i=0;i<count;++i) if(paths[i].status && !paths[i].reported && !paths[i].omit) {
        paths[i].reported=true; return i;
    }
    while(*cursor<end) {
        const Matter_Event_Record_T* r=&records[(*cursor)++];
        size_t i=matter_im_event_index(paths,count,&r->path);
        if(i<count && !paths[i].status && !paths[i].omit) { *record=r; return i; }
    }
    return count;
}
#endif
