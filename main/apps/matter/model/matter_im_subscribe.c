#include "matter_im_subscribe.h"
#include "matter_im_paths_internal.h"
#include "matter_im_events_internal.h"
#include "matter_im_snapshot_internal.h"
#include "../codec/matter_tlv_validate.h"
#include "../codec/matter_tlv_writer.h"
#include "matter_im_buffer_internal.h"
#include "matter_im_output_internal.h"
#include "matter_im_blocks_internal.h"
#include <stdlib.h>
#include <string.h>

enum { PRIME, RESPONSE, UPDATE, ERROR_REPLY };
typedef struct {
    Matter_Im_Read_Events_Port_T port; Matter_Event_Path_T path;
    uint64_t initial_min,next,pending_next; size_t count,cursor;
    bool requested,active,urgent,dirty,report; uint8_t status;
    size_t path_count,raw_count,access_cursor,filter_count;
    Matter_Im_Event_Expansion_T expansion;
    bool collected;
    Matter_Im_Blocks paths;
    Matter_Event_Filter_T* filters;
    Matter_Events_Snapshot records;
} SubEvents;
typedef struct {
    struct { size_t item,start,end; bool prefix; } plan[MATTER_IM_READ_MAX_PATHS];
    Matter_Tlv_Reader_T value_reader; Matter_Tlv_Element_T element;
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Writer_T writer;
    Matter_Tlv_Element_T token, root[9], fields[8], revision;
    Matter_Tlv_Validation_Workspace_T validation;
    uint8_t short_snapshot[MATTER_IM_SNAPSHOT_INLINE];
    Matter_Tlv_Tag_T tags[48];
} Matter_Im_Subscribe_Work;
/* Keep the full-width path IDs, but use the padding beside endpoint/status for
 * the four Boolean flags. Private C99 bool bitfields never cross the wire/ABI.
 * Only the path adapters construct the unchanged public provider DTO. */
typedef struct {
    uint32_t cluster,attribute,reported_version; uint16_t endpoint; uint8_t status;
    bool active:1,included:1,wildcard:1,reported:1;
} SubItem;
static Matter_Im_Path_T sub_item_path(const SubItem* item) {
    return (Matter_Im_Path_T){item->endpoint,item->cluster,item->attribute};
}
static void sub_item_set_path(SubItem* item,const Matter_Im_Path_T* path) {
    item->endpoint=path->endpoint; item->cluster=path->cluster; item->attribute=path->attribute;
}
MATTER_IM_BLOCK_TABLE(sub_items,SubItem)
MATTER_IM_BLOCK_TABLE(sub_values,Matter_Im_Snapshot_Value)
struct Matter_Im_Subscribe {
    Matter_Im_Subscribe_Work* work;
    Matter_Im_Read_Events_Port_T event_port; Matter_Im_Event_Enumerate_T event_enumerate;
    Matter_Im_Subscribe_Port_T port;
    Matter_Im_Read_Fabric_Port_T fabric; uint8_t fabric_index;
    bool fabric_resolved;
    Matter_Im_Subscribe_Config_T config;
    Matter_Exchange_Info_T exchange;
    Matter_Im_Subscribe_State_T state;
    uint64_t now, expires, last_report,last_activity;
    bool more,report_started;
    size_t count,cursor,list_offset,released;
    Matter_Im_Blocks items;
    Matter_Im_Blocks values; /* Only the current captured report, not idle subscription state. */
    Matter_Im_Selector_T* requests;
    size_t request_count,request_cursor,filter_count,collected,valid;
    struct { uint16_t endpoint; uint32_t cluster,version; } *filters;
    Matter_Im_Path_T after; bool after_valid,expanding,capture_data,attribute_report;
    Matter_Im_Snapshots snapshots; SubEvents* events;
    uint32_t id;
    uint16_t minimum, maximum;
    bool busy, queued, reserved, active, dirty, status_ok, filtered, terminal_report;
    uint8_t phase, opcode;
    size_t input_size, output_size;
    Matter_Im_Path_T path;
    Matter_Im_Attribute_T attribute;
    Matter_Im_Value_T value;
    uint8_t *input, *output;
    Matter_Im_Output_Pool* output_pool;
    bool output_copied;
};
static uint64_t add(uint64_t a,uint64_t b) { return UINT64_MAX-a<b ? UINT64_MAX : a+b; }
static Matter_Result_T check(Matter_Im_Subscribe_T s) { return !s ? MATTER_INVALID_ARGUMENT : s->busy ? MATTER_BUSY : MATTER_OK; }
static void clear_filters(Matter_Im_Subscribe_T s) {
    free(s->filters); s->filters=NULL; s->filter_count=0;
}
static void release(Matter_Im_Subscribe_T s) {
    clear_filters(s);
    if(s->events) { matter_events_snapshot_clear(&s->events->records); s->events->count=s->events->cursor=0; free(s->events->filters); s->events->filters=NULL; }
    if(s->reserved) { s->reserved=false; s->port.release(s->port.attributes.user,s->id); }
}
static Matter_Result_T fail(Matter_Im_Subscribe_T s) {
    s->state=MATTER_IM_SUB_FAILED; s->queued=false; s->output_size=0; s->active=false;
    matter_im_output_release(s->output_pool,s,&s->output);
    bool busy=s->busy; s->busy=true; release(s); s->busy=busy; return MATTER_PORT_ERROR;
}
static Matter_Result_T clock_check(Matter_Im_Subscribe_T s,uint64_t now) {
    if(now<s->now) return MATTER_INVALID_ARGUMENT;
    s->now=now;
    if(s->state==MATTER_IM_SUB_FAILED) return MATTER_INVALID_STATE;
    /* MaxInterval is the publisher's next work deadline, not an exact-tick
     * expiry. The owner loop can wake just after it. Once work is requested,
     * the existing exchange timeout bounds resource/transport starvation. */
    if(s->state!=MATTER_IM_SUB_IDLE && now>=s->expires) return fail(s);
    return MATTER_OK;
}
Matter_Im_Subscribe_T matter_im_subscribe_new(const Matter_Im_Subscribe_Port_T* p,const Matter_Im_Subscribe_Config_T* c,uint64_t now) {
    if(!p || !c || !p->attributes.authorize || !p->attributes.describe || !p->attributes.read || !p->reserve || !p->release ||
        !c->exchange.session || c->exchange.initiator || !c->pase_commissionee || !c->timeout_ms || c->output_capacity<8 || c->output_capacity>MATTER_IM_READ_MAX_OUTPUT) return NULL;
    Matter_Im_Subscribe_T s=calloc(1,sizeof(*s));
    if(s) {
        s->output=calloc(1,c->output_capacity);
        if(!s->output) { free(s); return NULL; }
        s->port=*p; s->config=*c; s->exchange=c->exchange; s->now=now; s->expires=add(now,c->timeout_ms); s->dirty=true;
    }
    return s;
}
Matter_Im_Subscribe_T matter_im_subscribe_new_case(const Matter_Im_Subscribe_Port_T* p,const Matter_Im_Read_Fabric_Port_T* f,
    const Matter_Im_Subscribe_Config_T* c,uint64_t now) {
    if(!c || c->pase_commissionee || !f || !f->index) return NULL;
    Matter_Im_Subscribe_Config_T config=*c; config.pase_commissionee=true;
    Matter_Im_Subscribe_T s=matter_im_subscribe_new(p,&config,now);
    if(s) { s->config=*c; s->fabric=*f; } return s;
}
Matter_Result_T matter_im_subscribe_bind_output_pool(Matter_Im_Subscribe_T s,Matter_Im_Output_Pool* pool) {
    Matter_Result_T r=check(s); if(r) return r;
    if(!pool) return MATTER_INVALID_ARGUMENT;
    if(s->state!=MATTER_IM_SUB_WAITING || s->queued || s->output_pool) return MATTER_INVALID_STATE;
    free(s->output); s->output=NULL; s->output_pool=pool; return MATTER_OK;
}
Matter_Result_T matter_im_subscribe_bind_events(Matter_Im_Subscribe_T s,const Matter_Im_Read_Events_Port_T* p) {
    Matter_Result_T r=check(s); if(r) return r;
    if(!p || !p->log || !p->describe) return MATTER_INVALID_ARGUMENT;
    if(s->state!=MATTER_IM_SUB_WAITING || s->queued || s->event_port.log) return MATTER_INVALID_STATE;
    s->event_port=*p; return MATTER_OK;
}
Matter_Result_T matter_im_subscribe_bind_snapshot_pool(Matter_Im_Subscribe_T s,Matter_Im_Snapshot_Pool* pool) {
    Matter_Result_T r=check(s); if(r) return r;
    if(!pool) return MATTER_INVALID_ARGUMENT;
    if(s->state!=MATTER_IM_SUB_WAITING || s->queued || s->snapshots.pool) return MATTER_INVALID_STATE;
    s->snapshots.pool=pool; return MATTER_OK;
}
Matter_Result_T matter_im_subscribe_bind_event_enumerator(Matter_Im_Subscribe_T s,Matter_Im_Event_Enumerate_T callback) {
    Matter_Result_T r=check(s); if(r) return r;
    if(!callback) return MATTER_INVALID_ARGUMENT;
    if(s->state!=MATTER_IM_SUB_WAITING || s->queued || !s->event_port.log || s->event_enumerate) return MATTER_INVALID_STATE;
    s->event_enumerate=callback; return MATTER_OK;
}
static bool fabric_scope(Matter_Im_Subscribe_T s) {
    if(!s->fabric.index) return true;
    uint8_t index=0;
    if(s->fabric.index(s->port.attributes.user,s->exchange.session,&index)!=MATTER_OK || !index || index==255 ||
        (s->fabric_resolved && index!=s->fabric_index)) return false;
    s->fabric_index=index; s->fabric_resolved=true; return true;
}
Matter_Result_T matter_im_subscribe_receive(Matter_Im_Subscribe_T s,const Matter_Rx_Decision_T* d) {
    Matter_Result_T r=check(s); if(r) return r;
    if(!d || (!d->payload && d->payload_size)) return MATTER_INVALID_ARGUMENT;
    bool initial=s->state==MATTER_IM_SUB_WAITING;
    if(!initial && !((s->phase==PRIME || s->phase==UPDATE) &&
        (s->state==MATTER_IM_SUB_IN_FLIGHT || s->state==MATTER_IM_SUB_WAIT_STATUS) && !s->status_ok)) return MATTER_INVALID_STATE;
    if(s->queued) return MATTER_WOULD_BLOCK;
    if(d->session!=s->exchange.session || d->header.exchange_id!=s->exchange.exchange_id || d->header.vendor_id ||
        d->header.protocol_id!=1 || d->header.opcode!=(initial ? 3 : 1) ||
        (!!(d->header.exchange_flags & MATTER_PROTOCOL_INITIATOR)==s->exchange.initiator) || d->standalone_ack ||
        (d->action!=MATTER_RX_NEW_RESPONDER && d->action!=MATTER_RX_EXISTING)) return MATTER_INVALID_ARGUMENT;
    if(d->payload_size>MATTER_IM_READ_MAX_PAYLOAD) return MATTER_LIMIT_REACHED;
    uint8_t* input=d->payload_size?calloc(1,d->payload_size):NULL;
    if(d->payload_size && !input) return MATTER_LIMIT_REACHED;
    if(d->payload_size) memcpy(input,d->payload,d->payload_size);
    Matter_Im_Subscribe_Work* work=s->work ? s->work : calloc(1,sizeof(*work));
    if(!work) { free(input); return MATTER_LIMIT_REACHED; }
    s->work=work; free(s->input); s->input=input;
    s->input_size=d->payload_size; s->queued=true; return MATTER_OK;
}
static bool container(Matter_Tlv_Type_T t) { return t==MATTER_TLV_ARRAY || t==MATTER_TLV_STRUCTURE || t==MATTER_TLV_LIST; }
static bool next(Matter_Im_Subscribe_T s) { return matter_tlv_next(&s->work->reader,&s->work->token)==MATTER_TLV_OK; }
static bool enter(Matter_Im_Subscribe_T s,const Matter_Tlv_Element_T* e) {
    if(matter_tlv_init(&s->work->reader,s->input,s->input_size,8)!=MATTER_TLV_OK) return false;
    do { if(!next(s)) return false; } while(s->work->token.offset<e->offset);
    return s->work->token.offset==e->offset;
}
static bool collect(Matter_Im_Subscribe_T s,Matter_Tlv_Element_T* out,size_t count) {
    memset(out,0,count*sizeof(*out));
    while(next(s)) {
        if(s->work->token.type==MATTER_TLV_END) return true;
        if(s->work->token.tag.control!=1) return false;
        uint32_t tag=s->work->token.tag.number;
        if(tag<count) { if(out[tag].tag.control) return false; out[tag]=s->work->token; }
        if(out==s->work->root && tag==255) s->work->revision=s->work->token;
        if(container(s->work->token.type) && matter_tlv_skip_container(&s->work->reader)!=MATTER_TLV_OK) return false;
    }
    return false;
}
static bool number(const Matter_Tlv_Element_T* e,uint64_t max) { return e->tag.control==1 && e->type==MATTER_TLV_UNSIGNED && e->unsigned_value<=max; }
static bool boolean(const Matter_Tlv_Element_T* e) { return e->tag.control==1 && e->type==MATTER_TLV_BOOL; }
static uint8_t decode_filters(Matter_Im_Subscribe_T s) {
    if(!s->work->root[8].tag.control) return 0;
    /* Count fully validated entries before allocating the exact per-request
     * table. Keep it only through priming, never for the subscription lifetime. */
    for(unsigned pass=0;pass<2;++pass) {
        s->filter_count=0;
        if(s->work->root[8].type!=MATTER_TLV_ARRAY || !enter(s,&s->work->root[8])) return MATTER_IM_INVALID_ACTION;
        while(next(s) && s->work->token.type!=MATTER_TLV_END) {
            if(s->filter_count==MATTER_IM_READ_MAX_FILTERS) return MATTER_IM_RESOURCE_EXHAUSTED;
            Matter_Tlv_Element_T element=s->work->token;
            if(element.type!=MATTER_TLV_STRUCTURE || element.tag.control || !collect(s,s->work->fields,8) ||
                !number(&s->work->fields[1],UINT32_MAX) || s->work->fields[0].tag.control!=1 || s->work->fields[0].type!=MATTER_TLV_LIST) return MATTER_IM_INVALID_ACTION;
            uint32_t version=(uint32_t)s->work->fields[1].unsigned_value;
            if(!enter(s,&s->work->fields[0]) || !collect(s,s->work->fields,8) || s->work->fields[0].tag.control ||
                !number(&s->work->fields[1],UINT16_MAX) || !number(&s->work->fields[2],UINT32_MAX)) return MATTER_IM_INVALID_ACTION;
            if(pass) {
                s->filters[s->filter_count].endpoint=(uint16_t)s->work->fields[1].unsigned_value;
                s->filters[s->filter_count].cluster=(uint32_t)s->work->fields[2].unsigned_value;
                s->filters[s->filter_count].version=version;
            }
            ++s->filter_count;
            if(!enter(s,&element) || matter_tlv_skip_container(&s->work->reader)!=MATTER_TLV_OK) return MATTER_IM_INVALID_ACTION;
        }
        if(!pass) {
            if(!s->filter_count) return 0;
            s->filters=calloc(s->filter_count,sizeof(*s->filters));
            if(!s->filters) { s->filter_count=0; return MATTER_IM_RESOURCE_EXHAUSTED; }
        }
    }
    return 0;
}
static uint8_t decode(Matter_Im_Subscribe_T s) {
    /* Include dense DataVersionFilters; at most one TLV token per input byte. */
    const Matter_Tlv_Validation_Options_T opt={MATTER_IM_READ_MAX_PAYLOAD,MATTER_IM_READ_MAX_PAYLOAD,2048,8,false,0,0};
    Matter_Tlv_Validation_Report_T report;
    Matter_Tlv_Result_T r=matter_tlv_validate(s->input,s->input_size,&opt,&s->work->validation,s->work->tags,48,&report);
    if(r!=MATTER_TLV_OK) return r==MATTER_TLV_LIMIT_REACHED || r==MATTER_TLV_DEPTH_LIMIT ? MATTER_IM_RESOURCE_EXHAUSTED : MATTER_IM_INVALID_ACTION;
    memset(&s->work->revision,0,sizeof(s->work->revision));
    if(matter_tlv_init(&s->work->reader,s->input,s->input_size,8)!=MATTER_TLV_OK || !next(s) || s->work->token.type!=MATTER_TLV_STRUCTURE ||
        s->work->token.tag.control || !collect(s,s->work->root,9) || !number(&s->work->revision,255) || !s->work->revision.unsigned_value) return MATTER_IM_INVALID_ACTION;
    if(s->state!=MATTER_IM_SUB_WAITING) return number(&s->work->root[0],255) ? (uint8_t)s->work->root[0].unsigned_value : MATTER_IM_INVALID_ACTION;
    if(!boolean(&s->work->root[0]) || !number(&s->work->root[1],UINT16_MAX) || !number(&s->work->root[2],UINT16_MAX) ||
        s->work->root[1].unsigned_value>s->work->root[2].unsigned_value || !boolean(&s->work->root[7])) return MATTER_IM_INVALID_ACTION;
    s->minimum=(uint16_t)s->work->root[1].unsigned_value; s->maximum=(uint16_t)s->work->root[2].unsigned_value;
    if(!s->maximum) s->maximum=1;
    s->filtered=s->work->root[7].unsigned_value!=0;
    if(s->work->root[3].tag.control) {
        for(unsigned pass=0;pass<2;++pass) {
            s->request_count=0;
        if(s->work->root[3].type!=MATTER_TLV_ARRAY || !enter(s,&s->work->root[3])) return MATTER_IM_INVALID_ACTION;
        while(next(s) && s->work->token.type!=MATTER_TLV_END) {
            if(s->request_count==MATTER_IM_SUB_MAX_ATTRIBUTE_PATHS) return MATTER_IM_PATHS_EXHAUSTED;
            if(s->work->token.type!=MATTER_TLV_LIST || s->work->token.tag.control || !collect(s,s->work->fields,8)) return MATTER_IM_INVALID_ACTION;
    if((s->work->fields[0].tag.control && (!boolean(&s->work->fields[0]) || s->work->fields[0].unsigned_value)) ||
        s->work->fields[1].tag.control || s->work->fields[5].tag.control ||
        (s->work->fields[6].tag.control && (!number(&s->work->fields[6],UINT32_MAX) || s->work->fields[6].unsigned_value)) ||
        (s->work->fields[7].tag.control && !number(&s->work->fields[7],UINT32_MAX))) return MATTER_IM_INVALID_ACTION;
            Matter_Im_Selector_T parsed={0}; Matter_Im_Selector_T* q=&parsed;
            ++s->request_count;
            for(unsigned i=2;i<=4;++i) if(s->work->fields[i].tag.control) {
                if(!number(&s->work->fields[i],i==2?UINT16_MAX:UINT32_MAX)) return MATTER_IM_INVALID_ACTION;
                q->present|=(uint8_t)(1u<<(i-2));
            }
            q->path=(Matter_Im_Path_T){(uint16_t)s->work->fields[2].unsigned_value,(uint32_t)s->work->fields[3].unsigned_value,(uint32_t)s->work->fields[4].unsigned_value};
            if(!matter_im_read_path_valid(q)) return MATTER_IM_INVALID_ACTION;
            if(pass) s->requests[s->request_count-1]=parsed;
            if(q->present!=MATTER_IM_CONCRETE) { if(!s->port.attributes.enumerate) return MATTER_IM_INVALID_ACTION; s->expanding=true; }
        }
            if(!pass) {
                if(!s->request_count) break;
                s->requests=calloc(s->request_count,sizeof(*s->requests));
                if(!s->requests) return MATTER_IM_RESOURCE_EXHAUSTED;
            }
        }
    }
    if(s->work->root[4].tag.control) {
        if(s->work->root[4].type!=MATTER_TLV_ARRAY || !enter(s,&s->work->root[4])) return MATTER_IM_INVALID_ACTION;
        while(next(s) && s->work->token.type!=MATTER_TLV_END) {
            if(s->request_count+(s->events?s->events->raw_count:0)>=MATTER_IM_READ_MAX_PATHS) return MATTER_IM_PATHS_EXHAUSTED;
            if(!s->event_port.log || s->work->token.type!=MATTER_TLV_LIST || s->work->token.tag.control || !collect(s,s->work->fields,8)) return MATTER_IM_INVALID_ACTION;
            if(!s->events) {
                s->events=calloc(1,sizeof(*s->events)); if(!s->events) return MATTER_IM_RESOURCE_EXHAUSTED;
                s->events->port=s->event_port; s->events->expansion.enumerate=s->event_enumerate;
            }
            if(s->work->fields[0].tag.control || (s->work->fields[4].tag.control && !boolean(&s->work->fields[4]))) return MATTER_IM_INVALID_ACTION;
            Matter_Im_Event_Selector_T q={0};
            for(unsigned i=1;i<=3;++i) if(s->work->fields[i].tag.control) {
                if(!number(&s->work->fields[i],i==1?UINT16_MAX:UINT32_MAX)) return MATTER_IM_INVALID_ACTION;
                q.present|=(uint8_t)(1u<<(i-1));
            }
            if((q.present&MATTER_IM_EVENT) && !(q.present&MATTER_IM_CLUSTER)) return MATTER_IM_INVALID_ACTION;
            SubEvents* e=s->events;
            q.path=(Matter_Event_Path_T){(uint16_t)s->work->fields[1].unsigned_value,(uint32_t)s->work->fields[2].unsigned_value,(uint32_t)s->work->fields[3].unsigned_value};
            uint8_t code=matter_im_event_selector_add(&e->expansion,&e->paths,&e->path_count,&q,s->work->fields[4].unsigned_value!=0);
            if(code) return code;
            ++e->raw_count;
            e->urgent|=s->work->fields[4].unsigned_value!=0; e->requested=true;
        }
    }
    if(s->work->root[5].tag.control) {
        if(!s->events || !s->events->requested || s->work->root[5].type!=MATTER_TLV_ARRAY || !enter(s,&s->work->root[5]) || !next(s)) return MATTER_IM_INVALID_ACTION;
        if(s->work->token.type!=MATTER_TLV_END) {
            if(s->work->token.type!=MATTER_TLV_STRUCTURE || s->work->token.tag.control || !collect(s,s->work->fields,8) ||
                s->work->fields[0].tag.control || !number(&s->work->fields[1],UINT64_MAX) || !next(s) || s->work->token.type!=MATTER_TLV_END) return MATTER_IM_INVALID_ACTION;
            s->events->initial_min=s->work->fields[1].unsigned_value;
        }
    }
    if(!s->request_count && !(s->events && s->events->requested)) return MATTER_IM_INVALID_ACTION;
    return decode_filters(s);
}
static bool put(Matter_Im_Subscribe_T s,Matter_Tlv_Type_T type,int tag,uint64_t value) {
    s->work->token=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0 ? 0 : 1,.number=tag<0 ? 0 : (uint32_t)tag},
        .unsigned_value=value,.signed_value=s->value.signed_value};
    return matter_tlv_write(&s->work->writer,&s->work->token,0)==MATTER_TLV_OK;
}
static bool end(Matter_Im_Subscribe_T s) { return put(s,MATTER_TLV_END,-1,0); }
static bool begin(Matter_Im_Subscribe_T s) {
    size_t cap=s->config.output_capacity;
    return matter_tlv_writer_init(&s->work->writer,s->output,cap,8)==MATTER_TLV_OK && put(s,MATTER_TLV_STRUCTURE,-1,0);
}
static bool finish(Matter_Im_Subscribe_T s) {
    return put(s,MATTER_TLV_UNSIGNED,255,MATTER_IM_REVISION) && end(s) && matter_tlv_writer_finish(&s->work->writer,&s->output_size)==MATTER_TLV_OK;
}
static bool status(Matter_Im_Subscribe_T s,uint8_t code) {
    clear_filters(s);
    s->phase=ERROR_REPLY; s->opcode=1;
    return begin(s) && put(s,MATTER_TLV_UNSIGNED,0,code) && finish(s);
}
static bool complex_value(Matter_Tlv_Type_T type) {
    return matter_im_snapshot_complex(type);
}
static uint8_t copy_value(Matter_Im_Subscribe_T s) {
    size_t size=s->value.size;
    if(size>MATTER_IM_READ_MAX_VALUE || size>MATTER_IM_READ_SNAPSHOT_BYTES-s->snapshots.size) return MATTER_IM_RESOURCE_EXHAUSTED;
    if((!s->value.data && size) || (container(s->value.type) && (!s->value.data || size<2))) return MATTER_IM_FAILURE;
    return matter_im_snapshot_copy(&s->snapshots,&s->value,&s->work->writer,&s->work->value_reader,&s->work->element,
        &s->work->validation,s->work->tags,48,s->work->short_snapshot);
}
static bool filtered_version(Matter_Im_Subscribe_T s,uint32_t version) {
    bool match=false;
    for(size_t i=0;i<s->filter_count;++i) if(s->filters[i].endpoint==s->path.endpoint && s->filters[i].cluster==s->path.cluster) {
        if(s->filters[i].version!=version) return false;
        match=true;
    }
    return match;
}
static bool path_error(uint8_t code) {
    return code==MATTER_IM_UNSUPPORTED_ACCESS || code==MATTER_IM_ACCESS_RESTRICTED || code==MATTER_IM_UNSUPPORTED_ENDPOINT ||
        code==MATTER_IM_UNSUPPORTED_CLUSTER || code==MATTER_IM_UNSUPPORTED_ATTRIBUTE || code==MATTER_IM_UNSUPPORTED_READ;
}
static uint8_t snapshot(Matter_Im_Subscribe_T s,bool read,bool wildcard,bool* omit) {
    *omit=false;
    if(!fabric_scope(s)) return MATTER_IM_UNSUPPORTED_ACCESS;
    Matter_Im_Read_Port_T* p=&s->port.attributes;
    Matter_Im_Status_T code=0;
    if(!wildcard) {
        code=p->authorize(p->user,s->exchange.session,&s->path,MATTER_IM_VIEW);
        if(code) return code==MATTER_IM_UNSUPPORTED_ACCESS || code==MATTER_IM_ACCESS_RESTRICTED ? code : MATTER_IM_FAILURE;
    }
    code=p->describe(p->user,&s->path,&s->attribute);
    if(code) return code==MATTER_IM_UNSUPPORTED_ENDPOINT || code==MATTER_IM_UNSUPPORTED_CLUSTER || code==MATTER_IM_UNSUPPORTED_ATTRIBUTE || code==MATTER_IM_UNSUPPORTED_READ ? code : MATTER_IM_FAILURE;
    if(s->attribute.privilege!=MATTER_IM_VIEW && s->attribute.privilege!=MATTER_IM_OPERATE && s->attribute.privilege!=MATTER_IM_MANAGE && s->attribute.privilege!=MATTER_IM_ADMINISTER) return MATTER_IM_FAILURE;
    code=p->authorize(p->user,s->exchange.session,&s->path,s->attribute.privilege);
    if(code) return code==MATTER_IM_UNSUPPORTED_ACCESS || code==MATTER_IM_ACCESS_RESTRICTED ? code : MATTER_IM_FAILURE;
    if(s->attribute.fabric_scoped && !s->fabric_index) return MATTER_IM_UNSUPPORTED_ACCESS;
    if(!read) return 0;
    if(s->phase==PRIME && p->version) {
        bool has_filter=false;
        for(size_t i=0;i<s->filter_count;++i) if(s->filters[i].endpoint==s->path.endpoint && s->filters[i].cluster==s->path.cluster) has_filter=true;
        if(has_filter) {
            uint32_t version=0;
            if(p->version(p->user,&s->path,&version)!=MATTER_OK) return MATTER_IM_FAILURE;
            if(filtered_version(s,version)) { *omit=true; return 0; }
        }
    }
    memset(&s->value,0,sizeof(s->value)); s->value.type=MATTER_TLV_END;
    if(p->read(p->user,&s->path,s->filtered,&s->value)!=MATTER_IM_SUCCESS) return MATTER_IM_FAILURE;
    if(s->value.type!=MATTER_TLV_SIGNED && s->value.type!=MATTER_TLV_UNSIGNED && s->value.type!=MATTER_TLV_BOOL &&
        s->value.type!=MATTER_TLV_NULL && !complex_value(s->value.type)) return MATTER_IM_FAILURE;
    if(s->value.type==MATTER_TLV_BOOL && s->value.unsigned_value>1) return MATTER_IM_FAILURE;
    if(s->phase==PRIME && filtered_version(s,s->value.data_version)) { *omit=true; return 0; }
    if(complex_value(s->value.type)) return copy_value(s);
    return 0;
}
static uint8_t event_access(Matter_Im_Subscribe_T s,bool wildcard) {
    SubEvents* e=s->events; Matter_Im_Read_Port_T* p=&s->port.attributes;
    if(!fabric_scope(s)) return MATTER_IM_UNSUPPORTED_ACCESS;
    s->path=(Matter_Im_Path_T){e->path.endpoint,e->path.cluster,e->path.event};
    Matter_Im_Status_T code=0;
    if(!wildcard) {
        code=p->authorize(p->user,s->exchange.session,&s->path,MATTER_IM_VIEW);
        if(code) return code==MATTER_IM_UNSUPPORTED_ACCESS || code==MATTER_IM_ACCESS_RESTRICTED?(uint8_t)code:MATTER_IM_FAILURE;
    }
    code=e->port.describe(e->port.user,&e->path,&s->attribute);
    if(code) return code==MATTER_IM_UNSUPPORTED_ENDPOINT || code==MATTER_IM_UNSUPPORTED_CLUSTER || code==MATTER_IM_UNSUPPORTED_EVENT?(uint8_t)code:MATTER_IM_FAILURE;
    if(s->attribute.fabric_scoped && !s->fabric_index) return MATTER_IM_UNSUPPORTED_ACCESS;
    Matter_Im_Privilege_T v=s->attribute.privilege;
    if(v!=MATTER_IM_VIEW && v!=MATTER_IM_OPERATE && v!=MATTER_IM_MANAGE && v!=MATTER_IM_ADMINISTER) return MATTER_IM_FAILURE;
    code=p->authorize(p->user,s->exchange.session,&s->path,v);
    return code==MATTER_IM_SUCCESS || code==MATTER_IM_UNSUPPORTED_ACCESS || code==MATTER_IM_ACCESS_RESTRICTED?(uint8_t)code:MATTER_IM_FAILURE;
}
static int compare_path(const Matter_Im_Path_T* a,const Matter_Im_Path_T* b) {
    if(a->endpoint!=b->endpoint) return a->endpoint<b->endpoint?-1:1;
    if(a->cluster!=b->cluster) return a->cluster<b->cluster?-1:1;
    return a->attribute==b->attribute?0:a->attribute<b->attribute?-1:1;
}
static bool reserve_items(Matter_Im_Subscribe_T s,size_t needed) {
    return sub_items_reserve(&s->items,needed,MATTER_IM_READ_MAX_RESULTS);
}
static uint8_t expand(Matter_Im_Subscribe_T s) {
    for(unsigned step=0;step<MATTER_IM_READ_WORK_BATCH && s->request_cursor<s->request_count;++step) {
        const Matter_Im_Selector_T* q=&s->requests[s->request_cursor];
        bool wildcard=q->present!=MATTER_IM_CONCRETE,found=false;
        if(wildcard) {
            if(s->port.attributes.enumerate(s->port.attributes.user,q,s->after_valid?&s->after:NULL,&s->path,&found)!=MATTER_OK) return MATTER_IM_FAILURE;
            if(!found) { ++s->request_cursor; s->after_valid=false; continue; }
            if(((q->present & MATTER_IM_ENDPOINT) && q->path.endpoint!=s->path.endpoint) ||
                ((q->present & MATTER_IM_CLUSTER) && q->path.cluster!=s->path.cluster) ||
                ((q->present & MATTER_IM_ATTRIBUTE) && q->path.attribute!=s->path.attribute) ||
                (s->after_valid && compare_path(&s->path,&s->after)<=0)) return MATTER_IM_FAILURE;
            s->after=s->path; s->after_valid=true;
        } else { s->path=q->path; ++s->request_cursor; }
        if(!reserve_items(s,s->count+1)) return MATTER_IM_RESOURCE_EXHAUSTED;
        SubItem* result=sub_items_at(&s->items,s->count++);
        sub_item_set_path(result,&s->path); result->wildcard=wildcard;
    }
    if(s->request_cursor==s->request_count) s->state=MATTER_IM_SUB_COLLECTING;
    return 0;
}
/* Only after whole-report IM success and MRP confirmation, on a skipped
 * report with no TX, or before a new capture in the drained idle state. */
static void clear_snapshots(Matter_Im_Subscribe_T s) {
    matter_im_snapshots_clear(&s->snapshots);
    s->value.data=NULL; s->value.size=0;
    matter_im_blocks_clear(&s->values); s->released=0;
}
static void release_consumed(Matter_Im_Subscribe_T s) {
    /* cursor advances past whole attributes only; a partial ARRAY stays live. */
    while(s->released<s->cursor) {
        size_t i=s->released++;
        if(s->values.head) {
            matter_im_snapshot_release_value(&s->snapshots,sub_values_at(&s->values,i));
        }
    }
    s->value.data=NULL; s->value.size=0;
    if(s->events) matter_events_snapshot_release_before(&s->events->records,s->events->cursor);
}
static void capture_begin(Matter_Im_Subscribe_T s,bool data) {
    clear_snapshots(s);
    s->cursor=0; s->list_offset=0; s->report_started=false; s->terminal_report=false;
    s->collected=s->valid=0; s->attribute_report=false; s->capture_data=data;
    if(s->events) { s->events->access_cursor=s->events->filter_count=0; s->events->collected=false; }
    s->state=MATTER_IM_SUB_COLLECTING;
}
static uint8_t capture(Matter_Im_Subscribe_T s) {
    bool prime=s->phase==PRIME;
    if(s->capture_data && s->count && !s->values.head) {
        if(!sub_values_reserve(&s->values,s->count,MATTER_IM_READ_MAX_RESULTS)) return MATTER_IM_RESOURCE_EXHAUSTED;
    }
    unsigned budget=s->expanding?MATTER_IM_READ_WORK_BATCH:MATTER_IM_READ_MAX_PATHS;
    while(budget-- && s->collected<s->count) {
        size_t i=s->collected++; bool omit=false;
        SubItem* result=sub_items_at(&s->items,i);
        result->included=false;
        if(!prime && !result->active) continue;
        s->path=sub_item_path(result);
        uint8_t code=snapshot(s,s->capture_data,prime && result->wildcard,&omit);
        if(code==MATTER_IM_RESOURCE_EXHAUSTED) return code;
        if(prime && result->wildcard && path_error(code)) omit=true;
        if(!prime && !code && s->capture_data && s->value.report_on_version_change &&
            result->reported && result->reported_version==s->value.data_version) omit=true;
        result->status=code;
        if(s->values.head) *sub_values_at(&s->values,i)=code || omit ? (Matter_Im_Snapshot_Value){0} : matter_im_snapshot_store(&s->value);
        if(prime) result->active=code==0;
        else if(code) s->terminal_report=true;
        if(!code) ++s->valid;
        result->included=!omit && (s->capture_data || code); s->attribute_report|=result->included;
        if(!code && result->included) { result->reported=true; result->reported_version=s->value.data_version; }
    }
    if(s->collected<s->count) return 0;
    SubEvents* e=s->events;
    if(e && e->requested && (prime || e->active)) {
        if(e->expansion.wildcard && e->expansion.cursor<e->raw_count) {
            uint8_t code=matter_im_event_expand(&e->expansion,e->port.user,e->raw_count,&e->paths,&e->path_count);
            if(code || e->expansion.cursor<e->raw_count) return code;
        }
        matter_im_event_selectors_clear(&e->expansion); e->expansion.cursor=e->raw_count;
        if(!matter_im_event_filters_reserve(&e->filters,e->path_count)) return MATTER_IM_RESOURCE_EXHAUSTED;
        unsigned event_budget=e->expansion.wildcard?MATTER_IM_READ_WORK_BATCH:MATTER_IM_READ_MAX_PATHS;
        while(event_budget-- && e->access_cursor<e->path_count) {
            Matter_Im_Event_Request_T* q=matter_im_event_paths_at(&e->paths,e->access_cursor++);
            q->reported=!prime && !q->active;
            if(!prime && !q->active) continue;
            e->path=q->path; q->status=event_access(s,q->wildcard); q->access=s->attribute;
            q->omit=matter_im_event_omitted(q->wildcard,q->status);
            if(!prime && q->omit) q->active=false;
            if(!q->status) e->filters[e->filter_count++]=(Matter_Event_Filter_T){q->path,q->access.fabric_scoped};
        }
        if(e->access_cursor<e->path_count) return 0;
        e->count=e->cursor=0; e->dirty=false;
        Matter_Result_T r=matter_im_event_snapshot(e->port.log,e->filters,e->filter_count,prime?e->initial_min:e->next,s->fabric_index,&e->records,&e->count);
        if(r==MATTER_LIMIT_REACHED) return MATTER_IM_RESOURCE_EXHAUSTED;
        if(r!=MATTER_OK || matter_events_position(e->port.log,&e->pending_next)!=MATTER_OK)
            for(size_t i=0;i<e->path_count;++i) if(!matter_im_event_paths_at(&e->paths,i)->status) matter_im_event_paths_at(&e->paths,i)->status=MATTER_IM_FAILURE;
        e->active=false;
        for(size_t i=0;i<e->path_count;++i) {
            Matter_Im_Event_Request_T* q=matter_im_event_paths_at(&e->paths,i);
            if(prime) q->active=!q->status;
            else if(q->active && q->status) s->terminal_report=true;
            e->active|=q->active;
            if(q->active && !q->status) ++s->valid;
        }
        e->report=matter_im_event_more(&e->paths,e->path_count,&e->records,0,e->count) || !s->attribute_report;
    } else if(e) e->report=false;
    if(e) e->collected=true;
    if(!prime && !s->valid) s->terminal_report=true;
    return prime && !s->valid?MATTER_IM_INVALID_ACTION:0;
}
static bool write_value(Matter_Im_Subscribe_T s,size_t part) {
    if(!complex_value(s->value.type)) return put(s,s->value.type,2,s->value.unsigned_value);
    size_t start=s->work->plan[part].start,stop=s->work->plan[part].end;
    bool prefix=s->work->plan[part].prefix;
    if(matter_tlv_init(&s->work->value_reader,s->value.data,s->value.size,4)!=MATTER_TLV_OK) return false;
    if(prefix && !put(s,MATTER_TLV_ARRAY,2,0)) return false;
    Matter_Tlv_Result_T r;
    while((r=matter_tlv_next(&s->work->value_reader,&s->work->element))==MATTER_TLV_OK) {
        if(stop && s->work->element.offset>=stop) break;
        if(s->work->element.offset<start) continue;
        if(!prefix && s->work->element.offset==start) s->work->element.tag=(Matter_Tlv_Tag_T){.control=1,.number=2};
        if(matter_tlv_write(&s->work->writer,&s->work->element,0)!=MATTER_TLV_OK) return false;
    }
    return (r==MATTER_TLV_DONE || (stop && r==MATTER_TLV_OK)) && (!prefix || end(s));
}
static bool report_attributes(Matter_Im_Subscribe_T s,size_t stop,bool more) {
    if(!begin(s) || !put(s,MATTER_TLV_UNSIGNED,0,s->id) || !put(s,MATTER_TLV_ARRAY,1,0)) return false;
    for(size_t part=0;part<stop;++part) {
        size_t i=s->work->plan[part].item;
        SubItem* result=sub_items_at(&s->items,i); s->path=sub_item_path(result);
        if(s->values.head) matter_im_snapshot_load(&s->value,sub_values_at(&s->values,i)); else memset(&s->value,0,sizeof(s->value));
        uint8_t code=result->status;
        if(!put(s,MATTER_TLV_STRUCTURE,-1,0) || !put(s,MATTER_TLV_STRUCTURE,code ? 0 : 1,0) ||
            (!code && !put(s,MATTER_TLV_UNSIGNED,0,s->value.data_version)) || !put(s,MATTER_TLV_LIST,code ? 0 : 1,0) ||
            !put(s,MATTER_TLV_UNSIGNED,2,s->path.endpoint) || !put(s,MATTER_TLV_UNSIGNED,3,s->path.cluster) ||
            !put(s,MATTER_TLV_UNSIGNED,4,s->path.attribute) ||
            (!code && s->work->plan[part].start && !s->work->plan[part].prefix && !put(s,MATTER_TLV_NULL,5,0)) || !end(s)) return false;
        if(code) { if(!put(s,MATTER_TLV_STRUCTURE,1,0) || !put(s,MATTER_TLV_UNSIGNED,0,code) || !end(s)) return false; }
        else if(!write_value(s,part)) return false;
        if(!end(s) || !end(s)) return false;
    }
    return end(s) && (!more || put(s,MATTER_TLV_BOOL,3,1)) && put(s,MATTER_TLV_BOOL,4,0) && finish(s);
}
static void recheck_events(Matter_Im_Subscribe_T s) {
    SubEvents* e=s->events; if(!e || !e->requested) return;
    for(size_t i=0;i<e->path_count;++i) if(!matter_im_event_paths_at(&e->paths,i)->status) {
        Matter_Im_Event_Request_T* q=matter_im_event_paths_at(&e->paths,i); e->path=q->path;
        uint8_t code=event_access(s,q->wildcard);
        if(code) {
            q->status=code; q->omit=matter_im_event_omitted(q->wildcard,code);
            if(q->omit) q->active=false;
            else if(q->active) s->terminal_report=true;
        }
    }
    e->active=false;
    for(size_t i=0;i<e->path_count;++i) e->active|=matter_im_event_paths_at(&e->paths,i)->active;
    if(!e->active) {
        bool active=false;
        for(size_t i=0;i<s->count;++i) active|=sub_items_at(&s->items,i)->active;
        if(!active) s->terminal_report=true;
    }
}
static bool report_event(Matter_Im_Subscribe_T s) {
    SubEvents* e=s->events;
    const Matter_Event_Record_T* record;
    size_t selected=matter_im_event_take(&e->paths,e->path_count,&e->records,&e->cursor,e->count,&record);
    e->status=selected<e->path_count?matter_im_event_paths_at(&e->paths,selected)->status:0;
    if(selected<e->path_count) e->path=matter_im_event_paths_at(&e->paths,selected)->path;
    bool more=matter_im_event_more(&e->paths,e->path_count,&e->records,e->cursor,e->count);
    if(!begin(s) || !put(s,MATTER_TLV_UNSIGNED,0,s->id) || !put(s,MATTER_TLV_ARRAY,2,0)) return false;
    if(selected<e->path_count) {
        if(!put(s,MATTER_TLV_STRUCTURE,-1,0) || !put(s,MATTER_TLV_STRUCTURE,e->status?0:1,0) ||
            !put(s,MATTER_TLV_LIST,0,0) || !put(s,MATTER_TLV_UNSIGNED,1,e->path.endpoint) ||
            !put(s,MATTER_TLV_UNSIGNED,2,e->path.cluster) || !put(s,MATTER_TLV_UNSIGNED,3,e->path.event) || !end(s)) return false;
        if(e->status) {
            if(!put(s,MATTER_TLV_STRUCTURE,1,0) || !put(s,MATTER_TLV_UNSIGNED,0,e->status) || !end(s)) return false;
        } else {
            const Matter_Event_Record_T* r=record;
            if(!put(s,MATTER_TLV_UNSIGNED,1,r->number) || !put(s,MATTER_TLV_UNSIGNED,2,r->priority) ||
                !put(s,MATTER_TLV_UNSIGNED,r->epoch?3:4,r->timestamp_ms) || matter_tlv_init(&s->work->value_reader,r->data,r->size,4)!=MATTER_TLV_OK) return false;
            Matter_Tlv_Result_T result;
            while((result=matter_tlv_next(&s->work->value_reader,&s->work->element))==MATTER_TLV_OK) {
                if(!s->work->element.offset) s->work->element.tag=(Matter_Tlv_Tag_T){.control=1,.number=7};
                if(matter_tlv_write(&s->work->writer,&s->work->element,0)!=MATTER_TLV_OK) return false;
            }
            if(result!=MATTER_TLV_DONE) return false;
        }
        if(!end(s) || !end(s)) return false;
    }
    if(!end(s) || (more && !put(s,MATTER_TLV_BOOL,3,1)) || !put(s,MATTER_TLV_BOOL,4,0) || !finish(s)) return false;
    e->report=more; s->more=more; return true;
}
/* Walk validated direct ARRAY children, as in Read. Never split an element or
 * invoke a provider while trying candidate encodings. */
static size_t list_next(Matter_Im_Subscribe_T s,size_t item,size_t offset) {
    const Matter_Im_Snapshot_Value* v=sub_values_at(&s->values,item);
    if(matter_tlv_init(&s->work->value_reader,matter_im_snapshot_data(v),matter_im_snapshot_size(v),4)!=MATTER_TLV_OK ||
        matter_tlv_next(&s->work->value_reader,&s->work->element)!=MATTER_TLV_OK) return 0;
    while(matter_tlv_next(&s->work->value_reader,&s->work->element)==MATTER_TLV_OK && s->work->element.type!=MATTER_TLV_END) {
        size_t current=s->work->element.offset;
        if(container(s->work->element.type) && matter_tlv_skip_container(&s->work->value_reader)!=MATTER_TLV_OK) return 0;
        if(current==offset) return matter_tlv_next(&s->work->value_reader,&s->work->element)==MATTER_TLV_OK?s->work->element.offset:0;
    }
    return 0;
}
static bool chunk(Matter_Im_Subscribe_T s,bool recheck) {
    s->opcode=5;
    /* Permissions may change between chunks; never read providers again here. */
    if(recheck) for(size_t i=s->cursor;i<s->count;++i) if(sub_items_at(&s->items,i)->active && sub_items_at(&s->items,i)->included) {
        s->path=sub_item_path(sub_items_at(&s->items,i)); bool omit=false; uint8_t code=snapshot(s,false,s->phase==PRIME && sub_items_at(&s->items,i)->wildcard,&omit);
        if(code) {
            sub_items_at(&s->items,i)->status=code;
            if(s->phase==PRIME && sub_items_at(&s->items,i)->wildcard && path_error(code)) { sub_items_at(&s->items,i)->included=false; sub_items_at(&s->items,i)->active=false; }
            else s->terminal_report=true;
        }
    }
    if(recheck && s->events && s->events->report) recheck_events(s);
    if(s->phase==PRIME) {
        bool active=s->events && s->events->active;
        for(size_t i=0;i<s->count;++i) active|=sub_items_at(&s->items,i)->active;
        if(!active) return status(s,MATTER_IM_INVALID_ACTION);
    }
    while(s->cursor<s->count && !sub_items_at(&s->items,s->cursor)->included) { ++s->cursor; s->list_offset=0; }
    if(s->cursor<s->count && sub_items_at(&s->items,s->cursor)->status) s->list_offset=0;
    bool events=s->events && s->events->report;
    if(s->cursor==s->count && events) return report_event(s);
    size_t n=0,item=s->cursor,offset=s->list_offset;
    while(item<s->count && n<MATTER_IM_READ_MAX_PATHS) {
        if(!sub_items_at(&s->items,item)->included) { ++item; continue; }
        s->work->plan[n].item=item; s->work->plan[n].start=offset; s->work->plan[n].prefix=false;
        size_t stop=offset?list_next(s,item,offset):0;
        if(offset && !stop) return false;
        s->work->plan[n].end=stop;
        bool last=!offset || stop==matter_im_snapshot_size(sub_values_at(&s->values,item))-1;
        size_t next_item=item+1;
        while(next_item<s->count && !sub_items_at(&s->items,next_item)->included) ++next_item;
        if(report_attributes(s,n+1,!last || next_item<s->count || events)) {
            ++n; offset=last?0:stop; if(last) item=next_item; continue;
        }
        if(n) break; /* First try the whole attribute on an empty report. */
        if(offset || sub_items_at(&s->items,item)->status || !s->values.head || sub_values_at(&s->values,item)->type!=MATTER_TLV_ARRAY) return false;
        s->work->plan[n].prefix=true; s->work->plan[n].start=1; s->work->plan[n].end=1;
        if(!report_attributes(s,1,true)) return false;
        stop=1;
        while(stop<matter_im_snapshot_size(sub_values_at(&s->values,item))-1) {
            size_t candidate=list_next(s,item,stop);
            if(!candidate) return false;
            s->work->plan[n].end=candidate;
            if(!report_attributes(s,1,true)) break;
            stop=candidate;
        }
        s->work->plan[n].end=stop; offset=stop; ++n; break;
    }
    s->more=item<s->count || events;
    if(!report_attributes(s,n,s->more)) return false;
    s->cursor=item; s->list_offset=offset; return true;
}
static bool pending_change(Matter_Im_Subscribe_T s) {
    if(s->dirty) return true;
    SubEvents* e=s->events;
    if(!e || !e->active || !e->urgent || !e->dirty) return false;
    size_t filters=0,count=0;
    for(size_t i=0;i<e->path_count;++i) if(matter_im_event_paths_at(&e->paths,i)->active && matter_im_event_paths_at(&e->paths,i)->urgent)
        e->filters[filters++]=(Matter_Event_Filter_T){matter_im_event_paths_at(&e->paths,i)->path,matter_im_event_paths_at(&e->paths,i)->access.fabric_scoped};
    /* No payload copy or callbacks; a non-urgent/unselected event cannot wake
     * an otherwise clean subscription merely because another path is urgent. */
    return matter_events_copy_selected(e->port.log,e->filters,filters,e->next,s->fabric_index,NULL,&count)!=MATTER_OK || count!=0;
}
Matter_Result_T matter_im_subscribe_process(Matter_Im_Subscribe_T s,uint64_t now) {
    Matter_Result_T r=check(s); if(r) return r;
    r=clock_check(s,now); if(r) return r;
    if(s->output_copied || !matter_im_output_acquire(s->output_pool,s,&s->output)) return MATTER_PENDING;
        if((s->queued || s->state==MATTER_IM_SUB_EXPANDING || s->state==MATTER_IM_SUB_COLLECTING || s->state==MATTER_IM_SUB_BUILD_REPORT || (s->state==MATTER_IM_SUB_WAIT_STATUS && s->status_ok)) && !s->work) {
        s->work=calloc(1,sizeof(*s->work));
        if(!s->work) { s->now=now; clear_filters(s); matter_im_status_bytes(s->output,MATTER_IM_RESOURCE_EXHAUSTED,MATTER_IM_REVISION); s->output_size=8; s->opcode=1; s->phase=ERROR_REPLY; s->queued=false; s->state=MATTER_IM_SUB_OUTPUT; return MATTER_PENDING; }
    }
    s->busy=true; bool encoded=true;
    if(s->queued) {
        s->queued=false; uint8_t code=decode(s);
        if(s->state==MATTER_IM_SUB_WAITING) {
            if(!code && !fabric_scope(s)) code=MATTER_IM_INVALID_ACTION;
            if(!code) {
                code=s->port.reserve(s->port.attributes.user,s->exchange.session,s->work->root[0].unsigned_value!=0,&s->id);
                if(!code) {
                    s->reserved=true; s->dirty=false; s->phase=PRIME; capture_begin(s,true);
                    if(s->expanding) s->state=MATTER_IM_SUB_EXPANDING;
                    else if(!reserve_items(s,s->request_count)) code=MATTER_IM_RESOURCE_EXHAUSTED;
                    else { s->count=s->request_count; for(size_t i=0;i<s->count;++i) sub_item_set_path(sub_items_at(&s->items,i),&s->requests[i].path); }
                }
                else if(code!=MATTER_IM_RESOURCE_EXHAUSTED) code=MATTER_IM_FAILURE;
            }
            if(code) { encoded=status(s,code); s->state=MATTER_IM_SUB_OUTPUT; }
        } else if(code) { r=fail(s); s->busy=false; goto finished; }
        else s->status_ok=true;
    }
    if(s->state==MATTER_IM_SUB_WAIT_STATUS && s->status_ok) {
        s->status_ok=false;
        release_consumed(s);
        if(s->terminal_report && !s->more) { r=fail(s); s->busy=false; goto finished; }
        if(s->more) {
            encoded=chunk(s,true); if(!encoded) encoded=status(s,MATTER_IM_RESOURCE_EXHAUSTED);
            s->state=MATTER_IM_SUB_OUTPUT;
        } else {
            clear_snapshots(s);
            if(s->events) {
                if(s->events->active) s->events->next=s->events->pending_next;
                matter_events_snapshot_clear(&s->events->records); s->events->count=s->events->cursor=0;
            }
            if(s->phase==PRIME) {
                clear_filters(s);
                s->phase=RESPONSE; s->opcode=4;
                encoded=begin(s) && put(s,MATTER_TLV_UNSIGNED,0,s->id) && put(s,MATTER_TLV_UNSIGNED,2,s->maximum) && finish(s);
                if(!encoded) encoded=status(s,MATTER_IM_RESOURCE_EXHAUSTED);
                s->state=MATTER_IM_SUB_OUTPUT;
            } else s->state=MATTER_IM_SUB_IDLE;
        }
    }
    if(s->state==MATTER_IM_SUB_IDLE && (now>=add(s->last_activity,(uint64_t)s->maximum*1000) ||
        (pending_change(s) && now>=add(s->last_report,(uint64_t)s->minimum*1000)))) {
        s->expires=add(now,s->config.timeout_ms); s->state=MATTER_IM_SUB_NEED_EXCHANGE;
    }
    if(s->state==MATTER_IM_SUB_BUILD_REPORT) {
        bool data=s->dirty; s->dirty=false;
        s->phase=UPDATE; capture_begin(s,data);
    }
    if(s->state==MATTER_IM_SUB_EXPANDING) {
        uint8_t code=expand(s);
        if(code) { encoded=status(s,code); s->state=MATTER_IM_SUB_OUTPUT; }
    }
    if(s->state==MATTER_IM_SUB_COLLECTING) {
        uint8_t code=capture(s);
        if(code || (s->collected==s->count && (!s->events || s->events->collected))) {
            /* A coarse application notification may concern no selected value.
             * Attribute-only subscriptions can { r=to idle without traffic; goto finished; }
             * do not move the heartbeat deadline or suppress access failures.
             * Event subscriptions retain their independent cursor/report rules. */
            if(!code && s->phase==UPDATE && !s->attribute_report && !s->terminal_report &&
                (!s->events || !s->events->requested) && now<add(s->last_activity,(uint64_t)s->maximum*1000)) {
                clear_snapshots(s); s->state=MATTER_IM_SUB_IDLE;
            } else {
                encoded=code?status(s,code):chunk(s,true);
                if(!encoded) encoded=status(s,MATTER_IM_RESOURCE_EXHAUSTED);
                s->state=MATTER_IM_SUB_OUTPUT;
            }
        }
    }
    if(!encoded) r=fail(s); else r=MATTER_PENDING;
    s->busy=false;
finished:
    if(s->state!=MATTER_IM_SUB_OUTPUT) matter_im_output_release(s->output_pool,s,&s->output);
    if(s->state!=MATTER_IM_SUB_WAITING && (!s->expanding || s->request_cursor==s->request_count)) { free(s->requests); s->requests=NULL; }
    if(!s->queued) { matter_im_workspace_delete(s->work,sizeof(*s->work)); s->work=NULL; }
    return r;
}

Matter_Result_T matter_im_subscribe_changed(Matter_Im_Subscribe_T s) {
    Matter_Result_T r=check(s); if(r) return r;
    if(s->state==MATTER_IM_SUB_FAILED) return MATTER_INVALID_STATE;
    if(s->request_count || s->state==MATTER_IM_SUB_WAITING) s->dirty=true;
    return MATTER_OK;
}
Matter_Result_T matter_im_subscribe_events_changed(Matter_Im_Subscribe_T s) {
    Matter_Result_T r=check(s); if(r) return r;
    if(s->state==MATTER_IM_SUB_FAILED || !s->events || !s->events->requested) return MATTER_INVALID_STATE;
    s->events->dirty=true; return MATTER_OK;
}
bool matter_im_subscribe_event_pending(Matter_Im_Subscribe_T s,const Matter_Event_Path_T* p,uint64_t number) {
    if(!s || !p || !s->reserved || s->state==MATTER_IM_SUB_FAILED) return false;
    SubEvents* e=s->events;
    if(!e || !e->active || number<e->initial_min || number<e->next) return false;
    for(size_t i=0;i<e->path_count;++i) {
        const Matter_Im_Event_Request_T* q=matter_im_event_paths_at(&e->paths,i);
        if(q->active && !q->status && q->path.endpoint==p->endpoint &&
            q->path.cluster==p->cluster && q->path.event==p->event) return true;
    }
    return false;
}
Matter_Result_T matter_im_subscribe_bind_report(Matter_Im_Subscribe_T s,const Matter_Exchange_Info_T* e,uint64_t now) {
    Matter_Result_T r=check(s); if(r) return r;
    if(!e || !e->initiator || e->session!=s->config.exchange.session || e->exchange_id==s->exchange.exchange_id) return MATTER_INVALID_ARGUMENT;
    if(s->state!=MATTER_IM_SUB_NEED_EXCHANGE) return MATTER_INVALID_STATE;
    r=clock_check(s,now); if(r) return r;
    s->exchange=*e; s->expires=add(now,s->config.timeout_ms); s->state=MATTER_IM_SUB_BUILD_REPORT; return MATTER_OK;
}
Matter_Result_T matter_im_subscribe_output(Matter_Im_Subscribe_T s,Matter_Im_Subscribe_Message_T* out) {
    Matter_Result_T r=check(s); if(r) return r;
    if(!out) return MATTER_INVALID_ARGUMENT;
    if(s->state!=MATTER_IM_SUB_OUTPUT) return MATTER_INVALID_STATE;
    if(s->output_copied) return MATTER_WOULD_BLOCK;
    *out=(Matter_Im_Subscribe_Message_T){s->output,s->output_size,s->opcode}; return MATTER_OK;
}
Matter_Result_T matter_im_subscribe_output_copied(Matter_Im_Subscribe_T s) {
    Matter_Result_T r=check(s); if(r) return r;
    if(s->state!=MATTER_IM_SUB_OUTPUT) return MATTER_INVALID_STATE;
    if(s->output_pool) {
        if(s->output_copied || s->output_pool->owner!=s) return MATTER_INVALID_STATE;
        matter_im_output_release(s->output_pool,s,&s->output); s->output_copied=true;
    }
    return MATTER_OK;
}
Matter_Result_T matter_im_subscribe_sent_at(Matter_Im_Subscribe_T s,uint64_t now) {
    Matter_Result_T r=check(s); if(r) return r;
    if(s->state!=MATTER_IM_SUB_OUTPUT) return MATTER_INVALID_STATE;
    r=clock_check(s,now); if(r) return r;
    if(s->phase==PRIME || s->phase==UPDATE) {
        if(!s->report_started) { s->last_report=now; s->report_started=true; }
        s->last_activity=now;
    } else if(s->phase==RESPONSE) s->active=true;
    matter_im_output_release(s->output_pool,s,&s->output); s->output_copied=false;
    s->state=MATTER_IM_SUB_IN_FLIGHT; return MATTER_OK;
}
Matter_Result_T matter_im_subscribe_confirm(Matter_Im_Subscribe_T s,uint64_t now) {
    Matter_Result_T r=check(s); if(r) return r;
    if(s->state!=MATTER_IM_SUB_IN_FLIGHT) return MATTER_INVALID_STATE;
    r=clock_check(s,now); if(r) return r;
    if(s->phase==ERROR_REPLY) return fail(s);
    s->state=s->phase==RESPONSE ? MATTER_IM_SUB_IDLE : MATTER_IM_SUB_WAIT_STATUS; return MATTER_OK;
}
Matter_Result_T matter_im_subscribe_deadline(Matter_Im_Subscribe_T s,uint64_t* out) {
    Matter_Result_T r=check(s); if(r) return r;
    if(!out) return MATTER_INVALID_ARGUMENT;
    if(s->state==MATTER_IM_SUB_FAILED) return MATTER_INVALID_STATE;
    *out=s->state==MATTER_IM_SUB_IDLE || s->state==MATTER_IM_SUB_NEED_EXCHANGE ?
        (pending_change(s)?add(s->last_report,(uint64_t)s->minimum*1000):add(s->last_activity,(uint64_t)s->maximum*1000)) : s->expires; return MATTER_OK;
}
Matter_Result_T matter_im_subscribe_cancel(Matter_Im_Subscribe_T s) {
    Matter_Result_T r=check(s); if(r) return r; (void)fail(s); return MATTER_OK;
}
Matter_Im_Subscribe_State_T matter_im_subscribe_state(Matter_Im_Subscribe_T s) { return s ? s->state : MATTER_IM_SUB_FAILED; }
Matter_Result_T matter_im_subscribe_delete(Matter_Im_Subscribe_T s) {
    if(!s) return MATTER_OK;
    Matter_Result_T r=check(s); if(r) return r;
    s->busy=true; release(s); matter_im_blocks_clear(&s->items); matter_im_blocks_clear(&s->values); free(s->input); matter_im_output_dispose(s->output_pool,s,&s->output); if(s->events) matter_im_event_metadata_clear(&s->events->expansion,&s->events->paths,&s->events->filters); free(s->events); matter_im_snapshots_clear(&s->snapshots); matter_im_workspace_delete(s->work,sizeof(*s->work)); free(s->requests); memset(s,0,sizeof(*s)); free(s); return MATTER_OK;
}
