#include "matter_im_subscribe.h"
#include "matter_im_paths_internal.h"
#include "matter_im_events_internal.h"
#include "../codec/matter_tlv_validate.h"
#include "../codec/matter_tlv_writer.h"
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
    Matter_Im_Event_Request_T paths[MATTER_EVENT_PATH_CAPACITY];
    Matter_Event_Filter_T filters[MATTER_EVENT_PATH_CAPACITY];
    Matter_Event_Record_T records[MATTER_EVENTS_CAPACITY];
} SubEvents;
struct Matter_Im_Subscribe {
    Matter_Im_Subscribe_Port_T port;
    Matter_Im_Read_Fabric_Port_T fabric; uint8_t fabric_index;
    bool fabric_resolved;
    Matter_Im_Subscribe_Config_T config;
    Matter_Exchange_Info_T exchange;
    Matter_Im_Subscribe_State_T state;
    uint64_t now, expires, last_report,last_activity;
    bool more,report_started;
    size_t count,cursor,snapshot_size,list_offset;
    struct { size_t item,start,end; bool prefix; } plan[MATTER_IM_READ_MAX_PATHS];
    struct { Matter_Im_Path_T path; Matter_Im_Value_T value; uint32_t reported_version; uint8_t status; bool active,included,wildcard,reported; } items[MATTER_IM_READ_MAX_RESULTS];
    Matter_Im_Selector_T requests[MATTER_IM_SUB_MAX_ATTRIBUTE_PATHS];
    size_t request_count,request_cursor,filter_count,collected,valid;
    struct { uint16_t endpoint; uint32_t cluster,version; } *filters;
    Matter_Im_Path_T after; bool after_valid,expanding,capture_data,attribute_report;
    uint8_t* snapshots; SubEvents* events;
    Matter_Tlv_Reader_T value_reader; Matter_Tlv_Element_T element;
    uint32_t id;
    uint16_t minimum, maximum;
    bool busy, queued, reserved, active, dirty, status_ok, filtered, terminal_report;
    uint8_t phase, opcode;
    size_t input_size, output_size;
    Matter_Im_Path_T path;
    Matter_Im_Attribute_T attribute;
    Matter_Im_Value_T value;
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Writer_T writer;
    Matter_Tlv_Element_T token, root[9], fields[8], revision;
    Matter_Tlv_Validation_Workspace_T validation;
    Matter_Tlv_Tag_T tags[48];
    uint8_t *input, *output;
};
static uint64_t add(uint64_t a,uint64_t b) { return UINT64_MAX-a<b ? UINT64_MAX : a+b; }
static Matter_Result_T check(Matter_Im_Subscribe_T s) { return !s ? MATTER_INVALID_ARGUMENT : s->busy ? MATTER_BUSY : MATTER_OK; }
static void clear_filters(Matter_Im_Subscribe_T s) {
    free(s->filters); s->filters=NULL; s->filter_count=0;
}
static void release(Matter_Im_Subscribe_T s) {
    clear_filters(s);
    if(s->reserved) { s->reserved=false; s->port.release(s->port.attributes.user,s->id); }
}
static Matter_Result_T fail(Matter_Im_Subscribe_T s) {
    s->state=MATTER_IM_SUB_FAILED; s->queued=false; s->output_size=0; s->active=false;
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
Matter_Result_T matter_im_subscribe_bind_events(Matter_Im_Subscribe_T s,const Matter_Im_Read_Events_Port_T* p) {
    Matter_Result_T r=check(s); if(r) return r;
    if(!p || !p->log || !p->describe) return MATTER_INVALID_ARGUMENT;
    if(s->state!=MATTER_IM_SUB_WAITING || s->queued || s->events) return MATTER_INVALID_STATE;
    s->events=calloc(1,sizeof(*s->events)); if(!s->events) return MATTER_LIMIT_REACHED;
    s->events->port=*p; return MATTER_OK;
}
Matter_Result_T matter_im_subscribe_bind_event_enumerator(Matter_Im_Subscribe_T s,Matter_Im_Event_Enumerate_T callback) {
    Matter_Result_T r=check(s); if(r) return r;
    if(!callback) return MATTER_INVALID_ARGUMENT;
    if(s->state!=MATTER_IM_SUB_WAITING || s->queued || !s->events || s->events->expansion.enumerate) return MATTER_INVALID_STATE;
    s->events->expansion.enumerate=callback; return MATTER_OK;
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
    free(s->input); s->input=input;
    s->input_size=d->payload_size; s->queued=true; return MATTER_OK;
}
static bool container(Matter_Tlv_Type_T t) { return t==MATTER_TLV_ARRAY || t==MATTER_TLV_STRUCTURE || t==MATTER_TLV_LIST; }
static bool next(Matter_Im_Subscribe_T s) { return matter_tlv_next(&s->reader,&s->token)==MATTER_TLV_OK; }
static bool enter(Matter_Im_Subscribe_T s,const Matter_Tlv_Element_T* e) {
    if(matter_tlv_init(&s->reader,s->input,s->input_size,8)!=MATTER_TLV_OK) return false;
    do { if(!next(s)) return false; } while(s->token.offset<e->offset);
    return s->token.offset==e->offset;
}
static bool collect(Matter_Im_Subscribe_T s,Matter_Tlv_Element_T* out,size_t count) {
    memset(out,0,count*sizeof(*out));
    while(next(s)) {
        if(s->token.type==MATTER_TLV_END) return true;
        if(s->token.tag.control!=1) return false;
        uint32_t tag=s->token.tag.number;
        if(tag<count) { if(out[tag].tag.control) return false; out[tag]=s->token; }
        if(out==s->root && tag==255) s->revision=s->token;
        if(container(s->token.type) && matter_tlv_skip_container(&s->reader)!=MATTER_TLV_OK) return false;
    }
    return false;
}
static bool number(const Matter_Tlv_Element_T* e,uint64_t max) { return e->tag.control==1 && e->type==MATTER_TLV_UNSIGNED && e->unsigned_value<=max; }
static bool boolean(const Matter_Tlv_Element_T* e) { return e->tag.control==1 && e->type==MATTER_TLV_BOOL; }
static uint8_t decode_filters(Matter_Im_Subscribe_T s) {
    if(!s->root[8].tag.control) return 0;
    /* Count fully validated entries before allocating the exact per-request
     * table. Keep it only through priming, never for the subscription lifetime. */
    for(unsigned pass=0;pass<2;++pass) {
        s->filter_count=0;
        if(s->root[8].type!=MATTER_TLV_ARRAY || !enter(s,&s->root[8])) return MATTER_IM_INVALID_ACTION;
        while(next(s) && s->token.type!=MATTER_TLV_END) {
            if(s->filter_count==MATTER_IM_READ_MAX_FILTERS) return MATTER_IM_RESOURCE_EXHAUSTED;
            Matter_Tlv_Element_T element=s->token;
            if(element.type!=MATTER_TLV_STRUCTURE || element.tag.control || !collect(s,s->fields,8) ||
                !number(&s->fields[1],UINT32_MAX) || s->fields[0].tag.control!=1 || s->fields[0].type!=MATTER_TLV_LIST) return MATTER_IM_INVALID_ACTION;
            uint32_t version=(uint32_t)s->fields[1].unsigned_value;
            if(!enter(s,&s->fields[0]) || !collect(s,s->fields,8) || s->fields[0].tag.control ||
                !number(&s->fields[1],UINT16_MAX) || !number(&s->fields[2],UINT32_MAX)) return MATTER_IM_INVALID_ACTION;
            if(pass) {
                s->filters[s->filter_count].endpoint=(uint16_t)s->fields[1].unsigned_value;
                s->filters[s->filter_count].cluster=(uint32_t)s->fields[2].unsigned_value;
                s->filters[s->filter_count].version=version;
            }
            ++s->filter_count;
            if(!enter(s,&element) || matter_tlv_skip_container(&s->reader)!=MATTER_TLV_OK) return MATTER_IM_INVALID_ACTION;
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
    Matter_Tlv_Result_T r=matter_tlv_validate(s->input,s->input_size,&opt,&s->validation,s->tags,48,&report);
    if(r!=MATTER_TLV_OK) return r==MATTER_TLV_LIMIT_REACHED || r==MATTER_TLV_DEPTH_LIMIT ? MATTER_IM_RESOURCE_EXHAUSTED : MATTER_IM_INVALID_ACTION;
    memset(&s->revision,0,sizeof(s->revision));
    if(matter_tlv_init(&s->reader,s->input,s->input_size,8)!=MATTER_TLV_OK || !next(s) || s->token.type!=MATTER_TLV_STRUCTURE ||
        s->token.tag.control || !collect(s,s->root,9) || !number(&s->revision,255) || !s->revision.unsigned_value) return MATTER_IM_INVALID_ACTION;
    if(s->state!=MATTER_IM_SUB_WAITING) return number(&s->root[0],255) ? (uint8_t)s->root[0].unsigned_value : MATTER_IM_INVALID_ACTION;
    if(!boolean(&s->root[0]) || !number(&s->root[1],UINT16_MAX) || !number(&s->root[2],UINT16_MAX) ||
        s->root[1].unsigned_value>s->root[2].unsigned_value || !boolean(&s->root[7])) return MATTER_IM_INVALID_ACTION;
    s->minimum=(uint16_t)s->root[1].unsigned_value; s->maximum=(uint16_t)s->root[2].unsigned_value;
    if(!s->maximum) s->maximum=1;
    s->filtered=s->root[7].unsigned_value!=0;
    if(s->root[3].tag.control) {
        if(s->root[3].type!=MATTER_TLV_ARRAY || !enter(s,&s->root[3])) return MATTER_IM_INVALID_ACTION;
        while(next(s) && s->token.type!=MATTER_TLV_END) {
            if(s->request_count==MATTER_IM_SUB_MAX_ATTRIBUTE_PATHS) return MATTER_IM_PATHS_EXHAUSTED;
            if(s->token.type!=MATTER_TLV_LIST || s->token.tag.control || !collect(s,s->fields,8)) return MATTER_IM_INVALID_ACTION;
    if((s->fields[0].tag.control && (!boolean(&s->fields[0]) || s->fields[0].unsigned_value)) ||
        s->fields[1].tag.control || s->fields[5].tag.control ||
        (s->fields[6].tag.control && (!number(&s->fields[6],UINT32_MAX) || s->fields[6].unsigned_value)) ||
        (s->fields[7].tag.control && !number(&s->fields[7],UINT32_MAX))) return MATTER_IM_INVALID_ACTION;
            Matter_Im_Selector_T* q=&s->requests[s->request_count++];
            for(unsigned i=2;i<=4;++i) if(s->fields[i].tag.control) {
                if(!number(&s->fields[i],i==2?UINT16_MAX:UINT32_MAX)) return MATTER_IM_INVALID_ACTION;
                q->present|=(uint8_t)(1u<<(i-2));
            }
            q->path=(Matter_Im_Path_T){(uint16_t)s->fields[2].unsigned_value,(uint32_t)s->fields[3].unsigned_value,(uint32_t)s->fields[4].unsigned_value};
            if(!matter_im_read_path_valid(q)) return MATTER_IM_INVALID_ACTION;
            if(q->present!=MATTER_IM_CONCRETE) { if(!s->port.attributes.enumerate) return MATTER_IM_INVALID_ACTION; s->expanding=true; }
        }
    }
    if(s->root[4].tag.control) {
        if(s->root[4].type!=MATTER_TLV_ARRAY || !enter(s,&s->root[4])) return MATTER_IM_INVALID_ACTION;
        while(next(s) && s->token.type!=MATTER_TLV_END) {
            if(s->request_count+(s->events?s->events->raw_count:0)>=MATTER_IM_READ_MAX_PATHS) return MATTER_IM_PATHS_EXHAUSTED;
            if(!s->events || s->token.type!=MATTER_TLV_LIST || s->token.tag.control || !collect(s,s->fields,8)) return MATTER_IM_INVALID_ACTION;
            if(s->fields[0].tag.control || (s->fields[4].tag.control && !boolean(&s->fields[4]))) return MATTER_IM_INVALID_ACTION;
            Matter_Im_Event_Selector_T q={0};
            for(unsigned i=1;i<=3;++i) if(s->fields[i].tag.control) {
                if(!number(&s->fields[i],i==1?UINT16_MAX:UINT32_MAX)) return MATTER_IM_INVALID_ACTION;
                q.present|=(uint8_t)(1u<<(i-1));
            }
            if((q.present&MATTER_IM_EVENT) && !(q.present&MATTER_IM_CLUSTER)) return MATTER_IM_INVALID_ACTION;
            SubEvents* e=s->events;
            q.path=(Matter_Event_Path_T){(uint16_t)s->fields[1].unsigned_value,(uint32_t)s->fields[2].unsigned_value,(uint32_t)s->fields[3].unsigned_value};
            e->expansion.requests[e->raw_count].selector=q;
            e->expansion.requests[e->raw_count++].urgent=s->fields[4].unsigned_value!=0;
            if(q.present==MATTER_IM_CONCRETE) {
                size_t i=matter_im_event_index(e->paths,e->path_count,&q.path);
                if(i==e->path_count) e->paths[e->path_count++].path=q.path;
                e->paths[i].urgent|=s->fields[4].unsigned_value!=0;
            } else {
                if(!e->expansion.enumerate) return MATTER_IM_INVALID_ACTION;
                e->expansion.wildcard=true;
            }
            e->urgent|=s->fields[4].unsigned_value!=0; e->requested=true;
        }
    }
    if(s->root[5].tag.control) {
        if(!s->events || !s->events->requested || s->root[5].type!=MATTER_TLV_ARRAY || !enter(s,&s->root[5]) || !next(s)) return MATTER_IM_INVALID_ACTION;
        if(s->token.type!=MATTER_TLV_END) {
            if(s->token.type!=MATTER_TLV_STRUCTURE || s->token.tag.control || !collect(s,s->fields,8) ||
                s->fields[0].tag.control || !number(&s->fields[1],UINT64_MAX) || !next(s) || s->token.type!=MATTER_TLV_END) return MATTER_IM_INVALID_ACTION;
            s->events->initial_min=s->fields[1].unsigned_value;
        }
    }
    if(!s->request_count && !(s->events && s->events->requested)) return MATTER_IM_INVALID_ACTION;
    return decode_filters(s);
}
static bool put(Matter_Im_Subscribe_T s,Matter_Tlv_Type_T type,int tag,uint64_t value) {
    s->token=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0 ? 0 : 1,.number=tag<0 ? 0 : (uint32_t)tag},
        .unsigned_value=value,.signed_value=s->value.signed_value};
    return matter_tlv_write(&s->writer,&s->token,0)==MATTER_TLV_OK;
}
static bool end(Matter_Im_Subscribe_T s) { return put(s,MATTER_TLV_END,-1,0); }
static bool begin(Matter_Im_Subscribe_T s) {
    size_t cap=s->config.output_capacity;
    return matter_tlv_writer_init(&s->writer,s->output,cap,8)==MATTER_TLV_OK && put(s,MATTER_TLV_STRUCTURE,-1,0);
}
static bool finish(Matter_Im_Subscribe_T s) {
    return put(s,MATTER_TLV_UNSIGNED,255,MATTER_IM_REVISION) && end(s) && matter_tlv_writer_finish(&s->writer,&s->output_size)==MATTER_TLV_OK;
}
static bool status(Matter_Im_Subscribe_T s,uint8_t code) {
    clear_filters(s);
    s->phase=ERROR_REPLY; s->opcode=1;
    return begin(s) && put(s,MATTER_TLV_UNSIGNED,0,code) && finish(s);
}
static bool complex_value(Matter_Tlv_Type_T type) {
    return type==MATTER_TLV_STRUCTURE || type==MATTER_TLV_ARRAY || type==MATTER_TLV_UTF8 || type==MATTER_TLV_BYTES;
}
static uint8_t copy_value(Matter_Im_Subscribe_T s) {
    size_t size=s->value.size;
    if(size>MATTER_IM_READ_MAX_VALUE || size>MATTER_IM_READ_SNAPSHOT_BYTES-s->snapshot_size) return MATTER_IM_RESOURCE_EXHAUSTED;
    if((!s->value.data && size) || (container(s->value.type) && (!s->value.data || size<2))) return MATTER_IM_FAILURE;
    if(!s->snapshots) { s->snapshots=calloc(1,MATTER_IM_READ_SNAPSHOT_BYTES); if(!s->snapshots) return MATTER_IM_RESOURCE_EXHAUSTED; }
    uint8_t* data=s->snapshots+s->snapshot_size;
    if(container(s->value.type)) memcpy(data,s->value.data,size);
    else {
        size_t cap=MATTER_IM_READ_SNAPSHOT_BYTES-s->snapshot_size;
        if(cap>MATTER_IM_READ_MAX_VALUE) cap=MATTER_IM_READ_MAX_VALUE;
        s->element=(Matter_Tlv_Element_T){.type=s->value.type,.data=s->value.data,.size=size};
        if(matter_tlv_writer_init(&s->writer,data,cap,4)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
        Matter_Tlv_Result_T r=matter_tlv_write(&s->writer,&s->element,0);
        if(r==MATTER_TLV_NO_SPACE) return MATTER_IM_RESOURCE_EXHAUSTED;
        if(r!=MATTER_TLV_OK || matter_tlv_writer_finish(&s->writer,&size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    }
    const Matter_Tlv_Validation_Options_T opt={MATTER_IM_READ_MAX_VALUE,1024,4096,4,false,0,0};
    Matter_Tlv_Validation_Report_T report;
    Matter_Tlv_Result_T r=matter_tlv_validate(data,size,&opt,&s->validation,s->tags,48,&report);
    if(r==MATTER_TLV_LIMIT_REACHED || r==MATTER_TLV_DEPTH_LIMIT) return MATTER_IM_RESOURCE_EXHAUSTED;
    if(r!=MATTER_TLV_OK || matter_tlv_init(&s->value_reader,data,size,4)!=MATTER_TLV_OK ||
        matter_tlv_next(&s->value_reader,&s->element)!=MATTER_TLV_OK || s->element.tag.control || s->element.type!=s->value.type) return MATTER_IM_FAILURE;
    s->value.data=data; s->value.size=size; s->snapshot_size+=size; return 0;
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
        if(s->count==MATTER_IM_READ_MAX_RESULTS) return MATTER_IM_RESOURCE_EXHAUSTED;
        s->items[s->count].path=s->path; s->items[s->count++].wildcard=wildcard;
    }
    if(s->request_cursor==s->request_count) s->state=MATTER_IM_SUB_COLLECTING;
    return 0;
}
static void capture_begin(Matter_Im_Subscribe_T s,bool data) {
    s->cursor=0; s->list_offset=0; s->snapshot_size=0; s->report_started=false; s->terminal_report=false;
    s->collected=s->valid=0; s->attribute_report=false; s->capture_data=data;
    if(s->events) { s->events->access_cursor=s->events->filter_count=0; s->events->collected=false; }
    s->state=MATTER_IM_SUB_COLLECTING;
}
static uint8_t capture(Matter_Im_Subscribe_T s) {
    bool prime=s->phase==PRIME;
    unsigned budget=s->expanding?MATTER_IM_READ_WORK_BATCH:MATTER_IM_READ_MAX_PATHS;
    while(budget-- && s->collected<s->count) {
        size_t i=s->collected++; bool omit=false;
        s->items[i].included=false;
        if(!prime && !s->items[i].active) continue;
        s->path=s->items[i].path;
        uint8_t code=snapshot(s,s->capture_data,prime && s->items[i].wildcard,&omit);
        if(code==MATTER_IM_RESOURCE_EXHAUSTED) return code;
        if(prime && s->items[i].wildcard && path_error(code)) omit=true;
        if(!prime && !code && s->capture_data && s->value.report_on_version_change &&
            s->items[i].reported && s->items[i].reported_version==s->value.data_version) omit=true;
        s->items[i].status=code; s->items[i].value=s->value;
        if(prime) s->items[i].active=code==0;
        else if(code) s->terminal_report=true;
        if(!code) ++s->valid;
        s->items[i].included=!omit && (s->capture_data || code); s->attribute_report|=s->items[i].included;
        if(!code && s->items[i].included) { s->items[i].reported=true; s->items[i].reported_version=s->value.data_version; }
    }
    if(s->collected<s->count) return 0;
    SubEvents* e=s->events;
    if(e && e->requested && (prime || e->active)) {
        if(e->expansion.wildcard && e->expansion.cursor<e->raw_count) {
            uint8_t code=matter_im_event_expand(&e->expansion,e->port.user,e->raw_count,e->paths,&e->path_count);
            if(code || e->expansion.cursor<e->raw_count) return code;
        }
        unsigned event_budget=e->expansion.wildcard?MATTER_IM_READ_WORK_BATCH:MATTER_IM_READ_MAX_PATHS;
        while(event_budget-- && e->access_cursor<e->path_count) {
            Matter_Im_Event_Request_T* q=&e->paths[e->access_cursor++];
            q->reported=!prime && !q->active;
            if(!prime && !q->active) continue;
            e->path=q->path; q->status=event_access(s,q->wildcard); q->access=s->attribute;
            q->omit=matter_im_event_omitted(q->wildcard,q->status);
            if(!prime && q->omit) q->active=false;
            if(!q->status) e->filters[e->filter_count++]=(Matter_Event_Filter_T){q->path,q->access.fabric_scoped};
        }
        if(e->access_cursor<e->path_count) return 0;
        e->count=e->cursor=0; e->dirty=false;
        if(matter_events_copy_selected(e->port.log,e->filters,e->filter_count,prime?e->initial_min:e->next,s->fabric_index,e->records,&e->count)!=MATTER_OK ||
            matter_events_position(e->port.log,&e->pending_next)!=MATTER_OK)
            for(size_t i=0;i<e->path_count;++i) if(!e->paths[i].status) e->paths[i].status=MATTER_IM_FAILURE;
        e->active=false;
        for(size_t i=0;i<e->path_count;++i) {
            Matter_Im_Event_Request_T* q=&e->paths[i];
            if(prime) q->active=!q->status;
            else if(q->active && q->status) s->terminal_report=true;
            e->active|=q->active;
            if(q->active && !q->status) ++s->valid;
        }
        e->report=matter_im_event_more(e->paths,e->path_count,e->records,0,e->count) || !s->attribute_report;
    } else if(e) e->report=false;
    if(e) e->collected=true;
    if(!prime && !s->valid) s->terminal_report=true;
    return prime && !s->valid?MATTER_IM_INVALID_ACTION:0;
}
static bool write_value(Matter_Im_Subscribe_T s,size_t part) {
    if(!complex_value(s->value.type)) return put(s,s->value.type,2,s->value.unsigned_value);
    size_t start=s->plan[part].start,stop=s->plan[part].end;
    bool prefix=s->plan[part].prefix;
    if(matter_tlv_init(&s->value_reader,s->value.data,s->value.size,4)!=MATTER_TLV_OK) return false;
    if(prefix && !put(s,MATTER_TLV_ARRAY,2,0)) return false;
    Matter_Tlv_Result_T r;
    while((r=matter_tlv_next(&s->value_reader,&s->element))==MATTER_TLV_OK) {
        if(stop && s->element.offset>=stop) break;
        if(s->element.offset<start) continue;
        if(!prefix && s->element.offset==start) s->element.tag=(Matter_Tlv_Tag_T){.control=1,.number=2};
        if(matter_tlv_write(&s->writer,&s->element,0)!=MATTER_TLV_OK) return false;
    }
    return (r==MATTER_TLV_DONE || (stop && r==MATTER_TLV_OK)) && (!prefix || end(s));
}
static bool report_attributes(Matter_Im_Subscribe_T s,size_t stop,bool more) {
    if(!begin(s) || !put(s,MATTER_TLV_UNSIGNED,0,s->id) || !put(s,MATTER_TLV_ARRAY,1,0)) return false;
    for(size_t part=0;part<stop;++part) {
        size_t i=s->plan[part].item;
        s->path=s->items[i].path; s->value=s->items[i].value; uint8_t code=s->items[i].status;
        if(!put(s,MATTER_TLV_STRUCTURE,-1,0) || !put(s,MATTER_TLV_STRUCTURE,code ? 0 : 1,0) ||
            (!code && !put(s,MATTER_TLV_UNSIGNED,0,s->value.data_version)) || !put(s,MATTER_TLV_LIST,code ? 0 : 1,0) ||
            !put(s,MATTER_TLV_UNSIGNED,2,s->path.endpoint) || !put(s,MATTER_TLV_UNSIGNED,3,s->path.cluster) ||
            !put(s,MATTER_TLV_UNSIGNED,4,s->path.attribute) ||
            (!code && s->plan[part].start && !s->plan[part].prefix && !put(s,MATTER_TLV_NULL,5,0)) || !end(s)) return false;
        if(code) { if(!put(s,MATTER_TLV_STRUCTURE,1,0) || !put(s,MATTER_TLV_UNSIGNED,0,code) || !end(s)) return false; }
        else if(!write_value(s,part)) return false;
        if(!end(s) || !end(s)) return false;
    }
    return end(s) && (!more || put(s,MATTER_TLV_BOOL,3,1)) && put(s,MATTER_TLV_BOOL,4,0) && finish(s);
}
static void recheck_events(Matter_Im_Subscribe_T s) {
    SubEvents* e=s->events; if(!e || !e->requested) return;
    for(size_t i=0;i<e->path_count;++i) if(!e->paths[i].status) {
        Matter_Im_Event_Request_T* q=&e->paths[i]; e->path=q->path;
        uint8_t code=event_access(s,q->wildcard);
        if(code) {
            q->status=code; q->omit=matter_im_event_omitted(q->wildcard,code);
            if(q->omit) q->active=false;
            else if(q->active) s->terminal_report=true;
        }
    }
    e->active=false;
    for(size_t i=0;i<e->path_count;++i) e->active|=e->paths[i].active;
    if(!e->active) {
        bool active=false;
        for(size_t i=0;i<s->count;++i) active|=s->items[i].active;
        if(!active) s->terminal_report=true;
    }
}
static bool report_event(Matter_Im_Subscribe_T s) {
    SubEvents* e=s->events;
    const Matter_Event_Record_T* record;
    size_t selected=matter_im_event_take(e->paths,e->path_count,e->records,&e->cursor,e->count,&record);
    e->status=selected<e->path_count?e->paths[selected].status:0;
    if(selected<e->path_count) e->path=e->paths[selected].path;
    bool more=matter_im_event_more(e->paths,e->path_count,e->records,e->cursor,e->count);
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
                !put(s,MATTER_TLV_UNSIGNED,r->epoch?3:4,r->timestamp_ms) || matter_tlv_init(&s->value_reader,r->data,r->size,4)!=MATTER_TLV_OK) return false;
            Matter_Tlv_Result_T result;
            while((result=matter_tlv_next(&s->value_reader,&s->element))==MATTER_TLV_OK) {
                if(!s->element.offset) s->element.tag=(Matter_Tlv_Tag_T){.control=1,.number=7};
                if(matter_tlv_write(&s->writer,&s->element,0)!=MATTER_TLV_OK) return false;
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
    const Matter_Im_Value_T* v=&s->items[item].value;
    if(matter_tlv_init(&s->value_reader,v->data,v->size,4)!=MATTER_TLV_OK ||
        matter_tlv_next(&s->value_reader,&s->element)!=MATTER_TLV_OK) return 0;
    while(matter_tlv_next(&s->value_reader,&s->element)==MATTER_TLV_OK && s->element.type!=MATTER_TLV_END) {
        size_t current=s->element.offset;
        if(container(s->element.type) && matter_tlv_skip_container(&s->value_reader)!=MATTER_TLV_OK) return 0;
        if(current==offset) return matter_tlv_next(&s->value_reader,&s->element)==MATTER_TLV_OK?s->element.offset:0;
    }
    return 0;
}
static bool chunk(Matter_Im_Subscribe_T s,bool recheck) {
    s->opcode=5;
    /* Permissions may change between chunks; never read providers again here. */
    if(recheck) for(size_t i=s->cursor;i<s->count;++i) if(s->items[i].active && s->items[i].included) {
        s->path=s->items[i].path; bool omit=false; uint8_t code=snapshot(s,false,s->phase==PRIME && s->items[i].wildcard,&omit);
        if(code) {
            s->items[i].status=code;
            if(s->phase==PRIME && s->items[i].wildcard && path_error(code)) { s->items[i].included=false; s->items[i].active=false; }
            else s->terminal_report=true;
        }
    }
    if(recheck && s->events && s->events->report) recheck_events(s);
    if(s->phase==PRIME) {
        bool active=s->events && s->events->active;
        for(size_t i=0;i<s->count;++i) active|=s->items[i].active;
        if(!active) return status(s,MATTER_IM_INVALID_ACTION);
    }
    while(s->cursor<s->count && !s->items[s->cursor].included) { ++s->cursor; s->list_offset=0; }
    if(s->cursor<s->count && s->items[s->cursor].status) s->list_offset=0;
    bool events=s->events && s->events->report;
    if(s->cursor==s->count && events) return report_event(s);
    size_t n=0,item=s->cursor,offset=s->list_offset;
    while(item<s->count && n<MATTER_IM_READ_MAX_PATHS) {
        if(!s->items[item].included) { ++item; continue; }
        s->plan[n].item=item; s->plan[n].start=offset; s->plan[n].prefix=false;
        size_t stop=offset?list_next(s,item,offset):0;
        if(offset && !stop) return false;
        s->plan[n].end=stop;
        bool last=!offset || stop==s->items[item].value.size-1;
        size_t next_item=item+1;
        while(next_item<s->count && !s->items[next_item].included) ++next_item;
        if(report_attributes(s,n+1,!last || next_item<s->count || events)) {
            ++n; offset=last?0:stop; if(last) item=next_item; continue;
        }
        if(n) break; /* First try the whole attribute on an empty report. */
        if(offset || s->items[item].status || s->items[item].value.type!=MATTER_TLV_ARRAY) return false;
        s->plan[n].prefix=true; s->plan[n].start=1; s->plan[n].end=1;
        if(!report_attributes(s,1,true)) return false;
        stop=1;
        while(stop<s->items[item].value.size-1) {
            size_t candidate=list_next(s,item,stop);
            if(!candidate) return false;
            s->plan[n].end=candidate;
            if(!report_attributes(s,1,true)) break;
            stop=candidate;
        }
        s->plan[n].end=stop; offset=stop; ++n; break;
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
    for(size_t i=0;i<e->path_count;++i) if(e->paths[i].active && e->paths[i].urgent)
        e->filters[filters++]=(Matter_Event_Filter_T){e->paths[i].path,e->paths[i].access.fabric_scoped};
    /* No payload copy or callbacks; a non-urgent/unselected event cannot wake
     * an otherwise clean subscription merely because another path is urgent. */
    return matter_events_copy_selected(e->port.log,e->filters,filters,e->next,s->fabric_index,NULL,&count)!=MATTER_OK || count!=0;
}
Matter_Result_T matter_im_subscribe_process(Matter_Im_Subscribe_T s,uint64_t now) {
    Matter_Result_T r=check(s); if(r) return r;
    r=clock_check(s,now); if(r) return r;
    s->busy=true; bool encoded=true;
    if(s->queued) {
        s->queued=false; uint8_t code=decode(s);
        if(s->state==MATTER_IM_SUB_WAITING) {
            if(!code && !fabric_scope(s)) code=MATTER_IM_INVALID_ACTION;
            if(!code) {
                code=s->port.reserve(s->port.attributes.user,s->exchange.session,s->root[0].unsigned_value!=0,&s->id);
                if(!code) {
                    s->reserved=true; s->dirty=false; s->phase=PRIME; capture_begin(s,true);
                    if(s->expanding) s->state=MATTER_IM_SUB_EXPANDING;
                    else { s->count=s->request_count; for(size_t i=0;i<s->count;++i) s->items[i].path=s->requests[i].path; }
                }
                else if(code!=MATTER_IM_RESOURCE_EXHAUSTED) code=MATTER_IM_FAILURE;
            }
            if(code) { encoded=status(s,code); s->state=MATTER_IM_SUB_OUTPUT; }
        } else if(code) { r=fail(s); s->busy=false; return r; }
        else s->status_ok=true;
    }
    if(s->state==MATTER_IM_SUB_WAIT_STATUS && s->status_ok) {
        s->status_ok=false;
        if(s->terminal_report && !s->more) { r=fail(s); s->busy=false; return r; }
        if(s->more) {
            encoded=chunk(s,true); if(!encoded) encoded=status(s,MATTER_IM_RESOURCE_EXHAUSTED);
            s->state=MATTER_IM_SUB_OUTPUT;
        } else {
            if(s->events && s->events->active) s->events->next=s->events->pending_next;
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
             * Attribute-only subscriptions can return to idle without traffic;
             * do not move the heartbeat deadline or suppress access failures.
             * Event subscriptions retain their independent cursor/report rules. */
            if(!code && s->phase==UPDATE && !s->attribute_report && !s->terminal_report &&
                (!s->events || !s->events->requested) && now<add(s->last_activity,(uint64_t)s->maximum*1000)) {
                s->state=MATTER_IM_SUB_IDLE;
            } else {
                encoded=code?status(s,code):chunk(s,true);
                if(!encoded) encoded=status(s,MATTER_IM_RESOURCE_EXHAUSTED);
                s->state=MATTER_IM_SUB_OUTPUT;
            }
        }
    }
    if(!encoded) r=fail(s); else r=MATTER_PENDING;
    s->busy=false; return r;
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
    *out=(Matter_Im_Subscribe_Message_T){s->output,s->output_size,s->opcode}; return MATTER_OK;
}
Matter_Result_T matter_im_subscribe_sent_at(Matter_Im_Subscribe_T s,uint64_t now) {
    Matter_Result_T r=check(s); if(r) return r;
    if(s->state!=MATTER_IM_SUB_OUTPUT) return MATTER_INVALID_STATE;
    r=clock_check(s,now); if(r) return r;
    if(s->phase==PRIME || s->phase==UPDATE) {
        if(!s->report_started) { s->last_report=now; s->report_started=true; }
        s->last_activity=now;
    } else if(s->phase==RESPONSE) s->active=true;
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
    s->busy=true; release(s); free(s->input); free(s->output); free(s->events); free(s->snapshots); memset(s,0,sizeof(*s)); free(s); return MATTER_OK;
}
