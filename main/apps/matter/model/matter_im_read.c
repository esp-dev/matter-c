#include "matter_im_read.h"
#include "matter_im_paths_internal.h"
#include "matter_im_events_internal.h"
#include "matter_im_snapshot_internal.h"
#include "../codec/matter_tlv_validate.h"
#include "../codec/matter_tlv_writer.h"
#include "matter_im_buffer_internal.h"
#include "matter_im_blocks_internal.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    Matter_Im_Read_Events_Port_T port; Matter_Event_Path_T path;
    Matter_Im_Attribute_T access; uint64_t minimum; size_t count,cursor;
    bool requested,collected; Matter_Im_Status_T status;
    size_t path_count,raw_count,access_cursor,filter_count;
    Matter_Im_Event_Expansion_T expansion;
    Matter_Im_Blocks paths;
    Matter_Event_Filter_T* filters;
    Matter_Events_Snapshot records;
} ReadEvents;
typedef struct {
	Matter_Tlv_Validation_Workspace_T validation;
	Matter_Tlv_Tag_T tags[48];
	Matter_Tlv_Reader_T reader;
	Matter_Tlv_Reader_T value_reader;
	Matter_Tlv_Element_T token;
	Matter_Tlv_Writer_T writer;
	Matter_Tlv_Element_T element, fields[5], revision, path_fields[8], filter_fields[2], filter_element;
} Matter_Im_Read_Work;
typedef struct {
		Matter_Im_Path_T path;
		Matter_Im_Attribute_T attribute;
		Matter_Im_Snapshot_Value value;
		Matter_Im_Status_T status;
		bool wildcard, omit;
} ReadItem;
MATTER_IM_BLOCK_TABLE(read_items,ReadItem)
struct Matter_Im_Read {
    Matter_Im_Read_Work* work;
    Matter_Im_Read_Events_Port_T event_port; Matter_Im_Event_Enumerate_T event_enumerate;
    ReadEvents* events;
	Matter_Im_Read_Port_T port;
    Matter_Im_Read_Fabric_Port_T fabric; uint8_t fabric_index; bool fabric_resolved, case_session;
	Matter_Im_Read_Config_T config;
	Matter_Im_Read_State_T state;
	uint64_t now, deadline;
	bool busy, queued, fabric_filtered, more, status_received, peer_status_valid;
	uint8_t peer_status;
	Matter_Im_Status_T continuation_error;
	size_t count, cursor, released;
	Matter_Im_Snapshots snapshots;
    Matter_Events_Snapshot event_tail; /* Only references survive final sent, not path/parser metadata. */
	size_t list_offset;
	/* Each planned IB either carries a whole attribute, a list prefix, or one ADD. */
	struct { size_t item, start, end; bool prefix; } *plan;
	size_t plan_capacity;
	Matter_Im_Selector_T* requests;
	size_t request_count, request_cursor, collected, filter_count;
	bool expanding, after_valid;
	Matter_Im_Path_T after;
	struct { uint16_t endpoint; uint32_t cluster, version; } *filters;
	Matter_Im_Blocks items;
	uint8_t opcode, response_opcode;
	size_t input_size, output_size;
	Matter_Im_Path_T path;
	Matter_Im_Attribute_T attribute;
	Matter_Im_Value_T value;
	uint8_t *input, *output;
};
static Matter_Result_T check(Matter_Im_Read_T s) {
	return !s ? MATTER_INVALID_ARGUMENT : s->busy ? MATTER_BUSY : MATTER_OK;
}
Matter_Im_Read_T matter_im_read_new(const Matter_Im_Read_Port_T* p, const Matter_Im_Read_Config_T* c, uint64_t now) {
	if (!p || !c || !p->authorize || !p->describe || !p->read || !c->exchange.session ||
		c->exchange.initiator || !c->pase_commissionee || !c->timeout_ms ||
		c->output_capacity < 8 || c->output_capacity > MATTER_IM_READ_MAX_OUTPUT) return NULL;
	Matter_Im_Read_T s=calloc(1,sizeof(*s));
	if (s) {
		s->output=calloc(1,c->output_capacity);
		if (!s->output) { free(s); return NULL; }
		s->port=*p; s->config=*c; s->now=now;
		s->deadline=UINT64_MAX-now < c->timeout_ms ? UINT64_MAX : now+c->timeout_ms; }
	return s;
}
Matter_Im_Read_T matter_im_read_new_fabric(const Matter_Im_Read_Port_T* p,const Matter_Im_Read_Fabric_Port_T* f,
    const Matter_Im_Read_Config_T* c,uint64_t now) {
    if(!f || !f->index) return NULL;
    Matter_Im_Read_T s=matter_im_read_new(p,c,now); if(s) s->fabric=*f; return s;
}
Matter_Result_T matter_im_read_bind_events(Matter_Im_Read_T s,const Matter_Im_Read_Events_Port_T* p) {
    Matter_Result_T r=check(s); if(r!=MATTER_OK) return r;
    if(!p || !p->log || !p->describe) return MATTER_INVALID_ARGUMENT;
    if(s->state!=MATTER_IM_READ_WAITING || s->queued || s->event_port.log) return MATTER_INVALID_STATE;
    s->event_port=*p; return MATTER_OK;
}
Matter_Result_T matter_im_read_bind_event_enumerator(Matter_Im_Read_T s,Matter_Im_Event_Enumerate_T callback) {
    Matter_Result_T r=check(s); if(r) return r;
    if(!callback) return MATTER_INVALID_ARGUMENT;
    if(s->state!=MATTER_IM_READ_WAITING || s->queued || !s->event_port.log || s->event_enumerate) return MATTER_INVALID_STATE;
    s->event_enumerate=callback; return MATTER_OK;
}
static Matter_Im_Status_T fabric_scope(Matter_Im_Read_T s) {
    if(!s->fabric.index) return MATTER_IM_SUCCESS;
    uint8_t index=0;
    if(s->fabric.index(s->port.user,s->config.exchange.session,&index)!=MATTER_OK || index==255 || (s->case_session && !index) ||
        (s->fabric_resolved && index!=s->fabric_index)) return MATTER_IM_UNSUPPORTED_ACCESS;
    s->fabric_index=index; s->fabric_resolved=true; return MATTER_IM_SUCCESS;
}
Matter_Result_T matter_im_read_receive(Matter_Im_Read_T s, const Matter_Rx_Decision_T* d) {
	Matter_Result_T r=check(s); if (r != MATTER_OK) return r;
	if (!d || (!d->payload && d->payload_size)) return MATTER_INVALID_ARGUMENT;
	bool continuation=s->more && (s->state == MATTER_IM_READ_IN_FLIGHT || s->state == MATTER_IM_READ_WAIT_STATUS);
	if (s->state != MATTER_IM_READ_WAITING && !continuation) return MATTER_INVALID_STATE;
	if (s->queued) return MATTER_WOULD_BLOCK;
	if (continuation && s->status_received) return MATTER_INVALID_STATE;
	if (d->session != s->config.exchange.session || d->header.exchange_id != s->config.exchange.exchange_id ||
		d->header.vendor_id || d->header.protocol_id != 1 || d->header.opcode != (continuation ? 1 : 2) ||
		!(d->header.exchange_flags & MATTER_PROTOCOL_INITIATOR) || d->standalone_ack ||
		(d->action != MATTER_RX_NEW_RESPONDER && d->action != MATTER_RX_EXISTING)) return MATTER_INVALID_ARGUMENT;
	if (d->payload_size > MATTER_IM_READ_MAX_PAYLOAD) return MATTER_LIMIT_REACHED;
	uint8_t* input=d->payload_size ? calloc(1,d->payload_size) : NULL;
	if (d->payload_size && !input) return MATTER_LIMIT_REACHED;
	if (d->payload_size) memcpy(input,d->payload,d->payload_size);
	Matter_Im_Read_Work* work=s->work ? s->work : calloc(1,sizeof(*work));
    if(!work) { free(input); return MATTER_LIMIT_REACHED; }
    s->work=work; free(s->input); s->input=input;
	s->input_size=d->payload_size; s->opcode=d->header.opcode; s->queued=true;
	return MATTER_OK;
}
static bool container(Matter_Tlv_Type_T t) {
	return t == MATTER_TLV_STRUCTURE || t == MATTER_TLV_ARRAY || t == MATTER_TLV_LIST;
}
static bool next(Matter_Im_Read_T s) { return matter_tlv_next(&s->work->reader,&s->work->element) == MATTER_TLV_OK; }
static bool skip(Matter_Im_Read_T s) {
	return !container(s->work->element.type) || matter_tlv_skip_container(&s->work->reader) == MATTER_TLV_OK;
}
static bool enter(Matter_Im_Read_T s, const Matter_Tlv_Element_T* e) {
	if (matter_tlv_init(&s->work->reader,s->input,s->input_size,8) != MATTER_TLV_OK) return false;
	do { if (!next(s)) return false; } while (s->work->element.offset < e->offset);
	return s->work->element.offset == e->offset;
}
static bool number(const Matter_Tlv_Element_T* e, uint64_t max) {
	return e->tag.control == 1 && e->type == MATTER_TLV_UNSIGNED && e->unsigned_value <= max;
}
static bool empty_array(Matter_Im_Read_T s, const Matter_Tlv_Element_T* e) {
	return !e->tag.control || (e->type == MATTER_TLV_ARRAY && enter(s,e) && next(s) && s->work->element.type == MATTER_TLV_END);
}
static Matter_Im_Status_T decode_fields(Matter_Im_Read_T s) {
	memset(s->work->fields,0,sizeof(s->work->fields)); memset(&s->work->revision,0,sizeof(s->work->revision));
	/* Every TLV token consumes at least one input byte. Accept dense filter lists
	 * within the existing request budget without weakening semantic validation. */
	const Matter_Tlv_Validation_Options_T opt={MATTER_IM_READ_MAX_PAYLOAD,MATTER_IM_READ_MAX_PAYLOAD,2048,8,false,0,0};
	Matter_Tlv_Validation_Report_T report;
	Matter_Tlv_Result_T r=matter_tlv_validate(s->input,s->input_size,&opt,&s->work->validation,s->work->tags,48,&report);
	if (r == MATTER_TLV_LIMIT_REACHED || r == MATTER_TLV_DEPTH_LIMIT) return MATTER_IM_RESOURCE_EXHAUSTED;
	if (r != MATTER_TLV_OK ||
		matter_tlv_init(&s->work->reader,s->input,s->input_size,8) != MATTER_TLV_OK || !next(s) ||
		s->work->element.type != MATTER_TLV_STRUCTURE || s->work->element.tag.control) return MATTER_IM_INVALID_ACTION;
	while (next(s) && s->work->element.type != MATTER_TLV_END) {
		if (s->work->element.tag.control != 1) return MATTER_IM_INVALID_ACTION;
		uint32_t tag=s->work->element.tag.number;
		if (tag < 5) s->work->fields[tag]=s->work->element;
		if (tag == 255) s->work->revision=s->work->element;
		if (!skip(s)) return MATTER_IM_INVALID_ACTION;
	}
	return number(&s->work->revision,UINT8_MAX) && s->work->revision.unsigned_value ? MATTER_IM_SUCCESS : MATTER_IM_INVALID_ACTION;
}
static Matter_Im_Status_T decode_path(Matter_Im_Read_T s, Matter_Im_Selector_T* selector) {
	if (s->work->element.type != MATTER_TLV_LIST || s->work->element.tag.control) return MATTER_IM_INVALID_ACTION;
	memset(s->work->path_fields,0,sizeof(s->work->path_fields));
	while (next(s) && s->work->element.type != MATTER_TLV_END) {
		if (s->work->element.tag.control != 1) return MATTER_IM_INVALID_ACTION;
		uint32_t tag=s->work->element.tag.number;
		if (tag < 8) {
			if (s->work->path_fields[tag].tag.control) return MATTER_IM_INVALID_ACTION; /* TLV List permits duplicate tags. */
			s->work->path_fields[tag]=s->work->element;
		}
		if (!skip(s)) return MATTER_IM_INVALID_ACTION;
	}
	if (s->work->path_fields[0].tag.control && (s->work->path_fields[0].type != MATTER_TLV_BOOL || s->work->path_fields[0].unsigned_value))
		return MATTER_IM_INVALID_ACTION;
	if (s->work->path_fields[1].tag.control || s->work->path_fields[5].tag.control ||
		(s->work->path_fields[6].tag.control && (!number(&s->work->path_fields[6],UINT32_MAX) || s->work->path_fields[6].unsigned_value)) ||
		(s->work->path_fields[7].tag.control && !number(&s->work->path_fields[7],UINT32_MAX))) return MATTER_IM_INVALID_ACTION;
	selector->present=0;
	for (unsigned i=2; i<=4; ++i) if (s->work->path_fields[i].tag.control) {
		if (!number(&s->work->path_fields[i],i==2 ? UINT16_MAX : UINT32_MAX)) return MATTER_IM_INVALID_ACTION;
		selector->present |= (uint8_t)(1u << (i-2));
	}
	selector->path=(Matter_Im_Path_T){(uint16_t)s->work->path_fields[2].unsigned_value,
		(uint32_t)s->work->path_fields[3].unsigned_value,(uint32_t)s->work->path_fields[4].unsigned_value};
	return matter_im_read_path_valid(selector) ? MATTER_IM_SUCCESS : MATTER_IM_INVALID_ACTION;
}
static Matter_Im_Status_T decode_filters(Matter_Im_Read_T s) {
	if (!s->work->fields[4].tag.control) return MATTER_IM_SUCCESS;
	/* Validate/count before allocating; the second pass fills exactly that many
	 * entries in this handler's private, immutable request snapshot. */
	for (unsigned pass=0; pass<2; ++pass) {
		s->filter_count=0;
		if (s->work->fields[4].type != MATTER_TLV_ARRAY || !enter(s,&s->work->fields[4])) return MATTER_IM_INVALID_ACTION;
		while (next(s) && s->work->element.type != MATTER_TLV_END) {
			if (s->filter_count == MATTER_IM_READ_MAX_FILTERS) return MATTER_IM_RESOURCE_EXHAUSTED;
			if (s->work->element.type != MATTER_TLV_STRUCTURE || s->work->element.tag.control) return MATTER_IM_INVALID_ACTION;
			s->work->filter_element=s->work->element; memset(s->work->filter_fields,0,sizeof(s->work->filter_fields));
			while (next(s) && s->work->element.type != MATTER_TLV_END) {
				if (s->work->element.tag.control != 1) return MATTER_IM_INVALID_ACTION;
				if (s->work->element.tag.number < 2) s->work->filter_fields[s->work->element.tag.number]=s->work->element;
				if (!skip(s)) return MATTER_IM_INVALID_ACTION;
			}
			if (!number(&s->work->filter_fields[1],UINT32_MAX) || !s->work->filter_fields[0].tag.control ||
				s->work->filter_fields[0].type != MATTER_TLV_LIST || !enter(s,&s->work->filter_fields[0])) return MATTER_IM_INVALID_ACTION;
			memset(s->work->path_fields,0,sizeof(s->work->path_fields));
			while (next(s) && s->work->element.type != MATTER_TLV_END) {
				if (s->work->element.tag.control != 1) return MATTER_IM_INVALID_ACTION;
				uint32_t tag=s->work->element.tag.number;
				if (tag < 3) {
					if (s->work->path_fields[tag].tag.control) return MATTER_IM_INVALID_ACTION;
					s->work->path_fields[tag]=s->work->element;
				}
				if (!skip(s)) return MATTER_IM_INVALID_ACTION;
			}
			if (s->work->path_fields[0].tag.control || !number(&s->work->path_fields[1],UINT16_MAX) ||
				!number(&s->work->path_fields[2],UINT32_MAX)) return MATTER_IM_INVALID_ACTION;
			if (pass) {
				s->filters[s->filter_count].endpoint=(uint16_t)s->work->path_fields[1].unsigned_value;
				s->filters[s->filter_count].cluster=(uint32_t)s->work->path_fields[2].unsigned_value;
				s->filters[s->filter_count].version=(uint32_t)s->work->filter_fields[1].unsigned_value;
			}
			++s->filter_count;
			if (!enter(s,&s->work->filter_element) || !skip(s)) return MATTER_IM_INVALID_ACTION;
		}
		if (!pass) {
			if (!s->filter_count) return MATTER_IM_SUCCESS;
			s->filters=calloc(s->filter_count,sizeof(*s->filters));
			if (!s->filters) { s->filter_count=0; return MATTER_IM_RESOURCE_EXHAUSTED; }
		}
	}
	return MATTER_IM_SUCCESS;
}
static Matter_Im_Status_T decode_events(Matter_Im_Read_T s) {
    if(empty_array(s,&s->work->fields[1])) return empty_array(s,&s->work->fields[2])?MATTER_IM_SUCCESS:MATTER_IM_INVALID_ACTION;
    if(!s->event_port.log || s->work->fields[1].type!=MATTER_TLV_ARRAY || !enter(s,&s->work->fields[1])) return MATTER_IM_INVALID_ACTION;
    s->events=calloc(1,sizeof(*s->events)); if(!s->events) return MATTER_IM_RESOURCE_EXHAUSTED;
    ReadEvents* e=s->events; e->port=s->event_port; e->expansion.enumerate=s->event_enumerate;
    while(next(s) && s->work->element.type!=MATTER_TLV_END) {
        if(e->raw_count==MATTER_IM_READ_MAX_PATHS) return MATTER_IM_PATHS_EXHAUSTED;
        if(s->work->element.type!=MATTER_TLV_LIST || s->work->element.tag.control) return MATTER_IM_INVALID_ACTION;
        memset(s->work->path_fields,0,sizeof(s->work->path_fields));
        while(next(s) && s->work->element.type!=MATTER_TLV_END) {
            if(s->work->element.tag.control!=1) return MATTER_IM_INVALID_ACTION;
            unsigned tag=s->work->element.tag.number;
            if(tag<5) {
                if(s->work->path_fields[tag].tag.control) return MATTER_IM_INVALID_ACTION;
                s->work->path_fields[tag]=s->work->element;
            }
            if(!skip(s)) return MATTER_IM_INVALID_ACTION;
        }
        if(s->work->path_fields[0].tag.control || (s->work->path_fields[4].tag.control && s->work->path_fields[4].type!=MATTER_TLV_BOOL)) return MATTER_IM_INVALID_ACTION;
        Matter_Im_Event_Selector_T q={0};
        for(unsigned i=1;i<=3;++i) if(s->work->path_fields[i].tag.control) {
            if(!number(&s->work->path_fields[i],i==1?UINT16_MAX:UINT32_MAX)) return MATTER_IM_INVALID_ACTION;
            q.present|=(uint8_t)(1u<<(i-1));
        }
        if((q.present&MATTER_IM_EVENT) && !(q.present&MATTER_IM_CLUSTER)) return MATTER_IM_INVALID_ACTION;
        q.path=(Matter_Event_Path_T){(uint16_t)s->work->path_fields[1].unsigned_value,(uint32_t)s->work->path_fields[2].unsigned_value,(uint32_t)s->work->path_fields[3].unsigned_value};
        uint8_t code=matter_im_event_selector_add(&e->expansion,&e->paths,&e->path_count,&q,false);
        if(code) return code;
        ++e->raw_count;
    }
    if(!empty_array(s,&s->work->fields[2])) {
        if(s->work->fields[2].type!=MATTER_TLV_ARRAY || !enter(s,&s->work->fields[2]) || !next(s) ||
            s->work->element.type!=MATTER_TLV_STRUCTURE || s->work->element.tag.control) return MATTER_IM_INVALID_ACTION;
        memset(s->work->filter_fields,0,sizeof(s->work->filter_fields));
        while(next(s) && s->work->element.type!=MATTER_TLV_END) {
            if(s->work->element.tag.control!=1) return MATTER_IM_INVALID_ACTION;
            if(s->work->element.tag.number<2) s->work->filter_fields[s->work->element.tag.number]=s->work->element;
            if(!skip(s)) return MATTER_IM_INVALID_ACTION;
        }
        if(s->work->filter_fields[0].tag.control || !number(&s->work->filter_fields[1],UINT64_MAX) || !next(s) || s->work->element.type!=MATTER_TLV_END) return MATTER_IM_INVALID_ACTION;
        e->minimum=s->work->filter_fields[1].unsigned_value;
    }
    e->requested=true; return MATTER_IM_SUCCESS;
}
static Matter_Im_Status_T decode(Matter_Im_Read_T s) {
	Matter_Im_Status_T r=decode_fields(s); if (r) return r;
	if (!s->work->fields[3].tag.control || s->work->fields[3].type != MATTER_TLV_BOOL) return MATTER_IM_INVALID_ACTION;
	s->fabric_filtered=s->work->fields[3].unsigned_value != 0;
	r=decode_events(s); if(r) return r;
	if (s->work->fields[0].tag.control) {
		for(unsigned pass=0;pass<2;++pass) {
            s->request_count=0;
		if (s->work->fields[0].type != MATTER_TLV_ARRAY || !enter(s,&s->work->fields[0])) return MATTER_IM_INVALID_ACTION;
		while (next(s) && s->work->element.type != MATTER_TLV_END) {
			if (s->request_count + (s->events ? s->events->raw_count : 0) == MATTER_IM_READ_MAX_PATHS) return MATTER_IM_PATHS_EXHAUSTED;
			Matter_Im_Selector_T parsed={0};
            r=decode_path(s,&parsed); if (r) return r;
			if(pass) s->requests[s->request_count]=parsed;
            ++s->request_count;
            if (parsed.present != MATTER_IM_CONCRETE) s->expanding=true;
		}
            if(!pass) {
                if(!s->request_count) break;
                s->requests=calloc(s->request_count,sizeof(*s->requests));
                if(!s->requests) return MATTER_IM_RESOURCE_EXHAUSTED;
            }
        }
	}
	r=decode_filters(s); if (r) return r;
	return s->expanding && !s->port.enumerate ? MATTER_IM_FAILURE : MATTER_IM_SUCCESS;
}
static bool put(Matter_Im_Read_T s, Matter_Tlv_Type_T type, int tag, uint64_t n) {
	s->work->element=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag < 0 ? 0 : 1,.number=tag < 0 ? 0 : (uint32_t)tag},
		.unsigned_value=n,.signed_value=s->value.signed_value};
	return matter_tlv_write(&s->work->writer,&s->work->element,0) == MATTER_TLV_OK;
}
static bool end(Matter_Im_Read_T s) { return put(s,MATTER_TLV_END,-1,0); }
static bool begin(Matter_Im_Read_T s) {
	return matter_tlv_writer_init(&s->work->writer,s->output,s->config.output_capacity,8) == MATTER_TLV_OK &&
		put(s,MATTER_TLV_STRUCTURE,-1,0);
}
static bool finish(Matter_Im_Read_T s) {
	return put(s,MATTER_TLV_UNSIGNED,255,MATTER_IM_REVISION) && end(s) &&
		matter_tlv_writer_finish(&s->work->writer,&s->output_size) == MATTER_TLV_OK;
}
static bool status(Matter_Im_Read_T s, Matter_Im_Status_T code) {
	s->response_opcode=1; s->more=false;
	return begin(s) && put(s,MATTER_TLV_UNSIGNED,0,code) && finish(s);
}
static bool path(Matter_Im_Read_T s, int tag, bool append) {
	return put(s,MATTER_TLV_LIST,tag,0) && put(s,MATTER_TLV_UNSIGNED,2,s->path.endpoint) &&
		put(s,MATTER_TLV_UNSIGNED,3,s->path.cluster) && put(s,MATTER_TLV_UNSIGNED,4,s->path.attribute) &&
		(!append || put(s,MATTER_TLV_NULL,5,0)) && end(s);
}
static bool complex_value(Matter_Tlv_Type_T t) {
	return matter_im_snapshot_complex(t);
}
static bool write_value(Matter_Im_Read_T s, size_t part) {
	if (!complex_value(s->value.type)) return put(s,s->value.type,2,s->value.unsigned_value);
	size_t start=s->plan[part].start, stop=s->plan[part].end;
	bool prefix=s->plan[part].prefix;
	if (matter_tlv_init(&s->work->value_reader,s->value.data,s->value.size,4)!=MATTER_TLV_OK) return false;
	if (prefix && !put(s,MATTER_TLV_ARRAY,2,0)) return false;
	Matter_Tlv_Result_T r;
	while ((r=matter_tlv_next(&s->work->value_reader,&s->work->token))==MATTER_TLV_OK) {
		if (stop && s->work->token.offset>=stop) break;
		if (s->work->token.offset<start) continue;
		if (!prefix && s->work->token.offset==start) s->work->token.tag=(Matter_Tlv_Tag_T){.control=1,.number=2};
		if (matter_tlv_write(&s->work->writer,&s->work->token,0)!=MATTER_TLV_OK) return false;
	}
	return (r==MATTER_TLV_DONE || (stop && r==MATTER_TLV_OK)) && (!prefix || end(s));
}
static bool report_data(Matter_Im_Read_T s, size_t count, bool more) {
	s->response_opcode=5;
	if (!begin(s) || !put(s,MATTER_TLV_ARRAY,1,0)) return false;
	for (size_t part=0; part<count; ++part) {
		size_t i=s->plan[part].item;
		ReadItem* result=read_items_at(&s->items,i);
		s->path=result->path; matter_im_snapshot_load(&s->value,&result->value);
		Matter_Im_Status_T code=result->status;
		if (!put(s,MATTER_TLV_STRUCTURE,-1,0) || !put(s,MATTER_TLV_STRUCTURE,code ? 0 : 1,0)) return false;
		if (code) {
			if (!path(s,0,false) || !put(s,MATTER_TLV_STRUCTURE,1,0) || !put(s,MATTER_TLV_UNSIGNED,0,code) || !end(s)) return false;
		} else if (!put(s,MATTER_TLV_UNSIGNED,0,s->value.data_version) ||
			!path(s,1,s->plan[part].start && !s->plan[part].prefix) || !write_value(s,part)) return false;
		if (!end(s) || !end(s)) return false;
	}
	return end(s) && put(s,MATTER_TLV_BOOL,more ? 3 : 4,1) && finish(s);
}
static Matter_Im_Status_T snapshot(Matter_Im_Read_T s) {
	if (s->value.size>MATTER_IM_READ_MAX_VALUE) return MATTER_IM_RESOURCE_EXHAUSTED;
	if (!s->value.data && (s->value.size || container(s->value.type))) return MATTER_IM_FAILURE;
	return matter_im_snapshot_copy(&s->snapshots,&s->value,&s->work->writer,&s->work->value_reader,&s->work->token,
        &s->work->validation,s->work->tags,48);
}
static bool privilege(Matter_Im_Privilege_T p) {
	return p == MATTER_IM_VIEW || p == MATTER_IM_OPERATE || p == MATTER_IM_MANAGE || p == MATTER_IM_ADMINISTER;
}
static Matter_Im_Status_T authorize(Matter_Im_Read_T s, Matter_Im_Privilege_T p) {
	Matter_Im_Status_T r=fabric_scope(s); if(r) return r;
    r=s->port.authorize(s->port.user,s->config.exchange.session,&s->path,p);
	return r == MATTER_IM_SUCCESS || r == MATTER_IM_UNSUPPORTED_ACCESS || r == MATTER_IM_ACCESS_RESTRICTED ? r : MATTER_IM_FAILURE;
}
static Matter_Im_Status_T event_access(Matter_Im_Read_T s,bool wildcard) {
    ReadEvents* e=s->events;
    s->path=(Matter_Im_Path_T){e->path.endpoint,e->path.cluster,e->path.event};
    Matter_Im_Status_T r=fabric_scope(s); if(r) return r;
    if(!wildcard) { r=authorize(s,MATTER_IM_VIEW); if(r) return r; }
    r=e->port.describe(e->port.user,&e->path,&e->access);
    if(r) return r==MATTER_IM_UNSUPPORTED_ENDPOINT || r==MATTER_IM_UNSUPPORTED_CLUSTER || r==MATTER_IM_UNSUPPORTED_EVENT ? r : MATTER_IM_FAILURE;
    if(!privilege(e->access.privilege)) return MATTER_IM_FAILURE;
    if(e->access.fabric_scoped && !s->fabric_index) return MATTER_IM_UNSUPPORTED_ACCESS;
    return authorize(s,e->access.privilege);
}
static Matter_Im_Status_T collect_events(Matter_Im_Read_T s) {
    ReadEvents* e=s->events; if(!e || !e->requested || e->collected) return 0;
    if(e->expansion.wildcard && e->expansion.cursor<e->raw_count) {
        uint8_t code=matter_im_event_expand(&e->expansion,e->port.user,e->raw_count,&e->paths,&e->path_count);
        if(code || e->expansion.cursor<e->raw_count) return code;
    }
    matter_im_event_selectors_clear(&e->expansion); e->expansion.cursor=e->raw_count;
    if(!matter_im_event_filters_reserve(&e->filters,e->path_count)) return MATTER_IM_RESOURCE_EXHAUSTED;
    unsigned budget=e->expansion.wildcard?MATTER_IM_READ_WORK_BATCH:MATTER_IM_READ_MAX_PATHS;
    while(budget-- && e->access_cursor<e->path_count) {
        Matter_Im_Event_Request_T* q=matter_im_event_paths_at(&e->paths,e->access_cursor++); e->path=q->path;
        q->status=event_access(s,q->wildcard); q->access=e->access;
        q->omit=matter_im_event_omitted(q->wildcard,q->status);
        if(!q->status) e->filters[e->filter_count++]=(Matter_Event_Filter_T){q->path,q->access.fabric_scoped};
    }
    if(e->access_cursor<e->path_count) return 0;
    e->collected=true;
    Matter_Result_T r=matter_im_event_snapshot(e->port.log,e->filters,e->filter_count,e->minimum,s->fabric_index,&e->records,&e->count);
    free(e->filters); e->filters=NULL; e->filter_count=0;
    if(r==MATTER_LIMIT_REACHED) return MATTER_IM_RESOURCE_EXHAUSTED;
    if(r!=MATTER_OK)
        for(size_t i=0;i<e->path_count;++i) if(!matter_im_event_paths_at(&e->paths,i)->status) matter_im_event_paths_at(&e->paths,i)->status=MATTER_IM_FAILURE;
    return 0;
}
static bool event_path(Matter_Im_Read_T s) {
    const Matter_Event_Path_T* p=&s->events->path;
    return put(s,MATTER_TLV_LIST,0,0) && put(s,MATTER_TLV_UNSIGNED,1,p->endpoint) &&
        put(s,MATTER_TLV_UNSIGNED,2,p->cluster) && put(s,MATTER_TLV_UNSIGNED,3,p->event) && end(s);
}
static bool event_chunk(Matter_Im_Read_T s) {
    ReadEvents* e=s->events;
    for(size_t i=0;i<e->path_count;++i) if(!matter_im_event_paths_at(&e->paths,i)->status) {
        e->path=matter_im_event_paths_at(&e->paths,i)->path;
        Matter_Im_Status_T code=event_access(s,matter_im_event_paths_at(&e->paths,i)->wildcard);
        if(code) { matter_im_event_paths_at(&e->paths,i)->status=code; matter_im_event_paths_at(&e->paths,i)->omit=matter_im_event_omitted(matter_im_event_paths_at(&e->paths,i)->wildcard,code); }
    }
    const Matter_Event_Record_T* record;
    size_t selected=matter_im_event_take(&e->paths,e->path_count,&e->records,&e->cursor,e->count,&record);
    e->status=selected<e->path_count?matter_im_event_paths_at(&e->paths,selected)->status:MATTER_IM_SUCCESS;
    if(selected<e->path_count) e->path=matter_im_event_paths_at(&e->paths,selected)->path;
    bool more=matter_im_event_more(&e->paths,e->path_count,&e->records,e->cursor,e->count);
    s->response_opcode=5;
    if(!begin(s) || !put(s,MATTER_TLV_ARRAY,2,0)) return status(s,MATTER_IM_RESOURCE_EXHAUSTED);
    if(selected<e->path_count) {
        if(!put(s,MATTER_TLV_STRUCTURE,-1,0) || !put(s,MATTER_TLV_STRUCTURE,e->status?0:1,0) || !event_path(s)) goto space;
        if(e->status) {
            if(!put(s,MATTER_TLV_STRUCTURE,1,0) || !put(s,MATTER_TLV_UNSIGNED,0,e->status) || !end(s)) goto space;
        } else {
            const Matter_Event_Record_T* r=record;
            if(!put(s,MATTER_TLV_UNSIGNED,1,r->number) || !put(s,MATTER_TLV_UNSIGNED,2,r->priority) ||
                !put(s,MATTER_TLV_UNSIGNED,r->epoch?3:4,r->timestamp_ms) ||
                matter_tlv_init(&s->work->value_reader,r->data,r->size,4)!=MATTER_TLV_OK) goto space;
            Matter_Tlv_Result_T result;
            while((result=matter_tlv_next(&s->work->value_reader,&s->work->token))==MATTER_TLV_OK) {
                if(!s->work->token.offset) s->work->token.tag=(Matter_Tlv_Tag_T){.control=1,.number=7};
                if(matter_tlv_write(&s->work->writer,&s->work->token,0)!=MATTER_TLV_OK) goto space;
            }
            if(result!=MATTER_TLV_DONE) return status(s,MATTER_IM_FAILURE);
        }
        if(!end(s) || !end(s)) goto space;
    }
    if(!end(s) || !put(s,MATTER_TLV_BOOL,more?3:4,1) || !finish(s)) goto space;
    s->more=more; return true;
space: return status(s,MATTER_IM_RESOURCE_EXHAUSTED);
}
static bool filtered(Matter_Im_Read_T s, uint32_t version) {
	bool match=false;
	for (size_t i=0; i<s->filter_count; ++i) if (s->filters[i].endpoint==s->path.endpoint && s->filters[i].cluster==s->path.cluster) {
		if (s->filters[i].version!=version) return false;
		match=true;
	}
	return match;
}
static Matter_Im_Status_T read_value(Matter_Im_Read_T s, bool wildcard, bool* omit) {
	memset(&s->attribute,0,sizeof(s->attribute)); memset(&s->value,0,sizeof(s->value));
	*omit=false;
	Matter_Im_Status_T r;
	if (!wildcard) { r=authorize(s,MATTER_IM_VIEW); if (r) return r; }
	r=s->port.describe(s->port.user,&s->path,&s->attribute);
	if (r) {
		bool unavailable=r == MATTER_IM_UNSUPPORTED_ENDPOINT || r == MATTER_IM_UNSUPPORTED_CLUSTER ||
			r == MATTER_IM_UNSUPPORTED_ATTRIBUTE || r == MATTER_IM_UNSUPPORTED_READ;
		*omit=wildcard && unavailable; return unavailable ? r : MATTER_IM_FAILURE;
	}
	if (!privilege(s->attribute.privilege)) return MATTER_IM_FAILURE;
	/* Fabric scoping filters list entries; it does not forbid PASE reads before
	 * AddNOC (Core 7.19.1.8.2). Require a trusted resolver, but allow its index 0. */
	if (s->attribute.fabric_scoped && (!s->fabric.index || fabric_scope(s)!=MATTER_IM_SUCCESS)) { *omit=wildcard; return MATTER_IM_UNSUPPORTED_ACCESS; }
	r=authorize(s,s->attribute.privilege);
	if (r) { *omit=wildcard && (r==MATTER_IM_UNSUPPORTED_ACCESS || r==MATTER_IM_ACCESS_RESTRICTED); return r; }
	bool has_filter=false;
	for (size_t i=0; i<s->filter_count; ++i)
		if (s->filters[i].endpoint==s->path.endpoint && s->filters[i].cluster==s->path.cluster) has_filter=true;
	if (has_filter && s->port.version) {
		uint32_t version=0;
		if (s->port.version(s->port.user,&s->path,&version)!=MATTER_OK) return MATTER_IM_FAILURE;
		if (filtered(s,version)) { *omit=true; return MATTER_IM_SUCCESS; }
	}
	s->value.type=MATTER_TLV_END; /* A provider must actually supply a value. */
	r=s->port.read(s->port.user,&s->path,s->fabric_filtered,&s->value);
	/* Providers may still require a fabric (e.g. ACL/key material). Preserve
	 * their denial instead of turning it into a generic provider failure. */
	if (r==MATTER_IM_UNSUPPORTED_ACCESS || r==MATTER_IM_ACCESS_RESTRICTED) { *omit=wildcard; return r; }
	if (r || (s->value.type != MATTER_TLV_SIGNED && s->value.type != MATTER_TLV_UNSIGNED &&
		s->value.type != MATTER_TLV_BOOL && s->value.type != MATTER_TLV_NULL && !complex_value(s->value.type)) ||
		(s->value.type == MATTER_TLV_BOOL && s->value.unsigned_value > 1)) return MATTER_IM_FAILURE;
	*omit=filtered(s,s->value.data_version);
	return !*omit && complex_value(s->value.type) ? snapshot(s) : MATTER_IM_SUCCESS;
}
static int compare_path(const Matter_Im_Path_T* a, const Matter_Im_Path_T* b) {
	if (a->endpoint!=b->endpoint) return a->endpoint < b->endpoint ? -1 : 1;
	if (a->cluster!=b->cluster) return a->cluster < b->cluster ? -1 : 1;
	return a->attribute==b->attribute ? 0 : a->attribute < b->attribute ? -1 : 1;
}
static bool matches(const Matter_Im_Selector_T* q, const Matter_Im_Path_T* p) {
	return (!(q->present & MATTER_IM_ENDPOINT) || q->path.endpoint==p->endpoint) &&
		(!(q->present & MATTER_IM_CLUSTER) || q->path.cluster==p->cluster) &&
		(!(q->present & MATTER_IM_ATTRIBUTE) || q->path.attribute==p->attribute);
}
static bool reserve_items(Matter_Im_Read_T s,size_t needed) {
    return read_items_reserve(&s->items,needed,MATTER_IM_READ_MAX_RESULTS);
}
static Matter_Im_Status_T expand(Matter_Im_Read_T s) {
	for (unsigned step=0; step<MATTER_IM_READ_WORK_BATCH && s->request_cursor<s->request_count; ++step) {
		const Matter_Im_Selector_T* q=&s->requests[s->request_cursor];
		bool wildcard=q->present!=MATTER_IM_CONCRETE, found=false;
		if (wildcard) {
			if (s->port.enumerate(s->port.user,q,s->after_valid ? &s->after : NULL,&s->path,&found)!=MATTER_OK)
				return MATTER_IM_FAILURE;
			if (!found) { ++s->request_cursor; s->after_valid=false; continue; }
			if (!matches(q,&s->path) || (s->after_valid && compare_path(&s->path,&s->after)<=0)) return MATTER_IM_FAILURE;
			s->after=s->path; s->after_valid=true;
		} else { s->path=q->path; ++s->request_cursor; }
		if (!reserve_items(s,s->count+1)) return MATTER_IM_RESOURCE_EXHAUSTED;
		ReadItem* result=read_items_at(&s->items,s->count++);
		result->path=s->path; result->wildcard=wildcard;
	}
	if (s->request_cursor==s->request_count) s->state=MATTER_IM_READ_COLLECTING;
	return MATTER_IM_SUCCESS;
}
static void compact(Matter_Im_Read_T s) {
	if (s->cursor<s->count && (read_items_at(&s->items,s->cursor)->omit || read_items_at(&s->items,s->cursor)->status)) s->list_offset=0;
	size_t out=s->cursor;
	for (size_t i=s->cursor; i<s->count; ++i) {
        ReadItem* result=read_items_at(&s->items,i);
        if(!result->omit) { if(out!=i) *read_items_at(&s->items,out)=*result; ++out; }
    }
	s->count=out;
}
/* Find the next direct ARRAY child boundary using the public reader API only.
 * Snapshot validation already established anonymous root, balance and limits. */
static size_t list_next(Matter_Im_Read_T s, size_t item, size_t offset) {
	const Matter_Im_Snapshot_Value* v=&read_items_at(&s->items,item)->value;
	if (matter_tlv_init(&s->work->value_reader,v->as.span.data,v->as.span.size,4)!=MATTER_TLV_OK ||
		matter_tlv_next(&s->work->value_reader,&s->work->token)!=MATTER_TLV_OK) return 0;
	while (matter_tlv_next(&s->work->value_reader,&s->work->token)==MATTER_TLV_OK && s->work->token.type!=MATTER_TLV_END) {
		size_t current=s->work->token.offset;
		if (container(s->work->token.type) && matter_tlv_skip_container(&s->work->value_reader)!=MATTER_TLV_OK) return 0;
		if (current==offset) return matter_tlv_next(&s->work->value_reader,&s->work->token)==MATTER_TLV_OK ? s->work->token.offset : 0;
	}
	return 0;
}
static bool report_chunk(Matter_Im_Read_T s) {
    bool events=s->events && s->events->requested;
    if(s->cursor==s->count && events) return event_chunk(s);
    if(!s->plan) {
        s->plan_capacity=s->config.output_capacity/MATTER_IM_READ_MIN_REPORT_BYTES+1;
        s->plan=calloc(s->plan_capacity,sizeof(*s->plan));
        if(!s->plan) return status(s,MATTER_IM_RESOURCE_EXHAUSTED);
    }
	/* Rebuild only from bounded snapshots, never invoke providers speculatively
	 * during packing. No dependence on private writer fields or rollback. */
	size_t n=0, item=s->cursor, offset=s->list_offset;
	while (item<s->count && n<s->plan_capacity) {
		s->plan[n].item=item; s->plan[n].start=offset; s->plan[n].prefix=false;
		size_t stop=offset ? list_next(s,item,offset) : 0;
		if (offset && !stop) return status(s,MATTER_IM_FAILURE);
		s->plan[n].end=stop;
		bool last=!offset || stop==read_items_at(&s->items,item)->value.as.span.size-1;
		if (report_data(s,n+1,!last || item+1<s->count || events)) {
			++n; offset=last ? 0 : stop; if (last) ++item; continue;
		}
		if (n) break; /* Retry a whole attribute on a fresh report before splitting. */
		if (offset || read_items_at(&s->items,item)->status || read_items_at(&s->items,item)->value.type!=MATTER_TLV_ARRAY)
			return status(s,MATTER_IM_RESOURCE_EXHAUSTED);
		/* Whole list did not fit even an empty report. Select the largest prefix,
		 * possibly empty; following reports append complete items with null index. */
		s->plan[n].prefix=true; s->plan[n].start=1; s->plan[n].end=1;
		if (!report_data(s,1,true)) return status(s,MATTER_IM_RESOURCE_EXHAUSTED);
		stop=1;
		while (stop<read_items_at(&s->items,item)->value.as.span.size-1) {
			size_t candidate=list_next(s,item,stop);
			if (!candidate) return status(s,MATTER_IM_FAILURE);
			s->plan[n].end=candidate;
			if (!report_data(s,1,true)) break;
			stop=candidate;
		}
		s->plan[n].end=stop; offset=stop; ++n;
		/* The complete array was already tried, so this prefix must be partial. */
		break;
	}
	if (!report_data(s,n,item<s->count || events)) return status(s,MATTER_IM_RESOURCE_EXHAUSTED);
	s->cursor=item; s->list_offset=offset; s->more=item<s->count || events;
	return true;
}
static Matter_Result_T clock_check(Matter_Im_Read_T s, uint64_t now) {
	if (now < s->now) return MATTER_INVALID_ARGUMENT;
	s->now=now;
	if (now >= s->deadline) {
		s->state=MATTER_IM_READ_FAILED; s->queued=false; s->output_size=0; return MATTER_PORT_ERROR;
	}
	return MATTER_OK;
}
static void release_consumed(Matter_Im_Read_T s) {
    /* cursor advances past whole attributes only; a partial ARRAY stays live. */
    while(s->released<s->cursor) {
        size_t i=s->released++;
        matter_im_snapshot_release_value(&s->snapshots,&read_items_at(&s->items,i)->value);
    }
    s->value.data=NULL; s->value.size=0;
    if(s->events) matter_events_snapshot_release_before(&s->events->records,s->events->cursor);
}
Matter_Result_T matter_im_read_process(Matter_Im_Read_T s, uint64_t now) {
	Matter_Result_T r=check(s); if (r != MATTER_OK) return r;
	if (now < s->now) return MATTER_INVALID_ARGUMENT;
	s->now=now;
	if (s->state == MATTER_IM_READ_COMPLETE) return MATTER_OK;
	if (s->state == MATTER_IM_READ_FAILED) return MATTER_INVALID_STATE;
	r=clock_check(s,now); if (r != MATTER_OK) return r;
    if((s->queued || s->state==MATTER_IM_READ_EXPANDING || s->state==MATTER_IM_READ_COLLECTING || (s->state==MATTER_IM_READ_WAIT_STATUS && s->status_received)) && !s->work) {
        s->work=calloc(1,sizeof(*s->work));
        if(!s->work) { s->now=now; matter_im_status_bytes(s->output,MATTER_IM_RESOURCE_EXHAUSTED,MATTER_IM_REVISION); s->output_size=8; s->response_opcode=1; s->more=false; s->queued=false; s->state=MATTER_IM_READ_OUTPUT; return MATTER_PENDING; }
    }
    s->busy=true;
	bool produce=false, encoded=true;
	if (s->queued) {
		s->queued=false;
		if (s->opcode == 2) {
			Matter_Im_Status_T code=decode(s);
			if (code) { encoded=status(s,code); produce=true; }
			else {
				if (s->expanding) s->state=MATTER_IM_READ_EXPANDING;
				else if(!reserve_items(s,s->request_count)) { encoded=status(s,MATTER_IM_RESOURCE_EXHAUSTED); produce=true; }
				else {
					for (size_t i=0; i<s->request_count; ++i) read_items_at(&s->items,i)->path=s->requests[i].path;
					s->count=s->request_count; s->state=MATTER_IM_READ_COLLECTING;
				}
			}
		} else {
			s->continuation_error=decode_fields(s);
			if (!s->continuation_error && !number(&s->work->fields[0],UINT8_MAX)) s->continuation_error=MATTER_IM_INVALID_ACTION;
			if (!s->continuation_error) {
				s->peer_status_valid=true; s->peer_status=(uint8_t)s->work->fields[0].unsigned_value;
				if (s->peer_status) {
					s->state=MATTER_IM_READ_FAILED; s->output_size=0; s->busy=false; r=MATTER_PORT_ERROR; goto finished;
				}
			}
			s->status_received=true;
		}
	}
	if (s->state == MATTER_IM_READ_EXPANDING) {
		Matter_Im_Status_T code=expand(s);
		if (code) { encoded=status(s,code); produce=true; }
	}
	if (!produce && s->state == MATTER_IM_READ_COLLECTING) {
		/* Preserve the one-call concrete-only API; wildcard work yields in batches. */
		unsigned budget=s->expanding ? MATTER_IM_READ_WORK_BATCH : MATTER_IM_READ_MAX_PATHS;
		while (budget-- && s->collected<s->count) {
            ReadItem* result=read_items_at(&s->items,s->collected++); s->path=result->path;
            result->status=read_value(s,result->wildcard,&result->omit);
            result->value=matter_im_snapshot_store(&s->value); result->attribute=s->attribute;
		}
		if (s->collected==s->count) {
            Matter_Im_Status_T code=collect_events(s);
            if(code) { encoded=status(s,code); produce=true; }
            else if(!s->events || !s->events->requested || s->events->collected) { compact(s); encoded=report_chunk(s); produce=true; }
        }
	}
	if (s->state == MATTER_IM_READ_WAIT_STATUS && s->status_received) {
		/* MRP has released the previous packet AND the peer consumed its chunk.
		 * Revalidate access to remaining snapshots without re-reading values. */
		if (s->continuation_error) encoded=status(s,s->continuation_error);
		else {
			release_consumed(s);
			for (size_t i=s->cursor; i<s->count; ++i) {
                ReadItem* result=read_items_at(&s->items,i);
				s->path=result->path;
				Matter_Im_Status_T code=authorize(s,MATTER_IM_VIEW);
				if (!code && !result->status) code=authorize(s,result->attribute.privilege);
				if (code) {
					result->status=code;
					if (result->wildcard && (code==MATTER_IM_UNSUPPORTED_ACCESS || code==MATTER_IM_ACCESS_RESTRICTED)) result->omit=true;
				}
			}
			compact(s);
			encoded=report_chunk(s);
		}
		s->status_received=false; s->continuation_error=MATTER_IM_SUCCESS; produce=true;
	}
	if (produce) s->state=encoded ? MATTER_IM_READ_OUTPUT : MATTER_IM_READ_FAILED;
	s->busy=false; r=encoded ? MATTER_PENDING : MATTER_PORT_ERROR;
finished:
    if(s->state!=MATTER_IM_READ_WAITING && (!s->expanding || s->request_cursor==s->request_count)) { free(s->requests); s->requests=NULL; }
    if(!s->queued) { matter_im_workspace_delete(s->work,sizeof(*s->work)); s->work=NULL; }
    return r;
}

Matter_Result_T matter_im_read_output(Matter_Im_Read_T s, Matter_Im_Read_Message_T* m) {
	Matter_Result_T r=check(s); if (r != MATTER_OK) return r;
	if (!m) return MATTER_INVALID_ARGUMENT;
	if (s->state != MATTER_IM_READ_OUTPUT) return MATTER_INVALID_STATE;
	*m=(Matter_Im_Read_Message_T){s->output,s->output_size,s->response_opcode}; return MATTER_OK;
}
bool matter_im_read_awaiting_delivery(Matter_Im_Read_T s) {
    return s && !s->busy && s->state==MATTER_IM_READ_IN_FLIGHT && !s->more;
}
Matter_Result_T matter_im_read_sent(Matter_Im_Read_T s) {
	Matter_Result_T r=check(s); if (r != MATTER_OK) return r;
	if (s->state != MATTER_IM_READ_OUTPUT) return MATTER_INVALID_STATE;
	s->state=MATTER_IM_READ_IN_FLIGHT;
    if(!s->more) {
        /* Output was copied to independent immutable MRP storage. No future
         * continuation can use these tables; value/event references retain
         * their existing confirmation/cancel/drain lifetime. */
        matter_im_blocks_clear(&s->items); s->count=s->cursor=s->released=0;
        free(s->plan); s->plan=NULL; s->plan_capacity=0;
        free(s->requests); s->requests=NULL; free(s->filters); s->filters=NULL;
        free(s->input); s->input=NULL; free(s->output); s->output=NULL;
        s->input_size=s->output_size=0;
        if(s->events) { s->event_tail=s->events->records; matter_im_event_metadata_clear(&s->events->expansion,&s->events->paths,&s->events->filters); free(s->events); s->events=NULL; }
    }
    return MATTER_OK;
}
Matter_Result_T matter_im_read_confirm(Matter_Im_Read_T s, uint64_t now) {
	Matter_Result_T r=check(s); if (r != MATTER_OK) return r;
	if (s->state != MATTER_IM_READ_IN_FLIGHT) return MATTER_INVALID_STATE;
	r=clock_check(s,now); if (r != MATTER_OK) return r;
	s->state=s->more ? MATTER_IM_READ_WAIT_STATUS : MATTER_IM_READ_COMPLETE;
    if(!s->more) { matter_im_snapshots_clear(&s->snapshots); matter_events_snapshot_clear(&s->event_tail); s->value.data=NULL; s->value.size=0; }
    return MATTER_OK;
}
Matter_Result_T matter_im_read_peer_status(Matter_Im_Read_T s, uint8_t* code) {
	Matter_Result_T r=check(s); if (r != MATTER_OK) return r;
	if (!code) return MATTER_INVALID_ARGUMENT;
	if (!s->peer_status_valid) return MATTER_INVALID_STATE;
	*code=s->peer_status; return MATTER_OK;
}
Matter_Result_T matter_im_read_cancel(Matter_Im_Read_T s) {
	Matter_Result_T r=check(s); if (r != MATTER_OK) return r;
	if (s->state != MATTER_IM_READ_COMPLETE) s->state=MATTER_IM_READ_FAILED;
	s->queued=false; s->output_size=0; return MATTER_OK;
}
Matter_Im_Read_State_T matter_im_read_state(Matter_Im_Read_T s) { return s ? s->state : MATTER_IM_READ_FAILED; }
Matter_Result_T matter_im_read_delete(Matter_Im_Read_T s) {
	if (!s) return MATTER_OK;
	Matter_Result_T r=check(s); if (r != MATTER_OK) return r;
	matter_im_blocks_clear(&s->items); free(s->plan); free(s->input); free(s->output); free(s->filters); if(s->events) { matter_events_snapshot_clear(&s->events->records); matter_im_event_metadata_clear(&s->events->expansion,&s->events->paths,&s->events->filters); } matter_events_snapshot_clear(&s->event_tail); free(s->events); matter_im_snapshots_clear(&s->snapshots); matter_im_workspace_delete(s->work,sizeof(*s->work)); free(s->requests); memset(s,0,sizeof(*s)); free(s); return MATTER_OK;
}

Matter_Im_Read_T matter_im_read_new_case(const Matter_Im_Read_Port_T* p,const Matter_Im_Read_Fabric_Port_T* f,
    const Matter_Im_Read_Config_T* c,uint64_t now) {
    if(!c || c->pase_commissionee || !f || !f->index) return NULL;
    /* Reuse allocation/preflight; legacy flag admits only the original PASE API. */
    Matter_Im_Read_Config_T config=*c; config.pase_commissionee=true;
    Matter_Im_Read_T s=matter_im_read_new_fabric(p,f,&config,now);
    if(s) { s->config=*c; s->case_session=true; } return s;
}
