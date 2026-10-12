#include "matter_im_write.h"
#include "../codec/matter_tlv_validate.h"
#include <stdlib.h>
#include <string.h>

struct Matter_Im_Write {
    Matter_Im_Write_Port_T port;
    Matter_Im_Read_Fabric_Port_T fabric; uint8_t fabric_index; bool fabric_resolved;
    Matter_Im_Write_Config_T config;
    Matter_Im_Write_State_T state;
    uint64_t now, deadline, received_at, timed_deadline;
    bool busy, queued, suppress, timed, timed_status, has_version;
    bool more, chunked, append, list_value, acl_list_authorized;
    unsigned chunks, block_count;
    Matter_Tlv_Element_T blocks[4]; Matter_Im_Write_Result_T results[4];
    uint16_t timed_timeout;
    uint32_t expected_version;
    uint8_t opcode, request_opcode;
    size_t input_size, value_size, output_size;
    Matter_Im_Path_T path;
    Matter_Im_Path_T list_path;
    Matter_Im_Write_Attribute_T attribute;
    Matter_Im_Write_Result_T result;
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Writer_T writer;
    Matter_Tlv_Element_T token, root[4], fields[3], path_fields[8], revision;
    Matter_Tlv_Validation_Workspace_T validation;
    Matter_Tlv_Tag_T tags[48];
    uint8_t input[1024], value[1024], output[256];
};
static Matter_Result_T check(Matter_Im_Write_T s) { return !s ? MATTER_INVALID_ARGUMENT : s->busy ? MATTER_BUSY : MATTER_OK; }
Matter_Im_Write_T matter_im_write_new(const Matter_Im_Write_Port_T* p,const Matter_Im_Write_Config_T* c,uint64_t now) {
	if (!p || !c || !p->authorize || !p->describe || !p->validate || !p->write || !p->version || !c->exchange.session ||
		(!!p->validate_list != !!p->write_list) ||
		c->exchange.initiator || !c->pase_commissionee || !c->timeout_ms || c->output_capacity<8 || c->output_capacity>1024) return NULL;
	Matter_Im_Write_T s=calloc(1,sizeof(*s));
	if (s) { s->port=*p; s->config=*c; s->now=now; s->deadline=UINT64_MAX-now<c->timeout_ms ? UINT64_MAX : now+c->timeout_ms; }
	return s;
}
Matter_Result_T matter_im_write_receive_at(Matter_Im_Write_T s,const Matter_Rx_Decision_T* d,uint64_t now) {
	Matter_Result_T r=check(s); if (r!=MATTER_OK) return r;
	if (!d || (!d->payload && d->payload_size)) return MATTER_INVALID_ARGUMENT;
	if (now<s->now) return MATTER_INVALID_ARGUMENT;
	bool continuation=(s->timed_status || s->more) && (s->state==MATTER_IM_WRITE_IN_FLIGHT ||
		s->state==MATTER_IM_WRITE_WAIT_WRITE || s->state==MATTER_IM_WRITE_WAIT_CHUNK);
	if (s->state!=MATTER_IM_WRITE_WAITING && !continuation) return MATTER_INVALID_STATE;
	if (s->queued) return MATTER_WOULD_BLOCK;
	if (d->session!=s->config.exchange.session || d->header.exchange_id!=s->config.exchange.exchange_id ||
		d->header.vendor_id || d->header.protocol_id!=1 ||
		(d->header.opcode!=6 && d->header.opcode!=10 && !(continuation && d->header.opcode==8)) ||
		!(d->header.exchange_flags & MATTER_PROTOCOL_INITIATOR) || d->standalone_ack ||
		(d->action!=MATTER_RX_NEW_RESPONDER && d->action!=MATTER_RX_EXISTING)) return MATTER_INVALID_ARGUMENT;
	if (d->payload_size>sizeof(s->input)) return MATTER_LIMIT_REACHED;
	if (d->payload_size) memcpy(s->input,d->payload,d->payload_size);
	s->input_size=d->payload_size; s->request_opcode=d->header.opcode;
	s->now=s->received_at=now; s->queued=true; return MATTER_OK;
}
static bool container(Matter_Tlv_Type_T t) { return t==MATTER_TLV_STRUCTURE || t==MATTER_TLV_ARRAY || t==MATTER_TLV_LIST; }
static bool next(Matter_Im_Write_T s) { return matter_tlv_next(&s->reader,&s->token)==MATTER_TLV_OK; }
static bool enter(Matter_Im_Write_T s,const Matter_Tlv_Element_T* e) {
	if (matter_tlv_init(&s->reader,s->input,s->input_size,8)!=MATTER_TLV_OK) return false;
	do { if (!next(s)) return false; } while (s->token.offset<e->offset);
	return s->token.offset==e->offset;
}
static uint8_t validate_tlv(Matter_Im_Write_T s,const uint8_t* data,size_t size,uint8_t depth) {
	const Matter_Tlv_Validation_Options_T opt={1024,256,2048,depth,false,0,0};
	Matter_Tlv_Validation_Report_T report;
	Matter_Tlv_Result_T r=matter_tlv_validate(data,size,&opt,&s->validation,s->tags,48,&report);
	return r==MATTER_TLV_OK ? 0 : r==MATTER_TLV_LIMIT_REACHED || r==MATTER_TLV_DEPTH_LIMIT ? MATTER_IM_RESOURCE_EXHAUSTED : MATTER_IM_INVALID_ACTION;
}
/* Current token is container open; duplicate known LIST fields need an explicit
 * check since generic TLV only enforces uniqueness for STRUCTURE. */
static bool collect(Matter_Im_Write_T s,Matter_Tlv_Element_T* out,size_t count) {
	memset(out,0,count*sizeof(*out));
	while (next(s)) {
		if (s->token.type==MATTER_TLV_END) return true;
		if (s->token.tag.control!=1) return false;
		uint32_t tag=s->token.tag.number;
		if (tag<count) { if (out[tag].tag.control) return false; out[tag]=s->token; }
		if (out==s->root && tag==255) s->revision=s->token;
		if (container(s->token.type) && matter_tlv_skip_container(&s->reader)!=MATTER_TLV_OK) return false;
	}
	return false;
}
static bool number(const Matter_Tlv_Element_T* e,uint64_t max) {
	return e->tag.control==1 && e->type==MATTER_TLV_UNSIGNED && e->unsigned_value<=max;
}
static uint8_t decode_item(Matter_Im_Write_T s,unsigned index) {
    if(!enter(s,&s->blocks[index]) || !collect(s,s->fields,3)) return MATTER_IM_INVALID_ACTION;
    s->has_version=s->fields[0].tag.control!=0;
    if (s->has_version && !number(&s->fields[0],UINT32_MAX)) return MATTER_IM_INVALID_ACTION;
    s->expected_version=(uint32_t)s->fields[0].unsigned_value;
    if (!s->fields[1].tag.control || s->fields[1].type!=MATTER_TLV_LIST ||
        !s->fields[2].tag.control || s->fields[2].type==MATTER_TLV_LIST ||
        !enter(s,&s->fields[1]) || !collect(s,s->path_fields,8)) return MATTER_IM_INVALID_ACTION;
    if ((s->path_fields[0].tag.control && (s->path_fields[0].type!=MATTER_TLV_BOOL || s->path_fields[0].unsigned_value)) ||
        s->path_fields[1].tag.control || (s->path_fields[5].tag.control && s->path_fields[5].type!=MATTER_TLV_NULL) ||
        (s->path_fields[6].tag.control && (!number(&s->path_fields[6],UINT32_MAX) || s->path_fields[6].unsigned_value)) ||
        (s->path_fields[7].tag.control && !number(&s->path_fields[7],UINT32_MAX)) ||
        !number(&s->path_fields[2],UINT16_MAX) || !number(&s->path_fields[3],UINT32_MAX) ||
        !number(&s->path_fields[4],UINT32_MAX)) return MATTER_IM_INVALID_ACTION;
    s->path=(Matter_Im_Path_T){(uint16_t)s->path_fields[2].unsigned_value,
        (uint32_t)s->path_fields[3].unsigned_value,(uint32_t)s->path_fields[4].unsigned_value};
    s->append=s->path_fields[5].tag.control!=0;
    s->list_value=s->append || s->fields[2].type==MATTER_TLV_ARRAY;
    if ((s->more || s->chunked) && !s->list_value) return MATTER_IM_INVALID_ACTION;
    if (s->chunked && (s->path.endpoint!=s->list_path.endpoint || s->path.cluster!=s->list_path.cluster ||
        s->path.attribute!=s->list_path.attribute)) return MATTER_IM_INVALID_ACTION;
    return 0;
}
static uint8_t decode(Matter_Im_Write_T s) {
    memset(&s->revision,0,sizeof(s->revision));
    uint8_t code=validate_tlv(s,s->input,s->input_size,8); if (code) return code;
    if (matter_tlv_init(&s->reader,s->input,s->input_size,8)!=MATTER_TLV_OK || !next(s) ||
        s->token.type!=MATTER_TLV_STRUCTURE || s->token.tag.control || !collect(s,s->root,4) ||
        !number(&s->revision,UINT8_MAX) || !s->revision.unsigned_value) return MATTER_IM_INVALID_ACTION;
    if (s->request_opcode==10) {
        if (s->timed || s->chunked || !number(&s->root[0],UINT16_MAX)) return MATTER_IM_INVALID_ACTION;
        s->timed_timeout=(uint16_t)s->root[0].unsigned_value; return 0;
    }
    if (s->request_opcode!=6) return MATTER_IM_INVALID_ACTION;
    if (s->timed && s->received_at>=s->timed_deadline) return MATTER_IM_TIMEOUT;
    if ((s->root[0].tag.control && s->root[0].type!=MATTER_TLV_BOOL) ||
        !s->root[1].tag.control || s->root[1].type!=MATTER_TLV_BOOL ||
        !s->root[2].tag.control || s->root[2].type!=MATTER_TLV_ARRAY ||
        (s->root[3].tag.control && s->root[3].type!=MATTER_TLV_BOOL)) return MATTER_IM_INVALID_ACTION;
    s->suppress=s->root[0].tag.control && s->root[0].unsigned_value;
    s->more=s->root[3].tag.control && s->root[3].unsigned_value;
    if ((s->root[1].unsigned_value!=0)!=s->timed) return MATTER_IM_TIMED_REQUEST_MISMATCH;
    if (s->more && (s->timed || s->suppress)) return MATTER_IM_INVALID_ACTION;
    s->block_count=0;
    if(!enter(s,&s->root[2])) return MATTER_IM_INVALID_ACTION;
    while(next(s) && s->token.type!=MATTER_TLV_END) {
        if(s->token.type!=MATTER_TLV_STRUCTURE || s->token.tag.control) return MATTER_IM_INVALID_ACTION;
        if(s->block_count==4) return MATTER_IM_RESOURCE_EXHAUSTED;
        s->blocks[s->block_count++]=s->token;
        if(matter_tlv_skip_container(&s->reader)!=MATTER_TLV_OK) return MATTER_IM_INVALID_ACTION;
    }
    if(!s->block_count || s->token.type!=MATTER_TLV_END) return MATTER_IM_INVALID_ACTION;
    /* Preflight ALL shapes before any callbacks. Same-path list IBs must reach
     * access/lookup even without a list writer (e.g. read-only NOCs over PASE).
     * Writable profiles remain bounded separately in execute(). */
    Matter_Im_Path_T first={0};
    for(unsigned i=0;i<s->block_count;++i) {
        code=decode_item(s,i); if(code) return code;
        if(s->block_count>1) {
            if(!s->list_value) return MATTER_IM_INVALID_ACTION;
            if(i && (s->path.endpoint!=first.endpoint || s->path.cluster!=first.cluster || s->path.attribute!=first.attribute)) return MATTER_IM_INVALID_ACTION;
        }
        first=s->path;
    }
    if (s->chunks==MATTER_IM_WRITE_MAX_CHUNKS) return MATTER_IM_RESOURCE_EXHAUSTED;
    ++s->chunks;
    if (s->more && !s->chunked) { s->chunked=true; s->list_path=s->path; }
    return 0;
}
static bool put(Matter_Im_Write_T s,Matter_Tlv_Type_T type,int tag,uint64_t value) {
	s->token=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0 ? 0 : 1,.number=tag<0 ? 0 : (uint32_t)tag},.unsigned_value=value};
	return matter_tlv_write(&s->writer,&s->token,0)==MATTER_TLV_OK;
}
static bool end(Matter_Im_Write_T s) { return put(s,MATTER_TLV_END,-1,0); }
static bool begin(Matter_Im_Write_T s) {
	return matter_tlv_writer_init(&s->writer,s->output,sizeof(s->output),8)==MATTER_TLV_OK && put(s,MATTER_TLV_STRUCTURE,-1,0);
}
static bool finish(Matter_Im_Write_T s) {
	return put(s,MATTER_TLV_UNSIGNED,255,MATTER_IM_REVISION) && end(s) && matter_tlv_writer_finish(&s->writer,&s->output_size)==MATTER_TLV_OK;
}
static bool status(Matter_Im_Write_T s,uint8_t code) { s->opcode=1; return begin(s) && put(s,MATTER_TLV_UNSIGNED,0,code) && finish(s); }
static bool response(Matter_Im_Write_T s) {
    s->opcode=7;
    return begin(s) && put(s,MATTER_TLV_ARRAY,0,0) && put(s,MATTER_TLV_STRUCTURE,-1,0) &&
        put(s,MATTER_TLV_LIST,0,0) && put(s,MATTER_TLV_UNSIGNED,2,s->path.endpoint) &&
        /* ListIndex=null is only valid in AttributeDataIB (Core 10.6.2.4).
         * Status reports the concrete attribute, not an append operation. */
        put(s,MATTER_TLV_UNSIGNED,3,s->path.cluster) && put(s,MATTER_TLV_UNSIGNED,4,s->path.attribute) && end(s) &&
        put(s,MATTER_TLV_STRUCTURE,1,0) && put(s,MATTER_TLV_UNSIGNED,0,s->result.status) &&
        (!s->result.has_cluster_status || put(s,MATTER_TLV_UNSIGNED,1,s->result.cluster_status)) &&
        end(s) && end(s) && end(s) && finish(s);
}
static bool responses(Matter_Im_Write_T s) {
    if(s->block_count==1) return response(s);
    s->opcode=7;
    if(!begin(s) || !put(s,MATTER_TLV_ARRAY,0,0)) return false;
    for(unsigned i=0;i<s->block_count;++i) {
        const Matter_Im_Write_Result_T* r=&s->results[i];
        if(!put(s,MATTER_TLV_STRUCTURE,-1,0) || !put(s,MATTER_TLV_LIST,0,0) || !put(s,MATTER_TLV_UNSIGNED,2,s->path.endpoint) ||
            !put(s,MATTER_TLV_UNSIGNED,3,s->path.cluster) || !put(s,MATTER_TLV_UNSIGNED,4,s->path.attribute) || !end(s) ||
            !put(s,MATTER_TLV_STRUCTURE,1,0) || !put(s,MATTER_TLV_UNSIGNED,0,r->status) ||
            (r->has_cluster_status && !put(s,MATTER_TLV_UNSIGNED,1,r->cluster_status)) || !end(s) || !end(s)) return false;
    }
    return end(s) && finish(s);
}
static uint8_t value(Matter_Im_Write_T s) {
    if (!enter(s,&s->fields[2]) || matter_tlv_writer_init(&s->writer,s->value,sizeof(s->value),4)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
    unsigned depth=0;
    do {
        if (!depth) s->token.tag=(Matter_Tlv_Tag_T){0};
        if (container(s->token.type)) ++depth;
        if (s->token.type==MATTER_TLV_END) --depth;
        Matter_Tlv_Result_T r=matter_tlv_write(&s->writer,&s->token,0);
        if (r!=MATTER_TLV_OK) return r==MATTER_TLV_DEPTH_LIMIT || r==MATTER_TLV_NO_SPACE ? MATTER_IM_RESOURCE_EXHAUSTED : MATTER_IM_INVALID_DATA_TYPE;
        if (!depth) break;
    } while (next(s));
    return matter_tlv_writer_finish(&s->writer,&s->value_size)==MATTER_TLV_OK ? 0 : MATTER_IM_INVALID_DATA_TYPE;
}
static uint8_t authorize(Matter_Im_Write_T s,Matter_Im_Privilege_T p) {
    if(s->fabric.index) {
        uint8_t index=0;
        if(s->fabric.index(s->port.user,s->config.exchange.session,&index)!=MATTER_OK || !index || index==255 ||
            (s->fabric_resolved && index!=s->fabric_index)) return MATTER_IM_UNSUPPORTED_ACCESS;
        s->fabric_index=index; s->fabric_resolved=true;
    }
    /* A legacy ACL replacement can clear its own grant before the append IBs.
     * Continue only the same preflighted list in this message after a successful
     * write; never reuse this grant for another message, path or fabric. */
    if(s->acl_list_authorized && s->append) return 0;
	uint8_t code=s->port.authorize(s->port.user,s->config.exchange.session,&s->path,p);
	return !code || code==MATTER_IM_UNSUPPORTED_ACCESS || code==MATTER_IM_ACCESS_RESTRICTED ? code : MATTER_IM_FAILURE;
}
static uint8_t execute(Matter_Im_Write_T s) {
    uint8_t code=authorize(s,MATTER_IM_VIEW); if (code) return code;
    code=s->port.describe(s->port.user,&s->path,&s->attribute);
    if (code) return code==MATTER_IM_UNSUPPORTED_ENDPOINT || code==MATTER_IM_UNSUPPORTED_CLUSTER ||
        code==MATTER_IM_UNSUPPORTED_ATTRIBUTE || code==MATTER_IM_UNSUPPORTED_WRITE ? code : MATTER_IM_FAILURE;
    if (s->attribute.privilege!=MATTER_IM_OPERATE && s->attribute.privilege!=MATTER_IM_MANAGE &&
        s->attribute.privilege!=MATTER_IM_ADMINISTER) return MATTER_IM_FAILURE;
    code=authorize(s,s->attribute.privilege); if (code) return code;
    if (s->attribute.timed && !s->timed) return MATTER_IM_NEEDS_TIMED_INTERACTION;
    if (s->attribute.fabric_scoped && !s->fabric_index) return MATTER_IM_UNSUPPORTED_ACCESS;
    if (s->attribute.list && (!s->port.write_list || !s->list_value)) return MATTER_IM_UNSUPPORTED_WRITE;
    if (s->list_value && !s->attribute.list) return MATTER_IM_INVALID_DATA_TYPE;
    /* These are implementation limits on writable list operations, not TLV
     * syntax errors. Lookup/ACL above must first report read-only/absent paths. */
    if (s->block_count>1 && !(s->fabric.index && (s->path.cluster==0x1f || s->path.cluster==0x2a) && !s->path.attribute)) return MATTER_IM_INVALID_ACTION;
    if (!s->append && s->list_value && !(s->fabric.index && (s->path.cluster==0x1f || s->path.cluster==0x2a) && !s->path.attribute) &&
        (!enter(s,&s->fields[2]) || !next(s) || s->token.type!=MATTER_TLV_END)) return MATTER_IM_INVALID_ACTION;
    if (s->has_version) {
        uint32_t current;
        if (s->port.version(s->port.user,&s->path,&current)!=MATTER_OK) return MATTER_IM_FAILURE;
        if (current!=s->expected_version) return MATTER_IM_DATA_VERSION_MISMATCH;
    }
    code=value(s); if (code) return code;
    Matter_Im_List_Change_T change=s->append ? MATTER_IM_LIST_ADD : MATTER_IM_LIST_REPLACE;
    code=s->list_value ? s->port.validate_list(s->port.user,&s->path,change,s->value,s->value_size) :
        s->port.validate(s->port.user,&s->path,s->value,s->value_size);
    if (code) return code==MATTER_IM_INVALID_DATA_TYPE || code==MATTER_IM_CONSTRAINT_ERROR || code==MATTER_IM_RESOURCE_EXHAUSTED ? code : MATTER_IM_FAILURE;
    /* Reserve largest possible status BEFORE side effects; no callback on retry. */
    s->result=(Matter_Im_Write_Result_T){UINT8_MAX,true,UINT8_MAX};
    if (!s->suppress && (!response(s) || s->output_size>s->config.output_capacity)) return MATTER_IM_RESOURCE_EXHAUSTED;
    s->result=s->list_value ? s->port.write_list(s->port.user,&s->path,change,s->value,s->value_size) :
        s->port.write(s->port.user,&s->path,s->value,s->value_size);
    return 0;
}
static Matter_Result_T clock_check(Matter_Im_Write_T s,uint64_t now) {
	if (now<s->now) return MATTER_INVALID_ARGUMENT;
	s->now=now;
	if (now>=s->deadline) { s->state=MATTER_IM_WRITE_FAILED; s->queued=false; s->output_size=0; return MATTER_PORT_ERROR; }
	return MATTER_OK;
}
Matter_Result_T matter_im_write_process(Matter_Im_Write_T s,uint64_t now) {
	Matter_Result_T r=check(s); if (r!=MATTER_OK) return r;
	if (now<s->now) return MATTER_INVALID_ARGUMENT;
	s->now=now;
	if (s->state==MATTER_IM_WRITE_COMPLETE) return MATTER_OK;
	if (s->state==MATTER_IM_WRITE_FAILED) return MATTER_INVALID_STATE;
	r=clock_check(s,now); if (r!=MATTER_OK) return r;
	if (!s->queued || s->state==MATTER_IM_WRITE_IN_FLIGHT) return MATTER_PENDING;
	s->busy=true; s->queued=false;
	uint8_t code=decode(s); bool encoded;
	s->timed_status=!code && s->request_opcode==10;
	if (code || s->timed_status) { s->more=false; encoded=status(s,code); }
	else {
        bool capacity=true;
        if(s->block_count>1 && !s->suppress) {
            for(unsigned i=0;i<s->block_count;++i) s->results[i]=(Matter_Im_Write_Result_T){UINT8_MAX,true,UINT8_MAX};
            capacity=responses(s) && s->output_size<=s->config.output_capacity;
        }
        s->acl_list_authorized=false;
        for(unsigned i=0;i<s->block_count;++i) {
            code=decode_item(s,i); /* Already preflighted immutable input. */
            if(!code) code=capacity?execute(s):MATTER_IM_RESOURCE_EXHAUSTED;
            if(code) s->result=(Matter_Im_Write_Result_T){.status=code};
            s->results[i]=s->result;
            s->acl_list_authorized=s->fabric.index && s->path.cluster==0x1f && !s->path.attribute &&
                !s->result.status && s->attribute.list;
        }
        s->acl_list_authorized=false;
		if (s->suppress) { s->output_size=0; s->state=MATTER_IM_WRITE_COMPLETE; s->busy=false; return MATTER_OK; }
		encoded=responses(s);
		if (!encoded || s->output_size>s->config.output_capacity) { s->more=false; encoded=status(s,MATTER_IM_RESOURCE_EXHAUSTED); }
	}
	s->state=encoded ? MATTER_IM_WRITE_OUTPUT : MATTER_IM_WRITE_FAILED;
	s->busy=false; return encoded ? MATTER_PENDING : MATTER_PORT_ERROR;
}
Matter_Result_T matter_im_write_output(Matter_Im_Write_T s,Matter_Im_Write_Message_T* m) {
	Matter_Result_T r=check(s); if (r!=MATTER_OK) return r;
	if (!m) return MATTER_INVALID_ARGUMENT;
	if (s->state!=MATTER_IM_WRITE_OUTPUT) return MATTER_INVALID_STATE;
	*m=(Matter_Im_Write_Message_T){s->output,s->output_size,s->opcode}; return MATTER_OK;
}
bool matter_im_write_awaiting_delivery(Matter_Im_Write_T s) {
    return s && !s->busy && s->state==MATTER_IM_WRITE_IN_FLIGHT && !s->timed_status && !s->more;
}
Matter_Result_T matter_im_write_sent_at(Matter_Im_Write_T s,uint64_t now) {
	Matter_Result_T r=check(s); if (r!=MATTER_OK) return r;
	if (s->state!=MATTER_IM_WRITE_OUTPUT) return MATTER_INVALID_STATE;
	r=clock_check(s,now); if (r!=MATTER_OK) return r;
	if (s->timed_status) {
		s->timed=true;
		s->timed_deadline=UINT64_MAX-now<s->timed_timeout ? UINT64_MAX : now+s->timed_timeout;
	}
	s->state=MATTER_IM_WRITE_IN_FLIGHT; return MATTER_OK;
}
Matter_Result_T matter_im_write_confirm(Matter_Im_Write_T s,uint64_t now) {
	Matter_Result_T r=check(s); if (r!=MATTER_OK) return r;
	if (s->state!=MATTER_IM_WRITE_IN_FLIGHT) return MATTER_INVALID_STATE;
	r=clock_check(s,now); if (r!=MATTER_OK) return r;
	s->state=s->timed_status ? MATTER_IM_WRITE_WAIT_WRITE : s->more ? MATTER_IM_WRITE_WAIT_CHUNK : MATTER_IM_WRITE_COMPLETE; return MATTER_OK;
}
Matter_Result_T matter_im_write_cancel(Matter_Im_Write_T s) {
	Matter_Result_T r=check(s); if (r!=MATTER_OK) return r;
	if (s->state!=MATTER_IM_WRITE_COMPLETE) s->state=MATTER_IM_WRITE_FAILED;
	s->queued=false; s->output_size=0; return MATTER_OK;
}
Matter_Im_Write_State_T matter_im_write_state(Matter_Im_Write_T s) { return s ? s->state : MATTER_IM_WRITE_FAILED; }
Matter_Result_T matter_im_write_delete(Matter_Im_Write_T s) {
	if (!s) return MATTER_OK;
	Matter_Result_T r=check(s); if (r!=MATTER_OK) return r;
	memset(s,0,sizeof(*s)); free(s); return MATTER_OK;
}

Matter_Im_Write_T matter_im_write_new_case(const Matter_Im_Write_Port_T* p,const Matter_Im_Read_Fabric_Port_T* f,
    const Matter_Im_Write_Config_T* c,uint64_t now) {
    if(!c || c->pase_commissionee || !f || !f->index) return NULL;
    Matter_Im_Write_Config_T config=*c; config.pase_commissionee=true;
    Matter_Im_Write_T s=matter_im_write_new(p,&config,now);
    if(s) { s->config=*c; s->fabric=*f; } return s;
}
