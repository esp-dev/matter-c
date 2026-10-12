#include "matter_im_invoke.h"
#include "../codec/matter_tlv_validate.h"
#include <stdlib.h>
#include <string.h>

struct Matter_Im_Invoke {
	Matter_Im_Invoke_Port_T port;
	Matter_Im_Invoke_Async_Port_T async;
    Matter_Im_Read_Fabric_Port_T fabric; uint8_t fabric_index; bool fabric_resolved, case_session;
	uint64_t pending_token;
	Matter_Im_Invoke_Config_T config;
	Matter_Im_Invoke_State_T state;
	uint64_t now, deadline, received_at, timed_deadline;
	bool busy, queued, suppress, has_ref, timed, timed_status;
	uint16_t ref, timed_timeout;
	uint8_t opcode, request_opcode;
	size_t input_size, args_size, body_size, output_size;
	Matter_Im_Command_Path_T path;
	Matter_Im_Command_T command;
	Matter_Im_Command_Result_T result;
	Matter_Tlv_Reader_T reader;
	Matter_Tlv_Writer_T writer, body_writer;
	Matter_Tlv_Element_T token, root[3], fields[3], path_fields[3], revision;
	Matter_Tlv_Validation_Workspace_T validation;
	Matter_Tlv_Tag_T tags[48];
	uint8_t input[1024], args[1024], body[1024], output[1024];
};
static Matter_Result_T check(Matter_Im_Invoke_T s) { return !s ? MATTER_INVALID_ARGUMENT : s->busy ? MATTER_BUSY : MATTER_OK; }
Matter_Im_Invoke_T matter_im_invoke_new(const Matter_Im_Invoke_Port_T* p,const Matter_Im_Invoke_Config_T* c,uint64_t now) {
	if (!p || !c || !p->authorize || !p->describe || !p->validate || !p->invoke || !c->exchange.session ||
		c->exchange.initiator || !c->pase_commissionee || !c->timeout_ms || c->output_capacity<8 || c->output_capacity>1024) return NULL;
	Matter_Im_Invoke_T s=calloc(1,sizeof(*s));
	if (s) { s->port=*p; s->config=*c; s->now=now; s->deadline=UINT64_MAX-now<c->timeout_ms ? UINT64_MAX : now+c->timeout_ms; }
	return s;
}
Matter_Im_Invoke_T matter_im_invoke_new_async(const Matter_Im_Invoke_Port_T* p,
    const Matter_Im_Invoke_Async_Port_T* a,const Matter_Im_Invoke_Config_T* c,uint64_t now) {
    if (!a || !a->start || !a->poll || !a->cancel) return NULL;
    Matter_Im_Invoke_T s=matter_im_invoke_new(p,c,now); if (s) s->async=*a; return s;
}
static void cancel_pending(Matter_Im_Invoke_T s) {
    if (s->pending_token) {
        uint64_t token=s->pending_token; s->pending_token=0;
        s->busy=true; s->async.cancel(s->port.user,token); s->busy=false;
    }
}
static void erase(void* data,size_t n) { volatile uint8_t* p=data; while(n--) *p++=0; }
Matter_Result_T matter_im_invoke_receive(Matter_Im_Invoke_T s,const Matter_Rx_Decision_T* d) {
	Matter_Result_T r=check(s); if (r!=MATTER_OK) return r;
	if (!d || (!d->payload && d->payload_size) || s->timed) return MATTER_INVALID_ARGUMENT;
	/* Preserve the untimed API's state/queue error precedence. */
	if (s->state!=MATTER_IM_INVOKE_WAITING) return MATTER_INVALID_STATE;
	if (s->queued) return MATTER_WOULD_BLOCK;
	if (d->header.opcode!=8) return MATTER_INVALID_ARGUMENT;
	return matter_im_invoke_receive_at(s,d,s->now);
}
Matter_Result_T matter_im_invoke_receive_at(Matter_Im_Invoke_T s,const Matter_Rx_Decision_T* d,uint64_t now) {
	Matter_Result_T r=check(s); if (r!=MATTER_OK) return r;
	if (!d || (!d->payload && d->payload_size)) return MATTER_INVALID_ARGUMENT;
	if (now<s->now) return MATTER_INVALID_ARGUMENT;
	bool continuation=s->timed_status && (s->state==MATTER_IM_INVOKE_IN_FLIGHT || s->state==MATTER_IM_INVOKE_WAIT_INVOKE);
	if (s->state!=MATTER_IM_INVOKE_WAITING && !continuation) return MATTER_INVALID_STATE;
	if (s->queued) return MATTER_WOULD_BLOCK;
	if (d->session!=s->config.exchange.session || d->header.exchange_id!=s->config.exchange.exchange_id ||
		d->header.vendor_id || d->header.protocol_id!=1 ||
		(d->header.opcode!=8 && d->header.opcode!=10 && !(continuation && d->header.opcode==6)) ||
		!(d->header.exchange_flags & MATTER_PROTOCOL_INITIATOR) || d->standalone_ack ||
		(d->action!=MATTER_RX_NEW_RESPONDER && d->action!=MATTER_RX_EXISTING)) return MATTER_INVALID_ARGUMENT;
	if (d->payload_size>sizeof(s->input)) return MATTER_LIMIT_REACHED;
	if (d->payload_size) memcpy(s->input,d->payload,d->payload_size);
	s->input_size=d->payload_size; s->request_opcode=d->header.opcode;
	s->now=s->received_at=now; s->queued=true; return MATTER_OK;
}
static bool container(Matter_Tlv_Type_T t) { return t==MATTER_TLV_STRUCTURE || t==MATTER_TLV_ARRAY || t==MATTER_TLV_LIST; }
static bool next(Matter_Im_Invoke_T s) { return matter_tlv_next(&s->reader,&s->token)==MATTER_TLV_OK; }
static bool enter(Matter_Im_Invoke_T s,const Matter_Tlv_Element_T* e) {
	if (matter_tlv_init(&s->reader,s->input,s->input_size,8)!=MATTER_TLV_OK) return false;
	do { if (!next(s)) return false; } while (s->token.offset<e->offset);
	return s->token.offset==e->offset;
}
static uint8_t validate_tlv(Matter_Im_Invoke_T s,const uint8_t* data,size_t size,uint8_t depth) {
	const Matter_Tlv_Validation_Options_T opt={1024,256,2048,depth,false,0,0};
	Matter_Tlv_Validation_Report_T report;
	Matter_Tlv_Result_T r=matter_tlv_validate(data,size,&opt,&s->validation,s->tags,48,&report);
	return r==MATTER_TLV_OK ? 0 : r==MATTER_TLV_LIMIT_REACHED || r==MATTER_TLV_DEPTH_LIMIT ? MATTER_IM_RESOURCE_EXHAUSTED : MATTER_IM_INVALID_ACTION;
}
/* Current token is container open; duplicate known LIST fields need an explicit
 * check since generic TLV only enforces uniqueness for STRUCTURE. */
static bool collect(Matter_Im_Invoke_T s,Matter_Tlv_Element_T* out) {
	memset(out,0,3*sizeof(*out));
	while (next(s)) {
		if (s->token.type==MATTER_TLV_END) return true;
		if (s->token.tag.control!=1) return false;
		uint32_t tag=s->token.tag.number;
		if (tag<3) { if (out[tag].tag.control) return false; out[tag]=s->token; }
		if (out==s->root && tag==255) s->revision=s->token;
		if (container(s->token.type) && matter_tlv_skip_container(&s->reader)!=MATTER_TLV_OK) return false;
	}
	return false;
}
static bool number(const Matter_Tlv_Element_T* e,uint64_t max) {
	return e->tag.control==1 && e->type==MATTER_TLV_UNSIGNED && e->unsigned_value<=max;
}
static uint8_t decode(Matter_Im_Invoke_T s) {
	memset(&s->revision,0,sizeof(s->revision)); /* Two documents share this workspace. */
	uint8_t code=validate_tlv(s,s->input,s->input_size,8); if (code) return code;
	if (matter_tlv_init(&s->reader,s->input,s->input_size,8)!=MATTER_TLV_OK || !next(s) ||
		s->token.type!=MATTER_TLV_STRUCTURE || s->token.tag.control || !collect(s,s->root) ||
		!number(&s->revision,UINT8_MAX) || !s->revision.unsigned_value) return MATTER_IM_INVALID_ACTION;
	if (s->request_opcode==10) {
		if (s->timed || !number(&s->root[0],UINT16_MAX)) return MATTER_IM_INVALID_ACTION;
		s->timed_timeout=(uint16_t)s->root[0].unsigned_value; return 0;
	}
	if (s->request_opcode!=8) return MATTER_IM_INVALID_ACTION;
	if (s->timed && s->received_at>=s->timed_deadline) return MATTER_IM_TIMEOUT;
	if (!s->root[0].tag.control || s->root[0].type!=MATTER_TLV_BOOL ||
		!s->root[1].tag.control || s->root[1].type!=MATTER_TLV_BOOL ||
		!s->root[2].tag.control || s->root[2].type!=MATTER_TLV_ARRAY) return MATTER_IM_INVALID_ACTION;
	s->suppress=s->root[0].unsigned_value!=0;
	if ((s->root[1].unsigned_value!=0)!=s->timed) return MATTER_IM_TIMED_REQUEST_MISMATCH;
	if (!enter(s,&s->root[2]) || !next(s) || s->token.type!=MATTER_TLV_STRUCTURE || s->token.tag.control ||
		!collect(s,s->fields) || !next(s) || s->token.type!=MATTER_TLV_END) return MATTER_IM_INVALID_ACTION;
	if (!s->fields[0].tag.control || s->fields[0].type!=MATTER_TLV_LIST || !enter(s,&s->fields[0]) ||
		!collect(s,s->path_fields) || !number(&s->path_fields[0],UINT16_MAX) ||
		!number(&s->path_fields[1],UINT32_MAX) || !number(&s->path_fields[2],UINT32_MAX)) return MATTER_IM_INVALID_ACTION;
	s->path=(Matter_Im_Command_Path_T){(uint16_t)s->path_fields[0].unsigned_value,
		(uint32_t)s->path_fields[1].unsigned_value,(uint32_t)s->path_fields[2].unsigned_value};
	s->has_ref=s->fields[2].tag.control!=0;
	if (s->has_ref && !number(&s->fields[2],UINT16_MAX)) return MATTER_IM_INVALID_ACTION;
	s->ref=(uint16_t)s->fields[2].unsigned_value; return 0;
}
static bool put(Matter_Im_Invoke_T s,Matter_Tlv_Type_T type,int tag,uint64_t value) {
	s->token=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0 ? 0 : 1,.number=tag<0 ? 0 : (uint32_t)tag},.unsigned_value=value};
	return matter_tlv_write(&s->writer,&s->token,0)==MATTER_TLV_OK;
}
static bool end(Matter_Im_Invoke_T s) { return put(s,MATTER_TLV_END,-1,0); }
static bool begin(Matter_Im_Invoke_T s) {
	return matter_tlv_writer_init(&s->writer,s->output,sizeof(s->output),8)==MATTER_TLV_OK && put(s,MATTER_TLV_STRUCTURE,-1,0);
}
static bool finish(Matter_Im_Invoke_T s) {
	return put(s,MATTER_TLV_UNSIGNED,255,MATTER_IM_REVISION) && end(s) && matter_tlv_writer_finish(&s->writer,&s->output_size)==MATTER_TLV_OK;
}
static bool status(Matter_Im_Invoke_T s,uint8_t code) { s->opcode=1; return begin(s) && put(s,MATTER_TLV_UNSIGNED,0,code) && finish(s); }
static bool response(Matter_Im_Invoke_T s,bool command) {
	s->opcode=9;
	if (!begin(s) || !put(s,MATTER_TLV_BOOL,0,1) || !put(s,MATTER_TLV_ARRAY,1,0) ||
		!put(s,MATTER_TLV_STRUCTURE,-1,0) || !put(s,MATTER_TLV_STRUCTURE,command ? 0 : 1,0) ||
		!put(s,MATTER_TLV_LIST,0,0) || !put(s,MATTER_TLV_UNSIGNED,0,s->path.endpoint) ||
		!put(s,MATTER_TLV_UNSIGNED,1,s->path.cluster) ||
		!put(s,MATTER_TLV_UNSIGNED,2,command ? s->command.response_command : s->path.command) || !end(s)) return false;
	if (command) {
		if (matter_tlv_init(&s->reader,s->body,s->body_size,4)!=MATTER_TLV_OK) return false;
		Matter_Tlv_Result_T r;
		while ((r=matter_tlv_next(&s->reader,&s->token))==MATTER_TLV_OK) {
			if (!s->token.offset) s->token.tag=(Matter_Tlv_Tag_T){.control=1,.number=1};
			if (matter_tlv_write(&s->writer,&s->token,0)!=MATTER_TLV_OK) return false;
		}
		if (r!=MATTER_TLV_DONE) return false;
	} else if (!put(s,MATTER_TLV_STRUCTURE,1,0) || !put(s,MATTER_TLV_UNSIGNED,0,s->result.status) ||
		(s->result.has_cluster_status && !put(s,MATTER_TLV_UNSIGNED,1,s->result.cluster_status)) || !end(s)) return false;
	return (!s->has_ref || put(s,MATTER_TLV_UNSIGNED,2,s->ref)) && end(s) && end(s) && end(s) && finish(s);
}
static uint8_t arguments(Matter_Im_Invoke_T s) {
	s->args[0]=0x15; s->args[1]=0x18; s->args_size=2;
	if (!s->fields[1].tag.control) return 0;
	if (s->fields[1].type!=MATTER_TLV_STRUCTURE || !enter(s,&s->fields[1])) return MATTER_IM_INVALID_COMMAND;
	if (matter_tlv_writer_init(&s->writer,s->args,sizeof(s->args),4)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
	unsigned depth=0;
	do {
		if (!depth) s->token.tag=(Matter_Tlv_Tag_T){0};
		if (container(s->token.type)) ++depth;
		if (s->token.type==MATTER_TLV_END) --depth;
		Matter_Tlv_Result_T r=matter_tlv_write(&s->writer,&s->token,0);
		if (r!=MATTER_TLV_OK) return r==MATTER_TLV_DEPTH_LIMIT || r==MATTER_TLV_NO_SPACE ? MATTER_IM_RESOURCE_EXHAUSTED : MATTER_IM_INVALID_COMMAND;
		if (!depth) break;
	} while (next(s));
	return matter_tlv_writer_finish(&s->writer,&s->args_size)==MATTER_TLV_OK ? 0 : MATTER_IM_INVALID_COMMAND;
}
static uint8_t authorize(Matter_Im_Invoke_T s,Matter_Im_Privilege_T p) {
	if(s->fabric.index) {
        uint8_t index=0;
        if(s->fabric.index(s->port.user,s->config.exchange.session,&index)!=MATTER_OK || index==255 ||
            (s->case_session && !index) || (s->fabric_resolved && index!=s->fabric_index)) return MATTER_IM_UNSUPPORTED_ACCESS;
        s->fabric_index=index; s->fabric_resolved=true;
    }
    uint8_t code=s->port.authorize(s->port.user,s->config.exchange.session,&s->path,p);
	return !code || code==MATTER_IM_UNSUPPORTED_ACCESS || code==MATTER_IM_ACCESS_RESTRICTED ? code : MATTER_IM_FAILURE;
}
static uint8_t execute(Matter_Im_Invoke_T s) {
	uint8_t code=authorize(s,MATTER_IM_OPERATE); if (code) return code;
	code=s->port.describe(s->port.user,&s->path,&s->command);
	if (code) return code==MATTER_IM_UNSUPPORTED_ENDPOINT || code==MATTER_IM_UNSUPPORTED_CLUSTER || code==MATTER_IM_UNSUPPORTED_COMMAND ? code : MATTER_IM_FAILURE;
	if (s->command.privilege!=MATTER_IM_OPERATE && s->command.privilege!=MATTER_IM_MANAGE && s->command.privilege!=MATTER_IM_ADMINISTER) return MATTER_IM_FAILURE;
	code=authorize(s,s->command.privilege); if (code) return code;
	if (s->command.large_message) return MATTER_IM_INVALID_TRANSPORT_TYPE;
	if (s->command.fabric_scoped && !s->fabric_index) return MATTER_IM_UNSUPPORTED_ACCESS;
	if (s->command.timed && !s->timed) return MATTER_IM_NEEDS_TIMED_INTERACTION;
	code=arguments(s); if (code) return code;
	code=s->port.validate(s->port.user,&s->path,s->args,s->args_size);
	if (code) return code==MATTER_IM_INVALID_COMMAND || code==MATTER_IM_CONSTRAINT_ERROR || code==MATTER_IM_RESOURCE_EXHAUSTED ? code : MATTER_IM_FAILURE;
	/* Reserve the largest status and declared command reply BEFORE side effects.
	 * There are no allocations or provider reads while sending/retrying. */
	s->result=(Matter_Im_Command_Result_T){UINT8_MAX,true,UINT8_MAX};
	if (!s->suppress && (!response(s,false) || s->output_size>s->config.output_capacity)) return MATTER_IM_RESOURCE_EXHAUSTED;
	s->body[0]=0x15; s->body[1]=0x18; s->body_size=2;
	if (s->command.response) {
		if (s->command.response_capacity<2 || s->command.response_capacity>sizeof(s->body)) return MATTER_IM_RESOURCE_EXHAUSTED;
		if (!response(s,true) || s->output_size-2>s->config.output_capacity ||
			s->command.response_capacity>s->config.output_capacity-(s->output_size-2)) return MATTER_IM_RESOURCE_EXHAUSTED;
		if (matter_tlv_writer_init(&s->body_writer,s->body,s->command.response_capacity,4)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
	}
	if (s->async.start) {
        Matter_Result_T r=s->async.start(s->port.user,&s->path,s->args,s->args_size,
            s->command.response ? &s->body_writer : NULL,&s->result,&s->pending_token);
        if (r==MATTER_PENDING && s->pending_token) { s->state=MATTER_IM_INVOKE_PENDING; return 0; }
        if (s->pending_token) { cancel_pending(s); s->busy=true; return MATTER_IM_FAILURE; }
        if (r!=MATTER_OK) return MATTER_IM_FAILURE;
    } else s->result=s->port.invoke(s->port.user,&s->path,s->args,s->args_size,s->command.response ? &s->body_writer : NULL);
    return 0;
}
static uint8_t validate_body(Matter_Im_Invoke_T s) {
    if (s->result.status || !s->command.response) return 0;
    if (s->result.has_cluster_status || matter_tlv_writer_finish(&s->body_writer,&s->body_size)!=MATTER_TLV_OK ||
        validate_tlv(s,s->body,s->body_size,4) || matter_tlv_init(&s->reader,s->body,s->body_size,4)!=MATTER_TLV_OK ||
        !next(s) || s->token.type!=MATTER_TLV_STRUCTURE || s->token.tag.control) return MATTER_IM_FAILURE;
    return 0;
}
static Matter_Result_T finish_response(Matter_Im_Invoke_T s,uint8_t code) {
    if (!code) code=validate_body(s);
    if (code) s->result=(Matter_Im_Command_Result_T){.status=code};
    bool command=!s->result.status && s->command.response;
    if (s->suppress && !command) { s->output_size=0; s->state=MATTER_IM_INVOKE_COMPLETE; s->busy=false; return MATTER_OK; }
    bool encoded=response(s,command);
    if (!encoded || s->output_size>s->config.output_capacity) encoded=status(s,MATTER_IM_RESOURCE_EXHAUSTED);
    s->state=encoded ? MATTER_IM_INVOKE_OUTPUT : MATTER_IM_INVOKE_FAILED;
    s->busy=false; return encoded ? MATTER_PENDING : MATTER_PORT_ERROR;
}
static Matter_Result_T clock_check(Matter_Im_Invoke_T s,uint64_t now) {
	if (now<s->now) return MATTER_INVALID_ARGUMENT;
	s->now=now;
	if (now>=s->deadline) { cancel_pending(s); erase(s->input,sizeof(s->input)); erase(s->args,sizeof(s->args)); s->state=MATTER_IM_INVOKE_FAILED; s->queued=false; s->output_size=0; return MATTER_PORT_ERROR; }
	return MATTER_OK;
}
Matter_Result_T matter_im_invoke_process(Matter_Im_Invoke_T s,uint64_t now) {
	Matter_Result_T r=check(s); if (r!=MATTER_OK) return r;
	if (now<s->now) return MATTER_INVALID_ARGUMENT;
	s->now=now;
	if (s->state==MATTER_IM_INVOKE_COMPLETE) return MATTER_OK;
	if (s->state==MATTER_IM_INVOKE_FAILED) return MATTER_INVALID_STATE;
	r=clock_check(s,now); if (r!=MATTER_OK) return r;
	if (s->state==MATTER_IM_INVOKE_PENDING) {
        s->busy=true;
        uint8_t code=authorize(s,s->command.privilege);
        if (code) { cancel_pending(s); s->busy=true; return finish_response(s,code); }
        if (s->command.response) matter_tlv_writer_init(&s->body_writer,s->body,s->command.response_capacity,4);
        Matter_Result_T done=s->async.poll(s->port.user,s->pending_token,
            s->command.response ? &s->body_writer : NULL,&s->result);
        if (done==MATTER_PENDING) { s->busy=false; return MATTER_PENDING; }
        if (done!=MATTER_OK) { cancel_pending(s); s->busy=true; code=MATTER_IM_FAILURE; }
        else s->pending_token=0;
        return finish_response(s,code);
    }
	if (!s->queued || (s->timed_status && s->state==MATTER_IM_INVOKE_IN_FLIGHT)) return MATTER_PENDING;
	s->busy=true; s->queued=false;
	uint8_t code=decode(s); bool encoded;
	s->timed_status=!code && s->request_opcode==10;
	if (code || s->timed_status) encoded=status(s,code);
	else {
		code=execute(s);
        erase(s->input,sizeof(s->input)); erase(s->args,sizeof(s->args));
        if (s->state==MATTER_IM_INVOKE_PENDING) { s->busy=false; return MATTER_PENDING; }
        return finish_response(s,code);
	}
	s->state=encoded ? MATTER_IM_INVOKE_OUTPUT : MATTER_IM_INVOKE_FAILED;
	s->busy=false; return encoded ? MATTER_PENDING : MATTER_PORT_ERROR;
}
Matter_Result_T matter_im_invoke_output(Matter_Im_Invoke_T s,Matter_Im_Invoke_Message_T* m) {
	Matter_Result_T r=check(s); if (r!=MATTER_OK) return r;
	if (!m) return MATTER_INVALID_ARGUMENT;
	if (s->state!=MATTER_IM_INVOKE_OUTPUT) return MATTER_INVALID_STATE;
	*m=(Matter_Im_Invoke_Message_T){s->output,s->output_size,s->opcode}; return MATTER_OK;
}
bool matter_im_invoke_awaiting_delivery(Matter_Im_Invoke_T s) {
    return s && !s->busy && s->state==MATTER_IM_INVOKE_IN_FLIGHT && !s->timed_status;
}
Matter_Result_T matter_im_invoke_sent(Matter_Im_Invoke_T s) {
	Matter_Result_T r=check(s); if (r!=MATTER_OK) return r;
	if (s->timed_status) return MATTER_INVALID_STATE;
	if (s->state!=MATTER_IM_INVOKE_OUTPUT) return MATTER_INVALID_STATE;
	s->state=MATTER_IM_INVOKE_IN_FLIGHT; return MATTER_OK;
}
Matter_Result_T matter_im_invoke_sent_at(Matter_Im_Invoke_T s,uint64_t now) {
	Matter_Result_T r=check(s); if (r!=MATTER_OK) return r;
	if (s->state!=MATTER_IM_INVOKE_OUTPUT) return MATTER_INVALID_STATE;
	r=clock_check(s,now); if (r!=MATTER_OK) return r;
	if (s->timed_status) {
		s->timed=true;
		s->timed_deadline=UINT64_MAX-now<s->timed_timeout ? UINT64_MAX : now+s->timed_timeout;
	}
	s->state=MATTER_IM_INVOKE_IN_FLIGHT; return MATTER_OK;
}
Matter_Result_T matter_im_invoke_confirm(Matter_Im_Invoke_T s,uint64_t now) {
	Matter_Result_T r=check(s); if (r!=MATTER_OK) return r;
	if (s->state!=MATTER_IM_INVOKE_IN_FLIGHT) return MATTER_INVALID_STATE;
	r=clock_check(s,now); if (r!=MATTER_OK) return r;
	s->state=s->timed_status ? MATTER_IM_INVOKE_WAIT_INVOKE : MATTER_IM_INVOKE_COMPLETE; return MATTER_OK;
}
Matter_Result_T matter_im_invoke_cancel(Matter_Im_Invoke_T s) {
	Matter_Result_T r=check(s); if (r!=MATTER_OK) return r;
	cancel_pending(s); erase(s->input,sizeof(s->input)); erase(s->args,sizeof(s->args));
	if (s->state!=MATTER_IM_INVOKE_COMPLETE) s->state=MATTER_IM_INVOKE_FAILED;
	s->queued=false; s->output_size=0; return MATTER_OK;
}
Matter_Im_Invoke_State_T matter_im_invoke_state(Matter_Im_Invoke_T s) { return s ? s->state : MATTER_IM_INVOKE_FAILED; }
Matter_Result_T matter_im_invoke_delete(Matter_Im_Invoke_T s) {
	if (!s) return MATTER_OK;
	Matter_Result_T r=check(s); if (r!=MATTER_OK) return r;
	cancel_pending(s); erase(s,sizeof(*s)); free(s); return MATTER_OK;
}

Matter_Im_Invoke_T matter_im_invoke_new_fabric(const Matter_Im_Invoke_Port_T* p,const Matter_Im_Invoke_Async_Port_T* a,
    const Matter_Im_Read_Fabric_Port_T* f,const Matter_Im_Invoke_Config_T* c,uint64_t now) {
    if(!f || !f->index) return NULL;
    Matter_Im_Invoke_T s=a?matter_im_invoke_new_async(p,a,c,now):matter_im_invoke_new(p,c,now);
    if(s) s->fabric=*f;
    return s;
}
Matter_Im_Invoke_T matter_im_invoke_new_case(const Matter_Im_Invoke_Port_T* p,const Matter_Im_Invoke_Async_Port_T* a,
    const Matter_Im_Read_Fabric_Port_T* f,const Matter_Im_Invoke_Config_T* c,uint64_t now) {
    if(!c || c->pase_commissionee) return NULL;
    Matter_Im_Invoke_Config_T config=*c; config.pase_commissionee=true;
    Matter_Im_Invoke_T s=matter_im_invoke_new_fabric(p,a,f,&config,now);
    if(s) { s->config=*c; s->case_session=true; } return s;
}
