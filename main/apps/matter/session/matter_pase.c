#include "matter_pase.h"
#include "matter_handshake_buffer_internal.h"
#include "../codec/matter_tlv_writer.h"
#include "../codec/matter_tlv_validate.h"
#include <stdlib.h>
#include <string.h>

enum { INIT, REQUEST, RESPONSE, PAKE1, PAKE2, PAKE3, STATUS, DELIVERY, COMPLETE, FAILED };
typedef struct {
	Matter_Tlv_Validation_Workspace_T validation;
	Matter_Tlv_Tag_T tags[48];
	Matter_Tlv_Reader_T reader;
	Matter_Tlv_Writer_T writer;
	Matter_Tlv_Element_T fields[6], sub[10], element;
} Matter_Pase_Work;
struct Matter_Pase {
	Matter_Crypto_Port_T port;
	Matter_Pase_Config_T config;
	Matter_Spake2p_T spake;
	Matter_Pase_Keys_T keys;
	unsigned phase, after_send;
	bool busy, queued, output, transferred;
	bool started; void* failure_user; uint64_t failure_token;
	void (*failed)(void*,uint64_t);
	uint64_t now, deadline;
	uint8_t in_opcode, out_opcode;
	size_t in_size, out_size, request_size, response_size;
	uint8_t *in, *out, *request, *response; size_t out_capacity;
	uint8_t status[8]; Matter_Pase_Work* workspace;
	uint8_t random[32], context[32], wide[80], w1[32], share[65], confirm[32], ke[16], derived[48], pin[4];

};
static Matter_Result_T check(Matter_Pase_T s) {
	return !s ? MATTER_INVALID_ARGUMENT : s->busy ? MATTER_BUSY : MATTER_OK;
}
static bool params(const Matter_Pase_Config_T* c) {
	return c->iterations >= 1000 && c->iterations <= 100000 && c->salt_size >= 16 && c->salt_size <= 32;
}
static bool valid_pin(uint32_t pin) {
	if (!pin || pin > 99999998 || pin == 12345678 || pin == 87654321) return false;
	return pin % 11111111 != 0;
}
static void secrets(Matter_Pase_T s) {
	(void)matter_spake2p_delete(s->spake); s->spake = NULL;
	matter_handshake_clear(&s->request,&s->request_size); matter_handshake_clear(&s->response,&s->response_size);
	s->port.clear(s->config.w0, 32); s->port.clear(s->config.L, 65);
	s->port.clear((uint8_t*)&s->config.pin, sizeof(s->config.pin));
	s->port.clear(s->wide, 80); s->port.clear(s->w1, 32); s->port.clear(s->ke, 16);
	s->port.clear(s->derived, 48); s->port.clear(s->pin, 4); s->port.clear(s->confirm, 32);
}
static void failure(Matter_Pase_T s, bool report, bool notify) {
	bool first=s->phase!=FAILED;
	secrets(s); s->port.clear((uint8_t*)&s->keys, sizeof(s->keys));
	matter_handshake_clear(&s->in,&s->in_size); matter_handshake_clear(&s->out,&s->out_capacity);
	s->queued = false; s->phase = FAILED; s->output = report;
	if (report) {
		/* Appendix D: uint16 general, uint32 protocol, uint16 protocol code. */
		memset(s->status, 0, 8); s->status[0] = 1; s->status[6] = 2;
		s->out_size = 8; s->out_opcode = 0x40; s->after_send = FAILED;
	}
	if(first && notify && s->failed) s->failed(s->failure_user,s->failure_token);
}
Matter_Pase_T matter_pase_new(const Matter_Crypto_Port_T* p, const Matter_Pase_Config_T* c, uint64_t now) {
	if (!p || !c || !p->random || !p->sha256 || !p->hmac_sha256 || !p->hkdf_sha256 ||
		!p->pbkdf2_sha256 || !p->p256_reduce || !p->p256_scalar || !p->spake_share ||
		!p->spake_secrets || !p->clear || !p->equal || !c->local_session_id || !c->timeout_ms ||
		(c->responder || c->has_parameters ? !params(c) : false) || (!c->responder && !valid_pin(c->pin))) return NULL;
	Matter_Pase_T s = calloc(1, sizeof(*s));
	if (!s) return NULL;
	s->port = *p; s->config = *c; s->now = now;
	s->deadline = UINT64_MAX - now < c->timeout_ms ? UINT64_MAX : now + c->timeout_ms;
	s->phase = c->responder ? REQUEST : INIT;
	s->keys.local_session_id = c->local_session_id;
	s->keys.peer_intervals = (Matter_Pase_Intervals_T){500, 300, 4000};
	return s;
}
Matter_Result_T matter_pase_on_failure(Matter_Pase_T s,void* user,uint64_t token,void (*failed)(void*,uint64_t)) {
	Matter_Result_T r=check(s); if(r!=MATTER_OK) return r;
	if(!failed) return MATTER_INVALID_ARGUMENT;
	if(s->started || s->failed || s->phase==FAILED) return MATTER_INVALID_STATE;
	s->failure_user=user; s->failure_token=token; s->failed=failed; return MATTER_OK;
}
Matter_Result_T matter_pase_receive(Matter_Pase_T s, uint8_t opcode, const uint8_t* data, size_t size) {
	Matter_Result_T r = check(s); if (r != MATTER_OK) return r;
	if (!data || !size) return MATTER_INVALID_ARGUMENT;
	if (size > MATTER_PASE_MAX_PAYLOAD) return MATTER_LIMIT_REACHED;
	if (s->phase == INIT || s->phase == FAILED || s->phase == COMPLETE || s->phase == DELIVERY) return MATTER_INVALID_STATE;
	if (s->queued || s->output) return MATTER_WOULD_BLOCK;
	if(!matter_handshake_copy(&s->in,&s->in_size,data,size)) return MATTER_LIMIT_REACHED;
	s->started=true; s->in_opcode = opcode; s->queued = true;
	return MATTER_OK;
}
/* Validation handles all unknown nested values and duplicate tags first. Known
 * schemas additionally require context tags in strictly increasing tag order. */
static bool fields(Matter_Pase_T s, Matter_Tlv_Element_T* out, size_t count) {
	memset(out, 0, count * sizeof(*out));
	uint32_t last = 0;
	bool seen = false;
	for (;;) {
		if (matter_tlv_next(&s->workspace->reader, &s->workspace->element) != MATTER_TLV_OK) return false;
		Matter_Tlv_Element_T* e = &s->workspace->element;
		if (e->type == MATTER_TLV_END) return true;
		if (e->tag.control != 1 || (seen && e->tag.number <= last)) return false;
		last = e->tag.number; seen = true;
		if (last < count) out[last] = *e;
		if (e->type == MATTER_TLV_STRUCTURE || e->type == MATTER_TLV_ARRAY || e->type == MATTER_TLV_LIST)
			if (matter_tlv_skip_container(&s->workspace->reader) != MATTER_TLV_OK) return false;
	}
}
static bool nested(Matter_Pase_T s, const Matter_Tlv_Element_T* e) {
	if (e->type != MATTER_TLV_STRUCTURE || !e->tag.control) return false;
	if (matter_tlv_init(&s->workspace->reader, s->in, s->in_size, 8) != MATTER_TLV_OK) return false;
	/* Enter by traversing original document, never reinterpret context tag as root. */
	do { if (matter_tlv_next(&s->workspace->reader, &s->workspace->element) != MATTER_TLV_OK) return false; }
	while (s->workspace->element.offset != e->offset);
	return fields(s, s->workspace->sub, 10);
}
static bool number(const Matter_Tlv_Element_T* e, uint64_t max) {
	return e->tag.control && e->type == MATTER_TLV_UNSIGNED && e->unsigned_value <= max;
}
static bool bytes(const Matter_Tlv_Element_T* e, size_t size) {
	return e->tag.control && e->type == MATTER_TLV_BYTES && e->size == size;
}
static bool decode(Matter_Pase_T s) {
	const Matter_Tlv_Validation_Options_T opt = {1024, 128, 2048, 8, false, 0, 0};
	Matter_Tlv_Validation_Report_T report;
	if (matter_tlv_validate(s->in, s->in_size, &opt, &s->workspace->validation, s->workspace->tags, 48, &report) != MATTER_TLV_OK ||
		matter_tlv_init(&s->workspace->reader, s->in, s->in_size, 8) != MATTER_TLV_OK ||
		matter_tlv_next(&s->workspace->reader, &s->workspace->element) != MATTER_TLV_OK ||
		s->workspace->element.type != MATTER_TLV_STRUCTURE || s->workspace->element.tag.control) return false;
	return fields(s, s->workspace->fields, 6);
}
static bool intervals(Matter_Pase_T s) {
	if (!s->workspace->fields[5].tag.control) return true;
	if (!nested(s, &s->workspace->fields[5])) return false;
	for (unsigned i = 1; i <= 9; ++i) {
		if (!s->workspace->sub[i].tag.control) continue;
		if (!number(&s->workspace->sub[i], i == 1 || i == 2 || i == 6 || i == 9 ? UINT32_MAX : UINT16_MAX)) return false;
	}
	if (s->workspace->sub[1].tag.control) s->keys.peer_intervals.idle_ms = (uint32_t)s->workspace->sub[1].unsigned_value;
	if (s->workspace->sub[2].tag.control) s->keys.peer_intervals.active_ms = (uint32_t)s->workspace->sub[2].unsigned_value;
	if (s->workspace->sub[3].tag.control) s->keys.peer_intervals.active_threshold_ms = (uint16_t)s->workspace->sub[3].unsigned_value;
	return true;
}
static bool put(Matter_Pase_T s, Matter_Tlv_Type_T type, uint8_t tag, uint64_t value,
	const uint8_t* data, size_t size, uint8_t width) {
	s->workspace->element = (Matter_Tlv_Element_T){.type = type, .tag = {.control = tag ? 1 : 0, .number = tag},
		.unsigned_value = value, .data = data, .size = size};
	return matter_tlv_write(&s->workspace->writer, &s->workspace->element, width) == MATTER_TLV_OK;
}
static bool begin(Matter_Pase_T s) {
	return matter_handshake_reserve(&s->out,&s->out_capacity,MATTER_PASE_MAX_PAYLOAD) &&
		matter_tlv_writer_init(&s->workspace->writer, s->out, MATTER_PASE_MAX_PAYLOAD, 3) == MATTER_TLV_OK &&
		put(s, MATTER_TLV_STRUCTURE, 0, 0, NULL, 0, 0);
}
static bool end(Matter_Pase_T s) { return put(s, MATTER_TLV_END, 0, 0, NULL, 0, 0); }
static bool output(Matter_Pase_T s, uint8_t opcode, unsigned next) {
	if (!end(s) || matter_tlv_writer_finish(&s->workspace->writer, &s->out_size) != MATTER_TLV_OK) return false;
	s->out_opcode = opcode; s->after_send = next; s->output = true; return true;
}
static bool octets(Matter_Pase_T s, uint8_t tag, const uint8_t* data, size_t size) {
	return put(s, MATTER_TLV_BYTES, tag, 0, data, size, 0);
}
static bool integer(Matter_Pase_T s, uint8_t tag, uint64_t n, uint8_t width) {
	return put(s, MATTER_TLV_UNSIGNED, tag, n, NULL, 0, width);
}
static bool start_spake(Matter_Pase_T s) {
	if (matter_spake2p_context(&s->port, s->request, s->request_size, s->response, s->response_size, s->context) != MATTER_OK) return false;
	matter_handshake_clear(&s->request,&s->request_size); matter_handshake_clear(&s->response,&s->response_size);
	if (!s->config.responder) {
		for (unsigned i = 0; i < 4; ++i) s->pin[i] = (uint8_t)(s->config.pin >> (8 * i));
		if (s->port.pbkdf2_sha256(s->port.user, s->pin, 4, s->config.salt, s->config.salt_size,
			s->config.iterations, s->wide, 80) != MATTER_OK ||
			s->port.p256_reduce(s->port.user, s->wide, 40, s->config.w0) != MATTER_OK ||
			s->port.p256_reduce(s->port.user, s->wide + 40, 40, s->w1) != MATTER_OK) return false;
	}
	s->spake = matter_spake2p_new(&s->port, s->config.responder, s->config.w0,
		s->config.responder ? s->config.L : s->w1, s->config.responder ? 65 : 32, s->context, 32);
	s->port.clear(s->wide, 80); s->port.clear(s->w1, 32); s->port.clear(s->pin, 4);
	s->port.clear((uint8_t*)&s->config.pin, sizeof(s->config.pin));
	s->port.clear(s->config.w0, 32); s->port.clear(s->config.L, 65);
	return s->spake && matter_spake2p_start(s->spake, s->share) == MATTER_OK;
}
static bool keys(Matter_Pase_T s) {
	static const uint8_t info[] = "SessionKeys";
	if (matter_spake2p_key(s->spake, s->ke) != MATTER_OK ||
		s->port.hkdf_sha256(s->port.user, s->ke, 16, NULL, 0, info, sizeof(info)-1, s->derived, 48) != MATTER_OK) return false;
	memcpy(s->keys.send_key, s->derived + (s->config.responder ? 16 : 0), 16);
	memcpy(s->keys.receive_key, s->derived + (s->config.responder ? 0 : 16), 16);
	memcpy(s->keys.attestation_challenge, s->derived + 32, 16);
	secrets(s); return true;
}
static bool work(Matter_Pase_T s) {
	Matter_Tlv_Element_T* f = s->workspace->fields;
	if (s->phase == INIT) {
		if (s->port.random(s->port.user, s->random, 32) != MATTER_OK || !begin(s) ||
			!octets(s, 1, s->random, 32) || !integer(s, 2, s->config.local_session_id, 2) ||
			!integer(s, 3, 0, 2) || !put(s, MATTER_TLV_BOOL, 4, s->config.has_parameters, NULL, 0, 0) ||
			!output(s, 0x20, RESPONSE)) return false;
		return matter_handshake_copy(&s->request,&s->request_size,s->out,s->out_size);
	}
	if (s->in_opcode == 0x40) {
		/* Success has no protocol data. Any remote failure is terminal, no reply loop. */
		static const uint8_t success[8] = {0};
		if (s->phase != STATUS || s->in_size != 8 || memcmp(s->in, success, 8) || !keys(s)) return false;
		s->phase = COMPLETE; return true;
	}
	uint8_t expected = s->phase == REQUEST ? 0x20 : s->phase == RESPONSE ? 0x21 :
		s->phase == PAKE1 ? 0x22 : s->phase == PAKE2 ? 0x23 : s->phase == PAKE3 ? 0x24 : 0;
	if (s->in_opcode != expected || !decode(s)) return false;
	if (s->phase == REQUEST) {
		if (!bytes(&f[1], 32) || !number(&f[2], UINT16_MAX) || !f[2].unsigned_value ||
			!number(&f[3], 0) || !f[4].tag.control || f[4].type != MATTER_TLV_BOOL || !intervals(s)) return false;
		s->keys.peer_session_id = (uint16_t)f[2].unsigned_value;
		if(!matter_handshake_copy(&s->request,&s->request_size,s->in,s->in_size)) return false;
		if (s->port.random(s->port.user, s->random, 32) != MATTER_OK || !begin(s) ||
			!octets(s, 1, f[1].data, 32) || !octets(s, 2, s->random, 32) || !integer(s, 3, s->config.local_session_id, 2)) return false;
		if (!f[4].unsigned_value && (!put(s, MATTER_TLV_STRUCTURE, 4, 0, NULL, 0, 0) ||
			!integer(s, 1, s->config.iterations, 0) || !octets(s, 2, s->config.salt, s->config.salt_size) || !end(s))) return false;
		if (!output(s, 0x21, PAKE1)) return false;
		return matter_handshake_copy(&s->response,&s->response_size,s->out,s->out_size);
	}
	if (s->phase == RESPONSE) {
		if (!bytes(&f[1], 32) || !s->port.equal(f[1].data, s->random, 32) || !bytes(&f[2], 32) ||
			!number(&f[3], UINT16_MAX) || !f[3].unsigned_value || !intervals(s)) return false;
		s->keys.peer_session_id = (uint16_t)f[3].unsigned_value;
		if (!s->config.has_parameters) {
			if (!nested(s, &f[4]) || !number(&s->workspace->sub[1], 100000) || s->workspace->sub[1].unsigned_value < 1000 ||
				s->workspace->sub[2].type != MATTER_TLV_BYTES || s->workspace->sub[2].size < 16 || s->workspace->sub[2].size > 32) return false;
			s->config.iterations = (uint32_t)s->workspace->sub[1].unsigned_value;
			s->config.salt_size = (uint8_t)s->workspace->sub[2].size; memcpy(s->config.salt, s->workspace->sub[2].data, s->workspace->sub[2].size);
		} else if (f[4].tag.control && (!nested(s, &f[4]) || s->workspace->sub[1].tag.control || s->workspace->sub[2].tag.control)) return false;
		if(!matter_handshake_copy(&s->response,&s->response_size,s->in,s->in_size)) return false;
		return start_spake(s) && begin(s) && octets(s, 1, s->share, 65) && output(s, 0x22, PAKE2);
	}
	if (s->phase == PAKE1) return bytes(&f[1], 65) && start_spake(s) &&
		matter_spake2p_derive(s->spake, f[1].data, 65) == MATTER_OK &&
		matter_spake2p_confirmation(s->spake, s->confirm) == MATTER_OK && begin(s) &&
		octets(s, 1, s->share, 65) && octets(s, 2, s->confirm, 32) && output(s, 0x23, PAKE3);
	if (s->phase == PAKE2) return bytes(&f[1], 65) && bytes(&f[2], 32) &&
		matter_spake2p_derive(s->spake, f[1].data, 65) == MATTER_OK &&
		matter_spake2p_verify(s->spake, f[2].data, 32) == MATTER_OK &&
		matter_spake2p_confirmation(s->spake, s->confirm) == MATTER_OK &&
		begin(s) && octets(s, 1, s->confirm, 32) && output(s, 0x24, STATUS);
	if (s->phase == PAKE3) {
		if (!bytes(&f[1], 32) || matter_spake2p_verify(s->spake, f[1].data, 32) != MATTER_OK || !keys(s)) return false;
		memset(s->status, 0, 8); s->out_size = 8; s->out_opcode = 0x40; s->output = true; s->after_send = DELIVERY; return true;
	}
	return false;
}
Matter_Result_T matter_pase_process(Matter_Pase_T s, uint64_t now) {
	Matter_Result_T r = check(s); if (r != MATTER_OK) return r;
	if (now < s->now) return MATTER_INVALID_ARGUMENT;
	s->now = now; s->busy = true; s->started=true;
	if (s->phase == COMPLETE) r = MATTER_OK;
	else if (s->phase == FAILED) r = MATTER_PORT_ERROR;
	else if (now >= s->deadline) { failure(s, false, true); r = MATTER_PORT_ERROR; }
	else if (s->output || (s->phase != INIT && !s->queued)) r = MATTER_PENDING;
	else {
		s->workspace=calloc(1,sizeof(*s->workspace));
		bool ok = s->workspace && work(s); s->queued = false;
		matter_handshake_clear(&s->in,&s->in_size);
		matter_handshake_delete(s->workspace,sizeof(*s->workspace)); s->workspace=NULL;
		if (!ok) { failure(s, s->in_opcode != 0x40 && s->phase != INIT, true); r = MATTER_PORT_ERROR; }
		else r = s->phase == COMPLETE ? MATTER_OK : MATTER_PENDING;
	}
	s->busy = false; return r;
}
Matter_Result_T matter_pase_output(Matter_Pase_T s, Matter_Pase_Message_T* out) {
	Matter_Result_T r = check(s); if (r != MATTER_OK) return r;
	if (!out) return MATTER_INVALID_ARGUMENT;
	if (!s->output) return MATTER_WOULD_BLOCK;
	*out = (Matter_Pase_Message_T){s->out_opcode, s->out_opcode==0x40?s->status:s->out, s->out_size}; return MATTER_OK;
}
Matter_Result_T matter_pase_sent(Matter_Pase_T s) {
	Matter_Result_T r = check(s); if (r != MATTER_OK) return r;
	if (!s->output) return MATTER_INVALID_STATE;
	matter_handshake_clear(&s->out,&s->out_capacity);
	s->output = false; s->phase = s->after_send; return MATTER_OK;
}
Matter_Result_T matter_pase_confirm_delivery(Matter_Pase_T s, uint64_t now) {
	Matter_Result_T r = check(s); if (r != MATTER_OK) return r;
	if (s->phase != DELIVERY) return MATTER_INVALID_STATE;
	if (now < s->now) return MATTER_INVALID_ARGUMENT;
	s->now = now;
	if (now >= s->deadline) { s->busy = true; failure(s, false, true); s->busy = false; return MATTER_PORT_ERROR; }
	s->phase = COMPLETE; return MATTER_OK;
}
Matter_Result_T matter_pase_keys(Matter_Pase_T s, Matter_Pase_Keys_T* out) {
	Matter_Result_T r = check(s); if (r != MATTER_OK) return r;
	if (!out) return MATTER_INVALID_ARGUMENT;
	if (s->phase != COMPLETE || s->transferred) return MATTER_INVALID_STATE;
	*out = s->keys; return MATTER_OK;
}
Matter_Result_T matter_pase_take_keys(Matter_Pase_T s, Matter_Pase_Keys_T* out) {
	Matter_Result_T r = matter_pase_keys(s, out);
	if (r != MATTER_OK) return r;
	s->busy = true;
	s->transferred = true;
	s->port.clear(s->keys.send_key, 16); s->port.clear(s->keys.receive_key, 16);
	s->port.clear(s->keys.attestation_challenge, 16);
	s->busy = false;
	return MATTER_OK;
}
Matter_Result_T matter_pase_peer_intervals(Matter_Pase_T s, Matter_Pase_Intervals_T* out) {
	Matter_Result_T r = check(s); if (r != MATTER_OK) return r;
	if (!out) return MATTER_INVALID_ARGUMENT;
	if (s->phase == FAILED) return MATTER_INVALID_STATE;
	*out = s->keys.peer_intervals; return MATTER_OK;
}
Matter_Pase_State_T matter_pase_state(Matter_Pase_T s) {
	return !s || s->phase == FAILED ? MATTER_PASE_FAILED : s->phase == COMPLETE ? MATTER_PASE_COMPLETE :
		s->output ? MATTER_PASE_OUTPUT : MATTER_PASE_WAITING;
}
Matter_Result_T matter_pase_cancel(Matter_Pase_T s) {
	Matter_Result_T r = check(s); if (r != MATTER_OK) return r;
	s->busy = true; failure(s, false, false); s->busy = false; return MATTER_OK;
}
Matter_Result_T matter_pase_delete(Matter_Pase_T s) {
	if (!s) return MATTER_OK;
	Matter_Result_T r = check(s); if (r != MATTER_OK) return r;
	s->busy = true; secrets(s);
	matter_handshake_clear(&s->in,&s->in_size); matter_handshake_clear(&s->out,&s->out_capacity);
	matter_handshake_delete(s->workspace,sizeof(*s->workspace));
	s->port.clear((uint8_t*)s, sizeof(*s)); free(s); return MATTER_OK;
}
