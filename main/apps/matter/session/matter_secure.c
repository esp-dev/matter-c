#include "matter_secure_internal.h"
#include "../transport/matter_counter.h"
#include "../transport/matter_reception.h"
#include <stdlib.h>
#include <string.h>

struct Matter_Secure {
	Matter_Crypto_Port_T port;
	Matter_Pase_Keys_T keys;
    Matter_Secure_Identity_T identity;
	Matter_Counter_T tx;
	Matter_Reception_T rx;
	Matter_Secure_Received_T received;
	uint64_t now, sent, received_at;
	size_t pins;
	bool busy, closing, admitting;
	uint8_t plain[MATTER_SECURE_MAX_PACKET];
};
static Matter_Result_T check(Matter_Secure_T s) {
	return !s ? MATTER_INVALID_ARGUMENT : s->busy ? MATTER_BUSY : MATTER_OK;
}
static Matter_Result_T check_reference(Matter_Secure_T s) {
	/* An admitted RX queue must be able to acquire its lifetime reference while
	 * traffic/state mutation stays locked. No close can run in this interval. */
	return s && s->admitting ? MATTER_OK : check(s);
}
static void clear_keys(Matter_Secure_T s) {
	s->port.clear((uint8_t*)&s->keys, sizeof(s->keys));
}
static Matter_Result_T random28(void* user, uint32_t* value) {
	Matter_Secure_T s = user;
	uint8_t bytes[4] = {0};
	Matter_Result_T r = s->port.random(s->port.user, bytes, sizeof(bytes));
	if (r == MATTER_OK) *value = ((uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
		(uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24) & UINT32_C(0x0fffffff);
	s->port.clear(bytes, sizeof(bytes));
	return r;
}
static void nonce(const Matter_Message_Header_T* h, uint64_t node, uint8_t out[13]) {
	memset(out, 0, 13);
    for(unsigned i=0;i<8;++i) out[5+i]=(uint8_t)(node>>(8*i));
	out[0] = h->security_flags;
	for (unsigned i = 0; i < 4; ++i) out[1+i] = (uint8_t)(h->message_counter >> (8*i));
}
Matter_Secure_T matter_secure_new(const Matter_Crypto_Port_T* p, Matter_Pase_T pase, uint64_t now) {
	if (!p || !pase || !p->random || !p->clear || !p->ccm_encrypt || !p->ccm_decrypt) return NULL;
	Matter_Secure_T s = calloc(1, sizeof(*s));
	if (!s) return NULL;
	s->port = *p; s->now = s->sent = s->received_at = now; s->busy = true;
	if (matter_counter_init(&s->tx, MATTER_COUNTER_SECURE_UNICAST, random28, s) != MATTER_OK ||
		matter_reception_seed(&s->rx, MATTER_RECEPTION_SECURE_UNICAST, 0) != MATTER_OK ||
		matter_pase_take_keys(pase, &s->keys) != MATTER_OK) {
		p->clear((uint8_t*)s, sizeof(*s)); free(s); return NULL;
	}
	s->busy = false; return s;
}
Matter_Result_T matter_secure_info(Matter_Secure_T s, Matter_Secure_Info_T* out) {
	Matter_Result_T r = check_reference(s); if (r != MATTER_OK) return r;
	if (!out) return MATTER_INVALID_ARGUMENT;
	*out = (Matter_Secure_Info_T){s->keys.local_session_id, s->keys.peer_session_id,
		s->sent, s->received_at, s->pins, s->tx.exhausted, s->closing, s->keys.peer_intervals};
	return MATTER_OK;
}
Matter_Result_T matter_secure_challenge(Matter_Secure_T s, uint8_t out[16]) {
	Matter_Result_T r = check(s); if (r != MATTER_OK) return r;
	if (!out) return MATTER_INVALID_ARGUMENT;
	if (s->closing) return MATTER_INVALID_STATE;
	memcpy(out, s->keys.attestation_challenge, 16); return MATTER_OK;
}
Matter_Result_T matter_secure_retain(Matter_Secure_T s) {
	Matter_Result_T r = check_reference(s); if (r != MATTER_OK) return r;
	if (s->closing) return MATTER_INVALID_STATE;
	if (s->pins == SIZE_MAX) return MATTER_LIMIT_REACHED;
	++s->pins; return MATTER_OK;
}
Matter_Result_T matter_secure_release(Matter_Secure_T s) {
	Matter_Result_T r = check_reference(s); if (r != MATTER_OK) return r;
	if (!s->pins) return MATTER_INVALID_STATE;
	bool was_busy = s->busy; s->busy = true;
	if (!--s->pins && s->closing) clear_keys(s);
	s->busy = was_busy; return MATTER_OK;
}
Matter_Result_T matter_secure_close(Matter_Secure_T s) {
	Matter_Result_T r = check(s); if (r != MATTER_OK) return r;
	s->busy = true; s->closing = true;
	if (!s->pins) clear_keys(s);
	s->busy = false; return MATTER_OK;
}
Matter_Result_T matter_secure_delete(Matter_Secure_T s) {
	if (!s) return MATTER_OK;
	Matter_Result_T r = check(s); if (r != MATTER_OK) return r;
	if (!s->closing || s->pins) return MATTER_INVALID_STATE;
	s->busy = true; s->port.clear((uint8_t*)s, sizeof(*s)); free(s); return MATTER_OK;
}
Matter_Result_T matter_secure_seal(Matter_Secure_T s, const uint8_t* plain, size_t size,
	uint64_t now, uint8_t* packet, size_t capacity, size_t* written) {
	Matter_Result_T r = check(s); if (r != MATTER_OK) return r;
	if (!plain || !packet || !written || now < s->now) return MATTER_INVALID_ARGUMENT;
	if (s->closing) return MATTER_INVALID_STATE;
	if (size > MATTER_SECURE_MAX_PACKET - MATTER_SECURE_OVERHEAD || capacity < size + MATTER_SECURE_OVERHEAD)
		return MATTER_LIMIT_REACHED;
	Matter_Protocol_Header_T protocol; size_t n;
	if (matter_protocol_header_read(plain, size, &protocol, &n) != MATTER_MESSAGE_OK) return MATTER_INVALID_ARGUMENT;
	Matter_Counter_Value_T value;
	r = matter_counter_take(&s->tx, &value); if (r != MATTER_OK) return r;
	s->busy = true; s->now = now;
	Matter_Message_Header_T header = {.session_id = s->keys.peer_session_id, .message_counter = value.counter};
	uint8_t iv[13]; nonce(&header, s->identity.local_node_id, iv);
	/* Fixed supported 8-byte header and prechecked capacity cannot fail. */
	(void)matter_message_header_write(&header, packet, capacity, &n);
	r = s->port.ccm_encrypt(s->port.user, s->keys.send_key, iv, packet, n, plain, size, packet + n);
	if (r == MATTER_OK) { *written = n + size + 16; s->sent = now; }
	else s->port.clear(packet, size + MATTER_SECURE_OVERHEAD);
	s->busy = false; return r;
}
Matter_Result_T matter_secure_receive(Matter_Secure_T s, const uint8_t* packet, size_t size,
	uint64_t now, Matter_Secure_Admit_T admit, void* user) {
	Matter_Result_T r = check(s); if (r != MATTER_OK) return r;
	if (!packet || !admit || now < s->now) return MATTER_INVALID_ARGUMENT;
	if (s->closing) return MATTER_INVALID_STATE;
	if (size > MATTER_SECURE_MAX_PACKET) return MATTER_LIMIT_REACHED;
	Matter_Message_Header_T header; size_t offset;
	if (matter_message_header_read(packet, size, &header, &offset) != MATTER_MESSAGE_OK ||
		header.session_id != s->keys.local_session_id ||
		(header.security_flags & (MATTER_MESSAGE_SESSION_MASK | MATTER_MESSAGE_CONTROL | MATTER_MESSAGE_PRIVACY)) ||
		(header.message_flags & MATTER_MESSAGE_DESTINATION_MASK) == MATTER_MESSAGE_DESTINATION_GROUP ||
		size - offset < 16) return MATTER_INVALID_ARGUMENT;
    if(s->identity.fabric_index &&
        (((header.message_flags & MATTER_MESSAGE_SOURCE_PRESENT) && header.source_node_id!=s->identity.peer_node_id) ||
         ((header.message_flags & MATTER_MESSAGE_DESTINATION_MASK)==MATTER_MESSAGE_DESTINATION_NODE && header.destination_id!=s->identity.local_node_id))) return MATTER_INVALID_ARGUMENT;
	s->busy = true;
	uint8_t iv[13]; nonce(&header, s->identity.peer_node_id, iv);
	size_t plain_size = size - offset - 16, payload_offset;
	r = s->port.ccm_decrypt(s->port.user, s->keys.receive_key, iv, packet, offset,
		packet + offset, plain_size, s->plain);
	if (r != MATTER_OK) goto done;
	if (matter_protocol_header_read(s->plain, plain_size, &s->received.protocol, &payload_offset) != MATTER_MESSAGE_OK) {
		r = MATTER_INVALID_ARGUMENT; goto done;
	}
	s->received.message = header;
	r = matter_reception_classify(&s->rx, header.message_counter, &s->received.duplicate);
	if (r != MATTER_OK) goto done;
	s->received.payload = s->received.duplicate ? NULL : s->plain + payload_offset;
	s->received.size = s->received.duplicate ? 0 : plain_size - payload_offset;
	s->received.encoded = s->plain;
	s->received.encoded_size = s->received.duplicate ? payload_offset : plain_size;
	s->received.payload_size_on_wire = plain_size - payload_offset;
	s->admitting = true;
	r = admit(user, &s->received);
	s->admitting = false;
	if (r == MATTER_OK) {
		/* Callbacks may change pins, never replay state between classify/commit. */
		(void)matter_reception_commit(&s->rx, header.message_counter, &s->received.duplicate);
		s->received_at = s->now = now;
	}
done:
	s->port.clear(s->plain, sizeof(s->plain));
	s->port.clear((uint8_t*)&s->received, sizeof(s->received));
	s->busy = false; return r;
}

Matter_Secure_T matter_secure_from_case(const Matter_Crypto_Port_T* p,void* user,
    Matter_Result_T (*take)(void*,Matter_Pase_Keys_T*,Matter_Secure_Identity_T*),uint64_t now) {
    if(!p || !take || !p->random || !p->clear || !p->ccm_encrypt || !p->ccm_decrypt) return NULL;
    Matter_Secure_T s=calloc(1,sizeof(*s)); if(!s) return NULL;
    s->port=*p; s->now=s->sent=s->received_at=now; s->busy=true;
    if(matter_counter_init(&s->tx,MATTER_COUNTER_SECURE_UNICAST,random28,s)!=MATTER_OK ||
        matter_reception_seed(&s->rx,MATTER_RECEPTION_SECURE_UNICAST,0)!=MATTER_OK || take(user,&s->keys,&s->identity)!=MATTER_OK) {
        p->clear((uint8_t*)s,sizeof(*s)); free(s); return NULL;
    }
    s->busy=false; return s;
}
Matter_Result_T matter_secure_identity(Matter_Secure_T s,Matter_Secure_Identity_T* out) {
    Matter_Result_T r=check_reference(s); if(r!=MATTER_OK) return r;
    if(!out) return MATTER_INVALID_ARGUMENT;
    if(s->closing || !s->identity.fabric_index) return MATTER_INVALID_STATE;
    *out=s->identity; return MATTER_OK;
}
