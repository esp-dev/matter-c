#include "matter_spake2p.h"
#include "matter_spake2p_points.h"
#include <stdlib.h>
#include <string.h>

enum { NEW, STARTED, WAITING, SENT, VERIFIED, DONE, FAILED };
struct Matter_Spake2p {
	Matter_Crypto_Port_T port;
	bool responder, busy;
	unsigned state;
	size_t context_size;
	uint8_t context[MATTER_SPAKE2P_MAX_CONTEXT];
	uint8_t secret[32], w0[32], credential[65], own[65], peer[65];
	uint8_t confirmation[32], expected[32], key[16];
	/* TT: ten 8-byte lengths, context<=64, six points, w0. Heap only. */
	uint8_t transcript[80 + MATTER_SPAKE2P_MAX_CONTEXT + 6 * 65 + 32];
	uint8_t zv[130], hash[32], kc[32];
};
static Matter_Result_T check(Matter_Spake2p_T s) {
	if (!s) return MATTER_INVALID_ARGUMENT;
	return s->busy ? MATTER_BUSY : MATTER_OK;
}
static void clear_work(Matter_Spake2p_T s) {
	s->port.clear(s->secret, sizeof(s->secret));
	s->port.clear(s->w0, sizeof(s->w0));
	s->port.clear(s->credential, sizeof(s->credential));
	s->port.clear(s->transcript, sizeof(s->transcript));
	s->port.clear(s->zv, sizeof(s->zv));
	s->port.clear(s->hash, sizeof(s->hash));
	s->port.clear(s->kc, sizeof(s->kc));
}
static void fail(Matter_Spake2p_T s) {
	clear_work(s);
	s->port.clear(s->confirmation, 32); s->port.clear(s->expected, 32);
	s->port.clear(s->key, 16); s->state = FAILED;
}
Matter_Result_T matter_spake2p_context(const Matter_Crypto_Port_T* p,
	const uint8_t* request, size_t request_size, const uint8_t* response, size_t response_size, uint8_t* out) {
	if (!p || !p->sha256 || !p->clear || !out || (!request && request_size) || (!response && response_size))
		return MATTER_INVALID_ARGUMENT;
	if (request_size > MATTER_SPAKE2P_MAX_PARAMS || response_size > MATTER_SPAKE2P_MAX_PARAMS) return MATTER_LIMIT_REACHED;
	static const uint8_t prefix[] = "CHIP PAKE V1 Commissioning";
	size_t size = sizeof(prefix) - 1 + request_size + response_size;
	uint8_t* data = calloc(1, size);
	if (!data) { p->clear(out, 32); return MATTER_PORT_ERROR; }
	memcpy(data, prefix, sizeof(prefix) - 1);
	if (request_size) memcpy(data + sizeof(prefix) - 1, request, request_size);
	if (response_size) memcpy(data + sizeof(prefix) - 1 + request_size, response, response_size);
	Matter_Result_T result = p->sha256(p->user, data, size, out);
	p->clear(data, size); free(data);
	if (result != MATTER_OK) p->clear(out, 32);
	return result;
}
Matter_Spake2p_T matter_spake2p_new(const Matter_Crypto_Port_T* p, bool responder,
	const uint8_t* w0, const uint8_t* credential, size_t credential_size, const uint8_t* context, size_t context_size) {
	if (!p || !p->p256_scalar || !p->spake_share || !p->spake_secrets || !p->sha256 ||
		!p->hkdf_sha256 || !p->hmac_sha256 || !p->clear || !p->equal || !w0 || !credential ||
		credential_size != (responder ? 65u : 32u) || (!context && context_size) || context_size > MATTER_SPAKE2P_MAX_CONTEXT)
		return NULL;
	Matter_Spake2p_T s = calloc(1, sizeof(*s));
	if (!s) return NULL;
	s->port = *p; s->responder = responder; s->context_size = context_size;
	memcpy(s->w0, w0, 32); memcpy(s->credential, credential, credential_size);
	if (context_size) memcpy(s->context, context, context_size);
	return s;
}
Matter_Result_T matter_spake2p_start(Matter_Spake2p_T s, uint8_t* out) {
	Matter_Result_T r = check(s);
	if (r != MATTER_OK) return r;
	if (!out) return MATTER_INVALID_ARGUMENT;
	if (s->state != NEW) return MATTER_INVALID_STATE;
	s->busy = true;
	r = s->port.p256_scalar(s->port.user, s->secret);
	if (r == MATTER_OK) r = s->port.spake_share(s->port.user, s->responder, s->secret, s->w0, s->own);
	if (r == MATTER_OK) { memcpy(out, s->own, 65); s->state = STARTED; }
	else { s->port.clear(out, 65); fail(s); }
	s->busy = false;
	return r;
}
static size_t append(Matter_Spake2p_T s, size_t offset, const uint8_t* data, size_t size) {
	/* All call sites use fixed, bounded internal fields; capacity proven above. */
	uint64_t length = size;
	for (unsigned i = 0; i < 8; ++i) { s->transcript[offset++] = (uint8_t)length; length >>= 8; }
	if (size) memcpy(s->transcript + offset, data, size);
	return offset + size;
}
Matter_Result_T matter_spake2p_derive(Matter_Spake2p_T s, const uint8_t* peer, size_t size) {
	Matter_Result_T r = check(s);
	if (r != MATTER_OK) return r;
	if (!peer || size != 65) return MATTER_INVALID_ARGUMENT;
	if (s->state != STARTED) return MATTER_INVALID_STATE;
	s->busy = true;
	memcpy(s->peer, peer, 65);
	r = s->port.spake_secrets(s->port.user, s->responder, s->secret, s->w0, s->credential, s->peer, s->zv);
	const uint8_t* a = s->responder ? s->peer : s->own;
	const uint8_t* b = s->responder ? s->own : s->peer;
	if (r == MATTER_OK) {
		size_t n = append(s, 0, s->context, s->context_size);
		n = append(s, n, NULL, 0); n = append(s, n, NULL, 0);
		n = append(s, n, matter_spake2p_M, 65); n = append(s, n, matter_spake2p_N, 65);
		n = append(s, n, a, 65); n = append(s, n, b, 65);
		n = append(s, n, s->zv, 65); n = append(s, n, s->zv + 65, 65);
		n = append(s, n, s->w0, 32);
		r = s->port.sha256(s->port.user, s->transcript, n, s->hash);
	}
	static const uint8_t info[] = "ConfirmationKeys";
	if (r == MATTER_OK) r = s->port.hkdf_sha256(s->port.user, s->hash, 16, NULL, 0, info, sizeof(info) - 1, s->kc, 32);
	if (r == MATTER_OK) r = s->port.hmac_sha256(s->port.user, s->kc + (s->responder ? 16 : 0), 16,
		s->responder ? a : b, 65, s->confirmation);
	if (r == MATTER_OK) r = s->port.hmac_sha256(s->port.user, s->kc + (s->responder ? 0 : 16), 16,
		s->responder ? b : a, 65, s->expected);
	if (r == MATTER_OK) { memcpy(s->key, s->hash + 16, 16); clear_work(s); s->state = WAITING; }
	else fail(s);
	s->busy = false;
	return r;
}
Matter_Result_T matter_spake2p_confirmation(Matter_Spake2p_T s, uint8_t* out) {
	Matter_Result_T r = check(s);
	if (r != MATTER_OK) return r;
	if (!out) return MATTER_INVALID_ARGUMENT;
	if (s->responder) {
		if (s->state != WAITING && s->state != SENT && s->state != DONE) return MATTER_INVALID_STATE;
		if (s->state == WAITING) s->state = SENT;
	} else {
		if (s->state != VERIFIED && s->state != DONE) return MATTER_INVALID_STATE;
		s->state = DONE;
	}
	memcpy(out, s->confirmation, 32);
	return MATTER_OK;
}
Matter_Result_T matter_spake2p_verify(Matter_Spake2p_T s, const uint8_t* in, size_t size) {
	Matter_Result_T r = check(s);
	if (r != MATTER_OK) return r;
	if (!in || size != 32) return MATTER_INVALID_ARGUMENT;
	if (s->state != (s->responder ? SENT : WAITING)) return MATTER_INVALID_STATE;
	s->busy = true;
	if (s->port.equal(in, s->expected, 32)) {
		s->port.clear(s->expected, 32);
		s->state = s->responder ? DONE : VERIFIED;
	} else { fail(s); r = MATTER_PORT_ERROR; }
	s->busy = false;
	return r;
}
Matter_Result_T matter_spake2p_key(Matter_Spake2p_T s, uint8_t* out) {
	Matter_Result_T r = check(s);
	if (r != MATTER_OK) return r;
	if (!out) return MATTER_INVALID_ARGUMENT;
	if (s->state != DONE) return MATTER_INVALID_STATE;
	memcpy(out, s->key, 16);
	return MATTER_OK;
}
Matter_Result_T matter_spake2p_delete(Matter_Spake2p_T s) {
	if (!s) return MATTER_OK;
	if (s->busy) return MATTER_BUSY;
	s->busy = true;
	s->port.clear((uint8_t*)s, sizeof(*s)); free(s);
	return MATTER_OK;
}
