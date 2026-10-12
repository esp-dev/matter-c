#include "matter_retransmission_sender.h"
#include <stdlib.h>

typedef struct {
	uint64_t id;
	uint8_t attempts;
	bool discovered;
} Entry;

struct Matter_Retransmission_Sender {
	Matter_Retransmission_T table;
	Matter_Retransmission_Port_T port;
	Entry entries[MATTER_RETRANSMISSION_CAPACITY];
	Matter_Retransmission_Request_T tx;
	bool pending, cancelling, stopping, drained, busy;
};

static Matter_Result_T check(Matter_Retransmission_Sender_T s) {
	return !s ? MATTER_INVALID_ARGUMENT : s->busy ? MATTER_BUSY : MATTER_OK;
}

static Matter_Result_T preflight(Matter_Result_T result) {
	return result == MATTER_OK || result == MATTER_WOULD_BLOCK || result == MATTER_OFFLINE ? result : MATTER_PORT_ERROR;
}

static Entry* find(Matter_Retransmission_Sender_T s, uint64_t id) {
	for (size_t i = 0; i < MATTER_RETRANSMISSION_CAPACITY; ++i)
		if (s->entries[i].id == id) return &s->entries[i];
	return NULL;
}

Matter_Retransmission_Sender_T matter_retransmission_sender_new(uint8_t max_attempts,
	const Matter_Retransmission_Port_T* port) {
	if (!max_attempts || max_attempts > MATTER_RETRANSMISSION_MAX_ATTEMPTS || !port || !port->retain ||
		!port->release || !port->ready || !port->parameters || !port->random || !port->rediscover ||
		!port->send || !port->cancel || !port->finished || !port->detach) return NULL;
	Matter_Retransmission_Sender_T s = calloc(1, sizeof(*s));
	if (!s) return NULL;
	s->table = matter_retransmission_new(max_attempts);
	if (!s->table) { free(s); return NULL; }
	s->port = *port;
	return s;
}

Matter_Result_T matter_retransmission_sender_delete(Matter_Retransmission_Sender_T s) {
	if (!s) return MATTER_OK;
	Matter_Result_T result = check(s);
	if (result != MATTER_OK) return result;
	if (!s->drained || s->pending) return MATTER_INVALID_STATE;
	s->busy = true;
	s->port.detach(s->port.user);
	matter_retransmission_delete(s->table);
	free(s);
	return MATTER_OK;
}

Matter_Result_T matter_retransmission_sender_add(Matter_Retransmission_Sender_T s,
	const Matter_Exchange_Info_T* key, uint32_t counter, const uint8_t* data, size_t size, uint64_t* id) {
	Matter_Result_T result = check(s);
	if (result != MATTER_OK) return result;
	if (!key || !key->session || !data || !size || !id) return MATTER_INVALID_ARGUMENT;
	if (size > MATTER_RETRANSMISSION_MAX_BYTES) return MATTER_LIMIT_REACHED;
	if (s->stopping) return MATTER_INVALID_STATE;
	Entry* entry = find(s, 0);
	if (!entry) return MATTER_LIMIT_REACHED;
	s->busy = true;
	result = preflight(s->port.retain(s->port.user, key, data, size));
	if (result == MATTER_OK) {
		result = matter_retransmission_add(s->table, key, counter, data, size, &entry->id);
		if (result != MATTER_OK) s->port.release(s->port.user, key, data, size);
		else *id = entry->id;
	}
	s->busy = false;
	return result;
}

/* All callbacks run with sender busy; only terminal records can be collected. */
static void collect(Matter_Retransmission_Sender_T s) {
	Matter_Retransmission_Result_T result; /* Small descriptor, no packet storage. */
	while (matter_retransmission_take(s->table, &result) == MATTER_OK) {
		s->port.finished(s->port.user, &result);
		s->port.release(s->port.user, &result.message.exchange, result.message.data, result.message.size);
		*find(s, result.message.id) = (Entry){0};
	}
}

static Matter_Result_T complete(Matter_Retransmission_Sender_T s, Matter_Retransmission_Tx_Result_T result) {
	Matter_Result_T done = matter_retransmission_complete(s->table, s->tx.id, result);
	if (done != MATTER_OK) return done;
	find(s, s->tx.message.id)->attempts = s->tx.attempt;
	s->pending = s->cancelling = false;
	s->tx = (Matter_Retransmission_Request_T){0};
	return MATTER_OK;
}

Matter_Result_T matter_retransmission_sender_complete(Matter_Retransmission_Sender_T s,
	uint64_t request, Matter_Retransmission_Tx_Result_T result) {
	Matter_Result_T checked = check(s);
	if (checked != MATTER_OK) return checked;
	if (!request || (result != MATTER_RETRANSMISSION_SENT && result != MATTER_RETRANSMISSION_RETRYABLE &&
		result != MATTER_RETRANSMISSION_FATAL)) return MATTER_INVALID_ARGUMENT;
	if (!s->pending || request != s->tx.id) return MATTER_INVALID_STATE;
	return complete(s, result);
}

static Matter_Result_T attempt(Matter_Retransmission_Sender_T s,
	const Matter_Retransmission_Message_T* message, uint64_t now_ms) {
	Entry* entry = find(s, message->id);
	Matter_Result_T result = preflight(s->port.ready(s->port.user));
	if (result != MATTER_OK) return result;
	if (entry->attempts == 1 && !entry->discovered) {
		result = preflight(s->port.rediscover(s->port.user, message));
		if (result != MATTER_OK) return result;
		entry->discovered = true;
	}
	Matter_Retransmission_Parameters_T parameters = {0};
	result = preflight(s->port.parameters(s->port.user, message, (uint8_t)(entry->attempts + 1u), &parameters));
	if (result != MATTER_OK) return result;
	uint16_t sample = 0;
	result = preflight(s->port.random(s->port.user, &sample));
	if (result != MATTER_OK) return result;
	result = matter_retransmission_prepare(s->table, message->id, &parameters, sample, now_ms, &s->tx);
	if (result != MATTER_OK) return result;
	Matter_Retransmission_Submission_T submitted = s->port.send(s->port.user, &s->tx);
	if (submitted == MATTER_RETRANSMISSION_SUBMITTED) {
		s->pending = true;
		return MATTER_PENDING;
	}
	result = complete(s, submitted == MATTER_RETRANSMISSION_REJECTED_RETRYABLE ?
		MATTER_RETRANSMISSION_RETRYABLE : MATTER_RETRANSMISSION_FATAL);
	if (result != MATTER_OK) return result;
	return submitted == MATTER_RETRANSMISSION_REJECTED_RETRYABLE ? MATTER_WOULD_BLOCK : MATTER_PORT_ERROR;
}

Matter_Result_T matter_retransmission_sender_process(Matter_Retransmission_Sender_T s, uint64_t now_ms) {
	Matter_Result_T result = check(s);
	if (result != MATTER_OK) return result;
	Matter_Retransmission_Message_T message; /* Does not alias retained TX. */
	result = matter_retransmission_next(s->table, now_ms, &message);
	if (result != MATTER_OK && result != MATTER_WOULD_BLOCK) return result;
	s->busy = true;
	collect(s);
	if (s->pending) result = MATTER_PENDING;
	else if (result == MATTER_OK) result = attempt(s, &message, now_ms);
	collect(s); /* Rejected fatal submission can finish in this process call. */
	if (s->stopping) {
		s->drained = matter_retransmission_stop(s->table) == MATTER_OK;
		if (s->drained && result != MATTER_PORT_ERROR) result = MATTER_OK;
		else if (result == MATTER_WOULD_BLOCK) result = MATTER_PENDING;
	}
	s->busy = false;
	return result;
}

Matter_Result_T matter_retransmission_sender_ack(Matter_Retransmission_Sender_T s,
	const Matter_Exchange_Info_T* key, uint32_t counter) {
	Matter_Result_T result = check(s);
	return result == MATTER_OK ? matter_retransmission_ack(s->table, key, counter) : result;
}

Matter_Result_T matter_retransmission_sender_drained(Matter_Retransmission_Sender_T s,
	const Matter_Exchange_Info_T* key) {
	Matter_Result_T result = check(s);
	return result == MATTER_OK ? matter_retransmission_drained(s->table, key) : result;
}

Matter_Result_T matter_retransmission_sender_deadline(Matter_Retransmission_Sender_T s, uint64_t* deadline_ms) {
	Matter_Result_T result = check(s);
	return result == MATTER_OK ? matter_retransmission_deadline(s->table, deadline_ms) : result;
}

Matter_Result_T matter_retransmission_sender_cancel(Matter_Retransmission_Sender_T s, uint64_t message_id) {
	Matter_Result_T result = check(s);
	if (result != MATTER_OK) return result;
	result = matter_retransmission_cancel(s->table, message_id);
	if (result == MATTER_PENDING && !s->cancelling) {
		s->cancelling = true;
		s->busy = true;
		s->port.cancel(s->port.user, s->tx.id);
		s->busy = false;
	}
	return result;
}

Matter_Result_T matter_retransmission_sender_stop(Matter_Retransmission_Sender_T s) {
	Matter_Result_T result = check(s);
	if (result != MATTER_OK) return result;
	s->stopping = true;
	result = matter_retransmission_stop(s->table);
	s->drained = result == MATTER_OK;
	return result;
}

Matter_Result_T matter_retransmission_sender_cancel_session(Matter_Retransmission_Sender_T s,
	Matter_Exchange_Session_T session) {
	Matter_Result_T result = check(s);
	if (result != MATTER_OK) return result;
	result = matter_retransmission_cancel_session(s->table, session);
	if (result == MATTER_PENDING && s->pending && s->tx.message.exchange.session == session && !s->cancelling) {
		s->cancelling = true;
		s->busy = true;
		s->port.cancel(s->port.user, s->tx.id);
		s->busy = false;
	}
	return result;
}
