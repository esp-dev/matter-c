#include "matter_retransmission.h"
#include <stdlib.h>

typedef struct {
	Matter_Retransmission_Message_T message;
	uint64_t deadline;
	Matter_Retransmission_Outcome_T outcome; /* Zero while waiting. */
	uint8_t attempts;
} Entry;

struct Matter_Retransmission {
	Entry entries[MATTER_RETRANSMISSION_CAPACITY];
	Entry* reserved;
	uint64_t last_message, last_request, now;
	uint8_t max_attempts;
	bool stopping;
};

static bool same(const Matter_Exchange_Info_T* a, const Matter_Exchange_Info_T* b) {
	return a->session == b->session && a->exchange_id == b->exchange_id && a->initiator == b->initiator;
}

static Entry* find(Matter_Retransmission_T table, uint64_t id) {
	for (size_t i = 0; i < MATTER_RETRANSMISSION_CAPACITY; ++i)
		if (table->entries[i].message.id == id) return &table->entries[i];
	return NULL;
}

static bool empty(Matter_Retransmission_T table) {
	for (size_t i = 0; i < MATTER_RETRANSMISSION_CAPACITY; ++i)
		if (table->entries[i].message.id) return false;
	return true;
}

Matter_Retransmission_T matter_retransmission_new(uint8_t max_attempts) {
	if (!max_attempts || max_attempts > MATTER_RETRANSMISSION_MAX_ATTEMPTS) return NULL;
	Matter_Retransmission_T table = calloc(1, sizeof(*table));
	if (table) table->max_attempts = max_attempts;
	return table;
}

Matter_Result_T matter_retransmission_delete(Matter_Retransmission_T table) {
	if (!table) return MATTER_OK;
	if (!empty(table)) return MATTER_INVALID_STATE;
	free(table);
	return MATTER_OK;
}

Matter_Result_T matter_retransmission_add(Matter_Retransmission_T table,
	const Matter_Exchange_Info_T* key, uint32_t counter, const uint8_t* data, size_t size, uint64_t* id) {
	if (!table || !key || !key->session || !data || !size || !id) return MATTER_INVALID_ARGUMENT;
	if (size > MATTER_RETRANSMISSION_MAX_BYTES) return MATTER_LIMIT_REACHED;
	if (table->stopping) return MATTER_INVALID_STATE;
	for (size_t i = 0; i < MATTER_RETRANSMISSION_CAPACITY; ++i) {
		Entry* entry = &table->entries[i];
		if (entry->message.id && (same(key, &entry->message.exchange) ||
			(key->session == entry->message.exchange.session && counter == entry->message.counter))) return MATTER_BUSY;
	}
	Entry* entry = find(table, 0);
	if (!entry || table->last_message == UINT64_MAX) return MATTER_LIMIT_REACHED;
	entry->message = (Matter_Retransmission_Message_T){++table->last_message, *key, counter, data, size};
	*id = entry->message.id;
	return MATTER_OK;
}

static void expire(Matter_Retransmission_T table, uint64_t now_ms) {
	table->now = now_ms;
	for (size_t i = 0; i < MATTER_RETRANSMISSION_CAPACITY; ++i) {
		Entry* entry = &table->entries[i];
		if (entry->message.id && !entry->outcome && entry != table->reserved &&
			entry->attempts == table->max_attempts && entry->deadline <= now_ms)
			entry->outcome = MATTER_RETRANSMISSION_TIMEOUT;
	}
}

Matter_Result_T matter_retransmission_next(Matter_Retransmission_T table, uint64_t now_ms,
	Matter_Retransmission_Message_T* message) {
	if (!table || !message || now_ms < table->now) return MATTER_INVALID_ARGUMENT;
	expire(table, now_ms);
	if (table->reserved) return MATTER_WOULD_BLOCK;
	Entry* candidate = NULL;
	for (size_t i = 0; i < MATTER_RETRANSMISSION_CAPACITY; ++i) {
		Entry* entry = &table->entries[i];
		if (entry->message.id && !entry->outcome && entry->deadline <= now_ms &&
			(!candidate || entry->deadline < candidate->deadline ||
			(entry->deadline == candidate->deadline && entry->message.id < candidate->message.id))) candidate = entry;
	}
	if (!candidate) return MATTER_WOULD_BLOCK;
	*message = candidate->message;
	return MATTER_OK;
}

Matter_Result_T matter_retransmission_deadline(Matter_Retransmission_T table, uint64_t* deadline_ms) {
	if (!table || !deadline_ms) return MATTER_INVALID_ARGUMENT;
	bool found = false;
	uint64_t deadline = UINT64_MAX;
	for (size_t i = 0; i < MATTER_RETRANSMISSION_CAPACITY; ++i) {
		Entry* entry = &table->entries[i];
		if (entry->message.id && !entry->outcome && entry != table->reserved) {
			if (entry->deadline < deadline) deadline = entry->deadline;
			found = true;
		}
	}
	if (!found) return MATTER_WOULD_BLOCK;
	*deadline_ms = deadline;
	return MATTER_OK;
}

static uint64_t delay(const Matter_Retransmission_Parameters_T* p, uint16_t jitter, uint8_t n) {
	/* Exact (8/5)^max(0,n-1), n <= 4. Full product < 2^63 even for UINT32_MAX
	 * intervals and maximal jitter. Round only once, after all rational factors. */
	static const uint16_t numerator[] = {1, 1, 8, 64, 512};
	static const uint16_t denominator[] = {1, 1, 5, 25, 125};
	uint64_t interval = p->peer_active ? p->active_interval_ms : p->idle_interval_ms;
	uint64_t a = interval * 11u * numerator[n] * (4u * UINT16_MAX + (uint32_t)jitter);
	uint64_t b = (uint64_t)10u * denominator[n] * 4u * UINT16_MAX;
	return a / b + (a % b != 0);
}

Matter_Result_T matter_retransmission_prepare(Matter_Retransmission_T table, uint64_t message_id,
	const Matter_Retransmission_Parameters_T* parameters, uint16_t jitter16, uint64_t now_ms,
	Matter_Retransmission_Request_T* request) {
	if (!table || !message_id || !parameters || !request || now_ms < table->now) return MATTER_INVALID_ARGUMENT;
	Entry* entry = find(table, message_id);
	if (!entry || entry->outcome) return MATTER_INVALID_STATE;
	if (table->reserved || entry->deadline > now_ms) return MATTER_WOULD_BLOCK;
	if (entry->attempts == table->max_attempts) return MATTER_INVALID_STATE; /* next expires it. */
	if (table->last_request == UINT64_MAX) return MATTER_LIMIT_REACHED;
	uint64_t wait = delay(parameters, jitter16, entry->attempts);
	entry->deadline = wait > UINT64_MAX - now_ms ? UINT64_MAX : now_ms + wait;
	table->now = now_ms;
	table->reserved = entry;
	*request = (Matter_Retransmission_Request_T){++table->last_request, entry->message, entry->deadline,
		(uint8_t)(entry->attempts + 1u)};
	return MATTER_OK;
}

Matter_Result_T matter_retransmission_complete(Matter_Retransmission_T table, uint64_t request_id,
	Matter_Retransmission_Tx_Result_T result) {
	if (!table || !request_id || (result != MATTER_RETRANSMISSION_SENT &&
		result != MATTER_RETRANSMISSION_RETRYABLE && result != MATTER_RETRANSMISSION_FATAL)) return MATTER_INVALID_ARGUMENT;
	if (!table->reserved || table->last_request != request_id) return MATTER_INVALID_STATE;
	Entry* entry = table->reserved;
	++entry->attempts;
	if (!entry->outcome && result == MATTER_RETRANSMISSION_FATAL) entry->outcome = MATTER_RETRANSMISSION_FAILED;
	table->reserved = NULL;
	return MATTER_OK;
}

Matter_Result_T matter_retransmission_ack(Matter_Retransmission_T table,
	const Matter_Exchange_Info_T* key, uint32_t counter) {
	if (!table || !key || !key->session) return MATTER_INVALID_ARGUMENT;
	for (size_t i = 0; i < MATTER_RETRANSMISSION_CAPACITY; ++i) {
		Entry* entry = &table->entries[i];
		if (entry->message.id && !entry->outcome && same(key, &entry->message.exchange) &&
			entry->message.counter == counter && (entry->attempts || entry == table->reserved)) {
			entry->outcome = MATTER_RETRANSMISSION_ACKNOWLEDGED;
			break;
		}
	}
	return MATTER_OK;
}

Matter_Result_T matter_retransmission_cancel(Matter_Retransmission_T table, uint64_t message_id) {
	if (!table || !message_id) return MATTER_INVALID_ARGUMENT;
	Entry* entry = find(table, message_id);
	if (!entry) return MATTER_INVALID_STATE;
	if (!entry->outcome) entry->outcome = MATTER_RETRANSMISSION_CANCELLED;
	return entry == table->reserved ? MATTER_PENDING : MATTER_OK;
}

Matter_Result_T matter_retransmission_take(Matter_Retransmission_T table, Matter_Retransmission_Result_T* result) {
	if (!table || !result) return MATTER_INVALID_ARGUMENT;
	Entry* candidate = NULL;
	for (size_t i = 0; i < MATTER_RETRANSMISSION_CAPACITY; ++i) {
		Entry* entry = &table->entries[i];
		if (entry->message.id && entry->outcome && entry != table->reserved &&
			(!candidate || entry->message.id < candidate->message.id)) candidate = entry;
	}
	if (!candidate) return MATTER_WOULD_BLOCK;
	*result = (Matter_Retransmission_Result_T){candidate->message, candidate->outcome, candidate->attempts};
	*candidate = (Entry){0};
	return MATTER_OK;
}

Matter_Result_T matter_retransmission_drained(Matter_Retransmission_T table, const Matter_Exchange_Info_T* key) {
	if (!table || !key || !key->session) return MATTER_INVALID_ARGUMENT;
	for (size_t i = 0; i < MATTER_RETRANSMISSION_CAPACITY; ++i)
		if (table->entries[i].message.id && same(key, &table->entries[i].message.exchange)) return MATTER_PENDING;
	return MATTER_OK;
}

Matter_Result_T matter_retransmission_stop(Matter_Retransmission_T table) {
	if (!table) return MATTER_INVALID_ARGUMENT;
	table->stopping = true;
	return empty(table) ? MATTER_OK : MATTER_PENDING;
}

Matter_Result_T matter_retransmission_cancel_session(Matter_Retransmission_T table, Matter_Exchange_Session_T session) {
	if (!table || !session) return MATTER_INVALID_ARGUMENT;
	Matter_Result_T result = MATTER_OK;
	for (size_t i = 0; i < MATTER_RETRANSMISSION_CAPACITY; ++i) {
		Entry* entry = &table->entries[i];
		if (!entry->message.id || entry->message.exchange.session != session) continue;
		if (!entry->outcome) entry->outcome = MATTER_RETRANSMISSION_CANCELLED;
		result = MATTER_PENDING; /* Includes terminal notifications not yet taken. */
	}
	return result;
}
