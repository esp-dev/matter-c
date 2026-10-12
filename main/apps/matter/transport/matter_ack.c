#include "matter_ack.h"
#include <stdlib.h>

typedef struct {
	Matter_Exchange_Info_T key; /* session == 0 marks a free slot. */
	uint64_t deadline;
	uint32_t counter;
	bool sent, closing, discarded;
} Entry;

struct Matter_Ack_Table {
	Entry entries[MATTER_ACK_CAPACITY];
	Entry immediate;
	Entry* reserved;
	uint64_t last_id, now;
	bool standalone, stopping;
};

static bool same(const Matter_Exchange_Info_T* a, const Matter_Exchange_Info_T* b) {
	return a->session == b->session && a->exchange_id == b->exchange_id && a->initiator == b->initiator;
}

static bool valid(Matter_Ack_Table_T table, const Matter_Exchange_Info_T* key) {
	return table && key && key->session;
}

static Entry* find(Matter_Ack_Table_T table, const Matter_Exchange_Info_T* key) {
	for (size_t i = 0; i < MATTER_ACK_CAPACITY; ++i)
		if (same(&table->entries[i].key, key)) return &table->entries[i];
	return NULL;
}

static bool reserved_key(Matter_Ack_Table_T table, const Matter_Exchange_Info_T* key) {
	return table->reserved && same(&table->reserved->key, key);
}

static bool empty(Matter_Ack_Table_T table) {
	if (table->reserved || table->immediate.key.session) return false;
	for (size_t i = 0; i < MATTER_ACK_CAPACITY; ++i)
		if (table->entries[i].key.session) return false;
	return true;
}

static void prune(Matter_Ack_Table_T table) {
	for (size_t i = 0; i < MATTER_ACK_CAPACITY; ++i) {
		Entry* entry = &table->entries[i];
		if (entry->key.session && entry->closing && entry->sent && !reserved_key(table, &entry->key))
			*entry = (Entry){0};
	}
}

Matter_Ack_Table_T matter_ack_new(void) {
	return calloc(1, sizeof(struct Matter_Ack_Table));
}

Matter_Result_T matter_ack_delete(Matter_Ack_Table_T table) {
	if (!table) return MATTER_OK;
	if (!empty(table)) return MATTER_INVALID_STATE;
	free(table);
	return MATTER_OK;
}

Matter_Result_T matter_ack_record(Matter_Ack_Table_T table,
	const Matter_Exchange_Info_T* key, uint32_t counter, uint64_t received_ms) {
	if (!valid(table, key)) return MATTER_INVALID_ARGUMENT;
	if (table->stopping) return MATTER_INVALID_STATE;
	if (received_ms > table->now) table->now = received_ms;
	Entry* entry = find(table, key);
	if (entry && entry->closing) return MATTER_INVALID_STATE;
	if (reserved_key(table, key)) return MATTER_WOULD_BLOCK;
	if (entry) {
		if (entry->counter == counter) return MATTER_OK;
		if (!entry->sent) {
			if (entry->deadline > table->now) entry->deadline = table->now;
			return MATTER_WOULD_BLOCK;
		}
	} else {
		for (size_t i = 0; i < MATTER_ACK_CAPACITY; ++i)
			if (!table->entries[i].key.session) { entry = &table->entries[i]; break; }
		if (!entry) return MATTER_LIMIT_REACHED;
	}
	uint64_t deadline = received_ms > UINT64_MAX - MATTER_ACK_TIMEOUT_MS ?
		UINT64_MAX : received_ms + MATTER_ACK_TIMEOUT_MS;
	*entry = (Entry){.key = *key, .counter = counter, .deadline = deadline};
	return MATTER_OK;
}

Matter_Result_T matter_ack_immediate(Matter_Ack_Table_T table,
	const Matter_Exchange_Info_T* key, uint32_t counter) {
	if (!valid(table, key)) return MATTER_INVALID_ARGUMENT;
	if (table->stopping) return MATTER_INVALID_STATE;
	if (table->immediate.key.session) return MATTER_WOULD_BLOCK;
	table->immediate = (Entry){.key = *key, .counter = counter};
	return MATTER_OK;
}

static Matter_Result_T reserve(Matter_Ack_Table_T table, Entry* entry,
	bool standalone, Matter_Ack_Request_T* request) {
	if (table->last_id == UINT64_MAX) return MATTER_LIMIT_REACHED;
	table->reserved = entry;
	table->standalone = standalone;
	*request = (Matter_Ack_Request_T){++table->last_id, entry->key, entry->counter, standalone};
	return MATTER_OK;
}

Matter_Result_T matter_ack_next(Matter_Ack_Table_T table, uint64_t now_ms,
	Matter_Ack_Request_T* request) {
	if (!table || !request || now_ms < table->now) return MATTER_INVALID_ARGUMENT;
	table->now = now_ms;
	if (table->reserved) return MATTER_WOULD_BLOCK;
	Entry* candidate = NULL;
	if (table->immediate.key.session) candidate = &table->immediate;
	else for (size_t i = 0; i < MATTER_ACK_CAPACITY; ++i) {
		Entry* entry = &table->entries[i];
		if (entry->key.session && !entry->sent && (entry->closing || entry->deadline <= now_ms) &&
			(!candidate || entry->deadline < candidate->deadline)) candidate = entry;
	}
	return candidate ? reserve(table, candidate, true, request) : MATTER_WOULD_BLOCK;
}

Matter_Result_T matter_ack_piggyback(Matter_Ack_Table_T table,
	const Matter_Exchange_Info_T* key, Matter_Ack_Request_T* request) {
	if (!valid(table, key) || !request) return MATTER_INVALID_ARGUMENT;
	if (table->stopping) return MATTER_INVALID_STATE;
	if (table->reserved) return MATTER_WOULD_BLOCK;
	Entry* entry = find(table, key);
	if (!entry || entry->closing) return MATTER_INVALID_STATE;
	return reserve(table, entry, false, request);
}

Matter_Result_T matter_ack_complete(Matter_Ack_Table_T table, uint64_t id,
	Matter_Operation_Result_T result) {
	if (!table || !id || (result != MATTER_OPERATION_SUCCEEDED &&
		result != MATTER_OPERATION_FAILED && result != MATTER_OPERATION_CANCELLED)) return MATTER_INVALID_ARGUMENT;
	if (!table->reserved || table->last_id != id) return MATTER_INVALID_STATE;
	Entry* entry = table->reserved;
	if (entry->discarded) *entry = (Entry){0};
	else if (result == MATTER_OPERATION_SUCCEEDED) {
		if (entry == &table->immediate) {
			Entry* normal = find(table, &entry->key);
			if (normal && normal->counter == entry->counter) normal->sent = true;
			*entry = (Entry){0};
		} else if (table->standalone) entry->sent = true;
		else *entry = (Entry){0};
	}
	table->reserved = NULL;
	prune(table);
	return MATTER_OK;
}

Matter_Result_T matter_ack_close(Matter_Ack_Table_T table, const Matter_Exchange_Info_T* key) {
	if (!valid(table, key)) return MATTER_INVALID_ARGUMENT;
	Entry* entry = find(table, key);
	if (entry) entry->closing = true;
	prune(table);
	return find(table, key) || same(&table->immediate.key, key) || reserved_key(table, key) ?
		MATTER_PENDING : MATTER_OK;
}

Matter_Result_T matter_ack_stop(Matter_Ack_Table_T table) {
	if (!table) return MATTER_INVALID_ARGUMENT;
	table->stopping = true;
	for (size_t i = 0; i < MATTER_ACK_CAPACITY; ++i) table->entries[i].closing = true;
	prune(table);
	return empty(table) ? MATTER_OK : MATTER_PENDING;
}

Matter_Result_T matter_ack_discard_session(Matter_Ack_Table_T table, Matter_Exchange_Session_T session) {
	if (!table || !session) return MATTER_INVALID_ARGUMENT;
	Matter_Result_T result = MATTER_OK;
	for (size_t i = 0; i <= MATTER_ACK_CAPACITY; ++i) {
		Entry* entry = i == MATTER_ACK_CAPACITY ? &table->immediate : &table->entries[i];
		if (entry->key.session != session) continue;
		if (entry == table->reserved) { entry->discarded = true; result = MATTER_PENDING; }
		else *entry = (Entry){0};
	}
	return result;
}
