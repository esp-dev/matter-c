#include "matter_unsecured.h"
#include "matter_reception.h"
#include <stdlib.h>

typedef struct {
	Matter_Exchange_Session_T token;
	uint64_t node;
	Matter_Reception_T reception;
	uint16_t pins;
	bool initiator;
} Entry;

struct Matter_Unsecured {
	Entry entries[MATTER_UNSECURED_CAPACITY];
	Matter_Exchange_Session_T next, last;
	bool exhausted, busy;
};

static Matter_Result_T check(Matter_Unsecured_T table) {
	if (!table) return MATTER_INVALID_ARGUMENT;
	return table->busy ? MATTER_BUSY : MATTER_OK;
}
static bool valid_node(uint64_t node) {
	return node && node <= UINT64_C(0xffffffefffffffff);
}
static Entry* find_node(Matter_Unsecured_T table, uint64_t node) {
	for (size_t i = 0; i < MATTER_UNSECURED_CAPACITY; ++i)
		if (table->entries[i].token && table->entries[i].node == node) return &table->entries[i];
	return NULL;
}
static Matter_Result_T find_token(Matter_Unsecured_T table, Matter_Exchange_Session_T token, Entry** entry) {
	Matter_Result_T result = check(table);
	if (result != MATTER_OK) return result;
	if (!token) return MATTER_INVALID_ARGUMENT;
	for (size_t i = 0; i < MATTER_UNSECURED_CAPACITY; ++i)
		if (table->entries[i].token == token) { *entry = &table->entries[i]; return MATTER_OK; }
	return MATTER_INVALID_STATE;
}
static Matter_Result_T vacant(Matter_Unsecured_T table, Entry** entry) {
	if (table->exhausted) return MATTER_LIMIT_REACHED;
	for (size_t i = 0; i < MATTER_UNSECURED_CAPACITY; ++i)
		if (!table->entries[i].token) { *entry = &table->entries[i]; return MATTER_OK; }
	return MATTER_BUSY;
}
static void insert(Matter_Unsecured_T table, Entry* entry, uint64_t node, bool initiator,
	Matter_Exchange_Session_T* token) {
	*entry = (Entry){.token = table->next, .node = node, .initiator = initiator};
	matter_reception_reset(&entry->reception, MATTER_RECEPTION_UNSECURED);
	*token = entry->token;
	if (table->next == table->last) table->exhausted = true;
	else ++table->next;
}

Matter_Unsecured_T matter_unsecured_new(Matter_Exchange_Session_T first, Matter_Exchange_Session_T last) {
	if (!first || first > last) return NULL;
	Matter_Unsecured_T table = calloc(1, sizeof(*table));
	if (!table) return NULL;
	table->next = first; table->last = last;
	return table;
}
Matter_Result_T matter_unsecured_delete(Matter_Unsecured_T table) {
	if (!table) return MATTER_OK;
	if (table->busy) return MATTER_BUSY;
	for (size_t i = 0; i < MATTER_UNSECURED_CAPACITY; ++i)
		if (table->entries[i].token) return MATTER_INVALID_STATE;
	free(table);
	return MATTER_OK;
}
Matter_Result_T matter_unsecured_initiate(Matter_Unsecured_T table,
	Matter_Unsecured_Random_T random, void* user, Matter_Exchange_Session_T* session) {
	Matter_Result_T result = check(table);
	if (result != MATTER_OK) return result;
	if (!random || !session) return MATTER_INVALID_ARGUMENT;
	Entry* entry;
	result = vacant(table, &entry);
	if (result != MATTER_OK) return result;
	table->busy = true;
	for (unsigned i = 0; i < MATTER_UNSECURED_RANDOM_ATTEMPTS; ++i) {
		uint64_t sample = 0;
		result = random(user, &sample);
		if (result != MATTER_OK) {
			if (result != MATTER_WOULD_BLOCK && result != MATTER_OFFLINE) result = MATTER_PORT_ERROR;
			break;
		}
		result = MATTER_LIMIT_REACHED;
		/* Avoid all existing IDs, including responders, to keep lookup unambiguous. */
		if (!valid_node(sample) || find_node(table, sample)) continue;
		insert(table, entry, sample, true, session);
		result = MATTER_OK;
		break;
	}
	table->busy = false;
	return result;
}
Matter_Result_T matter_unsecured_resolve(Matter_Unsecured_T table,
	const Matter_Message_Header_T* header, bool allow_create, Matter_Exchange_Session_T* session) {
	Matter_Result_T result = check(table);
	if (result != MATTER_OK) return result;
	if (!header || !session) return MATTER_INVALID_ARGUMENT;
	unsigned dest = header->message_flags & MATTER_MESSAGE_DESTINATION_MASK;
	bool source = (header->message_flags & MATTER_MESSAGE_SOURCE_PRESENT) != 0;
	if ((header->message_flags & 0xf0) || header->session_id ||
		(header->security_flags & (MATTER_MESSAGE_SESSION_MASK | MATTER_MESSAGE_PRIVACY | MATTER_MESSAGE_CONTROL)) ||
		(source ? dest != MATTER_MESSAGE_DESTINATION_NONE : dest != MATTER_MESSAGE_DESTINATION_NODE))
		return MATTER_INVALID_ARGUMENT;
	uint64_t node = source ? header->source_node_id : header->destination_id;
	if (!valid_node(node)) return MATTER_INVALID_ARGUMENT;
	Entry* entry = find_node(table, node);
	if (entry) { *session = entry->token; return MATTER_OK; }
	if (!source || !allow_create) return MATTER_INVALID_STATE;
	result = vacant(table, &entry);
	if (result != MATTER_OK) return result;
	insert(table, entry, node, false, session);
	return MATTER_OK;
}
Matter_Result_T matter_unsecured_get(Matter_Unsecured_T table,
	Matter_Exchange_Session_T session, Matter_Unsecured_Info_T* info) {
	Entry* entry;
	Matter_Result_T result = find_token(table, session, &entry);
	if (result != MATTER_OK) return result;
	if (!info) return MATTER_INVALID_ARGUMENT;
	*info = (Matter_Unsecured_Info_T){entry->node, entry->pins, entry->initiator};
	return MATTER_OK;
}
Matter_Result_T matter_unsecured_pin(Matter_Unsecured_T table, Matter_Exchange_Session_T session) {
	Entry* entry;
	Matter_Result_T result = find_token(table, session, &entry);
	if (result != MATTER_OK) return result;
	if (entry->pins == UINT16_MAX) return MATTER_LIMIT_REACHED;
	++entry->pins;
	return MATTER_OK;
}
Matter_Result_T matter_unsecured_unpin(Matter_Unsecured_T table, Matter_Exchange_Session_T session) {
	Entry* entry;
	Matter_Result_T result = find_token(table, session, &entry);
	if (result != MATTER_OK) return result;
	if (!entry->pins) return MATTER_INVALID_STATE;
	--entry->pins;
	return MATTER_OK;
}
Matter_Result_T matter_unsecured_remove(Matter_Unsecured_T table, Matter_Exchange_Session_T session) {
	Entry* entry;
	Matter_Result_T result = find_token(table, session, &entry);
	if (result != MATTER_OK) return result;
	if (entry->pins) return MATTER_BUSY;
	*entry = (Entry){0};
	return MATTER_OK;
}
Matter_Result_T matter_unsecured_classify(Matter_Unsecured_T table,
	Matter_Exchange_Session_T session, uint32_t counter, bool* duplicate) {
	Entry* entry;
	Matter_Result_T result = find_token(table, session, &entry);
	if (result != MATTER_OK) return result;
	if (!duplicate) return MATTER_INVALID_ARGUMENT;
	if (!entry->pins) return MATTER_INVALID_STATE;
	return matter_reception_classify(&entry->reception, counter, duplicate);
}
Matter_Result_T matter_unsecured_commit(Matter_Unsecured_T table,
	Matter_Exchange_Session_T session, uint32_t counter, bool* duplicate) {
	Entry* entry;
	Matter_Result_T result = find_token(table, session, &entry);
	if (result != MATTER_OK) return result;
	if (!duplicate) return MATTER_INVALID_ARGUMENT;
	if (!entry->pins) return MATTER_INVALID_STATE;
	return matter_reception_commit(&entry->reception, counter, duplicate);
}
