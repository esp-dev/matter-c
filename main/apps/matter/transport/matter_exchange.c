#include "matter_exchange.h"
#include <stdlib.h>

typedef struct {
	Matter_Exchange_Handle_T handle; /* Zero = free slot. */
	Matter_Exchange_Info_T info;
	bool closing;
} Entry;

struct Matter_Exchange_Table {
	Matter_T owner;
	Matter_Exchange_Close_Port_T close_port;
	Entry entries[MATTER_EXCHANGE_CAPACITY];
	Matter_Operation_Id_T lease;
	Matter_Exchange_Handle_T last_handle;
	uint16_t next_id;
	bool active, stopping, busy;
};

static Matter_Result_T ready(Matter_Exchange_Table_T table) {
	if (!table) return MATTER_INVALID_ARGUMENT;
	if (table->busy) return MATTER_BUSY;
	if (!table->active || table->stopping || matter_get_state(table->owner) != MATTER_STATE_RUNNING)
		return MATTER_INVALID_STATE;
	return MATTER_OK;
}

Matter_Result_T matter_exchange_check(Matter_Exchange_Table_T table) {
	return ready(table);
}

static Entry* find_handle(Matter_Exchange_Table_T table, Matter_Exchange_Handle_T handle) {
	for (size_t i = 0; i < MATTER_EXCHANGE_CAPACITY; ++i)
		if (table->entries[i].handle == handle) return &table->entries[i];
	return NULL;
}

static Entry* find_key(Matter_Exchange_Table_T table, Matter_Exchange_Session_T session,
	uint16_t exchange_id, bool initiator) {
	for (size_t i = 0; i < MATTER_EXCHANGE_CAPACITY; ++i) {
		Entry* entry = &table->entries[i];
		if (entry->handle && entry->info.session == session &&
			entry->info.exchange_id == exchange_id && entry->info.initiator == initiator) return entry;
	}
	return NULL;
}

Matter_Exchange_Table_T matter_exchange_new(Matter_T owner, uint16_t initial_id) {
	if (!owner) return NULL;
	Matter_Exchange_Table_T table = calloc(1, sizeof(*table));
	if (!table) return NULL;
	table->owner = owner;
	table->next_id = initial_id;
	return table;
}

Matter_Result_T matter_exchange_delete(Matter_Exchange_Table_T table) {
	if (!table) return MATTER_OK;
	if (table->busy) return MATTER_BUSY;
	if (table->active) return MATTER_INVALID_STATE;
	free(table);
	return MATTER_OK;
}

Matter_Result_T matter_exchange_set_close_port(Matter_Exchange_Table_T table,
	const Matter_Exchange_Close_Port_T* port) {
	if (!table) return MATTER_INVALID_ARGUMENT;
	if (table->busy) return MATTER_BUSY;
	if (table->active) return MATTER_INVALID_STATE;
	if (port && !port->prepare) return MATTER_INVALID_ARGUMENT;
	table->close_port = port ? *port : (Matter_Exchange_Close_Port_T){0};
	return MATTER_OK;
}

/* Called with table->busy set; callback cannot alter entries while iterating. */
static Matter_Result_T prepare_close(Matter_Exchange_Table_T table, Entry* entry) {
	entry->closing = true;
	if (!table->close_port.prepare) return MATTER_OK;
	Matter_Result_T result = table->close_port.prepare(table->close_port.user, entry->handle, &entry->info);
	return result == MATTER_OK || result == MATTER_PENDING ? result : MATTER_PORT_ERROR;
}

static Matter_Result_T prepare_batch(Matter_Exchange_Table_T table, Matter_Exchange_Session_T session) {
	Matter_Result_T result = MATTER_OK;
	for (size_t i = 0; i < MATTER_EXCHANGE_CAPACITY; ++i) {
		Entry* entry = &table->entries[i];
		if (!entry->handle || (session && entry->info.session != session)) continue;
		Matter_Result_T current = prepare_close(table, entry);
		if (current == MATTER_PORT_ERROR || (current == MATTER_PENDING && result == MATTER_OK)) result = current;
	}
	return result;
}

static void stop_requested(void* user, Matter_Operation_Id_T id) {
	Matter_Exchange_Table_T table = user;
	(void)id;
	table->stopping = true;
}

Matter_Result_T matter_exchange_start(Matter_Exchange_Table_T table) {
	if (!table) return MATTER_INVALID_ARGUMENT;
	if (table->busy) return MATTER_BUSY;
	if (table->active) return table->stopping ? MATTER_INVALID_STATE : MATTER_OK;
	Matter_Operation_Port_T operation = {table, stop_requested, NULL};
	Matter_Result_T result = matter_operation_begin(table->owner, &operation, &table->lease);
	if (result != MATTER_OK) return result;
	table->active = true;
	table->stopping = false;
	return MATTER_OK;
}

Matter_Result_T matter_exchange_stop(Matter_Exchange_Table_T table) {
	if (!table) return MATTER_INVALID_ARGUMENT;
	if (table->busy) return MATTER_BUSY;
	if (!table->active) return MATTER_OK;
	Matter_Result_T result = matter_operation_cancel(table->owner, table->lease);
	return result == MATTER_OK ? MATTER_PENDING : result;
}

Matter_Result_T matter_exchange_process(Matter_Exchange_Table_T table) {
	if (!table) return MATTER_INVALID_ARGUMENT;
	if (table->busy) return MATTER_BUSY;
	if (!table->active || !table->stopping) return MATTER_OK;
	table->busy = true;
	Matter_Result_T result = prepare_batch(table, 0);
	if (result == MATTER_OK) {
		for (size_t i = 0; i < MATTER_EXCHANGE_CAPACITY; ++i) table->entries[i] = (Entry){0};
		result = matter_operation_complete(table->owner, table->lease, MATTER_OPERATION_CANCELLED);
		if (result == MATTER_OK) table->active = false;
	}
	table->busy = false;
	return result;
}

static Matter_Result_T insert(Matter_Exchange_Table_T table, Matter_Exchange_Session_T session,
	uint16_t exchange_id, bool initiator, Matter_Exchange_Handle_T* handle) {
	if (find_key(table, session, exchange_id, initiator)) return MATTER_BUSY;
	Entry* entry = find_handle(table, 0);
	if (!entry || table->last_handle == UINT64_MAX) return MATTER_LIMIT_REACHED;
	*entry = (Entry){.handle = ++table->last_handle, .info = {session, exchange_id, initiator}};
	*handle = entry->handle;
	return MATTER_OK;
}

Matter_Result_T matter_exchange_initiate(Matter_Exchange_Table_T table,
	Matter_Exchange_Session_T session, Matter_Exchange_Handle_T* handle) {
	Matter_Result_T result = ready(table);
	if (result != MATTER_OK) return result;
	if (!session || !handle) return MATTER_INVALID_ARGUMENT;
	size_t count = 0;
	for (size_t i = 0; i < MATTER_EXCHANGE_CAPACITY; ++i)
		if (table->entries[i].handle && table->entries[i].info.session == session &&
			table->entries[i].info.initiator) ++count;
	if (count >= MATTER_EXCHANGE_INITIATORS_PER_SESSION) return MATTER_LIMIT_REACHED;
	result = insert(table, session, table->next_id, true, handle);
	if (result == MATTER_OK) table->next_id = (uint16_t)(table->next_id + 1u);
	return result;
}

Matter_Result_T matter_exchange_accept(Matter_Exchange_Table_T table,
	Matter_Exchange_Session_T session, uint16_t exchange_id, Matter_Exchange_Handle_T* handle) {
	Matter_Result_T result = ready(table);
	if (result != MATTER_OK) return result;
	if (!session || !handle) return MATTER_INVALID_ARGUMENT;
	return insert(table, session, exchange_id, false, handle);
}

Matter_Result_T matter_exchange_match(Matter_Exchange_Table_T table,
	Matter_Exchange_Session_T session, uint16_t exchange_id, bool incoming_initiator,
	Matter_Exchange_Handle_T* handle) {
	Matter_Result_T result = ready(table);
	if (result != MATTER_OK) return result;
	if (!session || !handle) return MATTER_INVALID_ARGUMENT;
	Entry* entry = find_key(table, session, exchange_id, !incoming_initiator);
	if (!entry) return MATTER_INVALID_STATE;
	*handle = entry->handle;
	return MATTER_OK;
}

Matter_Result_T matter_exchange_get(Matter_Exchange_Table_T table,
	Matter_Exchange_Handle_T handle, Matter_Exchange_Info_T* info) {
	Matter_Result_T result = ready(table);
	if (result != MATTER_OK) return result;
	if (!handle || !info) return MATTER_INVALID_ARGUMENT;
	Entry* entry = find_handle(table, handle);
	if (!entry) return MATTER_INVALID_STATE;
	*info = entry->info;
	return MATTER_OK;
}

Matter_Result_T matter_exchange_is_closing(Matter_Exchange_Table_T table,
	Matter_Exchange_Handle_T handle, bool* closing) {
	Matter_Result_T result = ready(table);
	if (result != MATTER_OK) return result;
	if (!handle || !closing) return MATTER_INVALID_ARGUMENT;
	Entry* entry = find_handle(table, handle);
	if (!entry) return MATTER_INVALID_STATE;
	*closing = entry->closing;
	return MATTER_OK;
}

Matter_Result_T matter_exchange_release(Matter_Exchange_Table_T table, Matter_Exchange_Handle_T handle) {
	Matter_Result_T result = ready(table);
	if (result != MATTER_OK) return result;
	if (!handle) return MATTER_INVALID_ARGUMENT;
	Entry* entry = find_handle(table, handle);
	if (!entry) return MATTER_INVALID_STATE;
	table->busy = true;
	result = prepare_close(table, entry);
	if (result == MATTER_OK) *entry = (Entry){0};
	table->busy = false;
	return result;
}

Matter_Result_T matter_exchange_release_session(Matter_Exchange_Table_T table,
	Matter_Exchange_Session_T session) {
	Matter_Result_T result = ready(table);
	if (result != MATTER_OK) return result;
	if (!session) return MATTER_INVALID_ARGUMENT;
	table->busy = true;
	result = prepare_batch(table, session);
	if (result == MATTER_OK)
		for (size_t i = 0; i < MATTER_EXCHANGE_CAPACITY; ++i)
			if (table->entries[i].handle && table->entries[i].info.session == session)
				table->entries[i] = (Entry){0};
	table->busy = false;
	return result;
}
