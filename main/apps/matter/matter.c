#include "matter.h"
#include <stdbool.h>
#include <stdlib.h>

typedef struct {
	Matter_Operation_Port_T port;
	Matter_Operation_Id_T id; /* Zero marks a free slot, never an issued ID. */
	bool cancelling;
} Matter_Operation_T;

struct Matter {
	Matter_Port_T port;
	Matter_State_T state;
	bool notifying;
	Matter_Operation_T operations[MATTER_OPERATION_CAPACITY];
	Matter_Operation_Id_T last_id;
	size_t pending;
};

static Matter_Operation_T* find_operation(Matter_T matter, Matter_Operation_Id_T id) {
	for (size_t i = 0; i < MATTER_OPERATION_CAPACITY; ++i)
		if (matter->operations[i].id == id) return &matter->operations[i];
	return NULL;
}

Matter_T matter_new(const Matter_Port_T* port) {
	Matter_T matter = calloc(1, sizeof(struct Matter));
	if (!matter) return NULL;
	if (port) matter->port = *port;
	else matter->port = (Matter_Port_T){0};
	matter->state = MATTER_STATE_STOPPED;
	return matter;
}

static Matter_Result_T set_state(Matter_T matter, Matter_State_T state) {
	if (!matter) return MATTER_INVALID_ARGUMENT;
	if (matter->notifying) return MATTER_BUSY;
	if (matter->state == state) return MATTER_OK;
	matter->state = state;
	if (matter->port.state_changed) {
		matter->notifying = true;
		matter->port.state_changed(matter->port.user, state);
		matter->notifying = false;
	}
	return MATTER_OK;
}

Matter_Result_T matter_start(Matter_T matter) {
	if (!matter) return MATTER_INVALID_ARGUMENT;
	if (matter->notifying) return MATTER_BUSY;
	if (matter->state == MATTER_STATE_STOPPING) return MATTER_INVALID_STATE;
	return set_state(matter, MATTER_STATE_RUNNING);
}

Matter_Result_T matter_stop(Matter_T matter) {
	if (!matter) return MATTER_INVALID_ARGUMENT;
	if (matter->notifying) return MATTER_BUSY;
	if (matter->pending) {
		set_state(matter, MATTER_STATE_STOPPING);
		for (size_t i = 0; i < MATTER_OPERATION_CAPACITY; ++i)
			if (matter->operations[i].id) matter_operation_cancel(matter, matter->operations[i].id);
		return MATTER_PENDING;
	}
	return set_state(matter, MATTER_STATE_STOPPED);
}

Matter_Result_T matter_delete(Matter_T matter) {
	if (!matter) return MATTER_OK;
	if (matter->notifying) return MATTER_BUSY;
	if (matter->state != MATTER_STATE_STOPPED) return MATTER_INVALID_STATE;
	free(matter);
	return MATTER_OK;
}

Matter_State_T matter_get_state(Matter_T matter) {
	return matter ? matter->state : MATTER_STATE_INVALID;
}

Matter_Result_T matter_operation_begin(Matter_T matter, const Matter_Operation_Port_T* port,
	Matter_Operation_Id_T* id) {
	if (!matter) return MATTER_INVALID_ARGUMENT;
	if (matter->notifying) return MATTER_BUSY;
	if (!port || !port->cancel || !id) return MATTER_INVALID_ARGUMENT;
	if (matter->state != MATTER_STATE_RUNNING) return MATTER_INVALID_STATE;
	Matter_Operation_T* operation = find_operation(matter, 0);
	if (!operation) return MATTER_BUSY;
	if (matter->last_id == UINT64_MAX) return MATTER_LIMIT_REACHED;
	*operation = (Matter_Operation_T){.port = *port, .id = ++matter->last_id};
	++matter->pending;
	*id = operation->id;
	return MATTER_OK;
}

Matter_Result_T matter_operation_cancel(Matter_T matter, Matter_Operation_Id_T id) {
	if (!matter) return MATTER_INVALID_ARGUMENT;
	if (matter->notifying) return MATTER_BUSY;
	if (!id) return MATTER_INVALID_ARGUMENT;
	Matter_Operation_T* operation = find_operation(matter, id);
	if (!operation) return MATTER_INVALID_STATE;
	if (!operation->cancelling) {
		operation->cancelling = true;
		matter->notifying = true;
		operation->port.cancel(operation->port.user, id);
		matter->notifying = false;
	}
	return MATTER_OK;
}

Matter_Result_T matter_operation_complete(Matter_T matter, Matter_Operation_Id_T id,
	Matter_Operation_Result_T result) {
	if (!matter) return MATTER_INVALID_ARGUMENT;
	if (matter->notifying) return MATTER_BUSY;
	if (!id || (result != MATTER_OPERATION_SUCCEEDED && result != MATTER_OPERATION_FAILED &&
		result != MATTER_OPERATION_CANCELLED)) return MATTER_INVALID_ARGUMENT;
	Matter_Operation_T* operation = find_operation(matter, id);
	if (!operation) return MATTER_INVALID_STATE;
	Matter_Operation_Port_T port = operation->port;
	*operation = (Matter_Operation_T){0};
	--matter->pending;
	if (port.completed) {
		matter->notifying = true;
		port.completed(port.user, id, result);
		matter->notifying = false;
	}
	if (matter->state == MATTER_STATE_STOPPING && !matter->pending) set_state(matter, MATTER_STATE_STOPPED);
	return MATTER_OK;
}
