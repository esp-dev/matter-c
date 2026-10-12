#include "matter_mdns.h"
#include <stdlib.h>

struct Matter_Mdns {
	Matter_T owner;
	Matter_Mdns_Port_T port;
	Matter_Mdns_Record_T record;
	Matter_Operation_Id_T lease;
	uint64_t generation, request;
	bool active, stopping, ready, published, pending, publishing, cancelling, failed, busy;
};

Matter_Mdns_T matter_mdns_new(Matter_T owner, const Matter_Mdns_Port_T* port,
	const Matter_Mdns_Record_T* record) {
	if (!owner || !port || !port->publish || !port->remove || !port->cancel || !port->detach ||
		!record || !record->instance || !record->instance[0] || !record->service || !record->service[0] ||
		!record->protocol || !record->protocol[0] || !record->port ||
		(record->txt_count && !record->txt) || (record->subtype_count && !record->subtypes)) return NULL;
	Matter_Mdns_T mdns = calloc(1, sizeof(struct Matter_Mdns));
	if (!mdns) return NULL;
	mdns->owner = owner;
	mdns->port = *port;
	mdns->record = *record;
	return mdns;
}

Matter_Result_T matter_mdns_delete(Matter_Mdns_T mdns) {
	if (!mdns) return MATTER_OK;
	if (mdns->busy) return MATTER_BUSY;
	if (mdns->active) return MATTER_INVALID_STATE;
	mdns->busy = true;
	mdns->port.detach(mdns->port.user);
	free(mdns);
	return MATTER_OK;
}

static void stop_requested(void* user, Matter_Operation_Id_T id) {
	Matter_Mdns_T mdns = user;
	(void)id;
	mdns->stopping = true;
}

Matter_Result_T matter_mdns_start(Matter_Mdns_T mdns) {
	if (!mdns) return MATTER_INVALID_ARGUMENT;
	if (mdns->busy) return MATTER_BUSY;
	if (mdns->active) return mdns->stopping ? MATTER_INVALID_STATE : MATTER_OK;
	Matter_Operation_Port_T operation = {mdns, stop_requested, NULL};
	Matter_Result_T result = matter_operation_begin(mdns->owner, &operation, &mdns->lease);
	if (result != MATTER_OK) return result;
	mdns->active = true;
	mdns->stopping = false;
	mdns->failed = false;
	return MATTER_OK;
}

Matter_Result_T matter_mdns_stop(Matter_Mdns_T mdns) {
	if (!mdns) return MATTER_INVALID_ARGUMENT;
	if (mdns->busy) return MATTER_BUSY;
	if (!mdns->active) return MATTER_OK;
	Matter_Result_T result = matter_operation_cancel(mdns->owner, mdns->lease);
	return result == MATTER_OK ? MATTER_PENDING : result;
}

Matter_Result_T matter_mdns_process(Matter_Mdns_T mdns) {
	if (!mdns) return MATTER_INVALID_ARGUMENT;
	if (mdns->busy) return MATTER_BUSY;
	if (!mdns->active) return MATTER_OK;
	if (mdns->pending) {
		if (mdns->stopping && mdns->publishing && !mdns->cancelling) {
			mdns->cancelling = true;
			mdns->busy = true;
			mdns->port.cancel(mdns->port.user, mdns->request);
			mdns->busy = false;
		}
		return MATTER_PENDING;
	}
	if (mdns->stopping && !mdns->published) {
		mdns->busy = true;
		Matter_Result_T result = matter_operation_complete(mdns->owner, mdns->lease,
			mdns->failed ? MATTER_OPERATION_FAILED : MATTER_OPERATION_CANCELLED);
		mdns->busy = false;
		if (result != MATTER_OK) return result;
		mdns->active = false;
		return mdns->failed ? MATTER_PORT_ERROR : MATTER_OK;
	}
	if (mdns->failed) return MATTER_PORT_ERROR;
	if (!mdns->ready) return MATTER_PENDING;
	if (mdns->published && !mdns->stopping) return MATTER_OK;
	/* Reserve one ID for removing a newly published record; never wrap. */
	if (mdns->request == UINT64_MAX ||
		(!mdns->stopping && mdns->request == UINT64_MAX - 1)) return MATTER_LIMIT_REACHED;
	++mdns->request;
	mdns->publishing = !mdns->stopping;
	mdns->pending = true;
	mdns->cancelling = false;
	mdns->busy = true;
	bool accepted = mdns->publishing ?
		mdns->port.publish(mdns->port.user, mdns->request, &mdns->record) :
		mdns->port.remove(mdns->port.user, mdns->request);
	mdns->busy = false;
	if (!accepted) {
		mdns->pending = false;
		mdns->failed = true;
		return MATTER_PORT_ERROR;
	}
	return MATTER_PENDING;
}

Matter_Result_T matter_mdns_retry(Matter_Mdns_T mdns) {
	if (!mdns) return MATTER_INVALID_ARGUMENT;
	if (mdns->busy) return MATTER_BUSY;
	if (!mdns->active) return MATTER_INVALID_STATE;
	if (mdns->pending) return MATTER_BUSY;
	mdns->failed = false;
	return MATTER_OK;
}

Matter_Result_T matter_mdns_backend(Matter_Mdns_T mdns, uint64_t generation, bool ready) {
	if (!mdns) return MATTER_INVALID_ARGUMENT;
	if (mdns->busy) return MATTER_BUSY;
	if (!generation) return MATTER_INVALID_ARGUMENT;
	if (generation <= mdns->generation) return MATTER_INVALID_STATE;
	mdns->generation = generation;
	mdns->ready = ready;
	mdns->pending = false;
	mdns->published = false;
	mdns->failed = false;
	return MATTER_OK;
}

Matter_Result_T matter_mdns_complete(Matter_Mdns_T mdns, uint64_t request,
	Matter_Operation_Result_T result) {
	if (!mdns) return MATTER_INVALID_ARGUMENT;
	if (mdns->busy) return MATTER_BUSY;
	if (!request || (result != MATTER_OPERATION_SUCCEEDED && result != MATTER_OPERATION_FAILED &&
		result != MATTER_OPERATION_CANCELLED)) return MATTER_INVALID_ARGUMENT;
	if (!mdns->pending || request != mdns->request) return MATTER_INVALID_STATE;
	mdns->pending = false;
	if (result == MATTER_OPERATION_SUCCEEDED) mdns->published = mdns->publishing;
	else if (result == MATTER_OPERATION_FAILED || !mdns->stopping || !mdns->publishing) mdns->failed = true;
	return MATTER_OK;
}

bool matter_mdns_is_active(Matter_Mdns_T mdns) {
	return mdns && mdns->active;
}

bool matter_mdns_is_published(Matter_Mdns_T mdns) {
	return mdns && mdns->published;
}
