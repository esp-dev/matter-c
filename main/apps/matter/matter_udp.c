#include "matter_udp.h"
#include <stdlib.h>

struct Matter_Udp {
	Matter_T owner;
	Matter_Udp_Port_T port;
	Matter_Udp_Listener_T listener;
	Matter_Udp_Datagram_T tx;
	Matter_Operation_Id_T lease;
	uint64_t request;
	bool active, stopping, quiesced, pending, cancelling, busy;
};

Matter_Udp_T matter_udp_new(Matter_T owner, const Matter_Udp_Port_T* port,
	const Matter_Udp_Listener_T* listener) {
	if (!owner || !port || !port->activate || !port->deactivate || !port->send ||
		!port->cancel || !port->detach) return NULL;
	Matter_Udp_T udp = calloc(1, sizeof(struct Matter_Udp));
	if (!udp) return NULL;
	udp->owner = owner;
	udp->port = *port;
	if (listener) udp->listener = *listener;
	return udp;
}

Matter_Result_T matter_udp_delete(Matter_Udp_T udp) {
	if (!udp) return MATTER_OK;
	if (udp->busy) return MATTER_BUSY;
	if (udp->active) return MATTER_INVALID_STATE;
	udp->busy = true;
	udp->port.detach(udp->port.user);
	free(udp);
	return MATTER_OK;
}

static void stop_requested(void* user, Matter_Operation_Id_T id) {
	Matter_Udp_T udp = user;
	(void)id;
	udp->stopping = true;
}

static Matter_Result_T submission_result(Matter_Result_T result) {
	return (result == MATTER_OK || result == MATTER_WOULD_BLOCK || result == MATTER_OFFLINE) ?
		result : MATTER_PORT_ERROR;
}

Matter_Result_T matter_udp_start(Matter_Udp_T udp) {
	if (!udp) return MATTER_INVALID_ARGUMENT;
	if (udp->busy) return MATTER_BUSY;
	if (udp->active) return udp->stopping ? MATTER_INVALID_STATE : MATTER_OK;
	Matter_Operation_Port_T operation = {udp, stop_requested, NULL};
	Matter_Result_T result = matter_operation_begin(udp->owner, &operation, &udp->lease);
	if (result != MATTER_OK) return result;
	udp->busy = true;
	result = submission_result(udp->port.activate(udp->port.user, udp->lease));
	if (result != MATTER_OK) {
		matter_operation_complete(udp->owner, udp->lease, MATTER_OPERATION_FAILED);
	} else {
		udp->active = true;
		udp->stopping = false;
		udp->quiesced = false;
	}
	udp->busy = false;
	return result;
}

Matter_Result_T matter_udp_stop(Matter_Udp_T udp) {
	if (!udp) return MATTER_INVALID_ARGUMENT;
	if (udp->busy) return MATTER_BUSY;
	if (!udp->active) return MATTER_OK;
	Matter_Result_T result = matter_operation_cancel(udp->owner, udp->lease);
	return result == MATTER_OK ? MATTER_PENDING : result;
}

Matter_Result_T matter_udp_process(Matter_Udp_T udp) {
	if (!udp) return MATTER_INVALID_ARGUMENT;
	if (udp->busy) return MATTER_BUSY;
	if (!udp->active || !udp->stopping) return MATTER_OK;
	udp->busy = true;
	Matter_Result_T result = MATTER_PENDING;
	if (!udp->quiesced) {
		udp->port.deactivate(udp->port.user, udp->lease);
		udp->quiesced = true;
	} else if (udp->pending) {
		if (!udp->cancelling) {
			udp->cancelling = true;
			udp->port.cancel(udp->port.user, udp->request);
		}
	} else {
		result = matter_operation_complete(udp->owner, udp->lease, MATTER_OPERATION_CANCELLED);
		if (result == MATTER_OK) udp->active = false;
	}
	udp->busy = false;
	return result;
}

static Matter_Result_T validate(const Matter_Udp_Datagram_T* datagram) {
	if (!datagram || !datagram->data || !datagram->size) return MATTER_INVALID_ARGUMENT;
	if (datagram->path.transport == MATTER_TRANSPORT_BTP) {
		if (!datagram->path.interface_id) return MATTER_INVALID_ARGUMENT;
	} else if (datagram->path.transport != MATTER_TRANSPORT_UDP ||
		!datagram->path.local.port || !datagram->path.peer.port) return MATTER_INVALID_ARGUMENT;
	if (datagram->size > MATTER_UDP_MAX_PAYLOAD) return MATTER_LIMIT_REACHED;
	return MATTER_OK;
}

Matter_Result_T matter_udp_send(Matter_Udp_T udp, const Matter_Udp_Datagram_T* datagram,
	uint64_t* request) {
	if (!udp || !request) return MATTER_INVALID_ARGUMENT;
	if (udp->busy) return MATTER_BUSY;
	Matter_Result_T result = validate(datagram);
	if (result != MATTER_OK) return result;
	if (!udp->active || udp->stopping || matter_get_state(udp->owner) != MATTER_STATE_RUNNING)
		return MATTER_INVALID_STATE;
	if (udp->pending) return MATTER_BUSY;
	if (udp->request == UINT64_MAX) return MATTER_LIMIT_REACHED;
	udp->tx = *datagram;
	++udp->request;
	udp->busy = true;
	result = submission_result(udp->port.send(udp->port.user, udp->request, &udp->tx));
	udp->busy = false;
	if (result != MATTER_OK) { udp->tx = (Matter_Udp_Datagram_T){0}; return result; }
	udp->pending = true;
	udp->cancelling = false;
	*request = udp->request;
	return MATTER_PENDING;
}

Matter_Result_T matter_udp_complete(Matter_Udp_T udp, uint64_t request,
	Matter_Operation_Result_T result) {
	if (!udp) return MATTER_INVALID_ARGUMENT;
	if (udp->busy) return MATTER_BUSY;
	if (!request || (result != MATTER_OPERATION_SUCCEEDED && result != MATTER_OPERATION_FAILED &&
		result != MATTER_OPERATION_CANCELLED)) return MATTER_INVALID_ARGUMENT;
	if (!udp->pending || request != udp->request) return MATTER_INVALID_STATE;
	udp->pending = false;
	udp->tx = (Matter_Udp_Datagram_T){0};
	if (udp->listener.sent) {
		udp->busy = true;
		udp->listener.sent(udp->listener.user, request, result);
		udp->busy = false;
	}
	return MATTER_OK;
}

Matter_Result_T matter_udp_receive(Matter_Udp_T udp, Matter_Operation_Id_T epoch,
	const Matter_Udp_Datagram_T* datagram, bool truncated) {
	if (!udp) return MATTER_INVALID_ARGUMENT;
	if (udp->busy) return MATTER_BUSY;
	if (!udp->active || udp->stopping || epoch != udp->lease ||
		matter_get_state(udp->owner) != MATTER_STATE_RUNNING) return MATTER_INVALID_STATE;
	Matter_Result_T result = validate(datagram);
	if (result != MATTER_OK) return result;
	if (truncated) return MATTER_LIMIT_REACHED;
	if (udp->listener.received) {
		udp->busy = true;
		udp->listener.received(udp->listener.user, datagram);
		udp->busy = false;
	}
	return MATTER_OK;
}

bool matter_udp_is_active(Matter_Udp_T udp) {
	return udp && udp->active;
}
