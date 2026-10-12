#include "matter_unsecured_tx.h"
#include <stdlib.h>

struct Matter_Unsecured_Tx {
	Matter_Udp_T udp;
	Matter_Unsecured_T sessions;
	Matter_Unsecured_Tx_Port_T port;
	Matter_Unsecured_Tx_Result_T result;
	Matter_Udp_Datagram_T datagram;
	bool pending, done, closed, busy;
};

static Matter_Result_T check(Matter_Unsecured_Tx_T tx) {
	if (!tx) return MATTER_INVALID_ARGUMENT;
	return tx->busy ? MATTER_BUSY : MATTER_OK;
}
static bool valid_outcome(Matter_Operation_Result_T outcome) {
	return outcome == MATTER_OPERATION_SUCCEEDED || outcome == MATTER_OPERATION_FAILED ||
		outcome == MATTER_OPERATION_CANCELLED;
}
static bool unicast(const Matter_Udp_Path_T* path) {
	if (!path->local.port || !path->peer.port || path->peer.address[0] == 0xff) return false;
	for (size_t i = 0; i < sizeof(path->peer.address); ++i)
		if (path->peer.address[i]) return true;
	return false;
}
static Matter_Result_T envelope(Matter_Unsecured_Tx_T tx, Matter_Exchange_Session_T session,
	const uint8_t* data, size_t size) {
	Matter_Unsecured_Info_T info;
	Matter_Result_T result = matter_unsecured_get(tx->sessions, session, &info);
	if (result != MATTER_OK) return result;
	Matter_Message_Header_T header;
	size_t used;
	if (matter_message_header_read(data, size, &header, &used) != MATTER_MESSAGE_OK || used == size ||
		header.session_id || header.security_flags ||
		header.message_flags != (info.initiator ? MATTER_MESSAGE_SOURCE_PRESENT : MATTER_MESSAGE_DESTINATION_NODE) ||
		(info.initiator ? header.source_node_id : header.destination_id) != info.ephemeral_node_id)
		return MATTER_INVALID_ARGUMENT;
	return MATTER_OK;
}
Matter_Unsecured_Tx_T matter_unsecured_tx_new(Matter_Udp_T udp, Matter_Unsecured_T sessions,
	const Matter_Unsecured_Tx_Port_T* port) {
	if (!udp || !sessions || !port || !port->route || !port->detach) return NULL;
	Matter_Unsecured_Tx_T tx = calloc(1, sizeof(*tx));
	if (!tx) return NULL;
	tx->udp = udp; tx->sessions = sessions; tx->port = *port;
	return tx;
}
Matter_Result_T matter_unsecured_tx_send(Matter_Unsecured_Tx_T tx, Matter_Exchange_Session_T session,
	const uint8_t* data, size_t size, uint64_t* request) {
	Matter_Result_T result = check(tx);
	if (result != MATTER_OK) return result;
	if (!session || !data || !size || !request) return MATTER_INVALID_ARGUMENT;
	if (tx->closed) return MATTER_INVALID_STATE;
	if (tx->pending) return MATTER_BUSY;
	if (size > MATTER_UDP_MAX_PAYLOAD) return MATTER_LIMIT_REACHED;
	result = envelope(tx, session, data, size);
	if (result != MATTER_OK) return result;
	result = matter_unsecured_pin(tx->sessions, session);
	if (result != MATTER_OK) return result;
	tx->busy = true;
	tx->datagram = (Matter_Udp_Datagram_T){.data = data, .size = size};
	result = tx->port.route(tx->port.user, session, &tx->datagram.path);
	if (result == MATTER_OK) {
		if (!unicast(&tx->datagram.path)) result = MATTER_PORT_ERROR;
		else {
			uint64_t id;
			result = matter_udp_send(tx->udp, &tx->datagram, &id);
			if (result == MATTER_PENDING) {
				tx->result = (Matter_Unsecured_Tx_Result_T){id, session, data, size, MATTER_OPERATION_SUCCEEDED};
				tx->pending = true;
				tx->done = false;
				*request = id;
			}
		}
	} else if (result != MATTER_WOULD_BLOCK && result != MATTER_OFFLINE) result = MATTER_PORT_ERROR;
	if (!tx->pending) {
		matter_unsecured_unpin(tx->sessions, session);
		tx->datagram = (Matter_Udp_Datagram_T){0};
	}
	tx->busy = false;
	return result;
}
Matter_Result_T matter_unsecured_tx_complete(Matter_Unsecured_Tx_T tx, uint64_t request,
	Matter_Operation_Result_T outcome) {
	Matter_Result_T result = check(tx);
	if (result != MATTER_OK) return result;
	if (!request || !valid_outcome(outcome)) return MATTER_INVALID_ARGUMENT;
	if (!tx->pending || tx->done || tx->result.request != request) return MATTER_INVALID_STATE;
	tx->result.outcome = outcome;
	tx->done = true;
	return MATTER_OK;
}
Matter_Result_T matter_unsecured_tx_take(Matter_Unsecured_Tx_T tx, Matter_Unsecured_Tx_Result_T* out) {
	Matter_Result_T result = check(tx);
	if (result != MATTER_OK) return result;
	if (!out) return MATTER_INVALID_ARGUMENT;
	if (!tx->pending) return MATTER_INVALID_STATE;
	if (!tx->done) return MATTER_PENDING;
	result = matter_unsecured_unpin(tx->sessions, tx->result.session);
	if (result != MATTER_OK) return result;
	*out = tx->result;
	tx->result = (Matter_Unsecured_Tx_Result_T){0};
	tx->datagram = (Matter_Udp_Datagram_T){0};
	tx->pending = tx->done = false;
	return MATTER_OK;
}
Matter_Result_T matter_unsecured_tx_close(Matter_Unsecured_Tx_T tx) {
	Matter_Result_T result = check(tx);
	if (result != MATTER_OK) return result;
	tx->closed = true;
	return tx->pending ? MATTER_PENDING : MATTER_OK;
}
Matter_Result_T matter_unsecured_tx_delete(Matter_Unsecured_Tx_T tx) {
	if (!tx) return MATTER_OK;
	if (tx->busy) return MATTER_BUSY;
	if (!tx->closed || tx->pending) return MATTER_INVALID_STATE;
	tx->busy = true;
	tx->port.detach(tx->port.user);
	free(tx);
	return MATTER_OK;
}
