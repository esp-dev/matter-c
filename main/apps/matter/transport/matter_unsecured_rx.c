#include "matter_unsecured_rx.h"
#include <stdlib.h>

struct Matter_Unsecured_Rx {
	Matter_Rx_T rx;
	Matter_Unsecured_T sessions;
	Matter_Unsecured_Rx_Port_T port;
	Matter_Unsecured_Rx_Message_T message; /* Metadata workspace, no packet copy. */
	bool closed, stopped, busy;
};

static Matter_Result_T check(Matter_Unsecured_Rx_T ingress) {
	if (!ingress) return MATTER_INVALID_ARGUMENT;
	return ingress->busy ? MATTER_BUSY : MATTER_OK;
}
static bool unicast(const Matter_Udp_Address_T* address) {
	if (!address->port || address->address[0] == 0xff) return false;
	for (size_t i = 0; i < sizeof(address->address); ++i)
		if (address->address[i]) return true;
	return false;
}
static Matter_Result_T admission_result(Matter_Result_T result) {
	return result == MATTER_OK || result == MATTER_INVALID_ARGUMENT || result == MATTER_INVALID_STATE ||
		result == MATTER_WOULD_BLOCK || result == MATTER_OFFLINE ? result : MATTER_PORT_ERROR;
}
Matter_Unsecured_Rx_T matter_unsecured_rx_new(Matter_Rx_T rx, Matter_Unsecured_T sessions,
	const Matter_Unsecured_Rx_Port_T* port) {
	if (!rx || !sessions || !port || !port->admit || !port->accepted || !port->detach) return NULL;
	Matter_Unsecured_Rx_T ingress = calloc(1, sizeof(*ingress));
	if (!ingress) return NULL;
	ingress->rx = rx; ingress->sessions = sessions; ingress->port = *port;
	return ingress;
}
Matter_Result_T matter_unsecured_rx_receive(Matter_Unsecured_Rx_T ingress,
	const Matter_Udp_Datagram_T* datagram, uint64_t received_ms) {
	Matter_Result_T result = check(ingress);
	if (result != MATTER_OK) return result;
	if (!datagram || !datagram->data || !datagram->size) return MATTER_INVALID_ARGUMENT;
	if (ingress->stopped) return MATTER_INVALID_STATE;
	if (datagram->size > MATTER_UDP_MAX_PAYLOAD) return MATTER_LIMIT_REACHED;
	if (!unicast(&datagram->path.local) || !unicast(&datagram->path.peer)) return MATTER_INVALID_ARGUMENT;
	ingress->busy = true;
	Matter_Unsecured_Rx_Message_T* m = &ingress->message;
	bool created = false, pinned = false, copied = false, allow_create = false, duplicate = false;
	size_t n, h;
	*m = (Matter_Unsecured_Rx_Message_T){.datagram = datagram};
	if (matter_message_header_read(datagram->data, datagram->size, &m->message, &n) != MATTER_MESSAGE_OK ||
		matter_protocol_header_read(datagram->data + n, datagram->size - n, &m->protocol, &h) != MATTER_MESSAGE_OK) {
		result = MATTER_INVALID_ARGUMENT; goto done;
	}
	m->payload = datagram->data + n + h; m->payload_size = datagram->size - n - h;
	/* Read-only resolve also validates the unsecured envelope before policy. */
	result = matter_unsecured_resolve(ingress->sessions, &m->message, false, &m->session);
	if (result != MATTER_OK && result != MATTER_INVALID_STATE) goto done;
	result = admission_result(ingress->port.admit(ingress->port.user, m, &allow_create));
	if (result != MATTER_OK) goto done;
	if (!m->session) {
		result = matter_unsecured_resolve(ingress->sessions, &m->message,
			allow_create && !ingress->closed, &m->session);
		if (result != MATTER_OK) goto done;
		created = true;
	}
	result = matter_unsecured_pin(ingress->sessions, m->session);
	if (result != MATTER_OK) goto done;
	pinned = true;
	result = matter_unsecured_classify(ingress->sessions, m->session, m->message.message_counter, &duplicate);
	if (result != MATTER_OK) goto done;
	Matter_Rx_Input_T input = {m->session, m->message.message_counter, duplicate, datagram->data + n, datagram->size - n};
	result = matter_rx_receive(ingress->rx, &input, received_ms);
	if (result != MATTER_OK) goto done;
	copied = true;
	/* Cannot fail with this pin and serialized, nonmutating callbacks. */
	result = matter_unsecured_commit(ingress->sessions, m->session, m->message.message_counter, &duplicate);
	if (result == MATTER_OK) ingress->port.accepted(ingress->port.user, m, duplicate);
done:
	if (pinned) matter_unsecured_unpin(ingress->sessions, m->session);
	if (created && !copied) matter_unsecured_remove(ingress->sessions, m->session);
	*m = (Matter_Unsecured_Rx_Message_T){0};
	ingress->busy = false;
	return result;
}
Matter_Result_T matter_unsecured_rx_close(Matter_Unsecured_Rx_T ingress) {
	Matter_Result_T result = check(ingress);
	if (result == MATTER_OK) ingress->closed = true;
	return result;
}
Matter_Result_T matter_unsecured_rx_stop(Matter_Unsecured_Rx_T ingress) {
	Matter_Result_T result = check(ingress);
	if (result == MATTER_OK) ingress->closed = ingress->stopped = true;
	return result;
}
Matter_Result_T matter_unsecured_rx_delete(Matter_Unsecured_Rx_T ingress) {
	if (!ingress) return MATTER_OK;
	if (ingress->busy) return MATTER_BUSY;
	if (!ingress->stopped) return MATTER_INVALID_STATE;
	ingress->busy = true;
	ingress->port.detach(ingress->port.user);
	free(ingress);
	return MATTER_OK;
}
