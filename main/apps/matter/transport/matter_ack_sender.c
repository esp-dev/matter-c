#include "matter_ack_sender.h"
#include "../codec/matter_protocol_header.h"
#include <stdlib.h>

struct Matter_Ack_Sender {
	Matter_Ack_Table_T table;
	Matter_Ack_Port_T port;
	Matter_Ack_Message_T tx;
	uint64_t request;
	uint8_t bytes[10];
	bool pending, stopping, drained, busy;
};

Matter_Ack_Sender_T matter_ack_sender_new(Matter_Ack_Table_T table, const Matter_Ack_Port_T* port) {
	if (!table || !port || !port->send || !port->detach) return NULL;
	Matter_Ack_Sender_T sender = calloc(1, sizeof(*sender));
	if (!sender) return NULL;
	sender->table = table;
	sender->port = *port;
	return sender;
}

Matter_Result_T matter_ack_sender_delete(Matter_Ack_Sender_T sender) {
	if (!sender) return MATTER_OK;
	if (sender->busy) return MATTER_BUSY;
	if (!sender->drained || sender->pending) return MATTER_INVALID_STATE;
	sender->busy = true;
	sender->port.detach(sender->port.user);
	free(sender);
	return MATTER_OK;
}

Matter_Result_T matter_ack_sender_complete(Matter_Ack_Sender_T sender, uint64_t request,
	Matter_Operation_Result_T result) {
	if (!sender) return MATTER_INVALID_ARGUMENT;
	if (sender->busy) return MATTER_BUSY;
	if (!request || (result != MATTER_OPERATION_SUCCEEDED && result != MATTER_OPERATION_FAILED &&
		result != MATTER_OPERATION_CANCELLED)) return MATTER_INVALID_ARGUMENT;
	if (!sender->pending || sender->request != request) return MATTER_INVALID_STATE;
	Matter_Result_T completed = matter_ack_complete(sender->table, request, result);
	if (completed != MATTER_OK) return completed;
	sender->pending = false;
	sender->request = 0;
	sender->tx = (Matter_Ack_Message_T){0};
	return MATTER_OK;
}

Matter_Result_T matter_ack_sender_stop(Matter_Ack_Sender_T sender) {
	if (!sender) return MATTER_INVALID_ARGUMENT;
	if (sender->busy) return MATTER_BUSY;
	sender->stopping = true;
	Matter_Result_T result = matter_ack_stop(sender->table);
	if (sender->pending) return MATTER_PENDING;
	sender->drained = result == MATTER_OK;
	return result;
}

Matter_Result_T matter_ack_sender_process(Matter_Ack_Sender_T sender, uint64_t now_ms) {
	if (!sender) return MATTER_INVALID_ARGUMENT;
	if (sender->busy) return MATTER_BUSY;
	if (sender->pending) return MATTER_PENDING;
	if (sender->stopping && matter_ack_sender_stop(sender) == MATTER_OK) return MATTER_OK;
	Matter_Ack_Request_T ack;
	Matter_Result_T result = matter_ack_next(sender->table, now_ms, &ack);
	if (result != MATTER_OK) return result;
	Matter_Protocol_Header_T header = {
		.acknowledged_message_counter = ack.counter, .exchange_id = ack.exchange.exchange_id,
		.exchange_flags = MATTER_PROTOCOL_ACK | (ack.exchange.initiator ? MATTER_PROTOCOL_INITIATOR : 0),
		.opcode = 0x10
	};
	sender->request = ack.id;
	sender->tx = (Matter_Ack_Message_T){.exchange = ack.exchange, .data = sender->bytes};
	if (matter_protocol_header_write(&header, sender->bytes, sizeof(sender->bytes), &sender->tx.size) !=
		MATTER_MESSAGE_OK) result = MATTER_PORT_ERROR;
	else {
		sender->busy = true;
		result = sender->port.send(sender->port.user, ack.id, &sender->tx);
		sender->busy = false;
	}
	if (result == MATTER_OK) {
		sender->pending = true;
		return MATTER_PENDING;
	}
	Matter_Result_T rolled_back = matter_ack_complete(sender->table, ack.id, MATTER_OPERATION_FAILED);
	if (rolled_back != MATTER_OK) return rolled_back;
	sender->request = 0;
	sender->tx = (Matter_Ack_Message_T){0};
	return result == MATTER_WOULD_BLOCK || result == MATTER_OFFLINE ? result : MATTER_PORT_ERROR;
}
