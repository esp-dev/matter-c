#include "matter_unsecured_prepare.h"
#include "../ports/matter_udp_port.h"
#include <string.h>

/* Fixed profile: session id/type zero and exactly one 64-bit ephemeral ID. */
enum { ENVELOPE_SIZE = 16, PROTOCOL_MAX = 12, TRANSMIT_FLAGS = 0x17 };

static Matter_Result_T prepare(Matter_Unsecured_T sessions, Matter_Exchange_Session_T session,
	Matter_Counter_T* counter, const uint8_t* prefix, size_t prefix_size,
	const uint8_t* payload, size_t payload_size, uint8_t* data, size_t capacity,
	Matter_Unsecured_Prepared_T* prepared) {
	if (!counter || !prepared || (!data && capacity) || (!payload && payload_size))
		return MATTER_INVALID_ARGUMENT;
	if (payload_size > MATTER_UDP_MAX_PAYLOAD - ENVELOPE_SIZE - prefix_size)
		return MATTER_LIMIT_REACHED;
	size_t size = ENVELOPE_SIZE + prefix_size + payload_size;
	if (capacity < size) return MATTER_LIMIT_REACHED;
	Matter_Unsecured_Info_T info;
	Matter_Result_T result = matter_unsecured_get(sessions, session, &info);
	if (result != MATTER_OK) return result;
	if (!info.pins || counter->mode != MATTER_COUNTER_UNSECURED) return MATTER_INVALID_STATE;
	Matter_Counter_Value_T value;
	result = matter_counter_take(counter, &value);
	if (result != MATTER_OK) return result;
	Matter_Message_Header_T header = {.message_counter = value.counter,
		.message_flags = info.initiator ? MATTER_MESSAGE_SOURCE_PRESENT : MATTER_MESSAGE_DESTINATION_NODE,
		.source_node_id = info.initiator ? info.ephemeral_node_id : 0,
		.destination_id = info.initiator ? 0 : info.ephemeral_node_id};
	uint8_t envelope[ENVELOPE_SIZE];
	size_t written;
	if (matter_message_header_write(&header, envelope, sizeof(envelope), &written) != MATTER_MESSAGE_OK ||
		written != ENVELOPE_SIZE) return MATTER_PORT_ERROR;
	/* Move borrowed input before writing either header: supports overlapping spans. */
	if (payload_size) memmove(data + ENVELOPE_SIZE + prefix_size, payload, payload_size);
	if (prefix_size) memcpy(data + ENVELOPE_SIZE, prefix, prefix_size);
	memcpy(data, envelope, ENVELOPE_SIZE);
	*prepared = (Matter_Unsecured_Prepared_T){size, value.counter};
	return MATTER_OK;
}

Matter_Result_T matter_unsecured_prepare(Matter_Unsecured_T sessions,
	Matter_Exchange_Session_T session, Matter_Counter_T* counter,
	const Matter_Protocol_Header_T* protocol, const uint8_t* payload, size_t payload_size,
	uint8_t* data, size_t capacity, Matter_Unsecured_Prepared_T* prepared) {
	if (!protocol || (protocol->exchange_flags & ~TRANSMIT_FLAGS)) return MATTER_INVALID_ARGUMENT;
	uint8_t prefix[PROTOCOL_MAX];
	size_t size;
	if (matter_protocol_header_write(protocol, prefix, sizeof(prefix), &size) != MATTER_MESSAGE_OK)
		return MATTER_INVALID_ARGUMENT;
	return prepare(sessions, session, counter, prefix, size, payload, payload_size, data, capacity, prepared);
}

Matter_Result_T matter_unsecured_prepare_encoded(Matter_Unsecured_T sessions,
	Matter_Exchange_Session_T session, Matter_Counter_T* counter,
	const uint8_t* protocol_message, size_t size,
	uint8_t* data, size_t capacity, Matter_Unsecured_Prepared_T* prepared) {
	if (!protocol_message) return MATTER_INVALID_ARGUMENT;
	if (size > MATTER_UDP_MAX_PAYLOAD - ENVELOPE_SIZE) return MATTER_LIMIT_REACHED;
	Matter_Protocol_Header_T protocol;
	size_t consumed;
	if (matter_protocol_header_read(protocol_message, size, &protocol, &consumed) != MATTER_MESSAGE_OK ||
		(protocol.exchange_flags & ~TRANSMIT_FLAGS)) return MATTER_INVALID_ARGUMENT;
	return prepare(sessions, session, counter, NULL, 0, protocol_message, size, data, capacity, prepared);
}
