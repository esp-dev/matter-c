#include "matter_protocol_header.h"

/* Only fixed widths 2/4, always after the whole fixed header bounds check. */
static uint32_t get_le(const uint8_t* data, size_t width) {
	uint32_t value = 0;
	for (size_t i = 0; i < width; ++i) value |= (uint32_t)data[i] << (8 * i);
	return value;
}

static void put_le(uint8_t* data, uint32_t value, size_t width) {
	for (size_t i = 0; i < width; ++i) { data[i] = (uint8_t)value; value >>= 8; }
}

Matter_Message_Result_T matter_protocol_header_read(const uint8_t* data, size_t size,
	Matter_Protocol_Header_T* header, size_t* consumed) {
	if ((!data && size) || !header || !consumed) return MATTER_MESSAGE_INVALID_ARGUMENT;
	if (size < 6) return MATTER_MESSAGE_TRUNCATED;
	size_t vendor_width = (data[0] & MATTER_PROTOCOL_VENDOR) ? 2 : 0;
	size_t ack_width = (data[0] & MATTER_PROTOCOL_ACK) ? 4 : 0;
	size_t pos = 6 + vendor_width + ack_width;
	if (size < pos) return MATTER_MESSAGE_TRUNCATED;
	if (data[0] & MATTER_PROTOCOL_EXTENSIONS) {
		if (size - pos < 2) return MATTER_MESSAGE_TRUNCATED;
		size_t extension_size = (size_t)get_le(data + pos, 2);
		pos += 2;
		if (extension_size > size - pos) return MATTER_MESSAGE_TRUNCATED;
		pos += extension_size;
	}
	Matter_Protocol_Header_T value = {
		.exchange_flags = data[0], .opcode = data[1],
		.exchange_id = (uint16_t)get_le(data + 2, 2),
		.protocol_id = (uint16_t)get_le(data + 4 + vendor_width, 2)
	};
	if (vendor_width) value.vendor_id = (uint16_t)get_le(data + 4, 2);
	if (ack_width) value.acknowledged_message_counter = get_le(data + 6 + vendor_width, 4);
	*header = value;
	*consumed = pos;
	return MATTER_MESSAGE_OK;
}

Matter_Message_Result_T matter_protocol_header_write(const Matter_Protocol_Header_T* header,
	uint8_t* data, size_t capacity, size_t* written) {
	if (!header || (!data && capacity) || !written) return MATTER_MESSAGE_INVALID_ARGUMENT;
	if (header->exchange_flags & MATTER_PROTOCOL_EXTENSIONS) return MATTER_MESSAGE_UNSUPPORTED;
	size_t vendor_width = (header->exchange_flags & MATTER_PROTOCOL_VENDOR) ? 2 : 0;
	size_t ack_width = (header->exchange_flags & MATTER_PROTOCOL_ACK) ? 4 : 0;
	size_t size = 6 + vendor_width + ack_width;
	if (capacity < size) return MATTER_MESSAGE_NO_SPACE;
	data[0] = header->exchange_flags & 0x17;
	data[1] = header->opcode;
	put_le(data + 2, header->exchange_id, 2);
	if (vendor_width) put_le(data + 4, header->vendor_id, 2);
	put_le(data + 4 + vendor_width, header->protocol_id, 2);
	if (ack_width) put_le(data + 6 + vendor_width, header->acknowledged_message_counter, 4);
	*written = size;
	return MATTER_MESSAGE_OK;
}
