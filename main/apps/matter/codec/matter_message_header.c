#include "matter_message_header.h"

static uint64_t get_le(const uint8_t* data, size_t width) {
	uint64_t value = 0;
	for (size_t i = 0; i < width; ++i) value |= (uint64_t)data[i] << (8 * i);
	return value;
}

static void put_le(uint8_t* data, uint64_t value, size_t width) {
	for (size_t i = 0; i < width; ++i) { data[i] = (uint8_t)value; value >>= 8; }
}

static Matter_Message_Result_T check_flags(uint8_t message, uint8_t security) {
	if ((message & 0xf0) || (message & MATTER_MESSAGE_DESTINATION_MASK) == 3 ||
		(security & MATTER_MESSAGE_SESSION_MASK) > MATTER_MESSAGE_SESSION_GROUP)
		return MATTER_MESSAGE_INVALID_ENCODING;
	if (security & MATTER_MESSAGE_PRIVACY) return MATTER_MESSAGE_UNSUPPORTED;
	return MATTER_MESSAGE_OK;
}

static size_t destination_width(uint8_t flags) {
	switch (flags & MATTER_MESSAGE_DESTINATION_MASK) {
		case MATTER_MESSAGE_DESTINATION_NODE: return 8;
		case MATTER_MESSAGE_DESTINATION_GROUP: return 2;
		default: return 0;
	}
}

Matter_Message_Result_T matter_message_header_read(const uint8_t* data, size_t size,
	Matter_Message_Header_T* header, size_t* consumed) {
	if ((!data && size) || !header || !consumed) return MATTER_MESSAGE_INVALID_ARGUMENT;
	if (size < 4) return MATTER_MESSAGE_TRUNCATED;
	Matter_Message_Result_T result = check_flags(data[0], data[3]);
	if (result != MATTER_MESSAGE_OK) return result;
	size_t source_width = (data[0] & MATTER_MESSAGE_SOURCE_PRESENT) ? 8 : 0;
	size_t dest_width = destination_width(data[0]);
	size_t pos = 8 + source_width + dest_width;
	if (size < pos) return MATTER_MESSAGE_TRUNCATED;
	if (data[3] & MATTER_MESSAGE_EXTENSIONS) {
		if (size - pos < 2) return MATTER_MESSAGE_TRUNCATED;
		size_t extension_size = (size_t)get_le(data + pos, 2);
		pos += 2;
		if (extension_size > size - pos) return MATTER_MESSAGE_TRUNCATED;
		pos += extension_size;
	}
	/* One small value object, committed only after every bounds check. */
	Matter_Message_Header_T value = {
		.message_flags = data[0], .security_flags = data[3],
		.session_id = (uint16_t)get_le(data + 1, 2),
		.message_counter = (uint32_t)get_le(data + 4, 4)
	};
	if (source_width) value.source_node_id = get_le(data + 8, source_width);
	if (dest_width) value.destination_id = get_le(data + 8 + source_width, dest_width);
	*header = value;
	*consumed = pos;
	return MATTER_MESSAGE_OK;
}

Matter_Message_Result_T matter_message_header_write(const Matter_Message_Header_T* header,
	uint8_t* data, size_t capacity, size_t* written) {
	if (!header || (!data && capacity) || !written) return MATTER_MESSAGE_INVALID_ARGUMENT;
	Matter_Message_Result_T result = check_flags(header->message_flags, header->security_flags);
	if (result != MATTER_MESSAGE_OK) return result;
	if (header->security_flags & MATTER_MESSAGE_EXTENSIONS) return MATTER_MESSAGE_UNSUPPORTED;
	size_t source_width = (header->message_flags & MATTER_MESSAGE_SOURCE_PRESENT) ? 8 : 0;
	size_t dest_width = destination_width(header->message_flags);
	if (dest_width == 2 && header->destination_id > UINT16_MAX) return MATTER_MESSAGE_INVALID_ARGUMENT;
	size_t size = 8 + source_width + dest_width;
	if (capacity < size) return MATTER_MESSAGE_NO_SPACE;
	data[0] = header->message_flags & 0x07;
	put_le(data + 1, header->session_id, 2);
	data[3] = header->security_flags & 0x43;
	put_le(data + 4, header->message_counter, 4);
	if (source_width) put_le(data + 8, header->source_node_id, source_width);
	if (dest_width) put_le(data + 8 + source_width, header->destination_id, dest_width);
	*written = size;
	return MATTER_MESSAGE_OK;
}
