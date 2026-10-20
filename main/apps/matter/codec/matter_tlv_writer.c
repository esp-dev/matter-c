#include "matter_tlv_writer.h"
#include "matter_tlv_internal.h"
#include <string.h>

static uint8_t smallest_width(uint64_t value) {
	if (value <= UINT8_MAX) return 1;
	if (value <= UINT16_MAX) return 2;
	if (value <= UINT32_MAX) return 4;
	return 8;
}

static void put_little_endian(uint8_t* data, uint64_t value, size_t width) {
	for (size_t i = 0; i < width; ++i) { data[i] = (uint8_t)value; value >>= 8; }
}

Matter_Tlv_Result_T matter_tlv_writer_init(Matter_Tlv_Writer_T* writer, uint8_t* data,
	size_t capacity, uint8_t max_depth) {
	if (!writer || (!data && capacity) || !max_depth || max_depth > MATTER_TLV_MAX_DEPTH)
		return MATTER_TLV_INVALID_ARGUMENT;
	*writer = (Matter_Tlv_Writer_T){.data = data, .capacity = capacity, .max_depth = max_depth};
	return MATTER_TLV_OK;
}

Matter_Tlv_Result_T matter_tlv_write(Matter_Tlv_Writer_T* writer,
	const Matter_Tlv_Element_T* element, uint8_t width) {
	if (!writer || !element || (width && width != 1 && width != 2 && width != 4 && width != 8))
		return MATTER_TLV_INVALID_ARGUMENT;
	const Matter_Tlv_Tag_T* tag = &element->tag;
	if (tag->control > 7 || (tag->control < 6 && (tag->vendor || tag->profile)) ||
		(!tag->control && tag->number) || (tag->control == 1 && tag->number > 255))
		return MATTER_TLV_INVALID_ARGUMENT;
	static const uint8_t tag_widths[] = {0, 1, 2, 4, 2, 4, 2, 4};
	uint8_t tag_width = tag_widths[tag->control];
	if ((tag_width == 2 && tag->number > 65535) || (tag_width == 4 && tag->number < 65536))
		return MATTER_TLV_INVALID_ARGUMENT;
	bool end = element->type == MATTER_TLV_END;
	bool container = element->type == MATTER_TLV_STRUCTURE || element->type == MATTER_TLV_ARRAY ||
		element->type == MATTER_TLV_LIST;
	if (end) {
		if (tag->control || !writer->depth) return MATTER_TLV_INVALID_ENCODING;
	} else {
		if (writer->root_seen && !writer->depth) return MATTER_TLV_INVALID_ENCODING;
		if (!writer->depth && tag->control == 1) return MATTER_TLV_INVALID_ENCODING;
		if (writer->depth) {
			uint8_t parent = writer->parents[writer->depth - 1];
			if ((parent == MATTER_TLV_STRUCTURE && !tag->control) ||
				(parent == MATTER_TLV_ARRAY && tag->control)) return MATTER_TLV_INVALID_ENCODING;
		}
		if (container && writer->depth == writer->max_depth) return MATTER_TLV_DEPTH_LIMIT;
	}
	uint8_t wire_type, length_width = 0;
	size_t payload_size = 0;
	uint64_t bits = 0;
	bool string = element->type == MATTER_TLV_UTF8 || element->type == MATTER_TLV_BYTES;
	if (element->type == MATTER_TLV_SIGNED || element->type == MATTER_TLV_UNSIGNED || string) {
		uint64_t magnitude;
		if (string) {
			if (!element->data && element->size) return MATTER_TLV_INVALID_ARGUMENT;
			magnitude = element->size;
		} else if (element->type == MATTER_TLV_SIGNED) {
			/* Complement magnitude fits even for INT64_MIN; no signed shift/negation. */
			magnitude = element->signed_value < 0 ? (uint64_t)(-(element->signed_value + 1)) :
				(uint64_t)element->signed_value;
			magnitude <<= 1;
			bits = (uint64_t)element->signed_value;
		} else magnitude = bits = element->unsigned_value;
		uint8_t minimum = smallest_width(magnitude);
		if (!width) width = minimum;
		if (width < minimum) return MATTER_TLV_INVALID_ARGUMENT;
		uint8_t code = width == 1 ? 0 : width == 2 ? 1 : width == 4 ? 2 : 3;
		wire_type = (uint8_t)(code + (string ? (element->type == MATTER_TLV_UTF8 ? 12 : 16) :
			(element->type == MATTER_TLV_SIGNED ? 0 : 4)));
		if (string) { length_width = width; payload_size = element->size; }
		else payload_size = width;
	} else {
		if (width) return MATTER_TLV_INVALID_ARGUMENT;
		switch (element->type) {
		case MATTER_TLV_BOOL:
			bits = element->unsigned_value;
			if (bits > 1) return MATTER_TLV_INVALID_ARGUMENT;
			wire_type = bits ? 9 : 8; break;
		case MATTER_TLV_FLOAT32:
			bits = element->unsigned_value;
			if (bits > UINT32_MAX) return MATTER_TLV_INVALID_ARGUMENT;
			wire_type = 10; payload_size = 4; break;
		case MATTER_TLV_FLOAT64: bits = element->unsigned_value; wire_type = 11; payload_size = 8; break;
		case MATTER_TLV_NULL: wire_type = 20; break;
		case MATTER_TLV_STRUCTURE: wire_type = 21; break;
		case MATTER_TLV_ARRAY: wire_type = 22; break;
		case MATTER_TLV_LIST: wire_type = 23; break;
		case MATTER_TLV_END: wire_type = 24; break;
		default: return MATTER_TLV_INVALID_ARGUMENT;
		}
	}
	/* At most 17 header bytes; no payload scratch buffer or unbounded stack use. */
	uint8_t header[17];
	size_t header_size = 1;
	header[0] = (uint8_t)((tag->control << 5) | wire_type);
	if (tag->control >= 6) {
		put_little_endian(header + header_size, tag->vendor, 2); header_size += 2;
		put_little_endian(header + header_size, tag->profile, 2); header_size += 2;
	}
	put_little_endian(header + header_size, tag->number, tag_width); header_size += tag_width;
	if (length_width) {
		put_little_endian(header + header_size, element->size, length_width); header_size += length_width;
	}
	size_t available = writer->capacity - writer->size;
	if (header_size > available || payload_size > available - header_size) return MATTER_TLV_NO_SPACE;
	if (element->type == MATTER_TLV_UTF8 && !valid_utf8(element->data, element->size))
		return MATTER_TLV_INVALID_ENCODING;
	/* No remaining failure path; publish bytes and state together. */
	/* Private sizing contexts validate/account without accessing output. Public
	 * init permits NULL only at capacity zero, so public write behavior is unchanged. */
	if (writer->data) {
		uint8_t* output = writer->data + writer->size;
		memcpy(output, header, header_size);
		if (string) {
			if (payload_size) memcpy(output + header_size, element->data, payload_size);
		} else put_little_endian(output + header_size, bits, payload_size);
	}
	writer->size += header_size + payload_size;
	writer->root_seen = true;
	if (end) --writer->depth;
	else if (container) writer->parents[writer->depth++] = (uint8_t)element->type;
	return MATTER_TLV_OK;
}

Matter_Tlv_Result_T matter_tlv_writer_finish(const Matter_Tlv_Writer_T* writer, size_t* size) {
	if (!writer || !size) return MATTER_TLV_INVALID_ARGUMENT;
	if (!writer->root_seen || writer->depth) return MATTER_TLV_TRUNCATED;
	*size = writer->size;
	return MATTER_TLV_OK;
}
