#include "matter_tlv.h"
#include "matter_tlv_internal.h"

static uint64_t little_endian(const uint8_t* data, size_t count) {
	uint64_t value = 0;
	for (size_t i = 0; i < count; ++i) value |= (uint64_t)data[i] << (8 * i);
	return value;
}

Matter_Tlv_Result_T matter_tlv_init(Matter_Tlv_Reader_T* reader, const uint8_t* data,
	size_t size, uint8_t max_depth) {
	if (!reader || (!data && size) || !max_depth || max_depth > MATTER_TLV_MAX_DEPTH)
		return MATTER_TLV_INVALID_ARGUMENT;
	*reader = (Matter_Tlv_Reader_T){.data = data, .size = size, .max_depth = max_depth};
	return MATTER_TLV_OK;
}

Matter_Tlv_Result_T matter_tlv_next(Matter_Tlv_Reader_T* reader, Matter_Tlv_Element_T* element) {
	if (!reader || !element) return MATTER_TLV_INVALID_ARGUMENT;
	if (reader->error) return reader->error;
	size_t pos = reader->offset;
	if (pos == reader->size) {
		if (reader->root_seen && !reader->depth) return MATTER_TLV_DONE;
		return reader->error = MATTER_TLV_TRUNCATED;
	}
	if (reader->root_seen && !reader->depth) return reader->error = MATTER_TLV_INVALID_ENCODING;
	uint8_t control = reader->data[pos++], wire_type = control & 0x1f;
	Matter_Tlv_Element_T value = {.offset = reader->offset};
	value.tag.control = control >> 5;
	if (wire_type > 0x18 || (wire_type == 0x18 && value.tag.control)) goto invalid;
	if (wire_type == 0x18) {
		if (!reader->depth) goto invalid;
		value.type = MATTER_TLV_END;
		--reader->depth;
		goto commit;
	}
	/* A.5.3 and A.12 explicitly permit context tags in lists as well as structs. */
	if (!reader->depth && value.tag.control == 1) goto invalid;
	if (reader->depth) {
		uint8_t parent = reader->parents[reader->depth - 1];
		if ((parent == 0x15 && !value.tag.control) || (parent == 0x16 && value.tag.control)) goto invalid;
	}
	static const uint8_t tag_sizes[] = {0, 1, 2, 4, 2, 4, 6, 8};
	size_t tag_size = tag_sizes[value.tag.control];
	if (tag_size > reader->size - pos) goto truncated;
	if (value.tag.control >= 6) {
		value.tag.vendor = (uint16_t)little_endian(reader->data + pos, 2);
		value.tag.profile = (uint16_t)little_endian(reader->data + pos + 2, 2);
		pos += 4;
		tag_size -= 4;
	}
	value.tag.number = (uint32_t)little_endian(reader->data + pos, tag_size);
	pos += tag_size;
	if (tag_size == 4 && value.tag.number < 65536) goto invalid;
	if (wire_type <= 7) {
		value.size = (size_t)1 << (wire_type & 3);
		value.type = wire_type < 4 ? MATTER_TLV_SIGNED : MATTER_TLV_UNSIGNED;
	} else if (wire_type <= 9) {
		value.type = MATTER_TLV_BOOL;
		value.unsigned_value = wire_type == 9;
	} else if (wire_type <= 11) {
		value.type = wire_type == 10 ? MATTER_TLV_FLOAT32 : MATTER_TLV_FLOAT64;
		value.size = wire_type == 10 ? 4 : 8;
	} else if (wire_type <= 19) {
		size_t width = (size_t)1 << (wire_type & 3);
		if (width > reader->size - pos) goto truncated;
		uint64_t length = little_endian(reader->data + pos, width);
		pos += width;
		if (length > reader->size - pos) goto truncated;
		value.size = (size_t)length;
		value.type = wire_type < 16 ? MATTER_TLV_UTF8 : MATTER_TLV_BYTES;
	} else if (wire_type == 20) value.type = MATTER_TLV_NULL;
	else {
		if (reader->depth == reader->max_depth) return reader->error = MATTER_TLV_DEPTH_LIMIT;
		value.type = wire_type == 21 ? MATTER_TLV_STRUCTURE :
			(wire_type == 22 ? MATTER_TLV_ARRAY : MATTER_TLV_LIST);
		reader->parents[reader->depth++] = wire_type;
	}
	if (value.size > reader->size - pos) goto truncated;
	if (wire_type <= 7 || wire_type == 10 || wire_type == 11) {
		uint64_t bits = little_endian(reader->data + pos, value.size);
		if (wire_type < 4) {
			uint64_t sign = UINT64_C(1) << (value.size * 8 - 1);
			/* Avoid conversion of out-of-range uint64 to int64, including INT64_MIN. */
			value.signed_value = (bits & sign) ?
				-1 - (int64_t)((sign - 1) - (bits & (sign - 1))) : (int64_t)bits;
		} else value.unsigned_value = bits;
	}
	if (value.type == MATTER_TLV_UTF8 && !valid_utf8(reader->data + pos, value.size)) goto invalid;
	if (value.size || value.type == MATTER_TLV_UTF8 || value.type == MATTER_TLV_BYTES)
		value.data = reader->data + pos;
	pos += value.size;
commit:
	reader->offset = pos;
	reader->root_seen = true;
	reader->can_skip = value.type == MATTER_TLV_STRUCTURE || value.type == MATTER_TLV_ARRAY ||
		value.type == MATTER_TLV_LIST;
	*element = value;
	return MATTER_TLV_OK;
invalid:
	return reader->error = MATTER_TLV_INVALID_ENCODING;
truncated:
	return reader->error = MATTER_TLV_TRUNCATED;
}

Matter_Tlv_Result_T matter_tlv_skip_container(Matter_Tlv_Reader_T* reader) {
	if (!reader) return MATTER_TLV_INVALID_ARGUMENT;
	if (reader->error) return reader->error;
	if (!reader->depth || !reader->can_skip) return MATTER_TLV_INVALID_ARGUMENT;
	uint8_t target_depth = reader->depth - 1;
	Matter_Tlv_Element_T element;
	while (reader->depth > target_depth) {
		Matter_Tlv_Result_T result = matter_tlv_next(reader, &element);
		if (result != MATTER_TLV_OK) return result;
	}
	return MATTER_TLV_OK;
}
