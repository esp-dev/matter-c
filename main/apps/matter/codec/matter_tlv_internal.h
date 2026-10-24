#ifndef MATTER_TLV_INTERNAL_H_INCLUDED
#define MATTER_TLV_INTERNAL_H_INCLUDED 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "matter_tlv_writer.h"

/* Internal sizing pass: identical token validation, widths, depth and capacity
 * accounting to write, with no output access. Only this private initializer
 * creates a nonzero-capacity writer without a buffer; public init still rejects
 * that combination. Use ordinary write/finish on this measuring context. */
static inline Matter_Tlv_Result_T matter_tlv_measure_init(Matter_Tlv_Writer_T* writer,size_t capacity,uint8_t depth) {
	Matter_Tlv_Result_T result=matter_tlv_writer_init(writer,NULL,0,depth);
	if(result==MATTER_TLV_OK) writer->capacity=capacity;
	return result;
}

/* Shared by the reader and writer; no public UTF-8 utility API. */
static inline bool valid_utf8(const uint8_t* data, size_t size) {
	size_t pos = 0;
	while (pos < size) {
		uint32_t cp = data[pos++], minimum;
		unsigned count;
		if (cp < 0x80) continue;
		if (cp >= 0xc2 && cp <= 0xdf) { count = 1; minimum = 0x80; cp &= 0x1f; }
		else if (cp >= 0xe0 && cp <= 0xef) { count = 2; minimum = 0x800; cp &= 0x0f; }
		else if (cp >= 0xf0 && cp <= 0xf4) { count = 3; minimum = 0x10000; cp &= 0x07; }
		else return false;
		if (count > size - pos) return false;
		while (count--) {
			uint8_t next = data[pos++];
			if ((next & 0xc0) != 0x80) return false;
			cp = (cp << 6) | (next & 0x3f);
		}
		if (cp < minimum || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return false;
	}
	return true;
}

#endif
