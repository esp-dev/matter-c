#ifndef MATTER_TLV_H_INCLUDED
#define MATTER_TLV_H_INCLUDED 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MATTER_TLV_MAX_DEPTH 16

typedef enum {
	MATTER_TLV_OK = 0,
	MATTER_TLV_DONE,
	MATTER_TLV_INVALID_ARGUMENT,
	MATTER_TLV_TRUNCATED,
	MATTER_TLV_INVALID_ENCODING,
	MATTER_TLV_DEPTH_LIMIT,
	MATTER_TLV_NO_SPACE,
	MATTER_TLV_DUPLICATE_TAG,
	MATTER_TLV_PROFILE_REQUIRED,
	MATTER_TLV_LIMIT_REACHED
} Matter_Tlv_Result_T;

typedef enum {
	MATTER_TLV_SIGNED, MATTER_TLV_UNSIGNED, MATTER_TLV_BOOL,
	MATTER_TLV_FLOAT32, MATTER_TLV_FLOAT64, MATTER_TLV_UTF8, MATTER_TLV_BYTES,
	MATTER_TLV_NULL, MATTER_TLV_STRUCTURE, MATTER_TLV_ARRAY, MATTER_TLV_LIST,
	MATTER_TLV_END
} Matter_Tlv_Type_T;

/* control is the wire tag control (0..7). vendor/profile are meaningful only
 * for fully qualified tags (6,7); implicit tags (4,5) stay unresolved.
 * Common/context/anonymous forms remain distinguishable; no schema inference.
 */
typedef struct {
	uint8_t control;
	uint16_t vendor, profile;
	uint32_t number;
} Matter_Tlv_Tag_T;

typedef struct {
	Matter_Tlv_Type_T type;
	Matter_Tlv_Tag_T tag;
	size_t offset;
	const uint8_t* data;
	size_t size;
	uint64_t unsigned_value; /* Unsigned, bool, or IEEE float bits, host byte order. */
	int64_t signed_value;
} Matter_Tlv_Element_T;

/* Caller-owned, small fixed storage; fields are private to the implementation.
 * No allocation, recursion, globals, hardware or hidden buffer ownership.
 * Input must remain readable/unchanged; output spans borrow that same input.
 * One thread per reader; multiple independent readers may share input.
 */
typedef struct {
	const uint8_t* data;
	size_t size, offset;
	uint8_t parents[MATTER_TLV_MAX_DEPTH];
	uint8_t depth, max_depth;
	bool root_seen, can_skip;
	Matter_Tlv_Result_T error;
} Matter_Tlv_Reader_T;

/* NULL data allowed only with size 0. max_depth is 1..MAX_DEPTH, including root.
 * Successful init required before use; failure leaves reader unchanged.
 * Caller bounds total message size/work budget; UTF-8 checking is linear.
 */
Matter_Tlv_Result_T matter_tlv_init(Matter_Tlv_Reader_T* reader, const uint8_t* data,
	size_t size, uint8_t max_depth);

/* Walk one complete document as tokens, including container open/end tokens.
 * OK consumes one token, DONE only after one root and exact buffer exhaustion.
 * Empty input/missing terminator -> TRUNCATED; trailing roots -> INVALID_ENCODING.
 * On error or DONE, output and offset are unchanged. Encoding errors latch until
 * reinit. Argument errors do not latch. Input, reader and output must not overlap.
 *
 * Checks wire types, tag widths/placement, container balance and UTF-8. Does NOT
 * validate schemas, required fields, duplicate structure tags, canonical order
 * or implicit profiles. Float conversion/range policy belongs to the caller.
 * Reading a start token does not establish validity of its complete container:
 * consume through DONE before treating the document as accepted.
 */
Matter_Tlv_Result_T matter_tlv_next(Matter_Tlv_Reader_T* reader, Matter_Tlv_Element_T* element);

/* After next returns a container start, skip its remaining contents through its
 * END token. Only valid immediately after a start token. Other scalar/unknown
 * fields need no skip: next already consumed their value. Uses next's validation
 * and limits. Failure may consume preceding valid children; error remains latched.
 */
Matter_Tlv_Result_T matter_tlv_skip_container(Matter_Tlv_Reader_T* reader);

#ifdef __cplusplus
}
#endif
#endif
