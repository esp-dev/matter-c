#ifndef MATTER_TLV_WRITER_H_INCLUDED
#define MATTER_TLV_WRITER_H_INCLUDED 1

#include "matter_tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Caller owns context and fixed output storage; no allocation, globals or
 * recursion. Fields are private: do not resize/change them between calls.
 * One thread per writer; independent writers require separate output buffers.
 */
typedef struct {
	uint8_t* data;
	size_t capacity, size;
	uint8_t parents[MATTER_TLV_MAX_DEPTH];
	uint8_t depth, max_depth;
	bool root_seen;
} Matter_Tlv_Writer_T;

/* Successful init required. NULL data only with capacity 0; depth 1..16.
 * Failure preserves writer. Init never touches output bytes.
 */
Matter_Tlv_Result_T matter_tlv_writer_init(Matter_Tlv_Writer_T* writer, uint8_t* data,
	size_t capacity, uint8_t max_depth);

/* Append one token, including container start or END, to one document.
 * Uses element.type/tag and signed_value, unsigned_value (uint/bool/IEEE bits),
 * or data/size (strings) as appropriate. Other value fields and offset ignored.
 * Strings are copied during this call; NULL allowed only for length zero.
 * width: integer value/string length width 1/2/4/8, or 0 for smallest encoding.
 * All other types require width 0. Float32 bits must fit uint32, bool is 0 or 1.
 * Tag control explicitly selects the form; number must fit and use A.8's width.
 * Unused tag fields must be zero. END requires a completely zero tag.
 *
 * All failures preserve the entire buffer AND writer, including NO_SPACE.
 * Errors do not latch: check EVERY return; finish cannot detect an omitted field
 * after an ignored failure. Correct/retry a token or reinit a larger buffer and
 * rebuild. No rollback of earlier tokens and no space reserved for future ENDs.
 * writer, element, source data and output storage must not overlap. Storage must
 * remain valid throughout use; source spans must be valid for the entire call.
 * Capacity is checked before reading any string payload, including UTF-8.
 * Caller bounds message size/work; UTF-8 checking/copying is linear.
 *
 * Checks syntax/UTF-8/placement/depth, not duplicate structure tags, implicit
 * profile resolution, schemas or canonical order (same boundary as reader).
 */
Matter_Tlv_Result_T matter_tlv_write(Matter_Tlv_Writer_T* writer,
	const Matter_Tlv_Element_T* element, uint8_t width);

/* OK and byte count only when exactly one root is complete. Otherwise TRUNCATED;
 * output count unchanged on failure. Does not append bytes or seal the writer.
 * Repeated success is allowed; a further root is rejected by write.
 * size must not overlap writer or output storage.
 */
Matter_Tlv_Result_T matter_tlv_writer_finish(const Matter_Tlv_Writer_T* writer, size_t* size);

#ifdef __cplusplus
}
#endif
#endif
