#ifndef MATTER_MESSAGE_HEADER_H_INCLUDED
#define MATTER_MESSAGE_HEADER_H_INCLUDED 1

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	MATTER_MESSAGE_DESTINATION_MASK = 0x03,
	MATTER_MESSAGE_DESTINATION_NONE = 0,
	MATTER_MESSAGE_DESTINATION_NODE = 1,
	MATTER_MESSAGE_DESTINATION_GROUP = 2,
	MATTER_MESSAGE_SOURCE_PRESENT = 0x04,
	MATTER_MESSAGE_SESSION_MASK = 0x03,
	MATTER_MESSAGE_SESSION_UNICAST = 0,
	MATTER_MESSAGE_SESSION_GROUP = 1,
	MATTER_MESSAGE_EXTENSIONS = 0x20,
	MATTER_MESSAGE_CONTROL = 0x40,
	MATTER_MESSAGE_PRIVACY = 0x80
};

typedef enum {
	MATTER_MESSAGE_OK = 0,
	MATTER_MESSAGE_INVALID_ARGUMENT,
	MATTER_MESSAGE_TRUNCATED,
	MATTER_MESSAGE_INVALID_ENCODING,
	MATTER_MESSAGE_UNSUPPORTED,
	MATTER_MESSAGE_NO_SPACE
} Matter_Message_Result_T;

typedef struct {
	uint64_t source_node_id;
	uint64_t destination_id; /* Node ID or Group ID, selected by DSIZ. */
	uint32_t message_counter;
	uint16_t session_id;
	uint8_t message_flags;
	uint8_t security_flags;
} Matter_Message_Header_T;

/* Core 1.6.1 section 4.4.1, message format version 0, without privacy.
 * Stateless, no allocation/globals/callbacks; all storage belongs to caller.
 * All pointers/spans must be disjoint and valid for the call. NULL data allowed
 * only for size/capacity zero. Every failure preserves ALL outputs/buffer bytes.
 * This is syntax only: no session/address policy, authentication, decryption,
 * MIC/payload parsing, or TCP length prefix. OK does NOT validate a message.
 */

/* Read a header prefix; consumed is the offset of the remaining message payload.
 * The input may end exactly after the header. Absent IDs become zero.
 * Reserved unused bits are ignored but retained in flags; reserved Version,
 * DSIZ and Session Type VALUES are INVALID_ENCODING. P returns UNSUPPORTED
 * before reading obscured fields. MX: bounds-check and skip its length-prefixed
 * payload (including zero-length payload); contents are not interpreted.
 * Keep the ORIGINAL wire bytes for future authentication; re-encoding normalizes
 * reserved bits and cannot reconstruct authenticated data or extensions.
 * Work is constant: skipped extensions are not scanned or copied.
 */
Matter_Message_Result_T matter_message_header_read(const uint8_t* data, size_t size,
	Matter_Message_Header_T* header, size_t* consumed);

/* Write 8..24 bytes, return written; remaining output bytes stay untouched.
 * Version/DSIZ/Session Type checked as in read. Reserved unused bits written as
 * zero. P or MX returns UNSUPPORTED (version 1.0 nodes must transmit MX=0).
 * Group destination must fit uint16. Absent ID values are ignored.
 * No hidden state: correct arguments/increase capacity and retry after error.
 */
Matter_Message_Result_T matter_message_header_write(const Matter_Message_Header_T* header,
	uint8_t* data, size_t capacity, size_t* written);

#ifdef __cplusplus
}
#endif
#endif
