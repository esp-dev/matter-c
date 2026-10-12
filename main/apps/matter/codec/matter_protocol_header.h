#ifndef MATTER_PROTOCOL_HEADER_H_INCLUDED
#define MATTER_PROTOCOL_HEADER_H_INCLUDED 1

/* Share the existing message-codec result type; no link dependency on its C. */
#include "matter_message_header.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
	MATTER_PROTOCOL_INITIATOR = 0x01,
	MATTER_PROTOCOL_ACK = 0x02,
	MATTER_PROTOCOL_RELIABLE = 0x04,
	MATTER_PROTOCOL_EXTENSIONS = 0x08,
	MATTER_PROTOCOL_VENDOR = 0x10
};

typedef struct {
	uint32_t acknowledged_message_counter;
	uint16_t exchange_id;
	uint16_t vendor_id;
	uint16_t protocol_id;
	uint8_t exchange_flags;
	uint8_t opcode;
} Matter_Protocol_Header_T;

/* Core 1.6.1 section 4.4.3. Stateless, no allocation or retained pointers.
 * Caller owns disjoint header, span and count storage, valid for the call.
 * NULL data allowed only for size/capacity zero. ALL failures preserve every
 * output byte and count. No framing, session/exchange/MRP policy or crypto.
 * For a secure session the caller must authenticate/decrypt BEFORE read, and
 * encrypt/authenticate AFTER write. This codec cannot detect ciphertext.
 * Protocol/vendor IDs and opcodes are raw numbers: the dispatcher must enforce
 * allocated/supported values (including Core Table 14 for standard vendor 0).
 * OK means syntax only, not a valid exchange or a supported protocol.
 */

/* Read the prefix of a plaintext protocol message. consumed is the application
 * payload offset; payload may be empty. Absent vendor defaults to standard 0,
 * absent ACK counter becomes 0. Presence is determined ONLY by V/A flags, not
 * by values. Reserved flags are ignored but retained. SX length is checked and
 * its payload skipped without copying/scanning (zero-length payload allowed).
 * Re-encoding cannot preserve reserved bits or skipped extensions; keep the
 * original bytes where required by the security layer. Constant bounded work.
 */
Matter_Message_Result_T matter_protocol_header_read(const uint8_t* data, size_t size,
	Matter_Protocol_Header_T* header, size_t* consumed);

/* Write 6..12 bytes. Reserved flags become zero; inactive vendor/ACK values are
 * ignored. SX returns UNSUPPORTED: version 1.0 nodes must transmit SX=0.
 * Remaining output storage is untouched. Check every return and retry as needed.
 */
Matter_Message_Result_T matter_protocol_header_write(const Matter_Protocol_Header_T* header,
	uint8_t* data, size_t capacity, size_t* written);

#ifdef __cplusplus
}
#endif
#endif
