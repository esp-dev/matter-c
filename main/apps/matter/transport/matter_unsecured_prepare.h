#ifndef MATTER_UNSECURED_PREPARE_H_INCLUDED
#define MATTER_UNSECURED_PREPARE_H_INCLUDED 1

#include "matter_unsecured.h"
#include "matter_counter.h"
#include "../codec/matter_protocol_header.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	size_t size;
	uint32_t counter;
} Matter_Unsecured_Prepared_T;

/* Prepare ONE NEW unsecured UDP message. No allocation, callbacks, retained
 * pointers or I/O. Owner-thread only; caller owns a session pin throughout
 * preparation and until the next consumer acquires its own pin. This does not
 * acquire/release pins. Use the node's ONE initialized UNSECURED counter.
 *
 * Caller owns output bytes through actual TX/MRP drain. Retransmission reuses
 * those bytes; NEVER prepare again for an MRP retry. Session role selects the
 * ephemeral source/destination ID, independently of the exchange I flag.
 * Protocol allowlist, exchange validity, close/admission and routing are caller
 * policy. OK is not authentication or permission to send an arbitrary protocol.
 *
 * Input byte span may overlap destination (including in-place prepend).
 * All metadata/state/output-result objects must be disjoint from byte spans
 * and each other, valid for the call. NULL input allowed only with size zero;
 * NULL destination only with capacity zero. Bytes beyond result.size unchanged.
 * Preflight checks syntax, <= MATTER_UDP_MAX_PAYLOAD, capacity, live pinned
 * session and counter mode. Capacity/size -> LIMIT_REACHED, invalid syntax ->
 * INVALID_ARGUMENT, unpinned/stale session or wrong mode -> INVALID_STATE.
 * Errors preserve destination/result. Preflight and counter_take errors consume
 * no counter. Once taken, a number NEVER returns after a later error or rejected
 * queue/send. Unexpected codec failure after take -> PORT_ERROR (number spent).
 * The backend must still enforce the full IPv6 MTU including extension headers.
 */
Matter_Result_T matter_unsecured_prepare(Matter_Unsecured_T sessions,
	Matter_Exchange_Session_T session, Matter_Counter_T* counter,
	const Matter_Protocol_Header_T* protocol, const uint8_t* payload, size_t payload_size,
	uint8_t* data, size_t capacity, Matter_Unsecured_Prepared_T* prepared);

/* Wrap an already encoded protocol header + payload, e.g. the ACK sender's
 * message. Validate header syntax, reject SX/reserved transmit flags; copy bytes
 * unchanged. No second implementation of standalone ACK semantics/encoding.
 */
Matter_Result_T matter_unsecured_prepare_encoded(Matter_Unsecured_T sessions,
	Matter_Exchange_Session_T session, Matter_Counter_T* counter,
	const uint8_t* protocol_message, size_t size,
	uint8_t* data, size_t capacity, Matter_Unsecured_Prepared_T* prepared);

#ifdef __cplusplus
}
#endif
#endif
