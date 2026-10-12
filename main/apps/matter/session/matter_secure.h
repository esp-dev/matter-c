#ifndef MATTER_SECURE_H_INCLUDED
#define MATTER_SECURE_H_INCLUDED 1
#include "matter_pase.h"
#include "../codec/matter_protocol_header.h"

#ifdef __cplusplus
extern "C" {
#endif
enum { MATTER_SECURE_MAX_PACKET = 1232, MATTER_SECURE_OVERHEAD = 24 };
typedef struct Matter_Secure* Matter_Secure_T;
/* Published only by a completed CASE handoff. PASE returns INVALID_STATE.
 * fabric_index is local; node/CAT values come from the verified peer NOC. */
typedef struct {
    uint8_t fabric_index, cat_count;
    uint64_t fabric_id, local_node_id, peer_node_id;
    uint32_t cats[3];
} Matter_Secure_Identity_T;
Matter_Result_T matter_secure_identity(Matter_Secure_T,Matter_Secure_Identity_T*);

typedef struct {
	uint16_t local_session_id, peer_session_id;
	uint64_t last_sent_ms, last_received_ms;
	size_t pins;
	bool exhausted, closing;
	Matter_Pase_Intervals_T peer_intervals;
} Matter_Secure_Info_T;
typedef struct {
	Matter_Message_Header_T message;
	Matter_Protocol_Header_T protocol;
	const uint8_t* payload;
	size_t size;
	bool duplicate;
	/* Exact authenticated protocol bytes, contiguous with payload for fresh RX.
	 * For duplicates encoded_size ends at the protocol header (no payload access).
	 * payload_size_on_wire preserves length for control-message validation. */
	const uint8_t* encoded;
	size_t encoded_size, payload_size_on_wire;
} Matter_Secure_Received_T;
/* Admission runs synchronously while the session is BUSY. Copy into owned RX
 * storage, return OK only if accepted; other results do not commit reception.
 * Borrowed message/payload expire on return and are erased. Duplicate packets
 * expose authenticated MRP header metadata ONLY (payload=NULL,size=0); never
 * dispatch their opcode to the application. They still need A/R handling.
 * info/identity/retain/release are allowed to pin accepted RX storage; failed admission
 * must unwind its new references. All other session reentry returns BUSY.
 * No retained pointers into this message or asynchronous admission completion.
 */
typedef Matter_Result_T (*Matter_Secure_Admit_T)(void* user, const Matter_Secure_Received_T* message);

/* PASE constructor (Core 1.6.1 4.8/4.14); CASE uses matter_secure_new_case. Heap-owned context/scratch; no OS,
 * tasks, timers or I/O. All calls serialized on application's owner thread.
 * Port copied, backend borrowed through delete. NULL on invalid port/PASE,
 * OOM or RNG failure; failed construction leaves PASE keys available. Successful
 * construction consumes them once, initializes fresh TX/RX counters. No reset,
 * clone or import of a live session. Application reserves unique local IDs and
 * routes by local ID AND bound peer/path; no address discovery/authorization here.
 */
Matter_Secure_T matter_secure_new(const Matter_Crypto_Port_T* port, Matter_Pase_T pase, uint64_t now_ms);
Matter_Result_T matter_secure_info(Matter_Secure_T session, Matter_Secure_Info_T* info);
Matter_Result_T matter_secure_challenge(Matter_Secure_T session, uint8_t challenge[16]);
/* Hold a pin for each exchange/queued TX/borrower until cancellation/completion
 * actually drains it. Call retain BEFORE handing out the reference. close blocks
 * new traffic; final release erases keys, delete requires closed and zero pins.
 * Retained ciphertext belongs to caller and may be retried unchanged during drain.
 */
Matter_Result_T matter_secure_retain(Matter_Secure_T session);
Matter_Result_T matter_secure_release(Matter_Secure_T session);
Matter_Result_T matter_secure_close(Matter_Secure_T session);
Matter_Result_T matter_secure_delete(Matter_Secure_T session);
/* plaintext includes encoded protocol header. Output is 8-byte message header,
 * ciphertext and 16-byte MIC, <=MAX_PACKET. Disjoint spans/count, no retention.
 * Preflight errors preserve output/counter. Once crypto starts, counter is
 * consumed even on failure; failure clears packet bytes, preserves written.
 * UINT32_MAX can be emitted once; info.exhausted then forbids new messages.
 * Every retry reuses the SAME packet, never calls seal again. now_ms monotonic
 * across seal/receive, measured by caller; info timestamps track accepted work.
 */
Matter_Result_T matter_secure_seal(Matter_Secure_T session, const uint8_t* plaintext, size_t size,
	uint64_t now_ms, uint8_t* packet, size_t capacity, size_t* written);
/* Authenticate exact wire header as AAD before decoding payload or replay checks.
 * PASE nonce node ID is zero; CASE uses authenticated sender NodeID. Optional
 * CASE wire IDs must match the session identity. Group/privacy/control
 * frames are outside this profile. Bad input/MIC never calls admit or alters RX
 * state. Successful admission commits counter; failed admission permits retry.
 * Work bounded by MAX_PACKET, scratch private per instance and cleared each call.
 */
Matter_Result_T matter_secure_receive(Matter_Secure_T session, const uint8_t* packet, size_t size,
	uint64_t now_ms, Matter_Secure_Admit_T admit, void* user);
#ifdef __cplusplus
}
#endif
#endif
