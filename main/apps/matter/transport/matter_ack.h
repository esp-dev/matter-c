#ifndef MATTER_ACK_H_INCLUDED
#define MATTER_ACK_H_INCLUDED 1

#include "matter_exchange.h"

#ifdef __cplusplus
extern "C" {
#endif

enum { MATTER_ACK_CAPACITY = MATTER_EXCHANGE_CAPACITY, MATTER_ACK_TIMEOUT_MS = 200 };
typedef struct Matter_Ack_Table* Matter_Ack_Table_T;

typedef struct {
	uint64_t id;
	Matter_Exchange_Info_T exchange;
	uint32_t counter;
	bool standalone;
} Matter_Ack_Request_T;

/* Pure bookkeeping, one calloc, CAPACITY normal entries + one immediate slot +
 * one send reservation. Owner thread only, no callbacks/tasks/clock/I/O/lease.
 * Keys copied; session token has the incarnation semantics in exchange.h.
 * This does NOT create an exchange or authenticate a message. Caller must keep
 * session/exchange/routing alive until close returns OK. In particular, drain
 * ACKs BEFORE exchange release/process and BEFORE stopping UDP/owner. The
 * existing owner stop does not enforce this ordering; integration is separate.
 * No payload buffers or pointers are retained. New table = new ID namespace.
 */
Matter_Ack_Table_T matter_ack_new(void);
/* NULL OK. Nonempty/reserved -> INVALID_STATE, never discards an obligation.
 * Before freeing, invalidate all external routing/events to this table.
 */
Matter_Result_T matter_ack_delete(Matter_Ack_Table_T table);

/* Record an admitted NONDUPLICATE R=1 unicast message. OK means recorded, not
 * sent. Counter zero is valid. Same counter is an idempotent retry; no rearm.
 * Previous unsent counter: make it due now and return WOULD_BLOCK WITHOUT
 * accepting the new counter. Caller retains/retries input before delivery.
 * An in-flight same-key send also gives WOULD_BLOCK; full -> LIMIT_REACHED.
 * Closing key/stopping table -> INVALID_STATE. No allocation per message.
 * received_ms is the ORIGINAL reception timestamp in application monotonic
 * milliseconds (same epoch as next), preserved on deferred retries. It may be
 * older than the current clock: retry must not extend the ACK deadline.
 * Deadline addition saturates at UINT64_MAX (never wraps).
 */
Matter_Result_T matter_ack_record(Matter_Ack_Table_T table,
	const Matter_Exchange_Info_T* key, uint32_t counter, uint64_t received_ms);
/* Duplicate or rejected unsolicited R=1: queue a standalone obligation NOW.
 * Separate slot preserves a different pending counter on the same exchange.
 * Unknown exchange uses copied key with local role = !incoming I; executor
 * owns ephemeral context/lifetime. No normal responder insertion here.
 * Slot occupied -> WOULD_BLOCK, input NOT accepted (including identical retry).
 * A successful immediate ACK also marks a matching normal counter as sent.
 */
Matter_Result_T matter_ack_immediate(Matter_Ack_Table_T table,
	const Matter_Exchange_Info_T* key, uint32_t counter);

/* Reserve at most one send: immediate first, otherwise earliest due/closing
 * normal entry. No ready work or reservation already held -> WOULD_BLOCK.
 * OK copies descriptor, but DOES NOT submit/send it. Standalone requires A=1,
 * this counter, Secure Channel protocol 0, opcode 0x10 and empty payload.
 * ID nonzero, monotonic, never wraps; exhaustion -> LIMIT_REACHED.
 * now_ms must not precede an earlier next call or any reception timestamp
 * supplied to record; otherwise INVALID_ARGUMENT. Even blocked/empty next
 * advances this clock. Failed reservation never changes the output.
 */
Matter_Result_T matter_ack_next(Matter_Ack_Table_T table, uint64_t now_ms,
	Matter_Ack_Request_T* request);
/* Reserve pending ACK for a NON-standalone outgoing message on the exact key,
 * including an entry already acknowledged standalone. Unknown -> INVALID_STATE.
 * No entries removed before successful completion; closing/stopping rejected.
 */
Matter_Result_T matter_ack_piggyback(Matter_Ack_Table_T table,
	const Matter_Exchange_Info_T* key, Matter_Ack_Request_T* request);
/* Exactly once per reservation, including submission rejection. Rejected
 * WOULD_BLOCK/OFFLINE/PORT_ERROR -> complete(FAILED); accepted asynchronous
 * send -> wait for its actual terminal outcome. SUCCEEDED means local send,
 * not peer receipt. FAILED/CANCELLED retain the obligation unless explicitly
 * discarded by terminal session removal; the reservation is always released.
 * Caller must stop using any backend references BEFORE complete, never fake a
 * success on acceptance/cancel. Stale ID -> INVALID_STATE; zero/bad result ->
 * INVALID_ARGUMENT. Output structs unchanged on errors throughout this API.
 */
Matter_Result_T matter_ack_complete(Matter_Ack_Table_T table, uint64_t id,
	Matter_Operation_Result_T result);

/* Make unsent entries immediately eligible, reject new records on closing
 * entries, keep in-flight/immediate work. OK only after all obligations for
 * this key drain. Caller gates further RX for closing keys, including keys
 * without a normal entry; this is NOT full MRP close (no retransmission table).
 */
Matter_Result_T matter_ack_close(Matter_Ack_Table_T table, const Matter_Exchange_Info_T* key);
/* Terminal session removal, unlike graceful close. Caller gates new admission.
 * Discards unsent obligations; a reserved TX remains PENDING until its actual
 * completion, then is discarded even on failure/cancel (never requeued).
 * Does not stop the table or affect other sessions. Idempotent, no allocation. */
Matter_Result_T matter_ack_discard_session(Matter_Ack_Table_T table, Matter_Exchange_Session_T session);
/* Irreversible drain of this table: rejects record/immediate/piggyback, allows
 * next/complete/close. Repeat to query: PENDING until empty, then OK. Does not
 * cancel accepted sends or discard failed ACKs; application drives retries.
 */
Matter_Result_T matter_ack_stop(Matter_Ack_Table_T table);

#ifdef __cplusplus
}
#endif
#endif
