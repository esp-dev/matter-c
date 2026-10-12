#ifndef MATTER_RETRANSMISSION_H_INCLUDED
#define MATTER_RETRANSMISSION_H_INCLUDED 1

#include "matter_exchange.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { MATTER_RETRANSMISSION_CAPACITY = MATTER_EXCHANGE_CAPACITY, MATTER_RETRANSMISSION_MAX_ATTEMPTS = 5,
	MATTER_RETRANSMISSION_MAX_BYTES = 1232 };
typedef struct Matter_Retransmission* Matter_Retransmission_T;

typedef struct {
	uint32_t idle_interval_ms, active_interval_ms;
	bool peer_active;
} Matter_Retransmission_Parameters_T;

typedef struct {
	uint64_t id; /* Message identity, NOT the wire counter or attempt ID. */
	Matter_Exchange_Info_T exchange;
	uint32_t counter;
	const uint8_t* data;
	size_t size;
} Matter_Retransmission_Message_T;

typedef struct {
	uint64_t id; /* Fresh reservation ID for each send attempt. */
	Matter_Retransmission_Message_T message;
	uint64_t deadline_ms;
	uint8_t attempt; /* 1..configured maximum, initial transmission included. */
} Matter_Retransmission_Request_T;

typedef enum {
	MATTER_RETRANSMISSION_SENT = 0, /* Local transport success, NOT peer delivery. */
	MATTER_RETRANSMISSION_RETRYABLE, /* Nonfatal submission/completion failure. */
	MATTER_RETRANSMISSION_FATAL
} Matter_Retransmission_Tx_Result_T;

typedef enum {
	MATTER_RETRANSMISSION_ACKNOWLEDGED = 1,
	MATTER_RETRANSMISSION_TIMEOUT,
	MATTER_RETRANSMISSION_FAILED,
	MATTER_RETRANSMISSION_CANCELLED
} Matter_Retransmission_Outcome_T;

typedef struct {
	Matter_Retransmission_Message_T message;
	Matter_Retransmission_Outcome_T outcome;
	uint8_t attempts; /* Completed attempts, including nonfatal/fatal errors. */
} Matter_Retransmission_Result_T;

/* Pure owner-thread bookkeeping, one calloc, CAPACITY records, one TX reservation.
 * No tasks, callbacks, clock reads, RNG, session ownership, encryption or I/O.
 * max_attempts must be 1..5; 5 is Core Table 22 default, current bounded profile.
 * No allocation per message. IDs monotonically increase, never wrap; fresh table
 * is a new namespace. Invalidate external event routing BEFORE delete/recreate.
 */
Matter_Retransmission_T matter_retransmission_new(uint8_t max_attempts);
Matter_Result_T matter_retransmission_delete(Matter_Retransmission_T table); /* NULL OK, nonempty invalid. */

/* Caller supplies a fully encoded (and encrypted if secured) UDP message with
 * R=1 and correct headers/counter, keeps bytes immutable and session/exchange/
 * credentials/transport alive until take returns its terminal result. No copy
 * or validation of opaque bytes, no new counter/encryption on retries. The
 * 1232 limit is storage/UDP ceiling, not validation of complete IPv6 MTU.
 * One record per exchange; also no duplicate counter in same session: BUSY,
 * including terminal records until take. Counter 0 valid. Caller prevents reuse
 * across completed messages within a session incarnation. Output unchanged on
 * failure (as for all output APIs). Full/ID exhaustion -> LIMIT_REACHED.
 */
Matter_Result_T matter_retransmission_add(Matter_Retransmission_T table,
	const Matter_Exchange_Info_T* key, uint32_t counter, const uint8_t* data, size_t size, uint64_t* id);
/* Advance monotonic time, expire last-attempt ACK waits, select earliest ready
 * message (ties by message ID). Does not reserve/send. Empty/not due or occupied
 * TX -> WOULD_BLOCK, but timeouts of other entries are still processed.
 * Call take after next, even on WOULD_BLOCK, to collect terminal outcomes.
 */
Matter_Result_T matter_retransmission_next(Matter_Retransmission_T table, uint64_t now_ms,
	Matter_Retransmission_Message_T* message);
/* Nearest timer/ready time; initial ready = 0. Excludes reserved and terminal
 * entries. WOULD_BLOCK = no timer, not necessarily drained (TX/results remain).
 */
Matter_Result_T matter_retransmission_deadline(Matter_Retransmission_T table, uint64_t* deadline_ms);
/* Immediately before a real send attempt, with current session parameters and
 * fresh uniform jitter16 from application RNG, mapped to [0,1] inclusively.
 * RNG failure: do not call prepare/send, propagate error in executor; no fallback.
 * Caller determines PeerActiveMode/first-message policy and validates discovery
 * parameters. Retries may use updated intervals. uint32 intervals include zero.
 * Core formula: interval * 1.1 * 1.6^max(0,n-1) * (1 + random*0.25), n=attempt-1.
 * Exact rational arithmetic, round UP once to integer ms, deadline saturates.
 * Reservation is not success. Submit without yielding to RX in between. Timer
 * starts at this submission time, not a possibly delayed completion callback.
 * First retry (attempt=2) requires discovery by the executor for ICD peers and
 * SHOULD trigger it otherwise. This table does not implement discovery.
 */
Matter_Result_T matter_retransmission_prepare(Matter_Retransmission_T table, uint64_t message_id,
	const Matter_Retransmission_Parameters_T* parameters, uint16_t jitter16, uint64_t now_ms,
	Matter_Retransmission_Request_T* request);
/* Exactly once per reservation AFTER dropping all backend references. Rejected
 * WOULD_BLOCK/OFFLINE etc must be classified RETRYABLE or FATAL, never SENT.
 * A RETRYABLE send attempt consumes the budget and starts the timer per Core
 * 4.12.5.1.2 (no busy retry loop). Accepted send waits for actual terminal result.
 * SENT/RETRYABLE await ACK even after the last attempt, then next expires it.
 * Stale ID -> INVALID_STATE. ACK/cancel during TX retains bytes until complete;
 * first terminal decision wins, even if complete reports a different outcome.
 */
Matter_Result_T matter_retransmission_complete(Matter_Retransmission_T table, uint64_t request_id,
	Matter_Retransmission_Tx_Result_T result);
/* Already authenticated RX with exact session/exchange/local role. Unknown,
 * wrong key/counter, duplicate or not-yet-attempted ACK -> OK no-op. During a
 * reservation marks delivered, stops retry, but keeps TX ownership until complete.
 * Compatible with the RX process_ack hook via a thin caller adapter.
 */
Matter_Result_T matter_retransmission_ack(Matter_Retransmission_T table,
	const Matter_Exchange_Info_T* key, uint32_t counter);
/* Explicit application abort, not graceful exchange close. No backend cancel
 * occurs here. Reserved -> PENDING until real complete; otherwise OK. Already
 * terminal remains unchanged. Missing message -> INVALID_STATE.
 */
Matter_Result_T matter_retransmission_cancel(Matter_Retransmission_T table, uint64_t message_id);
/* Cancel this session's records only; first terminal outcome wins. Caller gates
 * new adds. PENDING until real complete and take for every matching record.
 * Idempotent; no backend callbacks, allocation or table-wide stop. */
Matter_Result_T matter_retransmission_cancel_session(Matter_Retransmission_T table, Matter_Exchange_Session_T session);
/* Pull one terminal result, oldest message ID first, excluding in-flight TX.
 * Removes record and returns borrowed bytes to caller; it may now free/unpin
 * them and notify the application. No lost terminal events on a full table.
 */
Matter_Result_T matter_retransmission_take(Matter_Retransmission_T table, Matter_Retransmission_Result_T* result);
/* Conservative close barrier: PENDING until backend completion AND take for
 * every matching record. Does not cancel or change retry deadlines. Caller must
 * gate new sends on a closing exchange. A callback can use this for RX close.
 */
Matter_Result_T matter_retransmission_drained(Matter_Retransmission_T table, const Matter_Exchange_Info_T* key);
/* Irreversible graceful stop: reject add, keep next/prepare/complete/ACK/take.
 * PENDING until ALL results collected; never discard a record or force-free.
 */
Matter_Result_T matter_retransmission_stop(Matter_Retransmission_T table);

#ifdef __cplusplus
}
#endif
#endif
