#ifndef MATTER_EXCHANGE_H_INCLUDED
#define MATTER_EXCHANGE_H_INCLUDED 1

#include "../matter.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One target-wide pool budget for RX/exchanges, ACK and MRP. Define identically
 * for every translation unit. Legacy/core fixtures keep the default of eight;
 * application compositions must size it for their concurrent interaction quotas. */
#ifndef MATTER_TRANSPORT_CAPACITY
#define MATTER_TRANSPORT_CAPACITY 8
#endif
#if MATTER_TRANSPORT_CAPACITY < 8 || MATTER_TRANSPORT_CAPACITY > 128
#error "MATTER_TRANSPORT_CAPACITY must be in 8..128"
#endif
enum { MATTER_EXCHANGE_CAPACITY = MATTER_TRANSPORT_CAPACITY, MATTER_EXCHANGE_INITIATORS_PER_SESSION = 5 };
typedef struct Matter_Exchange_Table* Matter_Exchange_Table_T;
typedef uint64_t Matter_Exchange_Handle_T;

/* Opaque identity of ONE unicast session incarnation (secured or unsecured),
 * assigned by the caller/session layer, not the 16-bit wire Session ID, an IP
 * address or a pointer. Nonzero, owner-local, never reused for a different
 * session during the table lifetime, including stop/start. It incorporates the
 * peer identity: two peers with wire Session ID 0 MUST get different tokens.
 * Caller resolves/authenticates sessions BEFORE lookup; this is not proof of
 * identity. Retire all entries before destroying that session. No group/MCSP.
 */
typedef uint64_t Matter_Exchange_Session_T;

typedef struct {
	Matter_Exchange_Session_T session;
	uint16_t exchange_id; /* Wire ID, including zero. */
	bool initiator;       /* LOCAL role; incoming I flag must be the inverse. */
} Matter_Exchange_Info_T;

/* Optional drain barrier, copied by set_close_port while inactive only.
 * user borrowed until replacement/deletion. prepare runs on owner thread,
 * synchronously/nonblocking; handle/info borrowed only for the callback.
 * It may request/check ACK close (and later retransmission drain), but must
 * NOT mutate this table/owner or submit blocking work. Table reentry -> BUSY.
 * OK permits metadata removal; PENDING retains it; all other results become
 * PORT_ERROR and retain it. Called again on explicit release/process retry,
 * including entries that returned OK during a blocked batch: be idempotent.
 * No callbacks on set/new/delete, no queued callbacks or retained info pointers.
 */
typedef struct {
	void* user;
	Matter_Result_T (*prepare)(void* user, Matter_Exchange_Handle_T handle,
		const Matter_Exchange_Info_T* info);
} Matter_Exchange_Close_Port_T;

/* One table per initiator node: caller supplies a random initial wire ID from
 * its RNG BEFORE construction (no default/fallback seed). Tests may supply a
 * deterministic seed. One calloc, fixed slots, no allocation per exchange.
 * Owner borrowed; delete table before owner, even when never started.
 * Owner thread only, no tasks, OS types, payloads, protocol handlers or timers.
 */
Matter_Exchange_Table_T matter_exchange_new(Matter_T owner, uint16_t initial_id);
Matter_Result_T matter_exchange_delete(Matter_Exchange_Table_T table); /* NULL OK. */
/* NULL port disables barrier (legacy behavior). Non-NULL requires prepare.
 * Active/stopping table -> INVALID_STATE; failed set preserves current port.
 * Configuration survives stop/start. Dependency must outlive table or be
 * detached/replaced while inactive BEFORE that dependency is deleted.
 */
Matter_Result_T matter_exchange_set_close_port(Matter_Exchange_Table_T table,
	const Matter_Exchange_Close_Port_T* port);
/* Start reserves one owner operation slot for the ENTIRE table. RUNNING owner
 * required, active start idempotent, start while stopping INVALID_STATE.
 * Wire sequence and handle sequence survive stop/start. New table starts new
 * handle namespace: discard all old handles/events BEFORE deletion/recreation.
 */
Matter_Result_T matter_exchange_start(Matter_Exchange_Table_T table);
Matter_Result_T matter_exchange_stop(Matter_Exchange_Table_T table);
/* Owner stop also requests table stop. process checks the close barrier for
 * EVERY live entry (at most CAPACITY callbacks), retaining ALL metadata and
 * its owner lease until all return OK. PORT_ERROR takes priority over PENDING.
 * Without a barrier it clears metadata as before. This does not keep UDP or
 * sessions alive: drain BEFORE stopping those dependencies/owner. No force
 * close; a permanent barrier failure leaves stop pending. Not full MRP close.
 * Table mutations from owner callbacks are forbidden; reentry during process
 * completion returns BUSY. Call after the outer owner callback has returned.
 */
Matter_Result_T matter_exchange_process(Matter_Exchange_Table_T table);
/* Readiness query, no mutation: OK only when entry APIs can run. Separates a
 * stopped table from a missing key (match returns INVALID_STATE for both).
 * Owner thread only; BUSY during process completion, NULL INVALID_ARGUMENT.
 */
Matter_Result_T matter_exchange_check(Matter_Exchange_Table_T table);

/* All entry APIs require active table + RUNNING owner, reject after stop request.
 * Every error preserves outputs. Outputs must be disjoint and caller-owned.
 * Handles are table-local, nonzero, monotonically increasing, never wrap.
 * They are not wire IDs or pointers; stale get/release returns INVALID_STATE.
 */
/* Create local initiator with next wire ID; increment modulo 65536 on success
 * only. At most five local initiators per unicast session. Full/exhausted table
 * or handle space -> LIMIT_REACHED. A live same-session initiator collision on
 * wrap -> BUSY, no skipping IDs; retry after its release. No send occurs here.
 */
Matter_Result_T matter_exchange_initiate(Matter_Exchange_Table_T table,
	Matter_Exchange_Session_T session, Matter_Exchange_Handle_T* handle);
/* Metadata-only responder insertion using peer's wire ID. Caller MUST already
 * have admitted a nonduplicate incoming I=1 message on a registered protocol.
 * Does NOT perform admission/duplicate/security checks or ephemeral ACK logic.
 * Existing same-session responder -> BUSY; no change to initiator ID sequence.
 */
Matter_Result_T matter_exchange_accept(Matter_Exchange_Table_T table,
	Matter_Exchange_Session_T session, uint16_t exchange_id, Matter_Exchange_Handle_T* handle);
/* Lookup only; unknown returns INVALID_STATE and never creates an exchange. */
Matter_Result_T matter_exchange_match(Matter_Exchange_Table_T table,
	Matter_Exchange_Session_T session, uint16_t exchange_id, bool incoming_initiator,
	Matter_Exchange_Handle_T* handle);
Matter_Result_T matter_exchange_get(Matter_Exchange_Table_T table,
	Matter_Exchange_Handle_T handle, Matter_Exchange_Info_T* info);
/* Query while ready, no callback. match still finds closing entries so their
 * received A/R flags can be processed; application delivery must be suppressed.
 */
Matter_Result_T matter_exchange_is_closing(Matter_Exchange_Table_T table,
	Matter_Exchange_Handle_T handle, bool* closing);
/* Starts irreversible closing, calls barrier. PENDING/PORT_ERROR keeps entry
 * and closes application admission, but does NOT release it automatically:
 * caller retries release after drain. Existing same-key accept/initiate stays
 * BUSY while retained. get/match still resolve it; no un-close operation.
 */
Matter_Result_T matter_exchange_release(Matter_Exchange_Table_T table, Matter_Exchange_Handle_T handle);
/* Remove all metadata for a retired session, OK also if no entries match.
 * Begins closing all matching entries, invokes all barriers, removes none if
 * any barrier blocks/errors (closing/ACK side effects are not rolled back).
 * Other sessions unaffected. Caller must never reuse the retired session token.
 */
Matter_Result_T matter_exchange_release_session(Matter_Exchange_Table_T table,
	Matter_Exchange_Session_T session);

#ifdef __cplusplus
}
#endif
#endif
