#ifndef MATTER_UNSECURED_TX_H_INCLUDED
#define MATTER_UNSECURED_TX_H_INCLUDED 1

#include "matter_unsecured.h"
#include "../matter_udp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Matter_Unsecured_Tx* Matter_Unsecured_Tx_T;
typedef struct {
	void* user;
	/* Session is pinned during this call. OK writes a full unicast path snapshot;
	 * no pointer retention, blocking or inline mutation of adapter/dependencies.
	 * WOULD_BLOCK/OFFLINE preserved; other errors -> PORT_ERROR. Failed lookup
	 * acquires no work. Address refresh must not change the session identity.
	 */
	Matter_Result_T (*route)(void* user, Matter_Exchange_Session_T session, Matter_Udp_Path_T* path);
	/* Required synchronous barrier on successful delete: invalidate listener
	 * routing and queued references to THIS adapter before return. Do not stop
	 * shared UDP or release borrowed dependencies. New instance needs new binding.
	 */
	void (*detach)(void* user);
} Matter_Unsecured_Tx_Port_T;

typedef struct {
	uint64_t request; /* ID from this UDP instance, not an MRP/ACK request ID. */
	Matter_Exchange_Session_T session;
	const uint8_t* data;
	size_t size;
	Matter_Operation_Result_T outcome; /* Actual UDP result, no retry classification. */
} Matter_Unsecured_Tx_Result_T;

/* One allocation, one slot shared by already encoded data/ACK. No task, owner
 * lease, packet allocation, crypto, counters or timers. Copy port; borrow UDP,
 * sessions and user through delete. NULL on invalid args/OOM, no callbacks.
 * One application thread; serialize all calls and backend events. Construction
 * does not alter UDP's listener: application routes sent events to complete.
 */
Matter_Unsecured_Tx_T matter_unsecured_tx_new(Matter_Udp_T udp, Matter_Unsecured_T sessions,
	const Matter_Unsecured_Tx_Port_T* port);
/* Ready immediately after construction. PENDING accepts/pins immutable bytes
 * through successful take; every other result retains nothing, output unchanged.
 * BUSY while sending OR result unconsumed. Closed -> INVALID_STATE. Size ceiling
 * is UDP_MAX_PAYLOAD (LIMIT_REACHED); malformed/wrong-session envelope ->
 * INVALID_ARGUMENT. Unknown token -> INVALID_STATE. Must be standard unsecured
 * envelope: security flags 0, source/destination exactly as session role needs,
 * matching ephemeral ID and a nonempty remainder. Payload/protocol admission is
 * caller's duty. No encoding/counter changes, including on retransmission.
 * One route lookup per submission; accepted TX keeps its copied path even when
 * routing changes. Backend owns address/scope/whole IPv6 MTU validation.
 */
Matter_Result_T matter_unsecured_tx_send(Matter_Unsecured_Tx_T tx, Matter_Exchange_Session_T session,
	const uint8_t* data, size_t size, uint64_t* request);
/* Forward ONLY the matching UDP listener.sent event after backend released all
 * references. This function only records the outcome, no callback/free/unpin.
 * Can run inside sent; no other adapter API may run from UDP/host listeners.
 * Duplicate/unknown ID -> INVALID_STATE, invalid result/zero ID -> INVALID_ARGUMENT.
 * Application must route events by live binding + UDP request, never send raw
 * backend events here or route another UDP instance's numerically equal ID.
 */
Matter_Result_T matter_unsecured_tx_complete(Matter_Unsecured_Tx_T tx, uint64_t request,
	Matter_Operation_Result_T outcome);
/* Outside all UDP/host callbacks: one terminal result, releases adapter pin and
 * byte borrow. PENDING while I/O outstanding, INVALID_STATE when empty. Errors
 * leave output/ownership intact. Caller keeps any independent MRP byte/session
 * pins until MRP finishes; consuming this result does not release those pins.
 * SUCCEEDED means local transport success, not peer receipt; FAILED/CANCELLED
 * remain raw outcomes for the upper layer's explicit policy.
 */
Matter_Result_T matter_unsecured_tx_take(Matter_Unsecured_Tx_T tx, Matter_Unsecured_Tx_Result_T* result);
/* Irreversible, idempotent: PENDING until complete AND take, then OK. No UDP
 * stop/cancel or force-free. Close only after dependent ACK/MRP submissions
 * drain. A separate service shutdown may stop UDP and deliver its actual result.
 */
Matter_Result_T matter_unsecured_tx_close(Matter_Unsecured_Tx_T tx);
/* NULL OK; requires closed + empty, including unused adapters. Calls detach
 * before free. No restart. Dependencies outlive delete, stale pointers invalid.
 * All APIs reject reentry during route/backend-send/detach as BUSY. Pointers
 * and output storage valid/disjoint for calls. No hidden event queue.
 */
Matter_Result_T matter_unsecured_tx_delete(Matter_Unsecured_Tx_T tx);

#ifdef __cplusplus
}
#endif
#endif
