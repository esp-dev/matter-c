#ifndef MATTER_RX_H_INCLUDED
#define MATTER_RX_H_INCLUDED 1

#include "matter_rx_policy.h"
#include "matter_ack_sender.h"

#ifdef __cplusplus
extern "C" {
#endif

enum { MATTER_RX_MAX_PLAINTEXT = 1232 };
typedef struct Matter_Rx* Matter_Rx_T;

typedef struct {
	void* user;
	Matter_Ack_Port_T ack; /* Plaintext session TX, NOT raw UDP; existing port contract. */
	/* Pin one authenticated/resolved session incarnation AND its routing. OK
	 * acquires one reference; every other result acquires none. Must keep it
	 * usable until matching release, including while closing. Identity and
	 * credentials stay unchanged; discovery may update the SAME peer's address.
	 * Each accepted TX must keep its own route snapshot through completion.
	 * No callbacks from construction. A queued RX, each exchange and ephemeral
	 * own separate pins (queue pin may be transferred to ephemeral).
	 */
	Matter_Result_T (*retain)(void* user, Matter_Exchange_Session_T session);
	void (*release)(void* user, Matter_Exchange_Session_T session);
	/* Required handoff to future retransmission table, including counter 0 and
	 * unknown/duplicate messages. OK = processed once; WOULD_BLOCK/OFFLINE/
	 * PORT_ERROR = no effects, retry. Other results normalize to PORT_ERROR.
	 * Never report OK while silently ignoring an outstanding retransmission.
	 */
	Matter_Result_T (*process_ack)(void* user, const Matter_Exchange_Info_T* key, uint32_t counter);
	/* Required, idempotent probe/request for retransmission drain. OK = none,
	 * PENDING = keep exchange; anything else -> PORT_ERROR. ACK drain is handled
	 * internally and both barriers are checked, even when one is pending.
	 */
	Matter_Result_T (*exchange_drained)(void* user, const Matter_Exchange_Info_T* key);
	/* Borrowed descriptor/payload only during call, after MRP ACK admission.
	 * Generic dispatch hook; application binds protocol handlers to the handle.
	 * No delivery on duplicates, standalone ACK, closing or unsupported protocol.
	 */
	void (*deliver)(void* user, const Matter_Rx_Decision_T* decision);
	/* Called ONLY after RX, ACKs, ephemeral, exchanges and their table drain.
	 * Request/poll stop of this service's session/UDP dependencies; idempotent,
	 * nonblocking: OK fully drained, PENDING retry, others PORT_ERROR. Invalidate
	 * RX routing before OK. Do not stop/delete the shared owner in this callback.
	 */
	Matter_Result_T (*stop_dependencies)(void* user);
} Matter_Rx_Port_T;

/* Owns policy, exchange table, ACK ledger/sender and one heap RX packet. Five
 * bounded allocations, none per message. Borrows owner and copies port; user
 * lifetimes extend through delete (sender detach). All callbacks synchronous,
 * nonblocking, on owner thread; no inline mutations of executor/owner. Executor
 * reentry -> BUSY. No worker, OS types, security, deduplication or retransmission
 * implementation. Only already authenticated UDP unicast plaintext is accepted.
 * initial_id has exchange_new's random-seed contract. Failed new has no callbacks.
 */
Matter_Rx_T matter_rx_new(Matter_T owner, uint16_t initial_id, const Matter_Rx_Port_T* port);
/* One-shot lifecycle: start with RUNNING owner; stop, process to OK, delete.
 * No restart after stop. Delete also allowed if never started. NULL delete OK.
 * Call stop here BEFORE raw owner/UDP stop. Their cancel-all semantics are
 * unchanged; premature owner stop makes process fail INVALID_STATE, not free
 * undrained objects. The application may stop its owner after our stop is done.
 */
Matter_Result_T matter_rx_start(Matter_Rx_T rx);
Matter_Result_T matter_rx_stop(Matter_Rx_T rx);
Matter_Result_T matter_rx_delete(Matter_Rx_T rx);
Matter_Result_T matter_rx_register(Matter_Rx_T rx, uint16_t vendor, uint16_t protocol);
Matter_Result_T matter_rx_unregister(Matter_Rx_T rx, uint16_t vendor, uint16_t protocol);
Matter_Result_T matter_rx_initiate(Matter_Rx_T rx, Matter_Exchange_Session_T session,
	Matter_Exchange_Handle_T* handle);
Matter_Result_T matter_rx_get(Matter_Rx_T rx, Matter_Exchange_Handle_T handle, Matter_Exchange_Info_T* info);
/* PENDING/error closes admission irreversibly; process automatically retries
 * close, retaining metadata/pin until both barriers permit removal. Old handle
 * then returns INVALID_STATE. Deferred input on this key also holds the barrier.
 */
Matter_Result_T matter_rx_close(Matter_Rx_T rx, Matter_Exchange_Handle_T handle);
/* Terminal removal of one session. FIRST gate its route/retain and cancel its
 * MRP records, then call this (idempotent). Drops queued RX and unsent ACKs;
 * active ACK and MRP keep exchanges/pins until actual completion and drain.
 * Drive process/completions and repeat until OK. Does not stop shared RX/UDP
 * or retain permanent tombstones: the application must never reuse the token.
 */
Matter_Result_T matter_rx_retire_session(Matter_Rx_T rx, Matter_Exchange_Session_T session);

/* OK means COPIED and session pinned, not delivered. Caller can immediately
 * reuse bytes. Full slot -> WOULD_BLOCK without ownership/effects. Oversize ->
 * LIMIT_REACHED. Rejected input is caller's responsibility, never silently queued.
 * received_ms is original monotonic reception time, possibly older than the
 * last process time when the caller retries a previously rejected input.
 * Accepted input is retried internally; do not resubmit it. Registry/exchange
 * admission is re-evaluated on retries, A is committed only once. Stop keeps
 * control RX open until drain finishes, but never delivers application data.
 */
Matter_Result_T matter_rx_receive(Matter_Rx_T rx, const Matter_Rx_Input_T* input, uint64_t received_ms);
/* At most one queued RX and one ACK send per call. now >= earlier process and
 * queued reception. Pending/backpressure retains input and original deadline;
 * offline/error retains obligations for explicit retry. OK while running may
 * still have future ACK timers: keep driving process. While stopping, OK means
 * all dependencies drained. Continuous peer traffic may postpone graceful stop.
 */
Matter_Result_T matter_rx_process(Matter_Rx_T rx, uint64_t now_ms);
/* Forward actual deferred outcome after backend discards TX references. IDs
 * belong to this live binding; backend must suppress stale events after detach.
 */
Matter_Result_T matter_rx_complete(Matter_Rx_T rx, uint64_t request, Matter_Operation_Result_T result);

#ifdef __cplusplus
}
#endif
#endif
