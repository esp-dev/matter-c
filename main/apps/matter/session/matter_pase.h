#ifndef MATTER_PASE_H_INCLUDED
#define MATTER_PASE_H_INCLUDED 1
#include "../crypto/matter_spake2p.h"

#ifdef __cplusplus
extern "C" {
#endif
enum { MATTER_PASE_MAX_PAYLOAD = 1024 };
typedef struct Matter_Pase* Matter_Pase_T;
typedef struct {
	uint32_t idle_ms, active_ms;
	uint16_t active_threshold_ms;
} Matter_Pase_Intervals_T;
typedef struct {
	bool responder, has_parameters;
	uint16_t local_session_id;
	uint32_t pin, iterations;
	uint8_t salt[32], salt_size, w0[32], L[65];
	uint32_t timeout_ms;
} Matter_Pase_Config_T;
typedef struct {
	uint8_t opcode;
	const uint8_t* data;
	size_t size;
} Matter_Pase_Message_T;
typedef struct {
	uint16_t local_session_id, peer_session_id;
	uint8_t send_key[16], receive_key[16], attestation_challenge[16];
	Matter_Pase_Intervals_T peer_intervals;
} Matter_Pase_Keys_T;
typedef enum { MATTER_PASE_WAITING, MATTER_PASE_OUTPUT, MATTER_PASE_COMPLETE, MATTER_PASE_FAILED } Matter_Pase_State_T;

/* One attempt, heap context, copied config/port, borrowed crypto.user. Serialized
 * owner thread, no tasks/I/O. Caller reserves a unique nonzero local session ID
 * across PASE/CASE and keeps the commissioning window and backend alive.
 * Responder supplies matching w0/L, salt 16..32 and iterations 1000..100000;
 * initiator supplies valid setup PIN and (only if has_parameters) salt/iterations.
 * This profile sends default MRP intervals (500/300/4000), no optional local
 * session parameters. Received peer intervals are available for MRP immediately.
 * timeout_ms: nonzero application policy, absolute attempt deadline from now_ms,
 * no extension by traffic/retries. NULL invalid config/port/OOM. Clear input copies.
 */
Matter_Pase_T matter_pase_new(const Matter_Crypto_Port_T* port, const Matter_Pase_Config_T* config, uint64_t now_ms);
/* Optional owner notification, installed once before first receive/process.
 * Called exactly once for protocol/peer failure or attempt timeout, never for
 * explicit cancel/delete. token identifies the owner's commissioning window.
 * user must outlive this attempt; callback may only update owner state, never
 * reenter/delete this engine or its dispatcher. No callback on successful PASE. */
Matter_Result_T matter_pase_on_failure(Matter_Pase_T,void* user,uint64_t token,
    void (*failed)(void*,uint64_t));
/* Only copy one payload; no parsing/crypto. Call from accepted RX delivery AFTER
 * binding same unsecured session/exchange, protocol/vendor 0, peer I flag, R=1,
 * and duplicate filtering. Caller must reject unrelated exchanges before here.
 * Backpressure preserves state; after acceptance caller must schedule process.
 */
Matter_Result_T matter_pase_receive(Matter_Pase_T pase, uint8_t opcode, const uint8_t* data, size_t size);
/* Explicit potentially expensive PBKDF/ECP work OUTSIDE RX/poll callback. now_ms
 * monotonic, including while output waits for transport. Refresh process time
 * after expensive work before sending/handoff if strict deadline enforcement is
 * required; there is no clock read or preemption inside crypto. PORT_ERROR means terminal
 * failure; a failure StatusReport may still be available via output(). */
Matter_Result_T matter_pase_process(Matter_Pase_T pase, uint64_t now_ms);
/* Borrowed immutable payload until sent/cancel/delete or process failure;
 * repeated output is safe.
 * Copy/encode into retained MRP storage, enqueue reliably, THEN call sent().
 * Rejected submissions leave output pending. MRP owns immutable packet retries;
 * never call receive/process again for a duplicate or re-run PAKE on retry.
 */
Matter_Result_T matter_pase_output(Matter_Pase_T pase, Matter_Pase_Message_T* message);
Matter_Result_T matter_pase_sent(Matter_Pase_T pase);
/* Responder final success only: invoke after the success StatusReport was reliably
 * acknowledged, not after local UDP send. Other transport failures call cancel.
 * No retained transport references to pase; application must invalidate routing
 * and drain its own packet buffers before deleting/replacing its binding. */
Matter_Result_T matter_pase_confirm_delivery(Matter_Pase_T pase, uint64_t now_ms);
Matter_Result_T matter_pase_keys(Matter_Pase_T pase, Matter_Pase_Keys_T* keys);
/* Atomic one-shot transfer after COMPLETE. Clears internal keys/challenge;
 * subsequent keys()/take_keys() fail, state remains COMPLETE. Prepare all
 * fallible allocation/RNG work BEFORE taking. keys() is inspection only: do
 * not activate independent counter states from its copies. Clear all copies. */
Matter_Result_T matter_pase_take_keys(Matter_Pase_T pase, Matter_Pase_Keys_T* keys);
Matter_Result_T matter_pase_peer_intervals(Matter_Pase_T pase, Matter_Pase_Intervals_T* intervals);
Matter_Pase_State_T matter_pase_state(Matter_Pase_T pase);
Matter_Result_T matter_pase_cancel(Matter_Pase_T pase);
Matter_Result_T matter_pase_delete(Matter_Pase_T pase); /* NULL OK; clear entire context. */
/* No secure traffic activation here: take_keys() hands off to the secure
 * session/counters/CCM. Caller clears exported keys. Preflight errors and
 * BUSY preserve outputs/state. All spans disjoint, no concurrent API calls. */
#ifdef __cplusplus
}
#endif
#endif
