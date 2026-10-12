#ifndef MATTER_H_INCLUDED
#define MATTER_H_INCLUDED 1

#include "matter_port.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Matter* Matter_T;

/* Bounded in-context storage, allocated once by matter_new. No per-operation
 * allocation. This is a host-stage resource limit, not a Matter session limit.
 */
enum { MATTER_OPERATION_CAPACITY = 4 };

typedef enum {
	MATTER_OK = 0,
	MATTER_INVALID_ARGUMENT,
	MATTER_INVALID_STATE,
	MATTER_BUSY,
	MATTER_PENDING,
	MATTER_LIMIT_REACHED,
	MATTER_PORT_ERROR,
	MATTER_WOULD_BLOCK,
	MATTER_OFFLINE
} Matter_Result_T;

/* Each instance is owned and driven by one application thread; no concurrent
 * calls, internal task or scheduler. Different instances share no core state.
 * This initial module implements lifecycle only, not Matter networking.
 */

/* Allocate a STOPPED context with libc. NULL port means no callbacks.
 * Returns NULL on allocation failure, without invoking callbacks.
 */
Matter_T matter_new(const Matter_Port_T* port);

/* Idempotent; notify only on transitions. NULL -> INVALID_ARGUMENT.
 * Reentrant mutation of the notifying instance -> BUSY, even if idempotent.
 * With outstanding operations, stop enters STOPPING, requests cancel once per
 * active operation, and returns PENDING until ALL are drained. Repeated stop
 * is PENDING without another cancel; start while STOPPING -> INVALID_STATE.
 * Cancellation order is unspecified; callbacks must defer terminal delivery.
 * With no operation, stop remains synchronous (OK), as in M03.
 */
Matter_Result_T matter_start(Matter_T matter);
Matter_Result_T matter_stop(Matter_T matter);

/* NULL is harmless (OK). RUNNING/STOPPING -> INVALID_STATE; notifying -> BUSY.
 * Success frees the STOPPED context without callbacks. The caller must discard
 * all copies of the handle; non-NULL handles must always refer to live contexts.
 */
Matter_Result_T matter_delete(Matter_T matter);

/* Allowed during callbacks. NULL -> INVALID; RUNNING is a lifecycle state,
 * not evidence of network readiness, commissioning or protocol conformance.
 */
Matter_State_T matter_get_state(Matter_T matter);

/* Register backend work BEFORE submitting it. RUNNING required;
 * MATTER_OPERATION_CAPACITY slots per instance (BUSY if full), no additional
 * allocation. port, port->cancel,
 * and id must be non-NULL. On success write a nonzero id; otherwise leave *id
 * unchanged. IDs increase across restart; exhaustion -> LIMIT_REACHED, no wrap.
 * A submission failure must still call operation_complete(FAILED), after
 * removing backend references. This function does not submit work itself.
 */
Matter_Result_T matter_operation_begin(Matter_T matter, const Matter_Operation_Port_T* port,
	Matter_Operation_Id_T* id);

/* Request cancellation; OK means requested, NOT drained. Repeating it is OK.
 * id == 0 -> INVALID_ARGUMENT; unknown/completed id -> INVALID_STATE.
 */
Matter_Result_T matter_operation_cancel(Matter_T matter, Matter_Operation_Id_T id);

/* Owner thread only, after begin/cancel has returned. Before calling, backend
 * MUST discard all retained context references and drain/invalidate queued
 * callbacks for this operation. Complete exactly once, including on cancel or
 * backend failure. No force-free on timeout: without drain, stop stays pending.
 * Late/duplicate IDs on a LIVE context -> INVALID_STATE. IDs are scoped to a
 * context and do not make a freed pointer safe. Never call with a stale handle.
 * NULL context, zero id or invalid result -> INVALID_ARGUMENT. Reentry -> BUSY:
 * completion was not accepted and must be retried after the outer call returns.
 * Accepted completion releases its slot and notifies completed, then STOPPED
 * only if a stop was pending and this was the last active operation. Completion
 * order is arbitrary; released slots may be reused while RUNNING with fresh IDs.
 */
Matter_Result_T matter_operation_complete(Matter_T matter, Matter_Operation_Id_T id,
	Matter_Operation_Result_T result);

#ifdef __cplusplus
}
#endif

#endif
