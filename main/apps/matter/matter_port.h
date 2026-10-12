#ifndef MATTER_PORT_H_INCLUDED
#define MATTER_PORT_H_INCLUDED 1

#include <stdint.h>

typedef enum {
	MATTER_STATE_INVALID = 0,
	MATTER_STATE_STOPPED,
	MATTER_STATE_RUNNING,
	MATTER_STATE_STOPPING
} Matter_State_T;

/* Copied by matter_new; user remains borrowed until matter_delete succeeds.
 * state_changed is optional, synchronous on the owner's thread, and called
 * only after a state change. No notifications during construction/destruction.
 * The callback must return normally and should not block. It may query state;
 * mutations of the notifying instance return MATTER_BUSY. Defer those
 * operations in the application until the outer API call has returned.
 */
typedef struct {
	void* user;
	void (*state_changed)(void* user, Matter_State_T state);
} Matter_Port_T;

typedef uint64_t Matter_Operation_Id_T;

typedef enum {
	MATTER_OPERATION_SUCCEEDED = 0,
	MATTER_OPERATION_FAILED,
	MATTER_OPERATION_CANCELLED
} Matter_Operation_Result_T;

/* One descriptor per active operation in the bounded pool. Copied by operation_begin;
 * user is borrowed until operation_complete returns. Both callbacks run on
 * the owner's thread, must return normally and must not block. All mutations
 * of the same instance from either callback return BUSY; getters are allowed.
 *
 * cancel is required and requests cancellation at most once. It must arrange
 * a later operation_complete, NEVER complete inline. Cancellation may race
 * success/failure; the backend reports the actual terminal result. A failed
 * cancellation request does not authorize freeing the context.
 *
 * completed is optional; called once for an accepted terminal result, before
 * a pending stop transitions to STOPPED after the LAST operation completes.
 * It is not called on begin rejection.
 * Operation-specific data/resources remain the caller/backend's responsibility.
 */
typedef struct {
	void* user;
	void (*cancel)(void* user, Matter_Operation_Id_T id);
	void (*completed)(void* user, Matter_Operation_Id_T id, Matter_Operation_Result_T result);
} Matter_Operation_Port_T;

#endif
