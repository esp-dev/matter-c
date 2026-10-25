#ifndef MATTER_RECEPTION_H_INCLUDED
#define MATTER_RECEPTION_H_INCLUDED 1

#include "../matter.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { MATTER_RECEPTION_WINDOW_SIZE = 32 };
typedef enum {
	MATTER_RECEPTION_UNSECURED = 1,
	MATTER_RECEPTION_SECURE_UNICAST,
	MATTER_RECEPTION_SECURE_GROUP
} Matter_Reception_Mode_T;

/* Caller-owned value, no pointers/allocations. Fields are read-only to callers;
 * initialize through reset/seed, not raw writes. One state per concrete peer/
 * session/key as required by Core 4.6.5; this module does not own that identity.
 * bit 0 represents max_counter - 1, bit 31 max_counter - 32 (modulo 2^32).
 */
typedef struct {
	uint32_t max_counter, bitmap;
	Matter_Reception_Mode_T mode;
	bool initialized;
} Matter_Reception_T;

/* Start a NEW peer/session state. First committed counter initializes it with
 * all history bits set (Core 4.6.5.4). Never reset a live secure session on an
 * old counter, timeout or authentication failure: that would admit replay.
 */
Matter_Result_T matter_reception_reset(Matter_Reception_T* state, Matter_Reception_Mode_T mode);
/* Initialize a known reception maximum and all-ones bitmap. This counter is
 * already considered received. Session establishment supplies the appropriate
 * initial maximum; seed itself neither authenticates nor synchronizes a peer.
 */
Matter_Result_T matter_reception_seed(Matter_Reception_T* state, Matter_Reception_Mode_T mode, uint32_t counter);
/* Read-only classification. False means new according to the selected counter
 * policy, NOT trusted. Secure unicast never rolls its maximum back; unsecured
 * permits reboot/rollback outside the modulo window. Secure group counters use
 * the forward half of the modulo-2^32 space and retain the same replay window.
 * Group peer/key states MUST NOT be recycled during the boot (Core 4.16.1).
 * Duplicates still need MRP A/R processing after required authentication.
 */
Matter_Result_T matter_reception_classify(const Matter_Reception_T* state, uint32_t counter, bool* duplicate);
/* Re-evaluates against CURRENT state and commits only a new counter; returns
 * the classification actually used. Duplicate leaves state unchanged. Caller
 * must validate the session and authenticate secured input BEFORE commit.
 *
 * Owner-thread only. For deferred RX: classify -> admission/copy -> commit as
 * one serialized sequence, no intervening state mutation (including callbacks).
 * Failed admission must not commit; queued RX retains its original duplicate
 * flag on internal retry. Do not reuse a cached classification after another
 * commit/reset/seed. No locking or asynchronous reservation is provided here.
 * All pointers/output storage disjoint, valid for call. Errors preserve state
 * and output. Zeroed state requires reset/seed before classify/commit.
 */
Matter_Result_T matter_reception_commit(Matter_Reception_T* state, uint32_t counter, bool* duplicate);

#ifdef __cplusplus
}
#endif
#endif
