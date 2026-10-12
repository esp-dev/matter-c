#ifndef MATTER_COUNTER_H_INCLUDED
#define MATTER_COUNTER_H_INCLUDED 1

#include "../matter.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	MATTER_COUNTER_UNSECURED = 1,
	MATTER_COUNTER_SECURE_UNICAST
} Matter_Counter_Mode_T;

/* One caller-owned state per NODE for all unsecured peers/transports, or per
 * concrete secure session/key. No global storage, allocation, OS or key handles.
 * Start with {0}; fields are read-only to callers. Do not copy/fork/reset a live
 * state, even after exhaustion: creating another secure state needs NEW keys.
 * All accesses on the owner thread, serialized with outbound preparation.
 */
typedef struct {
	uint32_t next;
	Matter_Counter_Mode_T mode;
	bool initialized, exhausted, busy;
} Matter_Counter_T;

/* Synchronous nonblocking Crypto_DRBG(28) provider. OK MUST write a fresh
 * uniform value in 0..0x0fffffff. No pointer retention or inline mutation of
 * state/dependencies. Failure acquires no work; no fallback. May return
 * WOULD_BLOCK/OFFLINE/PORT_ERROR; other errors and out-of-range samples become
 * PORT_ERROR. This module cannot assess entropy quality or authenticate RNG.
 */
typedef Matter_Result_T (*Matter_Counter_Random_T)(void* user, uint32_t* random28);

typedef struct {
	uint32_t counter;
	bool expires_session;
} Matter_Counter_Value_T;

/* Fresh zeroed state only. First counter = Crypto_DRBG(28)+1 (1..2^28).
 * Does not retain callback/user. Failure preserves state; caller may retry.
 * Reseeding active/exhausted state -> INVALID_STATE without calling RNG.
 * Reentry from RNG into either API -> BUSY.
 */
Matter_Result_T matter_counter_init(Matter_Counter_T* state, Matter_Counter_Mode_T mode,
	Matter_Counter_Random_T random, void* user);

/* Irreversibly allocate ONE counter for a NEW message, including standalone
 * ACK. Returns current value, advances next. No rollback if encoding, queueing
 * or sending fails. MRP retries MUST reuse encoded bytes/counter, never take.
 * Unsecured UINT32_MAX advances to zero. Secure UINT32_MAX is returned once
 * with expires_session=true; next take -> LIMIT_REACHED (no nonce reuse).
 * Owner must immediately forbid new messages on that key, but keep credentials
 * pinned for final preparation/TX/retries until actual drain; this module does
 * not destroy keys, cancel I/O or renegotiate. The final value remains valid
 * even though the counter state is now exhausted (next is saturated).
 * Failures preserve state/output. Pointers valid and disjoint for the call.
 */
Matter_Result_T matter_counter_take(Matter_Counter_T* state, Matter_Counter_Value_T* value);

#ifdef __cplusplus
}
#endif
#endif
