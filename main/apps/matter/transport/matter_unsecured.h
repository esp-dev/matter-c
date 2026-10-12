#ifndef MATTER_UNSECURED_H_INCLUDED
#define MATTER_UNSECURED_H_INCLUDED 1

#include "matter_exchange.h"
#include "../codec/matter_message_header.h"

#ifdef __cplusplus
extern "C" {
#endif

enum { MATTER_UNSECURED_CAPACITY = 8, MATTER_UNSECURED_RANDOM_ATTEMPTS = 8 };
typedef struct Matter_Unsecured* Matter_Unsecured_T;
typedef struct {
	uint64_t ephemeral_node_id;
	uint16_t pins;
	bool initiator; /* LOCAL session role, independent of exchange I flag. */
} Matter_Unsecured_Info_T;

/* Synchronous, nonblocking fresh uniform 64-bit Crypto_DRBG sample. No retained
 * pointers or inline mutation of dependencies. OK writes sample; other results
 * acquire no work. WOULD_BLOCK/OFFLINE preserved, other errors -> PORT_ERROR.
 * Invalid Node IDs/collisions are rejection-sampled, at most RANDOM_ATTEMPTS.
 * Exhausting attempts -> LIMIT_REACHED, no fallback. Callback/user not retained.
 */
typedef Matter_Result_T (*Matter_Unsecured_Random_T)(void* user, uint64_t* sample);

/* One calloc with fixed slots, no allocation per session/message. Invalid range
 * (zero first or first > last) or OOM -> NULL. Owner-thread only, no owner lease,
 * task, OS types, routing, keys or outgoing counter. Caller owns lifetime.
 * Reserve first..last in the shared local session-token namespace; ranges of
 * all tables (including future secure sessions) used by one RX MUST be disjoint.
 * Tokens never wrap/reuse within a table. Before recreating with the same range,
 * destroy/drain all downstream tables and invalidate old events/routing.
 */
Matter_Unsecured_T matter_unsecured_new(Matter_Exchange_Session_T first, Matter_Exchange_Session_T last);
/* NULL OK. Nonempty table -> INVALID_STATE even with no pins; remove explicitly.
 * No force-free/eviction/automatic timeout. APIs on this table reject RNG reentry as BUSY.
 */
Matter_Result_T matter_unsecured_delete(Matter_Unsecured_T table);
Matter_Result_T matter_unsecured_initiate(Matter_Unsecured_T table,
	Matter_Unsecured_Random_T random, void* user, Matter_Exchange_Session_T* session);

/* Parsed message header only (codec already checked bounds/extensions). This
 * profile requires unsecured type/ID=0, P=C=0, exactly source OR destination
 * Node ID in Operational range 1..0xffffffefffffffff. Both/absent/group IDs
 * and invalid versions -> INVALID_ARGUMENT. Reserved unused bits are ignored.
 * Lookup by ephemeral ID as in Core 4.13.2.1, without changing existing role.
 * Unknown source may create responder only with allow_create; unknown dest
 * never creates. No match -> INVALID_STATE, full -> BUSY, exhausted -> LIMIT_REACHED.
 * Caller must check allowed unsecured protocol/opcode BEFORE allow_create and
 * enforce admission/delivery policy separately; OK is NOT authentication.
 * Does not pin or commit reception. Address is deliberately not an identity.
 */
Matter_Result_T matter_unsecured_resolve(Matter_Unsecured_T table,
	const Matter_Message_Header_T* header, bool allow_create, Matter_Exchange_Session_T* session);
Matter_Result_T matter_unsecured_get(Matter_Unsecured_T table,
	Matter_Exchange_Session_T session, Matter_Unsecured_Info_T* info);

/* Every accepted RX, live exchange, TX and resolver that uses the context must
 * own a pin until actual drain. Caller gates new application work during close,
 * while retaining control RX/ACK capability. No closing flag in this table.
 * Pin overflow (UINT16_MAX) -> LIMIT_REACHED, unpin at zero -> INVALID_STATE.
 * Remove with pins -> BUSY, otherwise erases context but never recycles token.
 */
Matter_Result_T matter_unsecured_pin(Matter_Unsecured_T table, Matter_Exchange_Session_T session);
Matter_Result_T matter_unsecured_unpin(Matter_Unsecured_T table, Matter_Exchange_Session_T session);
Matter_Result_T matter_unsecured_remove(Matter_Unsecured_T table, Matter_Exchange_Session_T session);

/* Requires a pin; uses production unsecured reception window. No reset/seed or
 * mutable state pointer exported. Serialize classify -> admission/copy -> commit
 * without intervening mutations; failed admission must not commit. Internal RX
 * retries keep original duplicate classification. Closing alone does not block
 * control RX. Pinning preserves lifetime, not exclusivity or peer authenticity.
 * All APIs: errors preserve outputs and entries (RNG may consume entropy).
 * Pointers must be valid/disjoint; NULL/zero token -> INVALID_ARGUMENT,
 * stale/unknown nonzero token -> INVALID_STATE. No calls on freed tables.
 */
Matter_Result_T matter_unsecured_classify(Matter_Unsecured_T table,
	Matter_Exchange_Session_T session, uint32_t counter, bool* duplicate);
Matter_Result_T matter_unsecured_commit(Matter_Unsecured_T table,
	Matter_Exchange_Session_T session, uint32_t counter, bool* duplicate);

#ifdef __cplusplus
}
#endif
#endif
