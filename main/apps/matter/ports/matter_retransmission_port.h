#ifndef MATTER_RETRANSMISSION_PORT_H_INCLUDED
#define MATTER_RETRANSMISSION_PORT_H_INCLUDED 1

#include "../transport/matter_retransmission.h"

typedef enum {
	MATTER_RETRANSMISSION_SUBMITTED = 0,
	MATTER_RETRANSMISSION_REJECTED_RETRYABLE,
	MATTER_RETRANSMISSION_REJECTED_FATAL
} Matter_Retransmission_Submission_T;

/* Copied port, user borrowed through delete. Owner thread, nonblocking, no
 * inline sender/dependency/owner mutation; sender reentry -> BUSY. Only send
 * retains the supplied descriptor; all other pointers borrowed for the call.
 */
typedef struct {
	void* user;
	/* Pin bytes (immutable), exchange, concrete session incarnation/credentials
	 * and routing facility. OK acquires one pin, any error none. Re-resolution
	 * may update the address of the SAME peer; never replace credentials/identity.
	 * Reject closing/retired exchanges here. A failed add may retain then release
	 * without finished. Successful add gets finished then matching release.
	 */
	Matter_Result_T (*retain)(void* user, const Matter_Exchange_Info_T* key, const uint8_t* data, size_t size);
	void (*release)(void* user, const Matter_Exchange_Info_T* key, const uint8_t* data, size_t size);
	/* Local scheduling gate BEFORE RNG/prepare/send: OK may attempt, WOULD_BLOCK
	 * yields to occupied TX or pending ACK. No reservation, no retained refs.
	 * Application/backend must service ACKs first and fairly arbitrate shared TX.
	 * A later send rejection still counts as an MRP attempt per ledger contract.
	 */
	Matter_Result_T (*ready)(void* user);
	/* Current peer mode/intervals, including completed discovery updates. Caller
	 * knows first-message exchange policy and validates peer parameters; next_attempt
	 * is 1..5. OK writes ALL fields. Error writes ignored, no send/budget change.
	 */
	Matter_Result_T (*parameters)(void* user, const Matter_Retransmission_Message_T* message,
		uint8_t next_attempt, Matter_Retransmission_Parameters_T* parameters);
	/* OK writes fresh uniform 16-bit entropy. Error -> no prepare or send, no
	 * deterministic fallback. Never return OK without producing a sample.
	 */
	Matter_Result_T (*random)(void* user, uint16_t* sample);
	/* First retry: initiate/coalesce operational re-resolution for this peer.
	 * OK = request accepted, not resolution completed; sender proceeds in parallel
	 * using current cache. Every peer triggers it, including ICDs. Backend maps
	 * session to discovery identity and must honor the ICD requirement. Failure
	 * has no retained work and prevents this retry; a later process retries start.
	 * Resolver owns separate session pins/lifecycle and updates its cache; it MUST
	 * NOT retain message/sender pointers or call sender asynchronously. Its drain
	 * belongs to the service's stop_dependencies, not to sender stop.
	 */
	Matter_Result_T (*rediscover)(void* user, const Matter_Retransmission_Message_T* message);
	/* Already fully encoded/encrypted message: do not change bytes/counter or
	 * credentials. Resolve latest peer address at submission; accepted TX owns
	 * its route snapshot. SUBMITTED borrows request descriptor AND bytes until
	 * deferred complete even for immediate local success. Rejection: no bytes
	 * sent, no refs/events. Invalid enum -> fatal rejection. RETRYABLE rejection
	 * consumes an attempt/timer, distinct from ready returning WOULD_BLOCK.
	 */
	Matter_Retransmission_Submission_T (*send)(void* user, const Matter_Retransmission_Request_T* request);
	/* Request cancellation once, not completion. Backend later drops ALL TX
	 * references and completes with actual classified SENT/RETRYABLE/FATAL.
	 * Explicit sender cancel already records CANCELLED; a prior ACK wins instead.
	 */
	void (*cancel)(void* user, uint64_t request);
	/* Exactly once per accepted message, only from process, with bytes still
	 * pinned. Copy needed result metadata; do not retain pointers or free/mutate
	 * bytes here. release immediately follows; owner may reclaim storage there
	 * or after process returns. No finished callback on failed add/construction.
	 */
	void (*finished)(void* user, const Matter_Retransmission_Result_T* result);
	/* Synchronous routing barrier on successful delete after full drain. Drop
	 * queued events/references to this sender; new sender needs new binding ID.
	 * Never use request IDs alone across recreation or stop shared networking.
	 */
	void (*detach)(void* user);
} Matter_Retransmission_Port_T;

/* retain/ready/parameters/random/rediscover return OK/WOULD_BLOCK/OFFLINE/
 * PORT_ERROR; other results normalize to PORT_ERROR. These preflight errors do
 * not consume attempts; application schedules retry or explicit cancel. Port
 * implementations must arrange finite retries/failure policy, not busy-spin.
 */
#endif
