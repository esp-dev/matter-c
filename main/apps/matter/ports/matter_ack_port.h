#ifndef MATTER_ACK_PORT_H_INCLUDED
#define MATTER_ACK_PORT_H_INCLUDED 1

#include "../transport/matter_exchange.h"
#include <stddef.h>

/* Plaintext protocol header + empty application payload, NOT a UDP datagram.
 * The session adapter resolves this exact session incarnation, assigns the
 * OUTBOUND message counter/header, authenticates/encrypts when required and
 * sends using the session's routing/credentials. counter in the ACK header is
 * the RECEIVED message counter; it is not the outbound message counter.
 */
typedef struct {
	Matter_Exchange_Info_T exchange;
	const uint8_t* data;
	size_t size;
} Matter_Ack_Message_T;

/* Copied descriptor, user borrowed through sender deletion. Same contract on
 * fake/x86/device: nonblocking callbacks on application owner thread, no task
 * or OS types. Do not mutate sender OR its ACK table inline from callbacks.
 *
 * send: OK accepts one whole message, borrows descriptor AND immutable bytes
 * until a deferred sender_complete, even for synchronous local send success.
 * WOULD_BLOCK/OFFLINE/PORT_ERROR reject: no sent bytes, references or completion.
 * Other return codes are contract errors, treated as PORT_ERROR rejection.
 * Before complete, discard ALL retained references. SUCCEEDED means actual
 * local send, not acceptance of this callback and not peer receipt. Every
 * accepted send owes one terminal result, even after offline/cancellation.
 * No inline completion: BUSY means not accepted, defer and retry later.
 *
 * detach: nonblocking synchronous barrier, called once on successful deletion
 * after drain. Invalidate all routing/events to this sender before return.
 * New sender needs a fresh binding identity; IDs/pointers can repeat across
 * recreation. Never deliver events to a freed sender. Do not stop shared I/O.
 * No cancel callback: graceful stop flushes ACKs and waits for accepted sends.
 * Cancellation initiated by the backend reports its ACTUAL terminal outcome.
 */
typedef struct {
	void* user;
	Matter_Result_T (*send)(void* user, uint64_t request, const Matter_Ack_Message_T* message);
	void (*detach)(void* user);
} Matter_Ack_Port_T;

#endif
