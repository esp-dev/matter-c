#ifndef MATTER_RX_POLICY_H_INCLUDED
#define MATTER_RX_POLICY_H_INCLUDED 1

#include "matter_exchange.h"
#include "../codec/matter_protocol_header.h"

#ifdef __cplusplus
extern "C" {
#endif

enum { MATTER_RX_PROTOCOL_CAPACITY = 8 };
typedef struct Matter_Rx_Policy* Matter_Rx_Policy_T;

typedef enum {
	MATTER_RX_DROP = 0,
	MATTER_RX_EXISTING,
	MATTER_RX_NEW_RESPONDER
} Matter_Rx_Action_T;

typedef enum {
	MATTER_RX_ACK_NONE = 0,
	MATTER_RX_ACK_PENDING,   /* Record counter, flush previous ACK if needed, arm timer. */
	MATTER_RX_ACK_IMMEDIATE  /* Duplicate or rejected unsolicited R=1. */
} Matter_Rx_Ack_T;

typedef struct {
	Matter_Exchange_Session_T session;
	uint32_t message_counter;
	bool duplicate;
	const uint8_t* data; /* Decrypted protocol header + application payload, NOT a full packet. */
	size_t size;
} Matter_Rx_Input_T;

typedef struct {
	Matter_Rx_Action_T action;
	Matter_Rx_Ack_T ack;
	bool process_ack; /* A flag: future MRP must process header.acknowledged_message_counter. */
	bool standalone_ack; /* Standard vendor/protocol 0, opcode 0x10: never upper-layer delivery. */
	Matter_Exchange_Handle_T exchange; /* Zero if no existing exchange matched. */
	Matter_Protocol_Header_T header;
	Matter_Exchange_Session_T session;
	uint32_t message_counter;
	const uint8_t* payload;
	size_t payload_size;
} Matter_Rx_Decision_T;

typedef struct {
	void* user;
	/* Exactly once for a successful policy evaluation, including DROP.
	 * This is a DECISION observer, not a protocol/application message handler.
	 * Descriptor and payload borrowed only during this synchronous callback.
	 * No mutations of policy, exchange table or owner; return normally, no blocking.
	 * Policy mutations/reentry return BUSY; queries of table/owner are allowed.
	 */
	void (*decided)(void* user, const Matter_Rx_Decision_T* decision);
} Matter_Rx_Listener_T;

/* One fixed registry allocation. Borrows table and listener.user, copies
 * listener. Delete policy BEFORE table; caller invalidates routing first.
 * No own task, lease, timers, queued events or start/stop: table readiness gates
 * receive. Registrations survive table stop/start. All calls owner thread only.
 */
Matter_Rx_Policy_T matter_rx_policy_new(Matter_Exchange_Table_T table, const Matter_Rx_Listener_T* listener);
Matter_Result_T matter_rx_policy_delete(Matter_Rx_Policy_T policy); /* NULL OK. */
/* Exact vendor/protocol pairs. Standard vendor 0 accepts only IDs 0..4 (Core
 * Table 14); ID 4 is for isolated testing. Vendor namespaces are caller-approved.
 * No automatic registrations. Duplicate -> BUSY, full -> LIMIT_REACHED.
 * Unregister missing pair -> INVALID_STATE. Allowed between evaluations, even
 * with table stopped. These register support, not per-exchange protocol handlers.
 */
Matter_Result_T matter_rx_policy_register(Matter_Rx_Policy_T policy, uint16_t vendor, uint16_t protocol);
Matter_Result_T matter_rx_policy_unregister(Matter_Rx_Policy_T policy, uint16_t vendor, uint16_t protocol);

/* UDP UNICAST only. Caller already validated message header, resolved the
 * session, authenticated/decrypted secured traffic and determined duplicates.
 * Does NOT infer trust from bytes, session token, IP or duplicate flag.
 * Uses existing parser + exchange matching without creating/releasing entries.
 * Bad arguments/truncated protocol header or standalone ACK without A/with
 * nonempty payload -> INVALID_ARGUMENT, no callback.
 * Stopped/stopping table -> INVALID_STATE, no callback; BUSY on reentry.
 * OK means decision delivered, NOT packet delivered/ACK processed/sent.
 *
 * Unknown protocol or duplicate never goes to upper layers. Nonduplicate
 * registered existing -> EXISTING, unmatched I=1 -> NEW_RESPONDER, else DROP.
 * A closing existing exchange -> DROP, but preserves its handle/process_ack;
 * R requests IMMEDIATE ACK, including for a nonduplicate. Do not discard these
 * control obligations just because application admission has closed.
 * Standalone ACK -> DROP for upper layers. R produces explicit ACK intent even
 * for drops; unmatched R=1 drops need a future ephemeral exchange. A produces
 * process_ack, including acknowledged counter 0. Nothing is executed here.
 * Executor must apply MRP before delivery and bind handlers to exchange handles;
 * revalidate registry/table/session if it defers work. No decisions retained.
 */
Matter_Result_T matter_rx_policy_receive(Matter_Rx_Policy_T policy, const Matter_Rx_Input_T* input);

#ifdef __cplusplus
}
#endif
#endif
