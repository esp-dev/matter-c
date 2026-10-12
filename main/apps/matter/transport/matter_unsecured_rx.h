#ifndef MATTER_UNSECURED_RX_H_INCLUDED
#define MATTER_UNSECURED_RX_H_INCLUDED 1

#include "matter_rx.h"
#include "matter_unsecured.h"
#include "../ports/matter_udp_port.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Matter_Unsecured_Rx* Matter_Unsecured_Rx_T;
typedef struct {
	Matter_Message_Header_T message;
	Matter_Protocol_Header_T protocol;
	const Matter_Udp_Datagram_T* datagram;
	const uint8_t* payload;
	size_t payload_size;
	Matter_Exchange_Session_T session; /* Existing token, or 0 before creation. */
} Matter_Unsecured_Rx_Message_T;
typedef struct {
	void* user;
	/* Required policy BEFORE context creation: validate unsecured protocol/opcode,
	 * payload and source/path. OK admits this packet; allow_create defaults false.
	 * Known contexts do not need allow_create. No default commissioning allowlist.
	 * OK/INVALID_ARGUMENT/INVALID_STATE/WOULD_BLOCK/OFFLINE preserved, other errors
	 * -> PORT_ERROR. Failure creates nothing and changes no reception history.
	 */
	Matter_Result_T (*admit)(void* user, const Matter_Unsecured_Rx_Message_T* message, bool* allow_create);
	/* Called only after RX copied bytes AND reception committed, with ingress pin
	 * still held. Save routing by token here before processing RX. No error return:
	 * reserve any required application resources in advance. Not application
	 * delivery or authentication; RX may later drop/handle only control fields.
	 */
	void (*accepted)(void* user, const Matter_Unsecured_Rx_Message_T* message, bool duplicate);
	/* Synchronous routing barrier at delete: invalidate queued references to this
	 * adapter. Does not stop borrowed RX/session table or invalidate their pins.
	 */
	void (*detach)(void* user);
} Matter_Unsecured_Rx_Port_T;

/* One calloc, no packet buffer/task/owner lease, no per-receive allocations.
 * Copies required port; borrows RX, table and user through delete. Ready at once;
 * caller starts RX independently. NULL on invalid args/OOM, no callbacks.
 * One owner thread: serialize all calls and the shared session table. Call
 * outside UDP/host listeners. All callbacks (including RX retain) nonblocking,
 * no retained input pointers or inline mutation of adapter/dependencies/packet,
 * except RX retain/release managing their OWN independent session pins.
 * No callback may alter reception, remove/create sessions or process RX inline.
 * Adapter reentry -> BUSY. accepted may update application routing cache only.
 */
Matter_Unsecured_Rx_T matter_unsecured_rx_new(Matter_Rx_T rx, Matter_Unsecured_T sessions,
	const Matter_Unsecured_Rx_Port_T* port);
/* Complete IPv6 unicast datagram only. Ports and both addresses must be nonzero,
 * nonmulticast; backend owns full MTU, scopes, mapped-address and truncation checks.
 * Size > UDP_MAX_PAYLOAD -> LIMIT_REACHED. Syntax/profile errors -> INVALID_ARGUMENT.
 * Existing codecs preserve ignored reserved bits and skip bounded MX/SX fields.
 * Secure/group/privacy/control envelopes are outside this profile.
 *
 * OK = copied by RX, not delivered. No input retained after return. Short ingress
 * pin spans classify/receive/commit; RX owns its independent pin/copy. Rejected
 * input does not commit or call accepted. A newly created context is removed
 * after downstream rejection (its token remains consumed); existing ones stay.
 * Once admitted, don't resubmit for RX's internal retries. received_ms is the
 * original time, with RX's monotonic scheduling contract. No process/send here.
 */
Matter_Result_T matter_unsecured_rx_receive(Matter_Unsecured_Rx_T ingress,
	const Matter_Udp_Datagram_T* datagram, uint64_t received_ms);
/* Irreversible close disables NEW CONTEXTS only, retaining lookup/control RX.
 * Application separately closes/stops RX/exchanges to suppress new delivery.
 * stop disables all ingress, synchronous because adapter retains no RX work.
 * Neither operation stops or drains borrowed RX. Both idempotent; no restart.
 */
Matter_Result_T matter_unsecured_rx_close(Matter_Unsecured_Rx_T ingress);
Matter_Result_T matter_unsecured_rx_stop(Matter_Unsecured_Rx_T ingress);
/* NULL OK; otherwise stop required, even if never used. detach before free.
 * RX may still own accepted copies; drain it before removing sessions/owner.
 * No calls on freed pointers; new instance requires a fresh routing binding.
 */
Matter_Result_T matter_unsecured_rx_delete(Matter_Unsecured_Rx_T ingress);

#ifdef __cplusplus
}
#endif
#endif
