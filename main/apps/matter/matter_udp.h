#ifndef MATTER_UDP_H_INCLUDED
#define MATTER_UDP_H_INCLUDED 1

#include "ports/matter_udp_port.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Matter_Udp* Matter_Udp_T;

/* Copied descriptor, user borrowed through delete. Callbacks are optional,
 * synchronous, nonblocking, owner thread only; do not mutate module/owner inline.
 * received borrows descriptor/bytes only for this callback. sent reports one
 * accepted send, releases its input bytes before callback, including on cancel.
 * No event for rejected send. These callbacks may query is_active.
 */
typedef struct {
	void* user;
	void (*received)(void* user, const Matter_Udp_Datagram_T* datagram);
	void (*sent)(void* user, uint64_t request, Matter_Operation_Result_T result);
} Matter_Udp_Listener_T;

/* Copies descriptors, borrows owner/user. All five port callbacks required.
 * NULL listener allowed. One allocation, NULL on invalid args/OOM, no callbacks.
 * Delete module BEFORE owner even if inactive. No per-send allocation/queue.
 * All calls owner thread; mutations during module callbacks return BUSY.
 */
Matter_Udp_T matter_udp_new(Matter_T owner, const Matter_Udp_Port_T* port,
	const Matter_Udp_Listener_T* listener);
Matter_Result_T matter_udp_delete(Matter_Udp_T udp); /* NULL OK; active rejected. */

/* RUNNING owner required. Reserves ONE pool slot for RX + any pending TX through
 * drain. activate returns OK/WOULD_BLOCK/OFFLINE/PORT_ERROR; failures release
 * lease so caller may retry explicitly. Repeated active start OK, stopping
 * start INVALID_STATE. No retries/timers/worker inside this module.
 */
Matter_Result_T matter_udp_start(Matter_Udp_T udp);
/* Request stop; active -> PENDING, inactive -> OK. Owner stop also requests it. */
Matter_Result_T matter_udp_stop(Matter_Udp_T udp);
/* Drive shutdown even while owner STOPPING. At most one backend callback or
 * lease release per call: deactivate RX, cancel pending TX, await complete,
 * release lease. PENDING until inactive; no timeout force-free. Active running
 * returns OK (does not poll sockets); application drives backend events itself.
 */
Matter_Result_T matter_udp_process(Matter_Udp_T udp);

/* One pending send/module; BUSY if occupied. Descriptor copied; bytes stay
 * immutable/valid until sent callback begins (or complete returns without one).
 * size 1..MAX_PAYLOAD, nonzero local/peer ports; backend validates routing.
 * Accepted -> PENDING and nonzero *request; all rejections leave *request alone
 * and release bytes before return. WOULD_BLOCK/OFFLINE are explicit rejections.
 * request IDs monotonic across restart, no wrap; exhaustion LIMIT_REACHED.
 * Output request must be disjoint from descriptors and payload.
 */
Matter_Result_T matter_udp_send(Matter_Udp_T udp, const Matter_Udp_Datagram_T* datagram,
	uint64_t* request);
/* Backend terminal TX event, after dropping references, deferred from send/cancel.
 * Stale/duplicate request INVALID_STATE; BUSY means retry after outer call.
 */
Matter_Result_T matter_udp_complete(Matter_Udp_T udp, uint64_t request,
	Matter_Operation_Result_T result);
/* Complete borrowed RX datagram for current activate epoch, not ciphertext
 * parsing/authentication. Empty -> INVALID_ARGUMENT, oversize/truncated ->
 * LIMIT_REACHED. Stale epoch, stopped module or stopping owner -> INVALID_STATE.
 * Backend must enforce whole IPv6 packet limit (see port header).
 */
Matter_Result_T matter_udp_receive(Matter_Udp_T udp, Matter_Operation_Id_T epoch,
	const Matter_Udp_Datagram_T* datagram, bool truncated);
bool matter_udp_is_active(Matter_Udp_T udp);

#ifdef __cplusplus
}
#endif
#endif
