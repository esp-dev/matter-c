#ifndef MATTER_RETRANSMISSION_SENDER_H_INCLUDED
#define MATTER_RETRANSMISSION_SENDER_H_INCLUDED 1

#include "../ports/matter_retransmission_port.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Matter_Retransmission_Sender* Matter_Retransmission_Sender_T;

/* Own ledger + sender (two calloc, no callbacks on failure, no per-message
 * allocation). No owner lease, task, OS types, encryption or UDP adapter. User
 * keeps dependencies operational until stop returns OK; resolver has its own
 * lifecycle beyond this sender. max_attempts is ledger's 1..5 profile.
 */
Matter_Retransmission_Sender_T matter_retransmission_sender_new(uint8_t max_attempts,
	const Matter_Retransmission_Port_T* port);
/* stop OK required, including on never-used instance. NULL OK. Detach then free. */
Matter_Result_T matter_retransmission_sender_delete(Matter_Retransmission_Sender_T sender);
/* Ledger add contract plus port retain/release. Copies metadata, borrows pinned
 * bytes. On failure output unchanged, no finished event, all acquired pins undone.
 * No actual send until process. Counter history/R/headers remain caller's duty.
 */
Matter_Result_T matter_retransmission_sender_add(Matter_Retransmission_Sender_T sender,
	const Matter_Exchange_Info_T* key, uint32_t counter, const uint8_t* data, size_t size, uint64_t* id);
/* At most one submission and CAPACITY terminal notifications. Process drives
 * timeout even while TX pending. Monotonic now; no inline completion accepted.
 * PENDING = TX accepted/in-flight or stop awaits records; WOULD_BLOCK = no due
 * work/preflight blocked/retryable rejection (consult deadline, don't spin).
 * OFFLINE/PORT_ERROR preserves preflight work; fatal send produces FAILED via
 * finished/release. OK after stop means records drained, not resolver shutdown.
 */
Matter_Result_T matter_retransmission_sender_process(Matter_Retransmission_Sender_T sender, uint64_t now_ms);
/* Actual backend outcome after all TX references discarded. Invalid result/ID
 * leaves ownership intact. No notification/release until a subsequent process.
 * Backend cancellation without application abort is RETRYABLE or FATAL according
 * to backend policy, never an invented SENT result.
 */
Matter_Result_T matter_retransmission_sender_complete(Matter_Retransmission_Sender_T sender,
	uint64_t request, Matter_Retransmission_Tx_Result_T result);
/* Adapters for RX process_ack/exchange_drained. ACK does not release pins inline.
 * Drained stays PENDING until process has delivered result and released its pin.
 * Gate closing exchanges via retain; drained itself does not close admission.
 */
Matter_Result_T matter_retransmission_sender_ack(Matter_Retransmission_Sender_T sender,
	const Matter_Exchange_Info_T* key, uint32_t counter);
Matter_Result_T matter_retransmission_sender_drained(Matter_Retransmission_Sender_T sender,
	const Matter_Exchange_Info_T* key);
Matter_Result_T matter_retransmission_sender_deadline(Matter_Retransmission_Sender_T sender, uint64_t* deadline_ms);
/* Explicit abort; pending TX invokes port cancel once then waits for real
 * completion. Queued message waits only for process notification/release.
 */
Matter_Result_T matter_retransmission_sender_cancel(Matter_Retransmission_Sender_T sender, uint64_t message_id);
/* Terminal per-session abort. Gates belong to the caller's retain/route hooks.
 * Cancels matching pending backend TX once; PENDING through actual completion
 * and process notification/release. Other sessions continue normally. */
Matter_Result_T matter_retransmission_sender_cancel_session(Matter_Retransmission_Sender_T sender,
	Matter_Exchange_Session_T session);
/* Irreversible graceful stop: no new adds, retries continue, no implicit cancel.
 * Drive process and terminal completions until OK. No restart or force-free.
 */
Matter_Result_T matter_retransmission_sender_stop(Matter_Retransmission_Sender_T sender);

#ifdef __cplusplus
}
#endif
#endif
