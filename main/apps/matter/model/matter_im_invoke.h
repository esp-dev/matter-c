#ifndef MATTER_IM_INVOKE_H_INCLUDED
#define MATTER_IM_INVOKE_H_INCLUDED 1
#include "matter_im_read.h" /* Shared IM revision, privileges, limits and transport types. */
#include "../codec/matter_tlv_writer.h"
#ifdef __cplusplus
extern "C" {
#endif

enum { MATTER_IM_UNSUPPORTED_COMMAND=0x81, MATTER_IM_INVALID_COMMAND=0x85, MATTER_IM_TIMEOUT=0x94,
	MATTER_IM_CONSTRAINT_ERROR=0x87, MATTER_IM_NEEDS_TIMED_INTERACTION=0xc6,
	MATTER_IM_TIMED_REQUEST_MISMATCH=0xc9, MATTER_IM_INVALID_TRANSPORT_TYPE=0xd1,
	MATTER_IM_INVOKE_MAX_PATHS=1 };
typedef struct { uint16_t endpoint; uint32_t cluster, command; } Matter_Im_Command_Path_T;
typedef struct {
	Matter_Im_Privilege_T privilege;
	bool fabric_scoped, timed, large_message, response;
	uint32_t response_command;
	size_t response_capacity; /* If response: 2..1024, max complete anonymous TLV bytes. */
} Matter_Im_Command_T;
typedef struct { uint8_t status; bool has_cluster_status; uint8_t cluster_status; } Matter_Im_Command_Result_T;
typedef struct {
	void* user;
	/* Authenticated PASE or CASE binding. First Operate, then actual privilege.
	 * Return SUCCESS/UNSUPPORTED_ACCESS/ACCESS_RESTRICTED. Check revocation here. */
	uint8_t (*authorize)(void*, Matter_Exchange_Session_T, const Matter_Im_Command_Path_T*, Matter_Im_Privilege_T);
	/* No effects. SUCCESS or UNSUPPORTED_ENDPOINT/CLUSTER/COMMAND. */
	uint8_t (*describe)(void*, const Matter_Im_Command_Path_T*, Matter_Im_Command_T*);
	/* No effects. Validate cluster schema/ranges before invoke. Arguments are one
	 * anonymous STRUCTURE, including open/end; missing fields become empty struct.
	 * Return SUCCESS/INVALID_COMMAND/CONSTRAINT_ERROR/RESOURCE_EXHAUSTED/FAILURE. */
	uint8_t (*validate)(void*, const Matter_Im_Command_Path_T*, const uint8_t*, size_t);
	/* Exactly once per accepted transaction, after access/schema/capacity checks.
	 * Synchronous, bounded and nonblocking: no hardware waits. Arguments borrowed
	 * only during this call; no pointer retention. response=NULL for status-only
	 * commands, otherwise an initialized writer for provider to emit one COMPLETE
	 * anonymous STRUCTURE within declared response_capacity/depth 4. Check EVERY
	 * write result; encoding failure must return FAILURE/RESOURCE_EXHAUSTED.
	 * Handler validates/copies output, never invokes again on encoding/TX failure.
	 * SUCCESS with metadata.response emits CommandDataIB; other outcomes emit
	 * CommandStatusIB. Cluster status is allowed for status replies only.
	 * Callback owns command side effects: cancellation/lost response is NOT rollback.
	 * No pending/async result in this initial subset. All callbacks forbid reentry. */
	Matter_Im_Command_Result_T (*invoke)(void*, const Matter_Im_Command_Path_T*, const uint8_t*, size_t,
		Matter_Tlv_Writer_T* response);
} Matter_Im_Invoke_Port_T;
typedef Matter_Im_Read_Config_T Matter_Im_Invoke_Config_T;
typedef Matter_Im_Read_Message_T Matter_Im_Invoke_Message_T;
typedef struct Matter_Im_Invoke* Matter_Im_Invoke_T;
typedef enum { MATTER_IM_INVOKE_WAITING, MATTER_IM_INVOKE_OUTPUT, MATTER_IM_INVOKE_IN_FLIGHT,
	MATTER_IM_INVOKE_COMPLETE, MATTER_IM_INVOKE_FAILED, MATTER_IM_INVOKE_WAIT_INVOKE, MATTER_IM_INVOKE_PENDING } Matter_Im_Invoke_State_T;

/* Small owner allocation, copied config/port, borrowed user, owner thread only.
 * RX and normalized arguments allocate on demand (1024-byte ceiling). Command
 * bodies reserve the declared capacity; replies reserve a bounded envelope plus
 * that capacity before effects. No allocation during async poll or delivery.
 * One concrete unicast command on a fresh authenticated exchange, optionally
 * preceded by TimedRequest on this SAME handler/session/exchange.
 * Transport authenticates, excludes group sessions, deduplicates RX, and owns
 * ACK/MRP. MaxPathsPerInvoke=1; >1/empty/invalid paths -> INVALID_ACTION.
 * Timed flag must match the transaction; timed metadata requires a timed invoke.
 * TimedRequest Timeout is uint16 including zero. Window is [first send, end),
 * saturating at UINT64_MAX; retry/ACK never extends it. Late Invoke -> TIMEOUT.
 * Expired idle window stays available for a TIMEOUT reply until the absolute
 * config timeout ends the handler; no unsolicited timed-timeout message.
 * No wildcard/group, multi-command/chunked response or full ACL.
 * SuppressResponse suppresses status-only replies, not CommandDataIB or root
 * schema errors. CommandRef echoed when present. Final InvokeResponse opcode 9
 * has SuppressResponse=true, no MoreChunkedMessages (Core 10.7.10.2).
 * COMPLETE means reply delivered OR intentionally suppressed, not command success.
 */
Matter_Im_Invoke_T matter_im_invoke_new(const Matter_Im_Invoke_Port_T*, const Matter_Im_Invoke_Config_T*, uint64_t now_ms);
/* Optional async execution; old port/constructor remain source-compatible.
 * start runs once after the SAME access/schema/capacity checks. OK produces a
 * result immediately; PENDING requires a nonzero provider-owned token. poll is
 * called once per process, with a fresh writer; PENDING produces no response.
 * No callback may retain arguments/writer/handler pointers or reenter. The
 * provider copies needed input and owns backend work independently of handler.
 * cancel detaches the token synchronously on timeout, revocation, cancel/delete;
 * backend drain may continue in provider storage. It must never call this freed
 * handler. Late backend events route by generation, not by handler pointer.
 * Terminal poll consumes the token; side effects are never retried/rolled back
 * by IM. Owner services provider time/completions BEFORE invoke_process.
 */
typedef struct {
    Matter_Result_T (*start)(void*, const Matter_Im_Command_Path_T*, const uint8_t*, size_t,
        Matter_Tlv_Writer_T*, Matter_Im_Command_Result_T*, uint64_t* token);
    Matter_Result_T (*poll)(void*, uint64_t token, Matter_Tlv_Writer_T*, Matter_Im_Command_Result_T*);
    void (*cancel)(void*, uint64_t token);
} Matter_Im_Invoke_Async_Port_T;
Matter_Im_Invoke_T matter_im_invoke_new_async(const Matter_Im_Invoke_Port_T*,
    const Matter_Im_Invoke_Async_Port_T*, const Matter_Im_Invoke_Config_T*, uint64_t now_ms);
/* Optional authenticated fabric resolver using port.user. Rechecked on each
 * authorization, including async poll; identity cannot change within handler.
 * PASE constructor requires pase_commissionee=true (index may be 0); CASE
 * requires false and nonzero index. NULL async selects synchronous execution. */
Matter_Im_Invoke_T matter_im_invoke_new_fabric(const Matter_Im_Invoke_Port_T*,const Matter_Im_Invoke_Async_Port_T*,
    const Matter_Im_Read_Fabric_Port_T*,const Matter_Im_Invoke_Config_T*,uint64_t);
Matter_Im_Invoke_T matter_im_invoke_new_case(const Matter_Im_Invoke_Port_T*,const Matter_Im_Invoke_Async_Port_T*,
    const Matter_Im_Read_Fabric_Port_T*,const Matter_Im_Invoke_Config_T*,uint64_t);
/* Legacy untimed-only receive, preserved for existing callers. TimedRequest and
 * timed continuation require receive_at; never infer RX time from process. */
Matter_Result_T matter_im_invoke_receive(Matter_Im_Invoke_T, const Matter_Rx_Decision_T*);
/* Copy fresh RX, protocol 1/opcode 8 or initial 10, exact session/exchange/I=1.
 * received_ms is trusted monotonic application time at delivery of accepted RX,
 * not wire data. It must not precede the last process/sent_at/confirm/receive_at.
 * After SUCCESS first send, one Invoke may queue before its ACK+drain. process
 * waits for confirm, using original RX time to test the timed window. Absolute
 * config timeout still bounds the entire transaction, including queued work.
 * A second TimedRequest or unsupported Write continuation gives INVALID_ACTION.
 * No parsing/effects in RX. Allocation failure returns LIMIT_REACHED without
 * accepting/queueing the request. Duplicates must be stopped by existing RX/MRP.
 * Same logical operation in a NEW exchange is not covered by deduplication. */
Matter_Result_T matter_im_invoke_receive_at(Matter_Im_Invoke_T, const Matter_Rx_Decision_T*, uint64_t received_ms);
/* Monotonic absolute timeout; work/effects only here. No retries of callbacks. */
Matter_Result_T matter_im_invoke_process(Matter_Im_Invoke_T, uint64_t now_ms);
/* Borrow until sent/cancel/delete/timeout. COPY to secure/MRP-owned bytes first. */
Matter_Result_T matter_im_invoke_output(Matter_Im_Invoke_T, Matter_Im_Invoke_Message_T*);
/* Final response sent, no pending command/TimedRequest continuation. Retained
 * output and confirm/cancel/delete obligations are unchanged. */
bool matter_im_invoke_awaiting_delivery(Matter_Im_Invoke_T);
Matter_Result_T matter_im_invoke_sent(Matter_Im_Invoke_T);
/* Required for the initial timed SUCCESS; also usable for all other outputs.
 * Call once at FIRST actual transport submission, after copying output to the
 * MRP-owned buffer. Merely enqueueing in MRP is NOT a send. WOULD_BLOCK/offline
 * must not start the window. Backend must notify before dispatching peer RX;
 * asynchronous backends use their first-send event, not ACK or later retry.
 * Legacy sent rejects the initial timed SUCCESS instead of using a stale clock.
 * All time values share one monotonic application clock. */
Matter_Result_T matter_im_invoke_sent_at(Matter_Im_Invoke_T, uint64_t sent_ms);
/* MRP ACK AND transport drain; timed SUCCESS -> WAIT_INVOKE, final -> COMPLETE.
 * failed TX -> cancel. No parsing/callbacks or window renewal in confirm. */
Matter_Result_T matter_im_invoke_confirm(Matter_Im_Invoke_T, uint64_t now_ms);
Matter_Result_T matter_im_invoke_cancel(Matter_Im_Invoke_T);
Matter_Im_Invoke_State_T matter_im_invoke_state(Matter_Im_Invoke_T);
/* Invalidate routing, cancel/drain transport before deleting its binding. */
Matter_Result_T matter_im_invoke_delete(Matter_Im_Invoke_T);
#ifdef __cplusplus
}
#endif
#endif
