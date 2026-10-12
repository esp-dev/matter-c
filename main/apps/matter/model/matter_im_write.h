#ifndef MATTER_IM_WRITE_H_INCLUDED
#define MATTER_IM_WRITE_H_INCLUDED 1
#include "matter_im_invoke.h" /* Shared IM status, privilege, config and message types. */
#ifdef __cplusplus
extern "C" {
#endif

enum { MATTER_IM_UNSUPPORTED_WRITE=0x88, MATTER_IM_INVALID_DATA_TYPE=0x8d,
	MATTER_IM_DATA_VERSION_MISMATCH=0x92, MATTER_IM_WRITE_MAX_CHUNKS=64 };
typedef enum { MATTER_IM_LIST_REPLACE, MATTER_IM_LIST_ADD } Matter_Im_List_Change_T;
typedef struct {
	Matter_Im_Privilege_T privilege;
	bool timed, fabric_scoped, list;
} Matter_Im_Write_Attribute_T;
typedef struct { uint8_t status; bool has_cluster_status; uint8_t cluster_status; } Matter_Im_Write_Result_T;
typedef struct {
	void* user;
	/* Authenticated PASE or CASE peer. View before lookup, then actual privilege.
	 * SUCCESS/UNSUPPORTED_ACCESS/ACCESS_RESTRICTED; check revocation each time. */
	uint8_t (*authorize)(void*, Matter_Exchange_Session_T, const Matter_Im_Path_T*, Matter_Im_Privilege_T);
	/* No effects: SUCCESS or UNSUPPORTED_ENDPOINT/CLUSTER/ATTRIBUTE/WRITE. */
	uint8_t (*describe)(void*, const Matter_Im_Path_T*, Matter_Im_Write_Attribute_T*);
	/* Required even if this request has no DataVersion. Queried only when present,
	 * after authorization; SUCCESS/FAILURE, current cluster instance version. */
	Matter_Result_T (*version)(void*, const Matter_Im_Path_T*, uint32_t*);
	/* No effects. One normalized anonymous TLV value (scalar, UTF8/bytes or
	 * STRUCTURE), depth <=4, <=1024 bytes. Validate complete cluster schema and
	 * ranges; SUCCESS/INVALID_DATA_TYPE/CONSTRAINT_ERROR/RESOURCE_EXHAUSTED/FAILURE. */
	uint8_t (*validate)(void*, const Matter_Im_Path_T*, const uint8_t*, size_t);
	/* Exactly once per accepted transaction, after access/version/schema/preflight.
	 * Same borrowed value as validate. On SUCCESS update cluster DataVersion when
	 * data changes; make value/version publication coherent for subsequent Read.
	 * Serialize model mutations through the owner thread for the ENTIRE process
	 * call (version check through write), including other application writers.
	 * On failure the provider owns atomicity/rollback; handler never retries write.
	 * All callbacks synchronous, bounded, nonblocking; no reentry or retained pointers.
	 * Cancellation or lost response never rolls back an already completed write. */
	Matter_Im_Write_Result_T (*write)(void*, const Matter_Im_Path_T*, const uint8_t*, size_t);
	/* Optional pair, both or neither. Ordinary lists: REPLACE receives anonymous
	 * empty ARRAY; ADD receives one complete anonymous item, depth <=4/1024 B.
	 * CASE constructor also permits nonempty ACL/DefaultOTAProviders REPLACE. No effects
	 * in validate_list: check item schema AND resulting list size/constraints.
	 * Same status contract as validate. No pointer retention or reentry. */
	uint8_t (*validate_list)(void*, const Matter_Im_Path_T*, Matter_Im_List_Change_T, const uint8_t*, size_t);
	/* One effect per accepted IB, never per retry. Commit each successful operation
	 * and update DataVersion coherently. Serialize model mutations for all process.
	 * Earlier successful operations remain on error/cancel/timeout/CloseSession.
	 * No list transaction handle, staging, commit callback or automatic rollback;
	 * do not retain resources requiring an end callback. Atomicity of ONE operation
	 * and failure effects belong to the provider, including its allocation failures. */
	Matter_Im_Write_Result_T (*write_list)(void*, const Matter_Im_Path_T*, Matter_Im_List_Change_T, const uint8_t*, size_t);
} Matter_Im_Write_Port_T;
typedef Matter_Im_Read_Config_T Matter_Im_Write_Config_T;
typedef Matter_Im_Read_Message_T Matter_Im_Write_Message_T;
typedef struct Matter_Im_Write* Matter_Im_Write_T;
typedef enum { MATTER_IM_WRITE_WAITING, MATTER_IM_WRITE_OUTPUT, MATTER_IM_WRITE_IN_FLIGHT,
	MATTER_IM_WRITE_COMPLETE, MATTER_IM_WRITE_FAILED, MATTER_IM_WRITE_WAIT_WRITE,
	MATTER_IM_WRITE_WAIT_CHUNK } Matter_Im_Write_State_T;

/* One heap allocation; config/port copied, user borrowed. Owner thread, no task,
 * transport ownership or hardware dependency. One concrete unicast/PASE attribute,
 * optionally TimedRequest then Write on this same session/exchange.
 * Whole input validated before callbacks. Optional list port supports empty ARRAY
 * REPLACE and ADD with ListIndex=null, same path across IBs/chunks,
 * at most 64 Write messages. Each IB compares optional DataVersion to CURRENT
 * provider version; omission does not inherit the previous condition. Earlier
 * operations may have changed the version. No wildcard, Node, compression, group,
 * numeric ListIndex (INVALID_ACTION). Up to four list IBs for the same path are
 * parsed even without list callbacks: View access and describe run first, so a
 * read-only attribute returns UNSUPPORTED_WRITE per IB, including PASE/chunks.
 * Writable profiles retain the limits below: ordinary nonempty REPLACE and
 * multi-IB writes outside CASE OTA return per-path INVALID_ACTION without effects.
 * Missing list callbacks return UNSUPPORTED_WRITE for a writable list; scalar
 * values never fall through to a list callback.
 * MoreChunkedMessages requires an untimed list write and SuppressResponse=false.
 * This is a bounded subset, not full IM conformance.
 * SuppressResponse defaults false and suppresses WriteResponse, including errors;
 * root schema/time errors still produce StatusResponse. COMPLETE is delivery or
 * suppression, not proof of a successful write. Duplicates filtered by RX/MRP;
 * a new exchange/restart is not covered by this at-most-once transaction contract. */
Matter_Im_Write_T matter_im_write_new(const Matter_Im_Write_Port_T*, const Matter_Im_Write_Config_T*, uint64_t now_ms);
/* CASE constructor: authenticated nonzero fabric resolver rechecked for every
 * authorization/chunk, using port.user. Requires pase_commissionee=false.
 * Also accepts nonempty REPLACE for AccessControl/ACL (Core 10.6.4.3) and OTA/DefaultOTAProviders.
 * CASE ACL and OTA/DefaultOTAProviders also accept up to four list IBs for one concrete
 * path in a message (CHIP empty REPLACE + ADD). All TLV/path shapes and maximum
 * response capacity checked before effects; fabric/version rechecked per IB.
 * For consecutive ACL ADDs in the same message, a successful preceding write
 * retains the grant for that path; clearing ACL does not reject its own append.
 * This grant never crosses messages; other cases recheck access per IB.
 * One status per IB; earlier successes remain after a later failure. Other
 * writable profiles remain single-IB. Provider owns atomicity of one IB; self-revocation
 * may deny later chunks. */
Matter_Im_Write_T matter_im_write_new_case(const Matter_Im_Write_Port_T*,const Matter_Im_Read_Fabric_Port_T*,
    const Matter_Im_Write_Config_T*,uint64_t now_ms);
/* Copy fresh authenticated RX opcode 6 or initial 10, exact session/exchange/I=1.
 * received_ms is trusted monotonic delivery time, never supplied by the peer.
 * One continuation may queue after SUCCESS/intermediate WriteResponse send,
 * before MRP ACK/drain; process waits for confirm before reusing output. No parsing
 * or effects here. RX time determines timeout, process delay does not extend it.
 * Wrong continuation opcode 8/10 produces INVALID_ACTION. Oversize is refused
 * without ownership; caller handles error/close. All timestamps share one clock. */
Matter_Result_T matter_im_write_receive_at(Matter_Im_Write_T, const Matter_Rx_Decision_T*, uint64_t received_ms);
/* Absolute config timeout bounds the whole transaction, including queued work.
 * Expired idle timed window remains available to return TIMEOUT until that bound.
 * Work and effects occur only here. Caller cancels/drains transport on failure. */
Matter_Result_T matter_im_write_process(Matter_Im_Write_T, uint64_t now_ms);
/* Borrow until sent/cancel/delete/timeout; COPY into secure/MRP-owned bytes first.
 * WriteResponse opcode 7 / StatusResponse opcode 1; same exchange, reliable TX. */
Matter_Result_T matter_im_write_output(Matter_Im_Write_T, Matter_Im_Write_Message_T*);
/* Final response sent, no TimedRequest/chunk continuation. Retained output and
 * confirm/cancel/delete obligations are unchanged. */
bool matter_im_write_awaiting_delivery(Matter_Im_Write_T);
/* FIRST actual transport submission, not enqueue, WOULD_BLOCK, ACK or retry.
 * Backend must notify before dispatching peer RX. Timed window [send,send+Timeout)
 * saturates at UINT64_MAX; zero is empty. Retries never call this again. */
Matter_Result_T matter_im_write_sent_at(Matter_Im_Write_T, uint64_t sent_ms);
/* MRP ACK AND drain. Initial SUCCESS -> WAIT_WRITE; intermediate -> WAIT_CHUNK;
 * final reply -> COMPLETE. All chunks share one absolute config deadline.
 * No effects here. Failed TX -> cancel; late confirm cannot revive a failure. */
Matter_Result_T matter_im_write_confirm(Matter_Im_Write_T, uint64_t now_ms);
Matter_Result_T matter_im_write_cancel(Matter_Im_Write_T);
Matter_Im_Write_State_T matter_im_write_state(Matter_Im_Write_T);
/* Invalidate routing and cancel/drain transport before deleting its binding. */
Matter_Result_T matter_im_write_delete(Matter_Im_Write_T);
#ifdef __cplusplus
}
#endif
#endif
