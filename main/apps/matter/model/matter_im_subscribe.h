#ifndef MATTER_IM_SUBSCRIBE_H_INCLUDED
#define MATTER_IM_SUBSCRIBE_H_INCLUDED 1
#include "matter_im_read.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    Matter_Im_Read_Port_T attributes; /* Same authorization/describe/read/enumerate/version and value contract as Read. */
    /* Owner registry, invoked after schema validation, outside RX. Terminate all
     * other pending/active subscriptions of THIS authenticated subscriber if !keep.
     * Allocate publisher-wide unique live ID; SUCCESS, RESOURCE_EXHAUSTED or FAILURE.
     * On error retain no reservation. ID zero is legal. Identity/grant and fabric
     * ownership belong to registry, never derive them from peer-supplied paths.
     * Callback may cancel OTHER subscriptions, never this one. */
    uint8_t (*reserve)(void*, Matter_Exchange_Session_T, bool keep, uint32_t* id);
    /* Exactly once for a successful reservation, on terminal failure/cancel/delete.
     * No transport ownership here. May run inside process; no reentry or retention. */
    void (*release)(void*, uint32_t id);
} Matter_Im_Subscribe_Port_T;
typedef Matter_Im_Read_Config_T Matter_Im_Subscribe_Config_T;
typedef Matter_Im_Read_Message_T Matter_Im_Subscribe_Message_T;
typedef struct Matter_Im_Subscribe* Matter_Im_Subscribe_T;
/* Attribute-only subscriptions can name every standard cluster in the host
 * profile without conflating selector capacity with per-chunk work/output. */
#define MATTER_IM_SUB_MAX_ATTRIBUTE_PATHS 32
typedef enum { MATTER_IM_SUB_WAITING, MATTER_IM_SUB_OUTPUT, MATTER_IM_SUB_IN_FLIGHT,
    MATTER_IM_SUB_WAIT_STATUS, MATTER_IM_SUB_IDLE, MATTER_IM_SUB_NEED_EXCHANGE,
    MATTER_IM_SUB_FAILED, MATTER_IM_SUB_BUILD_REPORT, MATTER_IM_SUB_EXPANDING,
    MATTER_IM_SUB_COLLECTING } Matter_Im_Subscribe_State_T;
/* One heap context, owner-thread scheduling; no task/socket/timer/global registry.
 * Legacy constructor requires trusted PASE commissionee config/grant as Read.
 * Up to MATTER_IM_SUB_MAX_ATTRIBUTE_PATHS attribute-only selectors (wildcards via
 * enumerate), MATTER_IM_READ_MAX_RESULTS expanded candidates,
 * 16 DataVersionFilters (priming only), all Read value types, plus
 * optional EventPaths/EventMin via bind_events (9 requested attribute
 * and event paths combined, before deduplication). Whole attribute
 * structures and events chunk between IBs; lists use ARRAY REPLACE followed by
 * whole-element ADD (ListIndex=null), preserving one snapshot/DataVersion.
 * Text/bytes are copied immediately, validated and never split between messages.
 * Wildcard expansion and capture yield after at most 8 candidates each per
 * process; concrete-only capture keeps its single-call budget of 9. Candidates
 * include overlapping selectors, before access/version filtering. No truncation.
 * Owner keeps topology stable until initial capture completes. Only error-free
 * existent paths activate (including version-filtered paths); no re-expansion
 * later. Wildcard unreadable/denied initial paths are omitted, concrete errors
 * reported. Event wildcards use the optional event enumerator (Read contract):
 * up to 120 event candidates, 8 enumeration/collection steps per process and
 * at most 120 path rechecks per chunk. Denied wildcard events are omitted and
 * deactivated; surviving paths continue. Loss of the final active path ends
 * after the empty update is acknowledged. Concrete revocation still terminates.
 * No Node/ListIndex selectors or nonzero provisional wildcard flags; no claims of full IM minima. reserve/release share attributes.user.
 * Config timeout bounds each exchange, not the lifetime of an active subscription.
 * output_capacity is an upper bound (8..1024). A lazy 16 KiB snapshot arena
 * holds encoded spans/containers (each <=4096 B, depth4); optional Events snapshot on heap.
 * Snapshots reused between transactions, released by delete; no per-chunk alloc.
 * Max chosen = requested ceiling (1 second when ceiling=0, within publisher limit).
 * An attribute-only update whose values are all unchanged returns to IDLE without
 * output until the maximum interval; its last-report/activity clocks are retained.
 * The owner should process at the returned deadline. A late wakeup requests the
 * due heartbeat, not immediate cancellation; exchange admission/delivery remain
 * bounded by timeout_ms. Peer rejection/timeout still terminates the subscription.
 * Failed subscriptions never resume. Caller cancels/drains transport on failure.
 */
Matter_Im_Subscribe_T matter_im_subscribe_new(const Matter_Im_Subscribe_Port_T*, const Matter_Im_Subscribe_Config_T*, uint64_t now_ms);
/* CASE variant requires pase_commissionee=false and live fabric resolver, sharing
 * attributes.user. Resolve before reserve and every report (including heartbeat);
 * reject zero/255, revoked identity or a change of fabric on an existing handler.
 * Bind attribute callbacks to the SAME authenticated session/fabric (Root CASE
 * Read port is suitable). Owner registry scopes keep=false to this subscriber's
 * authenticated fabric/node, owns ID and cancels on fabric/session removal.
 * Resolver/ports are copied; their borrowed context outlives the handler. */
Matter_Im_Subscribe_T matter_im_subscribe_new_case(const Matter_Im_Subscribe_Port_T*,const Matter_Im_Read_Fabric_Port_T*,
    const Matter_Im_Subscribe_Config_T*,uint64_t now_ms);
/* Optional events metadata/log binding, before the first receive, copied port,
 * borrowed contexts. Same selector/ACL contract as Read Events. One node log
 * is shared by subscriptions, but each subscription has an independent cursor.
 * EventMin filters PRIME only; subsequent transactions deliver retained records
 * since the preceding successful snapshot watermark. Commit watermark only after
 * all chunks have both IM SUCCESS and MRP completion. New events during TX remain
 * for the next transaction. Sensitive events always match the accessing fabric,
 * including when FabricFiltered=false; authorization is rechecked per chunk. */
Matter_Result_T matter_im_subscribe_bind_events(Matter_Im_Subscribe_T,const Matter_Im_Read_Events_Port_T*);
Matter_Result_T matter_im_subscribe_bind_event_enumerator(Matter_Im_Subscribe_T,Matter_Im_Event_Enumerate_T);
/* Owner calls for newly queued events (may notify all subscriptions). Urgent paths
 * trigger a report after min interval; other events wait for an attribute report
 * or max heartbeat. The engine checks matching urgent paths/fabric independently;
 * duplicate paths OR their urgency. Do NOT use changed() solely because an event was queued.
 * Notification during TX survives for the next report. No callbacks/reentry. */
Matter_Result_T matter_im_subscribe_events_changed(Matter_Im_Subscribe_T);
/* Fresh authenticated, deduplicated RX only; copy, no callbacks/parsing.
 * Initially SubscribeRequest opcode3/I=1 on config exchange; then StatusResponse
 * opcode1 on bound exchange with opposite initiator role, including before MRP ACK.
 */
Matter_Result_T matter_im_subscribe_receive(Matter_Im_Subscribe_T, const Matter_Rx_Decision_T*);
Matter_Result_T matter_im_subscribe_process(Matter_Im_Subscribe_T, uint64_t now_ms);
/* Notify value changes, coalesced until min interval. Notification during output/
 * in-flight survives for the next report. Call outside provider callbacks and
 * serialize changes with process; no cross-thread atomicity implied. */
Matter_Result_T matter_im_subscribe_changed(Matter_Im_Subscribe_T);
/* NEED_EXCHANGE asks application to allocate a fresh local-initiator exchange on
 * SAME session, after draining/closing the previous exchange including ACK sender.
 * This subset requires a different wire exchange ID from the preceding report.
 * No allocation/TX here. On binding, snapshot & encode happen in next process.
 * Caller drives process before max interval; late polling/binding terminates. */
Matter_Result_T matter_im_subscribe_bind_report(Matter_Im_Subscribe_T, const Matter_Exchange_Info_T*, uint64_t now_ms);
/* Borrow immutable bytes; copy into secure/MRP-owned storage before first send.
 * Initial reports/reply use original responder exchange. Subsequent reports use
 * bound initiator exchange. ReportData has SubscriptionId, SuppressResponse=false;
 * unchanged max-interval heartbeat has empty AttributeReports and/or EventReports. */
Matter_Result_T matter_im_subscribe_output(Matter_Im_Subscribe_T, Matter_Im_Subscribe_Message_T*);
/* First actual send, not enqueue, retry or ACK. Report intervals anchored here;
 * SubscribeResponse first send activates publisher (still waits MRP drain).
 * Backend notifies before peer RX. All times one monotonic application clock. */
Matter_Result_T matter_im_subscribe_sent_at(Matter_Im_Subscribe_T, uint64_t now_ms);
/* MRP ACK AND drain, independent of IM SUCCESS. No parsing/attribute callbacks;
 * terminal errors may invoke the registry's release callback. */
Matter_Result_T matter_im_subscribe_confirm(Matter_Im_Subscribe_T, uint64_t now_ms);
/* Next required work/deadline. IDLE: dirty min / heartbeat max; active exchange:
 * its absolute timeout. Poll promptly for OUTPUT/NEED_EXCHANGE/queued status. */
Matter_Result_T matter_im_subscribe_deadline(Matter_Im_Subscribe_T, uint64_t*);
Matter_Result_T matter_im_subscribe_cancel(Matter_Im_Subscribe_T);
Matter_Im_Subscribe_State_T matter_im_subscribe_state(Matter_Im_Subscribe_T);
/* Invalidate routing and drain transport first. Also releases a live reservation. */
Matter_Result_T matter_im_subscribe_delete(Matter_Im_Subscribe_T);
#ifdef __cplusplus
}
#endif
#endif
