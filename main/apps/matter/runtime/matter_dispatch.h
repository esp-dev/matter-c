#ifndef MATTER_DISPATCH_H
#define MATTER_DISPATCH_H 1
#include "../clusters/matter_root.h"
#include "../session/matter_case.h"
#include "../matter_udp.h"
#include "../ports/matter_resolver_port.h"
#include "../model/matter_im_client.h"
#include "../transport/matter_bdx.h"
/* Host composition of existing engines, one application owner. No socket,
 * thread or clock. Ports/root/UDP outlive delete. Receive/sent only copy events;
 * process performs protocol work outside UDP callbacks. All storage is owned.
 * RX queue lends delivery bytes through synchronous dispatch; TX plaintext
 * stays independent of queued/held RX. The borrowed view ends before TX work.
 * Recursive process/stop/delete and outgoing start/take during process return
 * BUSY without effects; received/sent may still enqueue their separate events.
 * Bounded host profile (matter_host_limits.h): 3 CASE sessions/fabric, one PASE,
 * configurable subscriptions/fabric, one Read/fabric, global one Invoke/Write.
 * Root CapabilityMinima.subscriptions is the single source of that budget.
 * new validates Core's range and the build's shared transport capacity, then
 * allocates the derived transaction table once. It never moves live callback
 * contexts; IM handlers still allocate on demand. Delete releases the table
 * after drain. Delivery/replacement/rejection/handshake slots stay reserved.
 * Eight unsecured routes. Tokens and wire IDs never wrap/reuse per lifetime.
 * On pressure reclaim same-fabric least-recently-used idle CASE only, after authenticating
 * the new handshake. PASE/live exchanges/subscriptions/I/O remain protected.
 * Send CloseSession and drain before reusing a reserved slot; all protected
 * slots produce an unsecured BUSY response to a new Sigma1/PBKDFParamRequest.
 * KeepSubscriptions=false scopes CASE subscriptions by verified fabric+node,
 * including other sessions; PASE remains scoped to its opaque session token. */
typedef struct Matter_Dispatch* Matter_Dispatch_T;
typedef struct {
    uint32_t sent,received,established;
    uint16_t current,current_for_fabric;
} Matter_Dispatch_Load_T;
/* Owner-thread snapshot, no allocation. Active subscriptions exclude pending
 * reservations and closing handlers. Fabric zero has no accessing fabric.
 * Successful local IM sends exclude MRP retries; all counters saturate.
 * NULL dispatcher returns zero (runtime construction before start). */
Matter_Dispatch_Load_T matter_dispatch_load(Matter_Dispatch_T,uint8_t fabric);
typedef struct {
    Matter_Root_T root; Matter_Events_T events;
    Matter_Crypto_Port_T crypto; Matter_Credentials_Port_T credentials;
    Matter_Case_Port_T fabrics; Matter_Cert_Time_Policy_T time;
    void* user;
    Matter_Pase_T (*pase)(void*,uint16_t local_id,uint64_t now);
    bool (*fabric_live)(void*,uint8_t index); /* Optional live gate; index0=false revokes ALL after reset (only removal reply may drain). */
    /* Optional runtime identity epoch. Rotation exception names the successful
     * UpdateNOC invoker; its unique pending OC exchange may drain its reply.
     * Process Root BEFORE dispatch; never update credentials reentrantly in RX. */
    uint64_t (*credential_revision)(void*,uint8_t,Matter_Exchange_Session_T* update_session);
    Matter_Resolver_Port_T resolver; /* Optional, borrowed through delete. */
    Matter_Result_T (*compressed_fabric)(void*,uint8_t index,uint8_t out[8]);
    Matter_Case_Resumption_Profile_T resumption_profile;
    Matter_Udp_Path_T outbound; /* Actual local IPv6/port and interface; peer resolved by DNS-SD. */
} Matter_Dispatch_Config_T;
/* One bounded outgoing CASE/Invoke job, distinct from server Invoke quota.
 * Copies request, owns discovery/handshake/MRP until take. Cancel only requests
 * drain; keep process/resolver/UDP alive until take is terminal. Reply is borrowed
 * until next invoke/delete. IDs never reused. All APIs on owner thread. */
Matter_Result_T matter_dispatch_invoke(Matter_Dispatch_T,uint8_t fabric,uint64_t node,
    const Matter_Im_Command_Path_T*,uint32_t response_command,const uint8_t* fields,size_t size,uint64_t* id);
Matter_Result_T matter_dispatch_invoke_take(Matter_Dispatch_T,uint64_t id,uint8_t* status,const uint8_t** fields,size_t* size);
void matter_dispatch_invoke_cancel(Matter_Dispatch_T,uint64_t id);
/* Shares the single outgoing slot with Invoke. Sink outlives terminal take;
 * success includes final BlockAckEOF MRP drain. Cancel through invoke_cancel. */
Matter_Result_T matter_dispatch_bdx(Matter_Dispatch_T,uint8_t fabric,uint64_t node,
    const uint8_t* fd,size_t fd_size,const Matter_Bdx_Sink_T*,uint64_t limit,uint64_t* id);
Matter_Result_T matter_dispatch_bdx_take(Matter_Dispatch_T,uint64_t id,uint64_t* bytes);
Matter_Dispatch_T matter_dispatch_new(Matter_T,Matter_Udp_T,const Matter_Dispatch_Config_T*);
/* Owner updates the concrete source for FUTURE outbound jobs after IPv6
 * readiness/reconnect. Each accepted job already owns its path/query copy;
 * existing handshake, ciphertext, sessions and ACK/MRP drain are untouched. */
Matter_Result_T matter_dispatch_set_outbound(Matter_Dispatch_T,const Matter_Udp_Path_T*);
/* Pure, allocation-free preflight for a durable caller's admission decision.
 * OK requires a reusable peer session or configured concrete source/resolver.
 * BUSY/OFFLINE do not consume one-shot application work. Does not guarantee
 * current network reachability or that a subsequent allocation will succeed. */
Matter_Result_T matter_dispatch_invoke_ready(Matter_Dispatch_T,uint8_t fabric,uint64_t node);
/* Prepare DNS/CASE without sending an application request. OK means an existing
 * reusable peer; PENDING owns the shared outgoing slot until peer_take includes
 * handshake ACK/drain. Cancel through invoke_cancel. Failed preparation can be
 * retried without consuming a durable application notification. */
Matter_Result_T matter_dispatch_peer(Matter_Dispatch_T,uint8_t fabric,uint64_t node,uint64_t* id);
Matter_Result_T matter_dispatch_peer_take(Matter_Dispatch_T,uint64_t id);
void matter_dispatch_received(void*,const Matter_Udp_Datagram_T*);
void matter_dispatch_sent(void*,uint64_t,Matter_Operation_Result_T);
Matter_Result_T matter_dispatch_process(Matter_Dispatch_T,uint64_t now);
/* Borrowed authenticated session only; NULL for unknown/revoked tokens. */
Matter_Secure_T matter_dispatch_session(Matter_Dispatch_T,Matter_Exchange_Session_T);
/* Revoke all PASE sessions, optionally all CASE sessions too. Repeated calls
 * drive retirement; include_case=false preserves CASE. Call before rollback.
 * An expiry response waits for local UDP completion, not a peer ACK. OK means
 * those session contexts have drained as well, so rollback can clear credentials.
 * include_case=true cancels any remaining response immediately. */
Matter_Result_T matter_dispatch_retire(Matter_Dispatch_T,bool include_case);
Matter_Result_T matter_dispatch_retire_fabric(Matter_Dispatch_T,uint8_t index);
void matter_dispatch_changed(Matter_Dispatch_T);
/* Observe existing live subscribers' confirmation cursor for a known public
 * event. No new work, callbacks or allocation; excludes closing subscriptions. */
bool matter_dispatch_event_pending(Matter_Dispatch_T,const Matter_Event_Path_T*,uint64_t number);
/* Reply-only session draining after synchronous self-removal. Bounded by MRP
 * completion/error and a 30s upper bound; keep receive/process running. */
bool matter_dispatch_removal_pending(Matter_Dispatch_T);
Matter_Result_T matter_dispatch_stop(Matter_Dispatch_T);
Matter_Result_T matter_dispatch_delete(Matter_Dispatch_T);
#endif
