#ifndef MATTER_ADMIN_COMMISSIONING_H_INCLUDED
#define MATTER_ADMIN_COMMISSIONING_H_INCLUDED 1
#include "../model/matter_cluster.h"
#include "../session/matter_pase.h"
enum { MATTER_ADMIN_COMMISSIONING_CLUSTER=0x3c };
typedef struct {
    void* user;
    /* Trusted fabric lookup; INVALID_STATE for a missing fabric. No wire VID. */
    Matter_Result_T (*vendor)(void*,uint8_t fabric,uint16_t* vendor);
    /* Includes initial/other commissioning windows and fail-safe cleanup.
     * Root also supplies armed state on Invoke. Errors fail closed. */
    Matter_Result_T (*blocked)(void*,bool*);
    /* Atomic, bounded publication of ECM DNS-SD (CM=2, supplied long D).
     * open failure MUST leave no publication. Close is idempotent, retried by
     * process on failure; local admission/verifier already revoked. No pointer
     * retention or reentry. Wire mDNS belongs to the application adapter. */
    Matter_Result_T (*advertise)(void*,bool open,uint16_t discriminator);
    /* ONLY called by process, never by Invoke: immediately revoke all PASE
     * grants, cancel attempts, retire/drain established PASE, expire fail-safe
     * held by PASE and perform rollback. Preserve unrelated CASE/fail-safe.
     * Idempotent; PENDING while draining, error retryable, OK only when complete.
     * The owner must stop routing revoked PASE before servicing more IM work. */
    Matter_Result_T (*revoke)(void*);
} Matter_Admin_Commissioning_Port_T;
/* Core 1.6.1 11.19 rev1, Enhanced only (FeatureMap=0). Two heap allocations,
 * copied ports, borrowed user/crypto backend. No tasks, sockets or globals.
 * Initial window is external and is NOT reflected by WindowStatus.
 * Application authorizes every IM call; commands require Timed/Administer.
 * Attach using matter_root_attach_cluster; Root borrows/pins the handle.
 * Owner MUST process current time BEFORE IM, and service deadline without RX.
 * Process this cluster outside Root callbacks, then Root cleanup/IM. Generic
 * Root does not automatically pump custom clusters. Serialize all API calls.
 * Delete refuses an open window, pending unpublish/revoke or IM handles.
 */
Matter_Cluster_T matter_admin_commissioning_new(const Matter_Admin_Commissioning_Port_T*,
    const Matter_Crypto_Port_T*,uint32_t data_version,uint64_t now_ms);
/* Owner hook for successful Complete, rollback or shutdown. Closes admission,
 * erases verifier now; process retries unpublish. Does NOT abort existing PASE:
 * commissioning owner already performs retirement/drain. Call until OK before
 * final commit/delete. PENDING means process must still finish unpublication. */
Matter_Result_T matter_admin_commissioning_close(Matter_Cluster_T);
/* Notify BEFORE deleting/reusing a fabric index. VID remains the opening VID. */
Matter_Result_T matter_admin_commissioning_fabric_removed(Matter_Cluster_T,uint8_t);
/* Admission + new responder, with no exported verifier. NULL if closed/expired,
 * revoking, invalid arguments or OOM. now shares the process clock. An admitted
 * attempt may continue after window expiry. Caller owns/registers each returned
 * PASE until delete, reserves a unique ID across PASE/CASE and implements the
 * revoke port for ALL attempts/sessions (including completed handoffs). Keep
 * crypto backend alive. No new attempt may bypass this gate in ECM mode. */
Matter_Pase_T matter_admin_commissioning_pase_new(Matter_Cluster_T,uint16_t local_session_id,
    uint32_t attempt_timeout_ms,uint64_t now_ms);
#endif
