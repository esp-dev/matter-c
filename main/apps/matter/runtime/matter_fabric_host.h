#ifndef MATTER_FABRIC_HOST_H_INCLUDED
#define MATTER_FABRIC_HOST_H_INCLUDED 1
#include "matter_opcreds_host.h"
#include "../clusters/matter_acl.h"
#include "../clusters/matter_groupkey.h"
#include "../clusters/matter_fabric.h"
#include "../session/matter_case.h"
/* Application-owned image outlives runtime adapters. Opaque: includes private
 * keys, IPK, ACL, discovery and journal. Optional matter_store_host attaches
 * durable TLV publication; without it behavior remains RAM-only. No flash claim. */
typedef struct Matter_Fabric_Host_Image* Matter_Fabric_Host_Image_T;
typedef struct Matter_Fabric_Host* Matter_Fabric_Host_T;
Matter_Fabric_Host_Image_T matter_fabric_host_image_new(void);
Matter_Result_T matter_fabric_host_image_delete(Matter_Fabric_Host_Image_T);
/* Exclusive owner; new rolls back an interrupted journal BEFORE publication.
 * Trusted UTC/LKG supplied by application, never taken from incoming NOC.
 * Crypto requires ECDSA sign and verify (RCAC admission before journal/store). */
Matter_Fabric_Host_T matter_fabric_host_new(Matter_Fabric_Host_Image_T, Matter_Opcreds_Host_T,
    const Matter_Crypto_Port_T*, const Matter_Credentials_Port_T*,const Matter_Cert_Time_Policy_T*);
Matter_Fabric_Port_T matter_fabric_host_port(Matter_Fabric_Host_T);
/* Borrowed CASE candidate port: up to 3 operational IPKs/fabric, preferred first.
 * Includes volatile resumption MRU cache (3 peers/fabric), erased on local
 * credential/IPK change, removal or adapter delete. Nodes allocate on first save;
 * OOM preserves old entries and merely forgoes caching this handshake. Updates
 * and per-fabric oldest eviction reuse nodes. No durable schema change. */
Matter_Case_Port_T matter_fabric_host_case_port(Matter_Fabric_Host_T);
Matter_Result_T matter_fabric_host_delete(Matter_Fabric_Host_T);
/* Last removal committed: owner must drain/delete the entire instance. */
bool matter_fabric_host_reset_requested(Matter_Fabric_Host_T);
/* Runtime identity epoch, unaffected by labels/ACL/IPK. Exception token identifies
 * the successful UpdateNOC invoker; owner permits only its pending response. */
uint64_t matter_fabric_host_credential_revision(Matter_Fabric_Host_T,uint8_t,Matter_Exchange_Session_T*);
/* Application finalization ONLY after authenticated CommissioningComplete.
 * commit_ready also accepts an existing fabric when no credential transaction
 * is pending, for network-only finalization; Root must check fail-safe ownership.
 * commit itself still requires pending credentials. Tests use it to seed state. */
Matter_Result_T matter_fabric_host_commit_ready(Matter_Fabric_Host_T,uint8_t index);
Matter_Result_T matter_fabric_host_commit(Matter_Fabric_Host_T);
Matter_Result_T matter_fabric_host_sign(Matter_Fabric_Host_T,uint8_t index,const uint8_t*,size_t,uint8_t signature[64]);
/* Same image as AddNOC/CASE/rollback; no persisted epoch InputKeys. */
Matter_Groupkey_Port_T matter_fabric_host_groupkey_port(Matter_Fabric_Host_T);
/* Trusted group receiver only: copy one already-derived operational epoch key.
 * KeySet0/IPK, absent fabric/key, disabled epoch and reentry are rejected.
 * Caller clears the16-byte output after its last crypto use. No ownership or
 * persistence change; never expose this material via the Data Model. */
Matter_Result_T matter_fabric_host_group_key(Matter_Fabric_Host_T,uint8_t fabric,
    uint16_t key_set,unsigned epoch,uint8_t out[16]);
/* Borrow the same ACL image used by AddNOC/rollback. Model user must die before host. */
Matter_Acl_Port_T matter_fabric_host_acl_port(Matter_Fabric_Host_T);
/* Optional host event integration before commissioning. Borrow ACL/log; admin
 * resolves the authenticated invoking session, never a client supplied Node ID. */
typedef struct {
    Matter_Acl_T acl; Matter_Events_T log; void* user;
    Matter_Result_T (*admin)(void*,Matter_Exchange_Session_T,Matter_Cluster_Request_T*);
    /* Optional synchronous notification after committed removal/rollback, before
     * index reuse. Never emitted for failed storage or credential rotation.
     * Runs on the owner thread; must not reenter this fabric host. */
    void (*removed)(void*,uint8_t index);
} Matter_Fabric_Host_Events_T;
Matter_Result_T matter_fabric_host_bind_events(Matter_Fabric_Host_T,const Matter_Fabric_Host_Events_T*);
/* Legacy whole-node grant query, now backed by live ACL. Target-specific grants
 * require matter_acl_authorize with the actual path and Descriptor callback. */
bool matter_fabric_host_case_authorize(Matter_Fabric_Host_T,uint8_t index,uint64_t node,
    const uint32_t* cats,size_t count,Matter_Im_Privilege_T);
/* Simulator fault controls, checked BEFORE transaction commit. */
typedef struct { bool fail_store, fail_acl, fail_discovery, fail_rollback; } Matter_Fabric_Host_Control_T;
void matter_fabric_host_control(Matter_Fabric_Host_T,const Matter_Fabric_Host_Control_T*);
#endif
