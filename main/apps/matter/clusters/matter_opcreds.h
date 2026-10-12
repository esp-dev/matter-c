#ifndef MATTER_OPCREDS_H_INCLUDED
#define MATTER_OPCREDS_H_INCLUDED 1
#include "../model/matter_cluster.h"
#include "../ports/matter_credentials_port.h"
#include "matter_fabric.h"
/* Core 1.6.1 11.18 rev2 subset: attestation/CSR plus optional fabric store.
 * AddTrustedRoot/AddNOC/UpdateNOC/UpdateFabricLabel/RemoveFabric and six store attributes require attach_fabrics.
 * UpdateNOC uses authenticated CASE through the generic cluster interface.
 * CSR purpose and secure incarnation bind the candidate key. VID verification
 * uses the fabric port for atomic metadata storage and operational-key signing;
 * owner coordinates journal and session retirement. Not full conformance. */
enum { MATTER_OPCREDS_CLUSTER=0x3e, MATTER_OPCREDS_RESP_MAX=900, MATTER_OPCREDS_ATTRIBUTES=5 };
typedef struct {
    /* Immutable public blobs borrowed through delete. DER DAC/PAI <=600 B;
     * CD is signed CMS DER supplied by provisioning, firmware_information is
     * optional opaque octets per 6.3.2. Combined AttestationElements <=900 B.
     * Application validates identity/CD/trust policy before publication. */
    Matter_Der_T dac, pai, certification_declaration, firmware_information;
    uint32_t data_version;
} Matter_Opcreds_Config_T;
typedef struct {
    void* user;
    /* Resolve authenticated PASE/CASE incarnation on EVERY call; closed/revoked or
     * missing mapping must fail. Copies 16-byte challenge; no session pointer
     * retained by core. This is never a challenge taken from the wire. */
    Matter_Result_T (*challenge)(void*, Matter_Exchange_Session_T, uint8_t challenge[16]);
    Matter_Result_T (*timestamp)(void*, uint32_t* epoch_s); /* Matter epoch 2000 UTC, app clock */
    /* Sign SHA256(message) using DAC private key, raw r||s (64 B), not DER.
     * Same synchronous, bounded crypto contract as M07; process only, outside
     * RX and Invoke callbacks. No hard latency guarantee on hardware. */
    Matter_Result_T (*sign)(void*, const uint8_t* message, size_t, uint8_t signature[64]);
    /* Create NEW staged operational key + signed PKCS#10 <=512 B. Success sets
     * a nonzero handle. Failure releases all new resources, leaves old candidate
     * and outputs unchanged/zeroized. Check collisions with installed keys when a
     * fabric backend is attached. Input/output pointers are never retained. */
    Matter_Result_T (*csr_prepare)(void*, uint64_t* handle, uint8_t* csr, size_t capacity, size_t* size);
    /* Atomically replace old candidate after outer signature succeeds. The
     * handle is still temporary under fail-safe; this is NOT AddNOC/persistence.
     * Failure preserves both handles for discard/retry of cleanup. */
    Matter_Result_T (*csr_publish)(void*, uint64_t handle);
    /* Idempotent erase of a staged/current handle; OK only after completion.
     * PENDING/error keeps core cleanup blocked/retryable. No retained pointers. */
    Matter_Result_T (*csr_discard)(void*, uint64_t handle);
} Matter_Opcreds_Port_T;
typedef Matter_Cluster_T Matter_Opcreds_T; /* Compatibility name; state is private. */
Matter_Cluster_T matter_opcreds_new(const Matter_Opcreds_Config_T*, const Matter_Opcreds_Port_T*);
Matter_Result_T matter_opcreds_delete(Matter_Opcreds_T);
/* One bounded phase per owner call: prepare elements/CSR, sign, publish.
 * Serialize before IM processing. Re-check session challenge before each phase.
 * No task/time/thread/hardware in core. Heap workspace, single pending operation.
 * Root/application admission supplies armed state. Optional fabric commands run
 * one bounded validation/install phase; successful AddNOC/UpdateNOC blocks further
 * CSR, AddTrustedRoot and NOC changes until rollback or explicit commit. */
Matter_Result_T matter_opcreds_process(Matter_Opcreds_T);
/* GC cleanup: revoke/drain PASE first, then rollback to erase staged/current CSR,
 * rollback an attached fabric transaction, then remove the application journal.
 * Handler cancellation alone preserves a published candidate/installed fabric.
 * Delete refuses pending work/keys. Backend ports/blobs outlive this module. */
Matter_Result_T matter_opcreds_rollback(Matter_Opcreds_T);
/* Transaction coordinator: preflight all participants under one owner, then
 * commit without callbacks/allocations/interleaving. Failure preserves snapshot.
 * Does not by itself commit any platform journal or retire sessions. */
Matter_Result_T matter_opcreds_commit_ready(Matter_Opcreds_T);
Matter_Result_T matter_opcreds_commit(Matter_Opcreds_T);
extern const uint32_t matter_opcreds_attributes[MATTER_OPCREDS_ATTRIBUTES];
uint32_t matter_opcreds_version(Matter_Opcreds_T);
uint8_t matter_opcreds_read(Matter_Opcreds_T, uint32_t attribute, Matter_Im_Value_T*);
uint8_t matter_opcreds_command(Matter_Opcreds_T, uint32_t command, Matter_Im_Command_T*);
uint8_t matter_opcreds_validate(Matter_Opcreds_T, uint32_t command, const uint8_t*, size_t);
Matter_Result_T matter_opcreds_start(Matter_Opcreds_T, Matter_Exchange_Session_T, uint32_t command,
    bool armed, const uint8_t*, size_t, Matter_Tlv_Writer_T*, Matter_Im_Command_Result_T*, uint64_t* token);
Matter_Result_T matter_opcreds_poll(Matter_Opcreds_T, uint64_t token, Matter_Tlv_Writer_T*, Matter_Im_Command_Result_T*);
void matter_opcreds_cancel(Matter_Opcreds_T, uint64_t token);
/* Optional AddTrustedRoot/AddNOC store, borrowed through delete. Attach once
 * before seal/Root attachment. Extension is atomic and allocates nothing;
 * after publication it returns INVALID_STATE. Rollback drains this backend. */
Matter_Result_T matter_opcreds_attach_fabrics(Matter_Opcreds_T, Matter_Fabric_T);
const uint32_t* matter_opcreds_attribute_ids(Matter_Opcreds_T,size_t* count);
uint8_t matter_opcreds_fabric_index(Matter_Opcreds_T,Matter_Exchange_Session_T);
uint8_t matter_opcreds_pending_fabric(Matter_Opcreds_T);
uint8_t matter_opcreds_read_session(Matter_Opcreds_T,uint32_t,Matter_Exchange_Session_T,bool,Matter_Im_Value_T*);
/* Trusted caller: authenticated fabric index, authorization already performed. */
uint8_t matter_opcreds_read_fabric(Matter_Opcreds_T,uint32_t,uint8_t,bool,Matter_Im_Value_T*);
#endif
