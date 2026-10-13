#ifndef MATTER_FABRIC_H_INCLUDED
#define MATTER_FABRIC_H_INCLUDED 1
#include "../model/matter_im_invoke.h"
#include "../crypto/matter_operational_cert.h"
enum { MATTER_FABRIC_CAPACITY=5, MATTER_FABRIC_CERT_MAX=400 };
/* Public store view only; private operational keys and IPKs stay in backend.
 * Five real slots (Core minimum). A pending root is an extra journal entry,
 * so TrustedRootCertificates can include one additional pending certificate. */
typedef struct {
    char discovery_instance[34]; /* Uppercase compressed-fabric + node identifier. */
    uint8_t index, root_public[65], operational_public[65], compressed_id[8];
    uint16_t vendor, noc_size, icac_size, root_size;
    uint64_t fabric_id, node_id, admin_subject;
    uint8_t noc[400], icac[400], root[400];
    uint8_t label_size, label[32];
    uint8_t vvs_size, vvs[85];
    uint16_t vvsc_size; uint8_t vvsc[400];
} Matter_Fabric_Record_T;

/* Presence is independent of length: an empty span erases that field. Borrowed
 * only during the synchronous callback; at least one field must be present. */
typedef struct {
    bool vendor_present, vvs_present, vvsc_present;
    uint16_t vendor;
    Matter_Cert_Tlv_T vvs, vvsc;
} Matter_Fabric_Vid_T;
typedef struct {
    uint32_t revision;
    uint8_t count, pending_index, pase_index;
    bool root_ready, added; /* added: successful AddNOC OR UpdateNOC in this fail-safe. */
    uint16_t root_size;
    uint8_t root[400];
    Matter_Exchange_Session_T pase_session;
    Matter_Fabric_Record_T records[MATTER_FABRIC_CAPACITY];
} Matter_Fabric_View_T;
typedef struct {
    Matter_Cert_Tlv_T noc, icac;
    uint8_t ipk[16]; uint64_t admin_subject; uint16_t vendor;
} Matter_Fabric_Add_T;
typedef struct {
    void* user;
    /* Stable until next port callback; owner thread only. Backend outlives model.
     * revision changes on visible changes, including rollback. */
    const Matter_Fabric_View_T* (*view)(void*);
    /* Validates RCAC profile/curve point, stages root under the journal. No trust
     * derived from self-signature. Returns an IM status, never partial success. */
    uint8_t (*root)(void*, Matter_Cert_Tlv_T);
    /* Validate NOC chain/time/IDs/key/fabric before ATOMIC storage of record,
     * operational key, IPK KeySet0, CASE Administer entry (one subject, all
     * targets), discovery identity, PASE and fail-safe fabric binding.
     * On failure preserve CSR/root/store unchanged. Consume candidate only when
     * both the function result and NOC status indicate success.
     * Response status is NodeOperationalCertStatusEnum; function errors -> IM
     * Failure. No retained spans, reentry or hardware waits. Called by process. */
    Matter_Result_T (*install)(void*, Matter_Exchange_Session_T, uint64_t candidate,
        const Matter_Fabric_Add_T*, uint8_t* status, uint8_t* index);
    /* Revoke/drain sessions first. Idempotent rollback removes journaled root,
     * fabric, keys, ACL, discovery and bindings. Errors remain retryable. */
    Matter_Result_T (*rollback)(void*);
    /* Atomic management of visible state; no session/transport callbacks here.
     * Owner reconciles removed identities before further RX/TX. Last removal
     * must reset all supported commissioned data; preserve provisioning. */
    Matter_Result_T (*label)(void*,uint8_t,const uint8_t*,size_t);
    Matter_Result_T (*remove)(void*,uint8_t);
    /* Optional atomic credential replacement. Same root/fabric, fresh CSR key;
     * preserve ACL/IPK/label/index. Journal old credentials until Complete.
     * Owner retires old CASE, preserving the invoking exchange through delivery. */
    Matter_Result_T (*update)(void*,Matter_Exchange_Session_T,uint8_t,uint64_t,
        Matter_Cert_Tlv_T,Matter_Cert_Tlv_T,uint8_t* status);
    /* Atomic visible metadata update, journaled with pending AddNOC/UpdateNOC.
     * Does not rotate operational identity or revoke CASE. */
    Matter_Result_T (*vid)(void*,uint8_t,const Matter_Fabric_Vid_T*);
    /* Operational key of target fabric; raw P-256 r||s over SHA256(message). */
    Matter_Result_T (*sign)(void*,uint8_t,const uint8_t*,size_t,uint8_t[64]);
} Matter_Fabric_Port_T;
typedef struct Matter_Fabric* Matter_Fabric_T;
Matter_Fabric_T matter_fabric_new(const Matter_Fabric_Port_T*);
Matter_Result_T matter_fabric_delete(Matter_Fabric_T);
uint32_t matter_fabric_revision(Matter_Fabric_T);
bool matter_fabric_added(Matter_Fabric_T);
uint8_t matter_fabric_index(Matter_Fabric_T, Matter_Exchange_Session_T);
uint8_t matter_fabric_pending_index(Matter_Fabric_T);
uint8_t matter_fabric_validate(uint32_t command,const uint8_t*,size_t);
/* Owner process only, after authorization and live secure challenge resolution.
 * Set uses accessing; Sign may target any installed fabric (Core 11.18.6.15). */
uint8_t matter_fabric_vid(Matter_Fabric_T,uint8_t accessing,uint32_t command,
    const uint8_t*,size_t,const uint8_t challenge[16],uint8_t* target,uint8_t signature[64]);
Matter_Im_Command_Result_T matter_fabric_manage(Matter_Fabric_T,uint8_t accessing,
    uint32_t command,const uint8_t*,size_t,uint8_t* noc_status,uint8_t* index);
/* Synchronous bounded phase, outside RX/Invoke. Arguments borrowed only here. */
Matter_Im_Command_Result_T matter_fabric_execute(Matter_Fabric_T, Matter_Exchange_Session_T,
    uint32_t command,uint64_t candidate,const uint8_t*,size_t,uint8_t* noc_status,uint8_t* index);
Matter_Im_Command_Result_T matter_fabric_update(Matter_Fabric_T,Matter_Exchange_Session_T,
    uint8_t accessing,uint64_t candidate,const uint8_t*,size_t,uint8_t* status,uint8_t* index);
Matter_Result_T matter_fabric_rollback(Matter_Fabric_T);
uint8_t matter_fabric_read(Matter_Fabric_T,uint32_t attr,Matter_Exchange_Session_T,bool filtered,Matter_Im_Value_T*);
/* Trusted caller only: accessing index from authenticated CASE identity/ACL. */
uint8_t matter_fabric_read_index(Matter_Fabric_T,uint32_t,uint8_t,bool,Matter_Im_Value_T*);
#endif
