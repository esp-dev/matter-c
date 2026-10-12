#ifndef MATTER_OTA_UPDATE_H_INCLUDED
#define MATTER_OTA_UPDATE_H_INCLUDED 1
#include "matter_ota_apply.h"
#include "../ports/matter_crypto_port.h"
#include "../storage/matter_store_blob.h"
/* Explicit SIMULATION format, not an ESP image or a vendor production format.
 * Payload = manifest56 || ECDSA-P256-SHA256 signature64(r||s) || body.
 * Manifest = "WWOTA001", VID16/PID16/version32/bodyLength64 LE, SHA256(body).
 * The signature covers all 56 manifest bytes. Trust key is supplied locally.
 * Reader computes digest/length from the same stream the application consumes. */
typedef struct { uint8_t manifest[56],signature[64],digest[32]; uint64_t body_size; } Matter_Ota_Signed_T;
typedef struct Matter_Ota_Update* Matter_Ota_Update_T;
/* Portable atomic journal on an application-owned blob. One heap workspace.
 * Verifies stored signature/identity before restoring installed version.
 * V2: staged -> trial -> confirmed/notification pending -> consumed.
 * Restart without trial confirmation restores the previous confirmed image.
 * V1 records retain their original already-installed meaning (no fallback).
 * No workers, filesystem, executable loading, or installation of machine code.
 * Blob and crypto ports must outlive instance; no callback reentry. */
Matter_Ota_Update_T matter_ota_update_new(const Matter_Store_Blob_Port_T*,const Matter_Crypto_Port_T*,
    const uint8_t public_key[65],uint16_t vendor,uint16_t product,uint32_t initial_version);
void matter_ota_update_delete(Matter_Ota_Update_T);
uint32_t matter_ota_update_version(Matter_Ota_Update_T);
bool matter_ota_update_booted(Matter_Ota_Update_T);
bool matter_ota_update_trial(Matter_Ota_Update_T);
bool matter_ota_update_rolled_back(Matter_Ota_Update_T);
/* Owner confirms only after successful application initialization, before
 * publication/Notify. Failure leaves the trial recoverable by rollback.
 * Trial version is tentative; no command is pending until confirm succeeds. */
Matter_Result_T matter_ota_update_confirm(Matter_Ota_Update_T);
Matter_Result_T matter_ota_update_verify(Matter_Ota_Update_T,uint32_t version,const Matter_Ota_Signed_T*);
/* Simulated consumption: only authenticated metadata becomes installed state.
 * Caller must stop old instance after OK, restart to expose version/BootReason.
 * Fabric fingerprint = SHA256(NOC), binding notification across index reuse. */
Matter_Result_T matter_ota_update_accept(Matter_Ota_Update_T,const Matter_Ota_Apply_Context_T*,
    const uint8_t fabric_fingerprint[32],const Matter_Ota_Signed_T*);
/* Borrowed notification context until next call; NULL when not pending. */
const Matter_Ota_Apply_Context_T* matter_ota_update_pending(Matter_Ota_Update_T);
/* Persist consumed BEFORE a single send attempt. Crash may lose notification;
 * never retries at application level, including after restart/start failure.
 * live=false or a mismatched fingerprint drops the orphan notification.
 * Context copied only on OK; OFFLINE = discarded, no command to send. */
Matter_Result_T matter_ota_update_claim(Matter_Ota_Update_T,const uint8_t fingerprint[32],bool live,
    Matter_Ota_Apply_Context_T*);
#endif
