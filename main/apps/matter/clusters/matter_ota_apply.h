#ifndef MATTER_OTA_APPLY_H_INCLUDED
#define MATTER_OTA_APPLY_H_INCLUDED 1
#include "matter_ota_requestor.h"
typedef struct Matter_Ota_Apply* Matter_Ota_Apply_T;
typedef struct {
    Matter_Ota_Provider_T provider;
    uint64_t generation,artifact; uint32_t version;
    uint8_t token[32]; size_t token_size;
} Matter_Ota_Apply_Context_T;
typedef enum {
    MATTER_OTA_APPLY_ACCEPTED, MATTER_OTA_APPLY_DISCONTINUED,
    MATTER_OTA_APPLY_ERROR, MATTER_OTA_APPLY_CANCELLED,
    MATTER_OTA_APPLY_INVALIDATED, MATTER_OTA_APPLY_REJECTED
} Matter_Ota_Apply_Result_T;
typedef struct {
    void* user;
    uint64_t (*generation)(void*,uint8_t);
    /* Command2 -> command3 on provider cluster0x29. Same owned-job/drain and
     * borrowed-response contract as QueryImage. No synchronous completion. */
    Matter_Result_T (*start)(void*,const Matter_Ota_Provider_T*,const uint8_t*,size_t,uint64_t*);
    Matter_Result_T (*take)(void*,uint64_t,uint8_t*,const uint8_t**,size_t*);
    void (*cancel)(void*,uint64_t);
    Matter_Result_T (*state)(void*,uint8_t state,uint8_t reason,uint32_t version,uint64_t now);
    /* Called once after Proceed's delay, with live fabric. Provider permission
     * is NOT image authentication. Owner must revalidate the bound artifact,
     * verify its vendor signature and authorize any installation separately.
     * OK means accepted handoff only, never successful installation. Applying
     * remains published; owner takes over completion and query scheduling.
     * No PENDING.
     * Context borrowed; callbacks may copy, but must not reenter this instance. */
    Matter_Result_T (*ready)(void*,const Matter_Ota_Apply_Context_T*);
    void (*done)(void*,const Matter_Ota_Apply_Context_T*,Matter_Ota_Apply_Result_T);
} Matter_Ota_Apply_Port_T;
/* One heap allocation. Application clock, no OS/task/filesystem dependency.
 * Begin copies a context ONLY after successful download/validation/commit.
 * Await floor120s; delays capped24h; 65s Invoke deadline. Errors return control
 * to owner's QueryImage policy. Never falls back to unapproved installation.
 * No restart persistence: new instance cannot reuse an old grant or token. */
Matter_Ota_Apply_T matter_ota_apply_new(const Matter_Ota_Apply_Port_T*,uint64_t now);
Matter_Result_T matter_ota_apply_begin(Matter_Ota_Apply_T,const Matter_Ota_Apply_Context_T*,uint64_t now);
Matter_Result_T matter_ota_apply_process(Matter_Ota_Apply_T,uint64_t now);
bool matter_ota_apply_busy(Matter_Ota_Apply_T);
void matter_ota_apply_cancel(Matter_Ota_Apply_T);
Matter_Result_T matter_ota_apply_delete(Matter_Ota_Apply_T);
#endif
