#ifndef MATTER_OTA_INSTALL_H_INCLUDED
#define MATTER_OTA_INSTALL_H_INCLUDED 1
#include "../clusters/matter_ota_apply.h"

/* Application-owned real bootloader policy, independent of the optional WWOTA
 * simulation journal. All callbacks are synchronous owner-thread operations;
 * no runtime reentry, PENDING, global sink or borrowed network response. */
typedef enum {
    MATTER_OTA_INSTALL_TRIAL, MATTER_OTA_INSTALL_NOTIFY, MATTER_OTA_INSTALL_ROLLBACK
} Matter_Ota_Install_State_T;
typedef struct {
    Matter_Ota_Install_State_T state;
    Matter_Ota_Apply_Context_T context;
} Matter_Ota_Install_Boot_T;
typedef struct {
    void* user;
    /* Borrowed through the next installer callback; NULL means no boot work.
     * State must be reconciled against the actual running firmware, never just
     * a stored target version. ROLLBACK describes the current boot only. */
    const Matter_Ota_Install_Boot_T* (*boot)(void*);
    /* Authenticate the SAME committed artifact, persist context/fingerprint,
     * and select the next boot image. OK authorizes reboot handoff, not proof
     * of a successful boot. Failure must keep the current image bootable. */
    Matter_Result_T (*accept)(void*,const Matter_Ota_Apply_Context_T*,const uint8_t fingerprint[32]);
    /* Called only after the application declares its new boot functional.
     * Confirm the real image before publishing durable notification readiness;
     * recovery must handle a reset between those two steps. */
    Matter_Result_T (*confirm)(void*);
    /* Persist consumption BEFORE the one application-level Notify attempt.
     * Reject/drop a removed or replaced fabric using the supplied fingerprint.
     * On success copy a stable context to out; mismatch returns OFFLINE. */
    Matter_Result_T (*claim)(void*,const uint8_t fingerprint[32],bool live,Matter_Ota_Apply_Context_T* out);
} Matter_Ota_Install_Port_T;
#endif
