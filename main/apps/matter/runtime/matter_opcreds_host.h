#ifndef MATTER_OPCREDS_HOST_H_INCLUDED
#define MATTER_OPCREDS_HOST_H_INCLUDED 1
#include "../clusters/matter_opcreds.h"
/* RAM key store for the x86 simulation. Crypto/credential ports (mbedTLS) and
 * application callbacks outlive it. Private DAC is copied at construction;
 * public identity spans remain borrowed. No file storage, tasks or OS clock.
 * Production hardware can implement the same core port with secure key handles. */
typedef struct {
    Matter_Opcreds_Config_T identity;
    Matter_Der_T trusted_paa;
    const uint8_t* dac_private; /* 32 bytes, copied; caller erases its own copy */
    uint16_t vendor_id, product_id;
    void* user;
    Matter_Result_T (*challenge)(void*, Matter_Exchange_Session_T, uint8_t[16]);
    Matter_Result_T (*timestamp)(void*, uint32_t*);
} Matter_Opcreds_Host_Config_T;
typedef struct Matter_Opcreds_Host* Matter_Opcreds_Host_T;
Matter_Opcreds_Host_T matter_opcreds_host_new(const Matter_Opcreds_Host_Config_T*,
    const Matter_Crypto_Port_T*, const Matter_Credentials_Port_T*);
Matter_Opcreds_Port_T matter_opcreds_host_port(Matter_Opcreds_Host_T);
/* Public key only, for subsequent AddNOC matching/host inspection. */
Matter_Result_T matter_opcreds_host_candidate(Matter_Opcreds_Host_T, uint8_t public_key[65]);
/* Refuses live keys; rollback core first. Erases the private DAC on deletion. */
Matter_Result_T matter_opcreds_host_delete(Matter_Opcreds_Host_T);
/* Host-only bridge to the fabric store. Callback borrows secret on heap for an
 * atomic transaction, never retains pointer. Failure preserves candidate; OK
 * consumes/zeroizes it. No core/IM API exposes private key bytes. */
Matter_Result_T matter_opcreds_host_consume(Matter_Opcreds_Host_T, uint64_t handle,
    void* user, Matter_Result_T (*store)(void*, const uint8_t key[32]));
/* Optional installed-key collision checker, detached before its user is freed.
 * Only public point crosses this callback; same owner, no reentry. */
Matter_Result_T matter_opcreds_host_collision(Matter_Opcreds_Host_T, void* user,
    bool (*exists)(void*, const uint8_t public_key[65]));
#endif
