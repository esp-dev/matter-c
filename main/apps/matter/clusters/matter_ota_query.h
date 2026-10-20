#ifndef MATTER_OTA_QUERY_H_INCLUDED
#define MATTER_OTA_QUERY_H_INCLUDED 1
#include "matter_ota_requestor.h"
typedef struct Matter_Ota_Query* Matter_Ota_Query_T;
typedef struct {
    uint16_t vendor,product,hardware; uint32_t version;
    uint8_t protocols[8],protocol_count;
} Matter_Ota_Query_Config_T;
typedef struct {
    uint8_t status; uint32_t delay,version;
    char uri[257],version_string[65]; uint8_t token[32],metadata[512];
    size_t token_size,metadata_size,version_string_size; bool consent_needed;
} Matter_Ota_Image_T; /* Keep off embedded stacks. Borrowed in available callback. */
typedef struct {
    void* user;
    uint64_t (*generation)(void*,uint8_t);
    Matter_Result_T (*random)(void*,uint32_t*);
    /* Starts one QueryImage (cluster29 command0 -> command1), copied anonymous
     * fields. PENDING owns a fresh job; all other returns own nothing. */
    Matter_Result_T (*start)(void*,const Matter_Ota_Provider_T*,const uint8_t*,size_t,uint64_t*);
    /* Terminal result consumes job; reply borrowed through next start. Includes
     * CASE/Invoke/status/drain failures. Cancel must eventually allow take. */
    Matter_Result_T (*take)(void*,uint64_t,uint8_t* im_status,const uint8_t**,size_t*);
    void (*cancel)(void*,uint64_t);
    Matter_Result_T (*state)(void*,uint8_t state,uint8_t reason,uint64_t now);
    /* Metadata only. No installation grant. Callback may copy; no reentry.
     * Called only for newer, supported bdx URI after DelayedActionTime. Owner
     * publishes its next state (or Idle if it cannot accept the image); no
     * intermediate Idle callback is published before this handoff. */
    void (*available)(void*,const Matter_Ota_Provider_T*,const Matter_Ota_Image_T*);
} Matter_Ota_Query_Port_T;
/* Application owns time, ports and scheduling. One allocation, no workers.
 * One selected provider; active queries are never preempted by announcements.
 * Conservative global 120s floor survives provider changes, 24h normal period,
 * exponential 120s..1h error backoff; Busy retries same provider. Urgent jitter
 * 1..600 seconds. No restart persistence/timekeeping, downloads or installer.
 * Protocols list must reflect actual download backends (zero is query-only).
 * No automatic echo of manufacturer announcement metadata. */
Matter_Ota_Query_T matter_ota_query_new(const Matter_Ota_Query_Config_T*,const Matter_Ota_Query_Port_T*,uint64_t now);
bool matter_ota_query_offer(Matter_Ota_Query_T,const Matter_Ota_Offer_T*,uint64_t now);
/* Explicit application/user query opportunity for the selected live provider.
 * Schedules only; process performs I/O. Preserves 120s/provider/urgent floors
 * and active error/Busy backoff. Does not preempt a query or pending image.
 * Does not change the default daily policy. No allocation or inline callback
 * except the fabric-generation check. All calls use the same owner thread. */
Matter_Result_T matter_ota_query_request(Matter_Ota_Query_T,uint64_t now);
Matter_Result_T matter_ota_query_process(Matter_Ota_Query_T,uint64_t now);
/* Stop requests cancellation. Continue process until OK, then delete. */
Matter_Result_T matter_ota_query_stop(Matter_Ota_Query_T);
Matter_Result_T matter_ota_query_delete(Matter_Ota_Query_T);
#endif
