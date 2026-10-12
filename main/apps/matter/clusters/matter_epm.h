#ifndef MATTER_EPM_H_INCLUDED
#define MATTER_EPM_H_INCLUDED 1
#include "../model/matter_cluster.h"
enum { MATTER_EPM_CLUSTER=0x0090, MATTER_EPM_MAX_RANGES=4,
    MATTER_EPM_PERCENT_MAX=1, MATTER_EPM_FIXED_MAX=2 };
#define MATTER_EPM_LIMIT (INT64_C(1)<<62)
/* Accuracy is immutable configuration, copied by new. Units are mW, except
 * percent_max (0..10000 = 0..100%). Select at least one max error field.
 * Ranges increase without gaps (next.min=previous.max+1); min < max.
 * This subset covers the entire min..max measurement interval. */
typedef struct {
    int64_t min_mw,max_mw; uint64_t fixed_max_mw;
    uint16_t percent_max; uint8_t fields;
} Matter_Epm_Accuracy_Range_T;
typedef struct {
    Matter_Epm_Accuracy_Range_T ranges[MATTER_EPM_MAX_RANGES];
    uint8_t range_count; bool measured,polyphase;
    uint32_t data_version,max_age_ms;
} Matter_Epm_Config_T;
typedef struct { int64_t active_mw; uint64_t sampled_ms; bool available; } Matter_Epm_Sample_T;
typedef struct {
    void* user;
    /* Bounded, nonblocking copy into zeroed model-owned workspace; no retention
     * or reentry. Signed aggregate mW: positive import, negative export.
     * Sample clock equals refresh's monotonic clock. Application performs any
     * source conversion/summation with overflow checks before setting available.
     * OK+!available means no measurement; errors also invalidate the live value. */
    Matter_Result_T (*snapshot)(void*,Matter_Epm_Sample_T*);
} Matter_Epm_Port_T;
/* App1.6.1 2.13 / rev3, AC, optionally POLY. Only ActivePower reported;
 * PowerMode=AC, NumberOfMeasurementTypes=1, Accuracy + five globals.
 * Starts at null; no callback during construction. max_age_ms must be >0.
 * No clock/task/hardware/global state. user outlives cluster; common delete. */
Matter_Cluster_T matter_epm_new(const Matter_Epm_Port_T*,const Matter_Epm_Config_T*,uint64_t now_ms);
/* Optional adapter conversion W -> mW, nearest integer, half away from zero.
 * Reject nonfinite/out-of-protocol-range input; leave output unchanged on error.
 * Configuration limits are checked separately by refresh. Integer mW sources
 * should bypass this helper to retain precision beyond double's exact integers. */
Matter_Result_T matter_epm_from_watts(double watts,int64_t* milliwatts);
/* Owner calls before IM, on source updates AND at least once per second to
 * expire samples and deliver pending report readiness. No allocation or I/O.
 * Reads/versions use only the published snapshot, never call the backend.
 * Age >= max_age_ms, unavailable, invalid/out-of-range/future sample or backend
 * failure publishes null. Invalid sample/backend returns PORT_ERROR, but still
 * sets report_ready: caller must consume it even on that error.
 * Wire value changes bump DataVersion once; timestamps alone do not.
 * report_ready is coalesced, at most once/1000ms (first >= new time+1000).
 * On true, owner notifies every affected subscription after refresh returns.
 * Backward owner clock/invalid arguments/reentry leave the model unchanged.
 * Serialize refresh with all model/IM calls. No automatic subscription registry. */
Matter_Result_T matter_epm_refresh(Matter_Cluster_T,uint64_t now_ms,bool* report_ready);
#endif
