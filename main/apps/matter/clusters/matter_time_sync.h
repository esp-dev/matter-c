#ifndef MATTER_TIME_SYNC_H_INCLUDED
#define MATTER_TIME_SYNC_H_INCLUDED 1
#include "../model/matter_cluster.h"
#include "../model/matter_events.h"
#define MATTER_TIME_SYNC_CLUSTER 0x0038
#define MATTER_TIME_SYNC_REVISION 2
#define MATTER_TIME_UTC 0
#define MATTER_TIME_GRANULARITY 1
#define MATTER_TIME_SOURCE 2
#define MATTER_TIME_SET_UTC 0
#define MATTER_TIME_FAILURE 3
#define MATTER_TIME_NOT_ACCEPTED 2
#define MATTER_TIME_NONE 0
#define MATTER_TIME_MINUTES 1
#define MATTER_TIME_SECONDS 2
#define MATTER_TIME_MILLISECONDS 3
#define MATTER_TIME_MICROSECONDS 4
#define MATTER_TIME_SOURCE_UNKNOWN 1
#define MATTER_TIME_SOURCE_ADMIN 2
#define MATTER_TIME_SOURCE_MAX 16
#define MATTER_TIME_HOUR_MS UINT64_C(3600000)
typedef struct { uint64_t utc_us; uint8_t granularity,source; } Matter_Time_Sync_Sample_T;
typedef struct {
    void* user;
    /* Nonblocking owner-thread clock snapshot, microseconds since 2000. Unknown
     * clock returns OK with granularity/source=0. No monotonic clock changes. */
    Matter_Result_T (*sample)(void*,uint64_t now_ms,Matter_Time_Sync_Sample_T*);
    /* Atomic persistence of Last Known Good UTC + clock publication. Core has
     * downgraded granularity by one level (minimum Minutes); source is Admin.
     * Granularity=0 updates LKG only and publishes unknown UTC. Error leaves
     * backend unchanged. INVALID_STATE rejects policy (TimeNotAccepted); must
     * not reject a valid command solely for policy when current UTC is unknown.
     * Storage/driver errors map to Failure, never falsely report success. */
    Matter_Result_T (*set)(void*,uint64_t utc_us,uint8_t granularity,uint64_t now_ms);
    /* Attempt/retry acquisition using supported sources. Must return promptly;
     * asynchronous work is driven by the application and observed via sample.
     * Called initially and hourly while unknown (at least daily per Core). */
    void (*synchronize)(void*);
} Matter_Time_Sync_Port_T;
/* Root EP0 only. Rev2, FeatureMap=0, TimeSource present; no TZ/NTPC/NTPS/TSC.
 * Mandatory TimeFailure is published to borrowed node log; it outlives cluster.
 * Owner processes before IM, services deadlines and notifies subscriptions on
 * version changes. Continuous UTC ticking alone does not change DataVersion.
 * Constructor does not call ports. Backend owns clock drift assessment and LKG,
 * including build/certificate floors, restart recovery and certificate fallback. */
Matter_Cluster_T matter_time_sync_new(const Matter_Time_Sync_Port_T*,Matter_Events_T,uint32_t version,uint64_t now_ms);
#endif
