#ifndef MATTER_OTA_REQUESTOR_H_INCLUDED
#define MATTER_OTA_REQUESTOR_H_INCLUDED 1
#include "../model/matter_cluster.h"
#include "../model/matter_events.h"
enum { MATTER_OTA_REQUESTOR_CLUSTER=0x2a, MATTER_OTA_PROVIDERS=5, MATTER_OTA_METADATA_MAX=512 };
typedef struct { uint64_t node; uint16_t endpoint; uint8_t fabric; } Matter_Ota_Provider_T;
typedef struct {
    Matter_Ota_Provider_T provider; bool announced; uint16_t vendor;
    uint8_t reason; size_t metadata_size; uint8_t metadata[MATTER_OTA_METADATA_MAX];
} Matter_Ota_Offer_T; /* Heap if retained by the application. */
typedef struct {
    void* user;
    /* Snapshot of all defaults, zero fabric denotes an empty slot. Atomic store
     * replaces/removes ONLY the authenticated fabric, before publishing RAM.
     * Remove defaults atomically with fabric removal/rollback. No reentry. */
    Matter_Result_T (*load)(void*,Matter_Ota_Provider_T out[MATTER_OTA_PROVIDERS]);
    Matter_Result_T (*store)(void*,uint8_t fabric,const Matter_Ota_Provider_T*); /* NULL removes */
    /* Nonzero incarnation of a live fabric; changes before index reuse. */
    uint64_t (*generation)(void*,uint8_t fabric);
    /* Owner process only. Copied offer is borrowed for this call. true selects;
     * false ignores. Selection is NOT permission to install, nor a QueryImage.
     * Bounded, nonblocking, no reentry. Scheduling/query policy belongs to owner,
     * including 1..600 s jitter for UrgentUpdateAvailable before QueryImage. */
    bool (*select)(void*,const Matter_Ota_Offer_T*);
} Matter_Ota_Requestor_Port_T;
/* Core 1.6.1 11.20.7 rev1. Demand-owned parser, encoding and pending offers; bounded allocation per operation.
 * One default and one pending announcement per fabric. Announcements never
 * overwrite defaults. Process before IM and after fabric mutations; defaults
 * refreshed from port, new/default changed offers delivered once. Latest queued
 * announcement per fabric wins. OOM leaves an old pending offer/default intact;
 * default-delivery OOM retries on process without blocking IM/ACK drain. Read encoding is borrowed until the
 * next read/process/state-event call or deletion; IM snapshots copy synchronously.
 * All calls serialized by application owner.
 * Root adapter enforces View/Administer ACL. Start/Write additionally require CASE.
 * Borrowed event log/user outlive cluster. Initial state Idle, progress null;
 * update_possible describes the actual backend capability (explicit signed host simulation: true).
 * No discovery, QueryImage client, BDX, verification or installation here. */
Matter_Cluster_T matter_ota_requestor_new(const Matter_Ota_Requestor_Port_T*,Matter_Events_T,
    uint32_t data_version,bool update_possible);
Matter_Result_T matter_ota_requestor_selected(Matter_Cluster_T,Matter_Ota_Provider_T*);
/* Owner reports actual backend state, never automatically from an announcement.
 * State enum 0..8, reason 0..4; progress -1=null or 0..100. Target is encoded only
 * for Downloading(4)/Applying(5)/RollingBack(7). Append failure leaves model intact. */
Matter_Result_T matter_ota_requestor_state(Matter_Cluster_T,bool possible,uint8_t state,
    int progress,uint8_t reason,uint32_t target_version,uint64_t now_ms);
Matter_Result_T matter_ota_requestor_applied(Matter_Cluster_T,uint32_t version,uint16_t product,uint64_t now_ms);
Matter_Result_T matter_ota_requestor_error(Matter_Cluster_T,uint32_t version,uint64_t bytes,
    int progress,const int64_t* platform_code,uint64_t now_ms);
#endif
