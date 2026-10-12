#ifndef MATTER_WIFI_H_INCLUDED
#define MATTER_WIFI_H_INCLUDED 1
#include "../model/matter_cluster.h"
/* Core 1.6.1 supplied PDF 11.9, rev2, WI only. Single concurrent-commissioning
 * interface. Fixed bounds, binary SSIDs, no radio/OS/task in this module. */
enum { MATTER_WIFI_NETWORKS=4, MATTER_WIFI_SCAN_RESULTS=8, MATTER_WIFI_CLUSTER=0x31,
    MATTER_WIFI_ATTRIBUTE_COUNT=14, MATTER_WIFI_BUSY=0x9c, MATTER_WIFI_FAILSAFE_REQUIRED=0xca };
typedef struct { uint8_t size, bytes[32]; } Matter_Wifi_Id_T;
typedef struct { Matter_Wifi_Id_T id; uint8_t credential_size, credentials[64]; } Matter_Wifi_Network_T;
typedef struct { uint8_t count; bool enabled; Matter_Wifi_Network_T networks[MATTER_WIFI_NETWORKS]; } Matter_Wifi_Settings_T;
typedef struct { Matter_Wifi_Id_T ssid; uint8_t security,bssid[6],band; uint16_t channel; int8_t rssi; } Matter_Wifi_Ap_T;
typedef struct {
    uint8_t max_networks, scan_seconds, connect_seconds, bands; /* bands bitmap bits 0..5, nonzero */
    uint32_t data_version;
    uint64_t token_seed; /* application-unique across replacement backend/context lifetimes */
} Matter_Wifi_Config_T;
typedef struct {
    uint8_t status; /* Core NetworkCommissioningStatusEnum 0..12 */
    bool has_error; int32_t error;
    uint8_t count; Matter_Wifi_Ap_T aps[MATTER_WIFI_SCAN_RESULTS];
} Matter_Wifi_Completion_T;
typedef struct {
    void* user;
    Matter_Result_T (*load)(void*, Matter_Wifi_Settings_T*, Matter_Wifi_Id_T* connected);
    /* Atomic bounded stage of complete settings; error leaves backend unchanged.
     * Does NOT connect on add/remove/reorder. Enabled=false disables interface.
     * Real slow storage needs adapter staging, never a wait in this callback. */
    Matter_Result_T (*configure)(void*, const Matter_Wifi_Settings_T*);
    /* start must copy input before returning. PENDING accepts token; other
     * results reject without effects. Completion is explicitly delivered by
     * owner to complete(), never inline or through an IM handler pointer.
     * Scan with empty id scans ALL supported bands, nonempty id is directed.
     * Connect includes association+IPv6 readiness and contextual security/PSK
     * selection. Only one operation on this interface; backend owns radio work. */
    Matter_Result_T (*start)(void*, uint64_t token, bool scan, const Matter_Wifi_Network_T*);
    /* Idempotent cancellation progress. OK guarantees no remaining effects or
     * borrowed storage; PENDING/error prevents reuse/delete/rollback. */
    Matter_Result_T (*cancel)(void*, uint64_t token);
    /* Restore settings AND previous connectivity; may return PENDING while
     * reconnecting. No retained input pointers. OK means restoration complete.
     * Durable recovery journal belongs to application (GC begin/cleanup). */
    Matter_Result_T (*restore)(void*, const Matter_Wifi_Settings_T*, const Matter_Wifi_Id_T*);
} Matter_Wifi_Port_T;
typedef Matter_Cluster_T Matter_Wifi_T; /* Compatibility name; state is private. */
Matter_Cluster_T matter_wifi_new(const Matter_Wifi_Config_T*, const Matter_Wifi_Port_T*, uint64_t now_ms);
Matter_Result_T matter_wifi_delete(Matter_Wifi_T);
/* Owner thread only. Process current time BEFORE IM and complete(), even on
 * silent network. At deadline cancellation wins over a simultaneous completion.
 * Results copied; stale/duplicate token rejected. Backend never retains core
 * pointers. All buffers/settings/scan workspaces are in per-instance heap. */
Matter_Result_T matter_wifi_process(Matter_Wifi_T, uint64_t now_ms);
Matter_Result_T matter_wifi_deadline(Matter_Wifi_T, uint64_t*);
Matter_Result_T matter_wifi_complete(Matter_Wifi_T, uint64_t token, const Matter_Wifi_Completion_T*);
/* GC begin calls checkpoint only after creating its durable recovery journal.
 * GC cleanup revokes/drains PASE, then calls rollback until OK, THEN clears its
 * journal. Snapshot is RAM only. Boot recovery is the application's durable
 * restore before load/new; this is not a flash crash-recovery implementation. */
Matter_Result_T matter_wifi_checkpoint(Matter_Wifi_T);
/* Transaction coordinator: preflight all participants under one owner, then
 * commit without callbacks/allocations/interleaving. Failure preserves snapshot.
 * Does not by itself commit any platform journal or retire sessions. */
Matter_Result_T matter_wifi_commit_ready(Matter_Wifi_T);
Matter_Result_T matter_wifi_commit(Matter_Wifi_T);
Matter_Result_T matter_wifi_rollback(Matter_Wifi_T);
Matter_Result_T matter_wifi_stop(Matter_Wifi_T); /* cancel/detach, bounded drain */
/* Root adapter surface; same storage, no second protocol implementation. */
bool matter_wifi_take_breadcrumb(Matter_Wifi_T, uint64_t*); /* Root consumes once before IM admission. */
extern const uint32_t matter_wifi_attributes[MATTER_WIFI_ATTRIBUTE_COUNT];
uint8_t matter_wifi_describe(Matter_Wifi_T, uint32_t attribute, Matter_Im_Attribute_T*);
uint8_t matter_wifi_read(Matter_Wifi_T, uint32_t attribute, Matter_Im_Value_T*);
uint32_t matter_wifi_version(Matter_Wifi_T);
uint8_t matter_wifi_write_validate(Matter_Wifi_T, const uint8_t*, size_t);
uint8_t matter_wifi_write(Matter_Wifi_T, const uint8_t*, size_t);
uint8_t matter_wifi_command(Matter_Wifi_T, uint32_t command, Matter_Im_Command_T*);
uint8_t matter_wifi_validate(Matter_Wifi_T, uint32_t command, const uint8_t*, size_t);
typedef struct { Matter_Im_Command_Result_T result; bool breadcrumb; uint64_t value; } Matter_Wifi_Reply_T;
Matter_Result_T matter_wifi_invoke(Matter_Wifi_T, uint32_t command, bool armed,
    const uint8_t*, size_t, Matter_Tlv_Writer_T*, Matter_Wifi_Reply_T*, uint64_t* token);
Matter_Result_T matter_wifi_poll(Matter_Wifi_T, uint64_t token, Matter_Tlv_Writer_T*, Matter_Wifi_Reply_T*);
void matter_wifi_cancel(Matter_Wifi_T, uint64_t token);
#endif
