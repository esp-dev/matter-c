#ifndef MATTER_DIAGNOSTICS_H_INCLUDED
#define MATTER_DIAGNOSTICS_H_INCLUDED 1
#include "../model/matter_cluster.h"
enum { MATTER_DIAGNOSTICS_GENERAL=0x33, MATTER_DIAGNOSTICS_WIFI=0x36,
    MATTER_DIAGNOSTICS_GENERAL_ATTRS=15, MATTER_DIAGNOSTICS_WIFI_ATTRS=18 };
typedef struct {
    uint8_t name[32],name_size,hardware[8],ipv4[4][4],ipv6[8][16],ipv4_count,ipv6_count,type;
    /* Hardware address in wire order, zero-prefixed for six-byte MACs. */
    bool operational; int8_t reachable4,reachable6; /* -1=null, 0=false, 1=true */
} Matter_Diagnostics_Interface_T;
typedef struct { uint8_t index; uint16_t current; } Matter_Diagnostics_Subscriptions_T;
typedef struct {
    Matter_Diagnostics_Interface_T interfaces[8]; uint8_t interface_count,boot_reason;
    uint16_t reboots,hardware_faults; uint8_t radio_faults,network_faults; /* Enum bit sets. */
    uint64_t system_ms,posix_ms; bool posix_valid;
    uint32_t operational_hours,total_subscriptions,im_sent,im_received;
    Matter_Diagnostics_Subscriptions_T subscriptions[5];
    uint16_t unfabric_subscriptions; /* Active PASE subscriptions: total only, never an accessing fabric. */
} Matter_Diagnostics_General_T;
typedef struct {
    uint64_t max_rate,overruns;
    uint32_t counts[6]; /* Lost beacon, RX beacon, multicast RX/TX, unicast RX/TX. */
    uint16_t channel; uint8_t bssid[6],security,version; int8_t rssi;
    bool online;
} Matter_Diagnostics_Wifi_T;
typedef struct { Matter_Diagnostics_General_T general; Matter_Diagnostics_Wifi_T wifi; } Matter_Diagnostics_Snapshot_T;
typedef struct {
    void* user;
    /* Copy one consistent view, zero-initialized by caller. Large output is heap
     * owned by the model. Bounded/nonblocking, no reentry or retained pointers.
     * System Time is the node's clock, NOT elapsed service-instance lifetime. */
    Matter_Result_T (*snapshot)(void*,Matter_Diagnostics_Snapshot_T*);
    /* Atomically reset only six count attributes. Preserve OverrunCount/rate.
     * On failure no effects. Owner serializes telemetry and command execution. */
    Matter_Result_T (*reset_counts)(void*);
} Matter_Diagnostics_Port_T;
typedef Matter_Cluster_T Matter_Diagnostics_T;
typedef struct {
    void* user;
    uint8_t enable_key[16]; /* Nonzero, copied; never persisted by this cluster. */
    /* Bounded, serialized, no reentry. Unknown event -> INVALID_COMMAND;
     * failure must have no effects. User context outlives the cluster. */
    uint8_t (*trigger)(void*,uint64_t event);
} Matter_Diagnostics_Test_Trigger_T;
/* Explicit laboratory configuration, before serving requests. NULL disables.
 * Defaults disabled. Owner must remove trigger effects on last-fabric reset. */
Matter_Result_T matter_diagnostics_set_test_trigger(Matter_Diagnostics_T,const Matter_Diagnostics_Test_Trigger_T*);
/* Returns General Diagnostics, owning a Wi-Fi sibling and one shared snapshot.
 * Deleting the General handle releases both; a pinned/busy sibling prevents it.
 * Both clusters attached together: General rev3/FeatureMap0, Wi-Fi rev1/features3.
 * Test triggers disabled by default. BootReason registered; owner emits once per boot.
 * No task/OS/clock/global state. Port.user outlives the model. */
Matter_Cluster_T matter_diagnostics_new(const Matter_Diagnostics_Port_T*,uint32_t general_version,uint32_t wifi_version);
/* Emit BootReason from the current valid backend snapshot once per boot.
 * Call after Root StartUp; repeated success is a no-op, errors may be retried. */
Matter_Result_T matter_diagnostics_boot(Matter_Diagnostics_T,Matter_Events_T,uint64_t timestamp_ms);
/* Borrowed Wi-Fi sibling; lifetime owned by the General Diagnostics handle. */
Matter_Cluster_T matter_diagnostics_wifi(Matter_Diagnostics_T);
Matter_Result_T matter_diagnostics_delete(Matter_Diagnostics_T);
/* Owner refreshes BEFORE IM processing. Error invalidates live reads instead of
 * serving stale diagnostics; metadata remains available. Failed snapshots never
 * partially publish. Current handler copies retain their existing IM semantics. */
Matter_Result_T matter_diagnostics_refresh(Matter_Diagnostics_T);
bool matter_diagnostics_cluster(uint32_t);
const uint32_t* matter_diagnostics_attributes(uint32_t,size_t*);
Matter_Result_T matter_diagnostics_version(Matter_Diagnostics_T,uint32_t,uint32_t*);
uint8_t matter_diagnostics_read(Matter_Diagnostics_T,uint32_t,uint32_t,uint8_t fabric,Matter_Im_Value_T*);
uint8_t matter_diagnostics_command(Matter_Diagnostics_T,uint32_t,uint32_t,Matter_Im_Command_T*);
uint8_t matter_diagnostics_validate(Matter_Diagnostics_T,uint32_t,uint32_t,const uint8_t*,size_t);
/* Trusted adapter only, after live ACL and response capacity checks. */
Matter_Im_Command_Result_T matter_diagnostics_invoke(Matter_Diagnostics_T,uint32_t,uint32_t,const uint8_t*,size_t,Matter_Tlv_Writer_T*);
#endif
