#ifndef MATTER_METER_SOURCE_H_INCLUDED
#define MATTER_METER_SOURCE_H_INCLUDED 1
#include "../model/matter_cluster.h"

/* Application-defined meter source extension, not a CSA standard cluster.
 * Configuration owns the vendor namespace and stable channel keys. No product,
 * parser, RTOS, hardware, storage or clock dependency. See doc/meter-source.md. */
enum { MATTER_SOURCE_MAX_CHANNELS=64, MATTER_SOURCE_METADATA_FIELDS=10,
    MATTER_SOURCE_TEXT_BYTES=100, MATTER_SOURCE_VOLUMES=4 };
enum { MATTER_SOURCE_REGISTERS=2, MATTER_SOURCE_DIRECTIONAL=3,
    MATTER_SOURCE_DEMAND=4, MATTER_SOURCE_VOLUME=5 };
enum { MATTER_SOURCE_UNKNOWN_UNIT=0, MATTER_SOURCE_WH=1, MATTER_SOURCE_VARH=2,
    MATTER_SOURCE_W=3, MATTER_SOURCE_VAR=4, MATTER_SOURCE_VA=5,
    MATTER_SOURCE_V=6, MATTER_SOURCE_A=7, MATTER_SOURCE_RATIO=8,
    MATTER_SOURCE_M3=9, MATTER_SOURCE_LITRE=10 };
enum { MATTER_SOURCE_UNKNOWN_ORIGIN=0, MATTER_SOURCE_MEASURED=1,
    MATTER_SOURCE_DERIVED=2, MATTER_SOURCE_SYNTHETIC=3 };
enum { MATTER_SOURCE_UNAVAILABLE=0, MATTER_SOURCE_FRESH=1,
    MATTER_SOURCE_STALE=2, MATTER_SOURCE_INVALID=3 };
#define MATTER_SOURCE_LIMIT (INT64_C(1)<<62)
typedef struct {
    uint16_t key;
    uint8_t group,quantity,phase,tariff,direction,quadrant,unit;
    int8_t exponent; /* value * 10^exponent in the declared base unit, -6..6 */
} Matter_Source_Channel_T;
typedef struct { uint8_t size; char text[MATTER_SOURCE_TEXT_BYTES]; bool known; } Matter_Source_Text_T;
typedef struct { int64_t value; bool available; uint8_t origin; } Matter_Source_Value_T;
typedef struct {
    uint64_t generation,sequence,sampled_ms,interval_ms;
    uint32_t status,epoch_s; bool online,utc_known;
    uint8_t tariff; /* 0 unknown, otherwise source register number (not a price) */
    int64_t conversion_mantissa; int8_t conversion_exponent; bool conversion_known;
    bool link_flags_known,encryption,authentication;
    Matter_Source_Text_T metadata[MATTER_SOURCE_METADATA_FIELDS];
    Matter_Source_Value_T values[MATTER_SOURCE_MAX_CHANNELS]; /* configuration order */
    struct { Matter_Source_Text_T id; uint32_t epoch_s,type; bool utc_known,type_known; } volume[MATTER_SOURCE_VOLUMES];
} Matter_Source_Snapshot_T;
typedef struct {
    uint16_t vendor,cluster_suffix; /* vendor 1..FFF4; suffix FC00..FFFE */
    uint32_t data_version,max_age_ms;
    const Matter_Source_Channel_T* channels; size_t count;
} Matter_Source_Config_T;
typedef struct {
    void* user;
    /* Copy one coherent snapshot into zeroed, cluster-owned heap workspace.
     * Bounded owner-thread callback, no allocation/I/O/reentry or retained pointers.
     * Conversion was already applied upstream; do not apply it here again. */
    Matter_Result_T (*snapshot)(void*,Matter_Source_Snapshot_T*);
} Matter_Source_Port_T;
/* Copies config. Revision 1, read-only attributes 0..5 and five globals. Starts
 * unavailable. Metadata indices/quantity IDs/key mapping belong to application.
 * List membership/order is immutable. Volume keys are 0..3; no inferred units.
 * Common cluster_delete, callback user outlives handle; no callback from new. */
Matter_Cluster_T matter_meter_source_new(const Matter_Source_Port_T*,const Matter_Source_Config_T*,uint64_t now_ms);
/* Publish atomically after validating/encoding the complete snapshot. Each list
 * carries generation/sequence; IM copies a list before chunking. Cross-attribute
 * reads are NOT one atomic IM transaction: compare versions/sequence to correlate.
 * Callback/validation error makes values null and quality INVALID, preserving
 * last good source identity; stale/offline becomes STALE/UNAVAILABLE. No writes
 * to persistent meter registers. Equal sequence must describe identical data;
 * decreased generation/sequence/time is rejected. Backward owner clock/reentry
 * leaves state unchanged. One version bump per encoded change, readiness <=1/s;
 * caller consumes ready even on PORT_ERROR and notifies subscriptions. */
Matter_Result_T matter_meter_source_refresh(Matter_Cluster_T,uint64_t now_ms,bool* ready);
/* Optional boundary helpers. No mutation on invalid input. Scale applies once;
 * integer sources should bypass double. Unix seconds -> Matter epoch 2000. */
Matter_Result_T matter_meter_source_scale(double value,int8_t exponent,int64_t* out);
Matter_Result_T matter_meter_source_epoch(int64_t unix_seconds,uint32_t* out);
#endif
