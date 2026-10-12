#ifndef MATTER_EEM_H_INCLUDED
#define MATTER_EEM_H_INCLUDED 1
#include "../model/matter_cluster.h"
#include "../model/matter_events.h"
enum { MATTER_EEM_CLUSTER=0x0091 };
#define MATTER_EEM_LIMIT (INT64_C(1)<<62)
/* Persist both directions atomically, independently of fabrics. This DTO is
 * NOT a disk format: backend serializes fields explicitly. Missing checkpoint
 * is all-zero. Corrupt/unreadable state must fail load, never silently reset. */
typedef struct {
    uint64_t generation; int64_t raw_mwh[2],total_mwh[2]; bool initialized;
    /* Register mode only; zero in legacy checkpoints. Persist explicitly. */
    bool registers; uint8_t register_mask;
} Matter_Eem_Checkpoint_T;
typedef struct {
    int64_t raw_mwh[2]; /* import, export: distinct nonnegative source registers */
    uint64_t generation,sampled_ms; uint32_t epoch_s;
    bool available,utc_known; /* coherent pair; epoch_s is seconds since 2000 */
    uint8_t available_mask; /* register mode: bits import=1/export=2; available=true means both */
} Matter_Eem_Sample_T;
typedef struct {
    void* user;
    /* Bounded owner-thread callbacks, no retention/reentry. load/store have
     * atomic durability semantics: successful store survives restart; failure
     * leaves previous state intact. App schedules storage off critical RX paths.
     * snapshot uses the same monotonic boot clock as refresh. */
    Matter_Result_T (*snapshot)(void*,Matter_Eem_Sample_T*);
    Matter_Result_T (*load)(void*,Matter_Eem_Checkpoint_T*);
    Matter_Result_T (*store)(void*,const Matter_Eem_Checkpoint_T*);
} Matter_Eem_Port_T;
typedef struct {
    uint16_t endpoint,percent_max; uint64_t fixed_max_mwh;
    uint32_t data_version,max_age_ms; bool measured;
    Matter_Events_T events; /* one node-owned log, borrowed */
} Matter_Eem_Config_T;
/* App1.6.1 2.12/rev2, IMPE|EXPE|CUME. One Accuracy range [0,2^62],
 * ElectricalEnergy, PercentMax and FixedMax, both configured by application.
 * Read-only Accuracy, nullable cumulative import/export, five globals, INFO
 * CumulativeEnergyMeasured. Optional CumulativeEnergyReset omitted.
 * Factory loads/validates checkpoint; starts at null until fresh measurement.
 * First ever sample establishes source baseline and cumulative zero (feature
 * introduction). Strictly increasing source generation rebases BOTH registers
 * without altering cumulative totals; the unobserved replacement gap is not
 * estimated. A decreasing register in the same generation is an error.
 * Do not change generation just because parser reset/reconnected. Backend must
 * distinguish replacement/reset and keep generation stable across reboots. */
Matter_Cluster_T matter_eem_new(const Matter_Eem_Port_T*,const Matter_Eem_Config_T*,uint64_t now_ms);
/* Explicit physical-register view. First sample reports raw_mwh, without a
 * zero baseline. Initialized checkpoints from the other mode are rejected.
 * A higher generation confirms meter replacement/reset; old totals are not
 * added to the new registers. Missing directions remain null independently.
 * Optional reset attribute reports unknown reset times (not sample/boot time).
 * Complete-pair snapshots generate CumulativeEnergyMeasured. Partial source
 * updates only update available attributes; no incomplete/nonconforming event
 * is emitted. Both directions remain configured capabilities (FeatureMap=7).
 * Source identity/generation and reset authorization belong to the backend. */
Matter_Cluster_T matter_eem_new_registers(const Matter_Eem_Port_T*,const Matter_Eem_Config_T*,uint64_t now_ms);
Matter_Result_T matter_eem_from_kwh(double,int64_t* milliwatt_hours);
/* Owner pumps before IM and >=once/s. Accept at most one coherent snapshot/s;
 * unavailable/stale/error -> both null, without erasing checkpoint. State is
 * persisted BEFORE publication. Events contain the same snapshot as attributes;
 * log/storage failure -> PORT_ERROR/null, retry on next pump. No lost accepted
 * delta: retry continues from durable checkpoint, never adds it twice.
 * Timestamps are measurement time; event record timestamp is capture time.
 * DataVersion changes on wire changes, including timestamps/null. report_ready
 * coalesces changes at >=1s intervals; consume even on PORT_ERROR. No implicit
 * scheduling/subscriptions. Reentry/backward clock rejected without changes.
 * Common cluster_delete; log and port.user outlive the cluster. */
Matter_Result_T matter_eem_refresh(Matter_Cluster_T,uint64_t now_ms,bool* report_ready);
#endif
