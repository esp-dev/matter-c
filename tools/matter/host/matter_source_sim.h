#ifndef MATTER_SOURCE_SIM_H_INCLUDED
#define MATTER_SOURCE_SIM_H_INCLUDED 1
#include "clusters/matter_meter_source.h"
/* Synthetic application mapping. Keep on the owning Node heap, not task stack.
 * Metadata/key meanings are this example's schema, not standard Matter IDs. */
typedef struct {
    Matter_Source_Snapshot_T snapshot;
    Matter_Source_Channel_T channels[MATTER_SOURCE_MAX_CHANNELS]; size_t count;
} Matter_Source_Sim_T;
Matter_Cluster_T matter_source_sim_new(Matter_Source_Sim_T*,uint16_t vendor,uint32_t version,uint64_t now);
void matter_source_sim_sample(Matter_Source_Sim_T*,uint64_t now,uint64_t seconds,int64_t imported,int64_t exported);
#endif
