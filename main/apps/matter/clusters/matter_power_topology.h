#ifndef MATTER_POWER_TOPOLOGY_H_INCLUDED
#define MATTER_POWER_TOPOLOGY_H_INCLUDED 1
#include "../model/matter_cluster.h"
enum { MATTER_POWER_TOPOLOGY_CLUSTER=0x009c };
/* Core 1.6.1 11.8, revision1: fixed TREE profile, FeatureMap=2. Measurements
 * apply to this endpoint and its descendants (just itself on a leaf). No SET,
 * DYPF, AvailableEndpoints, ActiveEndpoints, commands, events or hardware port.
 * Immutable instance, application supplies randomized initial DataVersion.
 * Returns common owned handle; Root attachment pins it until Root deletion.
 * Independent heap state, no tasks/globals/I/O. NULL on allocation failure. */
Matter_Cluster_T matter_power_topology_new(uint32_t data_version);
#endif
