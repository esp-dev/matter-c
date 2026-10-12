#ifndef MATTER_SWITCH_SIM_H_INCLUDED
#define MATTER_SWITCH_SIM_H_INCLUDED 1
#include "model/matter_cluster.h"
/* Host-only UI test: basic On/Off cluster, NOT a complete plug device profile.
 * State starts OFF on every boot. No hardware, storage, global state or tasks.
 * Callback/ctx are borrowed for the lifetime of the returned cluster.
 * The normal Root/CASE adapters enforce View/Operate privileges. */
Matter_Cluster_T matter_switch_sim_new(uint32_t version, void (*changed)(void*,bool), void* ctx);
#endif
