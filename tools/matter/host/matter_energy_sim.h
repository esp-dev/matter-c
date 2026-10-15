#ifndef MATTER_ENERGY_SIM_H
#define MATTER_ENERGY_SIM_H 1
#include "clusters/matter_eem.h"
/* Host-only, per-instance laboratory source. Owner serializes all calls.
 * No allocations, clocks, storage, hardware or changes to cluster callbacks. */
typedef struct {
    int64_t raw[2],power;
    uint64_t remainder[2],last,epoch;
    uint64_t normal_mw[2];
    unsigned mode;
} Matter_Energy_Sim_T;
Matter_Result_T matter_energy_sim_init(Matter_Energy_Sim_T*,const int64_t raw[2],uint64_t now);
/* Normal source rates, used after STOP; preserves the host profile's registers. */
Matter_Result_T matter_energy_sim_init_rates(Matter_Energy_Sim_T*,const int64_t raw[2],const uint64_t normal_mw[2],uint64_t now);
Matter_Result_T matter_energy_sim_sample(Matter_Energy_Sim_T*,uint64_t now);
/* CSA energy PIXIT: 0x0091000000000000 stop, +1 load1kW/2s, +2 generator3kW/5s.
 * Accepts target EP1 in bits32..47 and the legacy zero-endpoint form.
 * Unknown/time/overflow failures have no effects, including the counters. */
uint8_t matter_energy_sim_trigger(Matter_Energy_Sim_T*,uint64_t event,uint64_t now);
#endif
