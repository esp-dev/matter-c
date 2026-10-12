#ifndef MATTER_DIAGNOSTICS_HOST_COMPAT_H
#define MATTER_DIAGNOSTICS_HOST_COMPAT_H
#include "runtime/matter_diagnostics_host.h"
#include "matter_wifi_sim.h"
static inline Matter_Result_T matter_diagnostics_sim_observe(void* u,Matter_Wifi_Ap_T* a,bool* online) {
    return matter_wifi_sim_observe(u,a,online);
}
static inline Matter_Diagnostics_Host_T matter_diagnostics_host_new(Matter_Diagnostics_Host_Image_T* i,Matter_Wifi_Sim_T sim,
    const Matter_Diagnostics_Interface_T* f,uint8_t reason,bool reboot,uint64_t now) {
    Matter_Diagnostics_Radio_Port_T p={sim,matter_diagnostics_sim_observe};
    return sim?matter_diagnostics_host_new_port(i,&p,f,reason,reboot,now):NULL;
}
#endif
