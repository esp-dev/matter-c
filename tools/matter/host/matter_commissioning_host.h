#ifndef MATTER_COMMISSIONING_HOST_COMPAT_H
#define MATTER_COMMISSIONING_HOST_COMPAT_H
#include "runtime/matter_commissioning_host.h"
#include "matter_wifi_sim.h"
static inline Matter_Commissioning_Host_T matter_commissioning_host_new(Matter_Commissioning_Host_Image_T i,
    Matter_Wifi_T w,Matter_Wifi_Sim_T sim,Matter_Opcreds_T c,Matter_Fabric_Host_T f,const Matter_Commissioning_Host_Port_T* p) {
    Matter_Wifi_Port_T port=matter_wifi_sim_port(sim);
    return sim?matter_commissioning_host_new_port(i,w,&port,c,f,p):NULL;
}
#endif
