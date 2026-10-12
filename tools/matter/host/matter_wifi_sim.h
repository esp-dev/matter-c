#ifndef MATTER_WIFI_SIM_H_INCLUDED
#define MATTER_WIFI_SIM_H_INCLUDED 1
#include "clusters/matter_wifi.h"
/* Deterministic radio simulation, NOT the IPv6 transport (that remains real).
 * No sleep/thread, explicitly pumped on the application's owner thread. */
typedef struct { Matter_Wifi_Ap_T ap; uint8_t credential_size, credentials[64]; } Matter_Wifi_Sim_Ap_T;
typedef struct {
    Matter_Wifi_Settings_T initial;
    Matter_Wifi_Id_T connected;
    uint8_t count; Matter_Wifi_Sim_Ap_T aps[MATTER_WIFI_SCAN_RESULTS];
    uint32_t latency_ms;
} Matter_Wifi_Sim_Config_T;
typedef struct {
    bool hold, hold_cancel, fail_configure, fail_restore;
    uint8_t connect_status; /* nonzero injects connection failure */
    int32_t error;
} Matter_Wifi_Sim_Control_T;
typedef struct Matter_Wifi_Sim* Matter_Wifi_Sim_T;
Matter_Wifi_Sim_T matter_wifi_sim_new(const Matter_Wifi_Sim_Config_T*, uint64_t now_ms);
Matter_Wifi_Port_T matter_wifi_sim_port(Matter_Wifi_Sim_T);
Matter_Result_T matter_wifi_sim_process(Matter_Wifi_Sim_T, Matter_Wifi_T, uint64_t now_ms);
Matter_Result_T matter_wifi_sim_delete(Matter_Wifi_Sim_T);
void matter_wifi_sim_control(Matter_Wifi_Sim_T, const Matter_Wifi_Sim_Control_T*);
const Matter_Wifi_Settings_T* matter_wifi_sim_settings(Matter_Wifi_Sim_T);
const Matter_Wifi_Id_T* matter_wifi_sim_connected(Matter_Wifi_Sim_T);
/* Copy telemetry from the same simulated association selected by ConnectNetwork.
 * Unknown preconfigured AP returns online=false (no invented radio metrics). */
Matter_Result_T matter_wifi_sim_observe(Matter_Wifi_Sim_T,Matter_Wifi_Ap_T*,bool* online);
uint64_t matter_wifi_sim_token(Matter_Wifi_Sim_T);
unsigned matter_wifi_sim_starts(Matter_Wifi_Sim_T);
#endif
