#ifndef MATTER_DIAGNOSTICS_HOST_H_INCLUDED
#define MATTER_DIAGNOSTICS_HOST_H_INCLUDED 1
#include "../clusters/matter_diagnostics.h"
#include "../clusters/matter_wifi.h"
/* Application-owned RAM checkpoint for now. Schema is NOT a binary storage
 * format: atomic TLV blob adapters persist the checkpoint.
 * Do not clear at service restart/fabric removal; factory reset owns reset. */
typedef struct {
    uint32_t hours; uint16_t reboots; /* Persistent fields. */
    bool attached;
    /* Node-lifetime RAM, not serialized. Retain across service recreation and
     * clear only on reboot. Owner closes subscriptions when stopping service. */
    struct {
        uint64_t system_ms,accounted_hour,overruns;
        uint32_t counts[6],total_subscriptions,im_sent,im_received;
        Matter_Diagnostics_Subscriptions_T subscriptions[5];
    } runtime;
} Matter_Diagnostics_Host_Image_T;
typedef struct Matter_Diagnostics_Host* Matter_Diagnostics_Host_T;
/* Borrow image/radio port through delete. Copy interface description (SIMULATED radio,
 * not host adapter enumeration). reboot=true only at node boot, never at wake
 * or service recreation. now is the application's node System Time clock. */
typedef struct {
    void* user;
    Matter_Result_T (*observe)(void*,Matter_Wifi_Ap_T*,bool* online);
} Matter_Diagnostics_Radio_Port_T;
Matter_Diagnostics_Host_T matter_diagnostics_host_new_port(Matter_Diagnostics_Host_Image_T*,const Matter_Diagnostics_Radio_Port_T*,
    const Matter_Diagnostics_Interface_T*,uint8_t boot_reason,bool reboot,uint64_t now_ms);
Matter_Result_T matter_diagnostics_host_delete(Matter_Diagnostics_Host_T);
Matter_Diagnostics_Port_T matter_diagnostics_host_port(Matter_Diagnostics_Host_T);
Matter_Result_T matter_diagnostics_host_process(Matter_Diagnostics_Host_T,uint64_t now_ms);
/* Owner notifications: first successful IM TX / accepted nonduplicate IM RX.
 * Do not count retries, secure ACKs, CASE/PASE or failed transport submissions. */
void matter_diagnostics_host_message(Matter_Diagnostics_Host_T,bool tx);
Matter_Result_T matter_diagnostics_host_subscription(Matter_Diagnostics_Host_T,uint8_t fabric,bool opened);
/* Retire all fabric subscriptions when fabric is removed. */
void matter_diagnostics_host_remove_fabric(Matter_Diagnostics_Host_T,uint8_t);
/* Simulated platform signals. Advertising is separate from Wi-Fi association.
 * Wi-Fi counters wrap at type width; DeviceLoad counters saturate. */
void matter_diagnostics_host_advertising(Matter_Diagnostics_Host_T,bool);
Matter_Result_T matter_diagnostics_host_faults(Matter_Diagnostics_Host_T,uint16_t hardware,uint8_t radio,uint8_t network);
void matter_diagnostics_host_packets(Matter_Diagnostics_Host_T,unsigned counter,uint32_t delta);
void matter_diagnostics_host_overruns(Matter_Diagnostics_Host_T,uint64_t delta);
void matter_diagnostics_host_radio(Matter_Diagnostics_Host_T,uint8_t version,uint64_t rate);
void matter_diagnostics_host_control(Matter_Diagnostics_Host_T,bool fail_snapshot,bool fail_reset);
#endif
