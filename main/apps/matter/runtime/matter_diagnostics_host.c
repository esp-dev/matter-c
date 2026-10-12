#include "matter_diagnostics_host.h"
#include <stdlib.h>
#include <string.h>
struct Matter_Diagnostics_Host {
    Matter_Diagnostics_Host_Image_T* image; Matter_Diagnostics_Radio_Port_T radio;
    Matter_Diagnostics_Snapshot_T state; Matter_Wifi_Ap_T ap;
    bool advertising,fail_snapshot,fail_reset;
};
Matter_Diagnostics_Host_T matter_diagnostics_host_new_port(Matter_Diagnostics_Host_Image_T* image,const Matter_Diagnostics_Radio_Port_T* radio,
    const Matter_Diagnostics_Interface_T* iface,uint8_t reason,bool reboot,uint64_t now) {
    if(!image || image->attached || !radio || !radio->observe || !iface || reason>6 || iface->type!=1 || (!reboot && now<image->runtime.system_ms)) return NULL;
    Matter_Diagnostics_Host_T h=calloc(1,sizeof(*h)); if(!h) return NULL;
    h->image=image; h->radio=*radio; h->state.general.interfaces[0]=*iface; h->state.general.interface_count=1;
    h->state.general.boot_reason=reason;
    if(reboot) { memset(&image->runtime,0,sizeof(image->runtime)); if(image->reboots<UINT16_MAX) ++image->reboots; }
    /* No failure after allocation: process only updates the caller-owned RAM. */
    (void)matter_diagnostics_host_process(h,now);
    image->attached=true; return h;
}
Matter_Result_T matter_diagnostics_host_delete(Matter_Diagnostics_Host_T h) {
    if(!h) return MATTER_INVALID_ARGUMENT;
    h->image->attached=false; memset(h,0,sizeof(*h)); free(h); return MATTER_OK;
}
static Matter_Result_T snapshot(void* u,Matter_Diagnostics_Snapshot_T* out) {
    Matter_Diagnostics_Host_T h=u; if(h->fail_snapshot) return MATTER_PORT_ERROR;
    bool online=false; Matter_Result_T r=h->radio.observe(h->radio.user,&h->ap,&online); if(r!=MATTER_OK) return r;
    h->state.general.reboots=h->image->reboots; h->state.general.operational_hours=h->image->hours;
    h->state.general.system_ms=h->image->runtime.system_ms;
    h->state.general.total_subscriptions=h->image->runtime.total_subscriptions;
    h->state.general.im_sent=h->image->runtime.im_sent; h->state.general.im_received=h->image->runtime.im_received;
    memcpy(h->state.general.subscriptions,h->image->runtime.subscriptions,sizeof(h->state.general.subscriptions));
    memcpy(h->state.wifi.counts,h->image->runtime.counts,sizeof(h->state.wifi.counts));
    h->state.wifi.overruns=h->image->runtime.overruns;
    *out=h->state; out->wifi.online=online;
    /* Keep link association distinct from operational Matter advertising. */
    out->general.interfaces[0].operational=online && h->advertising;
    if(online) {
        memcpy(out->wifi.bssid,h->ap.bssid,6); out->wifi.channel=h->ap.channel; out->wifi.rssi=h->ap.rssi;
        uint8_t bits=h->ap.security;
        out->wifi.security=bits&16?5:bits&8?4:bits&4?3:bits&2?2:bits&1?1:0;
    }
    return MATTER_OK;
}
static Matter_Result_T reset(void* u) {
    Matter_Diagnostics_Host_T h=u; if(h->fail_reset) return MATTER_PORT_ERROR;
    memset(h->image->runtime.counts,0,sizeof(h->image->runtime.counts)); return MATTER_OK;
}
Matter_Diagnostics_Port_T matter_diagnostics_host_port(Matter_Diagnostics_Host_T h) { return (Matter_Diagnostics_Port_T){h,snapshot,reset}; }
Matter_Result_T matter_diagnostics_host_process(Matter_Diagnostics_Host_T h,uint64_t now) {
    if(!h || now<h->image->runtime.system_ms) return MATTER_INVALID_ARGUMENT;
    uint64_t hour=now/3600000,delta=hour-h->image->runtime.accounted_hour;
    h->image->hours=delta>UINT32_MAX-h->image->hours?UINT32_MAX:h->image->hours+(uint32_t)delta;
    h->image->runtime.accounted_hour=hour; h->image->runtime.system_ms=now; return MATTER_OK;
}
void matter_diagnostics_host_message(Matter_Diagnostics_Host_T h,bool tx) {
    if(h) { uint32_t* count=tx?&h->image->runtime.im_sent:&h->image->runtime.im_received; if(*count<UINT32_MAX) ++*count; }
}
Matter_Result_T matter_diagnostics_host_subscription(Matter_Diagnostics_Host_T h,uint8_t index,bool opened) {
    if(!h || !index || index==255) return MATTER_INVALID_ARGUMENT;
    Matter_Diagnostics_Subscriptions_T* slots=h->image->runtime.subscriptions; unsigned slot=5;
    for(unsigned i=0;i<5;++i) {
        if(slots[i].index==index) { slot=i; break; }
        if(!slots[i].index && slot==5) slot=i;
    }
    if(slot==5) return MATTER_LIMIT_REACHED;
    Matter_Diagnostics_Subscriptions_T* s=&slots[slot];
    if(!opened && (!s->index || !s->current)) return MATTER_INVALID_STATE;
    if(opened && s->current==UINT16_MAX) return MATTER_LIMIT_REACHED;
    s->index=index;
    if(opened) { ++s->current; if(h->image->runtime.total_subscriptions<UINT32_MAX) ++h->image->runtime.total_subscriptions; }
    else --s->current;
    return MATTER_OK;
}
void matter_diagnostics_host_remove_fabric(Matter_Diagnostics_Host_T h,uint8_t index) {
    if(h) for(unsigned i=0;i<5;++i) if(h->image->runtime.subscriptions[i].index==index) memset(&h->image->runtime.subscriptions[i],0,sizeof(h->image->runtime.subscriptions[i]));
}
void matter_diagnostics_host_advertising(Matter_Diagnostics_Host_T h,bool active) { if(h) h->advertising=active; }
Matter_Result_T matter_diagnostics_host_faults(Matter_Diagnostics_Host_T h,uint16_t hw,uint8_t radio,uint8_t network) {
    if(!h || hw>0x7ff || radio>0x7f || network>15) return MATTER_INVALID_ARGUMENT;
    h->state.general.hardware_faults=hw; h->state.general.radio_faults=radio; h->state.general.network_faults=network; return MATTER_OK;
}
void matter_diagnostics_host_packets(Matter_Diagnostics_Host_T h,unsigned counter,uint32_t delta) { if(h && counter<6) h->image->runtime.counts[counter]+=delta; }
void matter_diagnostics_host_overruns(Matter_Diagnostics_Host_T h,uint64_t delta) { if(h) h->image->runtime.overruns+=delta; }
void matter_diagnostics_host_radio(Matter_Diagnostics_Host_T h,uint8_t version,uint64_t rate) { if(h && version<=6) { h->state.wifi.version=version; h->state.wifi.max_rate=rate; } }
void matter_diagnostics_host_control(Matter_Diagnostics_Host_T h,bool fail_snapshot,bool fail_reset) { if(h) { h->fail_snapshot=fail_snapshot; h->fail_reset=fail_reset; } }
