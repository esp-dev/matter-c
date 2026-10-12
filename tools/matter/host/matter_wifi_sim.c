#include "matter_wifi_sim.h"
#include <stdlib.h>
#include <string.h>
struct Matter_Wifi_Sim {
    Matter_Wifi_Sim_Config_T config;
    Matter_Wifi_Sim_Control_T control;
    Matter_Wifi_Settings_T settings;
    Matter_Wifi_Id_T connected;
    Matter_Wifi_Network_T request;
    Matter_Wifi_Completion_T result;
    uint64_t now, due, token;
    unsigned starts;
    bool scan;
};
static void erase(void* p,size_t n) { volatile uint8_t* b=p; while(n--) *b++=0; }
Matter_Wifi_Sim_T matter_wifi_sim_new(const Matter_Wifi_Sim_Config_T* c,uint64_t now) {
    if(!c || c->count>MATTER_WIFI_SCAN_RESULTS || c->initial.count>MATTER_WIFI_NETWORKS || c->connected.size>32) return NULL;
    for(unsigned i=0;i<c->count;++i) if(c->aps[i].ap.ssid.size>32 || c->aps[i].credential_size>64 || c->aps[i].ap.band>5) return NULL;
    Matter_Wifi_Sim_T s=calloc(1,sizeof(*s)); if(s) { s->config=*c; s->settings=c->initial; s->connected=c->connected; s->now=now; } return s;
}
static Matter_Result_T load(void* u,Matter_Wifi_Settings_T* settings,Matter_Wifi_Id_T* connected) {
    Matter_Wifi_Sim_T s=u; *settings=s->settings; *connected=s->connected; return MATTER_OK;
}
static Matter_Result_T configure(void* u,const Matter_Wifi_Settings_T* settings) {
    Matter_Wifi_Sim_T s=u; if(s->control.fail_configure) return MATTER_PORT_ERROR;
    s->settings=*settings; if(!settings->enabled) s->connected.size=0; return MATTER_OK;
}
static Matter_Result_T start(void* u,uint64_t token,bool scan,const Matter_Wifi_Network_T* request) {
    Matter_Wifi_Sim_T s=u; if(s->token) return MATTER_BUSY;
    s->token=token; s->scan=scan; s->request=*request; ++s->starts;
    s->due=UINT64_MAX-s->now<s->config.latency_ms?UINT64_MAX:s->now+s->config.latency_ms; return MATTER_PENDING;
}
static Matter_Result_T cancel(void* u,uint64_t token) {
    Matter_Wifi_Sim_T s=u;
    if(s->token && s->token!=token) return MATTER_INVALID_STATE;
    if(s->token && s->control.hold_cancel) return MATTER_PENDING;
    s->token=0; erase(&s->request,sizeof(s->request)); return MATTER_OK;
}
static Matter_Result_T restore(void* u,const Matter_Wifi_Settings_T* settings,const Matter_Wifi_Id_T* connected) {
    Matter_Wifi_Sim_T s=u; if(s->control.fail_restore) return MATTER_PORT_ERROR;
    if(s->token) return MATTER_PENDING;
    s->settings=*settings; s->connected=*connected; return MATTER_OK;
}
Matter_Wifi_Port_T matter_wifi_sim_port(Matter_Wifi_Sim_T s) {
    return (Matter_Wifi_Port_T){s,load,configure,start,cancel,restore};
}
static bool match(const Matter_Wifi_Id_T* a,const Matter_Wifi_Id_T* b) { return a->size==b->size && !memcmp(a->bytes,b->bytes,a->size); }
Matter_Result_T matter_wifi_sim_process(Matter_Wifi_Sim_T s,Matter_Wifi_T wifi,uint64_t now) {
    if(!s || !wifi || now<s->now) return MATTER_INVALID_ARGUMENT;
    s->now=now; Matter_Result_T r=matter_wifi_process(wifi,now);
    if(r!=MATTER_OK && r!=MATTER_PENDING) return r;
    if(!s->token || s->control.hold || now<s->due) return s->token?MATTER_PENDING:MATTER_OK;
    memset(&s->result,0,sizeof(s->result)); int best=-1;
    for(unsigned i=0;i<s->config.count;++i) {
        Matter_Wifi_Sim_Ap_T* a=&s->config.aps[i];
        if(s->request.id.size && !match(&s->request.id,&a->ap.ssid)) continue;
        if(s->scan) {
            /* Insertion sort by RSSI, bounded to eight APs, no stack array. */
            unsigned at=s->result.count++;
            while(at && s->result.aps[at-1].rssi<a->ap.rssi) { s->result.aps[at]=s->result.aps[at-1]; --at; }
            s->result.aps[at]=a->ap;
        } else if(best<0 || a->ap.security>s->config.aps[best].ap.security ||
            (a->ap.security==s->config.aps[best].ap.security && a->ap.rssi>s->config.aps[best].ap.rssi)) best=(int)i;
    }
    if(s->scan) { if(s->request.id.size && !s->result.count) s->result.status=5; }
    else if(s->control.connect_status) { s->result.status=s->control.connect_status; s->result.has_error=true; s->result.error=s->control.error; }
    else if(best<0) s->result.status=5;
    else {
        Matter_Wifi_Sim_Ap_T* a=&s->config.aps[best];
        if(a->credential_size!=s->request.credential_size || memcmp(a->credentials,s->request.credentials,a->credential_size)) {
            s->result.status=7; s->result.has_error=true; s->result.error=13;
        }
    }
    r=matter_wifi_complete(wifi,s->token,&s->result);
    if(r!=MATTER_OK) return r;
    if(!s->scan) {
        if(!s->result.status) s->connected=s->request.id;
        else if(match(&s->connected,&s->request.id)) s->connected.size=0;
    }
    s->token=0; erase(&s->request,sizeof(s->request)); return MATTER_OK;
}
Matter_Result_T matter_wifi_sim_delete(Matter_Wifi_Sim_T s) {
    if(!s) return MATTER_INVALID_ARGUMENT;
    if(s->token) return MATTER_INVALID_STATE;
    erase(s,sizeof(*s)); free(s); return MATTER_OK;
}
void matter_wifi_sim_control(Matter_Wifi_Sim_T s,const Matter_Wifi_Sim_Control_T* c) { if(s && c) s->control=*c; }
const Matter_Wifi_Settings_T* matter_wifi_sim_settings(Matter_Wifi_Sim_T s) { return s?&s->settings:NULL; }
uint64_t matter_wifi_sim_token(Matter_Wifi_Sim_T s) { return s?s->token:0; }
unsigned matter_wifi_sim_starts(Matter_Wifi_Sim_T s) { return s?s->starts:0; }

const Matter_Wifi_Id_T* matter_wifi_sim_connected(Matter_Wifi_Sim_T s) { return s?&s->connected:NULL; }
Matter_Result_T matter_wifi_sim_observe(Matter_Wifi_Sim_T s,Matter_Wifi_Ap_T* out,bool* online) {
    if(!s || !out || !online) return MATTER_INVALID_ARGUMENT;
    *online=false; memset(out,0,sizeof(*out));
    if(!s->settings.enabled || !s->connected.size) return MATTER_OK;
    int best=-1;
    for(unsigned i=0;i<s->config.count;++i) {
        const Matter_Wifi_Ap_T* ap=&s->config.aps[i].ap;
        if(match(&ap->ssid,&s->connected) && (best<0 || ap->security>s->config.aps[best].ap.security ||
            (ap->security==s->config.aps[best].ap.security && ap->rssi>s->config.aps[best].ap.rssi))) best=(int)i;
    }
    if(best>=0) { *out=s->config.aps[best].ap; *online=true; }
    return MATTER_OK;
}
