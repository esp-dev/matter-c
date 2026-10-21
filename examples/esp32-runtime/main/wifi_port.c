#include "wifi_port.h"
#include "esp_wifi.h"
#include "esp_netif_ip_addr.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include <stdlib.h>
#include <string.h>
typedef struct {
    uint64_t token; bool scan,started,cancelled,scan_stop;
    Matter_Wifi_Network_T network; Matter_Wifi_Completion_T result;
} Job;
struct Lab_Wifi {
    esp_netif_t* iface; Matter_Wifi_Settings_T settings; Matter_Wifi_Id_T connected,target;
    Job* job; bool restoring,initializing,force,apply,stopped; esp_err_t last_error;
    portMUX_TYPE lock; bool scan_done; esp_event_handler_instance_t handler;
};
static void scan_event(void* user,esp_event_base_t base,int32_t id,void* event) {
    (void)base; (void)id; (void)event; Lab_Wifi_T w=user;
    portENTER_CRITICAL(&w->lock); w->scan_done=true; portEXIT_CRITICAL(&w->lock);
}
static bool scan_done(Lab_Wifi_T w,bool clear) {
    portENTER_CRITICAL(&w->lock); bool ready=w->scan_done;
    if(clear) w->scan_done=false;
    portEXIT_CRITICAL(&w->lock); return ready;
}
static bool same(const Matter_Wifi_Id_T* a,const Matter_Wifi_Id_T* b) {
    return a->size==b->size && !memcmp(a->bytes,b->bytes,a->size);
}
static bool online(Lab_Wifi_T w,const Matter_Wifi_Id_T* target) {
    wifi_ap_record_t ap; esp_ip6_addr_t ip;
    return esp_wifi_sta_get_ap_info(&ap)==ESP_OK && target->size &&
        strnlen((const char*)ap.ssid,sizeof(ap.ssid))==target->size &&
        !memcmp(ap.ssid,target->bytes,target->size) && esp_netif_get_ip6_linklocal(w->iface,&ip)==ESP_OK;
}
static void wipe(void* p,size_t n) { volatile uint8_t* b=p; while(n--) *b++=0; }
static Matter_Result_T load(void* u,Matter_Wifi_Settings_T* s,Matter_Wifi_Id_T* c) {
    Lab_Wifi_T w=u; *s=w->settings; *c=w->connected; return MATTER_OK;
}
static Matter_Result_T configure(void* u,const Matter_Wifi_Settings_T* s) {
    Lab_Wifi_T w=u; if(s->count>MATTER_WIFI_NETWORKS) return MATTER_INVALID_ARGUMENT;
    w->settings=*s; if(!s->enabled) { w->target.size=0; w->apply=true; } return MATTER_OK;
}
static Matter_Result_T start(void* u,uint64_t token,bool scan,const Matter_Wifi_Network_T* n) {
    Lab_Wifi_T w=u; if(w->job || w->restoring) return MATTER_BUSY;
    Job* job=calloc(1,sizeof(*job)); if(!job) return MATTER_LIMIT_REACHED;
    job->token=token; job->scan=scan; job->network=*n; w->job=job; return MATTER_PENDING;
}
static Matter_Result_T cancel(void* u,uint64_t token) {
    Lab_Wifi_T w=u; if(!w->job) return MATTER_OK;
    if(w->job->token!=token) return MATTER_INVALID_STATE;
    w->job->cancelled=true; return MATTER_PENDING;
}
static Matter_Result_T restore(void* u,const Matter_Wifi_Settings_T* s,const Matter_Wifi_Id_T* c) {
    Lab_Wifi_T w=u; if(w->job) return MATTER_PENDING;
    if(!w->restoring) { w->settings=*s; w->target=*c; w->restoring=true; w->apply=true; }
    if(w->apply) return MATTER_PENDING;
    wifi_ap_record_t ap;
    if((!c->size && esp_wifi_sta_get_ap_info(&ap)!=ESP_OK) || (s->enabled && same(c,&w->connected) && online(w,c))) {
        w->restoring=false; return MATTER_OK;
    }
    return MATTER_PENDING;
}
static Matter_Result_T initialize(void* u,const Matter_Wifi_Settings_T* s,const Matter_Wifi_Id_T* c) {
    Lab_Wifi_T w=u; w->settings=*s; w->target=*c;
    if(!online(w,c)) { w->connected.size=0; w->apply=true; w->initializing=true; }
    return MATTER_OK;
}
static esp_err_t connect_to(Lab_Wifi_T w,const Matter_Wifi_Network_T* n) {
    wifi_config_t* cfg=calloc(1,sizeof(*cfg)); if(!cfg) return ESP_ERR_NO_MEM;
    memcpy(cfg->sta.ssid,n->id.bytes,n->id.size); memcpy(cfg->sta.password,n->credentials,n->credential_size);
    cfg->sta.threshold.authmode=n->credential_size?WIFI_AUTH_WPA2_PSK:WIFI_AUTH_OPEN;
    /* An already-associated same-SSID AP must not masquerade as completion of
     * the new request. Stop is an effects barrier before the new association;
     * perform it only in the application pump, never in the port callback. */
    esp_err_t e=esp_wifi_stop();
    if(e==ESP_ERR_WIFI_NOT_STARTED) e=ESP_OK;
    if(!e) e=esp_wifi_start();
    if(!e) e=esp_wifi_set_config(WIFI_IF_STA,cfg);
    wipe(cfg,sizeof(*cfg)); free(cfg);
    if(!e) { (void)esp_netif_create_ip6_linklocal(w->iface); e=esp_wifi_connect(); }
    return e;
}
static Matter_Result_T process(void* u,Matter_Wifi_T model,uint64_t now) {
    Lab_Wifi_T w=u; Matter_Result_T r=matter_wifi_process(model,now);
    if(r!=MATTER_OK && r!=MATTER_PENDING) return r;
    if(w->job && w->job->cancelled) {
        if(w->job->scan && w->job->started && !scan_done(w,false)) {
            if(!w->job->scan_stop) {
                esp_err_t e=esp_wifi_scan_stop();
                if(e!=ESP_OK) return MATTER_PENDING;
                w->job->scan_stop=true;
            }
            return MATTER_PENDING;
        }
        if(w->job->scan) {
            (void)esp_wifi_clear_ap_list();
            wipe(w->job,sizeof(*w->job)); free(w->job); w->job=NULL;
            return MATTER_OK; /* Scanning cancellation must not break live UDP. */
        }
        /* Driver stop is a synchronous effects barrier; queued SDK events carry
         * no model/token pointers and are never used to complete a new job. */
        if(esp_wifi_stop()!=ESP_OK) return MATTER_PENDING;
        w->connected.size=0; wipe(w->job,sizeof(*w->job)); free(w->job); w->job=NULL;
        if(esp_wifi_start()!=ESP_OK) { w->stopped=true; return MATTER_PORT_ERROR; }
        return MATTER_OK;
    }
    if(w->stopped) return MATTER_OFFLINE;
    if(w->apply && !w->job) {
        w->last_error=ESP_OK;
        if(!w->settings.enabled || !w->target.size) {
            w->last_error=esp_wifi_disconnect();
            if(w->last_error==ESP_ERR_WIFI_NOT_CONNECT) w->last_error=ESP_OK;
            if(!w->last_error) w->connected.size=0;
        } else {
            bool found=false;
            for(unsigned i=0;i<w->settings.count;++i) if(same(&w->target,&w->settings.networks[i].id)) {
                found=true;
                if(w->force || !online(w,&w->target)) w->last_error=connect_to(w,&w->settings.networks[i]);
                if(!w->last_error) w->force=false;
                break;
            }
            if(!found) w->last_error=ESP_ERR_NOT_FOUND;
        }
        if(!w->last_error) w->apply=false;
    }
    if(w->target.size && online(w,&w->target)) w->connected=w->target;
    else w->connected.size=0;
    if(w->initializing) {
        wifi_ap_record_t ap;
        bool ready=w->target.size?same(&w->target,&w->connected):esp_wifi_sta_get_ap_info(&ap)!=ESP_OK;
        if(ready && !w->apply) w->initializing=false;
        else return MATTER_PENDING;
    }
    if(!w->job) return w->last_error?MATTER_PENDING:MATTER_OK;
    Job* job=w->job;
    if(!job->started) {
        esp_err_t e;
        if(job->scan) {
            (void)scan_done(w,true);
            wifi_scan_config_t cfg={0};
            /* SDK scan expects a terminated SSID; scan all then binary-filter
             * in the owner, preserving the 32-byte SSID limit. */
            e=esp_wifi_scan_start(&cfg,false);
        } else { w->target=job->network.id; e=connect_to(w,&job->network); }
        if(e) { job->result.status=12; job->result.has_error=true; job->result.error=e; }
        else { job->started=true; return MATTER_PENDING; }
    } else if(job->scan) {
        if(!scan_done(w,false)) return MATTER_PENDING;
        uint16_t count=0; esp_err_t e=esp_wifi_scan_get_ap_num(&count);
        if(e) return MATTER_PENDING;
        wifi_ap_record_t* aps=count?calloc(count>8?8:count,sizeof(*aps)):NULL;
        if(count && !aps) { job->result.status=12; (void)esp_wifi_clear_ap_list(); }
        else {
            if(count>8) count=8;
            e=count?esp_wifi_scan_get_ap_records(&count,aps):esp_wifi_clear_ap_list();
            if(e) { free(aps); return MATTER_PENDING; }
            for(unsigned i=0;i<count;++i) {
                wifi_ap_record_t* ap=&aps[i]; size_t n=strnlen((const char*)ap->ssid,32);
                if(job->network.id.size && (n!=job->network.id.size || memcmp(ap->ssid,job->network.id.bytes,n))) continue;
                Matter_Wifi_Ap_T* out=&job->result.aps[job->result.count++];
                out->ssid.size=n; memcpy(out->ssid.bytes,ap->ssid,n); memcpy(out->bssid,ap->bssid,6);
                out->rssi=ap->rssi; out->channel=ap->primary; out->band=0;
                out->security=ap->authmode==WIFI_AUTH_OPEN?1:ap->authmode==WIFI_AUTH_WPA3_PSK?16:8;
            }
            free(aps);
        }
    } else if(!online(w,&job->network.id)) return MATTER_PENDING;
    r=matter_wifi_complete(model,job->token,&job->result);
    if(r==MATTER_OK) { wipe(job,sizeof(*job)); free(job); w->job=NULL; }
    return r;
}
static Matter_Result_T observe(void* u,Matter_Wifi_Ap_T* out,bool* active) {
    Lab_Wifi_T w=u; wifi_ap_record_t ap; memset(out,0,sizeof(*out)); *active=false;
    if(esp_wifi_sta_get_ap_info(&ap)!=ESP_OK) return MATTER_OK;
    out->ssid.size=strnlen((const char*)ap.ssid,32); memcpy(out->ssid.bytes,ap.ssid,out->ssid.size);
    memcpy(out->bssid,ap.bssid,6); out->rssi=ap.rssi; out->channel=ap.primary; out->security=8;
    *active=online(w,&out->ssid); return MATTER_OK;
}
Lab_Wifi_T lab_wifi_new(esp_netif_t* iface,const Matter_Wifi_Settings_T* settings) {
    if(!iface || !settings) return NULL;
    Lab_Wifi_T w=calloc(1,sizeof(*w)); if(!w) return NULL;
    w->lock=(portMUX_TYPE)portMUX_INITIALIZER_UNLOCKED; w->iface=iface; w->settings=*settings;
    for(unsigned i=0;i<settings->count;++i) if(online(w,&settings->networks[i].id)) {
        w->connected=w->target=settings->networks[i].id; break;
    }
    if(esp_event_handler_instance_register(WIFI_EVENT,WIFI_EVENT_SCAN_DONE,scan_event,w,&w->handler)!=ESP_OK) { free(w); return NULL; }
    return w;
}
Matter_Runtime_Wifi_Port_T lab_wifi_port(Lab_Wifi_T w) {
    return (Matter_Runtime_Wifi_Port_T){{w,load,configure,start,cancel,restore},initialize,process,observe};
}
Matter_Result_T lab_wifi_delete(Lab_Wifi_T w) {
    if(!w) return MATTER_OK;
    if(w->job || w->restoring) return MATTER_BUSY;
    if(esp_event_handler_instance_unregister(WIFI_EVENT,WIFI_EVENT_SCAN_DONE,w->handler)!=ESP_OK) return MATTER_PORT_ERROR;
    wipe(w,sizeof(*w)); free(w); return MATTER_OK;
}
void lab_wifi_reconnect(Lab_Wifi_T w) { if(w) w->initializing=w->force=w->apply=true; }
