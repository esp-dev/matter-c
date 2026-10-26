#include "matter_idf_wifi.h"
#include "matter_idf_wifi_retry.h"
#include "clusters/matter_wifi_internal.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif_ip_addr.h"
#include "freertos/FreeRTOS.h"
#include <stdlib.h>
#include <string.h>
#include "sdkconfig.h"
#if CONFIG_MATTER_C_ESP32_UDP_TRACE
#include <stdio.h>
#define WIFI_TRACE(...) printf(__VA_ARGS__)
#else
#define WIFI_TRACE(...) ((void)0)
#endif

typedef struct {
    uint64_t token;bool scan,started,cancelled,scan_stop,disconnect;
    Matter_Wifi_Network_T network;Matter_Wifi_Completion_T result;
} Job;
struct Matter_Idf_Wifi {
    esp_netif_t* iface;Matter_Wifi_Settings_T settings;Matter_Wifi_Id_T target,connected;
    Matter_Idf_Wifi_Retry_T retry;Job* job;
    bool restoring,initializing,apply,allow,busy;unsigned phase;
    uint64_t now;esp_err_t last_error;
    portMUX_TYPE lock;bool scan_done,associated;uint32_t association_events,link_event;uint32_t disconnects,seen_disconnects;uint8_t reason;
    esp_event_handler_instance_t handler;
};
static void wipe(void* p,size_t n){volatile uint8_t* b=p;while(n--)*b++=0;}
static bool same(const Matter_Wifi_Id_T* a,const Matter_Wifi_Id_T* b){return a->size==b->size&&!memcmp(a->bytes,b->bytes,a->size);}
static esp_err_t ap_info(Matter_Idf_Wifi_T w,wifi_ap_record_t* ap){
    portENTER_CRITICAL(&w->lock);bool associated=w->associated;portEXIT_CRITICAL(&w->lock);
    return associated?esp_wifi_sta_get_ap_info(ap):ESP_ERR_WIFI_NOT_CONNECT;
}
static bool online(Matter_Idf_Wifi_T w,const Matter_Wifi_Id_T* id){
    wifi_ap_record_t ap;esp_ip6_addr_t ip;
    return id->size&&ap_info(w,&ap)==ESP_OK&&strnlen((const char*)ap.ssid,32)==id->size&&!memcmp(ap.ssid,id->bytes,id->size)&&esp_netif_get_ip6_linklocal(w->iface,&ip)==ESP_OK;
}
static void event(void* u,esp_event_base_t base,int32_t id,void* data){
    (void)base;Matter_Idf_Wifi_T w=u;
    portENTER_CRITICAL(&w->lock);
    if(id==WIFI_EVENT_SCAN_DONE)w->scan_done=true;
    else if(id==WIFI_EVENT_STA_CONNECTED){w->associated=true;++w->association_events;}
    else if(id==WIFI_EVENT_STA_DISCONNECTED){w->associated=false;++w->association_events;++w->disconnects;w->reason=data?((wifi_event_sta_disconnected_t*)data)->reason:0;}
    portEXIT_CRITICAL(&w->lock);
}
static bool scanned(Matter_Idf_Wifi_T w,bool clear){portENTER_CRITICAL(&w->lock);bool done=w->scan_done;if(clear)w->scan_done=false;portEXIT_CRITICAL(&w->lock);return done;}
static void release_job(Matter_Idf_Wifi_T w){wipe(w->job,sizeof(*w->job));free(w->job);w->job=NULL;}
static const Matter_Wifi_Network_T* network(Matter_Idf_Wifi_T w){
    if(w->job&&!w->job->scan)return &w->job->network;
    for(unsigned i=0;i<w->settings.count;++i)if(same(&w->target,&w->settings.networks[i].id))return &w->settings.networks[i];
    return NULL;
}
static Matter_Result_T load(void* u,Matter_Wifi_Settings_T* s,Matter_Wifi_Id_T* c){Matter_Idf_Wifi_T w=u;*s=w->settings;*c=w->connected;return MATTER_OK;}
static Matter_Result_T configure(void* u,const Matter_Wifi_Settings_T* s){
    Matter_Idf_Wifi_T w=u;if(w->busy)return MATTER_BUSY;
    Matter_Wifi_Id_T empty={0};if(!matter_wifi_settings_valid(s,&empty,MATTER_WIFI_NETWORKS))return MATTER_INVALID_ARGUMENT;
    WIFI_TRACE("MATTER_WIFI configure enabled=%u count=%u\n",s->enabled?1u:0u,(unsigned)s->count);
    w->settings=*s;if(!s->enabled||(!network(w)&&w->target.size)){w->target.size=0;w->apply=true;}return MATTER_OK;
}
static Matter_Result_T start(void* u,uint64_t token,bool scan,const Matter_Wifi_Network_T* n){
    Matter_Idf_Wifi_T w=u;
    WIFI_TRACE("MATTER_WIFI start scan=%u busy=%u job=%u restoring=%u initializing=%u enabled=%u\n",scan?1u:0u,w->busy?1u:0u,w->job?1u:0u,w->restoring?1u:0u,w->initializing?1u:0u,w->settings.enabled?1u:0u);
    if(w->busy||w->job||w->restoring)return MATTER_BUSY;
    if(!n||!token||n->id.size>32)return MATTER_INVALID_ARGUMENT;
    if(!scan){Matter_Wifi_Settings_T s={.enabled=true,.count=1,.networks={*n}};Matter_Wifi_Id_T empty={0};if(!matter_wifi_settings_valid(&s,&empty,1))return MATTER_INVALID_ARGUMENT;}
    Job* job=calloc(1,sizeof(*job));if(!job)return MATTER_LIMIT_REACHED;
    job->token=token;job->scan=scan;job->network=*n;w->job=job;return MATTER_PENDING;
}
static Matter_Result_T cancel(void* u,uint64_t token){Matter_Idf_Wifi_T w=u;if(w->busy)return MATTER_BUSY;if(!w->job)return MATTER_OK;if(w->job->token!=token)return MATTER_INVALID_STATE;w->job->cancelled=true;return MATTER_PENDING;}
static void select_target(Matter_Idf_Wifi_T w,const Matter_Wifi_Id_T* target){
    w->target=*target;w->apply=true;w->phase=0;matter_idf_wifi_retry_enabled(&w->retry,false,w->now);matter_idf_wifi_retry_enabled(&w->retry,w->settings.enabled&&target->size,w->now);
}
static Matter_Result_T restore(void* u,const Matter_Wifi_Settings_T* s,const Matter_Wifi_Id_T* c){
    Matter_Idf_Wifi_T w=u;if(w->busy)return MATTER_BUSY;if(w->job)return MATTER_PENDING;
    if(!matter_wifi_settings_valid(s,c,MATTER_WIFI_NETWORKS))return MATTER_INVALID_ARGUMENT;
    if(!w->restoring){w->settings=*s;select_target(w,c);w->restoring=true;}
    wifi_ap_record_t ap;
    if(!w->apply&&((!c->size&&ap_info(w,&ap)!=ESP_OK)||(s->enabled&&same(c,&w->connected)&&online(w,c)))){w->restoring=false;return MATTER_OK;}
    return MATTER_PENDING;
}
static Matter_Result_T initialize(void* u,const Matter_Wifi_Settings_T* s,const Matter_Wifi_Id_T* c){
    Matter_Idf_Wifi_T w=u;if(w->busy||w->job||w->restoring)return MATTER_BUSY;
    if(!matter_wifi_settings_valid(s,c,MATTER_WIFI_NETWORKS))return MATTER_INVALID_ARGUMENT;
    WIFI_TRACE("MATTER_WIFI initialize enabled=%u count=%u connected=%u\n",s->enabled?1u:0u,(unsigned)s->count,c->size?1u:0u);
    w->settings=*s;select_target(w,c);w->initializing=true;return MATTER_OK;
}
/* The heap configuration is wiped after the synchronous SDK copy. If the
 * current association uses old credentials for the same SSID, do not accept it
 * as proof that newly written credentials work. */
static esp_err_t matches(Matter_Idf_Wifi_T w,const Matter_Wifi_Network_T* n,bool* equal){
    *equal=false;if(!online(w,&n->id))return ESP_OK;
    wifi_config_t* config=calloc(1,sizeof(*config));if(!config)return ESP_ERR_NO_MEM;
    esp_err_t e=esp_wifi_get_config(WIFI_IF_STA,config);
    if(e==ESP_OK){*equal=!memcmp(config->sta.ssid,n->id.bytes,n->id.size)&&!memcmp(config->sta.password,n->credentials,n->credential_size);
        for(unsigned i=n->id.size;i<32;++i)if(config->sta.ssid[i])*equal=false;
        for(unsigned i=n->credential_size;i<64;++i)if(config->sta.password[i])*equal=false;}
    wipe(config,sizeof(*config));free(config);return e;
}
static esp_err_t connect_config(Matter_Idf_Wifi_T w,const Matter_Wifi_Network_T* n){
    (void)w;wifi_config_t* config=calloc(1,sizeof(*config));if(!config)return ESP_ERR_NO_MEM;
    memcpy(config->sta.ssid,n->id.bytes,n->id.size);memcpy(config->sta.password,n->credentials,n->credential_size);
    config->sta.threshold.authmode=n->credential_size==5?WIFI_AUTH_WEP:n->credential_size?WIFI_AUTH_WPA2_PSK:WIFI_AUTH_OPEN;
    config->sta.sae_pwe_h2e=WPA3_SAE_PWE_BOTH;
    config->sta.pmf_cfg.capable=true;config->sta.pmf_cfg.required=false;
    esp_err_t e=esp_wifi_set_config(WIFI_IF_STA,config);wipe(config,sizeof(*config));free(config);
    if(e==ESP_OK)e=esp_wifi_connect();
    return e;
}
static Matter_Result_T cancelled(Matter_Idf_Wifi_T w){
    Job* j=w->job;
    if(j->scan){if(j->started&&!scanned(w,false)){if(!j->scan_stop){if(esp_wifi_scan_stop()!=ESP_OK)return MATTER_PENDING;j->scan_stop=true;}return MATTER_PENDING;}(void)esp_wifi_clear_ap_list();release_job(w);return MATTER_OK;}
    if(!j->disconnect){esp_err_t e=esp_wifi_disconnect();if(e!=ESP_OK&&e!=ESP_ERR_WIFI_NOT_CONNECT)return MATTER_PENDING;j->disconnect=true;}
    wifi_ap_record_t ap;if(ap_info(w,&ap)==ESP_OK)return MATTER_PENDING;
    w->connected.size=0;w->target.size=0;w->apply=false;w->phase=0;matter_idf_wifi_retry_enabled(&w->retry,false,w->now);release_job(w);return MATTER_OK;
}
static void connection(Matter_Idf_Wifi_T w,uint64_t now){
    uint32_t serial;uint8_t reason;portENTER_CRITICAL(&w->lock);serial=w->disconnects;reason=w->reason;portEXIT_CRITICAL(&w->lock);
    bool disconnected=serial!=w->seen_disconnects;w->seen_disconnects=serial;
    if(disconnected)WIFI_TRACE("MATTER_WIFI disconnected reason=%u phase=%u explicit=%u\n",(unsigned)reason,w->phase,w->job?1u:0u);
    wifi_ap_record_t ap;esp_ip6_addr_t ip;uint32_t association;bool associated;
    portENTER_CRITICAL(&w->lock);association=w->association_events;associated=w->associated;portEXIT_CRITICAL(&w->lock);
    /* Creating LL again while DAD is tentative restarts DAD in lwIP. Do it
     * once per association, not once per owner tick; retry only API errors. */
    if(associated&&association!=w->link_event&&(esp_netif_get_ip6_linklocal(w->iface,&ip)==ESP_OK||esp_netif_create_ip6_linklocal(w->iface)==ESP_OK)){
        w->link_event=association;
        if(ap_info(w,&ap)==ESP_OK)WIFI_TRACE("MATTER_WIFI associated channel=%u auth=%u\n",(unsigned)ap.primary,(unsigned)ap.authmode);
    }
    if(!w->settings.enabled||!w->target.size){
        matter_idf_wifi_retry_enabled(&w->retry,false,now);
        if(w->apply){esp_err_t e=esp_wifi_disconnect();if(e==ESP_OK||e==ESP_ERR_WIFI_NOT_CONNECT){w->apply=false;w->phase=0;w->connected.size=0;}}
        return;
    }
    const Matter_Wifi_Network_T* n=network(w);if(!n){w->last_error=ESP_ERR_NOT_FOUND;return;}
    bool connected=online(w,&w->target);
    if(w->apply){bool identical=false;w->last_error=matches(w,n,&identical);if(w->last_error)return;if(identical){w->apply=false;w->phase=0;}else connected=false;}
    if(connected){w->connected=w->target;matter_idf_wifi_retry_result(&w->retry,true,now);w->last_error=ESP_OK;return;}
    w->connected.size=0;
    if(w->retry.online||(disconnected&&reason!=WIFI_REASON_ASSOC_LEAVE&&w->phase==2)){matter_idf_wifi_retry_result(&w->retry,false,now);w->phase=0;}
    bool permit=w->allow||w->restoring||w->initializing||(w->job&&!w->job->scan);
    if(w->job&&w->job->scan)permit=false;
    matter_idf_wifi_retry_enabled(&w->retry,true,now);
    if(matter_idf_wifi_retry_poll(&w->retry,now,permit)){
        w->last_error=esp_wifi_disconnect();
        if(w->last_error==ESP_OK||w->last_error==ESP_ERR_WIFI_NOT_CONNECT){w->phase=1;w->last_error=ESP_OK;}
        else matter_idf_wifi_retry_result(&w->retry,false,now);
    }
    if(w->phase==1){
        if(ap_info(w,&ap)==ESP_OK)return;
        w->last_error=connect_config(w,n);
        if(w->last_error==ESP_ERR_WIFI_STATE)return; /* Prior disconnect still owns the driver transition. */
        if(w->last_error){matter_idf_wifi_retry_result(&w->retry,false,now);w->phase=0;}
        else {w->phase=2;w->apply=false;}
    }
}
static uint8_t security(wifi_auth_mode_t mode){
    switch(mode){case WIFI_AUTH_OPEN:return 1;case WIFI_AUTH_WEP:return 2;
    case WIFI_AUTH_WPA_PSK:return 4;case WIFI_AUTH_WPA2_PSK:return 8;
    case WIFI_AUTH_WPA_WPA2_PSK:return 12;case WIFI_AUTH_WPA3_PSK:return 16;
    case WIFI_AUTH_WPA2_WPA3_PSK:return 24;default:return 0;}
}
static void scans(Matter_Idf_Wifi_T w){
    Job* j=w->job;uint16_t count=0;esp_err_t e=esp_wifi_scan_get_ap_num(&count);
    if(e!=ESP_OK){j->result.status=12;j->result.has_error=true;j->result.error=e;(void)esp_wifi_clear_ap_list();return;}
    if(count>MATTER_WIFI_SCAN_RESULTS)count=MATTER_WIFI_SCAN_RESULTS;
    wifi_ap_record_t* aps=count?calloc(count,sizeof(*aps)):NULL;
    if(count&&!aps){j->result.status=12;j->result.has_error=true;j->result.error=ESP_ERR_NO_MEM;(void)esp_wifi_clear_ap_list();return;}
    e=count?esp_wifi_scan_get_ap_records(&count,aps):esp_wifi_clear_ap_list();
    if(e==ESP_OK)for(unsigned i=0;i<count;++i){
        wifi_ap_record_t* ap=&aps[i];size_t size=strnlen((const char*)ap->ssid,32);
        if(j->network.id.size&&(size!=j->network.id.size||memcmp(ap->ssid,j->network.id.bytes,size)))continue;
        Matter_Wifi_Ap_T* out=&j->result.aps[j->result.count++];out->ssid.size=(uint8_t)size;memcpy(out->ssid.bytes,ap->ssid,size);memcpy(out->bssid,ap->bssid,6);
        out->rssi=ap->rssi;out->channel=ap->primary;out->security=security(ap->authmode);
    }
    free(aps);if(e!=ESP_OK){j->result.status=12;j->result.has_error=true;j->result.error=e;}
}
Matter_Result_T matter_idf_wifi_process(Matter_Idf_Wifi_T w,Matter_Wifi_T model,uint64_t now){
    if(!w||now<w->now)return MATTER_INVALID_ARGUMENT;
    if(w->busy)return MATTER_BUSY;
    w->now=now;
    if(model){Matter_Result_T r=matter_wifi_process(model,now);if(r!=MATTER_OK&&r!=MATTER_PENDING)return r;}
    if(w->job&&!model)return MATTER_INVALID_STATE;
    w->busy=true;
    if(w->job&&w->job->cancelled){Matter_Result_T r=cancelled(w);w->busy=false;return r;}
    if(w->allow&&!w->job&&!w->restoring&&!w->initializing&&!w->target.size&&w->settings.enabled&&w->settings.count)select_target(w,&w->settings.networks[0].id);
    if(w->job&&!w->job->started){
        Job* j=w->job;
        if(j->scan){(void)scanned(w,true);wifi_scan_config_t scan={0};esp_err_t e=esp_wifi_scan_start(&scan,false);
            if(e){j->result.status=12;j->result.has_error=true;j->result.error=e;}else j->started=true;
        }else {select_target(w,&j->network.id);j->started=true;}
    }
    connection(w,now);
    if(w->initializing){wifi_ap_record_t ap;bool ready=w->target.size?same(&w->connected,&w->target):ap_info(w,&ap)!=ESP_OK;if(ready&&!w->apply)w->initializing=false;}
    Job* j=w->job;bool ready=j&&(j->result.status||(j->scan?j->started&&scanned(w,false):online(w,&j->network.id)));
    if(ready&&j->scan&&!j->result.status)scans(w);
    w->busy=false;
    if(model)(void)matter_wifi_observe_connection(model,&w->connected);
    if(ready){Matter_Result_T r=matter_wifi_complete(model,j->token,&j->result);if(r==MATTER_OK)release_job(w);return r;}
    return w->job||w->initializing||w->restoring?MATTER_PENDING:MATTER_OK;
}
static Matter_Result_T process(void* u,Matter_Wifi_T model,uint64_t now){return matter_idf_wifi_process(u,model,now);}
static Matter_Result_T observe(void* u,Matter_Wifi_Ap_T* out,bool* active){Matter_Idf_Wifi_T w=u;wifi_ap_record_t ap;memset(out,0,sizeof(*out));*active=false;if(ap_info(w,&ap)!=ESP_OK)return MATTER_OK;out->ssid.size=(uint8_t)strnlen((const char*)ap.ssid,32);memcpy(out->ssid.bytes,ap.ssid,out->ssid.size);memcpy(out->bssid,ap.bssid,6);out->rssi=ap.rssi;out->channel=ap.primary;out->security=security(ap.authmode);*active=online(w,&out->ssid);return MATTER_OK;}
Matter_Idf_Wifi_T matter_idf_wifi_new(esp_netif_t* iface,const Matter_Wifi_Settings_T* settings,uint32_t seed,uint64_t now){
    Matter_Wifi_Id_T empty={0};
    if(!iface||!matter_wifi_settings_valid(settings,&empty,MATTER_WIFI_NETWORKS))return NULL;
    Matter_Idf_Wifi_T w=calloc(1,sizeof(*w));if(!w)return NULL;
    w->iface=iface;w->settings=*settings;w->lock=(portMUX_TYPE)portMUX_INITIALIZER_UNLOCKED;w->now=now;w->link_event=UINT32_MAX;matter_idf_wifi_retry_init(&w->retry,seed,now);
    if(settings->enabled&&settings->count)select_target(w,&settings->networks[0].id);
    if(esp_event_handler_instance_register(WIFI_EVENT,ESP_EVENT_ANY_ID,event,w,&w->handler)!=ESP_OK){wipe(w,sizeof(*w));free(w);return NULL;}
    wifi_ap_record_t ap;bool associated=esp_wifi_sta_get_ap_info(&ap)==ESP_OK;
    portENTER_CRITICAL(&w->lock);if(!w->association_events)w->associated=associated;portEXIT_CRITICAL(&w->lock);
    return w;
}
Matter_Runtime_Wifi_Port_T matter_idf_wifi_port(Matter_Idf_Wifi_T w){return (Matter_Runtime_Wifi_Port_T){{w,load,configure,start,cancel,restore},initialize,process,observe};}
void matter_idf_wifi_allow_reconnect(Matter_Idf_Wifi_T w,bool allow){if(w&&!w->busy)w->allow=allow;}
Matter_Result_T matter_idf_wifi_delete(Matter_Idf_Wifi_T w){if(!w)return MATTER_OK;if(w->busy||w->job||w->restoring)return MATTER_BUSY;if(esp_event_handler_instance_unregister(WIFI_EVENT,ESP_EVENT_ANY_ID,w->handler)!=ESP_OK)return MATTER_PORT_ERROR;wipe(w,sizeof(*w));free(w);return MATTER_OK;}
