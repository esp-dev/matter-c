#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include "driver/uart_vfs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_random.h"
#include "esp_heap_caps.h"
#include "esp_netif_ip_addr.h"
#include "bootloader_random.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "mdns.h"
#include "psa/crypto.h"
#include "crypto/matter_crypto_mbedtls.h"
#include "runtime/matter_runtime.h"
#include "runtime/matter_host_limits.h"
#include "storage/matter_store_tlv.h"
#include "matter_discovery.h"
#include "matter_idf_udp.h"
#include "matter_idf_ip6_internal.h"
#include "matter_idf_store.h"
#include "matter_idf_discovery.h"
#include "matter_idf_memory.h"
#include "wifi_port.h"
#include "soak_lab.h"
#if CONFIG_MATTER_C_RUNTIME_RGB
#include "rgb_led.h"
#endif
#include "lwip/sockets.h"
#include "matter_lab_wifi.h"
#include "test_opcreds_vectors.h" /* Public TEST identity/scalar, never production DAC. */
#define REQUIRE(x) do { if(!(x)) { printf("RUNTIME_FAIL line=%u\n",(unsigned)__LINE__); abort(); } } while(0)
static uint64_t now(void) { return (uint64_t)esp_timer_get_time()/1000; }
#include "../../esp32-common/matter_lab_memory.h"
typedef struct {
    Matter_T owner; Matter_Discovery_T record; Matter_Idf_Discovery_T backend;
    bool stopping; uint64_t retry_at;
} Ad;
typedef struct {
    esp_netif_t* iface; Lab_Wifi_T wifi; Matter_Idf_Store_T disk;
    Matter_Crypto_Mbedtls_T backend; Matter_Runtime_T runtime;
    Matter_T owner; Matter_Idf_Udp_T udp; Matter_Events_T events;
    Matter_Lab_Soak_T soak;
#if CONFIG_MATTER_C_RUNTIME_RGB
    Matter_Lab_Rgb_T light; Matter_Lab_Led_T led;
#endif
    Matter_Runtime_Config_T config; Matter_Root_Config_T identity;
    Matter_Wifi_Settings_T initial; uint8_t key[32],mac[6];
    esp_ip6_addr_t addresses[CONFIG_LWIP_IPV6_NUM_ADDRESSES];
    Ad ads[6]; uint8_t mode; uint16_t disc; bool advertised;
#if CONFIG_MATTER_C_RUNTIME_SOAK
    bool reentry_probe;
#endif
    uint64_t rx,tx;
} App;
static Matter_Result_T utc(void* user,Matter_Cert_Time_T* out) {
    (void)user; time_t t=time(NULL); struct tm value;
    if(!gmtime_r(&t,&value) || value.tm_year<120) return MATTER_OFFLINE;
    *out=(Matter_Cert_Time_T){value.tm_year+1900,value.tm_mon+1,value.tm_mday,value.tm_hour,value.tm_min,value.tm_sec};
    return MATTER_OK;
}
static Matter_Result_T timestamp(void* user,uint32_t* out) {
    (void)user; time_t t=time(NULL);
    if(t<946684800 || (uint64_t)t-946684800>UINT32_MAX) return MATTER_OFFLINE;
    *out=(uint32_t)(t-946684800); return MATTER_OK;
}
static Matter_Result_T regulatory(void* user,const Matter_Root_Settings_T* settings,uint8_t candidate,bool* supported) {
    (void)user; (void)candidate;
    /* Lab uses the SDK's existing region-agnostic defaults; no unsupported
     * country/radio configuration is claimed. Runtime still persists Location. */
    *supported=settings->location[0]=='X' && settings->location[1]=='X'; return MATTER_OK;
}
static Matter_Result_T network(void* user,Matter_Diagnostics_Interface_T* out,size_t cap,size_t* count) {
    App* a=user; *count=1; if(!cap) return MATTER_LIMIT_REACHED;
#if CONFIG_MATTER_C_RUNTIME_SOAK
    if(a->reentry_probe) {
        a->reentry_probe=false;
        uint64_t future=now()+1000;
        REQUIRE(matter_runtime_process(a->runtime,future)==MATTER_BUSY);
        REQUIRE(matter_runtime_stop(a->runtime,future)==MATTER_BUSY);
        REQUIRE(matter_runtime_delete(a->runtime)==MATTER_BUSY);
        puts("REENTRY_PASS runtime-process-stop-delete callback");
    }
#endif
    memset(out,0,sizeof(*out)); memcpy(out->name,"wifi",4); out->name_size=4; out->type=1;
    out->reachable4=out->reachable6=-1; memcpy(out->hardware+2,a->mac,6);
    out->operational=esp_netif_is_netif_up(a->iface);
    esp_netif_ip_info_t ip;
    if(esp_netif_get_ip_info(a->iface,&ip)==ESP_OK && ip.ip.addr) { out->ipv4_count=1; memcpy(out->ipv4[0],&ip.ip.addr,4); }
    int n=esp_netif_get_all_ip6(a->iface,a->addresses); if(n<0 || n>8) return MATTER_PORT_ERROR;
    out->ipv6_count=n; for(int i=0;i<n;++i) memcpy(out->ipv6[i],a->addresses[i].addr,16);
    return MATTER_OK;
}
static Matter_Result_T entropy(void* user,uint8_t* out,size_t size) { (void)user; esp_fill_random(out,size); return MATTER_OK; }
static Matter_Result_T event_load(void* user,uint64_t* high) { return matter_store_host_event_load(matter_runtime_store(((App*)user)->runtime),high); }
static Matter_Result_T event_store(void* user,uint64_t high) { return matter_store_host_event_store(matter_runtime_store(((App*)user)->runtime),high); }
static void received(void* user,const Matter_Udp_Datagram_T* packet) {
    App* a=user; ++a->rx;
    if(matter_lab_soak_received(a->soak)) matter_runtime_received(a->runtime,packet);
}
static void sent(void* user,uint64_t id,Matter_Operation_Result_T result) {
    App* a=user; ++a->tx;
    if(matter_lab_soak_sent(a->soak,id,result)) matter_runtime_sent(a->runtime,id,result);
}
static void log_line(void* user,const char* text) { (void)user; printf("CORE %s",text); }
static void wifi_event(void* user,esp_event_base_t base,int32_t id,void* event) {
    (void)event; App* a=user;
    if(base==WIFI_EVENT && id==WIFI_EVENT_STA_CONNECTED) (void)esp_netif_create_ip6_linklocal(a->iface);
}
static void boot_wifi(App* a) {
    REQUIRE(esp_netif_init()==ESP_OK); REQUIRE(esp_event_loop_create_default()==ESP_OK);
    a->iface=esp_netif_create_default_wifi_sta(); REQUIRE(a->iface);
    wifi_init_config_t init=WIFI_INIT_CONFIG_DEFAULT(); REQUIRE(esp_wifi_init(&init)==ESP_OK);
    REQUIRE(esp_wifi_set_storage(WIFI_STORAGE_RAM)==ESP_OK); REQUIRE(esp_wifi_set_mode(WIFI_MODE_STA)==ESP_OK);
    REQUIRE(esp_wifi_get_mac(WIFI_IF_STA,a->mac)==ESP_OK);
    wifi_config_t* cfg=calloc(1,sizeof(*cfg)); REQUIRE(cfg);
    size_t ssid=strlen(MATTER_LAB_WIFI_SSID),password=strlen(MATTER_LAB_WIFI_PASSWORD);
    REQUIRE(ssid && ssid<=32 && password<=64);
    memcpy(cfg->sta.ssid,MATTER_LAB_WIFI_SSID,ssid); memcpy(cfg->sta.password,MATTER_LAB_WIFI_PASSWORD,password);
    cfg->sta.threshold.authmode=WIFI_AUTH_WPA2_PSK;
    REQUIRE(esp_wifi_set_config(WIFI_IF_STA,cfg)==ESP_OK); memset(cfg,0,sizeof(*cfg)); free(cfg);
    REQUIRE(esp_event_handler_register(WIFI_EVENT,WIFI_EVENT_STA_CONNECTED,wifi_event,a)==ESP_OK);
    REQUIRE(esp_wifi_start()==ESP_OK); REQUIRE(esp_wifi_connect()==ESP_OK);
    uint64_t end=now()+30000; esp_ip6_addr_t ip; esp_netif_ip_info_t v4;
    while(now()<end && (esp_netif_get_ip6_linklocal(a->iface,&ip)!=ESP_OK ||
        esp_netif_get_ip_info(a->iface,&v4)!=ESP_OK || !v4.ip.addr)) vTaskDelay(pdMS_TO_TICKS(50));
    REQUIRE(now()<end);
    printf("IPV6_READY address=" IPV6STR " interface=%d\n",IPV62STR(ip),esp_netif_get_netif_impl_index(a->iface));
    a->initial.enabled=true; a->initial.count=1;
    a->initial.networks[0].id.size=ssid; memcpy(a->initial.networks[0].id.bytes,MATTER_LAB_WIFI_SSID,ssid);
    a->initial.networks[0].credential_size=password; memcpy(a->initial.networks[0].credentials,MATTER_LAB_WIFI_PASSWORD,password);
    a->wifi=lab_wifi_new(a->iface,&a->initial); REQUIRE(a->wifi); sample("wifi-ipv6-ready");
}
static void text(Matter_Root_Text_T* out,const char* value) { out->size=strlen(value); memcpy(out->data,value,out->size); }
static void configuration(App* a) {
    Matter_Root_Config_T* i=&a->identity;
    text(&i->vendor_name,"Matter C test"); text(&i->product_name,"C6 runtime lab");
    text(&i->hardware_string,"C6"); text(&i->software_string,"Memory14");
    char unique[13]; for(unsigned j=0;j<6;++j) snprintf(unique+2*j,3,"%02X",a->mac[j]); text(&i->unique_id,unique);
    i->vendor_id=0xfff1; i->product_id=0x8000; i->software_version=i->hardware_version=i->configuration_version=1;
    i->basic_version=i->descriptor_version=1; i->settings.location[0]=i->settings.location[1]='X';
    i->capabilities=(Matter_Root_Capabilities_T)MATTER_HOST_CAPABILITIES;
    Matter_Runtime_Config_T* c=&a->config; c->identity=i; c->user=a;
    c->utc=utc; c->timestamp=timestamp; c->log=log_line; c->regulatory=regulatory;
    c->wifi=lab_wifi_port(a->wifi); c->wifi_config=(Matter_Wifi_Config_T){4,10,20,1,1,1};
    c->storage=matter_idf_store_port(a->disk); c->boot_reason=1; c->reboot=true;
    c->iface=(Matter_Diagnostics_Interface_T){.name="wifi",.name_size=4,.type=1,.reachable4=-1,.reachable6=-1};
    c->network=(Matter_Diagnostics_Network_Port_T){a,network};
    REQUIRE(matter_crypto_mbedtls_port(a->backend,&c->crypto)==MATTER_OK);
    REQUIRE(matter_crypto_mbedtls_credentials(a->backend,&c->credentials)==MATTER_OK);
    a->key[31]=3;
    c->attestation.identity=(Matter_Opcreds_Config_T){.dac={oc_dac,sizeof(oc_dac)},.pai={oc_pai,sizeof(oc_pai)},
        .certification_declaration={oc_cd,sizeof(oc_cd)}};
    c->attestation.trusted_paa=(Matter_Der_T){oc_paa,sizeof(oc_paa)}; c->attestation.dac_private=a->key;
}
static void ad_pump(Ad* ad) {
    if(!ad->backend || now()<ad->retry_at) return;
    Matter_Mdns_T module=matter_idf_discovery_module(ad->backend);
    Matter_Result_T r=matter_mdns_process(module);
    (void)matter_idf_discovery_process(ad->backend);
    if(r==MATTER_PORT_ERROR) {
        REQUIRE(matter_mdns_retry(module)==MATTER_OK); ad->retry_at=now()+1000;
    }
}
static bool ad_stop(Ad* ad) {
    ad->stopping=true;
    if(ad->backend) {
        Matter_Mdns_T module=matter_idf_discovery_module(ad->backend);
        (void)matter_mdns_stop(module); ad_pump(ad);
        if(matter_idf_discovery_delete(ad->backend)!=MATTER_OK) return false;
        ad->backend=NULL;
    }
    if(ad->owner) { REQUIRE(matter_stop(ad->owner)==MATTER_OK); REQUIRE(matter_delete(ad->owner)==MATTER_OK); ad->owner=NULL; }
    matter_discovery_delete(ad->record); ad->record=NULL; ad->stopping=false; ad->retry_at=0; return true;
}
static bool ad_start(Ad* ad,Matter_Discovery_T record) {
    ad->record=record; if(!record) return false;
    ad->owner=matter_new(NULL); if(!ad->owner || matter_start(ad->owner)!=MATTER_OK) goto fail;
    ad->backend=matter_idf_discovery_new(ad->owner,matter_discovery_record(record));
    if(ad->backend && matter_mdns_start(matter_idf_discovery_module(ad->backend))==MATTER_OK) return true;
fail:
    REQUIRE(ad_stop(ad)); return false;
}
static void advertisements(App* a,bool stop) {
    uint16_t disc=3840; uint8_t mode=stop?0:matter_runtime_commissioning_mode(a->runtime,&disc);
    /* Initial lab exposes current open window only. No false CM0 pairing hint. */
    if(a->advertised && (stop || mode!=a->mode || disc!=a->disc || a->ads[0].stopping)) {
        if(!ad_stop(&a->ads[0])) return;
        a->advertised=false;
    }
    if(!stop && mode && !a->advertised && now()>=a->ads[0].retry_at) {
        uint8_t random[8]; esp_fill_random(random,sizeof(random));
        if(ad_start(&a->ads[0],matter_discovery_commissionable(a->mac,random,disc,mode,5540))) {
            a->mode=mode; a->disc=disc; a->advertised=true;
        } else a->ads[0].retry_at=now()+1000;
    }
    const Matter_Fabric_View_T* fabrics=matter_runtime_fabrics(a->runtime);
    for(unsigned j=0;j<5;++j) {
        Ad* ad=&a->ads[j+1]; const Matter_Fabric_Record_T* f=fabrics?&fabrics->records[j]:NULL;
        bool wanted=!stop && f && f->index;
        if(ad->record && (ad->stopping || !wanted || strcmp(matter_discovery_record(ad->record)->instance,f->discovery_instance))) {
            if(!ad_stop(ad)) continue;
        }
        if(wanted && !ad->record && now()>=ad->retry_at &&
            !ad_start(ad,matter_discovery_operational(a->mac,f->compressed_id,f->node_id,5540))) ad->retry_at=now()+1000;
    }
    for(unsigned j=0;j<6;++j) ad_pump(&a->ads[j]);
}
static void pump(App* a) {
    matter_lab_soak_process(a->soak,a->runtime);
#if CONFIG_MATTER_C_RUNTIME_RGB
    REQUIRE(matter_lab_rgb_process(a->light,now())==MATTER_OK);
#endif
    Matter_Result_T r=matter_runtime_process(a->runtime,now()); REQUIRE(r==MATTER_OK || r==MATTER_PENDING);
#if CONFIG_MATTER_C_RUNTIME_RGB
    bool changed=false; REQUIRE(matter_lab_led_process(a->led,a->light,&changed));
    if(changed) matter_runtime_changed(a->runtime);
#endif
    (void)matter_idf_udp_process(a->udp); (void)matter_udp_process(matter_idf_udp_module(a->udp));
    advertisements(a,false); vTaskDelay(pdMS_TO_TICKS(10));
}
#if CONFIG_MATTER_C_RUNTIME_SOAK
typedef struct { unsigned received,sent; uint32_t interface_id; uint8_t values[32]; } Udp_Fairness;
static void fairness_received(void* user,const Matter_Udp_Datagram_T* packet) {
    Udp_Fairness* f=user; REQUIRE(packet->size==1 && f->received<sizeof(f->values) && packet->path.interface_id==f->interface_id);
    f->values[f->received++]=packet->data[0];
}
static void fairness_sent(void* user,uint64_t id,Matter_Operation_Result_T result) {
    (void)id; REQUIRE(result==MATTER_OPERATION_SUCCEEDED); ++((Udp_Fairness*)user)->sent;
}
static void udp_fairness(App* a) {
    size_t live=matter_idf_memory().live;
    Udp_Fairness f={.interface_id=esp_netif_get_netif_impl_index(a->iface)};
    Matter_T owner=matter_new(NULL); REQUIRE(owner && matter_start(owner)==MATTER_OK);
    Matter_Udp_Listener_T listener={&f,fairness_received,fairness_sent};
    Matter_Idf_Udp_T udp=matter_idf_udp_new(owner,a->iface,5541,&listener); REQUIRE(udp);
    Matter_Udp_T module=matter_idf_udp_module(udp); REQUIRE(matter_udp_start(module)==MATTER_OK);
    const uint8_t byte=0xa5; esp_ip6_addr_t ip; REQUIRE(esp_netif_get_ip6_linklocal(a->iface,&ip)==ESP_OK);
    Matter_Udp_Datagram_T packet={0};
    memcpy(packet.path.local.address,ip.addr,16); memcpy(packet.path.peer.address,ip.addr,16);
    packet.path.local.port=packet.path.peer.port=5541; packet.path.interface_id=esp_netif_get_netif_impl_index(a->iface);
    packet.data=&byte; packet.size=1; uint64_t id=0;
    REQUIRE(matter_udp_send(module,&packet,&id)==MATTER_PENDING && id);
    uint64_t end=now()+3000;
    while(!matter_idf_udp_stats(udp).received && now()<end) vTaskDelay(1);
    REQUIRE(matter_idf_udp_stats(udp).received==1 && !f.received && !f.sent);
    REQUIRE(matter_idf_udp_process(udp)==MATTER_OK && f.received==1 && f.sent==1 && f.values[0]==byte);
    int sender=socket(AF_INET6,SOCK_DGRAM,IPPROTO_UDP); REQUIRE(sender>=0);
    struct sockaddr_in6 address={.sin6_family=AF_INET6,.sin6_port=htons(5541),.sin6_scope_id=packet.path.interface_id};
    memcpy(&address.sin6_addr,ip.addr,16);
    for(unsigned burst=0;burst<5;++burst) {
        Matter_Idf_Udp_Stats_T before=matter_idf_udp_stats(udp); unsigned delivered=f.received;
        for(uint8_t value=0;value<6;++value)
            REQUIRE(sendto(sender,&value,1,0,(struct sockaddr*)&address,sizeof(address))==1);
        end=now()+3000;
        while(now()<end) { Matter_Idf_Udp_Stats_T current=matter_idf_udp_stats(udp);
            if(current.received+current.dropped>=before.received+before.dropped+6) break;
            vTaskDelay(1);
        }
        Matter_Idf_Udp_Stats_T after=matter_idf_udp_stats(udp);
        REQUIRE(now()<end && after.received>before.received);
        if(!burst) matter_idf_memory_fail_after(1);
        REQUIRE(matter_idf_udp_process(udp)==MATTER_OK);
        matter_idf_memory_fail_after(0);
        if(!burst) REQUIRE(matter_idf_udp_stats(udp).rx_buffers==1); /* Growth OOM leaves FIFO intact. */
        while(f.received<after.received) REQUIRE(matter_idf_udp_process(udp)==MATTER_OK);
        for(unsigned j=delivered;j<f.received;++j) REQUIRE(f.values[j]==j-delivered);
    }
    REQUIRE(close(sender)==0 && matter_idf_udp_stats(udp).rx_buffer_peak==8);
    end=now()+12000;
    while(matter_idf_udp_stats(udp).rx_buffers>1 && now()<end) { (void)matter_idf_udp_process(udp); vTaskDelay(1); }
    REQUIRE(now()<end && matter_idf_udp_stats(udp).rx_buffers==1);
    /* A saved core path must outlive a radio stop/start and OS-index change. */
    REQUIRE(esp_wifi_stop()==ESP_OK && esp_wifi_start()==ESP_OK && esp_wifi_connect()==ESP_OK);
    end=now()+30000; esp_netif_ip_info_t v4;
    while(now()<end && (esp_netif_get_ip6_linklocal(a->iface,&ip)!=ESP_OK ||
        esp_netif_get_ip_info(a->iface,&v4)!=ESP_OK || !v4.ip.addr)) vTaskDelay(pdMS_TO_TICKS(50));
    REQUIRE(now()<end && esp_netif_get_netif_impl_index(a->iface)!=f.interface_id);
    unsigned received=f.received;
    REQUIRE(matter_udp_send(module,&packet,&id)==MATTER_PENDING);
    end=now()+3000;
    while(f.received==received && now()<end) { (void)matter_idf_udp_process(udp); vTaskDelay(1); }
    REQUIRE(now()<end && f.sent==2 && f.values[received]==byte);
    REQUIRE(matter_udp_stop(module)==MATTER_PENDING);
    while(matter_udp_is_active(module)) (void)matter_udp_process(module);
    REQUIRE(matter_idf_udp_delete(udp)==MATTER_OK);
    REQUIRE(matter_stop(owner)==MATTER_OK && matter_delete(owner)==MATTER_OK);
    REQUIRE(matter_idf_memory().live==live); puts("UDP_FAIRNESS_PASS simultaneous-RX-and-TX-completion");
    puts("UDP_FIFO_PASS demand-growth8 growth-OOM FIFO-order idle-trim1 cleanup");
    puts("UDP_SCOPE_PASS saved-path-after-radio-restart-and-OS-index-change");
}
#endif
static void wifi_tests(App* a) {
    Matter_Wifi_T model=matter_root_cluster(matter_runtime_root(a->runtime),MATTER_WIFI_CLUSTER);
    size_t live=matter_idf_memory().live;
    matter_idf_memory_fail_after(1);
    REQUIRE(a->config.wifi.control.start(a->wifi,999,true,&a->initial.networks[0])==MATTER_LIMIT_REACHED);
    matter_idf_memory_fail_after(0); REQUIRE(matter_idf_memory().live==live);
    uint8_t* bytes=calloc(1,1024); REQUIRE(bytes);
    const uint8_t scan[]={0x15,0x18}; Matter_Tlv_Writer_T writer;
    Matter_Wifi_Reply_T result; uint64_t token=0;
    REQUIRE(matter_tlv_writer_init(&writer,bytes,1024,4)==MATTER_TLV_OK);
    REQUIRE(matter_wifi_invoke(model,0,true,scan,sizeof(scan),&writer,&result,&token)==MATTER_PENDING);
    uint64_t end=now()+15000; Matter_Result_T r=MATTER_PENDING;
    while(r==MATTER_PENDING && now()<end) { pump(a); r=matter_wifi_poll(model,token,&writer,&result); }
    REQUIRE(r==MATTER_OK && !result.result.status);
    REQUIRE(matter_tlv_writer_init(&writer,bytes,1024,4)==MATTER_TLV_OK);
    REQUIRE(matter_wifi_invoke(model,0,true,scan,sizeof(scan),&writer,&result,&token)==MATTER_PENDING);
    pump(a); matter_wifi_cancel(model,token); end=now()+15000;
    do { pump(a); r=matter_wifi_poll(model,token,&writer,&result); } while(r==MATTER_PENDING && now()<end);
    REQUIRE(r==MATTER_INVALID_STATE);
    wifi_ap_record_t ap; esp_ip6_addr_t ip;
    REQUIRE(esp_wifi_sta_get_ap_info(&ap)==ESP_OK && esp_netif_get_ip6_linklocal(a->iface,&ip)==ESP_OK);
    free(bytes); puts("WIFI_PORT_PASS job-OOM scan async-cancel-drain connection-preserved");
}
static void clear_store_fixture(void) {
    nvs_handle_t disposable;
    REQUIRE(nvs_open_from_partition("matter","port_test",NVS_READWRITE,&disposable)==ESP_OK);
    REQUIRE(nvs_erase_all(disposable)==ESP_OK && nvs_commit(disposable)==ESP_OK); nvs_close(disposable);
}
static void header_tests(void) {
    uint8_t bytes[64]={0x60}; bytes[6]=17;
    REQUIRE(matter_idf_ip6_headers(bytes,40)); REQUIRE(!matter_idf_ip6_headers(bytes,39));
    bytes[6]=0; bytes[40]=17; REQUIRE(matter_idf_ip6_headers(bytes,48));
    REQUIRE(!matter_idf_ip6_headers(bytes,47)); bytes[41]=255; REQUIRE(!matter_idf_ip6_headers(bytes,48));
    bytes[41]=0; bytes[40]=60; bytes[48]=17; REQUIRE(matter_idf_ip6_headers(bytes,56));
    bytes[40]=44; REQUIRE(!matter_idf_ip6_headers(bytes,56));
    bytes[6]=44; REQUIRE(!matter_idf_ip6_headers(bytes,48));
    puts("IPV6_HEADER_PASS base-HBH-destination-truncation-overrun-fragment");
}
static void store_tests(void) {
    Matter_Idf_Store_T s=matter_idf_store_new("matter","port_test"); REQUIRE(s);
    Matter_Store_Blob_Port_T p=matter_idf_store_port(s); size_t n=0;
    uint8_t* data=calloc(1,MATTER_STORE_BLOB_MAX); uint8_t* read=calloc(1,MATTER_STORE_BLOB_MAX); REQUIRE(data && read);
    memset(data,0x31,MATTER_STORE_BLOB_MAX);
    REQUIRE(p.replace(p.user,data,MATTER_STORE_BLOB_MAX)==MATTER_OK);
    for(unsigned stage=1;stage<=2;++stage) {
        matter_idf_store_fail(s,stage); data[0]=0x32;
        REQUIRE(p.replace(p.user,data,MATTER_STORE_BLOB_MAX)==MATTER_PORT_ERROR);
        REQUIRE(p.read(p.user,read,MATTER_STORE_BLOB_MAX,&n)==MATTER_OK && n==MATTER_STORE_BLOB_MAX && read[0]==0x31);
        matter_idf_store_delete(s); s=matter_idf_store_new("matter","port_test"); REQUIRE(s); p=matter_idf_store_port(s);
        REQUIRE(p.read(p.user,read,MATTER_STORE_BLOB_MAX,&n)==MATTER_OK && read[0]==0x31);
    }
    REQUIRE(p.replace(p.user,data,MATTER_STORE_BLOB_MAX)==MATTER_OK);
    REQUIRE(p.read(p.user,read,MATTER_STORE_BLOB_MAX-1,&n)==MATTER_LIMIT_REACHED);
    matter_idf_store_delete(s); free(data); free(read);
    clear_store_fixture();
    puts("PERSISTENCE_PORT_PASS max32768 staged-failures reopen bounds");
}
static void constructor_faults(App* a) {
#if CONFIG_MATTER_C_RUNTIME_OOM_SWEEP
    nvs_handle_t lab; uint8_t checked=0,recovery=0;
    REQUIRE(nvs_open_from_partition("matter","lab",NVS_READWRITE,&lab)==ESP_OK);
    esp_err_t e=nvs_get_u8(lab,"oom_checked",&checked); REQUIRE(e==ESP_OK || e==ESP_ERR_NVS_NOT_FOUND);
    e=nvs_get_u8(lab,"recovery",&recovery); REQUIRE(e==ESP_OK || e==ESP_ERR_NVS_NOT_FOUND);
    enum { OOM_SUITE_REVISION=2 };
    if(checked!=OOM_SUITE_REVISION && recovery!=1) {
        size_t base=matter_idf_memory().live,begin=matter_idf_memory().calls;
        Matter_Runtime_T probe=matter_runtime_new(&a->config,20202021,now()); REQUIRE(probe);
        size_t count=matter_idf_memory().calls-begin;
        REQUIRE(matter_runtime_stop(probe,now())==MATTER_OK && matter_runtime_delete(probe)==MATTER_OK);
        REQUIRE(matter_idf_memory().live==base);
        for(size_t position=1;position<=count;++position) {
            matter_idf_memory_fail_after(position); probe=matter_runtime_new(&a->config,20202021,now());
            matter_idf_memory_fail_after(0);
            if(probe) REQUIRE(matter_runtime_stop(probe,now())==MATTER_OK && matter_runtime_delete(probe)==MATTER_OK);
            REQUIRE(matter_idf_memory().live==base);
            if(!(position%8)) { printf("RUNTIME_OOM_PROGRESS %u/%u\n",(unsigned)position,(unsigned)count); vTaskDelay(1); }
        }
        printf("RUNTIME_OOM_PASS positions=%u\n",(unsigned)count);
        REQUIRE(nvs_set_u8(lab,"oom_checked",OOM_SUITE_REVISION)==ESP_OK && nvs_commit(lab)==ESP_OK);
    }
    nvs_close(lab);
#endif
}
static void discovery_faults(App* a) {
    Matter_T owner=matter_new(NULL); REQUIRE(owner && matter_start(owner)==MATTER_OK);
    uint8_t random[8]; esp_fill_random(random,sizeof(random));
    Matter_Discovery_T record=matter_discovery_commissionable(a->mac,random,100,1,5540); REQUIRE(record);
    size_t base=matter_idf_memory().live;
    for(unsigned position=1;position<=2;++position) {
        matter_idf_memory_fail_after(position);
        REQUIRE(!matter_idf_discovery_new(owner,matter_discovery_record(record)));
        matter_idf_memory_fail_after(0); REQUIRE(matter_idf_memory().live==base);
    }
    Matter_Idf_Discovery_T backend=matter_idf_discovery_new(owner,matter_discovery_record(record)); REQUIRE(backend);
    Matter_Mdns_T module=matter_idf_discovery_module(backend);
    REQUIRE(matter_mdns_start(module)==MATTER_OK);
    REQUIRE(matter_mdns_process(module)==MATTER_PENDING);
    matter_idf_memory_fail_after(1);
    REQUIRE(matter_idf_discovery_process(backend)==MATTER_OK); matter_idf_memory_fail_after(0);
    REQUIRE(!matter_mdns_is_published(module) && !mdns_service_exists_with_instance(
        matter_discovery_record(record)->instance,"_matterc","_udp",matter_discovery_record(record)->hostname));
    REQUIRE(matter_mdns_retry(module)==MATTER_OK);
    for(unsigned j=0;j<8 && !matter_mdns_is_published(module);++j) {
        (void)matter_mdns_process(module); (void)matter_idf_discovery_process(backend);
    }
    REQUIRE(matter_mdns_is_published(module));
    REQUIRE(matter_mdns_stop(module)==MATTER_PENDING);
    while(matter_mdns_is_active(module)) { (void)matter_mdns_process(module); (void)matter_idf_discovery_process(backend); }
    REQUIRE(matter_idf_discovery_delete(backend)==MATTER_OK);
    REQUIRE(matter_stop(owner)==MATTER_OK && matter_delete(owner)==MATTER_OK); matter_discovery_delete(record);
    puts("DISCOVERY_OOM_PASS construct-publish-retry-remove-drain");
    base=matter_idf_memory().live;
    for(unsigned position=1;position<=3;++position) {
        Ad ad={0}; record=matter_discovery_commissionable(a->mac,random,100,1,5540); REQUIRE(record);
        matter_idf_memory_fail_after(position); REQUIRE(!ad_start(&ad,record)); matter_idf_memory_fail_after(0);
        REQUIRE(!ad.owner && !ad.record && !ad.backend && !ad.stopping && matter_idf_memory().live==base);
    }
    Ad ad={0}; REQUIRE(ad_start(&ad,matter_discovery_commissionable(a->mac,random,100,1,5540)));
    matter_idf_memory_fail_after(1); ad_pump(&ad); matter_idf_memory_fail_after(0);
    uint64_t end=now()+10000;
    while(!matter_mdns_is_published(matter_idf_discovery_module(ad.backend)) && now()<end) { ad_pump(&ad); vTaskDelay(1); }
    REQUIRE(matter_mdns_is_published(matter_idf_discovery_module(ad.backend)));
    REQUIRE(!ad_stop(&ad) && ad.stopping); /* Retain drain even if wanted mode returns. */
    while(!ad_stop(&ad)) vTaskDelay(1);
    REQUIRE(!ad.stopping && matter_idf_memory().live==base);
    puts("ADVERTISEMENT_OOM_PASS constructors retry sticky-drain cleanup");
}
static void start(App* a) {
    size_t base=matter_idf_memory().live;
    matter_idf_memory_fail_after(1); REQUIRE(!matter_runtime_new(&a->config,20202021,now()));
    matter_idf_memory_fail_after(0); REQUIRE(matter_idf_memory().live==base);
    a->runtime=matter_runtime_new(&a->config,20202021,now()); REQUIRE(a->runtime); sample("runtime-created");
#if CONFIG_MATTER_C_RUNTIME_RGB
    a->light=matter_lab_rgb_new(esp_random(),now()); REQUIRE(a->light);
    REQUIRE(matter_lab_rgb_attach(a->light,matter_runtime_root(a->runtime))==MATTER_OK);
    a->led=matter_lab_led_new(); REQUIRE(a->led);
    puts("RGB_MODEL endpoint=1 GPIO8 experimental-light-profile");
#endif
#if CONFIG_MATTER_C_RUNTIME_CHIP_RESUMPTION
    REQUIRE(matter_runtime_set_resumption(a->runtime,MATTER_CASE_RESUMPTION_CHIP)==MATTER_OK);
    puts("CASE_PROFILE CHIP previous-ID explicit-lab-configuration");
#else
    REQUIRE(matter_runtime_set_resumption(a->runtime,MATTER_CASE_RESUMPTION_SPEC)==MATTER_OK);
    puts("CASE_PROFILE SPEC new-ID explicit-lab-configuration");
#endif
    a->owner=matter_new(NULL); REQUIRE(a->owner && matter_start(a->owner)==MATTER_OK);
    Matter_Udp_Listener_T listener={a,received,sent};
    matter_idf_memory_fail_after(1); REQUIRE(!matter_idf_udp_new(a->owner,a->iface,5540,&listener)); matter_idf_memory_fail_after(0);
    a->udp=matter_idf_udp_new(a->owner,a->iface,5540,&listener); REQUIRE(a->udp);
    matter_idf_memory_fail_after(1); REQUIRE(matter_udp_start(matter_idf_udp_module(a->udp))==MATTER_WOULD_BLOCK);
    matter_idf_memory_fail_after(0); REQUIRE(matter_udp_start(matter_idf_udp_module(a->udp))==MATTER_OK);
    Matter_Events_Port_T events={a,event_load,event_store}; a->events=matter_events_new(&events); REQUIRE(a->events);
    REQUIRE(matter_runtime_start(a->runtime,a->owner,matter_idf_udp_module(a->udp),a->events)==MATTER_OK);
    uint64_t high,after; Matter_Store_Host_T store=matter_runtime_store(a->runtime);
    REQUIRE(matter_store_host_event_load(store,&high)==MATTER_OK);
    matter_idf_memory_fail_after(1);
    REQUIRE(matter_store_host_event_store(store,high+1024)==MATTER_LIMIT_REACHED);
    matter_idf_memory_fail_after(0);
    for(unsigned stage=1;stage<=2;++stage) {
        matter_idf_store_fail(a->disk,stage);
        REQUIRE(matter_store_host_event_store(store,high+1024)==MATTER_PORT_ERROR);
        REQUIRE(matter_store_host_event_load(store,&after)==MATTER_OK && after==high);
    }
    puts("ATOMIC_MODEL_PASS allocator-and-two-storage-failures");
    sample("runtime-started");
}
static void fail_safe_restart(App* a,nvs_handle_t lab) {
    uint8_t phase=0; esp_err_t e=nvs_get_u8(lab,"recovery",&phase); REQUIRE(e==ESP_OK || e==ESP_ERR_NVS_NOT_FOUND);
    if(phase==1) {
        lab_wifi_reconnect(a->wifi);
        REQUIRE(!matter_runtime_commissionable(a->runtime));
        puts("FAILSAFE_RADIO_RESTORE_PENDING");
        for(unsigned j=0;j<400;++j) pump(a);
        Matter_Root_Fail_Safe_State_T state;
        REQUIRE(matter_root_fail_safe_state(matter_runtime_root(a->runtime),&state)==MATTER_OK && state==MATTER_ROOT_FAIL_SAFE_IDLE);
        REQUIRE(nvs_set_u8(lab,"recovery",2)==ESP_OK && nvs_commit(lab)==ESP_OK);
        puts("FAILSAFE_REBOOT_PASS recovered-before-admission"); return;
    }
    if(phase) return;
    REQUIRE(nvs_set_u8(lab,"recovery",1)==ESP_OK && nvs_commit(lab)==ESP_OK);
    const uint8_t arm[]={0x15,0x24,0,60,0x24,1,0,0x18};
    uint8_t bytes[64]; Matter_Tlv_Writer_T writer; Matter_Im_Command_Result_T result;
    Matter_Im_Command_Path_T path={0,0x30,0};
    Matter_Root_Invoke_Binding_T binding; Matter_Im_Invoke_Port_T invoke;
    /* Explicit local trusted test binding; never accepts an unauthenticated
     * wire session. Network requests always enter the real dispatcher. */
    REQUIRE(matter_root_invoke_port(matter_runtime_root(a->runtime),42,&binding,&invoke)==MATTER_OK);
    REQUIRE(matter_tlv_writer_init(&writer,bytes,sizeof(bytes),4)==MATTER_TLV_OK);
    REQUIRE(invoke.validate(invoke.user,&path,arm,sizeof(arm))==MATTER_IM_SUCCESS);
    result=invoke.invoke(invoke.user,&path,arm,sizeof(arm),&writer); REQUIRE(!result.status);
    puts("FAILSAFE_DURABLE_RESTART pending-journal-published"); fflush(stdout);
    vTaskDelay(pdMS_TO_TICKS(200)); esp_restart();
}
static void recovery_restart(App* a) {
    Matter_Store_Blob_Port_T port=matter_idf_store_port(a->disk);
    uint8_t* bytes=calloc(1,MATTER_STORE_BLOB_MAX);
    Matter_Store_Data_T* image=calloc(1,sizeof(*image)); REQUIRE(bytes && image);
    size_t size=0; REQUIRE(port.read(port.user,bytes,MATTER_STORE_BLOB_MAX,&size)==MATTER_OK);
    REQUIRE(matter_store_tlv_decode(bytes,size,image)==MATTER_OK);
    /* Local crash fixture retains complete committed fabrics/settings and only
     * marks the Wi-Fi recovery journal pending, as at fail-safe begin. */
    image->wifi.pending=true;
    REQUIRE(matter_store_tlv_encode(image,bytes,MATTER_STORE_BLOB_MAX,&size)==MATTER_OK);
    REQUIRE(port.replace(port.user,bytes,size)==MATTER_OK);
    a->config.crypto.clear(bytes,MATTER_STORE_BLOB_MAX); a->config.crypto.clear((uint8_t*)image,sizeof(*image));
    free(bytes); free(image);
    nvs_handle_t lab; REQUIRE(nvs_open_from_partition("matter","lab",NVS_READWRITE,&lab)==ESP_OK);
    REQUIRE(nvs_set_u8(lab,"recovery",1)==ESP_OK && nvs_commit(lab)==ESP_OK); nvs_close(lab);
    puts("FAILSAFE_DURABLE_RESTART local-crash-fixture-preserves-committed-fabric"); fflush(stdout);
    vTaskDelay(pdMS_TO_TICKS(200)); esp_restart();
}
void app_main(void) {
#if CONFIG_MATTER_C_RUNTIME_SOAK
    REQUIRE(heap_caps_register_failed_alloc_callback(matter_lab_soak_heap_failed)==ESP_OK);
#endif
    sample("boot"); header_tests(); REQUIRE(psa_crypto_init()==PSA_SUCCESS);
    struct timeval clock={.tv_sec=MATTER_LAB_BOOT_UTC}; REQUIRE(settimeofday(&clock,NULL)==0);
    puts("LAB_CLOCK build-time-bootstrap TEST_DAC enabled");
    REQUIRE(nvs_flash_init()==ESP_OK); REQUIRE(nvs_flash_init_partition("matter")==ESP_OK);
    /* Dedicated capacity includes a live checkpoint plus maximum-size fixture
     * versions and NVS garbage collection. The fixture clears only its namespace. */
    store_tests();
    App* a=calloc(1,sizeof(*a)); REQUIRE(a);
    boot_wifi(a);
#if CONFIG_MATTER_C_RUNTIME_SOAK
    udp_fairness(a);
#endif
    a->disk=matter_idf_store_new("matter","runtime"); REQUIRE(a->disk);
    Matter_Crypto_Entropy_Port_T entropy_port={NULL,entropy}; a->backend=matter_crypto_mbedtls_new(&entropy_port); REQUIRE(a->backend);
    configuration(a);
    char hostname[13]; for(unsigned j=0;j<6;++j) snprintf(hostname+2*j,3,"%02X",a->mac[j]);
    REQUIRE(mdns_init()==ESP_OK); REQUIRE(mdns_hostname_set(hostname)==ESP_OK);
    vTaskPrioritySet(NULL,tskIDLE_PRIORITY);
    constructor_faults(a); discovery_faults(a); start(a);
    nvs_handle_t lab; REQUIRE(nvs_open_from_partition("matter","lab",NVS_READWRITE,&lab)==ESP_OK);
    fail_safe_restart(a,lab); nvs_close(lab);
    wifi_tests(a);
    a->soak=matter_lab_soak_new();
#if CONFIG_MATTER_C_RUNTIME_SOAK
    REQUIRE(a->soak);
    a->reentry_probe=true; /* Next diagnostics snapshot is inside runtime process. */
#endif
    for(unsigned j=0;j<200;++j) pump(a);
    sample("runtime-serving"); tasks(); puts("RUNTIME_READY port=5540 pin=20202021");
    uart_vfs_dev_use_nonblocking(CONFIG_ESP_CONSOLE_UART_NUM);
    uint64_t last=now();
    for(;;) {
        pump(a);
        char c=0; (void)read(STDIN_FILENO,&c,1);
        if(c=='q') break;
        if(c=='r') recovery_restart(a);
        (void)matter_lab_soak_control(a->soak,c,a->wifi,a->runtime);
#if CONFIG_MATTER_C_RUNTIME_SOAK
        const uint64_t sample_interval=5000;
#else
        const uint64_t sample_interval=30000;
#endif
        if(now()-last>sample_interval) {
            Matter_Idf_Udp_Stats_T stats=matter_idf_udp_stats(a->udp);
            sample("runtime-serving");
            (void)matter_lab_soak_control(a->soak,'m',a->wifi,a->runtime);
            printf("NETWORK rx=%llu tx=%llu dropped=%lu oversize=%lu extensions=%lu rx_buffers=%lu rx_peak=%lu\n",
                (unsigned long long)a->rx,(unsigned long long)a->tx,(unsigned long)stats.dropped,
                (unsigned long)stats.oversize,(unsigned long)stats.extensions,
                (unsigned long)stats.rx_buffers,(unsigned long)stats.rx_buffer_peak); last=now();
        }
    }
    /* Preserve UDP/backend/radio/storage through runtime retirement and MRP
     * drain. A timeout never permits freeing the live runtime. */
    while(matter_runtime_stop(a->runtime,now())!=MATTER_OK) pump(a);
    while(true) {
        bool done=true; for(unsigned j=0;j<6;++j) if(!ad_stop(&a->ads[j])) done=false;
        if(done) break;
        (void)matter_idf_udp_process(a->udp); vTaskDelay(1);
    }
    REQUIRE(matter_lab_soak_delete(a->soak)==MATTER_OK); a->soak=NULL;
    REQUIRE(matter_runtime_delete(a->runtime)==MATTER_OK); a->runtime=NULL;
#if CONFIG_MATTER_C_RUNTIME_RGB
    while(!matter_lab_led_delete(a->led)) vTaskDelay(1);
    REQUIRE(matter_lab_rgb_delete(a->light)==MATTER_OK);
#endif
    REQUIRE(matter_events_delete(a->events)==MATTER_OK);
    (void)matter_stop(a->owner);
    while(matter_get_state(a->owner)==MATTER_STATE_STOPPING) {
        (void)matter_udp_process(matter_idf_udp_module(a->udp)); (void)matter_idf_udp_process(a->udp); vTaskDelay(1);
    }
    REQUIRE(matter_idf_udp_delete(a->udp)==MATTER_OK); REQUIRE(matter_delete(a->owner)==MATTER_OK);
    mdns_free(); REQUIRE(lab_wifi_delete(a->wifi)==MATTER_OK); matter_idf_store_delete(a->disk);
    REQUIRE(matter_crypto_mbedtls_delete(a->backend)==MATTER_OK);
    REQUIRE(esp_event_handler_unregister(WIFI_EVENT,WIFI_EVENT_STA_CONNECTED,wifi_event)==ESP_OK);
    REQUIRE(esp_wifi_stop()==ESP_OK); REQUIRE(esp_wifi_deinit()==ESP_OK);
    esp_netif_destroy_default_wifi(a->iface); REQUIRE(esp_event_loop_delete_default()==ESP_OK);
    REQUIRE(nvs_flash_deinit_partition("matter")==ESP_OK); REQUIRE(nvs_flash_deinit()==ESP_OK);
    memset(a,0,sizeof(*a)); free(a);
    REQUIRE(!matter_idf_memory().live && !matter_idf_memory().live_bytes); REQUIRE(heap_caps_check_integrity_all(true));
    sample("complete"); tasks(); puts("RUNTIME_PASS");
    for(;;) vTaskDelay(pdMS_TO_TICKS(1000));
}
