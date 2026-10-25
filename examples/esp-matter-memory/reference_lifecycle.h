/* Only the generated pinned-reference comparison includes this observer.
 * This is a one-way shutdown experiment, not an ESP-Matter restart API. */
#pragma once
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include <platform/CHIPDeviceLayer.h>
#include <platform/ESP32/PlatformManagerImpl.h>
#include <app/server/Server.h>
static void reference_lifecycle_wifi_event(void*,esp_event_base_t base,int32_t id,void*) {
    if(base==WIFI_EVENT && id==WIFI_EVENT_STA_CONNECTED) {
        esp_netif_t* iface=esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        ESP_ERROR_CHECK(esp_netif_create_ip6_linklocal(iface));
    }
}
static void reference_lifecycle_wifi() {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_t* iface=esp_netif_create_default_wifi_sta();
    if(!iface) abort();
    wifi_init_config_t init=WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    wifi_config_t* config=static_cast<wifi_config_t*>(calloc(1,sizeof(wifi_config_t)));
    if(!config) abort();
    ESP_ERROR_CHECK(esp_wifi_get_config(WIFI_IF_STA,config));
    bool provisioned=config->sta.ssid[0]!=0;
    memset(config,0,sizeof(*config)); free(config);
    if(!provisioned) { puts("LIFECYCLE_NO_SAVED_WIFI"); abort(); }
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT,WIFI_EVENT_STA_CONNECTED,
                                              reference_lifecycle_wifi_event,nullptr));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_connect());
    int64_t until=esp_timer_get_time()+30000000;
    esp_ip6_addr_t address; esp_netif_ip_info_t v4;
    while(esp_timer_get_time()<until && (esp_netif_get_ip6_linklocal(iface,&address)!=ESP_OK ||
          esp_netif_get_ip_info(iface,&v4)!=ESP_OK || !v4.ip.addr)) vTaskDelay(pdMS_TO_TICKS(50));
    if(esp_timer_get_time()>=until) abort();
}
static void reference_lifecycle_shutdown() {
    using namespace chip::DeviceLayer;
    reference_memory_report("before-shutdown");
    PlatformMgr().LockChipStack();
    ESP_ERROR_CHECK(esp_matter::node::destroy());
    reference_memory_report("node-destroyed");
    chip::Server::GetInstance().Shutdown();
    reference_memory_report("server-shutdown");
    if(PlatformMgr().StopEventLoopTask()!=CHIP_NO_ERROR) abort();
    PlatformMgr().UnlockChipStack();
    /* ESP32 PlatformMgr::Shutdown unregisters IP events; the Wi-Fi registration
     * installed by ESP32Utils::InitWiFiStack needs explicit removal as well. */
    ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT,ESP_EVENT_ANY_ID,
                                               PlatformManagerImpl::HandleESPSystemEvent));
    ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT,ESP_EVENT_ANY_ID,
                                               PlatformManagerImpl::HandleESPSystemEvent));
    /* StopEventLoopTask only requests exit. Do not delete its queue/mutex
     * while RunEventLoop can still use them. This pinned fixture has exactly
     * one task with CHIP_DEVICE_CONFIG_CHIP_TASK_NAME. */
    int64_t until=esp_timer_get_time()+5000000;
    while(xTaskGetHandle(CHIP_DEVICE_CONFIG_CHIP_TASK_NAME) && esp_timer_get_time()<until)
        vTaskDelay(pdMS_TO_TICKS(10));
    if(xTaskGetHandle(CHIP_DEVICE_CONFIG_CHIP_TASK_NAME)) { puts("LIFECYCLE_JOIN_TIMEOUT"); abort(); }
    puts("LIFECYCLE_TASK_JOINED");
    PlatformMgr().Shutdown();
    reference_memory_report("platform-shutdown");
    reference_memory_tasks();
    matter_lab_lifecycle_settle("deleted-wifi-up");
    matter_lab_lifecycle_unreserve();
    puts("LIFECYCLE_SHUTDOWN_COMPLETE");
    for(;;) vTaskDelay(pdMS_TO_TICKS(1000));
}
