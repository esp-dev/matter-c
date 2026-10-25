#ifndef MATTER_LAB_LIFECYCLE_H
#define MATTER_LAB_LIFECYCLE_H 1
/* Isolated comparison images only. Keep Wi-Fi running while Matter is absent.
 * No allocation, extra task, pool change or production lifecycle hook. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#ifndef MATTER_LAB_RESERVE_BYTES
#define MATTER_LAB_RESERVE_BYTES 0
#endif
static unsigned char* matter_lab_lifecycle_reservation;
static void matter_lab_lifecycle_reserve(void) {
    if(!MATTER_LAB_RESERVE_BYTES) return;
    matter_lab_lifecycle_reservation=(unsigned char*)malloc(MATTER_LAB_RESERVE_BYTES);
    if(!matter_lab_lifecycle_reservation) { puts("LIFECYCLE_RESERVATION_OOM"); abort(); }
    memset(matter_lab_lifecycle_reservation,0x5a,MATTER_LAB_RESERVE_BYTES);
    printf("LIFECYCLE_RESERVATION {\"bytes\":%u}\n",(unsigned)MATTER_LAB_RESERVE_BYTES);
}
static void matter_lab_lifecycle_report(const char* phase,unsigned elapsed) {
    multi_heap_info_t h;
    heap_caps_get_info(&h,MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);
    wifi_ap_record_t ap;
    esp_netif_t* iface=esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_ip6_addr_t address;
    int connected=esp_wifi_sta_get_ap_info(&ap)==ESP_OK;
    int ipv6=iface && esp_netif_get_ip6_linklocal(iface,&address)==ESP_OK;
    printf("LIFECYCLE_MEMORY {\"phase\":\"%s\",\"elapsed_ms\":%u,"
        "\"heap_free\":%u,\"largest_free\":%u,\"heap_min\":%u,"
        "\"heap_allocated\":%u,\"wifi_connected\":%d,\"ipv6\":%d,\"reserved_payload\":%u}\n",
        phase,elapsed,(unsigned)h.total_free_bytes,(unsigned)h.largest_free_block,
        (unsigned)h.minimum_free_bytes,(unsigned)h.total_allocated_bytes,connected,ipv6,
        matter_lab_lifecycle_reservation?(unsigned)MATTER_LAB_RESERVE_BYTES:0);
}
static void matter_lab_lifecycle_unreserve(void) {
    if(!matter_lab_lifecycle_reservation) return;
    const size_t size=MATTER_LAB_RESERVE_BYTES;
    for(size_t i=0;i<size;++i)
        if(matter_lab_lifecycle_reservation[i]!=0x5a) { puts("LIFECYCLE_RESERVATION_CORRUPT"); abort(); }
    free(matter_lab_lifecycle_reservation); matter_lab_lifecycle_reservation=NULL;
    matter_lab_lifecycle_report("deleted-no-reservation",0);
    vTaskDelay(pdMS_TO_TICKS(5000));
    matter_lab_lifecycle_report("deleted-no-reservation",5000);
}
static void matter_lab_lifecycle_settle(const char* phase) {
    static const unsigned points[]={0,1000,5000,15000,30000,65000};
    int64_t begin=esp_timer_get_time();
    ESP_ERROR_CHECK(heap_caps_monitor_local_minimum_free_size_start());
    for(unsigned i=0;i<sizeof(points)/sizeof(points[0]);++i) {
        while((uint64_t)(esp_timer_get_time()-begin)<(uint64_t)points[i]*1000)
            vTaskDelay(pdMS_TO_TICKS(20));
        matter_lab_lifecycle_report(phase,points[i]);
    }
    ESP_ERROR_CHECK(heap_caps_monitor_local_minimum_free_size_stop());
}
#endif
