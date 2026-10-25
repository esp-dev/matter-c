#ifndef MATTER_LAB_USERCASE_H
#define MATTER_LAB_USERCASE_H 1
#include "matter_lab_heap_sample.h"
#include "esp_system.h"
/* Identical observer on both stacks. UART ASCII digits select public phase
 * numbers, never contain credentials. No extra console task or command parser. */
static const char* matter_lab_usercase_phase="boot";
static bool matter_lab_usercase_monitor;
static unsigned matter_lab_usercase_oom;
static size_t matter_lab_usercase_oom_largest;
static void matter_lab_usercase_failed(size_t bytes,uint32_t caps,const char* function) {
    (void)caps; (void)function;
    portENTER_CRITICAL(&matter_lab_heap_guard);
    ++matter_lab_usercase_oom;
    if(bytes>matter_lab_usercase_oom_largest) matter_lab_usercase_oom_largest=bytes;
    portEXIT_CRITICAL(&matter_lab_heap_guard);
}
static const char* const matter_lab_usercase_phases[]={
    "wifi-onboarding","commissioning","first-session","control-subscribe",
    "multiple-controllers","multi-admin","fabric-removal","ota-download",
    "ota-reboot-reconnect","matter-absent"
};
static void matter_lab_usercase_tasks(void) {
    static const char* const names[]={"main","CHIP","chip","wifi","esp_timer","tcpip","sys_evt","mdns","Tmr Svc","IDLE"};
    unsigned free_bytes[sizeof(names)/sizeof(names[0])]={0};
    bool present[sizeof(names)/sizeof(names[0])]={false};
    /* Single-core C6: prevent task deletion between lookup and watermark read.
     * No heap allocation, formatting, Matter call or blocking I/O under this
     * scheduler barrier. Task stack reservations remain in the measured heap. */
    vTaskSuspendAll();
    for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);++i) {
        TaskHandle_t task=xTaskGetHandle(names[i]);
        if(task) { present[i]=true; free_bytes[i]=(unsigned)uxTaskGetStackHighWaterMark(task); }
    }
    xTaskResumeAll();
    for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);++i) if(present[i])
        printf("USERCASE_TASK {\"name\":\"%s\",\"min_free_bytes\":%u}\n",names[i],free_bytes[i]);
}
static void matter_lab_usercase_report(void) {
    matter_lab_heap_report("USERCASE_MEMORY",matter_lab_usercase_phase);
    portENTER_CRITICAL(&matter_lab_heap_guard);
    unsigned failures=matter_lab_usercase_oom; size_t largest=matter_lab_usercase_oom_largest;
    portEXIT_CRITICAL(&matter_lab_heap_guard);
    printf("USERCASE_OOM {\"failures\":%u,\"largest_request\":%u}\n",failures,(unsigned)largest);
    matter_lab_usercase_tasks();
}
static void matter_lab_usercase_begin(unsigned phase) {
    if(phase>=sizeof(matter_lab_usercase_phases)/sizeof(matter_lab_usercase_phases[0])) return;
    if(!matter_lab_usercase_monitor) {
        ESP_ERROR_CHECK(esp_register_shutdown_handler(matter_lab_usercase_report));
        ESP_ERROR_CHECK(heap_caps_register_failed_alloc_callback(matter_lab_usercase_failed));
    }
    matter_lab_usercase_report();
    if(matter_lab_usercase_monitor) ESP_ERROR_CHECK(heap_caps_monitor_local_minimum_free_size_stop());
    ESP_ERROR_CHECK(heap_caps_monitor_local_minimum_free_size_start()); matter_lab_usercase_monitor=true;
    portENTER_CRITICAL(&matter_lab_heap_guard);
    matter_lab_heap_sample.samples=matter_lab_heap_sample.peak=0;
    matter_lab_heap_sample.min_free=matter_lab_heap_sample.min_largest=SIZE_MAX;
    matter_lab_usercase_phase=matter_lab_usercase_phases[phase];
    portEXIT_CRITICAL(&matter_lab_heap_guard);
    matter_lab_heap_tick(NULL); matter_lab_usercase_report();
}
static void matter_lab_usercase_control(char c) {
    if(c>='0' && c<='9') matter_lab_usercase_begin((unsigned)(c-'0'));
    if(c=='m') matter_lab_usercase_report();
}
#endif
