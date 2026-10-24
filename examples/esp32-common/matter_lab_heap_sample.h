#ifndef MATTER_LAB_HEAP_SAMPLE_H
#define MATTER_LAB_HEAP_SAMPLE_H 1
/* Optional laboratory observer shared by C and C++ C6 comparisons. The SDK
 * timer task samples internal 8-bit heap; never allocates/formats in callback.
 * One timer plus observer globals are included in both firmware measurements. */
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
static portMUX_TYPE matter_lab_heap_guard=portMUX_INITIALIZER_UNLOCKED;
static struct { size_t samples,peak,min_free,min_largest; esp_timer_handle_t timer; } matter_lab_heap_sample;
static void matter_lab_heap_tick(void* user) {
    (void)user;
    multi_heap_info_t h; heap_caps_get_info(&h,MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);
    portENTER_CRITICAL(&matter_lab_heap_guard);
    ++matter_lab_heap_sample.samples;
    if(h.total_allocated_bytes>matter_lab_heap_sample.peak) matter_lab_heap_sample.peak=h.total_allocated_bytes;
    if(h.total_free_bytes<matter_lab_heap_sample.min_free) matter_lab_heap_sample.min_free=h.total_free_bytes;
    if(h.largest_free_block<matter_lab_heap_sample.min_largest) matter_lab_heap_sample.min_largest=h.largest_free_block;
    portEXIT_CRITICAL(&matter_lab_heap_guard);
}
static void matter_lab_heap_report(const char* prefix,const char* phase) {
    multi_heap_info_t h; heap_caps_get_info(&h,MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);
    portENTER_CRITICAL(&matter_lab_heap_guard);
    size_t samples=matter_lab_heap_sample.samples,peak=matter_lab_heap_sample.peak;
    size_t minimum=matter_lab_heap_sample.min_free,largest=matter_lab_heap_sample.min_largest;
    portEXIT_CRITICAL(&matter_lab_heap_guard);
    printf("%s {\"phase\":\"%s\",\"ms\":%llu,\"heap_free\":%u,\"heap_allocated\":%u,\"heap_min\":%u,"
        "\"largest_free\":%u,\"free_blocks\":%u,\"allocated_blocks\":%u,\"heap_max_sampled\":%u,"
        "\"heap_min_sampled\":%u,\"largest_min_sampled\":%u,\"samples\":%u,\"task_min_free\":%u}\n",
        prefix,phase,(unsigned long long)(esp_timer_get_time()/1000),(unsigned)h.total_free_bytes,(unsigned)h.total_allocated_bytes,
        (unsigned)h.minimum_free_bytes,(unsigned)h.largest_free_block,(unsigned)h.free_blocks,(unsigned)h.allocated_blocks,
        (unsigned)peak,(unsigned)minimum,(unsigned)largest,(unsigned)samples,(unsigned)uxTaskGetStackHighWaterMark(NULL));
}
static void matter_lab_heap_start(void) {
    matter_lab_heap_sample.min_free=matter_lab_heap_sample.min_largest=SIZE_MAX;
    matter_lab_heap_tick(NULL);
    esp_timer_create_args_t args={0}; args.callback=matter_lab_heap_tick; args.name="memory-lab";
    ESP_ERROR_CHECK(esp_timer_create(&args,&matter_lab_heap_sample.timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(matter_lab_heap_sample.timer,100000));
}
static inline void matter_lab_heap_stop(void) {
    ESP_ERROR_CHECK(esp_timer_stop(matter_lab_heap_sample.timer));
    ESP_ERROR_CHECK(esp_timer_delete(matter_lab_heap_sample.timer));
    matter_lab_heap_sample.timer=NULL;
}
#endif
