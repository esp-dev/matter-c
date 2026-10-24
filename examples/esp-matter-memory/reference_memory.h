/* Laboratory observer for the external pinned ESP-Matter light example.
 * No new task: esp_timer samples internal 8-bit heap nominally every100ms.
 * Its callback never formats, allocates or touches Matter state. UART event/
 * console reports run outside the sampling guard. Observer cost is included. */
#pragma once
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_console.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "matter_lab_heap_sample.h"
static void reference_memory_report(const char* phase) {
    matter_lab_heap_report("REF_MEMORY",phase);
}
static void reference_memory_tasks() {
    struct Task { char name[configMAX_TASK_NAME_LEN]; unsigned free; };
    UBaseType_t capacity=uxTaskGetNumberOfTasks()+4;
    TaskStatus_t* entries=static_cast<TaskStatus_t*>(calloc(capacity,sizeof(*entries)));
    Task* copy=static_cast<Task*>(calloc(capacity,sizeof(*copy)));
    if(!entries || !copy) { free(copy); free(entries); puts("REF_TASK_OOM"); return; }
    vTaskSuspendAll();
    UBaseType_t count=uxTaskGetSystemState(entries,capacity,nullptr);
    for(UBaseType_t i=0;i<count;++i) {
        copy[i].free=(unsigned)entries[i].usStackHighWaterMark;
        for(size_t j=0;j+1<sizeof(copy[i].name) && entries[i].pcTaskName[j];++j) {
            char c=entries[i].pcTaskName[j];
            copy[i].name[j]=(c>='a' && c<='z') || (c>='A' && c<='Z') ||
                (c>='0' && c<='9') || c=='_' || c=='-'?c:'?';
        }
    }
    xTaskResumeAll();
    for(UBaseType_t i=0;i<count;++i)
        printf("REF_TASK {\"name\":\"%s\",\"min_free_bytes\":%u}\n",copy[i].name,copy[i].free);
    free(copy); free(entries);
}
static int reference_memory_command(int argc,char** argv) {
    const char* phase=argc==2?argv[1]:"checkpoint";
    /* Labels are controller supplied; bound/sanitize before JSON formatting. */
    size_t length=0;
    for(;phase[length];++length) if(length>=48 || !((phase[length]>='a' && phase[length]<='z') ||
        (phase[length]>='0' && phase[length]<='9') || phase[length]=='-')) return 1;
    reference_memory_report(phase); reference_memory_tasks(); return 0;
}
static void reference_memory_start() {
    matter_lab_heap_start();
}
static void reference_memory_console() {
    esp_console_cmd_t cmd={}; cmd.command="memstat"; cmd.help="Private laboratory heap/stack checkpoint"; cmd.func=reference_memory_command;
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
    reference_memory_report("reference-ready"); puts("REFERENCE_READY");
}
