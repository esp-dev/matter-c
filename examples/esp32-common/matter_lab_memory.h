#ifndef MATTER_LAB_MEMORY_H
#define MATTER_LAB_MEMORY_H 1
/* Shared owner-task laboratory telemetry. Caller supplies REQUIRE and now(). */
#include <stdio.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_heap_caps.h"
#include "esp_task.h"
#include "matter_idf_memory.h"
static void tasks(void) {
    typedef struct { unsigned id,free; char name[configMAX_TASK_NAME_LEN]; } Task;
    UBaseType_t count=uxTaskGetNumberOfTasks()+4;
    TaskStatus_t* status=calloc(count,sizeof(*status));
    Task* copy=calloc(count,sizeof(*copy)); REQUIRE(status && copy);
    /* Keep borrowed task names live while copying. Do no formatting or heap
     * work with the scheduler suspended; print only the owned copies. */
    vTaskSuspendAll();
    count=uxTaskGetSystemState(status,count,NULL);
    for(UBaseType_t i=0;i<count;++i) {
        copy[i].id=(unsigned)status[i].xTaskNumber; copy[i].free=(unsigned)status[i].usStackHighWaterMark;
        for(size_t j=0;j+1<sizeof(copy[i].name) && status[i].pcTaskName[j];++j) {
            char c=status[i].pcTaskName[j];
            copy[i].name[j]=(c>='a' && c<='z') || (c>='A' && c<='Z') ||
                (c>='0' && c<='9') || c=='_' || c=='-'?c:'?';
        }
    }
    xTaskResumeAll(); REQUIRE(count);
    for(UBaseType_t i=0;i<count;++i)
        printf("TASK_MEMORY {\"id\":%u,\"name\":\"%s\",\"min_free_bytes\":%u}\n",
            copy[i].id,copy[i].name,copy[i].free);
    free(copy); free(status);
}
static void sample(const char* phase) {
    multi_heap_info_t info; heap_caps_get_info(&info,MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);
    Matter_Idf_Memory m=matter_idf_memory();
    unsigned free_stack=(unsigned)uxTaskGetStackHighWaterMark(NULL);
    printf("MEMORY {\"phase\":\"%s\",\"ms\":%llu,\"heap_free\":%u,\"heap_allocated\":%u,\"heap_min\":%u,"
        "\"largest_free\":%u,\"owner_stack_reserved\":%u,\"owner_stack_min_free\":%u,"
        "\"core_live\":%u,\"core_bytes\":%u,\"core_peak\":%u,\"core_largest\":%u,\"core_failures\":%u}\n",
        phase,(unsigned long long)now(),(unsigned)info.total_free_bytes,(unsigned)info.total_allocated_bytes,(unsigned)info.minimum_free_bytes,
        (unsigned)info.largest_free_block,(unsigned)ESP_TASK_MAIN_STACK,free_stack,
        (unsigned)m.live,(unsigned)m.live_bytes,(unsigned)m.peak_bytes,(unsigned)m.largest_request,(unsigned)m.failures);
}
#endif
