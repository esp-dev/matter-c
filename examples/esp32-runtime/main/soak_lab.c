#include "soak_lab.h"
#include "sdkconfig.h"
#include "matter_idf_memory.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_attr.h"
#include <stdlib.h>
#include <stdio.h>
#if CONFIG_MATTER_C_RUNTIME_SOAK
static uint32_t sdk_failures,sdk_largest_failed;
void IRAM_ATTR matter_lab_soak_heap_failed(size_t size,uint32_t caps,const char* function) {
    (void)caps; (void)function;
    __atomic_fetch_add(&sdk_failures,1,__ATOMIC_RELAXED);
    uint32_t old=__atomic_load_n(&sdk_largest_failed,__ATOMIC_RELAXED);
    while(size>old && !__atomic_compare_exchange_n(&sdk_largest_failed,&old,(uint32_t)size,false,__ATOMIC_RELAXED,__ATOMIC_RELAXED)) {}
}
struct Matter_Lab_Soak {
    uint64_t next_sample,drop_until,fault_until,completion_until,held;
    Matter_Operation_Result_T result; bool hold_next;
    size_t samples,max_allocated,min_free,min_largest;
    unsigned dropped,delayed,injected,reconnects;
};
static uint64_t clock_ms(void) { return (uint64_t)esp_timer_get_time()/1000; }
Matter_Lab_Soak_T matter_lab_soak_new(void) {
    Matter_Lab_Soak_T s=calloc(1,sizeof(*s));
    if(s) s->min_free=s->min_largest=SIZE_MAX;
    return s;
}
bool matter_lab_soak_received(Matter_Lab_Soak_T s) {
    if(s && clock_ms()<s->drop_until) { ++s->dropped; return false; }
    return true;
}
bool matter_lab_soak_sent(Matter_Lab_Soak_T s,uint64_t id,Matter_Operation_Result_T result) {
    if(s && s->hold_next && !s->held) {
        s->hold_next=false; s->held=id; s->result=result;
        s->completion_until=clock_ms()+3000; ++s->delayed; return false;
    }
    return true;
}
void matter_lab_soak_process(Matter_Lab_Soak_T s,Matter_Runtime_T runtime) {
    if(!s) return;
    uint64_t now=clock_ms();
    if(s->held && now>=s->completion_until) {
        uint64_t id=s->held; s->held=0;
        matter_runtime_sent(runtime,id,s->result);
    }
    if(s->fault_until && now>=s->fault_until) {
        matter_idf_memory_fail_after(0); s->fault_until=0;
    }
    if(now<s->next_sample) return;
    s->next_sample=now+100;
    multi_heap_info_t h; heap_caps_get_info(&h,MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);
    ++s->samples;
    if(h.total_allocated_bytes>s->max_allocated) s->max_allocated=h.total_allocated_bytes;
    if(h.total_free_bytes<s->min_free) s->min_free=h.total_free_bytes;
    if(h.largest_free_block<s->min_largest) s->min_largest=h.largest_free_block;
}
bool matter_lab_soak_control(Matter_Lab_Soak_T s,char command,Lab_Wifi_T wifi,Matter_Runtime_T runtime) {
    if(!s) return false;
    uint64_t now=clock_ms();
    switch(command) {
    case 'f': case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9':
        matter_idf_memory_fail_after(command=='f'?1:(size_t)(command-'0'));
        s->fault_until=now+10000; ++s->injected; break;
    case 'a': matter_idf_memory_fail_after(0); s->fault_until=0; break;
    case 'w': lab_wifi_reconnect(wifi); ++s->reconnects; break;
    case 'd': s->drop_until=now+3000; break;
    case 'h': s->hold_next=true; break;
    case 'm': break;
    default: return false;
    }
    matter_lab_soak_process(s,runtime);
    multi_heap_info_t h,dma; heap_caps_get_info(&h,MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);
    heap_caps_get_info(&dma,MALLOC_CAP_INTERNAL|MALLOC_CAP_DMA);
    Matter_Idf_Memory m=matter_idf_memory();
    unsigned fabrics=0; const Matter_Fabric_View_T* view=matter_runtime_fabrics(runtime);
    if(view) for(unsigned j=0;j<MATTER_FABRIC_CAPACITY;++j) if(view->records[j].index) ++fabrics;
    printf("SOAK {\"command\":\"%c\",\"ms\":%llu,\"fabrics\":%u,\"samples\":%u,"
        "\"heap_max_sampled\":%u,\"heap_min_sampled\":%u,\"largest_min_sampled\":%u,"
        "\"heap_free\":%u,\"heap_allocated\":%u,\"largest_free\":%u,\"free_blocks\":%u,\"allocated_blocks\":%u,\"core_bytes\":%u,"
        "\"core_peak\":%u,\"core_live\":%u,\"core_calls\":%u,\"core_failures\":%u,"
        "\"rx_dropped_by_lab\":%u,\"delayed_completions\":%u,\"held_completion\":%u,"
        "\"faults_armed\":%u,\"reconnects\":%u,\"sdk_alloc_failures\":%u,\"sdk_largest_failed_request\":%u,"
        "\"dma_free\":%u,\"dma_largest_free\":%u}\n",command,(unsigned long long)now,fabrics,(unsigned)s->samples,
        (unsigned)s->max_allocated,(unsigned)s->min_free,(unsigned)s->min_largest,
        (unsigned)h.total_free_bytes,(unsigned)h.total_allocated_bytes,(unsigned)h.largest_free_block,
        (unsigned)h.free_blocks,(unsigned)h.allocated_blocks,
        (unsigned)m.live_bytes,(unsigned)m.peak_bytes,(unsigned)m.live,(unsigned)m.calls,(unsigned)m.failures,
        s->dropped,s->delayed,s->held?1:0,s->injected,s->reconnects,
        (unsigned)__atomic_load_n(&sdk_failures,__ATOMIC_RELAXED),(unsigned)__atomic_load_n(&sdk_largest_failed,__ATOMIC_RELAXED),
        (unsigned)dma.total_free_bytes,(unsigned)dma.largest_free_block);
    return true;
}
Matter_Result_T matter_lab_soak_delete(Matter_Lab_Soak_T s) {
    if(s && s->held) return MATTER_BUSY;
    matter_idf_memory_fail_after(0); free(s); return MATTER_OK;
}
#else
void matter_lab_soak_heap_failed(size_t size,uint32_t caps,const char* function) { (void)size; (void)caps; (void)function; }
Matter_Lab_Soak_T matter_lab_soak_new(void) { return NULL; }
bool matter_lab_soak_received(Matter_Lab_Soak_T s) { (void)s; return true; }
bool matter_lab_soak_sent(Matter_Lab_Soak_T s,uint64_t id,Matter_Operation_Result_T r) { (void)s; (void)id; (void)r; return true; }
void matter_lab_soak_process(Matter_Lab_Soak_T s,Matter_Runtime_T r) { (void)s; (void)r; }
bool matter_lab_soak_control(Matter_Lab_Soak_T s,char c,Lab_Wifi_T w,Matter_Runtime_T r) { (void)s; (void)c; (void)w; (void)r; return false; }
Matter_Result_T matter_lab_soak_delete(Matter_Lab_Soak_T s) { (void)s; return MATTER_OK; }
#endif
