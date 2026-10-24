#include "matter_idf_memory.h"
#undef calloc
#undef free
#include <stdint.h>
#include "esp_heap_caps.h"
static Matter_Idf_Memory memory;
static size_t fail_at;
Matter_Idf_Memory matter_idf_memory(void) { return memory; }
void matter_idf_memory_fail_after(size_t count) {
    fail_at=count && count<=SIZE_MAX-memory.calls?memory.calls+count:0;
}
void* matter_idf_calloc(size_t count, size_t size) {
    ++memory.calls;
    if ((count && size>SIZE_MAX/count) || (fail_at && memory.calls==fail_at)) {
        fail_at=0; ++memory.failures; return NULL;
    }
    void* result=calloc(count,size);
    if (!result) { ++memory.failures; return NULL; }
    ++memory.live; memory.live_bytes+=heap_caps_get_allocated_size(result);
    if(memory.live_bytes>memory.peak_bytes) memory.peak_bytes=memory.live_bytes;
    if(count*size>memory.largest_request) memory.largest_request=count*size;
    return result;
}
void matter_idf_free(void* pointer) {
    if(pointer) { --memory.live; memory.live_bytes-=heap_caps_get_allocated_size(pointer); }
    free(pointer);
}
