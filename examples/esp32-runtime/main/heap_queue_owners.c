/* Attribution-only SDK link wrappers. Never free SDK resources by guessing
 * their type from a heap map. No allocation/formatting under this guard. */
#include "heap_queue_owners.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include <sys/lock.h>
typedef struct { const void* address; uintptr_t caller; unsigned kind; } Entry;
static Entry entries[128];
static unsigned overflows;
static portMUX_TYPE guard=portMUX_INITIALIZER_UNLOCKED;
static void remember(const void* address,uintptr_t caller,unsigned kind) {
    if(!address) return;
    portENTER_CRITICAL(&guard);
    Entry* available=NULL;
    for(unsigned i=0;i<128;++i) {
        if(entries[i].address==address) { available=&entries[i]; break; }
        if(!entries[i].address && !available) available=&entries[i];
    }
    /* The first attributed lock owner replaces the generic queue creator.
     * Later acquisitions retain it. The handle is read only after acquiring
     * the real mutex, never raced against its lazy initialization. */
    if(available) {
        if(kind!=4 || available->address!=address || available->kind<3)
            *available=(Entry){address,caller,kind};
    } else ++overflows;
    portEXIT_CRITICAL(&guard);
}
QueueHandle_t __real_xQueueGenericCreate(UBaseType_t length,UBaseType_t size,uint8_t type);
QueueHandle_t __wrap_xQueueGenericCreate(UBaseType_t length,UBaseType_t size,uint8_t type) {
    QueueHandle_t value=__real_xQueueGenericCreate(length,size,type);
    remember(value,(uintptr_t)__builtin_return_address(0),1); return value;
}
QueueHandle_t __real_xQueueCreateMutex(uint8_t type);
QueueHandle_t __wrap_xQueueCreateMutex(uint8_t type) {
    QueueHandle_t value=__real_xQueueCreateMutex(type);
    remember(value,(uintptr_t)__builtin_return_address(0),2); return value;
}
void __real_vQueueDelete(QueueHandle_t queue);
void __wrap_vQueueDelete(QueueHandle_t queue) {
    portENTER_CRITICAL(&guard);
    for(unsigned i=0;i<128;++i) if(entries[i].address==queue) entries[i]=(Entry){0};
    portEXIT_CRITICAL(&guard);
    __real_vQueueDelete(queue);
}
HeapQueueOwner matter_lab_heap_queue_owner(const void* address) {
    HeapQueueOwner result={0};
    portENTER_CRITICAL(&guard);
    for(unsigned i=0;i<128;++i) if(entries[i].address==address) { result=(HeapQueueOwner){entries[i].caller,entries[i].kind}; break; }
    portEXIT_CRITICAL(&guard); return result;
}
unsigned matter_lab_heap_queue_overflows(void) {
    portENTER_CRITICAL(&guard); unsigned result=overflows; portEXIT_CRITICAL(&guard); return result;
}
/* Record the SDK caller of libc mutex initialization, including lazy first
 * acquire. The generic xQueueCreateMutex site alone names only locks.c. */
void __real__lock_init(_lock_t* lock);
void __wrap__lock_init(_lock_t* lock) {
    __real__lock_init(lock); remember((const void*)(uintptr_t)*lock,(uintptr_t)__builtin_return_address(0),3);
}
void __real__lock_init_recursive(_lock_t* lock);
void __wrap__lock_init_recursive(_lock_t* lock) {
    __real__lock_init_recursive(lock); remember((const void*)(uintptr_t)*lock,(uintptr_t)__builtin_return_address(0),3);
}
void __real__lock_acquire(_lock_t* lock);
void __wrap__lock_acquire(_lock_t* lock) {
    __real__lock_acquire(lock);
    remember((const void*)(uintptr_t)*lock,(uintptr_t)__builtin_return_address(0),4);
}
void __real__lock_acquire_recursive(_lock_t* lock);
void __wrap__lock_acquire_recursive(_lock_t* lock) {
    __real__lock_acquire_recursive(lock);
    remember((const void*)(uintptr_t)*lock,(uintptr_t)__builtin_return_address(0),4);
}
