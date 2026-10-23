/* Attribution-only SDK link wrappers. Never free SDK resources by guessing
 * their type from a heap map. No allocation/formatting under this guard. */
#include "heap_queue_owners.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include <pthread.h>
#include "esp_heap_caps.h"
#include <sys/lock.h>
typedef struct { uintptr_t address,caller; unsigned kind; } Entry;
#if CONFIG_MATTER_C_RUNTIME_HEAP_SMALL_OWNERS
enum { OWNER_SLOTS=1024 };
#else
enum { OWNER_SLOTS=128 };
#endif
static Entry entries[OWNER_SLOTS];
static unsigned overflows;
static portMUX_TYPE guard=portMUX_INITIALIZER_UNLOCKED;
static void remember(const void* address,uintptr_t caller,unsigned kind) {
    if(!address) return;
    uintptr_t identity=(uintptr_t)address;
    portENTER_CRITICAL(&guard);
    Entry* available=NULL;
    for(unsigned i=0;i<OWNER_SLOTS;++i) {
        if(entries[i].address==identity) { available=&entries[i]; break; }
        if(!entries[i].address && !available) available=&entries[i];
    }
    /* The first attributed lock owner replaces the generic queue creator.
     * Later acquisitions retain it. The handle is read only after acquiring
     * the real mutex, never raced against its lazy initialization. */
    if(available) {
        if((kind!=4 && kind!=5) || available->address!=identity ||
            (kind==5?available->kind!=5:available->kind<3))
            *available=(Entry){identity,caller,kind};
    } else ++overflows;
    portEXIT_CRITICAL(&guard);
}
static void forget(uintptr_t address) {
    if(!address) return;
    portENTER_CRITICAL(&guard);
    for(unsigned i=0;i<OWNER_SLOTS;++i) if(entries[i].address==address) entries[i]=(Entry){0};
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
    forget((uintptr_t)queue);
    __real_vQueueDelete(queue);
}
/* IDF 6.1 pthread_local_storage.c owns TLS slot 0. Remember only its list
 * head, never keys/values or payload contents. The head survives removing
 * the lwIP key until task exit and can pin a large free region. kind 5 is
 * the first successful setter; a later clear must not replace that caller. */
int __real_pthread_setspecific(pthread_key_t key,const void* value);
int __wrap_pthread_setspecific(pthread_key_t key,const void* value) {
    int result=__real_pthread_setspecific(key,value);
    if(!result) remember(pvTaskGetThreadLocalStoragePointer(NULL,0),(uintptr_t)__builtin_return_address(0),5);
    return result;
}
/* pthread task-exit cleanup frees its head with free(). Forget it before
 * address reuse, including non-queue allocations; no allocator/log in guard. */
void __real_free(void* address);
void __wrap_free(void* address) { forget((uintptr_t)address); __real_free(address); }
#if CONFIG_MATTER_C_RUNTIME_HEAP_SMALL_OWNERS
#include "lwip/memp.h"
#include "lwip/priv/memp_priv.h"
/* Requested-size filter; the walked block can be larger due to allocator
 * rounding. Keep the outer caller if libc delegates to a caps API. */
static void remember_small(void* address,size_t size,uintptr_t caller,unsigned kind) {
    if(size<=32) remember(address,caller,kind);
}
void* __real_malloc(size_t size);
void* __wrap_malloc(size_t size) {
    void* p=__real_malloc(size); remember_small(p,size,(uintptr_t)__builtin_return_address(0),6); return p;
}
void* __real_calloc(size_t n,size_t size);
void* __wrap_calloc(size_t n,size_t size) {
    void* p=__real_calloc(n,size);
    if(!n || size<=32/n) remember_small(p,n*size,(uintptr_t)__builtin_return_address(0),7);
    return p;
}
void* __real_heap_caps_malloc(size_t size,uint32_t caps);
void* __wrap_heap_caps_malloc(size_t size,uint32_t caps) {
    void* p=__real_heap_caps_malloc(size,caps); remember_small(p,size,(uintptr_t)__builtin_return_address(0),9); return p;
}
void* __real_heap_caps_calloc(size_t n,size_t size,uint32_t caps);
void* __wrap_heap_caps_calloc(size_t n,size_t size,uint32_t caps) {
    void* p=__real_heap_caps_calloc(n,size,caps);
    if(!n || size<=32/n) remember_small(p,n*size,(uintptr_t)__builtin_return_address(0),10);
    return p;
}
void __real_heap_caps_free(void* p);
void __wrap_heap_caps_free(void* p) { forget((uintptr_t)p); __real_heap_caps_free(p); }
static void resized(uintptr_t old,void* p,size_t size,uintptr_t caller,unsigned kind) {
    /* Failure for a nonzero request preserves the old allocation/record. A
     * successful in-place resize also replaces its old size/caller identity. */
    if(p || !size) { forget(old); remember_small(p,size,caller,kind); }
}
void* __real_realloc(void* old,size_t size);
void* __wrap_realloc(void* old,size_t size) {
    uintptr_t previous=(uintptr_t)old;
    void* p=__real_realloc(old,size); resized(previous,p,size,(uintptr_t)__builtin_return_address(0),8); return p;
}
void* __real_heap_caps_realloc(void* old,size_t size,uint32_t caps);
void* __wrap_heap_caps_realloc(void* old,size_t size,uint32_t caps) {
    uintptr_t previous=(uintptr_t)old;
    void* p=__real_heap_caps_realloc(old,size,caps); resized(previous,p,size,(uintptr_t)__builtin_return_address(0),11); return p;
}
/* Pool identity disambiguates equally sized lwIP objects. This IDF profile
 * uses heap-backed pools without an overflow prefix, so the returned payload
 * is the allocation address. Inspect only static pool metadata, not payload. */
void* __real_memp_malloc(memp_t type);
void* __wrap_memp_malloc(memp_t type) {
    void* p=__real_memp_malloc(type);
#if MEMP_MEM_MALLOC && !MEMP_OVERFLOW_CHECK
    if(p && memp_pools[type]->size<=32) remember(p,(uintptr_t)__builtin_return_address(0),64u+(unsigned)type);
#endif
    return p;
}
void __real_memp_free(memp_t type,void* p);
void __wrap_memp_free(memp_t type,void* p) { forget((uintptr_t)p); __real_memp_free(type,p); }
#endif
HeapQueueOwner matter_lab_heap_queue_owner(const void* address) {
    HeapQueueOwner result={0};
    portENTER_CRITICAL(&guard);
    for(unsigned i=0;i<OWNER_SLOTS;++i) if(entries[i].address==(uintptr_t)address) { result=(HeapQueueOwner){entries[i].caller,entries[i].kind}; break; }
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
