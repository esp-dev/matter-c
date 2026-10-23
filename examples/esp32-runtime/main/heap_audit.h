#ifndef MATTER_LAB_HEAP_AUDIT_H
#define MATTER_LAB_HEAP_AUDIT_H 1
/* Included after now()/REQUIRE/sample. No heap allocation or static map buffer.
 * Eight descriptors use <224 B of owner stack; this C6 main reserves 12800 B,
 * with >9 KiB free in Memory20. Verify compiler frames/high watermarks as well.
 * Each page is captured under the SDK heap lock, then formatted outside it.
 * Fingerprints expose mutations between pages; this is not an atomic SDK trace. */
#if CONFIG_MATTER_C_RUNTIME_HEAP_AUDIT
#include "arch/sys_arch.h"
#if CONFIG_MATTER_C_RUNTIME_HEAP_QUEUE_OWNERS
#include "heap_queue_owners.h"
#endif
typedef struct { uintptr_t heap,end,address; size_t size; bool used; } HeapAuditBlock;
typedef struct {
    size_t skip,seen,count; uint32_t fingerprint;
    HeapAuditBlock blocks[8];
} HeapAuditPage;
typedef char HeapAuditStackBudget[(sizeof(HeapAuditPage)<=224)?1:-1];
static bool heap_audit_walk(walker_heap_into_t heap,walker_block_info_t block,void* user) {
    HeapAuditPage* page=user;
    uint32_t part=(uint32_t)heap.start^(uint32_t)(uintptr_t)block.ptr^(uint32_t)block.size^(block.used?1u:0u);
    page->fingerprint=(page->fingerprint^part)*16777619u;
    if(page->seen++>=page->skip && page->count<8)
        page->blocks[page->count++]=(HeapAuditBlock){(uintptr_t)heap.start,(uintptr_t)heap.end,(uintptr_t)block.ptr,block.size,block.used};
    return true;
}
static void heap_audit_state(const char* phase) {
    multi_heap_info_t info; heap_caps_get_info(&info,MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);
    Matter_Idf_Memory core=matter_idf_memory();
    printf("HEAP_STATE {\"phase\":\"%s\",\"ms\":%llu,\"heap_free\":%u,\"heap_allocated\":%u,"
        "\"largest_free\":%u,\"free_blocks\":%u,\"allocated_blocks\":%u,\"tasks\":%u,"
        "\"core_live\":%u,\"core_bytes\":%u}\n",phase,(unsigned long long)now(),
        (unsigned)info.total_free_bytes,(unsigned)info.total_allocated_bytes,(unsigned)info.largest_free_block,
        (unsigned)info.free_blocks,(unsigned)info.allocated_blocks,(unsigned)uxTaskGetNumberOfTasks(),
        (unsigned)core.live,(unsigned)core.live_bytes);
}
static void heap_audit_map(const char* phase) {
    size_t skip=0; uint32_t fingerprint=0; bool stable=true,complete=false;
    for(unsigned index=0;index<256;++index) {
        HeapAuditPage page={.skip=skip,.fingerprint=2166136261u};
        heap_caps_walk(MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT,heap_audit_walk,&page);
        if(!index) fingerprint=page.fingerprint;
        else if(fingerprint!=page.fingerprint) stable=false;
        for(size_t i=0;i<page.count;++i) {
            const HeapAuditBlock* b=&page.blocks[i];
            unsigned caller=0,kind=0;
#if CONFIG_MATTER_C_RUNTIME_HEAP_QUEUE_OWNERS
            HeapQueueOwner owner=matter_lab_heap_queue_owner((const void*)b->address);
            caller=(unsigned)owner.caller; kind=owner.kind;
#endif
            printf("HEAP_BLOCK {\"phase\":\"%s\",\"heap\":%u,\"end\":%u,\"address\":%u,\"size\":%u,\"used\":%s,\"queue_caller\":%u,\"queue_kind\":%u}\n",
                phase,(unsigned)b->heap,(unsigned)b->end,(unsigned)b->address,(unsigned)b->size,b->used?"true":"false",caller,kind);
        }
        skip+=page.count;
        if(skip>=page.seen) { complete=true; break; }
    }
    printf("HEAP_MAP {\"phase\":\"%s\",\"blocks\":%u,\"fingerprint\":%u,\"stable\":%s,\"complete\":%s}\n",
        phase,(unsigned)skip,(unsigned)fingerprint,stable?"true":"false",complete?"true":"false");
}
static void heap_audit_settle(void) {
    const uint64_t begin=now();
    heap_audit_state("complete-immediate");
    /* Relative deadlines include map/UART time; actual timestamps are emitted.
     * Delay yields to idle/timer/tcpip tasks without adding a protocol timeout. */
    const unsigned delays[]={20,100,500,2000,5000
#if CONFIG_MATTER_C_RUNTIME_HEAP_SETTLE_LONG
        ,15000,30000,65000
#endif
    };
    const char* phases[]={"complete-20ms","complete-100ms","complete-500ms","complete-2s","complete-5s"
#if CONFIG_MATTER_C_RUNTIME_HEAP_SETTLE_LONG
        ,"complete-15s","complete-30s","complete-65s"
#endif
    };
    for(size_t i=0;i<sizeof(delays)/sizeof(*delays);++i) {
        uint64_t elapsed=now()-begin;
        if(elapsed<delays[i]) vTaskDelay(pdMS_TO_TICKS(delays[i]-elapsed)+1);
        REQUIRE(heap_caps_check_integrity_all(true));
        sample(phases[i]); heap_audit_state(phases[i]);
#if CONFIG_MATTER_C_RUNTIME_HEAP_SETTLE_LONG
        if(delays[i]==5000) heap_audit_map("complete-5s");
#endif
    }
#if CONFIG_MATTER_C_RUNTIME_HEAP_SETTLE_LONG
    heap_audit_map("complete-65s"); heap_audit_state("after-final-map");
#else
    heap_audit_map("complete-5s"); heap_audit_state("after-final-map");
#endif
#if CONFIG_MATTER_C_RUNTIME_HEAP_QUEUE_OWNERS
    printf("HEAP_OWNER {\"name\":\"queue-map-overflows\",\"count\":%u}\n",matter_lab_heap_queue_overflows());
#endif
}
static void heap_audit_thread_before(void) {
    /* The lab's main task survives forever after its LAST socket/netif call.
     * lwIP's per-thread semaphore otherwise survives until that task exits.
     * Read its existing handle after the exercised socket path, then use the
     * public cleanup API, never delete guessed SDK/global pointers directly. */
    sys_sem_t* sem=sys_thread_sem_get();
    printf("HEAP_OWNER {\"name\":\"lwip-owner-thread-semaphore\",\"address\":%u,\"size\":%u}\n",
        (unsigned)(uintptr_t)sem,(unsigned)heap_caps_get_allocated_size(sem));
}
static void heap_audit_thread_after(void) {
    heap_audit_state("owner-thread-cleaned"); heap_audit_map("owner-thread-cleaned");
}
#define HEAP_STATE(phase) heap_audit_state(phase)
#define HEAP_SETTLE() heap_audit_settle()
#define HEAP_THREAD_BEFORE() heap_audit_thread_before()
#define HEAP_THREAD_AFTER() heap_audit_thread_after()
#else
#define HEAP_STATE(phase) ((void)0)
#define HEAP_SETTLE() ((void)0)
#define HEAP_THREAD_BEFORE() ((void)0)
#define HEAP_THREAD_AFTER() ((void)0)
#endif
#endif
