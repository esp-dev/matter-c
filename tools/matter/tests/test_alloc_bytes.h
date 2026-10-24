#ifndef MATTER_TEST_ALLOC_BYTES_H
#define MATTER_TEST_ALLOC_BYTES_H 1
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
/* Test-only accounting: track requested payload bytes, excluding libc metadata.
 * The wrappers themselves use real libc; production objects alone are replaced. */
typedef struct TestAllocation { void* pointer; size_t size; struct TestAllocation* next; } TestAllocation;
static TestAllocation* allocations;
static size_t live,calls,fail_at,live_bytes,peak_bytes,max_request;
static inline size_t matter_test_allocation_size(const void* pointer) {
    for(TestAllocation* a=allocations;a;a=a->next) if(a->pointer==pointer) return a->size;
    return 0;
}
void* matter_test_calloc(size_t n,size_t z) {
    if(++calls==fail_at || (n && z>SIZE_MAX/n)) return NULL;
    void* p=calloc(n,z); if(!p) return NULL;
    TestAllocation* a=malloc(sizeof(*a)); assert(a);
    *a=(TestAllocation){p,n*z,allocations}; allocations=a; ++live; live_bytes+=a->size;
    if(live_bytes>peak_bytes) peak_bytes=live_bytes;
    if(a->size>max_request) max_request=a->size;
#ifdef MATTER_TEST_ALLOC_AFTER_ALLOC
    MATTER_TEST_ALLOC_AFTER_ALLOC(p,a->size);
#endif
    return p;
}
void matter_test_free(void* p) {
    if(p) {
        TestAllocation** a=&allocations;
        while(*a && (*a)->pointer!=p) a=&(*a)->next;
        assert(*a && live); TestAllocation* old=*a; *a=old->next;
#ifdef MATTER_TEST_ALLOC_BEFORE_FREE
        MATTER_TEST_ALLOC_BEFORE_FREE(p,old->size);
#endif
        --live; live_bytes-=old->size; free(old);
    }
    free(p);
}
#endif
