/* Test allocator only. libc/Mbed TLS/OS overhead is not part of this metric. */
#include <stdbool.h>
#include "wire_faults.h"
#include <assert.h>
#include <stdlib.h>
typedef struct Allocation { void* pointer; size_t size; struct Allocation* next; } Allocation;
static Allocation* allocations;
static size_t fail_at;
Wire_Stats wire_stats;
bool wire_completion_pending;
void wire_fail_after(size_t n) { fail_at=n?wire_stats.calls+n:0; }
static void* allocate(size_t n,size_t z,bool zero) {
    ++wire_stats.calls;
    if(wire_stats.calls==fail_at || (n && z>SIZE_MAX/n)) { ++wire_stats.failures; return NULL; }
    void* p=zero?calloc(n,z):malloc(n*z); if(!p) { ++wire_stats.failures; return NULL; }
    Allocation* a=malloc(sizeof(*a)); assert(a);
    *a=(Allocation){p,n*z,allocations}; allocations=a;
    ++wire_stats.live; wire_stats.bytes+=a->size;
    if(wire_stats.bytes>wire_stats.peak) wire_stats.peak=wire_stats.bytes;
    return p;
}
void* wire_calloc(size_t n,size_t z) { return allocate(n,z,true); }
void* wire_malloc(size_t n) { return allocate(1,n,false); }
void wire_free(void* p) {
    if(!p) return;
    Allocation** a=&allocations;
    while(*a && (*a)->pointer!=p) a=&(*a)->next;
    assert(*a && wire_stats.live); Allocation* old=*a; *a=old->next;
    --wire_stats.live; wire_stats.bytes-=old->size; free(old); free(p);
}
