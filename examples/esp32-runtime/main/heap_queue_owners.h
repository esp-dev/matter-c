#ifndef MATTER_LAB_HEAP_QUEUE_OWNERS_H
#define MATTER_LAB_HEAP_QUEUE_OWNERS_H 1
#include <stdint.h>
typedef struct { uintptr_t caller; unsigned kind; } HeapQueueOwner;
HeapQueueOwner matter_lab_heap_queue_owner(const void* address);
unsigned matter_lab_heap_queue_overflows(void);
#endif
