#ifndef MATTER_IDF_MEMORY_H_INCLUDED
#define MATTER_IDF_MEMORY_H_INCLUDED 1
#include <stddef.h>
#include <stdlib.h>
typedef struct {
    size_t calls, failures, live, live_bytes, peak_bytes, largest_request;
} Matter_Idf_Memory;
/* Optional laboratory accounting, serialized by the application's owner task.
 * Bytes are allocator block sizes; whole-system heap must be sampled separately.
 * fail_after(1) rejects the next library allocation once. Zero disables it. */
Matter_Idf_Memory matter_idf_memory(void);
void matter_idf_memory_fail_after(size_t);
void* matter_idf_calloc(size_t, size_t);
void matter_idf_free(void*);
#ifdef MATTER_C_PROFILE_ALLOCATOR
#define calloc matter_idf_calloc
#define free matter_idf_free
#endif
#endif
