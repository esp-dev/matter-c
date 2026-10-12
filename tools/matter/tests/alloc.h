#ifndef MATTER_TEST_ALLOC_H_INCLUDED
#define MATTER_TEST_ALLOC_H_INCLUDED 1

#include <stdlib.h>

void* matter_test_calloc(size_t count, size_t size);
void matter_test_free(void* ptr);

/* Only the production object is compiled with replacement enabled. The test
 * wrappers call real libc so ASan still sees the allocations and frees.
 */
#ifdef MATTER_TEST_ALLOC_REPLACE
#define calloc matter_test_calloc
#define free matter_test_free
#endif

#endif
