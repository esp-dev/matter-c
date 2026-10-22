#ifndef MATTER_IM_OUTPUT_INTERNAL_H
#define MATTER_IM_OUTPUT_INTERNAL_H 1
#include "matter_im_subscribe.h"
#include <stdlib.h>

/* Optional composition-owned encoder storage. A lease lasts through output
 * consumption, never through MRP/UDP borrowing of the independent ciphertext.
 * No callback, allocation, global owner or task-stack packet buffer. */
typedef struct {
    const void* owner;
    uint8_t bytes[MATTER_IM_READ_MAX_OUTPUT];
} Matter_Im_Output_Pool;
static inline bool matter_im_output_acquire(Matter_Im_Output_Pool* pool,const void* owner,uint8_t** bytes) {
    if(!pool) return true; /* Standalone engine keeps its original owned output. */
    if(pool->owner && pool->owner!=owner) return false;
    pool->owner=owner; *bytes=pool->bytes; return true;
}
static inline void matter_im_output_release(Matter_Im_Output_Pool* pool,const void* owner,uint8_t** bytes) {
    if(!pool) return;
    if(pool->owner==owner) pool->owner=NULL;
    *bytes=NULL;
}
static inline void matter_im_output_dispose(Matter_Im_Output_Pool* pool,const void* owner,uint8_t** bytes) {
    if(pool) matter_im_output_release(pool,owner,bytes);
    else { free(*bytes); *bytes=NULL; }
}
/* Bind once before receive. Frees the constructor's original output allocation;
 * borrowed pool outlives engine deletion. Standalone APIs keep their contract.
 * Contention yields before parser/provider work, with clocks/timeouts intact. */
Matter_Result_T matter_im_read_bind_output_pool(Matter_Im_Read_T,Matter_Im_Output_Pool*);
Matter_Result_T matter_im_subscribe_bind_output_pool(Matter_Im_Subscribe_T,Matter_Im_Output_Pool*);
/* Only after copying output into immutable MRP-owned storage. Relinquishes the
 * optional lease while preserving OUTPUT until first actual sent_at, so report
 * timing/activation does not move to enqueue. Further output polling blocks.
 * Standalone engines need no handoff and retain their original owned output. */
Matter_Result_T matter_im_subscribe_output_copied(Matter_Im_Subscribe_T);
#endif
