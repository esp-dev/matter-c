#ifndef MATTER_IM_CHUNK_INTERNAL_H_INCLUDED
#define MATTER_IM_CHUNK_INTERNAL_H_INCLUDED 1
#include "matter_im_read.h"
#include <stdint.h>

/* Private report plan, never a wire path or public DTO. Zero offsets retain
 * the whole-value sentinel; ARRAY boundaries are within the validated value.
 * Cursors and arithmetic stay size_t until the checked plan assignment. */
typedef struct {
    uint16_t item,start,end;
    bool prefix;
} Matter_Im_Chunk_Plan;
typedef char Matter_Im_Chunk_Limits[
    (MATTER_IM_READ_MAX_RESULTS<=UINT16_MAX && MATTER_IM_READ_MAX_VALUE<=UINT16_MAX &&
     sizeof(Matter_Im_Chunk_Plan)==8)?1:-1];
static inline bool matter_im_chunk_begin(Matter_Im_Chunk_Plan* plan,size_t item,size_t start) {
    if(item>=MATTER_IM_READ_MAX_RESULTS || start>MATTER_IM_READ_MAX_VALUE) return false;
    *plan=(Matter_Im_Chunk_Plan){(uint16_t)item,(uint16_t)start,0,false}; return true;
}
static inline bool matter_im_chunk_end(Matter_Im_Chunk_Plan* plan,size_t end) {
    if(end>MATTER_IM_READ_MAX_VALUE) return false;
    plan->end=(uint16_t)end; return true;
}
#endif
