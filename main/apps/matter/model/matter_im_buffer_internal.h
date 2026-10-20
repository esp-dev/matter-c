#ifndef MATTER_IM_BUFFER_INTERNAL_H
#define MATTER_IM_BUFFER_INTERNAL_H 1
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
static inline void matter_im_workspace_delete(void* data,size_t size) {
    if(data) { volatile uint8_t* p=data; while(size--) *p++=0; free(data); }
}
/* Per-handler storage. Growth publishes only after successful allocation;
 * callers reserve every possible reply/scratch byte before model effects. */
static inline void matter_im_buffer_clear(uint8_t** data,size_t* capacity) {
    volatile uint8_t* p=*data;
    for(size_t i=0;i<*capacity;++i) p[i]=0;
    free(*data); *data=NULL; *capacity=0;
}
static inline bool matter_im_buffer_reserve(uint8_t** data,size_t* capacity,size_t size) {
    if(size<=*capacity) return true;
    uint8_t* next=calloc(1,size); if(!next) return false;
    if(*capacity) memcpy(next,*data,*capacity);
    matter_im_buffer_clear(data,capacity); *data=next; *capacity=size; return true;
}
/* Emergency StatusResponse needs no parser/writer allocation. The caller owns
 * at least eight output bytes and must respect the same delivery state gates. */
static inline void matter_im_status_bytes(uint8_t* data,uint8_t code,uint8_t revision) {
    static const uint8_t status[]={0x15,0x24,0,0,0x24,255,0,0x18};
    memcpy(data,status,sizeof(status)); data[3]=code; data[6]=revision;
}
#endif
