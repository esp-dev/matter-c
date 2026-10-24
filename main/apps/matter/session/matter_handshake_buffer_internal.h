#ifndef MATTER_HANDSHAKE_BUFFER_INTERNAL_H
#define MATTER_HANDSHAKE_BUFFER_INTERNAL_H 1
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
/* Attempt-owned storage; no shared arena or borrowed transport references.
 * Growth is atomic. Erase before returning every allocation to the owner heap. */
static inline void matter_handshake_delete(void* data,size_t size) {
    if(data) { volatile uint8_t* p=data; while(size--) *p++=0; free(data); }
}
static inline void matter_handshake_clear(uint8_t** data,size_t* capacity) {
    matter_handshake_delete(*data,*capacity); *data=NULL; *capacity=0;
}
static inline bool matter_handshake_reserve(uint8_t** data,size_t* capacity,size_t size) {
    if(size<=*capacity) return true;
    uint8_t* next=calloc(1,size); if(!next) return false;
    if(*capacity) memcpy(next,*data,*capacity);
    matter_handshake_clear(data,capacity); *data=next; *capacity=size; return true;
}
static inline bool matter_handshake_copy(uint8_t** data,size_t* size,const uint8_t* source,size_t count) {
    uint8_t* next=calloc(1,count); if(!next) return false;
    memcpy(next,source,count); matter_handshake_clear(data,size); *data=next; *size=count; return true;
}
#endif
