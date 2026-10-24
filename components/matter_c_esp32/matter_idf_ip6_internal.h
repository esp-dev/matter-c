#ifndef MATTER_IDF_IP6_INTERNAL_H
#define MATTER_IDF_IP6_INTERNAL_H 1
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
/* lwIP validated each extension within the same first pbuf before advancing
 * its payload. The original header span remains live during its UDP callback.
 * Reject every Fragment header, including atomic fragments (lwIP accepts those
 * even with reassembly disabled). Header length comes from lwIP, never the peer. */
static inline bool matter_idf_ip6_headers(const uint8_t* bytes,size_t size) {
    if(size<40 || size>1280 || (bytes[0]>>4)!=6) return false;
    uint8_t next=bytes[6]; size_t offset=40;
    while(offset<size) {
        if((next!=0 && next!=43 && next!=60) || size-offset<2) return false;
        size_t length=((size_t)bytes[offset+1]+1)*8;
        if(length>size-offset) return false;
        next=bytes[offset]; offset+=length;
    }
    return next==17;
}
#endif
