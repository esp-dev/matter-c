#ifndef MATTER_STORE_BLOB_H
#define MATTER_STORE_BLOB_H 1
#include "../matter.h"
#include <stddef.h>
/* Application-owned blob transport: file on host, same TLV in one NVS blob
 * on ESP32. Synchronous storage adapter boundary; owner schedules disk/flash I/O.
 * No retained data pointers. Single writer per location. OFFLINE means missing,
 * never corruption/I/O failure. replace: OK publishes all bytes, error leaves
 * the previous readable blob unchanged. No write followed by a fallible step. */
typedef struct {
    void* user;
    Matter_Result_T (*read)(void*,uint8_t*,size_t,size_t*);
    Matter_Result_T (*replace)(void*,const uint8_t*,size_t);
} Matter_Store_Blob_Port_T;
#endif
