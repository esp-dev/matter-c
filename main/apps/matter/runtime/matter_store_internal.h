#ifndef MATTER_STORE_INTERNAL_H
#define MATTER_STORE_INTERNAL_H 1
#include "matter_commissioning_host.h"
#include "../storage/matter_store_tlv.h"
/* Overrides are borrowed only during publish. Error leaves durable state old.
 * Host reference adapter performs synchronous file I/O on the owner's thread;
 * no calls from RX callbacks, ISR or a firmware task with a latency budget. */
typedef struct {
    void* user;
    /* commit_fabrics projects cleared fail-safe fields into TLV; the borrowed
     * live image stays pending and immutable throughout the synchronous call. */
    Matter_Result_T (*publish)(void*,const Matter_Store_Fabrics_T*,const Matter_Store_Wifi_T*,bool commit_fabrics);
    Matter_Result_T (*reset)(void*,const Matter_Store_Fabrics_T*); /* Last fabric: atomic commissioned-data reset. */
} Matter_Store_Persist_T;
struct Matter_Fabric_Host_Image { Matter_Store_Fabrics_T data; bool attached; Matter_Store_Persist_T persist; };
struct Matter_Commissioning_Host_Image { Matter_Store_Wifi_T data; bool attached; Matter_Store_Persist_T persist; };
Matter_Result_T matter_fabric_host_publish_commit(Matter_Fabric_Host_T,const Matter_Store_Wifi_T*);
Matter_Result_T matter_fabric_host_apply_commit(Matter_Fabric_Host_T);
#endif
