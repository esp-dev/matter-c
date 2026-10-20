#ifndef MATTER_STORE_SOURCE_INTERNAL_H
#define MATTER_STORE_SOURCE_INTERNAL_H 1
#include "matter_store_tlv.h"
/* Synchronous, owner-thread encoding borrows the guarded Fabric candidate.
 * All pointers remain valid and immutable until encode returns. No retained
 * references, format changes or second Fabric image in publication staging. */
typedef struct {
    uint32_t schema;
    const Matter_Store_Fabrics_T* fabrics;
    const Matter_Store_Wifi_T* wifi;
    const Matter_Root_Settings_T* root;
    uint32_t hours; uint16_t reboots;
    const Matter_Eem_Checkpoint_T* eem;
    uint64_t event_high;
    const Matter_Ota_Provider_T* ota;
} Matter_Store_Source_T;
static inline Matter_Store_Source_T matter_store_source(const Matter_Store_Data_T* d) {
    return (Matter_Store_Source_T){d->schema,&d->fabrics,&d->wifi,&d->root,d->hours,d->reboots,&d->eem,d->event_high,d->ota};
}
bool matter_store_source_valid(const Matter_Store_Source_T*);
/* On success caller owns exactly *size zero-initialized/encoded bytes, to erase
 * and free after blob.replace. Every failure leaves *bytes=NULL and *size=0. */
Matter_Result_T matter_store_source_encode(const Matter_Store_Source_T*,uint8_t** bytes,size_t* size);
#endif
