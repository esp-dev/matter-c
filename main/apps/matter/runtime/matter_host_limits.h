#ifndef MATTER_HOST_LIMITS_H
#define MATTER_HOST_LIMITS_H 1
#include "../clusters/matter_fabric.h"
#include "../transport/matter_exchange.h"
/* Host composition budget, shared by admission and Basic Information. Fabric
 * indexes are opaque (1..254), never array offsets. PASE has a separate bucket. */
enum { MATTER_HOST_CASE_PER_FABRIC=3, MATTER_HOST_SUBS_MIN=3, MATTER_HOST_SUBS_MAX=10000,
    MATTER_HOST_SUBS_PER_FABRIC=MATTER_HOST_SUBS_MIN,
    MATTER_HOST_INVOKES=1, MATTER_HOST_WRITES=1,
    MATTER_HOST_READ_PATHS=9, MATTER_HOST_SUBSCRIBE_PATHS=3,
    MATTER_HOST_CONNECTIONS=MATTER_FABRIC_CAPACITY*MATTER_HOST_CASE_PER_FABRIC+1,
    MATTER_HOST_HANDSHAKES=2, MATTER_HOST_REJECTIONS=2,
    MATTER_HOST_DELIVERY_BURST=8,
    /* Per fabric/PASE: 3 subscriptions + one replacement candidate + one Read
     * + one finished Read awaiting ACK. Invoke/Write also have a delivery slot.
     * Eight shared delivery slots absorb sequential commands before delayed ACK.
     * No borrowed bytes are freed early; stalled ACKs cannot grow these pools. */
    MATTER_HOST_TRANSACTIONS=(MATTER_FABRIC_CAPACITY+1)*(MATTER_HOST_SUBS_PER_FABRIC+3)
        +2*(MATTER_HOST_INVOKES+MATTER_HOST_WRITES)+MATTER_HOST_HANDSHAKES+MATTER_HOST_REJECTIONS
        +MATTER_HOST_DELIVERY_BURST };
#define MATTER_HOST_CAPABILITIES {MATTER_HOST_CASE_PER_FABRIC,MATTER_HOST_SUBS_PER_FABRIC,\
    MATTER_HOST_INVOKES,MATTER_HOST_WRITES,MATTER_HOST_READ_PATHS,MATTER_HOST_SUBSCRIBE_PATHS}
/* Core CapabilityMinima permits 3..10000. This composition additionally needs
 * transport space for every fabric, optional PASE and protected non-Subscribe
 * work. Zero means the configured build cannot provide that guarantee. */
static inline size_t matter_host_transaction_capacity(uint16_t subscriptions) {
    if(subscriptions<MATTER_HOST_SUBS_MIN || subscriptions>MATTER_HOST_SUBS_MAX) return 0;
    size_t slots=(MATTER_FABRIC_CAPACITY+1)*((size_t)subscriptions+3)
        +2*(MATTER_HOST_INVOKES+MATTER_HOST_WRITES)+MATTER_HOST_HANDSHAKES+MATTER_HOST_REJECTIONS
        +MATTER_HOST_DELIVERY_BURST;
    return slots<=MATTER_TRANSPORT_CAPACITY?slots:0;
}
#endif
