#ifndef MATTER_DISCOVERY_H_INCLUDED
#define MATTER_DISCOVERY_H_INCLUDED 1
#include "ports/matter_mdns_port.h"
/* Immutable, owned record builder for Core1.6.1 4.3.1/4.3.2. No OS/network,
 * global state, random generator or assumptions about active commissioning.
 * App supplies fresh random instance on every commissioning entry/boot and
 * current link-layer identity. Actual fabric identity, not FabricID, must be
 * supplied for operational names: compressed_fabric is 8 bytes in wire order.
 * Six-byte Ethernet/Wi-Fi MAC in this subset. No optional identifying TXT. */
typedef struct Matter_Discovery* Matter_Discovery_T;
Matter_Discovery_T matter_discovery_commissionable(const uint8_t mac[6],
    const uint8_t random_instance[8],uint16_t discriminator,uint8_t commissioning_mode,uint16_t port);
/* Application-supplied Core4.3.1.11 hint bitmap; no platform assumptions.
 * Caller supplies truthful methods without a required PI dependency (otherwise
 * compose a custom record including PI). Legacy constructor emits PH=0 in CM0,
 * claiming no method, and omits optional PH in open modes. */
Matter_Discovery_T matter_discovery_commissionable_with_hint(const uint8_t mac[6],
    const uint8_t random_instance[8],uint16_t discriminator,uint8_t commissioning_mode,uint16_t port,uint32_t pairing_hint);
Matter_Discovery_T matter_discovery_operational(const uint8_t mac[6],
    const uint8_t compressed_fabric[8],uint64_t node_id,uint16_t port);
/* Borrowed through delete, including all strings/arrays. Delete only after all
 * mDNS modules using the record have been stopped/drained/deleted. */
const Matter_Mdns_Record_T* matter_discovery_record(Matter_Discovery_T);
void matter_discovery_delete(Matter_Discovery_T);
#endif
