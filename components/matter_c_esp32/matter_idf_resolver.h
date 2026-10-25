#ifndef MATTER_IDF_RESOLVER_H
#define MATTER_IDF_RESOLVER_H 1
#include "ports/matter_resolver_port.h"
#include "esp_netif.h"
typedef struct Matter_Idf_Resolver* Matter_Idf_Resolver_T;
/* Application initializes mDNS and owns netif until delete. No extra task or
 * callback into runtime; take polls SDK async searches with zero wait. Up to
 * eight demand-owned searches. Cancel drains the SDK search before completion;
 * keep pumping runtime during stop. Scoped IPv6 only, no IPv4 translation. */
Matter_Idf_Resolver_T matter_idf_resolver_new(esp_netif_t*);
Matter_Resolver_Port_T matter_idf_resolver_port(Matter_Idf_Resolver_T);
Matter_Result_T matter_idf_resolver_delete(Matter_Idf_Resolver_T);
#endif
