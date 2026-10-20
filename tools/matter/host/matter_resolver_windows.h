#ifndef MATTER_RESOLVER_WINDOWS_H_INCLUDED
#define MATTER_RESOLVER_WINDOWS_H_INCLUDED 1
#include "matter_mdns_windows.h"
#include "ports/matter_resolver_port.h"
typedef struct Matter_Resolver_Windows* Matter_Resolver_Windows_T;
/* Four copied jobs; owner-polled mDNS SRV/TXT/AAAA, selected interface only.
 * Own sockets/heap, no thread. 5s timeout, no persistent DNS cache. Provider
 * outlives consumers; cancel/take all jobs before delete. IPv6 UDP endpoints.
 * Fatal RX completes pending jobs as FAILED. The next valid start attempts to
 * reopen sockets on the configured interface; failure retains no new job/ID.
 * No background retry or interface/address rediscovery is performed. */
Matter_Resolver_Windows_T matter_resolver_windows_new(const Matter_Mdns_Windows_Interface_T*);
Matter_Resolver_Port_T matter_resolver_windows_port(Matter_Resolver_Windows_T);
Matter_Result_T matter_resolver_windows_poll(Matter_Resolver_Windows_T,uint64_t now);
Matter_Result_T matter_resolver_windows_delete(Matter_Resolver_Windows_T);
#endif
