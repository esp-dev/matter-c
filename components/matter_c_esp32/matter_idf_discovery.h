#ifndef MATTER_IDF_DISCOVERY_H
#define MATTER_IDF_DISCOVERY_H 1
#include "matter_mdns.h"
typedef struct Matter_Idf_Discovery* Matter_Idf_Discovery_T;
/* App owns mdns_init/hostname/netif/mdns_free; keep that service live through
 * every binding's stop/drain/delete. One independent service per binding.
 * ESP mDNS copies strings; all API work/completion is deferred to process.
 * Supports builder records with <=8 TXT items/4 subtypes. Uses exact instance
 * removal, never removes unrelated advertisements or stops the shared service.
 * SDK success means registry installation, not peer receipt or a Matter ACK. */
Matter_Idf_Discovery_T matter_idf_discovery_new(Matter_T,const Matter_Mdns_Record_T*);
Matter_Mdns_T matter_idf_discovery_module(Matter_Idf_Discovery_T);
Matter_Result_T matter_idf_discovery_process(Matter_Idf_Discovery_T);
Matter_Result_T matter_idf_discovery_delete(Matter_Idf_Discovery_T);
#endif
