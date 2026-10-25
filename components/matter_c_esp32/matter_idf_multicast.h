#ifndef MATTER_IDF_MULTICAST_H_INCLUDED
#define MATTER_IDF_MULTICAST_H_INCLUDED 1
#include "esp_netif.h"
#include "matter.h"
typedef struct Matter_Idf_Multicast* Matter_Idf_Multicast_T;
/* One owner/composition per borrowed physical netif. The application keeps the
 * netif/driver alive through deletion. All lwIP accesses take the TCPIP lock;
 * callbacks never enter Matter. Idempotence is local to this owner: one MLD
 * reference per address, independent of other users (mDNS, other services).
 * Join works before association; process restores reports after link recovery.
 * No fixed group table, no task, allocation failure leaves membership intact. */
Matter_Idf_Multicast_T matter_idf_multicast_new(esp_netif_t*);
Matter_Result_T matter_idf_multicast_join(void*,const uint8_t address[16]);
Matter_Result_T matter_idf_multicast_leave(void*,const uint8_t address[16]);
Matter_Result_T matter_idf_multicast_process(Matter_Idf_Multicast_T);
/* BUSY while owned memberships remain; composition must drain its leaves. */
Matter_Result_T matter_idf_multicast_delete(Matter_Idf_Multicast_T);
#endif
