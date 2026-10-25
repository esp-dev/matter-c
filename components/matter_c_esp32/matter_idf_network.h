#ifndef MATTER_IDF_NETWORK_H_INCLUDED
#define MATTER_IDF_NETWORK_H_INCLUDED 1
#include "esp_netif.h"
#include "matter_udp.h"
typedef struct Matter_Idf_Network* Matter_Idf_Network_T;
/* One runtime, common quotas and dispatcher across UDP and commissioning BTP.
 * At most one RX SDU per owner poll, fair between bearers; immutable TX remains
 * pinned through each backend's terminal completion. IPv4/DHCP is not a gate. */
Matter_Idf_Network_T matter_idf_network_new(Matter_T,esp_netif_t*,uint16_t port,uint16_t vendor,uint16_t product,const Matter_Udp_Listener_T*);
Matter_Udp_T matter_idf_network_module(Matter_Idf_Network_T);
void matter_idf_network_window(Matter_Idf_Network_T,bool,uint16_t discriminator);
Matter_Result_T matter_idf_network_process(Matter_Idf_Network_T,uint64_t now);
uint32_t matter_idf_network_closed_take(Matter_Idf_Network_T);
Matter_Result_T matter_idf_network_delete(Matter_Idf_Network_T);
#endif
