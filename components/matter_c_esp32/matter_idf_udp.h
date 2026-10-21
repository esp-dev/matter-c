#ifndef MATTER_IDF_UDP_H
#define MATTER_IDF_UDP_H 1
#include "esp_netif.h"
#include "matter_udp.h"
typedef struct Matter_Idf_Udp* Matter_Idf_Udp_T;
/* One owner, borrowed netif through delete. Uses the application's lwIP service,
 * no task. RX metadata comes from the raw IPv6 input context. One heap RX slot
 * per active binding; concurrent/burst RX while occupied is dropped, never blocks.
 * The raw callback cannot call Matter. process delivers RX/completions on owner.
 * Disable IPv6 reassembly: neither fragmented nor oversize packets reach core.
 * Core locking serializes callback/activate/deactivate/detach barriers. */
Matter_Idf_Udp_T matter_idf_udp_new(Matter_T,esp_netif_t*,uint16_t,const Matter_Udp_Listener_T*);
Matter_Udp_T matter_idf_udp_module(Matter_Idf_Udp_T);
Matter_Result_T matter_idf_udp_process(Matter_Idf_Udp_T);
Matter_Result_T matter_idf_udp_delete(Matter_Idf_Udp_T);
typedef struct { uint32_t received,dropped,oversize,extensions,sent; } Matter_Idf_Udp_Stats_T;
Matter_Idf_Udp_Stats_T matter_idf_udp_stats(Matter_Idf_Udp_T);
#endif
