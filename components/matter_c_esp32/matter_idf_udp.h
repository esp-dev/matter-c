#ifndef MATTER_IDF_UDP_H
#define MATTER_IDF_UDP_H 1
#include "esp_netif.h"
#include "matter_udp.h"
typedef struct Matter_Idf_Udp* Matter_Idf_Udp_T;
/* One owner, borrowed netif through delete. Uses the application's lwIP service,
 * no task. RX metadata comes from the raw IPv6 input context. Starts with one
 * heap RX slot; observed overflow lets the owner grow a stable FIFO to eight.
 * Extra free slots trim after ten seconds without RX. Growth OOM preserves
 * existing slots; a full FIFO drops datagrams without blocking the raw callback.
 * The raw callback cannot call Matter. process delivers RX/completions on owner.
 * Disable IPv6 reassembly: neither fragmented nor oversize packets reach core.
 * Core locking serializes callback/activate/deactivate/detach barriers. */
/* Paths use the netif's index at adapter construction as a stable scope key.
 * TX translates that key to its current lwIP zone after radio stop/start.
 * Link loss or a pinned source awaiting IPv6/DAD returns OFFLINE for bounded
 * MRP retry; it is not an invalid packet/path argument. */
Matter_Idf_Udp_T matter_idf_udp_new(Matter_T,esp_netif_t*,uint16_t,const Matter_Udp_Listener_T*);
Matter_Udp_T matter_idf_udp_module(Matter_Idf_Udp_T);
Matter_Result_T matter_idf_udp_process(Matter_Idf_Udp_T);
Matter_Result_T matter_idf_udp_delete(Matter_Idf_Udp_T);
typedef struct { uint32_t received,dropped,oversize,extensions,sent,rx_buffers,rx_buffer_peak; } Matter_Idf_Udp_Stats_T;
Matter_Idf_Udp_Stats_T matter_idf_udp_stats(Matter_Idf_Udp_T);
#endif
