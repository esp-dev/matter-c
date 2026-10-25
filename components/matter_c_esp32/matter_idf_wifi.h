#ifndef MATTER_IDF_WIFI_H_INCLUDED
#define MATTER_IDF_WIFI_H_INCLUDED 1
#include "runtime/matter_runtime.h"
#include "esp_netif.h"
typedef struct Matter_Idf_Wifi* Matter_Idf_Wifi_T;
/* One physical STA, one owner. Application owns initialized/started Wi-Fi
 * driver, event loop and stable netif until delete. This port never stops the
 * shared driver/AP, erases NVS, creates tasks or deletes Matter/fabrics.
 * Control callbacks only stage effects; process owns SDK work/completions.
 * SDK events only copy a scan flag / disconnect reason under a short lock.
 * Default passive policy is gated: application enables it after runtime boot
 * recovery and outside an armed fail-safe. Explicit connect/restore jobs still
 * progress while gated. Retry is 0.5..30s with jitter, attempt timeout 20s.
 * Exact driver configuration is checked before treating a same-SSID existing
 * association as success; changed credentials force fresh authentication. */
Matter_Idf_Wifi_T matter_idf_wifi_new(esp_netif_t*,const Matter_Wifi_Settings_T*,uint32_t seed,uint64_t now);
Matter_Runtime_Wifi_Port_T matter_idf_wifi_port(Matter_Idf_Wifi_T);
void matter_idf_wifi_allow_reconnect(Matter_Idf_Wifi_T,bool allow);
/* Optional pump before an identity/runtime exists. model=NULL is valid only
 * without an explicit IM job; no Matter callback is made in that mode. */
Matter_Result_T matter_idf_wifi_process(Matter_Idf_Wifi_T,Matter_Wifi_T,uint64_t now);
Matter_Result_T matter_idf_wifi_delete(Matter_Idf_Wifi_T);
#endif
