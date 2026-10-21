#ifndef MATTER_LAB_WIFI_PORT_H
#define MATTER_LAB_WIFI_PORT_H 1
#include "runtime/matter_runtime.h"
#include "esp_netif.h"
typedef struct Lab_Wifi* Lab_Wifi_T;
/* One physical STA, SDK driver/netif lifetime owned by app. Backend only stages
 * in callbacks; radio effects and completions run in owner process. */
Lab_Wifi_T lab_wifi_new(esp_netif_t*,const Matter_Wifi_Settings_T*);
Matter_Runtime_Wifi_Port_T lab_wifi_port(Lab_Wifi_T);
Matter_Result_T lab_wifi_delete(Lab_Wifi_T);
/* Local fixture: force an actual restore/reconnect while boot admission is gated. */
void lab_wifi_reconnect(Lab_Wifi_T);
#endif
