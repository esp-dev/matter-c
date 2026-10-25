#ifndef MATTER_WIFI_INTERNAL_H_INCLUDED
#define MATTER_WIFI_INTERNAL_H_INCLUDED 1
#include "matter_wifi.h"
/* Shared construction/provisioning schema, no effects or port calls. */
bool matter_wifi_settings_valid(const Matter_Wifi_Settings_T*,const Matter_Wifi_Id_T*,unsigned maximum);
#endif
