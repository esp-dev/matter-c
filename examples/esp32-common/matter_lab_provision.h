#ifndef MATTER_LAB_PROVISION_H
#define MATTER_LAB_PROVISION_H 1
/* Private lab network data is provisioned locally into NVS, never embedded in
 * source archives/build logs. Caller clears and releases its Wi-Fi config. */
#include "nvs.h"
#include "esp_wifi.h"
#include <string.h>
static bool matter_lab_wifi_config(wifi_config_t* cfg,size_t* ssid,size_t* password) {
    nvs_handle_t handle;
    if(nvs_open("lab_wifi",NVS_READONLY,&handle)!=ESP_OK) return false;
    *ssid=sizeof(cfg->sta.ssid); *password=sizeof(cfg->sta.password); memset(cfg,0,sizeof(*cfg));
    esp_err_t a=nvs_get_blob(handle,"ssid",cfg->sta.ssid,ssid);
    esp_err_t b=nvs_get_blob(handle,"password",cfg->sta.password,password); nvs_close(handle);
    cfg->sta.threshold.authmode=WIFI_AUTH_WPA2_PSK;
    return a==ESP_OK && b==ESP_OK && *ssid && *ssid<=32 && *password<=64;
}
#endif
