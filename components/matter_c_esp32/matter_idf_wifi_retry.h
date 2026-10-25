#ifndef MATTER_IDF_WIFI_RETRY_H
#define MATTER_IDF_WIFI_RETRY_H
#include <stdbool.h>
#include <stdint.h>
typedef struct {
    uint64_t due,until;
    uint32_t attempts,random;
    bool enabled,online,connecting;
} Matter_Idf_Wifi_Retry_T;
void matter_idf_wifi_retry_init(Matter_Idf_Wifi_Retry_T*,uint32_t random,uint64_t now);
void matter_idf_wifi_retry_enabled(Matter_Idf_Wifi_Retry_T*,bool enabled,uint64_t now);
void matter_idf_wifi_retry_result(Matter_Idf_Wifi_Retry_T*,bool online,uint64_t now);
/* Single owner. A false permit suspends passive reconnect during an explicit
 * NetworkCommissioning operation; it never changes credentials or fabrics. */
bool matter_idf_wifi_retry_poll(Matter_Idf_Wifi_Retry_T*,uint64_t now,bool permit);
#endif
