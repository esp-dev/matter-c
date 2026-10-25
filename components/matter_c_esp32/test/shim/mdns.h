#ifndef MATTER_RESOLVER_MDNS_SHIM_H
#define MATTER_RESOLVER_MDNS_SHIM_H 1
#include "sdk.h"
#include "esp_netif.h"
#include <assert.h>
#define MDNS_TYPE_SRV 33
#define MDNS_TYPE_TXT 16
#define MDNS_TYPE_AAAA 28
#define MDNS_TYPE_ANY 255
#define ESP_IPADDR_TYPE_V6 6
#define ESP_ERROR_CHECK(x) assert((x)==ESP_OK)
typedef struct { const char* key; const char* value; } mdns_txt_item_t;
typedef struct mdns_ip_addr_s { struct mdns_ip_addr_s* next; struct { int type; union { struct { uint32_t addr[4]; } ip6; } u_addr; } addr; } mdns_ip_addr_t;
typedef struct mdns_result_s {
    struct mdns_result_s* next; esp_netif_t* esp_netif; uint16_t port;
    const char* hostname; mdns_txt_item_t* txt; uint8_t* txt_value_len; size_t txt_count; mdns_ip_addr_t* addr;
} mdns_result_t;
typedef struct { uint16_t type; } mdns_search_once_t;
mdns_search_once_t* mdns_query_async_new(const char*,const char*,const char*,uint16_t,uint32_t,size_t,void*);
bool mdns_query_async_get_results(mdns_search_once_t*,uint32_t,mdns_result_t**,uint8_t*);
esp_err_t mdns_query_async_delete(mdns_search_once_t*);
void mdns_query_results_free(mdns_result_t*);
#endif
