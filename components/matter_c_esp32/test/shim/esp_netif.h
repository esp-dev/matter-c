#ifndef MATTER_RESOLVER_NETIF_SHIM_H
#define MATTER_RESOLVER_NETIF_SHIM_H 1
typedef struct { int index; } esp_netif_t;
static inline int esp_netif_get_netif_impl_index(esp_netif_t* p) { return p->index; }
#endif
