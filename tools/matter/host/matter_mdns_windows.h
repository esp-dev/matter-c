#ifndef MATTER_MDNS_WINDOWS_H_INCLUDED
#define MATTER_MDNS_WINDOWS_H_INCLUDED 1
#include "matter_mdns.h"

/* Shared Windows/Linux host API; legacy names retained for compatibility.
 * One explicitly selected, up, multicast-capable interface. IPv6 address and
 * MAC are discovered locally; no socket/OS types cross this boundary. */
enum { MATTER_MDNS_HOST_ADDRESSES=8 };
typedef struct { uint8_t bytes[16]; bool ipv4; } Matter_Mdns_Host_Address_T;
typedef struct {
    uint32_t index,ipv4_index;
    uint8_t ipv6[16],ipv4[4],mac[6];
    bool has_ipv4;
    uint8_t ipv4_prefix_length; /* Selected on-link prefix; 0 disables IPv4 unicast replies. */
    /* Complete snapshot on this interface, no silent truncation. Zero count
     * preserves manually supplied primary ipv6/optional ipv4 configurations. */
    unsigned address_count;
    Matter_Mdns_Host_Address_T addresses[MATTER_MDNS_HOST_ADDRESSES];
} Matter_Mdns_Windows_Interface_T;
Matter_Result_T matter_mdns_windows_interface(uint32_t index,Matter_Mdns_Windows_Interface_T*);
typedef struct Matter_Mdns_Windows* Matter_Mdns_Windows_T;
/* Owns one mDNS module, a Windows Winsock reference, two nonblocking sockets and heap
 * workspaces. Explicit hostname required. Max 8 TXT and 4 subtype entries,
 * text ASCII labels, 1200-byte output. Does not start threads or modify firewall.
 * IPv6 multicast plus optional IPv4 multicast carrying the same address set.
 * QU/direct and legacy unicast replies use four bounded heap slots; overflow
 * drops a reply for the querier to retry. Legacy DNS output is capped at 512.
 * Experimental host subset: see README for conflict/multi-interface limits. */
Matter_Mdns_Windows_T matter_mdns_windows_new(Matter_T,
    const Matter_Mdns_Windows_Interface_T*,const Matter_Mdns_Record_T*);
Matter_Mdns_T matter_mdns_windows_module(Matter_Mdns_Windows_T);
/* Owner calls after module process, also during stop. Bounded RX and timers.
 * Monotonic milliseconds. No callbacks from another thread. */
Matter_Result_T matter_mdns_windows_poll(Matter_Mdns_Windows_T,uint64_t now_ms);
/* Stop + pump first; no forced teardown of an active module. */
Matter_Result_T matter_mdns_windows_delete(Matter_Mdns_Windows_T);
#endif
