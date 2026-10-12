#ifndef MATTER_RESOLVER_PORT_H_INCLUDED
#define MATTER_RESOLVER_PORT_H_INCLUDED 1
#include "matter_udp_port.h"

typedef struct {
    uint8_t compressed_fabric[8]; uint64_t node_id; uint32_t interface_id;
} Matter_Resolver_Query_T;
typedef struct {
    Matter_Udp_Address_T peer;
    uint32_t idle_ms,active_ms,active_threshold_ms; /* Validated TXT, defaults 500/300/4000. */
} Matter_Resolver_Answer_T;
/* Owner-thread, nonblocking operational DNS-SD; no socket/task or callback into
 * the caller. Provider copied, user borrowed through consumer delete. Application
 * pumps backend also during stop. All query/answer arguments are call-borrowed.
 * DNS is routing information only, never an authenticated identity or grant. */
typedef struct {
    void* user;
    /* PENDING copies query and writes a fresh nonzero ID. Other result retains
     * nothing and preserves ID. IDs never reused for this backend lifetime. */
    Matter_Result_T (*start)(void*,const Matter_Resolver_Query_T*,uint64_t* id);
    /* PENDING: no output/change. OK: exactly one terminal result, backend drops
     * job before returning; answer valid only for SUCCEEDED. Unknown/stale ID
     * INVALID_STATE with unchanged outputs. Consumer owns a separate session pin. */
    Matter_Result_T (*take)(void*,uint64_t id,Matter_Operation_Result_T*,Matter_Resolver_Answer_T*);
    /* Request once; never implies completion. Must eventually permit take,
     * including success racing cancel. No references to consumer/session held. */
    void (*cancel)(void*,uint64_t id);
} Matter_Resolver_Port_T;
#endif
