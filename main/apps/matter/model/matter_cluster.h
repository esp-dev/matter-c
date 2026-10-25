#ifndef MATTER_CLUSTER_H_INCLUDED
#define MATTER_CLUSTER_H_INCLUDED 1
#include "matter_im_write.h"
/* Common server interface. Private state lives in the implementation .c.
 * Descriptors are copied at registration; ctx/ref are borrowed until delete.
 * All calls on one owner thread. IM/session adapters perform authorization;
 * this is a trusted model boundary, never an authorization bypass for wire RX. */
typedef struct Matter_Cluster* Matter_Cluster_T;
typedef struct {
    Matter_Exchange_Session_T session; uint8_t fabric;
    bool filtered,is_case,armed;
    uint64_t peer_node; /* Authenticated CASE subject, supplied by session binding. */
    /* Trusted group adapter only, after MIC/replay/fabric/ACL checks. Group
     * requests never impersonate CASE and cannot grant CASE-only operations. */
    bool is_group; uint16_t group;
} Matter_Cluster_Request_T;
typedef struct {
    uint32_t id; Matter_Im_Attribute_T read_access; Matter_Im_Write_Attribute_T write_access;
    const void* ref;
    uint8_t (*read)(void*,const void*,const Matter_Cluster_Request_T*,Matter_Im_Value_T*);
    uint8_t (*validate)(void*,const void*,const Matter_Cluster_Request_T*,const uint8_t*,size_t);
    Matter_Im_Write_Result_T (*write)(void*,const void*,const Matter_Cluster_Request_T*,const uint8_t*,size_t);
    uint8_t (*validate_list)(void*,const void*,const Matter_Cluster_Request_T*,Matter_Im_List_Change_T,const uint8_t*,size_t);
    Matter_Im_Write_Result_T (*write_list)(void*,const void*,const Matter_Cluster_Request_T*,Matter_Im_List_Change_T,const uint8_t*,size_t);
} Matter_Attribute_Def_T;
typedef struct {
    uint32_t id; Matter_Im_Command_T access; const void* ref;
    uint8_t (*validate)(void*,const void*,const Matter_Cluster_Request_T*,const uint8_t*,size_t);
    Matter_Result_T (*start)(void*,const void*,const Matter_Cluster_Request_T*,const uint8_t*,size_t,
        Matter_Tlv_Writer_T*,Matter_Im_Command_Result_T*,uint64_t*);
    Matter_Result_T (*poll)(void*,const void*,uint64_t,Matter_Tlv_Writer_T*,Matter_Im_Command_Result_T*);
    void (*cancel)(void*,const void*,uint64_t);
} Matter_Command_Def_T;
/* Static event metadata; the node log and IM Read Events port are separate. */
typedef struct { uint32_t id; Matter_Im_Privilege_T privilege; uint8_t priority; bool fabric_scoped; } Matter_Event_Def_T;
typedef struct {
    void* ctx;
    Matter_Result_T (*version)(void*,uint32_t*);
    Matter_Result_T (*process)(void*,uint64_t);
    Matter_Result_T (*deadline)(void*,uint64_t*);
    /* Must reject while backend work is still draining. On failure leave ctx
     * intact. Ownership transfers only after successful new. NULL borrows ctx. */
    Matter_Result_T (*destroy)(void*);
} Matter_Cluster_Callbacks_T;
typedef struct {
    uint32_t id; uint16_t attributes,commands,events,pending;
    Matter_Cluster_Callbacks_T callbacks;
} Matter_Cluster_Config_T;
/* Bounded contiguous collections: one allocation per instance, none per call or
 * per descriptor. add only before seal/bind; duplicate IDs rejected atomically.
 * IDs need not be inserted in order; enumeration is sorted. Limits 256/64/64/16. */
Matter_Cluster_T matter_cluster_new(const Matter_Cluster_Config_T*);
Matter_Result_T matter_cluster_add_attribute(Matter_Cluster_T,const Matter_Attribute_Def_T*);
Matter_Result_T matter_cluster_add_command(Matter_Cluster_T,const Matter_Command_Def_T*);
Matter_Result_T matter_cluster_add_event(Matter_Cluster_T,const Matter_Event_Def_T*);
Matter_Result_T matter_cluster_seal(Matter_Cluster_T);
uint32_t matter_cluster_id(Matter_Cluster_T);
size_t matter_cluster_attribute_count(Matter_Cluster_T);
bool matter_cluster_attribute_at(Matter_Cluster_T,size_t,uint32_t*);
const Matter_Event_Def_T* matter_cluster_event(Matter_Cluster_T,uint32_t);
size_t matter_cluster_event_count(Matter_Cluster_T);
bool matter_cluster_event_at(Matter_Cluster_T,size_t,uint32_t*);
/* Registry/owner pins lifetime; an attached or pending cluster cannot delete. */
Matter_Result_T matter_cluster_retain(Matter_Cluster_T);
Matter_Result_T matter_cluster_release(Matter_Cluster_T);
Matter_Result_T matter_cluster_delete(Matter_Cluster_T);
bool matter_cluster_in_use(Matter_Cluster_T);
Matter_Result_T matter_cluster_version(Matter_Cluster_T,uint32_t*);
Matter_Result_T matter_cluster_process(Matter_Cluster_T,uint64_t);
Matter_Result_T matter_cluster_deadline(Matter_Cluster_T,uint64_t*);
uint8_t matter_cluster_describe(Matter_Cluster_T,uint32_t,Matter_Im_Attribute_T*);
uint8_t matter_cluster_describe_write(Matter_Cluster_T,uint32_t,Matter_Im_Write_Attribute_T*);
uint8_t matter_cluster_read(Matter_Cluster_T,uint32_t,const Matter_Cluster_Request_T*,Matter_Im_Value_T*);
uint8_t matter_cluster_validate(Matter_Cluster_T,uint32_t,const Matter_Cluster_Request_T*,const uint8_t*,size_t);
Matter_Im_Write_Result_T matter_cluster_write(Matter_Cluster_T,uint32_t,const Matter_Cluster_Request_T*,const uint8_t*,size_t);
uint8_t matter_cluster_validate_list(Matter_Cluster_T,uint32_t,const Matter_Cluster_Request_T*,Matter_Im_List_Change_T,const uint8_t*,size_t);
Matter_Im_Write_Result_T matter_cluster_write_list(Matter_Cluster_T,uint32_t,const Matter_Cluster_Request_T*,Matter_Im_List_Change_T,const uint8_t*,size_t);
uint8_t matter_cluster_command(Matter_Cluster_T,uint32_t,Matter_Im_Command_T*);
bool matter_cluster_command_async(Matter_Cluster_T,uint32_t);
uint8_t matter_cluster_validate_command(Matter_Cluster_T,uint32_t,const Matter_Cluster_Request_T*,const uint8_t*,size_t);
/* Tokens exposed here are instance-local handles, not backend tokens. poll/cancel
 * route to the exact accepted command; terminal poll consumes the handle.
 * Cancel detaches IM synchronously; backend drain remains owned by ctx. */
Matter_Result_T matter_cluster_start(Matter_Cluster_T,uint32_t,const Matter_Cluster_Request_T*,const uint8_t*,size_t,Matter_Tlv_Writer_T*,Matter_Im_Command_Result_T*,uint64_t*);
Matter_Result_T matter_cluster_poll(Matter_Cluster_T,uint64_t,Matter_Tlv_Writer_T*,Matter_Im_Command_Result_T*);
Matter_Result_T matter_cluster_cancel(Matter_Cluster_T,uint64_t);
#endif
