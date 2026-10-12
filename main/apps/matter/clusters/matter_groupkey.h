#ifndef MATTER_GROUPKEY_H_INCLUDED
#define MATTER_GROUPKEY_H_INCLUDED 1
#include "../model/matter_cluster.h"

enum { MATTER_GROUPKEY_CLUSTER=0x3f, MATTER_GROUPKEY_ATTRIBUTES=9,
    MATTER_GROUPKEY_FABRICS=5, MATTER_GROUPKEY_SETS=4, MATTER_GROUPKEY_NOT_FOUND=0x8b };
/* Selected profile: no Groups/Groupcast, TrustFirst, zero group mappings.
 * Only public metadata crosses view(); epoch InputKeys are never persisted. */
typedef struct { uint64_t times[3]; uint16_t id; uint8_t count; } Matter_Groupkey_Set_T;
typedef struct { Matter_Groupkey_Set_T sets[MATTER_GROUPKEY_SETS]; uint8_t index; } Matter_Groupkey_Fabric_T;
typedef struct { Matter_Groupkey_Fabric_T fabrics[MATTER_GROUPKEY_FABRICS]; uint32_t version; } Matter_Groupkey_View_T;
typedef struct {
    void* user;
    /* Stable validated view: zero count means unused slot, count otherwise 1..3,
     * unique IDs, ascending times, existing fabric always has KeySet0. */
    const Matter_Groupkey_View_T* (*view)(void*);
    /* Atomically derive (HKDF GroupKey v1.0 / compressed fabric ID), replace and
     * persist ALL slots. Do not store input keys. Copy before return, no reentry.
     * Error has no effects, including on key removal/version. Erase workspaces.
     * UINT64_MAX time disables that slot; retain its public metadata only. */
    uint8_t (*store)(void*,uint8_t,const Matter_Groupkey_Set_T*,const uint8_t keys[3][16]);
    uint8_t (*remove)(void*,uint8_t,uint16_t);
} Matter_Groupkey_Port_T;
typedef Matter_Cluster_T Matter_Groupkey_T; /* Compatibility spelling; common handle. */
Matter_Cluster_T matter_groupkey_new(const Matter_Groupkey_Port_T*);
Matter_Result_T matter_groupkey_delete(Matter_Groupkey_T);
uint32_t matter_groupkey_version(Matter_Groupkey_T);
extern const uint32_t matter_groupkey_attributes[MATTER_GROUPKEY_ATTRIBUTES];
uint8_t matter_groupkey_read(Matter_Groupkey_T,uint32_t,uint8_t,Matter_Im_Value_T*);
uint8_t matter_groupkey_command(Matter_Groupkey_T,uint32_t,Matter_Im_Command_T*);
uint8_t matter_groupkey_validate(Matter_Groupkey_T,uint32_t,const uint8_t*,size_t);
/* Trusted adapters AFTER ACL/identity/schema/capacity checks; accessing index
 * is authenticated, never wire FabricIndex. One bounded synchronous operation. */
Matter_Im_Command_Result_T matter_groupkey_invoke(Matter_Groupkey_T,uint8_t,uint32_t,const uint8_t*,size_t,Matter_Tlv_Writer_T*);
uint8_t matter_groupkey_map(Matter_Groupkey_T,uint8_t,Matter_Im_List_Change_T,const uint8_t*,size_t);
#endif
