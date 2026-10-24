#ifndef MATTER_ACL_H_INCLUDED
#define MATTER_ACL_H_INCLUDED 1
#include "../model/matter_cluster.h"
enum { MATTER_ACL_CLUSTER=0x1f, MATTER_ACL_FABRICS=5, MATTER_ACL_ENTRIES=4,
    MATTER_ACL_SUBJECTS=4, MATTER_ACL_TARGETS=3, MATTER_ACL_ATTRIBUTES=9 };
typedef struct { uint32_t cluster,device_type; uint16_t endpoint; uint8_t present; } Matter_Acl_Target_T;
/* present bits: cluster=1, endpoint=2, device type=4. Endpoint/device type exclude. */
typedef struct {
    uint64_t subjects[MATTER_ACL_SUBJECTS]; Matter_Acl_Target_T targets[MATTER_ACL_TARGETS];
    uint8_t privilege,auth_mode,subject_count,target_count; bool subjects_null,targets_null;
} Matter_Acl_Entry_T;
typedef struct { Matter_Acl_Entry_T entries[MATTER_ACL_ENTRIES]; uint8_t index,count; } Matter_Acl_Fabric_T;
typedef struct { Matter_Acl_Fabric_T fabrics[MATTER_ACL_FABRICS]; uint32_t version; } Matter_Acl_View_T;
typedef struct {
    void* user;
    /* Stable borrowed, validated view, never NULL. Counts fit declared arrays;
     * entries obey ACL schema. Owner serializes all mutations, including boot load. */
    const Matter_Acl_View_T* (*view)(void*);
    /* Atomic replacement of ONLY this existing fabric. No effects on error.
     * Copy inputs; publish value/version together, no reentry/blocking. */
    uint8_t (*store)(void*,uint8_t,const Matter_Acl_Entry_T*,size_t);
} Matter_Acl_Port_T;
typedef struct { void* user; bool (*contains)(void*,uint16_t endpoint,uint32_t device_type); } Matter_Acl_Device_Port_T;
typedef Matter_Cluster_T Matter_Acl_T; /* Compatibility name; state is private. */
/* Private heap workspace plus common registry; no task/time/OS.
 * Borrow port.user through delete; Root attachment pins the common handle.
 * Encoded reads allocate their exact measured size, within the original
 * 4096-byte TLV budget. Scalars allocate no encoding bytes. The returned span
 * is owned/unchanged until the next accepted read or deletion; rejected reads,
 * version/access/authorization queries, validation and writes do not free it.
 * Read/Subscribe copy it synchronously into their independent snapshots.
 * Encoding OOM returns RESOURCE_EXHAUSTED to direct reads; existing IM provider
 * error mappings still apply. The owner serializes the stable backend view. */
Matter_Cluster_T matter_acl_new(const Matter_Acl_Port_T*);
typedef struct { Matter_Events_T log; void* user; uint64_t (*now)(void*); } Matter_Acl_Events_Port_T;
/* Bind before serving IM. Borrowed log/clock, once per instance. Internal
 * trusted matter_acl_write calls do not represent an Administrator and emit
 * no event. CASE cluster writes require authenticated request.peer_node. */
Matter_Result_T matter_acl_bind_events(Matter_Acl_T,const Matter_Acl_Events_Port_T*);
/* Trusted AddNOC backend: stage bootstrap Added before durable installation,
 * then finish with store outcome. q.fabric is the NEW fabric; q.is_case and
 * peer_node identify the invoking administrator, otherwise PASE passcode0.
 * Entry is already validated by the commissioning backend. */
Matter_Result_T matter_acl_prepare_added(Matter_Acl_T,const Matter_Cluster_Request_T*,const Matter_Acl_Entry_T*);
void matter_acl_finish_added(Matter_Acl_T,bool commit);
Matter_Result_T matter_acl_delete(Matter_Acl_T);
uint32_t matter_acl_version(Matter_Acl_T);
extern const uint32_t matter_acl_attributes[MATTER_ACL_ATTRIBUTES];
uint8_t matter_acl_read(Matter_Acl_T,uint32_t attribute,uint8_t accessing,bool filtered,Matter_Im_Value_T*);
/* Trusted adapter helpers AFTER ACL and fabric identity checks. Wire FabricIndex
 * ignored per Core fabric-scoped struct rules; only accessing determines the modified fabric.
 * One REPLACE/ADD is atomic. Chunks commit independently; no self-lockout guard. */
uint8_t matter_acl_validate(Matter_Acl_T,uint8_t accessing,Matter_Im_List_Change_T,const uint8_t*,size_t);
uint8_t matter_acl_write(Matter_Acl_T,uint8_t accessing,Matter_Im_List_Change_T,const uint8_t*,size_t);
/* CASE-only policy: authenticated Node/CAT/index, never client supplied. Optional
 * device port maps current Descriptor types. Missing callback denies such target.
 * path=NULL only matches wildcard Targets (legacy whole-node permission query).
 * Does not grant implicit PASE, process groups, ARL or auxiliary ACL. */
bool matter_acl_grants(const Matter_Acl_View_T*,uint8_t,uint64_t,const uint32_t*,size_t,
    const Matter_Im_Path_T*,Matter_Im_Privilege_T,const Matter_Acl_Device_Port_T*);
bool matter_acl_authorize(Matter_Acl_T,uint8_t,uint64_t,const uint32_t*,size_t,
    const Matter_Im_Path_T*,Matter_Im_Privilege_T,const Matter_Acl_Device_Port_T*);
#endif
