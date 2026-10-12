#ifndef MATTER_IDENTIFY_H_INCLUDED
#define MATTER_IDENTIFY_H_INCLUDED 1
#include "../model/matter_cluster.h"
#define MATTER_IDENTIFY_CLUSTER 0x0003
#define MATTER_IDENTIFY_REVISION 6
#define MATTER_IDENTIFY_TIME 0
#define MATTER_IDENTIFY_TYPE 1
#define MATTER_IDENTIFY_COMMAND 0
typedef struct {
    void* user;
    /* Bounded owner-thread notification: accepted write/command or expiration.
     * seconds=0 stops presentation. No failure, blocking or reentry. */
    void (*present)(void*,uint16_t seconds);
} Matter_Identify_Port_T;
typedef struct { uint32_t data_version; uint8_t identify_type; } Matter_Identify_Config_T;
/* Optional TriggerEffect is not implemented. Config copied, user borrowed.
 * Owner calls cluster_process before IM and services cluster_deadline. Ordinary
 * countdown ticks do not change report version; writes/commands and expiry do.
 * Destruction stops active presentation. One independently owned state per new. */
Matter_Cluster_T matter_identify_new(const Matter_Identify_Port_T*,const Matter_Identify_Config_T*,uint64_t now_ms);
#endif
