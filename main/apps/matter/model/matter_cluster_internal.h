#ifndef MATTER_CLUSTER_INTERNAL_H_INCLUDED
#define MATTER_CLUSTER_INTERNAL_H_INCLUDED 1
#include "matter_cluster.h"
/* Private factories may extend a profile only before publication. */
bool matter_cluster_mutable(Matter_Cluster_T);
size_t matter_cluster_pins(Matter_Cluster_T);
uint8_t matter_cluster_command_metadata(Matter_Cluster_T,uint32_t,Matter_Im_Command_T*);
/* All-or-nothing profile extension; descriptor arrays must not alias the registry. */
Matter_Result_T matter_cluster_extend(Matter_Cluster_T,const Matter_Attribute_Def_T*,size_t,const Matter_Command_Def_T*,size_t);
/* Implementation-only checked access. Never use from application/IM adapters. */
void* matter_cluster_context(Matter_Cluster_T,Matter_Result_T (*destroy)(void*));
void matter_cluster_abandon(Matter_Cluster_T); /* Unpublished factory failure; ctx remains owned by caller. */
#endif
