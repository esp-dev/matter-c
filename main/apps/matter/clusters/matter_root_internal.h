#ifndef MATTER_ROOT_INTERNAL_H_INCLUDED
#define MATTER_ROOT_INTERNAL_H_INCLUDED 1
#include "matter_root.h"
/* Trusted binding helpers; q contains authenticated session/fabric only. */
/* CASE binding only, after Revoke has started. Keep checking live session/ACL
 * while its own fail-safe cleanup runs; grants no access to a new command. */
uint8_t matter_root_authorize_pending_revoke(Matter_Root_T,Matter_Exchange_Session_T,const Matter_Im_Command_Path_T*,Matter_Im_Privilege_T);
uint8_t matter_root_cluster_read(Matter_Root_T,const Matter_Im_Path_T*,const Matter_Cluster_Request_T*,Matter_Im_Value_T*);
uint8_t matter_root_cluster_validate_command(Matter_Root_T,const Matter_Im_Command_Path_T*,const Matter_Cluster_Request_T*,const uint8_t*,size_t);
uint8_t matter_root_cluster_validate(Matter_Root_T,const Matter_Im_Path_T*,const Matter_Cluster_Request_T*,const uint8_t*,size_t);
Matter_Im_Write_Result_T matter_root_cluster_write(Matter_Root_T,const Matter_Im_Path_T*,const Matter_Cluster_Request_T*,const uint8_t*,size_t);
Matter_Im_Write_Result_T matter_root_cluster_list(Matter_Root_T,const Matter_Im_Path_T*,const Matter_Cluster_Request_T*,Matter_Im_List_Change_T,const uint8_t*,size_t,bool);
Matter_Result_T matter_root_cluster_start(Matter_Root_T,const Matter_Im_Command_Path_T*,const Matter_Cluster_Request_T*,const uint8_t*,size_t,Matter_Tlv_Writer_T*,Matter_Im_Command_Result_T*,uint64_t*);
Matter_Result_T matter_root_cluster_poll(Matter_Root_T,Matter_Cluster_T,uint64_t,Matter_Tlv_Writer_T*,Matter_Im_Command_Result_T*);
void matter_root_cluster_cancel(Matter_Root_T,Matter_Cluster_T,uint64_t);
#endif
