#include "matter_root_internal.h"
/* Delegate public Root port. Binding owns no cached identity or fabric grant. */
static Matter_Result_T ports(Matter_Root_Case_Read_Binding_T* b,Matter_Im_Read_Port_T* p) {
    Matter_Im_Write_Port_T unused; return matter_root_ports(b->base.root,p,&unused);
}
static Matter_Result_T index_of(void* u,Matter_Exchange_Session_T token,uint8_t* index) {
    Matter_Root_Case_Read_Binding_T* b=u; Matter_Secure_Identity_T id;
    if(!b || token!=b->base.session || matter_secure_identity(b->secure,&id)!=MATTER_OK) return MATTER_INVALID_STATE;
    *index=id.fabric_index; return MATTER_OK;
}
static Matter_Im_Status_T authorize(void* u,Matter_Exchange_Session_T token,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    Matter_Root_Case_Read_Binding_T* b=u; Matter_Im_Read_Port_T port; uint8_t index;
    if(index_of(u,token,&index)!=MATTER_OK || ports(b,&port)!=MATTER_OK) return MATTER_IM_UNSUPPORTED_ACCESS;
    return port.authorize(port.user,token,p,privilege);
}
static Matter_Im_Status_T describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* a) {
    Matter_Im_Read_Port_T port; if(ports(u,&port)!=MATTER_OK) return MATTER_IM_FAILURE;
    return port.describe(port.user,p,a);
}
static Matter_Im_Status_T read_value(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    Matter_Root_Case_Read_Binding_T* b=u; uint8_t index;
    if(index_of(u,b->base.session,&index)!=MATTER_OK) return MATTER_IM_UNSUPPORTED_ACCESS;
    Matter_Cluster_Request_T q={.session=b->base.session,.fabric=index,.filtered=filtered,.is_case=true};
    return (Matter_Im_Status_T)matter_root_cluster_read(b->base.root,p,&q,v);
}
static Matter_Result_T enumerate(void* u,const Matter_Im_Selector_T* q,const Matter_Im_Path_T* after,Matter_Im_Path_T* p,bool* found) {
    Matter_Im_Read_Port_T port; if(ports(u,&port)!=MATTER_OK) return MATTER_INVALID_STATE;
    return port.enumerate(port.user,q,after,p,found);
}
static Matter_Result_T version(void* u,const Matter_Im_Path_T* p,uint32_t* v) {
    Matter_Im_Read_Port_T port; if(ports(u,&port)!=MATTER_OK) return MATTER_INVALID_STATE;
    return port.version(port.user,p,v);
}
Matter_Result_T matter_root_case_read_port(Matter_Root_T root,Matter_Exchange_Session_T token,Matter_Secure_T secure,
    Matter_Root_Case_Read_Binding_T* b,Matter_Im_Read_Port_T* p,Matter_Im_Read_Fabric_Port_T* f) {
    if(!root || !token || !secure || !b || !p || !f) return MATTER_INVALID_ARGUMENT;
    Matter_Secure_Identity_T id; if(matter_secure_identity(secure,&id)!=MATTER_OK) return MATTER_INVALID_STATE;
    *b=(Matter_Root_Case_Read_Binding_T){{root,token},secure};
    *p=(Matter_Im_Read_Port_T){b,authorize,describe,read_value,enumerate,version}; *f=(Matter_Im_Read_Fabric_Port_T){index_of}; return MATTER_OK;
}

/* CASE Invoke exposes Complete, Group Key Management and Diagnostics. */
static Matter_Result_T invoke_ports(Matter_Root_Case_Invoke_Binding_T* b,Matter_Im_Invoke_Port_T* p) {
    return matter_root_invoke_port(b->base.root,b->base.session,&b->base,p);
}
static Matter_Result_T invoke_index(void* u,Matter_Exchange_Session_T token,uint8_t* index) {
    Matter_Root_Case_Invoke_Binding_T* b=u; Matter_Secure_Identity_T id;
    if(!b || !index || token!=b->base.session || matter_secure_identity(b->secure,&id)!=MATTER_OK) return MATTER_INVALID_STATE;
    *index=id.fabric_index; return MATTER_OK;
}
static uint8_t invoke_authorize(void* u,Matter_Exchange_Session_T token,const Matter_Im_Command_Path_T* path,Matter_Im_Privilege_T v) {
    Matter_Root_Case_Invoke_Binding_T* b=u; Matter_Im_Invoke_Port_T p; uint8_t index;
    if(invoke_index(u,token,&index)!=MATTER_OK || invoke_ports(b,&p)!=MATTER_OK) return MATTER_IM_UNSUPPORTED_ACCESS;
    /* Revoke expires fail-safe itself. Its accepted CASE operation must wait
     * for cleanup without mistaking the cleanup gate for ACL revocation. */
    if(b->pending && matter_cluster_id(b->pending)==0x3c)
        return matter_root_authorize_pending_revoke(b->base.root,token,path,v);
    return p.authorize(p.user,token,path,v);
}
static uint8_t invoke_describe(void* u,const Matter_Im_Command_Path_T* path,Matter_Im_Command_T* c) {
    Matter_Im_Invoke_Port_T p; if(!path || invoke_ports(u,&p)!=MATTER_OK) return MATTER_IM_FAILURE;
    return p.describe(p.user,path,c);
}
static uint8_t invoke_validate(void* u,const Matter_Im_Command_Path_T* path,const uint8_t* data,size_t size) {
    Matter_Root_Case_Invoke_Binding_T* b=u; uint8_t index;
    if(invoke_index(u,b->base.session,&index)!=MATTER_OK) return MATTER_IM_UNSUPPORTED_ACCESS;
    Matter_Cluster_Request_T q={.session=b->base.session,.fabric=index,.is_case=true};
    return matter_root_cluster_validate_command(b->base.root,path,&q,data,size);
}
static Matter_Im_Command_Result_T invoke_sync(void* u,const Matter_Im_Command_Path_T* p,const uint8_t* d,size_t n,Matter_Tlv_Writer_T* w) {
    Matter_Root_Case_Invoke_Binding_T* b=u; uint8_t index;
    if(!p || invoke_index(u,b->base.session,&index)!=MATTER_OK) return (Matter_Im_Command_Result_T){.status=MATTER_IM_UNSUPPORTED_ACCESS};
    Matter_Cluster_T c=matter_root_cluster_at(b->base.root,p->endpoint,p->cluster);
    if(matter_cluster_command_async(c,p->command)) return (Matter_Im_Command_Result_T){.status=MATTER_IM_INVALID_ACTION};
    Matter_Cluster_Request_T q={.session=b->base.session,.fabric=index,.is_case=true};
    Matter_Im_Command_Result_T out; uint64_t token;
    Matter_Result_T r=matter_root_cluster_start(b->base.root,p,&q,d,n,w,&out,&token);
    return r==MATTER_OK?out:(Matter_Im_Command_Result_T){.status=MATTER_IM_FAILURE};
}
static Matter_Result_T invoke_start(void* u,const Matter_Im_Command_Path_T* path,const uint8_t* data,size_t size,
    Matter_Tlv_Writer_T* out,Matter_Im_Command_Result_T* result,uint64_t* token) {
    Matter_Root_Case_Invoke_Binding_T* b=u; uint8_t index; *token=0;
    uint8_t code=invoke_validate(u,path,data,size);
    if(code || invoke_index(u,b->base.session,&index)!=MATTER_OK) {
        *result=(Matter_Im_Command_Result_T){.status=code?code:MATTER_IM_UNSUPPORTED_ACCESS}; return MATTER_OK;
    }
    Matter_Cluster_Request_T q={.session=b->base.session,.fabric=index,.is_case=true};
    Matter_Result_T r=matter_root_cluster_start(b->base.root,path,&q,data,size,out,result,token);
    if(r==MATTER_PENDING) b->pending=matter_root_cluster_at(b->base.root,path->endpoint,path->cluster);
    return r;
}
static Matter_Result_T invoke_poll(void* u,uint64_t token,Matter_Tlv_Writer_T* out,Matter_Im_Command_Result_T* result) {
    Matter_Root_Case_Invoke_Binding_T* b=u;
    if(b->pending) {
        Matter_Root_Fail_Safe_State_T state;
        if(matter_cluster_id(b->pending)==0x3c && matter_root_fail_safe_state(b->base.root,&state)==MATTER_OK &&
            state==MATTER_ROOT_FAIL_SAFE_CLEANUP) return MATTER_PENDING;
        Matter_Result_T r=matter_root_cluster_poll(b->base.root,b->pending,token,out,result);
        if(r==MATTER_OK) b->pending=NULL;
        return r;
    }
    return MATTER_INVALID_STATE;
}
static void invoke_cancel(void* u,uint64_t token) {
    Matter_Root_Case_Invoke_Binding_T* b=u;
    if(b->pending) { matter_root_cluster_cancel(b->base.root,b->pending,token); b->pending=NULL; }

}
Matter_Result_T matter_root_case_invoke_port(Matter_Root_T root,Matter_Exchange_Session_T token,Matter_Secure_T secure,
    Matter_Root_Case_Invoke_Binding_T* b,Matter_Im_Invoke_Port_T* p,Matter_Im_Invoke_Async_Port_T* a,Matter_Im_Read_Fabric_Port_T* f) {
    if(!root || !token || !secure || !b || !p || !a || !f) return MATTER_INVALID_ARGUMENT;
    Matter_Secure_Identity_T id; if(matter_secure_identity(secure,&id)!=MATTER_OK) return MATTER_INVALID_STATE;
    *b=(Matter_Root_Case_Invoke_Binding_T){{root,token},secure,NULL};
    *p=(Matter_Im_Invoke_Port_T){b,invoke_authorize,invoke_describe,invoke_validate,invoke_sync};
    *a=(Matter_Im_Invoke_Async_Port_T){invoke_start,invoke_poll,invoke_cancel}; *f=(Matter_Im_Read_Fabric_Port_T){invoke_index}; return MATTER_OK;
}

static Matter_Result_T write_ports(Matter_Root_Case_Write_Binding_T* b,Matter_Im_Write_Port_T* p) {
    Matter_Im_Read_Port_T unused; return matter_root_ports(b->base.root,&unused,p);
}
static uint8_t write_authorize(void* u,Matter_Exchange_Session_T s,const Matter_Im_Path_T* path,Matter_Im_Privilege_T v) {
    return authorize(u,s,path,v);
}
static uint8_t write_describe(void* u,const Matter_Im_Path_T* path,Matter_Im_Write_Attribute_T* a) {
    Matter_Im_Write_Port_T p; if(write_ports(u,&p)!=MATTER_OK) return MATTER_IM_FAILURE;
    return p.describe(p.user,path,a);
}
static uint8_t write_validate(void* u,const Matter_Im_Path_T* path,const uint8_t* data,size_t n) {
    Matter_Root_Case_Write_Binding_T* b=u; uint8_t index;
    if(index_of(u,b->base.session,&index)!=MATTER_OK) return MATTER_IM_UNSUPPORTED_ACCESS;
    Matter_Cluster_Request_T q={.session=b->base.session,.fabric=index,.is_case=true};
    return matter_root_cluster_validate(b->base.root,path,&q,data,n);
}
static Matter_Im_Write_Result_T write_value_case(void* u,const Matter_Im_Path_T* path,const uint8_t* data,size_t n) {
    Matter_Root_Case_Write_Binding_T* b=u; uint8_t index;
    if(index_of(u,b->base.session,&index)!=MATTER_OK) return (Matter_Im_Write_Result_T){.status=MATTER_IM_UNSUPPORTED_ACCESS};
    Matter_Cluster_Request_T q={.session=b->base.session,.fabric=index,.is_case=true};
    return matter_root_cluster_write(b->base.root,path,&q,data,n);
}
static uint8_t list_validate(void* u,const Matter_Im_Path_T* p,Matter_Im_List_Change_T c,const uint8_t* d,size_t n) {
    Matter_Root_Case_Write_Binding_T* b=u; uint8_t index;
    if(index_of(u,b->base.session,&index)!=MATTER_OK) return MATTER_IM_UNSUPPORTED_ACCESS;
    Matter_Cluster_Request_T q={.session=b->base.session,.fabric=index,.is_case=true};
    return matter_root_cluster_list(b->base.root,p,&q,c,d,n,false).status;
}
static Matter_Im_Write_Result_T list_write(void* u,const Matter_Im_Path_T* p,Matter_Im_List_Change_T c,const uint8_t* d,size_t n) {
    Matter_Root_Case_Write_Binding_T* b=u; uint8_t index;
    if(index_of(u,b->base.session,&index)!=MATTER_OK) return (Matter_Im_Write_Result_T){.status=MATTER_IM_UNSUPPORTED_ACCESS};
    Matter_Secure_Identity_T id;
    if(matter_secure_identity(b->secure,&id)!=MATTER_OK) return (Matter_Im_Write_Result_T){.status=MATTER_IM_UNSUPPORTED_ACCESS};
    Matter_Cluster_Request_T q={.session=b->base.session,.fabric=index,.is_case=true,.peer_node=id.peer_node_id};
    return matter_root_cluster_list(b->base.root,p,&q,c,d,n,true);
}
Matter_Result_T matter_root_case_write_port(Matter_Root_T root,Matter_Exchange_Session_T token,Matter_Secure_T secure,
    Matter_Root_Case_Write_Binding_T* b,Matter_Im_Write_Port_T* p,Matter_Im_Read_Fabric_Port_T* f) {
    if(!root || !token || !secure || !b || !p || !f) return MATTER_INVALID_ARGUMENT;
    Matter_Secure_Identity_T id; if(matter_secure_identity(secure,&id)!=MATTER_OK) return MATTER_INVALID_STATE;
    *b=(Matter_Root_Case_Write_Binding_T){{root,token},secure};
    *p=(Matter_Im_Write_Port_T){b,write_authorize,write_describe,version,write_validate,write_value_case,list_validate,list_write};
    *f=(Matter_Im_Read_Fabric_Port_T){index_of}; return MATTER_OK;
}
