#include "matter_switch_sim.h"
#include "model/matter_cluster_internal.h"
#include "codec/matter_tlv_validate.h"
#include <stdlib.h>

typedef struct {
    uint32_t version; bool on;
    void (*changed)(void*,bool); void* ctx;
    Matter_Tlv_Validation_Workspace_T validation;
    Matter_Tlv_Tag_T tags[32];
} Switch;
static Matter_Result_T destroy(void* u) { free(u); return MATTER_OK; }
static Matter_Result_T version(void* u,uint32_t* v) { *v=((Switch*)u)->version; return MATTER_OK; }
static uint8_t read_on(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    Switch* s=u; (void)ref; (void)q;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_BOOL,.unsigned_value=s->on,.data_version=s->version}; return 0;
}
static uint8_t read_constant(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)q; *v=*(const Matter_Im_Value_T*)ref; v->data_version=((Switch*)u)->version; return 0;
}
static uint8_t validate(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* data,size_t size) {
    Switch* s=u; (void)ref; (void)q;
    const Matter_Tlv_Validation_Options_T opt={1024,128,512,4,false,0,0};
    Matter_Tlv_Validation_Report_T report;
    /* No defined fields; ignore well-formed unknown fields for forward compatibility. */
    if(!data || size<2 || data[0]!=0x15) return MATTER_IM_INVALID_COMMAND;
    return matter_tlv_validate(data,size,&opt,&s->validation,s->tags,32,&report)==MATTER_TLV_OK?0:MATTER_IM_INVALID_COMMAND;
}
static Matter_Result_T start(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* data,size_t size,
    Matter_Tlv_Writer_T* writer,Matter_Im_Command_Result_T* result,uint64_t* token) {
    Switch* s=u; (void)q; (void)data; (void)size; (void)writer; (void)token;
    unsigned command=*(const unsigned*)ref;
    bool on=command==2?!s->on:command==1;
    if(on!=s->on) { s->on=on; ++s->version; if(s->changed) s->changed(s->ctx,on); }
    *result=(Matter_Im_Command_Result_T){.status=MATTER_IM_SUCCESS}; return MATTER_OK;
}
Matter_Cluster_T matter_switch_sim_new(uint32_t initial,void (*changed)(void*,bool),void* ctx) {
    Switch* s=calloc(1,sizeof(*s)); if(!s) return NULL;
    s->version=initial; s->changed=changed; s->ctx=ctx;
    Matter_Cluster_Config_T config={.id=6,.attributes=6,.commands=3,.callbacks={.ctx=s,.version=version,.destroy=destroy}};
    Matter_Cluster_T c=matter_cluster_new(&config); if(!c) { free(s); return NULL; }
    static const uint8_t empty[]={0x16,0x18},commands[]={0x16,4,0,4,1,4,2,0x18},
        attributes[]={0x16,4,0,5,0xf8,0xff,5,0xf9,0xff,5,0xfb,0xff,5,0xfc,0xff,5,0xfd,0xff,0x18};
    static const Matter_Im_Value_T values[]={
        {.type=MATTER_TLV_ARRAY,.data=empty,.size=sizeof(empty)},
        {.type=MATTER_TLV_ARRAY,.data=commands,.size=sizeof(commands)},
        {.type=MATTER_TLV_ARRAY,.data=attributes,.size=sizeof(attributes)},
        {.type=MATTER_TLV_UNSIGNED,.unsigned_value=0}, /* no optional features */
        {.type=MATTER_TLV_UNSIGNED,.unsigned_value=6}
    };
    static const Matter_Attribute_Def_T attrs[]={
        {.id=0,.read_access={MATTER_IM_VIEW,false},.read=read_on},
        {.id=0xfff8,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&values[0]},
        {.id=0xfff9,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&values[1]},
        {.id=0xfffb,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&values[2]},
        {.id=0xfffc,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&values[3]},
        {.id=0xfffd,.read_access={MATTER_IM_VIEW,false},.read=read_constant,.ref=&values[4]}
    };
    static const unsigned ids[]={0,1,2};
    for(unsigned i=0;i<6;++i) if(matter_cluster_add_attribute(c,&attrs[i])!=MATTER_OK) goto fail;
    for(unsigned i=0;i<3;++i) {
        Matter_Command_Def_T cmd={.id=ids[i],.access={.privilege=MATTER_IM_OPERATE},.ref=&ids[i],.validate=validate,.start=start};
        if(matter_cluster_add_command(c,&cmd)!=MATTER_OK) goto fail;
    }
    if(matter_cluster_seal(c)!=MATTER_OK) goto fail;
    return c;
fail: matter_cluster_abandon(c); free(s); return NULL;
}
