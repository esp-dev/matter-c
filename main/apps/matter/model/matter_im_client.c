#include "matter_im_client.h"
#include "../codec/matter_tlv_validate.h"
#include <stdlib.h>
#include <string.h>
struct Matter_Im_Client {
    Matter_Im_Command_Path_T path; uint32_t response_command;
    const uint8_t* source; size_t source_size;
    uint8_t opcode,status; bool waiting,done;
    uint8_t output[1024],body[1024]; size_t output_size,body_size;
    Matter_Tlv_Validation_Workspace_T validation; Matter_Tlv_Tag_T tags[64];
};
static bool container(Matter_Tlv_Type_T t) { return t==MATTER_TLV_STRUCTURE || t==MATTER_TLV_LIST || t==MATTER_TLV_ARRAY; }
static bool valid(Matter_Im_Client_T c,const uint8_t* d,size_t n) {
    const Matter_Tlv_Validation_Options_T o={1024,256,4096,8,false,0,0}; Matter_Tlv_Validation_Report_T report;
    return matter_tlv_validate(d,n,&o,&c->validation,c->tags,64,&report)==MATTER_TLV_OK;
}
/* A returned container borrows its complete encoding, including opening tag. */
static bool field(Matter_Im_Client_T c,const uint8_t* d,size_t n,int tag,Matter_Tlv_Element_T* out) {
    Matter_Tlv_Reader_T r; Matter_Tlv_Element_T e; bool found=false;
    if(matter_tlv_init(&r,c->source,c->source_size,8)!=MATTER_TLV_OK) return false;
    do { if(matter_tlv_next(&r,&e)!=MATTER_TLV_OK) return false; } while(e.offset<(size_t)(d-c->source));
    if(e.offset!=(size_t)(d-c->source) || !container(e.type)) return false;
    (void)n;
    while(matter_tlv_next(&r,&e)==MATTER_TLV_OK && e.type!=MATTER_TLV_END) {
        if(container(e.type)) {
            if(matter_tlv_skip_container(&r)!=MATTER_TLV_OK) return false;
            e.data=c->source+e.offset; e.size=r.offset-e.offset;
        }
        if((tag<0 && !e.tag.control) || (e.tag.control==1 && e.tag.number==(uint32_t)tag)) {
            if(found) return false;
            *out=e; found=true;
        }
    }
    return found;
}
static bool number(Matter_Im_Client_T c,const uint8_t* d,size_t n,int tag,uint64_t expected) {
    Matter_Tlv_Element_T e; return field(c,d,n,tag,&e) && e.type==MATTER_TLV_UNSIGNED && e.unsigned_value==expected;
}
static bool put(Matter_Tlv_Writer_T* w,Matter_Tlv_Type_T t,int tag,uint64_t v) {
    Matter_Tlv_Element_T e={.type=t,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=v};
    return matter_tlv_write(w,&e,0)==MATTER_TLV_OK;
}
static bool copy(Matter_Im_Client_T c,Matter_Tlv_Writer_T* w,const uint8_t* d,size_t n,int tag) {
    Matter_Tlv_Reader_T r; Matter_Tlv_Element_T e;
    if(matter_tlv_init(&r,c->source,c->source_size,8)!=MATTER_TLV_OK) return false;
    while(r.offset<(size_t)(d-c->source)+n) {
        if(matter_tlv_next(&r,&e)!=MATTER_TLV_OK) return false;
        if(e.offset<(size_t)(d-c->source)) continue;
        if(e.offset==(size_t)(d-c->source)) e.tag=(Matter_Tlv_Tag_T){.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag};
        if(matter_tlv_write(w,&e,0)!=MATTER_TLV_OK) return false;
    }
    return true;
}
Matter_Im_Client_T matter_im_client_new(const Matter_Im_Command_Path_T* p,uint32_t response,const uint8_t* d,size_t n) {
    if(!p || p->endpoint==65535 || !d || !n || d[0]!=0x15) return NULL;
    Matter_Im_Client_T c=calloc(1,sizeof(*c)); if(!c) return NULL;
    c->source=d; c->source_size=n; c->path=*p; c->response_command=response; Matter_Tlv_Writer_T w;
    if(!valid(c,d,n) || matter_tlv_writer_init(&w,c->output,sizeof(c->output),8)!=MATTER_TLV_OK ||
        !put(&w,MATTER_TLV_STRUCTURE,-1,0) || !put(&w,MATTER_TLV_BOOL,0,0) || !put(&w,MATTER_TLV_BOOL,1,0) ||
        !put(&w,MATTER_TLV_ARRAY,2,0) || !put(&w,MATTER_TLV_STRUCTURE,-1,0) || !put(&w,MATTER_TLV_LIST,0,0) ||
        !put(&w,MATTER_TLV_UNSIGNED,0,p->endpoint) || !put(&w,MATTER_TLV_UNSIGNED,1,p->cluster) ||
        !put(&w,MATTER_TLV_UNSIGNED,2,p->command) || !put(&w,MATTER_TLV_END,-1,0) || !copy(c,&w,d,n,1) ||
        !put(&w,MATTER_TLV_END,-1,0) || !put(&w,MATTER_TLV_END,-1,0) || !put(&w,MATTER_TLV_UNSIGNED,255,MATTER_IM_REVISION) ||
        !put(&w,MATTER_TLV_END,-1,0) || matter_tlv_writer_finish(&w,&c->output_size)!=MATTER_TLV_OK) { free(c); return NULL; }
    c->opcode=8; return c;
}
Matter_Result_T matter_im_client_output(Matter_Im_Client_T c,Matter_Im_Read_Message_T* out) {
    if(!c || !out) return MATTER_INVALID_ARGUMENT;
    if(!c->opcode) return MATTER_WOULD_BLOCK;
    *out=(Matter_Im_Read_Message_T){c->output,c->output_size,c->opcode}; return MATTER_OK;
}
Matter_Result_T matter_im_client_sent(Matter_Im_Client_T c) {
    if(!c || !c->opcode) return MATTER_INVALID_STATE;
    if(c->opcode==8) c->waiting=true; else c->done=true;
    c->opcode=0; return MATTER_OK;
}
Matter_Result_T matter_im_client_receive(Matter_Im_Client_T c,uint8_t opcode,const uint8_t* d,size_t n) {
    if(!c || !c->waiting || !d || !n) return MATTER_INVALID_STATE;
    c->source=d; c->source_size=n;
    Matter_Tlv_Element_T revision;
    if(d[0]!=0x15 || !valid(c,d,n) || !field(c,d,n,255,&revision) || revision.type!=MATTER_TLV_UNSIGNED ||
        !revision.unsigned_value || revision.unsigned_value>255) return MATTER_INVALID_ARGUMENT;
    Matter_Tlv_Element_T a,b,cmd,path,e; bool suppress=true; uint8_t status=0;
    if(opcode==1) {
        if(!field(c,d,n,0,&e) || e.type!=MATTER_TLV_UNSIGNED || !e.unsigned_value || e.unsigned_value>255) return MATTER_INVALID_ARGUMENT;
        status=(uint8_t)e.unsigned_value;
    } else if(opcode==9) {
        if(!field(c,d,n,0,&e) || e.type!=MATTER_TLV_BOOL) return MATTER_INVALID_ARGUMENT;
        suppress=e.unsigned_value!=0;
        if(field(c,d,n,2,&e) && (e.type!=MATTER_TLV_BOOL || e.unsigned_value)) return MATTER_INVALID_ARGUMENT;
        if(!field(c,d,n,1,&a) || a.type!=MATTER_TLV_ARRAY || !field(c,a.data,a.size,-1,&b) || b.type!=MATTER_TLV_STRUCTURE) return MATTER_INVALID_ARGUMENT;
        bool data=field(c,b.data,b.size,0,&cmd), code=field(c,b.data,b.size,1,&e);
        if(data==code) return MATTER_INVALID_ARGUMENT;
        if(data && c->response_command==MATTER_IM_CLIENT_STATUS_ONLY) return MATTER_INVALID_ARGUMENT;
        if(code) cmd=e;
        if(cmd.type!=MATTER_TLV_STRUCTURE || !field(c,cmd.data,cmd.size,0,&path) || path.type!=MATTER_TLV_LIST ||
            !number(c,path.data,path.size,0,c->path.endpoint) || !number(c,path.data,path.size,1,c->path.cluster) ||
            !number(c,path.data,path.size,2,data?c->response_command:c->path.command) ||
            !field(c,cmd.data,cmd.size,1,&e) || e.type!=MATTER_TLV_STRUCTURE) return MATTER_INVALID_ARGUMENT;
        if(code) {
            if(!field(c,e.data,e.size,0,&a) || a.type!=MATTER_TLV_UNSIGNED ||
                (!a.unsigned_value && c->response_command!=MATTER_IM_CLIENT_STATUS_ONLY) || a.unsigned_value>255) return MATTER_INVALID_ARGUMENT;
            status=(uint8_t)a.unsigned_value;
        } else {
            Matter_Tlv_Writer_T w;
            if(matter_tlv_writer_init(&w,c->body,sizeof(c->body),8)!=MATTER_TLV_OK || !copy(c,&w,e.data,e.size,-1) ||
                matter_tlv_writer_finish(&w,&c->body_size)!=MATTER_TLV_OK) return MATTER_INVALID_ARGUMENT;
        }
    } else return MATTER_INVALID_ARGUMENT;
    c->status=status; c->waiting=false; c->done=suppress;
    if(!suppress) {
        static const uint8_t ok[]={0x15,0x24,0,0,0x24,255,MATTER_IM_REVISION,0x18};
        memcpy(c->output,ok,sizeof(ok)); c->output_size=sizeof(ok); c->opcode=1;
    }
    return MATTER_OK;
}
Matter_Result_T matter_im_client_result(Matter_Im_Client_T c,uint8_t* code,const uint8_t** d,size_t* n) {
    if(!c || !code || !d || !n) return MATTER_INVALID_ARGUMENT;
    if(!c->done) return MATTER_PENDING;
    *code=c->status; *d=c->body; *n=c->body_size; return MATTER_OK;
}
void matter_im_client_delete(Matter_Im_Client_T c) { if(c) { memset(c,0,sizeof(*c)); free(c); } }
