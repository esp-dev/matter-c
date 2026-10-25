#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_alloc_bytes.h"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"group-invoke:%d: %s\n",__LINE__,#x);abort();}}while(0)
#define calloc matter_test_calloc
#define free matter_test_free
#include "../../../main/apps/matter/model/matter_im_invoke.c"
#undef calloc
#undef free
typedef struct {unsigned invokes,authorizations;bool deny,timed;uint8_t requested;} Fixture;
static bool emit(Matter_Tlv_Writer_T* w,Matter_Tlv_Type_T type,int tag,uint64_t value) {
    Matter_Tlv_Element_T e={.type=type,.unsigned_value=value};if(tag>=0)e.tag=(Matter_Tlv_Tag_T){.control=1,.number=(uint32_t)tag};return matter_tlv_write(w,&e,0)==MATTER_TLV_OK;
}
#define P(t,tag,v) CHECK(emit(w,t,tag,v))
#define U(tag,v) P(MATTER_TLV_UNSIGNED,tag,v)
#define END() P(MATTER_TLV_END,-1,0)
static void body(Matter_Tlv_Writer_T* w,int tag) {
    P(MATTER_TLV_STRUCTURE,tag,0);P(MATTER_TLV_ARRAY,0,0);P(MATTER_TLV_STRUCTURE,-1,0);
    P(MATTER_TLV_ARRAY,0,0);P(MATTER_TLV_STRUCTURE,-1,0);U(0,1);END();END();END();END();END();
}
static size_t request(uint8_t* data,bool endpoint,bool suppress,bool timed) {
    Matter_Tlv_Writer_T writer;Matter_Tlv_Writer_T* w=&writer;CHECK(matter_tlv_writer_init(w,data,256,8)==MATTER_TLV_OK);
    P(MATTER_TLV_STRUCTURE,-1,0);P(MATTER_TLV_BOOL,0,suppress);P(MATTER_TLV_BOOL,1,timed);P(MATTER_TLV_ARRAY,2,0);
    P(MATTER_TLV_STRUCTURE,-1,0);P(MATTER_TLV_LIST,0,0);if(endpoint)U(0,1);U(1,6);U(2,1);END();body(w,1);END();END();U(255,MATTER_IM_REVISION);END();size_t size=0;CHECK(matter_tlv_writer_finish(w,&size)==MATTER_TLV_OK);return size;
}
static uint8_t auth(void* u,Matter_Exchange_Session_T session,const Matter_Im_Command_Path_T* path,Matter_Im_Privilege_T privilege) {
    Fixture* f=u;CHECK(session==1&&path->endpoint==1&&path->cluster==6&&path->command==1);++f->authorizations;f->requested=(uint8_t)privilege;return f->deny?MATTER_IM_UNSUPPORTED_ACCESS:0;
}
static uint8_t describe(void* u,const Matter_Im_Command_Path_T* path,Matter_Im_Command_T* out) {
    (void)path;Fixture* f=u;*out=(Matter_Im_Command_T){.privilege=MATTER_IM_MANAGE,.fabric_scoped=true,.timed=f->timed,.response=true,.response_capacity=256};return 0;
}
static uint8_t validate(void* u,const Matter_Im_Command_Path_T* path,const uint8_t* data,size_t size) {
    (void)u;(void)path;Matter_Tlv_Reader_T r;Matter_Tlv_Element_T e;CHECK(matter_tlv_init(&r,data,size,5)==MATTER_TLV_OK);
    unsigned max=0;Matter_Tlv_Result_T result;while((result=matter_tlv_next(&r,&e))==MATTER_TLV_OK)if(r.depth>max)max=r.depth;CHECK(result==MATTER_TLV_DONE&&max==5);return 0;
}
static Matter_Im_Command_Result_T invoke(void* u,const Matter_Im_Command_Path_T* path,const uint8_t* data,size_t size,Matter_Tlv_Writer_T* w) {
    (void)path;(void)data;(void)size;Fixture* f=u;++f->invokes;CHECK(w&&w->capacity==256);body(w,-1);return (Matter_Im_Command_Result_T){0};
}
int main(void) {
    Fixture f={0};Matter_Im_Invoke_Port_T port={&f,auth,describe,validate,invoke};uint8_t data[256];size_t size=request(data,false,true,false);
    for(unsigned i=1;i<=4;++i){fail_at=calls+i;CHECK(matter_im_invoke_group(&port,1,1,data,size)==MATTER_IM_RESOURCE_EXHAUSTED&&!f.invokes);fail_at=0;CHECK(!live&&!live_bytes);}
    CHECK(!matter_im_invoke_group(&port,1,1,data,size)&&f.invokes==1&&f.requested==MATTER_IM_MANAGE);CHECK(!live&&!live_bytes);
    f.deny=true;CHECK(matter_im_invoke_group(&port,1,1,data,size)==MATTER_IM_UNSUPPORTED_ACCESS&&f.invokes==1);f.deny=false;
    f.timed=true;CHECK(matter_im_invoke_group(&port,1,1,data,size)==MATTER_IM_NEEDS_TIMED_INTERACTION&&f.invokes==1);f.timed=false;
    size=request(data,true,true,false);CHECK(matter_im_invoke_group(&port,1,1,data,size)==MATTER_IM_INVALID_ACTION);
    size=request(data,false,false,false);CHECK(matter_im_invoke_group(&port,1,1,data,size)==MATTER_IM_INVALID_ACTION);
    size=request(data,false,true,true);CHECK(matter_im_invoke_group(&port,1,1,data,size)==MATTER_IM_TIMED_REQUEST_MISMATCH);
    CHECK(matter_im_invoke_group(&port,1,0,data,size)==MATTER_IM_INVALID_ACTION);
    CHECK(!live&&!live_bytes);puts("PASS group invoke: shared IM parser, endpoint-less expansion, depth-5 arguments/reply, exact privilege, no outputs and pre-effect OOM");return 0;
}
