#include "matter_switch_sim.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); exit(1); } } while(0)
typedef struct { unsigned calls; bool on; } Observer;
static void changed(void* u,bool on) { Observer* o=u; ++o->calls; o->on=on; }
static Matter_Im_Value_T read(Matter_Cluster_T c) {
    Matter_Cluster_Request_T q={0}; Matter_Im_Value_T v;
    CHECK(matter_cluster_read(c,0,&q,&v)==0 && v.type==MATTER_TLV_BOOL); return v;
}
static uint8_t invoke(Matter_Cluster_T c,uint32_t id,const uint8_t* data,size_t size) {
    Matter_Cluster_Request_T q={0}; Matter_Im_Command_Result_T result; uint64_t token=99;
    CHECK(matter_cluster_start(c,id,&q,data,size,NULL,&result,&token)==MATTER_OK && !token); return result.status;
}
int main(void) {
    Observer observer={0}; Matter_Cluster_T a=matter_switch_sim_new(UINT32_MAX,changed,&observer),b=matter_switch_sim_new(20,NULL,NULL);
    CHECK(a && b); static const uint8_t empty[]={0x15,0x18},extra[]={0x15,0x24,7,42,0x18},bad[]={0x15,0x24};
    CHECK(read(a).unsigned_value==0 && read(a).data_version==UINT32_MAX);
    Matter_Im_Command_T access; CHECK(matter_cluster_command(a,1,&access)==0 && access.privilege==MATTER_IM_OPERATE);
    Matter_Im_Write_Attribute_T write; CHECK(matter_cluster_describe_write(a,0,&write)==MATTER_IM_UNSUPPORTED_WRITE);
    CHECK(invoke(a,1,empty,sizeof(empty))==0 && read(a).unsigned_value==1 && read(a).data_version==0);
    CHECK(observer.calls==1 && observer.on && read(b).unsigned_value==0);
    CHECK(invoke(a,1,extra,sizeof(extra))==0 && read(a).data_version==0 && observer.calls==1);
    CHECK(invoke(a,2,bad,sizeof(bad))==MATTER_IM_INVALID_COMMAND && read(a).unsigned_value==1);
    CHECK(invoke(a,2,empty,1)==MATTER_IM_INVALID_COMMAND);
    CHECK(invoke(a,2,NULL,0)==MATTER_IM_INVALID_COMMAND);
    CHECK(invoke(a,42,empty,sizeof(empty))==MATTER_IM_UNSUPPORTED_COMMAND);
    CHECK(invoke(a,2,empty,sizeof(empty))==0 && read(a).unsigned_value==0 && read(a).data_version==1);
    CHECK(invoke(a,0,empty,sizeof(empty))==0 && read(a).data_version==1 && observer.calls==2);
    CHECK(invoke(b,2,empty,sizeof(empty))==0 && read(b).unsigned_value==1 && read(a).unsigned_value==0);
    CHECK(matter_cluster_delete(a)==MATTER_OK && matter_cluster_delete(b)==MATTER_OK);
    puts("switch simulation: PASS state/versions/isolation/privileges/malformed/unknown fields/cleanup"); return 0;
}
