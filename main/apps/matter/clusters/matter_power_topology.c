#include "matter_power_topology.h"
#include "../model/matter_cluster_internal.h"
#include <stdlib.h>
static Matter_Result_T version(void* u,uint32_t* v) { *v=*(uint32_t*)u; return MATTER_OK; }
static Matter_Result_T destroy(void* u) { free(u); return MATTER_OK; }
static uint8_t read_value(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    (void)q; *v=*(const Matter_Im_Value_T*)ref; v->data_version=*(uint32_t*)u; return 0;
}
Matter_Cluster_T matter_power_topology_new(uint32_t data_version) {
    uint32_t* state=calloc(1,sizeof(*state)); if(!state) return NULL; *state=data_version;
    Matter_Cluster_Config_T config={.id=MATTER_POWER_TOPOLOGY_CLUSTER,.attributes=5,
        .callbacks={.ctx=state,.version=version,.destroy=destroy}};
    Matter_Cluster_T c=matter_cluster_new(&config); if(!c) { free(state); return NULL; }
    /* Immutable anonymous ARRAY TLV, as required by the common read contract. */
    static const uint8_t empty[]={0x16,0x18},attrs[]={0x16,5,0xf8,0xff,5,0xf9,0xff,5,0xfb,0xff,5,0xfc,0xff,5,0xfd,0xff,0x18};
    static const Matter_Im_Value_T values[]={
        {.type=MATTER_TLV_ARRAY,.data=empty,.size=sizeof(empty)},
        {.type=MATTER_TLV_ARRAY,.data=attrs,.size=sizeof(attrs)},
        {.type=MATTER_TLV_UNSIGNED,.unsigned_value=2},
        {.type=MATTER_TLV_UNSIGNED,.unsigned_value=1}
    };
    static const Matter_Attribute_Def_T definitions[]={
        {.id=0xfff8,.read_access={MATTER_IM_VIEW,false},.read=read_value,.ref=&values[0]},
        {.id=0xfff9,.read_access={MATTER_IM_VIEW,false},.read=read_value,.ref=&values[0]},
        {.id=0xfffb,.read_access={MATTER_IM_VIEW,false},.read=read_value,.ref=&values[1]},
        {.id=0xfffc,.read_access={MATTER_IM_VIEW,false},.read=read_value,.ref=&values[2]},
        {.id=0xfffd,.read_access={MATTER_IM_VIEW,false},.read=read_value,.ref=&values[3]}
    };
    for(unsigned i=0;i<5;++i) if(matter_cluster_add_attribute(c,&definitions[i])!=MATTER_OK) { matter_cluster_abandon(c); free(state); return NULL; }
    (void)matter_cluster_seal(c); return c;
}
