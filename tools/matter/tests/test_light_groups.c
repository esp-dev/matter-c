#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_alloc_bytes.h"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"light-groups:%d: %s\n",__LINE__,#x);abort();}}while(0)
#include "clusters/matter_light_groups_internal.h"

typedef struct {
    uint8_t data[MATTER_LIGHT_GROUP_IMAGE_MAX];size_t size;unsigned writes;
    Matter_Light_State_T state;Matter_Light_Groups_T groups;bool fail,reenter;
} Disk;
static Matter_Result_T load(void* u,uint8_t* data,size_t capacity,size_t* size) {
    Disk* d=u;*size=d->size;if(data){if(capacity<d->size)return MATTER_LIMIT_REACHED;memcpy(data,d->data,d->size);}return MATTER_OK;
}
static Matter_Result_T save(void* u,const uint8_t* data,size_t size) {
    Disk* d=u;if(d->reenter){CHECK(matter_light_groups_process(d->groups,0)==MATTER_BUSY);CHECK(matter_light_groups_delete(d->groups)==MATTER_BUSY);}
    if(d->fail)return MATTER_PORT_ERROR;
    CHECK(size<=sizeof(d->data));memcpy(d->data,data,size);d->size=size;++d->writes;return MATTER_OK;
}
static Matter_Result_T light_load(void* u,Matter_Light_State_T* out){*out=((Disk*)u)->state;return MATTER_OK;}
static Matter_Result_T light_store(void* u,const Matter_Light_State_T* s){((Disk*)u)->state=*s;return MATTER_OK;}
static Matter_Result_T joint_store(void* u,const uint8_t* data,size_t size,const Matter_Light_State_T* state){Matter_Result_T r=save(u,data,size);if(r==MATTER_OK)((Disk*)u)->state=*state;return r;}
static Matter_Cluster_Request_T q={.fabric=1,.is_case=true,.filtered=true};
static uint8_t call(Matter_Light_Groups_T m,uint32_t cluster,uint32_t id,const uint8_t* data,size_t size,uint8_t* status) {
    uint8_t* response=calloc(1,400);CHECK(response);Matter_Tlv_Writer_T writer;CHECK(matter_tlv_writer_init(&writer,response,400,6)==MATTER_TLV_OK);
    Matter_Im_Command_Result_T result;uint64_t token=0;
    CHECK(matter_cluster_start(matter_light_groups_cluster(m,cluster),id,&q,data,size,&writer,&result,&token)==MATTER_OK&&!token);
    if(!result.status&&writer.size){Matter_Tlv_Reader_T r;Matter_Tlv_Element_T e;CHECK(matter_tlv_init(&r,response,writer.size,6)==MATTER_TLV_OK);while(matter_tlv_next(&r,&e)==MATTER_TLV_OK)if(e.tag.control==1&&e.tag.number==0&&e.type==MATTER_TLV_UNSIGNED){*status=(uint8_t)e.unsigned_value;break;}}
    free(response);return result.status;
}
int main(void) {
    Disk* d=calloc(1,sizeof(*d));CHECK(d);matter_light_defaults(&d->state);
    Matter_Light_Port_T light_port={d,light_load,light_store};Matter_Light_T light=matter_light_new(&light_port,1,0,true);CHECK(light);
    Matter_Light_Groups_Config_T config={.light=light,.endpoint=1,.version=1,.storage={d,load,save},.store_light=joint_store};
    size_t baseline=live;
    for(unsigned i=1;i<=4;++i){fail_at=calls+i;CHECK(!matter_light_groups_new(&config));fail_at=0;CHECK(live==baseline);}
    Matter_Light_Groups_T m=d->groups=matter_light_groups_new(&config);CHECK(m);
    const uint8_t add[]={0x15,0x24,0,7,0x2c,1,0,0x18};uint8_t status=255;
    CHECK(call(m,4,0,add,sizeof(add),&status)==MATTER_IM_UNSUPPORTED_ACCESS);
    Matter_Light_Groups_Fabric_T fabrics[2]={{.index=1,.id=0x123},{.index=2,.id=0x456}};fabrics[0].root_public[0]=1;fabrics[1].root_public[0]=2;
    CHECK(matter_light_groups_bind(m,fabrics,2)==MATTER_OK);unsigned writes=d->writes;uint32_t version=m->version;
    d->fail=true;CHECK(!call(m,4,0,add,sizeof(add),&status)&&status==MATTER_IM_FAILURE&&!matter_light_groups_member(m,1,7)&&m->version==version);d->fail=false;
    /* Every demand allocation on AddGroup, including the atomic image encoder,
     * must fail without publishing state or retaining allocations. */
    size_t stable=live_bytes;
    for(unsigned i=1;i<=4;++i){fail_at=calls+i;uint8_t r=call(m,4,0,add,sizeof(add),&status);fail_at=0;CHECK(r==MATTER_IM_RESOURCE_EXHAUSTED||(!r&&status==MATTER_IM_RESOURCE_EXHAUSTED));CHECK(!matter_light_groups_member(m,1,7)&&live_bytes==stable&&d->writes==writes);}
    d->reenter=true;CHECK(!call(m,4,0,add,sizeof(add),&status)&&!status&&matter_light_groups_member(m,1,7));d->reenter=false;
    CHECK(!call(m,4,0,add,sizeof(add),&status)&&!status&&d->writes==writes+1);
    const uint8_t scene[]={0x15,0x24,0,7,0x24,1,1,0x18};
    CHECK(!call(m,0x62,4,scene,sizeof(scene),&status)&&!status);
    d->state.on=false;Matter_Light_State_T off=d->state;CHECK(matter_light_recall(light,&off,0)==MATTER_OK);
    CHECK(!call(m,0x62,5,scene,sizeof(scene),&status));Matter_Light_State_T state;CHECK(matter_light_state(light,&state)==MATTER_OK&&state.on);
    q.fabric=2;CHECK(!call(m,0x62,1,scene,sizeof(scene),&status)&&status==MATTER_IM_INVALID_COMMAND);q.fabric=1;
    /* Scene delete is in the same durable publication as group delete. */
    d->fail=true;CHECK(call(m,4,3,add,5,&status)==MATTER_IM_INVALID_COMMAND);d->fail=false; /* malformed truncated request */
    const uint8_t remove[]={0x15,0x24,0,7,0x18};
    d->fail=true;CHECK(!call(m,4,3,remove,sizeof(remove),&status)&&status==MATTER_IM_FAILURE&&matter_light_scene_count(m->image,1)==1);d->fail=false;
    CHECK(!call(m,4,3,remove,sizeof(remove),&status)&&!status&&matter_light_scene_count(m->image,1)==0);
    /* HS is stored through the mandatory XY scene representation even when
     * EnhancedHue is absent. Preserve exact scene XY across idle processing. */
    CHECK(matter_light_state(light,&state)==MATTER_OK);state.mode=0;state.hue=37;state.saturation=199;matter_light_color_normalize(&state);uint16_t scene_x=state.x,scene_y=state.y;
    CHECK(matter_light_recall(light,&state,0)==MATTER_OK);
    CHECK(!call(m,4,0,add,sizeof(add),&status)&&!status);
    CHECK(!call(m,0x62,4,scene,sizeof(scene),&status)&&!status);
    state.hue=170;matter_light_color_normalize(&state);CHECK(matter_light_recall(light,&state,0)==MATTER_OK);
    CHECK(!call(m,0x62,5,scene,sizeof(scene),&status));CHECK(matter_light_state(light,&state)==MATTER_OK&&abs((int)state.hue-37)<=1&&state.saturation==199&&state.x==scene_x&&state.y==scene_y);
    CHECK(matter_light_process(light,1)==MATTER_OK&&matter_light_groups_process(m,1)==MATTER_OK&&m->info[0].valid);
    /* OffWithEffect's global scene and the OFF state share one durable
     * application publication. Store failure changes neither half. */
    const uint8_t effect[]={0x15,0x24,0,0,0x24,1,0,0x18},empty[]={0x15,0x18};Matter_Im_Command_Result_T result;uint64_t token=0;
    d->fail=true;CHECK(matter_cluster_start(matter_light_cluster(light,6),0x40,&q,effect,sizeof(effect),NULL,&result,&token)==MATTER_OK&&result.status==MATTER_IM_FAILURE);
    CHECK(matter_light_state(light,&state)==MATTER_OK&&state.on&&!matter_light_scene_find(m->image,1,0,0));d->fail=false;
    CHECK(matter_cluster_start(matter_light_cluster(light,6),0x40,&q,effect,sizeof(effect),NULL,&result,&token)==MATTER_OK&&!result.status&&!d->state.on&&matter_light_scene_find(m->image,1,0,0));
    CHECK(matter_light_state(light,&state)==MATTER_OK&&!state.on);uint8_t original=state.level;state.level=1;CHECK(matter_light_recall(light,&state,0)==MATTER_OK);
    CHECK(matter_cluster_start(matter_light_cluster(light,6),0x41,&q,empty,sizeof(empty),NULL,&result,&token)==MATTER_OK&&!result.status);
    CHECK(matter_light_state(light,&state)==MATTER_OK&&state.on&&state.level==original&&m->info[0].group==0&&m->info[0].id==0&&m->info[0].valid);
    CHECK(matter_light_delete(light)==MATTER_BUSY);
    CHECK(!call(m,4,0,add,sizeof(add),&status)&&!status);
    CHECK(!call(m,0x62,4,scene,sizeof(scene),&status)&&!status);
    CHECK(matter_light_groups_delete(m)==MATTER_OK);m=d->groups=matter_light_groups_new(&config);CHECK(m);
    CHECK(matter_light_groups_bind(m,fabrics,2)==MATTER_OK&&matter_light_groups_member(m,1,7)&&matter_light_scene_count(m->image,1)==2);
    /* Index reuse with another root must never recover the old memberships. */
    fabrics[0].root_public[0]=3;d->fail=true;CHECK(matter_light_groups_bind(m,fabrics,2)==MATTER_PORT_ERROR&&!matter_light_groups_member(m,1,7));d->fail=false;
    CHECK(matter_light_groups_bind(m,fabrics,2)==MATTER_OK&&!matter_light_groups_member(m,1,7)&&!matter_light_scene_count(m->image,1));
    CHECK(matter_light_groups_delete(m)==MATTER_OK);CHECK(matter_light_delete(light)==MATTER_OK);free(d);CHECK(!live&&!live_bytes);
    puts("PASS light groups: atomic group/scene persistence, reboot, fabric isolation/index reuse, reentry and OOM");return 0;
}
