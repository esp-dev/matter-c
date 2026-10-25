#include "clusters/matter_acl.h"
#include "clusters/matter_groupkey.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"group-profiles:%d: %s\n",__LINE__,#x);abort();}}while(0)
#define OC_CHECK CHECK
#include "test_groupkey_wire.h"
typedef struct {
    Matter_Acl_View_T acl;Matter_Groupkey_View_T keys;
    Matter_Cluster_T cluster;unsigned reads,maps,stores,views;uint32_t extension_version;
} Fixture;
static const uint8_t empty[]={0x16,0x18};
static const Matter_Acl_View_T* acl_view(void* u){Fixture* f=u;++f->views;return &f->acl;}
static const Matter_Groupkey_View_T* key_view(void* u){return &((Fixture*)u)->keys;}
static uint8_t acl_store(void* u,uint8_t fabric,const Matter_Acl_Entry_T* entries,size_t count){(void)fabric;(void)entries;(void)count;++((Fixture*)u)->stores;return 0;}
static uint8_t key_store(void* u,uint8_t fabric,const Matter_Groupkey_Set_T* set,const uint8_t keys[3][16]){(void)fabric;(void)set;(void)keys;++((Fixture*)u)->stores;return 0;}
static uint8_t key_remove(void* u,uint8_t fabric,uint16_t key){(void)u;(void)fabric;(void)key;return 0;}
static uint32_t version(void* u){return ((Fixture*)u)->extension_version;}
static uint8_t read_aux(void* u,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* out){Fixture* f=u;CHECK(q->fabric==1);++f->reads;*out=(Matter_Im_Value_T){.type=MATTER_TLV_ARRAY,.data=empty,.size=sizeof(empty)};return 0;}
static uint8_t read_keys(void* u,uint32_t id,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* out){CHECK(id<=1);return read_aux(u,q,out);}
static uint8_t map(void* u,uint8_t index,Matter_Im_List_Change_T change,const uint8_t* data,size_t size,bool store){
    Fixture* f=u;CHECK(index==1&&change==MATTER_IM_LIST_REPLACE&&size==sizeof(empty)&&!memcmp(data,empty,size));++f->maps;if(store)++f->stores;CHECK(matter_cluster_delete(f->cluster)==MATTER_BUSY);return 0;
}
int main(void) {
    Fixture* f=calloc(1,sizeof(*f));CHECK(f);f->acl.fabrics[0].index=1;f->acl.version=100;f->keys.fabrics[0].index=1;f->keys.fabrics[0].sets[0].count=1;f->keys.version=200;f->extension_version=11;
    Matter_Acl_Port_T ap={f,acl_view,acl_store};Matter_Acl_Auxiliary_Port_T auxiliary={f,version,read_aux};
    f->cluster=matter_acl_new_auxiliary(&ap,&auxiliary);CHECK(f->cluster);Matter_Cluster_Request_T q={.fabric=1,.is_case=true,.filtered=true};Matter_Im_Value_T value;
    CHECK(!matter_cluster_read(f->cluster,0xfffc,&q,&value)&&value.unsigned_value==4&&value.data_version==111);
    CHECK(!matter_cluster_read(f->cluster,7,&q,&value)&&value.type==MATTER_TLV_ARRAY&&value.size==2&&f->reads==1);
    unsigned views=f->views;CHECK(!matter_cluster_read(f->cluster,0,&q,&value)&&f->views==views+1&&value.data_version==111);
    const Matter_Event_Def_T* event=matter_cluster_event(f->cluster,3);CHECK(event&&event->privilege==MATTER_IM_ADMINISTER&&event->fabric_scoped);
    static const uint8_t forbidden[]={0x16,0x15,0x24,1,3,0x24,2,2,0x34,3,0x34,4,0x24,5,1,0x18,0x18};
    CHECK(matter_acl_validate(f->cluster,1,MATTER_IM_LIST_REPLACE,forbidden,sizeof(forbidden))==MATTER_IM_CONSTRAINT_ERROR&&!f->stores);
    CHECK(matter_cluster_delete(f->cluster)==MATTER_OK);
    Matter_Acl_Fabric_T* fabric=&f->acl.fabrics[0];fabric->count=1;
    fabric->entries[0]=(Matter_Acl_Entry_T){.privilege=MATTER_IM_OPERATE,.auth_mode=3,.subject_count=1,.subjects={7},.target_count=1,.targets={{.cluster=6,.endpoint=1,.present=3}}};
    Matter_Im_Path_T path={1,6,0};CHECK(matter_acl_group_grants(&f->acl,1,7,&path,MATTER_IM_OPERATE,NULL));
    CHECK(!matter_acl_group_grants(&f->acl,1,8,&path,MATTER_IM_OPERATE,NULL)&&!matter_acl_group_grants(&f->acl,2,7,&path,MATTER_IM_OPERATE,NULL));
    CHECK(!matter_acl_group_grants(&f->acl,1,7,&path,MATTER_IM_MANAGE,NULL)&&!matter_acl_grants(&f->acl,1,7,NULL,0,&path,MATTER_IM_OPERATE,NULL));
    path.endpoint=0;CHECK(!matter_acl_group_grants(&f->acl,1,7,&path,MATTER_IM_OPERATE,NULL));
    Matter_Groupkey_Port_T kp={f,key_view,key_store,key_remove};Matter_Groupkey_Groups_Port_T groups={.user=f,.max_groups_per_fabric=20,.groupcast=true,.version=version,.read=read_keys,.map=map};
    f->cluster=matter_groupkey_new_groups(&kp,&groups);CHECK(f->cluster);
    CHECK(!matter_cluster_read(f->cluster,2,&q,&value)&&value.unsigned_value==0&&value.data_version==211);
    CHECK(!matter_cluster_read(f->cluster,0xfffc,&q,&value)&&value.unsigned_value==2);
    CHECK(!matter_cluster_read(f->cluster,0,&q,&value)&&f->reads==2);
    CHECK(matter_groupkey_map(f->cluster,0,MATTER_IM_LIST_REPLACE,empty,sizeof(empty))==MATTER_IM_UNSUPPORTED_ACCESS&&!f->maps);
    CHECK(!matter_groupkey_map(f->cluster,1,MATTER_IM_LIST_REPLACE,empty,sizeof(empty))&&f->maps==1&&!f->stores);
    CHECK(!matter_cluster_write_list(f->cluster,0,&q,MATTER_IM_LIST_REPLACE,empty,sizeof(empty)).status&&f->maps==3&&f->stores==1);
    q.fabric=2;CHECK(matter_cluster_write_list(f->cluster,0,&q,MATTER_IM_LIST_REPLACE,empty,sizeof(empty)).status==MATTER_IM_UNSUPPORTED_ACCESS&&f->maps==3);
    GkWire* wire=calloc(1,sizeof(*wire));CHECK(wire);gk_args(wire,0,7,3,100);
    CHECK(matter_groupkey_validate(f->cluster,0,wire->data,wire->n)==MATTER_IM_INVALID_COMMAND);
    gk_args(wire,0,0,3,100);CHECK(!matter_groupkey_validate(f->cluster,0,wire->data,wire->n));
    CHECK(matter_cluster_delete(f->cluster)==MATTER_OK);free(wire);free(f);
    puts("PASS group profiles: optional composition, single ACL snapshot, auxiliary protections, group-only grants, scoped map and two operational epochs");return 0;
}
