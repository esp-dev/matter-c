#include "matter_light_groups_internal.h"

static uint8_t save(void* u,uint8_t fabric,const Matter_Light_State_T* snapshot,const Matter_Light_State_T* next) {
    Matter_Light_Groups_T m=u;if(m->busy)return MATTER_IM_FAILURE;
    if(!m->ready||matter_light_group_fabric(m,fabric)<0)return MATTER_IM_UNSUPPORTED_ACCESS;
    Light_Scene* old=matter_light_scene_find(m->image,fabric,0,0);
    if(!old&&!matter_light_scene_capacity(m->image,fabric))return MATTER_IM_RESOURCE_EXHAUSTED;
    m->busy=true;Light_Group_Image* p=matter_light_group_image_clone(m->image);uint8_t result=MATTER_IM_RESOURCE_EXHAUSTED;
    if(p) {
        Light_Scene* scene=matter_light_scene_find(p,fabric,0,0);
        if(!scene){scene=calloc(1,sizeof(*scene));if(!scene){matter_light_group_image_free(p);goto done;}scene->next=p->scenes;p->scenes=scene;}
        scene->fabric=fabric;scene->group=0;scene->id=0;scene->ms=0;matter_light_scene_capture_state(snapshot,scene);
        result=matter_light_group_commit_light(m,p,next);
    }
done:m->busy=false;return result;
}
static uint8_t load(void* u,uint8_t fabric,Matter_Light_State_T* state,bool* found) {
    Matter_Light_Groups_T m=u;if(m->busy)return MATTER_IM_FAILURE;
    if(!m->ready||matter_light_group_fabric(m,fabric)<0)return MATTER_IM_UNSUPPORTED_ACCESS;
    Light_Scene* scene=matter_light_scene_find(m->image,fabric,0,0);*found=scene!=NULL;
    if(scene)matter_light_scene_apply(scene,state);
    return 0;
}
static void recalled(void* u,uint8_t fabric){matter_light_scene_current(u,fabric,0,0);}
Matter_Result_T matter_light_group_global_bind(Matter_Light_Groups_T m) {
    Matter_Light_Scenes_Port port={m,save,load,recalled};Matter_Result_T r=matter_light_bind_scenes(m->config.light,&port);
    if(r==MATTER_OK)m->global_bound=true;
    return r;
}
