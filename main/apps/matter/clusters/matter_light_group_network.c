#include "matter_light_groups_internal.h"

bool matter_light_group_address(const Light_Group_Image* p,const Light_Group* group,uint8_t out[16]) {
    if(!group->member)return false;
    memset(out,0,16);out[0]=0xff;
    if(!group->policy){out[1]=5;out[15]=0xfa;return true;}
    const Matter_Light_Groups_Fabric_T* fabric=NULL;
    for(size_t i=0;i<p->fabric_count;++i)if(p->fabrics[i].index==group->fabric)fabric=&p->fabrics[i];
    if(!fabric)return false;
    out[1]=0x35;out[3]=0x40;out[4]=0xfd;
    for(unsigned i=0;i<8;++i)out[5+i]=(uint8_t)(fabric->id>>(56-8*i));
    out[14]=(uint8_t)(group->id>>8);out[15]=(uint8_t)group->id;return true;
}
static bool wanted(const Light_Group_Image* p,const uint8_t address[16]) {
    uint8_t current[16];
    for(const Light_Group* g=p->groups;g;g=g->next)if(matter_light_group_address(p,g,current)&&!memcmp(current,address,16))return true;
    return false;
}
Matter_Result_T matter_light_group_network_cleanup(Matter_Light_Groups_T m,bool all) {
    if(!m->config.leave)return MATTER_OK;
    Matter_Result_T result=MATTER_OK;Light_Group_Multicast** link=&m->joined;
    while(*link) {
        Light_Group_Multicast* n=*link;
        if(!all&&wanted(m->image,n->address)){link=&n->next;continue;}
        if(m->config.leave(m->config.multicast_user,n->address)==MATTER_OK){*link=n->next;free(n);}
        else {result=MATTER_PORT_ERROR;link=&n->next;}
    }
    return result;
}
uint8_t matter_light_group_network_prepare(Matter_Light_Groups_T m,const Light_Group_Image* p) {
    if(!m->config.join)return 0;
    uint8_t address[16];
    for(const Light_Group* g=p->groups;g;g=g->next)if(matter_light_group_address(p,g,address)) {
        bool found=false;unsigned count=0;
        for(Light_Group_Multicast* n=m->joined;n;n=n->next){++count;if(!memcmp(address,n->address,16))found=true;}
        if(found)continue;
        if(count>=MATTER_LIGHT_GROUP_MEMBERSHIPS)return MATTER_IM_RESOURCE_EXHAUSTED;
        Light_Group_Multicast* n=calloc(1,sizeof(*n));if(!n)return MATTER_IM_RESOURCE_EXHAUSTED;
        Matter_Result_T r=m->config.join(m->config.multicast_user,address);
        if(r!=MATTER_OK){free(n);return r==MATTER_LIMIT_REACHED?MATTER_IM_RESOURCE_EXHAUSTED:MATTER_IM_FAILURE;}
        memcpy(n->address,address,16);n->next=m->joined;m->joined=n;
    }
    return 0;
}
