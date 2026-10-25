#include "matter_light_groups_internal.h"

static const uint32_t clusters[11]={6,8,0x300,0x300,0x300,0x300,0x300,0x300,0x300,0x300,0x300};
static const uint32_t attributes[11]={0,0,3,4,0x4000,1,0x4002,0x4003,0x4004,7,0x4001};
static const uint8_t widths[11]={1,1,3,3,3,1,1,1,3,3,1};

bool matter_light_group_put(Matter_Tlv_Writer_T* w,Matter_Tlv_Type_T type,int tag,uint64_t value) {
    Matter_Tlv_Element_T e={.type=type,.unsigned_value=value};
    if(tag>=0)e.tag=(Matter_Tlv_Tag_T){.control=1,.number=(uint32_t)tag};
    return matter_tlv_write(w,&e,0)==MATTER_TLV_OK;
}
#define P(t,tag,v) matter_light_group_put(w,t,tag,v)
#define U(tag,v) P(MATTER_TLV_UNSIGNED,tag,v)
#define END() P(MATTER_TLV_END,-1,0)

bool matter_light_scene_encode(Matter_Tlv_Writer_T* w,const Light_Scene* s,int tag) {
    if(!P(MATTER_TLV_ARRAY,tag,0))return false;
    for(unsigned k=0;k<3;++k) {
        unsigned first=k==0?0:k==1?1:2,last=k<2?first+1:11;
        if(!(s->mask&(((1u<<last)-1)^((1u<<first)-1))))continue;
        if(!P(MATTER_TLV_STRUCTURE,-1,0)||!U(0,clusters[first])||!P(MATTER_TLV_ARRAY,1,0))return false;
        for(unsigned i=first;i<last;++i)if(s->mask&(1u<<i))
            if(!P(MATTER_TLV_STRUCTURE,-1,0)||!U(0,attributes[i])||!U(widths[i],s->values[i])||!END())return false;
        if(!END()||!END())return false;
    }
    return END();
}
static uint16_t constrained(unsigned slot,uint64_t n) {
    if(slot==0)return n==1;
    if(slot==1)return n<1||n>254?255:(uint16_t)n;
    if(slot==2||slot==3)return n>65279?65279:(uint16_t)n;
    if(slot==4)return UINT16_MAX; /* EHUE not implemented. */
    if(slot==5)return n>254?255:(uint16_t)n;
    if(slot==6||slot==7||slot==8)return 0; /* Color loop not implemented. */
    if(slot==9)return n<153||n>500?UINT16_MAX:(uint16_t)n;
    return n>2?2:(uint16_t)n;
}
bool matter_light_scene_values_valid(const Light_Scene* s) {
    if((s->mask&2044)&&(s->mask&2044)!=2044)return false;
    for(unsigned i=0;i<11;++i)if((s->mask&(1u<<i))&&constrained(i,s->values[i])!=s->values[i])return false;
    return true;
}
uint8_t matter_light_scene_extensions(Matter_Fields* in,Light_Scene* s) {
    uint8_t error=MATTER_IM_INVALID_COMMAND;
    if(!(in->seen&16))return error;
    Matter_Field_Array* a=matter_field_array(&in->fields[4],&error);if(!a)return error;
    s->mask=0;
    while(matter_field_array_next(a)==MATTER_TLV_OK&&a->element.type!=MATTER_TLV_END) {
        if(a->element.type!=MATTER_TLV_STRUCTURE)goto bad;
        Matter_Fields* extension=matter_fields(a->element.data,a->element.size,4,&error);if(!extension)goto done;
        uint64_t cluster=0;
        if(!matter_field_u(extension,0,UINT32_MAX,true,false,&cluster)||!(extension->seen&2)) {free(extension);goto bad;}
        unsigned mask=cluster==6?1:cluster==8?2:cluster==0x300?2044:0;
        s->mask&=(uint16_t)~mask; /* Last extension for a cluster wins. */
        Matter_Field_Array* pairs=matter_field_array(&extension->fields[1],&error);
        if(!pairs){free(extension);goto done;}
        bool valid=true;
        while(matter_field_array_next(pairs)==MATTER_TLV_OK&&pairs->element.type!=MATTER_TLV_END) {
            if(pairs->element.type!=MATTER_TLV_STRUCTURE){valid=false;break;}
            Matter_Fields* pair=matter_fields(pairs->element.data,pairs->element.size,1,&error);
            if(!pair){valid=false;break;}
            uint64_t attribute=0;unsigned values=pair->seen&510;
            if(!matter_field_u(pair,0,UINT32_MAX,true,false,&attribute)||!values||(values&(values-1)))valid=false;
            unsigned field=0;for(unsigned i=1;i<9;++i)if(values&(1u<<i))field=i;
            if(valid) {
                Matter_Tlv_Element_T* value=&pair->fields[field];
                bool numeric=(field&1)?value->type==MATTER_TLV_UNSIGNED:value->type==MATTER_TLV_SIGNED;
                unsigned bits=field<=2?8:field<=4?16:field<=6?32:64;
                if(!numeric||((field&1)&&bits<64&&value->unsigned_value>(((uint64_t)1<<bits)-1))||
                    (!(field&1)&&bits<64&&(value->signed_value<-((int64_t)1<<(bits-1))||value->signed_value>=((int64_t)1<<(bits-1)))))valid=false;
                for(unsigned i=0;valid&&i<11;++i)if(cluster==clusters[i]&&attribute==attributes[i]) {
                    if(field!=widths[i]){valid=false;break;}
                    s->values[i]=constrained(i,value->unsigned_value);s->mask|=(uint16_t)(1u<<i);
                }
            }
            free(pair);if(!valid)break;
        }
        if(pairs->element.type!=MATTER_TLV_END)valid=false;
        free(pairs);free(extension);
        if(!valid){if(!error)error=MATTER_IM_INVALID_COMMAND;goto done;}
        /* Color rev >= 6 requires its complete nine-attribute extension. */
        if(cluster==0x300&&(s->mask&2044)!=2044)goto bad;
    }
    if(a->element.type!=MATTER_TLV_END)goto bad;
    error=0;goto done;
bad:error=MATTER_IM_INVALID_COMMAND;
done:free(a);return error;
}
uint8_t matter_light_scene_capture(Matter_Light_Groups_T m,Light_Scene* s) {
    Matter_Light_State_T state;if(matter_light_state(m->config.light,&state)!=MATTER_OK)return MATTER_IM_FAILURE;
    matter_light_scene_capture_state(&state,s);return 0;
}
void matter_light_scene_capture_state(const Matter_Light_State_T* state,Light_Scene* s) {
    s->mask=2047;s->values[0]=state->on;s->values[1]=state->level;s->values[2]=state->x;s->values[3]=state->y;
    s->values[4]=65535;s->values[5]=state->saturation;s->values[6]=s->values[7]=s->values[8]=0;
    s->values[9]=state->temperature;s->values[10]=state->mode;
}
void matter_light_scene_apply(const Light_Scene* s,Matter_Light_State_T* state) {
    if(s->mask&1)state->on=s->values[0]!=0;
    if((s->mask&2)&&s->values[1]>=1&&s->values[1]<=254)state->level=(uint8_t)s->values[1];
    if(s->mask&4)state->x=s->values[2];
    if(s->mask&8)state->y=s->values[3];
    if((s->mask&32)&&s->values[5]<=254)state->saturation=(uint8_t)s->values[5];
    if((s->mask&512)&&s->values[9]>=153&&s->values[9]<=500)state->temperature=s->values[9];
    if(s->mask&1024)state->mode=(uint8_t)s->values[10];
    if(state->mode==0&&(s->mask&12)==12) {
        uint8_t saturation=state->saturation;matter_light_color_hue_from_xy(state);
        if((s->mask&32)&&s->values[5]<=254)state->saturation=saturation;
    }
}
bool matter_light_scene_matches(Matter_Light_Groups_T m,const Light_Scene* s) {
    Matter_Light_State_T before;if(!s||matter_light_state(m->config.light,&before)!=MATTER_OK)return false;
    Matter_Light_State_T after=before;matter_light_scene_apply(s,&after);
    if(before.on!=after.on||before.level!=after.level||before.mode!=after.mode)return false;
    /* The mandatory scene representation is XY (HS has no stored CurrentHue
     * without EHUE). Compare that exact snapshot, not a second, quantized HSV
     * reconstruction; inactive color-space caches do not invalidate a scene. */
    return before.mode==2?before.temperature==after.temperature:
        before.x==after.x&&before.y==after.y&&(before.mode!=0||before.saturation==after.saturation);
}
uint8_t matter_light_scene_recall(Matter_Light_Groups_T m,const Light_Scene* s,uint32_t ms) {
    Matter_Light_State_T state;if(matter_light_state(m->config.light,&state)!=MATTER_OK)return MATTER_IM_FAILURE;
    matter_light_scene_apply(s,&state);Matter_Result_T r=matter_light_recall(m->config.light,&state,ms);
    return r==MATTER_OK?0:r==MATTER_LIMIT_REACHED?MATTER_IM_RESOURCE_EXHAUSTED:MATTER_IM_FAILURE;
}
Matter_Result_T matter_light_groups_process(Matter_Light_Groups_T m,uint64_t now) {
    if(!m)return MATTER_INVALID_ARGUMENT;
    if(m->busy||(m->groupcast&&m->groupcast->processing))return MATTER_BUSY;
    if(now>=m->multicast_retry){m->busy=true;(void)matter_light_group_network_cleanup(m,false);m->busy=false;m->multicast_retry=UINT64_MAX-now<1000?UINT64_MAX:now+1000;}
    static const uint32_t ids[]={6,8,0x300};bool changed=false;
    for(unsigned i=0;i<3;++i) {
        uint32_t version=0;Matter_Result_T r=matter_cluster_version(matter_light_cluster(m->config.light,ids[i]),&version);
        if(r!=MATTER_OK)return r;
        if(m->light_versions[i]!=version){m->light_versions[i]=version;changed=true;}
    }
    if(changed)for(size_t i=0;i<m->image->fabric_count;++i) {
        Light_Scene_Info* info=&m->info[i];Light_Scene* scene=matter_light_scene_find(m->image,m->image->fabrics[i].index,info->group,info->id);
        bool matches=matter_light_scene_matches(m,scene);
        if(info->pending&&matches){info->pending=false;info->valid=true;++m->version;}
        else if(info->valid&&!matches){info->valid=false;++m->version;}
    }
    return matter_light_groupcast_process(m,now);
}
