#include "matter_light_groups_internal.h"

static const uint32_t group_attrs[]={0,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
static const uint32_t scene_attrs[]={1,2,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
static const uint32_t group_commands[]={0,1,2,3,4,5},scene_commands[]={0,1,2,3,4,5,6,0x40};
static const uint32_t group_generated[]={0,1,2,3},scene_generated[]={0,1,2,3,4,6,0x40};
typedef struct { const uint32_t* values; size_t count; } Ids;
#define LIST(v) {v,sizeof(v)/sizeof(*(v))}
#define P(t,tag,v) matter_light_group_put(w,t,tag,v)
#define U(tag,v) P(MATTER_TLV_UNSIGNED,tag,v)
#define END() P(MATTER_TLV_END,-1,0)
static bool empty_string(Matter_Tlv_Writer_T* w,int tag) {
    Matter_Tlv_Element_T e={.type=MATTER_TLV_UTF8,.tag={.control=1,.number=(uint32_t)tag}};
    return matter_tlv_write(w,&e,0)==MATTER_TLV_OK;
}
static bool authorized(Matter_Light_Groups_T m,const Matter_Cluster_Request_T* q) {
    return m->ready&&(q->is_case||q->is_group)&&matter_light_group_fabric(m,q->fabric)>=0;
}
static uint8_t admission(Matter_Light_Groups_T m,const Matter_Cluster_Request_T* q) {
    return m->busy||(m->groupcast&&m->groupcast->processing&&!q->is_group)?MATTER_IM_FAILURE:authorized(m,q)?0:MATTER_IM_UNSUPPORTED_ACCESS;
}
static uint8_t read_list(Matter_Light_Groups_T m,Light_Group_Server* server,uint32_t id,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* out) {
    size_t size=0;Matter_Tlv_Writer_T writer;Matter_Tlv_Writer_T* w=&writer;
    for(unsigned pass=0;pass<2;++pass) {
        if((pass?matter_tlv_writer_init(w,m->encoded,size,3):matter_tlv_measure_init(w,4096,3))!=MATTER_TLV_OK||!P(MATTER_TLV_ARRAY,-1,0))return MATTER_IM_FAILURE;
        if(id==2&&server->scenes) {
            for(size_t i=0;i<m->image->fabric_count;++i) {
                uint8_t fabric=m->image->fabrics[i].index;if(q->filtered&&fabric!=q->fabric)continue;
                if(!P(MATTER_TLV_STRUCTURE,-1,0))return MATTER_IM_FAILURE;
                if(fabric==q->fabric) {
                    Light_Scene_Info* info=&m->info[i];
                    if(!U(0,matter_light_scene_count(m->image,fabric))||!U(1,info->id)||!U(2,info->group)||
                        !P(MATTER_TLV_BOOL,3,info->valid)||!U(4,matter_light_scene_capacity(m->image,fabric)))return MATTER_IM_FAILURE;
                }
                if(!U(254,fabric)||!END())return MATTER_IM_FAILURE;
            }
        } else {
            Ids list=server->scenes?(id==0xfff8?(Ids)LIST(scene_generated):id==0xfff9?(Ids)LIST(scene_commands):(Ids)LIST(scene_attrs)):
                id==0xfff8?(Ids)LIST(group_generated):id==0xfff9?(Ids)LIST(group_commands):(Ids)LIST(group_attrs);
            for(size_t i=0;i<list.count;++i)if(!U(-1,list.values[i]))return MATTER_IM_FAILURE;
        }
        if(!END()||matter_tlv_writer_finish(w,&size)!=MATTER_TLV_OK)return MATTER_IM_FAILURE;
        if(!pass){free(m->encoded);m->encoded=calloc(1,size);m->encoded_size=size;if(!m->encoded)return MATTER_IM_RESOURCE_EXHAUSTED;}
    }
    out->type=MATTER_TLV_ARRAY;out->data=m->encoded;out->size=size;return 0;
}
static uint8_t read_attr(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* out) {
    Light_Group_Server* server=u;Matter_Light_Groups_T m=server->owner;uint32_t id=*(const uint32_t*)ref;
    if(m->busy)return MATTER_IM_FAILURE;
    if(server->scenes&&!authorized(m,q))return MATTER_IM_UNSUPPORTED_ACCESS;
    m->busy=true;*out=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->version};uint8_t r=0;
    if(id==2||id==0xfff8||id==0xfff9||id==0xfffb)r=read_list(m,server,id,q,out);
    else out->unsigned_value=id==1?MATTER_LIGHT_SCENES:id==0xfffd?(server->scenes?1:4):0;
    m->busy=false;return r;
}
static bool string_field(Matter_Fields* in,unsigned tag) {
    return (in->seen&(1u<<tag))&&in->fields[tag].type==MATTER_TLV_UTF8&&in->fields[tag].size<=16;
}
static uint8_t group_schema(Matter_Fields* in,uint32_t command,uint16_t* group) {
    uint64_t id=0;
    if(command==4)return 0;
    if(command==2) {
        uint8_t error=0;Matter_Field_Array* a=matter_field_array(in->seen&1?&in->fields[0]:NULL,&error);if(!a)return error;
        while(matter_field_array_next(a)==MATTER_TLV_OK&&a->element.type!=MATTER_TLV_END)
            if(a->element.type!=MATTER_TLV_UNSIGNED||!a->element.unsigned_value||a->element.unsigned_value>65535){error=MATTER_IM_INVALID_COMMAND;break;}
        if(a->element.type!=MATTER_TLV_END&&!error)error=MATTER_IM_INVALID_COMMAND;
        free(a);return error;
    }
    if(!matter_field_u(in,0,65535,true,false,&id)||!id||((command==0||command==5)&&!string_field(in,1)))return MATTER_IM_INVALID_COMMAND;
    *group=(uint16_t)id;return 0;
}
static uint8_t group_add(Matter_Light_Groups_T m,uint8_t fabric,uint16_t id) {
    Light_Group* old=matter_light_group_find(m->image,fabric,id);if(old&&old->member)return 0;
    if(old&&old->retiring)return 0xcb;
    if(!old&&!matter_light_group_capacity(m->image,fabric))return MATTER_IM_RESOURCE_EXHAUSTED;
    Light_Group_Image* p=matter_light_group_image_clone(m->image);if(!p)return MATTER_IM_RESOURCE_EXHAUSTED;
    Light_Group* n=matter_light_group_find(p,fabric,id);
    if(!n) {
        n=calloc(1,sizeof(*n));if(!n){matter_light_group_image_free(p);return MATTER_IM_RESOURCE_EXHAUSTED;}
        *n=(Light_Group){.next=p->groups,.id=id,.key=65535,.fabric=fabric,.policy=1};p->groups=n;
    }
    n->member=true;return matter_light_group_commit(m,p);
}
static uint8_t groups(Matter_Light_Groups_T m,uint8_t fabric,uint32_t command,Matter_Fields* in,uint16_t id,Matter_Tlv_Writer_T* w) {
    uint8_t status=0;
    Light_Group* group=matter_light_group_find(m->image,fabric,id);
    if(command==0||(command==5&&matter_light_identifying(m->config.light)))status=group_add(m,fabric,id);
    else if(command==1||command==3) {
        if(!group||!group->member)status=MATTER_GROUPKEY_NOT_FOUND;
        else if(command==3) {
            Light_Group_Image* p=matter_light_group_image_clone(m->image);if(!p)status=MATTER_IM_RESOURCE_EXHAUSTED;
            else {matter_light_group_remove(p,fabric,id,false,false);status=matter_light_group_commit(m,p);}
        }
    } else if(command==4) {
        Light_Group_Image* p=matter_light_group_image_clone(m->image);if(!p)status=MATTER_IM_RESOURCE_EXHAUSTED;
        else {matter_light_group_remove(p,fabric,0,true,false);status=matter_light_group_commit(m,p);}
    }
    if(command==4||command==5)return status;
    if(!P(MATTER_TLV_STRUCTURE,-1,0))return MATTER_IM_FAILURE;
    if(command==2) {
        unsigned remaining=matter_light_group_capacity(m->image,fabric);
        if(!U(0,remaining)||!P(MATTER_TLV_ARRAY,1,0))return MATTER_IM_FAILURE;
        uint8_t error=0;Matter_Field_Array* list=matter_field_array(&in->fields[0],&error);if(!list)return error;
        bool empty=matter_field_array_next(list)==MATTER_TLV_OK&&list->element.type==MATTER_TLV_END;free(list);
        for(Light_Group* n=m->image->groups;n;n=n->next)if(n->fabric==fabric&&n->member) {
            bool selected=empty;
            if(!empty) {
                list=matter_field_array(&in->fields[0],&error);if(!list)return error;
                while(matter_field_array_next(list)==MATTER_TLV_OK&&list->element.type!=MATTER_TLV_END)if(list->element.unsigned_value==n->id)selected=true;
                free(list);
            }
            if(selected&&!U(-1,n->id))return MATTER_IM_FAILURE;
        }
        if(!END())return MATTER_IM_FAILURE;
    } else if(!U(0,status)||!U(1,id)||(command==1&&!empty_string(w,2)))return MATTER_IM_FAILURE;
    return END()?0:MATTER_IM_FAILURE;
}
static uint8_t scene_schema(Matter_Fields* in,uint32_t command,Light_Scene* s,uint16_t* to_group,uint8_t* to_id,unsigned* mode) {
    uint64_t group=0,id=0,ms=UINT16_MAX,copy=0,target=0,target_id=0;
    if(command==0x40) {
        if(!matter_field_u(in,0,255,true,false,&copy)||!matter_field_u(in,1,65535,true,false,&group)||
            !matter_field_u(in,2,254,true,false,&id)||!matter_field_u(in,3,65535,true,false,&target)||!matter_field_u(in,4,254,true,false,&target_id))return MATTER_IM_INVALID_COMMAND;
        *mode=(unsigned)copy&1;*to_group=(uint16_t)target;*to_id=(uint8_t)target_id;
    } else {
        if(!matter_field_u(in,0,65535,true,false,&group)||(command!=3&&command!=6&&!matter_field_u(in,1,254,true,false,&id)))return MATTER_IM_INVALID_COMMAND;
        if(command==0) {
            if(!matter_field_u(in,2,60000000,true,false,&ms)||!string_field(in,3))return MATTER_IM_INVALID_COMMAND;
            uint8_t r=matter_light_scene_extensions(in,s);if(r)return r;
        } else if(command==5) {
            if(!matter_field_u(in,2,60000000,false,true,&ms))return MATTER_IM_INVALID_COMMAND;
            if(!(in->seen&4)||in->fields[2].type==MATTER_TLV_NULL)ms=UINT32_MAX;
        }
    }
    s->group=(uint16_t)group;s->id=(uint8_t)id;s->ms=(uint32_t)ms;return 0;
}
static uint8_t store_scene(Matter_Light_Groups_T m,const Light_Scene* value) {
    Light_Scene* old=matter_light_scene_find(m->image,value->fabric,value->group,value->id);
    if(!old&&!matter_light_scene_capacity(m->image,value->fabric))return MATTER_IM_RESOURCE_EXHAUSTED;
    Light_Group_Image* p=matter_light_group_image_clone(m->image);if(!p)return MATTER_IM_RESOURCE_EXHAUSTED;
    Light_Scene* n=matter_light_scene_find(p,value->fabric,value->group,value->id);
    if(!n){n=calloc(1,sizeof(*n));if(!n){matter_light_group_image_free(p);return MATTER_IM_RESOURCE_EXHAUSTED;}n->next=p->scenes;p->scenes=n;}
    Light_Scene* next=n->next;*n=*value;n->next=next;return matter_light_group_commit(m,p);
}
static bool member(Matter_Light_Groups_T m,uint8_t fabric,uint16_t group) {
    Light_Group* n=matter_light_group_find(m->image,fabric,group);return !group||(n&&n->member);
}
void matter_light_scene_current(Matter_Light_Groups_T m,uint8_t fabric,uint16_t group,uint8_t id) {
    for(unsigned i=0;i<5;++i){m->info[i].valid=false;m->info[i].pending=false;}
    int i=matter_light_group_fabric(m,fabric);
    if(i>=0){bool matches=matter_light_scene_matches(m,matter_light_scene_find(m->image,fabric,group,id));m->info[i]=(Light_Scene_Info){.group=group,.id=id,.valid=matches,.pending=!matches};}
    static const uint32_t ids[]={6,8,0x300};
    for(unsigned j=0;j<3;++j)(void)matter_cluster_version(matter_light_cluster(m->config.light,ids[j]),&m->light_versions[j]);
    ++m->version;
}
static uint8_t scenes(Matter_Light_Groups_T m,uint32_t command,Light_Scene* value,uint16_t to_group,uint8_t to_id,unsigned mode,Matter_Tlv_Writer_T* w) {
    uint8_t fabric=value->fabric,status=member(m,fabric,value->group)?0:MATTER_IM_INVALID_COMMAND;
    Light_Scene* old=matter_light_scene_find(m->image,fabric,value->group,value->id);
    if(!status) {
        if(command==0)status=store_scene(m,value);
        else if(command==4){status=matter_light_scene_capture(m,value);value->ms=0;if(!status)status=store_scene(m,value);if(!status)matter_light_scene_current(m,fabric,value->group,value->id);}
        else if(command==1||command==5) {
            if(!old)status=MATTER_GROUPKEY_NOT_FOUND;
            else if(command==5){status=matter_light_scene_recall(m,old,value->ms==UINT32_MAX?old->ms:value->ms);if(!status)matter_light_scene_current(m,fabric,old->group,old->id);}
        } else if(command==2||command==3) {
            if(command==2&&!old)status=MATTER_GROUPKEY_NOT_FOUND;
            else {
                Light_Group_Image* p=matter_light_group_image_clone(m->image);
                if(!p)status=MATTER_IM_RESOURCE_EXHAUSTED;
                else {Light_Scene** n=&p->scenes;while(*n){Light_Scene* s=*n;if(s->fabric==fabric&&s->group==value->group&&(command==3||s->id==value->id)){*n=s->next;free(s);}else n=&s->next;}status=matter_light_group_commit(m,p);}
            }
        } else if(command==0x40) {
            if(!member(m,fabric,to_group))status=MATTER_IM_INVALID_COMMAND;
            else if(!mode&&!old)status=MATTER_GROUPKEY_NOT_FOUND;
            else {
                /* Iterate immutable pre-command snapshot: each copy commits
                 * independently; resource exhaustion keeps earlier copies. */
                Light_Group_Image* snapshot=matter_light_group_image_clone(m->image);
                if(!snapshot)status=MATTER_IM_RESOURCE_EXHAUSTED;
                else {for(Light_Scene* n=snapshot->scenes;n&&!status;n=n->next)if(n->fabric==fabric&&n->group==value->group&&(mode||n->id==value->id)){Light_Scene copy=*n;copy.group=to_group;if(!mode)copy.id=to_id;status=store_scene(m,&copy);}matter_light_group_image_free(snapshot);}
            }
        }
    }
    if(command==5)return status;
    if(!P(MATTER_TLV_STRUCTURE,-1,0)||!U(0,status))return MATTER_IM_FAILURE;
    if(command==6) {
        if(!U(1,matter_light_scene_capacity(m->image,fabric))||!U(2,value->group))return MATTER_IM_FAILURE;
        if(!status){if(!P(MATTER_TLV_ARRAY,3,0))return MATTER_IM_FAILURE;for(Light_Scene* n=m->image->scenes;n;n=n->next)if(n->fabric==fabric&&n->group==value->group&&!U(-1,n->id))return MATTER_IM_FAILURE;if(!END())return MATTER_IM_FAILURE;}
    } else {
        if(!U(1,value->group)||(command!=3&&!U(2,value->id)))return MATTER_IM_FAILURE;
        if(command==1&&!status)if(!U(3,old->ms)||!empty_string(w,4)||!matter_light_scene_encode(w,old,5))return MATTER_IM_FAILURE;
    }
    return END()?0:MATTER_IM_FAILURE;
}
static uint8_t run(Light_Group_Server* server,const Matter_Cluster_Request_T* q,uint32_t command,const uint8_t* data,size_t size,Matter_Tlv_Writer_T* w,bool execute) {
    Matter_Light_Groups_T m=server->owner;uint8_t r=admission(m,q);if(r)return r;
    Matter_Fields* in=matter_fields(data,size,5,&r);if(!in)return r;
    Light_Scene value={.fabric=q->fabric};uint16_t group=0,to_group=0;uint8_t to_id=0;unsigned mode=0;
    r=server->scenes?scene_schema(in,command,&value,&to_group,&to_id,&mode):group_schema(in,command,&group);
    if(!r&&q->is_group&&server->scenes&&!value.group)r=MATTER_IM_INVALID_COMMAND;
    if(!r&&execute) {
        bool response=server->scenes?command!=5:command<=3;
        if(response&&(!w||w->size||w->capacity<(server->scenes?(command==1?400u:48u):96u)))r=MATTER_IM_RESOURCE_EXHAUSTED;
        else {m->busy=true;if(m->groupcast)m->groupcast->administrator=q;r=server->scenes?scenes(m,command,&value,to_group,to_id,mode,w):groups(m,q->fabric,command,in,group,w);if(m->groupcast)m->groupcast->administrator=NULL;m->busy=false;}
    }
    free(in);return r;
}
static uint8_t validate(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* data,size_t size) {
    return run(u,q,*(const uint32_t*)ref,data,size,NULL,false);
}
static Matter_Result_T start(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* data,size_t size,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out,uint64_t* token) {
    *token=0;*out=(Matter_Im_Command_Result_T){.status=run(u,q,*(const uint32_t*)ref,data,size,w,true)};return MATTER_OK;
}
static Matter_Result_T version(void* u,uint32_t* out) {Light_Group_Server* s=u;*out=s->owner->version;return MATTER_OK;}
Matter_Result_T matter_light_group_interfaces(Matter_Light_Groups_T m) {
    for(unsigned k=0;k<2;++k) {
        m->server[k]=(Light_Group_Server){m,k!=0};Ids attrs=k?(Ids)LIST(scene_attrs):(Ids)LIST(group_attrs),commands=k?(Ids)LIST(scene_commands):(Ids)LIST(group_commands);
        Matter_Cluster_Config_T c={.id=k?0x62:4,.attributes=(uint16_t)attrs.count,.commands=(uint16_t)commands.count,.callbacks={.ctx=&m->server[k],.version=version}};
        m->clusters[k]=matter_cluster_new(&c);if(!m->clusters[k])return MATTER_LIMIT_REACHED;
        for(size_t i=0;i<attrs.count;++i) {
            Matter_Attribute_Def_T a={.id=attrs.values[i],.ref=&attrs.values[i],.read_access={MATTER_IM_VIEW,k!=0},.read=read_attr};
            if(matter_cluster_add_attribute(m->clusters[k],&a)!=MATTER_OK)return MATTER_LIMIT_REACHED;
        }
        for(size_t i=0;i<commands.count;++i) {
            uint32_t id=commands.values[i];bool response=k?id!=5:id<=3;
            Matter_Command_Def_T d={.id=id,.ref=&commands.values[i],.validate=validate,.start=start,
                .access={.privilege=id==1||(!k&&(id==2||id==5))||(k&&(id==5||id==6))?MATTER_IM_OPERATE:MATTER_IM_MANAGE,.fabric_scoped=true,
                    .response=response,.response_command=id,.response_capacity=k?(id==1?400:48):96}};
            if(matter_cluster_add_command(m->clusters[k],&d)!=MATTER_OK)return MATTER_LIMIT_REACHED;
        }
        if(matter_cluster_seal(m->clusters[k])!=MATTER_OK)return MATTER_PORT_ERROR;
    }
    return MATTER_OK;
}
