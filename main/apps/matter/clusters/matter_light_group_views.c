#include "matter_light_groups_internal.h"

#define P(t,tag,v) matter_light_group_put(w,t,tag,v)
#define U(tag,v) P(MATTER_TLV_UNSIGNED,tag,v)
#define END() P(MATTER_TLV_END,-1,0)
static uint32_t version(void* u){return ((Matter_Light_Groups_T)u)->version;}
static bool encode(Matter_Light_Groups_T m,uint32_t id,const Matter_Cluster_Request_T* q,Matter_Tlv_Writer_T* w) {
    if(!P(MATTER_TLV_ARRAY,-1,0))return false;
    for(Light_Group* n=m->image->groups;n;n=n->next) {
        if(n->retiring)continue;
        if(q->filtered&&n->fabric!=q->fabric)continue;
        if(id==1&&!n->member)continue;
        if(id==7&&(!n->member||!n->auxiliary))continue;
        if(!P(MATTER_TLV_STRUCTURE,-1,0))return false;
        if(id==0) {if(!U(1,n->id)||!U(2,n->key))return false;}
        else if(id==1) {
            if(!U(1,n->id)||!P(MATTER_TLV_ARRAY,2,0)||!U(-1,m->config.endpoint)||!END())return false;
        } else if(n->fabric==q->fabric) {
            if(!U(1,MATTER_IM_OPERATE)||!U(2,3)||!P(MATTER_TLV_ARRAY,3,0)||!U(-1,n->id)||!END()||
                !P(MATTER_TLV_ARRAY,4,0)||!P(MATTER_TLV_STRUCTURE,-1,0)||!U(1,m->config.endpoint)||!END()||!END()||!U(5,1))return false;
        }
        if(!U(254,n->fabric)||!END())return false;
    }
    return END();
}
static uint8_t read_view(void* u,uint32_t id,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* out) {
    Matter_Light_Groups_T m=u;if(m->busy||(m->groupcast&&m->groupcast->processing))return MATTER_IM_FAILURE;
    if(!m->ready||matter_light_group_fabric(m,q->fabric)<0)return MATTER_IM_UNSUPPORTED_ACCESS;
    m->busy=true;uint8_t result=MATTER_IM_FAILURE;Matter_Tlv_Writer_T writer;Matter_Tlv_Writer_T* w=&writer;size_t size=0;
    if(matter_tlv_measure_init(w,4096,4)!=MATTER_TLV_OK||!encode(m,id,q,w)||matter_tlv_writer_finish(w,&size)!=MATTER_TLV_OK)goto done;
    uint8_t* bytes=calloc(1,size);if(!bytes){result=MATTER_IM_RESOURCE_EXHAUSTED;goto done;}
    if(matter_tlv_writer_init(w,bytes,size,4)!=MATTER_TLV_OK||!encode(m,id,q,w)||matter_tlv_writer_finish(w,&size)!=MATTER_TLV_OK){free(bytes);goto done;}
    free(m->encoded);m->encoded=bytes;m->encoded_size=size;
    *out=(Matter_Im_Value_T){.type=MATTER_TLV_ARRAY,.data=bytes,.size=size,.data_version=m->version};result=0;
done:m->busy=false;return result;
}
static uint8_t auxiliary(void* u,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* out){return read_view(u,7,q,out);}
static uint8_t map(void* u,uint8_t fabric,Matter_Im_List_Change_T change,const uint8_t* data,size_t size,bool store) {
    Matter_Light_Groups_T m=u;if(m->busy||(m->groupcast&&m->groupcast->processing))return MATTER_IM_FAILURE;
    if(!m->ready||matter_light_group_fabric(m,fabric)<0)return MATTER_IM_UNSUPPORTED_ACCESS;
    if(change!=MATTER_IM_LIST_REPLACE&&change!=MATTER_IM_LIST_ADD)return MATTER_IM_INVALID_ACTION;
    m->busy=true;Light_Group_Image* p=matter_light_group_image_clone(m->image);uint8_t result=MATTER_IM_RESOURCE_EXHAUSTED;
    if(!p)goto done;
    if(change==MATTER_IM_LIST_REPLACE) {
        Light_Group** link=&p->groups;
        while(*link){Light_Group* n=*link;if(n->fabric==fabric&&!n->retiring){if(!n->member){*link=n->next;free(n);continue;}n->key=65535;}link=&(*link)->next;}
    }
    /* One bounded input document. Individual structs use the common schema
     * workspace; wire FabricIndex is ignored, authenticated fabric is decisive. */
    Matter_Tlv_Reader_T reader;Matter_Tlv_Element_T e;
    result=MATTER_IM_INVALID_DATA_TYPE;
    if(size>1024||matter_tlv_init(&reader,data,size,3)!=MATTER_TLV_OK||matter_tlv_next(&reader,&e)!=MATTER_TLV_OK||e.tag.control)goto done;
    bool list=change==MATTER_IM_LIST_REPLACE;
    if(list&&(e.type!=MATTER_TLV_ARRAY||matter_tlv_next(&reader,&e)!=MATTER_TLV_OK))goto done;
    uint16_t* seen=calloc(MATTER_LIGHT_GROUPS_PER_FABRIC,sizeof(*seen));if(!seen){result=MATTER_IM_RESOURCE_EXHAUSTED;goto done;}unsigned count=0;
    while(e.type!=MATTER_TLV_END) {
        if(e.type!=MATTER_TLV_STRUCTURE||e.tag.control)goto parsed;
        size_t start=e.offset;if(matter_tlv_skip_container(&reader)!=MATTER_TLV_OK)goto parsed;
        uint8_t error=0;Matter_Fields* fields=matter_fields(data+start,reader.offset-start,1,&error);
        if(!fields){result=error;goto parsed;}
        uint64_t group=0,key=0;bool valid=matter_field_u(fields,1,65535,true,false,&group)&&group&&matter_field_u(fields,2,65535,true,false,&key)&&key;free(fields);
        if(!valid){result=MATTER_IM_CONSTRAINT_ERROR;goto parsed;}
        for(unsigned i=0;i<count;++i)if(seen[i]==group){result=MATTER_IM_CONSTRAINT_ERROR;goto parsed;}
        if(count>=MATTER_LIGHT_GROUPS_PER_FABRIC){result=MATTER_IM_RESOURCE_EXHAUSTED;goto parsed;}seen[count++]=(uint16_t)group;
        Light_Group* n=matter_light_group_find(p,fabric,(uint16_t)group);
        if(!n) {
            if(!matter_light_group_capacity(p,fabric)){result=MATTER_IM_RESOURCE_EXHAUSTED;goto parsed;}
            n=calloc(1,sizeof(*n));if(!n){result=MATTER_IM_RESOURCE_EXHAUSTED;goto parsed;}
            *n=(Light_Group){.next=p->groups,.fabric=fabric,.id=(uint16_t)group,.policy=1};p->groups=n;
        }
        if(n->retiring){result=0xcb;goto parsed;}
        n->key=(uint16_t)key;
        if(!list)break;
        if(matter_tlv_next(&reader,&e)!=MATTER_TLV_OK)goto parsed;
    }
    if((!list&&!count)||matter_tlv_next(&reader,&e)!=MATTER_TLV_DONE)goto parsed;
    result=0;
parsed:free(seen);
    if(!result&&store){result=matter_light_group_commit(m,p);p=NULL;}
done:matter_light_group_image_free(p);m->busy=false;return result;
}
Matter_Groupkey_Groups_Port_T matter_light_groups_keymap(Matter_Light_Groups_T m) {
    return (Matter_Groupkey_Groups_Port_T){.user=m,.max_groups_per_fabric=MATTER_LIGHT_GROUPS_PER_FABRIC,.groupcast=m&&m->groupcast,.version=version,.read=read_view,.map=map};
}
Matter_Acl_Auxiliary_Port_T matter_light_groups_auxiliary(Matter_Light_Groups_T m) {
    return (Matter_Acl_Auxiliary_Port_T){.user=m,.version=version,.read=auxiliary};
}
