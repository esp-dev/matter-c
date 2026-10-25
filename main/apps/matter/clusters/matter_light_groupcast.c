#include "matter_light_groups_internal.h"

static const uint32_t attributes[]={0,1,2,3,4,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
static const uint32_t commands[]={0,1,3,4,5},generated[]={2};
#define P(t,tag,v) matter_light_group_put(w,t,tag,v)
#define U(tag,v) P(MATTER_TLV_UNSIGNED,tag,v)
#define END() P(MATTER_TLV_END,-1,0)
static bool encode(Matter_Light_Groups_T m,uint32_t id,const Matter_Cluster_Request_T* q,Matter_Tlv_Writer_T* w) {
    if(!P(MATTER_TLV_ARRAY,-1,0))return false;
    if(id==0) {
        for(Light_Group* n=m->image->groups;n;n=n->next)if(n->member&&(!q->filtered||n->fabric==q->fabric)) {
            if(!P(MATTER_TLV_STRUCTURE,-1,0)||!U(0,n->id)||!P(MATTER_TLV_ARRAY,1,0)||!U(-1,m->config.endpoint)||!END()||
                (n->fabric==q->fabric&&!U(2,n->key))||!P(MATTER_TLV_BOOL,3,n->auxiliary)||!U(4,n->policy)||!U(254,n->fabric)||!END())return false;
        }
    } else {
        const uint32_t* ids=id==0xfff8?generated:id==0xfff9?commands:attributes;
        size_t count=id==0xfff8?1:id==0xfff9?5:10;for(size_t i=0;i<count;++i)if(!U(-1,ids[i]))return false;
    }
    return END();
}
static uint8_t read_attr(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* out) {
    Matter_Light_Groups_T m=u;if(m->busy||(m->groupcast&&m->groupcast->processing))return MATTER_IM_FAILURE;
    uint32_t id=*(const uint32_t*)ref;
    if(id==0&&(!m->ready||matter_light_group_fabric(m,q->fabric)<0))return MATTER_IM_UNSUPPORTED_ACCESS;
    *out=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->version};
    if(id==0||id==0xfff8||id==0xfff9||id==0xfffb) {
        m->busy=true;Matter_Tlv_Writer_T writer;Matter_Tlv_Writer_T* w=&writer;size_t size=0;uint8_t result=MATTER_IM_FAILURE;
        if(matter_tlv_measure_init(w,4096,3)!=MATTER_TLV_OK||!encode(m,id,q,w)||matter_tlv_writer_finish(w,&size)!=MATTER_TLV_OK)goto done;
        uint8_t* bytes=calloc(1,size);if(!bytes){result=MATTER_IM_RESOURCE_EXHAUSTED;goto done;}
        if(matter_tlv_writer_init(w,bytes,size,3)!=MATTER_TLV_OK||!encode(m,id,q,w)||matter_tlv_writer_finish(w,&size)!=MATTER_TLV_OK){free(bytes);goto done;}
        free(m->encoded);m->encoded=bytes;m->encoded_size=size;out->type=MATTER_TLV_ARRAY;out->data=bytes;out->size=size;result=0;
done:m->busy=false;return result;
    }
    unsigned used=0;for(Light_Group_Multicast* n=m->joined;n;n=n->next)++used;
    out->unsigned_value=id==1?MATTER_LIGHT_GROUP_MEMBERSHIPS:id==2?MATTER_LIGHT_GROUP_MEMBERSHIPS:id==3?used:id==4?m->groupcast->test_fabric:id==0xfffc?5:1;
    return 0;
}
static const Matter_Groupkey_Fabric_T* keys(Matter_Light_Groups_T m,uint8_t fabric) {
    const Matter_Groupkey_View_T* view=m->groupcast->port.keys.view(m->groupcast->port.keys.user);
    if(view)for(unsigned i=0;i<MATTER_GROUPKEY_FABRICS;++i)if(view->fabrics[i].index==fabric)return &view->fabrics[i];
    return NULL;
}
static bool has_key(Matter_Light_Groups_T m,uint8_t fabric,uint16_t id) {
    const Matter_Groupkey_Fabric_T* f=keys(m,fabric);if(!f)return false;
    for(unsigned i=0;i<MATTER_GROUPKEY_SETS;++i)if(f->sets[i].count&&f->sets[i].id==id)return true;
    return false;
}
static uint8_t operational_key(Matter_Light_Groups_T m,const Matter_Cluster_Request_T* q,uint16_t id,const Matter_Tlv_Element_T* key) {
    if(!key)return has_key(m,q->fabric,id)?0:MATTER_GROUPKEY_NOT_FOUND;
    if(has_key(m,q->fabric,id))return 0xd0; /* ALREADY_EXISTS */
    uint8_t input[3][16]={{0}};memcpy(input[0],key->data,16);
    Matter_Groupkey_Set_T set={.times={1,0,0},.id=id,.count=1};
    uint8_t r=m->groupcast->port.keys.store(m->groupcast->port.keys.user,q->fabric,&set,(const uint8_t(*)[16])input);
    m->groupcast->port.crypto.clear((uint8_t*)input,sizeof(input));return r;
}
static uint8_t endpoint_list(Matter_Light_Groups_T m,Matter_Fields* in,unsigned tag,bool required,bool joining,bool* ours) {
    *ours=false;if(!(in->seen&(1u<<tag)))return required?MATTER_IM_INVALID_COMMAND:0;
    uint8_t result=0;Matter_Field_Array* a=matter_field_array(&in->fields[tag],&result);if(!a)return result;
    unsigned count=0;
    while(matter_field_array_next(a)==MATTER_TLV_OK&&a->element.type!=MATTER_TLV_END) {
        if(a->element.type!=MATTER_TLV_UNSIGNED||a->element.unsigned_value>65535){result=MATTER_IM_INVALID_COMMAND;goto done;}
        if(++count>20){result=MATTER_IM_CONSTRAINT_ERROR;goto done;}
        if(a->element.unsigned_value==m->config.endpoint)*ours=true;
        else if(joining){result=MATTER_IM_UNSUPPORTED_ENDPOINT;goto done;}
    }
    if(a->element.type!=MATTER_TLV_END)result=MATTER_IM_INVALID_COMMAND;
    else if(!count)result=MATTER_IM_CONSTRAINT_ERROR;
done:free(a);return result;
}
typedef struct {uint16_t group,set,duration;uint8_t policy,operation;bool aux,has_aux,ours;const Matter_Tlv_Element_T* key;} Args;
static uint8_t schema(Matter_Light_Groups_T m,const Matter_Cluster_Request_T* q,uint32_t command,Matter_Fields* in,Args* args) {
    if(!m->ready||!q->is_case||matter_light_group_fabric(m,q->fabric)<0)return MATTER_IM_UNSUPPORTED_ACCESS;
    uint64_t group=0,set=0,policy=0,operation=0,duration=60;bool replace=false;
    if(command==5) {
        if(!matter_field_u(in,0,255,true,false,&operation)||operation>1||!matter_field_u(in,1,65535,false,false,&duration))return MATTER_IM_CONSTRAINT_ERROR;
        if(operation&&(duration<10||duration>1200))return MATTER_IM_CONSTRAINT_ERROR;
        args->operation=(uint8_t)operation;args->duration=(uint16_t)duration;return 0;
    }
    if(!matter_field_u(in,0,65535,true,false,&group)||(command!=1&&command!=4&&!group))return MATTER_IM_INVALID_COMMAND;
    args->group=(uint16_t)group;
    if(command==0||command==3) {
        unsigned set_tag=command==0?2:1,key_tag=command==0?3:2;
        if(!matter_field_u(in,set_tag,65535,true,false,&set)||!set)return MATTER_IM_CONSTRAINT_ERROR;
        args->set=(uint16_t)set;
        if(in->seen&(1u<<key_tag)) {
            const Matter_Tlv_Element_T* key=&in->fields[key_tag];
            if(key->type!=MATTER_TLV_BYTES||key->size!=16)return MATTER_IM_CONSTRAINT_ERROR;
            args->key=key;
        }
    }
    if(command==0) {
        uint8_t r=endpoint_list(m,in,1,true,true,&args->ours);if(r)return r;
        if(!matter_field_u(in,6,1,false,false,&policy)||!matter_field_b(in,4,false,&args->aux)||!matter_field_b(in,5,false,&replace))return MATTER_IM_INVALID_COMMAND;
        args->policy=(uint8_t)policy;args->has_aux=(in->seen&16)!=0;
    } else if(command==1) {
        uint8_t r=endpoint_list(m,in,1,false,false,&args->ours);if(r)return r;
        if(!(in->seen&2))args->ours=true;
    } else if(command==4) {
        if(!matter_field_b(in,1,true,&args->aux))return MATTER_IM_INVALID_COMMAND;
    }
    if((args->key||args->has_aux)&&!m->groupcast->port.administrator(m->groupcast->port.user,q))return MATTER_IM_UNSUPPORTED_ACCESS;
    return 0;
}
static uint8_t auxiliary(Matter_Light_Groups_T m,uint8_t fabric,uint16_t id,bool enabled) {
    Light_Group* old=matter_light_group_find(m->image,fabric,id);if(!old||!old->member)return MATTER_GROUPKEY_NOT_FOUND;
    if(old->auxiliary==enabled)return 0;
    Light_Group_Image* p=matter_light_group_image_clone(m->image);if(!p)return MATTER_IM_RESOURCE_EXHAUSTED;
    matter_light_group_find(p,fabric,id)->auxiliary=enabled;return matter_light_group_commit(m,p);
}
uint8_t matter_light_group_key_cleanup(Matter_Light_Groups_T m) {
    if(!m->groupcast)return 0;
    for(Light_Group* n=m->image->groups;n;n=n->next)if(n->retiring) {
        bool shared=false;
        for(Light_Group* other=m->image->groups;other;other=other->next)if(other!=n&&!other->retiring&&other->fabric==n->fabric&&other->key==n->key)shared=true;
        if(!shared&&has_key(m,n->fabric,n->key)) {
            uint8_t r=m->groupcast->port.keys.remove(m->groupcast->port.keys.user,n->fabric,n->key);if(r)return r;
        }
        Light_Group_Image* p=matter_light_group_image_clone(m->image);if(!p)return MATTER_IM_RESOURCE_EXHAUSTED;
        Light_Group** at=&p->groups;while(*at){Light_Group* g=*at;if(g->fabric==n->fabric&&g->id==n->id){*at=g->next;free(g);break;}at=&g->next;}
        return matter_light_group_commit(m,p); /* One journal cleanup per tick. */
    }
    return 0;
}
static uint8_t invoke(Matter_Light_Groups_T m,const Matter_Cluster_Request_T* q,uint32_t command,const Args* args,Matter_Tlv_Writer_T* w) {
    Light_Groupcast* g=m->groupcast;
    if(command==5) {g->test_fabric=args->operation?q->fabric:0;g->test_end=g->now+(uint64_t)args->duration*1000;++m->version;return 0;}
    if(command==4)return auxiliary(m,q->fabric,args->group,args->aux);
    Light_Group* old=matter_light_group_find(m->image,q->fabric,args->group);
    if(command==0) {
        if(old&&old->retiring)return 0xcb;
        if(!old&&!matter_light_group_capacity(m->image,q->fabric))return MATTER_IM_RESOURCE_EXHAUSTED;
    } else if(command==3||args->group) {if(!old||!old->member)return MATTER_GROUPKEY_NOT_FOUND;}
    else if(!matter_light_group_count(m->image,q->fabric,true))return MATTER_GROUPKEY_NOT_FOUND;
    if(command==0||command==3) {
        uint8_t r=operational_key(m,q,args->set,args->key);if(r)return r;
        Light_Group_Image* p=matter_light_group_image_clone(m->image);if(!p)return MATTER_IM_RESOURCE_EXHAUSTED;
        Light_Group* n=matter_light_group_find(p,q->fabric,args->group);
        if(!n){n=calloc(1,sizeof(*n));if(!n){matter_light_group_image_free(p);return MATTER_IM_RESOURCE_EXHAUSTED;}*n=(Light_Group){.next=p->groups,.fabric=q->fabric,.id=args->group};p->groups=n;}
        n->key=args->set;
        if(command==0){n->member=true;n->policy=args->policy;}
        r=matter_light_group_commit(m,p);
        if(!r&&command==0&&args->has_aux)(void)auxiliary(m,q->fabric,args->group,args->aux); /* Spec: independent best-effort step. */
        return r;
    }
    /* Leave: durable tombstones prevent a crash/OOM from losing pending key
     * erasure. Membership/aux/scene removal publishes before key cleanup. */
    bool removed=false;
    if(args->ours) {
        Light_Group_Image* p=matter_light_group_image_clone(m->image);if(!p)return MATTER_IM_RESOURCE_EXHAUSTED;
        for(Light_Group* n=p->groups;n;n=n->next)if(n->fabric==q->fabric&&n->member&&(!args->group||n->id==args->group)){n->member=false;n->auxiliary=false;n->retiring=true;removed=true;}
        Light_Scene** scene=&p->scenes;while(*scene){Light_Scene* n=*scene;if(n->fabric==q->fabric&&n->group&&(!args->group||n->group==args->group)){*scene=n->next;free(n);}else scene=&n->next;}
        uint8_t r=matter_light_group_commit(m,p);if(r)return r;
        r=matter_light_group_key_cleanup(m);if(r)return r;
    }
    if(!P(MATTER_TLV_STRUCTURE,-1,0)||!U(0,args->group)||!P(MATTER_TLV_ARRAY,1,0)||(removed&&args->group&&!U(-1,m->config.endpoint))||!END()||!END())return MATTER_IM_FAILURE;
    return 0;
}
static uint8_t run(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* data,size_t size,Matter_Tlv_Writer_T* w,bool execute) {
    Matter_Light_Groups_T m=u;if(m->busy||(m->groupcast&&m->groupcast->processing))return MATTER_IM_FAILURE;uint32_t command=*(const uint32_t*)ref;
    uint8_t r=0;Matter_Fields* in=matter_fields(data,size,3,&r);if(!in)return r;Args args={0};r=schema(m,q,command,in,&args);
    if(!r&&execute) {
        if(command==1&&(!w||w->size||w->capacity<96))r=MATTER_IM_RESOURCE_EXHAUSTED;
        else {m->busy=true;m->groupcast->administrator=q;r=invoke(m,q,command,&args,w);m->groupcast->administrator=NULL;m->busy=false;}
    }
    free(in);return r;
}
static uint8_t validate(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n){return run(u,ref,q,d,n,NULL,false);}
static Matter_Result_T start(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out,uint64_t* token) {
    *token=0;*out=(Matter_Im_Command_Result_T){.status=run(u,ref,q,d,n,w,true)};return MATTER_OK;
}
static Matter_Result_T version(void* u,uint32_t* out){*out=((Matter_Light_Groups_T)u)->version;return MATTER_OK;}
Matter_Result_T matter_light_groupcast_interface(Matter_Light_Groups_T m) {
    Matter_Cluster_Config_T config={.id=0x65,.attributes=10,.commands=5,.events=1,.callbacks={.ctx=m,.version=version}};
    Matter_Cluster_T c=matter_cluster_new(&config);if(!c)return MATTER_LIMIT_REACHED;m->groupcast->cluster=c;
    for(unsigned i=0;i<10;++i) {
        Matter_Attribute_Def_T a={.id=attributes[i],.ref=&attributes[i],.read_access={MATTER_IM_VIEW,i==0},.read=read_attr};
        if(matter_cluster_add_attribute(c,&a)!=MATTER_OK)return MATTER_LIMIT_REACHED;
    }
    for(unsigned i=0;i<5;++i) {
        uint32_t id=commands[i];Matter_Command_Def_T d={.id=id,.ref=&commands[i],.validate=validate,.start=start,
            .access={.privilege=id>=4?MATTER_IM_ADMINISTER:MATTER_IM_MANAGE,.fabric_scoped=true,.response=id==1,.response_command=2,.response_capacity=96}};
        if(matter_cluster_add_command(c,&d)!=MATTER_OK)return MATTER_LIMIT_REACHED;
    }
    Matter_Event_Def_T event={.id=0,.priority=1,.privilege=MATTER_IM_ADMINISTER,.fabric_scoped=true};
    if(matter_cluster_add_event(c,&event)!=MATTER_OK)return MATTER_LIMIT_REACHED;
    return matter_cluster_seal(c);
}
Matter_Result_T matter_light_groups_groupcast(Matter_Light_Groups_T m,const Matter_Light_Groupcast_Port_T* p,Matter_Root_T root) {
    if(!m||!p||!p->keys.view||!p->keys.store||!p->keys.remove||!p->acl.view||!p->crypto.hkdf_sha256||!p->crypto.ccm_decrypt||!p->crypto.clear||!p->crypto.equal||!p->key||!p->privacy||!p->administrator||!m->config.join)return MATTER_INVALID_ARGUMENT;
    if(m->busy||(m->groupcast&&m->groupcast->processing))return MATTER_BUSY;
    if(m->groupcast) {
        if(m->groupcast->bound||matter_cluster_pins(m->groupcast->cluster))return MATTER_INVALID_STATE;
        m->groupcast->port=*p;m->groupcast->root=root;m->groupcast->bound=true;m->groupcast->stopping=false;return MATTER_OK;
    }
    m->groupcast=calloc(1,sizeof(*m->groupcast));if(!m->groupcast)return MATTER_LIMIT_REACHED;
    m->groupcast->port=*p;m->groupcast->root=root;m->groupcast->bound=true;
    Matter_Result_T r=matter_light_groupcast_interface(m);if(r!=MATTER_OK)matter_light_groupcast_free(m);return r;
}
void matter_light_groupcast_pause(Matter_Light_Groups_T m,bool stop) {
    if(!m||!m->groupcast)return;
    Light_Groupcast* g=m->groupcast;m->ready=false;if(stop)g->stopping=true;
    while(g->head){Light_Group_Rx* n=g->head;g->head=n->next;g->port.crypto.clear(n->data,n->size);free(n);}
    g->tail=NULL;g->queued=0;
}
void matter_light_groupcast_unbind(Matter_Light_Groups_T m) {
    if(!m||!m->groupcast)return;
    matter_light_groupcast_pause(m,true);Light_Groupcast* g=m->groupcast;
    Matter_Crypto_Port_T crypto=g->port.crypto;
    g->port=(Matter_Light_Groupcast_Port_T){.crypto=crypto};g->root=NULL;g->events=NULL;g->bound=false;g->test_fabric=0;
}
void matter_light_groupcast_free(Matter_Light_Groups_T m) {
    Light_Groupcast* g=m->groupcast;if(!g)return;
    if(g->cluster)(void)matter_cluster_delete(g->cluster);
    while(g->head){Light_Group_Rx* n=g->head;g->head=n->next;g->port.crypto.clear(n->data,n->size);free(n);}
    while(g->peers){Light_Group_Peer* n=g->peers;g->peers=n->next;g->port.crypto.clear((uint8_t*)n,sizeof(*n));free(n);}
    g->port.crypto.clear((uint8_t*)g,sizeof(*g));free(g);m->groupcast=NULL;
}
