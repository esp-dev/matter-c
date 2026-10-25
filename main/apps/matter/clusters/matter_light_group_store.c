#include "matter_light_groups_internal.h"

typedef struct { uint8_t* data; size_t size,offset; bool ok; } Bytes;
static void write_u(Bytes* b,uint64_t v,unsigned n) {
    if(n>b->size-b->offset) { b->ok=false; return; }
    for(unsigned i=0;i<n;++i) { if(b->data)b->data[b->offset]=(uint8_t)v; ++b->offset; v>>=8; }
}
static uint64_t read_u(Bytes* b,unsigned n) {
    if(n>b->size-b->offset) { b->ok=false; return 0; }
    uint64_t v=0; for(unsigned i=0;i<n;++i)v|=(uint64_t)b->data[b->offset++]<<(8*i); return v;
}
static uint32_t crc(const uint8_t* data,size_t size) {
    uint32_t v=UINT32_MAX;
    for(size_t i=0;i<size;++i) { v^=data[i]; for(unsigned j=0;j<8;++j)v=(v>>1)^(UINT32_C(0xedb88320)&(0u-(v&1))); }
    return ~v;
}
void matter_light_group_image_free(Light_Group_Image* p) {
    if(!p)return;
    while(p->groups) { Light_Group* n=p->groups; p->groups=n->next; free(n); }
    while(p->scenes) { Light_Scene* n=p->scenes; p->scenes=n->next; free(n); }
    free(p);
}
Light_Group_Image* matter_light_group_image_clone(const Light_Group_Image* p) {
    Light_Group_Image* out=calloc(1,sizeof(*out)); if(!out)return NULL;
    out->fabric_count=p->fabric_count; memcpy(out->fabrics,p->fabrics,sizeof(out->fabrics));
    Light_Group** g=&out->groups; Light_Scene** s=&out->scenes;
    for(const Light_Group* n=p->groups;n;n=n->next) { *g=calloc(1,sizeof(**g)); if(!*g)goto bad; **g=*n;(*g)->next=NULL;g=&(*g)->next; }
    for(const Light_Scene* n=p->scenes;n;n=n->next) { *s=calloc(1,sizeof(**s)); if(!*s)goto bad; **s=*n;(*s)->next=NULL;s=&(*s)->next; }
    return out;
bad: matter_light_group_image_free(out);return NULL;
}
unsigned matter_light_group_count(const Light_Group_Image* p,uint8_t fabric,bool members) {
    unsigned count=0;for(const Light_Group* n=p->groups;n;n=n->next)if((!fabric||n->fabric==fabric)&&(!members||n->member))++count;return count;
}
unsigned matter_light_group_capacity(const Light_Group_Image* p,uint8_t fabric) {
    unsigned own=matter_light_group_count(p,fabric,false),used=matter_light_group_count(p,0,false);
    unsigned reserve=(unsigned)(5-p->fabric_count)*4;
    for(size_t i=0;i<p->fabric_count;++i)if(p->fabrics[i].index!=fabric){unsigned n=matter_light_group_count(p,p->fabrics[i].index,false);if(n<4)reserve+=4-n;}
    unsigned global=used+reserve>=MATTER_LIGHT_GROUP_MEMBERSHIPS?0:MATTER_LIGHT_GROUP_MEMBERSHIPS-used-reserve;
    unsigned local=own>=MATTER_LIGHT_GROUPS_PER_FABRIC?0:MATTER_LIGHT_GROUPS_PER_FABRIC-own;
    return global<local?global:local;
}
unsigned matter_light_scene_count(const Light_Group_Image* p,uint8_t fabric) {
    unsigned count=0;for(const Light_Scene* n=p->scenes;n;n=n->next)if(!fabric||n->fabric==fabric)++count;return count;
}
unsigned matter_light_scene_capacity(const Light_Group_Image* p,uint8_t fabric) {
    unsigned a=MATTER_LIGHT_SCENES-matter_light_scene_count(p,0),b=MATTER_LIGHT_SCENES_PER_FABRIC-matter_light_scene_count(p,fabric);return a<b?a:b;
}
Light_Group* matter_light_group_find(Light_Group_Image* p,uint8_t fabric,uint16_t id) {
    for(Light_Group* n=p->groups;n;n=n->next)if(n->fabric==fabric&&n->id==id)return n;
    return NULL;
}
Light_Scene* matter_light_scene_find(Light_Group_Image* p,uint8_t fabric,uint16_t group,uint8_t id) {
    for(Light_Scene* n=p->scenes;n;n=n->next)if(n->fabric==fabric&&n->group==group&&n->id==id)return n;
    return NULL;
}
int matter_light_group_fabric(Matter_Light_Groups_T m,uint8_t fabric) {
    for(size_t i=0;i<m->image->fabric_count;++i)if(m->image->fabrics[i].index==fabric)return (int)i;
    return -1;
}
void matter_light_group_remove(Light_Group_Image* p,uint8_t fabric,uint16_t group,bool all,bool purge_fabric) {
    Light_Group** g=&p->groups;
    while(*g) {
        Light_Group* n=*g;
        if(n->fabric==fabric&&(all||n->id==group)) {
            /* Legacy Groups removes endpoint membership, not GroupKeyMap or
             * the crash-recovery journal of an earlier Groupcast Leave. */
            if(!purge_fabric&&(n->retiring||n->key!=UINT16_MAX)) {n->member=false;n->auxiliary=false;g=&n->next;}
            else {*g=n->next;free(n);}
        } else g=&n->next;
    }
    Light_Scene** s=&p->scenes;
    while(*s) { Light_Scene* n=*s;if(n->fabric==fabric&&(all?n->group!=0:n->group==group)){*s=n->next;free(n);}else s=&n->next; }
}
static bool encode(const Light_Group_Image* p,Bytes* b) {
    static const uint8_t magic[8]={'M','L','G','R','O','U','P',1};
    for(unsigned i=0;i<8;++i)write_u(b,magic[i],1);
    write_u(b,p->fabric_count,1);write_u(b,matter_light_group_count(p,0,false),1);write_u(b,matter_light_scene_count(p,0),1);
    for(size_t i=0;i<p->fabric_count;++i) {
        const Matter_Light_Groups_Fabric_T* f=&p->fabrics[i];write_u(b,f->index,1);write_u(b,f->id,8);
        for(unsigned j=0;j<64;++j)write_u(b,f->root_public[j],1);
    }
    for(const Light_Group* n=p->groups;n;n=n->next) {
        write_u(b,n->fabric,1);write_u(b,n->id,2);write_u(b,n->key,2);write_u(b,n->policy,1);write_u(b,n->member|(n->auxiliary<<1)|(n->retiring<<2),1);
    }
    for(const Light_Scene* n=p->scenes;n;n=n->next) {
        write_u(b,n->fabric,1);write_u(b,n->group,2);write_u(b,n->id,1);write_u(b,n->ms,4);write_u(b,n->mask,2);
        for(unsigned i=0;i<11;++i)write_u(b,n->values[i],2);
    }
    return b->ok;
}
static uint8_t commit(Matter_Light_Groups_T m,Light_Group_Image* p,const Matter_Light_State_T* light) {
    Bytes measure={NULL,MATTER_LIGHT_GROUP_IMAGE_MAX-4,0,true}; uint8_t result=MATTER_IM_FAILURE;
    if(!encode(p,&measure))goto done;
    size_t size=measure.offset+4;uint8_t* bytes=calloc(1,size);if(!bytes){result=MATTER_IM_RESOURCE_EXHAUSTED;goto done;}
    Bytes b={bytes,size,0,true};encode(p,&b);write_u(&b,crc(bytes,b.offset),4);
    result=b.ok?matter_light_group_network_prepare(m,p):MATTER_IM_FAILURE;
    bool prepared=false;
    if(!result)result=matter_light_group_aux_prepare(m,p,&prepared);
    Matter_Result_T stored=MATTER_PORT_ERROR;
    if(!result)stored=light?(m->config.store_light?m->config.store_light(m->config.storage.user,bytes,size,light):MATTER_PORT_ERROR):m->config.storage.store(m->config.storage.user,bytes,size);
    if(!result&&stored==MATTER_OK) {
        Light_Scene_Info info[5];for(unsigned i=0;i<5;++i)info[i]=(Light_Scene_Info){.id=255};
        for(size_t i=0;i<p->fabric_count;++i)for(size_t j=0;j<m->image->fabric_count;++j)
            if(p->fabrics[i].index==m->image->fabrics[j].index&&p->fabrics[i].id==m->image->fabrics[j].id&&!memcmp(p->fabrics[i].root_public,m->image->fabrics[j].root_public,64)) {
                info[i]=m->info[j];Light_Scene* old=matter_light_scene_find(m->image,p->fabrics[i].index,info[i].group,info[i].id);
                Light_Scene* next=matter_light_scene_find(p,p->fabrics[i].index,info[i].group,info[i].id);
                if(!old||!next||old->mask!=next->mask||memcmp(old->values,next->values,sizeof(old->values))){info[i].valid=false;info[i].pending=false;}
            }
        matter_light_group_image_free(m->image);m->image=p;p=NULL;++m->version;result=0;
        memcpy(m->info,info,sizeof(info));
    } else if(!result)result=stored==MATTER_LIMIT_REACHED?MATTER_IM_RESOURCE_EXHAUSTED:MATTER_IM_FAILURE;
    if(prepared)matter_events_finish(m->groupcast->events,!result);
    free(bytes);
done: matter_light_group_image_free(p);(void)matter_light_group_network_cleanup(m,false);return result;
}
uint8_t matter_light_group_commit(Matter_Light_Groups_T m,Light_Group_Image* p){return commit(m,p,NULL);}
uint8_t matter_light_group_commit_light(Matter_Light_Groups_T m,Light_Group_Image* p,const Matter_Light_State_T* light){return commit(m,p,light);}
static bool has_fabric(const Light_Group_Image* p,uint8_t index) {
    for(size_t i=0;i<p->fabric_count;++i)if(p->fabrics[i].index==index)return true;
    return false;
}
static Light_Group_Image* decode(uint8_t* data,size_t size) {
    if(size<15||size>MATTER_LIGHT_GROUP_IMAGE_MAX)return NULL;
    Bytes checksum={data,size,size-4,true};if(read_u(&checksum,4)!=crc(data,size-4))return NULL;
    Bytes b={data,size-4,0,true};static const uint8_t magic[8]={'M','L','G','R','O','U','P',1};
    for(unsigned i=0;i<8;++i)if(read_u(&b,1)!=magic[i])return NULL;
    Light_Group_Image* p=calloc(1,sizeof(*p));if(!p)return NULL;
    p->fabric_count=(size_t)read_u(&b,1);unsigned groups=(unsigned)read_u(&b,1),scenes=(unsigned)read_u(&b,1);
    if(p->fabric_count>5||groups>MATTER_LIGHT_GROUP_MEMBERSHIPS||scenes>MATTER_LIGHT_SCENES)goto bad;
    for(size_t i=0;i<p->fabric_count;++i) {
        Matter_Light_Groups_Fabric_T* f=&p->fabrics[i];f->index=(uint8_t)read_u(&b,1);f->id=read_u(&b,8);
        for(unsigned j=0;j<64;++j)f->root_public[j]=(uint8_t)read_u(&b,1);
        if(!f->index||f->index==255||!f->id)goto bad;
        for(size_t j=0;j<i;++j)if(p->fabrics[j].index==f->index)goto bad;
    }
    Light_Group** g=&p->groups;
    for(unsigned i=0;i<groups;++i) {
        Light_Group* n=calloc(1,sizeof(*n));if(!n)goto bad;
        n->fabric=(uint8_t)read_u(&b,1);n->id=(uint16_t)read_u(&b,2);n->key=(uint16_t)read_u(&b,2);n->policy=(uint8_t)read_u(&b,1);
        unsigned flags=(unsigned)read_u(&b,1);n->member=(flags&1)!=0;n->auxiliary=(flags&2)!=0;n->retiring=(flags&4)!=0;
        bool valid=has_fabric(p,n->fabric)&&n->id&&n->key&&n->policy<=1&&flags<=7&&(!n->auxiliary||n->member)&&(!n->retiring||!n->member)&&
            !matter_light_group_find(p,n->fabric,n->id)&&matter_light_group_count(p,n->fabric,false)<MATTER_LIGHT_GROUPS_PER_FABRIC;
        if(!valid){free(n);goto bad;}*g=n;g=&n->next;
    }
    Light_Scene** s=&p->scenes;
    for(unsigned i=0;i<scenes;++i) {
        Light_Scene* n=calloc(1,sizeof(*n));if(!n)goto bad;
        n->fabric=(uint8_t)read_u(&b,1);n->group=(uint16_t)read_u(&b,2);n->id=(uint8_t)read_u(&b,1);n->ms=(uint32_t)read_u(&b,4);n->mask=(uint16_t)read_u(&b,2);
        for(unsigned j=0;j<11;++j)n->values[j]=(uint16_t)read_u(&b,2);
        Light_Group* group=matter_light_group_find(p,n->fabric,n->group);
        bool valid=has_fabric(p,n->fabric)&&n->id<255&&n->ms<=60000000&&n->mask<=2047&&(!n->group||(group&&group->member))&&
            !matter_light_scene_find(p,n->fabric,n->group,n->id)&&matter_light_scene_count(p,n->fabric)<MATTER_LIGHT_SCENES_PER_FABRIC&&matter_light_scene_values_valid(n);
        if(!valid){free(n);goto bad;}*s=n;s=&n->next;
    }
    if(b.ok&&b.offset==b.size)return p;
bad: matter_light_group_image_free(p);return NULL;
}
Matter_Light_Groups_T matter_light_groups_new(const Matter_Light_Groups_Config_T* c) {
    if(!c||!c->light||!c->endpoint||c->endpoint==65535||!c->storage.load||!c->storage.store||!!c->join!=!!c->leave)return NULL;
    Matter_Light_Groups_T m=calloc(1,sizeof(*m));if(!m)return NULL;m->config=*c;m->version=c->version;
    if(matter_light_pin(c->light)!=MATTER_OK){free(m);return NULL;}m->light_pinned=true;
    size_t size=0;if(c->storage.load(c->storage.user,NULL,0,&size)!=MATTER_OK||size>MATTER_LIGHT_GROUP_IMAGE_MAX)goto bad;
    if(size) {
        uint8_t* data=calloc(1,size);if(!data)goto bad;size_t actual=size;
        if(c->storage.load(c->storage.user,data,size,&actual)==MATTER_OK&&actual==size)m->image=decode(data,size);
        free(data);
    } else m->image=calloc(1,sizeof(*m->image));
    if(!m->image||matter_light_group_interfaces(m)!=MATTER_OK)goto bad;
    if(c->store_light&&matter_light_group_global_bind(m)!=MATTER_OK)goto bad;
    for(unsigned i=0;i<5;++i)m->info[i].id=255;
    return m;
bad: (void)matter_light_groups_delete(m);return NULL;
}
Matter_Result_T matter_light_groups_bind(Matter_Light_Groups_T m,const Matter_Light_Groups_Fabric_T* fabrics,size_t count) {
    if(!m||count>5||(count&&!fabrics))return MATTER_INVALID_ARGUMENT;
    if(m->busy||(m->groupcast&&m->groupcast->processing))return MATTER_BUSY;
    for(size_t i=0;i<count;++i) {
        if(!fabrics[i].index||fabrics[i].index==255||!fabrics[i].id)return MATTER_INVALID_ARGUMENT;
        for(size_t j=0;j<i;++j)if(fabrics[i].index==fabrics[j].index)return MATTER_INVALID_ARGUMENT;
    }
    bool same=m->image->fabric_count==count;
    for(size_t i=0;same&&i<count;++i)same=m->image->fabrics[i].index==fabrics[i].index&&m->image->fabrics[i].id==fabrics[i].id&&!memcmp(m->image->fabrics[i].root_public,fabrics[i].root_public,64);
    if(same) {
        if(m->ready)return MATTER_OK;
        m->busy=true;uint8_t result=matter_light_group_network_prepare(m,m->image);(void)matter_light_group_network_cleanup(m,false);
        m->ready=!result;m->busy=false;return !result?MATTER_OK:result==MATTER_IM_RESOURCE_EXHAUSTED?MATTER_LIMIT_REACHED:MATTER_PORT_ERROR;
    }
    m->ready=false;m->busy=true;Light_Group_Image* p=matter_light_group_image_clone(m->image);uint8_t r=MATTER_IM_RESOURCE_EXHAUSTED;
    if(p) {
        for(size_t i=0;i<p->fabric_count;++i) {
            const Matter_Light_Groups_Fabric_T* old=&p->fabrics[i];bool same=false;
            for(size_t j=0;j<count;++j)if(old->index==fabrics[j].index&&old->id==fabrics[j].id&&!memcmp(old->root_public,fabrics[j].root_public,64))same=true;
            if(!same) {
                matter_light_group_remove(p,old->index,0,true,true);
                Light_Scene** s=&p->scenes;while(*s){Light_Scene* n=*s;if(n->fabric==old->index){*s=n->next;free(n);}else s=&n->next;}
            }
        }
        bool unchanged=p->fabric_count==count;
        for(size_t i=0;unchanged&&i<count;++i)unchanged=p->fabrics[i].index==fabrics[i].index&&p->fabrics[i].id==fabrics[i].id&&!memcmp(p->fabrics[i].root_public,fabrics[i].root_public,64);
        if(unchanged){r=matter_light_group_network_prepare(m,p);matter_light_group_image_free(p);}
        else {p->fabric_count=count;memset(p->fabrics,0,sizeof(p->fabrics));if(count)memcpy(p->fabrics,fabrics,count*sizeof(*fabrics));if(m->groupcast)m->groupcast->binding=true;r=matter_light_group_commit(m,p);if(m->groupcast)m->groupcast->binding=false;}
    }
    (void)matter_light_group_network_cleanup(m,false);
    m->ready=!r;m->busy=false;return !r?MATTER_OK:r==MATTER_IM_RESOURCE_EXHAUSTED?MATTER_LIMIT_REACHED:MATTER_PORT_ERROR;
}
bool matter_light_groups_member(Matter_Light_Groups_T m,uint8_t fabric,uint16_t group) {
    if(!m||!m->ready||m->busy)return false;
    Light_Group* n=matter_light_group_find(m->image,fabric,group);return n&&n->member;
}
Matter_Cluster_T matter_light_groups_cluster(Matter_Light_Groups_T m,uint32_t id) {return !m?NULL:id==4?m->clusters[0]:id==0x62?m->clusters[1]:id==0x65&&m->groupcast?m->groupcast->cluster:NULL;}
Matter_Result_T matter_light_groups_attach(Matter_Light_Groups_T m,Matter_Root_T root) {
    if(!m||!root)return MATTER_INVALID_ARGUMENT;
    if(m->groupcast){Matter_Result_T r=matter_root_attach_cluster_at(root,0,m->groupcast->cluster);if(r!=MATTER_OK)return r;m->groupcast->root=root;}
    for(unsigned i=0;i<2;++i){Matter_Result_T r=matter_root_attach_cluster_at(root,m->config.endpoint,m->clusters[i]);if(r!=MATTER_OK)return r;}return MATTER_OK;
}
Matter_Result_T matter_light_groups_delete(Matter_Light_Groups_T m) {
    if(!m)return MATTER_INVALID_ARGUMENT;
    if(m->busy||(m->groupcast&&m->groupcast->processing))return MATTER_BUSY;
    for(unsigned i=0;i<2;++i)if(m->clusters[i]&&(matter_cluster_pins(m->clusters[i])||matter_cluster_in_use(m->clusters[i])))return MATTER_BUSY;
    if(m->groupcast&&m->groupcast->cluster&&(matter_cluster_pins(m->groupcast->cluster)||matter_cluster_in_use(m->groupcast->cluster)))return MATTER_BUSY;
    if(m->global_bound) {
        static const uint32_t ids[]={3,6,8,0x300};Matter_Light_State_T snapshot;
        if(matter_light_state(m->config.light,&snapshot)!=MATTER_OK)return MATTER_BUSY;
        for(unsigned i=0;i<4;++i)if(matter_cluster_pins(matter_light_cluster(m->config.light,ids[i])))return MATTER_BUSY;
    }
    m->ready=false;m->busy=true;Matter_Result_T drained=matter_light_group_network_cleanup(m,true);m->busy=false;
    if(drained!=MATTER_OK)return MATTER_PORT_ERROR;
    if(m->global_bound&&matter_light_bind_scenes(m->config.light,NULL)!=MATTER_OK)return MATTER_BUSY;
    m->global_bound=false;
    for(unsigned i=0;i<2;++i)if(m->clusters[i])(void)matter_cluster_delete(m->clusters[i]);
    matter_light_groupcast_free(m);matter_light_group_image_free(m->image);free(m->encoded);if(m->light_pinned)(void)matter_light_unpin(m->config.light);free(m);return MATTER_OK;
}
