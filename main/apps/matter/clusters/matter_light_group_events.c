#include "matter_light_groups_internal.h"

static bool changed(const Light_Group_Image* old,const Light_Group_Image* next,uint8_t fabric) {
    for(const Light_Group* n=old->groups;n;n=n->next)if(n->fabric==fabric&&n->member&&n->auxiliary) {
        Light_Group* other=matter_light_group_find((Light_Group_Image*)next,fabric,n->id);
        if(!other||!other->member||!other->auxiliary)return true;
    }
    for(const Light_Group* n=next->groups;n;n=n->next)if(n->fabric==fabric&&n->member&&n->auxiliary) {
        Light_Group* other=matter_light_group_find((Light_Group_Image*)old,fabric,n->id);
        if(!other||!other->member||!other->auxiliary)return true;
    }
    return false;
}
uint8_t matter_light_group_aux_prepare(Matter_Light_Groups_T m,const Light_Group_Image* next,bool* prepared) {
    *prepared=false;Light_Groupcast* g=m->groupcast;
    if(!g||g->binding)return 0;
    size_t count=0;
    for(size_t i=0;i<m->image->fabric_count;++i)if(changed(m->image,next,m->image->fabrics[i].index))++count;
    if(!count)return 0;
    if(!g->events)return MATTER_IM_FAILURE;
    Matter_Event_Record_T* records=calloc(count,sizeof(*records));if(!records)return MATTER_IM_RESOURCE_EXHAUSTED;
    size_t at=0;bool valid=true;
    for(size_t i=0;i<m->image->fabric_count&&valid;++i) {
        uint8_t fabric=m->image->fabrics[i].index;if(!changed(m->image,next,fabric))continue;
        Matter_Event_Record_T* record=&records[at++];
        *record=(Matter_Event_Record_T){.path={0,MATTER_ACL_CLUSTER,3},.priority=1,.fabric=fabric,.timestamp_ms=g->now};
        Matter_Tlv_Writer_T writer;Matter_Tlv_Writer_T* w=&writer;
        const Matter_Cluster_Request_T* q=g->administrator;
        valid=matter_tlv_writer_init(w,record->data,sizeof(record->data),1)==MATTER_TLV_OK&&
            matter_light_group_put(w,MATTER_TLV_STRUCTURE,-1,0)&&
            matter_light_group_put(w,q&&q->is_case?MATTER_TLV_UNSIGNED:MATTER_TLV_NULL,0,q?q->peer_node:0)&&
            matter_light_group_put(w,MATTER_TLV_UNSIGNED,254,fabric)&&matter_light_group_put(w,MATTER_TLV_END,-1,0)&&
            matter_tlv_writer_finish(w,&record->size)==MATTER_TLV_OK;
    }
    Matter_Result_T r=valid?matter_events_prepare(g->events,records,count):MATTER_PORT_ERROR;
    free(records);if(r==MATTER_OK){*prepared=true;return 0;}
    return r==MATTER_LIMIT_REACHED?MATTER_IM_RESOURCE_EXHAUSTED:MATTER_IM_FAILURE;
}
Matter_Result_T matter_light_groups_events(Matter_Light_Groups_T m,Matter_Events_T events) {
    if(!m||!m->groupcast||!events)return MATTER_INVALID_ARGUMENT;
    if(m->busy||(m->groupcast&&m->groupcast->processing))return MATTER_BUSY;
    if(m->groupcast->events)return MATTER_INVALID_STATE;
    m->groupcast->events=events;return MATTER_OK;
}
