#include "matter_light_groups_internal.h"
#include "../codec/matter_message_header.h"
#include "../codec/matter_protocol_header.h"

typedef struct {
    Matter_Light_Groups_T owner;const Light_Group_Rx* received;
    Matter_Message_Header_T message;Matter_Protocol_Header_T protocol;
    Matter_Im_Command_Path_T path;Matter_Cluster_Request_T request;
    uint8_t key[16],privacy[16],nonce[13],hash[2],header[18];
    bool described,allowed;uint8_t plain[];
} Received;
static void test_event(Matter_Light_Groups_T m,const Light_Group_Rx* rx,const Received* context,uint8_t result) {
    Light_Groupcast* g=m->groupcast;if(!g->events||!g->test_fabric||g->now>=g->test_end)return;
    if(context&&context->request.fabric!=g->test_fabric)return;
    Matter_Event_Record_T* record=calloc(1,sizeof(*record));if(!record)return;
    *record=(Matter_Event_Record_T){.path={0,0x65,0},.priority=1,.fabric=g->test_fabric,.timestamp_ms=g->now};
    Matter_Tlv_Writer_T writer;Matter_Tlv_Writer_T* w=&writer;
    bool ok=matter_tlv_writer_init(w,record->data,sizeof(record->data),1)==MATTER_TLV_OK&&matter_light_group_put(w,MATTER_TLV_STRUCTURE,-1,0);
    for(unsigned i=0;i<2&&ok;++i) {
        Matter_Tlv_Element_T bytes={.type=MATTER_TLV_BYTES,.tag={.control=1,.number=i},.data=i?rx->path.local.address:rx->path.peer.address,.size=16};
        ok=matter_tlv_write(w,&bytes,0)==MATTER_TLV_OK;
    }
    if(context&&ok)ok=matter_light_group_put(w,MATTER_TLV_UNSIGNED,2,context->message.destination_id);
    if(context&&context->described&&ok)ok=matter_light_group_put(w,MATTER_TLV_UNSIGNED,3,context->path.endpoint)&&
        matter_light_group_put(w,MATTER_TLV_UNSIGNED,4,context->path.cluster)&&matter_light_group_put(w,MATTER_TLV_UNSIGNED,5,context->path.command)&&
        matter_light_group_put(w,MATTER_TLV_BOOL,6,context->allowed);
    ok=ok&&matter_light_group_put(w,MATTER_TLV_UNSIGNED,7,result)&&matter_light_group_put(w,MATTER_TLV_UNSIGNED,254,g->test_fabric)&&
        matter_light_group_put(w,MATTER_TLV_END,-1,0)&&matter_tlv_writer_finish(w,&record->size)==MATTER_TLV_OK;
    if(ok&&matter_events_prepare(g->events,record,1)==MATTER_OK)matter_events_finish(g->events,true);
    free(record);
}
Matter_Result_T matter_light_groups_received(Matter_Light_Groups_T m,const Matter_Udp_Datagram_T* d) {
    if(!m||!m->groupcast||!d||!d->data||d->size<34||d->size>MATTER_UDP_MAX_PAYLOAD)return MATTER_INVALID_ARGUMENT;
    if(m->busy||m->groupcast->processing)return MATTER_BUSY;
    if(!m->ready||!m->groupcast->bound||m->groupcast->stopping)return MATTER_INVALID_STATE;
    if(m->groupcast->queued>=8)return MATTER_LIMIT_REACHED;
    if(d->path.local.port!=5540||d->path.local.address[0]!=0xff||!d->path.interface_id||!d->path.peer.port||d->path.peer.address[0]==0xff)return MATTER_INVALID_ARGUMENT;
    Light_Group_Rx* n=calloc(1,sizeof(*n)+d->size);if(!n)return MATTER_LIMIT_REACHED;
    n->path=d->path;n->size=d->size;memcpy(n->data,d->data,d->size);
    Light_Groupcast* g=m->groupcast;if(g->tail)g->tail->next=n;else g->head=n;g->tail=n;++g->queued;return MATTER_OK;
}
static bool used_key(Matter_Light_Groups_T m,uint8_t fabric,uint16_t set) {
    for(Light_Group* n=m->image->groups;n;n=n->next)if(n->member&&n->fabric==fabric&&n->key==set)return true;
    return false;
}
static bool authenticate(Matter_Light_Groups_T m,const Light_Group_Rx* rx,Received* w,bool* candidate) {
    const uint8_t* data=rx->data;Light_Groupcast* g=m->groupcast;
    if((data[0]&0xf7)!=6||(data[3]&(MATTER_MESSAGE_SESSION_MASK|MATTER_MESSAGE_CONTROL|MATTER_MESSAGE_EXTENSIONS))!=MATTER_MESSAGE_SESSION_GROUP)return false;
    uint16_t session=(uint16_t)(data[1]|((uint16_t)data[2]<<8));
    const Matter_Groupkey_View_T* view=g->port.keys.view(g->port.keys.user);if(!view)return false;
    for(unsigned f=0;f<MATTER_GROUPKEY_FABRICS;++f) {
        const Matter_Groupkey_Fabric_T* fabric=&view->fabrics[f];if(!fabric->index||matter_light_group_fabric(m,fabric->index)<0)continue;
        for(unsigned set=0;set<MATTER_GROUPKEY_SETS;++set) {
            const Matter_Groupkey_Set_T* k=&fabric->sets[set];if(!k->id||!k->count||!used_key(m,fabric->index,k->id))continue;
            for(unsigned epoch=0;epoch<k->count;++epoch) {
                if(g->port.key(g->port.user,fabric->index,k->id,epoch,w->key)!=MATTER_OK)continue;
                if(g->port.crypto.hkdf_sha256(g->port.crypto.user,w->key,16,NULL,0,(const uint8_t*)"GroupKeyHash",12,w->hash,2)!=MATTER_OK)continue;
                if((((uint16_t)w->hash[0]<<8)|w->hash[1])!=session)continue;
                *candidate=true;memcpy(w->header,data,18);
                if(data[3]&MATTER_MESSAGE_PRIVACY) {
                    if(g->port.crypto.hkdf_sha256(g->port.crypto.user,w->key,16,NULL,0,(const uint8_t*)"PrivacyKey",10,w->privacy,16)!=MATTER_OK)continue;
                    w->nonce[0]=(uint8_t)(session>>8);w->nonce[1]=(uint8_t)session;memcpy(w->nonce+2,data+rx->size-11,11);
                    if(g->port.privacy(g->port.crypto.user,w->privacy,w->nonce,data+4,14,w->header+4)!=MATTER_OK)continue;
                }
                /* The syntax codec deliberately does not process privacy. Its
                 * temporary P mask never alters authenticated AAD or nonce. */
                w->header[3]&=(uint8_t)~MATTER_MESSAGE_PRIVACY;size_t offset=0;
                bool parsed=matter_message_header_read(w->header,18,&w->message,&offset)==MATTER_MESSAGE_OK&&offset==18;
                w->header[3]=data[3];w->message.security_flags=data[3];if(!parsed)continue;
                if(!w->message.source_node_id||w->message.source_node_id>UINT64_C(0xffffffefffffffff))continue;
                w->nonce[0]=data[3];memcpy(w->nonce+1,w->header+4,12);
                if(g->port.crypto.ccm_decrypt(g->port.crypto.user,w->key,w->nonce,w->header,18,data+18,rx->size-34,w->plain)!=MATTER_OK)continue;
                w->request=(Matter_Cluster_Request_T){.fabric=fabric->index,.filtered=true,.is_group=true,.group=(uint16_t)w->message.destination_id,.peer_node=w->message.source_node_id};
                Light_Group* member=matter_light_group_find(m->image,fabric->index,w->request.group);uint8_t address[16];
                if(!member||!member->member||member->key!=k->id||!matter_light_group_address(m->image,member,address)||memcmp(address,rx->path.local.address,16))return false;
                return true;
            }
        }
    }
    return false;
}
static uint8_t authorize(void* u,Matter_Exchange_Session_T session,const Matter_Im_Command_Path_T* path,Matter_Im_Privilege_T privilege) {
    (void)session;Received* w=u;Matter_Light_Groups_T m=w->owner;
    Matter_Im_Path_T attribute={path->endpoint,path->cluster,path->command};Light_Groupcast* g=m->groupcast;
    Light_Group* group=matter_light_group_find(m->image,w->request.fabric,w->request.group);
    bool allowed=path->endpoint==m->config.endpoint&&group&&group->member&&
        ((group->auxiliary&&privilege<=MATTER_IM_OPERATE)||matter_acl_group_grants(g->port.acl.view(g->port.acl.user),w->request.fabric,w->request.group,&attribute,privilege,&g->port.devices));
    w->allowed=allowed;w->path=*path;
    /* The path still exists when Operate was denied before describe. */
    Matter_Cluster_T cluster=matter_root_cluster_at(g->root,path->endpoint,path->cluster);Matter_Im_Command_T command;
    w->described=cluster&&matter_cluster_command(cluster,path->command,&command)==0;
    return allowed?0:MATTER_IM_UNSUPPORTED_ACCESS;
}
static uint8_t describe(void* u,const Matter_Im_Command_Path_T* path,Matter_Im_Command_T* out) {
    Received* w=u;Matter_Cluster_T c=matter_root_cluster_at(w->owner->groupcast->root,path->endpoint,path->cluster);
    if(!c)return MATTER_IM_UNSUPPORTED_CLUSTER;
    if(matter_cluster_command_async(c,path->command))return MATTER_IM_UNSUPPORTED_COMMAND;
    return matter_cluster_command(c,path->command,out);
}
static uint8_t validate(void* u,const Matter_Im_Command_Path_T* path,const uint8_t* data,size_t size) {
    Received* w=u;Matter_Cluster_T c=matter_root_cluster_at(w->owner->groupcast->root,path->endpoint,path->cluster);
    return matter_cluster_validate_command(c,path->command,&w->request,data,size);
}
static Matter_Im_Command_Result_T invoke(void* u,const Matter_Im_Command_Path_T* path,const uint8_t* data,size_t size,Matter_Tlv_Writer_T* output) {
    Received* w=u;Matter_Cluster_T c=matter_root_cluster_at(w->owner->groupcast->root,path->endpoint,path->cluster);
    Matter_Im_Command_Result_T result={.status=MATTER_IM_FAILURE};uint64_t token=0;
    if(matter_cluster_start(c,path->command,&w->request,data,size,output,&result,&token)!=MATTER_OK||token)result.status=MATTER_IM_FAILURE;
    return result;
}
static Light_Group_Peer* peer(Matter_Light_Groups_T m,const Received* w) {
    Light_Groupcast* g=m->groupcast;
    for(Light_Group_Peer* n=g->peers;n;n=n->next)if(n->node==w->message.source_node_id&&g->port.crypto.equal(n->key,w->key,16))return n;
    if(g->peer_count>=128)return NULL;
    Light_Group_Peer* n=calloc(1,sizeof(*n));if(!n)return NULL;n->node=w->message.source_node_id;memcpy(n->key,w->key,16);
    if(matter_reception_reset(&n->reception,MATTER_RECEPTION_SECURE_GROUP)!=MATTER_OK){g->port.crypto.clear((uint8_t*)n,sizeof(*n));free(n);return NULL;}
    n->next=g->peers;g->peers=n;++g->peer_count;return n;
}
Matter_Result_T matter_light_groupcast_process(Matter_Light_Groups_T m,uint64_t now) {
    Light_Groupcast* g=m->groupcast;if(!g||!g->bound||g->stopping)return MATTER_OK;
    if(g->processing||m->busy)return MATTER_BUSY;
    if(now<g->now)return MATTER_INVALID_ARGUMENT;
    g->processing=true;g->now=now;
    if(g->test_fabric&&now>=g->test_end){g->test_fabric=0;++m->version;}
    m->busy=true;if(m->ready)(void)matter_light_group_key_cleanup(m);
    Light_Group_Rx* rx=g->head;if(!rx||!m->ready||!g->root)goto done;
    g->head=rx->next;if(!g->head)g->tail=NULL;--g->queued;
    Received* w=calloc(1,sizeof(*w)+(rx->size>34?rx->size-34:1));
    if(!w)goto released;
    w->owner=m;w->received=rx;bool candidate=false;
    if(!authenticate(m,rx,w,&candidate)){test_event(m,rx,NULL,candidate?3:4);goto wipe;}
    bool duplicate=false;Light_Group_Peer* p=peer(m,w);
    if(!p){test_event(m,rx,w,1);goto wipe;}
    if(matter_reception_commit(&p->reception,w->message.message_counter,&duplicate)!=MATTER_OK||duplicate){test_event(m,rx,w,2);goto wipe;}
    size_t offset=0;
    if(matter_protocol_header_read(w->plain,rx->size-34,&w->protocol,&offset)!=MATTER_MESSAGE_OK||w->protocol.protocol_id!=1||w->protocol.vendor_id||w->protocol.opcode!=8||
        (w->protocol.exchange_flags&(MATTER_PROTOCOL_INITIATOR|MATTER_PROTOCOL_ACK|MATTER_PROTOCOL_RELIABLE))!=MATTER_PROTOCOL_INITIATOR){test_event(m,rx,w,1);goto wipe;}
    m->busy=false;
    Matter_Im_Invoke_Port_T port={w,authorize,describe,validate,invoke};
    uint8_t result=matter_im_invoke_group(&port,w->request.fabric,m->config.endpoint,w->plain+offset,rx->size-34-offset);
    m->busy=true;test_event(m,rx,w,w->described&&(result==0||result==MATTER_IM_UNSUPPORTED_ACCESS)?0:1);
wipe:g->port.crypto.clear((uint8_t*)w,sizeof(*w)+(rx->size>34?rx->size-34:1));free(w);
released:g->port.crypto.clear(rx->data,rx->size);free(rx);
done:m->busy=false;g->processing=false;return MATTER_OK;
}
