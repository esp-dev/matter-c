#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_alloc_bytes.h"
#include "clusters/matter_light_groups_internal.h"
#include "crypto/matter_crypto_mbedtls.h"
#include "codec/matter_message_header.h"
#include "codec/matter_protocol_header.h"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"groupcast:%d: %s\n",__LINE__,#x);abort();}}while(0)
typedef struct {
    Matter_Light_Groups_T groups;Matter_Light_T light;Matter_Root_T root;
    Matter_Crypto_Mbedtls_T backend;Matter_Crypto_Port_T crypto;
    Matter_Groupkey_View_T keys;Matter_Acl_View_T acl;Matter_Root_Config_T identity;
    Matter_Light_State_T state;Matter_Events_T events;uint64_t high;
    uint8_t image[4096],operational[16],packet[1232],plain[1024],backup[1232];size_t image_size,packet_size;
    unsigned writes,joins,leaves,key_removes;bool fail_store,fail_join,fail_leave,fail_key,admin,reenter;
} Fixture;
static Matter_Result_T load(void* u,uint8_t* data,size_t capacity,size_t* size){Fixture* f=u;*size=f->image_size;if(data){CHECK(capacity>=f->image_size);memcpy(data,f->image,f->image_size);}return MATTER_OK;}
static Matter_Result_T store(void* u,const uint8_t* data,size_t size){Fixture* f=u;if(f->reenter){CHECK(matter_light_groups_process(f->groups,0)==MATTER_BUSY);CHECK(matter_light_groups_delete(f->groups)==MATTER_BUSY);}if(f->fail_store)return MATTER_PORT_ERROR;CHECK(size<=sizeof(f->image));memcpy(f->image,data,size);f->image_size=size;++f->writes;return MATTER_OK;}
static Matter_Result_T light_load(void* u,Matter_Light_State_T* out){*out=((Fixture*)u)->state;return MATTER_OK;}
static Matter_Result_T light_store(void* u,const Matter_Light_State_T* in){Fixture* f=u;if(f->reenter){CHECK(matter_light_groups_process(f->groups,0)==MATTER_BUSY);CHECK(matter_light_groups_delete(f->groups)==MATTER_BUSY);}f->state=*in;return MATTER_OK;}
static Matter_Result_T root_load(void* u,Matter_Root_Config_T* out){*out=((Fixture*)u)->identity;return MATTER_OK;}
static Matter_Result_T root_store(void* u,const Matter_Root_Settings_T* s){(void)u;(void)s;return MATTER_OK;}
static uint8_t root_auth(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* path,Matter_Im_Privilege_T privilege){(void)u;(void)session;(void)path;(void)privilege;return MATTER_IM_UNSUPPORTED_ACCESS;}
static Matter_Result_T join(void* u,const uint8_t address[16]){Fixture* f=u;CHECK(address[0]==255);if(f->fail_join)return MATTER_PORT_ERROR;++f->joins;return MATTER_OK;}
static Matter_Result_T leave(void* u,const uint8_t address[16]){Fixture* f=u;CHECK(address[0]==255);if(f->fail_leave)return MATTER_PORT_ERROR;++f->leaves;return MATTER_OK;}
static const Matter_Groupkey_View_T* keys(void* u){return &((Fixture*)u)->keys;}
static const Matter_Acl_View_T* acl(void* u){return &((Fixture*)u)->acl;}
static uint8_t key_store(void* u,uint8_t fabric,const Matter_Groupkey_Set_T* set,const uint8_t input[3][16]){(void)u;(void)fabric;(void)set;(void)input;return MATTER_IM_FAILURE;}
static uint8_t key_remove(void* u,uint8_t fabric,uint16_t id){Fixture* f=u;CHECK(fabric==1&&id==7);if(f->fail_key)return MATTER_IM_FAILURE;++f->key_removes;f->keys.fabrics[0].sets[1].count=0;++f->keys.version;return 0;}
static Matter_Result_T key(void* u,uint8_t fabric,uint16_t id,unsigned epoch,uint8_t out[16]){Fixture* f=u;if(fabric!=1||id!=7||epoch||!f->keys.fabrics[0].sets[1].count)return MATTER_INVALID_ARGUMENT;memcpy(out,f->operational,16);return MATTER_OK;}
static Matter_Result_T privacy(void* u,const uint8_t key[16],const uint8_t nonce[13],const uint8_t* data,size_t size,uint8_t* out){return matter_crypto_mbedtls_privacy(u,key,nonce,data,size,out);}
static bool administrator(void* u,const Matter_Cluster_Request_T* q){Fixture* f=u;return f->admin&&q->is_case&&q->fabric==1&&q->peer_node==101;}
static Matter_Result_T event_load(void* u,uint64_t* high){*high=((Fixture*)u)->high;return MATTER_OK;}
static Matter_Result_T event_store(void* u,uint64_t high){((Fixture*)u)->high=high;return MATTER_OK;}
static bool emit(Matter_Tlv_Writer_T* w,Matter_Tlv_Type_T type,int tag,uint64_t value){Matter_Tlv_Element_T e={.type=type,.unsigned_value=value};if(tag>=0)e.tag=(Matter_Tlv_Tag_T){.control=1,.number=(uint32_t)tag};return matter_tlv_write(w,&e,0)==MATTER_TLV_OK;}
#define P(t,tag,v) CHECK(emit(w,t,tag,v))
#define U(tag,v) P(MATTER_TLV_UNSIGNED,tag,v)
#define END() P(MATTER_TLV_END,-1,0)
static size_t join_args(Fixture* f,unsigned group,unsigned endpoint,bool auxiliary){Matter_Tlv_Writer_T writer;Matter_Tlv_Writer_T* w=&writer;CHECK(matter_tlv_writer_init(w,f->plain,sizeof(f->plain),2)==MATTER_TLV_OK);P(MATTER_TLV_STRUCTURE,-1,0);U(0,group);P(MATTER_TLV_ARRAY,1,0);U(-1,endpoint);END();U(2,7);if(auxiliary)P(MATTER_TLV_BOOL,4,1);U(6,1);END();size_t size=0;CHECK(matter_tlv_writer_finish(w,&size)==MATTER_TLV_OK);return size;}
static uint8_t call(Fixture* f,unsigned command,size_t size){uint8_t response[96];Matter_Tlv_Writer_T writer;CHECK(matter_tlv_writer_init(&writer,response,sizeof(response),2)==MATTER_TLV_OK);Matter_Cluster_Request_T q={.fabric=1,.is_case=true,.peer_node=101,.filtered=true};Matter_Im_Command_Result_T result;uint64_t token=0;CHECK(matter_cluster_start(matter_light_groups_cluster(f->groups,0x65),command,&q,f->plain,size,&writer,&result,&token)==MATTER_OK&&!token);return result.status;}
static Matter_Udp_Datagram_T packet(Fixture* f,uint32_t counter,uint64_t node,bool private_message,unsigned group){
    Matter_Tlv_Writer_T writer;Matter_Tlv_Writer_T* w=&writer;CHECK(matter_tlv_writer_init(w,f->plain,sizeof(f->plain),4)==MATTER_TLV_OK);
    P(MATTER_TLV_STRUCTURE,-1,0);P(MATTER_TLV_BOOL,0,1);P(MATTER_TLV_BOOL,1,0);P(MATTER_TLV_ARRAY,2,0);P(MATTER_TLV_STRUCTURE,-1,0);
    P(MATTER_TLV_LIST,0,0);U(1,6);U(2,2);END();P(MATTER_TLV_STRUCTURE,1,0);END();END();END();U(255,MATTER_IM_REVISION);END();size_t args_size=0;CHECK(matter_tlv_writer_finish(w,&args_size)==MATTER_TLV_OK);
    memmove(f->plain+6,f->plain,args_size);Matter_Protocol_Header_T protocol={.exchange_flags=MATTER_PROTOCOL_INITIATOR,.exchange_id=1,.protocol_id=1,.opcode=8};size_t protocol_size=0;CHECK(matter_protocol_header_write(&protocol,f->plain,sizeof(f->plain),&protocol_size)==MATTER_MESSAGE_OK&&protocol_size==6);
    uint8_t hash[2];CHECK(f->crypto.hkdf_sha256(f->crypto.user,f->operational,16,NULL,0,(const uint8_t*)"GroupKeyHash",12,hash,2)==MATTER_OK);
    uint16_t session=(uint16_t)(((uint16_t)hash[0]<<8)|hash[1]);Matter_Message_Header_T header={.source_node_id=node,.destination_id=group,.message_counter=counter,.session_id=session,.message_flags=6,.security_flags=1};size_t offset=0;
    CHECK(matter_message_header_write(&header,f->packet,sizeof(f->packet),&offset)==MATTER_MESSAGE_OK&&offset==18);if(private_message)f->packet[3]|=0x80;
    uint8_t nonce[13];nonce[0]=f->packet[3];memcpy(nonce+1,f->packet+4,12);
    CHECK(f->crypto.ccm_encrypt(f->crypto.user,f->operational,nonce,f->packet,18,f->plain,args_size+6,f->packet+18)==MATTER_OK);f->packet_size=18+args_size+6+16;
    if(private_message){uint8_t secret[16],cipher[14];CHECK(f->crypto.hkdf_sha256(f->crypto.user,f->operational,16,NULL,0,(const uint8_t*)"PrivacyKey",10,secret,16)==MATTER_OK);nonce[0]=(uint8_t)(session>>8);nonce[1]=(uint8_t)session;memcpy(nonce+2,f->packet+f->packet_size-11,11);CHECK(matter_crypto_mbedtls_privacy(f->backend,secret,nonce,f->packet+4,14,cipher)==MATTER_OK);memcpy(f->packet+4,cipher,14);f->crypto.clear(secret,sizeof(secret));}
    Matter_Udp_Datagram_T d={.path={.local={.port=5540},.peer={.port=5540},.interface_id=1},.data=f->packet,.size=f->packet_size};d.path.peer.address[0]=0xfe;d.path.peer.address[1]=0x80;d.path.peer.address[15]=1;
    Light_Group* member=matter_light_group_find(f->groups->image,1,(uint16_t)group);CHECK(member&&matter_light_group_address(f->groups->image,member,d.path.local.address));return d;
}
static bool on(Fixture* f){Matter_Light_State_T state;CHECK(matter_light_state(f->light,&state)==MATTER_OK);return state.on;}
int main(void){
    Fixture* f=calloc(1,sizeof(*f));CHECK(f);f->admin=true;f->backend=matter_crypto_mbedtls_new(NULL);CHECK(f->backend&&matter_crypto_mbedtls_port(f->backend,&f->crypto)==MATTER_OK);for(unsigned i=0;i<16;++i)f->operational[i]=(uint8_t)i;
    matter_light_defaults(&f->state);Matter_Light_Port_T lp={f,light_load,light_store};f->light=matter_light_new(&lp,1,0,true);CHECK(f->light);
    Matter_Light_Groups_Config_T c={.light=f->light,.endpoint=1,.storage={f,load,store},.multicast_user=f,.join=join,.leave=leave};f->groups=matter_light_groups_new(&c);CHECK(f->groups);
    f->keys.fabrics[0].index=1;f->keys.fabrics[0].sets[0].count=1;f->keys.fabrics[0].sets[1]=(Matter_Groupkey_Set_T){.times={1},.id=7,.count=1};f->acl.fabrics[0].index=1;
    Matter_Light_Groupcast_Port_T gp={.keys={f,keys,key_store,key_remove},.acl={.user=f,.view=acl},.crypto=f->crypto,.user=f,.key=key,.privacy=privacy,.administrator=administrator};
    CHECK(matter_light_groups_groupcast(f->groups,&gp,NULL)==MATTER_OK);Matter_Light_Groups_Fabric_T fabric={.index=1,.id=UINT64_C(0x1122aabbccddeeff)};fabric.root_public[0]=1;CHECK(matter_light_groups_bind(f->groups,&fabric,1)==MATTER_OK);
    f->identity=(Matter_Root_Config_T){.vendor_id=0xfff1,.product_id=0x8000,.hardware_version=1,.software_version=1,.configuration_version=1,.capabilities={3,3,1,1,9,3},.settings={.location={'X','X'}}};
    f->identity.unique_id.size=1;f->identity.unique_id.data[0]='1';f->identity.hardware_string=f->identity.unique_id;f->identity.software_string=f->identity.unique_id;
    Matter_Root_Port_T rp={f,root_load,root_auth,root_store};f->root=matter_root_new(&rp);CHECK(f->root);CHECK(matter_light_attach(f->light,f->root,1)==MATTER_OK&&matter_light_groups_attach(f->groups,f->root)==MATTER_OK);
    Matter_Events_Port_T ep={f,event_load,event_store};f->events=matter_events_new(&ep);CHECK(f->events&&matter_light_groups_events(f->groups,f->events)==MATTER_OK);
    CHECK(call(f,0,join_args(f,7,0,false))==MATTER_IM_UNSUPPORTED_ENDPOINT);
    f->admin=false;CHECK(call(f,0,join_args(f,7,1,true))==MATTER_IM_UNSUPPORTED_ACCESS);f->admin=true;
    f->reenter=true;CHECK(!call(f,0,join_args(f,7,1,true)));f->reenter=false;CHECK(f->joins==1&&matter_light_groups_member(f->groups,1,7));
    const uint8_t expected[]={0xff,0x35,0,0x40,0xfd,0x11,0x22,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0,0,7};uint8_t address[16];CHECK(matter_light_group_address(f->groups->image,f->groups->image->groups,address)&&!memcmp(address,expected,16));
    Matter_Udp_Datagram_T d=packet(f,100,123,true,7);f->packet[f->packet_size-1]^=1;CHECK(matter_light_groups_received(f->groups,&d)==MATTER_OK&&matter_light_groups_process(f->groups,1)==MATTER_OK&&on(f)&&!f->groups->groupcast->peer_count);
    d=packet(f,100,123,false,7);CHECK(matter_light_groups_received(f->groups,&d)==MATTER_OK);memset(f->packet,0,f->packet_size);CHECK(matter_light_groups_process(f->groups,2)==MATTER_OK&&!on(f));
    d=packet(f,100,123,false,7);CHECK(matter_light_groups_received(f->groups,&d)==MATTER_OK&&matter_light_groups_process(f->groups,3)==MATTER_OK&&!on(f));
    d=packet(f,101,123,true,7);CHECK(matter_light_groups_received(f->groups,&d)==MATTER_OK&&matter_light_groups_process(f->groups,4)==MATTER_OK&&on(f));
    /* Faults in RX staging, peer admission and shared IM normalization never
     * execute Toggle. Successfully admitted peer counters remain until reboot. */
    for(unsigned i=1;i<=5;++i){d=packet(f,200+i,1000+i,true,7);CHECK(matter_light_groups_received(f->groups,&d)==MATTER_OK);fail_at=calls+i;CHECK(matter_light_groups_process(f->groups,10+i)==MATTER_OK&&on(f));fail_at=0;}
    size_t before=live_bytes;f->fail_join=true;CHECK(call(f,0,join_args(f,8,1,false))==MATTER_IM_FAILURE&&!matter_light_groups_member(f->groups,1,8));f->fail_join=false;CHECK(live_bytes==before);
    f->fail_store=true;f->fail_leave=true;CHECK(call(f,0,join_args(f,8,1,false))==MATTER_IM_FAILURE&&!matter_light_groups_member(f->groups,1,8));f->fail_store=false;f->fail_leave=false;CHECK(matter_light_groups_process(f->groups,2000)==MATTER_OK&&f->leaves==1);
    CHECK(!call(f,0,join_args(f,8,1,false)));d=packet(f,102,123,false,8);CHECK(matter_light_groups_received(f->groups,&d)==MATTER_OK&&matter_light_groups_process(f->groups,2001)==MATTER_OK&&on(f));
    f->acl.fabrics[0].count=1;f->acl.fabrics[0].entries[0]=(Matter_Acl_Entry_T){.auth_mode=3,.privilege=MATTER_IM_OPERATE,.subject_count=1,.subjects={8},.target_count=1,.targets={{.endpoint=1,.cluster=6,.present=3}}};
    d=packet(f,103,123,true,8);f->reenter=true;CHECK(matter_light_groups_received(f->groups,&d)==MATTER_OK&&matter_light_groups_process(f->groups,2002)==MATTER_OK&&!on(f));f->reenter=false;
    const uint8_t all[]={0x15,0x24,0,0,0x18};memcpy(f->plain,all,sizeof(all));
    f->fail_key=true;CHECK(call(f,1,sizeof(all))==MATTER_IM_FAILURE);
    CHECK(!f->key_removes&&!matter_light_group_count(f->groups->image,1,true));
    /* A later legacy RemoveAllGroups must not destroy pending key erasure. */
    Matter_Cluster_Request_T q={.fabric=1,.is_case=true,.peer_node=101};Matter_Im_Command_Result_T result;uint64_t token=0;
    CHECK(matter_cluster_start(matter_light_groups_cluster(f->groups,4),4,&q,(const uint8_t[]){0x15,0x18},2,NULL,&result,&token)==MATTER_OK&&!result.status&&!token);
    CHECK(matter_light_group_count(f->groups->image,1,false)==2);
    f->fail_key=false;CHECK(matter_light_groups_process(f->groups,2003)==MATTER_OK&&f->key_removes==1);
    CHECK(matter_light_groups_process(f->groups,2004)==MATTER_OK&&!matter_light_group_count(f->groups->image,1,false));
    CHECK(matter_light_groups_delete(f->groups)==MATTER_BUSY);CHECK(matter_light_delete(f->light)==MATTER_BUSY);CHECK(matter_root_delete(f->root)==MATTER_OK);CHECK(matter_light_groups_delete(f->groups)==MATTER_OK);CHECK(matter_light_delete(f->light)==MATTER_OK);CHECK(matter_events_delete(f->events)==MATTER_OK);CHECK(matter_crypto_mbedtls_delete(f->backend)==MATTER_OK);free(f);CHECK(!live&&!live_bytes);
    puts("PASS Groupcast: real AES-CCM/privacy, immutable RX, replay, scoped ACL/aux, multicast atomicity, deferred leave, key erasure, reentry and OOM");return 0;
}
