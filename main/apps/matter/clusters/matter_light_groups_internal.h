#ifndef MATTER_LIGHT_GROUPS_INTERNAL_H_INCLUDED
#define MATTER_LIGHT_GROUPS_INTERNAL_H_INCLUDED 1
#include "matter_light_groups.h"
#include "matter_light_internal.h"
#include "../codec/matter_fields_internal.h"
#include "../codec/matter_tlv_internal.h"
#include "../model/matter_cluster_internal.h"
#include "../transport/matter_reception.h"
#include <string.h>

typedef struct Light_Group Light_Group;
struct Light_Group {
    Light_Group* next; uint16_t id,key; uint8_t fabric,policy;
    bool member,auxiliary,retiring;
};
/* Values are OnOff, Level, X, Y, EnhancedHue, Saturation, ColorLoopActive,
 * ColorLoopDirection, ColorLoopTime, ColorTemperature, EnhancedColorMode.
 * Unsupported fields stay present for ColorControl's complete scene extension.
 * Nullable numeric fields use the corresponding type's out-of-range sentinel. */
typedef struct Light_Scene Light_Scene;
struct Light_Scene {
    Light_Scene* next; uint32_t ms; uint16_t group,mask,values[11];
    uint8_t fabric,id;
};
typedef struct {
    Light_Group* groups; Light_Scene* scenes;
    Matter_Light_Groups_Fabric_T fabrics[5]; size_t fabric_count;
} Light_Group_Image;
typedef struct {
    uint16_t group; uint8_t id; bool valid,pending;
} Light_Scene_Info;
typedef struct { struct Matter_Light_Groups* owner; bool scenes; } Light_Group_Server;
typedef struct Light_Group_Multicast Light_Group_Multicast;
struct Light_Group_Multicast { Light_Group_Multicast* next;uint8_t address[16]; };
typedef struct Light_Group_Rx Light_Group_Rx;
struct Light_Group_Rx {Light_Group_Rx* next;Matter_Udp_Path_T path;size_t size;uint8_t data[];};
typedef struct Light_Group_Peer Light_Group_Peer;
struct Light_Group_Peer {Light_Group_Peer* next;uint64_t node;uint8_t key[16];Matter_Reception_T reception;};
typedef struct {
    Matter_Light_Groupcast_Port_T port;Matter_Cluster_T cluster;Matter_Root_T root;Matter_Events_T events;
    Light_Group_Rx *head,*tail;Light_Group_Peer* peers;
    unsigned queued,peer_count;uint8_t test_fabric;uint64_t now,test_end;
    const Matter_Cluster_Request_T* administrator;
    bool binding,processing,bound,stopping;
} Light_Groupcast;
struct Matter_Light_Groups {
    Matter_Light_Groups_Config_T config; Light_Group_Image* image;
    Light_Group_Server server[2]; Matter_Cluster_T clusters[2];
    Light_Scene_Info info[5]; uint32_t version,light_versions[3];
    uint8_t* encoded; size_t encoded_size; bool busy,ready;
    Light_Group_Multicast* joined;uint64_t multicast_retry;
    Light_Groupcast* groupcast;
    bool light_pinned,global_bound;
};
void matter_light_group_image_free(Light_Group_Image*);
Light_Group_Image* matter_light_group_image_clone(const Light_Group_Image*);
uint8_t matter_light_group_commit(Matter_Light_Groups_T,Light_Group_Image*);
uint8_t matter_light_group_commit_light(Matter_Light_Groups_T,Light_Group_Image*,const Matter_Light_State_T*);
Light_Group* matter_light_group_find(Light_Group_Image*,uint8_t,uint16_t);
Light_Scene* matter_light_scene_find(Light_Group_Image*,uint8_t,uint16_t,uint8_t);
int matter_light_group_fabric(Matter_Light_Groups_T,uint8_t);
unsigned matter_light_group_count(const Light_Group_Image*,uint8_t,bool);
unsigned matter_light_group_capacity(const Light_Group_Image*,uint8_t);
unsigned matter_light_scene_count(const Light_Group_Image*,uint8_t);
unsigned matter_light_scene_capacity(const Light_Group_Image*,uint8_t);
void matter_light_group_remove(Light_Group_Image*,uint8_t,uint16_t,bool all,bool purge_fabric);
uint8_t matter_light_scene_capture(Matter_Light_Groups_T,Light_Scene*);
void matter_light_scene_capture_state(const Matter_Light_State_T*,Light_Scene*);
void matter_light_scene_apply(const Light_Scene*,Matter_Light_State_T*);
void matter_light_scene_current(Matter_Light_Groups_T,uint8_t,uint16_t,uint8_t);
Matter_Result_T matter_light_group_global_bind(Matter_Light_Groups_T);
uint8_t matter_light_scene_extensions(Matter_Fields*,Light_Scene*);
uint8_t matter_light_scene_recall(Matter_Light_Groups_T,const Light_Scene*,uint32_t);
bool matter_light_scene_matches(Matter_Light_Groups_T,const Light_Scene*);
bool matter_light_scene_values_valid(const Light_Scene*);
bool matter_light_group_put(Matter_Tlv_Writer_T*,Matter_Tlv_Type_T,int,uint64_t);
bool matter_light_scene_encode(Matter_Tlv_Writer_T*,const Light_Scene*,int);
Matter_Result_T matter_light_group_interfaces(Matter_Light_Groups_T);
bool matter_light_group_address(const Light_Group_Image*,const Light_Group*,uint8_t[16]);
uint8_t matter_light_group_network_prepare(Matter_Light_Groups_T,const Light_Group_Image*);
Matter_Result_T matter_light_group_network_cleanup(Matter_Light_Groups_T,bool all);
Matter_Result_T matter_light_groupcast_interface(Matter_Light_Groups_T);
Matter_Result_T matter_light_groupcast_process(Matter_Light_Groups_T,uint64_t);
void matter_light_groupcast_free(Matter_Light_Groups_T);
uint8_t matter_light_group_aux_prepare(Matter_Light_Groups_T,const Light_Group_Image*,bool*);
uint8_t matter_light_group_key_cleanup(Matter_Light_Groups_T);
void matter_light_groupcast_pause(Matter_Light_Groups_T,bool stop);
void matter_light_groupcast_unbind(Matter_Light_Groups_T);
#endif
