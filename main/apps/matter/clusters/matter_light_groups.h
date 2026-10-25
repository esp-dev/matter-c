#ifndef MATTER_LIGHT_GROUPS_H_INCLUDED
#define MATTER_LIGHT_GROUPS_H_INCLUDED 1
#include "matter_light.h"
#include "matter_groupkey.h"
#include "matter_acl.h"
#include "../ports/matter_crypto_port.h"
#include "../ports/matter_udp_port.h"

/* A bounded single-light node composition. One owner, no I/O or tasks. Group
 * and Scene records allocate only when used. All persistent mutations publish
 * one encoded image atomically; failed store leaves model/version unchanged.
 * The port copies bytes before returning and must preserve the previous image
 * on failure. An empty store is represented by a valid encoded empty image.
 * The application owns a namespace separate from the core fabric checkpoint. */
enum { MATTER_LIGHT_GROUP_MEMBERSHIPS=40, MATTER_LIGHT_GROUPS_PER_FABRIC=20,
    MATTER_LIGHT_SCENES=16, MATTER_LIGHT_SCENES_PER_FABRIC=7,
    MATTER_LIGHT_GROUP_IMAGE_MAX=4096 };
typedef struct {
    void* user;
    /* SIZE_QUERY uses NULL data; absent image succeeds with size zero. */
    Matter_Result_T (*load)(void*,uint8_t* data,size_t capacity,size_t* size);
    Matter_Result_T (*store)(void*,const uint8_t* data,size_t size);
} Matter_Light_Groups_Store_T;
typedef struct Matter_Light_Groups* Matter_Light_Groups_T;
typedef Matter_Result_T (*Matter_Group_Privacy_T)(void*,const uint8_t key[16],const uint8_t nonce[13],const uint8_t*,size_t,uint8_t*);
typedef struct { uint8_t index; uint64_t id; uint8_t root_public[64]; } Matter_Light_Groups_Fabric_T;
typedef struct {
    Matter_Light_T light; uint16_t endpoint; uint32_t version;
    Matter_Light_Groups_Store_T storage;
    /* Optional network membership port. join is idempotent by IPv6 address and
     * runs before durable publication; leave is idempotent and retryable. Both
     * run on the owner and never retain the address span or reenter the model. */
    void* multicast_user;
    Matter_Result_T (*join)(void*,const uint8_t address[16]);
    Matter_Result_T (*leave)(void*,const uint8_t address[16]);
    /* Optional atomic joint publication of metadata and light operating state.
     * A complete durable Lighting profile supplies this: OffWithEffect stores
     * scene 0/0 and the new light state in ONE application record. Uses
     * storage.user, copies both inputs, no effects on failure. */
    Matter_Result_T (*store_light)(void*,const uint8_t*,size_t,const Matter_Light_State_T*);
} Matter_Light_Groups_Config_T;
Matter_Light_Groups_T matter_light_groups_new(const Matter_Light_Groups_Config_T*);
/* Must succeed before command admission. Rebind after durable fabric removal,
 * before index reuse. Stale data is removed durably before being admitted.
 * Identity uses root public key + FabricID and survives UpdateNOC. A failed
 * cleanup closes group/scene admission, while ordinary runtime ACKs can drain. */
Matter_Result_T matter_light_groups_bind(Matter_Light_Groups_T,const Matter_Light_Groups_Fabric_T*,size_t);
Matter_Cluster_T matter_light_groups_cluster(Matter_Light_Groups_T,uint32_t);
Matter_Result_T matter_light_groups_attach(Matter_Light_Groups_T,Matter_Root_T);
Matter_Groupkey_Groups_Port_T matter_light_groups_keymap(Matter_Light_Groups_T);
Matter_Acl_Auxiliary_Port_T matter_light_groups_auxiliary(Matter_Light_Groups_T);
/* Optional root Groupcast Listener + PerGroup profile. Borrowed users and root
 * outlive this composition; bind once before attaching/serving clusters. Key
 * reads return only derived operational keys, never persistent InputKeys.
 * administrator resolves the authenticated CASE session (including CATs).
 * RX enqueues one bounded copy; process performs all cryptography/model work.
 * TrustFirst peer/key counters are bounded to 128 records and retained until
 * deletion/reboot; when full, a new peer is dropped, never evicts replay state. */
typedef struct {
    Matter_Groupkey_Port_T keys;Matter_Acl_Port_T acl;
    Matter_Crypto_Port_T crypto;Matter_Acl_Device_Port_T devices;
    void* user;
    Matter_Result_T (*key)(void*,uint8_t fabric,uint16_t set,unsigned epoch,uint8_t out[16]);
    Matter_Group_Privacy_T privacy;
    bool (*administrator)(void*,const Matter_Cluster_Request_T*);
} Matter_Light_Groupcast_Port_T;
Matter_Result_T matter_light_groups_groupcast(Matter_Light_Groups_T,const Matter_Light_Groupcast_Port_T*,Matter_Root_T);
Matter_Result_T matter_light_groups_events(Matter_Light_Groups_T,Matter_Events_T);
Matter_Result_T matter_light_groups_received(Matter_Light_Groups_T,const Matter_Udp_Datagram_T*);
bool matter_light_groups_member(Matter_Light_Groups_T,uint8_t fabric,uint16_t group);
Matter_Result_T matter_light_groups_process(Matter_Light_Groups_T,uint64_t);
Matter_Result_T matter_light_groups_delete(Matter_Light_Groups_T);
#endif
