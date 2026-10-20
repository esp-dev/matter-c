#ifndef MATTER_STORE_TLV_H
#define MATTER_STORE_TLV_H 1
#include "../clusters/matter_root.h"
#include "../clusters/matter_eem.h"
#include "../clusters/matter_ota_requestor.h"
/* Portable storage DTO, not a binary file layout. Allocate on heap. Only named
 * fields are serialized; PASE/session bindings never survive a process restart. */
typedef struct {
    Matter_Fabric_View_T view; Matter_Acl_View_T acl; Matter_Groupkey_View_T groupkey;
    uint8_t groupkeys[5][MATTER_GROUPKEY_SETS][3][16],keys[5][32],next_index,saved_next;
    bool journal;
    /* UpdateNOC rollback image. index=0 means no rotation; heap DTO only. */
    Matter_Fabric_Record_T previous; uint8_t previous_key[32];
} Matter_Store_Fabrics_T;
typedef struct { Matter_Wifi_Settings_T settings; Matter_Wifi_Id_T connected; bool pending; } Matter_Store_Wifi_T;
typedef struct {
    uint32_t schema;
    Matter_Store_Fabrics_T fabrics; Matter_Store_Wifi_T wifi; Matter_Root_Settings_T root;
    uint32_t hours; uint16_t reboots;
    Matter_Eem_Checkpoint_T eem; uint64_t event_high;
    Matter_Ota_Provider_T ota[MATTER_OTA_PROVIDERS];
} Matter_Store_Data_T;
enum { MATTER_STORE_BLOB_MAX=32768 };
/* Versioned TLV storage schema, independent of RAM layout. Existing Matter TLV
 * codec, no JSON or third-party persistence library. Encode uses a small heap
 * workspace; decode also stages one complete DTO for atomic publication.
 * Schema1 imports empty fabric labels, schema2 persists labels, schema3 journals credential rotation.
 * Schema4 appends VID verification metadata, also in the rollback record.
 * Schema5 appends node-wide EEM checkpoint and exclusive event high-water.
 * Schema6 appends fabric-scoped default OTA providers. Schema7 appends EEM mode
 * and known-register mask. Decode upgrades1..6 to7
 * with absent providers empty (and absent metering state zero); old binaries
 * reject7. Earlier volatile counters cannot be reconstructed during migration.
 * Decode publishes only a completely validated record. Unknown
 * versions/tags or wrong lengths fail. Caller owns all buffers and scheduling. */
Matter_Result_T matter_store_tlv_encode(const Matter_Store_Data_T*,uint8_t*,size_t,size_t*);
Matter_Result_T matter_store_tlv_decode(const uint8_t*,size_t,Matter_Store_Data_T*);
bool matter_store_data_valid(const Matter_Store_Data_T*);
#endif
