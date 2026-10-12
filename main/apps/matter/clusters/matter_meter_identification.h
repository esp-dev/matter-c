#ifndef MATTER_METER_IDENTIFICATION_H_INCLUDED
#define MATTER_METER_IDENTIFICATION_H_INCLUDED 1
#include "../model/matter_cluster.h"
#define MATTER_METER_IDENTIFICATION_CLUSTER 0x0b06
#define MATTER_METER_IDENTIFICATION_REVISION 1
#define MATTER_METER_ID_TEXT_MAX 64
#define MATTER_METER_ID_TYPE 0
#define MATTER_METER_ID_DELIVERY 1
#define MATTER_METER_ID_SERIAL 2
#define MATTER_METER_ID_PROTOCOL 3
typedef struct { uint8_t size; uint8_t data[MATTER_METER_ID_TEXT_MAX]; bool known; } Matter_Meter_Id_Text_T;
typedef struct {
    uint8_t meter_type; bool type_known;
    Matter_Meter_Id_Text_T delivery,serial,protocol;
} Matter_Meter_Id_Snapshot_T;
typedef struct { void* user; Matter_Result_T (*snapshot)(void*,Matter_Meter_Id_Snapshot_T*); } Matter_Meter_Id_Port_T;
/* Rev1, ProtocolVersion supported, no PowerThreshold feature. Callback copies
 * coherent data into zeroed heap workspace; no I/O, retained pointers or reentry.
 * Unknown identity remains null; no truncation or fallback from another ID. */
Matter_Cluster_T matter_meter_identification_new(const Matter_Meter_Id_Port_T*,uint32_t version);
/* Call before IM. Failed/invalid snapshot publishes nulls and returns PORT_ERROR.
 * Owner notifies subscriptions if cluster version changed, including on error. */
Matter_Result_T matter_meter_identification_refresh(Matter_Cluster_T);
#endif
