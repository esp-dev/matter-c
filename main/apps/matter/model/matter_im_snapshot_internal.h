#ifndef MATTER_IM_SNAPSHOT_INTERNAL_H_INCLUDED
#define MATTER_IM_SNAPSHOT_INTERNAL_H_INCLUDED 1
#include "matter_im_read.h"
#include "../codec/matter_tlv_validate.h"
#include "../codec/matter_tlv_writer.h"
#include <stdlib.h>
#include <string.h>

typedef struct Matter_Im_Snapshot_Node {
    struct Matter_Im_Snapshot_Node* next;
    uint8_t data[];
} Matter_Im_Snapshot_Node;
typedef struct {
    Matter_Im_Snapshot_Node* head;
    size_t size; /* Encoded payload only, with the original per-report ceiling. */
} Matter_Im_Snapshots;

static inline void matter_im_snapshots_clear(Matter_Im_Snapshots* snapshots) {
    while(snapshots->head) {
        Matter_Im_Snapshot_Node* next=snapshots->head->next;
        free(snapshots->head); snapshots->head=next;
    }
    snapshots->size=0;
}
/* Private immutable values, never realloc/move earlier copies. Caller performs
 * its existing type/pointer preflight and owns all scratch on its heap context.
 * Failure leaves published nodes, byte accounting and the supplied value intact.
 * The owner clears only after its report/ACK users drain, or during deletion. */
static inline Matter_Im_Status_T matter_im_snapshot_copy(Matter_Im_Snapshots* snapshots,
    Matter_Im_Value_T* value,Matter_Tlv_Writer_T* writer,Matter_Tlv_Reader_T* reader,
    Matter_Tlv_Element_T* element,Matter_Tlv_Validation_Workspace_T* validation,
    Matter_Tlv_Tag_T* tags,size_t tag_count) {
    size_t size=value->size;
    if(size>MATTER_IM_READ_MAX_VALUE || size>MATTER_IM_READ_SNAPSHOT_BYTES-snapshots->size)
        return MATTER_IM_RESOURCE_EXHAUSTED;
    bool container=value->type==MATTER_TLV_STRUCTURE || value->type==MATTER_TLV_ARRAY;
    if(!container) {
        /* Anonymous string: control byte + minimal length width + raw bytes.
         * The existing writer still owns encoding, UTF-8 and syntax validation. */
        size_t prefix=1+(size<=UINT8_MAX?1:size<=UINT16_MAX?2:size<=UINT32_MAX?4:8);
        size_t available=MATTER_IM_READ_SNAPSHOT_BYTES-snapshots->size;
        if(available>MATTER_IM_READ_MAX_VALUE) available=MATTER_IM_READ_MAX_VALUE;
        if(size>available || prefix>available-size) return MATTER_IM_RESOURCE_EXHAUSTED;
        size+=prefix;
    }
    Matter_Im_Snapshot_Node* node=calloc(1,sizeof(*node)+size);
    if(!node) return MATTER_IM_RESOURCE_EXHAUSTED;
    uint8_t* data=node->data;
    if(container) { if(size) memcpy(data,value->data,size); }
    else {
        *element=(Matter_Tlv_Element_T){.type=value->type,.data=value->data,.size=value->size};
        Matter_Tlv_Result_T r=matter_tlv_writer_init(writer,data,size,4);
        if(r==MATTER_TLV_OK) r=matter_tlv_write(writer,element,0);
        if(r!=MATTER_TLV_OK) { free(node); return r==MATTER_TLV_NO_SPACE?MATTER_IM_RESOURCE_EXHAUSTED:MATTER_IM_FAILURE; }
        if(matter_tlv_writer_finish(writer,&size)!=MATTER_TLV_OK) { free(node); return MATTER_IM_FAILURE; }
    }
    const Matter_Tlv_Validation_Options_T opt={MATTER_IM_READ_MAX_VALUE,1024,4096,4,false,0,0};
    Matter_Tlv_Validation_Report_T report;
    Matter_Tlv_Result_T r=matter_tlv_validate(data,size,&opt,validation,tags,tag_count,&report);
    if(r!=MATTER_TLV_OK || matter_tlv_init(reader,data,size,4)!=MATTER_TLV_OK ||
        matter_tlv_next(reader,element)!=MATTER_TLV_OK || element->tag.control || element->type!=value->type) {
        free(node);
        return r==MATTER_TLV_LIMIT_REACHED || r==MATTER_TLV_DEPTH_LIMIT?MATTER_IM_RESOURCE_EXHAUSTED:MATTER_IM_FAILURE;
    }
    node->next=snapshots->head; snapshots->head=node; snapshots->size+=size;
    value->data=data; value->size=size; return MATTER_IM_SUCCESS;
}
#endif
