#ifndef MATTER_FIELDS_INTERNAL_H_INCLUDED
#define MATTER_FIELDS_INTERNAL_H_INCLUDED 1
#include "matter_tlv_validate.h"
#include "../model/matter_im_invoke.h"
#include <stdlib.h>

/* Demand-owned schema workspace shared by application cluster commands.
 * Top-level fields borrow the normalized IM request through the synchronous
 * callback only. Container spans include their original open/end tokens. */
typedef struct {
    Matter_Tlv_Validation_Workspace_T validation;
    Matter_Tlv_Tag_T tags[64];
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Element_T e,fields[9];
    unsigned seen;
} Matter_Fields;
static inline Matter_Fields* matter_fields(const uint8_t* data,size_t size,unsigned depth,uint8_t* error) {
    Matter_Fields* in=calloc(1,sizeof(*in));
    if(!in) { *error=MATTER_IM_RESOURCE_EXHAUSTED; return NULL; }
    Matter_Tlv_Validation_Options_T options={1024,256,4096,(uint8_t)depth,false,0,0};
    Matter_Tlv_Validation_Report_T report;
    *error=MATTER_IM_INVALID_COMMAND;
    if(matter_tlv_validate(data,size,&options,&in->validation,in->tags,64,&report)!=MATTER_TLV_OK ||
        matter_tlv_init(&in->reader,data,size,(uint8_t)depth)!=MATTER_TLV_OK ||
        matter_tlv_next(&in->reader,&in->e)!=MATTER_TLV_OK ||
        in->e.type!=MATTER_TLV_STRUCTURE || in->e.tag.control) goto bad;
    while(matter_tlv_next(&in->reader,&in->e)==MATTER_TLV_OK && in->e.type!=MATTER_TLV_END) {
        if(in->e.tag.control!=1) goto bad;
        uint32_t tag=in->e.tag.number;
        Matter_Tlv_Element_T e=in->e;
        bool container=e.type==MATTER_TLV_ARRAY || e.type==MATTER_TLV_STRUCTURE || e.type==MATTER_TLV_LIST;
        if(container && matter_tlv_skip_container(&in->reader)!=MATTER_TLV_OK) goto bad;
        if(tag<9) {
            if(in->seen&(1u<<tag)) goto bad;
            in->seen|=1u<<tag;
            if(container) { e.data=data+e.offset; e.size=in->reader.offset-e.offset; }
            in->fields[tag]=e;
        }
    }
    if(in->e.type!=MATTER_TLV_END || matter_tlv_next(&in->reader,&in->e)!=MATTER_TLV_DONE) goto bad;
    *error=0; return in;
bad:
    free(in); return NULL;
}
/* Context-tagged array spans cannot be passed directly as TLV roots. Normalize
 * only their root tag into an independently owned bounded reader document. */
typedef struct {
    Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T element;
    uint8_t data[];
} Matter_Field_Array;
static inline Matter_Field_Array* matter_field_array(const Matter_Tlv_Element_T* e,uint8_t* error) {
    if(!e||e->type!=MATTER_TLV_ARRAY||e->tag.control!=1||e->size<3||e->size>1024) {
        *error=MATTER_IM_INVALID_COMMAND;return NULL;
    }
    Matter_Field_Array* a=calloc(1,sizeof(*a)+e->size-1);
    if(!a){*error=MATTER_IM_RESOURCE_EXHAUSTED;return NULL;}
    a->data[0]=0x16;
    for(size_t i=2;i<e->size;++i)a->data[i-1]=e->data[i];
    if(matter_tlv_init(&a->reader,a->data,e->size-1,6)!=MATTER_TLV_OK||matter_tlv_next(&a->reader,&a->element)!=MATTER_TLV_OK) {
        free(a);*error=MATTER_IM_INVALID_COMMAND;return NULL;
    }
    *error=0;return a;
}
static inline Matter_Tlv_Result_T matter_field_array_next(Matter_Field_Array* a) {
    Matter_Tlv_Result_T r=matter_tlv_next(&a->reader,&a->element);
    if(r==MATTER_TLV_OK&&(a->element.type==MATTER_TLV_STRUCTURE||a->element.type==MATTER_TLV_ARRAY||a->element.type==MATTER_TLV_LIST)) {
        r=matter_tlv_skip_container(&a->reader);
        a->element.data=a->data+a->element.offset;a->element.size=a->reader.offset-a->element.offset;
    }
    return r;
}
static inline bool matter_field_u(Matter_Fields* in,unsigned tag,uint64_t max,bool required,bool nullable,uint64_t* out) {
    if(!(in->seen&(1u<<tag))) return !required;
    Matter_Tlv_Element_T* e=&in->fields[tag];
    if(e->type==MATTER_TLV_NULL && nullable) { *out=UINT16_MAX; return true; }
    if(e->type!=MATTER_TLV_UNSIGNED || e->unsigned_value>max) return false;
    *out=e->unsigned_value; return true;
}
static inline bool matter_field_i(Matter_Fields* in,unsigned tag,int* out) {
    if(!(in->seen&(1u<<tag)) || in->fields[tag].type!=MATTER_TLV_SIGNED ||
        in->fields[tag].signed_value<INT16_MIN || in->fields[tag].signed_value>INT16_MAX) return false;
    *out=(int)in->fields[tag].signed_value; return true;
}
static inline bool matter_field_b(Matter_Fields* in,unsigned tag,bool required,bool* out) {
    if(!(in->seen&(1u<<tag))) return !required;
    if(in->fields[tag].type!=MATTER_TLV_BOOL) return false;
    *out=in->fields[tag].unsigned_value!=0; return true;
}
#endif
