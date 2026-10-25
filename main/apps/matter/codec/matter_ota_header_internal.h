#ifndef MATTER_OTA_HEADER_INTERNAL_H
#define MATTER_OTA_HEADER_INTERNAL_H 1
#include "matter_tlv_validate.h"
#include <string.h>
/* Shared bounded Matter OTA TLV header validation. Caller owns all workspace;
 * digest is meaningful only on success. The fixed 16-byte prefix is separate. */
static inline bool matter_ota_header_parse(const uint8_t* d,size_t n,uint64_t total,
    uint16_t vendor,uint16_t product,uint32_t current,uint32_t version,
    Matter_Tlv_Validation_Workspace_T* work,Matter_Tlv_Tag_T tags[32],uint8_t digest[32]) {
    const Matter_Tlv_Validation_Options_T options={1024,128,2048,4,false,0,0};
    Matter_Tlv_Validation_Report_T report; Matter_Tlv_Reader_T r; Matter_Tlv_Element_T e;
    if(!n || n>1024 || total<16+n || d[0]!=0x15 ||
        matter_tlv_validate(d,n,&options,work,tags,32,&report)!=MATTER_TLV_OK ||
        matter_tlv_init(&r,d,n,4)!=MATTER_TLV_OK || matter_tlv_next(&r,&e)!=MATTER_TLV_OK) return false;
    unsigned seen=0; uint64_t payload=0,min=0,max=UINT32_MAX;
    while(matter_tlv_next(&r,&e)==MATTER_TLV_OK && e.type!=MATTER_TLV_END) {
        if(e.tag.control!=1) return false;
        uint32_t tag=e.tag.number;
        if(tag>9) {
            if((e.type==MATTER_TLV_STRUCTURE || e.type==MATTER_TLV_LIST || e.type==MATTER_TLV_ARRAY) &&
                matter_tlv_skip_container(&r)!=MATTER_TLV_OK) return false;
            continue;
        }
        seen|=1u<<tag;
        if(tag==3 || tag==7) {
            if(e.type!=MATTER_TLV_UTF8 || !e.size || e.size>(tag==3?64u:256u)) return false;
        } else if(tag==9) {
            if(e.type!=MATTER_TLV_BYTES || e.size!=32) return false;
            memcpy(digest,e.data,32);
        } else {
            if(e.type!=MATTER_TLV_UNSIGNED) return false;
            uint64_t v=e.unsigned_value;
            if(tag==0 && v && v!=vendor) return false;
            if(tag==1 && v && v!=product) return false;
            if(tag==2 && v!=version) return false;
            if(tag==4) payload=v;
            if(tag==5) { if(v>UINT32_MAX) return false; min=v; }
            if(tag==6) { if(v>UINT32_MAX) return false; max=v; }
            if(tag==8 && v!=1) return false;
        }
    }
    return matter_tlv_next(&r,&e)==MATTER_TLV_DONE && (seen&0x31f)==0x31f &&
        min<=current && current<=max && payload==total-16-n;
}
#endif
