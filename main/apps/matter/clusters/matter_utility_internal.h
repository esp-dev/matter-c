#ifndef MATTER_UTILITY_INTERNAL_H_INCLUDED
#define MATTER_UTILITY_INTERNAL_H_INCLUDED 1
/* Private support for the MP04 utility servers; embedded in their heap state. */
#include "../model/matter_cluster_internal.h"
#include "../codec/matter_tlv_validate.h"
#define UTILITY_GLOBAL_COUNT 5
#define UTILITY_LIST_BYTES 64
#define UTILITY_COMMAND_BYTES 1024
#define UTILITY_COMMAND_TOKENS 128
#define UTILITY_COMMAND_DEPTH 4
#define UTILITY_COMMAND_TAGS 32
#define UTILITY_GENERATED 0xfff8
#define UTILITY_ACCEPTED 0xfff9
#define UTILITY_ATTRIBUTES 0xfffb
#define UTILITY_FEATURES 0xfffc
#define UTILITY_REVISION 0xfffd
typedef struct {
    uint32_t version,revision;
    uint8_t attributes[UTILITY_LIST_BYTES]; size_t attributes_size;
    bool command;
    Matter_Tlv_Validation_Workspace_T validation; Matter_Tlv_Tag_T tags[UTILITY_COMMAND_TAGS];
    Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T element; Matter_Tlv_Writer_T writer;
} Matter_Utility_T;
static inline Matter_Result_T utility_version(void* u,uint32_t* v) { *v=((Matter_Utility_T*)u)->version; return MATTER_OK; }
static inline uint8_t utility_read(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    Matter_Utility_T* m=u; uint32_t id=*(const uint32_t*)ref; (void)q;
    static const uint8_t empty[]={0x16,0x18},command_zero[]={0x16,4,0,0x18};
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->version};
    if(id==UTILITY_REVISION) v->unsigned_value=m->revision;
    else if(id!=UTILITY_FEATURES) {
        v->type=MATTER_TLV_ARRAY;
        v->data=id==UTILITY_ATTRIBUTES?m->attributes:id==UTILITY_ACCEPTED && m->command?command_zero:empty;
        v->size=id==UTILITY_ATTRIBUTES?m->attributes_size:id==UTILITY_ACCEPTED && m->command?sizeof(command_zero):sizeof(empty);
    }
    return MATTER_IM_SUCCESS;
}
static inline bool utility_globals(Matter_Cluster_T h,Matter_Utility_T* m,const uint32_t* ids,size_t count) {
    static const uint32_t globals[]={UTILITY_GENERATED,UTILITY_ACCEPTED,UTILITY_ATTRIBUTES,UTILITY_FEATURES,UTILITY_REVISION};
    if(matter_tlv_writer_init(&m->writer,m->attributes,sizeof(m->attributes),1)!=MATTER_TLV_OK) return false;
    m->element=(Matter_Tlv_Element_T){.type=MATTER_TLV_ARRAY};
    if(matter_tlv_write(&m->writer,&m->element,0)!=MATTER_TLV_OK) return false;
    for(size_t i=0;i<count+UTILITY_GLOBAL_COUNT;++i) {
        m->element=(Matter_Tlv_Element_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=i<count?ids[i]:globals[i-count]};
        if(matter_tlv_write(&m->writer,&m->element,0)!=MATTER_TLV_OK) return false;
    }
    m->element=(Matter_Tlv_Element_T){.type=MATTER_TLV_END};
    if(matter_tlv_write(&m->writer,&m->element,0)!=MATTER_TLV_OK || matter_tlv_writer_finish(&m->writer,&m->attributes_size)!=MATTER_TLV_OK) return false;
    for(size_t i=0;i<UTILITY_GLOBAL_COUNT;++i) {
        Matter_Attribute_Def_T a={.id=globals[i],.read_access={MATTER_IM_VIEW,false},.read=utility_read,.ref=&globals[i]};
        if(matter_cluster_add_attribute(h,&a)!=MATTER_OK) return false;
    }
    return true;
}
/* Ignore well-formed unknown fields, reject duplicate tags and malformed tails.
 * Known fields are unsigned scalars; caller supplies required-mask and ranges. */
static inline bool utility_command(Matter_Utility_T* m,const uint8_t* d,size_t n,uint64_t* values,unsigned count,unsigned required,unsigned* seen) {
    const Matter_Tlv_Validation_Options_T options={UTILITY_COMMAND_BYTES,UTILITY_COMMAND_TOKENS,UTILITY_COMMAND_BYTES,UTILITY_COMMAND_DEPTH,false,0,0};
    Matter_Tlv_Validation_Report_T report;
    *seen=0;
    if(matter_tlv_validate(d,n,&options,&m->validation,m->tags,UTILITY_COMMAND_TAGS,&report)!=MATTER_TLV_OK ||
        matter_tlv_init(&m->reader,d,n,UTILITY_COMMAND_DEPTH)!=MATTER_TLV_OK ||
        matter_tlv_next(&m->reader,&m->element)!=MATTER_TLV_OK || m->element.type!=MATTER_TLV_STRUCTURE || m->element.tag.control) return false;
    while(matter_tlv_next(&m->reader,&m->element)==MATTER_TLV_OK) {
        if(m->element.type==MATTER_TLV_END) return (*seen & required)==required && matter_tlv_next(&m->reader,&m->element)==MATTER_TLV_DONE;
        if(m->element.tag.control!=1) return false;
        unsigned tag=m->element.tag.number;
        if(tag<count) {
            if(m->element.type!=MATTER_TLV_UNSIGNED || (*seen&(1u<<tag))) return false;
            *seen|=1u<<tag; values[tag]=m->element.unsigned_value;
        } else if(m->element.type==MATTER_TLV_STRUCTURE || m->element.type==MATTER_TLV_ARRAY || m->element.type==MATTER_TLV_LIST) {
            if(matter_tlv_skip_container(&m->reader)!=MATTER_TLV_OK) return false;
        }
    }
    return false;
}
#endif
