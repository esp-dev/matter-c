/* Independent host model and wire fixtures shared by unit and PASE tests. */
#include "codec/matter_tlv_writer.h"
#define MODEL_CHECK(c) do { if (!(c)) { fprintf(stderr,"IM model:%d: %s\n",__LINE__,#c); abort(); } } while (0)
typedef struct {
    Matter_Im_Read_T active;
    unsigned size, enumerations, descriptions, auths, reads, versions, bad_enum;
    bool deny, unreadable, version_error, changing, override_version;
    uint32_t version;
    Matter_Tlv_Writer_T writer;
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Element_T element;
    uint8_t input[1024];
    struct { uint16_t endpoint; uint32_t cluster, version; } filters[17];
} ImTestModel;
static Matter_Im_Path_T model_path(unsigned i) {
    return (Matter_Im_Path_T){(uint16_t)(i/12),0x28+(i%12)/6,2+i%6};
}
static unsigned model_index(const Matter_Im_Path_T* p) { return p->endpoint*12+(p->cluster-0x28)*6+p->attribute-2; }
static void model_guard(ImTestModel* m) { if(m->active) MODEL_CHECK(matter_im_read_cancel(m->active)==MATTER_BUSY); }
static Matter_Result_T model_enumerate(void* u,const Matter_Im_Selector_T* q,const Matter_Im_Path_T* after,Matter_Im_Path_T* out,bool* found) {
    ImTestModel* m=u; model_guard(m); ++m->enumerations; MODEL_CHECK(m->size<=MATTER_IM_READ_MAX_RESULTS+1);
    if(m->bad_enum==3) return MATTER_PORT_ERROR;
    if(m->bad_enum==1) { *out=(Matter_Im_Path_T){99,99,99}; *found=true; return MATTER_OK; }
    if(m->bad_enum==2 && after) { *out=*after; *found=true; return MATTER_OK; }
    for(unsigned i=0;i<m->size;++i) {
        Matter_Im_Path_T p=model_path(i);
        if((q->present&1) && q->path.endpoint!=p.endpoint) continue;
        if((q->present&2) && q->path.cluster!=p.cluster) continue;
        if((q->present&4) && q->path.attribute!=p.attribute) continue;
        if(after && (p.endpoint<after->endpoint || (p.endpoint==after->endpoint &&
            (p.cluster<after->cluster || (p.cluster==after->cluster && p.attribute<=after->attribute))))) continue;
        *out=p; *found=true; return MATTER_OK;
    }
    *found=false; return MATTER_OK;
}
static Matter_Im_Status_T model_describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* a) {
    ImTestModel* m=u; model_guard(m); ++m->descriptions;
    if(p->cluster<0x28 || p->cluster>0x29 || p->attribute<2 || p->attribute>7 || model_index(p)>=m->size)
        return MATTER_IM_UNSUPPORTED_ATTRIBUTE;
    if(m->unreadable && p->attribute==4) return MATTER_IM_UNSUPPORTED_READ;
    *a=(Matter_Im_Attribute_T){MATTER_IM_VIEW,false}; return MATTER_IM_SUCCESS;
}
static Matter_Im_Status_T model_allow(void* u,Matter_Exchange_Session_T token,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    ImTestModel* m=u; model_guard(m); ++m->auths; MODEL_CHECK(token && privilege==MATTER_IM_VIEW);
    return m->deny && p->attribute==3 ? MATTER_IM_UNSUPPORTED_ACCESS : MATTER_IM_SUCCESS;
}
static uint32_t model_version_value(ImTestModel* m,const Matter_Im_Path_T* p) {
    return m->override_version ? m->version : 7+p->endpoint*2+p->cluster-0x28;
}
static Matter_Result_T model_version(void* u,const Matter_Im_Path_T* p,uint32_t* v) {
    ImTestModel* m=u; model_guard(m); ++m->versions;
    if(m->version_error) return MATTER_PORT_ERROR;
    *v=m->changing ? 6 : model_version_value(m,p); return MATTER_OK;
}
static Matter_Im_Status_T model_read(void* u,const Matter_Im_Path_T* p,bool fabric_filtered,Matter_Im_Value_T* v) {
    ImTestModel* m=u; model_guard(m); MODEL_CHECK(fabric_filtered); ++m->reads;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=1000+model_index(p),.data_version=model_version_value(m,p)};
    return MATTER_IM_SUCCESS;
}
static Matter_Im_Read_Port_T model_port(ImTestModel* m,bool fast) {
    return (Matter_Im_Read_Port_T){m,model_allow,model_describe,model_read,model_enumerate,fast ? model_version : NULL};
}
static void model_put(ImTestModel* m,Matter_Tlv_Type_T type,int tag,uint64_t value) {
    m->element=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0 ? 0 : 1,.number=tag<0 ? 0 : (uint32_t)tag},.unsigned_value=value};
    MODEL_CHECK(matter_tlv_write(&m->writer,&m->element,0)==MATTER_TLV_OK);
}
static size_t model_request(ImTestModel* m,unsigned mask,Matter_Im_Path_T p,unsigned filters) {
    MODEL_CHECK(filters<=17 && matter_tlv_writer_init(&m->writer,m->input,sizeof(m->input),8)==MATTER_TLV_OK);
    model_put(m,MATTER_TLV_STRUCTURE,-1,0); model_put(m,MATTER_TLV_ARRAY,0,0); model_put(m,MATTER_TLV_LIST,-1,0);
    if(mask&1) model_put(m,MATTER_TLV_UNSIGNED,2,p.endpoint);
    if(mask&2) model_put(m,MATTER_TLV_UNSIGNED,3,p.cluster);
    if(mask&4) model_put(m,MATTER_TLV_UNSIGNED,4,p.attribute);
    model_put(m,MATTER_TLV_END,-1,0); model_put(m,MATTER_TLV_END,-1,0); model_put(m,MATTER_TLV_BOOL,3,1);
    if(filters) {
        model_put(m,MATTER_TLV_ARRAY,4,0);
        for(unsigned i=0;i<filters;++i) {
            model_put(m,MATTER_TLV_STRUCTURE,-1,0); model_put(m,MATTER_TLV_LIST,0,0);
            model_put(m,MATTER_TLV_UNSIGNED,1,m->filters[i].endpoint); model_put(m,MATTER_TLV_UNSIGNED,2,m->filters[i].cluster);
            model_put(m,MATTER_TLV_END,-1,0); model_put(m,MATTER_TLV_UNSIGNED,1,m->filters[i].version);
            model_put(m,MATTER_TLV_END,-1,0);
        }
        model_put(m,MATTER_TLV_END,-1,0);
    }
    model_put(m,MATTER_TLV_UNSIGNED,255,13); model_put(m,MATTER_TLV_END,-1,0);
    size_t n; MODEL_CHECK(matter_tlv_writer_finish(&m->writer,&n)==MATTER_TLV_OK); return n;
}
static void model_process(ImTestModel* m,uint64_t now) {
    for(unsigned i=0;i<128;++i) {
        unsigned enums=m->enumerations, reads=m->reads;
        MODEL_CHECK(matter_im_read_process(m->active,now)==MATTER_PENDING);
        MODEL_CHECK(m->enumerations-enums<=8 && m->reads-reads<=9);
        Matter_Im_Read_State_T state=matter_im_read_state(m->active);
        if(state!=MATTER_IM_READ_EXPANDING && state!=MATTER_IM_READ_COLLECTING) return;
    }
    MODEL_CHECK(false);
}
/* Validate every concrete path/value/version, count only data/status IBs;
 * reader is heap-owned. This intentionally does not use the production decoder. */
static unsigned model_report(ImTestModel* m,const uint8_t* data,size_t n,bool* more,unsigned* errors) {
    MODEL_CHECK(matter_tlv_init(&m->reader,data,n,8)==MATTER_TLV_OK);
    Matter_Im_Path_T path={0}; uint32_t version=0; unsigned count=0, depth=0; *more=false; *errors=0;
    Matter_Tlv_Result_T r;
    while((r=matter_tlv_next(&m->reader,&m->element))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&m->element;
        if(e->type==MATTER_TLV_END) { --depth; continue; }
        if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) { ++depth; continue; }
        if(depth==1 && e->tag.number==3) { MODEL_CHECK(e->type==MATTER_TLV_BOOL); *more=e->unsigned_value!=0; }
        if(depth==4 && e->tag.number==0) version=(uint32_t)e->unsigned_value;
        if(depth==5 && e->tag.number==2) path.endpoint=(uint16_t)e->unsigned_value;
        if(depth==5 && e->tag.number==3) path.cluster=(uint32_t)e->unsigned_value;
        if(depth==5 && e->tag.number==4) path.attribute=(uint32_t)e->unsigned_value;
        if(depth==5 && e->tag.number==0) ++*errors;
        if(depth==4 && e->tag.number==2) {
            MODEL_CHECK(e->type==MATTER_TLV_UNSIGNED && e->unsigned_value==1000+model_index(&path));
            MODEL_CHECK(version==model_version_value(m,&path)); ++count;
        }
    }
    MODEL_CHECK(r==MATTER_TLV_DONE); return count;
}
