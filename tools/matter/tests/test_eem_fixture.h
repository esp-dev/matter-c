#include "clusters/matter_eem.h"
typedef struct {
    Matter_Eem_Config_T config; Matter_Eem_Sample_T sample; Matter_Eem_Checkpoint_T durable;
    Matter_Cluster_T cluster; uint64_t highwater; unsigned samples,stores,event_stores;
    bool fail_sample,fail_load,fail_store,fail_events,reenter;
} EemFixture;
static Matter_Result_T eem_sample(void* u,Matter_Eem_Sample_T* out) {
    EemFixture* f=u; ++f->samples;
    if(f->reenter) {
        bool ready; uint32_t version; Matter_Im_Value_T v; Matter_Cluster_Request_T q={0};
        ROOT_CHECK(matter_eem_refresh(f->cluster,0,&ready)==MATTER_BUSY && matter_cluster_delete(f->cluster)==MATTER_BUSY);
        ROOT_CHECK(matter_cluster_version(f->cluster,&version)==MATTER_BUSY && matter_cluster_read(f->cluster,1,&q,&v)==MATTER_IM_FAILURE);
    }
    *out=f->sample; return f->fail_sample?MATTER_PORT_ERROR:MATTER_OK;
}
static Matter_Result_T eem_load(void* u,Matter_Eem_Checkpoint_T* out) { EemFixture* f=u; *out=f->durable; return f->fail_load?MATTER_PORT_ERROR:MATTER_OK; }
static Matter_Result_T eem_store(void* u,const Matter_Eem_Checkpoint_T* v) { EemFixture* f=u; if(f->fail_store) return MATTER_PORT_ERROR; f->durable=*v; ++f->stores; return MATTER_OK; }
static Matter_Result_T eem_event_load(void* u,uint64_t* n) { EemFixture* f=u; *n=f->highwater; return f->fail_load?MATTER_PORT_ERROR:MATTER_OK; }
static Matter_Result_T eem_event_store(void* u,uint64_t n) { EemFixture* f=u; if(f->fail_events) return MATTER_PORT_ERROR; f->highwater=n; ++f->event_stores; return MATTER_OK; }
static Matter_Events_T eem_log(EemFixture* f) { Matter_Events_Port_T p={f,eem_event_load,eem_event_store}; return matter_events_new(&p); }
static Matter_Cluster_T eem_create(EemFixture* f,uint64_t now) { Matter_Eem_Port_T p={f,eem_sample,eem_load,eem_store}; return matter_eem_new(&p,&f->config,now); }
static EemFixture* eem_fixture(void) {
    EemFixture* f=calloc(1,sizeof(*f)); ROOT_CHECK(f);
    f->config=(Matter_Eem_Config_T){.endpoint=1,.percent_max=100,.fixed_max_mwh=5,.data_version=100,.max_age_ms=3000,.measured=true};
    f->config.events=eem_log(f); ROOT_CHECK(f->config.events); return f;
}
static void eem_free(EemFixture* f) {
    ROOT_CHECK(matter_cluster_delete(f->cluster)==MATTER_OK && matter_events_delete(f->config.events)==MATTER_OK); free(f);
}
static const uint8_t eem_accuracy[]={0x15,0x24,0,14,0x29,1,0x20,2,0,0x23,3,0,0,0,0,0,0,0,0x40,
    0x36,4,0x15,0x20,0,0,0x23,1,0,0,0,0,0,0,0,0x40,0x24,2,100,0x24,5,5,0x18,0x18,0x18};
/* Independent schema decoder: disallow unsigned Energy, period start fields,
 * extraneous fields, wrong time base widths and missing observation time. */
static void eem_measurement(const uint8_t* data,size_t size,int64_t energy,uint64_t sampled,bool utc,uint32_t epoch) {
    Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T e; unsigned seen=0;
    ROOT_CHECK(matter_tlv_init(&reader,data,size,2)==MATTER_TLV_OK && matter_tlv_next(&reader,&e)==MATTER_TLV_OK && e.type==MATTER_TLV_STRUCTURE);
    while(matter_tlv_next(&reader,&e)==MATTER_TLV_OK && e.type!=MATTER_TLV_END) {
        ROOT_CHECK(e.tag.control==1 && (e.tag.number==0 || e.tag.number==2 || e.tag.number==4));
        unsigned bit=1u<<e.tag.number; ROOT_CHECK(!(seen&bit)); seen|=bit;
        if(!e.tag.number) ROOT_CHECK(e.type==MATTER_TLV_SIGNED && e.signed_value==energy);
        if(e.tag.number==2) ROOT_CHECK(utc && e.type==MATTER_TLV_UNSIGNED && e.unsigned_value==epoch);
        if(e.tag.number==4) ROOT_CHECK(e.type==MATTER_TLV_UNSIGNED && e.unsigned_value==sampled);
    }
    ROOT_CHECK(seen==(utc?21u:17u) && e.type==MATTER_TLV_END && matter_tlv_next(&reader,&e)==MATTER_TLV_DONE);
}
