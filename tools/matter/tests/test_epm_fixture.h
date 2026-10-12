#include "clusters/matter_epm.h"
typedef struct {
    Matter_Epm_Config_T config; Matter_Epm_Sample_T sample;
    Matter_Cluster_T cluster; Matter_Result_T error; unsigned calls; bool reenter;
} EpmFixture;
static Matter_Result_T epm_sample(void* u,Matter_Epm_Sample_T* sample) {
    EpmFixture* f=u; ++f->calls;
    if(f->reenter) {
        bool ready; Matter_Im_Value_T v; Matter_Cluster_Request_T q={0}; uint32_t version;
        ROOT_CHECK(matter_epm_refresh(f->cluster,0,&ready)==MATTER_BUSY && matter_cluster_delete(f->cluster)==MATTER_BUSY);
        ROOT_CHECK(matter_cluster_version(f->cluster,&version)==MATTER_BUSY && matter_cluster_read(f->cluster,8,&q,&v)==MATTER_IM_FAILURE);
    }
    *sample=f->sample; return f->error;
}
static EpmFixture* epm_fixture(void) {
    EpmFixture* f=calloc(1,sizeof(*f)); ROOT_CHECK(f);
    f->config=(Matter_Epm_Config_T){.range_count=1,.measured=true,.polyphase=true,.data_version=100,.max_age_ms=3000,
        .ranges={{.min_mw=-2000,.max_mw=2000,.fixed_max_mw=5,.percent_max=100,.fields=3}}};
    return f;
}
static Matter_Cluster_T epm_create(EpmFixture* f,uint64_t now) { Matter_Epm_Port_T p={f,epm_sample}; return matter_epm_new(&p,&f->config,now); }
static const uint32_t epm_ids[]={0,1,2,8,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
static const uint8_t epm_accuracy[]={0x16,0x15,0x24,0,5,0x29,1,0x21,2,0x30,0xf8,0x21,3,0xd0,7,
    0x36,4,0x15,0x21,0,0x30,0xf8,0x21,1,0xd0,7,0x24,2,100,0x24,5,5,0x18,0x18,0x18,0x18};
static const uint8_t epm_attributes[]={0x16,4,0,4,1,4,2,4,8,5,0xf8,0xff,5,0xf9,0xff,5,0xfb,0xff,5,0xfc,0xff,5,0xfd,0xff,0x18};
static void epm_expect(uint32_t attr,const Matter_Im_Value_T* v,bool available,int64_t power,uint32_t version) {
    ROOT_CHECK(v->data_version==version);
    if(attr==8) { ROOT_CHECK(v->type==(available?MATTER_TLV_SIGNED:MATTER_TLV_NULL) && (!available || v->signed_value==power)); return; }
    if(attr==2 || attr==0xfffb || attr==0xfff8 || attr==0xfff9) {
        static const uint8_t empty[]={0x16,0x18}; const uint8_t* bytes=attr==2?epm_accuracy:attr==0xfffb?epm_attributes:empty;
        size_t size=attr==2?sizeof(epm_accuracy):attr==0xfffb?sizeof(epm_attributes):sizeof(empty);
        ROOT_CHECK(v->type==MATTER_TLV_ARRAY && v->size==size && !memcmp(v->data,bytes,size)); return;
    }
    ROOT_CHECK(v->type==MATTER_TLV_UNSIGNED && v->unsigned_value==(attr==0?2:attr==1?1:attr==0xfffc?6:3));
}
