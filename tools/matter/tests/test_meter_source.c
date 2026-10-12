#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "clusters/matter_meter_source.h"
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"source:%d: %s\n",__LINE__,#x); exit(1); } } while(0)
#ifdef MATTER_TEST_ALLOC
static size_t live,calls,fail_at;
void* matter_test_calloc(size_t n,size_t z) { if(++calls==fail_at) return NULL; void* p=calloc(n,z); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { CHECK(live); --live; } free(p); }
#endif
typedef struct {
    Matter_Source_Snapshot_T input; Matter_Source_Channel_T channels[64];
    Matter_Result_T result; Matter_Cluster_T handle; bool reenter;
} Fixture;
static Matter_Result_T snapshot(void* u,Matter_Source_Snapshot_T* out) {
    Fixture* f=u;
    if(f->reenter) { bool ready; CHECK(matter_meter_source_refresh(f->handle,100,&ready)==MATTER_BUSY); }
    *out=f->input; return f->result;
}
static int64_t field(Matter_Cluster_T c,unsigned attr,unsigned tag,unsigned occurrence,bool* null) {
    Matter_Cluster_Request_T q={0}; Matter_Im_Value_T v;
    CHECK(matter_cluster_read(c,attr,&q,&v)==MATTER_IM_SUCCESS);
    Matter_Tlv_Reader_T r; Matter_Tlv_Element_T e;
    CHECK(matter_tlv_init(&r,v.data,v.size,4)==MATTER_TLV_OK);
    while(matter_tlv_next(&r,&e)==MATTER_TLV_OK) if(e.tag.control==1 && e.tag.number==tag && !occurrence--) {
        if(null) *null=e.type==MATTER_TLV_NULL;
        return e.type==MATTER_TLV_SIGNED?e.signed_value:(int64_t)e.unsigned_value;
    }
    CHECK(false); return 0;
}
static uint32_t version(Matter_Cluster_T c) { uint32_t v; CHECK(matter_cluster_version(c,&v)==MATTER_OK); return v; }
int main(void) {
    Fixture* f=calloc(1,sizeof(*f)); CHECK(f); f->result=MATTER_OK;
    f->channels[0]=(Matter_Source_Channel_T){.key=3,.group=2,.unit=MATTER_SOURCE_WH,.exponent=-3};
    f->channels[1]=(Matter_Source_Channel_T){.key=4,.group=2,.unit=MATTER_SOURCE_VARH,.exponent=-3};
    Matter_Source_Config_T config={0xfff1,0xfc01,20,1000,f->channels,2}; Matter_Source_Port_T port={f,snapshot};
    CHECK(!matter_meter_source_new(NULL,&config,0)); config.vendor=0; CHECK(!matter_meter_source_new(&port,&config,0));
    config.vendor=0xfff5; CHECK(!matter_meter_source_new(&port,&config,0)); config.vendor=0xfff1;
    config.cluster_suffix=0x90; CHECK(!matter_meter_source_new(&port,&config,0)); config.cluster_suffix=0xfc01;
    f->channels[1].key=3; CHECK(!matter_meter_source_new(&port,&config,0)); f->channels[1].key=4;
#ifdef MATTER_TEST_ALLOC
    for(unsigned i=1;i<=2;++i) { calls=0; fail_at=i; CHECK(!matter_meter_source_new(&port,&config,0) && !live); }
    fail_at=0;
#endif
    f->handle=matter_meter_source_new(&port,&config,0); CHECK(f->handle && matter_cluster_id(f->handle)==0xfff1fc01);
    Matter_Cluster_T other=matter_meter_source_new(&port,&config,0); CHECK(other);
    f->channels[0].key=99; /* constructor copied descriptors */
    CHECK(field(f->handle,2,0,0,NULL)==3 && field(f->handle,1,0,0,NULL)==MATTER_SOURCE_UNAVAILABLE);
    bool null,ready=false; (void)field(f->handle,2,8,0,&null); CHECK(null);
    f->input.generation=4; f->input.sequence=1; f->input.sampled_ms=100; f->input.online=true;
    f->input.values[0]=(Matter_Source_Value_T){12345678000,true,MATTER_SOURCE_MEASURED};
    f->input.values[1]=(Matter_Source_Value_T){-321,true,MATTER_SOURCE_DERIVED};
    f->reenter=true; CHECK(matter_meter_source_refresh(f->handle,100,&ready)==MATTER_OK && !ready); f->reenter=false;
    CHECK(field(f->handle,2,8,0,NULL)==12345678000 && field(f->handle,2,8,1,NULL)==-321 && version(f->handle)==21 && version(other)==20);
    CHECK(matter_meter_source_refresh(f->handle,100,&ready)==MATTER_OK && version(f->handle)==21);
    ++f->input.values[0].value; CHECK(matter_meter_source_refresh(f->handle,101,&ready)==MATTER_PORT_ERROR);
    CHECK(field(f->handle,1,0,0,NULL)==MATTER_SOURCE_INVALID); (void)field(f->handle,2,8,0,&null); CHECK(null);
    --f->input.values[0].value; CHECK(matter_meter_source_refresh(f->handle,102,&ready)==MATTER_OK);
    CHECK(matter_meter_source_refresh(f->handle,1100,&ready)==MATTER_OK && ready && field(f->handle,1,0,0,NULL)==MATTER_SOURCE_STALE);
    ++f->input.sequence; f->input.sampled_ms=1101; f->input.values[1].available=false;
    CHECK(matter_meter_source_refresh(f->handle,1101,&ready)==MATTER_OK);
    CHECK(field(f->handle,2,8,0,NULL)==12345678000); (void)field(f->handle,2,8,1,&null); CHECK(null);
    f->input.sampled_ms=1200; CHECK(matter_meter_source_refresh(f->handle,1102,&ready)==MATTER_PORT_ERROR);
    f->input.sampled_ms=1101; f->input.sequence=0; CHECK(matter_meter_source_refresh(f->handle,1103,&ready)==MATTER_PORT_ERROR);
    f->input.sequence=3; f->input.metadata[0].known=true; f->input.metadata[0].size=2;
    f->input.metadata[0].text[0]=(char)0xc0; f->input.metadata[0].text[1]=(char)0x80;
    CHECK(matter_meter_source_refresh(f->handle,1104,&ready)==MATTER_PORT_ERROR);
    f->input.metadata[0].size=101; CHECK(matter_meter_source_refresh(f->handle,1105,&ready)==MATTER_PORT_ERROR);
    f->input.metadata[0].known=false; f->input.values[0].value=INT64_MAX;
    CHECK(matter_meter_source_refresh(f->handle,1106,&ready)==MATTER_PORT_ERROR);
    f->input.values[0].value=0; f->input.generation=5;
    CHECK(matter_meter_source_refresh(f->handle,1107,&ready)==MATTER_OK && field(f->handle,2,8,0,NULL)==0);
    f->result=MATTER_PORT_ERROR; CHECK(matter_meter_source_refresh(f->handle,1108,&ready)==MATTER_PORT_ERROR);
    CHECK(field(f->handle,2,20,0,NULL)==5); /* last accepted identity, values unavailable */
    CHECK(matter_meter_source_refresh(f->handle,100,&ready)==MATTER_INVALID_ARGUMENT);
    Matter_Im_Write_Attribute_T access; CHECK(matter_cluster_describe_write(f->handle,2,&access)==MATTER_IM_UNSUPPORTED_WRITE);
    CHECK(matter_cluster_delete(f->handle)==MATTER_OK && matter_cluster_delete(other)==MATTER_OK);
#ifdef MATTER_TEST_ALLOC
    CHECK(!live);
#endif
    /* Maximum configured list + metadata sizes: bounded owned buffers, no stack snapshot. */
    memset(&f->input,0,sizeof(f->input)); f->input.online=true; f->input.sampled_ms=1; f->result=MATTER_OK;
    for(unsigned i=0;i<64;++i) { f->channels[i]=(Matter_Source_Channel_T){.group=(uint8_t)(2+i/32),.key=(uint16_t)i,.unit=1,.exponent=-3}; f->input.values[i]=(Matter_Source_Value_T){MATTER_SOURCE_LIMIT,true,3}; }
    for(unsigned i=0;i<10;++i) { f->input.metadata[i].known=true; f->input.metadata[i].size=100; memset(f->input.metadata[i].text,'x',100); }
    config.count=64; f->handle=matter_meter_source_new(&port,&config,0); CHECK(f->handle);
    CHECK(matter_meter_source_refresh(f->handle,1,&ready)==MATTER_OK && field(f->handle,2,8,31,NULL)==MATTER_SOURCE_LIMIT);
    CHECK(matter_cluster_delete(f->handle)==MATTER_OK);
#ifdef MATTER_TEST_ALLOC
    CHECK(!live);
#endif
    int64_t n=37; uint32_t epoch=42;
    CHECK(matter_meter_source_scale(12345.678,-3,&n)==MATTER_OK && n==12345678);
    CHECK(matter_meter_source_scale(-1.25,-1,&n)==MATTER_OK && n==-13);
    CHECK(matter_meter_source_scale(NAN,0,&n)==MATTER_INVALID_ARGUMENT && n==-13);
    CHECK(matter_meter_source_scale(INFINITY,0,&n)==MATTER_INVALID_ARGUMENT && n==-13);
    CHECK(matter_meter_source_scale(1e30,-6,&n)==MATTER_INVALID_ARGUMENT && n==-13);
    CHECK(matter_meter_source_epoch(946684799,&epoch)==MATTER_INVALID_ARGUMENT && epoch==42);
    CHECK(matter_meter_source_epoch(INT64_C(946684800)+UINT32_MAX,&epoch)==MATTER_OK && epoch==UINT32_MAX);
    CHECK(matter_meter_source_epoch(INT64_C(946684801)+UINT32_MAX,&epoch)==MATTER_INVALID_ARGUMENT);
    free(f); puts("PASS meter source: namespace/config, copied descriptors, freshness, atomic errors, replay, UTF8, bounds, conversion, isolation, cleanup/OOM"); return 0;
}
