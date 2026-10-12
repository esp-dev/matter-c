#include "test_eem_fixture.h"
static void eem_value(EemFixture* f,bool available,int64_t imported,int64_t exported,uint64_t sampled,bool utc,uint32_t epoch) {
    Matter_Cluster_Request_T q={0}; Matter_Im_Value_T v;
    for(unsigned i=0;i<2;++i) {
        ROOT_CHECK(!matter_cluster_read(f->cluster,i+1,&q,&v) && v.type==(available?MATTER_TLV_STRUCTURE:MATTER_TLV_NULL));
        if(available) eem_measurement(v.data,v.size,i?exported:imported,sampled,utc,epoch);
    }
}
static void eem_tests(void) {
    int64_t n=19;
    ROOT_CHECK(matter_eem_from_kwh(1.25,&n)==MATTER_OK && n==1250000);
    ROOT_CHECK(matter_eem_from_kwh(0.0000005,&n)==MATTER_OK && n==1);
    ROOT_CHECK(matter_eem_from_kwh(0.00000049,&n)==MATTER_OK && n==0);
    const double bad[]={NAN,INFINITY,-INFINITY,-1,1e14};
    for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);++i) { n=19; ROOT_CHECK(matter_eem_from_kwh(bad[i],&n)==MATTER_INVALID_ARGUMENT && n==19); }
    ROOT_CHECK(matter_eem_from_kwh(0,NULL)==MATTER_INVALID_ARGUMENT);
    EemFixture* f=eem_fixture(); bool ready; Matter_Im_Value_T v; Matter_Cluster_Request_T q={0};
#ifdef MATTER_TEST_ALLOC
    size_t base=live;
    for(unsigned i=1;i<=2;++i) { fail_at=calls+i; ROOT_CHECK(!eem_create(f,0)); fail_at=0; ROOT_CHECK(live==base); }
    fail_at=calls+1; ROOT_CHECK(!eem_log(f)); fail_at=0; ROOT_CHECK(live==base);
#endif
    f->fail_load=true; ROOT_CHECK(!eem_create(f,0) && !eem_log(f)); f->fail_load=false;
    f->durable.total_mwh[0]=-1; ROOT_CHECK(!eem_create(f,0)); f->durable.total_mwh[0]=0;
    f->config.percent_max=10001; ROOT_CHECK(!eem_create(f,0)); f->config.percent_max=100;
    f->config.fixed_max_mwh=MATTER_EEM_LIMIT; ROOT_CHECK(!eem_create(f,0)); f->config.fixed_max_mwh=5;
    f->config.max_age_ms=0; ROOT_CHECK(!eem_create(f,0)); f->config.max_age_ms=3000;
    f->cluster=eem_create(f,0); ROOT_CHECK(f->cluster && !f->samples); f->reenter=true;
    ROOT_CHECK(matter_cluster_attribute_count(f->cluster)==8);
    const Matter_Event_Def_T* event=matter_cluster_event(f->cluster,0);
    ROOT_CHECK(event && event->priority==1 && event->privilege==MATTER_IM_VIEW && !event->fabric_scoped && !matter_cluster_event(f->cluster,1));
    ROOT_CHECK(!matter_cluster_read(f->cluster,0,&q,&v) && v.type==MATTER_TLV_STRUCTURE && v.size==sizeof(eem_accuracy) && !memcmp(v.data,eem_accuracy,sizeof(eem_accuracy)));
    ROOT_CHECK(!matter_cluster_read(f->cluster,0xfffc,&q,&v) && v.unsigned_value==7);
    ROOT_CHECK(!matter_cluster_read(f->cluster,0xfffd,&q,&v) && v.unsigned_value==2);
    eem_value(f,false,0,0,0,false,0);
    f->sample=(Matter_Eem_Sample_T){.raw_mwh={1000000,2000000},.generation=1,.available=true};
    ROOT_CHECK(matter_eem_refresh(f->cluster,0,&ready)==MATTER_OK && ready); eem_value(f,true,0,0,0,false,0);
    ROOT_CHECK(f->stores==1 && f->event_stores==1 && f->highwater==32);
    f->sample.raw_mwh[0]+=1250; f->sample.raw_mwh[1]+=500; f->sample.sampled_ms=999;
    ROOT_CHECK(matter_eem_refresh(f->cluster,999,&ready)==MATTER_OK && !ready && f->stores==1); eem_value(f,true,0,0,0,false,0);
    f->sample.sampled_ms=1000;
    ROOT_CHECK(matter_eem_refresh(f->cluster,1000,&ready)==MATTER_OK && ready); eem_value(f,true,1250,500,1000,false,0);
    static const uint8_t imported[]={0x15,0x21,0,0xe2,4,0x25,4,0xe8,3,0x18};
    ROOT_CHECK(!matter_cluster_read(f->cluster,1,&q,&v) && v.size==sizeof(imported) && !memcmp(v.data,imported,sizeof(imported)));
    uint32_t dv; ROOT_CHECK(matter_cluster_version(f->cluster,&dv)==MATTER_OK && dv==102);
    ROOT_CHECK(matter_eem_refresh(f->cluster,2000,&ready)==MATTER_OK && !ready && f->stores==2);
    ROOT_CHECK(matter_eem_refresh(f->cluster,4000,&ready)==MATTER_OK && ready); eem_value(f,false,0,0,0,false,0);
    f->sample.sampled_ms=5000; f->sample.utc_known=true; f->sample.epoch_s=100;
    ROOT_CHECK(matter_eem_refresh(f->cluster,5000,&ready)==MATTER_OK && ready && f->stores==2); eem_value(f,true,1250,500,5000,true,100);
    f->fail_sample=true; ROOT_CHECK(matter_eem_refresh(f->cluster,6000,&ready)==MATTER_PORT_ERROR && ready); eem_value(f,false,0,0,0,false,0); f->fail_sample=false;
    f->sample.sampled_ms=7001; ROOT_CHECK(matter_eem_refresh(f->cluster,7000,&ready)==MATTER_PORT_ERROR);
    f->sample.sampled_ms=7000; f->sample.raw_mwh[0]--;
    ROOT_CHECK(matter_eem_refresh(f->cluster,7000,&ready)==MATTER_PORT_ERROR && f->durable.total_mwh[0]==1250); eem_value(f,false,0,0,0,false,0);
    f->sample.raw_mwh[0]+=501; f->sample.raw_mwh[1]+=200; f->fail_store=true;
    ROOT_CHECK(matter_eem_refresh(f->cluster,8000,&ready)==MATTER_PORT_ERROR && f->durable.total_mwh[0]==1250); f->fail_store=false;
    ROOT_CHECK(matter_eem_refresh(f->cluster,8000,&ready)==MATTER_OK && ready); eem_value(f,true,1750,700,7000,true,100);
    unsigned samples=f->samples; ready=true;
    ROOT_CHECK(matter_eem_refresh(f->cluster,7999,&ready)==MATTER_INVALID_ARGUMENT && ready && f->samples==samples);
    ROOT_CHECK(matter_cluster_retain(f->cluster)==MATTER_OK && matter_cluster_delete(f->cluster)==MATTER_BUSY && matter_cluster_release(f->cluster)==MATTER_OK);
    /* Restart both objects with durable application state, boot clock resets. */
    ROOT_CHECK(matter_cluster_delete(f->cluster)==MATTER_OK && matter_events_delete(f->config.events)==MATTER_OK);
    f->config.events=eem_log(f); f->cluster=eem_create(f,0); ROOT_CHECK(f->cluster); f->sample.sampled_ms=0;
    f->fail_events=true; ROOT_CHECK(matter_eem_refresh(f->cluster,0,&ready)==MATTER_PORT_ERROR); eem_value(f,false,0,0,0,false,0);
    f->fail_events=false; ROOT_CHECK(matter_eem_refresh(f->cluster,0,&ready)==MATTER_OK && ready); eem_value(f,true,1750,700,0,true,100);
    Matter_Event_Record_T* records=calloc(MATTER_EVENTS_CAPACITY,sizeof(*records)); ROOT_CHECK(records); size_t count;
    Matter_Event_Path_T path={1,0x91,0}; ROOT_CHECK(matter_events_copy(f->config.events,&path,0,records,&count)==MATTER_OK && count==1 && records[0].number==32);
    f->sample.generation=2; f->sample.raw_mwh[0]=999999999; f->sample.raw_mwh[1]=0; f->sample.sampled_ms=1000;
    ROOT_CHECK(matter_eem_refresh(f->cluster,1000,&ready)==MATTER_OK && ready); eem_value(f,true,1750,700,1000,true,100);
    f->sample.generation=1; f->sample.sampled_ms=2000;
    ROOT_CHECK(matter_eem_refresh(f->cluster,2000,&ready)==MATTER_PORT_ERROR && f->durable.generation==2);
    f->sample.generation=2; f->sample.raw_mwh[0]=-1;
    ROOT_CHECK(matter_eem_refresh(f->cluster,3000,&ready)==MATTER_PORT_ERROR);
    f->sample.raw_mwh[0]=MATTER_EEM_LIMIT+1;
    ROOT_CHECK(matter_eem_refresh(f->cluster,4000,&ready)==MATTER_PORT_ERROR);
    eem_free(f);
    /* Inclusive upper bound, checkpoint corruption, overflow and version wrap. */
    f=eem_fixture(); f->config.data_version=UINT32_MAX;
    f->durable=(Matter_Eem_Checkpoint_T){.initialized=true,.generation=1,.total_mwh={MATTER_EEM_LIMIT-1,0}};
    f->cluster=eem_create(f,0); ROOT_CHECK(f->cluster);
    f->sample=(Matter_Eem_Sample_T){.available=true,.generation=1,.raw_mwh={1,1}};
    ROOT_CHECK(matter_eem_refresh(f->cluster,0,&ready)==MATTER_OK); eem_value(f,true,MATTER_EEM_LIMIT,1,0,false,0);
    ROOT_CHECK(matter_cluster_version(f->cluster,&dv)==MATTER_OK && !dv);
    f->sample.raw_mwh[0]=2; f->sample.sampled_ms=1000;
    ROOT_CHECK(matter_eem_refresh(f->cluster,1000,&ready)==MATTER_PORT_ERROR && f->durable.raw_mwh[0]==1);
    eem_free(f); free(records);
#ifdef MATTER_TEST_ALLOC
    ROOT_CHECK(!live);
#endif
    puts("PASS EEM: literal signed mWh/Accuracy, UTC/system time, baseline/deltas, stale/null, atomic checkpoint failure, restart/source generation, overflow, cadence, OOM/reentry");
}
