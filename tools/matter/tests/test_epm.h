#include "test_epm_fixture.h"
#include <math.h>
#include <float.h>
static void epm_value(EpmFixture* f,bool available,int64_t power,uint32_t version) {
    Matter_Im_Value_T v; Matter_Cluster_Request_T q={0}; uint32_t actual;
    ROOT_CHECK(matter_cluster_version(f->cluster,&actual)==MATTER_OK && actual==version);
    ROOT_CHECK(!matter_cluster_read(f->cluster,8,&q,&v)); epm_expect(8,&v,available,power,version);
}
static void epm_tests(void) {
    int64_t converted=19;
    ROOT_CHECK(matter_epm_from_watts(1.25,&converted)==MATTER_OK && converted==1250);
    ROOT_CHECK(matter_epm_from_watts(-1.25,&converted)==MATTER_OK && converted==-1250);
    ROOT_CHECK(matter_epm_from_watts(0.0005,&converted)==MATTER_OK && converted==1);
    ROOT_CHECK(matter_epm_from_watts(-0.0005,&converted)==MATTER_OK && converted==-1);
    ROOT_CHECK(matter_epm_from_watts(0.00049,&converted)==MATTER_OK && !converted);
    ROOT_CHECK(matter_epm_from_watts(-0.0,&converted)==MATTER_OK && !converted);
    const double invalid[]={NAN,INFINITY,-INFINITY,DBL_MAX,-DBL_MAX,1e16,-1e16};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(*invalid);++i) { converted=19; ROOT_CHECK(matter_epm_from_watts(invalid[i],&converted)==MATTER_INVALID_ARGUMENT && converted==19); }
    ROOT_CHECK(matter_epm_from_watts(1,NULL)==MATTER_INVALID_ARGUMENT);
    EpmFixture* f=epm_fixture(); bool ready; Matter_Cluster_Request_T q={0}; Matter_Im_Value_T v;
    Matter_Epm_Port_T port={f,epm_sample};
    ROOT_CHECK(!matter_epm_new(NULL,&f->config,0) && !matter_epm_new(&port,NULL,0));
    Matter_Epm_Config_T* bad=malloc(sizeof(*bad)); ROOT_CHECK(bad);
    for(unsigned mode=0;mode<9;++mode) {
        *bad=f->config;
        switch(mode) {
        case 0: bad->range_count=0; break; case 1: bad->range_count=5; break;
        case 2: bad->max_age_ms=0; break; case 3: bad->ranges[0].min_mw=-MATTER_EPM_LIMIT-1; break;
        case 4: bad->ranges[0].max_mw=MATTER_EPM_LIMIT+1; break; case 5: bad->ranges[0].max_mw=-2000; break;
        case 6: bad->ranges[0].fields=0; break; case 7: bad->ranges[0].percent_max=10001; break;
        case 8: bad->ranges[0].fixed_max_mw=MATTER_EPM_LIMIT; break;
        }
        ROOT_CHECK(!matter_epm_new(&port,bad,0));
    }
    *bad=f->config; bad->range_count=2; bad->ranges[1]=bad->ranges[0];
    bad->ranges[1].min_mw=2002; bad->ranges[1].max_mw=3000; ROOT_CHECK(!matter_epm_new(&port,bad,0));
#ifdef MATTER_TEST_ALLOC
    size_t baseline=live;
    for(unsigned i=1;i<=2;++i) { fail_at=calls+i; ROOT_CHECK(!epm_create(f,0)); fail_at=0; ROOT_CHECK(live==baseline); }
#endif
    f->cluster=epm_create(f,0); ROOT_CHECK(f->cluster && !f->calls); f->reenter=true;
    for(unsigned i=0;i<9;++i) {
        uint32_t id; Matter_Im_Attribute_T meta;
        ROOT_CHECK(matter_cluster_attribute_at(f->cluster,i,&id) && id==epm_ids[i]);
        ROOT_CHECK(!matter_cluster_describe(f->cluster,id,&meta) && meta.privilege==MATTER_IM_VIEW && !meta.fabric_scoped);
        ROOT_CHECK(!matter_cluster_read(f->cluster,id,&q,&v)); epm_expect(id,&v,false,0,100);
    }
    Matter_Im_Write_Attribute_T write; Matter_Im_Command_T command;
    ROOT_CHECK(matter_cluster_describe_write(f->cluster,8,&write)==MATTER_IM_UNSUPPORTED_WRITE &&
        matter_cluster_command(f->cluster,0,&command)==MATTER_IM_UNSUPPORTED_COMMAND);
    ROOT_CHECK(matter_cluster_read(f->cluster,3,&q,&v)==MATTER_IM_UNSUPPORTED_ATTRIBUTE);
    f->sample=(Matter_Epm_Sample_T){1000,0,true};
    ROOT_CHECK(matter_epm_refresh(f->cluster,0,&ready)==MATTER_OK && !ready); epm_value(f,true,1000,101);
    f->sample.active_mw=-1000;
    ROOT_CHECK(matter_epm_refresh(f->cluster,999,&ready)==MATTER_OK && !ready); epm_value(f,true,-1000,102);
    ROOT_CHECK(matter_epm_refresh(f->cluster,1000,&ready)==MATTER_OK && ready);
    f->sample.sampled_ms=1000; ROOT_CHECK(matter_epm_refresh(f->cluster,1500,&ready)==MATTER_OK && !ready); epm_value(f,true,-1000,102);
    f->sample.active_mw=0; ROOT_CHECK(matter_epm_refresh(f->cluster,1999,&ready)==MATTER_OK && !ready); epm_value(f,true,0,103);
    ROOT_CHECK(matter_epm_refresh(f->cluster,2000,&ready)==MATTER_OK && ready);
    ROOT_CHECK(matter_epm_refresh(f->cluster,3999,&ready)==MATTER_OK && !ready); epm_value(f,true,0,103);
    ROOT_CHECK(matter_epm_refresh(f->cluster,4000,&ready)==MATTER_OK && ready); epm_value(f,false,0,104);
    ROOT_CHECK(matter_epm_refresh(f->cluster,4001,&ready)==MATTER_OK && !ready); epm_value(f,false,0,104);
    f->sample.sampled_ms=5000; ROOT_CHECK(matter_epm_refresh(f->cluster,5000,&ready)==MATTER_OK && ready); epm_value(f,true,0,105);
    f->error=MATTER_PORT_ERROR; ROOT_CHECK(matter_epm_refresh(f->cluster,6000,&ready)==MATTER_PORT_ERROR && ready); epm_value(f,false,0,106);
    f->error=MATTER_OK; f->sample.sampled_ms=7001; ROOT_CHECK(matter_epm_refresh(f->cluster,7000,&ready)==MATTER_PORT_ERROR && !ready);
    f->sample.sampled_ms=7000; f->sample.active_mw=2001; ROOT_CHECK(matter_epm_refresh(f->cluster,7000,&ready)==MATTER_PORT_ERROR); epm_value(f,false,0,106);
    f->sample.available=false; ROOT_CHECK(matter_epm_refresh(f->cluster,7000,&ready)==MATTER_OK); epm_value(f,false,0,106);
    unsigned callbacks=f->calls; ready=true;
    ROOT_CHECK(matter_epm_refresh(f->cluster,6999,&ready)==MATTER_INVALID_ARGUMENT && ready && f->calls==callbacks);
    ROOT_CHECK(matter_epm_refresh(f->cluster,7000,NULL)==MATTER_INVALID_ARGUMENT && f->calls==callbacks);
    ROOT_CHECK(matter_cluster_delete(f->cluster)==MATTER_OK);
    /* Inclusive protocol bounds, version wrap, timestamp overflow and four ranges. */
    f->config.ranges[0].min_mw=-MATTER_EPM_LIMIT; f->config.ranges[0].max_mw=MATTER_EPM_LIMIT;
    f->config.data_version=UINT32_MAX; f->config.polyphase=false; f->cluster=epm_create(f,UINT64_MAX-2000); ROOT_CHECK(f->cluster);
    f->sample=(Matter_Epm_Sample_T){-MATTER_EPM_LIMIT,UINT64_MAX-2000,true};
    ROOT_CHECK(matter_epm_refresh(f->cluster,UINT64_MAX-2000,&ready)==MATTER_OK); epm_value(f,true,-MATTER_EPM_LIMIT,0);
    f->sample.active_mw=MATTER_EPM_LIMIT;
    ROOT_CHECK(matter_epm_refresh(f->cluster,UINT64_MAX,&ready)==MATTER_OK && ready); epm_value(f,true,MATTER_EPM_LIMIT,1);
    ROOT_CHECK(!matter_cluster_read(f->cluster,0xfffc,&q,&v) && v.unsigned_value==2);
    ROOT_CHECK(matter_cluster_delete(f->cluster)==MATTER_OK);
    f->config.range_count=4;
    for(unsigned i=0;i<4;++i) f->config.ranges[i]=(Matter_Epm_Accuracy_Range_T){.min_mw=-4000+2000*(int64_t)i,.max_mw=-2001+2000*(int64_t)i,.fields=2,.fixed_max_mw=MATTER_EPM_LIMIT-1};
    f->cluster=epm_create(f,0); Matter_Cluster_T other=epm_create(f,0); ROOT_CHECK(f->cluster && other);
    f->sample=(Matter_Epm_Sample_T){9,0,true}; ROOT_CHECK(matter_epm_refresh(f->cluster,0,&ready)==MATTER_OK);
    ROOT_CHECK(!matter_cluster_read(other,8,&q,&v) && v.type==MATTER_TLV_NULL && v.data_version==UINT32_MAX);
    ROOT_CHECK(matter_cluster_retain(f->cluster)==MATTER_OK && matter_cluster_delete(f->cluster)==MATTER_BUSY && matter_cluster_release(f->cluster)==MATTER_OK);
    ROOT_CHECK(matter_cluster_delete(f->cluster)==MATTER_OK && matter_cluster_delete(other)==MATTER_OK);
    free(bad); free(f);
#ifdef MATTER_TEST_ALLOC
    ROOT_CHECK(!live);
#endif
    puts("PASS EPM: literal Accuracy/globals, AC/POLY, signed mW/null, stale/error/recovery, report cadence, boundaries/version wrap, instances/reentry/pins and OOM");
}
