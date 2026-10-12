#include "clusters/matter_power_topology.h"
static void power_array(RootFixture* f,uint16_t ep,uint32_t cluster,uint32_t attr,const uint8_t* bytes,size_t n,uint32_t version) {
    Matter_Im_Path_T path={ep,cluster,attr}; Matter_Im_Value_T value;
    ROOT_CHECK(!f->read.read(f->read.user,&path,true,&value) && value.type==MATTER_TLV_ARRAY && value.size==n &&
        !memcmp(value.data,bytes,n) && value.data_version==version);
}
static Matter_Result_T power_test_version(void* u,uint32_t* v) { (void)u; *v=1; return MATTER_OK; }
static void power_tests(void) {
    RootFixture* f=root_fixture(); RootFixture* other=root_fixture(); root_open(f); root_open(other);
    Matter_Root_Endpoint_Config_T config={1,1,0x0510,41};
    ROOT_CHECK(matter_root_add_endpoint(NULL,&config)==MATTER_INVALID_ARGUMENT && matter_root_add_endpoint(f->root,NULL)==MATTER_INVALID_ARGUMENT);
    config.endpoint=0; ROOT_CHECK(matter_root_add_endpoint(f->root,&config)==MATTER_INVALID_ARGUMENT);
    config.endpoint=65535; ROOT_CHECK(matter_root_add_endpoint(f->root,&config)==MATTER_INVALID_ARGUMENT);
    config.endpoint=1; config.revision=0; ROOT_CHECK(matter_root_add_endpoint(f->root,&config)==MATTER_INVALID_ARGUMENT); config.revision=1;
#ifdef MATTER_TEST_ALLOC
    size_t baseline=live;
    for(unsigned i=1;i<=2;++i) {
        fail_at=calls+i; ROOT_CHECK(matter_root_add_endpoint(f->root,&config)==MATTER_LIMIT_REACHED); fail_at=0;
        ROOT_CHECK(live==baseline && !matter_root_cluster_at(f->root,1,0x1d));
        power_array(f,0,0x1d,3,(const uint8_t[]){0x16,0x18},2,11);
    }
    for(unsigned i=1;i<=2;++i) { fail_at=calls+i; ROOT_CHECK(!matter_power_topology_new(50)); fail_at=0; ROOT_CHECK(live==baseline); }
#endif
    ROOT_CHECK(matter_root_add_endpoint(f->root,&config)==MATTER_OK && matter_root_add_endpoint(f->root,&config)==MATTER_INVALID_STATE);
    Matter_Cluster_T power=matter_power_topology_new(50),second=matter_power_topology_new(99); ROOT_CHECK(power && second);
    ROOT_CHECK(matter_root_attach_cluster_at(f->root,2,power)==MATTER_INVALID_ARGUMENT);
    ROOT_CHECK(matter_root_attach_cluster_at(f->root,1,power)==MATTER_OK && matter_root_attach_cluster_at(f->root,1,second)==MATTER_INVALID_STATE);
    ROOT_CHECK(!matter_root_cluster(f->root,0x9c) && matter_root_cluster_at(f->root,1,0x9c)==power && matter_cluster_delete(power)==MATTER_BUSY);
    ROOT_CHECK(matter_root_cluster_at(f->root,0,0x1d)==matter_root_cluster(f->root,0x1d) && !matter_root_cluster_at(other->root,1,0x1d));
    power_array(f,0,0x1d,3,(const uint8_t[]){0x16,4,1,0x18},4,12);
    power_array(f,0,0x1d,1,(const uint8_t[]){0x16,4,0x1d,4,0x28,0x18},6,12);
    power_array(f,1,0x1d,0,(const uint8_t[]){0x16,0x15,0x25,0,0x10,5,0x24,1,1,0x18,0x18},11,42);
    power_array(f,1,0x1d,1,(const uint8_t[]){0x16,4,0x1d,4,0x9c,0x18},6,42);
    power_array(f,1,0x1d,2,(const uint8_t[]){0x16,0x18},2,42);
    power_array(f,1,0x1d,3,(const uint8_t[]){0x16,0x18},2,42);
    power_array(f,1,0x9c,0xfff8,(const uint8_t[]){0x16,0x18},2,50);
    power_array(f,1,0x9c,0xfff9,(const uint8_t[]){0x16,0x18},2,50);
    power_array(f,1,0x9c,0xfffb,(const uint8_t[]){0x16,5,0xf8,0xff,5,0xf9,0xff,5,0xfb,0xff,5,0xfc,0xff,5,0xfd,0xff,0x18},17,50);
    Matter_Cluster_Request_T q={0}; Matter_Im_Value_T value; Matter_Im_Attribute_T attr;
    ROOT_CHECK(!matter_cluster_read(power,0xfffc,&q,&value) && value.unsigned_value==2 && value.data_version==50);
    ROOT_CHECK(!matter_cluster_read(second,0xfffc,&q,&value) && value.unsigned_value==2 && value.data_version==99);
    ROOT_CHECK(!matter_cluster_read(power,0xfffd,&q,&value) && value.unsigned_value==1);
    for(unsigned a=0;a<2;++a) ROOT_CHECK(matter_cluster_read(power,a,&q,&value)==MATTER_IM_UNSUPPORTED_ATTRIBUTE);
    ROOT_CHECK(!matter_cluster_describe(power,0xfffc,&attr) && attr.privilege==MATTER_IM_VIEW && !attr.fabric_scoped);
    Matter_Im_Write_Attribute_T writable; Matter_Im_Command_T command;
    ROOT_CHECK(matter_cluster_describe_write(power,0xfffc,&writable)==MATTER_IM_UNSUPPORTED_WRITE);
    Matter_Root_Invoke_Binding_T binding; Matter_Im_Invoke_Port_T invoke;
    ROOT_CHECK(matter_root_invoke_port(f->root,1,&binding,&invoke)==MATTER_OK);
    ROOT_CHECK(invoke.describe(invoke.user,&(Matter_Im_Command_Path_T){1,0x9c,0},&command)==MATTER_IM_UNSUPPORTED_COMMAND);
    ROOT_CHECK(invoke.describe(invoke.user,&(Matter_Im_Command_Path_T){2,0x9c,0},&command)==MATTER_IM_UNSUPPORTED_ENDPOINT);
    ROOT_CHECK(f->read.describe(f->read.user,&(Matter_Im_Path_T){1,0x9c,0},&attr)==MATTER_IM_UNSUPPORTED_ATTRIBUTE);
    ROOT_CHECK(f->read.describe(f->read.user,&(Matter_Im_Path_T){0,0x9c,0xfffc},&attr)==MATTER_IM_UNSUPPORTED_CLUSTER);
    ROOT_CHECK(f->read.describe(f->read.user,&(Matter_Im_Path_T){2,0x9c,0xfffc},&attr)==MATTER_IM_UNSUPPORTED_ENDPOINT);
    /* Out-of-order, nontrivial endpoint IDs exercise the generic registry. */
    config.endpoint=9; config.data_version=60; ROOT_CHECK(matter_root_add_endpoint(f->root,&config)==MATTER_OK);
    config.endpoint=2; config.data_version=70; ROOT_CHECK(matter_root_add_endpoint(f->root,&config)==MATTER_OK);
    ROOT_CHECK(matter_root_attach_cluster_at(f->root,2,second)==MATTER_OK);
    Matter_Im_Selector_T selector={0}; Matter_Im_Path_T path={0},previous={0}; bool found; unsigned count=0;
    while(f->read.enumerate(f->read.user,&selector,count?&path:NULL,&path,&found)==MATTER_OK && found) {
        ROOT_CHECK(!count || path.endpoint>previous.endpoint || (path.endpoint==previous.endpoint &&
            (path.cluster>previous.cluster || (path.cluster==previous.cluster && path.attribute>previous.attribute))));
        previous=path; ++count;
    }
    ROOT_CHECK(count==67 && path.endpoint==9);
    selector=(Matter_Im_Selector_T){.present=MATTER_IM_ENDPOINT,.path={1,0,0}}; count=0;
    while(f->read.enumerate(f->read.user,&selector,count?&path:NULL,&path,&found)==MATTER_OK && found) { ROOT_CHECK(path.endpoint==1); ++count; }
    ROOT_CHECK(count==14);
    Matter_Cluster_T desc=matter_root_cluster_at(f->root,1,0x1d);
    ROOT_CHECK(matter_cluster_retain(desc)==MATTER_OK && matter_root_delete(f->root)==MATTER_BUSY && matter_cluster_delete(power)==MATTER_BUSY);
    ROOT_CHECK(matter_cluster_release(desc)==MATTER_OK);
    /* Capacity errors must neither pin a rejected cluster nor change its lists. */
    Matter_Cluster_T* extras=calloc(15,sizeof(*extras)); ROOT_CHECK(extras);
    for(unsigned i=0;i<15;++i) {
        Matter_Cluster_Config_T c={.id=0xfff10000+i,.callbacks={.version=power_test_version}};
        extras[i]=matter_cluster_new(&c); ROOT_CHECK(extras[i]);
        ROOT_CHECK(matter_root_attach_cluster_at(f->root,1,extras[i])==(i<14?MATTER_OK:MATTER_LIMIT_REACHED));
    }
    for(unsigned i=3;i<8;++i) { config.endpoint=(uint16_t)i; ROOT_CHECK(matter_root_add_endpoint(f->root,&config)==MATTER_OK); }
    config.endpoint=8; ROOT_CHECK(matter_root_add_endpoint(f->root,&config)==MATTER_LIMIT_REACHED);
    root_release(f); root_release(other);
    ROOT_CHECK(matter_cluster_delete(power)==MATTER_OK && matter_cluster_delete(second)==MATTER_OK);
    for(unsigned i=0;i<15;++i) ROOT_CHECK(matter_cluster_delete(extras[i])==MATTER_OK);
    free(extras);
#ifdef MATTER_TEST_ALLOC
    ROOT_CHECK(!live);
#endif
    puts("PASS Power Topology TREE and leaf endpoints: literal Descriptor/globals, PartsList, features, path statuses, sorted enumeration, limits, pins, isolation and OOM");
}
