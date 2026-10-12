#ifndef TEST_ADMIN_COMMISSIONING_H
#define TEST_ADMIN_COMMISSIONING_H
#include "clusters/matter_admin_commissioning.h"
typedef struct {
    uint8_t args[256],request[300],verifier[97]; size_t n,request_size;
    Matter_Cluster_T model; bool blocked,published,fail_open,fail_close,fail_blocked,missing;
    unsigned opens,closes,revokes; uint16_t discriminator; Matter_Result_T retire;
    Matter_Cluster_Request_T identity;
} AdminFixture;
static void admin_byte(AdminFixture* f,unsigned b) { REQUIRE(f->n<sizeof(f->args)); f->args[f->n++]=(uint8_t)b; }
static void admin_uint(AdminFixture* f,unsigned tag,uint32_t v) {
    unsigned width=v>65535?4:v>255?2:1;
    admin_byte(f,width==4?0x26:width==2?0x25:0x24); admin_byte(f,tag);
    for(unsigned i=0;i<width;++i) admin_byte(f,v>>(8*i));
}
static void admin_args(AdminFixture* f,const Matter_Pase_Config_T* c,unsigned timeout,unsigned discriminator,unsigned iterations,unsigned salt_size,unsigned verifier_size) {
    f->n=0; admin_byte(f,0x15); admin_uint(f,0,timeout);
    admin_byte(f,0x30); admin_byte(f,1); admin_byte(f,verifier_size);
    for(unsigned i=0;i<verifier_size;++i) admin_byte(f,i<97?f->verifier[i]:0);
    admin_uint(f,2,discriminator); admin_uint(f,3,iterations);
    admin_byte(f,0x30); admin_byte(f,4); admin_byte(f,salt_size);
    for(unsigned i=0;i<salt_size;++i) admin_byte(f,i<32?c->salt[i]:0);
    admin_byte(f,0x18);
}
static void admin_empty(AdminFixture* f) { f->n=0; admin_byte(f,0x15); admin_byte(f,0x18); }
static Matter_Result_T admin_vendor(void* u,uint8_t index,uint16_t* vid) { AdminFixture* f=u; if(f->missing || index!=1) return MATTER_INVALID_STATE; *vid=0xfff1; return MATTER_OK; }
static Matter_Result_T admin_blocked(void* u,bool* out) { AdminFixture* f=u; *out=f->blocked; return f->fail_blocked?MATTER_PORT_ERROR:MATTER_OK; }
static Matter_Result_T admin_advertise(void* u,bool open,uint16_t d) {
    AdminFixture* f=u;
    REQUIRE(matter_admin_commissioning_close(f->model)==MATTER_BUSY);
    if(open) { if(f->fail_open) return MATTER_PORT_ERROR; ++f->opens; f->published=true; f->discriminator=d; }
    else { ++f->closes; if(f->fail_close) return MATTER_PORT_ERROR; f->published=false; }
    return MATTER_OK;
}
static Matter_Result_T admin_revoke(void* u) { AdminFixture* f=u; ++f->revokes; return f->retire; }
static Matter_Admin_Commissioning_Port_T admin_port(AdminFixture* f) { return (Matter_Admin_Commissioning_Port_T){f,admin_vendor,admin_blocked,admin_advertise,admin_revoke}; }
static void admin_call(AdminFixture* f,unsigned cmd,uint8_t expected,int cluster) {
    Matter_Im_Command_Result_T r; uint64_t token=0;
    REQUIRE(matter_cluster_start(f->model,cmd,&f->identity,f->args,f->n,NULL,&r,&token)==MATTER_OK && !token);
    REQUIRE(r.status==expected && r.has_cluster_status==(cluster>=0) && (cluster<0 || r.cluster_status==cluster));
}
static uint32_t admin_value(AdminFixture* f,unsigned attr,bool null,uint64_t expected) {
    Matter_Im_Value_T v; REQUIRE(!matter_cluster_read(f->model,attr,&f->identity,&v));
    REQUIRE(v.type==(null?MATTER_TLV_NULL:MATTER_TLV_UNSIGNED) && (null || v.unsigned_value==expected)); return v.data_version;
}
static bool admin_core(void) {
    bool ok=false; PaseFixture* p=setup(false,false); AdminFixture* f=calloc(1,sizeof(*f)); REQUIRE(f);
    memcpy(f->verifier,p->config[1].w0,32); memcpy(f->verifier+32,p->config[1].L,65);
    f->identity=(Matter_Cluster_Request_T){.session=1,.fabric=1,.is_case=true};
    Matter_Admin_Commissioning_Port_T port=admin_port(f);
    CHECK(!matter_admin_commissioning_new(NULL,&p->port,0,0) && !matter_admin_commissioning_new(&port,NULL,0,0));
#ifdef MATTER_TEST_ALLOC
    size_t baseline=live;
    for(unsigned i=1;i<=2;++i) { fail_at=calls+i; CHECK(!matter_admin_commissioning_new(&port,&p->port,10,0)); fail_at=0; CHECK(live==baseline); }
#endif
    f->model=matter_admin_commissioning_new(&port,&p->port,10,0); CHECK(f->model);
    CHECK(admin_value(f,0,false,0)==10); admin_value(f,1,true,0); admin_value(f,2,true,0); admin_value(f,0xfffc,false,0); admin_value(f,0xfffd,false,1);
    Matter_Im_Command_T meta; CHECK(!matter_cluster_command(f->model,0,&meta) && meta.timed && meta.privilege==MATTER_IM_ADMINISTER && !meta.response);
    CHECK(matter_cluster_command(f->model,1,&meta)==MATTER_IM_UNSUPPORTED_COMMAND && !matter_cluster_command(f->model,2,&meta) && meta.timed);
    Matter_Im_Value_T v; CHECK(!matter_cluster_read(f->model,0xfff9,&f->identity,&v));
    const uint8_t accepted[]={0x16,4,0,4,2,0x18}; CHECK(v.size==sizeof(accepted) && !memcmp(v.data,accepted,sizeof(accepted)));
    CHECK(!matter_admin_commissioning_pase_new(f->model,789,30000,0));
    admin_args(f,&p->config[1],180,4095,1000,16,97);
    for(size_t n=0;n<f->n;++n) CHECK(matter_cluster_validate_command(f->model,0,&f->identity,f->args,n)==MATTER_IM_INVALID_COMMAND);
    f->blocked=true; admin_call(f,0,MATTER_IM_FAILURE,2); f->blocked=false;
    f->identity.armed=true; admin_call(f,0,MATTER_IM_FAILURE,2); f->identity.armed=false;
    f->identity.is_case=false; admin_call(f,0,MATTER_IM_UNSUPPORTED_ACCESS,-1); f->identity.is_case=true;
    f->fail_blocked=true; admin_call(f,0,MATTER_IM_FAILURE,-1); f->fail_blocked=false;
    f->missing=true; admin_call(f,0,MATTER_IM_FAILURE,-1); f->missing=false;
    f->fail_open=true; admin_call(f,0,MATTER_IM_FAILURE,-1); f->fail_open=false; CHECK(!f->published && !f->opens);
    for(unsigned i=0;i<8;++i) {
        admin_args(f,&p->config[1],i==0?179:i==1?901:180,i==2?4096:4095,i==3?999:i==4?100001:1000,i==5?15:i==6?33:16,i==7?96:97);
        admin_call(f,0,i<3?MATTER_IM_INVALID_COMMAND:MATTER_IM_FAILURE,i<3?-1:3);
    }
    f->verifier[32]=2; admin_args(f,&p->config[1],180,0,1000,16,97); admin_call(f,0,MATTER_IM_FAILURE,3);
    memset(f->verifier,255,32); memcpy(f->verifier+32,p->config[1].L,65); admin_args(f,&p->config[1],180,0,1000,16,97); admin_call(f,0,MATTER_IM_FAILURE,3);
    memcpy(f->verifier,p->config[1].w0,32); memset(f->verifier+33,0,64); admin_args(f,&p->config[1],180,0,1000,16,97); admin_call(f,0,MATTER_IM_FAILURE,3);
    memcpy(f->verifier+32,p->config[1].L,65);
#ifdef MATTER_TEST_ALLOC
    size_t before=calls; CHECK(p->port.pake_verifier(p->port.user,f->verifier,97)==MATTER_OK); size_t count=calls-before;
    for(size_t i=1;i<=count;++i) { baseline=live; fail_at=calls+i; CHECK(p->port.pake_verifier(p->port.user,f->verifier,97)==MATTER_PORT_ERROR); fail_at=0; CHECK(live==baseline); }
    admin_args(f,&p->config[1],180,4095,1000,16,97); fail_at=calls+1; admin_call(f,0,MATTER_IM_FAILURE,-1); fail_at=0;
#endif
    admin_args(f,&p->config[1],180,4095,1000,16,97); admin_call(f,0,0,-1);
    CHECK(f->published && f->opens==1 && f->discriminator==4095 && admin_value(f,0,false,1)==11);
    Matter_Cluster_T independent=matter_admin_commissioning_new(&port,&p->port,77,0); CHECK(independent);
    CHECK(!matter_cluster_read(independent,0,&f->identity,&v) && !v.unsigned_value && v.data_version==77);
    CHECK(!matter_admin_commissioning_pase_new(independent,800,30000,0) && matter_cluster_delete(independent)==MATTER_OK);
    admin_value(f,1,false,1); admin_value(f,2,false,0xfff1); admin_call(f,0,MATTER_IM_FAILURE,2);
    CHECK(matter_cluster_delete(f->model)==MATTER_BUSY);
    CHECK(matter_admin_commissioning_fabric_removed(f->model,1)==MATTER_OK); admin_value(f,1,true,0); admin_value(f,2,false,0xfff1);
    uint64_t deadline; CHECK(matter_cluster_deadline(f->model,&deadline)==MATTER_OK && deadline==180000);
    CHECK(matter_cluster_process(f->model,179999)==MATTER_OK);
#ifdef MATTER_TEST_ALLOC
    fail_at=calls+1; CHECK(!matter_admin_commissioning_pase_new(f->model,789,30000,179999)); fail_at=0;
#endif
    Matter_Pase_T attempt=matter_admin_commissioning_pase_new(f->model,789,30000,179999); CHECK(attempt);
    f->fail_close=true; CHECK(matter_cluster_process(f->model,180000)==MATTER_PORT_ERROR);
    admin_value(f,0,false,0); admin_value(f,1,true,0); admin_value(f,2,true,0);
    CHECK(!matter_admin_commissioning_pase_new(f->model,790,30000,180000) && matter_pase_process(attempt,180000)==MATTER_PENDING);
    CHECK(matter_pase_delete(attempt)==MATTER_OK); attempt=NULL;
    admin_call(f,0,MATTER_IM_FAILURE,2); f->fail_close=false; CHECK(matter_cluster_process(f->model,180000)==MATTER_OK && !f->published);
    admin_empty(f); uint64_t token,second; Matter_Im_Command_Result_T r;
    f->retire=MATTER_PENDING;
    CHECK(matter_cluster_start(f->model,2,&f->identity,f->args,f->n,NULL,&r,&token)==MATTER_PENDING);
    CHECK(matter_cluster_process(f->model,180001)==MATTER_PENDING && f->revokes==1);
    CHECK(matter_cluster_poll(f->model,token,NULL,&r)==MATTER_PENDING);
    CHECK(matter_cluster_start(f->model,2,&f->identity,f->args,f->n,NULL,&r,&second)==MATTER_PENDING);
    CHECK(matter_cluster_cancel(f->model,second)==MATTER_OK); /* Cleanup survives detached handler. */
    f->retire=MATTER_PORT_ERROR; CHECK(matter_cluster_process(f->model,180002)==MATTER_PORT_ERROR);
    CHECK(matter_cluster_poll(f->model,token,NULL,&r)==MATTER_OK && r.status==MATTER_IM_FAILURE && !r.has_cluster_status);
    CHECK(matter_cluster_delete(f->model)==MATTER_BUSY); f->retire=MATTER_OK; CHECK(matter_cluster_process(f->model,180003)==MATTER_OK);
    CHECK(matter_cluster_start(f->model,2,&f->identity,f->args,f->n,NULL,&r,&token)==MATTER_PENDING && matter_cluster_process(f->model,180004)==MATTER_OK);
    CHECK(matter_cluster_poll(f->model,token,NULL,&r)==MATTER_OK && r.has_cluster_status && r.cluster_status==4);
    admin_args(f,&p->config[1],900,0,100000,32,97); admin_call(f,0,0,-1);
    CHECK(matter_cluster_deadline(f->model,&deadline)==MATTER_OK && deadline==1080004);
    admin_empty(f); CHECK(matter_cluster_start(f->model,2,&f->identity,f->args,f->n,NULL,&r,&token)==MATTER_PENDING);
    CHECK(!matter_admin_commissioning_pase_new(f->model,790,30000,180004));
    CHECK(matter_cluster_process(f->model,180005)==MATTER_OK && matter_cluster_poll(f->model,token,NULL,&r)==MATTER_OK && !r.status);
    CHECK(matter_cluster_process(f->model,1)==MATTER_INVALID_ARGUMENT);
    /* Complete/shutdown close is retryable, independent from Revoke. */
    admin_args(f,&p->config[1],180,1,1000,16,97); admin_call(f,0,0,-1);
    unsigned revokes=f->revokes; CHECK(matter_admin_commissioning_close(f->model)==MATTER_PENDING);
    CHECK(matter_cluster_process(f->model,180005)==MATTER_OK && matter_admin_commissioning_close(f->model)==MATTER_OK && f->revokes==revokes);
    CHECK(matter_cluster_process(f->model,UINT64_MAX-1)==MATTER_OK); admin_call(f,0,MATTER_IM_FAILURE,-1);
    CHECK(matter_cluster_delete(f->model)==MATTER_OK); f->model=NULL;
    puts("PASS Administrator Commissioning: enhanced profile, schema/status/bounds, PAKE validation/OOM, expiry vs revoke, retries, cancel/drain, fabric removal and lifecycle"); ok=true;
done:
    free(f); dispose(p); return ok;
}
#endif
