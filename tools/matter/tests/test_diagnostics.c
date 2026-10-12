#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define DIAG_CHECK(x) do { if(!(x)) { fprintf(stderr,"diagnostics:%d: %s\n",__LINE__,#x); exit(1); } } while(0)
#include "test_diagnostics_fixture.h"
#ifdef MATTER_TEST_ALLOC
static size_t live,calls,fail_at;
void* matter_test_calloc(size_t n,size_t z) { if(++calls==fail_at) return NULL; void* p=calloc(n,z); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { DIAG_CHECK(live); --live; } free(p); }
#endif
static const uint8_t empty[]={0x15,0x18};
static Matter_Result_T fake_snapshot(void* u,Matter_Diagnostics_Snapshot_T* s) { *s=*(Matter_Diagnostics_Snapshot_T*)u; return MATTER_OK; }
static Matter_Result_T fake_reset(void* u) { memset(((Matter_Diagnostics_Snapshot_T*)u)->wifi.counts,0,24); return MATTER_OK; }
typedef struct { Matter_Diagnostics_T model; unsigned calls; } TriggerTest;
static uint8_t fake_trigger(void* u,uint64_t event) {
    TriggerTest* t=u; ++t->calls;
    DIAG_CHECK(matter_diagnostics_set_test_trigger(t->model,NULL)==MATTER_BUSY);
    DIAG_CHECK(matter_diagnostics_delete(t->model)==MATTER_BUSY);
    return event==1?MATTER_IM_SUCCESS:MATTER_IM_INVALID_COMMAND;
}
static void bounded_snapshot(void) {
    Matter_Diagnostics_Snapshot_T* s=calloc(1,sizeof(*s)); DIAG_CHECK(s);
    s->general.interface_count=8;
    for(unsigned i=0;i<8;++i) {
        Matter_Diagnostics_Interface_T* a=&s->general.interfaces[i]; a->name_size=32; memset(a->name,'a'+i,32);
        a->ipv4_count=4; a->ipv6_count=8; a->type=1; a->reachable4=a->reachable6=-1;
        for(unsigned j=0;j<8;++j) { a->ipv6[j][0]=0xfe; a->ipv6[j][1]=0x80; a->ipv6[j][15]=(uint8_t)(i*8+j+1); }
    }
    s->general.subscriptions[0]=(Matter_Diagnostics_Subscriptions_T){1,65535}; s->general.subscriptions[1]=(Matter_Diagnostics_Subscriptions_T){2,4};
    s->general.im_sent=s->general.im_received=s->general.total_subscriptions=UINT32_MAX;
    s->general.system_ms=UINT64_MAX; s->general.posix_valid=true; s->general.posix_ms=UINT64_MAX;
    Matter_Diagnostics_Port_T p={s,fake_snapshot,fake_reset}; Matter_Diagnostics_T m=matter_diagnostics_new(&p,0,UINT32_MAX); DIAG_CHECK(m);
    Matter_Cluster_T wifi=matter_diagnostics_wifi(m);
    DIAG_CHECK(matter_cluster_id(m)==0x33 && matter_cluster_id(wifi)==0x36);
    DIAG_CHECK(matter_cluster_attribute_count(m)==15 && matter_cluster_attribute_count(wifi)==18);
    DIAG_CHECK(matter_cluster_delete(wifi)==MATTER_BUSY && matter_cluster_retain(wifi)==MATTER_OK);
    DIAG_CHECK(matter_cluster_delete(m)==MATTER_BUSY && matter_cluster_release(wifi)==MATTER_OK);
    Matter_Im_Value_T v; DIAG_CHECK(!matter_diagnostics_read(m,0x33,0,1,&v) && v.size>1500 && v.size<=4096);
    DIAG_CHECK(!matter_diagnostics_read(m,0x33,10,2,&v));
    static const uint8_t load[]={0x15,0x25,0,255,255,0x24,1,4,0x26,2,255,255,255,255,0x26,3,255,255,255,255,0x26,4,255,255,255,255,0x18};
    DIAG_CHECK(v.size==sizeof(load) && !memcmp(v.data,load,sizeof(load)));
    /* One invalid port value rejects the WHOLE snapshot, including time/version. */
    s->general.interfaces[7].name[0]='a'; memcpy(s->general.interfaces[7].name,s->general.interfaces[0].name,32);
    DIAG_CHECK(matter_diagnostics_refresh(m)==MATTER_PORT_ERROR && matter_diagnostics_read(m,0x33,2,0,&v)==MATTER_IM_FAILURE);
    s->general.interfaces[7].name[0]='z'; DIAG_CHECK(matter_diagnostics_refresh(m)==MATTER_OK);
    s->general.interface_count=9; DIAG_CHECK(matter_diagnostics_refresh(m)==MATTER_PORT_ERROR);
    s->general.interface_count=8; s->general.interfaces[0].ipv6[0][0]=255; DIAG_CHECK(matter_diagnostics_refresh(m)==MATTER_PORT_ERROR);
    s->general.interfaces[0].ipv6[0][0]=0xfe; s->wifi.online=true; s->wifi.rssi=-121; DIAG_CHECK(matter_diagnostics_refresh(m)==MATTER_PORT_ERROR);
    s->wifi.rssi=0; DIAG_CHECK(matter_diagnostics_refresh(m)==MATTER_OK);
    s->general.interfaces[0].hardware[0]=1; DIAG_CHECK(matter_diagnostics_refresh(m)==MATTER_PORT_ERROR);
    s->general.interfaces[0].hardware[0]=0; DIAG_CHECK(matter_diagnostics_refresh(m)==MATTER_OK);
    s->general.system_ms=0; DIAG_CHECK(matter_diagnostics_refresh(m)==MATTER_PORT_ERROR);
    DIAG_CHECK(matter_diagnostics_refresh(m)==MATTER_PORT_ERROR); /* Failure cannot reset the monotonic guard. */
    DIAG_CHECK(matter_diagnostics_delete(m)==MATTER_OK); free(s);
}
int main(void) {
    DiagFixture* f=diag_fixture(); DiagFixture* other=diag_fixture(); Matter_Im_Value_T v;
#ifdef MATTER_TEST_ALLOC
    for(unsigned i=1;i<=3;++i) { size_t before=live; fail_at=calls+i; DIAG_CHECK(!matter_diagnostics_new(&f->port,1,1) && live==before); fail_at=0; }
#endif
    DIAG_CHECK(diag_read(f,0x33,1,0).unsigned_value==1 && diag_read(f,0x33,8,0).unsigned_value==0);
    DIAG_CHECK(diag_read(f,0x33,0xfffd,0).unsigned_value==3 && diag_read(f,0x36,0xfffc,0).unsigned_value==3);
    uint32_t gv,wv; DIAG_CHECK(matter_diagnostics_version(f->model,0x33,&gv)==MATTER_OK && gv==31);
    DIAG_CHECK(matter_diagnostics_version(f->model,0x36,&wv)==MATTER_OK && wv==41);
    diag_tick(f,0); DIAG_CHECK(diag_read(f,0x33,1,0).data_version==gv && diag_read(f,0x36,1,0).data_version==wv);
    static const uint8_t iface[]={0x16,0x15,0x2c,0,9,'s','i','m','-','w','l','a','n','0',0x28,1,0x34,2,0x34,3,
        0x30,4,8,0,0,2,3,4,5,6,8,0x36,5,0x18,0x36,6,0x10,16,0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0x18,0x24,7,1,0x18,0x18};
    v=diag_read(f,0x33,0,0); DIAG_CHECK(v.size==sizeof(iface) && !memcmp(v.data,iface,sizeof(iface)));
    v=diag_read(f,0x36,0,0); DIAG_CHECK(v.type==MATTER_TLV_BYTES && v.size==6 && !memcmp(v.data,f->config.aps[0].ap.bssid,6));
    DIAG_CHECK(diag_read(f,0x36,1,0).unsigned_value==4 && diag_read(f,0x36,4,0).signed_value==-42);
    matter_diagnostics_host_advertising(f->host,true);
    for(unsigned i=0;i<6;++i) matter_diagnostics_host_packets(f->host,i,10+i);
    matter_diagnostics_host_packets(f->host,0,UINT32_MAX); /* Unsigned counter rollover. */
    matter_diagnostics_host_overruns(f->host,99); diag_tick(f,1234);
    v=diag_read(f,0x33,0,0); DIAG_CHECK(v.size==sizeof(iface) && v.data[14]==0x29); /* Association AND advertising. */
    DIAG_CHECK(diag_read(f,0x33,2,0).unsigned_value==1 && diag_read(f,0x36,5,0).unsigned_value==9);
    DIAG_CHECK(diag_read(other,0x33,2,0).unsigned_value==0 && diag_read(other,0x36,5,0).unsigned_value==0);
    DIAG_CHECK(!diag_command(f,0x33,1,empty,sizeof(empty)));
    static const uint8_t time[]={0x15,0x25,0,0xd2,4,0x34,1,0x18}; DIAG_CHECK(f->response_size==sizeof(time) && !memcmp(f->response,time,sizeof(time)));
    memset(f->response,0,24); memcpy(f->response,(const uint8_t[]){0x15,0x30,0,16},4); memcpy(f->response+20,(const uint8_t[]){0x24,1,1,0x18},4);
    DIAG_CHECK(matter_diagnostics_validate(f->model,0x33,0,f->response,24)==0);
    DIAG_CHECK(matter_diagnostics_invoke(f->model,0x33,0,f->response,24,NULL).status==MATTER_IM_CONSTRAINT_ERROR);
    for(size_t i=0;i<24;++i) DIAG_CHECK(matter_diagnostics_validate(f->model,0x33,0,f->response,i)!=0);
    TriggerTest tt={.model=f->model}; Matter_Diagnostics_Test_Trigger_T tc={.user=&tt,.trigger=fake_trigger};
    DIAG_CHECK(matter_diagnostics_set_test_trigger(f->model,&tc)==MATTER_INVALID_ARGUMENT);
    tc.enable_key[0]=7; DIAG_CHECK(matter_diagnostics_set_test_trigger(f->model,&tc)==MATTER_OK);
    DIAG_CHECK(diag_read(f,0x33,8,0).unsigned_value==1 && diag_read(other,0x33,8,0).unsigned_value==0);
    DIAG_CHECK(matter_diagnostics_invoke(f->model,0x33,0,f->response,24,NULL).status==MATTER_IM_CONSTRAINT_ERROR && !tt.calls);
    f->response[4]=6;
    DIAG_CHECK(matter_diagnostics_invoke(f->model,0x33,0,f->response,24,NULL).status==MATTER_IM_CONSTRAINT_ERROR && !tt.calls);
    f->response[4]=7;
    DIAG_CHECK(matter_diagnostics_invoke(f->model,0x33,0,f->response,24,NULL).status==0 && tt.calls==1);
    f->response[22]=2;
    DIAG_CHECK(matter_diagnostics_invoke(f->model,0x33,0,f->response,24,NULL).status==MATTER_IM_INVALID_COMMAND && tt.calls==2);
    DIAG_CHECK(matter_diagnostics_set_test_trigger(f->model,NULL)==MATTER_OK && !diag_read(f,0x33,8,0).unsigned_value);
    DIAG_CHECK(matter_diagnostics_invoke(f->model,0x33,0,f->response,24,NULL).status==MATTER_IM_CONSTRAINT_ERROR && tt.calls==2);
    matter_diagnostics_host_control(f->host,false,true);
    DIAG_CHECK(diag_command(f,0x36,0,empty,sizeof(empty))==MATTER_IM_FAILURE && diag_read(f,0x36,5,0).unsigned_value==9);
    matter_diagnostics_host_control(f->host,false,false); DIAG_CHECK(!diag_command(f,0x36,0,empty,sizeof(empty)));
    for(unsigned i=5;i<11;++i) DIAG_CHECK(diag_read(f,0x36,i,0).unsigned_value==0);
    DIAG_CHECK(diag_read(f,0x36,12,0).unsigned_value==99 && diag_read(f,0x36,11,0).unsigned_value==65000000);
    DIAG_CHECK(matter_diagnostics_host_subscription(f->host,1,true)==MATTER_OK && matter_diagnostics_host_subscription(f->host,2,true)==MATTER_OK);
    matter_diagnostics_host_message(f->host,true); matter_diagnostics_host_message(f->host,false); diag_tick(f,1234);
    v=diag_read(f,0x33,10,2); static const uint8_t load[]={0x15,0x24,0,2,0x24,1,1,0x24,2,2,0x24,3,1,0x24,4,1,0x18};
    DIAG_CHECK(v.size==sizeof(load) && !memcmp(v.data,load,sizeof(load)));
    DIAG_CHECK(matter_diagnostics_host_subscription(f->host,2,false)==MATTER_OK && matter_diagnostics_host_subscription(f->host,2,false)==MATTER_INVALID_STATE);
    matter_diagnostics_host_remove_fabric(f->host,1); diag_tick(f,1234); v=diag_read(f,0x33,10,1); DIAG_CHECK(v.data[3]==0 && v.data[6]==0 && v.data[9]==2);
    DIAG_CHECK(matter_diagnostics_host_faults(f->host,0x404,2,8)==MATTER_OK && matter_diagnostics_host_faults(f->host,0x800,0,0)==MATTER_INVALID_ARGUMENT);
    diag_tick(f,1234); v=diag_read(f,0x33,5,0); static const uint8_t faults[]={0x16,0x04,2,0x04,10,0x18}; DIAG_CHECK(v.size==sizeof(faults) && !memcmp(v.data,faults,sizeof(faults)));
    matter_diagnostics_host_control(f->host,true,false); DIAG_CHECK(matter_diagnostics_refresh(f->model)==MATTER_PORT_ERROR);
    uint32_t version; DIAG_CHECK(matter_diagnostics_version(f->model,0x33,&version)==MATTER_PORT_ERROR && matter_diagnostics_read(f->model,0x36,0,0,&v)==MATTER_IM_FAILURE);
    matter_diagnostics_host_control(f->host,false,false); diag_tick(f,1234);
    DIAG_CHECK(matter_tlv_writer_init(&f->writer,f->response,21,4)==MATTER_TLV_OK);
    DIAG_CHECK(matter_diagnostics_invoke(f->model,0x33,1,empty,sizeof(empty),&f->writer).status==MATTER_IM_RESOURCE_EXHAUSTED && !f->writer.size);
    /* Actual Network Commissioning enable transition drives diagnostic nulls. */
    static const uint8_t off[]={0x08},on[]={0x09};
    DIAG_CHECK(!matter_wifi_write(f->wifi,off,1)); diag_tick(f,1235);
    for(unsigned i=0;i<13;++i) DIAG_CHECK(diag_read(f,0x36,i,0).type==MATTER_TLV_NULL);
    v=diag_read(f,0x33,0,0); DIAG_CHECK(v.data[14]==0x28);
    DIAG_CHECK(!matter_wifi_write(f->wifi,on,1) && matter_wifi_checkpoint(f->wifi)==MATTER_OK);
    static const uint8_t connect[]={0x15,0x30,0,3,'l','a','b',0x24,1,0,0x18};
    Matter_Wifi_Reply_T reply; uint64_t token;
    DIAG_CHECK(matter_tlv_writer_init(&f->writer,f->response,sizeof(f->response),4)==MATTER_TLV_OK);
    DIAG_CHECK(matter_wifi_invoke(f->wifi,6,true,connect,sizeof(connect),&f->writer,&reply,&token)==MATTER_PENDING);
    DIAG_CHECK(matter_wifi_sim_process(f->sim,f->wifi,1245)==MATTER_OK && matter_wifi_process(f->wifi,1245)==MATTER_OK);
    DIAG_CHECK(matter_wifi_poll(f->wifi,token,&f->writer,&reply)==MATTER_OK && !reply.result.status);
    diag_tick(f,1245); DIAG_CHECK(diag_read(f,0x36,4,0).signed_value==-42);
    DIAG_CHECK(matter_wifi_commit(f->wifi)==MATTER_OK);
    diag_tick(f,3600000); DIAG_CHECK(f->image.hours==1 && matter_diagnostics_host_process(f->host,100)==MATTER_INVALID_ARGUMENT);
    DIAG_CHECK(matter_diagnostics_delete(f->model)==MATTER_OK && matter_diagnostics_host_delete(f->host)==MATTER_OK);
#ifdef MATTER_TEST_ALLOC
    fail_at=calls+1; DIAG_CHECK(!matter_diagnostics_host_new(&f->image,f->sim,&f->iface,1,true,0)); fail_at=0;
    DIAG_CHECK(f->image.reboots==1 && f->image.runtime.im_sent==1 && !f->image.attached);
#endif
    f->host=matter_diagnostics_host_new(&f->image,f->sim,&f->iface,1,false,3600000); DIAG_CHECK(f->host); f->port=matter_diagnostics_host_port(f->host); f->model=matter_diagnostics_new(&f->port,1,2); DIAG_CHECK(f->model);
    DIAG_CHECK(diag_read(f,0x33,1,0).unsigned_value==1 && diag_read(f,0x33,2,0).unsigned_value==3600);
    DIAG_CHECK(diag_read(f,0x36,12,0).unsigned_value==99 && f->image.runtime.total_subscriptions==2 && f->image.runtime.im_sent==1);
    f->image.runtime.im_sent=f->image.runtime.im_received=f->image.runtime.total_subscriptions=UINT32_MAX;
    matter_diagnostics_host_message(f->host,true); matter_diagnostics_host_message(f->host,false);
    DIAG_CHECK(matter_diagnostics_host_subscription(f->host,1,true)==MATTER_OK);
    DIAG_CHECK(f->image.runtime.im_sent==UINT32_MAX && f->image.runtime.im_received==UINT32_MAX && f->image.runtime.total_subscriptions==UINT32_MAX);
    f->image.reboots=UINT16_MAX; f->image.hours=UINT32_MAX; diag_tick(f,UINT64_MAX); DIAG_CHECK(f->image.hours==UINT32_MAX);
    DIAG_CHECK(matter_diagnostics_delete(f->model)==MATTER_OK && matter_diagnostics_host_delete(f->host)==MATTER_OK);
    f->host=matter_diagnostics_host_new(&f->image,f->sim,&f->iface,6,true,0); DIAG_CHECK(f->host); f->port=matter_diagnostics_host_port(f->host); f->model=matter_diagnostics_new(&f->port,1,2); DIAG_CHECK(f->model);
    DIAG_CHECK(diag_read(f,0x33,1,0).unsigned_value==UINT16_MAX && diag_read(f,0x33,2,0).unsigned_value==0);
    DIAG_CHECK(diag_read(f,0x36,12,0).unsigned_value==0 && !f->image.runtime.total_subscriptions && !f->image.runtime.im_sent && f->image.hours==UINT32_MAX);
    diag_release(f); diag_release(other); bounded_snapshot();
#ifdef MATTER_TEST_ALLOC
    DIAG_CHECK(!live);
#endif
    puts("PASS diagnostics: literal TLV, snapshots/bounds, load/fabric counters, uptime/restart, Wi-Fi commissioning online/null, reset/failure, isolation and OOM"); return 0;
}
