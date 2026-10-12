#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "clusters/matter_identify.h"
#include "clusters/matter_meter_identification.h"
#include "clusters/matter_time_sync.h"
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"services:%d: %s\n",__LINE__,#x); exit(1); } } while(0)
#ifdef MATTER_TEST_ALLOC
static size_t live,calls,fail_at;
void* matter_test_calloc(size_t n,size_t z) { if(++calls==fail_at) return NULL; void* p=calloc(n,z); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { CHECK(live); --live; } free(p); }
#endif
typedef struct {
    uint16_t presentation; unsigned presents,syncs,sets; uint64_t high;
    Matter_Meter_Id_Snapshot_T identity;
    Matter_Time_Sync_Sample_T clock; Matter_Result_T error;
    Matter_Cluster_T reentry; bool reenter;
    Matter_Event_Record_T events[MATTER_EVENTS_CAPACITY];
} Fixture;
static void present(void* u,uint16_t seconds) { Fixture* f=u; f->presentation=seconds; ++f->presents; if(f->reenter) CHECK(matter_cluster_process(f->reentry,0)==MATTER_BUSY); }
static Matter_Result_T identity(void* u,Matter_Meter_Id_Snapshot_T* out) { Fixture* f=u; *out=f->identity; if(f->reenter) CHECK(matter_meter_identification_refresh(f->reentry)==MATTER_BUSY); return f->error; }
static Matter_Result_T sample(void* u,uint64_t now,Matter_Time_Sync_Sample_T* out) { (void)now; Fixture* f=u; *out=f->clock; return f->error; }
static Matter_Result_T set(void* u,uint64_t utc,uint8_t gran,uint64_t now) { (void)now; Fixture* f=u; if(f->error) return f->error; ++f->sets; f->clock=(Matter_Time_Sync_Sample_T){utc,gran,gran?MATTER_TIME_SOURCE_ADMIN:0}; return MATTER_OK; }
static void sync_clock(void* u) { ++((Fixture*)u)->syncs; }
static Matter_Result_T load(void* u,uint64_t* out) { *out=((Fixture*)u)->high; return MATTER_OK; }
static Matter_Result_T store(void* u,uint64_t high) { ((Fixture*)u)->high=high; return MATTER_OK; }
static Matter_Im_Value_T read(Matter_Cluster_T c,uint32_t id) { Matter_Im_Value_T v; Matter_Cluster_Request_T q={0}; CHECK(matter_cluster_read(c,id,&q,&v)==0); return v; }
static uint32_t version(Matter_Cluster_T c) { uint32_t v; CHECK(matter_cluster_version(c,&v)==MATTER_OK); return v; }
static Matter_Im_Command_Result_T invoke(Matter_Cluster_T c,const uint8_t* d,size_t n) {
    Matter_Cluster_Request_T q={0}; Matter_Im_Command_Result_T r; uint64_t token;
    CHECK(matter_cluster_start(c,0,&q,d,n,NULL,&r,&token)==MATTER_OK && !token); return r;
}
int main(void) {
    Fixture* f=calloc(1,sizeof(*f)); CHECK(f);
    Matter_Events_Port_T events_port={f,load,store}; Matter_Events_T events=matter_events_new(&events_port); CHECK(events);
    Matter_Identify_Port_T ip={f,present}; Matter_Identify_Config_T ic={100,0};
    Matter_Meter_Id_Port_T mp={f,identity}; Matter_Time_Sync_Port_T tp={f,sample,set,sync_clock};
#ifdef MATTER_TEST_ALLOC
    for(unsigned point=1;point<=2;++point) {
        calls=0; fail_at=point; CHECK(!matter_identify_new(&ip,&ic,100) && !live);
        calls=0; CHECK(!matter_meter_identification_new(&mp,100) && !live);
        calls=0; CHECK(!matter_time_sync_new(&tp,events,100,100) && !live);
    }
    fail_at=0;
#endif
    Matter_Cluster_T i=matter_identify_new(&ip,&ic,100),other=matter_identify_new(&ip,&ic,100);
    Matter_Cluster_T m=matter_meter_identification_new(&mp,100),t=matter_time_sync_new(&tp,events,100,100);
    CHECK(i && other && m && t && read(i,0).unsigned_value==0);
    Matter_Im_Command_T cmd; CHECK(!matter_cluster_command(i,0,&cmd) && cmd.privilege==MATTER_IM_MANAGE);
    CHECK(!matter_cluster_command(t,0,&cmd) && cmd.privilege==MATTER_IM_ADMINISTER);
    Matter_Im_Write_Attribute_T attr; CHECK(!matter_cluster_describe_write(i,0,&attr) && attr.privilege==MATTER_IM_OPERATE);
    CHECK(matter_cluster_describe_write(m,0,&attr)==MATTER_IM_UNSUPPORTED_WRITE);
    CHECK(matter_cluster_describe_write(t,0,&attr)==MATTER_IM_UNSUPPORTED_WRITE);
    const uint8_t identify[]={0x15,0x25,0,3,0,0x18},duplicate[]={0x15,0x24,0,1,0x24,0,2,0x18},missing[]={0x15,0x18},wrong[]={0x15,0x34,0,0x18};
    CHECK(invoke(i,missing,sizeof(missing)).status==MATTER_IM_INVALID_COMMAND);
    CHECK(invoke(i,duplicate,sizeof(duplicate)).status==MATTER_IM_INVALID_COMMAND);
    CHECK(invoke(i,wrong,sizeof(wrong)).status==MATTER_IM_INVALID_COMMAND && !f->presents);
    f->reentry=i; f->reenter=true; CHECK(invoke(i,identify,sizeof(identify)).status==0); f->reenter=false;
    CHECK(f->presentation==3 && read(other,0).unsigned_value==0 && version(i)==101);
    uint64_t deadline; CHECK(matter_cluster_deadline(i,&deadline)==MATTER_OK && deadline==1100);
    CHECK(matter_cluster_process(i,1099)==MATTER_OK && read(i,0).unsigned_value==3);
    CHECK(matter_cluster_process(i,1100)==MATTER_OK && read(i,0).unsigned_value==2 && version(i)==101);
    CHECK(matter_cluster_process(i,3100)==MATTER_OK && read(i,0).unsigned_value==0 && version(i)==102 && !f->presentation);
    CHECK(matter_cluster_process(i,3099)==MATTER_INVALID_ARGUMENT);
    Matter_Cluster_Request_T q={0}; const uint8_t two[]={4,2},big[]={6,0,0,1,0},negative[]={0,0xff};
    CHECK(matter_cluster_write(i,0,&q,two,sizeof(two)).status==0 && f->presentation==2);
    CHECK(matter_cluster_write(i,0,&q,two,sizeof(two)).status==0 && version(i)==104);
    CHECK(matter_cluster_write(i,0,&q,big,sizeof(big)).status==MATTER_IM_CONSTRAINT_ERROR);
    CHECK(matter_cluster_write(i,0,&q,negative,sizeof(negative)).status==MATTER_IM_INVALID_DATA_TYPE);
    CHECK(matter_cluster_delete(i)==MATTER_OK && !f->presentation);
    ic.identify_type=6; CHECK(!matter_identify_new(&ip,&ic,0)); ic.identify_type=0;
    i=matter_identify_new(&ip,&ic,UINT64_MAX-1); CHECK(i && invoke(i,identify,sizeof(identify)).status==MATTER_IM_CONSTRAINT_ERROR);
    CHECK(read(m,MATTER_METER_ID_SERIAL).type==MATTER_TLV_NULL);
    f->identity.type_known=true; f->identity.meter_type=2; f->identity.serial.known=true; f->identity.serial.size=MATTER_METER_ID_TEXT_MAX;
    memset(f->identity.serial.data,'A',sizeof(f->identity.serial.data));
    f->reentry=m; f->reenter=true; CHECK(matter_meter_identification_refresh(m)==MATTER_OK); f->reenter=false;
    CHECK(read(m,MATTER_METER_ID_SERIAL).size==64 && read(m,MATTER_METER_ID_DELIVERY).type==MATTER_TLV_NULL);
    CHECK(matter_meter_identification_refresh(m)==MATTER_OK && version(m)==101);
    f->identity.serial.data[0]=0xff; CHECK(matter_meter_identification_refresh(m)==MATTER_PORT_ERROR && read(m,0).type==MATTER_TLV_NULL);
    f->identity.serial.data[0]='A'; f->identity.serial.size=65; CHECK(matter_meter_identification_refresh(m)==MATTER_PORT_ERROR);
    f->identity.serial.size=0; f->identity.meter_type=3; CHECK(matter_meter_identification_refresh(m)==MATTER_PORT_ERROR);
    f->identity.meter_type=1; CHECK(matter_meter_identification_refresh(m)==MATTER_OK && read(m,2).size==0 && read(m,2).type==MATTER_TLV_UTF8);
    CHECK(read(t,0).type==MATTER_TLV_NULL && read(t,1).unsigned_value==0);
    CHECK(matter_cluster_process(t,100)==MATTER_OK && f->syncs==1);
    const Matter_Event_Path_T path={0,MATTER_TIME_SYNC_CLUSTER,MATTER_TIME_FAILURE}; size_t count;
    CHECK(matter_events_copy(events,&path,0,f->events,&count)==MATTER_OK && count==1);
    CHECK(matter_cluster_process(t,200)==MATTER_OK && f->syncs==1);
    CHECK(matter_cluster_process(t,100+MATTER_TIME_HOUR_MS)==MATTER_OK && f->syncs==2);
    CHECK(matter_events_copy(events,&path,0,f->events,&count)==MATTER_OK && count==2);
    const uint8_t utc[]={0x15,0x27,0,0,0,0,0,0,0,0,1,0x24,1,3,0x18};
    CHECK(invoke(t,missing,sizeof(missing)).status==MATTER_IM_INVALID_COMMAND);
    CHECK(invoke(t,utc,sizeof(utc)).status==0 && f->sets==1);
    CHECK(read(t,1).unsigned_value==2 && read(t,2).unsigned_value==MATTER_TIME_SOURCE_ADMIN && read(t,0).unsigned_value==UINT64_C(0x0100000000000000));
    uint32_t v=version(t); ++f->clock.utc_us; CHECK(matter_cluster_process(t,101+MATTER_TIME_HOUR_MS)==MATTER_OK && version(t)==v);
    f->error=MATTER_INVALID_STATE; Matter_Im_Command_Result_T rejected=invoke(t,utc,sizeof(utc));
    CHECK(rejected.status==MATTER_IM_FAILURE && rejected.has_cluster_status && rejected.cluster_status==MATTER_TIME_NOT_ACCEPTED && version(t)==v);
    f->error=MATTER_PORT_ERROR; rejected=invoke(t,utc,sizeof(utc)); CHECK(rejected.status==MATTER_IM_FAILURE && !rejected.has_cluster_status && f->sets==1);
    CHECK(matter_cluster_process(t,102+MATTER_TIME_HOUR_MS)==MATTER_PORT_ERROR && read(t,0).type==MATTER_TLV_NULL);
    f->error=MATTER_OK; f->clock.granularity=5; CHECK(matter_cluster_process(t,103+MATTER_TIME_HOUR_MS)==MATTER_PORT_ERROR);
    f->clock=(Matter_Time_Sync_Sample_T){42,2,1}; CHECK(matter_cluster_process(t,104+MATTER_TIME_HOUR_MS)==MATTER_OK && read(t,0).unsigned_value==42);
    CHECK(matter_cluster_process(t,103+MATTER_TIME_HOUR_MS)==MATTER_INVALID_ARGUMENT);
    uint8_t invalid[sizeof(utc)]; memcpy(invalid,utc,sizeof(utc)); invalid[sizeof(utc)-2]=5;
    CHECK(invoke(t,invalid,sizeof(invalid)).status==MATTER_IM_CONSTRAINT_ERROR);
    CHECK(matter_cluster_delete(i)==MATTER_OK && matter_cluster_delete(other)==MATTER_OK && matter_cluster_delete(m)==MATTER_OK && matter_cluster_delete(t)==MATTER_OK);
    CHECK(matter_events_delete(events)==MATTER_OK);
#ifdef MATTER_TEST_ALLOC
    CHECK(!live);
#endif
    free(f); puts("PASS meter services: countdown/reporting, schema, callbacks, unknown identity/time, events, failures and independent state"); return 0;
}
