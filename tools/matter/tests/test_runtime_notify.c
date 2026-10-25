#include "runtime/matter_runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"notify:%d: %s\n",__LINE__,#x);abort();}}while(0)
static Matter_Result_T ready_mock(Matter_Dispatch_T,uint8_t,uint64_t,uint64_t*);
static Matter_Result_T peer_take_mock(Matter_Dispatch_T,uint64_t);
static Matter_Result_T invoke_mock(Matter_Dispatch_T,uint8_t,uint64_t,const Matter_Im_Command_Path_T*,uint32_t,const uint8_t*,size_t,uint64_t*);
static Matter_Result_T take_mock(Matter_Dispatch_T,uint64_t,uint8_t*,const uint8_t**,size_t*);
static Matter_Result_T root_store_mock(void*,const Matter_Root_Settings_T*);
#define matter_dispatch_peer ready_mock
#define matter_dispatch_peer_take peer_take_mock
#define matter_dispatch_invoke invoke_mock
#define matter_dispatch_invoke_take take_mock
#define matter_store_host_root root_store_mock
#include "../../../main/apps/matter/runtime/matter_runtime.c"
#undef matter_dispatch_peer
#undef matter_dispatch_peer_take
#undef matter_dispatch_invoke
#undef matter_dispatch_invoke_take
#undef matter_store_host_root
typedef struct {
    struct Matter_Runtime runtime;Matter_Fabric_View_T fabrics;Matter_Ota_Install_Boot_T boot;
    Matter_Ota_Install_Port_T install;Matter_Result_T readiness,start,take,peer_take;
    unsigned ready_calls,claims,attempts,root_writes;bool present,root_failure;
    Matter_Root_Settings_T saved_root;
} Fixture;
static Matter_Result_T hash(void* u,const uint8_t* p,size_t n,uint8_t* out){(void)u;CHECK(n==1&&p[0]==42);memset(out,0x55,32);return MATTER_OK;}
static const Matter_Fabric_View_T* fabrics(void* u){return &((Fixture*)u)->fabrics;}
static const Matter_Ota_Install_Boot_T* boot(void* u){Fixture* f=u;return f->present?&f->boot:NULL;}
static Matter_Result_T claim(void* u,const uint8_t fp[32],bool live,Matter_Ota_Apply_Context_T* out){
    Fixture* f=u;CHECK(f->present);++f->claims;for(unsigned i=0;i<32;++i)CHECK(fp[i]==(live?0x55:0));
    f->present=false;if(!live)return MATTER_OFFLINE;*out=f->boot.context;return MATTER_OK;
}
static Matter_Result_T ready_mock(Matter_Dispatch_T d,uint8_t fabric,uint64_t node,uint64_t* id){Fixture* f=(Fixture*)d;CHECK(fabric==1&&node==42);++f->ready_calls;*id=f->readiness==MATTER_PENDING?11:0;return f->readiness;}
static Matter_Result_T peer_take_mock(Matter_Dispatch_T d,uint64_t id){Fixture* f=(Fixture*)d;CHECK(id==11);return f->peer_take;}
static Matter_Result_T invoke_mock(Matter_Dispatch_T d,uint8_t fabric,uint64_t node,const Matter_Im_Command_Path_T* path,uint32_t response,const uint8_t* bytes,size_t size,uint64_t* id){
    Fixture* f=(Fixture*)d;CHECK(fabric==1&&node==42&&path->cluster==0x29&&path->command==4&&response==MATTER_IM_CLIENT_STATUS_ONLY&&size==19&&bytes[0]==0x15);++f->attempts;if(f->start==MATTER_PENDING)*id=7;return f->start;
}
static Matter_Result_T take_mock(Matter_Dispatch_T d,uint64_t id,uint8_t* status,const uint8_t** data,size_t* size){Fixture* f=(Fixture*)d;CHECK(id==7);if(f->take==MATTER_PENDING)return MATTER_PENDING;*status=0;*data=NULL;*size=0;return f->take;}
static Matter_Result_T root_store_mock(void* u,const Matter_Root_Settings_T* s){Fixture* f=u;if(f->root_failure)return MATTER_PORT_ERROR;f->saved_root=*s;++f->root_writes;return MATTER_OK;}
static Matter_Result_T unsupported_country(void* u,const Matter_Root_Settings_T* s,uint8_t candidate,bool* supported){(void)u;(void)s;CHECK(candidate==0);*supported=false;return MATTER_OK;}
static void reset(Fixture* f){
    memset(f,0,sizeof(*f));f->present=true;f->readiness=MATTER_OFFLINE;f->start=MATTER_PENDING;f->take=MATTER_PENDING;f->peer_take=MATTER_PENDING;
    f->fabrics.records[0].index=1;f->fabrics.records[0].noc_size=1;f->fabrics.records[0].noc[0]=42;
    f->boot.state=MATTER_OTA_INSTALL_NOTIFY;f->boot.context=(Matter_Ota_Apply_Context_T){.provider={.fabric=1,.node=42,.endpoint=1},.version=2,.token_size=8};
    f->install=(Matter_Ota_Install_Port_T){.user=f,.boot=boot,.claim=claim};
    f->runtime.dispatch=(Matter_Dispatch_T)f;f->runtime.ota_port.install=&f->install;f->runtime.applied_event=true;f->runtime.fabric_host=(Matter_Fabric_Host_T)f;f->runtime.fabric_port=(Matter_Fabric_Port_T){.user=f,.view=fabrics};f->runtime.crypto.sha256=hash;
}
int main(void){
    Fixture* f=calloc(1,sizeof(*f));CHECK(f);reset(f);
    f->runtime.platform.user=f;f->runtime.platform.regulatory=unsupported_country;f->runtime.store=(Matter_Store_Host_T)f;
    Matter_Root_Settings_T settings={.location={'Z','Z'}};bool supported=true;
    CHECK(regulatory(&f->runtime,&settings,0,&supported)==MATTER_OK&&!supported&&f->root_writes==1&&!memcmp(f->saved_root.location,"ZZ",2));
    f->root_failure=true;settings.location[0]='P';CHECK(regulatory(&f->runtime,&settings,0,&supported)==MATTER_PORT_ERROR&&f->root_writes==1&&f->saved_root.location[0]=='Z');reset(f);
    for(unsigned i=0;i<100;++i)notify_process(&f->runtime);
    CHECK(f->present&&!f->claims&&!f->attempts);
    f->runtime.now=5000;f->readiness=MATTER_BUSY;notify_process(&f->runtime);CHECK(f->present&&!f->claims);
    f->readiness=MATTER_OK;notify_process(&f->runtime);CHECK(!f->present&&f->claims==1&&f->attempts==1&&f->runtime.notify==7);
    notify_process(&f->runtime);CHECK(f->runtime.notify==7&&f->claims==1);f->take=MATTER_OK;notify_process(&f->runtime);CHECK(!f->runtime.notify&&f->claims==1&&f->attempts==1);
    reset(f);f->runtime.applied_event=false;notify_process(&f->runtime);CHECK(!f->ready_calls&&!f->claims);f->runtime.applied_event=true;f->fabrics.records[0].index=0;notify_process(&f->runtime);CHECK(f->claims==1&&!f->ready_calls&&!f->attempts&&!f->present);
    reset(f);f->readiness=MATTER_OK;f->start=MATTER_LIMIT_REACHED;notify_process(&f->runtime);notify_process(&f->runtime);CHECK(f->claims==1&&f->attempts==1&&!f->present&&!f->runtime.notify);
    reset(f);f->readiness=MATTER_PENDING;notify_process(&f->runtime);CHECK(f->runtime.notify_peer==11&&!f->claims);
    for(unsigned i=0;i<100;++i)notify_process(&f->runtime);
    CHECK(f->runtime.notify_peer==11&&!f->claims);
    f->peer_take=MATTER_PORT_ERROR;notify_process(&f->runtime);CHECK(!f->runtime.notify_peer&&f->present&&!f->claims);
    f->readiness=MATTER_OK;f->runtime.now=4999;notify_process(&f->runtime);CHECK(!f->claims);
    f->runtime.now=5000;notify_process(&f->runtime);CHECK(f->claims==1&&f->attempts==1);
    free(f);puts("PASS Notify: preserve durable claim before IPv6/readiness and during busy drain; VersionApplied gate, orphan cleanup, single accepted attempt/MRP and existing OOM policy");return 0;
}
