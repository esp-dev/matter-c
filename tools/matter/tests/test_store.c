#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/matter_crypto_mbedtls.h"
#include "test_case_fixture.h"
#include "matter_store_host.h"
#include "matter_store_file.h"
#include "storage/matter_store_tlv.h"
#include "test_vid.h"
#ifdef MATTER_TEST_ALLOC
#include "test_alloc_bytes.h"
#endif
typedef struct {
    CaseFixture* cases; Matter_Store_File_T file; Matter_Store_Blob_Port_T blob; Matter_Store_Host_T store;
    Matter_Commissioning_Host_Image_T image; Matter_Commissioning_Host_T commissioning;
    Matter_Diagnostics_Host_Image_T diag; Matter_Root_Settings_T root,changed;
    Matter_Wifi_Sim_Config_T config; Matter_Wifi_Sim_T sim; Matter_Wifi_T wifi;
    Matter_Case_Resumption_T resumption[2];
    Matter_Store_Data_T data,previous; Matter_Acl_Entry_T entries[4]; Matter_Groupkey_Set_T set;
    uint8_t keys[3][16],bytes[MATTER_STORE_BLOB_MAX],copy[MATTER_STORE_BLOB_MAX]; size_t size,copy_size;
} StoreTest;
static Matter_Result_T retire(void* u,bool success) { (void)u; (void)success; return MATTER_OK; }
static void model_drop(FabFixture* f) {
    OC_CHECK(matter_opcreds_delete(f->o->core)==MATTER_OK && matter_fabric_delete(f->model)==MATTER_OK && matter_fabric_host_delete(f->host)==MATTER_OK);
    f->o->core=NULL; f->model=NULL; f->host=NULL;
}
static void model_attach(FabFixture* f) { f->o->core=matter_opcreds_new(&f->o->config.identity,&f->o->port); OC_CHECK(f->o->core); fab_attach(f); }
static void read_file(StoreTest* t) { OC_CHECK(t->blob.read(t->blob.user,t->bytes,sizeof(t->bytes),&t->size)==MATTER_OK); }
static void same_file(StoreTest* t) { read_file(t); OC_CHECK(t->size==t->copy_size && !memcmp(t->bytes,t->copy,t->size)); }
#ifdef MATTER_TEST_ALLOC
static void scratch_checks(StoreTest* t,FabFixture* f) {
    size_t idle=live_bytes,start=calls; peak_bytes=idle; max_request=0;
    OC_CHECK(matter_store_host_save(t->store)==MATTER_OK && live_bytes==idle);
    size_t count=calls-start,peak=peak_bytes-idle;
    read_file(t); memcpy(t->copy,t->bytes,t->size); t->copy_size=t->size;
    t->changed=t->root; t->changed.node_label_size=1; t->changed.node_label[0]='Q';
    for(size_t i=1;i<=count;++i) {
        fail_at=calls+i;
        OC_CHECK(matter_store_host_root(t->store,&t->changed)==MATTER_LIMIT_REACHED);
        fail_at=0; same_file(t);
        OC_CHECK(live_bytes==idle && memcmp(&t->root,&t->changed,sizeof(t->root)));
    }
    /* A failed rollback-image allocation must precede every model mutation. */
    const Matter_Fabric_View_T* view=f->port.view(f->host);
    uint32_t version=view->revision; uint8_t label_size=view->records[0].label_size;
    fail_at=calls+1;
    OC_CHECK(f->port.label(f->host,1,(const uint8_t*)"oom-check",9)==MATTER_LIMIT_REACHED);
    fail_at=0; same_file(t);
    OC_CHECK(view->revision==version && view->records[0].label_size==label_size && live_bytes==idle);
    printf("MEMORY store save: idle_tracked=%zu transient_peak=%zu largest_request=%zu fault_sites=%zu\n",idle,peak,max_request,count);
}
#endif
static void ota_seed(StoreTest* t) {
    Matter_Ota_Provider_T provider={UINT64_C(0x20000000000001),0,1};
    OC_CHECK(matter_store_host_ota_store(t->store,1,&provider)==MATTER_OK);
    read_file(t); memcpy(t->copy,t->bytes,t->size); t->copy_size=t->size;
    ++provider.node;
    for(unsigned fault=1;fault<=4;++fault) {
        matter_store_file_fault(t->file,fault);
        OC_CHECK(matter_store_host_ota_store(t->store,1,&provider)==MATTER_PORT_ERROR); same_file(t);
        OC_CHECK(matter_store_host_ota_load(t->store,t->data.ota)==MATTER_OK && t->data.ota[0].node==provider.node-1);
    }
    matter_store_file_fault(t->file,0);
    OC_CHECK(matter_store_tlv_decode(t->bytes,t->size,&t->data)==MATTER_OK);
    t->data.ota[1]=t->data.ota[0]; OC_CHECK(!matter_store_data_valid(&t->data)); t->data.ota[1]=(Matter_Ota_Provider_T){0};
    t->data.ota[0].fabric=2; OC_CHECK(!matter_store_data_valid(&t->data)); t->data.ota[0].fabric=1;
    t->data.schema=5; OC_CHECK(!matter_store_data_valid(&t->data));
    memset(t->data.ota,0,sizeof(t->data.ota)); size_t n;
    OC_CHECK(matter_store_tlv_encode(&t->data,t->copy,sizeof(t->copy),&n)==MATTER_OK);
    OC_CHECK(matter_store_tlv_decode(t->copy,n,&t->previous)==MATTER_OK && t->previous.schema==7 && !t->previous.ota[0].fabric);
    puts("PASS OTA persistence: exact uint64, four atomic file faults, duplicate/orphan rejection, schema5 migration");
}
static void codec_checks(StoreTest* t) {
    read_file(t); OC_CHECK(matter_store_tlv_decode(t->bytes,t->size,&t->data)==MATTER_OK);
    OC_CHECK(t->bytes[0]==0x15 && t->bytes[1]==0x24 && t->bytes[2]==0 && t->bytes[3]==7);
    t->previous=t->data;
    size_t sizes[]={0,1,t->size/2,t->size-1};
    for(unsigned i=0;i<4;++i) { OC_CHECK(matter_store_tlv_decode(t->bytes,sizes[i],&t->data)!=MATTER_OK); OC_CHECK(!memcmp(&t->data,&t->previous,sizeof(t->data))); }
    t->bytes[3]=8; OC_CHECK(matter_store_tlv_decode(t->bytes,t->size,&t->data)!=MATTER_OK); t->bytes[3]=7;
    t->bytes[t->size]=0x18; OC_CHECK(matter_store_tlv_decode(t->bytes,t->size+1,&t->data)!=MATTER_OK);
    OC_CHECK(!memcmp(&t->data,&t->previous,sizeof(t->data)));
    t->data.fabrics.view.count=6; size_t n=0; OC_CHECK(matter_store_tlv_encode(&t->data,t->copy,sizeof(t->copy),&n)==MATTER_INVALID_ARGUMENT);
    t->data=t->previous;
#ifdef MATTER_TEST_ALLOC
    fail_at=calls+1; OC_CHECK(matter_store_tlv_decode(t->bytes,t->size,&t->data)==MATTER_LIMIT_REACHED); fail_at=0;
    OC_CHECK(!memcmp(&t->data,&t->previous,sizeof(t->data)));
#endif
    OC_CHECK(matter_store_tlv_encode(&t->data,t->copy,16,&n)==MATTER_LIMIT_REACHED && n==0);
    /* Explicit schema6 import keeps legacy mode; schema7 round-trips registers. */
    t->data.schema=6;
    OC_CHECK(matter_store_tlv_encode(&t->data,t->copy,sizeof(t->copy),&n)==MATTER_OK);
    OC_CHECK(matter_store_tlv_decode(t->copy,n,&t->data)==MATTER_OK && t->data.schema==7 && !t->data.eem.registers);
    t->previous=t->data;
    t->data.eem=(Matter_Eem_Checkpoint_T){.generation=3,.raw_mwh={12345678000,0},.total_mwh={12345678000,0},.initialized=true,.registers=true,.register_mask=1};
    OC_CHECK(matter_store_tlv_encode(&t->data,t->copy,sizeof(t->copy),&n)==MATTER_OK);
    OC_CHECK(matter_store_tlv_decode(t->copy,n,&t->data)==MATTER_OK && t->data.eem.registers && t->data.eem.register_mask==1 && t->data.eem.total_mwh[0]==INT64_C(12345678000));
    t->data.schema=6; OC_CHECK(matter_store_tlv_encode(&t->data,t->copy,sizeof(t->copy),&n)==MATTER_INVALID_ARGUMENT);
    t->data=t->previous;
    t->data.schema=4;
    OC_CHECK(matter_store_tlv_encode(&t->data,t->copy,sizeof(t->copy),&n)==MATTER_INVALID_ARGUMENT); /* No loss of meter state. */
    memset(&t->data.eem,0,sizeof(t->data.eem)); t->data.event_high=0;
    t->previous=t->data; t->previous.schema=7;
    OC_CHECK(matter_store_tlv_encode(&t->data,t->copy,sizeof(t->copy),&n)==MATTER_OK && t->copy[3]==4);
    OC_CHECK(matter_store_tlv_decode(t->copy,n,&t->data)==MATTER_OK && !memcmp(&t->data,&t->previous,sizeof(t->data)));
    t->data.schema=3;
    OC_CHECK(matter_store_tlv_encode(&t->data,t->copy,sizeof(t->copy),&n)==MATTER_INVALID_ARGUMENT); /* No silent loss. */
    for(unsigned i=0;i<5;++i) {
        Matter_Fabric_Record_T* f=&t->data.fabrics.view.records[i]; f->vvs_size=0; f->vvsc_size=0;
        memset(f->vvs,0,85); memset(f->vvsc,0,400);
    }
    t->previous=t->data; t->previous.schema=7;
    OC_CHECK(matter_store_tlv_encode(&t->data,t->copy,sizeof(t->copy),&n)==MATTER_OK && t->copy[3]==3);
    OC_CHECK(matter_store_tlv_decode(t->copy,n,&t->data)==MATTER_OK && !memcmp(&t->data,&t->previous,sizeof(t->data)));
    t->data.schema=2; t->previous=t->data; t->previous.schema=7;
    OC_CHECK(matter_store_tlv_encode(&t->data,t->copy,sizeof(t->copy),&n)==MATTER_OK && t->copy[3]==2);
    OC_CHECK(matter_store_tlv_decode(t->copy,n,&t->data)==MATTER_OK && !memcmp(&t->data,&t->previous,sizeof(t->data)));
    t->data.schema=1;
    for(unsigned i=0;i<5;++i) { t->data.fabrics.view.records[i].label_size=0; memset(t->data.fabrics.view.records[i].label,0,32); }
    t->previous=t->data; t->previous.schema=7;
    OC_CHECK(matter_store_tlv_encode(&t->data,t->copy,sizeof(t->copy),&n)==MATTER_OK && t->copy[3]==1);
    OC_CHECK(matter_store_tlv_decode(t->copy,n,&t->data)==MATTER_OK && t->data.schema==7);
    OC_CHECK(!memcmp(&t->data,&t->previous,sizeof(t->data))); /* Exact schema1 migration, labels initially empty. */
}
/* Independent file and fresh images: malformed storage must not publish defaults
 * over existing data or silently reset a commissioned node. */
static void restore_checks(StoreTest* t,const char* path) {
    size_t size=strlen(path)+16; char* other=calloc(size,1); OC_CHECK(other);
    snprintf(other,size,"%s.probe",path);
    Matter_Store_File_T file=matter_store_file_new(other); OC_CHECK(file); free(other);
    Matter_Store_Blob_Port_T blob=matter_store_file_port(file);
    Matter_Fabric_Host_Image_T fabric=matter_fabric_host_image_new(); OC_CHECK(fabric);
    Matter_Commissioning_Host_Image_T image=matter_commissioning_host_image_new(&t->config.initial,&t->config.connected); OC_CHECK(image);
    Matter_Diagnostics_Host_Image_T* diag=calloc(1,sizeof(*diag)); OC_CHECK(diag);
    Matter_Root_Settings_T* root=calloc(1,sizeof(*root)); OC_CHECK(root); root->location[0]=root->location[1]='Z';
    Matter_Store_Host_T store=matter_store_host_new(&blob,fabric,image,root,diag,false); OC_CHECK(store);
    OC_CHECK(matter_store_host_save(store)==MATTER_OK && matter_store_host_delete(store)==MATTER_OK);
    OC_CHECK(blob.read(blob.user,t->copy,sizeof(t->copy),&t->copy_size)==MATTER_OK);
    root->location[0]='P'; root->location[1]='L'; diag->hours=13;
    for(unsigned fault=0;fault<3;++fault) {
        if(fault==1) t->copy[3]=8;
        OC_CHECK(blob.replace(blob.user,t->copy,fault==0?t->copy_size/2:t->copy_size)==MATTER_OK);
        if(fault==2) {
#ifdef MATTER_TEST_ALLOC
            fail_at=calls+2; /* Object succeeds; deferred work-image allocation fails. */
            OC_CHECK(!matter_store_host_new(&blob,fabric,image,root,diag,true)); fail_at=0;
#else
            continue;
#endif
        } else OC_CHECK(!matter_store_host_new(&blob,fabric,image,root,diag,true));
        OC_CHECK(root->location[0]=='P' && diag->hours==13);
        t->copy[3]=7;
    }
    OC_CHECK(blob.replace(blob.user,t->copy,t->copy_size)==MATTER_OK);
#ifdef MATTER_TEST_ALLOC
    size_t start=calls;
#endif
    store=matter_store_host_new(&blob,fabric,image,root,diag,true); OC_CHECK(store && root->location[0]=='Z' && !diag->hours);
#ifdef MATTER_TEST_ALLOC
    size_t restore_allocations=calls-start;
    OC_CHECK(matter_store_host_delete(store)==MATTER_OK);
    root->location[0]='P'; root->location[1]='L'; diag->hours=13;
    size_t base=live_bytes;
    for(size_t i=1;i<=restore_allocations;++i) {
        fail_at=calls+i; OC_CHECK(!matter_store_host_new(&blob,fabric,image,root,diag,true)); fail_at=0;
        OC_CHECK(root->location[0]=='P' && root->location[1]=='L' && diag->hours==13 && live_bytes==base);
    }
    store=matter_store_host_new(&blob,fabric,image,root,diag,true); OC_CHECK(store && root->location[0]=='Z' && !diag->hours);
    printf("MEMORY store restore: all %zu allocation faults preserve RAM and release scratch\n",restore_allocations);
#endif
    OC_CHECK(matter_store_host_delete(store)==MATTER_OK && matter_store_file_delete(file)==MATTER_OK);
    OC_CHECK(matter_fabric_host_image_delete(fabric)==MATTER_OK && matter_commissioning_host_image_delete(image)==MATTER_OK);
    free(root); free(diag);
    read_file(t); OC_CHECK(matter_store_tlv_decode(t->bytes,t->size,&t->data)==MATTER_OK && t->data.root.location[0]=='P');
    puts("PASS store restore: independent files, corrupt/truncated/schema/OOM rejection without partial publication");
}
#include "test_update_store.h"
#include "test_meter_store.h"
static void vid_store_checks(StoreTest* t,FabFixture* f) {
    read_file(t); memcpy(t->copy,t->bytes,t->size); t->copy_size=t->size;
    uint32_t version=matter_opcreds_version(f->o->core);
    vid_request(f,7,0x6a01,85,400);
    for(unsigned fault=1;fault<=4;++fault) {
        matter_store_file_fault(t->file,fault); vid_call(f,1,12,MATTER_IM_FAILURE); same_file(t);
        OC_CHECK(matter_opcreds_version(f->o->core)==version && !f->port.view(f->host)->records[0].vvs_size);
    }
    matter_store_file_fault(t->file,0);
#ifdef MATTER_TEST_ALLOC
    fail_at=calls+1; vid_call(f,1,12,MATTER_IM_FAILURE); fail_at=0; same_file(t);
#endif
    vid_call(f,1,12,0); read_file(t);
    OC_CHECK(matter_store_tlv_decode(t->bytes,t->size,&t->data)==MATTER_OK);
    OC_CHECK(t->data.fabrics.view.records[0].vendor==0x6a01 && t->data.fabrics.view.records[0].vvs_size==85 && t->data.fabrics.view.records[0].vvsc_size==400);
    /* Storage rejects malformed metadata without altering the supplied image. */
    t->data.fabrics.view.records[0].vvs_size=84; OC_CHECK(!matter_store_data_valid(&t->data));
    t->data.fabrics.view.records[0].vvs_size=85;
    t->data.fabrics.view.records[0].icac_size=1; OC_CHECK(!matter_store_data_valid(&t->data));
    puts("PASS VID store: schema4, atomic file failures/OOM, validation, pending/committed state");
}
int main(int argc,char** argv) {
    OC_CHECK(argc==4); bool load=!strcmp(argv[1],"load"),pending=!strcmp(argv[3],"pending");
    StoreTest* t=calloc(1,sizeof(*t)); OC_CHECK(t);
    Matter_Crypto_Mbedtls_T crypto=matter_crypto_mbedtls_new(NULL); OC_CHECK(crypto);
    Matter_Crypto_Port_T cp; Matter_Credentials_Port_T credentials;
    OC_CHECK(matter_crypto_mbedtls_port(crypto,&cp)==MATTER_OK && matter_crypto_mbedtls_credentials(crypto,&credentials)==MATTER_OK);
    t->cases=case_fixture(&cp,&credentials); FabFixture* server=t->cases->fabrics[1];
    t->config.initial.enabled=true; t->config.initial.count=1; t->config.initial.networks[0].id=(Matter_Wifi_Id_T){3,{'o','l','d'}};
    t->config.connected=t->config.initial.networks[0].id;
    t->image=matter_commissioning_host_image_new(&t->config.initial,&t->config.connected); OC_CHECK(t->image);
    t->root.location[0]=t->root.location[1]='Z';
    if(load) {
        for(unsigned i=0;i<2;++i) { OC_CHECK(matter_case_delete(t->cases->session[i])==MATTER_OK); t->cases->session[i]=NULL; }
        model_drop(server); OC_CHECK(matter_fabric_host_image_delete(server->image)==MATTER_OK);
        server->image=matter_fabric_host_image_new(); OC_CHECK(server->image);
    }
    t->file=matter_store_file_new(argv[2]); OC_CHECK(t->file && !matter_store_file_new(argv[2])); t->blob=matter_store_file_port(t->file);
    t->store=matter_store_host_new(&t->blob,server->image,t->image,&t->root,&t->diag,load); OC_CHECK(t->store);
    if(!load) meter_store_seed(t); else meter_store_restored(t);
    if(load) model_attach(server); /* Boot rolls back journal BEFORE CASE publication. */
#ifdef MATTER_TEST_ALLOC
    if(!load) scratch_checks(t,server);
#endif
    t->config.initial=*matter_commissioning_host_settings(t->image); t->config.connected=*matter_commissioning_host_connected(t->image);
    t->sim=matter_wifi_sim_new(&t->config,0); OC_CHECK(t->sim); Matter_Wifi_Port_T wp=matter_wifi_sim_port(t->sim); Matter_Wifi_Config_T wc={4,2,2,1,1,100};
    t->wifi=matter_wifi_new(&wc,&wp,0); OC_CHECK(t->wifi);
    Matter_Commissioning_Host_Port_T hp={NULL,retire}; t->commissioning=matter_commissioning_host_new(t->image,t->wifi,t->sim,server->o->core,server->host,&hp); OC_CHECK(t->commissioning);
    if(!load) {
        OC_CHECK(matter_commissioning_host_begin(t->commissioning)==MATTER_OK);
        OC_CHECK(server->port.label(server->host,1,(const uint8_t*)"persisted",9)==MATTER_OK);
        t->diag.hours=42; t->diag.reboots=7; t->changed=t->root;
        t->changed.node_label_size=4; memcpy(t->changed.node_label,"A\0BC",4); memcpy(t->changed.location,"PL",2);
        OC_CHECK(matter_store_host_root(t->store,&t->changed)==MATTER_OK);
        OC_CHECK(!matter_wifi_write(t->wifi,(const uint8_t[]){0x08},1));
        /* Storage faults must preserve both RAM and the previous durable blob. */
        Matter_Acl_Port_T acl=matter_fabric_host_acl_port(server->host);
        memcpy(t->entries,acl.view(acl.user)->fabrics[0].entries,sizeof(t->entries));
        t->entries[0].subject_count=2; t->entries[0].subjects[1]=UINT64_C(0x0123456789abcdef);
        read_file(t); memcpy(t->copy,t->bytes,t->size); t->copy_size=t->size;
        for(unsigned stage=1;stage<=4;++stage) {
            matter_store_file_fault(t->file,stage);
            OC_CHECK(server->port.label(server->host,1,(const uint8_t*)"failed",6)==MATTER_PORT_ERROR);
            OC_CHECK(server->port.remove(server->host,1)==MATTER_PORT_ERROR);
            OC_CHECK(!matter_fabric_host_reset_requested(server->host));
            OC_CHECK(server->port.view(server->host)->records[0].label_size==9 && t->root.node_label_size==4 && t->diag.hours==42);
            OC_CHECK(acl.store(acl.user,1,t->entries,1)==MATTER_IM_FAILURE && acl.view(acl.user)->fabrics[0].entries[0].subject_count==1);
            OC_CHECK(matter_commissioning_host_complete(t->commissioning,1)==MATTER_PORT_ERROR && matter_commissioning_host_pending(t->image) && server->port.view(server->host)->added);
            same_file(t);
        }
        matter_store_file_fault(t->file,0);
#ifdef MATTER_TEST_ALLOC
        fail_at=calls+1; OC_CHECK(acl.store(acl.user,1,t->entries,1)==MATTER_IM_FAILURE); fail_at=0; same_file(t);
#endif
        OC_CHECK(acl.store(acl.user,1,t->entries,1)==0);
        Matter_Groupkey_Port_T group=matter_fabric_host_groupkey_port(server->host);
        t->set=(Matter_Groupkey_Set_T){.id=9,.count=2,.times={UINT64_C(0x0020000000000001),UINT64_MAX}}; memset(t->keys,0x37,sizeof(t->keys));
        OC_CHECK(!group.store(group.user,1,&t->set,(const uint8_t (*)[16])t->keys));
        if(!pending) OC_CHECK(matter_commissioning_host_complete(t->commissioning,1)==MATTER_OK && !matter_commissioning_host_pending(t->image));
        if(!pending) update_checks(t,server);
        vid_store_checks(t,server);
        codec_checks(t); restore_checks(t,argv[2]);
        meter_store_restored(t); ota_seed(t); meter_staging(argv[2]);
        printf("PASS store seed %s: %zu-byte TLV, atomic file faults/OOM, ACL/GKM, combined commit\n",argv[3],t->size);
    } else {
        OC_CHECK(t->root.node_label_size==4 && !memcmp(t->root.node_label,"A\0BC",4) && !memcmp(t->root.location,"PL",2) && t->diag.hours==42 && t->diag.reboots==7);
        OC_CHECK(server->port.view(server->host)->count==(pending?0u:1u));
        OC_CHECK(matter_wifi_sim_settings(t->sim)->enabled==pending);
        OC_CHECK(matter_store_host_ota_load(t->store,t->data.ota)==MATTER_OK);
        OC_CHECK(pending?!t->data.ota[0].fabric:t->data.ota[0].node==UINT64_C(0x20000000000001));
        if(pending) OC_CHECK(matter_commissioning_host_pending(t->image) && matter_commissioning_host_cleanup(t->commissioning)==MATTER_OK && !matter_commissioning_host_pending(t->image));
        else {
            OC_CHECK(server->port.view(server->host)->records[0].vendor==0x6a01 && server->port.view(server->host)->records[0].vvs_size==85 && server->port.view(server->host)->records[0].vvsc_size==400);
            vid_sign_request(server,1,32); vid_call(server,1,13,0); vid_verify(server,0);
            OC_CHECK(server->port.view(server->host)->records[0].label_size==9 && !memcmp(server->port.view(server->host)->records[0].label,"persisted",9));
            Matter_Acl_Port_T acl=matter_fabric_host_acl_port(server->host); Matter_Groupkey_Port_T group=matter_fabric_host_groupkey_port(server->host);
            OC_CHECK(acl.view(acl.user)->fabrics[0].entries[0].subjects[1]==UINT64_C(0x0123456789abcdef));
            OC_CHECK(group.view(group.user)->fabrics[0].sets[1].times[0]==UINT64_C(0x0020000000000001) && group.view(group.user)->fabrics[0].sets[1].times[1]==UINT64_MAX);
            for(unsigned i=0;i<2;++i) { t->cases->ports[i]=matter_fabric_host_case_port(t->cases->fabrics[i]->host); t->cases->session[i]=matter_case_new(&cp,&credentials,&t->cases->ports[i],&t->cases->config[i],0); OC_CHECK(t->cases->session[i]); }
            case_establish(t->cases); OC_CHECK(matter_case_take_keys(t->cases->session[0],&t->cases->keys[0])==MATTER_OK);
            OC_CHECK(matter_case_take_keys(t->cases->session[1],&t->cases->keys[1])==MATTER_OK);
            OC_CHECK(!memcmp(t->cases->keys[0].traffic.send_key,t->cases->keys[1].traffic.receive_key,16));
            OC_CHECK(t->cases->ports[1].resume_find(server->host,1,101,NULL,&t->resumption[0])==MATTER_OK);
            OC_CHECK(server->port.remove(server->host,1)==MATTER_OK);
            OC_CHECK(t->cases->ports[1].resume_find(server->host,0,0,t->resumption[0].id,&t->resumption[1])==MATTER_INVALID_STATE);
            OC_CHECK(matter_fabric_host_reset_requested(server->host));
            read_file(t); OC_CHECK(matter_store_tlv_decode(t->bytes,t->size,&t->data)==MATTER_OK);
            OC_CHECK(!t->data.ota[0].fabric);
            OC_CHECK(!t->data.fabrics.view.count && !t->data.fabrics.journal && !t->data.root.node_label_size &&
                t->data.root.location[0]=='X' && !t->data.wifi.settings.count && !t->data.wifi.pending && !t->data.hours && !t->data.reboots);
            for(unsigned j=0;j<5;++j) for(unsigned k=0;k<32;++k) OC_CHECK(!t->data.fabrics.keys[j][k]);
            puts("PASS last fabric: atomic commissioned state reset, keys erased, provisioning external");
        }
        meter_store_restored(t);
        puts(pending?"PASS store process restart: unfinished journal removed fabric/key/ACL/GKM; old Wi-Fi restored":"PASS store process restart: CASE using restored operational key/IPK, exact uint64 ACL/GKM, settings and diagnostics");
    }
    OC_CHECK(matter_commissioning_host_delete(t->commissioning)==MATTER_OK && matter_store_host_delete(t->store)==MATTER_OK && matter_store_file_delete(t->file)==MATTER_OK);
    OC_CHECK(matter_wifi_stop(t->wifi)==MATTER_OK);
    if(!load && pending) OC_CHECK(matter_wifi_commit(t->wifi)==MATTER_OK);
    OC_CHECK(matter_wifi_delete(t->wifi)==MATTER_OK && matter_wifi_sim_delete(t->sim)==MATTER_OK && matter_commissioning_host_image_delete(t->image)==MATTER_OK);
    if(load && pending) for(unsigned i=0;i<2;++i) { t->cases->ports[i]=matter_fabric_host_case_port(t->cases->fabrics[i]->host); t->cases->session[i]=matter_case_new(&cp,&credentials,&t->cases->ports[i],&t->cases->config[i],0); OC_CHECK(t->cases->session[i]); }
    case_free(t->cases); OC_CHECK(matter_crypto_mbedtls_delete(crypto)==MATTER_OK); memset(t,0,sizeof(*t)); free(t);
#ifdef MATTER_TEST_ALLOC
    OC_CHECK(!live);
#endif
    return 0;
}
