/* File/clock/mbedTLS/simulated-radio adapter; protocol composition is portable. */
#include "matter_server.h"
#include "runtime/matter_runtime.h"
#include "matter_store_file.h"
#include "matter_ota_file.h"
#include "matter_host_platform.h"
#include "matter_wifi_sim.h"
#include "crypto/matter_crypto_mbedtls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct Matter_Server {
    void* clock_user; bool started;
    Matter_Result_T (*clock_utc)(void*,Matter_Cert_Time_T*);
    Matter_Result_T (*clock_timestamp)(void*,uint32_t*);
    Matter_Runtime_T runtime; Matter_Crypto_Mbedtls_T backend;
    Matter_Wifi_Sim_T sim; Matter_Store_File_T file,update_file;
    Matter_Ota_Update_T update; Matter_Ota_File_T ota_file;
    Matter_Runtime_Config_T config; Matter_Root_Config_T identity;
    uint8_t certs[4][2048],key[32];
};
static void erase(void* p,size_t n) { volatile uint8_t* b=p; while(n--) *b++=0; }
static Matter_Result_T utc(void* u,Matter_Cert_Time_T* out) {
    Matter_Server_T s=u; if(s->clock_utc) return s->clock_utc(s->clock_user,out);
    struct tm t; if(!matter_host_utc(&t)) return MATTER_OFFLINE;
    *out=(Matter_Cert_Time_T){(uint16_t)(t.tm_year+1900),(uint8_t)(t.tm_mon+1),(uint8_t)t.tm_mday,
        (uint8_t)t.tm_hour,(uint8_t)t.tm_min,(uint8_t)t.tm_sec}; return MATTER_OK;
}
static Matter_Result_T timestamp(void* u,uint32_t* out) {
    Matter_Server_T s=u; if(s->clock_timestamp) return s->clock_timestamp(s->clock_user,out);
    uint64_t seconds,epoch=UINT64_C(946684800);
    if(!matter_host_epoch(&seconds) || seconds<epoch || seconds-epoch>UINT32_MAX) return MATTER_PORT_ERROR;
    *out=(uint32_t)(seconds-epoch); return MATTER_OK;
}
static void log_line(void* u,const char* line) { (void)u; fputs(line,stdout); fflush(stdout); }
static Matter_Result_T regulatory(void* u,const Matter_Root_Settings_T* settings,uint8_t candidate,bool* supported) {
    (void)u; (void)settings; (void)candidate; *supported=true; return MATTER_OK;
}
static Matter_Result_T initialize(void* u,const Matter_Wifi_Settings_T* settings,const Matter_Wifi_Id_T* connected) {
    Matter_Wifi_Port_T p=matter_wifi_sim_port(u); return p.restore(p.user,settings,connected);
}
static Matter_Result_T process(void* u,Matter_Wifi_T w,uint64_t now) { return matter_wifi_sim_process(u,w,now); }
static Matter_Result_T observe(void* u,Matter_Wifi_Ap_T* a,bool* online) { return matter_wifi_sim_observe(u,a,online); }
static bool read_file(const char* dir,const char* name,uint8_t* out,size_t capacity,size_t* size) {
    size_t length=strlen(dir)+strlen(name)+2; char* path=malloc(length); if(!path) return false;
    snprintf(path,length,"%s/%s",dir,name); FILE* f=fopen(path,"rb"); free(path); if(!f) return false;
    *size=fread(out,1,capacity,f); bool ok=*size>0 && !ferror(f) && fgetc(f)==EOF; fclose(f); return ok;
}
Matter_Server_T matter_server_new(const char* directory,const char* path,const Matter_Root_Config_T* identity,uint32_t pin,uint64_t now) {
    return matter_server_new_ota_sim(directory,path,identity,pin,now,NULL);
}
Matter_Server_T matter_server_new_ota_sim(const char* directory,const char* path,const Matter_Root_Config_T* identity,uint32_t pin,uint64_t now,const char* public_key) {
    Matter_Server_Sim_Options_T options={.ota_public_key=public_key};
    return matter_server_new_sim(directory,path,identity,pin,now,&options);
}
Matter_Server_T matter_server_new_sim(const char* directory,const char* path,const Matter_Root_Config_T* identity,uint32_t pin,uint64_t now,const Matter_Server_Sim_Options_T* options) {
    if(!directory || !path || !identity) return NULL;
    const char* public_key=options?options->ota_public_key:NULL;
    Matter_Server_T s=calloc(1,sizeof(*s)); if(!s) return NULL;
    s->identity=*identity; Matter_Runtime_Config_T* c=&s->config; c->identity=&s->identity;
    if(options) c->network=options->network;
    s->backend=matter_crypto_mbedtls_new(NULL);
    if(!s->backend || matter_crypto_mbedtls_port(s->backend,&c->crypto)!=MATTER_OK ||
        matter_crypto_mbedtls_credentials(s->backend,&c->credentials)!=MATTER_OK) goto fail;
    const char* names[]={"dac.der","pai.der","paa.der","cd.der"};
    Matter_Der_T* blobs[]={&c->attestation.identity.dac,&c->attestation.identity.pai,&c->attestation.trusted_paa,&c->attestation.identity.certification_declaration};
    for(unsigned i=0;i<4;++i) { size_t size; if(!read_file(directory,names[i],s->certs[i],sizeof(s->certs[i]),&size)) goto fail; *blobs[i]=(Matter_Der_T){s->certs[i],size}; }
    size_t size; if(!read_file(directory,"dac-key.bin",s->key,sizeof(s->key),&size) || size!=32) goto fail;
    c->attestation.dac_private=s->key;
    uint8_t digest[32];
    /* Simulation identity remains stable across process restarts, independently
     * of the ephemeral DNS instance. New development credentials reset it. */
    if(c->crypto.sha256(c->crypto.user,c->attestation.identity.dac.data,c->attestation.identity.dac.size,digest)!=MATTER_OK) goto fail;
    static const char hex[]="0123456789ABCDEF";
    s->identity.unique_id.size=32;
    for(unsigned i=0;i<16;++i) { s->identity.unique_id.data[i*2]=(uint8_t)hex[digest[i]>>4]; s->identity.unique_id.data[i*2+1]=(uint8_t)hex[digest[i]&15]; }
    erase(digest,sizeof(digest));
    if(options && options->unique_id) {
        if(!options->unique_id->size || options->unique_id->size>sizeof(s->identity.unique_id.data)) goto fail;
        s->identity.unique_id=*options->unique_id;
    }
    Matter_Wifi_Sim_Config_T* wc=calloc(1,sizeof(*wc)); if(!wc) goto fail;
    wc->initial.enabled=true; wc->latency_ms=10;
    /* Deterministic radio environment only: no OS Wi-Fi configuration. */
    wc->count=2;
    static const char* const ssids[]={"testharness","testharness-2"};
    for(unsigned i=0;i<wc->count;++i) {
        Matter_Wifi_Sim_Ap_T* ap=&wc->aps[i];
        ap->ap.ssid.size=(uint8_t)strlen(ssids[i]); memcpy(ap->ap.ssid.bytes,ssids[i],ap->ap.ssid.size);
        ap->ap.security=8; ap->ap.bssid[0]=2; ap->ap.bssid[5]=(uint8_t)(i+1);
        ap->ap.channel=(uint16_t)(i?6:1); ap->ap.band=0; ap->ap.rssi=(int8_t)(i?-55:-40);
        ap->credential_size=13; memcpy(ap->credentials,"wifi-password",13);
    }
    if(options && options->wifi_connected) {
        /* Model an already associated on-network device. Runtime restoration
         * replaces this fresh-state seed before constructing the Wi-Fi cluster. */
        const Matter_Wifi_Sim_Ap_T* ap=&wc->aps[0];
        wc->initial.count=1; wc->connected=ap->ap.ssid;
        wc->initial.networks[0].id=ap->ap.ssid;
        wc->initial.networks[0].credential_size=ap->credential_size;
        memcpy(wc->initial.networks[0].credentials,ap->credentials,ap->credential_size);
    }
    s->sim=matter_wifi_sim_new(wc,now); erase(wc,sizeof(*wc)); free(wc); if(!s->sim) goto fail;
    s->file=matter_store_file_new(path); if(!s->file) goto fail;
    c->storage=matter_store_file_port(s->file);
    if(public_key) {
        uint8_t key[65]; FILE* file=fopen(public_key,"rb");
        bool ok=file && fread(key,1,sizeof(key),file)==sizeof(key) && fgetc(file)==EOF && !ferror(file);
        if(file && fclose(file)) ok=false;
        size_t length=strlen(path); char* journal=length<=32000?malloc(length+9):NULL;
        if(journal) { memcpy(journal,path,length); memcpy(journal+length,".ota-sim",9); s->update_file=matter_store_file_new(journal); free(journal); }
        if(ok && s->update_file) {
            Matter_Store_Blob_Port_T blob=matter_store_file_port(s->update_file);
            s->update=matter_ota_update_new(&blob,&c->crypto,key,identity->vendor_id,identity->product_id,identity->software_version);
        }
        if(!s->update) goto fail;
        s->identity.software_version=matter_ota_update_version(s->update);
        if(s->identity.software_version!=identity->software_version) {
            int n=snprintf((char*)s->identity.software_string.data,sizeof(s->identity.software_string.data),"sim-%lu",(unsigned long)s->identity.software_version);
            s->identity.software_string.size=(size_t)n;
        }
        printf("OTA_SIM_VERSION version=%lu boot=%u\n",(unsigned long)s->identity.software_version,
            matter_ota_update_booted(s->update) || matter_ota_update_trial(s->update)?5u:1u);
        if(matter_ota_update_rolled_back(s->update)) puts("OTA_SIM_ROLLBACK");
    }
    c->update=s->update; c->user=s; c->utc=utc; c->timestamp=timestamp; c->log=log_line; c->regulatory=regulatory;
    c->wifi=(Matter_Runtime_Wifi_Port_T){matter_wifi_sim_port(s->sim),initialize,process,observe};
    c->wifi_config=(Matter_Wifi_Config_T){4,10,20,1,identity->basic_version,1};
    c->iface=(Matter_Diagnostics_Interface_T){.name="simulated-wifi",.name_size=14,.type=1,.reachable4=-1,.reachable6=-1};
    c->boot_reason=matter_ota_update_booted(s->update) || matter_ota_update_trial(s->update)?5:1; c->reboot=true;
    s->runtime=matter_runtime_new(c,pin,now); erase(s->key,sizeof(s->key)); c->attestation.dac_private=NULL;
    if(s->runtime) return s;
fail:
    fprintf(stderr,"Host server initialization failed (credentials, state or allocation).\n");
    (void)matter_server_stop(s,now); (void)matter_server_delete(s); return NULL;
}
static Matter_Result_T prepare(void* u,uint32_t version) { return matter_ota_file_prepare(u,version); }
static Matter_Result_T commit(void* u) { return matter_ota_file_commit(u); }
static uint64_t artifact(void* u) { return matter_ota_file_artifact(u); }
static Matter_Result_T check(void* u,uint64_t id) { return matter_ota_file_check(u,id); }
static Matter_Result_T signed_image(void* u,uint64_t id,Matter_Ota_Signed_T* out) { return matter_ota_file_signed(u,id,out); }
static void invalidate(void* u) { matter_ota_file_invalidate(u); }
static void cancel(void* u) { matter_ota_file_cancel(u); }
static Matter_Result_T discard(void* u,uint64_t id) { return matter_ota_file_discard(u,id); }
static int progress(void* u) { return matter_ota_file_last_progress(u); }
Matter_Result_T matter_server_set_ota_file(Matter_Server_T s,const char* path) {
    if(!s || s->ota_file) return MATTER_INVALID_STATE;
    Matter_Ota_File_T file=matter_ota_file_new(path,s->identity.vendor_id,s->identity.product_id,s->identity.software_version);
    if(!file) return MATTER_INVALID_ARGUMENT;
    Matter_Runtime_Ota_Port_T port={file,matter_ota_file_sink(file),MATTER_OTA_FILE_LIMIT,prepare,commit,artifact,check,signed_image,invalidate,cancel,discard,progress};
    Matter_Result_T r=matter_runtime_set_ota(s->runtime,&port);
    if(r==MATTER_OK) s->ota_file=file; else matter_ota_file_delete(file);
    return r;
}
Matter_Result_T matter_server_delete(Matter_Server_T s) {
    if(!s) return MATTER_OK;
    Matter_Result_T r=matter_runtime_delete(s->runtime); if(r!=MATTER_OK) return r;
    matter_ota_file_delete(s->ota_file); matter_ota_update_delete(s->update);
    if(s->update_file) (void)matter_store_file_delete(s->update_file);
    if(s->file) (void)matter_store_file_delete(s->file);
    if(s->sim) (void)matter_wifi_sim_delete(s->sim);
    (void)matter_crypto_mbedtls_delete(s->backend); erase(s,sizeof(*s)); free(s); return MATTER_OK;
}
Matter_Root_T matter_server_root(Matter_Server_T s) { return matter_runtime_root(s?s->runtime:NULL); }
Matter_Store_Host_T matter_server_store(Matter_Server_T s) { return matter_runtime_store(s?s->runtime:NULL); }
bool matter_server_commissionable(Matter_Server_T s) { return matter_runtime_commissionable(s?s->runtime:NULL); }
bool matter_server_reset_requested(Matter_Server_T s) { return matter_runtime_reset_requested(s?s->runtime:NULL); }
bool matter_server_reset_ready(Matter_Server_T s) { return matter_runtime_reset_ready(s?s->runtime:NULL); }
bool matter_server_ota_reboot_requested(Matter_Server_T s) { return matter_runtime_ota_reboot_requested(s?s->runtime:NULL); }
bool matter_server_ota_trial(Matter_Server_T s) { return matter_runtime_ota_trial(s?s->runtime:NULL); }
const Matter_Fabric_View_T* matter_server_fabrics(Matter_Server_T s) { return matter_runtime_fabrics(s?s->runtime:NULL); }
uint8_t matter_server_commissioning_mode(Matter_Server_T s,uint16_t* d) { return matter_runtime_commissioning_mode(s?s->runtime:NULL,d); }
Matter_Result_T matter_server_ota_boot_ready(Matter_Server_T s) { return matter_runtime_ota_boot_ready(s?s->runtime:NULL); }
Matter_Result_T matter_server_set_resumption(Matter_Server_T s,Matter_Case_Resumption_Profile_T p) { return matter_runtime_set_resumption(s?s->runtime:NULL,p); }
Matter_Result_T matter_server_set_certificate_validity(Matter_Server_T s,bool chip) { return matter_runtime_set_certificate_validity(s?s->runtime:NULL,chip); }
Matter_Result_T matter_server_set_test_trigger(Matter_Server_T s,const Matter_Diagnostics_Test_Trigger_T* p) { return matter_runtime_set_test_trigger(s?s->runtime:NULL,p); }
Matter_Result_T matter_server_set_resolver(Matter_Server_T s,const Matter_Resolver_Port_T* p) { return matter_runtime_set_resolver(s?s->runtime:NULL,p); }
Matter_Result_T matter_server_set_outbound(Matter_Server_T s,const Matter_Udp_Path_T* p) { return matter_runtime_set_outbound(s?s->runtime:NULL,p); }
Matter_Result_T matter_server_set_clock(Matter_Server_T s,void* user,Matter_Result_T (*clock_utc)(void*,Matter_Cert_Time_T*),Matter_Result_T (*clock_timestamp)(void*,uint32_t*)) {
    if(!s || !clock_utc || !clock_timestamp) return MATTER_INVALID_ARGUMENT;
    if(s->started) return MATTER_INVALID_STATE;
    s->clock_user=user; s->clock_utc=clock_utc; s->clock_timestamp=clock_timestamp; return MATTER_OK;
}
Matter_Result_T matter_server_start(Matter_Server_T s,Matter_T owner,Matter_Udp_T udp,Matter_Events_T events) {
    if(s) s->started=true;
    return matter_runtime_start(s?s->runtime:NULL,owner,udp,events);
}
void matter_server_received(Matter_Server_T s,const Matter_Udp_Datagram_T* d) { matter_runtime_received(s?s->runtime:NULL,d); }
void matter_server_sent(Matter_Server_T s,uint64_t id,Matter_Operation_Result_T result) { matter_runtime_sent(s?s->runtime:NULL,id,result); }
void matter_server_changed(Matter_Server_T s) { matter_runtime_changed(s?s->runtime:NULL); }
Matter_Result_T matter_server_process(Matter_Server_T s,uint64_t now) { return matter_runtime_process(s?s->runtime:NULL,now); }
Matter_Result_T matter_server_stop(Matter_Server_T s,uint64_t now) { return matter_runtime_stop(s?s->runtime:NULL,now); }
