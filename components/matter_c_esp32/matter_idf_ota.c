#include "matter_idf_ota.h"
#include "matter_idf_store.h"
#include "codec/matter_ota_header_internal.h"
#include "esp_app_desc.h"
#include "esp_crc.h"
#include "esp_image_format.h"
#include "esp_ota_ops.h"
#include "psa/crypto.h"
#include <stdlib.h>
#include <string.h>

#if !CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE || !CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT
#define OTA_INSTALL_ENABLED 0
#else
#define OTA_INSTALL_ENABLED 1
#endif

enum { JOURNAL_SIZE=144, HEADER_MAX=1024 };
typedef struct {
    uint8_t header[16+HEADER_MAX]; size_t used,header_size;
    Matter_Tlv_Validation_Workspace_T validation; Matter_Tlv_Tag_T tags[32];
    psa_hash_operation_t hash; esp_ota_handle_t handle; bool opened,parsed;
} Download;
struct Matter_Idf_Ota {
    Matter_Idf_Store_T store; Matter_Store_Blob_Port_T journal;
    const esp_partition_t* target; Download* work;
    Matter_Ota_Install_Port_T install; Matter_Ota_Install_Boot_T boot;
    uint16_t vendor,product; uint32_t current,version,payload;
    uint64_t total,received,serial; uint8_t digest[32],fingerprint[32];
    bool boot_present,ready,valid,offline,selected;
};
static uint64_t le(const uint8_t* p,unsigned n) {
    uint64_t v=0; for(unsigned i=0;i<n;++i) v|=(uint64_t)p[i]<<(8*i); return v;
}
static void put(uint8_t* p,uint64_t v,unsigned n) {
    for(unsigned i=0;i<n;++i) { p[i]=(uint8_t)v; v>>=8; }
}
static bool number(const char* text,size_t capacity,uint32_t* out) {
    uint64_t v=0; size_t n=0;
    while(n<capacity && text[n]) {
        if(text[n]<'0' || text[n]>'9' || n>=10) return false;
        v=v*10+(unsigned)(text[n++]-'0'); if(v>UINT32_MAX) return false;
    }
    if(!n || n==capacity) return false;
    *out=(uint32_t)v; return true;
}
static Matter_Result_T save(Matter_Idf_Ota_T f,unsigned phase) {
    uint8_t d[JOURNAL_SIZE]={0}; const Matter_Ota_Apply_Context_T* c=&f->boot.context;
    memcpy(d,"MOTA01",6); d[6]=(uint8_t)phase;
    if(phase) {
        put(d+8,c->version,4); put(d+12,f->target->address,4); put(d+16,f->payload,4);
        memcpy(d+20,f->digest,32); put(d+52,c->provider.node,8); put(d+60,c->provider.endpoint,2);
        d[62]=c->provider.fabric; d[63]=(uint8_t)c->token_size; memcpy(d+64,c->token,c->token_size);
        memcpy(d+96,f->fingerprint,32);
    }
    put(d+140,esp_crc32_le(0,d,140),4);
    return f->journal.replace(f->journal.user,d,sizeof(d));
}
static void cancel(void* u) {
    Matter_Idf_Ota_T f=u; if(!f) return;
    if(f->work) {
        if(f->work->opened) (void)esp_ota_abort(f->work->handle);
        (void)psa_hash_abort(&f->work->hash); free(f->work); f->work=NULL;
    }
    f->ready=f->valid=false;
}
static Matter_Result_T prepare(void* u,uint32_t version) {
    Matter_Idf_Ota_T f=u;
    if(!f || f->offline || f->selected || f->boot_present || f->work || version<=f->current) return MATTER_INVALID_STATE;
    f->target=esp_ota_get_next_update_partition(NULL);
    if(!f->target || f->target==esp_ota_get_running_partition()) return MATTER_INVALID_STATE;
    f->version=version; f->total=f->received=0; f->payload=0; f->ready=f->valid=false;
    return MATTER_OK;
}
static Matter_Result_T open_sink(void* u) {
    Matter_Idf_Ota_T f=u;
    if(!f || !f->version || !f->target || f->work || f->offline || f->selected) return MATTER_INVALID_STATE;
    Download* w=calloc(1,sizeof(*w)); if(!w) return MATTER_LIMIT_REACHED;
    w->hash=psa_hash_operation_init();
    if(psa_hash_setup(&w->hash,PSA_ALG_SHA_256)!=PSA_SUCCESS) { (void)psa_hash_abort(&w->hash); free(w); return MATTER_PORT_ERROR; }
    f->work=w; return MATTER_OK;
}
static Matter_Result_T write_sink(void* u,const uint8_t* d,size_t n) {
    Matter_Idf_Ota_T f=u; Download* w=f?f->work:NULL;
    if(!w || !d || !n || n>1024 || f->received>UINT64_MAX-n) return MATTER_INVALID_ARGUMENT;
    size_t pos=0;
    while(pos<n && !w->parsed) {
        size_t target=w->used<16?16:16+w->header_size;
        size_t take=target-w->used; if(take>n-pos) take=n-pos;
        memcpy(w->header+w->used,d+pos,take); pos+=take; w->used+=take;
        if(w->used==16 && !w->header_size) {
            uint64_t header_size=le(w->header+12,4); f->total=le(w->header+4,8);
            if(le(w->header,4)!=UINT32_C(0x1beef11e) || !header_size || header_size>HEADER_MAX ||
                f->total<=16+header_size || f->total-16-header_size>f->target->size) return MATTER_INVALID_ARGUMENT;
            w->header_size=(size_t)header_size; f->payload=(uint32_t)(f->total-16-header_size);
        }
        if(w->header_size && w->used==16+w->header_size) {
            if(!matter_ota_header_parse(w->header+16,w->header_size,f->total,f->vendor,f->product,
                f->current,f->version,&w->validation,w->tags,f->digest)) return MATTER_INVALID_ARGUMENT;
            if(esp_ota_begin(f->target,OTA_WITH_SEQUENTIAL_WRITES,&w->handle)!=ESP_OK) return MATTER_PORT_ERROR;
            w->opened=w->parsed=true;
        }
    }
    if(f->total && (f->received>f->total || n>f->total-f->received)) return MATTER_INVALID_ARGUMENT;
    if(pos<n && (psa_hash_update(&w->hash,d+pos,n-pos)!=PSA_SUCCESS ||
        esp_ota_write(w->handle,d+pos,n-pos)!=ESP_OK)) return MATTER_PORT_ERROR;
    f->received+=n; return MATTER_OK;
}
static bool description(Matter_Idf_Ota_T f) {
    esp_app_desc_t* d=calloc(1,sizeof(*d)); if(!d) return false;
    uint32_t version=0; const esp_app_desc_t* running=esp_app_get_description();
    bool ok=esp_ota_get_partition_description(f->target,d)==ESP_OK &&
        number(d->version,sizeof(d->version),&version) && version==f->version &&
        !memcmp(d->project_name,running->project_name,sizeof(d->project_name));
    free(d); return ok;
}
static Matter_Result_T finish_sink(void* u,uint64_t bytes) {
    Matter_Idf_Ota_T f=u; Download* w=f?f->work:NULL; uint8_t digest[32]; size_t size=0;
    if(!w || !w->opened || !w->parsed || bytes!=f->total || bytes!=f->received ||
        psa_hash_finish(&w->hash,digest,sizeof(digest),&size)!=PSA_SUCCESS || size!=32 ||
        memcmp(digest,f->digest,32)) return MATTER_INVALID_ARGUMENT;
    esp_err_t e=esp_ota_end(w->handle); w->opened=false;
    if(e!=ESP_OK || !description(f)) return MATTER_PORT_ERROR;
    (void)psa_hash_abort(&w->hash); free(w); f->work=NULL; f->ready=true; return MATTER_OK;
}
static Matter_Result_T commit(void* u) {
    Matter_Idf_Ota_T f=u;
    if(!f || !f->ready || f->work || f->serial==UINT64_MAX) return MATTER_INVALID_STATE;
    f->ready=false; f->valid=true; ++f->serial; return MATTER_OK;
}
static uint64_t artifact(void* u) { Matter_Idf_Ota_T f=u; return f && f->valid?f->serial:0; }
static void invalidate(void* u) { Matter_Idf_Ota_T f=u; if(f) f->valid=false; }
static int progress(void* u) {
    Matter_Idf_Ota_T f=u;
    return f && f->total && f->received<=f->total?(int)((f->received*100+f->total/2)/f->total):-1;
}
static Matter_Result_T hash_partition(Matter_Idf_Ota_T f) {
    typedef struct { uint8_t bytes[1024]; psa_hash_operation_t hash; } Work;
    Work* w=calloc(1,sizeof(*w)); if(!w) return MATTER_LIMIT_REACHED;
    w->hash=psa_hash_operation_init();
    bool ok=psa_hash_setup(&w->hash,PSA_ALG_SHA_256)==PSA_SUCCESS;
    for(uint32_t offset=0;ok && offset<f->payload;) {
        size_t n=f->payload-offset; if(n>sizeof(w->bytes)) n=sizeof(w->bytes);
        ok=esp_partition_read(f->target,offset,w->bytes,n)==ESP_OK &&
            psa_hash_update(&w->hash,w->bytes,n)==PSA_SUCCESS; offset+=(uint32_t)n;
    }
    uint8_t digest[32]; size_t size=0;
    ok=ok && psa_hash_finish(&w->hash,digest,sizeof(digest),&size)==PSA_SUCCESS && size==32 && !memcmp(digest,f->digest,32);
    (void)psa_hash_abort(&w->hash); free(w); return ok?MATTER_OK:MATTER_PORT_ERROR;
}
static Matter_Result_T check(void* u,uint64_t id) {
    Matter_Idf_Ota_T f=u;
    if(!f || !id || !f->valid || id!=f->serial || f->work || f->offline || f->selected) return MATTER_INVALID_STATE;
    Matter_Result_T r=hash_partition(f); if(r!=MATTER_OK) return r;
    esp_image_metadata_t* data=calloc(1,sizeof(*data)); if(!data) return MATTER_LIMIT_REACHED;
    esp_partition_pos_t position={.offset=f->target->address,.size=f->target->size};
    bool ok=esp_image_verify(ESP_IMAGE_VERIFY_SILENT,&position,data)==ESP_OK && description(f);
    free(data); return ok?MATTER_OK:MATTER_PORT_ERROR;
}
static const Matter_Ota_Install_Boot_T* boot(void* u) {
    Matter_Idf_Ota_T f=u; return f && f->boot_present?&f->boot:NULL;
}
static Matter_Result_T accept(void* u,const Matter_Ota_Apply_Context_T* c,const uint8_t fingerprint[32]) {
    Matter_Idf_Ota_T f=u;
    if(!f || !c || !fingerprint || c->version!=f->version || c->token_size<8 || c->token_size>32 ||
        !c->provider.fabric || c->provider.fabric==255 || !c->provider.node ||
        c->provider.node>UINT64_C(0xffffffefffffffff) || c->provider.endpoint==UINT16_MAX) return MATTER_INVALID_ARGUMENT;
    Matter_Result_T r=check(f,c->artifact); if(r!=MATTER_OK) return r;
    f->boot.context=*c; memcpy(f->fingerprint,fingerprint,32);
    r=save(f,1); if(r!=MATTER_OK) { f->offline=true; return r; }
    esp_err_t e=esp_ota_set_boot_partition(f->target);
    if(e!=ESP_OK && esp_ota_get_boot_partition()!=f->target) { f->offline=true; return MATTER_PORT_ERROR; }
    f->selected=true; return MATTER_OK;
}
static Matter_Result_T confirm(void* u) {
    Matter_Idf_Ota_T f=u;
    if(!f || !f->boot_present || f->offline) return MATTER_INVALID_STATE;
    if(f->boot.state==MATTER_OTA_INSTALL_ROLLBACK) { f->boot_present=false; return MATTER_OK; }
    if(f->boot.state!=MATTER_OTA_INSTALL_TRIAL) return MATTER_INVALID_STATE;
    esp_ota_img_states_t state;
    if(esp_ota_get_state_partition(esp_ota_get_running_partition(),&state)!=ESP_OK) return MATTER_PORT_ERROR;
    if(state==ESP_OTA_IMG_PENDING_VERIFY && esp_ota_mark_app_valid_cancel_rollback()!=ESP_OK) return MATTER_PORT_ERROR;
    if(state!=ESP_OTA_IMG_PENDING_VERIFY && state!=ESP_OTA_IMG_VALID) return MATTER_INVALID_STATE;
    Matter_Result_T r=save(f,2);
    if(r==MATTER_OK) f->boot.state=MATTER_OTA_INSTALL_NOTIFY;
    return r;
}
static Matter_Result_T claim(void* u,const uint8_t fingerprint[32],bool live,Matter_Ota_Apply_Context_T* out) {
    Matter_Idf_Ota_T f=u;
    if(!f || !out || !fingerprint || !f->boot_present || f->boot.state!=MATTER_OTA_INSTALL_NOTIFY || f->offline) return MATTER_INVALID_STATE;
    bool match=live && !memcmp(fingerprint,f->fingerprint,32);
    Matter_Result_T r=save(f,0); if(r!=MATTER_OK) return r;
    if(match) *out=f->boot.context;
    f->boot_present=false; memset(&f->boot,0,sizeof(f->boot)); memset(f->fingerprint,0,32);
    return match?MATTER_OK:MATTER_OFFLINE;
}
static bool restore(Matter_Idf_Ota_T f) {
    uint8_t d[JOURNAL_SIZE]; size_t size=0;
    Matter_Result_T r=f->journal.read(f->journal.user,d,sizeof(d),&size);
    if(r==MATTER_OFFLINE) {
        esp_ota_img_states_t state;
        return esp_ota_get_state_partition(esp_ota_get_running_partition(),&state)!=ESP_OK || state!=ESP_OTA_IMG_PENDING_VERIFY;
    }
    if(r!=MATTER_OK || size!=sizeof(d) || memcmp(d,"MOTA01",6) || d[6]>2 || d[7] ||
        le(d+140,4)!=esp_crc32_le(0,d,140)) return false;
    for(unsigned i=128;i<140;++i) if(d[i]) return false;
    if(!d[6]) {
        esp_ota_img_states_t state;
        return esp_ota_get_state_partition(esp_ota_get_running_partition(),&state)!=ESP_OK || state!=ESP_OTA_IMG_PENDING_VERIFY;
    }
    Matter_Ota_Apply_Context_T* c=&f->boot.context;
    c->version=(uint32_t)le(d+8,4); c->provider.node=le(d+52,8); c->provider.endpoint=(uint16_t)le(d+60,2);
    c->provider.fabric=d[62]; c->token_size=d[63];
    if(!c->provider.fabric || c->provider.fabric==255 || !c->provider.node || c->provider.node>UINT64_C(0xffffffefffffffff) ||
        c->provider.endpoint==UINT16_MAX || c->token_size<8 || c->token_size>32) return false;
    memcpy(c->token,d+64,c->token_size); memcpy(f->fingerprint,d+96,32);
    esp_partition_iterator_t it=esp_partition_find(ESP_PARTITION_TYPE_APP,ESP_PARTITION_SUBTYPE_ANY,NULL);
    while(it) {
        const esp_partition_t* p=esp_partition_get(it);
        if(p->address==le(d+12,4)) { f->target=p; esp_partition_iterator_release(it); break; }
        it=esp_partition_next(it);
    }
    f->payload=(uint32_t)le(d+16,4); memcpy(f->digest,d+20,32);
    if(!f->target || f->target->subtype<ESP_PARTITION_SUBTYPE_APP_OTA_0 ||
        f->target->subtype>=ESP_PARTITION_SUBTYPE_APP_OTA_MAX || !f->payload || f->payload>f->target->size) return false;
    f->version=c->version;
    if(f->target!=esp_ota_get_running_partition()) {
        if(save(f,0)!=MATTER_OK) return false;
        f->boot.state=MATTER_OTA_INSTALL_ROLLBACK;
    } else {
        if(f->current!=c->version || hash_partition(f)!=MATTER_OK) return false;
        esp_ota_img_states_t state;
        if(esp_ota_get_state_partition(f->target,&state)!=ESP_OK ||
            (state!=ESP_OTA_IMG_VALID && state!=ESP_OTA_IMG_PENDING_VERIFY) ||
            (d[6]==2 && state!=ESP_OTA_IMG_VALID)) return false;
        f->boot.state=d[6]==2?MATTER_OTA_INSTALL_NOTIFY:MATTER_OTA_INSTALL_TRIAL;
    }
    f->boot_present=true; return true;
}
Matter_Idf_Ota_T matter_idf_ota_new(const char* partition,const char* space,uint16_t vendor,uint16_t product) {
    if(!OTA_INSTALL_ENABLED || !partition || !space || psa_crypto_init()!=PSA_SUCCESS) return NULL;
    Matter_Idf_Ota_T f=calloc(1,sizeof(*f)); if(!f) return NULL;
    f->vendor=vendor; f->product=product;
    const esp_app_desc_t* desc=esp_app_get_description();
    if(!number(desc->version,sizeof(desc->version),&f->current)) goto fail;
    f->store=matter_idf_store_new(partition,space); if(!f->store) goto fail;
    f->journal=matter_idf_store_port(f->store);
    f->install=(Matter_Ota_Install_Port_T){f,boot,accept,confirm,claim};
    if(!restore(f)) goto fail;
    return f;
fail:
    matter_idf_ota_delete(f); return NULL;
}
Matter_Runtime_Ota_Port_T matter_idf_ota_port(Matter_Idf_Ota_T f) {
    return (Matter_Runtime_Ota_Port_T){.user=f,.sink={f,open_sink,write_sink,finish_sink,cancel},
        .limit=UINT64_C(4)*1024*1024,.prepare=prepare,.commit=commit,.artifact=artifact,.check=check,
        .invalidate=invalidate,.cancel=cancel,.progress=progress,.install=f?&f->install:NULL};
}
uint32_t matter_idf_ota_version(Matter_Idf_Ota_T f) { return f?f->current:0; }
void matter_idf_ota_delete(Matter_Idf_Ota_T f) {
    if(f) { cancel(f); matter_idf_store_delete(f->store); memset(f,0,sizeof(*f)); free(f); }
}
