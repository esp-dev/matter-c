#include "matter_store_host.h"
#include "matter_store_internal.h"
#include "../storage/matter_store_source_internal.h"
#include <stdlib.h>
#include <string.h>
typedef struct {
    Matter_Store_Source_T source;
    Matter_Store_Wifi_T wifi; Matter_Root_Settings_T root;
    Matter_Eem_Checkpoint_T eem; Matter_Ota_Provider_T ota[5];
} Store_Work;
struct Matter_Store_Host {
    Matter_Store_Blob_Port_T blob; Matter_Fabric_Host_Image_T fabric;
    Matter_Commissioning_Host_Image_T commissioning; Matter_Root_Settings_T* root; Matter_Diagnostics_Host_Image_T* diagnostics;
    Matter_Eem_Checkpoint_T eem; uint64_t event_high; Matter_Ota_Provider_T ota[5];
    Store_Work* work; uint8_t* bytes; size_t bytes_size; bool busy;
};
static void wipe(void* p,size_t n) { volatile unsigned char* b=p; while(n--) *b++=0; }
static bool capture(Matter_Store_Host_T s,const Matter_Store_Fabrics_T* f,const Matter_Store_Wifi_T* w) {
    s->work=calloc(1,sizeof(*s->work)); if(!s->work) return false;
    s->work->wifi=w?*w:s->commissioning->data; s->work->root=*s->root;
    s->work->eem=s->eem;
    s->work->source=(Matter_Store_Source_T){7,f?f:&s->fabric->data,&s->work->wifi,&s->work->root,
        s->diagnostics->hours,s->diagnostics->reboots,&s->work->eem,s->event_high,s->work->ota};
    memcpy(s->work->ota,s->ota,sizeof(s->ota));
    for(unsigned i=0;i<5;++i) if(s->work->ota[i].fabric) {
        bool live=false; for(unsigned j=0;j<5;++j) if(s->work->source.fabrics->view.records[j].index==s->work->ota[i].fabric) live=true;
        if(!live) s->work->ota[i]=(Matter_Ota_Provider_T){0};
    }
    return true;
}
/* Per-operation scratch; callbacks remain guarded until it has been erased. */
static void clear_work(Matter_Store_Host_T s) {
    if(s->bytes) { wipe(s->bytes,s->bytes_size); free(s->bytes); s->bytes=NULL; s->bytes_size=0; }
    if(s->work) { wipe(s->work,sizeof(*s->work)); free(s->work); s->work=NULL; }
}
static Matter_Result_T save(Matter_Store_Host_T s) {
    Matter_Result_T r=matter_store_source_encode(&s->work->source,&s->bytes,&s->bytes_size);
    if(r==MATTER_OK) r=s->blob.replace(s->blob.user,s->bytes,s->bytes_size);
    if(r==MATTER_OK) memcpy(s->ota,s->work->ota,sizeof(s->ota));
    clear_work(s); return r;
}
static Matter_Result_T publish(void* u,const Matter_Store_Fabrics_T* f,const Matter_Store_Wifi_T* w) {
    Matter_Store_Host_T s=u; if(s->busy) return MATTER_BUSY;
    s->busy=true; if(!capture(s,f,w)) { s->busy=false; return MATTER_LIMIT_REACHED; } Matter_Result_T r=save(s); s->busy=false; return r;
}
static Matter_Result_T reset(void* u,const Matter_Store_Fabrics_T* f) {
    Matter_Store_Host_T s=u; if(s->busy) return MATTER_BUSY;
    s->busy=true; s->work=calloc(1,sizeof(*s->work)); if(!s->work) { s->busy=false; return MATTER_LIMIT_REACHED; }
    s->work->eem=s->eem;
    s->work->source=(Matter_Store_Source_T){7,f,&s->work->wifi,&s->work->root,0,0,&s->work->eem,s->event_high,s->work->ota};
    s->work->root.location[0]=s->work->root.location[1]='X'; s->work->wifi.settings.enabled=true;
    Matter_Result_T r=save(s);
    if(r==MATTER_OK) {
        memset(s->root,0,sizeof(*s->root)); s->root->location[0]=s->root->location[1]='X';
        memset(&s->commissioning->data,0,sizeof(s->commissioning->data)); s->commissioning->data.settings.enabled=true;
        s->diagnostics->hours=0; s->diagnostics->reboots=0;
    }
    s->busy=false; return r;
}
Matter_Store_Host_T matter_store_host_new(const Matter_Store_Blob_Port_T* p,Matter_Fabric_Host_Image_T f,
    Matter_Commissioning_Host_Image_T c,Matter_Root_Settings_T* root,Matter_Diagnostics_Host_Image_T* diag,bool restore) {
    if(!p || !p->read || !p->replace || !f || !c || !root || !diag || f->persist.publish || c->persist.publish ||
        (restore && (f->attached || c->attached || diag->attached))) return NULL;
    Matter_Store_Host_T s=calloc(1,sizeof(*s)); if(!s) return NULL;
    s->blob=*p; s->fabric=f; s->commissioning=c; s->root=root; s->diagnostics=diag;
    Matter_Store_Data_T* restored=NULL;
    Matter_Store_Source_T source;
    if(restore) {
        s->bytes=calloc(1,MATTER_STORE_BLOB_MAX); if(!s->bytes) goto fail;
        s->bytes_size=MATTER_STORE_BLOB_MAX;
        size_t n=0; Matter_Result_T r=p->read(p->user,s->bytes,MATTER_STORE_BLOB_MAX,&n);
        if(r==MATTER_OK) {
            restored=calloc(1,sizeof(*restored)); if(!restored) goto fail;
            if(matter_store_tlv_decode(s->bytes,n,restored)!=MATTER_OK) goto fail;
        } else if(r!=MATTER_OFFLINE) goto fail;
    }
    if(restored) source=matter_store_source(restored);
    else { if(!capture(s,NULL,NULL)) goto fail; source=s->work->source; }
    if(!matter_store_source_valid(&source)) goto fail;
    f->data=*source.fabrics; c->data=*source.wifi; *root=*source.root; diag->hours=source.hours; diag->reboots=source.reboots;
    s->eem=*source.eem; s->event_high=source.event_high; memcpy(s->ota,source.ota,sizeof(s->ota));
    f->persist=c->persist=(Matter_Store_Persist_T){s,publish,reset};
    if(restored) { wipe(restored,sizeof(*restored)); free(restored); }
    clear_work(s); return s;
fail:
    if(restored) { wipe(restored,sizeof(*restored)); free(restored); }
    clear_work(s); wipe(s,sizeof(*s)); free(s); return NULL;
}
Matter_Result_T matter_store_host_delete(Matter_Store_Host_T s) {
    if(!s) return MATTER_INVALID_ARGUMENT;
    if(s->busy) return MATTER_BUSY;
    s->fabric->persist=(Matter_Store_Persist_T){0}; s->commissioning->persist=(Matter_Store_Persist_T){0};
    wipe(s,sizeof(*s)); free(s); return MATTER_OK;
}
Matter_Result_T matter_store_host_root(void* u,const Matter_Root_Settings_T* root) {
    Matter_Store_Host_T s=u; if(!s || !root) return MATTER_INVALID_ARGUMENT;
    if(s->busy) return MATTER_BUSY;
    s->busy=true; if(!capture(s,NULL,NULL)) { s->busy=false; return MATTER_LIMIT_REACHED; } s->work->root=*root; Matter_Result_T r=save(s);
    if(r==MATTER_OK) *s->root=*root;
    s->busy=false; return r;
}
Matter_Result_T matter_store_host_save(Matter_Store_Host_T s) { return s?publish(s,NULL,NULL):MATTER_INVALID_ARGUMENT; }

Matter_Result_T matter_store_host_eem_load(void* u,Matter_Eem_Checkpoint_T* out) {
    Matter_Store_Host_T s=u; if(!s || !out) return MATTER_INVALID_ARGUMENT;
    if(s->busy) return MATTER_BUSY;
    *out=s->eem; return MATTER_OK;
}
Matter_Result_T matter_store_host_eem_store(void* u,const Matter_Eem_Checkpoint_T* in) {
    Matter_Store_Host_T s=u; if(!s || !in) return MATTER_INVALID_ARGUMENT;
    if(s->busy) return MATTER_BUSY;
    if(s->eem.initialized && (!in->initialized || in->registers!=s->eem.registers || in->generation<s->eem.generation)) return MATTER_INVALID_ARGUMENT;
    for(unsigned i=0;i<2;++i) if((!in->registers && in->total_mwh[i]<s->eem.total_mwh[i]) ||
        (s->eem.initialized && in->generation==s->eem.generation && (!in->registers || (s->eem.register_mask&(1u<<i))) &&
            (in->raw_mwh[i]<s->eem.raw_mwh[i] || (in->registers && !(in->register_mask&(1u<<i)))))) return MATTER_INVALID_ARGUMENT;
    s->busy=true; if(!capture(s,NULL,NULL)) { s->busy=false; return MATTER_LIMIT_REACHED; } s->work->eem=*in; Matter_Result_T r=save(s);
    if(r==MATTER_OK) s->eem=*in;
    s->busy=false; return r;
}
Matter_Result_T matter_store_host_event_load(void* u,uint64_t* out) {
    Matter_Store_Host_T s=u; if(!s || !out) return MATTER_INVALID_ARGUMENT;
    if(s->busy) return MATTER_BUSY;
    *out=s->event_high; return MATTER_OK;
}
Matter_Result_T matter_store_host_event_store(void* u,uint64_t high) {
    Matter_Store_Host_T s=u; if(!s) return MATTER_INVALID_ARGUMENT;
    if(s->busy) return MATTER_BUSY;
    if(high<s->event_high) return MATTER_INVALID_ARGUMENT;
    if(high==s->event_high) return MATTER_OK;
    s->busy=true; if(!capture(s,NULL,NULL)) { s->busy=false; return MATTER_LIMIT_REACHED; } s->work->source.event_high=high; Matter_Result_T r=save(s);
    if(r==MATTER_OK) s->event_high=high;
    s->busy=false; return r;
}

Matter_Result_T matter_store_host_ota_load(void* u,Matter_Ota_Provider_T out[MATTER_OTA_PROVIDERS]) {
    Matter_Store_Host_T s=u; if(!s || !out) return MATTER_INVALID_ARGUMENT;
    if(s->busy) return MATTER_BUSY;
    memcpy(out,s->ota,sizeof(s->ota)); return MATTER_OK;
}
Matter_Result_T matter_store_host_ota_store(void* u,uint8_t fabric,const Matter_Ota_Provider_T* provider) {
    Matter_Store_Host_T s=u; if(!s || !fabric || fabric==255 || (provider && provider->fabric!=fabric)) return MATTER_INVALID_ARGUMENT;
    if(s->busy) return MATTER_BUSY;
    bool live=false; for(unsigned i=0;i<5;++i) if(s->fabric->data.view.records[i].index==fabric) live=true;
    if(!live) return MATTER_INVALID_STATE;
    s->busy=true; if(!capture(s,NULL,NULL)) { s->busy=false; return MATTER_LIMIT_REACHED; } unsigned slot=5;
    for(unsigned i=0;i<5;++i) if(s->work->ota[i].fabric==fabric) { slot=i; break; }
    if(slot==5) for(unsigned i=0;i<5;++i) if(!s->work->ota[i].fabric) { slot=i; break; }
    Matter_Result_T r=MATTER_LIMIT_REACHED;
    if(slot<5) { s->work->ota[slot]=provider?*provider:(Matter_Ota_Provider_T){0}; r=save(s); }
    else clear_work(s);
    s->busy=false; return r;
}
