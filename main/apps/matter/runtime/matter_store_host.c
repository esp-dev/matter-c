#include "matter_store_host.h"
#include "matter_store_internal.h"
#include <stdlib.h>
#include <string.h>
struct Matter_Store_Host {
    Matter_Store_Blob_Port_T blob; Matter_Fabric_Host_Image_T fabric;
    Matter_Commissioning_Host_Image_T commissioning; Matter_Root_Settings_T* root; Matter_Diagnostics_Host_Image_T* diagnostics;
    Matter_Eem_Checkpoint_T eem; uint64_t event_high; Matter_Ota_Provider_T ota[5];
    Matter_Store_Data_T work; uint8_t bytes[MATTER_STORE_BLOB_MAX]; bool busy;
};
static void wipe(void* p,size_t n) { volatile unsigned char* b=p; while(n--) *b++=0; }
static void capture(Matter_Store_Host_T s,const Matter_Store_Fabrics_T* f,const Matter_Store_Wifi_T* w) {
    memset(&s->work,0,sizeof(s->work)); s->work.schema=6;
    s->work.fabrics=f?*f:s->fabric->data; s->work.wifi=w?*w:s->commissioning->data; s->work.root=*s->root;
    s->work.eem=s->eem; s->work.event_high=s->event_high;
    memcpy(s->work.ota,s->ota,sizeof(s->ota));
    for(unsigned i=0;i<5;++i) if(s->work.ota[i].fabric) {
        bool live=false; for(unsigned j=0;j<5;++j) if(s->work.fabrics.view.records[j].index==s->work.ota[i].fabric) live=true;
        if(!live) s->work.ota[i]=(Matter_Ota_Provider_T){0};
    }
    s->work.hours=s->diagnostics->hours; s->work.reboots=s->diagnostics->reboots;
}
static Matter_Result_T save(Matter_Store_Host_T s) {
    size_t n; Matter_Result_T r=matter_store_tlv_encode(&s->work,s->bytes,sizeof(s->bytes),&n);
    if(r==MATTER_OK) r=s->blob.replace(s->blob.user,s->bytes,n);
    if(r==MATTER_OK) memcpy(s->ota,s->work.ota,sizeof(s->ota));
    wipe(s->bytes,sizeof(s->bytes)); wipe(&s->work,sizeof(s->work)); return r;
}
static Matter_Result_T publish(void* u,const Matter_Store_Fabrics_T* f,const Matter_Store_Wifi_T* w) {
    Matter_Store_Host_T s=u; if(s->busy) return MATTER_BUSY;
    s->busy=true; capture(s,f,w); Matter_Result_T r=save(s); s->busy=false; return r;
}
static Matter_Result_T reset(void* u,const Matter_Store_Fabrics_T* f) {
    Matter_Store_Host_T s=u; if(s->busy) return MATTER_BUSY;
    s->busy=true; memset(&s->work,0,sizeof(s->work)); s->work.schema=6; s->work.fabrics=*f;
    s->work.eem=s->eem; s->work.event_high=s->event_high;
    s->work.root.location[0]=s->work.root.location[1]='X'; s->work.wifi.settings.enabled=true;
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
    capture(s,NULL,NULL);
    if(restore) {
        size_t n=0; Matter_Result_T r=p->read(p->user,s->bytes,sizeof(s->bytes),&n);
        if(r==MATTER_OK) {
            if(matter_store_tlv_decode(s->bytes,n,&s->work)!=MATTER_OK) goto fail;
        } else if(r!=MATTER_OFFLINE) goto fail;
    }
    if(!matter_store_data_valid(&s->work)) goto fail;
    f->data=s->work.fabrics; c->data=s->work.wifi; *root=s->work.root; diag->hours=s->work.hours; diag->reboots=s->work.reboots;
    s->eem=s->work.eem; s->event_high=s->work.event_high; memcpy(s->ota,s->work.ota,sizeof(s->ota));
    f->persist=c->persist=(Matter_Store_Persist_T){s,publish,reset};
    wipe(s->bytes,sizeof(s->bytes)); wipe(&s->work,sizeof(s->work)); return s;
fail: wipe(s,sizeof(*s)); free(s); return NULL;
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
    s->busy=true; capture(s,NULL,NULL); s->work.root=*root; Matter_Result_T r=save(s);
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
    if(s->eem.initialized && (!in->initialized || in->generation<s->eem.generation)) return MATTER_INVALID_ARGUMENT;
    for(unsigned i=0;i<2;++i) if(in->total_mwh[i]<s->eem.total_mwh[i] ||
        (s->eem.initialized && in->generation==s->eem.generation && in->raw_mwh[i]<s->eem.raw_mwh[i])) return MATTER_INVALID_ARGUMENT;
    s->busy=true; capture(s,NULL,NULL); s->work.eem=*in; Matter_Result_T r=save(s);
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
    s->busy=true; capture(s,NULL,NULL); s->work.event_high=high; Matter_Result_T r=save(s);
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
    s->busy=true; capture(s,NULL,NULL); unsigned slot=5;
    for(unsigned i=0;i<5;++i) if(s->work.ota[i].fabric==fabric) { slot=i; break; }
    if(slot==5) for(unsigned i=0;i<5;++i) if(!s->work.ota[i].fabric) { slot=i; break; }
    Matter_Result_T r=MATTER_LIMIT_REACHED;
    if(slot<5) { s->work.ota[slot]=provider?*provider:(Matter_Ota_Provider_T){0}; r=save(s); }
    else wipe(&s->work,sizeof(s->work));
    s->busy=false; return r;
}
