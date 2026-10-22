#include "matter_store_internal.h"
#include <stdlib.h>
struct Matter_Commissioning_Host {
    Matter_Commissioning_Host_Image_T image; Matter_Wifi_T wifi; Matter_Wifi_Port_T platform;
    Matter_Opcreds_T credentials; Matter_Fabric_Host_T fabric; Matter_Commissioning_Host_Port_T port;
    bool busy,fail_commit; Matter_Store_Wifi_T candidate;
};
static void erase(void* p,size_t n) { volatile uint8_t* b=p; while(n--) *b++=0; }
Matter_Commissioning_Host_Image_T matter_commissioning_host_image_new(const Matter_Wifi_Settings_T* s,const Matter_Wifi_Id_T* c) {
    if(!s || !c || s->count>MATTER_WIFI_NETWORKS || c->size>32) return NULL;
    Matter_Commissioning_Host_Image_T i=calloc(1,sizeof(*i)); if(i) { i->data.settings=*s; i->data.connected=*c; } return i;
}
Matter_Result_T matter_commissioning_host_image_delete(Matter_Commissioning_Host_Image_T i) {
    if(!i) return MATTER_INVALID_ARGUMENT;
    if(i->attached || i->persist.publish) return MATTER_BUSY;
    erase(i,sizeof(*i)); free(i); return MATTER_OK;
}
const Matter_Wifi_Settings_T* matter_commissioning_host_settings(Matter_Commissioning_Host_Image_T i) { return i?&i->data.settings:NULL; }
const Matter_Wifi_Id_T* matter_commissioning_host_connected(Matter_Commissioning_Host_Image_T i) { return i?&i->data.connected:NULL; }
bool matter_commissioning_host_pending(Matter_Commissioning_Host_Image_T i) { return i && i->data.pending; }
Matter_Commissioning_Host_T matter_commissioning_host_new_port(Matter_Commissioning_Host_Image_T i,
    Matter_Wifi_T w,const Matter_Wifi_Port_T* platform,Matter_Opcreds_T c,Matter_Fabric_Host_T f,const Matter_Commissioning_Host_Port_T* p) {
    if(!i || i->attached || !w || !platform || !platform->load || !c || !f || !p || !p->retire) return NULL;
    Matter_Commissioning_Host_T h=calloc(1,sizeof(*h));
    if(h) { h->image=i; h->wifi=w; h->platform=*platform; h->credentials=c; h->fabric=f; h->port=*p; i->attached=true; } return h;
}
Matter_Result_T matter_commissioning_host_delete(Matter_Commissioning_Host_T h) {
    if(!h) return MATTER_INVALID_ARGUMENT;
    if(h->busy) return MATTER_BUSY;
    h->image->attached=false; erase(h,sizeof(*h)); free(h); return MATTER_OK;
}
Matter_Result_T matter_commissioning_host_begin(void* u) {
    Matter_Commissioning_Host_T h=u;
    if(!h) return MATTER_INVALID_ARGUMENT;
    if(h->busy) return MATTER_BUSY;
    if(h->image->data.pending) return MATTER_INVALID_STATE;
    Matter_Result_T r=matter_wifi_checkpoint(h->wifi);
    if(r==MATTER_OK) {
        h->candidate=h->image->data;
        r=h->platform.load(h->platform.user,&h->candidate.settings,&h->candidate.connected); h->candidate.pending=true;
        h->busy=true;
        if(r==MATTER_OK && h->image->persist.publish) r=h->image->persist.publish(h->image->persist.user,NULL,&h->candidate,false);
        if(r==MATTER_OK) h->image->data=h->candidate;
        else (void)matter_wifi_commit(h->wifi); /* Undo checkpoint only; no radio changes. */
        h->busy=false; erase(&h->candidate,sizeof(h->candidate));
    }
    return r;
}
Matter_Result_T matter_commissioning_host_cleanup(void* u) {
    Matter_Commissioning_Host_T h=u;
    if(!h) return MATTER_INVALID_ARGUMENT;
    if(h->busy) return MATTER_BUSY;
    h->busy=true;
    Matter_Result_T r=h->port.retire(h->port.user,false);
    if(r==MATTER_OK) r=matter_opcreds_rollback(h->credentials);
    if(r==MATTER_OK) r=matter_wifi_rollback(h->wifi);
    if(r==MATTER_OK) {
        h->candidate=h->image->data; h->candidate.pending=false;
        if(r==MATTER_OK && h->image->persist.publish) r=h->image->persist.publish(h->image->persist.user,NULL,&h->candidate,false);
        if(r==MATTER_OK) h->image->data=h->candidate;
        erase(&h->candidate,sizeof(h->candidate));
    }
    h->busy=false; return r;
}
Matter_Result_T matter_commissioning_host_complete(void* u,uint8_t index) {
    Matter_Commissioning_Host_T h=u;
    if(!h) return MATTER_INVALID_ARGUMENT;
    if(h->busy) return MATTER_BUSY;
    if(!h->image->data.pending || matter_fabric_host_commit_ready(h->fabric,index)!=MATTER_OK) return MATTER_INVALID_STATE;
    h->busy=true;
    Matter_Result_T r=h->port.retire(h->port.user,true);
    if(r==MATTER_OK) r=matter_fabric_host_commit_ready(h->fabric,index);
    if(r==MATTER_OK && (matter_wifi_commit_ready(h->wifi)!=MATTER_OK || matter_opcreds_commit_ready(h->credentials)!=MATTER_OK)) r=MATTER_PENDING;
    if(r==MATTER_OK && h->fail_commit) r=MATTER_PORT_ERROR;
    if(r==MATTER_OK) {
        h->candidate=h->image->data;
        r=h->platform.load(h->platform.user,&h->candidate.settings,&h->candidate.connected); h->candidate.pending=false;
        if(r==MATTER_OK) r=matter_fabric_host_publish_commit(h->fabric,&h->candidate);
    }
    if(r==MATTER_OK) {
        /* Durable combined candidate is already published. One RAM transaction: all preflights above, no callbacks,
         * allocation or scheduling below. A future NVS backend must honor the same atomic blob contract. */
        r=matter_fabric_host_apply_commit(h->fabric);
        if(r==MATTER_OK) r=matter_opcreds_commit(h->credentials);
        if(r==MATTER_OK) r=matter_wifi_commit(h->wifi);
        if(r==MATTER_OK) {
            h->image->data.settings=h->candidate.settings;
            h->image->data.connected=h->candidate.connected;
            h->image->data.pending=false; /* Commit marker LAST. */
        }
    }
    erase(&h->candidate,sizeof(h->candidate)); h->busy=false; return r;
}
void matter_commissioning_host_fail_commit(Matter_Commissioning_Host_T h,bool fail) { if(h && !h->busy) h->fail_commit=fail; }
