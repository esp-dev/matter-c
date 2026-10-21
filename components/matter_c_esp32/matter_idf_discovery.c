#include "matter_idf_discovery.h"
#include "mdns.h"
#include <stdlib.h>
#include <string.h>
struct Matter_Idf_Discovery {
    Matter_Mdns_T module; Matter_Mdns_Record_T record;
    uint64_t request; bool publish,cancelled,installed,rollback,busy;
};
static bool publish(void* user,uint64_t id,const Matter_Mdns_Record_T* record) {
    Matter_Idf_Discovery_T s=user;
    if(s->request || s->installed || record->txt_count>8 || record->subtype_count>4) return false;
    s->record=*record; s->request=id; s->publish=true; return true;
}
static bool remove_record(void* user,uint64_t id) {
    Matter_Idf_Discovery_T s=user; if(s->request || !s->installed) return false;
    s->request=id; s->publish=false; return true;
}
static void cancel(void* user,uint64_t id) { Matter_Idf_Discovery_T s=user; if(s->request==id) s->cancelled=true; }
static void detach(void* user) { ((Matter_Idf_Discovery_T)user)->module=NULL; }
Matter_Idf_Discovery_T matter_idf_discovery_new(Matter_T owner,const Matter_Mdns_Record_T* record) {
    if(!owner || !record || record->txt_count>8 || record->subtype_count>4 ||
        (record->txt_count && !record->txt) || (record->subtype_count && !record->subtypes)) return NULL;
    Matter_Idf_Discovery_T s=calloc(1,sizeof(*s)); if(!s) return NULL;
    Matter_Mdns_Port_T port={s,publish,remove_record,cancel,detach};
    s->module=matter_mdns_new(owner,&port,record);
    if(!s->module) { free(s); return NULL; }
    if(matter_mdns_backend(s->module,1,true)!=MATTER_OK) { (void)matter_mdns_delete(s->module); free(s); return NULL; }
    return s;
}
Matter_Mdns_T matter_idf_discovery_module(Matter_Idf_Discovery_T s) { return s?s->module:NULL; }
Matter_Result_T matter_idf_discovery_process(Matter_Idf_Discovery_T s) {
    if(!s) return MATTER_INVALID_ARGUMENT;
    if(s->busy) return MATTER_BUSY;
    if(!s->request) return MATTER_WOULD_BLOCK;
    s->busy=true; Matter_Mdns_Record_T* r=&s->record;
    Matter_Operation_Result_T result=MATTER_OPERATION_FAILED;
    if(s->cancelled && !s->rollback) result=MATTER_OPERATION_CANCELLED;
    else if(s->publish && !s->rollback) {
        mdns_txt_item_t* txt=r->txt_count?calloc(r->txt_count,sizeof(*txt)):NULL;
        esp_err_t e=r->txt_count && !txt?ESP_ERR_NO_MEM:ESP_OK;
        if(!e) {
            for(unsigned i=0;i<r->txt_count;++i) txt[i]=(mdns_txt_item_t){r->txt[i].key,r->txt[i].value};
            e=mdns_service_add_for_host(r->instance,r->service,r->protocol,r->hostname,r->port,txt,r->txt_count);
        }
        free(txt);
        if(!e) {
            s->installed=true;
            for(unsigned i=0;i<r->subtype_count && !e;++i)
                e=mdns_service_subtype_add_for_host(r->instance,r->service,r->protocol,r->hostname,r->subtypes[i]);
            if(e) s->rollback=true;
            else result=MATTER_OPERATION_SUCCEEDED;
        }
    } else if(!s->rollback) {
        esp_err_t e=mdns_service_remove_for_host(r->instance,r->service,r->protocol,r->hostname);
        if(e==ESP_OK || e==ESP_ERR_NOT_FOUND) { s->installed=false; result=MATTER_OPERATION_SUCCEEDED; }
    }
    if(s->rollback) {
        esp_err_t e=mdns_service_remove_for_host(r->instance,r->service,r->protocol,r->hostname);
        if(e!=ESP_OK && e!=ESP_ERR_NOT_FOUND) { s->busy=false; return MATTER_PENDING; }
        s->installed=false; s->rollback=false; result=MATTER_OPERATION_FAILED;
    }
    uint64_t id=s->request; s->request=0; s->cancelled=false;
    Matter_Result_T e=matter_mdns_complete(s->module,id,result);
    s->busy=false; return e;
}
Matter_Result_T matter_idf_discovery_delete(Matter_Idf_Discovery_T s) {
    if(!s) return MATTER_OK;
    if(s->busy || s->request || s->installed) return MATTER_BUSY;
    Matter_Result_T r=matter_mdns_delete(s->module); if(r==MATTER_OK) free(s); return r;
}
