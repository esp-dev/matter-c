#include "matter_idf_store.h"
#include "storage/matter_store_tlv.h"
#include "esp_idf_version.h"
#include "nvs.h"
#include <stdlib.h>
#if ESP_IDF_VERSION_MAJOR != 6 || (ESP_IDF_VERSION_MINOR != 1 && \
    (ESP_IDF_VERSION_MINOR != 0 || ESP_IDF_VERSION_PATCH != 2))
#error "Review NVS synchronous publication/commit semantics for this SDK"
#endif
struct Matter_Idf_Store { nvs_handle_t nvs; uint8_t active; bool present,offline; unsigned fail; };
static const char* slot(unsigned active) { return active?"blob1":"blob0"; }
static Matter_Result_T read_blob(void* user,uint8_t* out,size_t capacity,size_t* size) {
    Matter_Idf_Store_T s=user; if(!s->present) return MATTER_OFFLINE;
    size_t n=0; esp_err_t e=nvs_get_blob(s->nvs,slot(s->active),NULL,&n);
    if(e || !n || n>MATTER_STORE_BLOB_MAX) return MATTER_PORT_ERROR;
    if(n>capacity) return MATTER_LIMIT_REACHED;
    e=nvs_get_blob(s->nvs,slot(s->active),out,&n);
    if(e) return MATTER_PORT_ERROR;
    *size=n; return MATTER_OK;
}
static bool fault(Matter_Idf_Store_T s,unsigned stage) {
    if(s->fail!=stage) return false;
    s->fail=0; return true;
}
static Matter_Result_T replace_blob(void* user,const uint8_t* data,size_t size) {
    Matter_Idf_Store_T s=user;
    if(!data || !size || size>MATTER_STORE_BLOB_MAX) return MATTER_INVALID_ARGUMENT;
    if(s->offline) return MATTER_PORT_ERROR;
    if(fault(s,1)) return MATTER_PORT_ERROR;
    uint8_t next=s->present?(s->active^1):0;
    esp_err_t e=nvs_set_blob(s->nvs,slot(next),data,size);
    if(e) { s->offline=true; return MATTER_PORT_ERROR; }
    if(nvs_commit(s->nvs)!=ESP_OK) { s->offline=true; return MATTER_PORT_ERROR; }
    if(fault(s,2)) return MATTER_PORT_ERROR;
    e=nvs_set_u8(s->nvs,"active",next);
    /* REMOVE_FAILED explicitly means new item WAS written, old cleanup failed.
     * Report publication success, then prohibit later writes until reinit. */
    if(e && e!=ESP_ERR_NVS_REMOVE_FAILED) { s->offline=true; return MATTER_PORT_ERROR; }
    s->active=next; s->present=true;
    if(e || nvs_commit(s->nvs)!=ESP_OK) s->offline=true;
    return MATTER_OK; /* No fallible step after publication can reject it. */
}
Matter_Idf_Store_T matter_idf_store_new(const char* partition,const char* space) {
    if(!partition || !space) return NULL;
    Matter_Idf_Store_T s=calloc(1,sizeof(*s)); if(!s) return NULL;
    if(nvs_open_from_partition(partition,space,NVS_READWRITE,&s->nvs)!=ESP_OK) { free(s); return NULL; }
    esp_err_t e=nvs_get_u8(s->nvs,"active",&s->active);
    if(e!=ESP_OK && e!=ESP_ERR_NVS_NOT_FOUND) goto fail;
    s->present=e==ESP_OK;
    if(s->present) {
        size_t n=0;
        if(s->active>1 || nvs_get_blob(s->nvs,slot(s->active),NULL,&n)!=ESP_OK || !n || n>MATTER_STORE_BLOB_MAX) goto fail;
    }
    return s;
fail:
    nvs_close(s->nvs); free(s); return NULL;
}
Matter_Store_Blob_Port_T matter_idf_store_port(Matter_Idf_Store_T s) { return (Matter_Store_Blob_Port_T){s,read_blob,replace_blob}; }
void matter_idf_store_delete(Matter_Idf_Store_T s) { if(s) { nvs_close(s->nvs); free(s); } }
void matter_idf_store_fail(Matter_Idf_Store_T s,unsigned stage) { if(s) s->fail=stage; }
