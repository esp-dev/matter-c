#ifndef MATTER_STORE_HOST_H
#define MATTER_STORE_HOST_H 1
#include "matter_commissioning_host.h"
#include "matter_diagnostics_host.h"
#include "../storage/matter_store_blob.h"
#include "../clusters/matter_root.h"
#include "../clusters/matter_eem.h"
#include "../clusters/matter_ota_requestor.h"
typedef struct Matter_Store_Host* Matter_Store_Host_T;
/* Borrows all images/settings/blob until delete. restore=true requires detached
 * images and loads atomically, missing blob uses supplied defaults. Corruption
 * fails without erasing the file or publishing any partial state. restore=false
 * attaches explicitly seeded RAM state (test/provisioning), no implicit load.
 * One application owner; reference file I/O is synchronous, not real-time safe. */
Matter_Store_Host_T matter_store_host_new(const Matter_Store_Blob_Port_T*,Matter_Fabric_Host_Image_T,
    Matter_Commissioning_Host_Image_T,Matter_Root_Settings_T*,Matter_Diagnostics_Host_Image_T*,bool restore);
/* Remove runtimes/handlers first, detach before freeing images. */
Matter_Result_T matter_store_host_delete(Matter_Store_Host_T);
/* Durable Root store callback; only settings are updated on success. */
Matter_Result_T matter_store_host_root(void*,const Matter_Root_Settings_T*);
/* Owner checkpoint, also persists best-effort diagnostic hours/reboot count. */
Matter_Result_T matter_store_host_save(Matter_Store_Host_T);
/* Node-wide data, independent of commissioning journal/last-fabric reset.
 * Callback-compatible API. Store commits before RAM publication; failures keep
 * both old. Bind one Events allocator per store. Store outlives producers.
 * Missing pre-schema5 state is zero, corrupt state fails constructor. */
Matter_Result_T matter_store_host_eem_load(void*,Matter_Eem_Checkpoint_T*);
Matter_Result_T matter_store_host_eem_store(void*,const Matter_Eem_Checkpoint_T*);
Matter_Result_T matter_store_host_event_load(void*,uint64_t*);
Matter_Result_T matter_store_host_event_store(void*,uint64_t);
/* Default OTA provider per live fabric, included in the same atomic blob.
 * Pruned during fabric remove/rollback/reset; old schemas import empty. */
Matter_Result_T matter_store_host_ota_load(void*,Matter_Ota_Provider_T out[MATTER_OTA_PROVIDERS]);
Matter_Result_T matter_store_host_ota_store(void*,uint8_t,const Matter_Ota_Provider_T*);
#endif
