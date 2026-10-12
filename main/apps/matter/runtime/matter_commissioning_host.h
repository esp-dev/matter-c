#ifndef MATTER_COMMISSIONING_HOST_H_INCLUDED
#define MATTER_COMMISSIONING_HOST_H_INCLUDED 1
#include "matter_fabric_host.h"
#include "../clusters/matter_wifi.h"
/* Persistence image, optionally attached to matter_store_host. Contains
 * Wi-Fi credentials. Boot loads committed settings/connection BEFORE model new;
 * pending=true requests Root recovery cleanup. Fabric image also survives. */
typedef struct Matter_Commissioning_Host_Image* Matter_Commissioning_Host_Image_T;
typedef struct Matter_Commissioning_Host* Matter_Commissioning_Host_T;
Matter_Commissioning_Host_Image_T matter_commissioning_host_image_new(const Matter_Wifi_Settings_T*,const Matter_Wifi_Id_T*);
Matter_Result_T matter_commissioning_host_image_delete(Matter_Commissioning_Host_Image_T);
const Matter_Wifi_Settings_T* matter_commissioning_host_settings(Matter_Commissioning_Host_Image_T);
const Matter_Wifi_Id_T* matter_commissioning_host_connected(Matter_Commissioning_Host_Image_T);
bool matter_commissioning_host_pending(Matter_Commissioning_Host_Image_T);
typedef struct {
    void* user;
    /* Revoke ALL PASE grants and progress secure retirement/drain. Close the
     * commissioning window on success only. Rollback (success=false) preserves
     * an unexpired window, but gates new PASE until cleanup finishes, and also
     * retires every CASE session on fabrics being removed. Calls are idempotent.
     * No mutation of transaction participants or root reentry. */
    Matter_Result_T (*retire)(void*,bool success);
} Matter_Commissioning_Host_Port_T;
Matter_Commissioning_Host_T matter_commissioning_host_new_port(Matter_Commissioning_Host_Image_T,
    Matter_Wifi_T,const Matter_Wifi_Port_T*,Matter_Opcreds_T,Matter_Fabric_Host_T,const Matter_Commissioning_Host_Port_T*);
/* Borrow all models/image/port user until delete, serialize on one owner thread.
 * Runtime delete may leave pending image for simulated crash/recovery. */
Matter_Result_T matter_commissioning_host_delete(Matter_Commissioning_Host_T);
Matter_Result_T matter_commissioning_host_begin(void*);
Matter_Result_T matter_commissioning_host_cleanup(void*);
Matter_Result_T matter_commissioning_host_complete(void*,uint8_t fabric_index);
/* Fault BEFORE commit, after drain. No partial effects; journal stays pending. */
void matter_commissioning_host_fail_commit(Matter_Commissioning_Host_T,bool);
#endif
