#ifndef MATTER_IDF_OTA_H
#define MATTER_IDF_OTA_H 1
#include "runtime/matter_runtime.h"

typedef struct Matter_Idf_Ota* Matter_Idf_Ota_T;
/* One application owner; no SDK/network task or automatic reboot. Requires two
 * OTA app partitions, otadata, SDK rollback and signed-on-update verification.
 * App descriptor version must be an unsigned decimal SoftwareVersion. Initial
 * firmware must carry the trusted signing key's signature too. No eFuse writes.
 * Dedicated journal namespace uses the existing atomic NVS blob adapter. */
Matter_Idf_Ota_T matter_idf_ota_new(const char* nvs_partition,const char* name_space,
    uint16_t vendor,uint16_t product);
Matter_Runtime_Ota_Port_T matter_idf_ota_port(Matter_Idf_Ota_T);
uint32_t matter_idf_ota_version(Matter_Idf_Ota_T);
/* Delete only after runtime stop/drain/delete; accepted boot selection survives.
 * Caller confirms a functional new boot via matter_runtime_ota_boot_ready, and
 * restarts only after runtime OTA event delivery and normal stop/drain. */
void matter_idf_ota_delete(Matter_Idf_Ota_T);
#endif
