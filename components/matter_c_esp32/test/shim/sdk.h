#ifndef MATTER_OTA_SDK_SHIM_H
#define MATTER_OTA_SDK_SHIM_H 1
/* Deterministic SDK boundary model, not an ESP bootloader/signature emulator. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "mbedtls/sha256.h"
#define CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE 1
#define CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT 1
#define ESP_OK 0
#define OTA_WITH_SEQUENTIAL_WRITES UINT32_C(0xfffffffe)
#define ESP_PARTITION_TYPE_APP 0
#define ESP_PARTITION_SUBTYPE_ANY 255
#define ESP_PARTITION_SUBTYPE_APP_OTA_0 16
#define ESP_PARTITION_SUBTYPE_APP_OTA_MAX 32
#define ESP_IMAGE_VERIFY_SILENT 1
#define PSA_SUCCESS 0
#define PSA_ALG_SHA_256 1
typedef int esp_err_t;
typedef unsigned esp_ota_handle_t;
typedef struct { uint32_t address,size; uint8_t subtype; } esp_partition_t;
typedef struct { uint32_t offset,size; } esp_partition_pos_t;
typedef struct { uint32_t unused; } esp_image_metadata_t;
typedef struct { char version[32],project_name[32]; } esp_app_desc_t;
typedef enum { ESP_OTA_IMG_NEW,ESP_OTA_IMG_PENDING_VERIFY,ESP_OTA_IMG_VALID } esp_ota_img_states_t;
typedef const esp_partition_t* esp_partition_iterator_t;
typedef mbedtls_sha256_context psa_hash_operation_t;
static inline psa_hash_operation_t psa_hash_operation_init(void) { psa_hash_operation_t h; mbedtls_sha256_init(&h); return h; }
static inline int psa_crypto_init(void) { return 0; }
static inline int psa_hash_setup(psa_hash_operation_t* h,int alg) { (void)alg; return mbedtls_sha256_starts(h,0); }
static inline int psa_hash_update(psa_hash_operation_t* h,const uint8_t* d,size_t n) { return mbedtls_sha256_update(h,d,n); }
static inline int psa_hash_finish(psa_hash_operation_t* h,uint8_t* d,size_t cap,size_t* n) { if(cap<32) return -1; *n=32; return mbedtls_sha256_finish(h,d); }
static inline int psa_hash_abort(psa_hash_operation_t* h) { mbedtls_sha256_free(h); return 0; }
uint32_t esp_crc32_le(uint32_t,const uint8_t*,size_t);
const esp_app_desc_t* esp_app_get_description(void);
const esp_partition_t* esp_ota_get_running_partition(void);
const esp_partition_t* esp_ota_get_next_update_partition(const esp_partition_t*);
const esp_partition_t* esp_ota_get_boot_partition(void);
esp_err_t esp_ota_begin(const esp_partition_t*,size_t,esp_ota_handle_t*);
esp_err_t esp_ota_write(esp_ota_handle_t,const void*,size_t);
esp_err_t esp_ota_end(esp_ota_handle_t);
esp_err_t esp_ota_abort(esp_ota_handle_t);
esp_err_t esp_ota_get_partition_description(const esp_partition_t*,esp_app_desc_t*);
esp_err_t esp_ota_set_boot_partition(const esp_partition_t*);
esp_err_t esp_ota_get_state_partition(const esp_partition_t*,esp_ota_img_states_t*);
esp_err_t esp_ota_mark_app_valid_cancel_rollback(void);
esp_err_t esp_partition_read(const esp_partition_t*,size_t,void*,size_t);
esp_err_t esp_image_verify(int,const esp_partition_pos_t*,esp_image_metadata_t*);
esp_partition_iterator_t esp_partition_find(int,int,const char*);
const esp_partition_t* esp_partition_get(esp_partition_iterator_t);
void esp_partition_iterator_release(esp_partition_iterator_t);
esp_partition_iterator_t esp_partition_next(esp_partition_iterator_t);
#endif
