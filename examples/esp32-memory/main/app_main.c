#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_random.h"
#include "bootloader_random.h"
#include "nvs_flash.h"
#include "psa/crypto.h"
#include "matter.h"
#include "crypto/matter_crypto_mbedtls.h"
#include "session/matter_pase.h"
#include "model/matter_events.h"
#include "matter_idf_memory.h"
#ifdef MATTER_C_LAB_WIFI_CONFIG
#include "matter_lab_wifi.h"
#else
#define MATTER_LAB_WIFI_SSID ""
#define MATTER_LAB_WIFI_PASSWORD ""
#endif

#define REQUIRE(x) do { if(!(x)) { printf("LAB_FAIL line=%u\n",(unsigned)__LINE__); abort(); } } while(0)
int matter_lab_test_crypto_mbedtls(void);
int matter_lab_test_spake2p(void);
int matter_lab_test_credentials(int,char**);
int matter_lab_test_operational_cert(int,char**);
int matter_lab_test_attestation_cert(void);
int matter_lab_test_im_read(void);
int matter_lab_test_im_subscribe(void);
int matter_lab_test_im_event_metadata(void);
static uint64_t now(void) { return (uint64_t)esp_timer_get_time()/1000; }
static void tasks(void) {
    typedef struct { unsigned id,free; char name[configMAX_TASK_NAME_LEN]; } Task;
    UBaseType_t count=uxTaskGetNumberOfTasks()+4;
    TaskStatus_t* status=calloc(count,sizeof(*status));
    Task* copy=calloc(count,sizeof(*copy)); REQUIRE(status && copy);
    /* Keep borrowed task names live while copying. Do no formatting or heap
     * work with the scheduler suspended; print only the owned copies. */
    vTaskSuspendAll();
    count=uxTaskGetSystemState(status,count,NULL);
    for(UBaseType_t i=0;i<count;++i) {
        copy[i].id=(unsigned)status[i].xTaskNumber; copy[i].free=(unsigned)status[i].usStackHighWaterMark;
        for(size_t j=0;j+1<sizeof(copy[i].name) && status[i].pcTaskName[j];++j) {
            char c=status[i].pcTaskName[j];
            copy[i].name[j]=(c>='a' && c<='z') || (c>='A' && c<='Z') ||
                (c>='0' && c<='9') || c=='_' || c=='-'?c:'?';
        }
    }
    xTaskResumeAll(); REQUIRE(count);
    for(UBaseType_t i=0;i<count;++i)
        printf("TASK_MEMORY {\"id\":%u,\"name\":\"%s\",\"min_free_bytes\":%u}\n",
            copy[i].id,copy[i].name,copy[i].free);
    free(copy); free(status);
}
static void sample(const char* phase) {
    multi_heap_info_t info; heap_caps_get_info(&info,MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);
    Matter_Idf_Memory m=matter_idf_memory();
    unsigned free_stack=(unsigned)uxTaskGetStackHighWaterMark(NULL);
    printf("MEMORY {\"phase\":\"%s\",\"ms\":%llu,\"heap_free\":%u,\"heap_allocated\":%u,\"heap_min\":%u,"
        "\"largest_free\":%u,\"owner_stack_reserved\":%u,\"owner_stack_min_free\":%u,"
        "\"core_live\":%u,\"core_bytes\":%u,\"core_peak\":%u,\"core_largest\":%u,\"core_failures\":%u}\n",
        phase,(unsigned long long)now(),(unsigned)info.total_free_bytes,(unsigned)info.total_allocated_bytes,(unsigned)info.minimum_free_bytes,
        (unsigned)info.largest_free_block,CONFIG_ESP_MAIN_TASK_STACK_SIZE,free_stack,
        (unsigned)m.live,(unsigned)m.live_bytes,(unsigned)m.peak_bytes,(unsigned)m.largest_request,(unsigned)m.failures);
}
static Matter_Result_T entropy(void* u,uint8_t* out,size_t size) {
    (void)u; esp_fill_random(out,size); return MATTER_OK;
}
static void crypto_faults(Matter_Crypto_Mbedtls_T backend,Matter_Crypto_Port_T* port) {
    uint8_t* work=calloc(1,608); REQUIRE(work);
    size_t baseline=matter_idf_memory().live;
    matter_idf_memory_fail_after(1); REQUIRE(!matter_crypto_mbedtls_new(NULL));
    memset(work,0xa5,608); matter_idf_memory_fail_after(1);
    REQUIRE(port->hkdf_sha256(port->user,(const uint8_t*)"key",3,NULL,0,NULL,0,work,32)==MATTER_PORT_ERROR);
    for(unsigned i=0;i<32;++i) REQUIRE(!work[i]);
    Matter_Credentials_Port_T credentials;
    REQUIRE(matter_crypto_mbedtls_credentials(backend,&credentials)==MATTER_OK);
    memset(work,0,32); work[31]=3; memset(work+32,0xa5,512);
    size_t size=999; matter_idf_memory_fail_after(1);
    REQUIRE(credentials.csr_create(credentials.user,work,work+32,512,&size)==MATTER_PORT_ERROR && !size);
    for(unsigned i=32;i<544;++i) REQUIRE(!work[i]);
    matter_idf_memory_fail_after(0); REQUIRE(matter_idf_memory().live==baseline);
    port->clear(work,608); free(work); sample("crypto-oom-clean");
}
typedef struct {
    Matter_Pase_Config_T cfg[2]; Matter_Pase_T pase[2];
    Matter_Pase_Keys_T keys[2]; uint8_t wide[80],w1[32];
} PaseWork;
/* Two genuine engines in one application task; this does not exercise UDP/MRP
 * or peer interoperability. A retained copy models the sender's immutable TX
 * lifetime; the final delivery gate is called only after receiver acceptance. */
static void pase_exchange(Matter_Crypto_Port_T* crypto) {
    PaseWork* w=calloc(1,sizeof(*w)); REQUIRE(w);
    uint64_t begin=now();
    w->cfg[0]=(Matter_Pase_Config_T){.local_session_id=123,.pin=20202021,.timeout_ms=60000};
    w->cfg[1]=(Matter_Pase_Config_T){.responder=true,.local_session_id=456,.iterations=1000,.salt_size=16,.timeout_ms=60000};
    REQUIRE(crypto->random(crypto->user,w->cfg[1].salt,16)==MATTER_OK);
    const uint8_t pin[]={0x25,0x42,0x34,1};
    REQUIRE(crypto->pbkdf2_sha256(crypto->user,pin,4,w->cfg[1].salt,16,1000,w->wide,80)==MATTER_OK);
    REQUIRE(crypto->p256_reduce(crypto->user,w->wide,40,w->cfg[1].w0)==MATTER_OK);
    REQUIRE(crypto->p256_reduce(crypto->user,w->wide+40,40,w->w1)==MATTER_OK);
    REQUIRE(crypto->p256_base(crypto->user,w->w1,32,w->cfg[1].L)==MATTER_OK);
    matter_idf_memory_fail_after(1); REQUIRE(!matter_pase_new(crypto,&w->cfg[0],begin));
    matter_idf_memory_fail_after(0);
    for(unsigned i=0;i<2;++i) { w->pase[i]=matter_pase_new(crypto,&w->cfg[i],begin); REQUIRE(w->pase[i]); }
    sample("pase-created-two-peers");
    for(unsigned i=0;i<6;++i) {
        unsigned from=i%2; Matter_Pase_Message_T message;
        REQUIRE(matter_pase_process(w->pase[from],now())==MATTER_PENDING);
        REQUIRE(matter_pase_output(w->pase[from],&message)==MATTER_OK);
        uint8_t* retained=malloc(message.size); REQUIRE(retained); memcpy(retained,message.data,message.size);
        REQUIRE(matter_pase_sent(w->pase[from])==MATTER_OK);
        if(!i) {
            matter_idf_memory_fail_after(1);
            REQUIRE(matter_pase_receive(w->pase[1-from],message.opcode,retained,message.size)==MATTER_LIMIT_REACHED);
            matter_idf_memory_fail_after(0); sample("pase-rx-oom-retry");
        }
        REQUIRE(matter_pase_receive(w->pase[1-from],message.opcode,retained,message.size)==MATTER_OK);
        free(retained); sample("pase-message"); taskYIELD();
    }
    REQUIRE(matter_pase_process(w->pase[0],now())==MATTER_OK);
    REQUIRE(matter_pase_confirm_delivery(w->pase[1],now())==MATTER_OK);
    for(unsigned i=0;i<2;++i) REQUIRE(matter_pase_take_keys(w->pase[i],&w->keys[i])==MATTER_OK);
    REQUIRE(!memcmp(w->keys[0].send_key,w->keys[1].receive_key,16));
    REQUIRE(!memcmp(w->keys[1].send_key,w->keys[0].receive_key,16));
    sample("pase-confirmed");
    for(unsigned i=0;i<2;++i) REQUIRE(matter_pase_delete(w->pase[i])==MATTER_OK);
    crypto->clear((uint8_t*)w,sizeof(*w)); free(w); sample("pase-drained");
}
static Matter_Result_T event_load(void* user,uint64_t* high) { *high=*(uint64_t*)user; return MATTER_OK; }
static Matter_Result_T event_store(void* user,uint64_t high) {
    uint64_t* previous=user; if(high<*previous) return MATTER_INVALID_ARGUMENT;
    *previous=high; return MATTER_OK;
}
static void events(void) {
    /* Independent volatile laboratory log, not a durable production port. */
    uint64_t high=0;
    Matter_Events_Port_T port={&high,event_load,event_store};
    Matter_Events_T log=matter_events_new(&port); REQUIRE(log);
    sample("event-log-empty");
    const Matter_Event_Path_T path={1,0x91,1}; const uint8_t data[]={0x15,0x24,0,1,0x18};
    for(unsigned i=0;i<MATTER_EVENTS_CAPACITY;++i)
        REQUIRE(matter_events_append(log,&path,1,now(),false,data,sizeof(data))==MATTER_OK);
    sample("event-log-full");
    matter_idf_memory_fail_after(1);
    REQUIRE(matter_events_append(log,&path,1,now(),false,data,sizeof(data))==MATTER_LIMIT_REACHED);
    matter_idf_memory_fail_after(0); sample("event-log-oom");
    REQUIRE(matter_events_delete(log)==MATTER_OK); sample("event-log-drained");
}
static EventGroupHandle_t wifi_events;
static void wifi_event(void* u,esp_event_base_t base,int32_t id,void* data) {
    (void)u; (void)data;
    if(base==WIFI_EVENT && id==WIFI_EVENT_STA_START) esp_wifi_connect();
    if(base==IP_EVENT && id==IP_EVENT_STA_GOT_IP) xEventGroupSetBits(wifi_events,1);
    if(base==WIFI_EVENT && id==WIFI_EVENT_STA_DISCONNECTED) xEventGroupSetBits(wifi_events,2);
}
static void wifi_cycle(void) {
    if(!strlen(MATTER_LAB_WIFI_SSID)) { puts("WIFI_SKIP no-private-config"); return; }
    REQUIRE(nvs_flash_init()==ESP_OK); REQUIRE(esp_netif_init()==ESP_OK);
    REQUIRE(esp_event_loop_create_default()==ESP_OK);
    esp_netif_t* iface=esp_netif_create_default_wifi_sta(); REQUIRE(iface);
    wifi_events=xEventGroupCreate(); REQUIRE(wifi_events);
    esp_event_handler_instance_t radio,ip;
    REQUIRE(esp_event_handler_instance_register(WIFI_EVENT,ESP_EVENT_ANY_ID,wifi_event,NULL,&radio)==ESP_OK);
    REQUIRE(esp_event_handler_instance_register(IP_EVENT,IP_EVENT_STA_GOT_IP,wifi_event,NULL,&ip)==ESP_OK);
    wifi_init_config_t init=WIFI_INIT_CONFIG_DEFAULT(); REQUIRE(esp_wifi_init(&init)==ESP_OK);
    wifi_config_t* cfg=calloc(1,sizeof(*cfg)); REQUIRE(cfg);
    REQUIRE(strlen(MATTER_LAB_WIFI_SSID)<=sizeof(cfg->sta.ssid));
    REQUIRE(strlen(MATTER_LAB_WIFI_PASSWORD)<=sizeof(cfg->sta.password));
    memcpy(cfg->sta.ssid,MATTER_LAB_WIFI_SSID,strlen(MATTER_LAB_WIFI_SSID));
    memcpy(cfg->sta.password,MATTER_LAB_WIFI_PASSWORD,strlen(MATTER_LAB_WIFI_PASSWORD));
    cfg->sta.threshold.authmode=WIFI_AUTH_WPA2_PSK;
    REQUIRE(esp_wifi_set_storage(WIFI_STORAGE_RAM)==ESP_OK); REQUIRE(esp_wifi_set_mode(WIFI_MODE_STA)==ESP_OK);
    REQUIRE(esp_wifi_set_config(WIFI_IF_STA,cfg)==ESP_OK); memset(cfg,0,sizeof(*cfg)); free(cfg);
    sample("wifi-initialized"); REQUIRE(esp_wifi_start()==ESP_OK);
    EventBits_t result=xEventGroupWaitBits(wifi_events,3,pdFALSE,pdFALSE,pdMS_TO_TICKS(30000));
    REQUIRE(result&1); sample("wifi-connected"); tasks();
    events();
    REQUIRE(esp_wifi_stop()==ESP_OK); REQUIRE(esp_wifi_deinit()==ESP_OK);
    REQUIRE(esp_event_handler_instance_unregister(IP_EVENT,IP_EVENT_STA_GOT_IP,ip)==ESP_OK);
    REQUIRE(esp_event_handler_instance_unregister(WIFI_EVENT,ESP_EVENT_ANY_ID,radio)==ESP_OK);
    esp_netif_destroy_default_wifi(iface); vEventGroupDelete(wifi_events); wifi_events=NULL;
    REQUIRE(esp_event_loop_delete_default()==ESP_OK); REQUIRE(nvs_flash_deinit()==ESP_OK);
    sample("wifi-stopped");
}
void app_main(void) {
    sample("boot"); REQUIRE(psa_crypto_init()==PSA_SUCCESS);
    /* Enable a true entropy source before RF initialization. This temporary
     * source must be disabled before the application starts Wi-Fi. */
    bootloader_random_enable();
    /* The host vectors deliberately exercise the maximum synchronous PBKDF2
     * cost. Run this laboratory owner alongside idle so idle's watchdog can
     * advance while the RTOS preempts that computation. */
    UBaseType_t priority=uxTaskPriorityGet(NULL);
    vTaskPrioritySet(NULL,tskIDLE_PRIORITY);
#if CONFIG_MATTER_C_LAB_SELF_TESTS
    REQUIRE(matter_lab_test_operational_cert(0,NULL)==0); vTaskDelay(1);
    REQUIRE(matter_lab_test_attestation_cert()==0); vTaskDelay(1);
    REQUIRE(matter_lab_test_crypto_mbedtls()==0); vTaskDelay(1);
    REQUIRE(matter_lab_test_spake2p()==0); vTaskDelay(1);
    REQUIRE(matter_lab_test_credentials(0,NULL)==0); vTaskDelay(1);
    REQUIRE(matter_lab_test_im_read()==0); vTaskDelay(1);
    REQUIRE(matter_lab_test_im_subscribe()==0); vTaskDelay(1);
    REQUIRE(matter_lab_test_im_event_metadata()==0); vTaskDelay(1);
    sample("library-tests-passed");
#else
    puts("LIBRARY_SELF_TESTS_SKIPPED profiling-build");
#endif
    Matter_Crypto_Entropy_Port_T source={NULL,entropy};
    Matter_Crypto_Mbedtls_T backend=matter_crypto_mbedtls_new(&source); REQUIRE(backend);
    Matter_Crypto_Port_T crypto; REQUIRE(matter_crypto_mbedtls_port(backend,&crypto)==MATTER_OK);
    sample("crypto-ready"); crypto_faults(backend,&crypto); events(); pase_exchange(&crypto);
    vTaskPrioritySet(NULL,priority);
    bootloader_random_disable(); wifi_cycle();
    REQUIRE(matter_crypto_mbedtls_delete(backend)==MATTER_OK);
    REQUIRE(matter_idf_memory().live==0); REQUIRE(heap_caps_check_integrity_all(true));
    sample("complete"); tasks(); puts("LAB_PASS");
    while(true) vTaskDelay(pdMS_TO_TICKS(1000));
}
