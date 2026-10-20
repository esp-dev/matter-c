#ifndef MATTER_RUNTIME_H_INCLUDED
#define MATTER_RUNTIME_H_INCLUDED 1
#include "matter_dispatch.h"
#include "matter_store_host.h"
#include "../clusters/matter_ota_update.h"

typedef struct Matter_Runtime* Matter_Runtime_T;
/* Copied ports, borrowed users; one owner thread, no inline runtime reentry.
 * initialize only stages the restored checkpoint before Wi-Fi model creation;
 * no pending work or retained pointers on return, including failure. Radio
 * work/completions are pumped by process, after the model advances its clock.
 * control.load is a bounded snapshot, also used at fail-safe begin/commit.
 * Each instance needs independent mutable backend state. */
typedef struct {
    Matter_Wifi_Port_T control;
    Matter_Result_T (*initialize)(void*,const Matter_Wifi_Settings_T*,const Matter_Wifi_Id_T*);
    Matter_Result_T (*process)(void*,Matter_Wifi_T,uint64_t now_ms);
    Matter_Result_T (*observe)(void*,Matter_Wifi_Ap_T*,bool* online);
} Matter_Runtime_Wifi_Port_T;
/* BDX bytes and artifact operations belong to the application. The sink and
 * user outlive stop/drain/delete. signed_image binds metadata to the SAME
 * artifact; the existing optional update journal is a SIMULATION, not a
 * production bootloader. No filenames or global sink in the runtime. */
typedef struct {
    void* user; Matter_Bdx_Sink_T sink; uint64_t limit;
    Matter_Result_T (*prepare)(void*,uint32_t version);
    Matter_Result_T (*commit)(void*);
    uint64_t (*artifact)(void*);
    Matter_Result_T (*check)(void*,uint64_t artifact);
    Matter_Result_T (*signed_image)(void*,uint64_t artifact,Matter_Ota_Signed_T*);
    void (*invalidate)(void*);
    void (*cancel)(void*);
    /* Optional synchronous disposal after Discontinue (Core 11.20.3.6 SHOULD).
     * Discard ONLY the identified candidate, never installed firmware. Return
     * failure if cleanup fails; runtime still revokes candidacy and stays Idle.
     * An omitted callback leaves disposal to the application. */
    Matter_Result_T (*discard)(void*,uint64_t artifact);
    /* Optional bounded owner-thread read: -1 unknown, otherwise nearest integer
     * 0..100 percent of this download. Retain its terminal snapshot through sink
     * cancellation until next prepare, for DownloadError. No I/O/reentry.
     * Invalid values are reported unknown.
     * Zero-initialize omitted callbacks; consumers must rebuild for this field. */
    int (*progress)(void*);
} Matter_Runtime_Ota_Port_T;
typedef struct {
    const Matter_Root_Config_T* identity; /* Copied, including caller's UniqueID. */
    Matter_Crypto_Port_T crypto; Matter_Credentials_Port_T credentials;
    /* DER spans borrowed through delete; DAC scalar copied during new only.
     * Challenge/timestamp/user/VID/PID are supplied by this runtime. */
    Matter_Opcreds_Host_Config_T attestation;
    Matter_Store_Blob_Port_T storage; /* Atomic publish, independent per node. */
    Matter_Runtime_Wifi_Port_T wifi;
    Matter_Wifi_Config_T wifi_config;
    Matter_Diagnostics_Interface_T iface;
    uint8_t boot_reason; bool reboot;
    Matter_Ota_Update_T update; /* Optional borrowed simulation journal. */
    void* user;
    Matter_Result_T (*utc)(void*,Matter_Cert_Time_T*);
    Matter_Result_T (*timestamp)(void*,uint32_t* matter_epoch_seconds);
    /* Optional diagnostic text, copied by receiver if retained. No secrets. */
    void (*log)(void*,const char*);
    /* Pure regulatory capability check; runtime persists settings on success. */
    Matter_Result_T (*regulatory)(void*,const Matter_Root_Settings_T*,uint8_t,bool* supported);
    /* Optional live replacement of iface/radio-derived NetworkInterfaces.
     * Zero-initialize when unused; borrowed user outlives delete. Rebuild
     * consumers after this configuration extension. Other diagnostics unchanged. */
    Matter_Diagnostics_Network_Port_T network;
} Matter_Runtime_Config_T;
/* Builds complete commissioning/fabric/ACL/diagnostics composition. No I/O
 * implementation, socket, OS clock, scheduler or crypto backend is created.
 * All ports above (except log/update/network) required. new calls load/initialize/UTC
 * and derives PASE on the owner thread. Failure releases owned allocations.
 * Public spans/users, crypto, storage, radio, update outlive successful delete.
 * Monotonic time is supplied by the caller, including all process/stop calls.
 * Borrowed root may be extended with application endpoints/clusters before start.
 * start is one-shot; on failure stop/drain/delete, then construct again.
 */
Matter_Runtime_T matter_runtime_new(const Matter_Runtime_Config_T*,uint32_t pin,uint64_t now_ms);
Matter_Root_T matter_runtime_root(Matter_Runtime_T);
Matter_Store_Host_T matter_runtime_store(Matter_Runtime_T);
Matter_Result_T matter_runtime_set_resumption(Matter_Runtime_T,Matter_Case_Resumption_Profile_T);
Matter_Result_T matter_runtime_set_certificate_validity(Matter_Runtime_T,bool chip);
Matter_Result_T matter_runtime_set_test_trigger(Matter_Runtime_T,const Matter_Diagnostics_Test_Trigger_T*);
Matter_Result_T matter_runtime_set_resolver(Matter_Runtime_T,const Matter_Resolver_Port_T*);
Matter_Result_T matter_runtime_set_outbound(Matter_Runtime_T,const Matter_Udp_Path_T*);
Matter_Result_T matter_runtime_set_ota(Matter_Runtime_T,const Matter_Runtime_Ota_Port_T*);
Matter_Result_T matter_runtime_start(Matter_Runtime_T,Matter_T,Matter_Udp_T,Matter_Events_T);
void matter_runtime_received(Matter_Runtime_T,const Matter_Udp_Datagram_T*);
void matter_runtime_sent(Matter_Runtime_T,uint64_t,Matter_Operation_Result_T);
void matter_runtime_changed(Matter_Runtime_T);
Matter_Result_T matter_runtime_process(Matter_Runtime_T,uint64_t now_ms);
bool matter_runtime_commissionable(Matter_Runtime_T);
uint8_t matter_runtime_commissioning_mode(Matter_Runtime_T,uint16_t* discriminator);
const Matter_Fabric_View_T* matter_runtime_fabrics(Matter_Runtime_T);
bool matter_runtime_reset_requested(Matter_Runtime_T);
bool matter_runtime_reset_ready(Matter_Runtime_T);
bool matter_runtime_ota_reboot_requested(Matter_Runtime_T);
bool matter_runtime_ota_trial(Matter_Runtime_T);
/* Local owner action: request a query of the selected live OTA provider.
 * OK means scheduled, not sent/available/installed. No schedule/rate-limit
 * bypass; no preemption during query, download, apply or boot notification. */
Matter_Result_T matter_runtime_ota_request_query(Matter_Runtime_T);
Matter_Result_T matter_runtime_ota_boot_ready(Matter_Runtime_T);
/* Keep UDP/resolver/radio and all borrowed ports alive while stop=PENDING.
 * Never free on timeout. stop=OK is required before delete; stop is terminal. */
Matter_Result_T matter_runtime_stop(Matter_Runtime_T,uint64_t now_ms);
Matter_Result_T matter_runtime_delete(Matter_Runtime_T);
#endif
