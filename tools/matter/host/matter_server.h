#ifndef MATTER_SERVER_H
#define MATTER_SERVER_H 1
#include "matter_dispatch.h"
#include "matter_store_host.h"
#include "clusters/matter_fabric.h"
typedef struct Matter_Server* Matter_Server_T;
/* Standalone host commissioning composition. Loads explicit DER DAC/PAI/PAA,
 * raw 32-byte dac-key.bin and cd.der from credentials directory. These files
 * must be simulation credentials; no built-in production keys/test fixtures.
 * State file is the existing atomic TLV backend, locked for this instance. */
Matter_Server_T matter_server_new(const char* credentials,const char* state,
    const Matter_Root_Config_T*,uint32_t pin,uint64_t now);
/* Explicit test-only installer. Raw SEC1 P256 public key, signed WWOTA001
 * payload; atomic journal at state + .ota-sim. Restores simulated version
 * before Root creation. Existing new() remains unsigned download-only. */
Matter_Server_T matter_server_new_ota_sim(const char* credentials,const char* state,
    const Matter_Root_Config_T*,uint32_t pin,uint64_t now,const char* public_key);
/* Host-only initial simulation options, copied during construction. A restored
 * state file takes precedence over wifi_connected, including an empty Networks
 * list. This never changes the OS network interface or the portable runtime API. */
typedef struct {
    const char* ota_public_key; bool wifi_connected;
    /* Optional copied desktop identity (1..32 bytes); default remains DAC hash.
     * Each simulated node sharing development credentials needs its own ID. */
    const Matter_Root_Text_T* unique_id;
    /* Optional actual transport interfaces, independent of simulated Wi-Fi. */
    Matter_Diagnostics_Network_Port_T network;
} Matter_Server_Sim_Options_T;
Matter_Server_T matter_server_new_sim(const char* credentials,const char* state,
    const Matter_Root_Config_T*,uint32_t pin,uint64_t now,const Matter_Server_Sim_Options_T*);
bool matter_server_ota_reboot_requested(Matter_Server_T);
bool matter_server_ota_trial(Matter_Server_T);
Matter_Result_T matter_server_ota_request_query(Matter_Server_T);
/* Owner calls after all host initialization and before network polling.
 * Failure stops this boot: unconfirmed trial rolls back on next construction. */
Matter_Result_T matter_server_ota_boot_ready(Matter_Server_T);
Matter_Root_T matter_server_root(Matter_Server_T);
/* Borrowed persistence for node-owned EEM/events; valid until server delete. */
Matter_Store_Host_T matter_server_store(Matter_Server_T);
/* Explicit resumption KDF profile, configured before start. Default SPEC. */
Matter_Result_T matter_server_set_resumption(Matter_Server_T,Matter_Case_Resumption_Profile_T);
/* Before start only. Default false: current OS UTC. True: CHIP server policy
 * waives only operational certificate validity periods (Core 3.5.6).
 * Signatures/trust/profile checks and attestation time policy are unchanged. */
Matter_Result_T matter_server_set_certificate_validity(Matter_Server_T,bool chip);
/* Optional per-instance clock, before start. Borrowed user/callbacks outlive
 * server deletion; affects credentials and attestation timestamps together. */
Matter_Result_T matter_server_set_clock(Matter_Server_T,void* user,
    Matter_Result_T (*utc)(void*,Matter_Cert_Time_T*),Matter_Result_T (*timestamp)(void*,uint32_t*));
/* Explicit laboratory triggers, before start only; NULL disables. */
Matter_Result_T matter_server_set_test_trigger(Matter_Server_T,const Matter_Diagnostics_Test_Trigger_T*);
/* Optional borrowed resolver, configured before start; backend outlives delete. */
Matter_Result_T matter_server_set_resolver(Matter_Server_T,const Matter_Resolver_Port_T*);
/* Explicit downloaded image destination; opt-in BDX, no installation. */
Matter_Result_T matter_server_set_ota_file(Matter_Server_T,const char* path);
Matter_Result_T matter_server_set_outbound(Matter_Server_T,const Matter_Udp_Path_T*);
/* Required node log outlives server; emits startup/boot before serving IM and
 * binds ACL events. On failure discard this unstarted server composition. */
Matter_Result_T matter_server_start(Matter_Server_T,Matter_T,Matter_Udp_T,Matter_Events_T);
void matter_server_received(Matter_Server_T,const Matter_Udp_Datagram_T*);
void matter_server_sent(Matter_Server_T,uint64_t,Matter_Operation_Result_T);
Matter_Result_T matter_server_process(Matter_Server_T,uint64_t now);
void matter_server_changed(Matter_Server_T);
bool matter_server_commissionable(Matter_Server_T);
/* 0 closed, 1 initial basic window, 2 enhanced. Writes discriminator only for 2. */
uint8_t matter_server_commissioning_mode(Matter_Server_T,uint16_t* discriminator);
const Matter_Fabric_View_T* matter_server_fabrics(Matter_Server_T);
bool matter_server_reset_requested(Matter_Server_T); /* Stop sampling/persistence; keep RX/process running. */
bool matter_server_reset_ready(Matter_Server_T); /* Removal reply finished/timed out: app may stop/delete. */
Matter_Result_T matter_server_stop(Matter_Server_T,uint64_t now);
Matter_Result_T matter_server_delete(Matter_Server_T);
#endif
