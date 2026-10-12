#ifndef MATTER_CASE_H_INCLUDED
#define MATTER_CASE_H_INCLUDED 1
#include "matter_secure.h"
#include "../crypto/matter_operational_cert.h"
#ifdef __cplusplus
extern "C" {
#endif
enum { MATTER_CASE_MAX_PAYLOAD=1200 };
typedef struct Matter_Case* Matter_Case_T;
typedef struct {
    uint8_t index, ipk[16], root_public[65]; /* OPERATIONAL IPK, not epoch key. */
    uint32_t revision;
    uint64_t fabric_id, node_id;
    uint16_t noc_size, icac_size, root_size;
    uint8_t noc[400], icac[400], root[400];
} Matter_Case_Fabric_T;

typedef struct {
    Matter_Secure_Identity_T identity; uint32_t revision;
    uint8_t shared_secret[32], id[16];
} Matter_Case_Resumption_T;
typedef struct {
    void* user; uint8_t capacity;
    /* Candidates 0..capacity-1; INVALID_STATE means empty/disabled. Copy entire snapshot.
     * A fabric may occur repeatedly with different operational IPKs. Its first
     * candidate is the initiator preferred key; responder tries every candidate.
     * No private operational key crosses this port. All buffers heap-owned. */
    Matter_Result_T (*load)(void*,unsigned slot,Matter_Case_Fabric_T*);
    Matter_Result_T (*valid)(void*,uint8_t index,uint32_t revision);
    Matter_Result_T (*sign)(void*,uint8_t index,const uint8_t*,size_t,uint8_t signature[64]);
    /* Optional pair. Trusted bounded cache, owned by application, same lifetime
     * as this port. id!=NULL: globally unique ID lookup; otherwise fabric/peer.
     * Copy record into caller's heap workspace, INVALID_STATE on miss. Cache
     * failures fall back to full CASE. Save is best-effort only at authenticated
     * one-shot handoff, never on receipt of unauthenticated resumption fields.
     * Invalidate on local credential/IPK revision change or fabric removal.
     * No traffic keys/counters are cached; volatile storage is permitted. */
    Matter_Result_T (*resume_find)(void*,uint8_t fabric,uint64_t peer,const uint8_t* id,Matter_Case_Resumption_T*);
    Matter_Result_T (*resume_save)(void*,const Matter_Case_Resumption_T*);
} Matter_Case_Port_T;
/* Explicit traffic-KDF profile; never auto-detected from ciphertext. Both
 * peers must agree. SPEC uses Sigma2Resume new ID (Core 1.6.1 4.14.2.6.4);
 * CHIP uses the previous ID, matching connectedhomeip 3bcdd56b. */
typedef enum { MATTER_CASE_RESUMPTION_SPEC, MATTER_CASE_RESUMPTION_CHIP } Matter_Case_Resumption_Profile_T;
typedef struct {
    bool responder; uint16_t local_session_id; uint32_t timeout_ms;
    uint8_t fabric_index; uint64_t peer_node_id; /* Initiator's intended identity. */
    Matter_Cert_Time_Policy_T time; /* Explicit trusted UTC/LKG. */
    Matter_Case_Resumption_Profile_T resumption_profile; /* Zero defaults to SPEC. */
} Matter_Case_Config_T;
typedef struct { Matter_Pase_Keys_T traffic; Matter_Secure_Identity_T identity; } Matter_Case_Keys_T;
typedef enum { MATTER_CASE_WAITING,MATTER_CASE_OUTPUT,MATTER_CASE_COMPLETE,MATTER_CASE_FAILED } Matter_Case_State_T;
/* Core 1.6.1 4.14.2: one full or resumed handshake, owner-driven, copied ports/config,
 * no I/O/task/OS time. All port users outlive attempt. Reserve unique nonzero
 * local session ID across PASE/CASE. Load validates local provisioning; peer
 * chain/signature/IDs are verified here using the configured trust anchor/time.
 * KeySet0 operational IPK candidates; missing/invalid Sigma1 resumption state
 * falls back to full CASE. Default local MRP parameters, peer parsed.
 * Crypto is synchronous and bounded by sizes, outside RX; no hard latency bound.
 */
Matter_Case_T matter_case_new(const Matter_Crypto_Port_T*,const Matter_Credentials_Port_T*,
    const Matter_Case_Port_T*,const Matter_Case_Config_T*,uint64_t now_ms);
/* Copy only after validated transport routing of UNSECURED exchange:
 * protocol/vendor0, peer I, R=1, same session/exchange, duplicate filtering.
 * Application schedules process, refreshes time after costly work if needed. */
Matter_Result_T matter_case_receive(Matter_Case_T,uint8_t opcode,const uint8_t*,size_t);
Matter_Result_T matter_case_process(Matter_Case_T,uint64_t now_ms);
Matter_Result_T matter_case_output(Matter_Case_T,Matter_Pase_Message_T*);
/* Copy/enqueue immutable payload into MRP before sent. Retries reuse packet.
 * Sending authenticated SigmaFinished completes CASE independently of its ACK
 * (4.14.2.3: Validate Sigma3/Sigma2Resume). Owner retains MRP packet/exchange
 * through ACK/timeout even after one-shot secure handoff. */
Matter_Result_T matter_case_sent(Matter_Case_T);
/* Optional one-shot ACK notification for final success sender (full responder
 * or resumed initiator). Does not gate keys/cache or extend handshake timeout.
 * After completion, MRP failure must only drain transport, not cancel CASE or
 * revoke the independent secure session. Explicit cancel still denies untaken keys. */
Matter_Result_T matter_case_confirm_delivery(Matter_Case_T,uint64_t now_ms);
Matter_Result_T matter_case_take_keys(Matter_Case_T,Matter_Case_Keys_T*);
/* Public peer timing remains available after handoff for final MRP retries. */
Matter_Result_T matter_case_peer_intervals(Matter_Case_T,Matter_Pase_Intervals_T*);
Matter_Case_State_T matter_case_state(Matter_Case_T);
/* Selected local fabric, zero until Sigma1 has selected a candidate. */
uint8_t matter_case_fabric_index(Matter_Case_T);
Matter_Result_T matter_case_cancel(Matter_Case_T);
Matter_Result_T matter_case_delete(Matter_Case_T);
/* Atomic one-shot activation; allocation/RNG failure preserves CASE handoff. */
Matter_Secure_T matter_secure_new_case(const Matter_Crypto_Port_T*,Matter_Case_T,uint64_t now_ms);
/* Small reusable protocol computations, disjoint spans. 4.17.2 and 4.14.2.4.1. */
Matter_Result_T matter_case_ipk(const Matter_Crypto_Port_T*,const uint8_t epoch[16],const uint8_t compressed[8],uint8_t out[16]);
Matter_Result_T matter_case_destination(const Matter_Crypto_Port_T*,const uint8_t ipk[16],const uint8_t random[32],
    const uint8_t root_public[65],uint64_t fabric,uint64_t node,uint8_t out[32]);
#ifdef __cplusplus
}
#endif
#endif
