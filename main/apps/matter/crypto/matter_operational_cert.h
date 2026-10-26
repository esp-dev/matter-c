#ifndef MATTER_OPERATIONAL_CERT_H_INCLUDED
#define MATTER_OPERATIONAL_CERT_H_INCLUDED 1
#include "../ports/matter_credentials_port.h"
#include "../ports/matter_crypto_port.h"

enum { MATTER_OPERATIONAL_MAX_TLV = 400, MATTER_OPERATIONAL_MAX_DER = 600 };
typedef struct { const uint8_t* data; size_t size; } Matter_Cert_Tlv_T;
typedef enum { MATTER_CERT_NOC, MATTER_CERT_ICAC, MATTER_CERT_RCAC } Matter_Operational_Type_T;
typedef struct {
    uint64_t node_id, fabric_id;
    uint32_t cats[3];
    uint8_t cat_count, public_key[65];
} Matter_Operational_Identity_T;

/* mbedTLS adapter, Core 1.6.1 sections 6.1/6.4/6.5. Synchronous, no global
 * state, retained pointers, OS time, tasks or trust store. Per-call bounded heap
 * workspace; all spans/output disjoint and stable until return. No MCU budget
 * claim. Input is exactly one anonymous TLV certificate, at most 400 bytes.
 * NOC/ICAC/RCAC only; not DAC, firmware signing or VVSC.
 *
 * Decode validates encoding, operational profile and derived SKID, reconstructs
 * the complete DER (including signature). It DOES NOT establish trust or check
 * the signature, public point, validity or issuer. Output MUST NOT authorize a
 * peer. Capacity must equal 600; writes at offset zero, clears unused tail.
 * Preflight INVALID_ARGUMENT/LIMIT_REACHED leaves outputs unchanged; all later
 * failures clear the entire output and *size, returning PORT_ERROR. */
Matter_Result_T matter_operational_cert_decode(Matter_Cert_Tlv_T certificate,
    Matter_Operational_Type_T type, uint8_t* der, size_t capacity, size_t* size);

/* Verify NOC -> optional ICAC -> caller's explicitly TRUSTED RCAC. Check all
 * profiles, AKID/SKID, CA Fabric IDs, expected_fabric (nonzero), signatures,
 * path length and validity using the DER credentials port. SUPPLIED validates
 * at trusted UTC; LAST_KNOWN_GOOD selects the bounded fallback described by
 * the credentials port (no attestation leaf-time fallback).
 * Uses operational_verify_chain when provided; the legacy cert_verify_chain
 * fallback may reject opaque future extensions understood by its X.509 parser.
 * Empty ICAC must be {NULL,0}. Root selection/trust provisioning and time/LKG
 * persistence belong to the application; never accept a peer-supplied anchor.
 * Identity is published atomically ONLY after all checks. After preflight,
 * every failure clears it (including callback BUSY/OFFLINE). No CASE handshake,
 * proof of peer key possession, revocation or durable fabric storage here. */
Matter_Result_T matter_operational_cert_verify(const Matter_Credentials_Port_T* port,
    Matter_Cert_Tlv_T noc, Matter_Cert_Tlv_T icac, Matter_Cert_Tlv_T trusted_rcac,
    uint64_t expected_fabric, const Matter_Cert_Time_Policy_T* time,
    Matter_Operational_Identity_T* identity);
/* Parse the operational profile and validate the public curve point, WITHOUT
 * chain/signature/time verification or trust. For commissioning diagnostics and
 * extracting the expected FabricID before verify. invalid_node distinguishes
 * an out-of-range NOC NodeID; failed identity output is cleared. RCAC trust comes
 * from the authorized commissioner (Core 6.4.5.3), not its self-signature. */
Matter_Result_T matter_operational_cert_inspect(Matter_Cert_Tlv_T, Matter_Operational_Type_T,
    Matter_Operational_Identity_T*, bool* invalid_node);
/* Admission check for AddTrustedRootCertificate: RCAC profile and self-signature
 * over the original DER TBSCertificate, including opaque future extensions.
 * The crypto port checks the P-256 point and SHA-256/ECDSA signature. No time
 * check or trust establishment: only an authorized commissioner may provision
 * the anchor. Existing trusted-anchor chain validation is unchanged.
 * Bounded per-call heap, no retained pointers. Invalid/missing callback or input
 * returns INVALID_ARGUMENT, oversize LIMIT_REACHED, invalid cert/OOM PORT_ERROR;
 * backend errors propagate. No output or persistent side effects. */
Matter_Result_T matter_operational_cert_verify_root(const Matter_Crypto_Port_T*, Matter_Cert_Tlv_T);
#endif
