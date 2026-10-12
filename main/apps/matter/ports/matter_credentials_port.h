#ifndef MATTER_CREDENTIALS_PORT_H_INCLUDED
#define MATTER_CREDENTIALS_PORT_H_INCLUDED 1
#include "matter_crypto_port.h"

enum { MATTER_CREDENTIALS_MAX_DER = 2048, MATTER_CREDENTIALS_MAX_CSR = 512 };
typedef struct { const uint8_t* data; size_t size; } Matter_Der_T;
typedef struct { uint16_t year; uint8_t month, day, hour, minute, second; } Matter_Cert_Time_T;
typedef enum { MATTER_CERT_TIME_SUPPLIED, MATTER_CERT_TIME_LEAF_NOT_BEFORE,
    MATTER_CERT_TIME_IGNORE_VALIDITY } Matter_Cert_Time_Mode_T;
typedef struct {
    Matter_Cert_Time_Mode_T mode;
    Matter_Cert_Time_T now; /* Trusted UTC or last-known-good time, never local time. */
} Matter_Cert_Time_Policy_T;

/* Bounded DER foundation; no OS time, filesystem, trust store or key ownership.
 * Synchronous owner-thread calls, no reentry. Inputs/output disjoint; no retained
 * pointers. Same preflight/output/zeroize rules as the crypto port. Certificates
 * <=MAX_DER each, CSR <=MAX_CSR; exactly one DER object per span, never PEM.
 * Does NOT implement Matter TLV certificates, DAC/NOC/VID/PID/fabric profiles,
 * attestation/CD, CSRResponse's attestation signature, storage or CASE.
 */
typedef struct {
    void* user;
    /* PKCS#10 P-256/SHA-256, fixed subject CN=Matter, no requested extensions.
     * Private key 32 B BE, caller-generated (not generated/replaced here).
     * Requires capacity=MAX_CSR; writes DER at offset zero, zeroes unused tail.
     * On cryptographic/OOM/RNG failure clears buffer and sets *size=0;
     * on preflight/offline/busy leaves buffer and *size untouched. */
    Matter_Result_T (*csr_create)(void*, const uint8_t* private_key, uint8_t* der, size_t capacity, size_t* size);
    /* Parse AND verify inner proof-of-possession signature; output SEC1 65 B.
     * Successful parsing alone is never treated as a verified CSR. */
    Matter_Result_T (*csr_verify)(void*, Matter_Der_T csr, uint8_t* public_key);
    /* Verify leaf -> optional intermediate -> explicit TRUSTED root, P-256,
     * SHA-256/ECDSA, X.509 v3, CA constraints, issuer/signatures and validity.
     * intermediate={NULL,0} omits it. Caller must obtain root from a trusted
     * source, not from an unauthenticated peer. Output verified leaf SEC1 key.
     * SUPPLIED checks every certificate at now; LEAF_NOT_BEFORE uses the leaf's
     * notBefore for all (Core 3.5.5 DER attestation time rule). IGNORE_VALIDITY
     * explicitly waives only not-yet-valid/expired errors (Core 3.5.6); malformed
     * periods and every other chain check still fail. Caller owns the choice
     * and time provenance/LKG persistence. No CRL/revocation
     * lookup, name/purpose/identity policy, or claim of full Crypto_VerifyChain. */
    Matter_Result_T (*cert_verify_chain)(void*, Matter_Der_T leaf, Matter_Der_T intermediate,
        Matter_Der_T trusted_root, const Matter_Cert_Time_Policy_T*, uint8_t* public_key);
    /* Optional operational-profile variant (Core 6.5.11.6). The caller has
     * validated the Matter TLV/profile and reconstructed the complete DER.
     * Interpret only the five extensions defined by Matter; preserve every
     * original TBS byte for signature verification. Reject unknown critical
     * extensions. Same chain/time/output contract, DER <=600 B per certificate.
     * NULL retains the legacy cert_verify_chain path (possibly stricter).
     * Never select this callback for attestation or arbitrary X.509 input. */
    Matter_Result_T (*operational_verify_chain)(void*, Matter_Der_T leaf, Matter_Der_T intermediate,
        Matter_Der_T trusted_root, const Matter_Cert_Time_Policy_T*, uint8_t* public_key);
} Matter_Credentials_Port_T;
#endif
