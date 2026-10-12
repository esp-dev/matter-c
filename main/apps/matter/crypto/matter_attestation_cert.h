#ifndef MATTER_ATTESTATION_CERT_H_INCLUDED
#define MATTER_ATTESTATION_CERT_H_INCLUDED 1
#include "../ports/matter_credentials_port.h"

enum { MATTER_ATTESTATION_MAX_DER = 600 };
typedef struct {
    uint16_t vendor_id, product_id;
    uint8_t public_key[65], paa_key_id[20];
} Matter_Attestation_Identity_T;

/* Core 1.6.1 6.1/6.2.2: exactly DAC -> PAI -> explicit TRUSTED PAA, each a
 * single DER certificate <=600 bytes. Synchronous mbedTLS profile adapter;
 * uses the existing credentials port for signatures, points, path and time.
 * No task, globals, OS clock, retained pointers or mutable shared workspace.
 * Inputs/outputs must be disjoint and stable; serialize use of the port.
 *
 * Expected IDs describe the DAC identity chosen by the application (future
 * Certification Declaration dac_origin rules can differ from BasicInformation).
 * Both must be nonzero. Dedicated VID/PID OIDs take precedence over CN fallback
 * for each DN independently; preferred MatterDAC/PA names retain RDN ordering.
 * PAA VID and PAI PID are optional; PAA PID is forbidden. Required extensions,
 * criticality, exact issuer/subject bytes and AKID/SKID links are checked.
 * SKID/AKID must be 20 bytes; no operational-certificate SHA-1 derivation rule
 * is imposed on the attestation PKI. PAA self-signature is not a trust source.
 * Time is always DAC notBefore for the entire chain (Core 3.5.5/6.2.3.1).
 *
 * Only a successful profile AND DER chain verification publishes identity.
 * INVALID_ARGUMENT/LIMIT_REACHED preflight leaves output untouched; after
 * preflight every failure clears it, including OOM (PORT_ERROR) and port errors.
 * No revocation, DCL/root lookup, CD, challenge/attestation signature, production
 * test-VID policy or proof of key possession: this is NOT full device attestation.
 */
Matter_Result_T matter_attestation_cert_verify(const Matter_Credentials_Port_T* port,
    Matter_Der_T dac, Matter_Der_T pai, Matter_Der_T trusted_paa,
    uint16_t expected_vendor, uint16_t expected_product, Matter_Attestation_Identity_T* identity);
#endif
