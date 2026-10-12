#ifndef MATTER_HOST_MBEDTLS_CONFIG_H
#define MATTER_HOST_MBEDTLS_CONFIG_H

#if MBEDTLS_VERSION_NUMBER != 0x03060000
#error Host crypto tests require the pinned upstream mbedTLS 3.6.0 revision
#endif

/* Isolated host configuration for official Mbed-TLS/mbedtls 3.6.0.
 * No ESP acceleration, PSA/TLS, filesystem seed, global allocator or threads.
 * Windows entropy_poll uses BCryptGenRandom; unix uses its platform source.
 */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CCM_C
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_ENTROPY_FORCE_SHA256
#define MBEDTLS_SHA256_C
/* Matter SKID/AKID derivation only; signature profiles still require SHA-256. */
#define MBEDTLS_SHA1_C
#define MBEDTLS_MD_C
#define MBEDTLS_HKDF_C
#define MBEDTLS_PKCS5_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CREATE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CSR_PARSE_C
#define MBEDTLS_X509_CSR_WRITE_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
/* Fast NIST field reduction and
 * read-only precomputed base-point table (no mutable global cache). */
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_ECP_FIXED_POINT_OPTIM 1
#define MBEDTLS_PLATFORM_C

#endif
