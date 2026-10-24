#ifndef MATTER_MBEDTLS_INTERNAL_H_INCLUDED
#define MATTER_MBEDTLS_INTERNAL_H_INCLUDED 1
#include <mbedtls/build_info.h>
/* IDF6 exposes the arithmetic needed by SPAKE2+ through TF-PSA's builtin
 * headers. Keep that version-specific dependency private to this backend. */
#if MBEDTLS_VERSION_MAJOR >= 4
#include <mbedtls/compat-3-crypto.h>
#include <mbedtls/private/ctr_drbg.h>
#include <mbedtls/private/ccm.h>
#include <mbedtls/private/entropy.h>
#include <mbedtls/private/sha256.h>
#include <mbedtls/private/sha1.h>
#include <mbedtls/private/pkcs5.h>
#include <mbedtls/private/ecp.h>
#include <mbedtls/private/ecdsa.h>
#include <psa/crypto.h>
#include "x509_oid.h"
#define MATTER_MBEDTLS_ECDSA_SIGNATURE MBEDTLS_PK_SIGALG_ECDSA
#define matter_mbedtls_extension_type mbedtls_x509_oid_get_x509_ext_type
static inline int matter_mbedtls_sha1(const unsigned char* input,size_t size,unsigned char out[20]) {
    size_t written=0;
    int error=psa_hash_compute(PSA_ALG_SHA_1,input,size,out,20,&written);
    return error?error:written==20?0:PSA_ERROR_CORRUPTION_DETECTED;
}
#else
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ccm.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha1.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#define MATTER_MBEDTLS_ECDSA_SIGNATURE MBEDTLS_PK_ECDSA
#define matter_mbedtls_extension_type mbedtls_oid_get_x509_ext_type
#define matter_mbedtls_sha1 mbedtls_sha1
#endif
#endif
