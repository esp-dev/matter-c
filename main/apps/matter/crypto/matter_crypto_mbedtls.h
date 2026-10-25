#ifndef MATTER_CRYPTO_MBEDTLS_H_INCLUDED
#define MATTER_CRYPTO_MBEDTLS_H_INCLUDED 1

#include "../ports/matter_crypto_port.h"
#include "../ports/matter_credentials_port.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Matter_Crypto_Mbedtls* Matter_Crypto_Mbedtls_T;

/* Own heap context (entropy + AES-256 CTR-DRBG); no global setup or task.
 * NULL entropy uses mbedTLS platform entropy (Windows host: BCryptGenRandom).
 * Non-NULL descriptor copied, user borrowed. NULL result: invalid port, OOM
 * or seed failure, all internal storage released/zeroized. No usable RNG before
 * successful seed. Sources/host configuration pinned to ESP-IDF in the runner.
 * Construction/reseed may call the OS entropy provider synchronously. This is
 * not an ISR API and gives no hard real-time latency guarantee. MCU integration
 * must measure stack/latency and provide a suitable entropy backend at M16.
 * With Mbed TLS4, the application initializes PSA before constructing this
 * backend and retains that service through deletion. NULL entropy then uses
 * PSA random; each instance still owns its separate AES-256 CTR-DRBG.
 * Its CSR writer uses the application's PSA signing RNG after checking the
 * instance's RNG health. Software ECP is required for the private blinding
 * callback contract; the IDF component rejects hardware ECP overrides.
 */
Matter_Crypto_Mbedtls_T matter_crypto_mbedtls_new(const Matter_Crypto_Entropy_Port_T* entropy);
Matter_Result_T matter_crypto_mbedtls_port(Matter_Crypto_Mbedtls_T crypto, Matter_Crypto_Port_T* port);
/* Same borrowed backend lifetime/owner thread; DER/CSR foundation plus the
 * explicit operational extension policy. Matter TLV/profile checks remain
 * the caller's responsibility; generic DER/attestation policy is unchanged. */
Matter_Result_T matter_crypto_mbedtls_credentials(Matter_Crypto_Mbedtls_T crypto, Matter_Credentials_Port_T* port);
/* Matter Core3.7 privacy transform: AES-CTR, q=2, counter starts at0.
 * Same operation encrypts/decrypts <=20 header bytes. Key16/nonce13 and input/
 * output spans are disjoint. Invalid/preflight/OOM preserves output; a crypto
 * failure clears it. No RNG dependency after key provisioning. */
/* Callback-compatible context is the same crypto instance / crypto.port.user. */
Matter_Result_T matter_crypto_mbedtls_privacy(void*,
    const uint8_t key[16],const uint8_t nonce[13],const uint8_t*,size_t,uint8_t*);
/* Explicit entropy refresh/recovery. Failure disables random (OFFLINE) until
 * a successful explicit reseed. Automatic reseed failure has the same rule.
 * Hash/HMAC/HKDF/PBKDF2 and P-256 reduction remain usable; P-256 base/SPAKE2+
 * require RNG blinding and are OFFLINE too. Failed random/point output is zeroized.
 */
Matter_Result_T matter_crypto_mbedtls_reseed(Matter_Crypto_Mbedtls_T crypto);
/* Synchronous; caller first discards ports/consumers. NULL OK, reentry BUSY.
 * Frees/zeroizes entropy and DRBG. HMAC/HKDF/PBKDF2/P-256 use temporary allocations;
 * those are cleaned on success AND error, including intermediate key material.
 */
Matter_Result_T matter_crypto_mbedtls_delete(Matter_Crypto_Mbedtls_T crypto);

#ifdef __cplusplus
}
#endif
#endif
