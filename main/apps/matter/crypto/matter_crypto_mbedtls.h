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
 */
Matter_Crypto_Mbedtls_T matter_crypto_mbedtls_new(const Matter_Crypto_Entropy_Port_T* entropy);
Matter_Result_T matter_crypto_mbedtls_port(Matter_Crypto_Mbedtls_T crypto, Matter_Crypto_Port_T* port);
/* Same borrowed backend lifetime/owner thread; DER/CSR foundation plus the
 * explicit operational extension policy. Matter TLV/profile checks remain
 * the caller's responsibility; generic DER/attestation policy is unchanged. */
Matter_Result_T matter_crypto_mbedtls_credentials(Matter_Crypto_Mbedtls_T crypto, Matter_Credentials_Port_T* port);
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
