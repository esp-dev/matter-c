#ifndef MATTER_CRYPTO_PORT_H_INCLUDED
#define MATTER_CRYPTO_PORT_H_INCLUDED 1

#include "../matter.h"
#include <stddef.h>
#include <stdbool.h>

enum {
	MATTER_CRYPTO_SHA256_SIZE = 32,
	MATTER_CRYPTO_MAX_INPUT = 65536,
	MATTER_CRYPTO_MAX_RANDOM = 1024,
	MATTER_CRYPTO_MAX_HKDF = 255 * MATTER_CRYPTO_SHA256_SIZE,
	MATTER_CRYPTO_MAX_PBKDF2 = 80,
	MATTER_CRYPTO_MAX_PBKDF2_ITERATIONS = 100000,
	MATTER_CRYPTO_P256_WIDE_SIZE = 40,
	MATTER_CRYPTO_P256_SCALAR_SIZE = 32,
	MATTER_CRYPTO_P256_POINT_SIZE = 65,
	MATTER_CRYPTO_MAX_CCM = 1232
};

/* Same contract for fake, x86 and device backends. No OS/library types.
 * Synchronous, serialized on the application owner thread. No retained spans,
 * hidden tasks or inline completion. Caller owns valid, disjoint input/output
 * spans (inputs may share read-only bytes). NULL spans only with size zero.
 * SHA/HMAC output always has 32 writable bytes. Sizes are BYTES, not bits.
 * Input/key/salt/info each <= MAX_INPUT; random <= MAX_RANDOM, HKDF <= MAX_HKDF.
 * These are bounded implementation limits, not new Matter protocol limits.
 *
 * OK writes the entire output. Invalid args/limit/busy/offline preserve output.
 * PORT_ERROR means a cryptographic/entropy/allocation failure: output is fully
 * zeroized, never usable. RNG never falls back to predictable data. A caller
 * must check every result. No assertions about entropy quality follow from OK.
 * clear securely erases caller-owned bytes (NULL allowed only for zero size).
 * Backend context/user must outlive all copied ports; discard them before delete.
 */
typedef struct {
	void* user;
	Matter_Result_T (*random)(void* user, uint8_t* output, size_t size);
	Matter_Result_T (*sha256)(void* user, const uint8_t* input, size_t size, uint8_t* output);
	Matter_Result_T (*hmac_sha256)(void* user, const uint8_t* key, size_t key_size,
		const uint8_t* input, size_t size, uint8_t* output);
	Matter_Result_T (*hkdf_sha256)(void* user, const uint8_t* key, size_t key_size,
		const uint8_t* salt, size_t salt_size, const uint8_t* info, size_t info_size,
		uint8_t* output, size_t size);
	void (*clear)(uint8_t* data, size_t size);
	/* Explicit synchronous work: call outside transport RX/poll callbacks, on
	 * an application-scheduled preparation step. No yield/cancellation/deadline
	 * guarantee; HMAC rounds = iterations * ceil(size / 32), plus bounded input
	 * preprocessing. A future async
	 * adapter needs a separate submit/completion contract, not inline callbacks.
	 * Primitive accepts 1..MAX_PBKDF2_ITERATIONS, output 1..MAX_PBKDF2 bytes;
	 * password/salt <= MAX_INPUT, empty spans allowed. Zero iterations/output
	 * are INVALID_ARGUMENT, excess is LIMIT_REACHED. Never converts a PIN.
	 * PASE caller MUST enforce salt 16..32 B, iterations 1000..100000 and use
	 * the 4-byte little-endian passcode, output 80 B (two 40 B values before
	 * reduction modulo P-256 order). Caller clears secret input/output after use.
	 */
	Matter_Result_T (*pbkdf2_sha256)(void* user, const uint8_t* password, size_t password_size,
		const uint8_t* salt, size_t salt_size, uint32_t iterations, uint8_t* output, size_t size);
	/* Fixed P-256 preparation operations, synchronous outside RX/poll, no
	 * deadline/yield. Sizes other than the exact input length are INVALID_ARGUMENT.
	 * reduce: 40-byte unsigned BIG-endian integer modulo the group ORDER n
	 * (not the field prime), producing 32 big-endian bytes, including zero.
	 * base: 32-byte big-endian scalar -> 65-byte SEC1 uncompressed 04 || X || Y.
	 * Requires working RNG for blinding; OFFLINE preserves output. Scalar zero
	 * or >= n is a cryptographic error (PORT_ERROR, zeroized output).
	 * All spans must be disjoint. Caller provides full 32/65-byte output storage.
	 * For PASE: reduce each 40-byte half of PBKDF2, then base(w1) gives L.
	 * Responder retains only w0/L; caller MUST clear PBKDF2 material and w1.
	 */
	Matter_Result_T (*p256_reduce)(void* user, const uint8_t* wide, size_t size, uint8_t* scalar);
	Matter_Result_T (*p256_base)(void* user, const uint8_t* scalar, size_t size, uint8_t* point);
	/* Fixed-size SPAKE2+ arithmetic. All spans disjoint and caller-owned.
	 * scalar returns 32 B uniformly sampled in 1..N-1. share returns 65 B.
	 * secrets returns Z || V (130 B); peer is 65 B SEC1; credential is w1 (32 B)
	 * for initiator or L (65 B) for responder. secret/w0 are canonical 32 B BE;
	 * w0 may be zero. Invalid scalars/points/infinity -> PORT_ERROR/zeroize.
	 * RNG required, OFFLINE/preflight preserve output, synchronous outside RX.
	 * Arithmetic only: these do NOT authenticate a peer or authorize key use.
	 */
	Matter_Result_T (*p256_scalar)(void* user, uint8_t* scalar);
	Matter_Result_T (*spake_share)(void* user, bool responder,
		const uint8_t* secret, const uint8_t* w0, uint8_t* share);
	Matter_Result_T (*spake_secrets)(void* user, bool responder, const uint8_t* secret,
		const uint8_t* w0, const uint8_t* credential, const uint8_t* peer, uint8_t* zv);
	/* Constant-time content comparison; valid spans, NULL only for zero size. */
	bool (*equal)(const uint8_t* a, const uint8_t* b, size_t size);
	/* Matter AES-128-CCM: key 16, nonce 13, tag 16 bytes. size is PLAINTEXT
	 * length in both calls; cipher span is size+16 (appended tag). AAD and size
	 * each <= MAX_CCM. Encrypt output size+16; decrypt output size, even on
	 * authentication failure (PORT_ERROR clears it all). Empty plaintext allowed;
	 * cipher/output of encrypt always non-NULL. Other span/error rules above apply.
	 * No RNG required once the key/nonce are supplied. NEVER reuse a nonce/key.
	 */
	Matter_Result_T (*ccm_encrypt)(void* user, const uint8_t* key, const uint8_t* nonce,
		const uint8_t* aad, size_t aad_size, const uint8_t* plain, size_t size, uint8_t* cipher);
	Matter_Result_T (*ccm_decrypt)(void* user, const uint8_t* key, const uint8_t* nonce,
		const uint8_t* aad, size_t aad_size, const uint8_t* cipher, size_t size, uint8_t* plain);
	/* P-256 ECDSA over SHA-256(message), NOT an already hashed digest. Private
	 * scalar 32 B BE, SEC1 public point 65 B uncompressed; signature = r || s,
	 * two 32 B BE integers (Matter format, not DER). size <= MAX_INPUT.
	 * Verify returns PORT_ERROR for invalid point/signature or backend failure.
	 * Sign requires RNG (nonce and blinding); verify works with RNG offline.
	 * Key generation reuses p256_scalar + p256_base; clear private keys after use.
	 */
	Matter_Result_T (*ecdsa_sign)(void*, const uint8_t* private_key, const uint8_t* message, size_t size, uint8_t* signature);
	Matter_Result_T (*ecdsa_verify)(void*, const uint8_t* public_key, const uint8_t* message, size_t size, const uint8_t* signature);
	/* P-256 ECDH: scalar 32 B, peer SEC1 65 B; validates both, returns the shared
	 * x-coordinate as 32 B BE. RNG required for blinding. Caller applies the
	 * protocol KDF and clears the secret; this does not authenticate the peer. */
	Matter_Result_T (*ecdh)(void*, const uint8_t* private_key, const uint8_t* peer_key, uint8_t* secret);
	/* Validate ECM w0 || L (97 bytes): canonical w0 in [0,N), finite P-256
	 * uncompressed L. No RNG or secret derivation. INVALID_ARGUMENT means an
	 * invalid verifier; PORT_ERROR is backend/OOM failure. No input retention. */
	Matter_Result_T (*pake_verifier)(void*, const uint8_t* verifier, size_t size);
} Matter_Crypto_Port_T;

/* Optional entropy override for backend construction: fill ALL bytes with
 * fresh strong entropy, synchronously; no retention/reentry or fallback.
 * The mbedTLS backend requests 48 bytes for a combined seed/nonce (384 bits).
 * Production sources must provide entropy, not timestamps, counters or a
 * deterministic PRNG.
 * Any non-OK result is failure. Callback/user live until backend deletion.
 * Deterministic providers are for tests only. Raw entropy is NOT protocol RNG.
 */
typedef struct {
	void* user;
	Matter_Result_T (*fill)(void* user, uint8_t* output, size_t size);
} Matter_Crypto_Entropy_Port_T;

#endif
