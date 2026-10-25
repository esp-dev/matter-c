#include "matter_crypto_mbedtls.h"
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "matter_mbedtls_internal.h"
#include <mbedtls/md.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/oid.h>
#include <mbedtls/constant_time.h>
#if MBEDTLS_VERSION_MAJOR < 4
#include <mbedtls/aes.h>
#endif
#include "matter_spake2p_points.h"
#include <mbedtls/platform_util.h>

#if defined(MBEDTLS_CTR_DRBG_USE_128_BIT_KEY)
#error Matter backend requires AES-256 CTR-DRBG
#endif

struct Matter_Crypto_Mbedtls {
#if MBEDTLS_VERSION_MAJOR < 4
	mbedtls_entropy_context entropy;
#endif
	mbedtls_ctr_drbg_context drbg;
	Matter_Crypto_Entropy_Port_T source;
	bool busy, ready;
};

static Matter_Result_T check(Matter_Crypto_Mbedtls_T crypto) {
	if (!crypto) return MATTER_INVALID_ARGUMENT;
	return crypto->busy ? MATTER_BUSY : MATTER_OK;
}
static bool span(const void* data, size_t size) { return data || !size; }
static const uint8_t* input(const uint8_t* data) { return data ? data : (const uint8_t*)""; }
static void clear(uint8_t* data, size_t size) { mbedtls_platform_zeroize(data, size); }
static Matter_Result_T finish(Matter_Crypto_Mbedtls_T crypto, int result, uint8_t* out, size_t size) {
	if (result) clear(out, size);
	crypto->busy = false;
	return result ? MATTER_PORT_ERROR : MATTER_OK;
}
static int entropy(void* user, unsigned char* out, size_t size) {
	Matter_Crypto_Mbedtls_T crypto = user;
	int result = 0;
	if (crypto->source.fill) {
		if (crypto->source.fill(crypto->source.user, out, size) != MATTER_OK) result = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
	} else {
#if MBEDTLS_VERSION_MAJOR >= 4
		result = psa_generate_random(out, size);
#else
		/* entropy_func permits at most one hash block per call. */
		for (size_t offset = 0; offset < size && !result;) {
			size_t n = size - offset;
			if (n > MBEDTLS_ENTROPY_BLOCK_SIZE) n = MBEDTLS_ENTROPY_BLOCK_SIZE;
			result = mbedtls_entropy_func(&crypto->entropy, out + offset, n);
			offset += n;
		}
		if (result) {
			/* An OOM in entropy_func may leave its accumulator unconfigured. */
			mbedtls_entropy_free(&crypto->entropy);
			mbedtls_entropy_init(&crypto->entropy);
		}
#endif
	}
	if (result) clear(out, size);
	return result;
}
static Matter_Result_T random_bytes(void* user, uint8_t* out, size_t size) {
	Matter_Crypto_Mbedtls_T crypto = user;
	Matter_Result_T result = check(crypto);
	if (result != MATTER_OK) return result;
	if (!span(out, size)) return MATTER_INVALID_ARGUMENT;
	if (size > MATTER_CRYPTO_MAX_RANDOM) return MATTER_LIMIT_REACHED;
	if (!crypto->ready) return MATTER_OFFLINE;
	if (!size) return MATTER_OK;
	crypto->busy = true;
	int error = mbedtls_ctr_drbg_random(&crypto->drbg, out, size);
	if (error) crypto->ready = false;
	return finish(crypto, error, out, size);
}
static Matter_Result_T sha256(void* user, const uint8_t* data, size_t size, uint8_t* out) {
	Matter_Crypto_Mbedtls_T crypto = user;
	Matter_Result_T result = check(crypto);
	if (result != MATTER_OK) return result;
	if (!span(data, size) || !out) return MATTER_INVALID_ARGUMENT;
	if (size > MATTER_CRYPTO_MAX_INPUT) return MATTER_LIMIT_REACHED;
	crypto->busy = true;
	return finish(crypto, mbedtls_sha256(input(data), size, out, 0), out, MATTER_CRYPTO_SHA256_SIZE);
}
static Matter_Result_T hmac_sha256(void* user, const uint8_t* key, size_t key_size,
	const uint8_t* data, size_t size, uint8_t* out) {
	Matter_Crypto_Mbedtls_T crypto = user;
	Matter_Result_T result = check(crypto);
	if (result != MATTER_OK) return result;
	if (!span(key, key_size) || !span(data, size) || !out) return MATTER_INVALID_ARGUMENT;
	if (key_size > MATTER_CRYPTO_MAX_INPUT || size > MATTER_CRYPTO_MAX_INPUT) return MATTER_LIMIT_REACHED;
	crypto->busy = true;
	return finish(crypto, mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
		input(key), key_size, input(data), size, out), out, MATTER_CRYPTO_SHA256_SIZE);
}
static Matter_Result_T hkdf_sha256(void* user, const uint8_t* key, size_t key_size,
	const uint8_t* salt, size_t salt_size, const uint8_t* info, size_t info_size,
	uint8_t* out, size_t size) {
	Matter_Crypto_Mbedtls_T crypto = user;
	Matter_Result_T result = check(crypto);
	if (result != MATTER_OK) return result;
	if (!span(key, key_size) || !span(salt, salt_size) || !span(info, info_size) || !span(out, size))
		return MATTER_INVALID_ARGUMENT;
	if (key_size > MATTER_CRYPTO_MAX_INPUT || salt_size > MATTER_CRYPTO_MAX_INPUT ||
		info_size > MATTER_CRYPTO_MAX_INPUT || size > MATTER_CRYPTO_MAX_HKDF) return MATTER_LIMIT_REACHED;
	if (!size) return MATTER_OK;
	crypto->busy = true;
#if MBEDTLS_VERSION_MAJOR >= 4
	psa_key_derivation_operation_t* op = calloc(1, sizeof(*op));
	int error = PSA_ERROR_INSUFFICIENT_MEMORY;
	if (op) {
		/* The by-value initializer creates a large return temporary on the
		 * task stack with the target compiler. Copy an immutable flash template
		 * directly into the owned heap operation instead. */
		static const psa_key_derivation_operation_t initial = PSA_KEY_DERIVATION_OPERATION_INIT;
		memcpy(op, &initial, sizeof(*op));
		error = psa_key_derivation_setup(op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
		if (!error) error = psa_key_derivation_input_bytes(op, PSA_KEY_DERIVATION_INPUT_SALT, input(salt), salt_size);
		if (!error) error = psa_key_derivation_input_bytes(op, PSA_KEY_DERIVATION_INPUT_SECRET, input(key), key_size);
		if (!error) error = psa_key_derivation_input_bytes(op, PSA_KEY_DERIVATION_INPUT_INFO, input(info), info_size);
		if (!error) error = psa_key_derivation_output_bytes(op, out, size);
		psa_key_derivation_abort(op); clear((uint8_t*)op, sizeof(*op)); free(op);
	}
	return finish(crypto, error, out, size);
#else
	return finish(crypto, mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
		salt, salt_size, input(key), key_size, input(info), info_size, out, size), out, size);
#endif
}
static Matter_Result_T pbkdf2_sha256(void* user, const uint8_t* password, size_t password_size,
	const uint8_t* salt, size_t salt_size, uint32_t iterations, uint8_t* out, size_t size) {
	Matter_Crypto_Mbedtls_T crypto = user;
	Matter_Result_T result = check(crypto);
	if (result != MATTER_OK) return result;
	if (!span(password, password_size) || !span(salt, salt_size) || !out || !size || !iterations)
		return MATTER_INVALID_ARGUMENT;
	if (password_size > MATTER_CRYPTO_MAX_INPUT || salt_size > MATTER_CRYPTO_MAX_INPUT ||
		size > MATTER_CRYPTO_MAX_PBKDF2 || iterations > MATTER_CRYPTO_MAX_PBKDF2_ITERATIONS)
		return MATTER_LIMIT_REACHED;
	crypto->busy = true;
	return finish(crypto, mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
		input(password), password_size, input(salt), salt_size, (unsigned int)iterations,
		(uint32_t)size, out), out, size);
}
/* Group and intermediate MPI/point descriptors belong to this call, not the
 * task stack or shared static storage. mbedTLS owns their temporary limbs. */
typedef struct {
	mbedtls_ecp_group group;
	mbedtls_mpi wide, scalar;
	mbedtls_ecp_point point;
} P256_Work_T;
static void p256_free(P256_Work_T* work) {
	if (!work) return;
	mbedtls_ecp_point_free(&work->point);
	mbedtls_mpi_free(&work->scalar);
	mbedtls_mpi_free(&work->wide);
	mbedtls_ecp_group_free(&work->group);
	mbedtls_platform_zeroize(work, sizeof(*work));
	free(work);
}
static P256_Work_T* p256_new(void) {
	P256_Work_T* work = calloc(1, sizeof(*work));
	if (!work) return NULL;
	mbedtls_ecp_group_init(&work->group);
	mbedtls_mpi_init(&work->wide);
	mbedtls_mpi_init(&work->scalar);
	mbedtls_ecp_point_init(&work->point);
	if (mbedtls_ecp_group_load(&work->group, MBEDTLS_ECP_DP_SECP256R1)) {
		p256_free(work);
		return NULL;
	}
	return work;
}
static int p256_random(void* user, unsigned char* out, size_t size) {
	/* Called only inside a BUSY operation; do not re-enter the public RNG port. */
	Matter_Crypto_Mbedtls_T crypto = user;
	int error = mbedtls_ctr_drbg_random(&crypto->drbg, out, size);
	if (error) { crypto->ready = false; clear(out, size); }
	return error;
}
static Matter_Result_T pake_verifier(void* user, const uint8_t* verifier, size_t size) {
	Matter_Crypto_Mbedtls_T c = user;
	Matter_Result_T r = check(c);
	if (r != MATTER_OK) return r;
	if (!verifier || size != 97 || verifier[32] != 4) return MATTER_INVALID_ARGUMENT;
	c->busy = true;
	P256_Work_T* w = p256_new();
	int e = w ? mbedtls_mpi_read_binary(&w->scalar, verifier, 32) : MBEDTLS_ERR_MPI_ALLOC_FAILED;
	bool invalid = false;
	if (!e) invalid = mbedtls_mpi_cmp_mpi(&w->scalar, &w->group.N) >= 0;
	if (!e && !invalid) e = mbedtls_ecp_point_read_binary(&w->group, &w->point, verifier + 32, 65);
	if (!e && !invalid) e = mbedtls_ecp_check_pubkey(&w->group, &w->point);
	if (e == MBEDTLS_ERR_ECP_BAD_INPUT_DATA || e == MBEDTLS_ERR_ECP_INVALID_KEY) invalid = true;
	p256_free(w); c->busy = false;
	return invalid ? MATTER_INVALID_ARGUMENT : e ? MATTER_PORT_ERROR : MATTER_OK;
}
static Matter_Result_T p256_reduce(void* user, const uint8_t* wide, size_t size, uint8_t* out) {
	Matter_Crypto_Mbedtls_T crypto = user;
	Matter_Result_T result = check(crypto);
	if (result != MATTER_OK) return result;
	if (!wide || !out || size != MATTER_CRYPTO_P256_WIDE_SIZE) return MATTER_INVALID_ARGUMENT;
	crypto->busy = true;
	P256_Work_T* work = p256_new();
	int error = work ? mbedtls_mpi_read_binary(&work->wide, wide, size) : MBEDTLS_ERR_MPI_ALLOC_FAILED;
	if (!error) error = mbedtls_mpi_mod_mpi(&work->scalar, &work->wide, &work->group.N);
	if (!error) error = mbedtls_mpi_write_binary(&work->scalar, out, MATTER_CRYPTO_P256_SCALAR_SIZE);
	p256_free(work);
	return finish(crypto, error, out, MATTER_CRYPTO_P256_SCALAR_SIZE);
}
static Matter_Result_T p256_base(void* user, const uint8_t* scalar, size_t size, uint8_t* out) {
	Matter_Crypto_Mbedtls_T crypto = user;
	Matter_Result_T result = check(crypto);
	if (result != MATTER_OK) return result;
	if (!scalar || !out || size != MATTER_CRYPTO_P256_SCALAR_SIZE) return MATTER_INVALID_ARGUMENT;
	if (!crypto->ready) return MATTER_OFFLINE;
	crypto->busy = true;
	P256_Work_T* work = p256_new();
	int error = work ? mbedtls_mpi_read_binary(&work->scalar, scalar, size) : MBEDTLS_ERR_MPI_ALLOC_FAILED;
	if (!error) error = mbedtls_ecp_mul(&work->group, &work->point, &work->scalar,
		&work->group.G, p256_random, crypto);
	size_t written = 0;
	if (!error) error = mbedtls_ecp_point_write_binary(&work->group, &work->point,
		MBEDTLS_ECP_PF_UNCOMPRESSED, &written, out, MATTER_CRYPTO_P256_POINT_SIZE);
	if (!error && written != MATTER_CRYPTO_P256_POINT_SIZE) error = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
	p256_free(work);
	return finish(crypto, error, out, MATTER_CRYPTO_P256_POINT_SIZE);
}
static bool equal(const uint8_t* a, const uint8_t* b, size_t size) {
	return !size || mbedtls_ct_memcmp(a, b, size) == 0;
}
static Matter_Result_T p256_scalar(void* user, uint8_t* out) {
	Matter_Crypto_Mbedtls_T crypto = user;
	Matter_Result_T result = check(crypto);
	if (result != MATTER_OK) return result;
	if (!out) return MATTER_INVALID_ARGUMENT;
	if (!crypto->ready) return MATTER_OFFLINE;
	crypto->busy = true;
	P256_Work_T* work = p256_new();
	int error = work ? mbedtls_ecp_gen_privkey(&work->group, &work->scalar, p256_random, crypto) : MBEDTLS_ERR_MPI_ALLOC_FAILED;
	if (!error) error = mbedtls_mpi_write_binary(&work->scalar, out, 32);
	p256_free(work);
	return finish(crypto, error, out, 32);
}
typedef struct {
	mbedtls_ecp_group group;
	mbedtls_mpi secret, w0, one, sign;
	mbedtls_ecp_point mask, p, q, r;
} Spake_Work_T;
static void spake_free(Spake_Work_T* w) {
	if (!w) return;
	mbedtls_ecp_point_free(&w->mask); mbedtls_ecp_point_free(&w->p);
	mbedtls_ecp_point_free(&w->q); mbedtls_ecp_point_free(&w->r);
	mbedtls_mpi_free(&w->secret); mbedtls_mpi_free(&w->w0);
	mbedtls_mpi_free(&w->one); mbedtls_mpi_free(&w->sign);
	mbedtls_ecp_group_free(&w->group);
	mbedtls_platform_zeroize(w, sizeof(*w)); free(w);
}
static int read_point(Spake_Work_T* w, mbedtls_ecp_point* p, const uint8_t* in) {
	if (in[0] != 4) return MBEDTLS_ERR_ECP_INVALID_KEY;
	int error = mbedtls_ecp_point_read_binary(&w->group, p, in, 65);
	return error ? error : mbedtls_ecp_check_pubkey(&w->group, p);
}
static int write_point(Spake_Work_T* w, const mbedtls_ecp_point* p, uint8_t* out) {
	int error = mbedtls_ecp_check_pubkey(&w->group, p); /* Includes infinity. */
	size_t size = 0;
	if (!error) error = mbedtls_ecp_point_write_binary(&w->group, p, MBEDTLS_ECP_PF_UNCOMPRESSED, &size, out, 65);
	return error ? error : (size == 65 ? 0 : MBEDTLS_ERR_ECP_BAD_INPUT_DATA);
}
/* Secret multiplications use ecp_mul + blinding. muladd is used ONLY with
 * public constants +1/-1 to add/subtract already computed points. */
static Matter_Result_T spake_compute(void* user, bool responder, const uint8_t* secret,
	const uint8_t* w0, const uint8_t* credential, const uint8_t* peer, uint8_t* out, bool derive) {
	Matter_Crypto_Mbedtls_T crypto = user;
	Matter_Result_T result = check(crypto);
	if (result != MATTER_OK) return result;
	if (!secret || !w0 || !out || (derive && (!credential || !peer))) return MATTER_INVALID_ARGUMENT;
	if (!crypto->ready) return MATTER_OFFLINE;
	crypto->busy = true;
	Spake_Work_T* w = calloc(1, sizeof(*w));
	int error = MBEDTLS_ERR_MPI_ALLOC_FAILED;
	if (!w) return finish(crypto, error, out, derive ? 130 : 65);
	mbedtls_ecp_group_init(&w->group);
	mbedtls_mpi_init(&w->secret); mbedtls_mpi_init(&w->w0);
	mbedtls_mpi_init(&w->one); mbedtls_mpi_init(&w->sign);
	mbedtls_ecp_point_init(&w->mask); mbedtls_ecp_point_init(&w->p);
	mbedtls_ecp_point_init(&w->q); mbedtls_ecp_point_init(&w->r);
#define DO(call) do { error = (call); if (error) goto cleanup; } while (0)
	DO(mbedtls_ecp_group_load(&w->group, MBEDTLS_ECP_DP_SECP256R1));
	DO(mbedtls_mpi_read_binary(&w->secret, secret, 32));
	DO(mbedtls_ecp_check_privkey(&w->group, &w->secret));
	DO(mbedtls_mpi_read_binary(&w->w0, w0, 32));
	if (mbedtls_mpi_cmp_mpi(&w->w0, &w->group.N) >= 0) { error = MBEDTLS_ERR_ECP_INVALID_KEY; goto cleanup; }
	DO(mbedtls_mpi_lset(&w->one, 1));
	DO(mbedtls_mpi_lset(&w->sign, derive ? -1 : 1));
	/* Share uses own mask, unmask uses peer's mask. */
	DO(read_point(w, &w->mask, (responder != derive) ? matter_spake2p_N : matter_spake2p_M));
	if (derive) DO(read_point(w, &w->p, peer));
	else DO(mbedtls_ecp_mul(&w->group, &w->p, &w->secret, &w->group.G, p256_random, crypto));
	if (mbedtls_mpi_cmp_int(&w->w0, 0) != 0) {
		DO(mbedtls_ecp_mul(&w->group, &w->q, &w->w0, &w->mask, p256_random, crypto));
		DO(mbedtls_ecp_muladd(&w->group, &w->r, &w->one, &w->p, &w->sign, &w->q));
	} else DO(mbedtls_ecp_copy(&w->r, &w->p));
	DO(mbedtls_ecp_check_pubkey(&w->group, &w->r));
	if (!derive) { DO(write_point(w, &w->r, out)); goto cleanup; }
	DO(mbedtls_ecp_mul(&w->group, &w->p, &w->secret, &w->r, p256_random, crypto));
	DO(write_point(w, &w->p, out)); /* Z */
	if (responder) {
		DO(read_point(w, &w->q, credential));
		DO(mbedtls_ecp_mul(&w->group, &w->p, &w->secret, &w->q, p256_random, crypto));
	} else {
		DO(mbedtls_mpi_read_binary(&w->secret, credential, 32));
		DO(mbedtls_ecp_mul(&w->group, &w->p, &w->secret, &w->r, p256_random, crypto));
	}
	DO(write_point(w, &w->p, out + 65)); /* V */
cleanup:
#undef DO
	spake_free(w);
	return finish(crypto, error, out, derive ? 130 : 65);
}
static Matter_Result_T spake_share(void* user, bool responder, const uint8_t* secret, const uint8_t* w0, uint8_t* out) {
	return spake_compute(user, responder, secret, w0, NULL, NULL, out, false);
}
static Matter_Result_T spake_secrets(void* user, bool responder, const uint8_t* secret,
	const uint8_t* w0, const uint8_t* credential, const uint8_t* peer, uint8_t* out) {
	return spake_compute(user, responder, secret, w0, credential, peer, out, true);
}
static Matter_Result_T ccm(void* user, const uint8_t* key, const uint8_t* nonce,
	const uint8_t* aad, size_t aad_size, const uint8_t* data, size_t size, uint8_t* out, bool decrypt) {
	Matter_Crypto_Mbedtls_T crypto = user;
	Matter_Result_T result = check(crypto);
	if (result != MATTER_OK) return result;
	if (!key || !nonce || !span(aad, aad_size) ||
		(decrypt ? (!data || !span(out, size)) : (!span(data, size) || !out))) return MATTER_INVALID_ARGUMENT;
	if (size > MATTER_CRYPTO_MAX_CCM || aad_size > MATTER_CRYPTO_MAX_CCM) return MATTER_LIMIT_REACHED;
	crypto->busy = true;
	mbedtls_ccm_context* ctx = calloc(1, sizeof(*ctx));
	int error = -1;
	uint8_t empty = 0; /* mbedTLS accepts a valid pointer also for empty plaintext. */
	if (ctx) {
		mbedtls_ccm_init(ctx);
		error = mbedtls_ccm_setkey(ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
		if (!error) error = decrypt ? mbedtls_ccm_auth_decrypt(ctx, size, nonce, 13,
			input(aad), aad_size, data, out ? out : &empty, data + size, 16) :
			mbedtls_ccm_encrypt_and_tag(ctx, size, nonce, 13, input(aad), aad_size,
			input(data), out, out + size, 16);
		mbedtls_ccm_free(ctx); free(ctx);
	}
	return finish(crypto, error, out, decrypt ? size : size + 16);
}
static Matter_Result_T ccm_encrypt(void* user, const uint8_t* key, const uint8_t* nonce,
	const uint8_t* aad, size_t aad_size, const uint8_t* plain, size_t size, uint8_t* cipher) {
	return ccm(user, key, nonce, aad, aad_size, plain, size, cipher, false);
}
static Matter_Result_T ccm_decrypt(void* user, const uint8_t* key, const uint8_t* nonce,
	const uint8_t* aad, size_t aad_size, const uint8_t* cipher, size_t size, uint8_t* plain) {
	return ccm(user, key, nonce, aad, aad_size, cipher, size, plain, true);
}
Matter_Result_T matter_crypto_mbedtls_privacy(void* user,
    const uint8_t key[16],const uint8_t nonce[13],const uint8_t* data,size_t size,uint8_t* out) {
    Matter_Crypto_Mbedtls_T c=user;
    Matter_Result_T r=check(c);if(r!=MATTER_OK)return r;
    if(!key||!nonce||!span(data,size)||!span(out,size)||size>20)return MATTER_INVALID_ARGUMENT;
    uint8_t counter[16]={1},stream[16]={0};size_t offset=0;memcpy(counter+1,nonce,13);
#if MBEDTLS_VERSION_MAJOR >= 4
    typedef struct { psa_key_attributes_t attributes; psa_cipher_operation_t operation; mbedtls_svc_key_id_t key; } Work;
    Work* w=calloc(1,sizeof(*w));if(!w)return MATTER_LIMIT_REACHED;
    w->attributes=psa_key_attributes_init();w->operation=psa_cipher_operation_init();
    psa_set_key_type(&w->attributes,PSA_KEY_TYPE_AES);psa_set_key_bits(&w->attributes,128);
    psa_set_key_algorithm(&w->attributes,PSA_ALG_CTR);psa_set_key_usage_flags(&w->attributes,PSA_KEY_USAGE_ENCRYPT);
    c->busy=true;
    int error=psa_import_key(&w->attributes,key,16,&w->key);size_t written=0,last=0;
    if(!error)error=psa_cipher_encrypt_setup(&w->operation,w->key,PSA_ALG_CTR);
    if(!error)error=psa_cipher_set_iv(&w->operation,counter,sizeof(counter));
    if(!error)error=psa_cipher_update(&w->operation,input(data),size,out,size,&written);
    if(!error)error=psa_cipher_finish(&w->operation,out?out+written:NULL,size-written,&last);
    if(!error && written+last!=size)error=PSA_ERROR_CORRUPTION_DETECTED;
    (void)psa_cipher_abort(&w->operation);(void)psa_destroy_key(w->key);psa_reset_key_attributes(&w->attributes);
    clear((uint8_t*)w,sizeof(*w));free(w);(void)stream;(void)offset;
#else
    mbedtls_aes_context* aes=calloc(1,sizeof(*aes));if(!aes)return MATTER_LIMIT_REACHED;
    c->busy=true;mbedtls_aes_init(aes);
    int error=mbedtls_aes_setkey_enc(aes,key,128);
    if(!error&&size)error=mbedtls_aes_crypt_ctr(aes,size,&offset,counter,stream,data,out);
    mbedtls_aes_free(aes);clear((uint8_t*)aes,sizeof(*aes));free(aes);
#endif
    clear(counter,sizeof(counter));clear(stream,sizeof(stream));
    return finish(c,error,out,size);
}
/* Credential workspaces are per call on the heap, never a task-stack keypair. */
typedef struct {
	mbedtls_ecp_keypair key;
	mbedtls_mpi r, s;
	uint8_t hash[32];
} Signature_Work_T;
static void signature_free(Signature_Work_T* w) {
	if (!w) return;
	mbedtls_ecp_keypair_free(&w->key); mbedtls_mpi_free(&w->r); mbedtls_mpi_free(&w->s);
	clear((uint8_t*)w, sizeof(*w)); free(w);
}
static Matter_Result_T ecdsa(void* user, const uint8_t* key, const uint8_t* message, size_t size,
	uint8_t* output, const uint8_t* signature) {
	Matter_Crypto_Mbedtls_T c = user;
	Matter_Result_T r = check(c); if (r != MATTER_OK) return r;
	if (!key || !span(message, size) || (!output && !signature)) return MATTER_INVALID_ARGUMENT;
	if (size > MATTER_CRYPTO_MAX_INPUT) return MATTER_LIMIT_REACHED;
	if (output && !c->ready) return MATTER_OFFLINE;
	c->busy = true;
	Signature_Work_T* w = calloc(1, sizeof(*w));
	if (w) { mbedtls_ecp_keypair_init(&w->key); mbedtls_mpi_init(&w->r); mbedtls_mpi_init(&w->s); }
	int e = w ? mbedtls_sha256(input(message), size, w->hash, 0) : MBEDTLS_ERR_MPI_ALLOC_FAILED;
	if (!e && output) {
		e = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &w->key, key, 32);
		if (!e) e = mbedtls_ecdsa_sign(&w->key.MBEDTLS_PRIVATE(grp), &w->r, &w->s,
			&w->key.MBEDTLS_PRIVATE(d), w->hash, 32, p256_random, c);
		if (!e) e = mbedtls_mpi_write_binary(&w->r, output, 32);
		if (!e) e = mbedtls_mpi_write_binary(&w->s, output + 32, 32);
	} else if (!e) {
		e = mbedtls_ecp_group_load(&w->key.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);
		if (!e && key[0] != 4) e = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
		if (!e) e = mbedtls_ecp_point_read_binary(&w->key.MBEDTLS_PRIVATE(grp), &w->key.MBEDTLS_PRIVATE(Q), key, 65);
		if (!e) e = mbedtls_ecp_check_pubkey(&w->key.MBEDTLS_PRIVATE(grp), &w->key.MBEDTLS_PRIVATE(Q));
		if (!e) e = mbedtls_mpi_read_binary(&w->r, signature, 32);
		if (!e) e = mbedtls_mpi_read_binary(&w->s, signature + 32, 32);
		if (!e) e = mbedtls_ecdsa_verify(&w->key.MBEDTLS_PRIVATE(grp), w->hash, 32,
			&w->key.MBEDTLS_PRIVATE(Q), &w->r, &w->s);
	}
	signature_free(w);
	if (output) return finish(c, e, output, 64);
	c->busy = false; return e ? MATTER_PORT_ERROR : MATTER_OK;
}
static Matter_Result_T ecdsa_sign(void* u, const uint8_t* k, const uint8_t* m, size_t n, uint8_t* out) {
	return ecdsa(u, k, m, n, out, NULL);
}
static Matter_Result_T ecdsa_verify(void* u, const uint8_t* k, const uint8_t* m, size_t n, const uint8_t* sig) {
	return ecdsa(u, k, m, n, NULL, sig);
}
static Matter_Result_T ecdh(void* user, const uint8_t* key, const uint8_t* peer, uint8_t* out) {
	Matter_Crypto_Mbedtls_T c = user;
	Matter_Result_T r = check(c); if (r != MATTER_OK) return r;
	if (!key || !peer || !out) return MATTER_INVALID_ARGUMENT;
	if (!c->ready) return MATTER_OFFLINE;
	c->busy = true; P256_Work_T* w = p256_new();
	int e = w ? mbedtls_mpi_read_binary(&w->scalar, key, 32) : MBEDTLS_ERR_MPI_ALLOC_FAILED;
	if (!e) e = mbedtls_ecp_check_privkey(&w->group, &w->scalar);
	if (!e && peer[0] != 4) e = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
	if (!e) e = mbedtls_ecp_point_read_binary(&w->group, &w->point, peer, 65);
	if (!e) e = mbedtls_ecp_check_pubkey(&w->group, &w->point);
#if MBEDTLS_VERSION_MAJOR >= 4
	if (!e) e = mbedtls_ecp_mul(&w->group, &w->point, &w->scalar, &w->point, p256_random, c);
	if (!e) e = mbedtls_mpi_copy(&w->wide, &w->point.MBEDTLS_PRIVATE(X));
#else
	if (!e) e = mbedtls_ecdh_compute_shared(&w->group, &w->wide, &w->point, &w->scalar, p256_random, c);
#endif
	if (!e) e = mbedtls_mpi_write_binary(&w->wide, out, 32);
	p256_free(w); return finish(c, e, out, 32);
}
static bool der_single(Matter_Der_T der) {
	if (!der.data || der.size < 2) return false;
	unsigned char* p = (unsigned char*)der.data;
	size_t n;
	return !mbedtls_asn1_get_tag(&p, der.data + der.size, &n, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) &&
		n == (size_t)(der.data + der.size - p);
}
static bool p256_public(mbedtls_pk_context* pk) {
#if MBEDTLS_VERSION_MAJOR >= 4
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	int error = mbedtls_pk_get_psa_attributes(pk, PSA_KEY_USAGE_VERIFY_HASH, &attributes);
	psa_key_type_t type = psa_get_key_type(&attributes);
	bool valid = !error && PSA_KEY_TYPE_IS_ECC(type) &&
		PSA_KEY_TYPE_ECC_GET_FAMILY(type) == PSA_ECC_FAMILY_SECP_R1 && psa_get_key_bits(&attributes) == 256;
	psa_reset_key_attributes(&attributes); return valid;
#else
	mbedtls_ecp_keypair* ec = mbedtls_pk_ec(*pk);
	return ec && mbedtls_ecp_keypair_get_group_id(ec) == MBEDTLS_ECP_DP_SECP256R1 &&
		!mbedtls_ecp_check_pubkey(&ec->MBEDTLS_PRIVATE(grp), &ec->MBEDTLS_PRIVATE(Q));
#endif
}
static int export_public(mbedtls_pk_context* pk, uint8_t* out) {
	size_t n = 0;
#if MBEDTLS_VERSION_MAJOR >= 4
	int e = mbedtls_pk_write_pubkey_psa(pk, out, 65, &n);
#else
	int e = mbedtls_ecp_point_write_binary(&mbedtls_pk_ec(*pk)->MBEDTLS_PRIVATE(grp),
		&mbedtls_pk_ec(*pk)->MBEDTLS_PRIVATE(Q), MBEDTLS_ECP_PF_UNCOMPRESSED, &n, out, 65);
#endif
	return e ? e : n == 65 ? 0 : MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
}
typedef struct {
	mbedtls_pk_context key; mbedtls_x509write_csr writer;
#if MBEDTLS_VERSION_MAJOR >= 4
	mbedtls_svc_key_id_t psa_key;
	uint8_t rng_check;
#endif
} Csr_Write_Work_T;
static Matter_Result_T csr_create(void* user, const uint8_t* key, uint8_t* out, size_t capacity, size_t* size) {
	Matter_Crypto_Mbedtls_T c = user;
	Matter_Result_T r = check(c); if (r != MATTER_OK) return r;
	if (!key || !out || !size) return MATTER_INVALID_ARGUMENT;
	if (capacity != MATTER_CREDENTIALS_MAX_CSR) return MATTER_LIMIT_REACHED;
	if (!c->ready) return MATTER_OFFLINE;
	c->busy = true; *size = 0;
	Csr_Write_Work_T* w = calloc(1, sizeof(*w));
	if (w) { mbedtls_pk_init(&w->key); mbedtls_x509write_csr_init(&w->writer); }
#if MBEDTLS_VERSION_MAJOR >= 4
	int e = PSA_ERROR_INSUFFICIENT_MEMORY;
	if (w) {
		psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
		psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
		psa_set_key_bits(&attributes, 256); psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
		psa_set_key_algorithm(&attributes, MBEDTLS_PK_ALG_ECDSA(PSA_ALG_SHA_256));
		/* PSA's writer owns its signing RNG. Retain this instance's explicit
		 * RNG health/reseed gate before importing or using the temporary key. */
		e = p256_random(c, &w->rng_check, sizeof(w->rng_check));
		if (!e) e = psa_import_key(&attributes, key, 32, &w->psa_key);
		psa_reset_key_attributes(&attributes);
		if (!e) e = mbedtls_pk_wrap_psa(&w->key, w->psa_key);
	}
#else
	int e = w ? mbedtls_pk_setup(&w->key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) : MBEDTLS_ERR_MPI_ALLOC_FAILED;
	if (!e) e = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(w->key), key, 32);
	if (!e) {
		mbedtls_ecp_keypair* ec = mbedtls_pk_ec(w->key);
		e = mbedtls_ecp_mul(&ec->MBEDTLS_PRIVATE(grp), &ec->MBEDTLS_PRIVATE(Q), &ec->MBEDTLS_PRIVATE(d),
			&ec->MBEDTLS_PRIVATE(grp).G, p256_random, c);
	}
#endif
	if (!e) {
		/* Pinned x509_string_to_names dereferences an unchecked OID allocation.
		 * Fixed subject needs no string parser; this ASN.1 helper checks all OOM. */
		mbedtls_asn1_named_data* name = mbedtls_asn1_store_named_data(&w->writer.MBEDTLS_PRIVATE(subject),
			MBEDTLS_OID_AT_CN, MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN), (const unsigned char*)"Matter", 6);
		if (!name) e = MBEDTLS_ERR_X509_ALLOC_FAILED;
		else name->val.tag = MBEDTLS_ASN1_UTF8_STRING;
	}
	if (!e) {
		mbedtls_x509write_csr_set_md_alg(&w->writer, MBEDTLS_MD_SHA256);
		mbedtls_x509write_csr_set_key(&w->writer, &w->key);
#if MBEDTLS_VERSION_MAJOR >= 4
		e = mbedtls_x509write_csr_der(&w->writer, out, capacity);
#else
		e = mbedtls_x509write_csr_der(&w->writer, out, capacity, p256_random, c);
#endif
		if (e > 0 && (size_t)e <= capacity) {
			*size = (size_t)e; memmove(out, out + capacity - *size, *size);
			clear(out + *size, capacity - *size); e = 0;
		} else if (!e) e = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
	}
	if (w) {
		mbedtls_x509write_csr_free(&w->writer); mbedtls_pk_free(&w->key);
#if MBEDTLS_VERSION_MAJOR >= 4
		if (!mbedtls_svc_key_id_is_null(w->psa_key)) psa_destroy_key(w->psa_key);
#endif
		clear((uint8_t*)w, sizeof(*w)); free(w);
	}
	return finish(c, e, out, capacity);
}
typedef struct { mbedtls_x509_csr csr; uint8_t hash[32]; } Csr_Read_Work_T;
static Matter_Result_T csr_verify(void* user, Matter_Der_T der, uint8_t* out) {
	Matter_Crypto_Mbedtls_T c = user;
	Matter_Result_T r = check(c); if (r != MATTER_OK) return r;
	if (!der.data || !der.size || !out) return MATTER_INVALID_ARGUMENT;
	if (der.size > MATTER_CREDENTIALS_MAX_CSR) return MATTER_LIMIT_REACHED;
	c->busy = true;
	Csr_Read_Work_T* w = calloc(1, sizeof(*w));
	if (w) mbedtls_x509_csr_init(&w->csr);
	int e = !w ? MBEDTLS_ERR_MPI_ALLOC_FAILED : !der_single(der) ? MBEDTLS_ERR_X509_BAD_INPUT_DATA :
		mbedtls_x509_csr_parse_der(&w->csr, der.data, der.size);
	if (!e && (w->csr.version != 1 || w->csr.MBEDTLS_PRIVATE(sig_md) != MBEDTLS_MD_SHA256 ||
		w->csr.MBEDTLS_PRIVATE(sig_pk) != MATTER_MBEDTLS_ECDSA_SIGNATURE || !p256_public(&w->csr.pk))) e = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
	if (!e) e = mbedtls_sha256(w->csr.cri.p, w->csr.cri.len, w->hash, 0);
	if (!e) e = mbedtls_pk_verify(&w->csr.pk, MBEDTLS_MD_SHA256, w->hash, 32,
		w->csr.MBEDTLS_PRIVATE(sig).p, w->csr.MBEDTLS_PRIVATE(sig).len);
	if (!e) e = export_public(&w->csr.pk, out);
	if (w) { mbedtls_x509_csr_free(&w->csr); clear((uint8_t*)w, sizeof(*w)); free(w); }
	return finish(c, e, out, 65);
}
/* Lexicographic calendar key, no OS clock or epoch/time_t conversions. */
static uint64_t time_key(int y, int m, int d, int h, int min, int sec) {
	static const uint8_t days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
	if (y < 1 || y > 9999 || m < 1 || m > 12 || d < 1 || h < 0 || h > 23 || min < 0 || min > 59 || sec < 0 || sec > 59) return 0;
	unsigned leap = m == 2 && y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
	if ((unsigned)d > days[m - 1] + leap) return 0;
	return (((((uint64_t)y * 13 + m) * 32 + d) * 24 + h) * 60 + min) * 60 + sec;
}
static uint64_t cert_time(const mbedtls_x509_time* t) { return time_key(t->year,t->mon,t->day,t->hour,t->min,t->sec); }
typedef struct { mbedtls_x509_crt chain, root; uint64_t now; unsigned seen; bool ignore_validity; } Chain_Work_T;
static int check_cert_time(void* user, mbedtls_x509_crt* cert, int depth, uint32_t* flags) {
	Chain_Work_T* w = user; (void)depth;
	w->seen |= cert == &w->chain ? 1u : cert == &w->root ? 4u : cert == w->chain.next ? 2u : 0u;
	/* Replace only mbedTLS's wall-clock flags; preserve every other failure. */
	*flags &= ~(MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE);
	uint64_t from = cert_time(&cert->valid_from), to = cert_time(&cert->valid_to);
	if (!from || !to || to < from) *flags |= MBEDTLS_X509_BADCERT_OTHER;
	if (!w->ignore_validity && w->now < from) *flags |= MBEDTLS_X509_BADCERT_FUTURE;
	if (!w->ignore_validity && w->now > to) *flags |= MBEDTLS_X509_BADCERT_EXPIRED;
	return 0;
}
/* Same-length private parsing view: make only opaque future-extension OIDs
 * unknown to mbedTLS, whose SAN parser otherwise rejects CHIP's test padding.
 * Never change caller bytes, lengths, values, criticality or known extensions.
 * After parsing, restore the ENTIRE owned raw buffer BEFORE any signature
 * check. mbedTLS hashes crt->tbs from that buffer at verification time, so the
 * signature still covers the exact original extension OIDs and values.
 * Generic X.509/attestation never uses this operational-profile adapter. */
static bool operational_item(unsigned char** p, const unsigned char* end, int tag,
    unsigned char** value, size_t* size) {
    unsigned char* start=*p;
    if(mbedtls_asn1_get_tag(p,end,size,tag)) return false;
    if((size_t)(*p-start)!=(*size<128?2u:*size<256?3u:4u)) return false;
    *value=*p; *p+=*size; return true;
}
static bool operational_view(unsigned char* data,size_t size) {
    unsigned char *p=data,*value; const unsigned char* end=data+size; size_t n;
    if(!operational_item(&p,end,0x30,&value,&n) || p!=end) return false;
    p=value;
    if(!operational_item(&p,end,0x30,&value,&n)) return false;
    p=value; end=value+n;
    static const uint8_t fields[]={0xa0,2,0x30,0x30,0x30,0x30,0x30};
    for(size_t i=0;i<sizeof(fields);++i)
        if(!operational_item(&p,end,fields[i],&value,&n)) return false;
    if(!operational_item(&p,end,0xa3,&value,&n) || p!=end) return false;
    p=value;
    if(!operational_item(&p,end,0x30,&value,&n) || p!=end) return false;
    p=value;
    while(p<end) {
        unsigned char* oid; size_t oid_size;
        if(!operational_item(&p,end,0x30,&value,&n)) return false;
        const unsigned char* ext_end=value+n; unsigned char* e=value;
        if(!operational_item(&e,ext_end,6,&oid,&oid_size) || !oid_size) return false;
        bool known=oid_size==3 && oid[0]==0x55 && oid[1]==0x1d &&
            (oid[2]==19 || oid[2]==15 || oid[2]==37 || oid[2]==14 || oid[2]==35);
        if(known) continue; /* mbedTLS validates the known extension contents. */
        /* DER critical DEFAULT FALSE is omitted; unknown TRUE must fail. */
        if(!operational_item(&e,ext_end,4,&value,&n) || e!=ext_end) return false;
        /* Keep a valid, minimally encoded OID with an unsupported first arc.
         * Assert it is unknown in the linked mbedTLS version, not just today. */
        mbedtls_x509_buf id={MBEDTLS_ASN1_OID,oid_size,oid}; int type;
        if(matter_mbedtls_extension_type(&id,&type)!=0) continue;
        oid[0]=0x7f;
        if(matter_mbedtls_extension_type(&id,&type)==0) return false;
    }
    return p==end;
}
static int parse_cert(mbedtls_x509_crt* chain, Matter_Der_T der, bool operational) {
	if (!der_single(der)) return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    unsigned char* view=NULL;
    if(operational) {
        if(der.size>600) return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        view=calloc(1,der.size); if(!view) return MBEDTLS_ERR_MPI_ALLOC_FAILED;
        memcpy(view,der.data,der.size);
        if(!operational_view(view,der.size)) { clear(view,der.size); free(view); return MBEDTLS_ERR_X509_INVALID_EXTENSIONS; }
    }
	int e = mbedtls_x509_crt_parse_der(chain, view ? view : der.data, der.size);
    if(view) { clear(view,der.size); free(view); }
	if (e) return e;
	mbedtls_x509_crt* last = chain; while (last->next) last = last->next;
    if(operational) {
        if(last->raw.len!=der.size) return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        memcpy(last->raw.p,der.data,der.size);
    }
	if (last->version != 3 || last->MBEDTLS_PRIVATE(sig_md) != MBEDTLS_MD_SHA256 ||
		last->MBEDTLS_PRIVATE(sig_pk) != MATTER_MBEDTLS_ECDSA_SIGNATURE || !p256_public(&last->pk)) return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
	return 0;
}
static Matter_Result_T verify_chain(void* user, Matter_Der_T leaf, Matter_Der_T intermediate,
	Matter_Der_T root, const Matter_Cert_Time_Policy_T* policy, uint8_t* out, bool operational) {
	Matter_Crypto_Mbedtls_T c = user;
	Matter_Result_T r = check(c); if (r != MATTER_OK) return r;
	if (!leaf.data || !leaf.size || !root.data || !root.size || !out || !policy ||
		(!intermediate.data != !intermediate.size) ||
		(policy->mode != MATTER_CERT_TIME_SUPPLIED && policy->mode != MATTER_CERT_TIME_LEAF_NOT_BEFORE &&
		 policy->mode != MATTER_CERT_TIME_IGNORE_VALIDITY)) return MATTER_INVALID_ARGUMENT;
	uint64_t now = time_key(policy->now.year,policy->now.month,policy->now.day,policy->now.hour,policy->now.minute,policy->now.second);
	if (policy->mode == MATTER_CERT_TIME_SUPPLIED && !now) return MATTER_INVALID_ARGUMENT;
	if (leaf.size > MATTER_CREDENTIALS_MAX_DER || intermediate.size > MATTER_CREDENTIALS_MAX_DER || root.size > MATTER_CREDENTIALS_MAX_DER) return MATTER_LIMIT_REACHED;
    if(operational && (leaf.size>600 || intermediate.size>600 || root.size>600)) return MATTER_LIMIT_REACHED;
	c->busy = true; Chain_Work_T* w = calloc(1, sizeof(*w));
	if (w) { mbedtls_x509_crt_init(&w->chain); mbedtls_x509_crt_init(&w->root); }
	int e = w ? parse_cert(&w->chain, leaf, operational) : MBEDTLS_ERR_MPI_ALLOC_FAILED;
	if (!e && intermediate.size) e = parse_cert(&w->chain, intermediate, operational);
	if (!e) e = parse_cert(&w->root, root, operational);
	if (!e && (mbedtls_x509_crt_get_ca_istrue(&w->chain) || !mbedtls_x509_crt_get_ca_istrue(&w->root) ||
		(intermediate.size && !mbedtls_x509_crt_get_ca_istrue(w->chain.next)))) e = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
	if (!e) {
		w->now = policy->mode == MATTER_CERT_TIME_LEAF_NOT_BEFORE ? cert_time(&w->chain.valid_from) : now;
		w->ignore_validity = policy->mode == MATTER_CERT_TIME_IGNORE_VALIDITY;
#if MBEDTLS_VERSION_MAJOR >= 4
		mbedtls_x509_crt_profile profile = mbedtls_x509_crt_profile_suiteb;
		profile.allowed_mds = MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256);
		profile.allowed_curves = MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP256R1);
		profile.rsa_min_bitlen = 0;
#else
		const mbedtls_x509_crt_profile profile = {MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256),
			MBEDTLS_X509_ID_FLAG(MBEDTLS_PK_ECKEY) | MBEDTLS_X509_ID_FLAG(MBEDTLS_PK_ECDSA),
			MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP256R1), 0};
#endif
		uint32_t flags = 0;
		e = mbedtls_x509_crt_verify_with_profile(&w->chain, &w->root, NULL, &profile, NULL, &flags, check_cert_time, w);
		if (!e && (flags || w->seen != (intermediate.size ? 7u : 5u))) e = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
	}
	if (!e) e = export_public(&w->chain.pk, out);
	if (w) { mbedtls_x509_crt_free(&w->chain); mbedtls_x509_crt_free(&w->root); clear((uint8_t*)w, sizeof(*w)); free(w); }
	return finish(c, e, out, 65);
}
static Matter_Result_T cert_verify_chain(void* user, Matter_Der_T leaf, Matter_Der_T intermediate,
    Matter_Der_T root, const Matter_Cert_Time_Policy_T* policy, uint8_t* out) {
    return verify_chain(user,leaf,intermediate,root,policy,out,false);
}
static Matter_Result_T operational_verify_chain(void* user, Matter_Der_T leaf, Matter_Der_T intermediate,
    Matter_Der_T root, const Matter_Cert_Time_Policy_T* policy, uint8_t* out) {
    return verify_chain(user,leaf,intermediate,root,policy,out,true);
}
Matter_Result_T matter_crypto_mbedtls_credentials(Matter_Crypto_Mbedtls_T c, Matter_Credentials_Port_T* p) {
	Matter_Result_T r = check(c); if (r != MATTER_OK) return r;
	if (!p) return MATTER_INVALID_ARGUMENT;
	*p = (Matter_Credentials_Port_T){c, csr_create, csr_verify, cert_verify_chain, operational_verify_chain}; return MATTER_OK;
}
Matter_Crypto_Mbedtls_T matter_crypto_mbedtls_new(const Matter_Crypto_Entropy_Port_T* source) {
	if (source && !source->fill) return NULL;
	Matter_Crypto_Mbedtls_T crypto = calloc(1, sizeof(*crypto));
	if (!crypto) return NULL;
	if (source) crypto->source = *source;
#if MBEDTLS_VERSION_MAJOR < 4
	mbedtls_entropy_init(&crypto->entropy);
#endif
	mbedtls_ctr_drbg_init(&crypto->drbg);
	/* Single 384-bit entropy request includes the nonce (SP800-90A 8.6.7).
	 * Avoid a separate nonce callback: 3.6.0 returns early on its failure without
	 * erasing the preceding seed. Our callback wipes the WHOLE request on failure. */
	mbedtls_ctr_drbg_set_entropy_len(&crypto->drbg, 48);
	crypto->busy = true;
	static const unsigned char personalization[] = "Matter C RNG";
	int result = mbedtls_ctr_drbg_set_nonce_len(&crypto->drbg, 0);
	if (!result) result = mbedtls_ctr_drbg_seed(&crypto->drbg, entropy, crypto,
		personalization, sizeof(personalization) - 1);
	crypto->busy = false;
	if (result) { matter_crypto_mbedtls_delete(crypto); return NULL; }
	crypto->ready = true;
	return crypto;
}
Matter_Result_T matter_crypto_mbedtls_port(Matter_Crypto_Mbedtls_T crypto, Matter_Crypto_Port_T* port) {
	Matter_Result_T result = check(crypto);
	if (result != MATTER_OK) return result;
	if (!port) return MATTER_INVALID_ARGUMENT;
	*port = (Matter_Crypto_Port_T){crypto, random_bytes, sha256, hmac_sha256, hkdf_sha256,
		clear, pbkdf2_sha256, p256_reduce, p256_base, p256_scalar, spake_share, spake_secrets, equal,
		ccm_encrypt, ccm_decrypt, ecdsa_sign, ecdsa_verify, ecdh, pake_verifier};
	return MATTER_OK;
}
Matter_Result_T matter_crypto_mbedtls_reseed(Matter_Crypto_Mbedtls_T crypto) {
	Matter_Result_T result = check(crypto);
	if (result != MATTER_OK) return result;
	crypto->busy = true;
	int error = mbedtls_ctr_drbg_reseed(&crypto->drbg, NULL, 0);
	crypto->ready = !error;
	crypto->busy = false;
	return error ? MATTER_PORT_ERROR : MATTER_OK;
}
Matter_Result_T matter_crypto_mbedtls_delete(Matter_Crypto_Mbedtls_T crypto) {
	if (!crypto) return MATTER_OK;
	if (crypto->busy) return MATTER_BUSY;
	mbedtls_ctr_drbg_free(&crypto->drbg);
#if MBEDTLS_VERSION_MAJOR < 4
	mbedtls_entropy_free(&crypto->entropy);
#endif
	mbedtls_platform_zeroize(crypto, sizeof(*crypto));
	free(crypto);
	return MATTER_OK;
}
