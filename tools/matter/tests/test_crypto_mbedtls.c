/* SPAKE2+ P-256 reference values: draft-bar-cfrg-spake2plus-01 Appendix B,
 * Copyright (c) 2020 IETF Trust / Tim Taubert / Christopher A. Wood.
 * See licenses/IETF-BSD-2-Clause.txt. Other tests are first-party Apache-2.0. */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <windows.h>
#include "crypto/matter_crypto_mbedtls.h"

#define REQUIRE(c) do { if (!(c)) { fprintf(stderr, "fixture:%d: %s\n", __LINE__, #c); abort(); } } while (0)
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #c); return false; } } while (0)
static bool filled(const uint8_t* data, size_t size, uint8_t byte) {
    for (size_t i = 0; i < size; ++i) if (data[i] != byte) return false;
    return true;
}
#ifdef MATTER_TEST_ALLOC
static size_t calls, live, fail_at, uncleared;
static struct { void* ptr; size_t size; } allocations[32];
void* matter_test_calloc(size_t n, size_t size) {
    ++calls; if (calls == fail_at) return NULL;
    void* p = calloc(n, size);
    if (p) {
        size_t i = 0; while (i < 32 && allocations[i].ptr) ++i;
        REQUIRE(i < 32); allocations[i].ptr = p; allocations[i].size = n * size; ++live;
    }
    return p;
}
void matter_test_free(void* p) {
    if (p) {
        size_t i = 0; while (i < 32 && allocations[i].ptr != p) ++i;
        REQUIRE(i < 32 && live);
        if (!filled(p, allocations[i].size, 0)) ++uncleared;
        allocations[i].ptr = NULL; --live;
    }
    free(p);
}
#endif
typedef struct {
    Matter_Crypto_Mbedtls_T crypto;
    Matter_Crypto_Port_T port;
    unsigned calls, reentries;
    uint8_t next;
    bool fail, reenter;
} Entropy;
typedef struct {
    Matter_Crypto_Mbedtls_T real;
    Matter_Crypto_Port_T port;
    Entropy source;
    uint8_t input[MATTER_CRYPTO_MAX_INPUT + 1];
    uint8_t output[MATTER_CRYPTO_MAX_HKDF + 1];
    uint8_t other[MATTER_CRYPTO_MAX_RANDOM + 1];
    uint8_t key[131];
} Fixture;
static Matter_Result_T entropy(void* user, uint8_t* out, size_t size) {
    Entropy* e = user; ++e->calls;
    REQUIRE(size == 48);
    if (e->reenter) {
        uint8_t byte = 0xaa;
        REQUIRE(e->port.random(e->port.user, &byte, 1) == MATTER_BUSY && byte == 0xaa);
        REQUIRE(e->port.pbkdf2_sha256(e->port.user, NULL, 0, NULL, 0, 1, &byte, 1) == MATTER_BUSY && byte == 0xaa);
        REQUIRE(e->port.p256_reduce(e->port.user, NULL, 0, &byte) == MATTER_BUSY && byte == 0xaa);
        REQUIRE(e->port.p256_base(e->port.user, NULL, 0, &byte) == MATTER_BUSY && byte == 0xaa);
        REQUIRE(matter_crypto_mbedtls_reseed(e->crypto) == MATTER_BUSY);
        REQUIRE(matter_crypto_mbedtls_delete(e->crypto) == MATTER_BUSY);
        ++e->reentries;
    }
    for (size_t i = 0; i < size; ++i) out[i] = e->next++; /* Test-only entropy! */
    return e->fail ? MATTER_OFFLINE : MATTER_OK;
}
static bool hex(const uint8_t* data, const char* expected) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; expected[i]; i += 2)
        if (!expected[i + 1] || digits[data[i / 2] >> 4] != expected[i] ||
            digits[data[i / 2] & 15] != expected[i + 1]) return false;
    return true;
}
static void decode(uint8_t* out, const char* text) {
    for (size_t i = 0; text[2 * i]; ++i) {
        unsigned byte;
        REQUIRE(text[2 * i + 1] && sscanf(text + 2 * i, "%2x", &byte) == 1);
        out[i] = (uint8_t)byte;
    }
}
static const char order_hex[] = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
static const char generator_hex[] = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
static bool p256(Fixture* f) {
    Matter_Crypto_Port_T* p = &f->port;
    memset(f->input, 0xff, 40); memset(f->other, 0xa5, sizeof(f->other));
    CHECK(p->p256_reduce(p->user, f->input, 40, f->other) == MATTER_OK);
    CHECK(hex(f->other, "fffffffe00000001431905529c0166cd22159165b6faae70f756a571fc632550") && f->other[32] == 0xa5);
    memset(f->input, 0, 40);
    CHECK(p->p256_reduce(p->user, f->input, 40, f->other) == MATTER_OK && filled(f->other, 32, 0));
    decode(f->input + 8, order_hex);
    CHECK(p->p256_reduce(p->user, f->input, 40, f->other) == MATTER_OK && filled(f->other, 32, 0));
    ++f->input[39];
    CHECK(p->p256_reduce(p->user, f->input, 40, f->other) == MATTER_OK && filled(f->other, 31, 0) && f->other[31] == 1);
    CHECK(p->p256_base(p->user, f->other, 32, f->output) == MATTER_OK && hex(f->output, generator_hex));
    decode(f->other, order_hex); --f->other[31];
    CHECK(p->p256_base(p->user, f->other, 32, f->output) == MATTER_OK);
    CHECK(hex(f->output, "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a"));
    /* Published SPAKE2+ draft-01 Appendix B w1 -> L. */
    decode(f->other, "24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512");
    CHECK(p->p256_base(p->user, f->other, 32, f->output) == MATTER_OK);
    CHECK(hex(f->output, "0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f706"
        "3a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9"));
    /* Real M07b -> reduce -> base pipeline. Independently computed with Node/OpenSSL. */
    static const uint8_t pin[] = {0xf1, 0xc1, 0x20, 0x01};
    for (size_t i = 0; i < 16; ++i) f->key[i] = (uint8_t)i;
    CHECK(p->pbkdf2_sha256(p->user, pin, 4, f->key, 16, 1000, f->output, 80) == MATTER_OK);
    LARGE_INTEGER frequency, start, end;
    CHECK(QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0 && QueryPerformanceCounter(&start));
    CHECK(p->p256_reduce(p->user, f->output, 40, f->other) == MATTER_OK);
    CHECK(p->p256_reduce(p->user, f->output + 40, 40, f->other + 32) == MATTER_OK);
    memset(f->key, 0xa5, sizeof(f->key));
    CHECK(p->p256_base(p->user, f->other + 32, 32, f->key) == MATTER_OK);
    CHECK(QueryPerformanceCounter(&end));
    CHECK(hex(f->other, "aa00b11cc4df2c05424b628ff5eb61b3eb1b4512c1a7df12a7af859c4b18557d"));
    CHECK(hex(f->other + 32, "fdeffdccba7c97d4f79706d4566d735a3ff5953521a2a1f929922b288d2a07a3"));
    CHECK(hex(f->key, "042f706e2cca77972ade9cea130e8389b0c86831c12bca6663b1200a9647cbd9eee6"
        "0f7016a3f85ac759b327a1f787d853dda6b7989b8e302b063dd589a8f12d26") && f->key[65] == 0xa5);
    printf("P-256 x86: 2 reductions + L, %.3f ms elapsed (without PBKDF2)\n",
        1000.0 * (end.QuadPart - start.QuadPart) / frequency.QuadPart);
    p->clear(f->output, 80); p->clear(f->other, 64); p->clear(f->key, 65);
    /* Domain errors are crypto errors, erase output; no implicit reduction in base. */
    for (unsigned i = 0; i < 4; ++i) {
        memset(f->other, 0, 32);
        if (i) decode(f->other, order_hex);
        if (i == 2) ++f->other[31];
        if (i == 3) memset(f->other, 0xff, 32);
        memset(f->output, 0xa5, 66);
        CHECK(p->p256_base(p->user, f->other, 32, f->output) == MATTER_PORT_ERROR);
        CHECK(filled(f->output, 65, 0) && f->output[65] == 0xa5);
    }
    return true;
}
#include "test_hash_reference.h"
static bool vectors(Fixture* f) {
    Matter_Crypto_Port_T* p = &f->port;
    memset(f->output, 0xa5, sizeof(f->output));
    CHECK(p->sha256(p->user, NULL, 0, f->output) == MATTER_OK);
    CHECK(hex(f->output, hash_empty));
    CHECK(p->sha256(p->user, (const uint8_t*)"abc", 3, f->output) == MATTER_OK);
    CHECK(hex(f->output, hash_abc));
    memset(f->key, 0x23, 20);
    CHECK(p->hmac_sha256(p->user, f->key, 20, hash_short_message, sizeof(hash_short_message), f->output) == MATTER_OK);
    CHECK(hex(f->output, hash_short));
    memset(f->key, 0x79, sizeof(f->key));
    CHECK(p->hmac_sha256(p->user, f->key, sizeof(f->key), hash_long_message, sizeof(hash_long_message), f->output) == MATTER_OK);
    CHECK(hex(f->output, hash_long));
    CHECK(f->output[32] == 0xa5);
    memset(f->key, 0x35, 22);
    CHECK(p->hkdf_sha256(p->user, f->key, 22, hash_salt, sizeof(hash_salt), hash_info, sizeof(hash_info), f->output, 42) == MATTER_OK);
    CHECK(hex(f->output, hash_hkdf));
    CHECK(p->hkdf_sha256(p->user, f->key, 22, NULL, 0, NULL, 0, f->output, 42) == MATTER_OK);
    CHECK(hex(f->output, hash_hkdf_empty));
    CHECK(f->output[42] == 0xa5);
    return true;
}
static bool pbkdf2(Fixture* f) {
    Matter_Crypto_Port_T* p = &f->port;
    /* Independent Python hashlib/OpenSSL vectors; recipe in fixtures/fixture-provenance.md. */
    memset(f->output, 0xa5, sizeof(f->output));
    CHECK(p->pbkdf2_sha256(p->user, (const uint8_t*)"passwd", 6, (const uint8_t*)"salt", 4, 1, f->output, 64) == MATTER_OK);
    CHECK(hex(f->output, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49c"
        "a9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783") && f->output[64] == 0xa5);
    CHECK(p->pbkdf2_sha256(p->user, NULL, 0, NULL, 0, 1, f->output, 32) == MATTER_OK);
    CHECK(hex(f->output, "f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad"));
    CHECK(p->pbkdf2_sha256(p->user, NULL, 0, NULL, 0, 1, f->output, 1) == MATTER_OK && f->output[0] == 0xf7);
    static const uint8_t pin[] = {0xf1, 0xc1, 0x20, 0x01}; /* Core 3.10: 18924017, not ASCII. */
    static const struct { uint32_t iterations; const char* expected; } cases[] = {
        {1000, "4c781029f9ec980eb014190f0b43d43d2e407d0460097972e41f839d9ce8ff6f"
            "8f22b81d4ae9a735c37cd4cb3a7e59c2c371a40bb877c661c45a3fe1d900669f4"
            "fab67661649709e4db2fe3903e52340"},
        {100000, "a32bd60048d51487eb66b4bf3d7252529aa89fe5c4ee4282e73c23905d811d8f"
            "6533bd150d6af9c3dc201869a3c2a9e55bde3d043fcdd8a6eec97959ce8abc4d2"
            "1a6461f9d74351152419618272ba501"}
    };
    for (size_t i = 0; i < 16; ++i) f->key[i] = (uint8_t)i;
    LARGE_INTEGER frequency, start, end;
    CHECK(QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        memset(f->output, 0xa5, sizeof(f->output));
        CHECK(QueryPerformanceCounter(&start));
        CHECK(p->pbkdf2_sha256(p->user, pin, sizeof(pin), f->key, 16, cases[i].iterations, f->output, 80) == MATTER_OK);
        CHECK(QueryPerformanceCounter(&end));
        CHECK(hex(f->output, cases[i].expected) && f->output[80] == 0xa5);
        printf("PBKDF2 x86: %lu iterations, 80 B, %.3f ms elapsed (no deadline assertion)\n",
            (unsigned long)cases[i].iterations, 1000.0 * (end.QuadPart - start.QuadPart) / frequency.QuadPart);
    }
    p->clear(f->output, sizeof(f->output));
    return true;
}
static bool random_and_lifecycle(Fixture* f) {
    Entropy* e = &f->source;
    Matter_Crypto_Entropy_Port_T ep = {e, entropy};
    e->fail = true;
    CHECK(!matter_crypto_mbedtls_new(&ep));
    e->fail = false; e->calls = 0;
    e->crypto = matter_crypto_mbedtls_new(&ep);
    CHECK(e->crypto && e->calls == 1); /* Combined 256-bit seed plus 128-bit nonce. */
    CHECK(matter_crypto_mbedtls_port(e->crypto, &e->port) == MATTER_OK);
    ep.fill = NULL; /* Backend copied the descriptor. */
    CHECK(!matter_crypto_mbedtls_new(&ep));
    CHECK(f->port.random(f->port.user, f->output, MATTER_CRYPTO_MAX_RANDOM) == MATTER_OK);
    CHECK(e->port.random(e->port.user, f->other, MATTER_CRYPTO_MAX_RANDOM) == MATTER_OK);
    CHECK(!filled(f->output, MATTER_CRYPTO_MAX_RANDOM, 0));
    CHECK(memcmp(f->output, f->other, MATTER_CRYPTO_MAX_RANDOM)); /* Smoke check, not entropy proof. */
    e->reenter = true;
    CHECK(matter_crypto_mbedtls_reseed(e->crypto) == MATTER_OK && e->reentries == 1);
    e->fail = true;
    CHECK(matter_crypto_mbedtls_reseed(e->crypto) == MATTER_PORT_ERROR);
    memset(f->other, 0xa5, sizeof(f->other));
    CHECK(e->port.random(e->port.user, f->other, 32) == MATTER_OFFLINE && filled(f->other, sizeof(f->other), 0xa5));
    CHECK(e->port.sha256(e->port.user, NULL, 0, f->output) == MATTER_OK); /* Only RNG disabled. */
    CHECK(e->port.pbkdf2_sha256(e->port.user, NULL, 0, NULL, 0, 1, f->output, 1) == MATTER_OK && f->output[0] == 0xf7);
    CHECK(f->port.random(f->port.user, f->output, 32) == MATTER_OK); /* Other instance unaffected. */
    e->fail = false;
    CHECK(matter_crypto_mbedtls_reseed(e->crypto) == MATTER_OK);
    e->reenter = false; e->fail = true;
    /* Exercise the library's default automatic reseed without editing private state. */
    unsigned n = 0;
    Matter_Result_T result;
    do { result = e->port.random(e->port.user, f->other, 1); ++n; } while (result == MATTER_OK && n <= 10001);
    CHECK(n == 10001 && result == MATTER_PORT_ERROR && f->other[0] == 0);
    CHECK(e->port.random(e->port.user, f->other, 1) == MATTER_OFFLINE);
    e->fail = false;
    CHECK(matter_crypto_mbedtls_reseed(e->crypto) == MATTER_OK);
    CHECK(e->port.random(e->port.user, f->other, 32) == MATTER_OK);
    e->port = (Matter_Crypto_Port_T){0};
    CHECK(matter_crypto_mbedtls_delete(e->crypto) == MATTER_OK); e->crypto = NULL;
    return true;
}
static bool p256_rng_failure(Fixture* f) {
    Entropy* e = &f->source;
    *e = (Entropy){0};
    Matter_Crypto_Entropy_Port_T ep = {e, entropy};
    e->crypto = matter_crypto_mbedtls_new(&ep);
    CHECK(e->crypto && matter_crypto_mbedtls_port(e->crypto, &e->port) == MATTER_OK);
    /* Exhaust the default reseed interval, so ECP's first blinding request
     * must ask entropy. No test-only production API or private state mutation. */
    for (unsigned i = 0; i < 10000; ++i) CHECK(e->port.random(e->port.user, f->other, 1) == MATTER_OK);
    memset(f->input, 0, 40); f->input[31] = 1;
    memset(f->output, 0xa5, 66); e->fail = true; e->reenter = true;
    CHECK(e->port.p256_base(e->port.user, f->input, 32, f->output) == MATTER_PORT_ERROR);
    CHECK(filled(f->output, 65, 0) && f->output[65] == 0xa5 && e->reentries == 1);
    memset(f->output, 0xa5, 66);
    CHECK(e->port.p256_base(e->port.user, f->input, 32, f->output) == MATTER_OFFLINE && filled(f->output, 66, 0xa5));
    CHECK(e->port.p256_reduce(e->port.user, f->input, 40, f->other) == MATTER_OK); /* No RNG required. */
    CHECK(f->port.p256_base(f->port.user, f->input, 32, f->output) == MATTER_OK && hex(f->output, generator_hex));
    e->fail = false;
    CHECK(matter_crypto_mbedtls_reseed(e->crypto) == MATTER_OK);
    CHECK(e->port.p256_base(e->port.user, f->input, 32, f->output) == MATTER_OK && hex(f->output, generator_hex));
    e->port = (Matter_Crypto_Port_T){0};
    CHECK(matter_crypto_mbedtls_delete(e->crypto) == MATTER_OK); e->crypto = NULL;
    return true;
}
static bool bounds(Fixture* f) {
    Matter_Crypto_Port_T* p = &f->port;
    memset(f->output, 0xa5, sizeof(f->output));
    CHECK(p->sha256(p->user, NULL, 1, f->output) == MATTER_INVALID_ARGUMENT);
    CHECK(p->sha256(p->user, f->input, sizeof(f->input), f->output) == MATTER_LIMIT_REACHED);
    CHECK(p->hmac_sha256(p->user, NULL, 1, NULL, 0, f->output) == MATTER_INVALID_ARGUMENT);
    CHECK(p->hmac_sha256(p->user, f->input, sizeof(f->input), NULL, 0, f->output) == MATTER_LIMIT_REACHED);
    CHECK(p->random(p->user, NULL, 1) == MATTER_INVALID_ARGUMENT);
    CHECK(p->random(p->user, f->output, MATTER_CRYPTO_MAX_RANDOM + 1) == MATTER_LIMIT_REACHED);
    CHECK(p->hkdf_sha256(p->user, NULL, 0, NULL, 1, NULL, 0, f->output, 32) == MATTER_INVALID_ARGUMENT);
    CHECK(p->hkdf_sha256(p->user, NULL, 0, NULL, 0, NULL, 1, f->output, 32) == MATTER_INVALID_ARGUMENT);
    CHECK(p->hkdf_sha256(p->user, NULL, 0, NULL, 0, NULL, 0, f->output, sizeof(f->output)) == MATTER_LIMIT_REACHED);
    CHECK(p->pbkdf2_sha256(NULL, NULL, 0, NULL, 0, 1, f->output, 32) == MATTER_INVALID_ARGUMENT);
    CHECK(p->pbkdf2_sha256(p->user, NULL, 1, NULL, 0, 1, f->output, 32) == MATTER_INVALID_ARGUMENT);
    CHECK(p->pbkdf2_sha256(p->user, NULL, 0, NULL, 1, 1, f->output, 32) == MATTER_INVALID_ARGUMENT);
    CHECK(p->pbkdf2_sha256(p->user, NULL, 0, NULL, 0, 1, NULL, 32) == MATTER_INVALID_ARGUMENT);
    CHECK(p->pbkdf2_sha256(p->user, NULL, 0, NULL, 0, 1, f->output, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(p->pbkdf2_sha256(p->user, NULL, 0, NULL, 0, 0, f->output, 32) == MATTER_INVALID_ARGUMENT);
    CHECK(p->pbkdf2_sha256(p->user, NULL, 0, NULL, 0, 100001, f->output, 32) == MATTER_LIMIT_REACHED);
    CHECK(p->pbkdf2_sha256(p->user, NULL, 0, NULL, 0, UINT32_MAX, f->output, 32) == MATTER_LIMIT_REACHED);
    CHECK(p->pbkdf2_sha256(p->user, NULL, 0, NULL, 0, 1, f->output, 81) == MATTER_LIMIT_REACHED);
    CHECK(p->pbkdf2_sha256(p->user, f->input, sizeof(f->input), NULL, 0, 1, f->output, 32) == MATTER_LIMIT_REACHED);
    CHECK(p->pbkdf2_sha256(p->user, NULL, 0, f->input, sizeof(f->input), 1, f->output, 32) == MATTER_LIMIT_REACHED);
    CHECK(p->p256_reduce(NULL, f->input, 40, f->output) == MATTER_INVALID_ARGUMENT);
    CHECK(p->p256_base(NULL, f->input, 32, f->output) == MATTER_INVALID_ARGUMENT);
    CHECK(p->p256_reduce(p->user, NULL, 40, f->output) == MATTER_INVALID_ARGUMENT);
    CHECK(p->p256_reduce(p->user, f->input, 40, NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(p->p256_base(p->user, NULL, 32, f->output) == MATTER_INVALID_ARGUMENT);
    CHECK(p->p256_base(p->user, f->input, 32, NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(p->p256_reduce(p->user, f->input, 39, f->output) == MATTER_INVALID_ARGUMENT);
    CHECK(p->p256_reduce(p->user, f->input, 41, f->output) == MATTER_INVALID_ARGUMENT);
    CHECK(p->p256_base(p->user, f->input, 31, f->output) == MATTER_INVALID_ARGUMENT);
    CHECK(p->p256_base(p->user, f->input, 33, f->output) == MATTER_INVALID_ARGUMENT);
    CHECK(filled(f->output, sizeof(f->output), 0xa5));
    CHECK(p->random(p->user, NULL, 0) == MATTER_OK);
    CHECK(p->hkdf_sha256(p->user, NULL, 0, NULL, 0, NULL, 0, NULL, 0) == MATTER_OK);
    CHECK(p->sha256(p->user, f->input, MATTER_CRYPTO_MAX_INPUT, f->output) == MATTER_OK);
    CHECK(p->hmac_sha256(p->user, NULL, 0, NULL, 0, f->output) == MATTER_OK);
    CHECK(p->hkdf_sha256(p->user, NULL, 0, NULL, 0, NULL, 0, f->output, MATTER_CRYPTO_MAX_HKDF) == MATTER_OK);
    CHECK(f->output[MATTER_CRYPTO_MAX_HKDF] == 0xa5);
    p->clear(f->output, sizeof(f->output)); p->clear(NULL, 0);
    CHECK(filled(f->output, sizeof(f->output), 0));
    CHECK(matter_crypto_mbedtls_port(NULL, p) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_crypto_mbedtls_port(f->real, NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_crypto_mbedtls_reseed(NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_crypto_mbedtls_delete(NULL) == MATTER_OK);
    return true;
}
#ifdef MATTER_TEST_ALLOC
static bool reset_p256_entropy(Entropy* e) {
    CHECK(matter_crypto_mbedtls_delete(e->crypto) == MATTER_OK);
    *e = (Entropy){0};
    Matter_Crypto_Entropy_Port_T ep = {e, entropy};
    e->crypto = matter_crypto_mbedtls_new(&ep);
    CHECK(e->crypto && matter_crypto_mbedtls_port(e->crypto, &e->port) == MATTER_OK);
    return true;
}
static bool p256_allocation_failures(Fixture* f) {
    CHECK(reset_p256_entropy(&f->source));
    Matter_Crypto_Port_T* p = &f->source.port;
    size_t baseline = live;
    for (unsigned base = 0; base < 2; ++base) {
        memset(f->input, 0xff, 40);
        if (base) decode(f->input, "24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512");
        CHECK(reset_p256_entropy(&f->source));
        size_t before = calls;
        CHECK((base ? p->p256_base(p->user, f->input, 32, f->other) :
            p->p256_reduce(p->user, f->input, 40, f->other)) == MATTER_OK);
        size_t count = calls - before, size = base ? 65 : 32;
        CHECK(count > 0 && live == baseline);
        for (size_t n = 1; n <= count; ++n) {
            /* Fresh deterministic test DRBG also fixes blinding-dependent MPI
             * sizes; reseeding a live DRBG does not reproduce an allocation trace. */
            CHECK(reset_p256_entropy(&f->source));
            memset(f->output, 0xa5, size + 1); fail_at = calls + n;
            CHECK((base ? p->p256_base(p->user, f->input, 32, f->output) :
                p->p256_reduce(p->user, f->input, 40, f->output)) == MATTER_PORT_ERROR);
            fail_at = 0;
            CHECK(live == baseline && filled(f->output, size, 0) && f->output[size] == 0xa5);
            CHECK((base ? p->p256_base(p->user, f->input, 32, f->output) :
                p->p256_reduce(p->user, f->input, 40, f->output)) == MATTER_OK);
            CHECK(live == baseline && !memcmp(f->output, f->other, size));
        }
        printf("P-256 %s: %zu allocation points, OOM/recovery/zeroize checked\n", base ? "base" : "reduce", count);
    }
    CHECK(matter_crypto_mbedtls_delete(f->source.crypto) == MATTER_OK);
    f->source.crypto = NULL; f->source.port = (Matter_Crypto_Port_T){0};
    CHECK(!uncleared);
    return true;
}
static bool allocation_failures(Fixture* f) {
    size_t baseline = live, before = calls;
    Matter_Crypto_Mbedtls_T c = matter_crypto_mbedtls_new(NULL);
    CHECK(c); size_t construction = calls - before;
    CHECK(matter_crypto_mbedtls_delete(c) == MATTER_OK && live == baseline);
    for (size_t n = 1; n <= construction; ++n) {
        fail_at = calls + n;
        c = matter_crypto_mbedtls_new(NULL);
        CHECK(!c && live == baseline); fail_at = 0;
    }
    Matter_Crypto_Port_T* p = &f->port;
    before = calls;
    CHECK(matter_crypto_mbedtls_reseed(f->real) == MATTER_OK);
    size_t reseeding = calls - before;
    for (size_t n = 1; n <= reseeding; ++n) {
        fail_at = calls + n;
        CHECK(matter_crypto_mbedtls_reseed(f->real) == MATTER_PORT_ERROR);
        fail_at = 0;
        CHECK(p->random(p->user, f->output, 32) == MATTER_OFFLINE);
        CHECK(matter_crypto_mbedtls_reseed(f->real) == MATTER_OK && live == baseline);
        CHECK(p->random(p->user, f->output, 32) == MATTER_OK);
    }
    for (unsigned hkdf = 0; hkdf < 2; ++hkdf) {
        before = calls;
        Matter_Result_T result = hkdf ? p->hkdf_sha256(p->user, f->key, 22, NULL, 0, NULL, 0, f->output, 42) :
            p->hmac_sha256(p->user, f->key, 22, NULL, 0, f->output);
        CHECK(result == MATTER_OK && live == baseline);
        size_t total = calls - before, size = hkdf ? 42 : 32;
        CHECK(total > 0);
        for (size_t n = 1; n <= total; ++n) {
            memset(f->output, 0xa5, sizeof(f->output)); fail_at = calls + n;
            result = hkdf ? p->hkdf_sha256(p->user, f->key, 22, NULL, 0, NULL, 0, f->output, 42) :
                p->hmac_sha256(p->user, f->key, 22, NULL, 0, f->output);
            CHECK(result == MATTER_PORT_ERROR && live == baseline && filled(f->output, size, 0));
            CHECK(f->output[size] == 0xa5); fail_at = 0;
        }
    }
    before = calls;
    CHECK(p->pbkdf2_sha256(p->user, NULL, 0, NULL, 0, 1, f->output, 80) == MATTER_OK);
    size_t deriving = calls - before;
    CHECK(deriving > 0 && live == baseline);
    for (size_t n = 1; n <= deriving; ++n) {
        memset(f->output, 0xa5, sizeof(f->output)); fail_at = calls + n;
        CHECK(p->pbkdf2_sha256(p->user, NULL, 0, NULL, 0, 1, f->output, 80) == MATTER_PORT_ERROR);
        CHECK(live == baseline && filled(f->output, 80, 0) && f->output[80] == 0xa5);
        fail_at = 0;
        CHECK(p->pbkdf2_sha256(p->user, NULL, 0, NULL, 0, 1, f->output, 32) == MATTER_OK);
        CHECK(hex(f->output, "f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad") && live == baseline);
    }
    CHECK(!uncleared);
    printf("PBKDF2: %zu allocation points, OOM/recovery/zeroize checked\n", deriving);
    printf("Crypto: constructor %zu, reseed %zu allocation points; HMAC/HKDF OOM and zeroize checked\n",
        construction, reseeding);
    return true;
}
#endif
int main(void) {
    Fixture* f = calloc(1, sizeof(*f));
    if (!f) return 1;
    f->real = matter_crypto_mbedtls_new(NULL);
    bool ok = f->real && matter_crypto_mbedtls_port(f->real, &f->port) == MATTER_OK &&
        vectors(f) && pbkdf2(f) && p256(f) && random_and_lifecycle(f) && p256_rng_failure(f) && bounds(f);
#ifdef MATTER_TEST_ALLOC
    if (ok) ok = allocation_failures(f) && p256_allocation_failures(f);
    fail_at = 0;
#endif
    REQUIRE(matter_crypto_mbedtls_delete(f->source.crypto) == MATTER_OK);
    f->port = (Matter_Crypto_Port_T){0};
    REQUIRE(matter_crypto_mbedtls_delete(f->real) == MATTER_OK);
    free(f);
#ifdef MATTER_TEST_ALLOC
    REQUIRE(live == 0 && uncleared == 0);
#endif
    if (ok) puts("PASS mbedTLS crypto: vectors, PBKDF2, P-256, RNG/lifecycle, bounds (plus OOM in alloc variant)");
    return ok ? 0 : 1;
}
