/* Numeric test vectors: IETF draft-bar-cfrg-spake2plus-01 Appendix B.
 * Copyright (c) 2020 IETF Trust / Tim Taubert / Christopher A. Wood.
 * See licenses/IETF-BSD-2-Clause.txt; test implementation is first-party Apache-2.0. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "crypto/matter_spake2p.h"
#include "crypto/matter_crypto_mbedtls.h"
#include "crypto/matter_spake2p_points.h"

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #c); return false; } } while (0)
#define REQUIRE(c) do { if (!(c)) { fprintf(stderr, "fixture:%d: %s\n", __LINE__, #c); abort(); } } while (0)
static bool filled(const uint8_t* p, size_t n, uint8_t b) { while (n--) if (*p++ != b) return false; return true; }
#ifdef MATTER_TEST_ALLOC
static size_t calls, live, fail_at, wiped;
static struct { void* p; size_t size; bool session; } blocks[256];
void* matter_test_calloc(size_t n, size_t size) {
    if (++calls == fail_at) return NULL;
    void* p = calloc(n, size);
    if (p) {
        size_t i = 0; while (i < 256 && blocks[i].p) ++i;
        REQUIRE(i < 256); blocks[i].p = p; blocks[i].size = n * size; blocks[i].session = false; ++live;
    }
    return p;
}
void matter_test_free(void* p) {
    if (p) {
        size_t i = 0; while (i < 256 && blocks[i].p != p) ++i;
        REQUIRE(i < 256 && live);
        if (blocks[i].session) { REQUIRE(filled(p, blocks[i].size, 0)); ++wiped; }
        blocks[i].p = NULL; --live;
    }
    free(p);
}
static void watch(void* p) {
    for (size_t i = 0; i < 256; ++i) if (blocks[i].p == p) { blocks[i].session = true; return; }
    REQUIRE(false);
}
#else
static void watch(void* p) { (void)p; }
#endif
static void decode(uint8_t* out, const char* h) {
    while (*h) { unsigned byte; REQUIRE(h[1] && sscanf(h, "%2x", &byte) == 1); *out++ = (uint8_t)byte; h += 2; }
}
static bool hex(const uint8_t* p, const char* h) {
    while (*h) { unsigned byte; if (!h[1] || sscanf(h, "%2x", &byte) != 1 || *p++ != byte) return false; h += 2; }
    return true;
}
static const char x_hex[] = "5b478619804f4938d361fbba3a20648725222f0a54cc4c876139efe7d9a21786";
static const char y_hex[] = "766770dad8c8eecba936823c0aed044b8c3c4f7655e8beec44a15dcbcaf78e5e";
static const char a_hex[] = "04a6db23d001723fb01fcfc9d08746c3c2a0a3feff8635d29cad2853e7358623425cf39712e928054561ba71e2dc11f300f1760e71eb177021a8f85e78689071cd";
static const char b_hex[] = "04390d29bf185c3abf99f150ae7c13388c82b6be0c07b1b8d90d26853e84374bbdc82becdb978ca3792f472424106a2578012752c11938fcf60a41df75ff7cf947";
static Matter_Result_T fixed_x(void* user, uint8_t* out) { (void)user; decode(out, x_hex); return MATTER_OK; }
static Matter_Result_T fixed_y(void* user, uint8_t* out) { (void)user; decode(out, y_hex); return MATTER_OK; }
typedef struct {
    Matter_Crypto_Mbedtls_T crypto[2];
    Matter_Crypto_Port_T port[2];
    Matter_Crypto_Mbedtls_T extra;
    Matter_Crypto_Port_T extra_port;
    bool entropy_failed;
    Matter_Spake2p_T s[2];
    uint8_t w0[32], w1[32], L[65], context[64], share[2][65], confirm[2][32], key[2][16];
    uint8_t wide[80], scratch[131], saved[65], expected[130];
} Fixture;
static void close_pair(Fixture* f) {
    for (unsigned i = 0; i < 2; ++i) { REQUIRE(matter_spake2p_delete(f->s[i]) == MATTER_OK); f->s[i] = NULL; }
}
static bool pair(Fixture* f, bool fixed, const uint8_t* context, size_t size) {
    close_pair(f);
    for (unsigned i = 0; i < 2; ++i) {
        CHECK(matter_crypto_mbedtls_port(f->crypto[i], &f->port[i]) == MATTER_OK);
        if (fixed) f->port[i].p256_scalar = i ? fixed_y : fixed_x;
        f->s[i] = matter_spake2p_new(&f->port[i], i != 0, f->w0, i ? f->L : f->w1, i ? 65 : 32, context, size);
        CHECK(f->s[i]); watch(f->s[i]);
    }
    return true;
}
static bool exchange(Fixture* f, bool known) {
    for (unsigned i = 0; i < 2; ++i) {
        memset(f->key[i], 0xa5, 16);
        CHECK(matter_spake2p_key(f->s[i], f->key[i]) == MATTER_INVALID_STATE && filled(f->key[i], 16, 0xa5));
        CHECK(matter_spake2p_start(f->s[i], f->share[i]) == MATTER_OK);
    }
    if (known) CHECK(hex(f->share[0], a_hex) && hex(f->share[1], b_hex));
    for (unsigned i = 0; i < 2; ++i) {
        CHECK(matter_spake2p_start(f->s[i], f->scratch) == MATTER_INVALID_STATE);
        CHECK(matter_spake2p_derive(f->s[i], f->share[1-i], 65) == MATTER_OK);
        CHECK(matter_spake2p_key(f->s[i], f->key[i]) == MATTER_INVALID_STATE);
    }
    CHECK(matter_spake2p_confirmation(f->s[0], f->confirm[0]) == MATTER_INVALID_STATE);
    CHECK(matter_spake2p_verify(f->s[1], f->confirm[0], 32) == MATTER_INVALID_STATE);
    CHECK(matter_spake2p_confirmation(f->s[1], f->confirm[1]) == MATTER_OK);
    if (known) CHECK(hex(f->confirm[1], "095dc0400355cc233fde7437811815b3c1524aae80fd4e6810cf531cf11d20e3"));
    CHECK(matter_spake2p_verify(f->s[0], f->confirm[1], 32) == MATTER_OK);
    CHECK(matter_spake2p_key(f->s[0], f->key[0]) == MATTER_INVALID_STATE);
    CHECK(matter_spake2p_confirmation(f->s[0], f->confirm[0]) == MATTER_OK);
    if (known) CHECK(hex(f->confirm[0], "71d9412779b6c45a2c615c9df3f1fd93dc0aaf63104da8ece4aa1b5a3a415fea"));
    CHECK(matter_spake2p_verify(f->s[1], f->confirm[0], 32) == MATTER_OK);
    for (unsigned i = 0; i < 2; ++i) {
        CHECK(matter_spake2p_key(f->s[i], f->key[i]) == MATTER_OK);
        CHECK(matter_spake2p_verify(f->s[i], f->confirm[1-i], 32) == MATTER_INVALID_STATE);
        CHECK(matter_spake2p_derive(f->s[i], f->share[1-i], 65) == MATTER_INVALID_STATE);
        CHECK(matter_spake2p_confirmation(f->s[i], f->scratch) == MATTER_OK && !memcmp(f->scratch, f->confirm[i], 32));
    }
    CHECK(!memcmp(f->key[0], f->key[1], 16));
    if (known) CHECK(hex(f->key[0], "ea3276d68334576097e04b19ee5a3a8b"));
    return true;
}
static bool functional(Fixture* f) {
    static const uint8_t context[] = "SPAKE2+-P256-SHA256-HKDF draft-01";
    decode(f->w0, "e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c");
    decode(f->w1, "24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512");
    CHECK(f->port[0].p256_base(f->port[0].user, f->w1, 32, f->L) == MATTER_OK);
    CHECK(pair(f, true, context, sizeof(context)-1) && exchange(f, true));
    CHECK(matter_spake2p_context(&f->port[0], NULL, 0, NULL, 0, f->context) == MATTER_OK);
    CHECK(hex(f->context, "988c4f8a98f0ff44d7dcdcaac3daa4c894d305c07ef6ab4067f10b73fdd1b21a"));
    static const uint8_t request[] = {0x15,0x18}, response[] = {0x15,0x24,0,1,0x18};
    CHECK(matter_spake2p_context(&f->port[0], request, sizeof(request), response, sizeof(response), f->context) == MATTER_OK);
    CHECK(hex(f->context, "a6df4604685f0186d5c814dc0820ee9ee1e75598c4e162a2dc9d741b0b242a8f"));
    LARGE_INTEGER frequency, start, end;
    CHECK(QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0 && QueryPerformanceCounter(&start));
    CHECK(pair(f, false, f->context, 32) && exchange(f, false));
    CHECK(QueryPerformanceCounter(&end));
    printf("SPAKE2+ x86: random two-party exchange %.3f ms (without PBKDF2/network)\n",
        1000.0 * (end.QuadPart - start.QuadPart) / frequency.QuadPart);
    memcpy(f->saved, f->share[0], 65);
    CHECK(pair(f, false, f->context, 32) && exchange(f, false));
    CHECK(memcmp(f->saved, f->share[0], 65)); /* Fresh scalar, smoke check. */
    /* Actual PIN -> PBKDF2 -> verifier -> exchange. */
    static const uint8_t pin[] = {0xf1,0xc1,0x20,0x01};
    memset(f->scratch, 0x42, 16);
    CHECK(f->port[0].pbkdf2_sha256(f->port[0].user, pin, 4, f->scratch, 16, 1000, f->wide, 80) == MATTER_OK);
    CHECK(f->port[0].p256_reduce(f->port[0].user, f->wide, 40, f->w0) == MATTER_OK);
    CHECK(f->port[0].p256_reduce(f->port[0].user, f->wide + 40, 40, f->w1) == MATTER_OK);
    CHECK(f->port[0].p256_base(f->port[0].user, f->w1, 32, f->L) == MATTER_OK);
    f->port[0].clear(f->wide, 80);
    CHECK(pair(f, false, f->context, 32) && exchange(f, false));
    return true;
}
static bool negative(Fixture* f) {
    for (unsigned mode = 0; mode < 5; ++mode) {
        CHECK(pair(f, true, f->context, 32));
        CHECK(matter_spake2p_start(f->s[0], f->share[0]) == MATTER_OK);
        CHECK(matter_spake2p_start(f->s[1], f->share[1]) == MATTER_OK);
        if (mode < 3) {
            if (mode == 0) f->share[1][0] = 0; /* infinity */
            if (mode == 1) f->share[1][0] = 2; /* compressed form rejected */
            if (mode == 2) memset(f->share[1] + 1, 0xff, 64); /* out of field/off curve */
            CHECK(matter_spake2p_derive(f->s[0], f->share[1], 65) == MATTER_PORT_ERROR);
        } else {
            CHECK(matter_spake2p_derive(f->s[0], f->share[1], 65) == MATTER_OK);
            CHECK(matter_spake2p_derive(f->s[1], f->share[0], 65) == MATTER_OK);
            CHECK(matter_spake2p_confirmation(f->s[1], f->confirm[1]) == MATTER_OK);
            f->confirm[1][mode == 3 ? 0 : 31] ^= 1;
            CHECK(matter_spake2p_verify(f->s[0], f->confirm[1], 32) == MATTER_PORT_ERROR);
        }
        memset(f->scratch, 0xa5, 65);
        CHECK(matter_spake2p_key(f->s[0], f->scratch) == MATTER_INVALID_STATE && filled(f->scratch, 65, 0xa5));
        CHECK(matter_spake2p_start(f->s[0], f->scratch) == MATTER_INVALID_STATE);
        CHECK(matter_spake2p_confirmation(f->s[0], f->scratch) == MATTER_INVALID_STATE);
    }
    /* w0=0 is legal; unmasking a point to infinity is not. */
    memset(f->w0, 0, 32);
    CHECK(pair(f, true, f->context, 32) && exchange(f, false));
    f->w0[31] = 1;
    CHECK(pair(f, true, f->context, 32));
    CHECK(matter_spake2p_start(f->s[0], f->share[0]) == MATTER_OK);
    CHECK(matter_spake2p_derive(f->s[0], matter_spake2p_N, 65) == MATTER_PORT_ERROR);
    return true;
}
static bool mismatches(Fixture* f) {
    for (unsigned mode = 0; mode < 3; ++mode) {
        CHECK(pair(f, true, f->context, 32));
        REQUIRE(matter_spake2p_delete(f->s[0]) == MATTER_OK); f->s[0] = NULL;
        if (mode == 0) f->context[0] ^= 1;
        if (mode == 1) f->w0[31] ^= 2;
        if (mode == 2) f->w1[31] ^= 1;
        f->s[0] = matter_spake2p_new(&f->port[0], false, f->w0, f->w1, 32, f->context, 32);
        CHECK(f->s[0]); watch(f->s[0]);
        if (mode == 0) f->context[0] ^= 1;
        if (mode == 1) f->w0[31] ^= 2;
        if (mode == 2) f->w1[31] ^= 1;
        for (unsigned i = 0; i < 2; ++i) CHECK(matter_spake2p_start(f->s[i], f->share[i]) == MATTER_OK);
        for (unsigned i = 0; i < 2; ++i) CHECK(matter_spake2p_derive(f->s[i], f->share[1-i], 65) == MATTER_OK);
        CHECK(matter_spake2p_confirmation(f->s[1], f->confirm[1]) == MATTER_OK);
        CHECK(matter_spake2p_verify(f->s[0], f->confirm[1], 32) == MATTER_PORT_ERROR);
        CHECK(matter_spake2p_key(f->s[0], f->key[0]) == MATTER_INVALID_STATE);
    }
    memset(f->scratch, 0xa5, sizeof(f->scratch));
    CHECK(matter_spake2p_context(&f->port[0], NULL, 1, NULL, 0, f->scratch) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_spake2p_context(&f->port[0], f->scratch, 1025, NULL, 0, f->saved) == MATTER_LIMIT_REACHED);
    CHECK(filled(f->scratch, sizeof(f->scratch), 0xa5));
    CHECK(!matter_spake2p_new(&f->port[0], false, f->w0, f->w1, 31, f->context, 32));
    CHECK(!matter_spake2p_new(&f->port[0], false, f->w0, f->w1, 32, f->context, 65));
    CHECK(matter_spake2p_delete(NULL) == MATTER_OK);
    return true;
}
/* Port faults isolate each logical step, including the second HMAC, without
 * depending on the allocation sequence inside mbedTLS. Test-only globals. */
static Matter_Crypto_Port_T forward;
static Matter_Spake2p_T reenter;
static unsigned phase, hmac_calls;
static Matter_Result_T faulty_scalar(void* user, uint8_t* out) {
    REQUIRE(matter_spake2p_delete(reenter) == MATTER_BUSY);
    REQUIRE(matter_spake2p_start(reenter, out) == MATTER_BUSY);
    if (phase == 0) { out[0] = 0x55; return MATTER_PORT_ERROR; }
    return forward.p256_scalar(user, out);
}
static Matter_Result_T faulty_share(void* u, bool b, const uint8_t* x, const uint8_t* w, uint8_t* out) {
    if (phase == 1) { out[0] = 0x55; return MATTER_PORT_ERROR; }
    return forward.spake_share(u,b,x,w,out);
}
static Matter_Result_T faulty_secrets(void* u, bool b, const uint8_t* x, const uint8_t* w,
    const uint8_t* cred, const uint8_t* peer, uint8_t* out) {
    if (phase == 2) { out[0] = 0x55; return MATTER_PORT_ERROR; }
    return forward.spake_secrets(u,b,x,w,cred,peer,out);
}
static Matter_Result_T faulty_hash(void* u, const uint8_t* in, size_t n, uint8_t* out) {
    if (phase == 3) { out[0] = 0x55; return MATTER_PORT_ERROR; }
    return forward.sha256(u,in,n,out);
}
static Matter_Result_T faulty_hkdf(void* u, const uint8_t* k, size_t kn, const uint8_t* salt, size_t sn,
    const uint8_t* info, size_t n, uint8_t* out, size_t on) {
    if (phase == 4) { out[0] = 0x55; return MATTER_PORT_ERROR; }
    return forward.hkdf_sha256(u,k,kn,salt,sn,info,n,out,on);
}
static Matter_Result_T faulty_hmac(void* u, const uint8_t* k, size_t kn, const uint8_t* in, size_t n, uint8_t* out) {
    if ((phase == 5 && ++hmac_calls == 1) || (phase == 6 && ++hmac_calls == 2)) {
        out[0] = 0x55; return MATTER_PORT_ERROR;
    }
    return forward.hmac_sha256(u,k,kn,in,n,out);
}
static bool port_failures(Fixture* f) {
    for (phase = 0; phase < 7; ++phase) {
        CHECK(pair(f, true, f->context, 32));
        forward = f->port[0];
        Matter_Crypto_Port_T p = forward;
        p.p256_scalar = faulty_scalar; p.spake_share = faulty_share; p.spake_secrets = faulty_secrets;
        p.sha256 = faulty_hash; p.hkdf_sha256 = faulty_hkdf; p.hmac_sha256 = faulty_hmac;
        REQUIRE(matter_spake2p_delete(f->s[0]) == MATTER_OK);
        f->s[0] = matter_spake2p_new(&p, false, f->w0, f->w1, 32, f->context, 32);
        CHECK(f->s[0]); watch(f->s[0]); reenter = f->s[0]; hmac_calls = 0;
        memset(f->share[0], 0xa5, 65);
        if (phase < 2) {
            CHECK(matter_spake2p_start(f->s[0], f->share[0]) == MATTER_PORT_ERROR && filled(f->share[0], 65, 0));
        } else {
            CHECK(matter_spake2p_start(f->s[0], f->share[0]) == MATTER_OK);
            CHECK(matter_spake2p_start(f->s[1], f->share[1]) == MATTER_OK);
            CHECK(matter_spake2p_derive(f->s[0], f->share[1], 65) == MATTER_PORT_ERROR);
        }
        CHECK(matter_spake2p_key(f->s[0], f->scratch) == MATTER_INVALID_STATE);
        CHECK(matter_spake2p_confirmation(f->s[0], f->scratch) == MATTER_INVALID_STATE);
        CHECK(matter_spake2p_start(f->s[0], f->scratch) == MATTER_INVALID_STATE);
    }
    reenter = NULL;
    return true;
}
static Matter_Result_T entropy_fault(void* user, uint8_t* out, size_t size) {
    for (size_t i = 0; i < size; ++i) out[i] = (uint8_t)(i + 19); /* Test only. */
    return *(bool*)user ? MATTER_PORT_ERROR : MATTER_OK;
}
static bool rng_and_partial_output(Fixture* f) {
    Matter_Crypto_Entropy_Port_T source = {&f->entropy_failed, entropy_fault};
    f->extra = matter_crypto_mbedtls_new(&source);
    CHECK(f->extra && matter_crypto_mbedtls_port(f->extra, &f->extra_port) == MATTER_OK);
    Matter_Crypto_Port_T* p = &f->extra_port;
    decode(f->wide, x_hex);
    for (unsigned mode = 0; mode < 3; ++mode) {
        f->entropy_failed = false;
        CHECK(matter_crypto_mbedtls_reseed(f->extra) == MATTER_OK);
        for (unsigned i = 0; i < 10000; ++i) CHECK(p->random(p->user, f->scratch, 1) == MATTER_OK);
        f->entropy_failed = true; memset(f->scratch, 0xa5, 131);
        Matter_Result_T r = mode == 0 ? p->p256_scalar(p->user, f->scratch) : mode == 1 ?
            p->spake_share(p->user, false, f->wide, f->w0, f->scratch) :
            p->spake_secrets(p->user, false, f->wide, f->w0, f->w1, f->share[1], f->scratch);
        size_t size = mode == 0 ? 32 : mode == 1 ? 65 : 130;
        CHECK(r == MATTER_PORT_ERROR && filled(f->scratch, size, 0) && f->scratch[size] == 0xa5);
        memset(f->scratch, 0xa5, 131);
        CHECK(p->p256_scalar(p->user, f->scratch) == MATTER_OFFLINE && filled(f->scratch, 131, 0xa5));
    }
    f->entropy_failed = false;
    CHECK(matter_crypto_mbedtls_reseed(f->extra) == MATTER_OK);
    CHECK(p->p256_scalar(p->user, f->scratch) == MATTER_OK);
    /* Invalid responder L is checked after Z was calculated: erase both Z/V. */
    memset(f->saved, 0, 65); memset(f->scratch, 0xa5, 131);
    CHECK(p->spake_secrets(p->user, true, f->wide, f->w0, f->saved, f->share[0], f->scratch) == MATTER_PORT_ERROR);
    CHECK(filled(f->scratch, 130, 0) && f->scratch[130] == 0xa5);
    /* Canonical scalars are mandatory, never implicitly reduced. */
    memset(f->saved, 0xff, 32);
    CHECK(p->spake_share(p->user, false, f->wide, f->saved, f->scratch) == MATTER_PORT_ERROR);
    memset(f->saved, 0, 32);
    CHECK(p->spake_share(p->user, false, f->saved, f->w0, f->scratch) == MATTER_PORT_ERROR);
    CHECK(matter_crypto_mbedtls_delete(f->extra) == MATTER_OK); f->extra = NULL;
    return true;
}
#ifdef MATTER_TEST_ALLOC
static Matter_Result_T operation(Fixture* f, unsigned mode, uint8_t* out) {
    Matter_Crypto_Port_T* p = &f->extra_port;
    bool responder = mode == 2 || mode == 4;
    const uint8_t* secret = f->wide + (responder ? 32 : 0);
    if (!mode) return p->p256_scalar(p->user, out);
    if (mode < 3) return p->spake_share(p->user, responder, secret, f->w0, out);
    return p->spake_secrets(p->user, responder, secret, f->w0, responder ? f->L : f->w1, f->share[responder ? 0 : 1], out);
}
static bool allocation_failures(Fixture* f) {
    close_pair(f);
    CHECK(matter_crypto_mbedtls_port(f->crypto[0], &f->port[0]) == MATTER_OK);
    fail_at = calls + 1;
    CHECK(!matter_spake2p_new(&f->port[0], false, f->w0, f->w1, 32, f->context, 32)); fail_at = 0;
    memset(f->scratch, 0xa5, 33); fail_at = calls + 1;
    CHECK(matter_spake2p_context(&f->port[0], NULL, 0, NULL, 0, f->scratch) == MATTER_PORT_ERROR);
    CHECK(filled(f->scratch, 32, 0) && f->scratch[32] == 0xa5); fail_at = 0;
    decode(f->wide, x_hex); decode(f->wide + 32, y_hex);
    Matter_Crypto_Entropy_Port_T source = {&f->entropy_failed, entropy_fault};
    f->extra = matter_crypto_mbedtls_new(&source);
    CHECK(f->extra && matter_crypto_mbedtls_port(f->extra, &f->extra_port) == MATTER_OK);
    /* Nontrivial w0 exercises arbitrary-point precomputation and cleanup. */
    decode(f->w0, "e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c");
    CHECK(operation(f, 1, f->share[0]) == MATTER_OK && operation(f, 2, f->share[1]) == MATTER_OK);
    size_t baseline = live;
    for (unsigned mode = 0; mode < 5; ++mode) {
        CHECK(matter_crypto_mbedtls_delete(f->extra) == MATTER_OK);
        f->extra = matter_crypto_mbedtls_new(&source);
        CHECK(f->extra && matter_crypto_mbedtls_port(f->extra, &f->extra_port) == MATTER_OK);
        size_t before = calls, size = mode == 0 ? 32 : mode < 3 ? 65 : 130;
        CHECK(operation(f, mode, f->expected) == MATTER_OK);
        size_t count = calls - before;
        CHECK(count && live == baseline);
        for (size_t n = 1; n <= count; ++n) {
            /* Fresh deterministic test DRBG makes the allocation trace stable:
             * random blinding can otherwise alter intermediate MPI sizes. */
            CHECK(matter_crypto_mbedtls_delete(f->extra) == MATTER_OK);
            f->extra = matter_crypto_mbedtls_new(&source);
            CHECK(f->extra && matter_crypto_mbedtls_port(f->extra, &f->extra_port) == MATTER_OK);
            memset(f->scratch, 0xa5, size + 1); fail_at = calls + n;
            Matter_Result_T r = operation(f, mode, f->scratch);
            if (r != MATTER_PORT_ERROR) fprintf(stderr, "OOM mode=%u n=%zu count=%zu result=%d\n", mode, n, count, r);
            CHECK(r == MATTER_PORT_ERROR);
            fail_at = 0;
            CHECK(live == baseline && filled(f->scratch, size, 0) && f->scratch[size] == 0xa5);
        }
        CHECK(operation(f, mode, f->scratch) == MATTER_OK && live == baseline);
        if (mode) CHECK(!memcmp(f->scratch, f->expected, size));
        printf("SPAKE2+ operation %u: all %zu allocation failures + recovery checked\n", mode, count);
        fflush(stdout);
    }
    CHECK(matter_crypto_mbedtls_delete(f->extra) == MATTER_OK); f->extra = NULL;
    return true;
}
#endif
int main(void) {
    Fixture* f = calloc(1, sizeof(*f)); REQUIRE(f);
    for (unsigned i = 0; i < 2; ++i) {
        f->crypto[i] = matter_crypto_mbedtls_new(NULL); REQUIRE(f->crypto[i]);
        REQUIRE(matter_crypto_mbedtls_port(f->crypto[i], &f->port[i]) == MATTER_OK);
    }
    bool ok = functional(f) && negative(f) && mismatches(f) && port_failures(f) && rng_and_partial_output(f);
#ifdef MATTER_TEST_ALLOC
    if (ok) ok = allocation_failures(f);
    fail_at = 0;
#endif
    close_pair(f);
    REQUIRE(matter_crypto_mbedtls_delete(f->extra) == MATTER_OK);
    for (unsigned i = 0; i < 2; ++i) REQUIRE(matter_crypto_mbedtls_delete(f->crypto[i]) == MATTER_OK);
    free(f);
#ifdef MATTER_TEST_ALLOC
    REQUIRE(live == 0 && wiped > 0);
    printf("SPAKE2+: %zu session contexts zeroized before free\n", wiped);
#endif
    if (ok) puts("PASS SPAKE2+: independent vector, random pairs, PIN pipeline, confirmation order, invalid points/tags");
    return ok ? 0 : 1;
}
