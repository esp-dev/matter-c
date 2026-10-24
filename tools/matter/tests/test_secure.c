#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/matter_crypto_mbedtls.h"
#include "session/matter_secure.h"
#define REQUIRE(c) do { if (!(c)) { fprintf(stderr, "secure:%d: %s\n", __LINE__, #c); abort(); } } while (0)
static bool zero(const void* data, size_t n) {
    const uint8_t* p = data; for (size_t i = 0; i < n; ++i) if (p[i]) return false; return true;
}
#ifdef MATTER_TEST_ALLOC
static size_t calls, live, fail_at;
static struct { void* p; size_t n; } blocks[32];
void* matter_test_calloc(size_t n, size_t z) {
    if (++calls == fail_at) return NULL;
    void* p = calloc(n, z);
    if (p) {
        size_t i=0; while (i<32 && blocks[i].p) ++i;
        REQUIRE(i<32); blocks[i].p=p; blocks[i].n=n*z; ++live;
    }
    return p;
}
void matter_test_free(void* p) {
    if (p) {
        size_t i=0; while (i<32 && blocks[i].p!=p) ++i;
        REQUIRE(i<32 && live && zero(p,blocks[i].n)); blocks[i].p=NULL; --live;
    }
    free(p);
}
#define calloc matter_test_calloc
#define free matter_test_free
#endif
/* White-box only to fast-forward UINT32_MAX and inspect erasure/atomicity.
 * No production counter mutation API. Normal network tests link the C object. */
#include "../../../main/apps/matter/session/matter_secure.c"
#ifdef MATTER_TEST_ALLOC
#undef calloc
#undef free
#endif

typedef struct { Matter_Pase_Keys_T keys; bool taken, ready; } Handoff;
/* Isolate session unit tests from handshake arithmetic. Real PASE activation is
 * exercised separately in test_pase.c, including one-shot transfer. */
Matter_Result_T matter_pase_take_keys(Matter_Pase_T p, Matter_Pase_Keys_T* out) {
    Handoff* h = (Handoff*)p;
    if (!h->ready || h->taken) return MATTER_INVALID_STATE;
    *out=h->keys; h->taken=true; return MATTER_OK;
}
static Matter_Result_T test_random(void* u, uint8_t* p, size_t n) {
    (void)u; REQUIRE(n==4); p[0]=3; p[1]=3; p[2]=2; p[3]=1; return MATTER_OK;
}
static Matter_Result_T bad_random(void* u, uint8_t* p, size_t n) {
    (void)u; memset(p,0xaa,n); return MATTER_PORT_ERROR;
}
typedef struct {
    Matter_Crypto_Mbedtls_T backend;
    Matter_Crypto_Port_T port;
    Handoff handoff[2];
    Matter_Secure_T a,b;
    uint8_t packet[3][MATTER_SECURE_MAX_PACKET], plain[MATTER_SECURE_MAX_PACKET], cipher[MATTER_SECURE_MAX_PACKET+16];
    uint8_t key[16], iv[13], result[MATTER_SECURE_MAX_PACKET], challenge[16];
    size_t size[3];
    unsigned admitted, duplicates;
    Matter_Result_T admission;
    Matter_Secure_Info_T info;
} Fixture;
static Matter_Result_T admit(void* u, const Matter_Secure_Received_T* m) {
    Fixture* f=u;
    REQUIRE(matter_secure_close(f->b)==MATTER_BUSY);
    REQUIRE(matter_secure_delete(f->b)==MATTER_BUSY);
    REQUIRE(matter_secure_retain(f->b)==MATTER_OK);
    REQUIRE(matter_secure_info(f->b,&f->info)==MATTER_OK && f->info.pins==1);
    REQUIRE(matter_secure_release(f->b)==MATTER_OK);
    REQUIRE(matter_secure_close(f->b)==MATTER_BUSY); /* release must preserve the guard. */
    REQUIRE(matter_secure_receive(f->b,NULL,0,0,admit,f)==MATTER_BUSY);
    if (f->admission!=MATTER_OK) return f->admission;
    if (m->duplicate) { REQUIRE(!m->payload && !m->size); ++f->duplicates; }
    else { REQUIRE(m->size==3 && !memcmp(m->payload,"\xa1\xb2\xc3",3)); ++f->admitted; }
    return MATTER_OK;
}
static void check_erased(Fixture* f) {
    /* Allocation tracker verifies plaintext erasure before every free. No
     * plaintext storage remains attached to an idle secure session. */
    REQUIRE(zero(&f->b->received,sizeof(f->b->received)));
}
static void seal_packet(Fixture* f, unsigned slot, uint64_t now) {
    static const uint8_t payload[]={5,1,0x34,0x12,4,0,0xa1,0xb2,0xc3};
    REQUIRE(matter_secure_seal(f->a,payload,sizeof(payload),now,f->packet[slot],sizeof(f->packet[slot]),&f->size[slot])==MATTER_OK);
}
static void primitive(Fixture* f) {
    Matter_Crypto_Port_T* p=&f->port;
    static const uint8_t aad[]={0,0xc8,1,0,4,3,2,1};
    static const uint8_t plain[]={5,1,0x34,0x12,4,0,0xa1,0xb2,0xc3};
    static const uint8_t expected[]={0xce,0x91,0x4a,0x0f,0xa9,0xa4,0x70,0xa7,0x08,0x3d,0xff,0xed,0x82,0x6a,0x8d,0xc3,0,0xd2,0xdd,0x42,0xe1,0x2f,0xb4,0x3b,0xdc};
    f->iv[1]=4; f->iv[2]=3; f->iv[3]=2; f->iv[4]=1;
    for (unsigned i=0;i<16;++i) f->key[i]=(uint8_t)i;
    REQUIRE(p->ccm_encrypt(p->user,f->key,f->iv,aad,8,plain,9,f->cipher)==MATTER_OK && !memcmp(f->cipher,expected,25));
    REQUIRE(p->ccm_decrypt(p->user,f->key,f->iv,aad,8,f->cipher,9,f->result)==MATTER_OK && !memcmp(f->result,plain,9));
    f->cipher[24]^=1;
    REQUIRE(p->ccm_decrypt(p->user,f->key,f->iv,aad,8,f->cipher,9,f->result)==MATTER_PORT_ERROR && zero(f->result,9));
    REQUIRE(p->ccm_encrypt(p->user,f->key,f->iv,NULL,0,NULL,0,f->cipher)==MATTER_OK);
    REQUIRE(p->ccm_decrypt(p->user,f->key,f->iv,NULL,0,f->cipher,0,NULL)==MATTER_OK);
    memset(f->result,0xa5,sizeof(f->result));
    REQUIRE(p->ccm_encrypt(p->user,NULL,f->iv,NULL,0,NULL,0,f->result)==MATTER_INVALID_ARGUMENT && f->result[0]==0xa5);
    REQUIRE(p->ccm_decrypt(p->user,f->key,f->iv,NULL,0,f->cipher,MATTER_CRYPTO_MAX_CCM+1,f->result)==MATTER_LIMIT_REACHED && f->result[0]==0xa5);
    REQUIRE(p->ccm_encrypt(p->user,f->key,f->iv,NULL,0,f->plain,MATTER_CRYPTO_MAX_CCM,f->cipher)==MATTER_OK);
    REQUIRE(p->ccm_decrypt(p->user,f->key,f->iv,NULL,0,f->cipher,MATTER_CRYPTO_MAX_CCM,f->result)==MATTER_OK && zero(f->result,sizeof(f->result)));
#ifdef MATTER_TEST_ALLOC
    size_t before=calls;
    REQUIRE(p->ccm_encrypt(p->user,f->key,f->iv,aad,8,plain,9,f->cipher)==MATTER_OK);
    size_t count=calls-before, baseline=live; REQUIRE(count>=1);
    for (unsigned decrypt=0;decrypt<2;++decrypt) for (size_t i=1;i<=count;++i) {
        memcpy(f->cipher,expected,25); memset(f->result,0xa5,25); fail_at=calls+i;
        Matter_Result_T r=decrypt ? p->ccm_decrypt(p->user,f->key,f->iv,aad,8,f->cipher,9,f->result) :
            p->ccm_encrypt(p->user,f->key,f->iv,aad,8,plain,9,f->result);
        fail_at=0; REQUIRE(r==MATTER_PORT_ERROR && live==baseline && zero(f->result,decrypt?9:25));
    }
#endif
}
static void sessions(Fixture* f) {
    for (unsigned i=0;i<2;++i) {
        f->handoff[i].ready=true;
        f->handoff[i].keys.local_session_id=i?456:123;
        f->handoff[i].keys.peer_session_id=i?123:456;
        for (unsigned j=0;j<16;++j) {
            f->handoff[i].keys.send_key[j]=(uint8_t)(j+(i?16:0));
            f->handoff[i].keys.receive_key[j]=(uint8_t)(j+(i?0:16));
            f->handoff[i].keys.attestation_challenge[j]=(uint8_t)j;
        }
    }
    f->port.random=bad_random;
    REQUIRE(!matter_secure_new(&f->port,(Matter_Pase_T)&f->handoff[0],0) && !f->handoff[0].taken);
    f->port.random=test_random;
#ifdef MATTER_TEST_ALLOC
    fail_at=calls+1; REQUIRE(!matter_secure_new(&f->port,(Matter_Pase_T)&f->handoff[0],0)); fail_at=0;
    REQUIRE(!f->handoff[0].taken);
#endif
    f->a=matter_secure_new(&f->port,(Matter_Pase_T)&f->handoff[0],0);
    f->b=matter_secure_new(&f->port,(Matter_Pase_T)&f->handoff[1],0); REQUIRE(f->a && f->b);
    REQUIRE(!matter_secure_new(&f->port,(Matter_Pase_T)&f->handoff[0],0));
    REQUIRE(matter_secure_challenge(f->a,f->challenge)==MATTER_OK && !memcmp(f->challenge,f->key,16));
    seal_packet(f,0,1);
    static const uint8_t prefix[]={0,0xc8,1,0,4,3,2,1,0xce,0x91,0x4a,0x0f,0xa9,0xa4,0x70,0xa7,8};
    REQUIRE(f->size[0]==33 && !memcmp(f->packet[0],prefix,sizeof(prefix)));
    Matter_Reception_T before=f->b->rx;
#ifdef MATTER_TEST_ALLOC
    size_t rx_live=live; unsigned admitted=f->admitted;
    fail_at=calls+1;
    REQUIRE(matter_secure_receive(f->b,f->packet[0],f->size[0],2,admit,f)==MATTER_LIMIT_REACHED);
    fail_at=0;
    REQUIRE(live==rx_live && f->admitted==admitted && !memcmp(&before,&f->b->rx,sizeof(before)));
    REQUIRE(matter_secure_info(f->b,&f->info)==MATTER_OK && f->info.last_received_ms==0);
    check_erased(f);
#endif
    for (size_t n=0;n<f->size[0];++n) {
        REQUIRE(matter_secure_receive(f->b,f->packet[0],n,2,admit,f)!=MATTER_OK);
        REQUIRE(!memcmp(&before,&f->b->rx,sizeof(before)) && !f->admitted);
    }
    /* Corrupt every header/cipher/MIC byte: no callback, no replay mutation. */
    for (size_t i=0;i<f->size[0];++i) {
        f->packet[0][i]^=1;
        REQUIRE(matter_secure_receive(f->b,f->packet[0],f->size[0],2,admit,f)!=MATTER_OK);
        REQUIRE(!f->admitted && !f->duplicates && !memcmp(&before,&f->b->rx,sizeof(before)));
        f->packet[0][i]^=1; check_erased(f);
    }
    f->b->keys.receive_key[0]^=1;
    REQUIRE(matter_secure_receive(f->b,f->packet[0],f->size[0],2,admit,f)==MATTER_PORT_ERROR);
    f->b->keys.receive_key[0]^=1; REQUIRE(!memcmp(&before,&f->b->rx,sizeof(before)));
    f->admission=MATTER_WOULD_BLOCK;
    REQUIRE(matter_secure_receive(f->b,f->packet[0],f->size[0],2,admit,f)==MATTER_WOULD_BLOCK && !memcmp(&before,&f->b->rx,sizeof(before)));
    f->admission=MATTER_OK;
    REQUIRE(matter_secure_receive(f->b,f->packet[0],f->size[0],2,admit,f)==MATTER_OK && f->admitted==1); check_erased(f);
    REQUIRE(matter_secure_receive(f->b,f->packet[0],f->size[0],3,admit,f)==MATTER_OK && f->admitted==1 && f->duplicates==1);
    seal_packet(f,1,3); seal_packet(f,2,4);
    REQUIRE(matter_secure_receive(f->b,f->packet[2],f->size[2],4,admit,f)==MATTER_OK);
    REQUIRE(matter_secure_receive(f->b,f->packet[1],f->size[1],4,admit,f)==MATTER_OK && f->admitted==3); /* Out of order. */
    REQUIRE(matter_secure_receive(f->b,f->packet[1],f->size[1],4,admit,f)==MATTER_OK && f->duplicates==2);
    REQUIRE(matter_secure_receive(f->b,f->packet[1],f->size[1],3,admit,f)==MATTER_INVALID_ARGUMENT);
    /* RX must authenticate ORIGINAL reserved bits, optional IDs and MX. PASE
     * nonce still has zero Node ID. A writer would discard these reserved bits. */
    memset(f->packet[2],0,26);
    f->packet[2][0]=0x0d; f->packet[2][1]=0xc8; f->packet[2][2]=1;
    f->packet[2][3]=0x30; f->packet[2][4]=1; f->packet[2][7]=0x80;
    memset(f->packet[2]+8,0x33,16); /* source/destination, then zero MX length */
    memset(f->iv,0,13); f->iv[0]=0x30; f->iv[1]=1; f->iv[4]=0x80;
    static const uint8_t extra_plain[]={5,1,0x34,0x12,4,0,0xa1,0xb2,0xc3};
    REQUIRE(f->port.ccm_encrypt(f->port.user,f->key,f->iv,f->packet[2],26,extra_plain,9,f->packet[2]+26)==MATTER_OK);
    f->packet[2][8]^=1;
    REQUIRE(matter_secure_receive(f->b,f->packet[2],51,4,admit,f)==MATTER_PORT_ERROR);
    f->packet[2][8]^=1;
    REQUIRE(matter_secure_receive(f->b,f->packet[2],51,4,admit,f)==MATTER_OK && f->admitted==4);
    before=f->b->rx;
    f->packet[2][4]=2; f->iv[1]=2; f->plain[0]=MATTER_PROTOCOL_EXTENSIONS;
    REQUIRE(f->port.ccm_encrypt(f->port.user,f->key,f->iv,f->packet[2],26,f->plain,6,f->packet[2]+26)==MATTER_OK);
    REQUIRE(matter_secure_receive(f->b,f->packet[2],48,4,admit,f)==MATTER_INVALID_ARGUMENT && !memcmp(&before,&f->b->rx,sizeof(before)));
    check_erased(f);
    uint32_t next=f->a->tx.next; size_t n=99;
    REQUIRE(matter_secure_seal(f->a,f->plain,5,4,f->packet[1],1232,&n)==MATTER_INVALID_ARGUMENT && f->a->tx.next==next && n==99);
    REQUIRE(matter_secure_seal(f->a,f->plain,1209,4,f->packet[1],1232,&n)==MATTER_LIMIT_REACHED && f->a->tx.next==next);
#ifdef MATTER_TEST_ALLOC
    static const uint8_t payload[]={5,1,0x34,0x12,4,0,0xa1,0xb2,0xc3};
    fail_at=calls+1;
    REQUIRE(matter_secure_seal(f->a,payload,9,4,f->packet[1],1232,&n)==MATTER_PORT_ERROR);
    fail_at=0; REQUIRE(f->a->tx.next==next+1 && n==99 && zero(f->packet[1],33));
    before=f->b->rx; fail_at=calls+2; /* Plaintext succeeds; crypto workspace fails. */
    REQUIRE(matter_secure_receive(f->b,f->packet[0],f->size[0],4,admit,f)==MATTER_PORT_ERROR);
    fail_at=0; REQUIRE(!memcmp(&before,&f->b->rx,sizeof(before))); check_erased(f);
#endif
    f->a->tx.next=UINT32_MAX; /* Simulate prior consumption, never production reset. */
    REQUIRE(matter_secure_retain(f->a)==MATTER_OK); seal_packet(f,1,5);
    REQUIRE(matter_secure_info(f->a,&f->info)==MATTER_OK && f->info.exhausted && f->info.last_sent_ms==5);
    REQUIRE(matter_secure_receive(f->b,f->packet[1],f->size[1],5,admit,f)==MATTER_OK && f->admitted==5);
    REQUIRE(matter_secure_receive(f->b,f->packet[0],f->size[0],5,admit,f)==MATTER_OK && f->duplicates==3); /* Old outside window. */
    REQUIRE(matter_secure_seal(f->a,f->packet[0],9,5,f->packet[2],1232,&n)==MATTER_LIMIT_REACHED);
    REQUIRE(matter_secure_close(f->a)==MATTER_OK && matter_secure_delete(f->a)==MATTER_INVALID_STATE);
    REQUIRE(!zero(f->a->keys.send_key,16));
    REQUIRE(matter_secure_receive(f->b,f->packet[1],f->size[1],6,admit,f)==MATTER_OK && f->duplicates==4);
    REQUIRE(matter_secure_release(f->a)==MATTER_OK && zero(&f->a->keys,sizeof(f->a->keys)));
    REQUIRE(matter_secure_retain(f->a)==MATTER_INVALID_STATE && matter_secure_delete(f->a)==MATTER_OK); f->a=NULL;
    REQUIRE(matter_secure_release(f->b)==MATTER_INVALID_STATE && matter_secure_delete(f->b)==MATTER_INVALID_STATE);
    REQUIRE(matter_secure_close(f->b)==MATTER_OK && matter_secure_delete(f->b)==MATTER_OK); f->b=NULL;
}
int main(void) {
    Fixture* f=calloc(1,sizeof(*f)); REQUIRE(f);
    f->backend=matter_crypto_mbedtls_new(NULL); REQUIRE(f->backend);
    REQUIRE(matter_crypto_mbedtls_port(f->backend,&f->port)==MATTER_OK);
    primitive(f); sessions(f);
    REQUIRE(matter_crypto_mbedtls_delete(f->backend)==MATTER_OK);
    memset(f,0,sizeof(*f)); free(f);
#ifdef MATTER_TEST_ALLOC
    REQUIRE(!live);
#endif
    puts("PASS secure: OpenSSL CCM vector, tamper/auth, replay/reorder, admission, exhaustion, drain, OOM/zeroize");
    return 0;
}
