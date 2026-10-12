#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/matter_crypto_mbedtls.h"
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"Credentials:%d: %s\n",__LINE__,#c); abort(); } } while(0)
#ifdef MATTER_TEST_ALLOC
static size_t live, calls, fail_at;
void* matter_test_calloc(size_t n,size_t z) { ++calls; if(calls==fail_at) return NULL; void* p=calloc(n,z); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { CHECK(live); --live; } free(p); }
#endif
#include "test_credentials_vectors.h"
#define DER(a) (Matter_Der_T){a,sizeof(a)}
typedef struct {
    Matter_Crypto_Mbedtls_T context;
    Matter_Crypto_Port_T crypto;
    Matter_Credentials_Port_T credentials;
    uint8_t key[32], signature[65], shared[33], public_key[66], csr[513], bad[2049];
    size_t csr_size;
    bool rng_failure, reenter;
    unsigned entropy_calls;
} Fixture;
static bool filled(const uint8_t* p,size_t n,uint8_t v) { for(size_t i=0;i<n;++i) if(p[i]!=v) return false; return true; }
static Matter_Result_T entropy(void* u,uint8_t* out,size_t size) {
    Fixture* f=u; CHECK(size==48); ++f->entropy_calls;
    if(f->reenter) {
        CHECK(f->crypto.ecdsa_sign(f->crypto.user,NULL,NULL,0,NULL)==MATTER_BUSY);
        CHECK(f->crypto.ecdh(f->crypto.user,NULL,NULL,NULL)==MATTER_BUSY);
        CHECK(f->credentials.csr_create(f->credentials.user,NULL,NULL,0,NULL)==MATTER_BUSY);
        CHECK(f->credentials.cert_verify_chain(f->credentials.user,(Matter_Der_T){0},(Matter_Der_T){0},(Matter_Der_T){0},NULL,NULL)==MATTER_BUSY);
        CHECK(matter_crypto_mbedtls_delete(f->context)==MATTER_BUSY);
    }
    for(size_t i=0;i<size;++i) out[i]=(uint8_t)(i+f->entropy_calls); /* Test-only source. */
    return f->rng_failure ? MATTER_PORT_ERROR : MATTER_OK;
}
static Matter_Result_T chain(Fixture* f,Matter_Der_T leaf,Matter_Der_T intermediate,Matter_Der_T root,const Matter_Cert_Time_Policy_T* t) {
    return f->credentials.cert_verify_chain(f->credentials.user,leaf,intermediate,root,t,f->public_key);
}
static void primitives(Fixture* f) {
    Matter_Crypto_Port_T* p=&f->crypto;
    CHECK(p->ecdsa_verify(p->user,cred_leaf_public,cred_message,sizeof(cred_message),cred_signature)==MATTER_OK);
    memcpy(f->signature,cred_signature,64); f->signature[63]^=1;
    CHECK(p->ecdsa_verify(p->user,cred_leaf_public,cred_message,sizeof(cred_message),f->signature)==MATTER_PORT_ERROR);
    CHECK(p->ecdsa_verify(p->user,cred_intermediate_public,cred_message,sizeof(cred_message),cred_signature)==MATTER_PORT_ERROR);
    CHECK(p->ecdsa_verify(p->user,cred_leaf_public,cred_message,sizeof(cred_message)-1,cred_signature)==MATTER_PORT_ERROR);
    memset(f->signature,0,64); CHECK(p->ecdsa_verify(p->user,cred_leaf_public,cred_message,sizeof(cred_message),f->signature)==MATTER_PORT_ERROR);
    memset(f->signature,0xa5,sizeof(f->signature));
    CHECK(p->ecdsa_sign(p->user,f->key,cred_message,sizeof(cred_message),f->signature)==MATTER_OK && f->signature[64]==0xa5);
    CHECK(p->ecdsa_verify(p->user,cred_leaf_public,cred_message,sizeof(cred_message),f->signature)==MATTER_OK);
    memset(f->shared,0xa5,sizeof(f->shared));
    CHECK(p->ecdh(p->user,f->key,cred_intermediate_public,f->shared)==MATTER_OK && !memcmp(f->shared,cred_secret,32) && f->shared[32]==0xa5);
    f->key[31]=2; CHECK(p->ecdh(p->user,f->key,cred_leaf_public,f->shared)==MATTER_OK && !memcmp(f->shared,cred_secret,32)); f->key[31]=3;
    memset(f->bad,0,65); f->bad[0]=4;
    CHECK(p->ecdh(p->user,f->key,f->bad,f->shared)==MATTER_PORT_ERROR && filled(f->shared,32,0));
    CHECK(p->ecdsa_verify(p->user,f->bad,cred_message,sizeof(cred_message),cred_signature)==MATTER_PORT_ERROR);
    memset(f->key,0,32);
    CHECK(p->ecdh(p->user,f->key,cred_intermediate_public,f->shared)==MATTER_PORT_ERROR);
    CHECK(p->ecdsa_sign(p->user,f->key,cred_message,sizeof(cred_message),f->signature)==MATTER_PORT_ERROR && filled(f->signature,64,0));
    memset(f->key,0xff,32); CHECK(p->ecdh(p->user,f->key,cred_leaf_public,f->shared)==MATTER_PORT_ERROR);
    memset(f->key,0,32); f->key[31]=3;
    CHECK(p->ecdsa_sign(p->user,f->key,NULL,0,f->signature)==MATTER_OK && p->ecdsa_verify(p->user,cred_leaf_public,NULL,0,f->signature)==MATTER_OK);
    CHECK(p->ecdsa_sign(p->user,f->key,cred_message,sizeof(cred_message),f->signature)==MATTER_OK);
}
static void certificates(Fixture* f) {
    Matter_Credentials_Port_T* p=&f->credentials;
    memset(f->public_key,0xa5,sizeof(f->public_key));
    CHECK(p->csr_verify(p->user,DER(cred_csr),f->public_key)==MATTER_OK && !memcmp(f->public_key,cred_leaf_public,65) && f->public_key[65]==0xa5);
    memset(f->csr,0xa5,sizeof(f->csr));
    CHECK(p->csr_create(p->user,f->key,f->csr,512,&f->csr_size)==MATTER_OK && f->csr_size>0 && f->csr_size<=512 && f->csr[512]==0xa5);
    CHECK(filled(f->csr+f->csr_size,512-f->csr_size,0));
    CHECK(p->csr_verify(p->user,(Matter_Der_T){f->csr,f->csr_size},f->public_key)==MATTER_OK && !memcmp(f->public_key,cred_leaf_public,65));
    CHECK(chain(f,DER(cred_leaf),DER(cred_intermediate),DER(cred_root),&cred_time)==MATTER_OK && !memcmp(f->public_key,cred_leaf_public,65));
    CHECK(chain(f,DER(cred_leaf),(Matter_Der_T){0},DER(cred_intermediate),&cred_time)==MATTER_OK);
    CHECK(chain(f,DER(cred_leaf),DER(cred_intermediate),DER(cred_other),&cred_time)==MATTER_PORT_ERROR && filled(f->public_key,65,0));
    CHECK(chain(f,DER(cred_leaf),DER(cred_notca),DER(cred_root),&cred_time)==MATTER_PORT_ERROR);
    CHECK(chain(f,DER(cred_leaf),DER(cred_intermediate),DER(cred_root0),&cred_time)==MATTER_PORT_ERROR);
    CHECK(chain(f,DER(cred_leaf),(Matter_Der_T){0},DER(cred_root),&cred_time)==MATTER_PORT_ERROR);
    CHECK(chain(f,DER(cred_intermediate),(Matter_Der_T){0},DER(cred_root),&cred_time)==MATTER_PORT_ERROR); /* CA is not a leaf. */
    Matter_Cert_Time_Policy_T t=cred_time; t.now.year=2000;
    CHECK(chain(f,DER(cred_leaf),DER(cred_intermediate),DER(cred_root),&t)==MATTER_PORT_ERROR);
    t.now.year=2099; CHECK(chain(f,DER(cred_leaf),DER(cred_intermediate),DER(cred_root),&t)==MATTER_PORT_ERROR);
    t.mode=MATTER_CERT_TIME_LEAF_NOT_BEFORE; CHECK(chain(f,DER(cred_leaf),DER(cred_intermediate),DER(cred_root),&t)==MATTER_OK);
    t.mode=MATTER_CERT_TIME_IGNORE_VALIDITY;
    CHECK(chain(f,DER(cred_leaf),DER(cred_intermediate),DER(cred_root),&t)==MATTER_OK);
    t.now.year=2000; CHECK(chain(f,DER(cred_leaf),DER(cred_intermediate),DER(cred_root),&t)==MATTER_OK);
    CHECK(chain(f,DER(cred_leaf),DER(cred_intermediate),DER(cred_other),&t)==MATTER_PORT_ERROR && filled(f->public_key,65,0));
    CHECK(chain(f,DER(cred_leaf),DER(cred_notca),DER(cred_root),&t)==MATTER_PORT_ERROR);
    CHECK(chain(f,DER(cred_leaf),DER(cred_intermediate),DER(cred_root0),&t)==MATTER_PORT_ERROR);
    CHECK(chain(f,DER(cred_leaf),(Matter_Der_T){0},DER(cred_root),&t)==MATTER_PORT_ERROR);
    memcpy(f->bad,cred_leaf,sizeof(cred_leaf)); f->bad[sizeof(cred_leaf)-1]^=1;
    CHECK(chain(f,(Matter_Der_T){f->bad,sizeof(cred_leaf)},DER(cred_intermediate),DER(cred_root),&t)==MATTER_PORT_ERROR && filled(f->public_key,65,0));
    CHECK(chain(f,(Matter_Der_T){f->bad,sizeof(cred_leaf)},DER(cred_intermediate),DER(cred_root),&cred_time)==MATTER_PORT_ERROR);
    memcpy(f->bad,cred_intermediate,sizeof(cred_intermediate)); f->bad[sizeof(cred_intermediate)-1]^=1;
    CHECK(chain(f,DER(cred_leaf),(Matter_Der_T){f->bad,sizeof(cred_intermediate)},DER(cred_root),&t)==MATTER_PORT_ERROR);
    CHECK(chain(f,DER(cred_leaf),(Matter_Der_T){f->bad,sizeof(cred_intermediate)},DER(cred_root),&cred_time)==MATTER_PORT_ERROR);
    memcpy(f->bad,cred_csr,sizeof(cred_csr)); f->bad[sizeof(cred_csr)-1]^=1;
    CHECK(p->csr_verify(p->user,(Matter_Der_T){f->bad,sizeof(cred_csr)},f->public_key)==MATTER_PORT_ERROR && filled(f->public_key,65,0));
    memcpy(f->bad,cred_csr,sizeof(cred_csr));
    static const uint8_t sha256_oid[]={6,8,0x2a,0x86,0x48,0xce,0x3d,4,3,2};
    bool found=false;
    for(size_t i=0;i+sizeof(sha256_oid)<=sizeof(cred_csr);++i) if(!memcmp(f->bad+i,sha256_oid,sizeof(sha256_oid))) {
        f->bad[i+9]=3; found=true; break; /* Declared SHA-384 cannot pass as SHA-256. */
    }
    CHECK(found && p->csr_verify(p->user,(Matter_Der_T){f->bad,sizeof(cred_csr)},f->public_key)==MATTER_PORT_ERROR);
    memcpy(f->bad,cred_csr,sizeof(cred_csr)); f->bad[sizeof(cred_csr)]=0;
    CHECK(p->csr_verify(p->user,(Matter_Der_T){f->bad,sizeof(cred_csr)+1},f->public_key)==MATTER_PORT_ERROR);
    memcpy(f->bad,cred_leaf,sizeof(cred_leaf)); f->bad[sizeof(cred_leaf)]=0;
    CHECK(chain(f,(Matter_Der_T){f->bad,sizeof(cred_leaf)+1},DER(cred_intermediate),DER(cred_root),&cred_time)==MATTER_PORT_ERROR);
    for(size_t n=1;n<sizeof(cred_csr);++n) CHECK(p->csr_verify(p->user,(Matter_Der_T){cred_csr,n},f->public_key)==MATTER_PORT_ERROR);
    for(size_t n=1;n<sizeof(cred_leaf);++n) CHECK(chain(f,(Matter_Der_T){cred_leaf,n},DER(cred_intermediate),DER(cred_root),&cred_time)==MATTER_PORT_ERROR);
}
static void bounds_and_rng(Fixture* f) {
    Matter_Crypto_Port_T* c=&f->crypto; Matter_Credentials_Port_T* p=&f->credentials;
    memset(f->signature,0xa5,65); memset(f->public_key,0xa5,66); memset(f->csr,0xa5,513); f->csr_size=99;
    CHECK(c->ecdsa_sign(c->user,f->key,cred_message,MATTER_CRYPTO_MAX_INPUT+1,f->signature)==MATTER_LIMIT_REACHED && filled(f->signature,65,0xa5));
    CHECK(c->ecdsa_verify(c->user,NULL,NULL,0,NULL)==MATTER_INVALID_ARGUMENT);
    CHECK(p->csr_create(p->user,f->key,f->csr,511,&f->csr_size)==MATTER_LIMIT_REACHED && f->csr_size==99 && filled(f->csr,513,0xa5));
    CHECK(p->csr_verify(p->user,(Matter_Der_T){f->bad,513},f->public_key)==MATTER_LIMIT_REACHED && filled(f->public_key,66,0xa5));
    CHECK(chain(f,(Matter_Der_T){f->bad,2049},DER(cred_intermediate),DER(cred_root),&cred_time)==MATTER_LIMIT_REACHED);
    Matter_Cert_Time_Policy_T t=cred_time; t.now.month=2; t.now.day=30;
    CHECK(chain(f,DER(cred_leaf),DER(cred_intermediate),DER(cred_root),&t)==MATTER_INVALID_ARGUMENT && filled(f->public_key,66,0xa5));
    f->reenter=true; f->rng_failure=true;
    CHECK(matter_crypto_mbedtls_reseed(f->context)==MATTER_PORT_ERROR);
    CHECK(c->ecdsa_sign(c->user,f->key,NULL,0,f->signature)==MATTER_OFFLINE && filled(f->signature,65,0xa5));
    CHECK(c->ecdh(c->user,f->key,cred_leaf_public,f->shared)==MATTER_OFFLINE);
    CHECK(p->csr_create(p->user,f->key,f->csr,512,&f->csr_size)==MATTER_OFFLINE && f->csr_size==99 && filled(f->csr,513,0xa5));
    CHECK(c->ecdsa_verify(c->user,cred_leaf_public,cred_message,sizeof(cred_message),cred_signature)==MATTER_OK);
    CHECK(p->csr_verify(p->user,DER(cred_csr),f->public_key)==MATTER_OK);
    CHECK(chain(f,DER(cred_leaf),DER(cred_intermediate),DER(cred_root),&cred_time)==MATTER_OK);
    f->rng_failure=false; CHECK(matter_crypto_mbedtls_reseed(f->context)==MATTER_OK); f->reenter=false;
    for(unsigned op=0;op<3;++op) {
        /* Trigger entropy failure inside the operation, not only before entry. */
        CHECK(matter_crypto_mbedtls_reseed(f->context)==MATTER_OK);
        for(unsigned i=0;i<10000;++i) CHECK(c->random(c->user,f->shared,1)==MATTER_OK);
        f->rng_failure=true; f->reenter=true;
        if(op==0) CHECK(c->ecdsa_sign(c->user,f->key,NULL,0,f->signature)==MATTER_PORT_ERROR && filled(f->signature,64,0));
        if(op==1) CHECK(c->ecdh(c->user,f->key,cred_leaf_public,f->shared)==MATTER_PORT_ERROR && filled(f->shared,32,0));
        if(op==2) CHECK(p->csr_create(p->user,f->key,f->csr,512,&f->csr_size)==MATTER_PORT_ERROR && !f->csr_size && filled(f->csr,512,0));
        f->rng_failure=false; f->reenter=false;
        CHECK(matter_crypto_mbedtls_reseed(f->context)==MATTER_OK);
    }
}
#ifdef MATTER_TEST_ALLOC
static Matter_Result_T operation(Fixture* f,unsigned op) {
    Matter_Crypto_Port_T* c=&f->crypto; Matter_Credentials_Port_T* p=&f->credentials;
    if(op==0) return c->ecdsa_sign(c->user,f->key,cred_message,sizeof(cred_message),f->signature);
    if(op==1) return c->ecdsa_verify(c->user,cred_leaf_public,cred_message,sizeof(cred_message),cred_signature);
    if(op==2) return c->ecdh(c->user,f->key,cred_intermediate_public,f->shared);
    if(op==3) return p->csr_create(p->user,f->key,f->csr,512,&f->csr_size);
    if(op==4) return p->csr_verify(p->user,DER(cred_csr),f->public_key);
    if(op==6) {
        Matter_Cert_Time_Policy_T time={MATTER_CERT_TIME_IGNORE_VALIDITY,{0}};
        return chain(f,DER(cred_leaf),DER(cred_intermediate),DER(cred_root),&time);
    }
    return chain(f,DER(cred_leaf),DER(cred_intermediate),DER(cred_root),&cred_time);
}
static void oom(Fixture* f) {
    size_t baseline=live;
    for(unsigned op=0;op<7;++op) {
        size_t before=calls; CHECK(operation(f,op)==MATTER_OK); size_t count=calls-before;
        for(size_t point=1;point<=count;++point) {
            fail_at=calls+point; Matter_Result_T r=operation(f,op); fail_at=0;
            CHECK((r==MATTER_PORT_ERROR || r==MATTER_OK) && live==baseline);
            if(r==MATTER_PORT_ERROR) {
                if(op==0) CHECK(filled(f->signature,64,0));
                if(op==2) CHECK(filled(f->shared,32,0));
                if(op==3) CHECK(!f->csr_size && filled(f->csr,512,0));
                if(op>=4) CHECK(filled(f->public_key,65,0));
            }
            CHECK(matter_crypto_mbedtls_reseed(f->context)==MATTER_OK);
        }
        CHECK(operation(f,op)==MATTER_OK && live==baseline);
        printf("Credentials OOM: operation %u, %zu allocation positions, output cleanup/balance/recovery\n",op,count);
    }
}
#endif
int main(int argc,char** argv) {
    Fixture* f=calloc(1,sizeof(*f)); CHECK(f); f->key[31]=3;
    Matter_Crypto_Entropy_Port_T source={f,entropy}; f->context=matter_crypto_mbedtls_new(&source); CHECK(f->context);
    CHECK(matter_crypto_mbedtls_port(f->context,&f->crypto)==MATTER_OK && matter_crypto_mbedtls_credentials(f->context,&f->credentials)==MATTER_OK);
    primitives(f); certificates(f);
    if(argc==3) { /* Optional independent OpenSSL verification artifacts. */
        FILE* out=fopen(argv[1],"wb"); CHECK(out && fwrite(f->csr,1,f->csr_size,out)==f->csr_size && !fclose(out));
        out=fopen(argv[2],"wb"); CHECK(out && fwrite(f->signature,1,64,out)==64 && !fclose(out));
    }
    bounds_and_rng(f);
#ifdef MATTER_TEST_ALLOC
    oom(f);
#endif
    CHECK(matter_crypto_mbedtls_delete(f->context)==MATTER_OK); memset(f,0,sizeof(*f)); free(f);
#ifdef MATTER_TEST_ALLOC
    CHECK(!live);
#endif
    puts("PASS credentials: independent ECDSA/ECDH, signed CSR, DER chain/trust/CA/time, malformed/trailing DER, RNG/reentry and bounds");
    return 0;
}
