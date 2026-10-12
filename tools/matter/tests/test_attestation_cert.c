#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/matter_attestation_cert.h"
#include "crypto/matter_crypto_mbedtls.h"
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"Attestation:%d: %s\n",__LINE__,#c); abort(); } } while(0)
#ifdef MATTER_TEST_ALLOC
static size_t live,calls,fail_at;
void* matter_test_calloc(size_t n,size_t size) { ++calls; if(calls==fail_at) return NULL; void* p=calloc(n,size); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { CHECK(live); --live; } free(p); }
#endif
#include "test_attestation_vectors.h"
#define DER(a) (Matter_Der_T){a,sizeof(a)}
typedef struct {
    Matter_Crypto_Mbedtls_T context;
    Matter_Credentials_Port_T backend,port;
    Matter_Attestation_Identity_T output;
    uint8_t sentinel,bad[601],key[65];
    unsigned port_calls;
    bool fail_port;
} Fixture;
static bool filled(const void* data,size_t n,uint8_t v) { const uint8_t* p=data; for(size_t i=0;i<n;++i) if(p[i]!=v) return false; return true; }
static Matter_Result_T verify_port(void* user,Matter_Der_T dac,Matter_Der_T pai,Matter_Der_T paa,const Matter_Cert_Time_Policy_T* time,uint8_t* key) {
    Fixture* f=user; ++f->port_calls;
    CHECK(time->mode==MATTER_CERT_TIME_LEAF_NOT_BEFORE && pai.size && paa.size && dac.size);
    CHECK(filled(&f->output,sizeof(f->output),0)); /* No premature identity. */
    if(f->fail_port) { memset(key,0xa5,65); return MATTER_BUSY; }
    return f->backend.cert_verify_chain(f->backend.user,dac,pai,paa,time,key);
}
static Matter_Result_T verify(Fixture* f,Matter_Der_T dac,Matter_Der_T pai,Matter_Der_T paa,uint16_t vid,uint16_t pid) {
    memset(&f->output,0xa5,sizeof(f->output)); f->sentinel=0x5a;
    Matter_Result_T result=matter_attestation_cert_verify(&f->port,dac,pai,paa,vid,pid,&f->output);
    CHECK(f->sentinel==0x5a);
    if(result==MATTER_OK) CHECK(f->output.vendor_id==vid && f->output.product_id==pid);
    else if(result==MATTER_INVALID_ARGUMENT || result==MATTER_LIMIT_REACHED) CHECK(filled(&f->output,sizeof(f->output),0xa5));
    else CHECK(filled(&f->output,sizeof(f->output),0));
    return result;
}
static void vectors(Fixture* f) {
    for(size_t i=0;i<sizeof(att_cases)/sizeof(att_cases[0]);++i) {
        printf("Attestation profile: %s\n",att_cases[i].name); fflush(stdout);
        CHECK(verify(f,att_cases[i].dac,att_cases[i].pai,att_cases[i].paa,0xfff1,0x8000)==
            (att_cases[i].valid?MATTER_OK:MATTER_PORT_ERROR));
        if(att_cases[i].valid) CHECK(!memcmp(f->output.public_key,att_public,65));
    }
    /* These signed certificates pass generic chain verification, yet fail the
     * Matter profile. This separates policy rejection from signature failure. */
    static const Matter_Cert_Time_Policy_T time={MATTER_CERT_TIME_LEAF_NOT_BEFORE,{0}};
    const Matter_Der_T invalid[]={DER(att_fallback_lowercase),DER(att_oid_mixed),DER(att_oid_order),DER(att_wrong_key_usage)};
    for(size_t i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i) {
        CHECK(f->backend.cert_verify_chain(f->backend.user,invalid[i],DER(att_pai),DER(att_paa),&time,f->key)==MATTER_OK);
        unsigned before=f->port_calls;
        CHECK(verify(f,invalid[i],DER(att_pai),DER(att_paa),0xfff1,0x8000)==MATTER_PORT_ERROR && f->port_calls==before);
    }
    CHECK(verify(f,DER(att_dac),DER(att_custom_pai),DER(att_custom_paa),0xfff1,0x8000)==MATTER_OK);
    for(unsigned i=0;i<20;++i) CHECK(f->output.paa_key_id[i]==i);
}
static void errors(Fixture* f) {
    const Matter_Der_T chain[]={DER(att_dac),DER(att_pai),DER(att_paa)};
    for(unsigned c=0;c<3;++c) for(size_t n=1;n<chain[c].size;++n) {
        Matter_Der_T parts[]={chain[0],chain[1],chain[2]}; parts[c].size=n;
        CHECK(verify(f,parts[0],parts[1],parts[2],0xfff1,0x8000)==MATTER_PORT_ERROR);
    }
    for(unsigned c=0;c<3;++c) {
        Matter_Der_T parts[]={chain[0],chain[1],chain[2]};
        memcpy(f->bad,parts[c].data,parts[c].size); f->bad[parts[c].size]=0;
        parts[c]=(Matter_Der_T){f->bad,parts[c].size+1};
        CHECK(verify(f,parts[0],parts[1],parts[2],0xfff1,0x8000)==MATTER_PORT_ERROR);
    }
    for(unsigned c=0;c<2;++c) {
        Matter_Der_T parts[]={chain[0],chain[1],chain[2]};
        memcpy(f->bad,parts[c].data,parts[c].size); f->bad[parts[c].size-1]^=1;
        parts[c].data=f->bad;
        CHECK(verify(f,parts[0],parts[1],parts[2],0xfff1,0x8000)==MATTER_PORT_ERROR);
    }
    CHECK(verify(f,DER(att_dac),DER(att_pai),DER(att_other_paa),0xfff1,0x8000)==MATTER_PORT_ERROR);
    CHECK(verify(f,DER(att_dac),DER(att_pai),DER(att_paa),0xfff2,0x8000)==MATTER_PORT_ERROR);
    CHECK(verify(f,DER(att_dac),DER(att_pai),DER(att_paa),0xfff1,0x8001)==MATTER_PORT_ERROR);
    CHECK(verify(f,DER(att_dac),DER(att_paa),DER(att_pai),0xfff1,0x8000)==MATTER_PORT_ERROR);
    CHECK(verify(f,DER(att_dac),(Matter_Der_T){0},DER(att_paa),0xfff1,0x8000)==MATTER_INVALID_ARGUMENT);
    CHECK(verify(f,DER(att_dac),DER(att_pai),DER(att_paa),0,0x8000)==MATTER_INVALID_ARGUMENT);
    CHECK(verify(f,(Matter_Der_T){f->bad,601},DER(att_pai),DER(att_paa),0xfff1,0x8000)==MATTER_LIMIT_REACHED);
    f->fail_port=true;
    CHECK(verify(f,DER(att_dac),DER(att_pai),DER(att_paa),0xfff1,0x8000)==MATTER_BUSY);
    f->fail_port=false;
    CHECK(verify(f,DER(att_dac),DER(att_pai),DER(att_paa),0xfff1,0x8000)==MATTER_OK);
    /* Trust is explicit; a changed PAA self-signature cannot create or revoke
     * the application's decision to trust that same root subject/public key. */
    memcpy(f->bad,att_paa,sizeof(att_paa)); f->bad[sizeof(att_paa)-1]^=1;
    CHECK(verify(f,DER(att_dac),DER(att_pai),(Matter_Der_T){f->bad,sizeof(att_paa)},0xfff1,0x8000)==MATTER_OK);
}
#ifdef MATTER_TEST_ALLOC
static void oom(Fixture* f) {
    size_t baseline=live; calls=0;
    CHECK(verify(f,DER(att_dac),DER(att_pai),DER(att_paa),0xfff1,0x8000)==MATTER_OK);
    size_t positions=calls;
    for(size_t i=1;i<=positions;++i) {
        calls=0; fail_at=i;
        Matter_Result_T r=verify(f,DER(att_dac),DER(att_pai),DER(att_paa),0xfff1,0x8000);
        CHECK(r==MATTER_OK || r==MATTER_PORT_ERROR); CHECK(live==baseline);
        if(r==MATTER_OK) CHECK(!memcmp(f->output.public_key,att_public,65));
    }
    fail_at=0;
    CHECK(verify(f,DER(att_dac),DER(att_pai),DER(att_paa),0xfff1,0x8000)==MATTER_OK && live==baseline);
    printf("Attestation OOM: %zu allocation positions, balance/output/recovery OK\n",positions);
}
#endif
int main(void) {
    Fixture* f=calloc(1,sizeof(*f)); CHECK(f);
    f->context=matter_crypto_mbedtls_new(NULL); CHECK(f->context);
    CHECK(matter_crypto_mbedtls_credentials(f->context,&f->backend)==MATTER_OK);
    f->port=(Matter_Credentials_Port_T){.user=f,.cert_verify_chain=verify_port};
    vectors(f); errors(f);
#ifdef MATTER_TEST_ALLOC
    oom(f);
#endif
    CHECK(matter_crypto_mbedtls_delete(f->context)==MATTER_OK); free(f);
#ifdef MATTER_TEST_ALLOC
    CHECK(!live);
#endif
    puts("PASS Matter attestation certificate profiles/chain/identity"); return 0;
}
