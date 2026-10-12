/* Exercise the actual host adapter with a controllable OS clock. The portable
 * credential backend still receives explicit UTC and verifies real signatures. */
#include "runtime/matter_runtime.h"
static bool clock_available=true;
static unsigned clock_calls;
static Matter_Cert_Time_T clock_value={2026,10,10,0,0,0};
static Matter_Result_T test_utc(void* u,Matter_Cert_Time_T* out) {
    (void)u; ++clock_calls; *out=clock_value; return clock_available?MATTER_OK:MATTER_OFFLINE;
}
#include "runtime/matter_runtime.c"
#include "crypto/matter_crypto_mbedtls.h"
#include "test_operational_vectors.h"
#include "test_synthetic_operational_vectors.h"
#include "crypto/matter_operational_cert.h"
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"Host clock:%d: %s\n",__LINE__,#c); abort(); } } while(0)
#define CERT(a) (Matter_Cert_Tlv_T){a,sizeof(a)}
typedef struct { uint8_t der[3][600],key[65]; size_t size[3]; } Work;
int main(void) {
    (void)reference; (void)chains;
    Work* w=calloc(1,sizeof(*w)); CHECK(w);
    CHECK(matter_operational_cert_decode(CERT(rs_noc1_success),MATTER_CERT_NOC,w->der[0],600,&w->size[0])==MATTER_OK);
    CHECK(matter_operational_cert_decode(CERT(rs_icac1_success),MATTER_CERT_ICAC,w->der[1],600,&w->size[1])==MATTER_OK);
    CHECK(matter_operational_cert_decode(CERT(rs_rca1_success),MATTER_CERT_RCAC,w->der[2],600,&w->size[2])==MATTER_OK);
    Matter_Der_T leaf={w->der[0],w->size[0]},ca={w->der[1],w->size[1]},root={w->der[2],w->size[2]};
    Matter_Crypto_Mbedtls_T backend=matter_crypto_mbedtls_new(NULL); CHECK(backend);
    Matter_Credentials_Port_T base; CHECK(matter_crypto_mbedtls_credentials(backend,&base)==MATTER_OK);
    Host_Credentials_T adapter={.base=base,.utc=test_utc};
    Matter_Cert_Time_Policy_T stale={MATTER_CERT_TIME_SUPPLIED,{2000,1,1,0,0,0}};
    CHECK(base.cert_verify_chain(base.user,leaf,ca,root,&stale,w->key)==MATTER_PORT_ERROR);
    CHECK(live_cert_verify(&adapter,leaf,ca,root,&stale,w->key)==MATTER_OK);
    CHECK(stale.now.year==2000 && clock_calls==1); /* Caller policy not mutated. */
    clock_value.year=2099; /* A long-running process must reject expiry too. */
    CHECK(live_cert_verify(&adapter,leaf,ca,root,&stale,w->key)==MATTER_PORT_ERROR);
    clock_value.year=2000;
    CHECK(live_cert_verify(&adapter,leaf,ca,root,&stale,w->key)==MATTER_PORT_ERROR);
    clock_available=false; memset(w->key,0xa5,sizeof(w->key));
    CHECK(live_cert_verify(&adapter,leaf,ca,root,&stale,w->key)==MATTER_OFFLINE);
    for(unsigned i=0;i<65;++i) CHECK(!w->key[i]);
    Matter_Cert_Time_Policy_T attestation={MATTER_CERT_TIME_LEAF_NOT_BEFORE,{0}};
    unsigned before=clock_calls;
    Matter_Result_T expected=base.cert_verify_chain(base.user,leaf,ca,root,&attestation,w->key);
    CHECK(live_cert_verify(&adapter,leaf,ca,root,&attestation,w->key)==expected && clock_calls==before);
    Host_Credentials_T compatible={.base=base,.utc=test_utc,.chip_validity=true};
    CHECK(live_cert_verify(&compatible,leaf,ca,root,&stale,w->key)==MATTER_OK && clock_calls==before);
    CHECK(live_cert_verify(&compatible,leaf,ca,root,&attestation,w->key)==expected && clock_calls==before);
    CHECK(live_cert_verify(&adapter,leaf,ca,root,&stale,w->key)==MATTER_OFFLINE); /* Independent policies. */
    clock_available=true; clock_value.year=2026;
    Matter_Der_T th_leaf={synthetic_noc_der,sizeof(synthetic_noc_der)},th_ca={synthetic_icac_der,sizeof(synthetic_icac_der)},
        th_root={synthetic_root_der,sizeof(synthetic_root_der)};
    CHECK(live_operational_verify(&adapter,th_leaf,th_ca,th_root,&stale,w->key)==MATTER_OK);
    CHECK(live_cert_verify(&adapter,th_leaf,th_ca,th_root,&stale,w->key)==MATTER_PORT_ERROR);
    clock_value.year=2040;
    CHECK(live_operational_verify(&adapter,th_leaf,th_ca,th_root,&stale,w->key)==MATTER_PORT_ERROR);
    CHECK(live_operational_verify(&compatible,th_leaf,th_ca,th_root,&stale,w->key)==MATTER_OK);
    clock_available=false;
    CHECK(live_operational_verify(&adapter,th_leaf,th_ca,th_root,&stale,w->key)==MATTER_OFFLINE);
    clock_available=true; clock_value.year=2026;
    w->der[0][w->size[0]-1]^=1;
    CHECK(live_cert_verify(&adapter,leaf,ca,root,&stale,w->key)==MATTER_PORT_ERROR);
    CHECK(live_cert_verify(&compatible,leaf,ca,root,&stale,w->key)==MATTER_PORT_ERROR);
    CHECK(live_cert_verify(&adapter,leaf,ca,root,NULL,w->key)==MATTER_INVALID_ARGUMENT);
    CHECK(live_cert_verify(&adapter,leaf,ca,root,&stale,NULL)==MATTER_INVALID_ARGUMENT);
    memset(w->key,0,32); w->key[31]=1;
    size_t csr_size=0;
    CHECK(host_csr_create(&adapter,w->key,w->der[0],MATTER_CREDENTIALS_MAX_CSR,&csr_size)==MATTER_OK);
    CHECK(host_csr_verify(&adapter,(Matter_Der_T){w->der[0],csr_size},w->key)==MATTER_OK && w->key[0]==4);
    Matter_Runtime_T server=calloc(1,sizeof(*server)); CHECK(server);
    CHECK(!server->credential_adapter.chip_validity);
    CHECK(matter_runtime_set_certificate_validity(NULL,true)==MATTER_INVALID_ARGUMENT);
    CHECK(matter_runtime_set_certificate_validity(server,true)==MATTER_OK && server->credential_adapter.chip_validity);
    CHECK(matter_runtime_set_certificate_validity(server,false)==MATTER_OK && !server->credential_adapter.chip_validity);
    server->stopping=true;
    CHECK(matter_runtime_set_certificate_validity(server,true)==MATTER_INVALID_STATE && !server->credential_adapter.chip_validity);
    free(server);
    CHECK(matter_crypto_mbedtls_delete(backend)==MATTER_OK); free(w);
    puts("PASS host live UTC, strict/CHIP policy isolation, clock failure, attestation, bad signature, CSR and configuration lifecycle");
    return 0;
}
