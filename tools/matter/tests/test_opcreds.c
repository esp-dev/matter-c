#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/matter_crypto_mbedtls.h"
#include "test_opcreds_fixture.h"
#ifdef MATTER_TEST_ALLOC
static size_t live,calls,fail_at;
void* matter_test_calloc(size_t n,size_t z) { ++calls; if(calls==fail_at) return NULL; void* p=calloc(n,z); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { OC_CHECK(live); --live; } free(p); }
#endif
static void exported(const char* dir,const char* name,const uint8_t* p,size_t n) {
    size_t size=strlen(dir)+strlen(name)+2; char* path=malloc(size); OC_CHECK(path);
    snprintf(path,size,"%s/%s",dir,name); FILE* out=fopen(path,"wb"); OC_CHECK(out);
    OC_CHECK(fwrite(p,1,n,out)==n && fclose(out)==0); free(path);
}
int main(int argc,char** argv) {
    Matter_Crypto_Mbedtls_T backend=matter_crypto_mbedtls_new(NULL); OC_CHECK(backend);
    Matter_Crypto_Port_T crypto; Matter_Credentials_Port_T cp;
    OC_CHECK(matter_crypto_mbedtls_port(backend,&crypto)==MATTER_OK && matter_crypto_mbedtls_credentials(backend,&cp)==MATTER_OK);
    OcFixture* f=oc_new(&crypto,&cp); f->reenter=true;
    Matter_Im_Value_T v; OC_CHECK(matter_opcreds_read(f->core,0xfffd,&v)==0 && v.unsigned_value==2);
    OC_CHECK(matter_opcreds_read(f->core,2,&v)==MATTER_IM_UNSUPPORTED_ATTRIBUTE);
    for(unsigned cert=0;cert<4;++cert) {
        oc_request(f,2,cert,32,false); OC_CHECK(oc_start(f,2,false)==MATTER_OK);
        if(cert==0 || cert==3) { OC_CHECK(f->result.status==MATTER_IM_INVALID_COMMAND); continue; }
        OC_CHECK(!f->result.status && matter_tlv_writer_finish(&f->writer,&f->reply_size)==MATTER_TLV_OK);
        OC_CHECK(matter_tlv_init(&f->reader,f->reply,f->reply_size,2)==MATTER_TLV_OK && matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK);
        OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.type==MATTER_TLV_BYTES &&
            f->e.size==(cert==1?sizeof(oc_dac):sizeof(oc_pai)) && !memcmp(f->e.data,cert==1?oc_dac:oc_pai,f->e.size));
    }
    for(unsigned cmd=0;cmd<=4;cmd+=4) {
        oc_request(f,cmd,0,31,false); OC_CHECK(oc_start(f,cmd,true)==MATTER_OK && f->result.status==MATTER_IM_INVALID_COMMAND);
        oc_request(f,cmd,0,32,false); f->request[f->request_size++]=0x18;
        OC_CHECK(oc_start(f,cmd,true)==MATTER_OK && f->result.status==MATTER_IM_INVALID_COMMAND);
        oc_request(f,cmd,0,32,false); OC_CHECK(oc_start(f,cmd,cmd==4)==MATTER_PENDING);
        OC_CHECK(matter_opcreds_delete(f->core)==MATTER_INVALID_STATE); oc_finish(f); OC_CHECK(!f->result.status);
        oc_verify(f,cmd,f->reply,f->reply_size);
        if(argc>1) {
            exported(argv[1],cmd?"csr-tbs.bin":"attestation-tbs.bin",f->tbs,f->tbs_size+16);
            exported(argv[1],cmd?"csr-signature.bin":"attestation-signature.bin",f->signature,64);
            if(cmd) exported(argv[1],"csr.der",f->csr,f->csr_size);
        }
    }
    /* Admission has no crypto/key side effects on insufficient output capacity. */
    oc_request(f,4,0,32,false); unsigned prepares=f->prepares;
    OC_CHECK(matter_tlv_writer_init(&f->writer,f->reply,975,4)==MATTER_TLV_OK);
    OC_CHECK(matter_opcreds_start(f->core,1,4,true,f->request,f->request_size,&f->writer,&f->result,&f->token)==MATTER_OK &&
        f->result.status==MATTER_IM_RESOURCE_EXHAUSTED && f->prepares==prepares);
    /* Distinct instances can be pending on the same owner thread. */
    OcFixture* other=oc_new(&crypto,&cp); oc_request(other,0,0,32,false);
    oc_request(f,0,0,32,false); OC_CHECK(oc_start(f,0,false)==MATTER_PENDING && oc_start(other,0,false)==MATTER_PENDING);
    oc_finish(other); oc_finish(f); oc_verify(other,0,other->reply,other->reply_size); oc_verify(f,0,f->reply,f->reply_size); oc_free(other);
    /* Timestamp failure returns Failure, not a signed fabricated timestamp. */
    f->fail_time=true; OC_CHECK(oc_start(f,0,false)==MATTER_PENDING); oc_finish(f);
    OC_CHECK(f->result.status==MATTER_IM_FAILURE); f->fail_time=false;
    /* Duplicate nonce and wrong type are InvalidCommand. */
    oc_request(f,0,0,32,false); memcpy(f->request+f->request_size-1,f->request+1,35);
    f->request_size+=35; f->request[f->request_size-1]=0x18;
    OC_CHECK(oc_start(f,0,false)==MATTER_OK && f->result.status==MATTER_IM_INVALID_COMMAND);
    oc_request(f,0,0,32,false); f->request[1]=0x2c; /* UTF8 instead of octets. */
    OC_CHECK(oc_start(f,0,false)==MATTER_OK && f->result.status==MATTER_IM_INVALID_COMMAND);
    OC_CHECK(matter_opcreds_host_delete(f->host)==MATTER_INVALID_STATE);
    memcpy(f->previous,f->candidate,65);
    oc_request(f,4,0,32,true); OC_CHECK(oc_start(f,4,true)==MATTER_OK && f->result.status==MATTER_IM_INVALID_COMMAND);
    OC_CHECK(oc_start(f,4,false)==MATTER_OK && f->result.status==MATTER_IM_INVALID_COMMAND);
    oc_request(f,4,0,32,false); OC_CHECK(oc_start(f,4,false)==MATTER_OK && f->result.status==0xca);
    for(unsigned failure=0;failure<5;++failure) {
        f->fail_prepare=failure==0; f->fail_sign=failure==1; f->fail_publish=failure==2;
        oc_request(f,4,0,32,false); OC_CHECK(oc_start(f,4,true)==MATTER_PENDING);
        OC_CHECK(matter_opcreds_process(f->core)==MATTER_PENDING);
        if(failure==3) f->revoked=true;
        if(failure==4) ++f->challenge[0];
        oc_finish(f); OC_CHECK(f->result.status==(failure>=3?MATTER_IM_UNSUPPORTED_ACCESS:MATTER_IM_FAILURE));
        f->revoked=false; if(failure==4) --f->challenge[0];
        OC_CHECK(matter_opcreds_host_candidate(f->host,f->candidate)==MATTER_OK && !memcmp(f->previous,f->candidate,65));
    }
    f->fail_prepare=f->fail_sign=f->fail_publish=false;
    oc_request(f,4,0,32,false); OC_CHECK(oc_start(f,4,true)==MATTER_PENDING); oc_finish(f); oc_verify(f,4,f->reply,f->reply_size);
    OC_CHECK(memcmp(f->candidate,f->previous,65)); /* Each CSR gets a fresh key. */
    /* Cancellation keeps the published candidate, but drains staged keys. */
    OC_CHECK(oc_start(f,4,true)==MATTER_PENDING && matter_opcreds_process(f->core)==MATTER_PENDING);
    f->hold_discard=true; matter_opcreds_cancel(f->core,f->token);
    OC_CHECK(matter_opcreds_process(f->core)==MATTER_PENDING && matter_opcreds_rollback(f->core)==MATTER_PENDING);
    f->hold_discard=false; OC_CHECK(matter_opcreds_rollback(f->core)==MATTER_OK);
    OC_CHECK(matter_opcreds_host_candidate(f->host,f->candidate)==MATTER_INVALID_STATE);
    /* Constructor fail-closed: wrong private DAC and wrong expected identity. */
    f->key[31]=2; OC_CHECK(!matter_opcreds_host_new(&f->config,&crypto,&cp)); f->key[31]=3;
    ++f->config.product_id; OC_CHECK(!matter_opcreds_host_new(&f->config,&crypto,&cp)); --f->config.product_id;
#ifdef MATTER_TEST_ALLOC
    for(unsigned i=1;i<=2;++i) { size_t before=live; fail_at=calls+i; OC_CHECK(!matter_opcreds_new(&f->config.identity,&f->port) && live==before); fail_at=0; }
    fail_at=calls+1; OC_CHECK(!matter_opcreds_host_new(&f->config,&crypto,&cp)); fail_at=0;
    /* Fail CSR scratch allocation before key generation, then outer signing. */
    oc_request(f,4,0,32,false); OC_CHECK(oc_start(f,4,true)==MATTER_PENDING);
    fail_at=calls+1; OC_CHECK(matter_opcreds_process(f->core)==MATTER_PENDING); fail_at=0;
    oc_finish(f); OC_CHECK(f->result.status==MATTER_IM_RESOURCE_EXHAUSTED);
    oc_request(f,4,0,32,false); OC_CHECK(oc_start(f,4,true)==MATTER_PENDING && matter_opcreds_process(f->core)==MATTER_PENDING);
    fail_at=calls+1; OC_CHECK(matter_opcreds_process(f->core)==MATTER_PENDING); fail_at=0;
    oc_finish(f); OC_CHECK(f->result.status==MATTER_IM_FAILURE && matter_opcreds_host_candidate(f->host,f->candidate)==MATTER_INVALID_STATE);
#endif
    /* Exact RESP_MAX boundary (opaque fake CD here tests length only). */
    Matter_Opcreds_Config_T limit=f->config.identity; limit.certification_declaration=(Matter_Der_T){f->tbs,854};
    OC_CHECK(!matter_opcreds_new(&limit,&f->port)); limit.certification_declaration.size=853;
    Matter_Opcreds_T saved=f->core; f->core=matter_opcreds_new(&limit,&f->port); OC_CHECK(f->core);
    oc_request(f,0,0,32,false); OC_CHECK(oc_start(f,0,false)==MATTER_PENDING); oc_finish(f);
    OC_CHECK(!f->result.status && f->reply_size==973);
    OC_CHECK(matter_opcreds_delete(f->core)==MATTER_OK); f->core=saved;
    oc_free(f); OC_CHECK(matter_crypto_mbedtls_delete(backend)==MATTER_OK);
#ifdef MATTER_TEST_ALLOC
    OC_CHECK(!live);
#endif
    puts("PASS Operational Credentials: DAC/PAI, session-bound attestation, fresh signed CSR, gates, key failure atomicity and rollback"); return 0;
}
