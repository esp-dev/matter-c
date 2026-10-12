#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/matter_crypto_mbedtls.h"
#include "test_case_fixture.h"
#include "test_groupkey_wire.h"
#ifdef MATTER_TEST_ALLOC
static size_t live,calls,fail_at;
void* matter_test_calloc(size_t n,size_t z) { if(++calls==fail_at) return NULL; void* p=calloc(n,z); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { OC_CHECK(live); --live; } free(p); }
#endif
typedef struct {
    GkWire wire; Matter_Groupkey_T model; Matter_Groupkey_Port_T port;
    Matter_Case_Fabric_T snapshot; uint8_t derived[16];
} GkFixture;
static uint8_t call(GkFixture* g,FabFixture* f,uint8_t index,unsigned cmd) {
    OC_CHECK(matter_tlv_writer_init(&f->writer,f->response,sizeof(f->response),4)==MATTER_TLV_OK);
    uint8_t r=matter_groupkey_invoke(g->model,index,cmd,g->wire.data,g->wire.n,&f->writer).status;
    if(!r && (cmd==1 || cmd==4)) OC_CHECK(matter_tlv_writer_finish(&f->writer,&f->response_size)==MATTER_TLV_OK);
    return r;
}
static void read_redacted(GkFixture* g,FabFixture* f,unsigned id,unsigned epochs,uint64_t first) {
    gk_args(&g->wire,1,id,0,0); OC_CHECK(!call(g,f,1,1));
    unsigned nulls=0,times=0,index=0;
    OC_CHECK(matter_tlv_init(&f->reader,f->response,f->response_size,4)==MATTER_TLV_OK);
    while(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK) {
        OC_CHECK(f->e.type!=MATTER_TLV_BYTES);
        if(f->e.tag.control==1 && (f->e.tag.number==2 || f->e.tag.number==4 || f->e.tag.number==6)) { OC_CHECK(f->e.type==MATTER_TLV_NULL); ++nulls; }
        if(f->e.tag.control==1 && (f->e.tag.number==3 || f->e.tag.number==5 || f->e.tag.number==7)) {
            if(times<epochs) OC_CHECK(f->e.type==MATTER_TLV_UNSIGNED && f->e.unsigned_value==first+times);
            else OC_CHECK(f->e.type==MATTER_TLV_NULL);
            ++times;
        }
        if(f->e.tag.control==1 && f->e.tag.number==254) { OC_CHECK(f->e.unsigned_value==1); ++index; }
        OC_CHECK(f->e.tag.control!=1 || f->e.tag.number!=8);
    }
    OC_CHECK(nulls==3 && times==3 && index==1);
}
static unsigned hkdf_calls,hkdf_fail;
static Matter_Crypto_Port_T real_crypto;
static Matter_Result_T fail_hkdf(void* u,const uint8_t* k,size_t kn,const uint8_t* s,size_t sn,const uint8_t* i,size_t in,uint8_t* out,size_t n) {
    if(++hkdf_calls==hkdf_fail) return MATTER_PORT_ERROR;
    return real_crypto.hkdf_sha256(u,k,kn,s,sn,i,in,out,n);
}
int main(void) {
    Matter_Crypto_Mbedtls_T backend=matter_crypto_mbedtls_new(NULL); OC_CHECK(backend);
    Matter_Crypto_Port_T crypto; Matter_Credentials_Port_T cp;
    OC_CHECK(matter_crypto_mbedtls_port(backend,&crypto)==MATTER_OK && matter_crypto_mbedtls_credentials(backend,&cp)==MATTER_OK);
    real_crypto=crypto; crypto.hkdf_sha256=fail_hkdf;
    CaseFixture* c=case_fixture(&crypto,&cp); FabFixture* f=c->fabrics[1];
    GkFixture* g=calloc(1,sizeof(*g)); OC_CHECK(g); g->port=matter_fabric_host_groupkey_port(f->host);
#ifdef MATTER_TEST_ALLOC
    for(unsigned i=1;i<=2;++i) { fail_at=calls+i; OC_CHECK(!matter_groupkey_new(&g->port)); fail_at=0; }
#endif
    g->model=matter_groupkey_new(&g->port); OC_CHECK(g->model);
    read_redacted(g,f,0,1,0); /* Synthesized by AddNOC. */
    Matter_Case_Port_T cases=matter_fabric_host_case_port(f->host);
    OC_CHECK(cases.load(cases.user,0,&g->snapshot)==MATTER_OK);
    memset(f->ipk,0x42,16);
    OC_CHECK(matter_case_ipk(&crypto,f->ipk,f->port.view(f->host)->records[0].compressed_id,g->derived)==MATTER_OK && !memcmp(g->derived,g->snapshot.ipk,16));
    uint32_t version=matter_groupkey_version(g->model);
    gk_args(&g->wire,0,7,3,100);
    for(size_t n=0;n<g->wire.n;++n) OC_CHECK(matter_groupkey_validate(g->model,0,g->wire.data,n)!=0);
    static const uint8_t empty_map[]={0x16,0x18}, map[]={0x15,0x24,1,1,0x24,2,7,0x18};
    OC_CHECK(!matter_groupkey_map(g->model,1,MATTER_IM_LIST_REPLACE,empty_map,sizeof(empty_map)));
    OC_CHECK(matter_groupkey_map(g->model,1,MATTER_IM_LIST_ADD,map,sizeof(map))==MATTER_IM_RESOURCE_EXHAUSTED);
    memcpy(g->wire.request,map,sizeof(map)); g->wire.request[6]=0;
    OC_CHECK(matter_groupkey_map(g->model,1,MATTER_IM_LIST_ADD,g->wire.request,sizeof(map))==MATTER_IM_CONSTRAINT_ERROR);
    for(unsigned bad=0;bad<10;++bad) {
        gk_args(&g->wire,0,7,3,100);
        uint8_t expected=MATTER_IM_INVALID_COMMAND;
        if(bad==0) g->wire.data[8]=1; /* Unsupported CS. */
        if(bad==1) g->wire.data[30]=0; /* Epoch0 start=0. */
        if(bad==2) g->wire.data[52]=100; /* Unordered epoch1. */
        if(bad==3) g->wire.data[74]=100; /* Unordered epoch2. */
        if(bad==4) { g->wire.data[11]=15; memmove(g->wire.data+27,g->wire.data+28,g->wire.n-28); --g->wire.n; expected=MATTER_IM_CONSTRAINT_ERROR; }
        if(bad==5) { g->wire.data[11]=17; memmove(g->wire.data+29,g->wire.data+28,g->wire.n-28); g->wire.data[28]=0x42; ++g->wire.n; expected=MATTER_IM_CONSTRAINT_ERROR; }
        if(bad==6) { g->wire.data[28]=0x34; memmove(g->wire.data+30,g->wire.data+31,g->wire.n-31); --g->wire.n; } /* Null time with key. */
        if(bad==7) --g->wire.n; /* Truncated. */
        if(bad==8) g->wire.data[32]=2; /* Duplicate key field. */
        if(bad==9) { gk_args(&g->wire,0,7,0,100); }
        OC_CHECK(call(g,f,1,0)==expected && matter_groupkey_version(g->model)==version);
    }
    gk_args(&g->wire,0,7,3,100); OC_CHECK(call(g,f,0,0)==MATTER_IM_UNSUPPORTED_ACCESS && call(g,f,2,0)==MATTER_IM_UNSUPPORTED_ACCESS);
    f->control.fail_store=true; matter_fabric_host_control(f->host,&f->control);
    OC_CHECK(call(g,f,1,0)==MATTER_IM_FAILURE && matter_groupkey_version(g->model)==version);
    f->control.fail_store=false; matter_fabric_host_control(f->host,&f->control);
    hkdf_fail=hkdf_calls+2; OC_CHECK(call(g,f,1,0)==MATTER_IM_FAILURE && matter_groupkey_version(g->model)==version); hkdf_fail=0;
    OC_CHECK(!call(g,f,1,0) && matter_groupkey_version(g->model)==version+1);
    OC_CHECK(!call(g,f,1,0) && matter_groupkey_version(g->model)==version+1); /* Idempotent. */
    read_redacted(g,f,7,3,100);
    /* Deprecated multicast policy and supplied FabricIndex are ignored. */
    gk_args(&g->wire,0,7,1,200); g->wire.n-=2; gk_uint(&g->wire,8,1); gk_uint(&g->wire,254,2); gk_byte(&g->wire,0x18); gk_byte(&g->wire,0x18);
    OC_CHECK(!call(g,f,1,0)); read_redacted(g,f,7,1,200);
    for(unsigned id=8;id<11;++id) { gk_args(&g->wire,0,id,1,100); OC_CHECK(call(g,f,1,0)==(id==10?MATTER_IM_RESOURCE_EXHAUSTED:0)); }
    gk_args(&g->wire,3,0,0,0); OC_CHECK(call(g,f,1,3)==MATTER_IM_INVALID_COMMAND);
    gk_args(&g->wire,3,8,0,0); f->control.fail_store=true; matter_fabric_host_control(f->host,&f->control);
    OC_CHECK(call(g,f,1,3)==MATTER_IM_FAILURE); f->control.fail_store=false; matter_fabric_host_control(f->host,&f->control);
    OC_CHECK(!call(g,f,1,3) && call(g,f,1,3)==MATTER_GROUPKEY_NOT_FOUND);
    gk_args(&g->wire,1,8,0,0); OC_CHECK(call(g,f,1,1)==MATTER_GROUPKEY_NOT_FOUND);
    gk_args(&g->wire,4,0,0,0); OC_CHECK(!call(g,f,1,4));
    static const uint8_t ids[]={0x15,0x36,0,0x04,0,0x04,7,0x04,9,0x18,0x18};
    OC_CHECK(f->response_size==sizeof(ids) && !memcmp(ids,f->response,sizeof(ids)));
    /* Each accepted IPK epoch can receive CASE; initiator uses second newest. */
    gk_args(&g->wire,0,0,3,100); OC_CHECK(!call(g,f,1,0));
    for(unsigned candidate=0;candidate<3;++candidate) {
        OC_CHECK(cases.load(cases.user,5*candidate,&g->snapshot)==MATTER_OK);
        memset(f->ipk,candidate==0?0x43:candidate==1?0x42:0x44,16);
        OC_CHECK(matter_case_ipk(&crypto,f->ipk,f->port.view(f->host)->records[0].compressed_id,g->derived)==MATTER_OK && !memcmp(g->derived,g->snapshot.ipk,16));
    }
    case_establish(c); /* Initiator still has old 0x42: responder finds alternate. */
    Matter_Groupkey_Port_T client_port=matter_fabric_host_groupkey_port(c->fabrics[0]->host);
    Matter_Groupkey_T client=matter_groupkey_new(&client_port); OC_CHECK(client);
    for(unsigned epoch=1;epoch<3;++epoch) {
        gk_args(&g->wire,0,0,1,100); memset(g->wire.data+12,0x42+epoch,16);
        OC_CHECK(!matter_groupkey_invoke(client,1,0,g->wire.data,g->wire.n,NULL).status);
        for(unsigned i=0;i<2;++i) {
            OC_CHECK(matter_case_delete(c->session[i])==MATTER_OK);
            c->session[i]=matter_case_new(&crypto,&cp,&c->ports[i],&c->config[i],0); OC_CHECK(c->session[i]);
        }
        case_establish(c);
    }
    OC_CHECK(matter_groupkey_delete(client)==MATTER_OK);
    /* Disabled maximum-time slot is absent from CASE candidates, retained in read. */
    gk_args(&g->wire,0,0,1,UINT64_MAX); OC_CHECK(!call(g,f,1,0) && cases.load(cases.user,0,&g->snapshot)==MATTER_INVALID_STATE);
    read_redacted(g,f,0,1,UINT64_MAX);
    OC_CHECK(matter_fabric_host_commit(f->host)==MATTER_OK && matter_groupkey_delete(g->model)==MATTER_OK); g->model=NULL;
    fab_restart(f); g->port=matter_fabric_host_groupkey_port(f->host); g->model=matter_groupkey_new(&g->port); OC_CHECK(g->model); read_redacted(g,f,7,1,200);
    /* A second fabric cannot see/remove the first fabric's key set. */
    fab_csr(f,11); fab_request(f,11,FAB_CERT(fab_root),(Matter_Cert_Tlv_T){0},0); fab_call(f,1,11,true,0,0);
    fab_request(f,6,FAB_CERT(fab_noc1),(Matter_Cert_Tlv_T){0},101); fab_call(f,1,6,true,0,0);
    gk_args(&g->wire,1,7,0,0); OC_CHECK(call(g,f,2,1)==MATTER_GROUPKEY_NOT_FOUND);
    gk_args(&g->wire,3,7,0,0); OC_CHECK(call(g,f,2,3)==MATTER_GROUPKEY_NOT_FOUND);
    gk_args(&g->wire,0,7,1,300); OC_CHECK(!call(g,f,2,0)); read_redacted(g,f,7,1,200);
    OC_CHECK(matter_groupkey_delete(g->model)==MATTER_OK); fab_restart(f);
    g->port=matter_fabric_host_groupkey_port(f->host); g->model=matter_groupkey_new(&g->port); OC_CHECK(g->model);
    gk_args(&g->wire,1,7,0,0); OC_CHECK(call(g,f,2,1)==MATTER_IM_UNSUPPORTED_ACCESS); read_redacted(g,f,7,1,200);
    OC_CHECK(matter_groupkey_delete(g->model)==MATTER_OK); free(g); case_free(c);
    OC_CHECK(matter_crypto_mbedtls_delete(backend)==MATTER_OK);
#ifdef MATTER_TEST_ALLOC
    OC_CHECK(!live);
#endif
    puts("PASS Group Key Management: schema/redaction, atomic HKDF/store/remove, capacity, isolation, rollback/restart, rotating IPK CASE and disabled epoch"); return 0;
}
