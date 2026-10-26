#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/matter_operational_cert.h"
#include "crypto/matter_crypto_mbedtls.h"
#include "codec/matter_tlv.h"
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"Operational:%d: %s\n",__LINE__,#c); abort(); } } while(0)
#ifdef MATTER_TEST_ALLOC
static size_t live,calls,fail_at;
void* matter_test_calloc(size_t n,size_t s) { ++calls; if(calls==fail_at) return NULL; void* p=calloc(n,s); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { CHECK(live); --live; } free(p); }
#endif
#include "test_operational_vectors.h"
#include "test_synthetic_operational_vectors.h"
#define TLV(a) (Matter_Cert_Tlv_T){a,sizeof(a)}
typedef struct {
    Matter_Crypto_Mbedtls_T backend;
    Matter_Credentials_Port_T port;
    Matter_Crypto_Port_T crypto;
    Matter_Operational_Identity_T identity;
    uint8_t der[601],bad[401],saved[401];
    size_t size;
} Fixture;
static const Matter_Cert_Time_Policy_T now={MATTER_CERT_TIME_SUPPLIED,{2026,10,8,0,0,0}};
static bool filled(const void* data,size_t n,uint8_t v) { const uint8_t* p=data; for(size_t i=0;i<n;++i) if(p[i]!=v) return false; return true; }
static Matter_Result_T decode(Fixture* f,Matter_Cert_Tlv_T cert,Matter_Operational_Type_T type) {
    memset(f->der,0xa5,sizeof(f->der)); f->size=999;
    Matter_Result_T r=matter_operational_cert_decode(cert,type,f->der,600,&f->size);
    CHECK(f->der[600]==0xa5);
    if(r==MATTER_OK) CHECK(f->size<=600 && filled(f->der+f->size,600-f->size,0));
    else if(r==MATTER_PORT_ERROR) CHECK(!f->size && filled(f->der,600,0));
    return r;
}
/* Test-only inspection of a known fixture, not the production identity path. */
static uint64_t field(Matter_Cert_Tlv_T cert,unsigned list,unsigned tag) {
    Matter_Tlv_Reader_T r; Matter_Tlv_Element_T e; unsigned parent=0;
    CHECK(matter_tlv_init(&r,cert.data,cert.size,4)==MATTER_TLV_OK);
    while(matter_tlv_next(&r,&e)==MATTER_TLV_OK) {
        if(e.type==MATTER_TLV_LIST && r.depth==2) parent=e.tag.number;
        if(e.type==MATTER_TLV_END && r.depth==1) parent=0;
        if(parent==list && e.type==MATTER_TLV_UNSIGNED && e.tag.number==tag) return e.unsigned_value;
    }
    return 0;
}
static void compare_tbs(Fixture* f,const uint8_t* expected,size_t size) {
    /* Full certificate SEQUENCE header; the first child is the reference TBS. */
    CHECK(f->der[0]==0x30); size_t h=f->der[1]<128?2:2+(f->der[1]&127);
    CHECK(h+size<f->size && !memcmp(f->der+h,expected,size));
}
static void references(Fixture* f) {
    CHECK(decode(f,TLV(rs_chip_cert_input1),MATTER_CERT_ICAC)==MATTER_OK);
    compare_tbs(f,rs_asn1_output1,sizeof(rs_asn1_output1));
    CHECK(decode(f,TLV(rs_chip_cert_input2),MATTER_CERT_NOC)==MATTER_OK);
    compare_tbs(f,rs_asn1_output2,sizeof(rs_asn1_output2));
    CHECK(decode(f,TLV(rs_chip_cert_txt_in_dn),MATTER_CERT_RCAC)==MATTER_OK);
    compare_tbs(f,rs_asn1_output_txt_in_dn,sizeof(rs_asn1_output_txt_in_dn));
    for(size_t i=0;i<sizeof(reference)/sizeof(reference[0]);++i) {
        printf("Decode %s\n",reference[i].name); fflush(stdout);
        if((strstr(reference[i].name,"21_octet_noc_serial_noc") || strstr(reference[i].name,"smartthings_certificates_noc") || strstr(reference[i].name,"noc_signed_with_root"))) {
            CHECK(decode(f,reference[i].tlv,reference[i].type)==MATTER_PORT_ERROR); continue;
        }
        CHECK(decode(f,reference[i].tlv,reference[i].type)==MATTER_OK);
        if(reference[i].tbs.size) compare_tbs(f,reference[i].tbs.data,reference[i].tbs.size);
    }
    CHECK(decode(f,TLV(rs_noc1_success),MATTER_CERT_NOC)==MATTER_OK);
    CHECK(decode(f,TLV(rs_icac1_success),MATTER_CERT_ICAC)==MATTER_OK);
    CHECK(decode(f,TLV(rs_rca1_success),MATTER_CERT_RCAC)==MATTER_OK);
    CHECK(matter_operational_cert_verify(&f->port,TLV(rs_noc1_success),TLV(rs_icac1_success),TLV(rs_rca1_success),1,&now,&f->identity)==MATTER_OK);
    CHECK(f->identity.fabric_id==1 && f->identity.node_id==field(TLV(rs_noc1_success),6,17));
    for(size_t i=0;i<sizeof(chains)/sizeof(chains[0]);++i) {
        printf("Chain %s\n",chains[i].name); fflush(stdout);
        uint64_t fabric=field(chains[i].noc,6,21);
        Matter_Result_T expected=(strstr(chains[i].name,"21_octet") || strstr(chains[i].name,"smartthings") || strstr(chains[i].name,"noc_signed_with_root")) ? MATTER_PORT_ERROR : MATTER_OK;
        CHECK(matter_operational_cert_verify(&f->port,chains[i].noc,chains[i].icac,chains[i].root,fabric,&now,&f->identity)==expected);
        if(expected!=MATTER_OK) { CHECK(filled(&f->identity,sizeof(f->identity),0)); continue; }
        CHECK(f->identity.fabric_id==fabric && f->identity.node_id==field(chains[i].noc,6,17));
        uint64_t cat=field(chains[i].noc,6,22);
        CHECK(f->identity.cat_count==(cat?1:0));
        if(cat) CHECK(f->identity.cats[0]==cat);
    }
}
static void negatives(Fixture* f) {
    for(size_t i=1;i<sizeof(rs_noc1_success);++i) CHECK(decode(f,(Matter_Cert_Tlv_T){rs_noc1_success,i},MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    CHECK(decode(f,TLV(rs_noc1_success),MATTER_CERT_ICAC)==MATTER_PORT_ERROR);
    memcpy(f->bad,rs_noc1_success,sizeof(rs_noc1_success)); f->bad[sizeof(rs_noc1_success)]=0;
    CHECK(decode(f,(Matter_Cert_Tlv_T){f->bad,sizeof(rs_noc1_success)+1},MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    CHECK(matter_operational_cert_verify(&f->port,TLV(rs_noc1_success),TLV(rs_icac1_success),TLV(rs_rca1_success),2,&now,&f->identity)==MATTER_PORT_ERROR);
    CHECK(filled(&f->identity,sizeof(f->identity),0));
    f->bad[sizeof(rs_noc1_success)-2]^=1;
    CHECK(matter_operational_cert_verify(&f->port,(Matter_Cert_Tlv_T){f->bad,sizeof(rs_noc1_success)},TLV(rs_icac1_success),TLV(rs_rca1_success),1,&now,&f->identity)==MATTER_PORT_ERROR);
    CHECK(filled(&f->identity,sizeof(f->identity),0));
    Matter_Cert_Time_Policy_T time=now; time.now.year=2000;
    CHECK(matter_operational_cert_verify(&f->port,TLV(rs_noc1_success),TLV(rs_icac1_success),TLV(rs_rca1_success),1,&time,&f->identity)==MATTER_PORT_ERROR);
    time.now.year=2200;
    CHECK(matter_operational_cert_verify(&f->port,TLV(rs_noc1_success),TLV(rs_icac1_success),TLV(rs_rca1_success),1,&time,&f->identity)==MATTER_PORT_ERROR);
}
static size_t offset(Matter_Cert_Tlv_T cert,unsigned list,unsigned tag) {
    Matter_Tlv_Reader_T r; Matter_Tlv_Element_T e; unsigned parent=0;
    CHECK(matter_tlv_init(&r,cert.data,cert.size,4)==MATTER_TLV_OK);
    while(matter_tlv_next(&r,&e)==MATTER_TLV_OK) {
        unsigned depth=r.depth-(e.type==MATTER_TLV_STRUCTURE||e.type==MATTER_TLV_ARRAY||e.type==MATTER_TLV_LIST);
        if(parent==list && depth==(list?2u:1u) && e.tag.control==1 && e.tag.number==tag) return e.offset;
        if(list && parent==list && e.type==MATTER_TLV_END && r.depth==1 && !tag) return e.offset;
        if(e.type==MATTER_TLV_LIST && r.depth==2) parent=e.tag.number;
        if(e.type==MATTER_TLV_END && r.depth==1) parent=0;
    }
    CHECK(false); return 0;
}
static Matter_Cert_Tlv_T edit(Fixture* f,Matter_Cert_Tlv_T original,size_t at,size_t remove,const uint8_t* add,size_t size) {
    CHECK(at<=original.size && remove<=original.size-at && original.size-remove+size<=sizeof(f->bad));
    memcpy(f->bad,original.data,at);
    if(size) memcpy(f->bad+at,add,size);
    memcpy(f->bad+at+size,original.data+at+remove,original.size-at-remove);
    return (Matter_Cert_Tlv_T){f->bad,original.size-remove+size};
}
static void schema(Fixture* f) {
    Matter_Cert_Tlv_T noc=TLV(js_general_test_certificates_noc_tlv);
    /* Three distinct CATs and their order match an independent matter.js TBS. */
    static const uint8_t cats[]={0x26,22,0x78,0x56,0x34,0x12,0x26,22,0x12,0x90,0x78,0x56,0x26,22,0x56,0x34,0x12,0x90};
    size_t end=offset(noc,6,0);
    Matter_Cert_Tlv_T changed=edit(f,noc,end,0,cats,sizeof(cats));
    CHECK(decode(f,changed,MATTER_CERT_NOC)==MATTER_OK);
    compare_tbs(f,js_cat_tbs,sizeof(js_cat_tbs));
    f->bad[end+2]=f->bad[end+3]=0; /* Version zero. */
    CHECK(decode(f,changed,MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    changed=edit(f,noc,end,0,cats,sizeof(cats));
    f->bad[end+10]=f->bad[end+4]; f->bad[end+11]=f->bad[end+5]; /* Same ID, different version. */
    CHECK(decode(f,changed,MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    static const uint8_t too_many[]={0x24,22,1,0x26,22,1,0,1,0,0x26,22,1,0,2,0,0x26,22,1,0,3,0};
    CHECK(decode(f,edit(f,noc,end,0,too_many,sizeof(too_many)),MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    for(unsigned tag=17;tag<=21;tag+=4) {
        size_t at=offset(noc,6,tag);
        changed=edit(f,noc,at+2,1,(const uint8_t[]){0},1);
        CHECK(decode(f,changed,MATTER_CERT_NOC)==MATTER_PORT_ERROR);
        CHECK(decode(f,edit(f,noc,end,0,noc.data+at,3),MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    }
    static const uint8_t reserved[]={0x27,17,0,0,0,0,0xf0,0xff,0xff,0xff};
    CHECK(decode(f,edit(f,noc,offset(noc,6,17),3,reserved,sizeof(reserved)),MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    for(unsigned tag=2;tag<=8;tag+=(tag==2?5:1)) {
        size_t at=offset(noc,0,tag);
        CHECK(decode(f,edit(f,noc,at+2,1,(const uint8_t[]){2},1),MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    }
    size_t at=offset(noc,10,2);
    CHECK(decode(f,edit(f,noc,at+2,1,(const uint8_t[]){5},1),MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    CHECK(decode(f,edit(f,noc,at,3,NULL,0),MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    CHECK(decode(f,edit(f,noc,at,0,noc.data+at,3),MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    at=offset(noc,10,3);
    changed=edit(f,noc,at+3,1,(const uint8_t[]){1},1); /* Duplicate serverAuth. */
    CHECK(decode(f,changed,MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    at=offset(noc,10,4)+3;
    changed=edit(f,noc,at,1,(const uint8_t[]){0},1); /* Derived SKID differs. */
    CHECK(decode(f,changed,MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    /* Unknown noncritical extensions survive DER reconstruction; duplicate
     * OIDs, unknown critical OIDs and disguised known extensions are rejected. */
    static const uint8_t unknown[]={0x30,6,8,0x30,6,6,2,0x2a,3,4,0};
    end=offset(noc,10,0); changed=edit(f,noc,end,0,unknown,sizeof(unknown));
    CHECK(decode(f,changed,MATTER_CERT_NOC)==MATTER_OK);
    uint8_t pair[22]; memcpy(pair,unknown,11); memcpy(pair+11,unknown,11);
    CHECK(decode(f,edit(f,noc,end,0,pair,sizeof(pair)),MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    pair[19]=4;
    CHECK(decode(f,edit(f,noc,end,0,pair,sizeof(pair)),MATTER_CERT_NOC)==MATTER_OK);
    static const uint8_t critical[]={0x30,6,11,0x30,9,6,2,0x2a,3,1,1,255,4,0};
    CHECK(decode(f,edit(f,noc,end,0,critical,sizeof(critical)),MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    static const uint8_t disguised[]={0x30,6,9,0x30,7,6,3,0x55,0x1d,19,4,0};
    CHECK(decode(f,edit(f,noc,end,0,disguised,sizeof(disguised)),MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    /* Changed TBS with the original signature must never yield identity. */
    changed=edit(f,noc,end,0,unknown,sizeof(unknown));
    CHECK(matter_operational_cert_verify(&f->port,changed,(Matter_Cert_Tlv_T){0},TLV(js_general_test_certificates_root_tlv),1,&now,&f->identity)==MATTER_PORT_ERROR);
    CHECK(filled(&f->identity,sizeof(f->identity),0));
    /* Five RDNs in each DN fit TLV but can exceed the 600-byte DER limit. */
    changed=edit(f,noc,offset(noc,6,0),0,cats,sizeof(cats));
    memcpy(f->saved,changed.data,changed.size);
    Matter_Cert_Tlv_T saved={f->saved,changed.size};
    static const uint8_t names[]={0x2c,1,5,'a','b','c','d','e',0x2c,2,5,'a','b','c','d','e',
        0x2c,3,5,'a','b','c','d','e',0x2c,4,5,'a','b','c','d','e'};
    CHECK(decode(f,edit(f,saved,offset(saved,3,0),0,names,sizeof(names)),MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    /* Root pathLen=0 disallows an ICAC, independently of the trusted root's
     * ignored self-signature. Missing ICAC or a different trusted root fails. */
    Matter_Cert_Tlv_T root=TLV(rs_rca1_success);
    static const uint8_t path0[]={0x24,2,0};
    changed=edit(f,root,offset(root,10,1)+4,0,path0,sizeof(path0));
    CHECK(decode(f,changed,MATTER_CERT_RCAC)==MATTER_OK);
    CHECK(matter_operational_cert_verify(&f->port,TLV(rs_noc1_success),TLV(rs_icac1_success),changed,1,&now,&f->identity)==MATTER_PORT_ERROR);
    CHECK(matter_operational_cert_verify(&f->port,TLV(rs_noc1_success),(Matter_Cert_Tlv_T){0},root,1,&now,&f->identity)==MATTER_PORT_ERROR);
    CHECK(matter_operational_cert_verify(&f->port,TLV(rs_noc1_success),TLV(rs_icac1_success),TLV(js_general_test_certificates_root_tlv),1,&now,&f->identity)==MATTER_PORT_ERROR);
    /* Correct trusted root requires no self-signature verification. */
    changed=edit(f,root,root.size-2,1,(const uint8_t[]){0},1);
    CHECK(matter_operational_cert_verify(&f->port,TLV(rs_noc1_success),TLV(rs_icac1_success),changed,1,&now,&f->identity)==MATTER_OK);
    /* CA Fabric ID mismatch and wrong issuer linkage must clear identity. */
    changed=edit(f,root,offset(root,6,21)+2,1,(const uint8_t[]){2},1);
    f->bad[offset(root,3,21)+2]=2;
    CHECK(decode(f,changed,MATTER_CERT_RCAC)==MATTER_OK);
    CHECK(matter_operational_cert_verify(&f->port,TLV(rs_noc1_success),TLV(rs_icac1_success),changed,1,&now,&f->identity)==MATTER_PORT_ERROR);
    CHECK(filled(&f->identity,sizeof(f->identity),0));
}
static Matter_Result_T root_backend_failure(void* user,const uint8_t key[65],const uint8_t* message,
    size_t size,const uint8_t signature[64]) {
    (void)user; (void)key; (void)message; (void)size; (void)signature; return MATTER_BUSY;
}
static void root_admission(Fixture* f) {
    const Matter_Cert_Tlv_T roots[]={TLV(rs_rca1_success),TLV(js_general_test_certificates_root_tlv),TLV(synthetic_root_tlv)};
    for(unsigned i=0;i<3;++i) {
        Matter_Cert_Tlv_T root=roots[i];
        CHECK(matter_operational_cert_verify_root(&f->crypto,root)==MATTER_OK);
        const size_t positions[]={offset(root,0,11)+3,root.size-2,offset(root,0,1)+3};
        for(unsigned j=0;j<3;++j) {
            memcpy(f->bad,root.data,root.size); f->bad[positions[j]]^=1;
            Matter_Cert_Tlv_T bad={f->bad,root.size};
            CHECK(decode(f,bad,MATTER_CERT_RCAC)==MATTER_OK);
            CHECK(matter_operational_cert_verify_root(&f->crypto,bad)==MATTER_PORT_ERROR);
        }
        for(size_t size=1;size<root.size;++size)
            CHECK(matter_operational_cert_verify_root(&f->crypto,(Matter_Cert_Tlv_T){root.data,size})==MATTER_PORT_ERROR);
    }
    /* Opaque extension contents are part of the signed TBS, including RCAC. */
    memcpy(f->bad,synthetic_root_tlv,sizeof(synthetic_root_tlv));
    f->bad[offset(TLV(synthetic_root_tlv),10,0)-1]^=1;
    CHECK(decode(f,(Matter_Cert_Tlv_T){f->bad,sizeof(synthetic_root_tlv)},MATTER_CERT_RCAC)==MATTER_OK);
    CHECK(matter_operational_cert_verify_root(&f->crypto,(Matter_Cert_Tlv_T){f->bad,sizeof(synthetic_root_tlv)})==MATTER_PORT_ERROR);
    CHECK(matter_operational_cert_verify_root(&f->crypto,TLV(rs_noc1_success))==MATTER_PORT_ERROR);
    CHECK(matter_operational_cert_verify_root(&f->crypto,(Matter_Cert_Tlv_T){0})==MATTER_INVALID_ARGUMENT);
    CHECK(matter_operational_cert_verify_root(&f->crypto,(Matter_Cert_Tlv_T){f->bad,401})==MATTER_LIMIT_REACHED);
    CHECK(matter_operational_cert_verify_root(NULL,roots[0])==MATTER_INVALID_ARGUMENT);
    Matter_Crypto_Port_T port=f->crypto; port.ecdsa_verify=NULL;
    CHECK(matter_operational_cert_verify_root(&port,roots[0])==MATTER_INVALID_ARGUMENT);
    port.ecdsa_verify=root_backend_failure;
    CHECK(matter_operational_cert_verify_root(&port,roots[0])==MATTER_BUSY);
    CHECK(matter_operational_cert_verify_root(&f->crypto,roots[0])==MATTER_OK);
    puts("PASS RCAC admission: valid signatures, changed r/s/TBS/future extension, truncation, bounds, backend recovery");
}
static void bounds(Fixture* f) {
    memset(f->der,0xa5,sizeof(f->der)); f->size=999;
    CHECK(matter_operational_cert_decode(TLV(rs_noc1_success),MATTER_CERT_NOC,f->der,599,&f->size)==MATTER_LIMIT_REACHED);
    CHECK(f->size==999 && filled(f->der,sizeof(f->der),0xa5));
    CHECK(matter_operational_cert_decode((Matter_Cert_Tlv_T){f->bad,401},MATTER_CERT_NOC,f->der,600,&f->size)==MATTER_LIMIT_REACHED);
    CHECK(matter_operational_cert_decode((Matter_Cert_Tlv_T){0},MATTER_CERT_NOC,f->der,600,&f->size)==MATTER_INVALID_ARGUMENT);
    memset(&f->identity,0xa5,sizeof(f->identity));
    CHECK(matter_operational_cert_verify(&f->port,TLV(rs_noc1_success),(Matter_Cert_Tlv_T){0},TLV(rs_rca1_success),0,&now,&f->identity)==MATTER_INVALID_ARGUMENT);
    CHECK(filled(&f->identity,sizeof(f->identity),0xa5));
    Matter_Cert_Time_Policy_T time={MATTER_CERT_TIME_LEAF_NOT_BEFORE,{0}};
    CHECK(matter_operational_cert_verify(&f->port,TLV(rs_noc1_success),TLV(rs_icac1_success),TLV(rs_rca1_success),1,&time,&f->identity)==MATTER_INVALID_ARGUMENT);
    CHECK(filled(&f->identity,sizeof(f->identity),0xa5));
    time=(Matter_Cert_Time_Policy_T){MATTER_CERT_TIME_LAST_KNOWN_GOOD,{2000,1,1,0,0,0}};
    CHECK(matter_operational_cert_verify(&f->port,TLV(rs_noc1_success),TLV(rs_icac1_success),TLV(rs_rca1_success),1,&time,&f->identity)==MATTER_OK);
    time.now.year=2099;
    CHECK(matter_operational_cert_verify(&f->port,TLV(rs_noc1_success),TLV(rs_icac1_success),TLV(rs_rca1_success),1,&time,&f->identity)==MATTER_PORT_ERROR);
    CHECK(filled(&f->identity,sizeof(f->identity),0));
}
static void future_chain(Fixture* f) {
    const Matter_Cert_Tlv_T tlv[]={TLV(synthetic_noc_tlv),TLV(synthetic_icac_tlv),TLV(synthetic_root_tlv)};
    const Matter_Der_T der[]={{synthetic_noc_der,sizeof(synthetic_noc_der)},{synthetic_icac_der,sizeof(synthetic_icac_der)},
        {synthetic_root_der,sizeof(synthetic_root_der)}};
    CHECK(f->port.operational_verify_chain);
    for(unsigned i=0;i<3;++i) {
        CHECK(decode(f,tlv[i],(Matter_Operational_Type_T)i)==MATTER_OK);
        CHECK(f->size==der[i].size && !memcmp(f->der,der[i].data,f->size));
    }
    CHECK(f->port.cert_verify_chain(f->port.user,der[0],der[1],der[2],&now,f->identity.public_key)==MATTER_PORT_ERROR);
    CHECK(matter_operational_cert_verify(&f->port,tlv[0],tlv[1],tlv[2],1,&now,&f->identity)==MATTER_OK);
    CHECK(f->identity.node_id==UINT64_C(23) && f->identity.fabric_id==1);
    /* Unsupported future contents are ignored semantically, NEVER unsigned. */
    for(unsigned cert=0;cert<2;++cert) {
        for(unsigned which=0;which<3;++which) {
            Matter_Cert_Tlv_T changed[3]={tlv[0],tlv[1],tlv[2]};
            memcpy(f->bad,tlv[cert].data,tlv[cert].size);
            changed[cert]=(Matter_Cert_Tlv_T){f->bad,tlv[cert].size};
            size_t at=which==0?offset(tlv[cert],10,0)-1: /* opaque value */
                which==1?offset(tlv[cert],0,11)+3: /* signature */
                offset(tlv[cert],10,6)+3; /* future OID, located below */
            if(which==2) {
                at=offset(tlv[cert],10,6)+3;
                while(at+2<tlv[cert].size && !(f->bad[at]==0x55 && f->bad[at+1]==0x1d && f->bad[at+2]==17)) ++at;
                CHECK(at+2<tlv[cert].size); at+=2;
            }
            f->bad[at]^=1;
            CHECK(decode(f,changed[cert],(Matter_Operational_Type_T)cert)==MATTER_OK);
            memset(&f->identity,0xa5,sizeof(f->identity));
            CHECK(matter_operational_cert_verify(&f->port,changed[0],changed[1],changed[2],1,&now,&f->identity)==MATTER_PORT_ERROR);
            CHECK(filled(&f->identity,sizeof(f->identity),0));
        }
    }
    /* Critical unknown, duplicate OID and disguised known OID cannot use this
     * adapter to evade profile validation, even with a valid original chain. */
    const uint8_t critical[]={0x30,6,12,0x30,10,6,3,0x55,0x1d,17,1,1,255,4,0};
    size_t at=offset(tlv[0],10,6),end=offset(tlv[0],10,0);
    Matter_Cert_Tlv_T changed=edit(f,tlv[0],at,end-at,critical,sizeof(critical));
    CHECK(matter_operational_cert_verify(&f->port,changed,tlv[1],tlv[2],1,&now,&f->identity)==MATTER_PORT_ERROR);
    CHECK(filled(&f->identity,sizeof(f->identity),0));
    const uint8_t extra[]={0x30,6,9,0x30,7,6,3,0x55,0x1d,17,4,0};
    changed=edit(f,tlv[0],end,0,extra,sizeof(extra));
    CHECK(decode(f,changed,MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    f->bad[end+9]=19;
    CHECK(decode(f,changed,MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    CHECK(matter_operational_cert_verify(&f->port,tlv[0],tlv[1],tlv[2],2,&now,&f->identity)==MATTER_PORT_ERROR);
    Matter_Cert_Time_Policy_T expired=now; expired.now.year=2040;
    CHECK(matter_operational_cert_verify(&f->port,tlv[0],tlv[1],tlv[2],1,&expired,&f->identity)==MATTER_PORT_ERROR);
    CHECK(matter_operational_cert_verify(&f->port,tlv[0],tlv[1],TLV(rs_rca1_success),1,&now,&f->identity)==MATTER_PORT_ERROR);
    /* Legacy adapters remain source-compatible and fail closed on this chain. */
    Matter_Credentials_Port_T legacy=f->port; legacy.operational_verify_chain=NULL;
    CHECK(matter_operational_cert_verify(&legacy,tlv[0],tlv[1],tlv[2],1,&now,&f->identity)==MATTER_PORT_ERROR);
    CHECK(matter_operational_cert_verify(&f->port,tlv[0],tlv[1],tlv[2],1,&now,&f->identity)==MATTER_OK);
    puts("PASS synthetic padded chain, exact DER, independently signed TBS, strict generic X.509, critical/duplicate/profile/time/trust negatives");
}
#ifdef MATTER_TEST_ALLOC
static void allocations(Fixture* f) {
    size_t baseline=live; calls=0; fail_at=1;
    CHECK(decode(f,TLV(rs_noc1_success),MATTER_CERT_NOC)==MATTER_PORT_ERROR);
    CHECK(live==baseline); fail_at=0; calls=0;
    const Matter_Cert_Tlv_T cases[][3]={
        {TLV(rs_noc1_success),TLV(rs_icac1_success),TLV(rs_rca1_success)},
        {TLV(synthetic_noc_tlv),TLV(synthetic_icac_tlv),TLV(synthetic_root_tlv)}};
    for(unsigned chain=0;chain<2;++chain) {
        const Matter_Cert_Tlv_T* certs=cases[chain];
        fail_at=0; calls=0;
        CHECK(matter_operational_cert_verify(&f->port,certs[0],certs[1],certs[2],1,&now,&f->identity)==MATTER_OK);
        size_t positions=calls;
        for(size_t i=1;i<=positions;++i) {
            calls=0; fail_at=i; memset(&f->identity,0xa5,sizeof(f->identity));
            Matter_Result_T r=matter_operational_cert_verify(&f->port,certs[0],certs[1],certs[2],1,&now,&f->identity);
            CHECK(r==MATTER_OK || r==MATTER_PORT_ERROR);
            if(r!=MATTER_OK) CHECK(filled(&f->identity,sizeof(f->identity),0));
            else CHECK(f->identity.fabric_id==1 && f->identity.node_id==field(certs[0],6,17));
            CHECK(live==baseline);
        }
        printf("Operational OOM chain%u positions: %zu; balanced and recovery OK\n",chain,positions);
    }
    fail_at=0;
    calls=0;
    CHECK(matter_operational_cert_verify_root(&f->crypto,TLV(synthetic_root_tlv))==MATTER_OK);
    size_t root_positions=calls;
    for(size_t i=1;i<=root_positions;++i) {
        calls=0; fail_at=i;
        Matter_Result_T r=matter_operational_cert_verify_root(&f->crypto,TLV(synthetic_root_tlv));
        CHECK(r==MATTER_PORT_ERROR && live==baseline);
    }
    fail_at=0;
    CHECK(matter_operational_cert_verify_root(&f->crypto,TLV(synthetic_root_tlv))==MATTER_OK);
    printf("RCAC admission OOM positions: %zu; balanced and recovery OK\n",root_positions);
    CHECK(matter_operational_cert_verify(&f->port,TLV(rs_noc1_success),TLV(rs_icac1_success),TLV(rs_rca1_success),1,&now,&f->identity)==MATTER_OK);
}
#endif
int main(int argc,char** argv) {
    Fixture* f=calloc(1,sizeof(*f)); CHECK(f);
    f->backend=matter_crypto_mbedtls_new(NULL); CHECK(f->backend);
    CHECK(matter_crypto_mbedtls_credentials(f->backend,&f->port)==MATTER_OK);
    CHECK(matter_crypto_mbedtls_port(f->backend,&f->crypto)==MATTER_OK);
    references(f); negatives(f); schema(f); bounds(f); future_chain(f); root_admission(f);
#ifdef MATTER_TEST_ALLOC
    allocations(f);
#endif
    if(argc==4) {
        const Matter_Cert_Tlv_T certs[]={TLV(rs_noc1_success),TLV(rs_icac1_success),TLV(rs_rca1_success)};
        for(unsigned i=0;i<3;++i) {
            CHECK(decode(f,certs[i],(Matter_Operational_Type_T)i)==MATTER_OK);
            FILE* file=fopen(argv[i+1],"wb"); CHECK(file);
            CHECK(fwrite(f->der,1,f->size,file)==f->size); CHECK(!fclose(file));
        }
    }
    CHECK(matter_crypto_mbedtls_delete(f->backend)==MATTER_OK);
#ifdef MATTER_TEST_ALLOC
    CHECK(!live);
#endif
    free(f); puts("Matter operational certificates: PASS"); return 0;
}
