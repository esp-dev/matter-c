#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/matter_crypto_mbedtls.h"
#include "test_case_fixture.h"
#ifdef MATTER_TEST_ALLOC
static size_t live,calls,fail_at;
void* matter_test_calloc(size_t n,size_t z) { if(++calls==fail_at) return NULL; void* p=calloc(n,z); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { OC_CHECK(live); --live; } free(p); }
#endif
static Matter_Result_T admit(void* u,const Matter_Secure_Received_T* m) {
    CaseFixture* f=u; ++f->admitted; OC_CHECK(m->protocol.protocol_id==1);
    if(!m->duplicate) OC_CHECK(m->size==1 && m->payload[0]==0x15);
    return MATTER_OK;
}
static void hex(const char* s,uint8_t* out) { while(*s) { unsigned v; OC_CHECK(sscanf(s,"%2x",&v)==1); *out++=(uint8_t)v; s+=2; } }
/* Known public TEST scalars let an independent OpenSSL oracle reconstruct ECDH. */
static unsigned test_scalar;
static Matter_Result_T scalar(void* u,uint8_t out[32]) { (void)u; memset(out,0,32); out[31]=(uint8_t)test_scalar++; return MATTER_OK; }
static void save(const char* dir,const char* name,const void* data,size_t n) {
    char* path=malloc(strlen(dir)+strlen(name)+2); OC_CHECK(path); sprintf(path,"%s/%s",dir,name);
    FILE* file=fopen(path,"wb"); OC_CHECK(file); OC_CHECK(fwrite(data,1,n,file)==n && fclose(file)==0); free(path);
}
static void export_resume(CaseFixture*,const Matter_Credentials_Port_T*,const char*);
static void export_case(const char* dir,const Matter_Crypto_Port_T* crypto,const Matter_Credentials_Port_T* cp,bool chip) {
    Matter_Crypto_Port_T deterministic=*crypto; deterministic.p256_scalar=scalar; test_scalar=21;
    CaseFixture* f=case_fixture(&deterministic,cp); OC_CHECK(matter_case_process(f->session[0],0)==MATTER_PENDING);
    const char* names[]={"sigma1.bin","sigma2.bin","sigma3.bin"};
    for(unsigned i=0;i<3;++i) { Matter_Pase_Message_T m; OC_CHECK(matter_case_output(f->session[i%2],&m)==MATTER_OK); save(dir,names[i],m.data,m.size); case_step(f,i%2,i+1); }
    case_step(f,1,4); OC_CHECK(matter_case_confirm_delivery(f->session[1],5)==MATTER_OK);
    f->secure[0]=matter_secure_new_case(crypto,f->session[0],5); OC_CHECK(f->secure[0]);
    OC_CHECK(matter_secure_challenge(f->secure[0],f->bytes)==MATTER_OK); save(dir,"challenge.bin",f->bytes,16);
    static const uint8_t plain[]={1,2,0x34,0x12,1,0,0x15};
    OC_CHECK(matter_secure_seal(f->secure[0],plain,sizeof(plain),6,f->packet,sizeof(f->packet),&f->size)==MATTER_OK); save(dir,"secure.bin",f->packet,f->size);
    for(unsigned i=0;i<2;++i) f->config[i].resumption_profile=chip?MATTER_CASE_RESUMPTION_CHIP:MATTER_CASE_RESUMPTION_SPEC;
    export_resume(f,cp,dir); case_free(f);
}
/* Fault injection at the local provisioned port; the peer must independently
 * reject a bad chain/proof/identity even when CCM and ECDH are valid. */
static Matter_Case_Port_T original;
static unsigned fault;
static const uint8_t* replacement; static size_t replacement_size;
static Matter_Result_T load_changed(void* u,unsigned slot,Matter_Case_Fabric_T* out) {
    Matter_Result_T r=original.load(u,slot,out);
    if(r==MATTER_OK) {
        if(replacement) { OC_CHECK(replacement_size<=sizeof(out->noc)); memcpy(out->noc,replacement,replacement_size); out->noc_size=(uint16_t)replacement_size; }
        else if(fault==0) out->noc[out->noc_size-2]^=1;
        else if(fault==2) { memcpy(out->noc,fab_conflict,sizeof(fab_conflict)); out->noc_size=sizeof(fab_conflict); }
        else if(fault==3) { memcpy(out->noc,fab_noc1,sizeof(fab_noc1)); out->noc_size=sizeof(fab_noc1); }
    }
    return r;
}
static Matter_Result_T sign_changed(void* u,uint8_t index,const uint8_t* msg,size_t n,uint8_t sig[64]) {
    Matter_Result_T r=original.sign(u,index,msg,n,sig); if(r==MATTER_OK && fault==1) sig[0]^=1; return r;
}
static void peer_rejection(const Matter_Crypto_Port_T* crypto,const Matter_Credentials_Port_T* cp) {
    for(fault=0;fault<6;++fault) {
        CaseFixture* f=case_fixture(crypto,cp); original=f->ports[1]; replacement=NULL;
        if(fault<4) { f->ports[1].load=load_changed; f->ports[1].sign=sign_changed; }
        OC_CHECK(matter_case_delete(f->session[1])==MATTER_OK);
        f->session[1]=matter_case_new(crypto,cp,&f->ports[1],&f->config[1],0); OC_CHECK(f->session[1]);
        if(fault==4) {
            f->config[0].time.now.year=2050;
            OC_CHECK(matter_case_delete(f->session[0])==MATTER_OK);
            f->session[0]=matter_case_new(crypto,cp,&f->ports[0],&f->config[0],0); OC_CHECK(f->session[0]);
        }
        OC_CHECK(matter_case_process(f->session[0],0)==MATTER_PENDING);
        Matter_Pase_Message_T m;
        if(fault==5) {
            OC_CHECK(matter_case_output(f->session[0],&m)==MATTER_OK); memcpy(f->bytes,m.data,m.size-1);
            /* Unknown context field: accepted, but bound into exact transcript. */
            memcpy(f->bytes+m.size-1,(const uint8_t[]){0x24,8,1,0x18},4);
            OC_CHECK(matter_case_receive(f->session[1],m.opcode,f->bytes,m.size+3)==MATTER_OK && matter_case_sent(f->session[0])==MATTER_OK && matter_case_process(f->session[1],1)==MATTER_PENDING);
        } else case_step(f,0,1);
        OC_CHECK(matter_case_output(f->session[1],&m)==MATTER_OK && m.opcode==0x31);
        OC_CHECK(matter_case_receive(f->session[0],m.opcode,m.data,m.size)==MATTER_OK && matter_case_process(f->session[0],2)==MATTER_PORT_ERROR);
        OC_CHECK(matter_case_take_keys(f->session[0],&f->keys[0])==MATTER_INVALID_STATE); case_free(f);
    }
}
static size_t der_header(const uint8_t* p,size_t* size) {
    size_t h=2,n=p[1]; if(n&128) { unsigned count=(unsigned)n&127; n=0; for(unsigned i=0;i<count;++i) n=(n<<8)|p[h++]; } *size=n; return h;
}
static void resume_new(CaseFixture*,const Matter_Credentials_Port_T*);
static void resume_exchange(CaseFixture*,bool);
static void resume_take(CaseFixture*);
static void cat_identity(const Matter_Crypto_Port_T* crypto,const Matter_Credentials_Port_T* cp) {
    CaseFixture* f=case_fixture(crypto,cp); FabFixture* m=f->fabrics[0]; size_t at=0,n=sizeof(fab_conflict); bool subject=false;
    OC_CHECK(matter_tlv_init(&m->reader,fab_conflict,n,4)==MATTER_TLV_OK);
    while(matter_tlv_next(&m->reader,&m->e)==MATTER_TLV_OK) {
        if(m->e.type==MATTER_TLV_LIST && m->e.tag.number==6) subject=true;
        if(subject && m->e.type==MATTER_TLV_END) { at=m->e.offset; break; }
    }
    OC_CHECK(at && n+6<=sizeof(m->changed)); memcpy(m->changed,fab_conflict,at);
    memcpy(m->changed+at,(const uint8_t[]){0x26,22,2,0,0x34,0x12},6); memcpy(m->changed+at+6,fab_conflict+at,n-at); n+=6;
    size_t der_size,tbs_size,h; OC_CHECK(matter_operational_cert_decode((Matter_Cert_Tlv_T){m->changed,n},MATTER_CERT_NOC,f->bytes,600,&der_size)==MATTER_OK);
    h=der_header(f->bytes,&tbs_size); size_t th=der_header(f->bytes+h,&tbs_size); OC_CHECK(h+th+tbs_size<=der_size);
    uint8_t root_key[32]={0}; root_key[31]=8;
    OC_CHECK(crypto->ecdsa_sign(crypto->user,root_key,f->bytes+h,th+tbs_size,m->signature)==MATTER_OK);
    /* Signature is final context bytes field, then anonymous structure end. */
    OC_CHECK(m->changed[n-68]==0x30 && m->changed[n-67]==11 && m->changed[n-66]==64); memcpy(m->changed+n-65,m->signature,64);
    original=f->ports[0]; replacement=m->changed; replacement_size=n; f->ports[0].load=load_changed;
    OC_CHECK(matter_case_delete(f->session[0])==MATTER_OK);
    f->session[0]=matter_case_new(crypto,cp,&f->ports[0],&f->config[0],0); OC_CHECK(f->session[0]); case_establish(f);
    f->secure[1]=matter_secure_new_case(crypto,f->session[1],5); OC_CHECK(f->secure[1]);
    Matter_Secure_Identity_T id; OC_CHECK(matter_secure_identity(f->secure[1],&id)==MATTER_OK && id.cat_count==1 && id.cats[0]==0x12340002 && id.peer_node_id==101);
    OC_CHECK(matter_case_take_keys(f->session[0],&f->keys[0])==MATTER_OK);
    resume_new(f,cp); resume_exchange(f,true); resume_take(f);
    OC_CHECK(f->keys[1].identity.cat_count==1 && f->keys[1].identity.cats[0]==0x12340002 && f->keys[1].identity.peer_node_id==101);
    puts("PASS resumed CAT identity from previously verified peer NOC");
    replacement=NULL; case_free(f);
}
static void sigma_schema(const Matter_Crypto_Port_T* crypto,const Matter_Credentials_Port_T* cp) {
    for(unsigned mode=0;mode<3;++mode) {
        CaseFixture* f=case_fixture(crypto,cp); OC_CHECK(matter_case_process(f->session[0],0)==MATTER_PENDING);
        Matter_Pase_Message_T m; OC_CHECK(matter_case_output(f->session[0],&m)==MATTER_OK); memcpy(f->bytes,m.data,m.size-1); size_t n=m.size-1;
        if(mode==0) {
            /* Explicit peer MRP intervals, leaving local defaults unchanged. */
            static const uint8_t params[]={0x35,5,0x25,1,0xe8,3,0x24,2,250,0x25,3,0xd0,7,0x18};
            memcpy(f->bytes+n,params,sizeof(params)); n+=sizeof(params);
        } else {
            f->bytes[n++]=0x30; f->bytes[n++]=6; f->bytes[n++]=16; memset(f->bytes+n,0,16); n+=16;
            if(mode==1) { f->bytes[n++]=0x30; f->bytes[n++]=7; f->bytes[n++]=16; memset(f->bytes+n,0,16); n+=16; }
        }
        f->bytes[n++]=0x18;
        OC_CHECK(matter_case_receive(f->session[1],0x30,f->bytes,n)==MATTER_OK);
        OC_CHECK(matter_case_process(f->session[1],1)==(mode==2?MATTER_PORT_ERROR:MATTER_PENDING));
        OC_CHECK(matter_case_output(f->session[1],&m)==MATTER_OK && m.opcode==(mode==2?0x40:0x31));
        if(mode==0) { Matter_Pase_Intervals_T intervals; OC_CHECK(matter_case_peer_intervals(f->session[1],&intervals)==MATTER_OK && intervals.idle_ms==1000 && intervals.active_ms==250 && intervals.active_threshold_ms==2000); }
        OC_CHECK(matter_case_cancel(f->session[1])==MATTER_OK && matter_case_take_keys(f->session[1],&f->keys[1])==MATTER_INVALID_STATE); case_free(f);
    }
}
#include "test_case_resumption.h"
static void export_resume(CaseFixture* f,const Matter_Credentials_Port_T* cp,const char* dir) {
    OC_CHECK(matter_case_take_keys(f->session[1],&f->keys[1])==MATTER_OK);
    resume_new(f,cp); OC_CHECK(matter_case_process(f->session[0],0)==MATTER_PENDING);
    Matter_Pase_Message_T m; OC_CHECK(matter_case_output(f->session[0],&m)==MATTER_OK);
    save(dir,"resume1.bin",m.data,m.size); case_step(f,0,1);
    OC_CHECK(matter_case_output(f->session[1],&m)==MATTER_OK && m.opcode==0x33);
    save(dir,"resume2.bin",m.data,m.size); case_step(f,1,2); case_step(f,0,3);
    OC_CHECK(matter_case_confirm_delivery(f->session[0],4)==MATTER_OK);
    OC_CHECK(matter_secure_close(f->secure[0])==MATTER_OK && matter_secure_delete(f->secure[0])==MATTER_OK);
    f->secure[0]=matter_secure_new_case(&f->crypto,f->session[0],5); OC_CHECK(f->secure[0]);
    OC_CHECK(matter_secure_challenge(f->secure[0],f->bytes)==MATTER_OK); save(dir,"resume-challenge.bin",f->bytes,16);
    static const uint8_t plain[]={1,2,0x34,0x12,1,0,0x15};
    OC_CHECK(matter_secure_seal(f->secure[0],plain,sizeof(plain),6,f->packet,sizeof(f->packet),&f->size)==MATTER_OK);
    save(dir,"resume-secure.bin",f->packet,f->size);
}
int main(int argc,char** argv) {
    Matter_Crypto_Mbedtls_T backend=matter_crypto_mbedtls_new(NULL); OC_CHECK(backend); Matter_Crypto_Port_T crypto; Matter_Credentials_Port_T cp;
    OC_CHECK(matter_crypto_mbedtls_port(backend,&crypto)==MATTER_OK && matter_crypto_mbedtls_credentials(backend,&cp)==MATTER_OK);
    OcFixture* legacy=oc_new(&crypto,&cp); oc_free(legacy);
    /* Normative 1.6.1 4.17.2 vector; output distinct from input epoch key. */
    uint8_t epoch[16],compressed[8],expected[32],actual[32],root[65],random[32];
    hex("235bf7e62823d358dca4ba50b1535f4b",epoch); hex("87e1b004e235a130",compressed); hex("a6f5306baf6d050af23ba4bd6b9dd960",expected);
    OC_CHECK(matter_case_ipk(&crypto,epoch,compressed,actual)==MATTER_OK && !memcmp(actual,expected,16));
    hex("044a9f42b1ca4840d37292bbc7f6a7e11e22200c976fc900dbc98a7a383a641cb8254a2e56d4e295a847943b4e3897c4a773e930277b4d9fbede8a052686bfacfa",root);
    hex("9bc61cd9c62a2df6d64dfcaa9dc472d4",epoch); hex("7e171231568dfa17206b3accf8faec2f4d21b580113196f47c7c4deb810a73dc",random);
    hex("dc35dd5fc9134cc5544538c9c3fc4297c1ec3370c839136a80e10796451d4c53",expected);
    OC_CHECK(matter_case_destination(&crypto,epoch,random,root,UINT64_C(0x2906c908d115d362),UINT64_C(0xcd5544aa7b13ef14),actual)==MATTER_OK && !memcmp(actual,expected,32));
    CaseFixture* f=case_fixture(&crypto,&cp); case_establish(f);
    for(unsigned i=0;i<2;++i) {
        OC_CHECK(matter_case_take_keys(f->session[i],&f->keys[i])==MATTER_OK && matter_case_take_keys(f->session[i],&f->keys[i])==MATTER_INVALID_STATE);
        OC_CHECK(f->keys[i].identity.fabric_index==1 && f->keys[i].identity.fabric_id==1 && f->keys[i].identity.peer_node_id==(i?101:100));
    }
    OC_CHECK(!memcmp(f->keys[0].traffic.send_key,f->keys[1].traffic.receive_key,16) && !memcmp(f->keys[0].traffic.receive_key,f->keys[1].traffic.send_key,16) &&
        !memcmp(f->keys[0].traffic.attestation_challenge,f->keys[1].traffic.attestation_challenge,16)); case_free(f);
    f=case_fixture(&crypto,&cp); case_establish(f);
    for(unsigned i=0;i<2;++i) { f->secure[i]=matter_secure_new_case(&crypto,f->session[i],5); OC_CHECK(f->secure[i] && !matter_secure_new_case(&crypto,f->session[i],5)); }
    static const uint8_t plain[]={1,2,0x34,0x12,1,0,0x15};
    OC_CHECK(matter_secure_seal(f->secure[0],plain,sizeof(plain),6,f->packet,sizeof(f->packet),&f->size)==MATTER_OK);
    OC_CHECK(matter_secure_receive(f->secure[1],f->packet,f->size,6,admit,f)==MATTER_OK && matter_secure_receive(f->secure[1],f->packet,f->size,7,admit,f)==MATTER_OK && f->admitted==2);
    f->packet[f->size-1]^=1; OC_CHECK(matter_secure_receive(f->secure[1],f->packet,f->size,8,admit,f)==MATTER_PORT_ERROR && f->admitted==2);
    Matter_Secure_Identity_T id; OC_CHECK(matter_secure_identity(f->secure[1],&id)==MATTER_OK && id.peer_node_id==101);
    OC_CHECK(matter_fabric_host_case_authorize(f->fabrics[1]->host,id.fabric_index,id.peer_node_id,id.cats,id.cat_count,MATTER_IM_VIEW));
    case_free(f);
    for(unsigned bad=0;bad<7;++bad) {
        f=case_fixture(&crypto,&cp); OC_CHECK(matter_case_process(f->session[0],0)==MATTER_PENDING);
        Matter_Pase_Message_T m;
        if(bad<3) {
            OC_CHECK(matter_case_output(f->session[0],&m)==MATTER_OK); memcpy(f->bytes,m.data,m.size);
            if(bad==0) f->bytes[45]^=1; /* Destination identifier. */
            if(bad==1) f->bytes[m.size-2]^=1; /* Ephemeral public point. */
            if(bad==2) f->bytes[1]=0x2c; /* Random wrong type. */
            OC_CHECK(matter_case_receive(f->session[1],m.opcode,f->bytes,m.size)==MATTER_OK && matter_case_process(f->session[1],1)==MATTER_PORT_ERROR);
            OC_CHECK(matter_case_output(f->session[1],&m)==MATTER_OK && m.opcode==0x40 && m.data[6]==(bad?2:1));
        } else if(bad<5) {
            case_step(f,0,1); if(bad==4) case_step(f,1,2);
            unsigned from=bad==3?1:0,to=1-from; OC_CHECK(matter_case_output(f->session[from],&m)==MATTER_OK);
            memcpy(f->bytes,m.data,m.size); f->bytes[m.size-2]^=1;
            OC_CHECK(matter_case_receive(f->session[to],m.opcode,f->bytes,m.size)==MATTER_OK && matter_case_process(f->session[to],3)==MATTER_PORT_ERROR);
        } else if(bad==5) { OC_CHECK(matter_case_process(f->session[0],30000)==MATTER_PORT_ERROR); }
        else { OC_CHECK(matter_opcreds_rollback(f->fabrics[0]->o->core)==MATTER_OK && matter_case_process(f->session[0],1)==MATTER_PORT_ERROR); }
        for(unsigned i=0;i<2;++i) OC_CHECK(matter_case_take_keys(f->session[i],&f->keys[i])==MATTER_INVALID_STATE);
        case_free(f);
    }
#ifdef MATTER_TEST_ALLOC
    f=case_fixture(&crypto,&cp); fail_at=calls+1; OC_CHECK(!matter_case_new(&crypto,&cp,&f->ports[0],&f->config[0],0)); fail_at=0;
    fail_at=calls+1; OC_CHECK(matter_case_process(f->session[0],0)==MATTER_PORT_ERROR); fail_at=0; case_free(f);
    f=case_fixture(&crypto,&cp); case_establish(f); fail_at=calls+1; OC_CHECK(!matter_secure_new_case(&crypto,f->session[0],5)); fail_at=0;
    f->secure[0]=matter_secure_new_case(&crypto,f->session[0],5); OC_CHECK(f->secure[0]); case_free(f);
#endif
    case_activation(&crypto,&cp); resume_tests(&crypto,&cp); resume_cache_tests(&crypto,&cp);
    peer_rejection(&crypto,&cp); cat_identity(&crypto,&cp); sigma_schema(&crypto,&cp);
    if(argc>=2) { OC_CHECK(argc==2 || (argc==3 && !strcmp(argv[2],"chip"))); export_case(argv[1],&crypto,&cp,argc==3); }
    OC_CHECK(matter_crypto_mbedtls_delete(backend)==MATTER_OK);
#ifdef MATTER_TEST_ALLOC
    OC_CHECK(!live);
#endif
    puts("PASS CASE: normative IPK/destination, Sigma1/2/3, chain/proof, confirmation gates, CAT/identity, schema/MRP, CCM/replay, errors/timeout/revocation/OOM"); return 0;
}
