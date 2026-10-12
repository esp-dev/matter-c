#include "clusters/matter_ota_update.h"
#include "crypto/matter_crypto_mbedtls.h"
#include "matter_ota_file.h"
#include "matter_store_file.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"update:%d %s\n",__LINE__,#x); exit(1); } } while(0)
#ifdef MATTER_TEST_ALLOC
static bool fail_alloc; static size_t live;
void* matter_test_calloc(size_t n,size_t s) { if(fail_alloc) return NULL; void* p=calloc(n,s); if(p) ++live; return p; }
void* matter_test_malloc(size_t n) { if(fail_alloc) return NULL; void* p=malloc(n); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { CHECK(live); --live; } free(p); }
#endif
typedef struct {
    Matter_Crypto_Mbedtls_T crypto; Matter_Crypto_Port_T port;
    Matter_Ota_Signed_T image,proof; uint8_t private_key[32],key[65],fingerprint[32];
    Matter_Ota_Apply_Context_T context,out;
    uint8_t bytes[4096],original[512]; char path[1024];
    Matter_Store_Blob_Port_T inner; unsigned crash;
} Test;
static Matter_Result_T crash_read(void* user,uint8_t* data,size_t capacity,size_t* size) {
    Test* t=user; return t->inner.read(t->inner.user,data,capacity,size);
}
static Matter_Result_T crash_replace(void* user,const uint8_t* data,size_t size) {
    Test* t=user; if(t->crash==1) _Exit(86);
    Matter_Result_T r=t->inner.replace(t->inner.user,data,size);
    if(r==MATTER_OK && t->crash==2) _Exit(87);
    return r;
}
static void le(uint8_t* d,uint64_t v,unsigned n) { for(unsigned i=0;i<n;++i) d[i]=(uint8_t)(v>>(i*8)); }
static void signed_image(Test* t) {
    memset(&t->image,0,sizeof(t->image)); memcpy(t->image.manifest,"WWOTA001",8);
    le(t->image.manifest+8,0xfff1,2); le(t->image.manifest+10,0x8001,2); le(t->image.manifest+12,2,4);
    t->image.body_size=2049; le(t->image.manifest+16,t->image.body_size,8);
    memset(t->bytes,0xa5,(size_t)t->image.body_size);
    CHECK(t->port.sha256(t->port.user,t->bytes,(size_t)t->image.body_size,t->image.digest)==MATTER_OK);
    memcpy(t->image.manifest+24,t->image.digest,32);
    CHECK(t->port.ecdsa_sign(t->port.user,t->private_key,t->image.manifest,56,t->image.signature)==MATTER_OK);
}
static Matter_Ota_Update_T create(Test* t,Matter_Store_Blob_Port_T* b) {
    return matter_ota_update_new(b,&t->port,t->key,0xfff1,0x8001,1);
}
static void journal(Test* t,const char* path) {
    Matter_Store_File_T file=matter_store_file_new(path); CHECK(file);
    Matter_Store_Blob_Port_T b=matter_store_file_port(file);
#ifdef MATTER_TEST_ALLOC
    fail_alloc=true; CHECK(!create(t,&b)); fail_alloc=false;
#endif
    Matter_Ota_Update_T u=create(t,&b); CHECK(u && matter_ota_update_version(u)==1 && !matter_ota_update_booted(u));
    CHECK(matter_ota_update_verify(u,2,&t->image)==MATTER_OK);
    for(unsigned i=0;i<7;++i) {
        t->proof=t->image;
        if(i==0) t->proof.signature[0]^=1;
        if(i==1) t->proof.digest[0]^=1;
        if(i==2) t->proof.body_size++;
        if(i==3) t->proof.manifest[8]^=1;
        if(i==4) t->proof.manifest[10]^=1;
        CHECK(matter_ota_update_verify(u,i==5?1:i==6?3:2,&t->proof)!=MATTER_OK);
    }
    t->context=(Matter_Ota_Apply_Context_T){.provider={42,1,1},.version=2,.token_size=32};
    memset(t->context.token,0x59,32); memset(t->fingerprint,0x73,32);
    for(unsigned fault=1;fault<=4;++fault) {
        matter_store_file_fault(file,fault);
        CHECK(matter_ota_update_accept(u,&t->context,t->fingerprint,&t->image)!=MATTER_OK);
        CHECK(matter_ota_update_version(u)==1 && !matter_ota_update_pending(u));
    }
    matter_store_file_fault(file,0);
    CHECK(matter_ota_update_accept(u,&t->context,t->fingerprint,&t->image)==MATTER_OK);
    CHECK(matter_ota_update_version(u)==2 && !matter_ota_update_pending(u));
    CHECK(matter_ota_update_accept(u,&t->context,t->fingerprint,&t->image)!=MATTER_OK);
    matter_ota_update_delete(u);
    /* A failed boot-marker transition leaves the committed version recoverable. */
    matter_store_file_fault(file,1); CHECK(!create(t,&b)); matter_store_file_fault(file,0);
    u=create(t,&b); CHECK(u && matter_ota_update_trial(u) && !matter_ota_update_booted(u) && matter_ota_update_version(u)==2);
    CHECK(!matter_ota_update_pending(u));
    for(unsigned fault=1;fault<=4;++fault) {
        matter_store_file_fault(file,fault); CHECK(matter_ota_update_confirm(u)!=MATTER_OK && matter_ota_update_trial(u) && !matter_ota_update_pending(u));
    }
    matter_store_file_fault(file,0);
    CHECK(matter_ota_update_confirm(u)==MATTER_OK && matter_ota_update_booted(u) && !matter_ota_update_trial(u));
    const Matter_Ota_Apply_Context_T* c=matter_ota_update_pending(u);
    CHECK(c && c->token_size==32 && !memcmp(c->token,t->context.token,32) && c->provider.node==42);
    matter_ota_update_delete(u); u=create(t,&b); CHECK(u && !matter_ota_update_booted(u) && matter_ota_update_pending(u));
    size_t size; CHECK(b.read(b.user,t->original,sizeof(t->original),&size)==MATTER_OK);
    for(unsigned fault=1;fault<=4;++fault) {
        matter_store_file_fault(file,fault); memset(&t->out,0,sizeof(t->out));
        CHECK(matter_ota_update_claim(u,t->fingerprint,true,&t->out)!=MATTER_OK && !t->out.token_size);
        CHECK(matter_ota_update_pending(u));
    }
    matter_store_file_fault(file,0);
    CHECK(matter_ota_update_claim(u,t->fingerprint,true,&t->out)==MATTER_OK && t->out.version==2 && t->out.token_size==32);
    CHECK(!matter_ota_update_pending(u)); matter_ota_update_delete(u);
    u=create(t,&b); CHECK(u && !matter_ota_update_pending(u) && matter_ota_update_version(u)==2); matter_ota_update_delete(u);
    /* Fabric index reuse/removal must not notify an unrelated provider. */
    for(unsigned mode=0;mode<2;++mode) {
        CHECK(b.replace(b.user,t->original,size)==MATTER_OK); u=create(t,&b); CHECK(u);
        if(mode) t->fingerprint[0]^=1;
        CHECK(matter_ota_update_claim(u,t->fingerprint,mode!=0,&t->out)==MATTER_OFFLINE && !matter_ota_update_pending(u));
        matter_ota_update_delete(u);
    }
    /* Truncated/corrupt signed state fails closed and is not rewritten. */
    for(unsigned mode=0;mode<2;++mode) {
        memcpy(t->bytes,t->original,size); if(mode) t->bytes[30]^=1;
        CHECK(b.replace(b.user,t->bytes,size-(mode?0:1))==MATTER_OK); CHECK(!create(t,&b));
    }
    CHECK(matter_store_file_delete(file)==MATTER_OK); CHECK(!remove(path));
    puts("PASS OTA journal: real ECDSA, identity/digest/version, atomic faults1..4, boot restore, one claim, orphan, corrupt state, cleanup");
}
static void rollback(Test* t,const char* path) {
    Matter_Store_File_T file=matter_store_file_new(path); CHECK(file); Matter_Store_Blob_Port_T b=matter_store_file_port(file);
    Matter_Ota_Update_T u=create(t,&b); CHECK(u); t->context.version=2;
    CHECK(matter_ota_update_accept(u,&t->context,t->fingerprint,&t->image)==MATTER_OK); matter_ota_update_delete(u);
    u=create(t,&b); CHECK(u && matter_ota_update_trial(u)); matter_ota_update_delete(u);
    /* Every failed rollback write must leave phase3 recoverable and no Notify. */
    for(unsigned fault=1;fault<=4;++fault) { matter_store_file_fault(file,fault); CHECK(!create(t,&b)); }
    matter_store_file_fault(file,0); u=create(t,&b);
    CHECK(u && matter_ota_update_rolled_back(u) && matter_ota_update_version(u)==1 && !matter_ota_update_pending(u));
    CHECK(matter_ota_update_confirm(u)==MATTER_INVALID_STATE);
    matter_ota_update_delete(u); u=create(t,&b); CHECK(u && matter_ota_update_version(u)==1 && !matter_ota_update_rolled_back(u));
    /* Retry the rejected update; confirm2, then fail3 and recover signed2. */
    CHECK(matter_ota_update_accept(u,&t->context,t->fingerprint,&t->image)==MATTER_OK); matter_ota_update_delete(u);
    u=create(t,&b); CHECK(u && matter_ota_update_confirm(u)==MATTER_OK);
    CHECK(matter_ota_update_claim(u,t->fingerprint,true,&t->out)==MATTER_OK);
    t->proof=t->image; le(t->proof.manifest+12,3,4);
    CHECK(t->port.ecdsa_sign(t->port.user,t->private_key,t->proof.manifest,56,t->proof.signature)==MATTER_OK);
    t->context.version=3; CHECK(matter_ota_update_accept(u,&t->context,t->fingerprint,&t->proof)==MATTER_OK); matter_ota_update_delete(u);
    /* A valid candidate must not hide a forged fallback signature. */
    size_t n; CHECK(b.read(b.user,t->original,sizeof(t->original),&n)==MATTER_OK);
    memcpy(t->bytes,t->original,n); Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T e; bool changed=false;
    CHECK(matter_tlv_init(&reader,t->bytes,n,2)==MATTER_TLV_OK);
    while(matter_tlv_next(&reader,&e)==MATTER_TLV_OK) if(e.tag.control==1 && e.tag.number==10) {
        CHECK(e.type==MATTER_TLV_BYTES && e.size==64); t->bytes[e.data-t->bytes]^=1; changed=true;
    }
    CHECK(changed && b.replace(b.user,t->bytes,n)==MATTER_OK && !create(t,&b));
    size_t stored; CHECK(b.read(b.user,t->bytes,sizeof(t->bytes),&stored)==MATTER_OK && stored==n && memcmp(t->bytes,t->original,n));
    CHECK(b.replace(b.user,t->original,n)==MATTER_OK);
    u=create(t,&b); CHECK(u && matter_ota_update_trial(u) && matter_ota_update_version(u)==3); matter_ota_update_delete(u);
    u=create(t,&b); CHECK(u && matter_ota_update_rolled_back(u) && matter_ota_update_version(u)==2 && !matter_ota_update_pending(u));
    CHECK(matter_ota_update_verify(u,2,&t->image)!=MATTER_OK && matter_ota_update_verify(u,3,&t->proof)==MATTER_OK);
    matter_ota_update_delete(u); CHECK(matter_store_file_delete(file)==MATTER_OK && !remove(path));
    puts("PASS OTA rollback: unconfirmed boot, atomic faults, base/signed fallback, retry2 then3, no Notify, no OTA downgrade");
}
static void put(Matter_Tlv_Writer_T* w,Matter_Tlv_Type_T type,int tag,uint64_t v,const void* d,size_t n) {
    Matter_Tlv_Element_T e={.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=v,.data=d,.size=n};
    CHECK(matter_tlv_write(w,&e,0)==MATTER_TLV_OK);
}
static void legacy(Test* t,const char* path) {
    Matter_Store_File_T file=matter_store_file_new(path); CHECK(file); Matter_Store_Blob_Port_T b=matter_store_file_port(file);
    for(unsigned phase=0;phase<3;++phase) {
        Matter_Tlv_Writer_T w; size_t n; CHECK(matter_tlv_writer_init(&w,t->bytes,sizeof(t->bytes),2)==MATTER_TLV_OK);
        put(&w,MATTER_TLV_STRUCTURE,-1,0,NULL,0); put(&w,MATTER_TLV_UNSIGNED,0,1,NULL,0); put(&w,MATTER_TLV_UNSIGNED,1,phase,NULL,0);
        put(&w,MATTER_TLV_BYTES,2,0,t->image.manifest,56); put(&w,MATTER_TLV_BYTES,3,0,t->image.signature,64);
        put(&w,MATTER_TLV_UNSIGNED,4,phase?42:0,NULL,0); put(&w,MATTER_TLV_UNSIGNED,5,phase?1:0,NULL,0); put(&w,MATTER_TLV_UNSIGNED,6,phase?1:0,NULL,0);
        put(&w,MATTER_TLV_BYTES,7,0,t->context.token,phase?32:0); memset(t->fingerprint,0,32);
        put(&w,MATTER_TLV_BYTES,8,0,t->fingerprint,32); put(&w,MATTER_TLV_END,-1,0,NULL,0);
        CHECK(matter_tlv_writer_finish(&w,&n)==MATTER_TLV_OK && b.replace(b.user,t->bytes,n)==MATTER_OK);
        Matter_Ota_Update_T u=create(t,&b); CHECK(u && matter_ota_update_version(u)==2 && !matter_ota_update_trial(u));
        CHECK(matter_ota_update_booted(u)==(phase==2) && (matter_ota_update_pending(u)!=NULL)==(phase!=0));
        matter_ota_update_delete(u);
    }
    CHECK(matter_store_file_delete(file)==MATTER_OK && !remove(path)); puts("PASS OTA V1 migration: all phases retain installed version and notification semantics");
}
static void stream(Test* t,const char* path) {
    Matter_Ota_File_T f=matter_ota_file_new(path,0xfff1,0x8001,1); CHECK(f);
    Matter_Bdx_Sink_T s=matter_ota_file_sink(f); uint8_t digest[32];
    memcpy(t->bytes+1024,t->image.manifest,56); memcpy(t->bytes+1080,t->image.signature,64);
    memset(t->bytes+1144,0xa5,2049); CHECK(t->port.sha256(t->port.user,t->bytes+1024,2169,digest)==MATTER_OK);
    Matter_Tlv_Writer_T w; size_t n;
    CHECK(matter_tlv_writer_init(&w,t->bytes+16,512,2)==MATTER_TLV_OK);
    put(&w,MATTER_TLV_STRUCTURE,-1,0,NULL,0); put(&w,MATTER_TLV_UNSIGNED,0,0xfff1,NULL,0); put(&w,MATTER_TLV_UNSIGNED,1,0x8001,NULL,0);
    put(&w,MATTER_TLV_UNSIGNED,2,2,NULL,0); put(&w,MATTER_TLV_UTF8,3,0,"v2",2); put(&w,MATTER_TLV_UNSIGNED,4,2169,NULL,0);
    put(&w,MATTER_TLV_UNSIGNED,8,1,NULL,0); put(&w,MATTER_TLV_BYTES,9,0,digest,32); put(&w,MATTER_TLV_END,-1,0,NULL,0);
    CHECK(matter_tlv_writer_finish(&w,&n)==MATTER_TLV_OK);
    le(t->bytes,0x1beef11e,4); le(t->bytes+4,16+n+2169,8); le(t->bytes+12,n,4);
    CHECK(matter_ota_file_prepare(f,2)==MATTER_OK && s.open(s.user)==MATTER_OK);
    CHECK(s.write(s.user,t->bytes,16+n)==MATTER_OK);
    for(size_t at=0;at<2169;) { size_t take=2169-at; if(take>1024) take=1024; CHECK(s.write(s.user,t->bytes+1024+at,take)==MATTER_OK); at+=take; }
    CHECK(s.finish(s.user,16+n+2169)==MATTER_OK && matter_ota_file_commit(f)==MATTER_OK);
    uint64_t artifact=matter_ota_file_artifact(f);
#ifdef MATTER_TEST_ALLOC
    fail_alloc=true; CHECK(matter_ota_file_signed(f,artifact,&t->proof)==MATTER_LIMIT_REACHED); fail_alloc=false;
#endif
    CHECK(matter_ota_file_signed(f,artifact,&t->proof)==MATTER_OK);
    CHECK(!memcmp(t->proof.manifest,t->image.manifest,56) && !memcmp(t->proof.signature,t->image.signature,64));
    CHECK(t->proof.body_size==2049 && !memcmp(t->proof.digest,t->image.digest,32));
    CHECK(matter_ota_file_signed(f,artifact+1,&t->proof)==MATTER_INVALID_STATE);
    FILE* out=fopen(path,"r+b"); CHECK(out && !fseek(out,-1,SEEK_END) && fputc(0,out)!=EOF && !fclose(out));
    CHECK(matter_ota_file_signed(f,artifact,&t->proof)!=MATTER_OK);
    CHECK(!remove(path)); CHECK(matter_ota_file_signed(f,artifact,&t->proof)==MATTER_PORT_ERROR);
    matter_ota_file_delete(f);
    puts("PASS OTA signed reader: multi-block same-stream proof, artifact binding, mutation, missing file, cleanup");
}
static void crash_process(Test* t,const char* path,const char* action,const char* boundary) {
    unsigned crash=!strcmp(boundary,"before")?1:!strcmp(boundary,"after")?2:0;
    Matter_Store_File_T file=matter_store_file_new(path); CHECK(file); t->inner=matter_store_file_port(file);
    Matter_Store_Blob_Port_T b={t,crash_read,crash_replace};
    if(!strcmp(action,"boot")) t->crash=crash;
    Matter_Ota_Update_T u=create(t,&b); CHECK(u); t->crash=crash;
    if(!strcmp(action,"seed")) {
        t->context=(Matter_Ota_Apply_Context_T){.provider={42,1,1},.version=2,.token_size=8};
        CHECK(matter_ota_update_accept(u,&t->context,t->fingerprint,&t->image)==MATTER_OK);
    } else if(!strcmp(action,"confirm")) CHECK(matter_ota_update_confirm(u)==MATTER_OK);
    else if(!strcmp(action,"claim")) CHECK(matter_ota_update_claim(u,t->fingerprint,true,&t->out)==MATTER_OK);
    else CHECK(!strcmp(action,"boot") || !strcmp(action,"inspect"));
    printf("RECOVER %lu %u %u %u\n",(unsigned long)matter_ota_update_version(u),matter_ota_update_trial(u)?1:0,
        matter_ota_update_rolled_back(u)?1:0,matter_ota_update_pending(u)?1:0);
    matter_ota_update_delete(u); CHECK(matter_store_file_delete(file)==MATTER_OK);
}
int main(int argc,char** argv) {
    CHECK(argc==2 || argc==4); Test* t=calloc(1,sizeof(*t)); CHECK(t);
    t->crypto=matter_crypto_mbedtls_new(NULL); CHECK(t->crypto && matter_crypto_mbedtls_port(t->crypto,&t->port)==MATTER_OK);
    t->private_key[31]=1; CHECK(t->port.p256_base(t->port.user,t->private_key,32,t->key)==MATTER_OK);
    signed_image(t);
    if(argc==4) crash_process(t,argv[1],argv[2],argv[3]);
    else { journal(t,argv[1]); rollback(t,argv[1]); legacy(t,argv[1]); stream(t,argv[1]); }
    CHECK(matter_crypto_mbedtls_delete(t->crypto)==MATTER_OK); free(t);
#ifdef MATTER_TEST_ALLOC
    CHECK(!live); puts("PASS OTA update/reader allocation failure ownership");
#endif
    return 0;
}
