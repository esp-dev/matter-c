#include "shim/sdk.h"
#include "../matter_idf_store.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static unsigned allocations,fail_after,aborted,confirmed;
static void* alloc(size_t n) { if(fail_after && !--fail_after) return NULL; void* p=malloc(n); if(p) ++allocations; return p; }
static void* zero(size_t n,size_t s) { void* p=alloc(n*s); if(p) memset(p,0,n*s); return p; }
static void release(void* p) { if(p) { assert(allocations); --allocations; free(p); } }
#define malloc alloc
#define calloc zero
#define free release
#include "../matter_idf_ota.c"
#undef malloc
#undef calloc
#undef free
static esp_partition_t partitions[2]={{0x10000,4096,16},{0x20000,4096,17}};
static unsigned running,chosen; static esp_ota_img_states_t states[2];
static esp_app_desc_t desc[2]; static uint8_t flash[2][4096],journal[JOURNAL_SIZE];
static size_t journal_size,written; static bool write_failure,select_failure,confirm_failure,signature=true;
static Matter_Result_T read_journal(void* u,uint8_t* d,size_t cap,size_t* n) {
    (void)u; if(!journal_size) return MATTER_OFFLINE;
    if(cap<journal_size) return MATTER_LIMIT_REACHED;
    memcpy(d,journal,journal_size); *n=journal_size; return MATTER_OK;
}
static Matter_Result_T replace_journal(void* u,const uint8_t* d,size_t n) {
    (void)u; if(write_failure) return MATTER_PORT_ERROR;
    assert(n==sizeof(journal)); memcpy(journal,d,n); journal_size=n; return MATTER_OK;
}
Matter_Idf_Store_T matter_idf_store_new(const char* p,const char* s) { (void)p;(void)s; return (Matter_Idf_Store_T)alloc(1); }
Matter_Store_Blob_Port_T matter_idf_store_port(Matter_Idf_Store_T s) { return (Matter_Store_Blob_Port_T){s,read_journal,replace_journal}; }
void matter_idf_store_delete(Matter_Idf_Store_T s) { release(s); }
uint32_t esp_crc32_le(uint32_t crc,const uint8_t* d,size_t n) { crc=~crc; for(size_t i=0;i<n;++i) { crc^=d[i]; for(unsigned b=0;b<8;++b) crc=(crc>>1)^(0xedb88320u & (0u-(crc&1))); } return ~crc; }
const esp_app_desc_t* esp_app_get_description(void) { return &desc[running]; }
const esp_partition_t* esp_ota_get_running_partition(void) { return &partitions[running]; }
const esp_partition_t* esp_ota_get_next_update_partition(const esp_partition_t* p) { (void)p; return &partitions[running^1]; }
const esp_partition_t* esp_ota_get_boot_partition(void) { return &partitions[chosen]; }
esp_err_t esp_ota_begin(const esp_partition_t* p,size_t n,esp_ota_handle_t* h) { assert(n==OTA_WITH_SEQUENTIAL_WRITES); *h=(unsigned)(p-partitions)+1; written=0; return 0; }
esp_err_t esp_ota_write(esp_ota_handle_t h,const void* d,size_t n) { assert(written+n<=4096); memcpy(flash[h-1]+written,d,n); written+=n; return 0; }
esp_err_t esp_ota_end(esp_ota_handle_t h) { (void)h; return signature?0:-1; }
esp_err_t esp_ota_abort(esp_ota_handle_t h) { (void)h; ++aborted; return 0; }
esp_err_t esp_ota_get_partition_description(const esp_partition_t* p,esp_app_desc_t* d) { *d=desc[p-partitions]; return 0; }
esp_err_t esp_ota_set_boot_partition(const esp_partition_t* p) { if(select_failure) return -1; chosen=(unsigned)(p-partitions); return 0; }
esp_err_t esp_ota_get_state_partition(const esp_partition_t* p,esp_ota_img_states_t* s) { *s=states[p-partitions]; return 0; }
esp_err_t esp_ota_mark_app_valid_cancel_rollback(void) { if(confirm_failure) return -1; ++confirmed; states[running]=ESP_OTA_IMG_VALID; return 0; }
esp_err_t esp_partition_read(const esp_partition_t* p,size_t at,void* d,size_t n) { assert(at+n<=4096); memcpy(d,flash[p-partitions]+at,n); return 0; }
esp_err_t esp_image_verify(int mode,const esp_partition_pos_t* p,esp_image_metadata_t* d) { (void)mode;(void)p;(void)d; return signature?0:-1; }
esp_partition_iterator_t esp_partition_find(int a,int b,const char* c) { (void)a;(void)b;(void)c; return partitions; }
const esp_partition_t* esp_partition_get(esp_partition_iterator_t p) { return p; }
void esp_partition_iterator_release(esp_partition_iterator_t p) { (void)p; }
esp_partition_iterator_t esp_partition_next(esp_partition_iterator_t p) { return p==partitions?partitions+1:NULL; }
static size_t image(uint8_t* out) {
    const uint8_t payload[]={0xe9,1,2,3,4,5,6,7}; uint8_t digest[32];
    assert(!mbedtls_sha256(payload,sizeof(payload),digest,0));
    uint8_t h[]={0x15,0x25,0,0xf1,0xff,0x25,1,0,0x80,0x24,2,2,0x2c,3,1,'2',0x24,4,8,0x24,8,1,0x30,9,32};
    memset(out,0,16); put(out,0x1beef11e,4); put(out+12,sizeof(h)+33,4);
    memcpy(out+16,h,sizeof(h)); memcpy(out+16+sizeof(h),digest,32); out[16+sizeof(h)+32]=0x18;
    size_t n=16+sizeof(h)+33; memcpy(out+n,payload,sizeof(payload)); n+=sizeof(payload); put(out+4,n,8); return n;
}
static Matter_Idf_Ota_T fresh(void) { Matter_Idf_Ota_T f=matter_idf_ota_new("nvs","ota",0xfff1,0x8000); assert(f); return f; }
static Matter_Ota_Apply_Context_T candidate(Matter_Idf_Ota_T f) {
    uint8_t bytes[128]; size_t n=image(bytes); Matter_Runtime_Ota_Port_T p=matter_idf_ota_port(f);
    assert(p.prepare(f,2)==MATTER_OK); assert(p.sink.open(f)==MATTER_OK);
    for(size_t i=0;i<n;++i) assert(p.sink.write(f,bytes+i,1)==MATTER_OK);
    assert(p.sink.finish(f,n)==MATTER_OK && p.commit(f)==MATTER_OK);
    assert(p.check(f,p.artifact(f))==MATTER_OK);
    return (Matter_Ota_Apply_Context_T){.provider={.fabric=1,.node=123,.endpoint=0},.version=2,.artifact=p.artifact(f),.token_size=8,.token={1}};
}
static void reset(void) {
    assert(!allocations); running=chosen=0; states[0]=ESP_OTA_IMG_VALID; states[1]=ESP_OTA_IMG_NEW;
    memset(desc,0,sizeof(desc)); strcpy(desc[0].version,"1"); strcpy(desc[1].version,"2");
    strcpy(desc[0].project_name,"test"); strcpy(desc[1].project_name,"test");
    journal_size=0; write_failure=select_failure=confirm_failure=false; signature=true;
}
int main(void) {
    uint8_t fingerprint[32]={7}; Matter_Ota_Apply_Context_T out;
    reset();
    for(unsigned i=1;i<=2;++i) { fail_after=i; assert(!matter_idf_ota_new("nvs","ota",0xfff1,0x8000)); assert(!allocations); }
    fail_after=0; Matter_Idf_Ota_T f=fresh(); Matter_Runtime_Ota_Port_T p=matter_idf_ota_port(f);
    assert(p.prepare(f,2)==MATTER_OK); fail_after=1; assert(p.sink.open(f)==MATTER_LIMIT_REACHED); fail_after=0;
    assert(p.sink.open(f)==MATTER_OK); p.sink.cancel(f); assert(!aborted); /* Header was not complete, flash not opened. */
    uint8_t invalid[128]; size_t invalid_size=image(invalid); invalid[0]^=1;
    assert(p.prepare(f,2)==MATTER_OK && p.sink.open(f)==MATTER_OK);
    assert(p.sink.write(f,invalid,invalid_size)==MATTER_INVALID_ARGUMENT); p.cancel(f);
    invalid_size=image(invalid);
    assert(p.prepare(f,2)==MATTER_OK && p.sink.open(f)==MATTER_OK);
    assert(p.sink.write(f,invalid,invalid_size-1)==MATTER_OK);
    assert(p.sink.finish(f,invalid_size-1)==MATTER_INVALID_ARGUMENT); p.cancel(f); assert(aborted==1);
    Matter_Ota_Apply_Context_T c=candidate(f);
    fail_after=1; assert(p.check(f,c.artifact)==MATTER_LIMIT_REACHED); fail_after=0;
    flash[1][1]^=1; assert(p.check(f,c.artifact)!=MATTER_OK); flash[1][1]^=1;
    signature=false; assert(p.check(f,c.artifact)!=MATTER_OK); signature=true;
    write_failure=true; assert(p.install->accept(f,&c,fingerprint)==MATTER_PORT_ERROR && chosen==0);
    matter_idf_ota_delete(f); reset(); f=fresh(); c=candidate(f); p=matter_idf_ota_port(f);
    select_failure=true; assert(p.install->accept(f,&c,fingerprint)==MATTER_PORT_ERROR && chosen==0);
    matter_idf_ota_delete(f); select_failure=false; f=fresh(); p=matter_idf_ota_port(f);
    assert(p.install->boot(f)->state==MATTER_OTA_INSTALL_ROLLBACK); assert(p.install->confirm(f)==MATTER_OK);
    c=candidate(f); assert(p.install->accept(f,&c,fingerprint)==MATTER_OK && chosen==1);
    p.invalidate(f); p.cancel(f); matter_idf_ota_delete(f); /* Accepted boot selection and journal survive drain. */
    running=1; states[1]=ESP_OTA_IMG_PENDING_VERIFY; f=fresh(); p=matter_idf_ota_port(f);
    assert(p.install->boot(f)->state==MATTER_OTA_INSTALL_TRIAL);
    confirm_failure=true; assert(p.install->confirm(f)==MATTER_PORT_ERROR); confirm_failure=false;
    write_failure=true; assert(p.install->confirm(f)==MATTER_PORT_ERROR && states[1]==ESP_OTA_IMG_VALID);
    matter_idf_ota_delete(f); write_failure=false; f=fresh(); p=matter_idf_ota_port(f);
    assert(p.install->boot(f)->state==MATTER_OTA_INSTALL_TRIAL && p.install->confirm(f)==MATTER_OK);
    assert(confirmed==1 && p.install->boot(f)->state==MATTER_OTA_INSTALL_NOTIFY);
    write_failure=true; assert(p.install->claim(f,fingerprint,true,&out)==MATTER_PORT_ERROR && p.install->boot(f));
    write_failure=false; fingerprint[0]^=1;
    assert(p.install->claim(f,fingerprint,true,&out)==MATTER_OFFLINE && !p.install->boot(f));
    matter_idf_ota_delete(f); f=fresh(); assert(!matter_idf_ota_port(f).install->boot(f)); matter_idf_ota_delete(f);
    journal[10]^=1; assert(!matter_idf_ota_new("nvs","ota",0xfff1,0x8000)); assert(!allocations);
    reset(); f=fresh(); p=matter_idf_ota_port(f); c=candidate(f);
    assert(p.install->accept(f,&c,fingerprint)==MATTER_OK); matter_idf_ota_delete(f);
    running=1; states[1]=ESP_OTA_IMG_PENDING_VERIFY; f=fresh(); p=matter_idf_ota_port(f);
    assert(p.install->confirm(f)==MATTER_OK && p.install->claim(f,fingerprint,true,&out)==MATTER_OK);
    assert(out.version==2 && out.provider.node==c.provider.node && out.token_size==c.token_size && !memcmp(out.token,c.token,c.token_size));
    assert(!p.install->boot(f)); matter_idf_ota_delete(f);
    states[1]=ESP_OTA_IMG_PENDING_VERIFY; assert(!matter_idf_ota_new("nvs","ota",0xfff1,0x8000)); assert(!allocations);
    reset(); states[0]=ESP_OTA_IMG_PENDING_VERIFY; assert(!matter_idf_ota_new("nvs","ota",0xfff1,0x8000)); assert(!allocations);
    puts("PASS native OTA boundary: OOM, artifact mutation, signature rejection, selection failure, rollback, confirm crash, orphan and journal corruption");
    return 0;
}
