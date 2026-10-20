/* Private storage tests; wire/ACK integration remains in Read/Subscribe tests. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_alloc_bytes.h"
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"snapshots:%d: %s\n",__LINE__,#x); abort(); } } while(0)
#define calloc matter_test_calloc
#define free matter_test_free
#include "model/matter_im_snapshot_internal.h"
#undef calloc
#undef free
typedef struct {
    Matter_Im_Snapshots snapshots;
    Matter_Im_Value_T value;
    Matter_Tlv_Writer_T writer;
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Element_T element;
    Matter_Tlv_Validation_Workspace_T validation;
    Matter_Tlv_Tag_T tags[48];
    uint8_t input[MATTER_IM_READ_MAX_VALUE+1];
    const uint8_t* retained[MATTER_IM_READ_MAX_RESULTS];
} Fixture;
static Fixture* create(void) { Fixture* f=calloc(1,sizeof(*f)); CHECK(f && !live && !live_bytes); return f; }
static void destroy(Fixture* f) { matter_im_snapshots_clear(&f->snapshots); CHECK(!live && !live_bytes); free(f); }
static uint8_t copy(Fixture* f) {
    return matter_im_snapshot_copy(&f->snapshots,&f->value,&f->writer,&f->reader,&f->element,&f->validation,f->tags,48);
}
static void string(Fixture* f,size_t size,bool text) {
    memset(f->input,'a',sizeof(f->input));
    f->value=(Matter_Im_Value_T){.type=text?MATTER_TLV_UTF8:MATTER_TLV_BYTES,.data=f->input,.size=size};
}
static void exact_and_boundaries(void) {
    const size_t sizes[]={0,1,8,255,256,4093};
    for(unsigned text=0;text<2;++text) for(size_t i=0;i<sizeof(sizes)/sizeof(*sizes);++i) {
        Fixture* f=create(); string(f,sizes[i],text!=0);
        if(!sizes[i]) f->value.data=NULL;
        CHECK(copy(f)==0);
        size_t encoded=sizes[i]+(sizes[i]<=255?2:3);
        CHECK(f->value.size==encoded && f->snapshots.size==encoded && live==1 && live_bytes==sizeof(Matter_Im_Snapshot_Node)+encoded);
        const uint8_t* data=f->value.data; CHECK(data!=f->input);
        CHECK(data[0]==(text?(sizes[i]<=255?0x0c:0x0d):(sizes[i]<=255?0x10:0x11)));
        CHECK(data[1]==(uint8_t)sizes[i] && (sizes[i]<=255 || data[2]==(uint8_t)(sizes[i]>>8)));
        memset(f->input,0,sizeof(f->input));
        for(size_t j=encoded-sizes[i];j<encoded;++j) CHECK(data[j]=='a');
        destroy(f);
    }
    Fixture* f=create();
    for(size_t i=0;i<4;++i) {
        string(f,4093,false); CHECK(copy(f)==0 && f->value.size==4096); f->retained[i]=f->value.data;
        for(size_t j=0;j<=i;++j) CHECK(f->retained[j][3]=='a');
    }
    CHECK(f->snapshots.size==16384 && live_bytes==16384+4*sizeof(Matter_Im_Snapshot_Node));
    size_t before=calls; string(f,0,false); CHECK(copy(f)==MATTER_IM_RESOURCE_EXHAUSTED && calls==before);
    matter_im_snapshots_clear(&f->snapshots); CHECK(!f->snapshots.head && !f->snapshots.size && !live);
    for(size_t i=4094;i<=4097;++i) {
        string(f,i,false); before=calls; CHECK(copy(f)==MATTER_IM_RESOURCE_EXHAUSTED && calls==before && !live);
    }
    destroy(f);
    /* The result ceiling and encoded-byte ceiling are independent. A full
     * result set with 32 encoded bytes each still uses exactly the old 16 KiB. */
    f=create();
    for(size_t i=0;i<MATTER_IM_READ_MAX_RESULTS;++i) {
        string(f,30,false); f->input[0]=(uint8_t)i;
        CHECK(copy(f)==0); f->retained[i]=f->value.data;
    }
    CHECK(f->snapshots.size==MATTER_IM_READ_SNAPSHOT_BYTES && live==MATTER_IM_READ_MAX_RESULTS);
    for(size_t i=0;i<MATTER_IM_READ_MAX_RESULTS;++i) CHECK(f->retained[i][2]==(uint8_t)i);
    CHECK(live_bytes==16384+MATTER_IM_READ_MAX_RESULTS*sizeof(Matter_Im_Snapshot_Node)); destroy(f);
    puts("PASS snapshot bounds: exact anonymous string bytes/length widths, empty strings, encoded 4096 and aggregate 16384, 512 stable references");
}
static void errors_and_oom(void) {
    for(size_t site=1;site<=9;++site) {
        Fixture* f=create();
        for(size_t i=1;i<=9;++i) {
            string(f,8,false); f->input[0]=(uint8_t)i; size_t before=live_bytes,used=f->snapshots.size;
            if(i==site) {
                fail_at=calls+1; CHECK(copy(f)==MATTER_IM_RESOURCE_EXHAUSTED); fail_at=0;
                CHECK(live_bytes==before && f->snapshots.size==used && f->value.data==f->input && f->value.size==8);
            }
            CHECK(copy(f)==0); f->retained[i-1]=f->value.data;
            memset(f->input,0,sizeof(f->input));
            for(size_t j=0;j<i;++j) CHECK(f->retained[j][2]==j+1);
        }
        destroy(f);
    }
    Fixture* f=create(); string(f,1,false); CHECK(copy(f)==0); const uint8_t* first=f->value.data;
    size_t bytes=live_bytes,used=f->snapshots.size;
    for(unsigned mode=0;mode<6;++mode) {
        static const uint8_t duplicate[]={0x15,0x24,0,1,0x24,0,2,0x18};
        static const uint8_t deep[]={0x15,0x35,0,0x35,0,0x35,0,0x35,0,0x18,0x18,0x18,0x18,0x18};
        memcpy(f->input,duplicate,sizeof(duplicate)); size_t size=sizeof(duplicate);
        if(mode==0) --size;
        if(mode==1) f->input[0]=0x16;
        if(mode==3) { memcpy(f->input,deep,sizeof(deep)); size=sizeof(deep); }
        if(mode==4) size=0;
        f->value=(Matter_Im_Value_T){.type=MATTER_TLV_STRUCTURE,.data=f->input,.size=size};
        if(mode==5) { string(f,1,true); f->input[0]=0xff; }
        CHECK(copy(f)==(mode==3?MATTER_IM_RESOURCE_EXHAUSTED:MATTER_IM_FAILURE));
        CHECK(live_bytes==bytes && f->snapshots.size==used && first[2]=='a' && f->value.data==f->input);
    }
    size_t before=calls; fail_at=calls+1; matter_im_snapshots_clear(&f->snapshots); fail_at=0;
    CHECK(calls==before && !live && !f->snapshots.size); destroy(f);
    printf("PASS snapshot OOM/error: each of 9 allocations, retry, earlier references preserved, malformed/deep/UTF8 cleanup; node header=%zu\n",sizeof(Matter_Im_Snapshot_Node));
}
int main(void) { exact_and_boundaries(); errors_and_oom(); return 0; }
