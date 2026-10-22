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
    uint8_t short_data[MATTER_IM_SNAPSHOT_INLINE];
    Matter_Im_Snapshot_Value saved[MATTER_IM_READ_MAX_RESULTS];
    size_t saved_count;
    uint8_t input[MATTER_IM_READ_MAX_VALUE+1];
    const uint8_t* retained[MATTER_IM_READ_MAX_RESULTS];
} Fixture;
static Fixture* create(void) { Fixture* f=calloc(1,sizeof(*f)); CHECK(f && !live && !live_bytes); return f; }
static void destroy(Fixture* f) { matter_im_snapshots_clear(&f->snapshots); CHECK(!live && !live_bytes); free(f); }
static uint8_t copy(Fixture* f) {
    uint8_t status=matter_im_snapshot_copy(&f->snapshots,&f->value,&f->writer,&f->reader,&f->element,&f->validation,f->tags,48,f->short_data);
    if(!status) {
        CHECK(f->saved_count<MATTER_IM_READ_MAX_RESULTS);
        Matter_Im_Snapshot_Value* stored=&f->saved[f->saved_count++];
        *stored=matter_im_snapshot_store(&f->value); matter_im_snapshot_load(&f->value,stored);
    }
    return status;
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
        bool inlined=encoded<=MATTER_IM_SNAPSHOT_INLINE;
        CHECK(f->value.size==encoded && f->snapshots.size==encoded && live==(inlined?0:1) &&
            live_bytes==(inlined?0:sizeof(Matter_Im_Snapshot_Node)+encoded));
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
static void consumed_and_compact(void) {
    Fixture* f=create();
    for(size_t i=0;i<4;++i) { string(f,4093,false); CHECK(copy(f)==0); f->retained[i]=f->value.data; }
    /* Unlink tail, middle and head independently. A completed chunk must not
     * replenish the original report's admission budget. No allocations here. */
    size_t before=calls;
    matter_im_snapshot_release(&f->snapshots,f->retained[0]);
    matter_im_snapshot_release(&f->snapshots,f->retained[2]);
    matter_im_snapshot_release(&f->snapshots,f->retained[3]);
    matter_im_snapshot_release(&f->snapshots,NULL);
    CHECK(live==1 && calls==before && f->snapshots.size==16384 && f->retained[1][3]=='a');
    string(f,0,false); CHECK(copy(f)==MATTER_IM_RESOURCE_EXHAUSTED && calls==before);
    destroy(f);
    CHECK(sizeof(Matter_Im_Snapshot_Value)<sizeof(Matter_Im_Value_T));
    const Matter_Tlv_Type_T types[]={MATTER_TLV_UNSIGNED,MATTER_TLV_SIGNED,MATTER_TLV_BOOL,MATTER_TLV_NULL,
        MATTER_TLV_UTF8,MATTER_TLV_BYTES,MATTER_TLV_STRUCTURE,MATTER_TLV_ARRAY};
    for(size_t i=0;i<sizeof(types)/sizeof(*types);++i) {
        Matter_Im_Value_T value={.type=types[i],.unsigned_value=UINT64_MAX,.signed_value=INT64_MIN,
            .data_version=UINT32_MAX,.data=(const uint8_t*)types,.size=4096};
        Matter_Im_Snapshot_Value stored=matter_im_snapshot_store(&value);
        Matter_Im_Value_T restored; matter_im_snapshot_load(&restored,&stored);
        CHECK(restored.type==value.type && restored.data_version==value.data_version);
        if(matter_im_snapshot_complex(value.type)) CHECK(restored.data==value.data && restored.size==value.size);
        else if(value.type==MATTER_TLV_SIGNED) CHECK(restored.signed_value==INT64_MIN);
        else CHECK(restored.unsigned_value==UINT64_MAX);
    }
    puts("PASS consumed snapshot release: stable remaining references, cumulative limit and compact scalar/span round trips");
}
static void inline_values(void) {
    Fixture* f=create(); size_t before=calls;
    for(unsigned text=0;text<2;++text) for(size_t n=0;n<=7;++n) {
        string(f,n,text!=0); size_t used=f->snapshots.size;
        if(n<=6) fail_at=calls+1;
        CHECK(!copy(f)); fail_at=0;
        CHECK(f->snapshots.size==used+n+2);
        CHECK(f->saved[f->saved_count-1].inline_size==(n<=6?n+2:0));
        if(n<=6) CHECK(calls==before); else { CHECK(calls==before+1); before=calls; }
        const uint8_t* bytes=f->value.data;
        memset(f->short_data,0xff,sizeof(f->short_data)); memset(f->input,0xff,sizeof(f->input));
        for(size_t i=2;i<n+2;++i) CHECK(bytes[i]=='a');
    }
    /* Values may move during Read compaction: load must derive their new
     * address, and releasing either copy must never free inline storage. */
    Matter_Im_Snapshot_Value moved=f->saved[6];
    memset(&f->saved[6],0,sizeof(f->saved[6]));
    Matter_Im_Value_T loaded; matter_im_snapshot_load(&loaded,&moved);
    CHECK(loaded.size==8 && loaded.data==moved.as.encoded && loaded.data[7]=='a');
    matter_im_snapshot_release_value(&f->snapshots,&moved);
    CHECK(!moved.inline_size && !moved.as.span.data && !moved.as.span.size);
    static const uint8_t containers[][8]={{0x16,0x18},{0x15,0x18},{0x16,0x04,1,0x04,2,0x04,3,0x18}};
    const size_t lengths[]={2,2,8};
    for(unsigned i=0;i<3;++i) {
        memcpy(f->input,containers[i],lengths[i]);
        f->value=(Matter_Im_Value_T){.type=i==1?MATTER_TLV_STRUCTURE:MATTER_TLV_ARRAY,.data=f->input,.size=lengths[i],.data_version=UINT32_MAX};
        before=calls; CHECK(!copy(f) && calls==before);
        CHECK(f->value.data_version==UINT32_MAX && !memcmp(f->value.data,containers[i],lengths[i]));
    }
    matter_im_snapshots_clear(&f->snapshots); CHECK(!live);
    /* Inline bytes still consume the original cumulative admission budget. */
    f->snapshots.size=MATTER_IM_READ_SNAPSHOT_BYTES-8; string(f,6,false);
    before=calls; CHECK(!copy(f) && calls==before && f->snapshots.size==MATTER_IM_READ_SNAPSHOT_BYTES);
    string(f,0,false); CHECK(copy(f)==MATTER_IM_RESOURCE_EXHAUSTED && calls==before);
    destroy(f);
    printf("PASS inline snapshots: strings/bytes through 8 encoded bytes, 9-byte fallback, ARRAY/STRUCTURE, scratch overwrite, record relocation, cumulative budget; value=%zu\n",sizeof(Matter_Im_Snapshot_Value));
}
static void shared_snapshots(void) {
    Fixture* a=create();
    Fixture* b=calloc(1,sizeof(*b)); CHECK(b);
    Matter_Im_Snapshot_Pool* pool=calloc(1,sizeof(*pool)); CHECK(pool);
    a->snapshots.pool=b->snapshots.pool=pool;
    string(a,4093,false); CHECK(!copy(a)); const uint8_t* first=a->value.data;
    size_t retained=live_bytes,used=b->snapshots.size;
    for(size_t fault=1;fault<=2;++fault) {
        string(b,4093,false); fail_at=calls+fault;
        CHECK(copy(b)==MATTER_IM_RESOURCE_EXHAUSTED); fail_at=0;
        CHECK(live_bytes==retained && b->snapshots.size==used && b->value.data==b->input && first[3]=='a');
    }
    string(b,4093,false); CHECK(!copy(b) && b->value.data==first);
    CHECK(live_bytes==retained+sizeof(Matter_Im_Snapshot_Reference));
    /* One pool may share identical bytes across different fabric/report
     * identities only AFTER each independent provider read and validation.
     * Changed bytes retain their own generation; versions live in each value. */
    string(b,4093,false); b->input[0]='b'; CHECK(!copy(b) && b->value.data!=first);
    const uint8_t* changed=b->value.data;
    memset(a->input,0,sizeof(a->input)); memset(b->input,0,sizeof(b->input));
    matter_im_snapshots_clear(&a->snapshots); CHECK(first[3]=='a' && changed[3]=='b');
    CHECK(a->snapshots.pool==pool); /* Binding survives report cleanup. */
    size_t before=calls;
    matter_im_snapshot_release(&b->snapshots,first);
    CHECK(calls==before && changed[3]=='b' && b->snapshots.size==8192);
    matter_im_snapshots_clear(&b->snapshots); CHECK(!live && !live_bytes);
    for(unsigned i=0;i<MATTER_IM_SNAPSHOT_BUCKETS;++i) CHECK(!pool->buckets[i]);
    /* Duplicate references still consume the original per-report byte budget. */
    for(unsigned i=0;i<4;++i) { string(a,4093,false); CHECK(!copy(a)); }
    CHECK(a->snapshots.size==16384);
    string(a,0,false); before=calls; CHECK(copy(a)==MATTER_IM_RESOURCE_EXHAUSTED && before==calls);
    matter_im_snapshots_clear(&a->snapshots);
    /* A saturated reference count cannot wrap or publish a partial reference. */
    string(a,30,false); CHECK(!copy(a)); Matter_Im_Shared_Snapshot* shared=a->snapshots.shared->value;
    shared->references=SIZE_MAX; string(b,30,false); retained=live_bytes;
    CHECK(copy(b)==MATTER_IM_RESOURCE_EXHAUSTED && live_bytes==retained && !b->snapshots.size);
    shared->references=1;
    matter_im_snapshots_clear(&a->snapshots); CHECK(!live && !live_bytes);
    free(a); free(b); free(pool);
    puts("PASS shared snapshots: immutable generations, per-report limits, OOM at both sites, reference overflow, independent release and empty pool");
}
static void bounded_index(void) {
    Fixture* a=create(); Fixture* b=calloc(1,sizeof(*b)); CHECK(b);
    Matter_Im_Snapshot_Pool* pool=calloc(1,sizeof(*pool)); CHECK(pool);
    a->snapshots.pool=b->snapshots.pool=pool;
    for(unsigned i=0;i<120;++i) {
        string(a,30,false); a->input[0]=(uint8_t)i; CHECK(!copy(a)); a->retained[i]=a->value.data;
    }
    CHECK(pool->entries==112 && pool->small_entries==112);
    string(b,30,false); b->input[0]=0; CHECK(!copy(b) && b->value.data==a->retained[0]);
    for(unsigned i=0;i<16;++i) {
        string(b,254,false); b->input[0]=(uint8_t)i; CHECK(!copy(b));
    }
    CHECK(pool->entries==128 && pool->small_entries==112);
    string(a,254,false); a->input[0]=33; size_t before=live_bytes,used=a->snapshots.size;
    fail_at=calls+1; CHECK(copy(a)==MATTER_IM_RESOURCE_EXHAUSTED); fail_at=0;
    CHECK(live_bytes==before && a->snapshots.size==used && pool->entries==128);
    CHECK(!copy(a) && a->value.data==a->snapshots.head->data && pool->entries==128);
    /* The exhausted index cannot reject a valid report, move old references,
     * or stop sharing a value already in the index. */
    matter_im_snapshots_clear(&a->snapshots);
    CHECK(pool->entries==17 && b->snapshots.shared && b->snapshots.size==4128);
    CHECK(b->snapshots.shared->value->data[0]==0x10);
    matter_im_snapshots_clear(&b->snapshots); CHECK(!pool->entries && !pool->small_entries && !live);
    static const uint8_t collision[2][8]={{0x63,0xa5,0x30,0x85,0x64,0x96,0x5f,0xd7},{0x79,0x93,0xd2,0x25,0x1b,0x5b,0xa3,0xc1}};
    string(a,30,false); memcpy(a->input,collision[0],8); CHECK(!copy(a));
    string(b,30,false); memcpy(b->input,collision[1],8); CHECK(!copy(b));
    CHECK(a->snapshots.shared->value->hash==b->snapshots.shared->value->hash);
    CHECK(a->value.data!=b->value.data && !memcmp(a->value.data+2,collision[0],8) && !memcmp(b->value.data+2,collision[1],8));
    matter_im_snapshots_clear(&a->snapshots); matter_im_snapshots_clear(&b->snapshots);
    CHECK(!pool->entries && !live && !live_bytes); free(a); free(b); free(pool);
    puts("PASS bounded snapshot index: unique-data fallback/OOM, reserved large entries, sharing at capacity, real hash collision and full cleanup");
}
int main(void) { exact_and_boundaries(); errors_and_oom(); consumed_and_compact(); inline_values(); shared_snapshots(); bounded_index(); return 0; }
