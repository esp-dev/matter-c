/* Private indexed-table lifetime/OOM contract; no large task-stack fixture. */
#include <stdio.h>
#include <string.h>
#include "test_alloc_bytes.h"
#define calloc matter_test_calloc
#define free matter_test_free
#include "model/matter_im_blocks_internal.h"
#undef calloc
#undef free
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"blocks:%d: %s\n",__LINE__,#x); abort(); } } while(0)
typedef struct { uint64_t value; uint8_t bytes[40]; } Item;
MATTER_IM_BLOCK_TABLE(items,Item)
typedef struct { Matter_Im_Blocks table; Item* pointers[512]; } Fixture;
static void stable(void) {
    Fixture* f=calloc(1,sizeof(*f)); CHECK(f); peak_bytes=max_request=0;
    CHECK(items_reserve(&f->table,0,512) && !calls && !live);
    for(size_t i=0;i<512;++i) {
        size_t old_live=live,old_capacity=f->table.capacity;
        CHECK(items_reserve(&f->table,i+1,512));
        CHECK(live==old_live+(i==old_capacity)); /* No freed/replaced old block. */
        f->pointers[i]=items_at(&f->table,i);
        CHECK(f->pointers[i] && (uintptr_t)f->pointers[i]%sizeof(uint64_t)==0);
        CHECK(!f->pointers[i]->value);
        for(size_t j=0;j<sizeof(f->pointers[i]->bytes);++j) CHECK(!f->pointers[i]->bytes[j]);
        f->pointers[i]->value=UINT64_MAX-i; memset(f->pointers[i]->bytes,(int)i,sizeof(f->pointers[i]->bytes));
        for(size_t j=i+1;j--;) {
            CHECK(items_at(&f->table,j)==f->pointers[j]);
            CHECK(f->pointers[j]->value==UINT64_MAX-j && f->pointers[j]->bytes[39]==(uint8_t)j);
        }
    }
    size_t before=calls; fail_at=calls+1;
    CHECK(items_reserve(&f->table,512,512) && !items_reserve(&f->table,513,512) && calls==before);
    CHECK(!items_at(&f->table,512));
    matter_im_blocks_clear(&f->table); matter_im_blocks_clear(&f->table); fail_at=0;
    CHECK(!live && !live_bytes && calls==before && !f->table.cache && !f->table.capacity);
    CHECK(max_request<=offsetof(items_Block,data)+16*sizeof(Item));
    printf("MEMORY stable blocks: items=512 peak=%zu largest=%zu\n",peak_bytes,max_request); free(f);
}
static void oom(void) {
    /* Empty and partially populated tables: fail each allocation in one atomic
     * multi-block reservation. Existing payloads/links/cache stay untouched. */
    for(unsigned existing=0;existing<2;++existing) {
        for(size_t site=1;site<=32;++site) {
            Matter_Im_Blocks table={0};
            if(existing) { CHECK(items_reserve(&table,1,512)); items_at(&table,0)->value=73; }
            Matter_Im_Blocks before=table; Item* first=existing?items_at(&table,0):NULL;
            size_t bytes=live_bytes,blocks=live; fail_at=calls+site;
            CHECK(!items_reserve(&table,512,512)); fail_at=0;
            CHECK(table.head==before.head && table.tail==before.tail && table.cache==before.cache && table.capacity==before.capacity);
            CHECK(live==blocks && live_bytes==bytes && (!first || (first==items_at(&table,0) && first->value==73 && !table.tail->next)));
            matter_im_blocks_clear(&table); CHECK(!live && !live_bytes);
        }
    }
    Matter_Im_Blocks table={0}; size_t before=calls;
    CHECK(!matter_im_blocks_reserve(&table,1,512,offsetof(items_Block,data),SIZE_MAX));
    CHECK(!matter_im_blocks_reserve(&table,1,512,offsetof(items_Block,data),0) && calls==before);
    CHECK(items_reserve(&table,17,17) && table.capacity==17 && !items_reserve(&table,18,17));
    matter_im_blocks_clear(&table); CHECK(!live && !live_bytes);
    puts("PASS blocks: stable/aligned/zeroed addresses, bounded allocations, forward/backward lookup, all 64 staged OOM positions, overflow/limit and allocation-free cleanup");
}
static void sparse(void) {
    Fixture* f=calloc(1,sizeof(*f)); CHECK(f);
    const size_t selected[]={511,32,255,0,17,300};
    for(size_t i=0;i<sizeof(selected)/sizeof(*selected);++i) {
        size_t index=selected[i]; CHECK(items_reserve_at(&f->table,index,512));
        f->pointers[index]=items_at(&f->table,index); CHECK(f->pointers[index]);
        f->pointers[index]->value=index+1;
        for(size_t j=0;j<=i;++j) {
            index=selected[j]; CHECK(items_at(&f->table,index)==f->pointers[index] && f->pointers[index]->value==index+1);
        }
    }
    CHECK(!items_at(&f->table,64) && !items_at(&f->table,400) && !items_at(&f->table,512));
    for(size_t index=512;index--;) {
        CHECK(items_reserve_at(&f->table,index,512));
        Item* item=items_at(&f->table,index); CHECK(item && (uintptr_t)item%sizeof(uint64_t)==0);
        if(!f->pointers[index]) { CHECK(!item->value && !item->bytes[39]); item->value=index+1; f->pointers[index]=item; }
    }
    CHECK(f->table.capacity==512);
    for(size_t index=0;index<512;++index) CHECK(items_at(&f->table,index)==f->pointers[index] && f->pointers[index]->value==index+1);
    matter_im_blocks_clear(&f->table); CHECK(!live && !live_bytes); free(f);
    const unsigned faults[]={0,32,511};
    for(unsigned position=0;position<3;++position) {
        unsigned index=faults[position];
        Matter_Im_Blocks table={0}; CHECK(items_reserve_at(&table,128,512));
        Item* held=items_at(&table,128); held->value=73;
        CHECK(!items_at(&table,0) && !items_at(&table,511));
        Matter_Im_Blocks before=table; size_t bytes=live_bytes,blocks=live;
        fail_at=calls+1; CHECK(!items_reserve_at(&table,index,512)); fail_at=0;
        CHECK(table.head==before.head && table.tail==before.tail && table.cache==before.cache && table.capacity==before.capacity);
        CHECK(live_bytes==bytes && live==blocks && items_at(&table,128)==held && held->value==73 && !table.tail->next);
        CHECK(items_reserve_at(&table,index,512)); matter_im_blocks_clear(&table); CHECK(!live && !live_bytes);
    }
    Matter_Im_Blocks table={0}; size_t before=calls;
    CHECK(!items_reserve_at(&table,0,0) && !items_reserve_at(&table,512,512) && !items_reserve_at(&table,SIZE_MAX,512));
    CHECK(!matter_im_blocks_reserve_at(&table,0,512,offsetof(items_Block,data),SIZE_MAX) && calls==before);
    CHECK(items_reserve_at(&table,16,17) && table.head==table.tail && table.head->start==16 && table.head->count==1 && table.capacity==1);
    CHECK(!items_at(&table,15) && items_at(&table,16) && !items_at(&table,17));
    matter_im_blocks_clear(&table); CHECK(!live && !live_bytes);
    puts("PASS sparse blocks: arbitrary insertion, leading/interior/trailing gaps, all512 stable aligned slots, short tail, OOM unchanged links/cache/data and full cleanup");
}
int main(void) { stable(); oom(); sparse(); return 0; }
