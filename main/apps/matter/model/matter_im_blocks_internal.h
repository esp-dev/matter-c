#ifndef MATTER_IM_BLOCKS_INTERNAL_H_INCLUDED
#define MATTER_IM_BLOCKS_INTERNAL_H_INCLUDED 1
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Bounded indexed storage. Growth never moves existing elements. The owner
 * serializes access, and keeps logical count/cursors independently of capacity.
 * A cache makes forward scans linear; backwards access restarts at the head.
 * No global allocator, directory of maximum-sized pointers or task-stack data. */
enum { MATTER_IM_BLOCK_ITEMS=16, MATTER_IM_BLOCK_INITIAL=9 };
typedef struct Matter_Im_Block {
    struct Matter_Im_Block* next;
    uint16_t start,count; /* Internal result ceiling is 512, never wire indexes. */
} Matter_Im_Block;
typedef struct {
    Matter_Im_Block *head,*tail,*cache;
    size_t capacity;
} Matter_Im_Blocks;
static inline void matter_im_blocks_free(Matter_Im_Block* block) {
    while(block) { Matter_Im_Block* next=block->next; free(block); block=next; }
}
static inline void matter_im_blocks_clear(Matter_Im_Blocks* blocks) {
    matter_im_blocks_free(blocks->head); memset(blocks,0,sizeof(*blocks));
}
static inline bool matter_im_blocks_reserve(Matter_Im_Blocks* blocks,size_t needed,size_t limit,
    size_t offset,size_t item_size) {
    if(needed>limit || limit>UINT16_MAX || offset<sizeof(Matter_Im_Block) || !item_size) return false;
    if(needed<=blocks->capacity) return true;
    Matter_Im_Block *head=NULL,*tail=NULL;
    size_t capacity=blocks->capacity;
    while(capacity<needed) {
        size_t count=MATTER_IM_BLOCK_ITEMS;
        if(!capacity && needed<MATTER_IM_BLOCK_ITEMS)
            count=needed<MATTER_IM_BLOCK_INITIAL?MATTER_IM_BLOCK_INITIAL:needed;
        if(count>limit-capacity) count=limit-capacity;
        if(count>(SIZE_MAX-offset)/item_size) { matter_im_blocks_free(head); return false; }
        Matter_Im_Block* block=calloc(1,offset+count*item_size);
        if(!block) { matter_im_blocks_free(head); return false; }
        *block=(Matter_Im_Block){NULL,(uint16_t)capacity,(uint16_t)count};
        if(tail) tail->next=block; else head=block;
        tail=block; capacity+=count;
    }
    /* A multi-block reservation publishes only after every allocation succeeds.
     * OOM preserves all old elements, capacity, links and the lookup cache. */
    if(blocks->tail) blocks->tail->next=head; else blocks->head=head;
    blocks->tail=tail; blocks->capacity=capacity; return true;
}
static inline Matter_Im_Block* matter_im_blocks_find(Matter_Im_Blocks* blocks,size_t index) {
    Matter_Im_Block* block=blocks->cache; Matter_Im_Block* previous=NULL;
    if(!block || index<block->start) block=blocks->head;
    while(block && index>=block->start && index-block->start>=block->count) { previous=block; block=block->next; }
    if(block && index>=block->start) { blocks->cache=block; return block; }
    /* Cache the preceding group for forward holes, so each skipped ordinal
     * does not rescan the head when a later selected group exists. */
    blocks->cache=previous?previous:block; return NULL;
}
/* Alternative to dense reserve: allocate only the indexed group needed now.
 * Do not mix reservation modes in one table. limit is fixed for this capture;
 * capacity counts allocated slots, including holes inside selected groups.
 * Sorted links preserve stable addresses and linear forward lookup. In-order
 * capture appends through tail without rescanning earlier groups. OOM changes
 * no published link, capacity or cache. */
static inline bool matter_im_blocks_reserve_at(Matter_Im_Blocks* blocks,size_t index,size_t limit,
    size_t offset,size_t item_size) {
    if(index>=limit || limit>UINT16_MAX || offset<sizeof(Matter_Im_Block) || !item_size) return false;
    size_t start=index-index%MATTER_IM_BLOCK_ITEMS,count=limit-start;
    if(count>MATTER_IM_BLOCK_ITEMS) count=MATTER_IM_BLOCK_ITEMS;
    if(count>(SIZE_MAX-offset)/item_size) return false;
    Matter_Im_Block** link=&blocks->head;
    if(blocks->tail && start>=blocks->tail->start) {
        if(start==blocks->tail->start) return index-start<blocks->tail->count;
        link=&blocks->tail->next;
    } else {
        while(*link && (*link)->start<start) link=&(*link)->next;
        if(*link && (*link)->start==start) return index-start<(*link)->count;
    }
    Matter_Im_Block* block=calloc(1,offset+count*item_size);
    if(!block) return false;
    *block=(Matter_Im_Block){*link,(uint16_t)start,(uint16_t)count};
    *link=block; if(!block->next) blocks->tail=block;
    blocks->cache=block; blocks->capacity+=count; return true;
}
/* Typed flexible arrays preserve each element's alignment and effective type.
 * The link is the initial member, so conversion back to its typed owner is C99. */
#define MATTER_IM_BLOCK_TABLE(Name,Type) \
    typedef struct { Matter_Im_Block link; Type data[]; } Name##_Block; \
    static inline bool Name##_reserve(Matter_Im_Blocks* blocks,size_t needed,size_t limit) { \
        return matter_im_blocks_reserve(blocks,needed,limit,offsetof(Name##_Block,data),sizeof(Type)); \
    } \
    static inline bool Name##_reserve_at(Matter_Im_Blocks* blocks,size_t index,size_t limit) { \
        return matter_im_blocks_reserve_at(blocks,index,limit,offsetof(Name##_Block,data),sizeof(Type)); \
    } \
    static inline Type* Name##_at(Matter_Im_Blocks* blocks,size_t index) { \
        Matter_Im_Block* block=matter_im_blocks_find(blocks,index); \
        return block?&((Name##_Block*)(void*)block)->data[index-block->start]:NULL; \
    }
#endif
