/* The frozen array policy is an independent oracle for the new list storage.
 * Allocation accounting covers the log alone; the large oracle lives on heap. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_alloc_bytes.h"
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"events:%d: %s\n",__LINE__,#x); abort(); } } while(0)
#define calloc matter_test_calloc
#define free matter_test_free
#include "../../../main/apps/matter/model/matter_events.c"
#undef calloc
#undef free
typedef struct {
    Matter_Events_T log;
    uint64_t high,next,limit,pending_next;
    size_t count,pending_count,stores;
    bool fail_load,fail_store;
    Matter_Event_Record_T records[MATTER_EVENTS_CAPACITY],pending[MATTER_EVENTS_CAPACITY];
    Matter_Event_Record_T input[MATTER_EVENTS_CAPACITY],out[MATTER_EVENTS_CAPACITY];
} Fixture;
static Matter_Result_T load(void* u,uint64_t* next) {
    Fixture* f=u; if(f->fail_load) return MATTER_PORT_ERROR; *next=f->high; return MATTER_OK;
}
static Matter_Result_T store(void* u,uint64_t high) {
    Fixture* f=u; ++f->stores; uint64_t next=123; size_t count=123;
    CHECK(matter_events_delete(f->log)==MATTER_BUSY && matter_events_position(f->log,&next)==MATTER_BUSY && next==123);
    CHECK(matter_events_copy(f->log,&f->input[0].path,0,f->out,&count)==MATTER_BUSY && count==123);
    CHECK(matter_events_forget_fabric(f->log,1)==MATTER_BUSY);
    CHECK(matter_events_prepare(f->log,f->input,1)==MATTER_BUSY);
    if(f->fail_store) return MATTER_PORT_ERROR;
    f->high=high; return MATTER_OK;
}
static Fixture* create(void) {
    Fixture* f=calloc(1,sizeof(*f)); CHECK(f);
    Matter_Events_Port_T port={f,load,store}; f->log=matter_events_new(&port); CHECK(f->log);
    CHECK(live==1 && live_bytes==sizeof(*f->log)); return f;
}
static void destroy(Fixture* f) { CHECK(matter_events_delete(f->log)==MATTER_OK); free(f); CHECK(!live && !live_bytes); }
static void input(Fixture* f,size_t count,uint8_t priority,uint8_t fabric) {
    for(size_t i=0;i<count;++i) {
        Matter_Event_Record_T* r=&f->input[i]; memset(r,0,sizeof(*r));
        r->path=(Matter_Event_Path_T){0,0x28,2}; r->number=UINT64_MAX;
        r->priority=priority; r->fabric=fabric; r->timestamp_ms=123+i; r->epoch=(i&1)!=0;
        r->size=5; memcpy(r->data,(uint8_t[]){0x15,0x24,0,(uint8_t)i,0x18},5);
    }
}
/* Original array admission/eviction algorithm, with the same durable block
 * reservation. It intentionally has no knowledge of nodes or eviction marks. */
static Matter_Result_T reference_prepare(Fixture* f,size_t count) {
    if(count>UINT64_MAX-f->next) return MATTER_LIMIT_REACHED;
    memcpy(f->pending,f->records,f->count*sizeof(*f->records)); f->pending_count=f->count;
    for(size_t j=0;j<count;++j) {
        const Matter_Event_Record_T* r=&f->input[j];
        if(f->pending_count==MATTER_EVENTS_CAPACITY) {
            size_t v=0;
            for(size_t i=1;i<f->pending_count;++i) if(f->pending[i].priority<f->pending[v].priority) v=i;
            if(f->pending[v].priority>r->priority || f->pending[v].number>=f->next) return MATTER_LIMIT_REACHED;
            memmove(&f->pending[v],&f->pending[v+1],(f->pending_count-v-1)*sizeof(*f->pending)); --f->pending_count;
        }
        f->pending[f->pending_count]=*r; f->pending[f->pending_count++].number=f->next+j;
    }
    f->pending_next=f->next+count;
    if(f->pending_next>f->limit) {
        if(f->fail_store) return MATTER_PORT_ERROR;
        uint64_t reserve=count>32?count:32;
        f->limit=UINT64_MAX-f->next<reserve?UINT64_MAX:f->next+reserve;
    }
    return MATTER_OK;
}
static void compare(Fixture* f) {
    uint64_t next; size_t count;
    CHECK(matter_events_position(f->log,&next)==MATTER_OK && next==f->next && f->high==f->limit);
    Matter_Event_Path_T path={0,0x28,2};
    CHECK(matter_events_copy(f->log,&path,0,f->out,&count)==MATTER_OK && count==f->count);
    for(size_t i=0;i<count;++i) CHECK(!memcmp(&f->out[i],&f->records[i],sizeof(*f->out)));
    CHECK(live==1+count && live_bytes==sizeof(*f->log)+count*sizeof(EventNode));
    CHECK(!f->log->pending && !f->log->pending_count);
    size_t nodes=0; EventNode* last=NULL;
    for(EventNode* n=f->log->records;n;n=n->next) { CHECK(!n->evicted); last=n; ++nodes; }
    CHECK(nodes==count && f->log->last==last);
    Matter_Event_Filter_T filters[]={{{0,0x28,2},false},{{0,0x28,2},true},{{0,0x28,2},true}};
    CHECK(matter_events_copy_selected(f->log,filters,3,0,1,NULL,&count)==MATTER_OK);
    size_t expected=0; for(size_t i=0;i<f->count;++i) expected+=f->records[i].fabric<=1;
    CHECK(count==expected && matter_events_copy_selected(f->log,filters,3,0,1,f->out,&count)==MATTER_OK && count==expected);
}
static Matter_Result_T batch(Fixture* f,size_t count,bool commit) {
    Matter_Result_T expected=reference_prepare(f,count),actual=matter_events_prepare(f->log,f->input,count);
    CHECK(actual==expected);
    if(actual==MATTER_OK) {
        size_t before=calls; uint64_t next=123;
        CHECK(matter_events_delete(f->log)==MATTER_BUSY && matter_events_position(f->log,&next)==MATTER_BUSY && next==123);
        CHECK(matter_events_forget_fabric(f->log,1)==MATTER_BUSY && matter_events_prepare(f->log,f->input,1)==MATTER_BUSY);
        /* Caller may overwrite input after prepare; publication owns its copy. */
        f->input[0].data[3]^=0x55;
        fail_at=calls+1; matter_events_finish(f->log,commit); fail_at=0; CHECK(calls==before);
        f->input[0].data[3]^=0x55;
        if(commit) { memcpy(f->records,f->pending,f->pending_count*sizeof(*f->records)); f->count=f->pending_count; f->next=f->pending_next; }
    }
    compare(f); return actual;
}
static void forget(Fixture* f,uint8_t fabric) {
    size_t n=0;
    for(size_t i=0;i<f->count;++i) if(f->records[i].fabric!=fabric) f->records[n++]=f->records[i];
    f->count=n; CHECK(matter_events_forget_fabric(f->log,fabric)==MATTER_OK); compare(f);
}
static void allocation_failures(void) {
    Fixture* f=calloc(1,sizeof(*f)); CHECK(f); Matter_Events_Port_T port={f,load,store};
    fail_at=calls+1; CHECK(!matter_events_new(&port)); fail_at=0; CHECK(!live);
    f->fail_load=true; CHECK(!matter_events_new(&port) && !live); free(f);
    for(unsigned full=0;full<2;++full) {
        f=create(); size_t idle=live_bytes;
        input(f,full?MATTER_EVENTS_CAPACITY:4,1,1); CHECK(batch(f,full?MATTER_EVENTS_CAPACITY:4,true)==MATTER_OK);
        /* Capacity 16 still reserves 32 numbers. Reach the durable boundary
         * before injecting a store failure, rather than assuming full == due. */
        if(full && f->next<f->limit) {
            size_t gap=(size_t)(f->limit-f->next); CHECK(gap<=MATTER_EVENTS_CAPACITY);
            input(f,gap,1,1); CHECK(batch(f,gap,true)==MATTER_OK);
        }
        EventNode* first=f->log->records; size_t old_bytes=live_bytes,stores=f->stores;
        input(f,4,2,2);
        for(size_t site=1;site<=4;++site) {
            fail_at=calls+site; CHECK(matter_events_prepare(f->log,f->input,4)==MATTER_LIMIT_REACHED); fail_at=0;
            CHECK(f->stores==stores && live_bytes==old_bytes && f->log->records==first); compare(f);
        }
        if(full) {
            f->fail_store=true; CHECK(batch(f,4,true)==MATTER_PORT_ERROR); f->fail_store=false;
            CHECK(live_bytes==old_bytes && f->log->records==first);
        }
        CHECK(batch(f,4,false)==MATTER_OK && live_bytes==old_bytes && f->log->records==first);
        input(f,MATTER_EVENTS_CAPACITY,2,2);
        fail_at=calls+MATTER_EVENTS_CAPACITY; CHECK(matter_events_prepare(f->log,f->input,MATTER_EVENTS_CAPACITY)==MATTER_LIMIT_REACHED); fail_at=0;
        CHECK(live_bytes==old_bytes); compare(f);
        CHECK(batch(f,MATTER_EVENTS_CAPACITY,true)==MATTER_OK);
        CHECK(live_bytes==idle+MATTER_EVENTS_CAPACITY*sizeof(EventNode));
        forget(f,2); CHECK(live_bytes==idle); destroy(f);
    }
    f=create(); input(f,1,1,0); f->fail_store=true;
    CHECK(batch(f,1,true)==MATTER_PORT_ERROR && f->stores==1); f->fail_store=false;
    CHECK(batch(f,1,false)==MATTER_OK && f->high==32 && !f->next);
    CHECK(matter_events_delete(f->log)==MATTER_OK); f->next=f->limit=f->high;
    port.user=f; f->log=matter_events_new(&port);
    CHECK(f->log); input(f,1,1,0); CHECK(batch(f,1,true)==MATTER_OK && f->records[0].number==32);
    destroy(f);
    puts("PASS event OOM: constructor/load, every batch node, full-batch tail, unchanged published log/numbers, allocation-free commit/abort, durable failure/restart");
}
static void priorities_and_edges(void) {
    Fixture* f=create(); input(f,MATTER_EVENTS_CAPACITY,2,0);
    CHECK(batch(f,MATTER_EVENTS_CAPACITY,true)==MATTER_OK);
    input(f,1,1,0); CHECK(batch(f,1,true)==MATTER_LIMIT_REACHED);
    /* One free slot holds new DEBUG; the next input must not evict it even
     * though the incoming CRITICAL could replace a retained CRITICAL. */
    f->records[0].fabric=1; f->log->records->record.fabric=1; forget(f,1);
    input(f,2,0,0); f->input[1].priority=2; CHECK(batch(f,2,true)==MATTER_LIMIT_REACHED);
    input(f,2,2,0); CHECK(batch(f,2,false)==MATTER_OK && batch(f,2,true)==MATTER_OK);
    EventNode* stable=f->log->records->next;
    input(f,1,2,0); CHECK(batch(f,1,true)==MATTER_OK && f->log->records==stable);
    /* Validation rejects the entire batch before allocating or reserving. */
    input(f,2,2,0); size_t before=calls;
    f->input[1].data[4]=0x15; CHECK(matter_events_prepare(f->log,f->input,2)==MATTER_INVALID_ARGUMENT && calls==before); compare(f);
    f->input[1].data[4]=0x18; f->input[1].fabric=255; CHECK(matter_events_prepare(f->log,f->input,2)==MATTER_INVALID_ARGUMENT); compare(f);
    CHECK(matter_events_prepare(f->log,f->input,0)==MATTER_INVALID_ARGUMENT && matter_events_prepare(f->log,f->input,MATTER_EVENTS_CAPACITY+1)==MATTER_INVALID_ARGUMENT);
    destroy(f);
    f=create(); CHECK(matter_events_delete(f->log)==MATTER_OK); f->high=f->next=f->limit=UINT64_MAX-1;
    Matter_Events_Port_T port={f,load,store}; f->log=matter_events_new(&port); CHECK(f->log);
    input(f,2,2,0); before=calls; CHECK(batch(f,2,true)==MATTER_LIMIT_REACHED && calls==before);
    CHECK(batch(f,1,true)==MATTER_OK && f->records[0].number==UINT64_MAX-1);
    CHECK(batch(f,1,true)==MATTER_LIMIT_REACHED); destroy(f);
    puts("PASS event policy: oldest lowest priority, reject staged eviction, full batch abort/commit, malformed/fabric/size, number exhaustion");
}
static uint32_t random_step(uint32_t* state) { *state=*state*1664525u+1013904223u; return *state; }
static void differential(void) {
    Fixture* f=create(); uint32_t seed=12345;
    for(unsigned step=0;step<4000;++step) {
        uint32_t r=random_step(&seed);
        if(r%7==0) forget(f,1+(r%3));
        else {
            size_t n=1+(r%7); input(f,n,0,0);
            for(size_t i=0;i<n;++i) { uint32_t v=random_step(&seed); f->input[i].priority=v%3; f->input[i].fabric=(v>>8)%4; }
            f->fail_store=(r%11)==0; (void)batch(f,n,(r%5)!=0); f->fail_store=false;
        }
    }
    destroy(f); printf("PASS event differential: 4000 mixed batches/aborts/store failures/fabric removals, capacity=%u\n",MATTER_EVENTS_CAPACITY);
}
int main(void) {
    allocation_failures(); priorities_and_edges(); differential();
    printf("MEMORY event log: idle=%zu record=%zu node=%zu full=%zu full-plus-one=%zu full-batch-peak=%zu\n",
        sizeof(struct Matter_Events),sizeof(Matter_Event_Record_T),sizeof(EventNode),
        sizeof(struct Matter_Events)+MATTER_EVENTS_CAPACITY*sizeof(EventNode),
        sizeof(struct Matter_Events)+(MATTER_EVENTS_CAPACITY+1)*sizeof(EventNode),
        sizeof(struct Matter_Events)+2*MATTER_EVENTS_CAPACITY*sizeof(EventNode));
    return 0;
}
