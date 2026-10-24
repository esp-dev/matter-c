#include <stdio.h>
#include "test_alloc_bytes.h"
#define calloc matter_test_calloc
#define free matter_test_free
#include "model/matter_im_events_internal.h"
#undef calloc
#undef free
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"event-metadata:%d: %s\n",__LINE__,#x); abort(); } } while(0)
typedef struct {
    Matter_Im_Event_Expansion_T expansion;
    Matter_Im_Blocks paths;
    Matter_Event_Filter_T* filters;
    size_t count;
    unsigned maximum,enumerations;
    Matter_Im_Event_Request_T* references[MATTER_EVENT_PATH_CAPACITY];
} Fixture;
static Matter_Result_T enumerate(void* u,const Matter_Im_Event_Selector_T* q,const Matter_Event_Path_T* after,
    Matter_Event_Path_T* path,bool* found) {
    Fixture* f=u; CHECK(!q->present); ++f->enumerations;
    uint32_t event=after?after->event+1:1; *found=event<=f->maximum;
    *path=(Matter_Event_Path_T){1,0x91,event}; return MATTER_OK;
}
static Fixture* create(void) {
    Fixture* f=calloc(1,sizeof(*f)); CHECK(f && !live);
    f->maximum=MATTER_EVENT_PATH_CAPACITY; f->expansion.enumerate=enumerate; return f;
}
static void destroy(Fixture* f) {
    size_t before=calls; fail_at=calls+1;
    matter_im_event_metadata_clear(&f->expansion,&f->paths,&f->filters);
    matter_im_event_metadata_clear(&f->expansion,&f->paths,&f->filters); fail_at=0;
    CHECK(calls==before && !live && !live_bytes); free(f);
}
int main(void) {
    Fixture* f=create(); Matter_Im_Event_Selector_T wildcard={0};
    CHECK(!matter_im_event_selector_add(&f->expansion,&f->paths,&f->count,&wildcard,true) && !f->count);
    while(f->expansion.cursor<1) {
        size_t old=f->count; unsigned calls_before=f->enumerations;
        CHECK(!matter_im_event_expand(&f->expansion,f,1,&f->paths,&f->count));
        CHECK(f->enumerations-calls_before<=MATTER_IM_READ_WORK_BATCH);
        for(size_t i=0;i<f->count;++i) {
            Matter_Im_Event_Request_T* q=matter_im_event_paths_at(&f->paths,i);
            if(i<old) CHECK(q==f->references[i]); else f->references[i]=q;
            CHECK(q->path.event==i+1 && q->wildcard && q->urgent && !q->status);
        }
    }
    CHECK(f->count==MATTER_EVENT_PATH_CAPACITY && f->expansion.candidates==MATTER_EVENT_PATH_CAPACITY);
    size_t before=calls; fail_at=calls+1; matter_im_event_selectors_clear(&f->expansion); fail_at=0;
    CHECK(calls==before && !f->expansion.requests && !f->expansion.current && !f->expansion.last);
    size_t held=live_bytes; fail_at=calls+1;
    CHECK(!matter_im_event_filters_reserve(&f->filters,f->count) && !f->filters && live_bytes==held); fail_at=0;
    CHECK(matter_im_event_filters_reserve(&f->filters,f->count));
    CHECK(matter_test_allocation_size(f->filters)==f->count*sizeof(*f->filters));
    before=calls; fail_at=calls+1;
    CHECK(matter_im_event_filters_reserve(&f->filters,f->count) && calls==before); fail_at=0;
    printf("MEMORY event metadata: full_paths=%zu retained_path_blocks=%zu filter_bytes=%zu\n",f->count,held,live_bytes-held);
    destroy(f);
    /* Raw-selector and first concrete-path allocation fail independently. */
    Matter_Im_Event_Selector_T concrete={.present=MATTER_IM_CONCRETE,.path={1,0x91,3}};
    for(size_t site=1;site<=2;++site) {
        f=create(); fail_at=calls+site;
        CHECK(matter_im_event_selector_add(&f->expansion,&f->paths,&f->count,&concrete,false)==MATTER_IM_RESOURCE_EXHAUSTED); fail_at=0;
        CHECK(!f->count && !f->paths.head && !f->expansion.requests && !live_bytes); destroy(f);
    }
    /* Concrete metadata wins over overlapping wildcard results; urgency is ORed.
     * 119 wildcard candidates plus the concrete selector consume exactly120. */
    f=create(); f->maximum=MATTER_EVENT_PATH_CAPACITY-1;
    CHECK(!matter_im_event_selector_add(&f->expansion,&f->paths,&f->count,&concrete,false));
    Matter_Im_Event_Request_T* explicit_path=matter_im_event_paths_at(&f->paths,0);
    CHECK(!matter_im_event_selector_add(&f->expansion,&f->paths,&f->count,&wildcard,true));
    while(f->expansion.cursor<2) CHECK(!matter_im_event_expand(&f->expansion,f,2,&f->paths,&f->count));
    CHECK(f->count==MATTER_EVENT_PATH_CAPACITY-1 && f->expansion.candidates==MATTER_EVENT_PATH_CAPACITY);
    CHECK(matter_im_event_paths_at(&f->paths,0)==explicit_path && !explicit_path->wildcard && explicit_path->urgent);
    destroy(f);
    puts("PASS event metadata: stable paths, exact filters, selector phase cleanup, atomic admission/filter OOM, concrete precedence, union/urgency, candidate/work limits and allocation-free cleanup");
    return 0;
}
