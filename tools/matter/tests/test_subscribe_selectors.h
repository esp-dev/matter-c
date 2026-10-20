typedef struct {
    RichSub rich;
    unsigned count,enumerations,versions,denied,unreadable,seen,statuses;
    uint32_t version_hint; unsigned bad_enum;
    size_t span_size;
    bool version_error,deny_view,empty,bad_utf8,null_data,too_large,wrong_filter,bad_filter_tail;
    uint8_t large[4096];
} SelectorSub;
static const uint8_t selector_text[]={'a',0,0xc4,0x85};
static const uint8_t selector_bytes[]={0,0xff,1};
static Matter_Im_Status_T selector_allow(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    SelectorSub* s=u; sub_guard(&s->rich.model); CHECK(session==1 && p->endpoint==1 && p->cluster==0x91);
    ++s->rich.model.auths;
    return p->attribute==s->denied || (s->deny_view && privilege==MATTER_IM_VIEW)?MATTER_IM_UNSUPPORTED_ACCESS:0;
}
static Matter_Im_Status_T selector_describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* a) {
    SelectorSub* s=u; sub_guard(&s->rich.model);
    if(!p->attribute || p->attribute>s->count) return MATTER_IM_UNSUPPORTED_ATTRIBUTE;
    if(p->attribute==s->unreadable) return MATTER_IM_UNSUPPORTED_READ;
    *a=(Matter_Im_Attribute_T){MATTER_IM_ADMINISTER,false}; return 0;
}
static Matter_Im_Status_T selector_read(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    SelectorSub* s=u; RichSub* r=&s->rich; sub_guard(&r->model); CHECK(filtered); ++r->model.reads;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=p->attribute,.data_version=r->model.version};
    if(p->attribute<=2) {
        const uint8_t* data=p->attribute==1?selector_text:selector_bytes;
        size_t size=p->attribute==1?sizeof(selector_text):sizeof(selector_bytes);
        memcpy(r->scratch,data,size); if(s->bad_utf8) r->scratch[0]=0xff;
        v->type=p->attribute==1?MATTER_TLV_UTF8:MATTER_TLV_BYTES;
        v->data=s->empty || s->null_data?NULL:s->too_large || s->span_size?s->large:r->scratch;
        v->size=s->empty?0:s->too_large?4096:s->span_size?s->span_size:size;
    }
    return 0;
}
static Matter_Result_T selector_version(void* u,const Matter_Im_Path_T* p,uint32_t* version) {
    SelectorSub* s=u; (void)p; sub_guard(&s->rich.model); ++s->versions; *version=s->version_hint;
    return s->version_error?MATTER_PORT_ERROR:MATTER_OK;
}
static Matter_Result_T selector_enumerate(void* u,const Matter_Im_Selector_T* q,const Matter_Im_Path_T* after,Matter_Im_Path_T* next,bool* found) {
    SelectorSub* s=u; sub_guard(&s->rich.model); ++s->enumerations;
    if(s->bad_enum==1) return MATTER_PORT_ERROR;
    unsigned attr=after?after->attribute+1:1;
    *found=attr<=s->count;
    if(*found) {
        *next=(Matter_Im_Path_T){1,0x91,attr};
        if(s->bad_enum==2 && after) *next=*after;
        if(s->bad_enum==3) next->cluster=0x92;
        CHECK(!(q->present & MATTER_IM_ATTRIBUTE));
    }
    return MATTER_OK;
}
static SelectorSub* selector_new(unsigned count,bool fast) {
    SelectorSub* s=calloc(1,sizeof(*s)); CHECK(s); s->count=count; s->version_hint=7;
    RichSub* r=&s->rich; r->fabric=1; r->expected_version=7;
    Matter_Im_Subscribe_Port_T p=sub_port(&r->model);
    p.attributes=(Matter_Im_Read_Port_T){s,selector_allow,selector_describe,selector_read,selector_enumerate,fast?selector_version:NULL};
    Matter_Im_Read_Fabric_Port_T f={rich_fabric}; Matter_Im_Subscribe_Config_T c={{1,12,false},30000,100,false};
    r->model.active=matter_im_subscribe_new_case(&p,&f,&c,0); CHECK(r->model.active); return s;
}
static void selector_request(SelectorSub* s,unsigned selectors,bool concrete,unsigned filters,bool conflict) {
    RichSub* r=&s->rich; CHECK(!matter_tlv_writer_init(&r->writer,r->model.input,sizeof(r->model.input),8));
    rich_put(r,MATTER_TLV_STRUCTURE,-1,0); rich_put(r,MATTER_TLV_BOOL,0,1); rich_put(r,MATTER_TLV_UNSIGNED,1,2); rich_put(r,MATTER_TLV_UNSIGNED,2,5);
    rich_put(r,MATTER_TLV_ARRAY,3,0);
    for(unsigned i=0;i<selectors;++i) {
        rich_put(r,MATTER_TLV_LIST,-1,0); rich_put(r,MATTER_TLV_UNSIGNED,2,1); rich_put(r,MATTER_TLV_UNSIGNED,3,0x91);
        if(concrete) rich_put(r,MATTER_TLV_UNSIGNED,4,i+1);
        rich_put(r,MATTER_TLV_END,-1,0);
    }
    rich_put(r,MATTER_TLV_END,-1,0); rich_put(r,MATTER_TLV_BOOL,7,1);
    if(filters) {
        rich_put(r,MATTER_TLV_ARRAY,8,0);
        for(unsigned i=0;i<filters;++i) {
            rich_put(r,MATTER_TLV_STRUCTURE,-1,0); rich_put(r,MATTER_TLV_LIST,0,0);
            if(s->wrong_filter || (s->bad_filter_tail && i+1==filters)) rich_put(r,MATTER_TLV_UNSIGNED,0,1);
            rich_put(r,MATTER_TLV_UNSIGNED,1,1); rich_put(r,MATTER_TLV_UNSIGNED,2,0x91); rich_put(r,MATTER_TLV_END,-1,0);
            rich_put(r,MATTER_TLV_UNSIGNED,1,conflict && i?8:7); rich_put(r,MATTER_TLV_END,-1,0);
        }
        rich_put(r,MATTER_TLV_END,-1,0);
    }
    rich_put(r,MATTER_TLV_UNSIGNED,255,13); rich_put(r,MATTER_TLV_END,-1,0); CHECK(!matter_tlv_writer_finish(&r->writer,&r->size));
    receive(&r->model,r->model.input,r->size,3,12,true);
}
static Matter_Im_Subscribe_Message_T selector_output(SelectorSub* s) {
    RichSub* r=&s->rich; Matter_Im_Subscribe_Message_T out;
    for(unsigned i=0;i<128;++i) {
        unsigned before=s->enumerations,reads=r->model.reads;
        CHECK(matter_im_subscribe_process(r->model.active,r->clock)==MATTER_PENDING);
        CHECK(s->enumerations-before<=8 && r->model.reads-reads<=9);
        if(!matter_im_subscribe_output(r->model.active,&out)) return out;
    }
    CHECK(false); return (Matter_Im_Subscribe_Message_T){0};
}
static bool selector_report(SelectorSub* s,Matter_Im_Subscribe_Message_T out) {
    RichSub* r=&s->rich; CHECK(out.opcode==5 && !matter_tlv_init(&r->reader,out.data,out.size,8));
    unsigned depth=0,attr=0; bool more=false;
    while(!matter_tlv_next(&r->reader,&r->token)) {
        Matter_Tlv_Element_T* e=&r->token;
        if(e->type==MATTER_TLV_END) { CHECK(depth); --depth; continue; }
        if(depth==1 && e->tag.number==3) more=e->unsigned_value!=0;
        if(depth==4 && !e->tag.number && e->type==MATTER_TLV_UNSIGNED) CHECK(e->unsigned_value==r->expected_version);
        if(depth==5 && e->tag.number==4) attr=(unsigned)e->unsigned_value;
        if(depth==5 && !e->tag.number) { CHECK(e->unsigned_value==MATTER_IM_UNSUPPORTED_ACCESS); ++s->statuses; }
        if(depth==4 && e->tag.number==2) {
            CHECK(attr && attr!=s->denied && attr!=s->unreadable); ++s->seen;
            if(attr<=2) {
                const uint8_t* bytes=attr==1?selector_text:selector_bytes; size_t size=attr==1?sizeof(selector_text):sizeof(selector_bytes);
                CHECK(e->type==(attr==1?MATTER_TLV_UTF8:MATTER_TLV_BYTES));
                CHECK(e->size==(s->empty?0:size) && (!e->size || !memcmp(e->data,bytes,size)));
            } else CHECK(e->type==MATTER_TLV_UNSIGNED && e->unsigned_value==attr);
        }
        if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) ++depth;
    }
    CHECK(!depth); return more;
}
static void selector_finish(SelectorSub* s,bool prime) {
    bool more; do { more=selector_report(s,selector_output(s)); memset(s->rich.scratch,0,sizeof(s->rich.scratch)); rich_ack(&s->rich,prime,false); } while(more);
    if(prime) rich_prime_finish(&s->rich);
    else CHECK(matter_im_subscribe_process(s->rich.model.active,s->rich.clock)==MATTER_PENDING);
}
static void selector_tests(void) {
    /* Multiple cluster selectors must not share the nine-item output budget.
     * Concrete-only collection also yields; neither path silently truncates. */
    for(unsigned wildcard=0;wildcard<2;++wildcard) {
        SelectorSub* many=selector_new(wildcard?2:MATTER_IM_SUB_MAX_ATTRIBUTE_PATHS,true);
        selector_request(many,MATTER_IM_SUB_MAX_ATTRIBUTE_PATHS,!wildcard,0,false); selector_finish(many,true);
        CHECK(many->seen==MATTER_IM_SUB_MAX_ATTRIBUTE_PATHS*(wildcard?2u:1u)); rich_free(&many->rich);
    }
    SelectorSub* overflow=selector_new(MATTER_IM_SUB_MAX_ATTRIBUTE_PATHS+1,true);
    selector_request(overflow,MATTER_IM_SUB_MAX_ATTRIBUTE_PATHS+1,true,0,false);
    Matter_Im_Subscribe_Message_T rejected=selector_output(overflow);
    CHECK(rejected.opcode==1 && rejected.data[3]==MATTER_IM_PATHS_EXHAUSTED && !overflow->rich.model.reserves && !overflow->rich.model.reads);
    rich_free(&overflow->rich);
    /* More than nine results; wildcard must use actual privilege, skip denied
     * or unreadable paths, and own UTF8/bytes before shared scratch changes. */
    SelectorSub* s=selector_new(20,true); s->deny_view=true; s->denied=3; s->unreadable=4;
    selector_request(s,1,false,0,false); selector_finish(s,true);
    CHECK(s->seen==18 && s->rich.model.reads==18 && !s->statuses && s->enumerations==21);
    s->deny_view=false; s->seen=0; s->count=21; /* Activation retains initial error-free paths. */
    CHECK(!matter_im_subscribe_changed(s->rich.model.active)); rich_update(&s->rich,2000); selector_finish(s,false);
    CHECK(s->seen==18 && s->enumerations==21); rich_free(&s->rich);
    s=selector_new(MATTER_IM_READ_MAX_RESULTS,false); selector_request(s,1,false,0,false); selector_finish(s,true);
    CHECK(s->seen==MATTER_IM_READ_MAX_RESULTS && s->rich.model.reads==MATTER_IM_READ_MAX_RESULTS); rich_free(&s->rich);
    s=selector_new(20,false); selector_request(s,1,false,0,false);
    while(matter_im_subscribe_state(s->rich.model.active)!=MATTER_IM_SUB_COLLECTING) CHECK(matter_im_subscribe_process(s->rich.model.active,0)==MATTER_PENDING);
    CHECK(s->rich.model.reads==8); s->denied=1; selector_finish(s,true);
    CHECK(s->seen==19 && !s->statuses); rich_free(&s->rich);
    s=selector_new(20,false); selector_request(s,1,false,0,false);
    while(matter_im_subscribe_state(s->rich.model.active)!=MATTER_IM_SUB_COLLECTING) CHECK(matter_im_subscribe_process(s->rich.model.active,0)==MATTER_PENDING);
    s->rich.fabric=0; Matter_Im_Subscribe_Message_T revoked=selector_output(s);
    CHECK(revoked.opcode==1 && revoked.data[3]==MATTER_IM_INVALID_ACTION); rich_free(&s->rich);
    /* Priming filters cannot unsubscribe values, including fast version bypass,
     * fallback read, duplicate equal filters, or a version changing during read. */
    for(unsigned mode=0;mode<4;++mode) {
        s=selector_new(12,mode!=0); if(mode==2) s->version_hint=8;
        selector_request(s,1,false,mode==3?83:1,false); selector_finish(s,true);
        CHECK(!s->seen && s->rich.model.reads==(mode==0 || mode==2?12u:0u));
        unsigned before=s->rich.model.reads,versions=s->versions;
        CHECK(!matter_im_subscribe_changed(s->rich.model.active)); rich_update(&s->rich,2000); selector_finish(s,false);
        CHECK(s->seen==12 && s->rich.model.reads==before+12 && s->versions==versions); rich_free(&s->rich);
    }
    s=selector_new(3,true); selector_request(s,2,false,83,true); selector_finish(s,true);
    CHECK(s->seen==6 && s->rich.model.reads==6); rich_free(&s->rich);
    /* Concrete paths retain View gating despite equal version filters. */
    s=selector_new(2,true); s->denied=1; selector_request(s,2,true,1,false); selector_finish(s,true);
    CHECK(s->statuses==1 && !s->seen && s->versions==1 && !s->rich.model.reads); rich_free(&s->rich);
    s=selector_new(2,false); s->empty=true; selector_request(s,2,true,0,false); selector_finish(s,true); CHECK(s->seen==2); rich_free(&s->rich);
    for(unsigned mode=0;mode<12;++mode) {
        s=selector_new(mode==3?MATTER_IM_READ_MAX_RESULTS+1:mode==4?0:2,true);
        s->bad_enum=mode<3?mode+1:0; s->wrong_filter=mode==5; s->bad_filter_tail=mode==6; s->version_error=mode==7;
        s->bad_utf8=mode==8; s->null_data=mode==9; s->too_large=mode==10;
        if(mode==11) s->span_size=180; /* Valid text must fit one entire report. */
        selector_request(s,1,mode>=8,mode==6?83:mode==5 || mode==7?1:0,false);
        Matter_Im_Subscribe_Message_T out=selector_output(s);
        CHECK(out.opcode==1 && out.data[3]==(mode<3?MATTER_IM_FAILURE:mode==3 || mode>=10?MATTER_IM_RESOURCE_EXHAUSTED:MATTER_IM_INVALID_ACTION));
        if(mode==5 || mode==6) CHECK(!s->rich.model.reads && !s->rich.model.reserves);
        rich_free(&s->rich);
    }
    /* Delete during collection and fail allocation of the first copied span. */
#ifdef MATTER_TEST_ALLOC
    for(unsigned allocation=1;allocation<=7;++allocation) {
        s=selector_new(24,true); selector_request(s,1,false,0,false);
        fail_at=calls+allocation; Matter_Im_Subscribe_Message_T error=selector_output(s); fail_at=0;
        CHECK(error.opcode==1 && error.data[3]==MATTER_IM_RESOURCE_EXHAUSTED && !s->rich.model.reads);
        rich_free(&s->rich); CHECK(!live); /* Selectors, yielded parsers and initial/growing results. */
    }
    s=selector_new(12,true); selector_request(s,1,false,83,false); size_t filter_base=live; fail_at=calls+2; /* Selectors, then filters. */
    Matter_Im_Subscribe_Message_T filter_error=selector_output(s); fail_at=0;
    CHECK(filter_error.opcode==1 && filter_error.data[3]==MATTER_IM_RESOURCE_EXHAUSTED && live==filter_base);
    CHECK(!s->rich.model.reads && !s->rich.model.reserves); rich_free(&s->rich); CHECK(!live);
    s=selector_new(12,true); selector_request(s,1,false,83,false); filter_base=live;
    selector_finish(s,true); CHECK(live==filter_base); /* Parser/selectors/filters released; one result table remains. */
    size_t idle_calls=calls,idle_bytes=live_bytes; fail_at=calls+1;
    for(unsigned i=0;i<64;++i) CHECK(matter_im_subscribe_process(s->rich.model.active,0)==MATTER_PENDING);
    CHECK(calls==idle_calls && live_bytes==idle_bytes && matter_im_subscribe_state(s->rich.model.active)==MATTER_IM_SUB_IDLE); fail_at=0;
    rich_free(&s->rich); CHECK(!live);
    s=selector_new(12,true); selector_request(s,1,false,83,false);
    while(matter_im_subscribe_state(s->rich.model.active)!=MATTER_IM_SUB_COLLECTING) CHECK(matter_im_subscribe_process(s->rich.model.active,0)==MATTER_PENDING);
    rich_free(&s->rich); CHECK(!live);
    s=selector_new(12,true); s->rich.model.reserve_error=true; selector_request(s,1,false,83,false); filter_base=live;
    filter_error=selector_output(s);
    CHECK(filter_error.opcode==1 && filter_error.data[3]==MATTER_IM_RESOURCE_EXHAUSTED && live==filter_base);
    rich_free(&s->rich); CHECK(!live);
    s=selector_new(2,true); selector_request(s,2,true,0,false); size_t base=live; fail_at=calls+1;
    Matter_Im_Subscribe_Message_T out=selector_output(s); fail_at=0;
    CHECK(out.opcode==1 && out.data[3]==MATTER_IM_RESOURCE_EXHAUSTED && live+1==base); rich_free(&s->rich); CHECK(!live); /* RX parser freed after selector failure. */
#endif
    puts("PASS Subscribe selectors: bounded wildcard/ACL, result cap and overflow, duplicate/conflicting/one-time DVF, fast/fallback version, UTF8/bytes snapshots/empty/invalid, enumeration errors");
}
