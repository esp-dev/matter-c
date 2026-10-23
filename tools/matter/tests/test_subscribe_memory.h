/* Saturate independently owned interactions, without relying on host model
 * attribute sizes. Fifteen CASE subscriptions across five fabric identities.
 * Provider scratch, request encoders and report consumers are heap fixtures. */
static Matter_Im_Snapshot_Pool* memory_pool;
static Matter_Im_Output_Pool* memory_encoder;
static size_t memory_value_size=30;
static Matter_Im_Status_T memory_read(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    SelectorSub* s=u; RichSub* r=&s->rich; sub_guard(&r->model); CHECK(filtered);
    ++r->model.reads; memset(r->scratch,(int)(p->attribute&255),memory_value_size);
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_BYTES,.data=r->scratch,.size=memory_value_size,.data_version=7};
    return MATTER_IM_SUCCESS;
}
static SelectorSub* memory_new(unsigned count,unsigned fabric) {
    SelectorSub* s=calloc(1,sizeof(*s)); CHECK(s); s->count=count;
    RichSub* r=&s->rich; r->fabric=(uint8_t)fabric;
    Matter_Im_Subscribe_Port_T p=sub_port(&r->model);
    p.attributes=(Matter_Im_Read_Port_T){s,selector_allow,selector_describe,memory_read,selector_enumerate,NULL};
    Matter_Im_Read_Fabric_Port_T f={rich_fabric};
    Matter_Im_Subscribe_Config_T c={{1,12,false},30000,1198,false};
    r->model.active=matter_im_subscribe_new_case(&p,&f,&c,0); CHECK(r->model.active);
    if(memory_encoder) CHECK(matter_im_subscribe_bind_output_pool(r->model.active,memory_encoder)==MATTER_OK);
    if(memory_pool) CHECK(matter_im_subscribe_bind_snapshot_pool(r->model.active,memory_pool)==MATTER_OK);
    selector_request(s,1,false,0,false); return s;
}
static bool memory_report(SelectorSub* s,Matter_Im_Subscribe_Message_T out) {
    RichSub* r=&s->rich; CHECK(out.opcode==5);
    CHECK(matter_tlv_init(&r->reader,out.data,out.size,8)==MATTER_TLV_OK);
    unsigned depth=0,attribute=0; bool more=false; Matter_Tlv_Result_T result;
    while((result=matter_tlv_next(&r->reader,&r->token))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&r->token;
        if(e->type==MATTER_TLV_END) { CHECK(depth); --depth; continue; }
        if(depth==1 && e->tag.number==3) more=e->unsigned_value!=0;
        if(depth==5 && e->tag.number==4) attribute=(unsigned)e->unsigned_value;
        if(depth==4 && e->tag.number==2) {
            CHECK(attribute==s->seen+1 && e->type==MATTER_TLV_BYTES && e->size==memory_value_size);
            for(size_t i=0;i<e->size;++i) CHECK(e->data[i]==(uint8_t)attribute);
            ++s->seen;
        }
        if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) ++depth;
    }
    CHECK(result==MATTER_TLV_DONE && !depth); return more;
}
typedef struct {
    RichSub rich;
    Matter_Im_Read_T active;
    unsigned reads,values,attributes;
    uint8_t data[1762]; /* ARRAY of 55 anonymous 30-byte BYTES, 9 copies =15858 B. */
} MemoryRead;
static Matter_Im_Status_T memory_read_allow(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    MemoryRead* m=u; (void)p; CHECK(session==1 && privilege==MATTER_IM_VIEW);
    CHECK(matter_im_read_cancel(m->active)==MATTER_BUSY); return MATTER_IM_SUCCESS;
}
static Matter_Im_Status_T memory_read_describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* a) {
    (void)u; CHECK(p->attribute>=1 && p->attribute<=9); *a=(Matter_Im_Attribute_T){MATTER_IM_VIEW,false}; return 0;
}
static Matter_Im_Status_T memory_read_value(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    MemoryRead* m=u; CHECK(filtered); ++m->reads;
    m->data[0]=0x16; m->data[1761]=0x18;
    for(unsigned i=0;i<55;++i) { m->data[1+32*i]=0x10; m->data[2+32*i]=30; memset(m->data+3+32*i,(int)p->attribute,30); }
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_ARRAY,.data=m->data,.size=sizeof(m->data),.data_version=7}; return 0;
}
static MemoryRead* memory_read_new(void) {
    MemoryRead* m=calloc(1,sizeof(*m)); CHECK(m); RichSub* r=&m->rich;
    Matter_Im_Read_Port_T p={m,memory_read_allow,memory_read_describe,memory_read_value,NULL,NULL};
    Matter_Im_Read_Config_T c={{1,12,false},30000,1198,true};
    m->active=matter_im_read_new(&p,&c,0); CHECK(m->active);
    if(memory_encoder) CHECK(matter_im_read_bind_output_pool(m->active,memory_encoder)==MATTER_OK);
    if(memory_pool) CHECK(matter_im_read_bind_snapshot_pool(m->active,memory_pool)==MATTER_OK);
    CHECK(!matter_tlv_writer_init(&r->writer,r->model.input,sizeof(r->model.input),8));
    rich_put(r,MATTER_TLV_STRUCTURE,-1,0); rich_put(r,MATTER_TLV_ARRAY,0,0);
    for(unsigned i=1;i<=9;++i) {
        rich_put(r,MATTER_TLV_LIST,-1,0); rich_put(r,MATTER_TLV_UNSIGNED,2,1);
        rich_put(r,MATTER_TLV_UNSIGNED,3,0x91); rich_put(r,MATTER_TLV_UNSIGNED,4,i); rich_put(r,MATTER_TLV_END,-1,0);
    }
    rich_put(r,MATTER_TLV_END,-1,0); rich_put(r,MATTER_TLV_BOOL,3,1); rich_put(r,MATTER_TLV_UNSIGNED,255,13); rich_put(r,MATTER_TLV_END,-1,0);
    CHECK(!matter_tlv_writer_finish(&r->writer,&r->size));
    Matter_Rx_Decision_T d=decision(r->model.input,r->size,2,12,true);
    CHECK(!matter_im_read_receive(m->active,&d) && matter_im_read_process(m->active,0)==MATTER_PENDING && m->reads==9);
    memset(m->data,0xff,sizeof(m->data)); return m;
}
static void memory_read_drain(MemoryRead* m) {
    RichSub* r=&m->rich;
    for(unsigned chunk=0;chunk<600;++chunk) {
        Matter_Im_Read_Message_T out; CHECK(!matter_im_read_output(m->active,&out) && out.opcode==5);
        CHECK(!matter_tlv_init(&r->reader,out.data,out.size,8)); unsigned depth=0; bool more=false; Matter_Tlv_Result_T result;
        while((result=matter_tlv_next(&r->reader,&r->token))==MATTER_TLV_OK) {
            Matter_Tlv_Element_T* e=&r->token;
            if(e->type==MATTER_TLV_END) { CHECK(depth); --depth; continue; }
            if(depth==1 && e->tag.number==3) more=e->unsigned_value!=0;
            if(e->type==MATTER_TLV_BYTES) {
                CHECK(e->size==30 && m->values<9*55);
                for(size_t i=0;i<30;++i) CHECK(e->data[i]==1+m->values/55);
                ++m->values;
            }
            if(depth==4 && e->tag.number==2 && e->type==MATTER_TLV_ARRAY) ++m->attributes;
            if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) ++depth;
        }
        CHECK(result==MATTER_TLV_DONE && !depth && !matter_im_read_sent(m->active));
        Matter_Rx_Decision_T d=decision(sub_success,sizeof(sub_success),1,12,true);
        if(more && chunk%2) CHECK(!matter_im_read_receive(m->active,&d) && matter_im_read_process(m->active,0)==MATTER_PENDING);
        CHECK(!matter_im_read_confirm(m->active,0));
        if(!more) break;
        if(!(chunk%2)) CHECK(!matter_im_read_receive(m->active,&d));
        CHECK(matter_im_read_process(m->active,0)==MATTER_PENDING);
    }
    CHECK(m->values==9*55 && m->attributes==9 && m->reads==9 && matter_im_read_state(m->active)==MATTER_IM_READ_COMPLETE);
    CHECK(!matter_im_read_delete(m->active)); free(m);
}
static void subscription_memory_profile(bool shared) {
    if(shared) { memory_pool=calloc(1,sizeof(*memory_pool)); CHECK(memory_pool); }
    SelectorSub** subs=calloc(15,sizeof(*subs)); CHECK(subs);
    MemoryRead** reads=calloc(5,sizeof(*reads)); CHECK(reads);
#ifdef MATTER_TEST_ALLOC
    CHECK(!live); peak_bytes=max_request=0;
#endif
    for(unsigned i=0;i<15;++i) {
        subs[i]=memory_new(MATTER_IM_READ_MAX_RESULTS,1+i/3);
        Matter_Im_Subscribe_Message_T out=selector_output(subs[i]);
        CHECK(out.opcode==5 && subs[i]->rich.model.reads==MATTER_IM_READ_MAX_RESULTS);
        memset(subs[i]->rich.scratch,0xff,sizeof(subs[i]->rich.scratch));
    }
#ifdef MATTER_TEST_ALLOC
    size_t captured=live_bytes,captured_blocks=live,half=0;
#endif
    for(unsigned i=0;i<5;++i) reads[i]=memory_read_new();
#ifdef MATTER_TEST_ALLOC
    size_t with_reads=live_bytes;
#endif
    unsigned rounds=0,finished=0;
    while(finished<15) {
        for(unsigned i=0;i<15;++i) {
            SelectorSub* s=subs[i]; RichSub* r=&s->rich;
            if(matter_im_subscribe_state(r->model.active)==MATTER_IM_SUB_IDLE) continue;
            Matter_Im_Subscribe_Message_T out;
            CHECK(matter_im_subscribe_output(r->model.active,&out)==MATTER_OK);
            bool more=memory_report(s,out);
            rich_ack(r,true,(i+rounds)%2!=0);
            CHECK(matter_im_subscribe_process(r->model.active,0)==MATTER_PENDING);
            if(!more) { CHECK(s->seen==MATTER_IM_READ_MAX_RESULTS); rich_prime_finish(r); ++finished; }
        }
        CHECK(++rounds<=MATTER_IM_READ_MAX_RESULTS);
#ifdef MATTER_TEST_ALLOC
        if(!half && subs[0]->seen>=MATTER_IM_READ_MAX_RESULTS/2) half=live_bytes;
#endif
    }
    for(unsigned i=0;i<5;++i) memory_read_drain(reads[i]);
    free(reads);
#ifdef MATTER_TEST_ALLOC
    printf("MEMORY subscriptions=15 results_each=%u encoded_each=%zu report_budget=%u captured=%zu with_reads=%zu half=%zu idle=%zu peak=%zu largest=%zu rounds=%u\n",
        MATTER_IM_READ_MAX_RESULTS,memory_value_size+2,MATTER_IM_READ_SNAPSHOT_BYTES,captured,with_reads,half,live_bytes,peak_bytes,max_request,rounds);
    printf("MEMORY_BLOCKS captured=%zu idle=%zu\n",captured_blocks,live);
#endif
    for(unsigned i=0;i<15;++i) { CHECK(subs[i]->rich.model.reads==MATTER_IM_READ_MAX_RESULTS); rich_free(&subs[i]->rich); }
    free(subs);
    if(memory_pool) {
        for(unsigned i=0;i<MATTER_IM_SNAPSHOT_BUCKETS;++i) CHECK(!memory_pool->buckets[i]);
        free(memory_pool); memory_pool=NULL;
    }
#ifdef MATTER_TEST_ALLOC
    CHECK(!live && !live_bytes);
#endif
}
#ifdef MATTER_TEST_ALLOC
static void subscription_memory_oom(void) {
    /* Fail every allocation in a nine-value initial capture, independently.
     * A failed capture may not leak or publish partial successful ReportData. */
    SelectorSub* s=memory_new(9,1); size_t start=calls; (void)selector_output(s);
    size_t count=calls-start; rich_free(&s->rich); CHECK(!live);
    for(size_t fault=1;fault<=count;++fault) {
        s=memory_new(9,1); fail_at=calls+fault;
        Matter_Im_Subscribe_Message_T out=selector_output(s); fail_at=0;
        CHECK(out.opcode==1 && out.data[3]==MATTER_IM_RESOURCE_EXHAUSTED);
        rich_free(&s->rich); CHECK(!live && !live_bytes);
    }
    /* Reject continuation RX atomically, then accept exactly the same bytes.
     * Neither a status before ACK nor ACK alone may release captured values. */
    for(unsigned order=0;order<2;++order) {
        s=memory_new(24,1); (void)selector_output(s); RichSub* r=&s->rich;
        CHECK(matter_im_subscribe_sent_at(r->model.active,0)==MATTER_OK);
        if(order) CHECK(matter_im_subscribe_confirm(r->model.active,0)==MATTER_OK);
        Matter_Rx_Decision_T d=decision(sub_success,sizeof(sub_success),1,12,true);
        size_t held=live_bytes;
        for(size_t fault=1;fault<=2;++fault) {
            fail_at=calls+fault;
            CHECK(matter_im_subscribe_receive(r->model.active,&d)==MATTER_LIMIT_REACHED);
            fail_at=0; CHECK(live_bytes==held);
        }
        CHECK(matter_im_subscribe_receive(r->model.active,&d)==MATTER_OK);
        held=held-r->size+sizeof(sub_success); /* Replaced request, unchanged captured values. */
        if(!order) {
            CHECK(matter_im_subscribe_process(r->model.active,0)==MATTER_PENDING && live_bytes==held);
            CHECK(matter_im_subscribe_confirm(r->model.active,0)==MATTER_OK);
        }
        CHECK(matter_im_subscribe_process(r->model.active,0)==MATTER_PENDING && live_bytes<held);
        rich_free(r); CHECK(!live && !live_bytes);
    }
    printf("PASS subscription capture OOM positions=%zu, continuation RX OOM=4, both ACK/status orders\n",count);
}
#endif
/* Sparse updates preserve catalog ordinals, inline snapshot contents and both
 * delivery gates, including values in distant blocks and the last result. */
typedef struct {
    SelectorSub selector;
    uint32_t versions[MATTER_IM_READ_MAX_RESULTS];
    bool wanted[MATTER_IM_READ_MAX_RESULTS];
    unsigned bias,expected_bias,next,seen,span;
    uint32_t expected_version;
    bool array; unsigned array_seen,array_replaces,array_adds;
} SparseSub;
static Matter_Im_Status_T sparse_read(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    SparseSub* f=u; SelectorSub* s=&f->selector; RichSub* r=&s->rich;
    sub_guard(&r->model); CHECK(filtered && p->attribute>=1 && p->attribute<=s->count); ++r->model.reads;
    memset(r->scratch,(int)(p->attribute+f->bias),f->span);
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_BYTES,.data=r->scratch,.size=f->span,
        .data_version=f->versions[p->attribute-1],.report_on_version_change=true};
    if(f->array && p->attribute==s->count) {
        r->scratch[0]=0x16; r->scratch[385]=0x18;
        for(unsigned i=0;i<12;++i) { r->scratch[1+32*i]=0x10; r->scratch[2+32*i]=30; memset(r->scratch+3+32*i,(int)(p->attribute+f->bias+i),30); }
        v->type=MATTER_TLV_ARRAY; v->size=386;
    }
    return 0;
}
static SparseSub* sparse_new(unsigned count) {
    SparseSub* f=calloc(1,sizeof(*f)); CHECK(f); SelectorSub* s=&f->selector; s->count=count;
    RichSub* r=&s->rich; r->fabric=1; f->expected_version=7; f->span=6;
    for(unsigned i=0;i<count;++i) { f->versions[i]=7; f->wanted[i]=true; }
    Matter_Im_Subscribe_Port_T p=sub_port(&r->model);
    p.attributes=(Matter_Im_Read_Port_T){f,selector_allow,selector_describe,sparse_read,selector_enumerate,NULL};
    Matter_Im_Read_Fabric_Port_T fp={rich_fabric}; Matter_Im_Subscribe_Config_T c={{1,12,false},30000,128,false};
    r->model.active=matter_im_subscribe_new_case(&p,&fp,&c,0); CHECK(r->model.active);
    selector_request(s,1,false,0,false); return f;
}
static bool sparse_report(SparseSub* f,Matter_Im_Subscribe_Message_T out) {
    RichSub* r=&f->selector.rich; CHECK(out.opcode==5 && !matter_tlv_init(&r->reader,out.data,out.size,8));
    unsigned depth=0,attribute=0; uint32_t version=0; bool more=false,append=false; Matter_Tlv_Result_T result;
    while((result=matter_tlv_next(&r->reader,&r->token))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&r->token;
        if(e->type==MATTER_TLV_END) { CHECK(depth); --depth; continue; }
        if(depth==1 && e->tag.number==3) more=e->unsigned_value!=0;
        if(depth==4 && e->tag.number==0) version=(uint32_t)e->unsigned_value;
        if(depth==4 && e->tag.number==1) append=false;
        if(depth==5 && e->tag.number==5) { CHECK(e->type==MATTER_TLV_NULL); append=true; }
        if(depth==5 && e->tag.number==4) attribute=(unsigned)e->unsigned_value;
        bool array_value=f->array && attribute==f->selector.count;
        if(array_value && depth==4 && e->tag.number==2 && e->type==MATTER_TLV_ARRAY) {
            CHECK(!append && !f->array_replaces && version==f->expected_version); ++f->array_replaces;
        }
        if(array_value && e->type==MATTER_TLV_BYTES && ((depth==5 && !e->tag.control) || (depth==4 && e->tag.number==2))) {
            CHECK(f->array_replaces==1 && f->array_seen<12 && e->size==30 && version==f->expected_version);
            if(depth==4) { CHECK(append); ++f->array_adds; }
            for(size_t i=0;i<e->size;++i) CHECK(e->data[i]==(uint8_t)(attribute+f->expected_bias+f->array_seen));
            if(++f->array_seen==12) {
                while(f->next<f->selector.count && !f->wanted[f->next]) ++f->next;
                CHECK(attribute==f->next+1); ++f->next; ++f->seen;
            }
        }
        if(!array_value && depth==4 && e->tag.number==2) {
            while(f->next<f->selector.count && !f->wanted[f->next]) ++f->next;
            CHECK(f->next<f->selector.count && attribute==f->next+1 && version==f->expected_version);
            CHECK(e->type==MATTER_TLV_BYTES && e->size==f->span);
            for(size_t i=0;i<f->span;++i) CHECK(e->data[i]==(uint8_t)(attribute+f->expected_bias));
            ++f->next; ++f->seen;
        }
        if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) ++depth;
    }
    CHECK(result==MATTER_TLV_DONE && !depth); return more;
}
static void sparse_finish(SparseSub* f,Matter_Im_Subscribe_Message_T out,bool prime,unsigned order) {
    RichSub* r=&f->selector.rich; unsigned chunks=0,reads=r->model.reads; bool more;
    do {
        more=sparse_report(f,out); CHECK(++chunks<=MATTER_IM_READ_MAX_RESULTS);
        /* Later packets must keep the captured bytes despite provider changes. */
        memset(r->scratch,0xff,sizeof(r->scratch)); ++f->bias;
        rich_ack(r,prime,(chunks+order)%2!=0);
        if(more) out=selector_output(&f->selector);
    } while(more);
    for(;f->next<f->selector.count;++f->next) CHECK(!f->wanted[f->next]);
    CHECK(r->model.reads==reads);
    if(prime) rich_prime_finish(r);
    else CHECK(matter_im_subscribe_process(r->model.active,r->clock)==MATTER_PENDING && matter_im_subscribe_state(r->model.active)==MATTER_IM_SUB_IDLE);
}
static void sparse_prepare(SparseSub* f,const unsigned selected[3]) {
    memset(f->wanted,0,sizeof(f->wanted)); f->next=f->seen=0; f->expected_bias=f->bias; f->expected_version=8;
    for(unsigned i=0;i<3;++i) { CHECK(selected[i] && selected[i]<=f->selector.count); f->wanted[selected[i]-1]=true; ++f->versions[selected[i]-1]; }
    CHECK(!matter_im_subscribe_changed(f->selector.rich.model.active)); rich_update(&f->selector.rich,2000);
}
static void sparse_value_tests(void) {
    const unsigned selected[3]={17,255,512};
    for(unsigned order=0;order<2;++order) {
        SparseSub* f=sparse_new(MATTER_IM_READ_MAX_RESULTS); RichSub* r=&f->selector.rich;
        sparse_finish(f,selector_output(&f->selector),true,order); CHECK(f->seen==MATTER_IM_READ_MAX_RESULTS);
        sparse_prepare(f,selected);
        Matter_Im_Subscribe_Message_T out=selector_output(&f->selector);
#ifdef MATTER_TEST_ALLOC
        size_t captured=live_bytes;
        printf("MEMORY_SPARSE results=%u included=3 captured=%zu blocks=%zu\n",MATTER_IM_READ_MAX_RESULTS,captured,live);
#endif
        sparse_finish(f,out,false,order); CHECK(f->seen==3); rich_free(r);
#ifdef MATTER_TEST_ALLOC
        CHECK(!live && !live_bytes);
#endif
    }
    SparseSub* list=sparse_new(MATTER_IM_READ_MAX_RESULTS);
    sparse_finish(list,selector_output(&list->selector),true,0); list->array=true;
    sparse_prepare(list,selected); sparse_finish(list,selector_output(&list->selector),false,1);
    CHECK(list->seen==3 && list->array_seen==12 && list->array_replaces==1 && list->array_adds);
    rich_free(&list->selector.rich);
#ifdef MATTER_TEST_ALLOC
    CHECK(!live && !live_bytes);
    /* Every allocator ordinal in a sparse update, including provider-copy and
     * selected block allocation after earlier paths were already captured. */
    const unsigned small[3]={1,33,48};
    SparseSub* f=sparse_new(48); sparse_finish(f,selector_output(&f->selector),true,0);
    f->span=30; sparse_prepare(f,small); size_t start=calls;
    CHECK(selector_output(&f->selector).opcode==5); size_t total=calls-start;
    rich_free(&f->selector.rich); CHECK(!live && !live_bytes);
    for(size_t site=1;site<=total;++site) {
        f=sparse_new(48); sparse_finish(f,selector_output(&f->selector),true,0); f->span=30; sparse_prepare(f,small);
        fail_at=calls+site; Matter_Im_Subscribe_Message_T error=selector_output(&f->selector); fail_at=0;
        CHECK(error.opcode==1 && error.data[3]==MATTER_IM_RESOURCE_EXHAUSTED);
        rich_free(&f->selector.rich); CHECK(!live && !live_bytes);
    }
    printf("PASS sparse update OOM all%zu ordinals: no partial successful ReportData and zero-live cleanup\n",total);
#endif
    puts("PASS sparse Subscribe: 512 catalog paths, selected17/255/512, ordered immutable inline snapshots, ARRAY continuation across sparse gaps, both ACK/status orders and full drain");
}
