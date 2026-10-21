/* Saturate independently owned interactions, without relying on host model
 * attribute sizes. Fifteen CASE subscriptions across five fabric identities.
 * Provider scratch, request encoders and report consumers are heap fixtures. */
static Matter_Im_Snapshot_Pool* memory_pool;
static Matter_Im_Status_T memory_read(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    SelectorSub* s=u; RichSub* r=&s->rich; sub_guard(&r->model); CHECK(filtered);
    ++r->model.reads; memset(r->scratch,(int)(p->attribute&255),30);
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_BYTES,.data=r->scratch,.size=30,.data_version=7};
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
            CHECK(attribute==s->seen+1 && e->type==MATTER_TLV_BYTES && e->size==30);
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
    size_t captured=live_bytes,half=0;
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
    printf("MEMORY subscriptions=15 results_each=%u encoded_each=%u captured=%zu with_reads=%zu half=%zu idle=%zu peak=%zu largest=%zu rounds=%u\n",
        MATTER_IM_READ_MAX_RESULTS,MATTER_IM_READ_SNAPSHOT_BYTES,captured,with_reads,half,live_bytes,peak_bytes,max_request,rounds);
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
