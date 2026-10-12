typedef struct {
    Fixture f; Matter_Events_T log; uint64_t high; uint8_t fabric;
    bool fail,scoped;
    Matter_Event_Record_T pending;
} EventsFixture;
static Matter_Result_T ev_load(void* u,uint64_t* n) { *n=((EventsFixture*)u)->high; return MATTER_OK; }
static Matter_Result_T ev_store(void* u,uint64_t n) {
    EventsFixture* f=u;
    CHECK(matter_events_delete(f->log)==MATTER_BUSY);
    if(f->fail) return MATTER_PORT_ERROR;
    f->high=n; return MATTER_OK;
}
static Matter_Im_Status_T ev_authorize(void* u,Matter_Exchange_Session_T token,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    EventsFixture* f=u; guard(&f->f); ++f->f.auths;
    CHECK(token==1 && p->endpoint==0 && p->cluster==0x28 && p->attribute==2 && (privilege==MATTER_IM_VIEW || privilege==MATTER_IM_MANAGE));
    return f->f.auth;
}
static Matter_Result_T ev_fabric(void* u,Matter_Exchange_Session_T token,uint8_t* index) { CHECK(token==1); *index=((EventsFixture*)u)->fabric; return MATTER_OK; }
static Matter_Im_Status_T ev_describe(void* u,const Matter_Event_Path_T* p,Matter_Im_Attribute_T* a) {
    EventsFixture* f=u; guard(&f->f); ++f->f.describes; CHECK(p->endpoint==0 && p->cluster==0x28 && p->event==2);
    *a=(Matter_Im_Attribute_T){MATTER_IM_MANAGE,f->scoped}; return f->f.description;
}
static EventsFixture* ev_create(size_t capacity) {
    EventsFixture* f=calloc(1,sizeof(*f)); CHECK(f); f->fabric=1;
    Matter_Events_Port_T lp={f,ev_load,ev_store}; f->log=matter_events_new(&lp); CHECK(f->log);
    Matter_Im_Read_Port_T p={&f->f,ev_authorize,describe,read_value,NULL,NULL}; Matter_Im_Read_Fabric_Port_T fp={ev_fabric};
    Matter_Im_Read_Config_T c={{1,0x1234,false},1000,capacity,false}; f->f.s=matter_im_read_new_case(&p,&fp,&c,10); CHECK(f->f.s);
    Matter_Im_Read_Events_Port_T ep={f,f->log,ev_describe};
#ifdef MATTER_TEST_ALLOC
    size_t base=live; fail_at=calls+1; CHECK(matter_im_read_bind_events(f->f.s,&ep)==MATTER_LIMIT_REACHED); fail_at=0; CHECK(live==base);
#endif
    CHECK(matter_im_read_bind_events(f->f.s,&ep)==MATTER_OK && matter_im_read_bind_events(f->f.s,&ep)==MATTER_INVALID_STATE); return f;
}
static void ev_free(EventsFixture* f) { CHECK(matter_im_read_delete(f->f.s)==MATTER_OK && matter_events_delete(f->log)==MATTER_OK); free(f); }
static Matter_Result_T ev_append(EventsFixture* f,uint8_t priority) {
    static const uint8_t data[]={0x15,0x24,0,7,0x18}; Matter_Event_Path_T p={0,0x28,2};
    return matter_events_append(f->log,&p,priority,25,false,data,sizeof(data));
}
static void ev_sensitive(EventsFixture* f,uint8_t fabric) {
    static const uint8_t data[]={0x15,0x24,0,7,0x18};
    f->pending=(Matter_Event_Record_T){.path={0,0x28,2},.priority=1,.fabric=fabric,.timestamp_ms=25,.size=sizeof(data)};
    memcpy(f->pending.data,data,sizeof(data));
    CHECK(matter_events_prepare(f->log,&f->pending,1)==MATTER_OK); matter_events_finish(f->log,true);
}
static const uint8_t ev_request[]={0x15,0x36,1,0x17,0x24,1,0,0x24,2,0x28,0x24,3,2,0x18,0x18,0x29,3,0x24,255,13,0x18};
static void ev_expected(EventsFixture* f,uint8_t number,bool more) {
    const uint8_t expected[]={0x15,0x36,2,0x15,0x35,1,0x37,0,0x24,1,0,0x24,2,0x28,0x24,3,2,0x18,
        0x24,1,number,0x24,2,1,0x24,4,25,0x35,7,0x24,0,7,0x18,0x18,0x18,0x18,0x29,more?3:4,0x24,255,13,0x18};
    CHECK(f->f.out.opcode==5 && f->f.out.size==sizeof(expected) && !memcmp(f->f.out.data,expected,sizeof(expected)));
}
static void ev_next(EventsFixture* f) {
    CHECK(matter_im_read_sent(f->f.s)==MATTER_OK && matter_im_read_confirm(f->f.s,11)==MATTER_OK);
    static const uint8_t success[]={0x15,0x24,0,0,0x24,255,13,0x18};
    Matter_Rx_Decision_T d=decision(success,sizeof(success)); d.header.opcode=1;
    CHECK(matter_im_read_receive(f->f.s,&d)==MATTER_OK && matter_im_read_process(f->f.s,11)==MATTER_PENDING && matter_im_read_output(f->f.s,&f->f.out)==MATTER_OK);
}
static void ev_status(EventsFixture* f,uint8_t code) {
    const uint8_t expected[]={0x15,0x36,2,0x15,0x35,0,0x37,0,0x24,1,0,0x24,2,0x28,0x24,3,2,0x18,
        0x35,1,0x24,0,code,0x18,0x18,0x18,0x18,0x29,4,0x24,255,13,0x18};
    CHECK(f->f.out.opcode==5 && f->f.out.size==sizeof(expected) && !memcmp(f->f.out.data,expected,sizeof(expected)));
}
static void test_im_events(void) {
    EventsFixture* f=ev_create(1024); CHECK(ev_append(f,1)==MATTER_OK);
    execute(&f->f,ev_request,sizeof(ev_request)); ev_expected(f,0,false); CHECK(!f->f.reads); ev_free(f);
    /* Inclusive EventMin, no attrs, exactly one remaining record. */
    f=ev_create(1024); CHECK(ev_append(f,1)==MATTER_OK && ev_append(f,1)==MATTER_OK);
    memcpy(f->f.input,ev_request,sizeof(ev_request)-1);
    static const uint8_t filter[]={0x36,2,0x15,0x24,1,1,0x18,0x18,0x18};
    memcpy(f->f.input+sizeof(ev_request)-1,filter,sizeof(filter));
    execute(&f->f,f->f.input,sizeof(ev_request)-1+sizeof(filter)); ev_expected(f,1,false); ev_free(f);
    f=ev_create(1024); execute(&f->f,ev_request,sizeof(ev_request));
    static const uint8_t empty[]={0x15,0x36,2,0x18,0x29,4,0x24,255,13,0x18};
    CHECK(f->f.out.size==sizeof(empty) && !memcmp(f->f.out.data,empty,sizeof(empty))); ev_free(f);
    /* Log overwrite cannot mutate private copies in an in-progress interaction. */
    f=ev_create(64); CHECK(ev_append(f,1)==MATTER_OK && ev_append(f,1)==MATTER_OK);
    execute(&f->f,ev_request,sizeof(ev_request)); ev_expected(f,0,true);
    for(unsigned i=0;i<16;++i) CHECK(ev_append(f,1)==MATTER_OK);
    ev_next(f); ev_expected(f,1,false); ev_free(f);
    for(unsigned mode=0;mode<4;++mode) {
        f=ev_create(64); CHECK(ev_append(f,1)==MATTER_OK && ev_append(f,1)==MATTER_OK);
        execute(&f->f,ev_request,sizeof(ev_request)); ev_expected(f,0,true);
        if(mode==0) f->f.auth=MATTER_IM_UNSUPPORTED_ACCESS;
        if(mode==1) f->fabric=2;
        if(mode==2) f->fabric=0;
        if(mode==3) f->fabric=255;
        ev_next(f); ev_status(f,MATTER_IM_UNSUPPORTED_ACCESS); ev_free(f);
    }
    for(unsigned filtered=0;filtered<2;++filtered) {
        f=ev_create(64); f->scoped=true; ev_sensitive(f,2); ev_sensitive(f,1); ev_sensitive(f,2);
        memcpy(f->f.input,ev_request,sizeof(ev_request)); f->f.input[15]=filtered?0x29:0x28;
        execute(&f->f,f->f.input,sizeof(ev_request)); ev_expected(f,1,false); ev_free(f);
    }
    f=ev_create(64); f->scoped=true; f->fabric=0; execute(&f->f,ev_request,sizeof(ev_request)); ev_status(f,MATTER_IM_UNSUPPORTED_ACCESS); ev_free(f);
    f=ev_create(64); f->f.description=MATTER_IM_UNSUPPORTED_EVENT; execute(&f->f,ev_request,sizeof(ev_request)); ev_status(f,MATTER_IM_UNSUPPORTED_EVENT); ev_free(f);
    f=ev_create(8); CHECK(ev_append(f,1)==MATTER_OK); execute(&f->f,ev_request,sizeof(ev_request)); status_response(&f->f,MATTER_IM_RESOURCE_EXHAUSTED); ev_free(f);
    for(unsigned mode=0;mode<5;++mode) {
        f=ev_create(64); memcpy(f->f.input,ev_request,sizeof(ev_request));
        if(mode==0) f->f.input[3]=0x15; /* wrong path container */
        if(mode==1) f->f.input[5]=0; /* explicit Node */
        if(mode==2) f->f.input[8]=1; /* duplicate endpoint */
        if(mode==3) f->f.input[11]=5; /* event omitted/wildcard */
        if(mode==4) f->f.input[10]=0x20; /* signed event */
        execute(&f->f,f->f.input,sizeof(ev_request)); status_response(&f->f,MATTER_IM_INVALID_ACTION); CHECK(!f->f.auths); ev_free(f);
    }
    /* Durable reservation failure is atomic; boot skip, exhaustion, priorities. */
    f=ev_create(64); f->fail=true; CHECK(ev_append(f,1)==MATTER_PORT_ERROR && !f->high); f->fail=false;
    CHECK(ev_append(f,1)==MATTER_OK && f->high==32);
    Matter_Event_Record_T* records=calloc(MATTER_EVENTS_CAPACITY,sizeof(*records)); CHECK(records); size_t count;
    Matter_Event_Path_T path={0,0x28,2};
    CHECK(matter_events_copy(f->log,&path,0,records,&count)==MATTER_OK && count==1 && !records[0].number);
    /* No live handler operation uses the borrowed log after this replacement. */
    CHECK(matter_im_read_delete(f->f.s)==MATTER_OK); f->f.s=NULL;
    CHECK(matter_events_delete(f->log)==MATTER_OK); Matter_Events_Port_T lp={f,ev_load,ev_store}; f->log=matter_events_new(&lp); CHECK(f->log);
    CHECK(ev_append(f,1)==MATTER_OK && matter_events_copy(f->log,&path,0,records,&count)==MATTER_OK && records[0].number==32);
    for(unsigned i=0;i<MATTER_EVENTS_CAPACITY;++i) CHECK(ev_append(f,2)==MATTER_OK);
    CHECK(ev_append(f,1)==MATTER_LIMIT_REACHED);
    CHECK(matter_events_copy(f->log,&path,0,records,&count)==MATTER_OK && count==MATTER_EVENTS_CAPACITY && records[0].number==33 && records[count-1].number==32+count);
    CHECK(ev_append(f,2)==MATTER_OK && matter_events_copy(f->log,&path,0,records,&count)==MATTER_OK && records[count-1].number==33+count);
    /* One full-capacity atomic batch must durably reserve every number, even
     * when the configured log exceeds the usual 32-number flash-wear block. */
    CHECK(matter_events_prepare(f->log,records,count)==MATTER_OK);
    matter_events_finish(f->log,true);
    uint64_t next; CHECK(matter_events_position(f->log,&next)==MATTER_OK && f->high>=next);
    CHECK(matter_events_copy(f->log,&path,0,records,&count)==MATTER_OK && records[count-1].number==next-1);
    uint64_t saved_next=next;
    CHECK(matter_events_prepare(f->log,records,count)==MATTER_OK); matter_events_finish(f->log,false);
    CHECK(matter_events_position(f->log,&next)==MATTER_OK && next==saved_next);
    CHECK(matter_events_delete(f->log)==MATTER_OK); f->high=UINT64_MAX-1; f->log=matter_events_new(&lp); CHECK(f->log);
    CHECK(ev_append(f,1)==MATTER_OK && ev_append(f,1)==MATTER_LIMIT_REACHED);
    static const uint8_t invalid[]={0x15,0x24,0,7};
    CHECK(matter_events_append(f->log,&path,1,0,false,invalid,sizeof(invalid))==MATTER_INVALID_ARGUMENT);
    ev_free(f); free(records);
#ifdef MATTER_TEST_ALLOC
    CHECK(!live);
#endif
    puts("PASS IM events: literal EventReportIB/StatusIB, inclusive filter, copied chunks, ACL/fabric revocation, malformed requests, durable numbers, priority eviction, exhaustion/OOM");
}
