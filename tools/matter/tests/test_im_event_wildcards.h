/* Metadata-driven event selection, shared by both public IM engines. */
static Matter_Result_T event_wild_enumerate(void* u,const Matter_Im_Event_Selector_T* q,const Matter_Event_Path_T* after,Matter_Event_Path_T* out,bool* found) {
    MultiEvents* m=u; ++m->enums;
#ifdef TEST_MULTI_SUB
    CHECK(matter_im_subscribe_delete(m->engine)==MATTER_BUSY);
#else
    CHECK(matter_im_read_delete(m->engine)==MATTER_BUSY);
#endif
    if(m->enum_mode==1) return MATTER_PORT_ERROR;
    if(m->enum_mode==2 && after) { *out=*after; *found=true; return MATTER_OK; }
    if(m->enum_mode==3) { *out=(Matter_Event_Path_T){99,0x28,1}; *found=true; return MATTER_OK; }
    *found=false;
    for(unsigned ep=0;ep<m->model_endpoints;++ep) for(unsigned c=0;c<m->model_clusters;++c) for(unsigned e=1;e<=m->model_events;++e) {
        if((q->present&1) && q->path.endpoint!=ep) continue;
        if((q->present&2) && q->path.cluster!=0x28+c) continue;
        if((q->present&4) && q->path.event!=e) continue;
        if(after && (ep<after->endpoint || (ep==after->endpoint &&
            (0x28+c<after->cluster || (0x28+c==after->cluster && e<=after->event))))) continue;
        *out=(Matter_Event_Path_T){(uint16_t)ep,0x28+c,e}; *found=true; return MATTER_OK;
    }
    return MATTER_OK;
}
static MultiEvents* event_wild_new(uint8_t mask) {
    MultiEvents* m=multi_new(); m->wild_model=m->wild_request=true;
    m->model_endpoints=m->model_clusters=2; m->model_events=3;
    for(unsigned i=0;i<9;++i) m->masks[i]=mask;
#ifdef TEST_MULTI_SUB
    CHECK(matter_im_subscribe_bind_event_enumerator(m->engine,NULL)==MATTER_INVALID_ARGUMENT);
    CHECK(matter_im_subscribe_bind_event_enumerator(m->engine,event_wild_enumerate)==MATTER_OK);
    CHECK(matter_im_subscribe_bind_event_enumerator(m->engine,event_wild_enumerate)==MATTER_INVALID_STATE);
#else
    CHECK(matter_im_read_bind_event_enumerator(m->engine,NULL)==MATTER_INVALID_ARGUMENT);
    CHECK(matter_im_read_bind_event_enumerator(m->engine,event_wild_enumerate)==MATTER_OK);
    CHECK(matter_im_read_bind_event_enumerator(m->engine,event_wild_enumerate)==MATTER_INVALID_STATE);
#endif
    return m;
}
static void event_wild_append(MultiEvents* m,uint16_t ep,uint32_t c,uint32_t e,uint8_t fabric) {
    static const uint8_t data[]={0x15,0x24,0,7,0x18};
    m->pending=(Matter_Event_Record_T){.path={ep,c,e},.priority=1,.fabric=fabric,.timestamp_ms=25,.size=sizeof(data)};
    memcpy(m->pending.data,data,sizeof(data)); CHECK(matter_events_prepare(m->log,&m->pending,1)==MATTER_OK); matter_events_finish(m->log,true);
}
static void event_wild_tests(void) {
    static const uint32_t ids[]={1,2,3};
    static const uint8_t masks[]={0,1,2,3,6,7},counts[]={5,3,3,2,2,1};
    static const uint8_t expected[6][5]={{0,2,3,4,5},{0,2,3},{0,2,4},{0,2},{0,4},{0}};
    for(unsigned t=0;t<6;++t) {
        MultiEvents* m=event_wild_new(masks[t]);
        event_wild_append(m,0,0x28,1,0); event_wild_append(m,0,0x28,2,2); event_wild_append(m,0,0x28,2,1);
        event_wild_append(m,0,0x29,3,0); event_wild_append(m,1,0x28,1,0); event_wild_append(m,1,0x29,3,0);
        multi_request(m,1,ids,1,1,0); multi_start(m); multi_drain(m);
        CHECK(m->attributes==1 && m->events==counts[t] && !m->statuses);
        for(unsigned i=0;i<m->events;++i) CHECK(m->numbers[i]==expected[t][i]);
        if(!t) CHECK(m->clusters[2]==0x29 && m->endpoints[3]==1 && m->processes>2);
        multi_free(m);
    }
    /* An event without a cluster is not a valid wildcard (Core 8.9.3.3). */
    for(unsigned mask=4;mask<=5;++mask) {
        MultiEvents* m=event_wild_new((uint8_t)mask); multi_request(m,1,ids,1,0,0); multi_start(m);
        CHECK(m->opcode==1 && m->out[3]==MATTER_IM_INVALID_ACTION && !m->reads && !m->enums); multi_free(m);
    }
    /* Wildcard access uses actual metadata privilege, not preliminary View. */
    MultiEvents* m=event_wild_new(3); m->manage=m->deny_view=true; multi_append(m,1,0);
    multi_request(m,0,ids,1,0,0); multi_start(m); multi_drain(m);
    CHECK(m->events==1 && !m->statuses && !m->views); multi_free(m);
    /* Overlapping wildcard/concrete paths share records, but explicit errors survive. */
    m=event_wild_new(3); m->masks[1]=7; m->masks[2]=0; m->denied=2;
    multi_append(m,1,0); multi_append(m,2,1); multi_append(m,3,0);
    multi_request(m,0,ids,3,0,0); multi_start(m); multi_drain(m);
    CHECK(m->events==2 && m->numbers[0]==0 && m->numbers[1]==2 && m->statuses==1 && m->codes[0]==MATTER_IM_UNSUPPORTED_ACCESS); multi_free(m);
    /* Nonexistent wildcard gives no status; concrete counterpart still does. */
    m=event_wild_new(3); m->query_endpoint=9; multi_request(m,1,ids,1,0,0); multi_start(m); multi_drain(m);
    CHECK(m->attributes==1 && !m->events && !m->statuses); multi_free(m);
    m=event_wild_new(7); m->query_endpoint=9; multi_request(m,1,ids,1,0,0); multi_start(m); multi_drain(m);
    CHECK(m->statuses==1 && m->codes[0]==MATTER_IM_UNSUPPORTED_ENDPOINT); multi_free(m);
    /* The cap counts expanded candidates before ACL/dedup; no partial report. */
    for(unsigned n=120;n<=121;++n) {
        m=event_wild_new(3); m->model_events=n;
        multi_request(m,0,ids,1,0,0); multi_start(m);
        if(n==120) { multi_drain(m); CHECK(!m->events && !m->statuses && m->processes>20); }
        else CHECK(m->opcode==1 && m->out[3]==MATTER_IM_RESOURCE_EXHAUSTED);
        multi_free(m);
    }
    m=event_wild_new(3); m->model_events=61; multi_request(m,0,ids,2,0,0); multi_start(m);
    CHECK(m->opcode==1 && m->out[3]==MATTER_IM_RESOURCE_EXHAUSTED); multi_free(m);
    for(unsigned mode=1;mode<=3;++mode) {
        m=event_wild_new(3); m->enum_mode=mode; multi_request(m,1,ids,1,0,0); multi_start(m);
        CHECK(m->opcode==1 && m->out[3]==MATTER_IM_FAILURE); multi_free(m);
    }
    /* Revoked wildcard snapshots disappear; other paths continue without status. */
    m=event_wild_new(3); multi_append(m,1,0); multi_append(m,2,1); multi_append(m,3,0);
    multi_request(m,0,ids,1,0,0); multi_start(m); multi_report(m); CHECK(m->events==1 && m->more);
    m->denied=2; multi_confirm(m); multi_receive(m,false); multi_process(m); multi_drain(m);
    CHECK(m->events==2 && m->ids[1]==3 && !m->statuses); multi_free(m);
    /* Delete during yielded expansion releases all memory; no provider pointers retained. */
    m=event_wild_new(0); m->model_events=30; multi_request(m,0,ids,1,0,0); multi_receive(m,true);
#ifdef TEST_MULTI_SUB
    CHECK(matter_im_subscribe_process(m->engine,0)==MATTER_PENDING && matter_im_subscribe_state(m->engine)==MATTER_IM_SUB_COLLECTING);
#else
    CHECK(matter_im_read_process(m->engine,0)==MATTER_PENDING && matter_im_read_state(m->engine)==MATTER_IM_READ_COLLECTING);
#endif
    CHECK(m->enums==8 && !m->describes); multi_free(m);
    puts("PASS event wildcards: six valid masks, concrete paths/order/fabric, empty metadata, ACL privilege/omission/overlap/revoke, 120/121 candidates, callback errors and bounded work");
}
#ifdef TEST_MULTI_SUB
static void event_wild_sub_tests(void) {
    static const uint32_t ids[]={1,2}; MultiEvents* m=event_wild_new(3);
    /* No queued event yet: existent metadata is enough to activate. */
    multi_request(m,0,ids,1,1,0); multi_start(m); multi_drain(m); CHECK(!m->events);
    multi_append(m,2,2); CHECK(matter_im_subscribe_events_changed(m->engine)==MATTER_OK);
    uint64_t due=0; CHECK(matter_im_subscribe_deadline(m->engine,&due)==MATTER_OK && due==5000);
    multi_append(m,2,1); CHECK(matter_im_subscribe_events_changed(m->engine)==MATTER_OK); multi_update(m,1000); multi_drain(m);
    CHECK(m->events==1 && m->numbers[0]==1); multi_free(m);
    /* Wildcard with no existent path cannot create an event-only subscription. */
    m=event_wild_new(3); m->query_endpoint=9; multi_request(m,0,ids,1,0,0); multi_start(m);
    CHECK(m->opcode==1 && m->out[3]==MATTER_IM_INVALID_ACTION); multi_free(m);
    /* Losing one wildcard grant omits its status and keeps surviving paths active. */
    m=event_wild_new(3); multi_request(m,0,ids,1,1,0); multi_start(m); multi_drain(m);
    m->denied=2; multi_append(m,2,1); multi_append(m,1,0);
    CHECK(matter_im_subscribe_events_changed(m->engine)==MATTER_OK); multi_update(m,1000); multi_drain(m);
    CHECK(m->events==1 && m->ids[0]==1 && !m->statuses); multi_free(m);
    /* Loss of the last grant ends after the empty update is acknowledged. */
    m=event_wild_new(6); m->model_endpoints=1; multi_request(m,0,ids,1,1,0); multi_start(m); multi_drain(m);
    m->denied=1; multi_append(m,1,0); CHECK(matter_im_subscribe_events_changed(m->engine)==MATTER_OK); multi_update(m,1000);
    multi_report(m); CHECK(!m->events && !m->statuses && !m->more); multi_confirm(m); multi_receive(m,false);
    CHECK(matter_im_subscribe_process(m->engine,1000)==MATTER_PORT_ERROR && m->releases==1); multi_free(m);
    puts("PASS event wildcard Subscribe: empty prime activates metadata, fabric-sensitive urgency, partial/last grant revocation");
}
#endif
