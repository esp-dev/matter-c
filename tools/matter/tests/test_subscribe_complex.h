typedef struct {
    SubModel model; Matter_Events_T log; uint64_t high,clock; uint8_t fabric;
    uint8_t values[2],scratch[512]; size_t size;
    bool deny_event,deny_attribute,malformed,large,own_log,bad_auth,scoped;
    Matter_Event_Record_T pending;
    unsigned seen_attributes,seen_events,seen_status; uint64_t first_event;
    uint8_t expected[2]; uint32_t expected_version;
    Matter_Tlv_Reader_T reader; Matter_Tlv_Writer_T writer; Matter_Tlv_Element_T token;
} RichSub;
static Matter_Result_T rich_load(void* u,uint64_t* n) { *n=((RichSub*)u)->high; return MATTER_OK; }
static Matter_Result_T rich_store(void* u,uint64_t n) { ((RichSub*)u)->high=n; return MATTER_OK; }
static Matter_Result_T rich_fabric(void* u,Matter_Exchange_Session_T token,uint8_t* index) { RichSub* r=u; sub_guard(&r->model); CHECK(token==1); *index=r->fabric; return MATTER_OK; }
static Matter_Im_Status_T rich_allow(void* u,Matter_Exchange_Session_T token,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    RichSub* r=u; sub_guard(&r->model); ++r->model.auths;
    CHECK(token==1 && p->endpoint==1 && p->cluster==0x91 && privilege==MATTER_IM_VIEW);
    if(r->bad_auth) return (Matter_Im_Status_T)256;
    return (r->deny_event && !p->attribute) || (r->deny_attribute && p->attribute==2)?MATTER_IM_UNSUPPORTED_ACCESS:0;
}
static Matter_Im_Status_T rich_describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* a) {
    RichSub* r=u; sub_guard(&r->model); CHECK(p->attribute==1 || p->attribute==2);
    *a=(Matter_Im_Attribute_T){MATTER_IM_VIEW,false}; return 0;
}
static Matter_Im_Status_T rich_read(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    RichSub* r=u; sub_guard(&r->model); CHECK(filtered); ++r->model.reads;
    /* Deliberately shared scratch is overwritten by the NEXT provider call. */
    const uint8_t bytes[]={0x15,0x20,0,r->values[p->attribute-1],0x24,4,17,0x18};
    memcpy(r->scratch,bytes,sizeof(bytes)); size_t size=sizeof(bytes);
    if(r->malformed) --size;
    if(r->large) {
        r->scratch[0]=0x15; r->scratch[1]=0x30; r->scratch[2]=0; r->scratch[3]=200;
        memset(r->scratch+4,0,200); r->scratch[204]=0x18; size=205;
    }
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_STRUCTURE,.data=r->scratch,.size=size,.data_version=r->model.version}; return 0;
}
static Matter_Im_Status_T rich_event_describe(void* u,const Matter_Event_Path_T* p,Matter_Im_Attribute_T* a) {
    RichSub* r=u; sub_guard(&r->model); CHECK(p->endpoint==1 && p->cluster==0x91 && !p->event);
    *a=(Matter_Im_Attribute_T){MATTER_IM_VIEW,r->scoped}; return 0;
}
static void rich_bind(RichSub* r,Matter_Events_T log) {
    r->log=log; Matter_Im_Read_Events_Port_T p={r,log,rich_event_describe};
#ifdef MATTER_TEST_ALLOC
    size_t base=live,allocations_before=calls; fail_at=calls+1;
    CHECK(matter_im_subscribe_bind_events(r->model.active,&p)==MATTER_OK); fail_at=0;
    CHECK(live==base && calls==allocations_before);
#else
    CHECK(matter_im_subscribe_bind_events(r->model.active,&p)==MATTER_OK);
#endif
    CHECK(matter_im_subscribe_bind_events(r->model.active,&p)==MATTER_INVALID_STATE);
}
static RichSub* rich_new(bool events,size_t cap) {
    RichSub* r=calloc(1,sizeof(*r)); CHECK(r); r->fabric=1; r->values[0]=9; r->values[1]=10;
    r->expected[0]=9; r->expected[1]=10; r->expected_version=7;
    Matter_Im_Subscribe_Port_T p=sub_port(&r->model); p.attributes.authorize=rich_allow; p.attributes.describe=rich_describe; p.attributes.read=rich_read;
    Matter_Im_Read_Fabric_Port_T fp={rich_fabric}; Matter_Im_Subscribe_Config_T c={{1,12,false},30000,cap,false};
    r->model.active=matter_im_subscribe_new_case(&p,&fp,&c,0); CHECK(r->model.active);
    if(events) { Matter_Events_Port_T ep={r,rich_load,rich_store}; Matter_Events_T log=matter_events_new(&ep); CHECK(log); rich_bind(r,log); r->own_log=true; }
    return r;
}
static void rich_free(RichSub* r) {
    CHECK(matter_im_subscribe_delete(r->model.active)==MATTER_OK);
    if(r->own_log) CHECK(matter_events_delete(r->log)==MATTER_OK);
    free(r);
}
static void rich_put(RichSub* r,Matter_Tlv_Type_T type,int tag,uint64_t n) {
    r->token=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=n};
    CHECK(matter_tlv_write(&r->writer,&r->token,0)==MATTER_TLV_OK);
}
static void rich_request(RichSub* r,unsigned attributes,bool events,bool urgent,uint64_t minimum) {
    CHECK(matter_tlv_writer_init(&r->writer,r->model.input,sizeof(r->model.input),6)==MATTER_TLV_OK);
    rich_put(r,MATTER_TLV_STRUCTURE,-1,0); rich_put(r,MATTER_TLV_BOOL,0,1);
    rich_put(r,MATTER_TLV_UNSIGNED,1,2); rich_put(r,MATTER_TLV_UNSIGNED,2,5);
    if(attributes) {
        rich_put(r,MATTER_TLV_ARRAY,3,0);
        for(unsigned i=0;i<attributes;++i) {
            rich_put(r,MATTER_TLV_LIST,-1,0); rich_put(r,MATTER_TLV_UNSIGNED,2,1); rich_put(r,MATTER_TLV_UNSIGNED,3,0x91);
            rich_put(r,MATTER_TLV_UNSIGNED,4,1+i%2); rich_put(r,MATTER_TLV_END,-1,0);
        }
        rich_put(r,MATTER_TLV_END,-1,0);
    }
    if(events) {
        rich_put(r,MATTER_TLV_ARRAY,4,0); rich_put(r,MATTER_TLV_LIST,-1,0);
        rich_put(r,MATTER_TLV_UNSIGNED,1,1); rich_put(r,MATTER_TLV_UNSIGNED,2,0x91); rich_put(r,MATTER_TLV_UNSIGNED,3,0);
        rich_put(r,MATTER_TLV_BOOL,4,urgent); rich_put(r,MATTER_TLV_END,-1,0); rich_put(r,MATTER_TLV_END,-1,0);
        rich_put(r,MATTER_TLV_ARRAY,5,0); rich_put(r,MATTER_TLV_STRUCTURE,-1,0); rich_put(r,MATTER_TLV_UNSIGNED,1,minimum);
        rich_put(r,MATTER_TLV_END,-1,0); rich_put(r,MATTER_TLV_END,-1,0);
    }
    rich_put(r,MATTER_TLV_BOOL,7,1); rich_put(r,MATTER_TLV_UNSIGNED,255,13); rich_put(r,MATTER_TLV_END,-1,0);
    CHECK(matter_tlv_writer_finish(&r->writer,&r->size)==MATTER_TLV_OK);
}
static void rich_event(RichSub* r) {
    static const uint8_t payload[]={0x15,0x24,0,7,0x18}; Matter_Event_Path_T p={1,0x91,0};
    CHECK(matter_events_append(r->log,&p,1,25,false,payload,sizeof(payload))==MATTER_OK);
}
static bool rich_report(RichSub* r,Matter_Im_Subscribe_Message_T out) {
    CHECK(out.opcode==5 && matter_tlv_init(&r->reader,out.data,out.size,8)==MATTER_TLV_OK);
    unsigned depth=0,parent[8]={0}; uint32_t attr=0; bool more=false,suppress=true; Matter_Tlv_Result_T result;
    while((result=matter_tlv_next(&r->reader,&r->token))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&r->token;
        if(e->type==MATTER_TLV_END) { CHECK(depth); --depth; continue; }
        if(depth==1 && !e->tag.number) CHECK(e->unsigned_value==42);
        if(depth==1 && e->tag.number==3) more=e->unsigned_value!=0;
        if(depth==1 && e->tag.number==4) suppress=e->unsigned_value!=0;
        if(parent[1]==1 && depth==4 && !e->tag.number && parent[3]==1) CHECK(e->unsigned_value==r->expected_version);
        if(parent[1]==1 && depth==5 && e->tag.number==4) attr=(uint32_t)e->unsigned_value;
        if(parent[1]==1 && depth==4 && e->tag.number==2) {
            CHECK(attr==1 || attr==2); CHECK(e->type==MATTER_TLV_STRUCTURE);
            const uint8_t expected[]={0x35,2,0x20,0,r->expected[attr-1],0x24,4,17,0x18};
            CHECK(e->offset+sizeof(expected)<=out.size && !memcmp(out.data+e->offset,expected,sizeof(expected)));
            CHECK(matter_tlv_skip_container(&r->reader)==MATTER_TLV_OK); ++r->seen_attributes; continue;
        }
        if(parent[1]==2 && depth==4 && e->tag.number==1 && e->type==MATTER_TLV_UNSIGNED) CHECK(e->unsigned_value==r->first_event+r->seen_events++);
        if(parent[1]==2 && depth==4 && e->tag.number==7) {
            static const uint8_t data[]={0x35,7,0x24,0,7,0x18}; CHECK(e->offset+sizeof(data)<=out.size && !memcmp(out.data+e->offset,data,sizeof(data)));
        }
        if(depth==5 && parent[3]==0 && parent[4]==1 && !e->tag.number) { CHECK(e->unsigned_value==MATTER_IM_UNSUPPORTED_ACCESS); ++r->seen_status; }
        if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) { CHECK(depth<8); parent[depth++]=e->tag.number; }
    }
    CHECK(result==MATTER_TLV_DONE && !depth && !suppress); return more;
}
static void rich_ack(RichSub* r,bool first,bool ack_first) {
    CHECK(matter_im_subscribe_sent_at(r->model.active,r->clock)==MATTER_OK);
    if(ack_first) CHECK(matter_im_subscribe_confirm(r->model.active,r->clock)==MATTER_OK);
    receive(&r->model,sub_success,sizeof(sub_success),1,first?12:13,first);
    if(!ack_first) {
        CHECK(matter_im_subscribe_process(r->model.active,r->clock)==MATTER_PENDING && matter_im_subscribe_state(r->model.active)==MATTER_IM_SUB_IN_FLIGHT);
        CHECK(matter_im_subscribe_confirm(r->model.active,r->clock)==MATTER_OK);
    }
}
static void rich_prime_finish(RichSub* r) {
    literal(output(&r->model,r->clock),4,sub_response,sizeof(sub_response));
    CHECK(matter_im_subscribe_sent_at(r->model.active,r->clock)==MATTER_OK && matter_im_subscribe_confirm(r->model.active,r->clock)==MATTER_OK);
}
static void rich_update(RichSub* r,uint64_t now) {
    r->clock=now; CHECK(matter_im_subscribe_process(r->model.active,now)==MATTER_PENDING && matter_im_subscribe_state(r->model.active)==MATTER_IM_SUB_NEED_EXCHANGE);
    Matter_Exchange_Info_T e={1,13,true}; CHECK(matter_im_subscribe_bind_report(r->model.active,&e,now)==MATTER_OK);
}
static void complex_tests(void) {
#ifdef MATTER_TEST_ALLOC
    for(unsigned order=0;order<2;++order) {
        RichSub* gated=rich_new(false,64); rich_request(gated,2,false,false,0);
        receive(&gated->model,gated->model.input,gated->size,3,12,true);
        CHECK(rich_report(gated,output(&gated->model,0))); size_t held=live;
        CHECK(matter_im_subscribe_sent_at(gated->model.active,0)==MATTER_OK);
        if(order) CHECK(matter_im_subscribe_confirm(gated->model.active,0)==MATTER_OK);
        receive(&gated->model,sub_success,sizeof(sub_success),1,12,true);
        if(!order) {
            CHECK(matter_im_subscribe_process(gated->model.active,0)==MATTER_PENDING && live==held);
            CHECK(matter_im_subscribe_confirm(gated->model.active,0)==MATTER_OK);
        }
        CHECK(live==held); /* Chunk one drained; chunk two still owns both values. */
        CHECK(!rich_report(gated,output(&gated->model,0)) && live==held);
        rich_ack(gated,true,false); CHECK(live==held);
        size_t bytes=live_bytes;
        literal(output(&gated->model,0),4,sub_response,sizeof(sub_response));
        CHECK(live==held-2 && bytes-live_bytes==2*(sizeof(void*)+8));
        rich_prime_finish(gated);
        CHECK(matter_im_subscribe_changed(gated->model.active)==MATTER_OK); rich_update(gated,2000);
        CHECK(rich_report(gated,output(&gated->model,2000)) && live==held);
        CHECK(matter_im_subscribe_sent_at(gated->model.active,2000)==MATTER_OK);
        if(!order) CHECK(matter_im_subscribe_cancel(gated->model.active)==MATTER_OK);
        else CHECK(matter_im_subscribe_process(gated->model.active,32000)==MATTER_PORT_ERROR);
        CHECK(live==held); /* Cancellation/timeout still leaves cleanup to drain/delete. */
        rich_free(gated); CHECK(!live && !live_bytes);
    }
#endif
    /* Sensitive history and subsequent updates never leak another fabric,
     * even if FabricFiltered=false. Cursor advances over foreign records. */
    for(unsigned filtered=0;filtered<2;++filtered) {
        RichSub* scoped=rich_new(true,128); scoped->scoped=true;
        scoped->pending=(Matter_Event_Record_T){.path={1,0x91,0},.priority=1,.timestamp_ms=25,.size=5,.data={0x15,0x24,0,7,0x18}};
        for(unsigned i=0;i<3;++i) {
            scoped->pending.fabric=i==1?1:2;
            CHECK(matter_events_prepare(scoped->log,&scoped->pending,1)==MATTER_OK); matter_events_finish(scoped->log,true);
        }
        rich_request(scoped,0,true,true,0); scoped->model.input[scoped->size-6]=filtered?0x29:0x28;
        scoped->first_event=1; receive(&scoped->model,scoped->model.input,scoped->size,3,12,true);
        CHECK(!rich_report(scoped,output(&scoped->model,0)) && scoped->seen_events==1);
        rich_ack(scoped,true,true); rich_prime_finish(scoped);
        scoped->pending.fabric=1;
        CHECK(matter_events_prepare(scoped->log,&scoped->pending,1)==MATTER_OK); matter_events_finish(scoped->log,true);
        CHECK(matter_im_subscribe_events_changed(scoped->model.active)==MATTER_OK);
        rich_update(scoped,2000); scoped->first_event=3; scoped->seen_events=0;
        CHECK(!rich_report(scoped,output(&scoped->model,2000)) && scoped->seen_events==1);
        rich_ack(scoped,false,true); rich_free(scoped);
    }
    RichSub* r=rich_new(true,64); rich_event(r); rich_event(r); rich_request(r,2,true,true,1); r->first_event=1; r->clock=100;
    receive(&r->model,r->model.input,r->size,3,12,true);
    CHECK(rich_report(r,output(&r->model,r->clock)) && r->seen_attributes==1 && r->model.reads==2);
    memset(r->scratch,0,sizeof(r->scratch)); r->values[0]=20; r->values[1]=30; ++r->model.version;
    CHECK(matter_im_subscribe_changed(r->model.active)==MATTER_OK); rich_event(r); CHECK(matter_im_subscribe_events_changed(r->model.active)==MATTER_OK);
    rich_ack(r,true,false); ++r->clock; CHECK(rich_report(r,output(&r->model,r->clock)) && r->seen_attributes==2);
    rich_ack(r,true,true); ++r->clock; CHECK(!rich_report(r,output(&r->model,r->clock)) && r->seen_events==1); rich_ack(r,true,false); rich_prime_finish(r);
    uint64_t due; CHECK(matter_im_subscribe_deadline(r->model.active,&due)==MATTER_OK && due==2100);
    CHECK(matter_im_subscribe_process(r->model.active,2099)==MATTER_PENDING && matter_im_subscribe_state(r->model.active)==MATTER_IM_SUB_IDLE);
    rich_update(r,2100); r->expected[0]=20; r->expected[1]=30; r->expected_version=8; r->first_event=2; r->seen_attributes=r->seen_events=0;
    for(unsigned i=0;i<3;++i) { CHECK(rich_report(r,output(&r->model,r->clock))==(i<2)); rich_ack(r,false,i%2==0); ++r->clock; }
    CHECK(matter_im_subscribe_process(r->model.active,r->clock)==MATTER_PENDING && matter_im_subscribe_state(r->model.active)==MATTER_IM_SUB_IDLE);
    CHECK(r->seen_attributes==2 && r->seen_events==1 && r->model.reads==4);
    /* A second subscriber sees its own priming history on the SAME node log. */
    RichSub* other=rich_new(false,128); rich_bind(other,r->log); rich_request(other,0,true,false,0);
    receive(&other->model,other->model.input,other->size,3,12,true);
    for(unsigned i=0;i<3;++i) { CHECK(rich_report(other,output(&other->model,0))==(i<2)); rich_ack(other,true,true); }
    rich_prime_finish(other); CHECK(other->seen_events==3); rich_free(other); rich_free(r);
    /* Urgent event-only subscriptions trigger at min; nonurgent wait for max.
     * A future initial EventMin is not retained as a permanent filter. */
    for(unsigned urgent=0;urgent<2;++urgent) {
        r=rich_new(true,128); rich_event(r); rich_event(r); rich_request(r,0,true,urgent!=0,999); r->clock=100;
        receive(&r->model,r->model.input,r->size,3,12,true); CHECK(!rich_report(r,output(&r->model,100)) && !r->seen_events);
        rich_ack(r,true,true); rich_prime_finish(r); rich_event(r); CHECK(matter_im_subscribe_events_changed(r->model.active)==MATTER_OK);
        CHECK(matter_im_subscribe_deadline(r->model.active,&due)==MATTER_OK && due==(urgent?2100u:5100u));
        CHECK(matter_im_subscribe_process(r->model.active,due-1)==MATTER_PENDING && matter_im_subscribe_state(r->model.active)==MATTER_IM_SUB_IDLE);
        rich_update(r,due); r->first_event=2; CHECK(!rich_report(r,output(&r->model,due)) && r->seen_events==1); rich_ack(r,false,false);
        CHECK(matter_im_subscribe_process(r->model.active,due)==MATTER_PENDING); rich_free(r);
    }
    /* Revocation after the first chunk must replace unsent attribute/event data. */
    for(unsigned mode=0;mode<2;++mode) {
        r=rich_new(true,64); rich_event(r); rich_request(r,2,true,true,0); receive(&r->model,r->model.input,r->size,3,12,true);
        CHECK(rich_report(r,output(&r->model,0))); rich_ack(r,true,true);
        if(!mode) r->fabric=2; else { r->deny_attribute=true; r->deny_event=true; }
        CHECK(rich_report(r,output(&r->model,0))); rich_ack(r,true,false);
        CHECK(!rich_report(r,output(&r->model,0))); rich_ack(r,true,true);
        CHECK(matter_im_subscribe_process(r->model.active,0)==MATTER_PORT_ERROR && r->model.releases==1 && r->model.reads==2 && r->seen_status==2); rich_free(r);
    }
    /* Unexpected backend status must never wrap to SUCCESS at the event gate. */
    r=rich_new(true,128); r->bad_auth=true; rich_request(r,0,true,true,0);
    receive(&r->model,r->model.input,r->size,3,12,true);
    Matter_Im_Subscribe_Message_T invalid=output(&r->model,0);
    CHECK(invalid.opcode==1 && invalid.data[3]==MATTER_IM_INVALID_ACTION && !r->model.reads); rich_free(r);
    for(unsigned mode=0;mode<5;++mode) {
        r=rich_new(false,64); rich_request(r,mode==2?MATTER_IM_SUB_MAX_ATTRIBUTE_PATHS+1:mode==3?0:1,mode==4,false,0); r->large=mode==0; r->malformed=mode==1;
        receive(&r->model,r->model.input,r->size,3,12,true); Matter_Im_Subscribe_Message_T out=output(&r->model,0);
        CHECK(out.opcode==1 && out.data[3]==(mode==0?MATTER_IM_RESOURCE_EXHAUSTED:mode==2?MATTER_IM_PATHS_EXHAUSTED:MATTER_IM_INVALID_ACTION));
        CHECK(r->model.reserves==(mode<2?1u:0u)); rich_free(r);
    }
#ifdef MATTER_TEST_ALLOC
    r=rich_new(false,128); rich_request(r,2,false,false,0); receive(&r->model,r->model.input,r->size,3,12,true);
    size_t base=live; fail_at=calls+1; Matter_Im_Subscribe_Message_T out=output(&r->model,0); fail_at=0;
    CHECK(out.opcode==1 && out.data[3]==MATTER_IM_RESOURCE_EXHAUSTED && live==base); rich_free(r); CHECK(!live);
#endif
    puts("PASS structured/event Subscribe: shared scratch snapshots, mixed chunks, ACK/status ordering, changes during TX, per-subscriber cursor, one-time EventMin, nonurgent/max, revocation and OOM");
}
